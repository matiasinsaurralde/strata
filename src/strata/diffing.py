"""Deterministic pass-1 input construction and Git-diff chunking."""

from __future__ import annotations

import re
import shlex
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum

from .contracts import InputProfile, sha256_text

# A byte ceiling is intentionally conservative across provider tokenizers.
# GPT-family BPE token counts cannot exceed the UTF-8 byte count, so this leaves
# headroom below a 128k-token context for prompts and provider framing.
DEFAULT_MAX_INPUT_BYTES = 110_000
DEFAULT_SUBJECT_BYTES = 512
DEFAULT_MESSAGE_BYTES = 8_192


class ChangeKind(StrEnum):
    SOURCE = "source"
    TEST = "test"
    DOCS = "docs"
    DEPENDENCY = "dependency"
    GENERATED_VENDOR = "generated_vendor"
    BINARY = "binary"
    SUBMODULE = "submodule"
    MERGE_RESOLUTION = "merge_resolution"
    OTHER = "other"


class InputBuildStatus(StrEnum):
    READY = "ready"
    EMPTY = "empty"
    EMPTY_FIRST_PARTY = "empty_first_party"
    MALFORMED = "malformed"
    OVERSIZE = "oversize"


class DiffInputError(ValueError):
    pass


class InputOversizeError(DiffInputError):
    pass


@dataclass(frozen=True, slots=True)
class InputLimits:
    max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES
    max_subject_bytes: int = DEFAULT_SUBJECT_BYTES
    max_message_bytes: int = DEFAULT_MESSAGE_BYTES

    def __post_init__(self) -> None:
        for name in ("max_input_bytes", "max_subject_bytes", "max_message_bytes"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True, slots=True)
class FileDiff:
    old_path: str | None
    new_path: str | None
    path: str
    text: str
    change_kind: ChangeKind
    excluded: bool = False
    exclusion_reason: str | None = None


@dataclass(frozen=True, slots=True)
class NormalizedDiff:
    text: str
    files: tuple[FileDiff, ...]
    excluded_files: tuple[FileDiff, ...]
    raw_hash: str
    normalized_hash: str
    status: InputBuildStatus

    @property
    def change_kinds(self) -> tuple[ChangeKind, ...]:
        present = {item.change_kind for item in self.files + self.excluded_files}
        return tuple(kind for kind in ChangeKind if kind in present)


@dataclass(frozen=True, slots=True)
class InputChunk:
    index: int
    text: str
    input_hash: str
    paths: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class TriageInput:
    profile: InputProfile
    text: str
    input_hash: str
    raw_diff_hash: str
    normalized_diff_hash: str
    chunks: tuple[InputChunk, ...]
    status: InputBuildStatus
    error: str | None
    excluded_paths: tuple[str, ...]
    change_kinds: tuple[ChangeKind, ...]

    @property
    def ready(self) -> bool:
        return self.status is InputBuildStatus.READY

    @property
    def chunk_hashes(self) -> tuple[str, ...]:
        return tuple(chunk.input_hash for chunk in self.chunks)


_DIFF_HEADER_RE = re.compile(r"^diff --(?:git|cc|combined) ", re.MULTILINE)
_INDEX_RE = re.compile(r"^index [0-9a-fA-F]+\.\.[0-9a-fA-F]+(?: \d+)?\n?$")
_GENERATED_MARKER_RE = re.compile(
    r"(?:code generated .* do not edit|@generated\b|automatically generated)",
    re.IGNORECASE,
)

_VENDOR_COMPONENTS = frozenset(
    {
        "vendor",
        "vendors",
        "node_modules",
        "third_party",
        "third-party",
        "vendored",
        "external",
    }
)
_GENERATED_COMPONENTS = frozenset({"generated", "dist"})
_GENERATED_SUFFIXES = (
    ".min.js",
    ".min.css",
    ".js.map",
    ".css.map",
    ".pb.go",
    ".pb.cc",
    ".pb.h",
    ".designer.cs",
    ".g.dart",
)
_DEPENDENCY_NAMES = frozenset(
    {
        "go.mod",
        "go.sum",
        "cargo.toml",
        "cargo.lock",
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "pyproject.toml",
        "poetry.lock",
        "pdm.lock",
        "pipfile",
        "pipfile.lock",
        "gemfile",
        "gemfile.lock",
        "composer.json",
        "composer.lock",
        "mix.exs",
        "mix.lock",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "gradle.lockfile",
        "packages.config",
        "deps.edn",
        "flake.lock",
    }
)
_DOC_NAMES = (
    "readme",
    "changelog",
    "changes",
    "news",
    "license",
    "contributing",
    "security",
    "authors",
)
_DOC_SUFFIXES = (".md", ".mdx", ".rst", ".adoc", ".asciidoc")
_SOURCE_SUFFIXES = (
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".go",
    ".rs",
    ".py",
    ".pyi",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".kt",
    ".kts",
    ".rb",
    ".php",
    ".cs",
    ".swift",
    ".scala",
    ".sh",
    ".bash",
    ".zsh",
    ".sql",
    ".lua",
    ".ex",
    ".exs",
    ".erl",
    ".hrl",
)


def normalize_newlines(text: str) -> str:
    if not isinstance(text, str):
        raise TypeError("diff must be text")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def cap_utf8(text: str, max_bytes: int, *, marker: str = "\n[TRUNCATED]\n") -> str:
    """Return a deterministic UTF-8-safe prefix no larger than ``max_bytes``."""

    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text
    marker_bytes = marker.encode("utf-8")
    if len(marker_bytes) >= max_bytes:
        marker = ""
        marker_bytes = b""
    budget = max_bytes - len(marker_bytes)
    prefix = encoded[:budget]
    while prefix:
        try:
            return prefix.decode("utf-8") + marker
        except UnicodeDecodeError:
            prefix = prefix[:-1]
    return marker


def _clean_git_path(path: str | None) -> str | None:
    if path is None or path == "/dev/null":
        return None
    if path.startswith(("a/", "b/")):
        return path[2:]
    return path


def _header_paths(header: str) -> tuple[str | None, str | None]:
    first = header.splitlines()[0] if header else ""
    try:
        parts = shlex.split(first)
    except ValueError:
        parts = first.split()
    if len(parts) >= 4 and parts[:2] == ["diff", "--git"]:
        return _clean_git_path(parts[2]), _clean_git_path(parts[3])
    if len(parts) >= 3 and parts[0] == "diff" and parts[1] in {"--cc", "--combined"}:
        path = _clean_git_path(parts[2])
        return path, path
    return None, None


def _section_paths(section: str) -> tuple[str | None, str | None, str]:
    old_path, new_path = _header_paths(section)
    for line in section.splitlines():
        if line.startswith("rename from "):
            old_path = _clean_git_path(line.removeprefix("rename from "))
        elif line.startswith("rename to "):
            new_path = _clean_git_path(line.removeprefix("rename to "))
        elif line.startswith("--- ") and old_path is None:
            old_path = _clean_git_path(line[4:].split("\t", 1)[0])
        elif line.startswith("+++ ") and new_path is None:
            new_path = _clean_git_path(line[4:].split("\t", 1)[0])
    path = new_path or old_path or "<unknown>"
    return old_path, new_path, path


def split_file_diffs(diff_text: str) -> tuple[str, tuple[str, ...]]:
    """Split a Git diff into preamble and file sections without losing bytes."""

    starts = [match.start() for match in _DIFF_HEADER_RE.finditer(diff_text)]
    if not starts:
        return diff_text, ()
    preamble = diff_text[: starts[0]]
    sections = tuple(
        diff_text[start : starts[index + 1] if index + 1 < len(starts) else len(diff_text)]
        for index, start in enumerate(starts)
    )
    return preamble, sections


def generated_vendor_reason(path: str, patch: str = "") -> str | None:
    lowered = path.lower()
    components = tuple(part for part in lowered.split("/") if part)
    if any(component in _VENDOR_COMPONENTS for component in components):
        return "vendor_directory"
    if any(component in _GENERATED_COMPONENTS for component in components[:-1]):
        return "generated_directory"
    filename = components[-1] if components else lowered
    if filename.endswith(_GENERATED_SUFFIXES):
        return "generated_filename"
    if filename.endswith(
        (".go", ".rs", ".java", ".kt", ".cs", ".js", ".ts")
    ) and _GENERATED_MARKER_RE.search(patch[:4_096]):
        return "generated_marker"
    return None


def is_generated_or_vendor(path: str, patch: str = "") -> bool:
    return generated_vendor_reason(path, patch) is not None


def classify_change_kind(path: str, patch: str = "") -> ChangeKind:
    """Classify one changed file using deterministic, ordered rules."""

    lowered = path.lower()
    components = tuple(part for part in lowered.split("/") if part)
    filename = components[-1] if components else lowered
    if patch.startswith(("diff --cc ", "diff --combined ")):
        return ChangeKind.MERGE_RESOLUTION
    if "Subproject commit " in patch or re.search(
        r"^(?:new |deleted )?file mode 160000$", patch, re.M
    ):
        return ChangeKind.SUBMODULE
    if "GIT binary patch" in patch or re.search(r"^Binary files .+ differ$", patch, re.M):
        return ChangeKind.BINARY
    if is_generated_or_vendor(path, patch):
        return ChangeKind.GENERATED_VENDOR
    if (
        any(
            component in {"test", "tests", "__tests__", "spec", "specs"}
            for component in components
        )
        or filename.startswith("test_")
        or filename.endswith(
            ("_test.go", "_test.py", ".test.js", ".test.ts", ".spec.js", ".spec.ts")
        )
    ):
        return ChangeKind.TEST
    if (
        "docs" in components
        or "doc" in components
        or filename.endswith(_DOC_SUFFIXES)
        or filename in _DOC_NAMES
    ):
        return ChangeKind.DOCS
    if (
        filename in _DEPENDENCY_NAMES
        or (
            filename.startswith(("requirements", "constraints"))
            and filename.endswith((".txt", ".in"))
        )
        or filename.endswith((".lock", ".sum"))
    ):
        return ChangeKind.DEPENDENCY
    if filename.endswith(_SOURCE_SUFFIXES):
        return ChangeKind.SOURCE
    return ChangeKind.OTHER


def _normalize_file_section(section: str) -> str:
    lines = normalize_newlines(section).splitlines(keepends=True)
    normalized = "".join(line for line in lines if not _INDEX_RE.fullmatch(line))
    if normalized and not normalized.endswith("\n"):
        normalized += "\n"
    return normalized


def normalize_first_party_diff(raw_diff: str) -> NormalizedDiff:
    """Build D1: LF-normalized Git diff with generated/vendor files removed."""

    if not isinstance(raw_diff, str):
        raise TypeError("raw_diff must be str")
    raw_hash = sha256_text(raw_diff)
    normalized_raw = normalize_newlines(raw_diff)
    if not normalized_raw.strip():
        return NormalizedDiff(
            text="",
            files=(),
            excluded_files=(),
            raw_hash=raw_hash,
            normalized_hash=sha256_text(""),
            status=InputBuildStatus.EMPTY,
        )
    _, sections = split_file_diffs(normalized_raw)
    if not sections:
        return NormalizedDiff(
            text="",
            files=(),
            excluded_files=(),
            raw_hash=raw_hash,
            normalized_hash=sha256_text(""),
            status=InputBuildStatus.MALFORMED,
        )

    included: list[FileDiff] = []
    excluded: list[FileDiff] = []
    for raw_section in sections:
        section = _normalize_file_section(raw_section)
        old_path, new_path, path = _section_paths(section)
        reason = generated_vendor_reason(path, section)
        item = FileDiff(
            old_path=old_path,
            new_path=new_path,
            path=path,
            text=section,
            change_kind=classify_change_kind(path, section),
            excluded=reason is not None,
            exclusion_reason=reason,
        )
        (excluded if item.excluded else included).append(item)

    text = "".join(item.text for item in included)
    status = InputBuildStatus.READY if text.strip() else InputBuildStatus.EMPTY_FIRST_PARTY
    return NormalizedDiff(
        text=text,
        files=tuple(included),
        excluded_files=tuple(excluded),
        raw_hash=raw_hash,
        normalized_hash=sha256_text(text),
        status=status,
    )


def _split_utf8(text: str, max_bytes: int) -> tuple[str, ...]:
    if len(text.encode("utf-8")) <= max_bytes:
        return (text,)
    chunks: list[str] = []
    current: list[str] = []
    current_bytes = 0
    for character in text:
        size = len(character.encode("utf-8"))
        if current and current_bytes + size > max_bytes:
            chunks.append("".join(current))
            current = []
            current_bytes = 0
        if size > max_bytes:  # UTF-8 code points are at most four bytes.
            raise InputOversizeError("max_input_bytes is too small for one character")
        current.append(character)
        current_bytes += size
    if current:
        chunks.append("".join(current))
    return tuple(chunks)


def _split_by_lines(text: str, max_bytes: int) -> tuple[str, ...]:
    if len(text.encode("utf-8")) <= max_bytes:
        return (text,)
    chunks: list[str] = []
    current = ""
    for line in text.splitlines(keepends=True):
        if len(line.encode("utf-8")) > max_bytes:
            if current:
                chunks.append(current)
                current = ""
            chunks.extend(_split_utf8(line, max_bytes))
            continue
        if current and len((current + line).encode("utf-8")) > max_bytes:
            chunks.append(current)
            current = line
        else:
            current += line
    if current:
        chunks.append(current)
    return tuple(chunks)


def _section_units(section: str, max_bytes: int) -> tuple[str, ...]:
    if len(section.encode("utf-8")) <= max_bytes:
        return (section,)
    lines = section.splitlines(keepends=True)
    hunk_indices = [
        index for index, line in enumerate(lines) if line.startswith(("@@ ", "@@@ "))
    ]
    if not hunk_indices:
        return _split_by_lines(section, max_bytes)
    header = "".join(lines[: hunk_indices[0]])
    units: list[str] = []
    for position, start in enumerate(hunk_indices):
        stop = hunk_indices[position + 1] if position + 1 < len(hunk_indices) else len(lines)
        hunk_lines = lines[start:stop]
        structural_prefix = header + hunk_lines[0]
        body = "".join(hunk_lines[1:])
        prefix_bytes = len(structural_prefix.encode("utf-8"))
        if prefix_bytes >= max_bytes:
            units.extend(_split_by_lines(structural_prefix + body, max_bytes))
            continue
        if not body:
            units.append(structural_prefix)
            continue
        for fragment in _split_by_lines(body, max_bytes - prefix_bytes):
            units.append(structural_prefix + fragment)
    return tuple(units)


def chunk_diff(
    diff_text: str,
    *,
    max_bytes: int = DEFAULT_MAX_INPUT_BYTES,
    prefix: str = "",
) -> tuple[InputChunk, ...]:
    """Chunk by files, then hunks, then lines; no oversized input is dropped."""

    if not isinstance(diff_text, str) or not isinstance(prefix, str):
        raise TypeError("diff_text and prefix must be strings")
    prefix_size = len(prefix.encode("utf-8"))
    if prefix_size >= max_bytes:
        raise InputOversizeError("profile prefix consumes the entire input budget")
    content_budget = max_bytes - prefix_size
    preamble, sections = split_file_diffs(diff_text)
    units: list[tuple[str, tuple[str, ...]]] = []
    if preamble:
        units.extend((part, ()) for part in _split_by_lines(preamble, content_budget))
    for section in sections:
        _, _, path = _section_paths(section)
        units.extend(
            (part, () if path == "<unknown>" else (path,))
            for part in _section_units(section, content_budget)
        )
    if not sections and diff_text:
        units.extend((part, ()) for part in _split_by_lines(diff_text, content_budget))
    if not units:
        return ()

    packed: list[tuple[str, set[str]]] = []
    current = ""
    paths: set[str] = set()
    for unit, unit_paths in units:
        if current and len((current + unit).encode("utf-8")) > content_budget:
            packed.append((current, paths))
            current = unit
            paths = set(unit_paths)
        else:
            current += unit
            paths.update(unit_paths)
    if current:
        packed.append((current, paths))

    result = tuple(
        InputChunk(
            index=index,
            text=prefix + content,
            input_hash=sha256_text(prefix + content),
            paths=tuple(sorted(paths)),
        )
        for index, (content, paths) in enumerate(packed)
    )
    if any(len(chunk.text.encode("utf-8")) > max_bytes for chunk in result):
        raise InputOversizeError("internal chunking error produced an oversized chunk")
    return result


def _profile_prefix(
    profile: InputProfile,
    *,
    subject: str,
    message: str,
    limits: InputLimits,
) -> str:
    if profile is InputProfile.D2:
        first_line = normalize_newlines(subject).split("\n", 1)[0].strip() or "(empty)"
        capped = cap_utf8(first_line, limits.max_subject_bytes)
        return f"### Commit subject\n{capped}\n\n### Diff\n"
    if profile is InputProfile.D3:
        normalized = normalize_newlines(message).strip() or "(empty)"
        capped = cap_utf8(normalized, limits.max_message_bytes)
        return f"### Commit message\n{capped}\n\n### Diff\n"
    return ""


def build_input_profile(
    profile: InputProfile | str,
    raw_diff: str,
    *,
    subject: str = "",
    message: str = "",
    limits: InputLimits | None = None,
) -> TriageInput:
    """Build D0/D1/D2/D3 and all model-visible chunk hashes."""

    try:
        selected = profile if isinstance(profile, InputProfile) else InputProfile(profile)
    except (TypeError, ValueError) as exc:
        raise ValueError("profile must be D0, D1, D2, or D3") from exc
    limits = limits or InputLimits()
    normalized = normalize_first_party_diff(raw_diff)
    if selected is InputProfile.D0:
        body = raw_diff
        status = (
            InputBuildStatus.EMPTY
            if not raw_diff.strip()
            else InputBuildStatus.READY
            if split_file_diffs(raw_diff)[1]
            else InputBuildStatus.MALFORMED
        )
    else:
        body = normalized.text
        status = normalized.status

    prefix = _profile_prefix(selected, subject=subject, message=message, limits=limits)
    logical_text = prefix + body
    error: str | None = None
    chunks: tuple[InputChunk, ...] = ()
    if status is InputBuildStatus.READY:
        try:
            chunks = chunk_diff(body, max_bytes=limits.max_input_bytes, prefix=prefix)
        except InputOversizeError as exc:
            status = InputBuildStatus.OVERSIZE
            error = str(exc)
    elif status is InputBuildStatus.EMPTY:
        error = "raw diff is empty"
    elif status is InputBuildStatus.EMPTY_FIRST_PARTY:
        error = "no first-party files remain after generated/vendor filtering"
    elif status is InputBuildStatus.MALFORMED:
        error = "input is not a recognizable Git diff"

    all_files = normalized.files + normalized.excluded_files
    present = {item.change_kind for item in all_files}
    return TriageInput(
        profile=selected,
        text=logical_text,
        input_hash=sha256_text(logical_text),
        raw_diff_hash=normalized.raw_hash,
        normalized_diff_hash=normalized.normalized_hash,
        chunks=chunks,
        status=status,
        error=error,
        excluded_paths=tuple(sorted(item.path for item in normalized.excluded_files)),
        change_kinds=tuple(kind for kind in ChangeKind if kind in present),
    )


def build_d0(raw_diff: str, *, limits: InputLimits | None = None) -> TriageInput:
    return build_input_profile(InputProfile.D0, raw_diff, limits=limits)


def build_d1(raw_diff: str, *, limits: InputLimits | None = None) -> TriageInput:
    return build_input_profile(InputProfile.D1, raw_diff, limits=limits)


def build_d2(
    raw_diff: str,
    subject: str,
    *,
    limits: InputLimits | None = None,
) -> TriageInput:
    return build_input_profile(InputProfile.D2, raw_diff, subject=subject, limits=limits)


def build_d3(
    raw_diff: str,
    message: str,
    *,
    limits: InputLimits | None = None,
) -> TriageInput:
    return build_input_profile(InputProfile.D3, raw_diff, message=message, limits=limits)


def conservative_boolean_aggregate(
    verdicts: Sequence[bool | None] | Iterable[bool | None],
) -> bool | None:
    """YES dominates; NO is returned only when every chunk is a valid NO."""

    values = tuple(verdicts)
    if any(value is True for value in values):
        return True
    if values and all(value is False for value in values):
        return False
    return None


def input_hashes(value: TriageInput) -> dict[str, str | tuple[str, ...]]:
    return {
        "raw_diff_hash": value.raw_diff_hash,
        "normalized_diff_hash": value.normalized_diff_hash,
        "input_hash": value.input_hash,
        "chunk_hashes": value.chunk_hashes,
    }
