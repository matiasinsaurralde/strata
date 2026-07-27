"""Measured, dependency-optional static-analysis ablations.

The text arm is always available. Optional tools are only reported available
when an executable or module can actually be located, and are never credited
with findings unless an explicit runner is injected.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import shutil
import time
from collections import Counter
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

_HUNK_RE = re.compile(
    r"^@@ -(?P<old>\d+)(?:,(?P<old_count>\d+))? "
    r"\+(?P<new>\d+)(?:,(?P<new_count>\d+))? @@(?P<context>.*)$"
)
_CALL_RE = re.compile(
    r"(?<![\w$])(?:[A-Za-z_$][\w$]*\s*(?:\.|::|->)\s*)*"
    r"(?P<name>[A-Za-z_$][\w$]*)\s*\("
)
_CALL_EXCLUSIONS = frozenset(
    {
        "if",
        "for",
        "while",
        "switch",
        "catch",
        "return",
        "sizeof",
        "typeof",
        "new",
        "delete",
        "func",
        "function",
        "def",
        "class",
        "match",
        "select",
    }
)
_SAFE_COMMENT_EXTENSIONS = frozenset(
    {
        ".c",
        ".cc",
        ".cpp",
        ".cxx",
        ".h",
        ".hh",
        ".hpp",
        ".go",
        ".java",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".rs",
        ".py",
        ".rb",
        ".sh",
    }
)
_BEHAVIORAL_COMMENT_RE = re.compile(
    r"^\s*(?://\s*(?:go:(?:build|generate|linkname|noescape|nosplit|"
    r"noinline|norace|embed|wasmimport|wasmexport)|line\b|export\b|nolint|"
    r"@ts-|#\s*sourceMappingURL)|"
    r"#\s*(?:noqa|type:|pragma:|shellcheck|coding[:=]|-\*-\s*coding)|"
    r"/\*\s*(?:eslint|istanbul|c8|webpack))",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class Availability(Mapping[str, Any]):
    tool: str
    available: bool
    reason: str
    executable: str | None = None
    module: str | None = None
    probe_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.to_dict())

    def __len__(self) -> int:
        return len(self.to_dict())


@dataclass(frozen=True, slots=True)
class DiffHunk:
    path: str
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    context: str
    lines: tuple[str, ...]

    @property
    def additions(self) -> tuple[str, ...]:
        return tuple(
            line[1:]
            for line in self.lines
            if line.startswith("+") and not line.startswith("+++")
        )

    @property
    def deletions(self) -> tuple[str, ...]:
        return tuple(
            line[1:]
            for line in self.lines
            if line.startswith("-") and not line.startswith("---")
        )


@dataclass(frozen=True, slots=True)
class SymbolAnchor:
    path: str
    symbol: str
    kind: str
    start_line: int
    confidence: str = "heuristic"
    method: str = "text_fallback"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class AnalysisRequest:
    diff: str
    before_files: Mapping[str, str] = field(default_factory=dict)
    after_files: Mapping[str, str] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def coerce(
        cls,
        value: AnalysisRequest | str,
        *,
        before_files: Mapping[str, str] | None = None,
        after_files: Mapping[str, str] | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> AnalysisRequest:
        if isinstance(value, cls):
            return value
        if not isinstance(value, str):
            raise TypeError("analysis input must be AnalysisRequest or diff text")
        return cls(
            diff=value,
            before_files=dict(before_files or {}),
            after_files=dict(after_files or {}),
            metadata=dict(metadata or {}),
        )


@dataclass(slots=True)
class AnalysisResult(Mapping[str, Any]):
    analyzer: str
    availability: Availability
    status: str
    findings: Mapping[str, Any]
    metrics: Mapping[str, Any]
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "analyzer": self.analyzer,
            "availability": self.availability.to_dict(),
            "status": self.status,
            "findings": dict(self.findings),
            "metrics": dict(self.metrics),
            "error": self.error,
        }

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.to_dict())

    def __len__(self) -> int:
        return len(self.to_dict())


@dataclass(slots=True)
class AblationReport(Mapping[str, Any]):
    arms: Mapping[str, AnalysisResult]
    elapsed_ms: float
    input_hash: str

    def to_dict(self) -> dict[str, Any]:
        serialized = {name: result.to_dict() for name, result in self.arms.items()}
        return {
            "schema_version": "static-analysis-ablation-v1",
            "input_hash": self.input_hash,
            "elapsed_ms": round(self.elapsed_ms, 3),
            "arms": serialized,
            "summary": {
                "arm_count": len(serialized),
                "available": [
                    name
                    for name, result in serialized.items()
                    if result["availability"]["available"]
                ],
                "unavailable": [
                    name
                    for name, result in serialized.items()
                    if not result["availability"]["available"]
                ],
                "executed": [
                    name for name, result in serialized.items() if result["status"] == "ok"
                ],
                "total_result_count": sum(
                    int(result["metrics"].get("result_count", 0))
                    for result in serialized.values()
                ),
                "total_external_processes": sum(
                    int(result["metrics"].get("external_processes", 0))
                    for result in serialized.values()
                ),
                "estimated_cost_usd": round(
                    sum(
                        float(result["metrics"].get("estimated_cost_usd", 0.0))
                        for result in serialized.values()
                    ),
                    8,
                ),
            },
        }

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.to_dict())

    def __len__(self) -> int:
        return len(self.to_dict())


class Analyzer(Protocol):
    name: str

    def probe(self) -> Availability: ...

    def analyze(self, request: AnalysisRequest) -> AnalysisResult: ...


def _safe_diff_path(value: str) -> str:
    value = value.strip()
    if value == "/dev/null":
        return value
    if value.startswith(("a/", "b/")):
        value = value[2:]
    value = value.split("\t", 1)[0]
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts:
        return value
    return path.as_posix()


def parse_unified_diff(diff: str) -> list[DiffHunk]:
    """Parse ordinary unified hunks without attempting to execute git."""

    result: list[DiffHunk] = []
    current_path = ""
    current_header: re.Match[str] | None = None
    current_lines: list[str] = []

    def flush() -> None:
        nonlocal current_header, current_lines
        if current_header is None:
            return
        groups = current_header.groupdict()
        result.append(
            DiffHunk(
                path=current_path,
                old_start=int(groups["old"]),
                old_count=int(groups["old_count"] or 1),
                new_start=int(groups["new"]),
                new_count=int(groups["new_count"] or 1),
                context=(groups["context"] or "").strip(),
                lines=tuple(current_lines),
            )
        )
        current_header = None
        current_lines = []

    for line in diff.splitlines():
        if line.startswith("diff --git "):
            flush()
            match = re.match(r"diff --git a/(.+?) b/(.+)$", line)
            if match:
                current_path = _safe_diff_path(match.group(2))
            continue
        if line.startswith("+++ "):
            candidate = _safe_diff_path(line[4:])
            if candidate != "/dev/null":
                current_path = candidate
            continue
        match = _HUNK_RE.match(line)
        if match:
            flush()
            current_header = match
            current_lines = []
            continue
        if current_header is not None:
            current_lines.append(line)
    flush()
    return result


_PY_SYMBOL_RE = re.compile(
    r"^(?P<indent>[ \t]*)(?P<kind>async\s+def|def|class)\s+"
    r"(?P<name>[A-Za-z_]\w*)"
)
_SYMBOL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "function",
        re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?(?P<name>[A-Za-z_]\w*)\s*\("),
    ),
    (
        "function",
        re.compile(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+(?P<name>[A-Za-z_]\w*)\s*[<(]"),
    ),
    (
        "function",
        re.compile(
            r"^\s*(?:export\s+)?(?:async\s+)?function\s+"
            r"(?P<name>[A-Za-z_$][\w$]*)\s*\("
        ),
    ),
    (
        "function",
        re.compile(
            r"^\s*(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*="
            r"\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>"
        ),
    ),
    (
        "type",
        re.compile(
            r"^\s*(?:class|struct|interface|enum|trait)\s+"
            r"(?P<name>[A-Za-z_]\w*)"
        ),
    ),
    (
        "function",
        re.compile(
            r"^\s*(?:(?:public|private|protected|static|final|virtual|inline|"
            r"constexpr|extern|synchronized|native|override)\s+)*"
            r"(?:[A-Za-z_~][\w:<>,~*&\[\].?]*\s+)+"
            r"(?P<name>[A-Za-z_~][\w:~]*)\s*\([^;]*\)\s*(?:\{|$)"
        ),
    ),
)


def hunk_to_symbol(
    source: str,
    line_number: int,
    *,
    path: str = "",
) -> SymbolAnchor:
    """Map a changed line to the nearest plausible enclosing symbol."""

    lines = source.splitlines()
    if not lines:
        return SymbolAnchor(path=path, symbol="<file>", kind="file", start_line=1)
    target = min(max(1, int(line_number)), len(lines))
    extension = Path(path).suffix.lower()
    if extension == ".py":
        definitions: list[tuple[int, int, str, str]] = []
        for index, line in enumerate(lines[:target], start=1):
            match = _PY_SYMBOL_RE.match(line)
            if not match:
                continue
            indent = len(match.group("indent").expandtabs(8))
            kind = "class" if match.group("kind") == "class" else "function"
            definitions.append((index, indent, kind, match.group("name")))
        if definitions:
            index, indent, kind, name = definitions[-1]
            if kind == "function":
                classes = [
                    item
                    for item in definitions
                    if item[0] < index and item[2] == "class" and item[1] < indent
                ]
                if classes:
                    name = f"{classes[-1][3]}.{name}"
            return SymbolAnchor(path, name, kind, index)

    for index in range(target - 1, -1, -1):
        line = lines[index]
        stripped = line.lstrip()
        if re.match(
            r"^(?:return|if|for|while|switch|catch|throw|yield|await)\b",
            stripped,
        ):
            continue
        for kind, pattern in _SYMBOL_PATTERNS:
            match = pattern.match(line)
            if match:
                return SymbolAnchor(
                    path=path,
                    symbol=match.group("name"),
                    kind=kind,
                    start_line=index + 1,
                )
    return SymbolAnchor(path=path, symbol="<file>", kind="file", start_line=1)


map_hunk_to_symbol = hunk_to_symbol


def _is_comment_only(line: str, path: str) -> bool:
    extension = Path(path).suffix.lower()
    if extension not in _SAFE_COMMENT_EXTENSIONS:
        return False
    if _BEHAVIORAL_COMMENT_RE.match(line):
        return False
    stripped = line.strip()
    if extension in {".py", ".rb", ".sh"}:
        return stripped.startswith("#") and not stripped.startswith("#!")
    return (
        stripped.startswith("//")
        or stripped.startswith("/*")
        or stripped.startswith("*")
        or stripped.endswith("*/")
    )


def normalize_changed_line(line: str, path: str) -> str | None:
    """Normalize only changes known to be whitespace/comment-only safe."""

    if not line.strip() or _is_comment_only(line, path):
        return None
    extension = Path(path).suffix.lower()
    if extension == ".py":
        # Python indentation is semantic; preserve leading width.
        leading = len(line) - len(line.lstrip(" \t"))
        return f"{leading}:{line.strip()}"
    if extension in _SAFE_COMMENT_EXTENSIONS:
        return re.sub(r"\s+", " ", line.strip())
    # Unknown formats receive only trailing-space normalization.
    return line.rstrip()


def hunk_is_comment_or_whitespace_only(hunk: DiffHunk) -> bool:
    additions = Counter(
        value
        for line in hunk.additions
        if (value := normalize_changed_line(line, hunk.path)) is not None
    )
    deletions = Counter(
        value
        for line in hunk.deletions
        if (value := normalize_changed_line(line, hunk.path)) is not None
    )
    return additions == deletions


def filter_comment_whitespace_hunks(
    diff_or_hunks: str | Sequence[DiffHunk],
) -> tuple[list[DiffHunk], dict[str, int]]:
    hunks = (
        parse_unified_diff(diff_or_hunks)
        if isinstance(diff_or_hunks, str)
        else list(diff_or_hunks)
    )
    substantive = [hunk for hunk in hunks if not hunk_is_comment_or_whitespace_only(hunk)]
    return substantive, {
        "input_hunks": len(hunks),
        "filtered_hunks": len(hunks) - len(substantive),
        "substantive_hunks": len(substantive),
    }


def is_comment_or_whitespace_only_change(diff: str) -> bool:
    hunks = parse_unified_diff(diff)
    return bool(hunks) and all(hunk_is_comment_or_whitespace_only(hunk) for hunk in hunks)


def map_hunks_to_symbols(
    diff_or_hunks: str | Sequence[DiffHunk],
    *,
    before_files: Mapping[str, str] | None = None,
    after_files: Mapping[str, str] | None = None,
) -> list[dict[str, Any]]:
    hunks = (
        parse_unified_diff(diff_or_hunks)
        if isinstance(diff_or_hunks, str)
        else list(diff_or_hunks)
    )
    before = before_files or {}
    after = after_files or {}
    mapped: list[dict[str, Any]] = []
    for index, hunk in enumerate(hunks):
        source = after.get(hunk.path)
        line = hunk.new_start
        revision = "after"
        if source is None:
            source = before.get(hunk.path, "")
            line = hunk.old_start
            revision = "before"
        anchor = hunk_to_symbol(source, line, path=hunk.path)
        mapped.append(
            {
                "hunk_index": index,
                "path": hunk.path,
                "old_start": hunk.old_start,
                "new_start": hunk.new_start,
                "revision": revision,
                "symbol": anchor.to_dict(),
                "cosmetic_only": hunk_is_comment_or_whitespace_only(hunk),
            }
        )
    return mapped


def _changed_call_names(hunks: Sequence[DiffHunk]) -> list[str]:
    names: set[str] = set()
    for hunk in hunks:
        for line in (*hunk.additions, *hunk.deletions):
            stripped = line.strip()
            for match in _CALL_RE.finditer(stripped):
                name = match.group("name")
                if name not in _CALL_EXCLUSIONS:
                    names.add(name)
    return sorted(names)


def search_similar_call_sites(
    diff_or_hunks: str | Sequence[DiffHunk],
    files: Mapping[str, str],
    *,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Find deterministic textual call sites for calls touched by the patch."""

    if limit < 0:
        raise ValueError("limit must be non-negative")
    hunks = (
        parse_unified_diff(diff_or_hunks)
        if isinstance(diff_or_hunks, str)
        else list(diff_or_hunks)
    )
    names = _changed_call_names(hunks)
    if not names or limit == 0:
        return []
    changed_paths = {hunk.path for hunk in hunks}
    results: list[dict[str, Any]] = []
    patterns = {
        name: re.compile(
            rf"(?<![\w$])(?:[A-Za-z_$][\w$]*\s*(?:\.|::|->)\s*)*"
            rf"{re.escape(name)}\s*\("
        )
        for name in names
    }
    for path in sorted(files):
        source = files[path]
        for line_number, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("def ", "func ", "function ")):
                continue
            for name in names:
                if not patterns[name].search(line):
                    continue
                anchor = hunk_to_symbol(source, line_number, path=path)
                results.append(
                    {
                        "callee": name,
                        "path": path,
                        "line": line_number,
                        "snippet": stripped[:500],
                        "symbol": anchor.symbol,
                        "changed_path": path in changed_paths,
                        "method": "text_call_pattern",
                    }
                )
                if len(results) >= limit:
                    return results
    return results


similar_call_site_search = search_similar_call_sites


def probe_availability(
    tool: str,
    *,
    executable_names: Sequence[str] = (),
    module_names: Sequence[str] = (),
    which: Callable[[str], str | None] = shutil.which,
    find_spec: Callable[[str], Any] = importlib.util.find_spec,
    monotonic: Callable[[], float] = time.monotonic,
) -> Availability:
    started = monotonic()
    for executable_name in executable_names:
        location = which(executable_name)
        if location:
            return Availability(
                tool=tool,
                available=True,
                reason=f"executable {executable_name!r} found",
                executable=location,
                probe_ms=(monotonic() - started) * 1000.0,
            )
    for module_name in module_names:
        try:
            spec = find_spec(module_name)
        except ImportError, ModuleNotFoundError, ValueError:
            spec = None
        if spec is not None:
            return Availability(
                tool=tool,
                available=True,
                reason=f"Python module {module_name!r} found",
                module=module_name,
                probe_ms=(monotonic() - started) * 1000.0,
            )
    searched = [*executable_names, *module_names]
    return Availability(
        tool=tool,
        available=False,
        reason="not installed; searched " + ", ".join(searched),
        probe_ms=(monotonic() - started) * 1000.0,
    )


class TextBaselineAnalyzer:
    name = "text_baseline"

    def __init__(
        self,
        *,
        similar_call_limit: int = 100,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.similar_call_limit = similar_call_limit
        self._monotonic = monotonic

    def probe(self) -> Availability:
        return Availability(
            tool=self.name,
            available=True,
            reason="built into the Python standard-library implementation",
        )

    def analyze(
        self,
        request: AnalysisRequest | str,
        *,
        before_files: Mapping[str, str] | None = None,
        after_files: Mapping[str, str] | None = None,
    ) -> AnalysisResult:
        request = AnalysisRequest.coerce(
            request, before_files=before_files, after_files=after_files
        )
        started = self._monotonic()
        hunks = parse_unified_diff(request.diff)
        substantive, filtering = filter_comment_whitespace_hunks(hunks)
        symbols = map_hunks_to_symbols(
            hunks,
            before_files=request.before_files,
            after_files=request.after_files,
        )
        files = request.after_files or request.before_files
        similar = search_similar_call_sites(
            substantive,
            files,
            limit=self.similar_call_limit,
        )
        elapsed_ms = (self._monotonic() - started) * 1000.0
        findings = {
            "hunk_symbols": symbols,
            "cosmetic_only": bool(hunks) and not substantive,
            "similar_call_sites": similar,
            "changed_call_names": _changed_call_names(substantive),
        }
        return AnalysisResult(
            analyzer=self.name,
            availability=self.probe(),
            status="ok",
            findings=findings,
            metrics={
                "elapsed_ms": round(elapsed_ms, 3),
                "input_bytes": len(request.diff.encode("utf-8")),
                "file_bytes": sum(len(text.encode("utf-8")) for text in files.values()),
                "hunk_count": len(hunks),
                **filtering,
                "symbol_count": len(symbols),
                "similar_call_site_count": len(similar),
                "result_count": len(symbols) + len(similar),
                "external_processes": 0,
                "estimated_cost_usd": 0.0,
            },
        )


OptionalRunner = Callable[[AnalysisRequest, Availability], Mapping[str, Any]]


class OptionalToolAnalyzer:
    """Availability/provenance wrapper for an optional analyzer.

    A found binary is not the same as an executed analysis. Without an injected
    runner the status is explicitly ``available_not_run``.
    """

    name = "optional"
    executable_names: tuple[str, ...] = ()
    module_names: tuple[str, ...] = ()

    def __init__(
        self,
        *,
        runner: OptionalRunner | None = None,
        which: Callable[[str], str | None] = shutil.which,
        find_spec: Callable[[str], Any] = importlib.util.find_spec,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.runner = runner
        self._which = which
        self._find_spec = find_spec
        self._monotonic = monotonic

    def probe(self) -> Availability:
        return probe_availability(
            self.name,
            executable_names=self.executable_names,
            module_names=self.module_names,
            which=self._which,
            find_spec=self._find_spec,
            monotonic=self._monotonic,
        )

    def analyze(self, request: AnalysisRequest | str) -> AnalysisResult:
        request = AnalysisRequest.coerce(request)
        started = self._monotonic()
        availability = self.probe()
        common = {
            "input_bytes": len(request.diff.encode("utf-8")),
            "external_processes": 0,
            "estimated_cost_usd": 0.0,
            "result_count": 0,
        }
        if not availability.available:
            return AnalysisResult(
                analyzer=self.name,
                availability=availability,
                status="unavailable",
                findings={},
                metrics={
                    **common,
                    "elapsed_ms": round((self._monotonic() - started) * 1000.0, 3),
                },
                error=availability.reason,
            )
        if self.runner is None:
            return AnalysisResult(
                analyzer=self.name,
                availability=availability,
                status="available_not_run",
                findings={},
                metrics={
                    **common,
                    "elapsed_ms": round((self._monotonic() - started) * 1000.0, 3),
                },
                error=(
                    "tool is installed, but no explicit runner/language database was configured"
                ),
            )
        try:
            supplied = self.runner(request, availability)
            if not isinstance(supplied, Mapping):
                raise TypeError("optional analyzer runner must return a mapping")
            findings = supplied.get("findings", supplied)
            if not isinstance(findings, Mapping):
                findings = {"results": findings}
            result_count = supplied.get("result_count")
            if result_count is None:
                result_count = _count_results(findings)
            external_processes = int(supplied.get("external_processes", 1))
            estimated_cost = float(supplied.get("estimated_cost_usd", 0.0))
            return AnalysisResult(
                analyzer=self.name,
                availability=availability,
                status="ok",
                findings=dict(findings),
                metrics={
                    "elapsed_ms": round((self._monotonic() - started) * 1000.0, 3),
                    "input_bytes": common["input_bytes"],
                    "result_count": int(result_count),
                    "external_processes": external_processes,
                    "estimated_cost_usd": estimated_cost,
                },
            )
        except Exception as exc:
            return AnalysisResult(
                analyzer=self.name,
                availability=availability,
                status="error",
                findings={},
                metrics={
                    **common,
                    "elapsed_ms": round((self._monotonic() - started) * 1000.0, 3),
                },
                error=f"{type(exc).__name__}: {exc!s}"[:500],
            )


def _count_results(value: Any) -> int:
    if isinstance(value, Mapping):
        return sum(_count_results(item) for item in value.values())
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return len(value)
    return 0


class TreeSitterAnalyzer(OptionalToolAnalyzer):
    name = "tree_sitter"
    executable_names = ("tree-sitter",)
    module_names = ("tree_sitter",)


class AstGrepAnalyzer(OptionalToolAnalyzer):
    name = "ast_grep"
    executable_names = ("ast-grep", "sg")
    module_names = ("ast_grep_py",)


class CodeQLAnalyzer(OptionalToolAnalyzer):
    name = "codeql"
    executable_names = ("codeql",)


class JoernAnalyzer(OptionalToolAnalyzer):
    name = "joern"
    executable_names = ("joern", "joern-parse")


def default_analyzers() -> tuple[Analyzer, ...]:
    return (
        TextBaselineAnalyzer(),
        TreeSitterAnalyzer(),
        AstGrepAnalyzer(),
        CodeQLAnalyzer(),
        JoernAnalyzer(),
    )


def availability_report(
    analyzers: Sequence[Analyzer] | None = None,
) -> dict[str, dict[str, Any]]:
    return {
        analyzer.name: analyzer.probe().to_dict()
        for analyzer in (analyzers or default_analyzers())
    }


class AblationRunner:
    def __init__(
        self,
        analyzers: Sequence[Analyzer] | None = None,
        *,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.analyzers = tuple(analyzers or default_analyzers())
        names = [analyzer.name for analyzer in self.analyzers]
        if len(set(names)) != len(names):
            raise ValueError("ablation analyzer names must be unique")
        self._monotonic = monotonic

    def run(
        self,
        request: AnalysisRequest | str,
        *,
        before_files: Mapping[str, str] | None = None,
        after_files: Mapping[str, str] | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> AblationReport:
        request = AnalysisRequest.coerce(
            request,
            before_files=before_files,
            after_files=after_files,
            metadata=metadata,
        )
        started = self._monotonic()
        arms: dict[str, AnalysisResult] = {}
        for analyzer in self.analyzers:
            arm_started = self._monotonic()
            try:
                arms[analyzer.name] = analyzer.analyze(request)
            except Exception as exc:
                try:
                    availability = analyzer.probe()
                except Exception as probe_exc:
                    availability = Availability(
                        tool=analyzer.name,
                        available=False,
                        reason=f"availability probe failed: {type(probe_exc).__name__}",
                    )
                arms[analyzer.name] = AnalysisResult(
                    analyzer=analyzer.name,
                    availability=availability,
                    status="error",
                    findings={},
                    metrics={
                        "elapsed_ms": round((self._monotonic() - arm_started) * 1000.0, 3),
                        "input_bytes": len(request.diff.encode("utf-8")),
                        "result_count": 0,
                        "external_processes": 0,
                        "estimated_cost_usd": 0.0,
                    },
                    error=f"{type(exc).__name__}: {exc!s}"[:500],
                )
        input_material = json.dumps(
            {
                "diff": request.diff,
                "before_paths": sorted(request.before_files),
                "after_paths": sorted(request.after_files),
                "metadata": request.metadata,
            },
            sort_keys=True,
            ensure_ascii=False,
            default=str,
            separators=(",", ":"),
        ).encode("utf-8")
        return AblationReport(
            arms=arms,
            elapsed_ms=(self._monotonic() - started) * 1000.0,
            input_hash="sha256:" + hashlib.sha256(input_material).hexdigest(),
        )


def run_ablation(
    request: AnalysisRequest | str,
    *,
    before_files: Mapping[str, str] | None = None,
    after_files: Mapping[str, str] | None = None,
    metadata: Mapping[str, Any] | None = None,
    analyzers: Sequence[Analyzer] | None = None,
) -> AblationReport:
    return AblationRunner(analyzers).run(
        request,
        before_files=before_files,
        after_files=after_files,
        metadata=metadata,
    )


TextAnalyzer = TextBaselineAnalyzer
StaticAnalysisAblation = AblationRunner


__all__ = [
    "AblationReport",
    "AblationRunner",
    "AnalysisRequest",
    "AnalysisResult",
    "Analyzer",
    "AstGrepAnalyzer",
    "Availability",
    "CodeQLAnalyzer",
    "DiffHunk",
    "JoernAnalyzer",
    "OptionalToolAnalyzer",
    "StaticAnalysisAblation",
    "SymbolAnchor",
    "TextAnalyzer",
    "TextBaselineAnalyzer",
    "TreeSitterAnalyzer",
    "availability_report",
    "default_analyzers",
    "filter_comment_whitespace_hunks",
    "hunk_is_comment_or_whitespace_only",
    "hunk_to_symbol",
    "is_comment_or_whitespace_only_change",
    "map_hunk_to_symbol",
    "map_hunks_to_symbols",
    "normalize_changed_line",
    "parse_unified_diff",
    "probe_availability",
    "run_ablation",
    "search_similar_call_sites",
    "similar_call_site_search",
]
