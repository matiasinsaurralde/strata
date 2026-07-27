"""Bounded, read-only access to untrusted Git repositories.

Repositories are copied into content-addressed bare mirrors.  All Git
invocations use argument arrays, a scrubbed environment, explicit timeouts,
and bounded output pipes.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import threading
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit, urlunsplit

DEFAULT_COMMAND_TIMEOUT = 30.0
DEFAULT_FETCH_TIMEOUT = 120.0
DEFAULT_MAX_OUTPUT = 8 * 1024 * 1024
DEFAULT_MAX_PATCH = 16 * 1024 * 1024
HARD_MAX_BLOB = 16 * 1024 * 1024
HARD_MAX_COMMITS = 100_000

_FULL_SHA_RE = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_SAFE_REV_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")
_SCP_URL_RE = re.compile(
    r"^(?:(?P<user>[A-Za-z0-9._-]+)@)?"
    r"(?P<host>[A-Za-z0-9.-]+):"
    r"(?P<path>[A-Za-z0-9._~/-]+)$"
)


class GitRepositoryError(RuntimeError):
    """Base error for repository operations."""


class GitCommandError(GitRepositoryError):
    """A bounded Git command failed."""

    def __init__(
        self,
        args: Iterable[str],
        returncode: int,
        stderr: str,
    ) -> None:
        self.args_array = tuple(args)
        self.returncode = returncode
        self.stderr = stderr
        command = " ".join(self.args_array[:4])
        super().__init__(f"Git command failed ({returncode}): {command}: {stderr.strip()}")


class GitTimeoutError(GitRepositoryError):
    """A Git command exceeded its timeout."""


class GitOutputLimitError(GitRepositoryError):
    """A Git command exceeded its output budget."""


class InvalidRevisionError(ValueError):
    """A revision is not in the deliberately small accepted grammar."""


class InvalidRepositoryPathError(ValueError):
    """A repository path is unsafe or unsupported."""


@dataclass(frozen=True, slots=True)
class RepositorySnapshot:
    source: str
    canonical_source: str
    repository_hash: str
    mirror_path: Path
    default_branch: str
    head_sha: str


@dataclass(frozen=True, slots=True)
class ChangedPath:
    status: str
    path: str
    old_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class GitCommit:
    sha: str
    parents: tuple[str, ...]
    message: str
    author_name: str
    author_email: str
    author_time: str
    committer_name: str
    committer_email: str
    committer_time: str
    changed_paths: tuple[ChangedPath, ...] = ()
    patch: bytes = b""
    patch_id: str | None = None

    @property
    def parent_sha(self) -> str | None:
        """The first parent used for the extracted diff."""
        return self.parents[0] if self.parents else None

    @property
    def is_root(self) -> bool:
        return not self.parents

    @property
    def is_merge(self) -> bool:
        return len(self.parents) > 1

    @property
    def patch_text(self) -> str:
        return self.patch.decode("utf-8", errors="replace")

    def to_dict(self, *, include_patch: bool = True) -> dict[str, Any]:
        row: dict[str, Any] = {
            "sha": self.sha,
            "parents": list(self.parents),
            "parent_sha": self.parent_sha,
            "message": self.message,
            "author_name": self.author_name,
            "author_email": self.author_email,
            "author_time": self.author_time,
            "committer_name": self.committer_name,
            "committer_email": self.committer_email,
            "committer_time": self.committer_time,
            "changed_paths": [path.to_dict() for path in self.changed_paths],
            "patch_id": self.patch_id,
            "is_root": self.is_root,
            "is_merge": self.is_merge,
        }
        if include_patch:
            row["patch"] = self.patch_text
        return row


@dataclass(frozen=True, slots=True)
class SearchMatch:
    path: str
    line: int
    text: str
    revision: str


@dataclass(frozen=True, slots=True)
class BlameLine:
    revision: str
    original_line: int
    final_line: int
    author: str
    author_email: str
    text: str


def _contains_control(value: str) -> bool:
    return any(ord(char) < 32 or ord(char) == 127 for char in value)


def _normalise_source(source: str | os.PathLike[str]) -> tuple[str, str, bool]:
    raw = os.fspath(source).strip()
    if not raw or "\x00" in raw or _contains_control(raw):
        raise ValueError("repository source is empty or contains control characters")

    candidate = Path(raw).expanduser()
    if candidate.exists():
        resolved = candidate.resolve(strict=True)
        return str(resolved), resolved.as_uri(), True

    if _SCP_URL_RE.fullmatch(raw):
        return raw, raw, False

    parsed = urlsplit(raw)
    if parsed.scheme not in {"http", "https", "ssh", "git"}:
        raise ValueError(
            "repository source must be an existing local path or an "
            "http(s), ssh, git, or scp-style URL"
        )
    if not parsed.hostname or parsed.password is not None:
        raise ValueError("remote repository URL has an invalid host or embedded password")
    if parsed.query or parsed.fragment:
        raise ValueError("remote repository URL must not contain a query or fragment")
    if parsed.scheme in {"http", "https", "git"} and parsed.username is not None:
        raise ValueError("credentials must not be embedded in remote repository URLs")
    if not parsed.path or parsed.path == "/":
        raise ValueError("remote repository URL has no repository path")

    host = parsed.hostname.lower()
    if parsed.port is not None:
        host = f"{host}:{parsed.port}"
    if parsed.username:
        host = f"{parsed.username}@{host}"
    path = parsed.path.rstrip("/")
    canonical = urlunsplit((parsed.scheme.lower(), host, path, "", ""))
    return canonical, canonical, False


def stable_repository_hash(source: str | os.PathLike[str]) -> str:
    """Return the stable SHA-256 cache key for a repository source."""
    _, canonical, _ = _normalise_source(source)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def validate_revision(revision: str, *, allow_range: bool = False) -> str:
    """Validate a revision without accepting Git's option/revspec language."""
    if not isinstance(revision, str):
        raise InvalidRevisionError("revision must be text")
    if not revision or _contains_control(revision) or revision.startswith("-"):
        raise InvalidRevisionError("invalid revision")
    if allow_range:
        separator = "..." if "..." in revision else ".." if ".." in revision else None
        if separator is not None:
            if revision.count(separator) != 1:
                raise InvalidRevisionError("invalid revision range")
            left, right = revision.split(separator, 1)
            if not left or not right:
                raise InvalidRevisionError("both range endpoints are required")
            validate_revision(left)
            validate_revision(right)
            return revision
    if _FULL_SHA_RE.fullmatch(revision) or _SAFE_REV_RE.fullmatch(revision):
        if ".." not in revision and "//" not in revision and not revision.endswith(("/", ".")):
            return revision
    raise InvalidRevisionError(f"unsupported revision syntax: {revision!r}")


def validate_path(path: str) -> str:
    """Accept only relative, normalized, text Git paths."""
    if not isinstance(path, str) or not path or _contains_control(path):
        raise InvalidRepositoryPathError("path is empty or contains control characters")
    if "\\" in path or ":" in path:
        raise InvalidRepositoryPathError("path contains an unsupported separator")
    pure = PurePosixPath(path)
    if (
        pure.is_absolute()
        or pure.as_posix() != path
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise InvalidRepositoryPathError("path must be normalized and relative")
    if len(path.encode("utf-8")) > 4096:
        raise InvalidRepositoryPathError("path is too long")
    return path


def _scrubbed_environment() -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "LC_ALL": "C.UTF-8",
        }
    )
    return env


def _run_bounded(
    args: list[str],
    *,
    timeout: float,
    max_output: int,
    input_data: bytes | None = None,
    allowed_returncodes: tuple[int, ...] = (0,),
) -> bytes:
    if not args or any(not isinstance(arg, str) or "\x00" in arg for arg in args):
        raise ValueError("subprocess arguments must be non-NUL strings")
    if timeout <= 0 or max_output <= 0:
        raise ValueError("timeout and max_output must be positive")

    process = subprocess.Popen(
        args,
        stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_scrubbed_environment(),
        close_fds=True,
    )
    output_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    exceeded: list[str] = []
    state_lock = threading.Lock()

    def drain(
        stream: Any,
        chunks: list[bytes],
        limit: int,
        stream_name: str,
    ) -> None:
        size = 0
        try:
            while chunk := stream.read(64 * 1024):
                remaining = limit - size
                if remaining > 0:
                    chunks.append(chunk[:remaining])
                    size += min(len(chunk), remaining)
                if len(chunk) > remaining:
                    with state_lock:
                        if not exceeded:
                            exceeded.append(stream_name)
                    with contextlib.suppress(ProcessLookupError):
                        process.kill()
        finally:
            stream.close()

    def write_input() -> None:
        assert process.stdin is not None
        try:
            process.stdin.write(input_data or b"")
            process.stdin.flush()
        except BrokenPipeError, OSError:
            pass
        finally:
            process.stdin.close()

    # Pipes are drained continuously so neither Git nor the parent can buffer
    # unbounded output in memory or on disk.
    assert process.stdout is not None and process.stderr is not None
    stderr_limit = min(max_output, 64 * 1024)
    readers = [
        threading.Thread(
            target=drain,
            args=(process.stdout, output_chunks, max_output, "stdout"),
            daemon=True,
        ),
        threading.Thread(
            target=drain,
            args=(process.stderr, stderr_chunks, stderr_limit, "stderr"),
            daemon=True,
        ),
    ]
    for reader in readers:
        reader.start()
    writer = (
        threading.Thread(target=write_input, daemon=True) if input_data is not None else None
    )
    if writer is not None:
        writer.start()

    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.wait()
        raise GitTimeoutError(f"Git command exceeded {timeout:g}s") from exc
    finally:
        for reader in readers:
            reader.join()
        if writer is not None:
            writer.join()

    output = b"".join(output_chunks)
    stderr_bytes = b"".join(stderr_chunks)
    if exceeded:
        raise GitOutputLimitError(
            f"Git {exceeded[0]} exceeded "
            f"{max_output if exceeded[0] == 'stdout' else stderr_limit} bytes"
        )
    if process.returncode not in allowed_returncodes:
        raise GitCommandError(
            args,
            process.returncode,
            stderr_bytes.decode("utf-8", errors="replace"),
        )
    return output


class GitRepository:
    """A content-addressed bare mirror with bounded read-only operations."""

    def __init__(
        self,
        source: str | os.PathLike[str],
        *,
        cache_root: str | os.PathLike[str] = ".strata/repos",
        command_timeout: float = DEFAULT_COMMAND_TIMEOUT,
        fetch_timeout: float = DEFAULT_FETCH_TIMEOUT,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT,
        max_patch_bytes: int = DEFAULT_MAX_PATCH,
    ) -> None:
        source_arg, canonical_source, is_local = _normalise_source(source)
        self.source = source_arg
        self.canonical_source = canonical_source
        self.is_local = is_local
        self.repository_hash = hashlib.sha256(canonical_source.encode("utf-8")).hexdigest()
        self.cache_root = Path(cache_root).expanduser().resolve()
        self.mirror_path = self.cache_root / f"{self.repository_hash}.git"
        self.command_timeout = float(command_timeout)
        self.fetch_timeout = float(fetch_timeout)
        self.max_output_bytes = int(max_output_bytes)
        self.max_patch_bytes = int(max_patch_bytes)
        if (
            min(
                self.command_timeout,
                self.fetch_timeout,
                self.max_output_bytes,
                self.max_patch_bytes,
            )
            <= 0
        ):
            raise ValueError("timeouts and output limits must be positive")

    def _base_git(self, *, in_mirror: bool = True) -> list[str]:
        args = [
            "git",
            "--no-pager",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "protocol.ext.allow=never",
            "-c",
            f"protocol.file.allow={'always' if self.is_local else 'never'}",
            "-c",
            "fetch.recurseSubmodules=false",
            "-c",
            "submodule.recurse=false",
            "-c",
            "credential.interactive=never",
            "-c",
            "remote.origin.uploadpack=git-upload-pack",
        ]
        if in_mirror:
            self._require_mirror()
            args.extend(["-C", str(self.mirror_path)])
        return args

    def _git(
        self,
        arguments: list[str],
        *,
        timeout: float | None = None,
        max_output: int | None = None,
        input_data: bytes | None = None,
        allowed_returncodes: tuple[int, ...] = (0,),
        in_mirror: bool = True,
    ) -> bytes:
        return _run_bounded(
            self._base_git(in_mirror=in_mirror) + arguments,
            timeout=timeout or self.command_timeout,
            max_output=max_output or self.max_output_bytes,
            input_data=input_data,
            allowed_returncodes=allowed_returncodes,
        )

    def _require_mirror(self) -> None:
        if not self.mirror_path.is_dir():
            raise GitRepositoryError("repository has not been fetched")

    def _clone(self) -> None:
        self.cache_root.mkdir(parents=True, exist_ok=True)
        temporary_parent = Path(
            tempfile.mkdtemp(prefix=f".{self.repository_hash[:12]}-", dir=self.cache_root)
        )
        temporary_mirror = temporary_parent / "mirror.git"
        try:
            self._git(
                [
                    "clone",
                    "--mirror",
                    "--no-hardlinks",
                    "--no-recurse-submodules",
                    "--upload-pack=git-upload-pack",
                    "--",
                    self.source,
                    str(temporary_mirror),
                ],
                timeout=self.fetch_timeout,
                max_output=256 * 1024,
                in_mirror=False,
            )
            if self.mirror_path.exists():
                return
            os.replace(temporary_mirror, self.mirror_path)
        finally:
            shutil.rmtree(temporary_parent, ignore_errors=True)

    def _remote_head_branch(self) -> str | None:
        output = self._git(
            ["ls-remote", "--symref", "origin", "HEAD"],
            timeout=self.fetch_timeout,
            max_output=64 * 1024,
        ).decode("utf-8", errors="replace")
        for line in output.splitlines():
            if not line.startswith("ref: "):
                continue
            ref, separator, target = line[5:].partition("\t")
            if separator and target == "HEAD" and ref.startswith("refs/heads/"):
                branch = ref.removeprefix("refs/heads/")
                try:
                    return validate_revision(branch)
                except InvalidRevisionError:
                    return None
        return None

    def fetch(self) -> RepositorySnapshot:
        """Create or update the mirror and return its current default head."""
        if not self.mirror_path.exists():
            self._clone()
        if not self.mirror_path.is_dir():
            raise GitRepositoryError(f"mirror path is not a directory: {self.mirror_path}")

        bare = self._git(["rev-parse", "--is-bare-repository"], max_output=128).strip()
        if bare != b"true":
            raise GitRepositoryError("cache entry is not a bare Git repository")

        self._git(["remote", "set-url", "origin", self.source], max_output=64 * 1024)
        branch = self._remote_head_branch()
        self._git(
            [
                "fetch",
                "--prune",
                "--force",
                "--no-recurse-submodules",
                "origin",
                "+refs/heads/*:refs/heads/*",
                "+refs/tags/*:refs/tags/*",
            ],
            timeout=self.fetch_timeout,
            max_output=512 * 1024,
        )
        if branch is not None:
            exists = self._git(
                ["show-ref", "--verify", "--quiet", f"refs/heads/{branch}"],
                max_output=128,
                allowed_returncodes=(0, 1),
            )
            del exists
            # show-ref emits nothing; inspect its status through rev-parse instead.
            try:
                self.resolve_revision(branch)
            except GitRepositoryError, InvalidRevisionError:
                branch = None
            else:
                self._git(["symbolic-ref", "HEAD", f"refs/heads/{branch}"], max_output=128)

        default_branch = self.default_branch()
        head_sha = self.resolve_revision(default_branch)
        return RepositorySnapshot(
            source=self.source,
            canonical_source=self.canonical_source,
            repository_hash=self.repository_hash,
            mirror_path=self.mirror_path,
            default_branch=default_branch,
            head_sha=head_sha,
        )

    def default_branch(self) -> str:
        """Discover the mirror's default branch without trusting local config."""
        symbolic = (
            self._git(
                ["symbolic-ref", "--quiet", "HEAD"],
                max_output=4096,
                allowed_returncodes=(0, 1),
            )
            .decode("utf-8", errors="strict")
            .strip()
        )
        if symbolic.startswith("refs/heads/"):
            branch = symbolic.removeprefix("refs/heads/")
            try:
                validate_revision(branch)
                self.resolve_revision(branch)
                return branch
            except InvalidRevisionError, GitRepositoryError:
                pass

        for candidate in ("main", "master"):
            try:
                self.resolve_revision(candidate)
                return candidate
            except GitRepositoryError:
                pass

        output = self._git(
            [
                "for-each-ref",
                "--sort=-committerdate",
                "--format=%(refname:strip=2)",
                "refs/heads",
            ],
            max_output=256 * 1024,
        ).decode("utf-8", errors="replace")
        for branch in output.splitlines():
            try:
                return validate_revision(branch)
            except InvalidRevisionError:
                continue
        raise GitRepositoryError("repository has no valid branch")

    def resolve_revision(self, revision: str) -> str:
        revision = validate_revision(revision)
        output = (
            self._git(
                ["rev-parse", "--verify", f"{revision}^{{commit}}", "--"],
                max_output=128,
            )
            .decode("ascii", errors="strict")
            .strip()
        )
        if not _FULL_SHA_RE.fullmatch(output):
            raise GitRepositoryError("Git returned an invalid commit ID")
        return output.lower()

    def enumerate_shas(
        self,
        *,
        last: int | None = None,
        since: str | None = None,
        revision_range: str | None = None,
        revision: str | None = None,
    ) -> list[str]:
        """Enumerate newest-first commits from a branch, date, or explicit range."""
        if last is not None and (last <= 0 or last > HARD_MAX_COMMITS):
            raise ValueError(f"last must be between 1 and {HARD_MAX_COMMITS}")
        if since is not None:
            if (
                not since
                or len(since) > 128
                or _contains_control(since)
                or since.startswith("-")
            ):
                raise ValueError("invalid --since value")
        if revision_range is not None and revision is not None:
            raise ValueError("revision and revision_range are mutually exclusive")

        if revision_range is not None:
            target = validate_revision(revision_range, allow_range=True)
            if ".." not in target:
                raise InvalidRevisionError("an explicit range must contain '..'")
        else:
            target = self.resolve_revision(revision or self.default_branch())

        arguments = ["rev-list", "--topo-order", "--date-order"]
        if last is not None:
            arguments.append(f"--max-count={last}")
        if since is not None:
            arguments.append(f"--since={since}")
        arguments.extend([target, "--"])
        commit_width = 65
        requested = last if last is not None else HARD_MAX_COMMITS
        list_limit = requested * commit_width + 1
        output = self._git(
            arguments,
            max_output=min(self.max_output_bytes, list_limit),
        )
        shas = output.decode("ascii", errors="strict").splitlines()
        if any(not _FULL_SHA_RE.fullmatch(sha) for sha in shas):
            raise GitRepositoryError("Git returned an invalid commit list")
        return [sha.lower() for sha in shas]

    def enumerate_commits(
        self,
        *,
        last: int | None = None,
        since: str | None = None,
        revision_range: str | None = None,
        revision: str | None = None,
    ) -> list[GitCommit]:
        return [
            self.get_commit(sha)
            for sha in self.enumerate_shas(
                last=last,
                since=since,
                revision_range=revision_range,
                revision=revision,
            )
        ]

    def _metadata(self, sha: str) -> GitCommit:
        output = self._git(
            [
                "show",
                "--no-patch",
                "--no-show-signature",
                "--format=%H%x00%P%x00%an%x00%ae%x00%aI%x00%cn%x00%ce%x00%cI%x00%B",
                sha,
                "--",
            ],
            max_output=min(self.max_output_bytes, 2 * 1024 * 1024),
        )
        fields = output.decode("utf-8", errors="replace").split("\x00", 8)
        if len(fields) != 9 or not _FULL_SHA_RE.fullmatch(fields[0]):
            raise GitRepositoryError("malformed commit metadata")
        parents = tuple(parent.lower() for parent in fields[1].split() if parent)
        if any(not _FULL_SHA_RE.fullmatch(parent) for parent in parents):
            raise GitRepositoryError("malformed commit parents")
        return GitCommit(
            sha=fields[0].lower(),
            parents=parents,
            author_name=fields[2],
            author_email=fields[3],
            author_time=fields[4],
            committer_name=fields[5],
            committer_email=fields[6],
            committer_time=fields[7],
            message=fields[8].rstrip("\n"),
        )

    def get_commit_metadata(self, revision: str) -> GitCommit:
        return self._metadata(self.resolve_revision(revision))

    def _diff_arguments(self, commit: GitCommit, *, names_only: bool) -> list[str]:
        common = ["--find-renames", "--no-ext-diff", "--no-textconv"]
        if names_only:
            common.extend(["--name-status", "-z"])
        else:
            common.extend(["--patch", "--binary", "--full-index"])
        if commit.parent_sha is None:
            return [
                "diff-tree",
                "--root",
                "--no-commit-id",
                "-r",
                *common,
                commit.sha,
                "--",
            ]
        return ["diff", *common, commit.parent_sha, commit.sha, "--"]

    def diff_for_commit(self, revision: str) -> bytes:
        commit = self.get_commit_metadata(revision)
        return self._git(
            self._diff_arguments(commit, names_only=False),
            max_output=self.max_patch_bytes,
        )

    def changed_paths(self, revision: str) -> tuple[ChangedPath, ...]:
        commit = self.get_commit_metadata(revision)
        output = self._git(
            self._diff_arguments(commit, names_only=True),
            max_output=min(self.max_output_bytes, 4 * 1024 * 1024),
        )
        fields = output.decode("utf-8", errors="replace").split("\x00")
        if fields and fields[-1] == "":
            fields.pop()
        paths: list[ChangedPath] = []
        index = 0
        while index < len(fields):
            status = fields[index]
            index += 1
            if not status or index >= len(fields):
                raise GitRepositoryError("malformed changed-path output")
            if status[0] in {"R", "C"}:
                if index + 1 >= len(fields):
                    raise GitRepositoryError("malformed rename/copy output")
                old_path, path = fields[index], fields[index + 1]
                index += 2
                paths.append(ChangedPath(status=status, path=path, old_path=old_path))
            else:
                path = fields[index]
                index += 1
                paths.append(ChangedPath(status=status, path=path))
        return tuple(paths)

    def compute_patch_id(self, patch: bytes) -> str | None:
        if not patch:
            return None
        output = (
            self._git(
                ["patch-id", "--stable"],
                input_data=patch,
                max_output=4096,
            )
            .decode("ascii", errors="replace")
            .strip()
        )
        if not output:
            return None
        patch_id = output.split(maxsplit=1)[0].lower()
        return patch_id if _FULL_SHA_RE.fullmatch(patch_id) else None

    def get_commit(self, revision: str) -> GitCommit:
        metadata = self.get_commit_metadata(revision)
        patch = self._git(
            self._diff_arguments(metadata, names_only=False),
            max_output=self.max_patch_bytes,
        )
        paths = self.changed_paths(metadata.sha)
        return GitCommit(
            sha=metadata.sha,
            parents=metadata.parents,
            message=metadata.message,
            author_name=metadata.author_name,
            author_email=metadata.author_email,
            author_time=metadata.author_time,
            committer_name=metadata.committer_name,
            committer_email=metadata.committer_email,
            committer_time=metadata.committer_time,
            changed_paths=paths,
            patch=patch,
            patch_id=self.compute_patch_id(patch),
        )

    def read_blob(
        self,
        revision: str,
        path: str,
        *,
        max_bytes: int = 1_000_000,
    ) -> bytes:
        if max_bytes <= 0 or max_bytes > HARD_MAX_BLOB:
            raise ValueError(f"max_bytes must be between 1 and {HARD_MAX_BLOB}")
        sha = self.resolve_revision(revision)
        path = validate_path(path)
        object_name = f"{sha}:{path}"
        object_type = self._git(["cat-file", "-t", object_name], max_output=64).strip()
        if object_type != b"blob":
            raise GitRepositoryError("requested path is not a blob")
        size_raw = self._git(["cat-file", "-s", object_name], max_output=64).strip()
        try:
            size = int(size_raw)
        except ValueError as exc:
            raise GitRepositoryError("Git returned an invalid blob size") from exc
        if size > max_bytes:
            raise GitOutputLimitError(f"blob is {size} bytes; limit is {max_bytes}")
        return self._git(["cat-file", "blob", object_name], max_output=max_bytes)

    def read_range(
        self,
        revision: str,
        path: str,
        start_line: int,
        end_line: int,
        *,
        max_bytes: int = 1_000_000,
        max_lines: int = 500,
    ) -> str:
        if start_line < 1 or end_line < start_line:
            raise ValueError("line range must be positive and ordered")
        if end_line - start_line + 1 > max_lines or max_lines <= 0:
            raise ValueError("line range exceeds max_lines")
        text = self.read_blob(revision, path, max_bytes=max_bytes).decode(
            "utf-8", errors="replace"
        )
        lines = text.splitlines(keepends=True)
        return "".join(lines[start_line - 1 : end_line])

    def list_paths(
        self,
        revision: str,
        *,
        prefix: str | None = None,
        max_paths: int = 10_000,
    ) -> list[str]:
        if max_paths <= 0 or max_paths > 100_000:
            raise ValueError("invalid max_paths")
        sha = self.resolve_revision(revision)
        arguments = ["ls-tree", "-r", "-z", "--name-only", sha, "--"]
        if prefix is not None:
            arguments.append(f":(literal){validate_path(prefix)}")
        output = self._git(arguments, max_output=self.max_output_bytes)
        paths = output.decode("utf-8", errors="replace").rstrip("\x00").split("\x00")
        if paths == [""]:
            return []
        if len(paths) > max_paths:
            raise GitOutputLimitError(f"path count exceeds {max_paths}")
        return paths

    def search_text(
        self,
        revision: str,
        query: str,
        *,
        path: str | None = None,
        max_results: int = 100,
    ) -> list[SearchMatch]:
        if (
            not query
            or len(query.encode("utf-8")) > 1024
            or "\x00" in query
            or _contains_control(query)
        ):
            raise ValueError("query is empty, too long, or contains control characters")
        if max_results <= 0 or max_results > 1_000:
            raise ValueError("invalid max_results")
        sha = self.resolve_revision(revision)
        arguments = ["grep", "-n", "-I", "-F", "-e", query, sha, "--"]
        if path is not None:
            arguments.append(f":(literal){validate_path(path)}")
        output = self._git(
            arguments,
            max_output=min(self.max_output_bytes, 2 * 1024 * 1024),
            allowed_returncodes=(0, 1),
        ).decode("utf-8", errors="replace")
        matches: list[SearchMatch] = []
        prefix = f"{sha}:"
        for raw_line in output.splitlines():
            if not raw_line.startswith(prefix):
                continue
            remainder = raw_line[len(prefix) :]
            file_path, separator, rest = remainder.partition(":")
            if not separator:
                continue
            line_text, separator, text = rest.partition(":")
            if not separator or not line_text.isdigit():
                continue
            matches.append(
                SearchMatch(
                    path=file_path,
                    line=int(line_text),
                    text=text,
                    revision=sha,
                )
            )
            if len(matches) >= max_results:
                break
        return matches

    def path_history(
        self,
        revision: str,
        path: str,
        *,
        max_commits: int = 20,
    ) -> list[GitCommit]:
        if max_commits <= 0 or max_commits > 100:
            raise ValueError("invalid max_commits")
        sha = self.resolve_revision(revision)
        path = validate_path(path)
        output = self._git(
            [
                "log",
                "--follow",
                f"--max-count={max_commits}",
                "--format=%H",
                sha,
                "--",
                f":(literal){path}",
            ],
            max_output=64 * 1024,
        ).decode("ascii", errors="strict")
        shas = [item for item in output.splitlines() if item]
        if any(not _FULL_SHA_RE.fullmatch(item) for item in shas):
            raise GitRepositoryError("Git returned invalid path history")
        return [self._metadata(item) for item in shas]

    def blame(
        self,
        revision: str,
        path: str,
        *,
        start_line: int = 1,
        end_line: int | None = None,
        max_lines: int = 200,
    ) -> list[BlameLine]:
        if start_line < 1 or max_lines <= 0 or max_lines > 1_000:
            raise ValueError("invalid blame bounds")
        if end_line is None:
            end_line = start_line + max_lines - 1
        if end_line < start_line or end_line - start_line + 1 > max_lines:
            raise ValueError("blame range exceeds max_lines")
        sha = self.resolve_revision(revision)
        path = validate_path(path)
        output = self._git(
            [
                "blame",
                "--line-porcelain",
                "-L",
                f"{start_line},{end_line}",
                sha,
                "--",
                path,
            ],
            max_output=min(self.max_output_bytes, 2 * 1024 * 1024),
        ).decode("utf-8", errors="replace")

        lines: list[BlameLine] = []
        current_sha = ""
        original_line = 0
        final_line = 0
        author = ""
        author_email = ""
        for row in output.splitlines():
            header = row.split()
            if (
                len(header) >= 3
                and _FULL_SHA_RE.fullmatch(header[0].lstrip("^"))
                and header[1].isdigit()
                and header[2].isdigit()
            ):
                current_sha = header[0].lstrip("^").lower()
                original_line = int(header[1])
                final_line = int(header[2])
                author = ""
                author_email = ""
            elif row.startswith("author "):
                author = row.removeprefix("author ")
            elif row.startswith("author-mail "):
                author_email = row.removeprefix("author-mail ").strip("<>")
            elif row.startswith("\t") and current_sha:
                lines.append(
                    BlameLine(
                        revision=current_sha,
                        original_line=original_line,
                        final_line=final_line,
                        author=author,
                        author_email=author_email,
                        text=row[1:],
                    )
                )
                if len(lines) >= max_lines:
                    break
        return lines


# Small compatibility aliases for callers that prefer shorter names.
GitRepo = GitRepository
CommitInfo = GitCommit
