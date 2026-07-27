"""Single-process SQLite persistence and content-addressed blob storage."""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import os
import sqlite3
import tempfile
import threading
import uuid
from collections.abc import Iterator, Mapping
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 2


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _json_default(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (set, frozenset, tuple)):
        return list(value)
    if hasattr(value, "to_dict"):
        return value.to_dict()
    raise TypeError(f"{type(value).__name__} is not JSON serializable")


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        default=_json_default,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def config_hash(config: Mapping[str, Any] | Any) -> str:
    payload = canonical_json(config).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _decode_json(value: str | None, default: Any = None) -> Any:
    if value is None:
        return default
    return json.loads(value)


_MIGRATION_1 = (
    """
    CREATE TABLE repositories (
        id INTEGER PRIMARY KEY,
        source TEXT NOT NULL,
        canonical_source TEXT NOT NULL UNIQUE,
        repository_hash TEXT NOT NULL UNIQUE,
        mirror_path TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE snapshots (
        id INTEGER PRIMARY KEY,
        repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
        head_sha TEXT NOT NULL,
        default_branch TEXT NOT NULL,
        fetched_at TEXT NOT NULL,
        UNIQUE(repository_id, head_sha, default_branch)
    )
    """,
    """
    CREATE TABLE commits (
        id INTEGER PRIMARY KEY,
        repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
        sha TEXT NOT NULL,
        first_parent_sha TEXT,
        parents_json TEXT NOT NULL,
        message TEXT NOT NULL,
        author_name TEXT NOT NULL,
        author_email TEXT NOT NULL,
        author_time TEXT NOT NULL,
        committer_name TEXT NOT NULL,
        committer_email TEXT NOT NULL,
        committer_time TEXT NOT NULL,
        changed_paths_json TEXT NOT NULL,
        patch_blob_hash TEXT,
        patch_id TEXT,
        metadata_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(repository_id, sha)
    )
    """,
    """
    CREATE TABLE pipeline_runs (
        id TEXT PRIMARY KEY,
        repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
        snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
        config_hash TEXT NOT NULL,
        request_hash TEXT NOT NULL,
        config_json TEXT NOT NULL,
        request_json TEXT NOT NULL,
        limits_json TEXT NOT NULL,
        counters_json TEXT NOT NULL,
        status TEXT NOT NULL,
        dry_run INTEGER NOT NULL CHECK(dry_run IN (0, 1)),
        error_json TEXT,
        started_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        completed_at TEXT,
        UNIQUE(repository_id, snapshot_id, config_hash, request_hash, dry_run)
    )
    """,
    """
    CREATE TABLE run_commits (
        run_id TEXT NOT NULL REFERENCES pipeline_runs(id) ON DELETE CASCADE,
        commit_id INTEGER NOT NULL REFERENCES commits(id) ON DELETE CASCADE,
        -- Presentation ordering within a run, NOT an identity. It is
        -- deliberately not unique: a re-run with a sliding --since window
        -- renumbers every surviving commit, and a uniqueness constraint
        -- turned that into an IntegrityError that left the run
        -- permanently unresumable.
        position INTEGER NOT NULL,
        status TEXT NOT NULL,
        triage_status TEXT,
        adjudication_status TEXT,
        error_json TEXT,
        updated_at TEXT NOT NULL,
        PRIMARY KEY(run_id, commit_id)
    )
    """,
    """
    CREATE TABLE triage_results (
        id INTEGER PRIMARY KEY,
        repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
        commit_id INTEGER NOT NULL REFERENCES commits(id) ON DELETE CASCADE,
        run_id TEXT NOT NULL REFERENCES pipeline_runs(id) ON DELETE CASCADE,
        config_hash TEXT NOT NULL,
        verdict TEXT NOT NULL,
        result_json TEXT NOT NULL,
        usage_json TEXT NOT NULL,
        input_blob_hash TEXT,
        error_json TEXT,
        created_at TEXT NOT NULL,
        UNIQUE(repository_id, commit_id, config_hash)
    )
    """,
    """
    CREATE TABLE adjudication_results (
        id INTEGER PRIMARY KEY,
        repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
        commit_id INTEGER NOT NULL REFERENCES commits(id) ON DELETE CASCADE,
        run_id TEXT NOT NULL REFERENCES pipeline_runs(id) ON DELETE CASCADE,
        config_hash TEXT NOT NULL,
        verdict TEXT NOT NULL,
        result_json TEXT NOT NULL,
        usage_json TEXT NOT NULL,
        input_blob_hash TEXT,
        error_json TEXT,
        created_at TEXT NOT NULL,
        UNIQUE(repository_id, commit_id, config_hash)
    )
    """,
    """
    CREATE TABLE findings (
        id INTEGER PRIMARY KEY,
        repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
        commit_id INTEGER NOT NULL REFERENCES commits(id) ON DELETE CASCADE,
        adjudication_result_id INTEGER NOT NULL
            REFERENCES adjudication_results(id) ON DELETE CASCADE,
        config_hash TEXT NOT NULL,
        finding_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(repository_id, commit_id, config_hash)
    )
    """,
    """
    CREATE TABLE usage_records (
        id INTEGER PRIMARY KEY,
        stage TEXT NOT NULL,
        repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
        commit_id INTEGER REFERENCES commits(id) ON DELETE CASCADE,
        run_id TEXT NOT NULL REFERENCES pipeline_runs(id) ON DELETE CASCADE,
        config_hash TEXT NOT NULL,
        calls INTEGER NOT NULL,
        input_tokens INTEGER,
        output_tokens INTEGER,
        total_tokens INTEGER,
        estimated_cost REAL,
        details_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(stage, repository_id, commit_id, config_hash)
    )
    """,
    """
    CREATE TABLE errors (
        id INTEGER PRIMARY KEY,
        stage TEXT NOT NULL,
        repository_id INTEGER REFERENCES repositories(id) ON DELETE CASCADE,
        commit_id INTEGER REFERENCES commits(id) ON DELETE CASCADE,
        run_id TEXT REFERENCES pipeline_runs(id) ON DELETE CASCADE,
        config_hash TEXT,
        kind TEXT NOT NULL,
        message TEXT NOT NULL,
        details_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(stage, repository_id, commit_id, config_hash, kind, message)
    )
    """,
    "CREATE INDEX idx_commits_repository_sha ON commits(repository_id, sha)",
    "CREATE INDEX idx_run_commits_run_position ON run_commits(run_id, position)",
    "CREATE INDEX idx_triage_run ON triage_results(run_id)",
    "CREATE INDEX idx_adjudication_run ON adjudication_results(run_id)",
    "CREATE INDEX idx_findings_commit ON findings(repository_id, commit_id)",
)

#: v1 shipped ``UNIQUE(run_id, position)`` on ``run_commits``. Position is
#: presentation ordering, and a re-run whose revision selection shifted
#: renumbered every surviving commit into a constraint violation. v2 rebuilds
#: the table without it; ``PRIMARY KEY(run_id, commit_id)`` remains the identity.
_MIGRATION_2: tuple[str, ...] = (
    """
    CREATE TABLE run_commits_v2 (
        run_id TEXT NOT NULL REFERENCES pipeline_runs(id) ON DELETE CASCADE,
        commit_id INTEGER NOT NULL REFERENCES commits(id) ON DELETE CASCADE,
        position INTEGER NOT NULL,
        status TEXT NOT NULL,
        triage_status TEXT,
        adjudication_status TEXT,
        error_json TEXT,
        updated_at TEXT NOT NULL,
        PRIMARY KEY(run_id, commit_id)
    )
    """,
    """
    INSERT INTO run_commits_v2(
        run_id, commit_id, position, status, triage_status,
        adjudication_status, error_json, updated_at
    )
    SELECT run_id, commit_id, position, status, triage_status,
           adjudication_status, error_json, updated_at
    FROM run_commits
    """,
    "DROP TABLE run_commits",
    "ALTER TABLE run_commits_v2 RENAME TO run_commits",
    "CREATE INDEX idx_run_commits_run_position ON run_commits(run_id, position)",
)


class Store:
    """SQLite store intended for one local process and one node."""

    def __init__(
        self,
        database: str | os.PathLike[str],
        *,
        blob_root: str | os.PathLike[str] | None = None,
    ) -> None:
        self.path = Path(database).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.blob_root = (
            Path(blob_root).expanduser().resolve()
            if blob_root is not None
            else self.path.parent / "blobs"
        )
        self.blob_root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._savepoint_counter = 0
        self.connection = sqlite3.connect(
            self.path,
            timeout=30.0,
            isolation_level=None,
            check_same_thread=False,
        )
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA busy_timeout = 30000")
        self.connection.execute("PRAGMA synchronous = NORMAL")
        journal_mode = self.connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
        if str(journal_mode).lower() != "wal":
            self.close()
            raise RuntimeError("SQLite WAL mode is unavailable")
        self._migrate()

    def close(self) -> None:
        with self._lock:
            self.connection.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    @contextlib.contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Create a write transaction, nesting through SQLite savepoints."""
        with self._lock:
            nested = self.connection.in_transaction
            savepoint = ""
            if nested:
                self._savepoint_counter += 1
                savepoint = f"strata_{self._savepoint_counter}"
                self.connection.execute(f"SAVEPOINT {savepoint}")
            else:
                self.connection.execute("BEGIN IMMEDIATE")
            try:
                yield self.connection
            except BaseException:
                if nested:
                    self.connection.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                    self.connection.execute(f"RELEASE SAVEPOINT {savepoint}")
                else:
                    self.connection.rollback()
                raise
            else:
                if nested:
                    self.connection.execute(f"RELEASE SAVEPOINT {savepoint}")
                else:
                    self.connection.commit()

    def _migrate(self) -> None:
        with self.transaction() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                )
                """
            )
            row = connection.execute("SELECT MAX(version) FROM schema_version").fetchone()
            current = int(row[0] or 0)
            if current > SCHEMA_VERSION:
                raise RuntimeError(
                    f"database schema {current} is newer than supported {SCHEMA_VERSION}"
                )
            if current < 1:
                for statement in _MIGRATION_1:
                    connection.execute(statement)
                connection.execute(
                    "INSERT INTO schema_version(version, applied_at) VALUES (?, ?)",
                    (1, _now()),
                )
            if current < 2:
                for statement in _MIGRATION_2:
                    connection.execute(statement)
                connection.execute(
                    "INSERT INTO schema_version(version, applied_at) VALUES (?, ?)",
                    (2, _now()),
                )
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    @property
    def schema_version(self) -> int:
        with self._lock:
            row = self.connection.execute("SELECT MAX(version) FROM schema_version").fetchone()
            return int(row[0] or 0)

    def put_blob(self, data: bytes | str) -> str:
        if isinstance(data, str):
            data = data.encode("utf-8")
        if not isinstance(data, bytes):
            raise TypeError("blob data must be bytes or text")
        digest = hashlib.sha256(data).hexdigest()
        blob_hash = f"sha256:{digest}"
        directory = self.blob_root / "sha256" / digest[:2]
        destination = directory / digest[2:]
        with self._lock:
            if destination.is_file():
                return blob_hash
            directory.mkdir(parents=True, exist_ok=True)
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{digest[:12]}-", dir=directory
            )
            try:
                with os.fdopen(descriptor, "wb") as temporary:
                    temporary.write(data)
                    temporary.flush()
                    os.fsync(temporary.fileno())
                with contextlib.suppress(FileExistsError):
                    os.replace(temporary_name, destination)
            finally:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(temporary_name)
        return blob_hash

    def _blob_path(self, blob_hash: str) -> Path:
        if not isinstance(blob_hash, str) or not blob_hash.startswith("sha256:"):
            raise ValueError("invalid blob hash")
        digest = blob_hash.removeprefix("sha256:")
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError("invalid blob hash")
        return self.blob_root / "sha256" / digest[:2] / digest[2:]

    def get_blob(self, blob_hash: str, *, max_bytes: int | None = None) -> bytes:
        path = self._blob_path(blob_hash)
        if max_bytes is not None:
            if max_bytes <= 0:
                raise ValueError("max_bytes must be positive")
            size = path.stat().st_size
            if size > max_bytes:
                raise ValueError(f"blob is {size} bytes; limit is {max_bytes}")
        return path.read_bytes()

    def register_repository(
        self,
        *,
        source: str,
        canonical_source: str,
        repository_hash: str,
        mirror_path: str | os.PathLike[str],
    ) -> int:
        timestamp = _now()
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO repositories(
                    source, canonical_source, repository_hash, mirror_path,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(canonical_source) DO UPDATE SET
                    source = excluded.source,
                    repository_hash = excluded.repository_hash,
                    mirror_path = excluded.mirror_path,
                    updated_at = excluded.updated_at
                """,
                (
                    source,
                    canonical_source,
                    repository_hash,
                    str(mirror_path),
                    timestamp,
                    timestamp,
                ),
            )
            row = connection.execute(
                "SELECT id FROM repositories WHERE canonical_source = ?",
                (canonical_source,),
            ).fetchone()
            assert row is not None
            return int(row["id"])

    upsert_repository = register_repository

    def create_snapshot(
        self,
        repository_id: int,
        *,
        head_sha: str,
        default_branch: str,
    ) -> int:
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO snapshots(repository_id, head_sha, default_branch, fetched_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(repository_id, head_sha, default_branch) DO NOTHING
                """,
                (repository_id, head_sha.lower(), default_branch, _now()),
            )
            row = connection.execute(
                """
                SELECT id FROM snapshots
                WHERE repository_id = ? AND head_sha = ? AND default_branch = ?
                """,
                (repository_id, head_sha.lower(), default_branch),
            ).fetchone()
            assert row is not None
            return int(row["id"])

    upsert_snapshot = create_snapshot

    def create_or_resume_run(
        self,
        repository_id: int,
        snapshot_id: int,
        *,
        config_hash: str,
        config: Mapping[str, Any],
        request_hash: str | None = None,
        request: Mapping[str, Any] | None = None,
        limits: Mapping[str, Any] | None = None,
        dry_run: bool = False,
    ) -> tuple[str, bool]:
        request_value = dict(request or {})
        request_hash = request_hash or globals()["config_hash"](request_value)
        timestamp = _now()
        run_id = uuid.uuid4().hex
        with self.transaction() as connection:
            cursor = connection.execute(
                """
                INSERT INTO pipeline_runs(
                    id, repository_id, snapshot_id, config_hash, request_hash,
                    config_json, request_json, limits_json, counters_json,
                    status, dry_run, started_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(
                    repository_id, snapshot_id, config_hash, request_hash, dry_run
                ) DO NOTHING
                """,
                (
                    run_id,
                    repository_id,
                    snapshot_id,
                    config_hash,
                    request_hash,
                    canonical_json(config),
                    canonical_json(request_value),
                    canonical_json(dict(limits or {})),
                    canonical_json({}),
                    "running",
                    int(dry_run),
                    timestamp,
                    timestamp,
                ),
            )
            created = cursor.rowcount == 1
            if not created:
                row = connection.execute(
                    """
                    SELECT id FROM pipeline_runs
                    WHERE repository_id = ? AND snapshot_id = ?
                      AND config_hash = ? AND request_hash = ? AND dry_run = ?
                    """,
                    (
                        repository_id,
                        snapshot_id,
                        config_hash,
                        request_hash,
                        int(dry_run),
                    ),
                ).fetchone()
                assert row is not None
                run_id = str(row["id"])
            return run_id, created

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self.connection.execute(
                """
                SELECT r.*, p.source AS repository_source,
                       p.canonical_source, p.repository_hash, p.mirror_path,
                       s.head_sha, s.default_branch
                FROM pipeline_runs r
                JOIN repositories p ON p.id = r.repository_id
                JOIN snapshots s ON s.id = r.snapshot_id
                WHERE r.id = ?
                """,
                (run_id,),
            ).fetchone()
        if row is None:
            return None
        result = dict(row)
        for key in (
            "config_json",
            "request_json",
            "limits_json",
            "counters_json",
            "error_json",
        ):
            result[key.removesuffix("_json")] = _decode_json(result.pop(key), None)
        result["dry_run"] = bool(result["dry_run"])
        return result

    def update_run(
        self,
        run_id: str,
        *,
        status: str | None = None,
        counters: Mapping[str, Any] | None = None,
        error: Mapping[str, Any] | None = None,
        completed: bool = False,
    ) -> None:
        assignments = ["updated_at = ?"]
        values: list[Any] = [_now()]
        if status is not None:
            assignments.append("status = ?")
            values.append(status)
        if counters is not None:
            assignments.append("counters_json = ?")
            values.append(canonical_json(counters))
        if error is not None:
            assignments.append("error_json = ?")
            values.append(canonical_json(error))
        if completed:
            if error is None:
                assignments.append("error_json = NULL")
            assignments.append("completed_at = ?")
            values.append(_now())
        values.append(run_id)
        with self.transaction() as connection:
            cursor = connection.execute(
                f"UPDATE pipeline_runs SET {', '.join(assignments)} WHERE id = ?",
                values,
            )
            if cursor.rowcount != 1:
                raise KeyError(f"unknown run: {run_id}")

    def upsert_commit(
        self,
        repository_id: int,
        commit: Mapping[str, Any] | Any,
        *,
        patch_blob_hash: str | None = None,
    ) -> int:
        if not isinstance(commit, Mapping):
            if hasattr(commit, "to_dict"):
                commit = commit.to_dict(include_patch=False)
            elif is_dataclass(commit):
                commit = asdict(commit)
            else:
                raise TypeError("commit must be a mapping or dataclass")
        row = dict(commit)
        sha = str(row["sha"]).lower()
        parents = [str(parent).lower() for parent in row.get("parents", [])]
        changed_paths = row.get("changed_paths", [])
        timestamp = _now()
        values = (
            repository_id,
            sha,
            parents[0] if parents else None,
            canonical_json(parents),
            str(row.get("message") or ""),
            str(row.get("author_name") or ""),
            str(row.get("author_email") or ""),
            str(row.get("author_time") or ""),
            str(row.get("committer_name") or ""),
            str(row.get("committer_email") or ""),
            str(row.get("committer_time") or ""),
            canonical_json(changed_paths),
            patch_blob_hash,
            row.get("patch_id"),
            canonical_json(row),
            timestamp,
        )
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO commits(
                    repository_id, sha, first_parent_sha, parents_json, message,
                    author_name, author_email, author_time, committer_name,
                    committer_email, committer_time, changed_paths_json,
                    patch_blob_hash, patch_id, metadata_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(repository_id, sha) DO UPDATE SET
                    first_parent_sha = excluded.first_parent_sha,
                    parents_json = excluded.parents_json,
                    message = excluded.message,
                    author_name = excluded.author_name,
                    author_email = excluded.author_email,
                    author_time = excluded.author_time,
                    committer_name = excluded.committer_name,
                    committer_email = excluded.committer_email,
                    committer_time = excluded.committer_time,
                    changed_paths_json = excluded.changed_paths_json,
                    patch_blob_hash = COALESCE(
                        commits.patch_blob_hash, excluded.patch_blob_hash),
                    patch_id = COALESCE(commits.patch_id, excluded.patch_id),
                    metadata_json = excluded.metadata_json
                """,
                values,
            )
            result = connection.execute(
                "SELECT id FROM commits WHERE repository_id = ? AND sha = ?",
                (repository_id, sha),
            ).fetchone()
            assert result is not None
            return int(result["id"])

    def checkpoint_commit(
        self,
        run_id: str,
        commit_id: int,
        *,
        position: int,
        status: str,
        triage_status: str | None = None,
        adjudication_status: str | None = None,
        error: Mapping[str, Any] | None = None,
    ) -> None:
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO run_commits(
                    run_id, commit_id, position, status, triage_status,
                    adjudication_status, error_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id, commit_id) DO UPDATE SET
                    position = excluded.position,
                    status = excluded.status,
                    triage_status = COALESCE(
                        excluded.triage_status, run_commits.triage_status
                    ),
                    adjudication_status = COALESCE(
                        excluded.adjudication_status, run_commits.adjudication_status
                    ),
                    error_json = excluded.error_json,
                    updated_at = excluded.updated_at
                """,
                (
                    run_id,
                    commit_id,
                    position,
                    status,
                    triage_status,
                    adjudication_status,
                    canonical_json(error) if error is not None else None,
                    _now(),
                ),
            )

    def get_checkpoint(self, run_id: str, commit_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self.connection.execute(
                "SELECT * FROM run_commits WHERE run_id = ? AND commit_id = ?",
                (run_id, commit_id),
            ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["error"] = _decode_json(result.pop("error_json"), None)
        return result

    def _save_usage(
        self,
        connection: sqlite3.Connection,
        *,
        stage: str,
        repository_id: int,
        commit_id: int,
        run_id: str,
        config_hash: str,
        usage: Mapping[str, Any],
    ) -> None:
        input_tokens = usage.get("input_tokens", usage.get("prompt_tokens"))
        output_tokens = usage.get("output_tokens", usage.get("completion_tokens"))
        total_tokens = usage.get("total_tokens")
        if total_tokens is None and (
            isinstance(input_tokens, int) or isinstance(output_tokens, int)
        ):
            total_tokens = int(input_tokens or 0) + int(output_tokens or 0)
        cost = usage.get(
            "estimated_cost",
            usage.get(
                "estimated_cost_usd",
                usage.get("cost_usd", usage.get("cost")),
            ),
        )
        connection.execute(
            """
            INSERT INTO usage_records(
                stage, repository_id, commit_id, run_id, config_hash, calls,
                input_tokens, output_tokens, total_tokens, estimated_cost,
                details_json, created_at
            ) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(stage, repository_id, commit_id, config_hash) DO NOTHING
            """,
            (
                stage,
                repository_id,
                commit_id,
                run_id,
                config_hash,
                input_tokens if isinstance(input_tokens, int) else None,
                output_tokens if isinstance(output_tokens, int) else None,
                total_tokens if isinstance(total_tokens, int) else None,
                float(cost)
                if isinstance(cost, (int, float)) and math.isfinite(float(cost))
                else None,
                canonical_json(usage),
                _now(),
            ),
        )

    def _save_stage_result(
        self,
        *,
        table: str,
        stage: str,
        repository_id: int,
        commit_id: int,
        run_id: str,
        config_hash: str,
        verdict: str,
        result: Mapping[str, Any],
        usage: Mapping[str, Any] | None,
        input_blob_hash: str | None,
        error: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        if table not in {"triage_results", "adjudication_results"}:
            raise ValueError("invalid stage table")
        usage_value = dict(usage or {})
        with self.transaction() as connection:
            connection.execute(
                f"""
                INSERT INTO {table}(
                    repository_id, commit_id, run_id, config_hash, verdict,
                    result_json, usage_json, input_blob_hash, error_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(repository_id, commit_id, config_hash) DO NOTHING
                """,
                (
                    repository_id,
                    commit_id,
                    run_id,
                    config_hash,
                    verdict,
                    canonical_json(result),
                    canonical_json(usage_value),
                    input_blob_hash,
                    canonical_json(error) if error is not None else None,
                    _now(),
                ),
            )
            self._save_usage(
                connection,
                stage=stage,
                repository_id=repository_id,
                commit_id=commit_id,
                run_id=run_id,
                config_hash=config_hash,
                usage=usage_value,
            )
            row = connection.execute(
                f"""
                SELECT * FROM {table}
                WHERE repository_id = ? AND commit_id = ? AND config_hash = ?
                """,
                (repository_id, commit_id, config_hash),
            ).fetchone()
            assert row is not None
            return self._result_row(row)

    def save_triage_result(
        self,
        *,
        repository_id: int,
        commit_id: int,
        run_id: str,
        config_hash: str,
        verdict: str,
        result: Mapping[str, Any],
        usage: Mapping[str, Any] | None = None,
        input_blob_hash: str | None = None,
        error: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self._save_stage_result(
            table="triage_results",
            stage="triage",
            repository_id=repository_id,
            commit_id=commit_id,
            run_id=run_id,
            config_hash=config_hash,
            verdict=verdict,
            result=result,
            usage=usage,
            input_blob_hash=input_blob_hash,
            error=error,
        )

    def save_adjudication_result(
        self,
        *,
        repository_id: int,
        commit_id: int,
        run_id: str,
        config_hash: str,
        verdict: str,
        result: Mapping[str, Any],
        usage: Mapping[str, Any] | None = None,
        input_blob_hash: str | None = None,
        error: Mapping[str, Any] | None = None,
        finding: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        saved = self._save_stage_result(
            table="adjudication_results",
            stage="adjudication",
            repository_id=repository_id,
            commit_id=commit_id,
            run_id=run_id,
            config_hash=config_hash,
            verdict=verdict,
            result=result,
            usage=usage,
            input_blob_hash=input_blob_hash,
            error=error,
        )
        if verdict.upper() == "YES" and finding is not None:
            with self.transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO findings(
                        repository_id, commit_id, adjudication_result_id,
                        config_hash, finding_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(repository_id, commit_id, config_hash) DO NOTHING
                    """,
                    (
                        repository_id,
                        commit_id,
                        saved["id"],
                        config_hash,
                        canonical_json(finding),
                        _now(),
                    ),
                )
        return saved

    @staticmethod
    def _result_row(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["result"] = _decode_json(result.pop("result_json"), {})
        result["usage"] = _decode_json(result.pop("usage_json"), {})
        result["error"] = _decode_json(result.pop("error_json"), None)
        return result

    def get_triage_result(
        self,
        repository_id: int,
        commit_id: int,
        config_hash: str,
    ) -> dict[str, Any] | None:
        return self._get_stage_result("triage_results", repository_id, commit_id, config_hash)

    def get_adjudication_result(
        self,
        repository_id: int,
        commit_id: int,
        config_hash: str,
    ) -> dict[str, Any] | None:
        return self._get_stage_result(
            "adjudication_results", repository_id, commit_id, config_hash
        )

    def _get_stage_result(
        self,
        table: str,
        repository_id: int,
        commit_id: int,
        config_hash: str,
    ) -> dict[str, Any] | None:
        if table not in {"triage_results", "adjudication_results"}:
            raise ValueError("invalid stage table")
        with self._lock:
            row = self.connection.execute(
                f"""
                SELECT * FROM {table}
                WHERE repository_id = ? AND commit_id = ? AND config_hash = ?
                """,
                (repository_id, commit_id, config_hash),
            ).fetchone()
        return self._result_row(row) if row is not None else None

    def record_error(
        self,
        *,
        stage: str,
        kind: str,
        message: str,
        repository_id: int | None = None,
        commit_id: int | None = None,
        run_id: str | None = None,
        config_hash: str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO errors(
                    stage, repository_id, commit_id, run_id, config_hash,
                    kind, message, details_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(
                    stage, repository_id, commit_id, config_hash, kind, message
                ) DO NOTHING
                """,
                (
                    stage,
                    repository_id,
                    commit_id,
                    run_id,
                    config_hash,
                    kind,
                    message,
                    canonical_json(dict(details or {})),
                    _now(),
                ),
            )

    def status(self, run_id: str | None = None) -> dict[str, Any]:
        if run_id is not None:
            run = self.get_run(run_id)
            if run is None:
                raise KeyError(f"unknown run: {run_id}")
            with self._lock:
                grouped = self.connection.execute(
                    """
                    SELECT status, COUNT(*) AS count
                    FROM run_commits WHERE run_id = ? GROUP BY status
                    """,
                    (run_id,),
                ).fetchall()
                stage_counts = self.connection.execute(
                    """
                    SELECT
                        SUM(CASE WHEN triage_status IS NOT NULL THEN 1 ELSE 0 END)
                            AS triaged,
                        SUM(CASE WHEN adjudication_status IS NOT NULL THEN 1 ELSE 0 END)
                            AS adjudicated
                    FROM run_commits WHERE run_id = ?
                    """,
                    (run_id,),
                ).fetchone()
            run["commit_statuses"] = {
                str(item["status"]): int(item["count"]) for item in grouped
            }
            run["triaged"] = int(stage_counts["triaged"] or 0)
            run["adjudicated"] = int(stage_counts["adjudicated"] or 0)
            return run

        with self._lock:
            counts = {}
            for table in (
                "repositories",
                "snapshots",
                "commits",
                "pipeline_runs",
                "triage_results",
                "adjudication_results",
                "findings",
                "usage_records",
                "errors",
            ):
                counts[table] = int(
                    self.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                )
            rows = self.connection.execute(
                """
                SELECT id, status, started_at, updated_at, completed_at
                FROM pipeline_runs ORDER BY started_at, id
                """
            ).fetchall()
        return {
            "schema_version": self.schema_version,
            "counts": counts,
            "runs": [dict(r) for r in rows],
        }

    def _triage_export_rows(self, run_id: str | None) -> list[dict[str, Any]]:
        where = "WHERE rc.run_id = ?" if run_id is not None else ""
        values: tuple[Any, ...] = (run_id,) if run_id is not None else ()
        with self._lock:
            rows = self.connection.execute(
                f"""
                SELECT rc.run_id, rc.position, p.canonical_source AS repository,
                       c.sha, c.parents_json, c.message, c.changed_paths_json,
                       c.patch_blob_hash, c.patch_id,
                       t.verdict, t.result_json, t.usage_json,
                       t.input_blob_hash, t.error_json, t.created_at
                FROM run_commits rc
                JOIN pipeline_runs r ON r.id = rc.run_id
                JOIN repositories p ON p.id = r.repository_id
                JOIN commits c ON c.id = rc.commit_id
                LEFT JOIN triage_results t
                  ON t.repository_id = r.repository_id
                 AND t.commit_id = c.id
                 AND t.config_hash = r.config_hash
                {where}
                ORDER BY rc.run_id, rc.position, c.sha
                """,
                values,
            ).fetchall()
        result = []
        # Same de-duplication as findings: triage results are keyed on
        # (repository_id, commit_id, config_hash), so walking run_commits
        # repeats a row once per run that touched the commit.
        seen: set[tuple[Any, ...]] = set()
        for source in rows:
            row = dict(source)
            for key, default in (
                ("parents_json", []),
                ("changed_paths_json", []),
                ("result_json", None),
                ("usage_json", None),
                ("error_json", None),
            ):
                row[key.removesuffix("_json")] = _decode_json(row.pop(key), default)
            identity = (row["repository"], row["sha"], row["created_at"])
            if identity in seen:
                continue
            seen.add(identity)
            result.append(row)
        return result

    def _findings_export_rows(self, run_id: str | None) -> list[dict[str, Any]]:
        where = "WHERE rc.run_id = ?" if run_id is not None else ""
        values: tuple[Any, ...] = (run_id,) if run_id is not None else ()
        with self._lock:
            rows = self.connection.execute(
                f"""
                SELECT rc.run_id, rc.position, p.canonical_source AS repository,
                       c.sha, c.parents_json, c.message, c.changed_paths_json,
                       a.verdict, a.result_json, a.usage_json,
                       f.finding_json, f.created_at
                FROM run_commits rc
                JOIN pipeline_runs r ON r.id = rc.run_id
                JOIN repositories p ON p.id = r.repository_id
                JOIN commits c ON c.id = rc.commit_id
                JOIN adjudication_results a
                  ON a.repository_id = r.repository_id
                 AND a.commit_id = c.id
                 AND a.config_hash = r.config_hash
                JOIN findings f ON f.adjudication_result_id = a.id
                {where}
                ORDER BY rc.run_id, rc.position, c.sha
                """,
                values,
            ).fetchall()
        result = []
        # Findings are keyed (repository_id, commit_id, config_hash) while the
        # query walks run_commits, so a commit touched by N runs yields N
        # identical rows. Without --run the documented invocation therefore
        # produced a findings.jsonl with duplicates. The export must be
        # *stable*, so de-duplicate on the finding's own identity and keep the
        # earliest run that produced it.
        seen: set[tuple[Any, ...]] = set()
        for source in rows:
            row = dict(source)
            for key, default in (
                ("parents_json", []),
                ("changed_paths_json", []),
                ("result_json", {}),
                ("usage_json", {}),
                ("finding_json", {}),
            ):
                row[key.removesuffix("_json")] = _decode_json(row.pop(key), default)
            identity = (row["repository"], row["sha"], row["created_at"])
            if identity in seen:
                continue
            seen.add(identity)
            result.append(row)
        return result

    def _manifest_export_rows(self, run_id: str | None) -> list[dict[str, Any]]:
        if run_id is not None:
            return [self.status(run_id)]
        with self._lock:
            ids = [
                str(row["id"])
                for row in self.connection.execute(
                    "SELECT id FROM pipeline_runs ORDER BY started_at, id"
                ).fetchall()
            ]
        return [self.status(item) for item in ids]

    def export(
        self,
        kind: str,
        output_path: str | os.PathLike[str],
        *,
        run_id: str | None = None,
    ) -> int:
        """Atomically export stable triage, findings, or manifest JSONL."""
        normalized = kind.lower().removesuffix(".jsonl")
        if normalized == "triage":
            rows = self._triage_export_rows(run_id)
        elif normalized == "findings":
            rows = self._findings_export_rows(run_id)
        elif normalized in {"manifest", "manifests"}:
            rows = self._manifest_export_rows(run_id)
        else:
            raise ValueError("kind must be triage, findings, or manifests")

        destination = Path(output_path).expanduser().resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}-", dir=destination.parent
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
                for row in rows:
                    output.write(canonical_json(row))
                    output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary_name, destination)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary_name)
        return len(rows)

    def export_triage(
        self, output_path: str | os.PathLike[str], *, run_id: str | None = None
    ) -> int:
        return self.export("triage", output_path, run_id=run_id)

    def export_findings(
        self, output_path: str | os.PathLike[str], *, run_id: str | None = None
    ) -> int:
        return self.export("findings", output_path, run_id=run_id)

    def export_manifests(
        self, output_path: str | os.PathLike[str], *, run_id: str | None = None
    ) -> int:
        return self.export("manifests", output_path, run_id=run_id)


SQLiteStore = Store
StrataStore = Store
