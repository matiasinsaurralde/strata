"""Append-only rich human labels and deterministic review queues."""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "rich-label-v1"
ANNOTATION = "annotation"
ADJUDICATION = "adjudication"
VERDICTS = frozenset({"YES", "NO", "ABSTAIN"})
ROLES = frozenset({"fix", "context", "backport", "introduce", "other"})
L0_CLASSES = frozenset(
    {
        "memory_safety",
        "input_validation",
        "injection",
        "path_traversal",
        "access_control",
        "authentication",
        "cryptography",
        "resource_exhaustion",
        "concurrency_toctou",
        "deserialization",
        "information_disclosure",
        "logic_flaw",
        "supply_chain",
        "other",
    }
)
SEVERITY_LEVELS = frozenset({"low", "medium", "high", "critical", "unknown"})
SEVERITY_SOURCES = frozenset({"cvss", "advisory", "repository", "human", "model_estimate"})
FIX_COMPLETENESS = frozenset({"complete", "partial", "unknown"})
EVIDENCE_CLAIMS = frozenset(
    {
        "root_cause",
        "attacker_preconditions",
        "impact",
        "fix_effect",
        "l0_class",
        "cwe_id",
        "severity",
        "affected_paths",
        "fix_completeness",
        "invariant",
    }
)
_SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_APPEND_LOCK = threading.Lock()

_RICH_FIELDS = (
    "verdict",
    "role",
    "l0_class",
    "cwe_id",
    "severity",
    "root_cause",
    "attacker_preconditions",
    "impact",
    "fix_effect",
    "affected_paths",
    "fix_completeness",
)


class RichLabelError(ValueError):
    """Raised for malformed rich-label data."""


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _as_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if hasattr(value, "to_dict"):
        converted = value.to_dict()
        if isinstance(converted, Mapping):
            return dict(converted)
    if hasattr(value, "__dict__"):
        return {key: item for key, item in vars(value).items() if not key.startswith("_")}
    raise RichLabelError("label must be a mapping or mapping-like object")


def _repository(record: Mapping[str, Any]) -> str:
    for name in ("repository", "repo", "repository_url"):
        value = record.get(name)
        if isinstance(value, str) and value.strip():
            if name == "repo" and record.get("host"):
                return f"{record['host']}/{value}".strip("/")
            return value.strip().rstrip("/")
    raise RichLabelError("record has no repository identity")


def _sha(record: Mapping[str, Any]) -> str:
    for name in ("commit_sha", "sha", "fix_commit", "commit"):
        value = record.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    raise RichLabelError("record has no commit SHA")


def _annotator(record: Mapping[str, Any]) -> str:
    value = record.get("annotator_id", record.get("annotator"))
    if isinstance(value, Mapping):
        value = value.get("id", value.get("name"))
    if not isinstance(value, str) or not value.strip():
        raise RichLabelError("record has no annotator identity")
    return value.strip()


def candidate_key(record: Mapping[str, Any] | Any) -> tuple[str, str]:
    value = _as_mapping(record)
    return (_repository(value), _sha(value))


def rich_label_key(record: Mapping[str, Any] | Any) -> tuple[str, str, str]:
    value = _as_mapping(record)
    return (*candidate_key(value), _annotator(value))


label_key = rich_label_key


def _canonical(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _canonical(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [_canonical(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def record_hash(record: Mapping[str, Any] | Any) -> str:
    body = json.dumps(
        _canonical(_as_mapping(record)),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _canonical_verdict(record: Mapping[str, Any]) -> str | None:
    value = record.get("verdict", record.get("decision", record.get("label")))
    if value is None and "is_security_fix" in record:
        flag = record["is_security_fix"]
        value = "YES" if flag is True else "NO" if flag is False else "ABSTAIN"
    if isinstance(value, str):
        upper = value.upper()
        if upper in VERDICTS:
            return upper
    role = record.get("role")
    if isinstance(role, str):
        normalized = role.lower()
        if normalized in {"fix", "backport"}:
            return "YES"
        if normalized in {"context", "introduce", "other", "nonfix", "non_fix"}:
            return "NO"
        if normalized in {"uncertain", "abstain", "unknown"}:
            return "ABSTAIN"
    return None


_CANONICAL_KEYS = frozenset(
    {
        "schema_version",
        "record_type",
        "status",
        "record_id",
        "repository",
        "commit_sha",
        "parent_sha",
        "label_version",
        "verdict",
        "role",
        "rationale",
        "annotator_id",
        "created_at",
        "independent",
        "abstain_reason",
        "root_cause",
        "attacker_preconditions",
        "impact",
        "fix_effect",
        "l0_class",
        "cwe_id",
        "severity",
        "affected_paths",
        "evidence",
        "fix_completeness",
        "invariant",
        "source_record_hashes",
        "source_annotators",
        "notes",
    }
)


def _optional_text(value: Any, name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise RichLabelError(f"{name} must be null or a non-empty string")
    return " ".join(value.split())


def _relative_path(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise RichLabelError(f"{name} must be a non-empty path")
    if value.startswith("/") or "\\" in value or "\x00" in value:
        raise RichLabelError(f"{name} must be a relative POSIX path")
    if ".." in value.split("/"):
        raise RichLabelError(f"{name} must not traverse parent directories")
    return value


def _normalize_severity(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise RichLabelError("severity must be null or an object")
    level = str(value.get("level", value.get("value")) or "").lower()
    source = str(value.get("source") or "").lower()
    if level not in SEVERITY_LEVELS:
        raise RichLabelError("severity.level is invalid")
    if source not in SEVERITY_SOURCES:
        raise RichLabelError("severity.source is invalid")
    score = value.get("score")
    if score is not None:
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            raise RichLabelError("severity.score must be null or numeric")
        score = float(score)
        if not 0 <= score <= 10:
            raise RichLabelError("severity.score must be between 0 and 10")
    vector = _optional_text(value.get("vector"), "severity.vector")
    if vector is not None and source != "cvss":
        raise RichLabelError("severity.vector requires source=cvss")
    return {"level": level, "source": source, "score": score, "vector": vector}


def _normalize_evidence(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise RichLabelError("evidence must be an array")
    result: list[dict[str, Any]] = []
    for index, raw in enumerate(value):
        if not isinstance(raw, Mapping):
            raise RichLabelError(f"evidence[{index}] must be an object")
        revision = str(raw.get("revision") or "").lower()
        if revision not in {"parent", "commit", "head"}:
            raise RichLabelError(f"evidence[{index}].revision is invalid")
        revision_sha = str(raw.get("revision_sha") or "").lower()
        if not _SHA_RE.fullmatch(revision_sha):
            raise RichLabelError(f"evidence[{index}].revision_sha is invalid")
        path = _relative_path(raw.get("path"), f"evidence[{index}].path")
        try:
            start = int(raw.get("start_line"))
            end = int(raw.get("end_line"))
        except (TypeError, ValueError) as exc:
            raise RichLabelError(f"evidence[{index}] lines must be integers") from exc
        if start < 1 or end < start:
            raise RichLabelError(f"evidence[{index}] line range is invalid")
        quote = _optional_text(
            raw.get("quoted_span", raw.get("quote")),
            f"evidence[{index}].quoted_span",
        )
        if quote is None or len(quote) > 500:
            raise RichLabelError(f"evidence[{index}].quoted_span must contain 1-500 characters")
        supports_raw = raw.get("supports")
        if not isinstance(supports_raw, Sequence) or isinstance(supports_raw, (str, bytes)):
            raise RichLabelError(f"evidence[{index}].supports must be an array")
        supports = tuple(dict.fromkeys(str(item) for item in supports_raw))
        if not supports:
            raise RichLabelError(f"evidence[{index}].supports must not be empty")
        unknown_claims = sorted(set(supports) - EVIDENCE_CLAIMS)
        if unknown_claims:
            raise RichLabelError(
                f"evidence[{index}].supports has unknown claims: " + ", ".join(unknown_claims)
            )
        result.append(
            {
                "revision": revision,
                "revision_sha": revision_sha,
                "path": path,
                "start_line": start,
                "end_line": end,
                "quoted_span": quote,
                "supports": list(supports),
            }
        )
    return result


def validate_rich_label(
    record: Mapping[str, Any] | Any,
    *,
    require_frozen: bool = False,
) -> dict[str, Any]:
    value = _as_mapping(record)
    unknown = sorted(set(value) - _CANONICAL_KEYS)
    missing = sorted(_CANONICAL_KEYS - set(value))
    if unknown or missing:
        details = []
        if unknown:
            details.append("unknown fields: " + ", ".join(unknown))
        if missing:
            details.append("missing fields: " + ", ".join(missing))
        raise RichLabelError("; ".join(details))
    if value.get("schema_version") != SCHEMA_VERSION:
        raise RichLabelError(f"schema_version must equal {SCHEMA_VERSION}")
    record_type = value.get("record_type")
    if record_type not in {ANNOTATION, ADJUDICATION}:
        raise RichLabelError("record_type must be annotation or adjudication")
    status = value.get("status")
    if status not in {"draft", "frozen"}:
        raise RichLabelError("status must be draft or frozen")
    if require_frozen and status != "frozen":
        raise RichLabelError("label must be frozen")
    if not _SHA_RE.fullmatch(str(value.get("commit_sha") or "")):
        raise RichLabelError("commit_sha must be a full lowercase Git SHA")
    parent_sha = value.get("parent_sha")
    if parent_sha is not None and not _SHA_RE.fullmatch(str(parent_sha)):
        raise RichLabelError("parent_sha must be null or a full lowercase Git SHA")
    if not _HASH_RE.fullmatch(str(value.get("record_id") or "")):
        raise RichLabelError("record_id must be a prefixed SHA-256")
    if any(not _HASH_RE.fullmatch(str(item)) for item in value["source_record_hashes"]):
        raise RichLabelError("source_record_hashes contains an invalid hash")
    expected_hash = record_hash(
        {key: item for key, item in value.items() if key != "record_id"}
    )
    if value["record_id"] != expected_hash:
        raise RichLabelError("record_id does not match canonical record content")
    try:
        parsed = datetime.fromisoformat(str(value["created_at"]).replace("Z", "+00:00"))
    except ValueError as exc:
        raise RichLabelError("created_at must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise RichLabelError("created_at must include a timezone")
    if record_type == ANNOTATION:
        if value["independent"] is not True:
            raise RichLabelError("annotations must be independently produced")
        if value["source_record_hashes"] or value["source_annotators"]:
            raise RichLabelError("annotations cannot cite source annotations")
    else:
        if status != "frozen" or value["independent"] is not False:
            raise RichLabelError("adjudications must be frozen and non-independent")
        if len(value["source_record_hashes"]) < 2 or len(value["source_annotators"]) < 2:
            raise RichLabelError("adjudication requires two source annotations")

    if status == "draft":
        return value
    role = value.get("role")
    rationale = value.get("rationale")
    verdict = value.get("verdict")
    if role not in ROLES or not isinstance(rationale, str) or not rationale.strip():
        raise RichLabelError("frozen labels require role and rationale")
    if verdict == "YES":
        if role not in {"fix", "backport"}:
            raise RichLabelError("YES requires fix or backport role")
        required = (
            "root_cause",
            "attacker_preconditions",
            "impact",
            "fix_effect",
            "l0_class",
            "severity",
            "fix_completeness",
        )
        if any(value.get(name) is None for name in required):
            raise RichLabelError("frozen YES label is missing rich finding fields")
        if value["l0_class"] not in L0_CLASSES:
            raise RichLabelError("l0_class is outside the closed vocabulary")
        if value["fix_completeness"] not in FIX_COMPLETENESS:
            raise RichLabelError("fix_completeness is invalid")
        if not value["affected_paths"] or not value["evidence"]:
            raise RichLabelError("frozen YES requires affected paths and evidence")
    elif verdict in {"NO", "ABSTAIN"}:
        positive_fields = (
            "root_cause",
            "attacker_preconditions",
            "impact",
            "fix_effect",
            "l0_class",
            "cwe_id",
            "severity",
            "fix_completeness",
            "invariant",
        )
        if (
            any(value.get(name) is not None for name in positive_fields)
            or value["affected_paths"]
        ):
            raise RichLabelError("NO/ABSTAIN labels cannot contain positive fields")
        if verdict == "NO" and role not in {"context", "introduce", "other"}:
            raise RichLabelError("NO role is inconsistent")
        if verdict == "ABSTAIN" and not value.get("abstain_reason"):
            raise RichLabelError("ABSTAIN requires abstain_reason")
    else:
        raise RichLabelError("verdict must be YES, NO, or ABSTAIN")
    return value


def normalize_rich_label(
    record: Mapping[str, Any] | Any,
    *,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Canonicalize identity/provenance while preserving rich label fields."""

    supplied = _as_mapping(record)
    repository = _repository(supplied)
    sha = _sha(supplied)
    annotator = _annotator(supplied)
    record_type = str(supplied.get("record_type") or ANNOTATION).lower()
    if record_type not in {ANNOTATION, ADJUDICATION}:
        raise RichLabelError("record_type must be annotation or adjudication")
    verdict = _canonical_verdict(supplied)
    if verdict is None:
        raise RichLabelError("record has no valid verdict or role")
    label_version = supplied.get("label_version", 1)
    if isinstance(label_version, bool):
        raise RichLabelError("label_version must be a positive integer")
    try:
        label_version = int(label_version)
    except (TypeError, ValueError) as exc:
        raise RichLabelError("label_version must be a positive integer") from exc
    if label_version < 1:
        raise RichLabelError("label_version must be a positive integer")

    status = str(supplied.get("status") or "draft").lower()
    if status == "resolved":
        status = "frozen"
    if record_type == ADJUDICATION:
        status = "frozen"
    if status not in {"draft", "frozen"}:
        raise RichLabelError("status must be draft or frozen")
    role_value = supplied.get("role")
    role = str(role_value).lower() if role_value is not None else None
    if role is not None and role not in ROLES:
        raise RichLabelError("role is outside the labeling rubric")
    l0_value = supplied.get("l0_class", supplied.get("class"))
    l0_class = str(l0_value).lower() if l0_value is not None else None
    if l0_class is not None and l0_class not in L0_CLASSES:
        raise RichLabelError("l0_class is outside the closed vocabulary")
    cwe_value = supplied.get("cwe_id")
    cwe_id = str(cwe_value).upper() if cwe_value is not None else None
    if cwe_id is not None and not re.fullmatch(r"CWE-[1-9][0-9]{0,5}", cwe_id):
        raise RichLabelError("cwe_id must be null or canonical CWE-N")
    paths_value = supplied.get("affected_paths") or []
    if not isinstance(paths_value, Sequence) or isinstance(paths_value, (str, bytes)):
        raise RichLabelError("affected_paths must be an array")
    paths = list(
        dict.fromkeys(
            _relative_path(
                item.get("path") if isinstance(item, Mapping) else item,
                f"affected_paths[{index}]",
            )
            for index, item in enumerate(paths_value)
        )
    )
    source_hashes = sorted(
        set(str(item) for item in supplied.get("source_record_hashes") or [])
    )
    source_annotators = sorted(
        set(str(item) for item in supplied.get("source_annotators") or [])
    )
    completeness_value = supplied.get("fix_completeness")
    completeness = str(completeness_value).lower() if completeness_value is not None else None
    if completeness is not None and completeness not in FIX_COMPLETENESS:
        raise RichLabelError("fix_completeness is invalid")
    output = {
        "schema_version": SCHEMA_VERSION,
        "record_type": record_type,
        "status": status,
        "repository": repository,
        "commit_sha": sha,
        "parent_sha": (
            str(supplied["parent_sha"]).lower()
            if supplied.get("parent_sha") is not None
            else None
        ),
        "label_version": label_version,
        "verdict": verdict,
        "role": role,
        "rationale": _optional_text(supplied.get("rationale"), "rationale"),
        "annotator_id": annotator,
        "created_at": str(created_at or supplied.get("created_at") or _now()),
        "independent": record_type == ANNOTATION,
        "abstain_reason": _optional_text(supplied.get("abstain_reason"), "abstain_reason"),
        "root_cause": _optional_text(supplied.get("root_cause"), "root_cause"),
        "attacker_preconditions": _optional_text(
            supplied.get("attacker_preconditions"), "attacker_preconditions"
        ),
        "impact": _optional_text(supplied.get("impact"), "impact"),
        "fix_effect": _optional_text(supplied.get("fix_effect"), "fix_effect"),
        "l0_class": l0_class,
        "cwe_id": cwe_id,
        "severity": _normalize_severity(supplied.get("severity")),
        "affected_paths": paths,
        "evidence": _normalize_evidence(
            supplied.get("evidence", supplied.get("evidence_anchors"))
        ),
        "fix_completeness": completeness,
        "invariant": _optional_text(supplied.get("invariant"), "invariant"),
        "source_record_hashes": source_hashes,
        "source_annotators": source_annotators,
        "notes": _optional_text(supplied.get("notes"), "notes"),
    }
    output["record_id"] = record_hash(
        {key: value for key, value in output.items() if key not in {"record_id"}}
    )
    return validate_rich_label(output, require_frozen=status == "frozen")


def append_rich_label(
    path: Path | str,
    record: Mapping[str, Any] | Any | None = None,
    **fields: Any,
) -> dict[str, Any]:
    """Append exactly one canonical JSONL record.

    Existing rows are never rewritten. A flush and ``fsync`` make the return
    value mean that the line has reached the filesystem.
    """

    combined = _as_mapping(record) if record is not None else {}
    combined.update(fields)
    normalized = normalize_rich_label(combined)
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    with _APPEND_LOCK, destination.open("a", encoding="utf-8") as handle:
        try:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        except ImportError, OSError:
            pass
        handle.write(line + "\n")
        handle.flush()
        os.fsync(handle.fileno())
        try:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except ImportError, OSError:
            pass
    return normalized


append_label = append_rich_label


def read_rich_labels(
    path: Path | str,
    *,
    strict: bool = True,
) -> list[dict[str, Any]]:
    source = Path(path)
    if not source.exists():
        return []
    records: list[dict[str, Any]] = []
    with source.open(encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, start=1):
            if not raw.strip():
                continue
            try:
                value = json.loads(raw)
            except json.JSONDecodeError as exc:
                if strict:
                    raise RichLabelError(f"{source}:{line_number}: malformed JSON") from exc
                continue
            if not isinstance(value, Mapping):
                if strict:
                    raise RichLabelError(f"{source}:{line_number}: record is not an object")
                continue
            records.append(dict(value))
    return records


def _records(value: Any, *, strict: bool = True) -> list[dict[str, Any]]:
    if value is None:
        return []
    if isinstance(value, (str, Path)):
        return read_rich_labels(value, strict=strict)
    if isinstance(value, Mapping):
        # A latest-wins mapping can be passed directly.
        if all(isinstance(item, Mapping) for item in value.values()):
            return [dict(item) for item in value.values()]
        return [dict(value)]
    if isinstance(value, Iterable):
        return [_as_mapping(item) for item in value]
    raise RichLabelError("labels must be a path, mapping, or iterable")


def load_latest_labels(
    path_or_records: Path | str | Iterable[Mapping[str, Any]],
    *,
    record_type: str | None = None,
    strict: bool = True,
) -> dict[tuple[str, str, str], dict[str, Any]]:
    """Return the last appended record for each candidate and annotator."""

    latest: dict[tuple[str, str, str], dict[str, Any]] = {}
    for record in _records(path_or_records, strict=strict):
        if record_type and str(record.get("record_type", ANNOTATION)) != record_type:
            continue
        try:
            key = rich_label_key(record)
        except RichLabelError:
            if strict:
                raise
            continue
        latest[key] = record
    return latest


load_latest = load_latest_labels
load_labels = load_latest_labels


def labels_by_candidate(
    path_or_records: Any,
    *,
    annotations_only: bool = False,
    strict: bool = True,
) -> dict[tuple[str, str], list[dict[str, Any]]]:
    latest = load_latest_labels(path_or_records, strict=strict)
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for (repository, sha, _), record in latest.items():
        if annotations_only and record.get("record_type", ANNOTATION) != ANNOTATION:
            continue
        grouped[(repository, sha)].append(record)
    for records in grouped.values():
        records.sort(key=_annotator)
    return dict(grouped)


def independent_annotations(
    path_or_records: Any,
    repository: str | None = None,
    commit_sha: str | None = None,
) -> list[dict[str, Any]]:
    grouped = labels_by_candidate(path_or_records, annotations_only=True)
    if repository is None and commit_sha is None:
        return [record for records in grouped.values() for record in records]
    if repository is None or commit_sha is None:
        raise RichLabelError("repository and commit_sha must be supplied together")
    return list(grouped.get((repository.rstrip("/"), commit_sha.lower()), ()))


def _comparison_value(record: Mapping[str, Any], field: str) -> Any:
    if field == "verdict":
        return _canonical_verdict(record)
    if field == "l0_class":
        return record.get("l0_class", record.get("class"))
    value = record.get(field)
    if field == "severity" and isinstance(value, Mapping):
        return (value.get("level", value.get("value")), value.get("source"))
    if (
        field == "affected_paths"
        and isinstance(value, Sequence)
        and not isinstance(value, (str, bytes))
    ):
        paths = [item.get("path") if isinstance(item, Mapping) else item for item in value]
        return tuple(sorted(str(item) for item in paths if item))
    return _canonical(value)


def disagreement(
    records: Sequence[Mapping[str, Any]] | Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Compare the latest independent labels for one candidate."""

    supplied = [dict(record) for record in records]
    latest: dict[str, dict[str, Any]] = {}
    for record in supplied:
        if record.get("record_type", ANNOTATION) != ANNOTATION:
            continue
        latest[_annotator(record)] = record
    ordered = [latest[key] for key in sorted(latest)]
    changed: list[str] = []
    values: dict[str, list[Any]] = {}
    for field in _RICH_FIELDS:
        field_values = [_comparison_value(record, field) for record in ordered]
        values[field] = field_values
        serialized = {
            json.dumps(_canonical(value), sort_keys=True, ensure_ascii=False)
            for value in field_values
        }
        if len(serialized) > 1:
            changed.append(field)
    verdicts = [_canonical_verdict(record) for record in ordered]
    return {
        "annotators": sorted(latest),
        "annotation_count": len(ordered),
        "verdicts": verdicts,
        "agrees": len(ordered) >= 2 and not changed,
        "has_disagreement": len(ordered) >= 2 and bool(changed),
        "needs_more_annotations": len(ordered) < 2,
        "needs_adjudication": len(ordered) >= 2 and bool(changed),
        "disagreed_fields": changed,
        "values": values,
    }


compute_disagreement = disagreement


def disagreement_report(path_or_records: Any) -> list[dict[str, Any]]:
    grouped = labels_by_candidate(path_or_records, annotations_only=True)
    all_records = _records(path_or_records)
    latest_annotation: dict[tuple[str, str], int] = {}
    latest_adjudication: dict[tuple[str, str], int] = {}
    for index, record in enumerate(all_records):
        try:
            key = candidate_key(record)
        except RichLabelError:
            continue
        if record.get("record_type", ANNOTATION) == ANNOTATION:
            latest_annotation[key] = index
        if record.get("record_type") == ADJUDICATION and record.get("status") in {
            "frozen",
            "resolved",
        }:
            latest_adjudication[key] = index
    adjudicated = {
        key
        for key, index in latest_adjudication.items()
        if index > latest_annotation.get(key, -1)
    }
    report: list[dict[str, Any]] = []
    for key in sorted(grouped):
        details = disagreement(grouped[key])
        details.update(
            {
                "repository": key[0],
                "commit_sha": key[1],
                "adjudicated": key in adjudicated,
                "unresolved": details["needs_adjudication"] and key not in adjudicated,
            }
        )
        report.append(details)
    return report


def disagreements(
    path_or_records: Any, *, unresolved_only: bool = True
) -> list[dict[str, Any]]:
    report = disagreement_report(path_or_records)
    if unresolved_only:
        return [row for row in report if row["unresolved"]]
    return [row for row in report if row["has_disagreement"]]


find_disagreements = disagreements


def make_adjudication_record(
    repository: str,
    commit_sha: str,
    adjudicator_id: str,
    decision: Mapping[str, Any],
    source_records: Sequence[Mapping[str, Any]],
    *,
    notes: str | None = None,
    label_version: int = 1,
) -> dict[str, Any]:
    """Build a provenance-bearing resolution without mutating source labels."""

    if len({_annotator(record) for record in source_records}) < 2:
        raise RichLabelError("adjudication requires two independent annotators")
    record = {
        **dict(decision),
        "repository": repository,
        "commit_sha": commit_sha,
        "annotator_id": adjudicator_id,
        "record_type": ADJUDICATION,
        "label_version": label_version,
        "status": "frozen",
        "source_record_hashes": sorted(
            str(item.get("record_id"))
            if _HASH_RE.fullmatch(str(item.get("record_id") or ""))
            else record_hash({key: value for key, value in item.items() if key != "record_id"})
            for item in source_records
        ),
        "source_annotators": sorted({_annotator(item) for item in source_records}),
        "notes": notes,
    }
    return normalize_rich_label(record)


def append_adjudication(
    path: Path | str,
    repository: str,
    commit_sha: str,
    adjudicator_id: str,
    decision: Mapping[str, Any],
    source_records: Sequence[Mapping[str, Any]],
    **kwargs: Any,
) -> dict[str, Any]:
    record = make_adjudication_record(
        repository,
        commit_sha,
        adjudicator_id,
        decision,
        source_records,
        **kwargs,
    )
    return append_rich_label(path, record)


resolve_disagreement = append_adjudication


def _triage_candidate(row: Mapping[str, Any], *, include_errors: bool) -> bool:
    if include_errors and row.get("error"):
        return True
    if row.get("candidate") is True or row.get("flagged") is True:
        return True
    value = row.get("verdict", row.get("decision", row.get("triage_verdict")))
    if isinstance(value, str):
        return value.upper() in {"YES", "ABSTAIN", "CANDIDATE", "ERROR"}
    # Rows without triage markers are already assumed to be candidate inputs.
    marker_fields = {
        "candidate",
        "flagged",
        "verdict",
        "decision",
        "triage_verdict",
        "error",
    }
    return not marker_fields.intersection(row)


def _join_key(record: Mapping[str, Any]) -> tuple[str, str]:
    try:
        return candidate_key(record)
    except RichLabelError:
        repo = str(record.get("repo") or record.get("repository") or "")
        host = str(record.get("host") or "")
        repository = f"{host}/{repo}".strip("/") if host else repo
        sha = str(
            record.get("sha") or record.get("commit_sha") or record.get("fix_commit") or ""
        ).lower()
        if not repository or not sha:
            raise
        return repository, sha


def build_candidate_queue(
    commits: Iterable[Mapping[str, Any]],
    triage_results: Iterable[Mapping[str, Any]] | None = None,
    labels: Any = None,
    *,
    annotators: Sequence[str] = (),
    include_errors: bool = True,
    include_fully_labeled: bool = False,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """Join triage candidates to commits and annotation coverage."""

    commits_list = [dict(item) for item in commits]
    commits_by_key = {_join_key(item): item for item in commits_list}
    triage = (
        [dict(item) for item in triage_results] if triage_results is not None else commits_list
    )
    latest = load_latest_labels(labels, strict=False) if labels is not None else {}
    queue: list[dict[str, Any]] = []
    for decision in triage:
        if not _triage_candidate(decision, include_errors=include_errors):
            continue
        key = _join_key(decision)
        commit = commits_by_key.get(key, decision)
        present = sorted(
            annotator
            for repository, sha, annotator in latest
            if (repository, sha) == key
            and latest[(repository, sha, annotator)].get("record_type", ANNOTATION)
            == ANNOTATION
        )
        missing = [annotator for annotator in annotators if annotator not in present]
        if annotators and not missing and not include_fully_labeled:
            continue
        row = dict(commit)
        row["triage"] = {
            key_name: decision.get(key_name)
            for key_name in (
                "verdict",
                "decision",
                "flagged",
                "candidate",
                "error",
                "score",
            )
            if key_name in decision
        }
        row["queue"] = {
            "reason": "triage_error" if decision.get("error") else "triage_candidate",
            "annotators_present": present,
            "annotators_missing": missing,
        }
        queue.append(row)
    queue.sort(key=lambda row: _join_key(row))
    if limit is not None:
        if limit < 0:
            raise ValueError("limit must be non-negative")
        queue = queue[:limit]
    return queue


def _pilot_stratum(
    row: Mapping[str, Any],
    annotations: Sequence[Mapping[str, Any]],
) -> str:
    roles = {
        str(record.get("role")).lower()
        for record in annotations
        if record.get("role") is not None
    }
    verdicts = {
        verdict for record in annotations if (verdict := _canonical_verdict(record)) is not None
    }
    role = str(row.get("role") or "").lower()
    if role in {"fix", "backport"} or roles.intersection({"fix", "backport"}):
        return "positive"
    if role in {"context", "introduce", "other"} or roles.intersection(
        {"context", "introduce", "other"}
    ):
        return "hard_negative"
    if verdicts == {"YES"}:
        return "positive"
    if verdicts == {"NO"}:
        return "hard_negative"
    return "unknown"


def _stable_order(row: Mapping[str, Any], seed: str) -> str:
    repository, sha = _join_key(row)
    return hashlib.sha256(f"{seed}\0{repository}\0{sha}".encode()).hexdigest()


def build_rich_pilot_queue(
    candidates: Iterable[Mapping[str, Any]],
    labels: Any = None,
    *,
    size: int = 40,
    positive_fraction: float = 0.5,
    seed: str = "rich-pilot-v1",
) -> list[dict[str, Any]]:
    """Construct a deterministic positive/hard-negative pilot sample.

    Existing disagreements are prioritized. Remaining rows are selected by a
    stable hash, so rebuilding the queue cannot reshuffle because of input order.
    """

    if size < 0:
        raise ValueError("size must be non-negative")
    if not 0.0 <= positive_fraction <= 1.0:
        raise ValueError("positive_fraction must be between zero and one")
    grouped = labels_by_candidate(labels, annotations_only=True, strict=False) if labels else {}
    buckets: dict[str, list[dict[str, Any]]] = {
        "positive": [],
        "hard_negative": [],
        "unknown": [],
    }
    for supplied in candidates:
        row = dict(supplied)
        key = _join_key(row)
        annotations = grouped.get(key, [])
        status = disagreement(annotations)
        stratum = _pilot_stratum(row, annotations)
        row["pilot"] = {
            "stratum": stratum,
            "has_disagreement": status["has_disagreement"],
            "annotation_count": status["annotation_count"],
        }
        buckets[stratum].append(row)
    for rows in buckets.values():
        rows.sort(
            key=lambda row: (
                not row["pilot"]["has_disagreement"],
                _stable_order(row, seed),
            )
        )

    positive_target = round(size * positive_fraction)
    negative_target = size - positive_target
    selected = buckets["positive"][:positive_target]
    selected += buckets["hard_negative"][:negative_target]
    selected_keys = {_join_key(row) for row in selected}
    remainder = [
        row
        for stratum in ("positive", "hard_negative", "unknown")
        for row in buckets[stratum]
        if _join_key(row) not in selected_keys
    ]
    remainder.sort(
        key=lambda row: (
            not row["pilot"]["has_disagreement"],
            _stable_order(row, seed),
        )
    )
    selected.extend(remainder[: max(0, size - len(selected))])
    selected.sort(
        key=lambda row: (
            {"positive": 0, "hard_negative": 1, "unknown": 2}[row["pilot"]["stratum"]],
            _stable_order(row, seed),
        )
    )
    return selected[:size]


build_pilot_queue = build_rich_pilot_queue


__all__ = [
    "ADJUDICATION",
    "ANNOTATION",
    "SCHEMA_VERSION",
    "RichLabelError",
    "append_adjudication",
    "append_label",
    "append_rich_label",
    "build_candidate_queue",
    "build_pilot_queue",
    "build_rich_pilot_queue",
    "candidate_key",
    "compute_disagreement",
    "disagreement",
    "disagreement_report",
    "disagreements",
    "find_disagreements",
    "independent_annotations",
    "label_key",
    "labels_by_candidate",
    "load_labels",
    "load_latest",
    "load_latest_labels",
    "make_adjudication_record",
    "normalize_rich_label",
    "read_rich_labels",
    "record_hash",
    "resolve_disagreement",
    "rich_label_key",
    "validate_rich_label",
]
