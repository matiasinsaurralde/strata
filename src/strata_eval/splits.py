"""Deterministic grouped and temporal evaluation holdout assignment."""

from __future__ import annotations

import hashlib
import math
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, time
from enum import Enum, StrEnum
from typing import Any

from strata.contracts import canonical_hash, canonical_json


class Split(StrEnum):
    DEVELOPMENT = "development"
    HOLDOUT = "holdout"


class AssignmentMethod(StrEnum):
    GROUPED_HASH = "grouped_hash"
    TEMPORAL = "temporal"


DEFAULT_GROUP_KEYS = (
    "advisory_id",
    "advisory_ids",
    "ghsa_id",
    "ghsa_ids",
    "patch_group_id",
    "patch_id",
    "backport_group_id",
)


@dataclass(frozen=True, slots=True)
class RecordGroup:
    group_id: str
    record_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SplitAssignment:
    record_id: str
    group_id: str
    split: Split

    def __post_init__(self) -> None:
        if not isinstance(self.record_id, str) or not self.record_id:
            raise ValueError("record_id must be a non-empty string")
        if not isinstance(self.group_id, str) or not self.group_id:
            raise ValueError("group_id must be a non-empty string")
        if not isinstance(self.split, Split):
            object.__setattr__(self, "split", Split(self.split))

    def to_dict(self) -> dict[str, str]:
        return {
            "record_id": self.record_id,
            "group_id": self.group_id,
            "split": self.split.value,
        }


class _UnionFind:
    def __init__(self, values: Iterable[str]) -> None:
        self.parent = {value: value for value in values}

    def find(self, value: str) -> str:
        parent = self.parent[value]
        while parent != self.parent[parent]:
            parent = self.parent[parent]
        while value != parent:
            next_value = self.parent[value]
            self.parent[value] = parent
            value = next_value
        return parent

    def union(self, left: str, right: str) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root == right_root:
            return
        # Lexicographic root choice makes construction order irrelevant.
        low, high = sorted((left_root, right_root))
        self.parent[high] = low


def _record_id(
    row: Mapping[str, Any],
    id_key: str | Callable[[Mapping[str, Any]], object],
) -> str:
    value = id_key(row) if callable(id_key) else row.get(id_key)
    if value is None and not callable(id_key) and id_key == "id":
        repository = row.get("repository", row.get("repo"))
        sha = row.get("commit_sha", row.get("sha"))
        if repository is not None and sha is not None:
            value = f"{repository}@{sha}"
    if value is None or not str(value).strip():
        raise ValueError("every record needs a stable non-empty identity")
    return str(value)


def _relation_values(value: object) -> tuple[str, ...]:
    if value is None or value == "":
        return ()
    if isinstance(value, (str, int)):
        return (str(value),)
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray, Mapping)):
        result = tuple(str(item) for item in value if item is not None and str(item))
        return tuple(sorted(set(result)))
    raise TypeError(f"group relation must be scalar or array, got {type(value).__name__}")


def linked_record_groups(
    records: Iterable[Mapping[str, Any]],
    *,
    id_key: str | Callable[[Mapping[str, Any]], object] = "id",
    group_keys: Sequence[str] | str = DEFAULT_GROUP_KEYS,
) -> tuple[RecordGroup, ...]:
    """Create transitive groups from advisory, patch, and backport links."""

    rows = tuple(records)
    keys = (group_keys,) if isinstance(group_keys, str) else tuple(group_keys)
    if not keys or any(not isinstance(key, str) or not key for key in keys):
        raise ValueError("group_keys must contain non-empty field names")
    identities = tuple(_record_id(row, id_key) for row in rows)
    if len(set(identities)) != len(identities):
        raise ValueError("record identities must be unique")
    union = _UnionFind(identities)
    relation_owner: dict[tuple[str, str], str] = {}
    namespaces = {
        "advisory_id": "advisory",
        "advisory_ids": "advisory",
        "ghsa_id": "advisory",
        "ghsa_ids": "advisory",
    }
    for identity, row in zip(identities, rows, strict=True):
        for key in keys:
            for relation in _relation_values(row.get(key)):
                token = (namespaces.get(key, key), relation)
                previous = relation_owner.get(token)
                if previous is None:
                    relation_owner[token] = identity
                else:
                    union.union(previous, identity)
    members: dict[str, list[str]] = {}
    for identity in identities:
        members.setdefault(union.find(identity), []).append(identity)
    groups = []
    for record_ids in members.values():
        stable_members = tuple(sorted(record_ids))
        group_id = f"group:{canonical_hash(stable_members).removeprefix('sha256:')}"
        groups.append(RecordGroup(group_id=group_id, record_ids=stable_members))
    return tuple(sorted(groups, key=lambda group: group.group_id))


def _fraction(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("holdout_fraction must be numeric")
    result = float(value)
    if not math.isfinite(result) or not 0.0 <= result <= 1.0:
        raise ValueError("holdout_fraction must be between 0 and 1")
    return result


def stable_group_score(group_id: str, *, seed: str = "strata-v1") -> float:
    if not isinstance(seed, str) or not seed:
        raise ValueError("seed must be a non-empty string")
    digest = hashlib.sha256(f"{seed}\0{group_id}".encode()).digest()
    return int.from_bytes(digest, "big") / (1 << (8 * len(digest)))


def grouped_holdout_assignments(
    records: Iterable[Mapping[str, Any]],
    *,
    id_key: str | Callable[[Mapping[str, Any]], object] = "id",
    group_keys: Sequence[str] | str = DEFAULT_GROUP_KEYS,
    holdout_fraction: float = 0.2,
    seed: str = "strata-v1",
) -> tuple[SplitAssignment, ...]:
    """Hash whole linked groups into a stable development/holdout split."""

    fraction = _fraction(holdout_fraction)
    groups = linked_record_groups(records, id_key=id_key, group_keys=group_keys)
    result = []
    for group in groups:
        split = (
            Split.HOLDOUT
            if stable_group_score(group.group_id, seed=seed) < fraction
            else Split.DEVELOPMENT
        )
        result.extend(
            SplitAssignment(record_id=record_id, group_id=group.group_id, split=split)
            for record_id in group.record_ids
        )
    return tuple(sorted(result, key=lambda item: item.record_id))


def _parse_timestamp(value: object) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, date):
        parsed = datetime.combine(value, time.min, tzinfo=UTC)
    elif isinstance(value, str) and value.strip():
        raw = value.strip()
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            try:
                parsed = datetime.combine(date.fromisoformat(raw), time.min)
            except ValueError as exc:
                raise ValueError(f"invalid ISO timestamp: {value!r}") from exc
    else:
        raise ValueError(f"invalid timestamp: {value!r}")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def temporal_holdout_assignments(
    records: Iterable[Mapping[str, Any]],
    *,
    timestamp_key: str = "committed_at",
    id_key: str | Callable[[Mapping[str, Any]], object] = "id",
    group_keys: Sequence[str] | str = DEFAULT_GROUP_KEYS,
    holdout_fraction: float = 0.2,
    cutoff: str | date | datetime | None = None,
) -> tuple[SplitAssignment, ...]:
    """Assign newest groups to holdout while preserving all relationship links."""

    rows = tuple(records)
    identities = tuple(_record_id(row, id_key) for row in rows)
    if len(set(identities)) != len(identities):
        raise ValueError("record identities must be unique")

    def timestamp_value(row: Mapping[str, Any]) -> object:
        value = row.get(timestamp_key)
        if value is None and timestamp_key == "committed_at":
            for alias in ("committer_time", "commit_time", "timestamp", "date"):
                if row.get(alias) is not None:
                    return row[alias]
        return value

    timestamp_by_id = {
        identity: _parse_timestamp(timestamp_value(row))
        for identity, row in zip(identities, rows, strict=True)
    }
    groups = linked_record_groups(rows, id_key=id_key, group_keys=group_keys)
    latest = {
        group.group_id: max(timestamp_by_id[record_id] for record_id in group.record_ids)
        for group in groups
    }
    if cutoff is not None:
        cutoff_time = _parse_timestamp(cutoff)
        holdout_groups = {
            group.group_id for group in groups if latest[group.group_id] >= cutoff_time
        }
    else:
        fraction = _fraction(holdout_fraction)
        target = math.ceil(len(rows) * fraction)
        newest = sorted(
            groups, key=lambda group: (latest[group.group_id], group.group_id), reverse=True
        )
        holdout_groups: set[str] = set()
        selected = 0
        for group in newest:
            if selected >= target:
                break
            holdout_groups.add(group.group_id)
            selected += len(group.record_ids)

    result = [
        SplitAssignment(
            record_id=record_id,
            group_id=group.group_id,
            split=Split.HOLDOUT if group.group_id in holdout_groups else Split.DEVELOPMENT,
        )
        for group in groups
        for record_id in group.record_ids
    ]
    return tuple(sorted(result, key=lambda item: item.record_id))


def assignment_map(
    assignments: Iterable[SplitAssignment],
) -> dict[str, Split]:
    return {
        assignment.record_id: assignment.split
        for assignment in sorted(assignments, key=lambda item: item.record_id)
    }


def _jsonable_dataset(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    def convert(value: object) -> object:
        if isinstance(value, (datetime, date)):
            return value.isoformat()
        if isinstance(value, Mapping):
            return {str(key): convert(item) for key, item in value.items()}
        if isinstance(value, (list, tuple, set, frozenset)):
            converted = [convert(item) for item in value]
            return sorted(converted, key=lambda item: canonical_json(item))
        if isinstance(value, Enum):
            return value.value
        return value

    converted = [convert(dict(row)) for row in records]
    return sorted(converted, key=canonical_json)  # type: ignore[arg-type,return-value]


def dataset_content_hash(records: Iterable[Mapping[str, Any]]) -> str:
    return canonical_hash(_jsonable_dataset(records))


# Short aliases for interactive evaluation code.
assign_grouped_holdout = grouped_holdout_assignments
assign_temporal_holdout = temporal_holdout_assignments
