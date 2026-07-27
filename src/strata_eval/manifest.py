"""Immutable models and builders for frozen evaluation splits."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any

from strata.contracts import canonical_hash, canonical_json

from .splits import (
    DEFAULT_GROUP_KEYS,
    AssignmentMethod,
    Split,
    SplitAssignment,
    dataset_content_hash,
    grouped_holdout_assignments,
    temporal_holdout_assignments,
)

EVALUATION_MANIFEST_SCHEMA_VERSION = "evaluation-manifest-v1"


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime | str) -> str:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("created_at must be an ISO-8601 timestamp") from exc
    else:
        raise TypeError("created_at must be datetime or string")
    if parsed.tzinfo is None:
        raise ValueError("created_at must include a timezone")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class EvaluationManifestV1:
    dataset_id: str
    dataset_hash: str
    method: AssignmentMethod
    assignments: tuple[SplitAssignment, ...]
    created_at: str
    group_keys: tuple[str, ...] = DEFAULT_GROUP_KEYS
    seed: str | None = None
    holdout_fraction: float | None = None
    cutoff: str | None = None
    schema_version: str = EVALUATION_MANIFEST_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != EVALUATION_MANIFEST_SCHEMA_VERSION:
            raise ValueError(
                f"schema_version must equal {EVALUATION_MANIFEST_SCHEMA_VERSION!r}"
            )
        if not isinstance(self.dataset_id, str) or not self.dataset_id.strip():
            raise ValueError("dataset_id must be a non-empty string")
        if (
            not isinstance(self.dataset_hash, str)
            or not self.dataset_hash.startswith("sha256:")
            or len(self.dataset_hash) != 71
        ):
            raise ValueError("dataset_hash must be a prefixed SHA-256 hash")
        if not isinstance(self.method, AssignmentMethod):
            object.__setattr__(self, "method", AssignmentMethod(self.method))
        assignments = tuple(self.assignments)
        if len({item.record_id for item in assignments}) != len(assignments):
            raise ValueError("manifest record identities must be unique")
        if tuple(sorted(assignments, key=lambda item: item.record_id)) != assignments:
            raise ValueError("assignments must be sorted by record_id")
        group_splits: dict[str, Split] = {}
        for assignment in assignments:
            previous = group_splits.setdefault(assignment.group_id, assignment.split)
            if previous != assignment.split:
                raise ValueError("one linked group cannot span multiple splits")
        object.__setattr__(self, "assignments", assignments)
        group_keys = tuple(self.group_keys)
        if not group_keys or any(not isinstance(key, str) or not key for key in group_keys):
            raise ValueError("group_keys must contain non-empty strings")
        object.__setattr__(self, "group_keys", group_keys)
        object.__setattr__(self, "created_at", _iso(self.created_at))
        if self.method is AssignmentMethod.GROUPED_HASH:
            if not isinstance(self.seed, str) or not self.seed:
                raise ValueError("grouped_hash manifests require a seed")
            if self.cutoff is not None:
                raise ValueError("grouped_hash manifests cannot have a cutoff")
        elif self.seed is not None:
            raise ValueError("temporal manifests do not use a random seed")
        if self.holdout_fraction is not None and not 0.0 <= self.holdout_fraction <= 1.0:
            raise ValueError("holdout_fraction must be between 0 and 1")

    @property
    def manifest_id(self) -> str:
        """Stable identity independent of the manifest creation timestamp."""

        return canonical_hash(
            {
                "schema_version": self.schema_version,
                "dataset_id": self.dataset_id,
                "dataset_hash": self.dataset_hash,
                "method": self.method.value,
                "group_keys": self.group_keys,
                "seed": self.seed,
                "holdout_fraction": self.holdout_fraction,
                "cutoff": self.cutoff,
                "assignments": [item.to_dict() for item in self.assignments],
            }
        )

    def to_dict(self) -> dict[str, Any]:
        counts = Counter(item.split.value for item in self.assignments)
        return {
            "schema_version": self.schema_version,
            "manifest_id": self.manifest_id,
            "dataset_id": self.dataset_id,
            "dataset_hash": self.dataset_hash,
            "method": self.method.value,
            "created_at": self.created_at,
            "group_keys": list(self.group_keys),
            "seed": self.seed,
            "holdout_fraction": self.holdout_fraction,
            "cutoff": self.cutoff,
            "counts": {
                Split.DEVELOPMENT.value: counts[Split.DEVELOPMENT.value],
                Split.HOLDOUT.value: counts[Split.HOLDOUT.value],
            },
            "assignments": [item.to_dict() for item in self.assignments],
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    def content_hash(self) -> str:
        return canonical_hash(self.to_dict())


def build_grouped_manifest(
    records: Iterable[Mapping[str, Any]],
    *,
    dataset_id: str,
    id_key: str | Callable[[Mapping[str, Any]], object] = "id",
    group_keys: Sequence[str] | str = DEFAULT_GROUP_KEYS,
    holdout_fraction: float = 0.2,
    seed: str = "strata-v1",
    dataset_hash: str | None = None,
    created_at: datetime | str | None = None,
) -> EvaluationManifestV1:
    rows = tuple(records)
    keys = (group_keys,) if isinstance(group_keys, str) else tuple(group_keys)
    assignments = grouped_holdout_assignments(
        rows,
        id_key=id_key,
        group_keys=keys,
        holdout_fraction=holdout_fraction,
        seed=seed,
    )
    return EvaluationManifestV1(
        dataset_id=dataset_id,
        dataset_hash=dataset_hash or dataset_content_hash(rows),
        method=AssignmentMethod.GROUPED_HASH,
        assignments=assignments,
        created_at=_iso(created_at or _now()),
        group_keys=keys,
        seed=seed,
        holdout_fraction=float(holdout_fraction),
    )


def build_temporal_manifest(
    records: Iterable[Mapping[str, Any]],
    *,
    dataset_id: str,
    timestamp_key: str = "committed_at",
    id_key: str | Callable[[Mapping[str, Any]], object] = "id",
    group_keys: Sequence[str] | str = DEFAULT_GROUP_KEYS,
    holdout_fraction: float = 0.2,
    cutoff: str | date | datetime | None = None,
    dataset_hash: str | None = None,
    created_at: datetime | str | None = None,
) -> EvaluationManifestV1:
    rows = tuple(records)
    keys = (group_keys,) if isinstance(group_keys, str) else tuple(group_keys)
    assignments = temporal_holdout_assignments(
        rows,
        timestamp_key=timestamp_key,
        id_key=id_key,
        group_keys=keys,
        holdout_fraction=holdout_fraction,
        cutoff=cutoff,
    )
    normalized_cutoff: str | None
    if cutoff is None:
        normalized_cutoff = None
    elif isinstance(cutoff, datetime):
        normalized_cutoff = _iso(cutoff)
    elif isinstance(cutoff, date):
        normalized_cutoff = cutoff.isoformat()
    else:
        normalized_cutoff = cutoff
    return EvaluationManifestV1(
        dataset_id=dataset_id,
        dataset_hash=dataset_hash or dataset_content_hash(rows),
        method=AssignmentMethod.TEMPORAL,
        assignments=assignments,
        created_at=_iso(created_at or _now()),
        group_keys=keys,
        holdout_fraction=float(holdout_fraction) if cutoff is None else None,
        cutoff=normalized_cutoff,
    )
