"""Deterministic pre-filter: reject commits before any inference runs.

This is the largest cost lever in the pipeline, and its reduction rate is
*measured* rather than assumed: on an FFmpeg-scale import the difference is
roughly $250 versus $6,000. Before this existed, nothing measured it and every
eligible commit went to the model.

The rules here are cheap, local and conservative. Each one drops a commit only
when no first-party source change survives, and each rejection is recorded with
a reason so the reduction rate is auditable and a mistaken rule is visible in
the report rather than invisible in the bill.

Deliberately *not* filtered:

* Test-only changes are kept as a weak positive signal — a security test added
  alongside a fix is evidence, so they are flagged rather than dropped. They
  are marked, not rejected.
* Dependency bumps are routed, not dropped: they matter for supply chain but
  have nothing to analyse in-diff, so they get their own reason code.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .diffing import ChangeKind, classify_change_kind

__all__ = [
    "PrefilterDecision",
    "PrefilterReason",
    "PrefilterStats",
    "prefilter_commit",
]


class PrefilterReason(StrEnum):
    """Why a commit did not reach the model."""

    EMPTY_DIFF = "empty_diff"
    NO_FIRST_PARTY_SOURCE = "no_first_party_source"
    DOCS_ONLY = "docs_only"
    TEST_ONLY = "test_only"
    DEPENDENCY_ONLY = "dependency_only"
    GENERATED_VENDOR_ONLY = "generated_vendor_only"
    BINARY_ONLY = "binary_only"
    SUBMODULE_ONLY = "submodule_only"
    OVERSIZE = "oversize"


#: Kinds that never justify an inference call on their own.
_NON_SOURCE = {
    ChangeKind.DOCS: PrefilterReason.DOCS_ONLY,
    ChangeKind.TEST: PrefilterReason.TEST_ONLY,
    ChangeKind.DEPENDENCY: PrefilterReason.DEPENDENCY_ONLY,
    ChangeKind.GENERATED_VENDOR: PrefilterReason.GENERATED_VENDOR_ONLY,
    ChangeKind.BINARY: PrefilterReason.BINARY_ONLY,
    ChangeKind.SUBMODULE: PrefilterReason.SUBMODULE_ONLY,
}


@dataclass(frozen=True, slots=True)
class PrefilterDecision:
    """Whether a commit proceeds, and what was observed while deciding."""

    admit: bool
    reason: PrefilterReason | None
    kinds: tuple[str, ...]
    first_party_paths: tuple[str, ...]
    touches_tests: bool
    diff_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "admit": self.admit,
            "reason": self.reason.value if self.reason else None,
            "kinds": list(self.kinds),
            "first_party_paths": list(self.first_party_paths),
            "touches_tests": self.touches_tests,
            "diff_bytes": self.diff_bytes,
        }


@dataclass(slots=True)
class PrefilterStats:
    """Reduction-rate accounting for E9."""

    seen: int = 0
    admitted: int = 0
    rejected_by_reason: dict[str, int] = field(default_factory=dict)

    def record(self, decision: PrefilterDecision) -> None:
        self.seen += 1
        if decision.admit:
            self.admitted += 1
        else:
            key = decision.reason.value if decision.reason else "unknown"
            self.rejected_by_reason[key] = self.rejected_by_reason.get(key, 0) + 1

    @property
    def rejected(self) -> int:
        return self.seen - self.admitted

    @property
    def reduction_rate(self) -> float:
        """Fraction of commits that never reached the model."""
        return (self.rejected / self.seen) if self.seen else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "seen": self.seen,
            "admitted": self.admitted,
            "rejected": self.rejected,
            "reduction_rate": round(self.reduction_rate, 4),
            "rejected_by_reason": dict(
                sorted(self.rejected_by_reason.items(), key=lambda kv: -kv[1])
            ),
        }


def prefilter_commit(
    changed_paths: Iterable[Mapping[str, Any] | Any],
    patch: str | bytes,
    *,
    max_diff_bytes: int | None = None,
) -> PrefilterDecision:
    """Decide whether one commit is worth an inference call.

    Args:
        changed_paths: Path records from the git layer; each may be a mapping
            or an object exposing ``path``.
        patch: The commit's first-parent diff.
        max_diff_bytes: Reject above this size. ``None`` disables the check —
            chunking handles oversize inputs, so this is only for callers that
            deliberately skip rather than chunk.

    Returns:
        A :class:`PrefilterDecision` carrying the outcome and the observations
        behind it.
    """
    if isinstance(patch, bytes):
        text = patch.decode("utf-8", errors="replace")
        size = len(patch)
    else:
        text = patch or ""
        size = len(text.encode("utf-8"))

    paths: list[str] = []
    for record in changed_paths or ():
        value = (
            record.get("path") if isinstance(record, Mapping) else getattr(record, "path", None)
        )
        if value:
            paths.append(str(value))

    if not text.strip() or not paths:
        return PrefilterDecision(
            admit=False,
            reason=PrefilterReason.EMPTY_DIFF,
            kinds=(),
            first_party_paths=(),
            touches_tests=False,
            diff_bytes=size,
        )

    # Size is checked before classification: an oversize commit is rejected
    # regardless of kind, so classifying it first is wasted -- and on a
    # multi-megabyte patch ``classify_change_kind``'s per-file ``re.M`` scans of
    # the whole text are pathologically slow, which is exactly the input a
    # streaming walk (no per-commit patch cap) can hand this. Reject on size
    # first and never run the classifier over an outsized diff.
    if max_diff_bytes is not None and size > max_diff_bytes:
        return PrefilterDecision(
            admit=False,
            reason=PrefilterReason.OVERSIZE,
            kinds=(),
            first_party_paths=(),
            touches_tests=False,
            diff_bytes=size,
        )

    kinds = [classify_change_kind(path, text) for path in paths]
    first_party = tuple(
        path
        for path, kind in zip(paths, kinds, strict=True)
        if kind in (ChangeKind.SOURCE, ChangeKind.MERGE_RESOLUTION, ChangeKind.OTHER)
    )
    touches_tests = ChangeKind.TEST in kinds
    kind_names = tuple(dict.fromkeys(kind.value for kind in kinds))

    if first_party:
        return PrefilterDecision(
            admit=True,
            reason=None,
            kinds=kind_names,
            first_party_paths=first_party,
            touches_tests=touches_tests,
            diff_bytes=size,
        )

    # No first-party source survived. Attribute the rejection to the single
    # kind that explains it when there is one, so the report distinguishes
    # "docs commit" from "vendor bump".
    distinct = {kind for kind in kinds}
    reason = PrefilterReason.NO_FIRST_PARTY_SOURCE
    if len(distinct) == 1:
        reason = _NON_SOURCE.get(next(iter(distinct)), reason)
    return PrefilterDecision(
        admit=False,
        reason=reason,
        kinds=kind_names,
        first_party_paths=(),
        touches_tests=touches_tests,
        diff_bytes=size,
    )
