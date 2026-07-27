"""Typed shape of the compiled security context.

The artifact is a *compiled* object: every count, ranking and grouping in it is
computed by :mod:`strata.context.compiler` from validated findings, with no
model in the loop. Only two free-text fields (``summary`` and ``agent_brief``)
are model-written, and both are derived from the same structured data, so a
reader can check them against it.

That split is the point. Aggregate claims like "this component has a recurring
fix history" are unfalsifiable when a model asserts them and trivially checkable
when code counts them.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from typing import Any

SCHEMA_VERSION = "security-context-v1"

__all__ = [
    "SCHEMA_VERSION",
    "Anchor",
    "Fingerprint",
    "KnownCve",
    "Lead",
    "Remediation",
    "RepoRef",
    "ScanStats",
    "SecurityContext",
    "SharedSurface",
    "TopRisk",
]


def _clean(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {k: _clean(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_clean(v) for v in value]
    return value


@dataclass(frozen=True, slots=True)
class Anchor:
    """A provenance pointer whose quote was re-read from git and matched.

    This is the field comparable artifacts have no equivalent for: their
    ``evidence`` is a list of commit SHAs, which tells a reader *that* a claim
    came from somewhere but not *where* to look or what to read.
    """

    revision: str
    revision_sha: str
    path: str
    start_line: int
    end_line: int
    quoted_span: str
    supports: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return _clean(asdict(self))


@dataclass(frozen=True, slots=True)
class Fingerprint:
    """One adjudicated historical fix, anchored to code."""

    id: str
    commit_sha: str
    commit_date: str
    commit_subject: str
    l0_class: str
    cwe: tuple[str, ...]
    components: tuple[str, ...]
    sink: str | None
    sink_symbols: tuple[str, ...]
    fix_shape: str | None
    severity: str
    summary: str
    poc: str | None
    invariant: str | None
    fix_completeness: str
    anchors: tuple[Anchor, ...] = ()
    still_applies: bool | None = None
    advisory_ids: tuple[str, ...] = ()
    #: Provenance for the two gates and for any re-attribution, so a reader can
    #: see why a finding was accepted and which commit it was moved from.
    reachability_delta: Mapping[str, Any] | None = None
    failure_containment: str | None = None
    attributed_from: str | None = None
    attribution_method: str | None = None
    patch_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = _clean(asdict(self))
        payload["anchors"] = [anchor.to_dict() for anchor in self.anchors]
        return payload


@dataclass(frozen=True, slots=True)
class TopRisk:
    """A recurring (class, component) pair, ranked by weighted fix history."""

    l0_class: str
    component: str
    severity: str
    fix_count: int
    cwe: tuple[str, ...]
    rationale: str
    evidence: tuple[str, ...]
    recency_weight: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return _clean(asdict(self))


@dataclass(frozen=True, slots=True)
class SharedSurface:
    """A guard that must hold on every listed entry point.

    The invariant is stated in the shape a downstream agent can act on: the
    check, where it must hold, and what a violation looks like.
    """

    surface: str
    guard: tuple[str, ...]
    entry_points: tuple[str, ...]
    check_hint: str
    evidence: tuple[str, ...]
    origin_fixes: tuple[str, ...] = ()
    still_applies: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return _clean(asdict(self))


@dataclass(frozen=True, slots=True)
class Lead:
    """An unfixed site matching a known-dangerous pattern.

    Dual-use surface: an inventory of unreviewed call sites in live code.
    Gated behind an explicit flag and never written into the public artifact
    by default.
    """

    path: str
    line: int
    symbol: str | None
    matched_sink: str
    origin_fingerprint: str
    rationale: str
    reviewed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return _clean(asdict(self))


@dataclass(frozen=True, slots=True)
class KnownCve:
    id: str
    cwe: tuple[str, ...]
    severity: str
    published: str | None
    summary: str
    references: tuple[str, ...] = ()
    matched_fingerprint: str | None = None
    repository_confirmed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return _clean(asdict(self))


@dataclass(frozen=True, slots=True)
class RepoRef:
    owner: str
    name: str
    url: str
    ref: str
    head_sha: str

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.name}"

    def to_dict(self) -> dict[str, Any]:
        return _clean(asdict(self))


@dataclass(frozen=True, slots=True)
class ScanStats:
    """What the pipeline actually did, so coverage claims can be checked."""

    commits_scanned: int
    commits_triaged: int
    triage_candidates: int
    adjudicated: int
    findings: int
    abstained: int
    rejected: int
    triage_errors: int = 0
    adjudication_errors: int = 0
    tokens: int = 0
    estimated_cost_usd: float = 0.0
    wall_clock_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return _clean(asdict(self))


@dataclass(frozen=True, slots=True)
class Remediation:
    """Coverage, with its formula stated in the artifact.

    An under-defined headline metric is a credibility gap. A bare
    ``coverage: 40`` that a reader cannot reconstruct from the artifact's own
    fields invites them to either over-trust it or discard it. Here the
    numerator, denominator and formula all ship alongside the value.
    """

    coverage: float | None
    measurable_fixes: int
    guarded_fixes: int
    open_leads: int
    guarded_sites: int
    formula: str = "guarded_fixes / measurable_fixes"
    definition: str = (
        "measurable_fixes = adjudicated YES findings whose anchored code still "
        "exists at HEAD (still_applies is true). guarded_fixes = those whose "
        "invariant is still enforced at every entry point of its shared "
        "surface. Findings whose code was deleted or rewritten are excluded "
        "from both, not counted as remediated."
    )

    def to_dict(self) -> dict[str, Any]:
        return _clean(asdict(self))


@dataclass(frozen=True, slots=True)
class SecurityContext:
    """The compiled artifact."""

    repo: RepoRef
    generated_at: str
    provenance: Mapping[str, Any]
    scan: ScanStats
    archetype: str
    summary: str
    agent_brief: str
    remediation: Remediation
    top_risks: tuple[TopRisk, ...]
    shared_surfaces: tuple[SharedSurface, ...]
    fingerprints: tuple[Fingerprint, ...]
    known_cves: tuple[KnownCve, ...] = ()
    l0_class_counts: Mapping[str, int] = field(default_factory=dict)
    component_counts: Mapping[str, int] = field(default_factory=dict)
    leads: tuple[Lead, ...] = ()
    schema_version: str = SCHEMA_VERSION

    def to_dict(self, *, include_leads: bool = False) -> dict[str, Any]:
        """Serialise the artifact.

        Args:
            include_leads: Emit the ``leads`` inventory. Off by default: leads
                are unfixed sites in live code and are dual-use.
        """
        payload: dict[str, Any] = {
            "schema_version": self.schema_version,
            "repo": self.repo.to_dict(),
            "generated_at": self.generated_at,
            "provenance": _clean(dict(self.provenance)),
            "scan": self.scan.to_dict(),
            "archetype": self.archetype,
            "summary": self.summary,
            "agent_brief": self.agent_brief,
            "remediation": self.remediation.to_dict(),
            "top_risks": [risk.to_dict() for risk in self.top_risks],
            "shared_surfaces": [s.to_dict() for s in self.shared_surfaces],
            "fingerprints": [f.to_dict() for f in self.fingerprints],
            "known_cves": [c.to_dict() for c in self.known_cves],
            "l0_class_counts": dict(self.l0_class_counts),
            "component_counts": dict(self.component_counts),
        }
        if include_leads:
            payload["leads"] = [lead.to_dict() for lead in self.leads]
        else:
            payload["leads_withheld"] = len(self.leads)
        return payload
