"""Deterministic aggregation of findings into a security context.

No model runs in this module. Counts, rankings, hotspots, component
normalisation and the coverage metric are computed from validated findings by
code — no LLM takes part in the aggregation step. Two narrative fields are
model-written and live in :mod:`strata.context.narrative`, which consumes this
module's output rather than the raw findings.
"""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from .models import (
    Anchor,
    Fingerprint,
    KnownCve,
    Lead,
    Remediation,
    RepoRef,
    ScanStats,
    SecurityContext,
    SharedSurface,
    TopRisk,
)

__all__ = [
    "compile_context",
    "component_of",
    "normalise_component",
    "recency_weight",
]

#: Half-life for hotspot recency weighting, in days. Hotspots are
#: fixes-per-file weighted by recency, so "genuinely fragile" separates from
#: "merely large and busy".
_RECENCY_HALF_LIFE_DAYS = 730.0

_SEVERITY_ORDER = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_SEVERITY_BY_RANK = {rank: name for name, rank in _SEVERITY_ORDER.items()}

_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def normalise_component(value: str) -> str:
    """Reduce a component label to a single canonical form.

    Component labels arrive as a type name, a bare identifier or a path, so
    an uncanonicalised tally produces ``{"Context": 1, "context": 1,
    "context.go": 6, ...}`` — three keys for one component, which makes the
    count meaningless and the ranking wrong. The
    canonical form here is the repository-relative *path* where one is
    available, lowercased, with a leading ``./`` and any ``a/``/``b/`` diff
    prefix removed.
    """
    text = (value or "").strip().replace("\\", "/")
    if not text:
        return ""
    for prefix in ("a/", "b/", "./"):
        if text.startswith(prefix):
            text = text[len(prefix) :]
    return text.lower()


def component_of(path: str) -> str:
    """The component a path belongs to: the file itself, canonically named."""
    return normalise_component(path)


def recency_weight(commit_date: str | None, *, now: datetime | None = None) -> float:
    """Exponential decay on a commit's age.

    Diff Rolling observation #4: later commits are likelier to still be
    vulnerable, so a fix from last year says more about present risk than one
    from 2014. Weight is 1.0 today and halves every
    :data:`_RECENCY_HALF_LIFE_DAYS`.
    """
    if not commit_date:
        return 0.5
    try:
        parsed = datetime.fromisoformat(commit_date.replace("Z", "+00:00"))
    except ValueError:
        return 0.5
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    reference = now or datetime.now(UTC)
    age_days = max(0.0, (reference - parsed).total_seconds() / 86_400.0)
    return math.pow(0.5, age_days / _RECENCY_HALF_LIFE_DAYS)


def _severity_name(rank: int) -> str:
    return _SEVERITY_BY_RANK.get(max(0, min(4, rank)), "unknown")


def _anchors_from(finding: Mapping[str, Any]) -> tuple[Anchor, ...]:
    anchors: list[Anchor] = []
    for item in finding.get("evidence") or ():
        if not isinstance(item, Mapping):
            continue
        try:
            anchors.append(
                Anchor(
                    revision=str(item.get("revision") or "commit"),
                    revision_sha=str(item.get("revision_sha") or ""),
                    path=str(item.get("path") or ""),
                    start_line=int(item.get("start_line") or 0),
                    end_line=int(item.get("end_line") or 0),
                    quoted_span=str(item.get("quoted_span") or ""),
                    supports=tuple(str(s) for s in item.get("supports") or ()),
                )
            )
        except TypeError, ValueError:
            continue
    return tuple(anchors)


def _sink_symbols(finding: Mapping[str, Any], anchors: Sequence[Anchor]) -> tuple[str, ...]:
    """Best-effort dangerous-symbol extraction from the anchored spans.

    Deterministic and quote-derived: a symbol only appears here if it occurs in
    text that was verified against the repository.
    """
    declared = finding.get("sink_symbols")
    if isinstance(declared, Sequence) and not isinstance(declared, (str, bytes)):
        found = [str(item) for item in declared if str(item).strip()]
        if found:
            return tuple(dict.fromkeys(found))
    symbols: list[str] = []
    for anchor in anchors:
        # Prefer call-shaped tokens: `foo.Bar(` reads as a sink, `if` does not.
        for match in re.finditer(r"([A-Za-z_][\w.]*)\s*\(", anchor.quoted_span):
            token = match.group(1)
            if len(token) > 2 and token not in symbols:
                symbols.append(token)
    return tuple(symbols[:4])


def _still_applies(anchors: Sequence[Anchor], repo: Any) -> bool | None:
    """Theseus folding: does the anchored code still exist at HEAD?

    A finding whose subject was deleted should not clutter the artifact, and
    should not be counted as remediated either — it is simply no longer
    measurable.
    """
    if repo is None or not anchors:
        return None
    resolved: bool | None = None
    for anchor in anchors:
        if not anchor.path or not anchor.quoted_span:
            continue
        try:
            blob = repo.read_blob("HEAD", anchor.path)
        except Exception:
            resolved = resolved if resolved else False
            continue
        text = blob.decode("utf-8", errors="replace") if isinstance(blob, bytes) else str(blob)
        needle = " ".join(anchor.quoted_span.split())
        haystack = " ".join(text.split())
        if needle and needle in haystack:
            return True
        resolved = False
    return resolved


def _fingerprint_from(
    finding: Mapping[str, Any],
    *,
    repo: Any = None,
    now: datetime | None = None,
) -> Fingerprint | None:
    sha = str(finding.get("commit_sha") or "")
    if not sha:
        return None
    anchors = _anchors_from(finding)
    paths = [
        component_of(str(p)) for p in (finding.get("affected_paths") or ()) if str(p).strip()
    ]
    if not paths:
        paths = [component_of(a.path) for a in anchors if a.path]
    components = tuple(dict.fromkeys(p for p in paths if p))

    severity = finding.get("severity")
    level = "unknown"
    if isinstance(severity, Mapping):
        level = str(severity.get("level") or "unknown")
    elif isinstance(severity, str):
        level = severity

    cwe = finding.get("cwe_id")
    cwes = tuple(c for c in ([str(cwe)] if cwe else []) if c)

    return Fingerprint(
        id=f"fp_{sha[:10]}",
        commit_sha=sha,
        commit_date=str(finding.get("commit_date") or ""),
        commit_subject=str(finding.get("commit_subject") or "")[:200],
        l0_class=str(finding.get("l0_class") or "other"),
        cwe=cwes,
        components=components,
        sink=str(finding.get("sink")) if finding.get("sink") else None,
        sink_symbols=_sink_symbols(finding, anchors),
        fix_shape=str(finding.get("fix_effect") or "")[:200] or None,
        severity=level,
        summary=str(finding.get("root_cause") or "")[:400],
        poc=str(finding.get("impact") or "") or None,
        invariant=str(finding.get("invariant")) if finding.get("invariant") else None,
        fix_completeness=str(finding.get("fix_completeness") or "unknown"),
        anchors=anchors,
        still_applies=_still_applies(anchors, repo),
        advisory_ids=tuple(str(a) for a in finding.get("advisory_ids") or ()),
        reachability_delta=(
            dict(finding["reachability_delta"])
            if isinstance(finding.get("reachability_delta"), Mapping)
            else None
        ),
        failure_containment=(
            str(finding["failure_containment"]) if finding.get("failure_containment") else None
        ),
        attributed_from=(
            str(finding["attributed_from"]) if finding.get("attributed_from") else None
        ),
        attribution_method=(
            str(finding["attribution_method"]) if finding.get("attribution_method") else None
        ),
        patch_id=str(finding["patch_id"]) if finding.get("patch_id") else None,
    )


def _build_top_risks(
    fingerprints: Sequence[Fingerprint],
    *,
    limit: int = 5,
    now: datetime | None = None,
) -> tuple[TopRisk, ...]:
    """Rank (class, component) pairs by recency-weighted fix count."""
    grouped: dict[tuple[str, str], list[Fingerprint]] = defaultdict(list)
    for fingerprint in fingerprints:
        for component in fingerprint.components or ("",):
            grouped[(fingerprint.l0_class, component)].append(fingerprint)

    risks: list[TopRisk] = []
    for (l0_class, component), group in grouped.items():
        if not component:
            continue
        weight = sum(recency_weight(f.commit_date, now=now) for f in group)
        peak = max(_SEVERITY_ORDER.get(f.severity, 0) for f in group)
        cwes = tuple(dict.fromkeys(c for f in group for c in f.cwe))
        invariants = [f.invariant for f in group if f.invariant]
        rationale = (
            invariants[0]
            if invariants
            else (group[0].summary or f"Recurring {l0_class} fixes in {component}.")
        )
        risks.append(
            TopRisk(
                l0_class=l0_class,
                component=component,
                severity=_severity_name(peak),
                fix_count=len(group),
                cwe=cwes,
                rationale=rationale,
                evidence=tuple(f.commit_sha for f in group),
                recency_weight=round(weight, 4),
            )
        )
    risks.sort(key=lambda r: (r.recency_weight, r.fix_count), reverse=True)
    return tuple(risks[:limit])


def _build_shared_surfaces(
    fingerprints: Sequence[Fingerprint],
    *,
    limit: int = 6,
) -> tuple[SharedSurface, ...]:
    """Group findings that share a guard into one surface.

    A surface exists when the same class of fix recurs across more than one
    entry point: that is the shape where one unguarded sibling path is a live
    bug, and it is the highest-yield thing to hand a downstream agent.
    """
    grouped: dict[str, list[Fingerprint]] = defaultdict(list)
    for fingerprint in fingerprints:
        if not fingerprint.invariant:
            continue
        grouped[fingerprint.l0_class].append(fingerprint)

    surfaces: list[SharedSurface] = []
    for l0_class, group in grouped.items():
        entry_points = tuple(dict.fromkeys(c for f in group for c in f.components if c))
        guards = tuple(dict.fromkeys(s for f in group for s in f.sink_symbols if s))
        if len(group) < 2 and len(entry_points) < 2:
            continue
        surfaces.append(
            SharedSurface(
                surface=l0_class.replace("_", " ").title(),
                guard=guards[:4],
                entry_points=entry_points,
                check_hint=(
                    group[0].invariant
                    or f"Verify the {l0_class} guard holds on every listed entry point."
                ),
                evidence=tuple(f.commit_sha for f in group),
                origin_fixes=tuple(f.id for f in group),
                still_applies=any(f.still_applies for f in group)
                if any(f.still_applies is not None for f in group)
                else None,
            )
        )
    surfaces.sort(key=lambda s: (len(s.entry_points), len(s.evidence)), reverse=True)
    return tuple(surfaces[:limit])


def _remediation(fingerprints: Sequence[Fingerprint], leads: Sequence[Lead]) -> Remediation:
    measurable = [f for f in fingerprints if f.still_applies is not False]
    guarded = [f for f in measurable if f.invariant and f.still_applies]
    coverage = round(100.0 * len(guarded) / len(measurable), 1) if measurable else None
    return Remediation(
        coverage=coverage,
        measurable_fixes=len(measurable),
        guarded_fixes=len(guarded),
        open_leads=len(leads),
        guarded_sites=sum(len(f.anchors) for f in guarded),
    )


def _archetype(components: Iterable[str]) -> str:
    """Coarse repository shape, used to focus the downstream agent brief."""
    joined = " ".join(components).lower()
    if any(token in joined for token in ("cmd/", "main.go", "cli")):
        return "cli"
    if any(token in joined for token in ("server", "handler", "router", "http", "context.go")):
        return "server"
    if any(token in joined for token in ("parser", "decode", "codec", "lexer")):
        return "parser"
    return "library"


def compile_context(
    findings: Iterable[Mapping[str, Any]],
    *,
    repo_ref: RepoRef,
    scan: ScanStats,
    provenance: Mapping[str, Any],
    repository: Any = None,
    known_cves: Sequence[KnownCve] = (),
    leads: Sequence[Lead] = (),
    now: datetime | None = None,
    top_risk_limit: int = 5,
) -> SecurityContext:
    """Aggregate validated findings into a security context.

    Args:
        findings: Adjudicated YES findings, already contract-validated.
        repo_ref: Repository identity and the head this reflects.
        scan: What the pipeline did, for coverage honesty.
        provenance: Model, prompt hashes, catalog version, pipeline version.
        repository: Optional :class:`~strata.git_repo.GitRepository` used for
            Theseus folding (does the anchored code still exist at HEAD).
        known_cves: Advisory join, if one was performed.
        leads: Unfixed candidate sites. Withheld from output unless explicitly
            requested at serialisation time.
        now: Reference time for recency weighting; defaults to the wall clock.
        top_risk_limit: How many ranked risks to surface.
    """
    timestamp = (now or datetime.now(UTC)).isoformat()

    fingerprints = tuple(
        fingerprint
        for fingerprint in (
            _fingerprint_from(finding, repo=repository, now=now) for finding in findings
        )
        if fingerprint is not None
    )
    fingerprints = tuple(sorted(fingerprints, key=lambda f: f.commit_date or "", reverse=True))

    class_counts = Counter(f.l0_class for f in fingerprints)
    component_counts: Counter[str] = Counter()
    for fingerprint in fingerprints:
        for component in fingerprint.components:
            component_counts[component] += 1

    top_risks = _build_top_risks(fingerprints, limit=top_risk_limit, now=now)
    surfaces = _build_shared_surfaces(fingerprints)

    return SecurityContext(
        repo=repo_ref,
        generated_at=timestamp,
        provenance=dict(provenance),
        scan=scan,
        archetype=_archetype(component_counts),
        summary="",  # filled by strata.context.narrative
        agent_brief="",  # filled by strata.context.narrative
        remediation=_remediation(fingerprints, leads),
        top_risks=top_risks,
        shared_surfaces=surfaces,
        fingerprints=fingerprints,
        known_cves=tuple(known_cves),
        l0_class_counts=dict(class_counts.most_common()),
        component_counts=dict(component_counts.most_common()),
        leads=tuple(leads),
    )
