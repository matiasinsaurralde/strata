"""The two model-written fields of the artifact, and the brief that uses them.

Everything else is compiled. These two are prose for a reader — a human skimming
the page, and an agent being pointed at the code — and both are generated from
the *already-aggregated* structure rather than from raw findings, so a reviewer
can check each sentence against the counts beside it.

``agent_brief`` is assembled deterministically from the compiled surfaces and
risks; only the one-paragraph ``summary`` is a model call. That keeps the part
an agent acts on verifiable, and confines hallucination risk to the part a human
reads.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .models import SecurityContext

__all__ = ["build_agent_brief", "write_narrative"]

_SUMMARY_SYSTEM = (
    "You write one paragraph of security-posture prose for a repository, from "
    "structured findings that have already been verified against the code. "
    "Describe only what the data shows: which components recur, which classes "
    "recur, and what a reviewer should therefore watch. Do not invent "
    "vulnerabilities, CVEs, counts or component names that are absent from the "
    "input. No preamble, no bullet points, no headings. 80-140 words."
)


def build_agent_brief(context: SecurityContext) -> str:
    """Assemble the downstream-agent brief from compiled structure only.

    The brief's job is to say *where to look first* and *what would count as a
    finding*, without implying that re-confirming a fixed bug is a result. It
    is deterministic: every line traces to a compiled field.
    """
    repo = context.repo.slug
    lines: list[str] = [
        f"You are performing a security review of {repo} at {context.repo.head_sha[:12]}.",
        "",
        "Objective: find NEW, verified vulnerabilities in the CURRENT code. Re-confirming "
        "an already-fixed issue is NOT a finding. An unguarded variant of a past fix, or a "
        "novel exploitable flaw in the hot spots below, IS. Use the signals as a map of "
        "where risk concentrates, then hunt openly.",
    ]

    if context.shared_surfaces:
        lines += [
            "",
            "Shared guards that must hold on EVERY path (highest priority — one bypassed "
            "path is a live bug):",
        ]
        for surface in context.shared_surfaces:
            lines.append(f"- {surface.surface}")
            if surface.guard:
                lines.append(f"    guard: {', '.join(surface.guard)}")
            if surface.entry_points:
                lines.append(
                    f"    verify on every entry point: {'; '.join(surface.entry_points)}"
                )
            lines.append(f"    specifically: {surface.check_hint}")

    if context.component_counts:
        lines += ["", "Components with a recurring fix history (review these first):"]
        by_component: dict[str, list[Any]] = {}
        for fingerprint in context.fingerprints:
            for component in fingerprint.components:
                by_component.setdefault(component, []).append(fingerprint)
        for component, count in list(context.component_counts.items())[:8]:
            group = by_component.get(component, [])
            classes = sorted({f.l0_class for f in group})
            symbols = sorted({s for f in group for s in f.sink_symbols})
            line = f"- {component} — {count} past fix(es): {', '.join(classes)}"
            if symbols:
                line += f" | known dangerous symbols: {', '.join(symbols[:6])}"
            lines.append(line)

    if context.top_risks:
        lines += ["", "Highest-weighted risks (recency-weighted fix history):"]
        for risk in context.top_risks:
            lines.append(
                f"- {risk.l0_class} in {risk.component} "
                f"({risk.fix_count} fix(es), peak {risk.severity}): {risk.rationale}"
            )

    lines += [
        "",
        "How to hunt:",
        "1. For each shared guard, trace EVERY listed entry point and confirm the guard is "
        "actually reached. A guard enforced on the direct path but skipped on a sibling "
        "path is a live vulnerability — this is the highest-yield check.",
        "2. Treat each guard as a SET: when several checks are listed, confirm EVERY member "
        "holds on EVERY entry point. Enforcing some but not all is still a bug.",
        "3. In each component, look for new code paths reaching the known dangerous symbols "
        "without the guard.",
        "4. Do NOT stop at the patterns above. The fix history shows where risk concentrates, "
        "not the only bugs that exist.",
        "5. VERIFY before reporting: trace attacker-controlled input to the sink, confirm the "
        "guard is genuinely absent on that path, and state a concrete exploit (attacker, "
        "input, impact). Report findings as file:line plus the exploit. Discard anything you "
        "cannot actually exploit — no speculative leads.",
    ]
    return "\n".join(lines)


def _summary_payload(context: SecurityContext) -> Mapping[str, Any]:
    """The compiled facts the summary is allowed to describe."""
    return {
        "repository": context.repo.slug,
        "archetype": context.archetype,
        "commits_scanned": context.scan.commits_scanned,
        "findings": context.scan.findings,
        "l0_class_counts": dict(context.l0_class_counts),
        "component_counts": dict(list(context.component_counts.items())[:8]),
        "top_risks": [
            {
                "class": risk.l0_class,
                "component": risk.component,
                "severity": risk.severity,
                "fix_count": risk.fix_count,
                "rationale": risk.rationale,
            }
            for risk in context.top_risks
        ],
        "shared_surfaces": [
            {"surface": s.surface, "entry_points": list(s.entry_points), "check": s.check_hint}
            for s in context.shared_surfaces
        ],
    }


def write_narrative(
    context: SecurityContext,
    *,
    client: Any | None = None,
    max_tokens: int = 4096,
) -> SecurityContext:
    """Return ``context`` with ``summary`` and ``agent_brief`` filled in.

    Args:
        context: A compiled context from :func:`strata.context.compiler.compile_context`.
        client: Chat client for the summary paragraph. When ``None`` the
            summary is derived deterministically from the same facts, so the
            artifact is still complete without a model.
        max_tokens: Output budget for the summary call.
    """
    import dataclasses
    import json

    brief = build_agent_brief(context)

    if client is None or not context.fingerprints:
        summary = _fallback_summary(context)
    else:
        try:
            response = client.complete(
                [
                    {"role": "system", "content": _SUMMARY_SYSTEM},
                    {
                        "role": "user",
                        "content": json.dumps(
                            _summary_payload(context), ensure_ascii=False, indent=1
                        ),
                    },
                ],
                max_tokens=max_tokens,
            )
            summary = (response.content or "").strip() or _fallback_summary(context)
        except Exception:
            # A narrative failure must not void a compiled artifact.
            summary = _fallback_summary(context)

    return dataclasses.replace(context, summary=summary, agent_brief=brief)


def _fallback_summary(context: SecurityContext) -> str:
    """Deterministic prose, used when no model is available."""
    if not context.fingerprints:
        return (
            f"No confirmed security fixes were adjudicated in "
            f"{context.scan.commits_scanned} scanned commits of "
            f"{context.repo.slug}."
        )
    classes = ", ".join(list(context.l0_class_counts)[:4])
    components = ", ".join(list(context.component_counts)[:3])
    return (
        f"{context.repo.slug} ({context.archetype}) has {len(context.fingerprints)} "
        f"confirmed historical security fixes across "
        f"{context.scan.commits_scanned} scanned commits. Fixes concentrate in "
        f"{components}, and recur as {classes}. Changes touching those components "
        f"should be reviewed against the shared guards listed in this artifact."
    )
