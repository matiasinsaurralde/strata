"""Minimal, deterministic introduced-to-fixed span attribution.

For each confirmed fix fingerprint this stage answers one narrow question: how
long did the vulnerable code exist before the fix landed? It blames the pre-fix
lines the fix touched (the ``parent``-revision evidence anchors), takes the
*oldest* commit that last touched any of them as the introduction, and records
the span in days between that commit and the fix.

This is a deterministic, blame-only core -- no pickaxe, no LLM adjudication, no
author attribution, no candidate set. It trades recall for simplicity and
honesty: it declines (leaves the span ``None``) rather
than guess when there is no parent anchor to blame, when blame yields nothing,
when the oldest touch is the file's genesis commit ("present since creation"),
or when any git object is missing. A declined span is strictly better than a
confident wrong one -- a wrong-old attribution poisons any downstream reading of
"how long was this live" in a way an honest gap does not.

The two keys it stamps on each finding dict:

- ``introduced_to_fixed``: ``{sha, date, method, note}`` provenance, or a
  ``declined_*`` record with ``sha`` = ``None``.
- ``introduced_to_fixed_days``: ``int`` span in days, or ``None`` when declined.

Both are read back by ``_fingerprint_from`` in the context compiler so they ride
into the emitted ``fingerprints[]`` array.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

LOGGER = logging.getLogger(__name__)

__all__ = ["attribute_introductions"]

#: git blame is bounded to this many lines per anchor span (mirrors the
#: adjudicator tool cap; a fix anchor is a handful of lines in practice).
_MAX_BLAME_LINES = 400


def _parse_date(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _parent_anchors(finding: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Evidence rows quoting the pre-fix tree: the lines the fix changed/guarded.

    Only ``revision == "parent"`` rows carry a usable ``revision_sha`` (the
    parent commit) plus a line range to blame against. ``commit``-revision rows
    quote the fix itself and have nothing older to attribute.
    """
    anchors: list[dict[str, Any]] = []
    for item in finding.get("evidence") or ():
        if not isinstance(item, Mapping):
            continue
        if str(item.get("revision") or "") != "parent":
            continue
        path = str(item.get("path") or "").strip()
        parent_sha = str(item.get("revision_sha") or "").strip()
        try:
            start = int(item.get("start_line") or 0)
            end = int(item.get("end_line") or 0)
        except TypeError, ValueError:
            continue
        if not path or not parent_sha or start < 1 or end < start:
            continue
        anchors.append(
            {"path": path, "parent_sha": parent_sha, "start_line": start, "end_line": end}
        )
    return anchors


def _oldest_introducing_commit(
    finding: Mapping[str, Any], repository: Any
) -> tuple[str | None, datetime | None, bool, str]:
    """Blame the parent anchors and pick the oldest last-touch commit.

    Returns ``(sha, date, is_genesis, note)``. ``sha`` is ``None`` when nothing
    could be attributed. ``is_genesis`` marks that the oldest touch is the file's
    root commit -- "present since creation", which we decline rather than date.
    """
    anchors = _parent_anchors(finding)
    if not anchors:
        return None, None, False, "no parent anchor to blame"

    # sha -> (date, is_root); dedup blame calls across identical spans.
    candidates: dict[str, tuple[datetime, bool]] = {}
    seen_spans: set[tuple[str, str, int, int]] = set()
    blamed_any = False
    for anchor in anchors:
        span = (anchor["parent_sha"], anchor["path"], anchor["start_line"], anchor["end_line"])
        if span in seen_spans:
            continue
        seen_spans.add(span)
        span_lines = anchor["end_line"] - anchor["start_line"] + 1
        if span_lines > _MAX_BLAME_LINES:
            continue
        try:
            blame_lines = repository.blame(
                anchor["parent_sha"],
                anchor["path"],
                start_line=anchor["start_line"],
                end_line=anchor["end_line"],
                max_lines=_MAX_BLAME_LINES,
            )
        except Exception as exc:  # broken object, missing path at parent, bad range
            LOGGER.debug(
                "blame failed for %s@%s: %s", anchor["path"], anchor["parent_sha"], exc
            )
            continue
        for line in blame_lines:
            sha = getattr(line, "revision", "") or ""
            if not sha or sha in candidates:
                continue
            try:
                commit = repository.get_commit(sha)
            except Exception as exc:
                LOGGER.debug("get_commit failed for %s: %s", sha, exc)
                continue
            date = _parse_date(getattr(commit, "committer_time", None))
            if date is None:
                continue
            candidates[sha] = (date, bool(getattr(commit, "is_root", False)))
            blamed_any = True

    if not candidates:
        note = "blame yielded no dateable commit" if blamed_any is False else "no signal"
        return None, None, False, note

    oldest_sha = min(candidates, key=lambda s: candidates[s][0])
    oldest_date, is_genesis = candidates[oldest_sha]
    return oldest_sha, oldest_date, is_genesis, "oldest blamed last-touch across parent anchors"


def _attribute_one(
    finding: Mapping[str, Any], repository: Any
) -> tuple[dict[str, Any], int | None]:
    """Compute the introduced-to-fixed record for a single finding.

    Never raises: any failure degrades to a ``declined_*`` record with a null
    span, so a finding is never lost to this stage.
    """
    fix_date = _parse_date(finding.get("commit_date"))
    try:
        sha, date, is_genesis, note = _oldest_introducing_commit(finding, repository)
    except Exception as exc:  # defensive: the resolver must never drop a finding
        LOGGER.debug("introduction attribution errored: %s", exc)
        return (
            {"sha": None, "date": None, "method": "declined_no_signal", "note": str(exc)},
            None,
        )

    if sha is None:
        return {"sha": None, "date": None, "method": "declined_no_signal", "note": note}, None
    if is_genesis:
        return (
            {
                "sha": sha,
                "date": date.isoformat() if date else None,
                "method": "declined_file_genesis",
                "note": "oldest blamed commit is the file's genesis; present since creation",
            },
            None,
        )
    if fix_date is None or date is None:
        return (
            {
                "sha": sha,
                "date": date.isoformat() if date else None,
                "method": "declined_no_signal",
                "note": "missing a comparable fix or introduction date",
            },
            None,
        )

    span_days = (fix_date - date).days
    if span_days < 0:
        # A rebase/backport can date the "introduction" after the fix; do not
        # emit a negative span -- decline instead of reporting nonsense.
        return (
            {
                "sha": sha,
                "date": date.isoformat(),
                "method": "declined_no_signal",
                "note": "introduction dated after fix (rebase/backport); span not meaningful",
            },
            None,
        )
    return (
        {"sha": sha, "date": date.isoformat(), "method": "blame", "note": note},
        span_days,
    )


def attribute_introductions(
    findings: Sequence[Mapping[str, Any]], repository: Any
) -> list[dict]:
    """Stamp ``introduced_to_fixed`` + ``introduced_to_fixed_days`` on each finding.

    Mutates and returns the same list of finding dicts (mirroring
    ``attribution.apply``). Deterministic and LLM-free.
    """
    result: list[dict] = []
    for finding in findings:
        record = dict(finding)
        provenance, span_days = _attribute_one(record, repository)
        record["introduced_to_fixed"] = provenance
        record["introduced_to_fixed_days"] = span_days
        result.append(record)
    return result
