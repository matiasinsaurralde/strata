"""Build blind labelling worklists.

Every task here exists because a number in the frozen baseline is conditioned on
something it should be independent of. The controlling property is therefore
*blindness*: a worklist never shows the model's verdict, and never shows the
prior label when the point of the task is to re-decide it.

The three tasks, and what each one unblocks:

``relabel-audit``
    The five ``other -> fix`` relabels were applied after reviewing the
    classifier's own false positives, and three of those commits were flagged
    YES in the frozen run. Every FPR and precision figure downstream is
    therefore conditioned on the model's errors. ~30 minutes.

``negative-audit``
    Only model-*positives* were ever reviewed, so the FPR arm is one-sided by
    construction — the random model-negative audit it needs was never run.
    ~1 hour for 40 items.

``holdout``
    ``holdouts/triage-v1`` is reserved but every row has ``role: null``, so it
    scores zero rows today. It is the only untainted number available.
    ~2.5-3 hours for 58 commits.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

__all__ = [
    "ROLES",
    "WorklistItem",
    "build_holdout_worklist",
    "build_negative_audit_worklist",
    "build_relabel_audit_worklist",
    "write_worklist",
]

#: The five-way labelling taxonomy. This is a relationship to a vulnerability,
#: not a binary "is it a fix".
ROLES = ("fix", "context", "backport", "introduce", "other")

_RUBRIC_REMINDER = (
    "Revert test: if this commit were reverted, would a vulnerability come "
    "back? yes -> fix, no -> context. When still undecidable, use other."
)


@dataclass(frozen=True, slots=True)
class WorklistItem:
    """One decision for a human, with everything needed and nothing more."""

    task: str
    item_id: str
    repo: str
    sha: str
    subject: str
    diff_path: str | None
    diff_bytes: int
    #: Context the labeller is *allowed* to see. The rubric permits message and
    #: advisory even though stage 1 sees diff only: richer labels measure
    #: whether the classifier can recover reality from a weaker view.
    advisory: Mapping[str, Any] | None = None
    message: str = ""
    #: Free-form notes for the labeller — never the model verdict.
    guidance: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "task": self.task,
            "item_id": self.item_id,
            "repo": self.repo,
            "sha": self.sha,
            "subject": self.subject,
            "diff_path": self.diff_path,
            "diff_bytes": self.diff_bytes,
            "advisory": dict(self.advisory) if self.advisory else None,
            "message": self.message,
            "guidance": self.guidance,
            "role": None,
            "notes": None,
            "annotator_id": None,
            "decided_at": None,
        }


def _item_id(task: str, repo: str, sha: str) -> str:
    digest = hashlib.sha256(f"{task}|{repo}|{sha}".encode()).hexdigest()
    return f"{task}-{digest[:10]}"


def _advisory_index(advisories: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for advisory in advisories:
        key = str(advisory.get("ghsa_id") or advisory.get("id") or "")
        if key:
            index[key] = dict(advisory)
    return index


def build_relabel_audit_worklist(
    rows: Sequence[Any],
    relabelled_shas: Iterable[str],
    *,
    advisories: Iterable[Mapping[str, Any]] = (),
) -> list[WorklistItem]:
    """Re-decide the contested relabels, blind.

    The prior role is deliberately omitted: the task is to decide the commit on
    its merits, not to agree or disagree with an earlier call that was made
    while looking at the classifier's output.
    """
    # Callers identify commits by abbreviated SHA, so match by prefix rather
    # than by a fixed-width slice of each side.
    wanted = tuple(sha.lower() for sha in relabelled_shas if sha)
    index = _advisory_index(advisories)
    seen: set[str] = set()
    items: list[WorklistItem] = []
    for row in rows:
        sha = row.sha.lower()
        if sha in seen or not any(sha.startswith(prefix) for prefix in wanted):
            continue
        seen.add(sha)
        items.append(
            WorklistItem(
                task="relabel-audit",
                item_id=_item_id("relabel-audit", row.repo, row.sha),
                repo=row.repo,
                sha=row.sha,
                subject=row.subject,
                diff_path=row.diff_path,
                diff_bytes=row.diff_bytes,
                advisory=index.get(row.ghsa_id),
                message=row.message,
                guidance=(
                    "Decide this commit on its own merits. Its earlier label and "
                    "the classifier's verdict are both withheld on purpose. " + _RUBRIC_REMINDER
                ),
            )
        )
    return items


def build_negative_audit_worklist(
    rows: Sequence[Any],
    model_negative_shas: Iterable[str],
    *,
    sample_size: int = 40,
    seed: str = "strata-negative-audit-v1",
    advisories: Iterable[Mapping[str, Any]] = (),
) -> list[WorklistItem]:
    """Sample rows the classifier called NO and a human labelled non-fix.

    Sampling is seeded and content-addressed rather than random, so the same
    corpus always yields the same worklist and a second rater can be given an
    identical set without coordination.
    """
    negatives = {sha.lower() for sha in model_negative_shas}
    index = _advisory_index(advisories)
    eligible = [
        row for row in rows if row.sha.lower() in negatives and row.role in ("other", "context")
    ]
    eligible.sort(key=lambda row: hashlib.sha256(f"{seed}|{row.sha}".encode()).hexdigest())
    return [
        WorklistItem(
            task="negative-audit",
            item_id=_item_id("negative-audit", row.repo, row.sha),
            repo=row.repo,
            sha=row.sha,
            subject=row.subject,
            diff_path=row.diff_path,
            diff_bytes=row.diff_bytes,
            advisory=index.get(row.ghsa_id),
            message=row.message,
            guidance=(
                "This commit is currently labelled non-fix and the classifier "
                "agreed. Nobody has re-checked that agreement. If it is really a "
                "fix, both recall and FPR are wrong. " + _RUBRIC_REMINDER
            ),
        )
        for row in eligible[:sample_size]
    ]


def build_holdout_worklist(
    rows: Sequence[Any],
    *,
    advisories: Iterable[Mapping[str, Any]] = (),
) -> list[WorklistItem]:
    """Label the reserved holdout so it can be scored at all."""
    index = _advisory_index(advisories)
    seen: set[str] = set()
    items: list[WorklistItem] = []
    for row in rows:
        if row.sha in seen:
            continue
        seen.add(row.sha)
        items.append(
            WorklistItem(
                task="holdout",
                item_id=_item_id("holdout", row.repo, row.sha),
                repo=row.repo,
                sha=row.sha,
                subject=row.subject,
                diff_path=row.diff_path,
                diff_bytes=row.diff_bytes,
                advisory=index.get(row.ghsa_id),
                message=row.message,
                guidance=(
                    "Reserved holdout. Do not tune prompts against these commits "
                    "after labelling them. " + _RUBRIC_REMINDER
                ),
            )
        )
    return items


def write_worklist(
    items: Sequence[WorklistItem],
    path: str | Path,
    *,
    task: str,
    estimated_minutes: int | None = None,
) -> dict[str, Any]:
    """Write a worklist as JSONL plus a sibling manifest."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = "\n".join(
        json.dumps(item.to_dict(), ensure_ascii=False, sort_keys=True) for item in items
    )
    target.write_text(payload + "\n" if payload else "", encoding="utf-8")

    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    manifest = {
        "task": task,
        "items": len(items),
        "created_at": datetime.now(UTC).isoformat(),
        "roles": list(ROLES),
        "blind": True,
        "model_verdict_withheld": True,
        "prior_label_withheld": task == "relabel-audit",
        "estimated_minutes": estimated_minutes,
        "total_diff_bytes": sum(item.diff_bytes for item in items),
        "worklist_sha256": f"sha256:{digest}",
        "instructions": (
            "Set `role` to one of "
            + "/".join(ROLES)
            + " and `annotator_id` on every row, then save. Leave rows you "
            "cannot decide as `other` with a note rather than guessing."
        ),
    }
    manifest_path = target.with_name(target.stem + "-manifest.json")
    manifest_path.write_text(
        json.dumps(manifest, indent=1, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return manifest
