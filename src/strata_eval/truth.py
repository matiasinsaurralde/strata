"""Frozen ground truth and a scorer, so pipeline changes are measurable in seconds.

Every measurement in this project so far has cost a multi-agent panel run and
real money, which means changes get evaluated in batches and their effects
confound. This module turns the adjudicated commits from the four-repository
matrix into a fixture, and scoring against it is free.

**What the fixture is.** A commit-level role assignment for every commit that
this pipeline, or another tool it was compared against, claimed as a security
fix — adjudicated by LLM panels working from bare mirrors. Two panels overlapped on 13 commits and agreed on 12 roles
(and on all 13 for the binary fix-vs-not question), so the labels are at least
reproducible. The adversarial gin panel — investigator plus a refuter per
commit — takes precedence where the two disagree.

**What the fixture is not.** Human ground truth, and not a random sample. It
covers only commits *some tool flagged*, so:

* Recall here is recall over that union, not over all real fixes. A change that
  finds a fix neither tool ever claimed scores zero for it.
* Precision is measured only over commits the fixture knows. Findings outside
  it are reported as ``unscored`` rather than silently counted either way.

Both properties are stable across runs, which is what a regression harness
needs. Treat the absolute numbers as comparable to each other and not as
estimates of field performance.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from strata.resources import repo_root

__all__ = [
    "DEFAULT_TRUTH_PATH",
    "RepoScore",
    "ScoreReport",
    "TruthEntry",
    "TruthSet",
    "score_artifacts",
]

DEFAULT_TRUTH_PATH = repo_root() / "tests" / "fixtures" / "matrix-truth.json"

#: Roles that count as a genuine security fix. Everything else — a commit that
#: created the surface, hardening with no pre-existing exploitable state, a
#: backport, an unrelated change — is not something the pipeline should emit.
FIX_ROLES = frozenset({"fix"})


@dataclass(frozen=True, slots=True)
class TruthEntry:
    sha: str
    repo: str
    role: str
    confidence: str
    source: str
    subject: str = ""
    rationale: str = ""

    @property
    def is_fix(self) -> bool:
        return self.role in FIX_ROLES

    def to_dict(self) -> dict[str, Any]:
        return {
            "sha": self.sha,
            "repo": self.repo,
            "role": self.role,
            "confidence": self.confidence,
            "source": self.source,
            "subject": self.subject,
            "rationale": self.rationale,
        }


@dataclass(frozen=True, slots=True)
class TruthSet:
    entries: tuple[TruthEntry, ...]

    @classmethod
    def load(cls, path: str | Path = DEFAULT_TRUTH_PATH) -> TruthSet:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            entries=tuple(
                TruthEntry(
                    sha=row["sha"],
                    repo=row["repo"],
                    role=row["role"],
                    confidence=row.get("confidence", "medium"),
                    source=row.get("source", "unknown"),
                    subject=row.get("subject", ""),
                    rationale=row.get("rationale", ""),
                )
                for row in payload["entries"]
            )
        )

    def for_repo(self, repo: str) -> dict[str, TruthEntry]:
        return {e.sha: e for e in self.entries if e.repo == repo}

    @property
    def repos(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(e.repo for e in self.entries))


@dataclass(slots=True)
class RepoScore:
    repo: str
    emitted: int = 0
    true_positives: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    missed: list[str] = field(default_factory=list)
    unscored: list[str] = field(default_factory=list)

    @property
    def known_emitted(self) -> int:
        return len(self.true_positives) + len(self.false_positives)

    @property
    def precision(self) -> float | None:
        return len(self.true_positives) / self.known_emitted if self.known_emitted else None

    @property
    def recall(self) -> float | None:
        total = len(self.true_positives) + len(self.missed)
        return len(self.true_positives) / total if total else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo": self.repo,
            "emitted": self.emitted,
            "true_positives": sorted(self.true_positives),
            "false_positives": sorted(self.false_positives),
            "missed": sorted(self.missed),
            "unscored": sorted(self.unscored),
            "precision": self.precision,
            "recall": self.recall,
        }


@dataclass(slots=True)
class ScoreReport:
    per_repo: list[RepoScore]
    label: str = ""

    @property
    def true_positives(self) -> int:
        return sum(len(r.true_positives) for r in self.per_repo)

    @property
    def false_positives(self) -> int:
        return sum(len(r.false_positives) for r in self.per_repo)

    @property
    def missed(self) -> int:
        return sum(len(r.missed) for r in self.per_repo)

    @property
    def unscored(self) -> int:
        return sum(len(r.unscored) for r in self.per_repo)

    @property
    def precision(self) -> float | None:
        known = self.true_positives + self.false_positives
        return self.true_positives / known if known else None

    @property
    def recall(self) -> float | None:
        total = self.true_positives + self.missed
        return self.true_positives / total if total else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "precision": self.precision,
            "recall": self.recall,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "missed": self.missed,
            "unscored": self.unscored,
            "per_repo": [r.to_dict() for r in self.per_repo],
        }

    def render(self) -> str:
        lines = [
            f"{'repo':22} {'emit':>5} {'TP':>4} {'FP':>4} {'miss':>5} {'unsc':>5} "
            f"{'prec':>6} {'recall':>7}"
        ]
        lines.append("-" * 68)
        for r in self.per_repo:
            prec = f"{r.precision:.0%}" if r.precision is not None else "  -"
            rec = f"{r.recall:.0%}" if r.recall is not None else "  -"
            lines.append(
                f"{r.repo:22} {r.emitted:>5} {len(r.true_positives):>4} "
                f"{len(r.false_positives):>4} {len(r.missed):>5} {len(r.unscored):>5} "
                f"{prec:>6} {rec:>7}"
            )
        prec = f"{self.precision:.0%}" if self.precision is not None else "-"
        rec = f"{self.recall:.0%}" if self.recall is not None else "-"
        lines.append("-" * 68)
        lines.append(
            f"{'TOTAL':22} {'':>5} {self.true_positives:>4} {self.false_positives:>4} "
            f"{self.missed:>5} {self.unscored:>5} {prec:>6} {rec:>7}"
        )
        return "\n".join(lines)

    def diff_against(self, other: ScoreReport) -> str:
        """Render the change relative to a previous report."""

        def delta(new: float | None, old: float | None) -> str:
            if new is None or old is None:
                return "  n/a"
            points = (new - old) * 100
            return f"{points:+5.1f}pp"

        gained = sorted(
            {s for r in self.per_repo for s in r.true_positives}
            - {s for r in other.per_repo for s in r.true_positives}
        )
        lost = sorted(
            {s for r in other.per_repo for s in r.true_positives}
            - {s for r in self.per_repo for s in r.true_positives}
        )
        fixed = sorted(
            {s for r in other.per_repo for s in r.false_positives}
            - {s for r in self.per_repo for s in r.false_positives}
        )
        introduced = sorted(
            {s for r in self.per_repo for s in r.false_positives}
            - {s for r in other.per_repo for s in r.false_positives}
        )
        return "\n".join(
            [
                f"precision {other.precision or 0:.0%} -> {self.precision or 0:.0%}  "
                f"({delta(self.precision, other.precision)})",
                f"recall    {other.recall or 0:.0%} -> {self.recall or 0:.0%}  "
                f"({delta(self.recall, other.recall)})",
                f"  true positives gained: {[s[:10] for s in gained] or 'none'}",
                f"  true positives LOST:   {[s[:10] for s in lost] or 'none'}",
                f"  false positives fixed: {[s[:10] for s in fixed] or 'none'}",
                f"  false positives ADDED: {[s[:10] for s in introduced] or 'none'}",
            ]
        )


def score_artifacts(
    artifacts: Mapping[str, Mapping[str, Any]] | Iterable[tuple[str, Mapping[str, Any]]],
    truth: TruthSet,
    *,
    label: str = "",
) -> ScoreReport:
    """Score compiled security-context artifacts against the fixture.

    Args:
        artifacts: Mapping of ``repo slug -> compiled artifact dict``.
        truth: The frozen ground truth.
        label: Free-form tag recorded in the report (e.g. a config name).
    """
    items = dict(artifacts)
    scores: list[RepoScore] = []
    for repo in truth.repos:
        known = truth.for_repo(repo)
        artifact = items.get(repo)
        # A finding re-attributed past a merge answers for BOTH shas: the
        # fixture may key on the merge (which is what the tools originally
        # claimed) while the pipeline now correctly reports the authoring
        # commit. Scoring only the new sha would record a true positive as
        # simultaneously missed and unscored.
        emitted: set[str] = set()
        aliases: dict[str, str] = {}
        for fingerprint in (artifact.get("fingerprints") or []) if artifact else []:
            sha = fingerprint["commit_sha"]
            origin = fingerprint.get("attributed_from")
            if origin and origin in known and sha not in known:
                emitted.add(origin)
                aliases[origin] = sha
            else:
                emitted.add(sha)
        score = RepoScore(repo=repo, emitted=len(emitted))
        for sha in emitted:
            entry = known.get(sha)
            if entry is None:
                score.unscored.append(sha)
            elif entry.is_fix:
                score.true_positives.append(sha)
            else:
                score.false_positives.append(sha)
        for sha, entry in known.items():
            if entry.is_fix and sha not in emitted:
                score.missed.append(sha)
        scores.append(score)
    return ScoreReport(per_repo=scores, label=label)


def build_truth(
    matrix_verdicts: Sequence[Mapping[str, Any]],
    panel_commits: Sequence[Mapping[str, Any]] = (),
) -> list[dict[str, Any]]:
    """Merge panel outputs into fixture rows.

    The adversarial panel (investigator plus a dedicated refuter per commit)
    outranks the single-pass matrix evaluation wherever both covered a commit.
    """
    rows: dict[str, dict[str, Any]] = {}
    for verdict in matrix_verdicts:
        rows[verdict["sha"]] = {
            "sha": verdict["sha"],
            "repo": verdict["repo"],
            "role": verdict["role"],
            "confidence": verdict.get("confidence", "medium"),
            "source": "matrix-panel",
            "subject": "",
            "rationale": verdict.get("why", "")[:400],
        }
    for commit in panel_commits:
        sha = commit["sha"]
        existing = rows.get(sha, {})
        rows[sha] = {
            "sha": sha,
            "repo": existing.get("repo", "gin-gonic/gin"),
            "role": commit["ground_truth_role"],
            "confidence": commit.get("confidence", "medium"),
            "source": "adversarial-panel",
            "subject": commit.get("subject", ""),
            "rationale": commit.get("rationale", "")[:400],
        }
    return sorted(rows.values(), key=lambda r: (r["repo"], r["sha"]))
