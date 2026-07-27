"""Read, classify and repair the GHSA evaluation bundle.

The bundle is a JSONL pair (``advisories.jsonl`` + ``commits.jsonl``) plus a
tree of ``.diff`` files. It is append-only: rows are frozen once written, since
GHSA advisories do not change after publication.

Two corrections live here relative to the original builder:

*Grouping.* Fix commits are keyed on ``(ghsa_id, host, repo, sha)``. The
builder keyed them on ``(host, repo, sha)`` alone, so when two advisories
cited the same commit the second one lost its row entirely — five advisories in
the 306-commit corpus ended up with no commits at all, and advisory-level recall
was reported over 176 advisories when the corpus holds 184.

*Stratification.* ``msg_class`` is recomputed through
:mod:`strata_eval.corpus.keywords`, whose boundary-anchored matching fixes the
six rows that were marked ``announced`` because ``rce`` matched inside
"enforce" and "source".
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .keywords import (
    CVE_OR_GHSA_RE,
    announcement_strength,
    count_matches,
    matched_keywords,
)

__all__ = [
    "MSG_CLASS_ANNOUNCED",
    "MSG_CLASS_EMPTY",
    "MSG_CLASS_MERGE_NOISE",
    "MSG_CLASS_QUIET",
    "Bundle",
    "CommitRow",
    "advisory_commit_refs",
    "classify_msg_class",
    "commit_key",
    "diff_leaks_disclosure",
    "extract_github_commit_refs",
]

MSG_CLASS_ANNOUNCED = "announced"
MSG_CLASS_QUIET = "quiet"
MSG_CLASS_EMPTY = "empty"
MSG_CLASS_MERGE_NOISE = "merge_noise"

GITHUB_COMMIT_URL_RE = re.compile(
    r"https?://(?:www\.)?github\.com/"
    r"(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)/"
    r"(?:commit|pull/\d+/commits)/(?P<sha>[0-9a-fA-F]{7,40})"
    r"(?:[/?#][^\s\"'<>)\]}>]*)?",
    re.IGNORECASE,
)

MERGE_SUBJECT_RE = re.compile(
    r"^(?:Merge (?:pull request|branch|remote-tracking branch|tag)\b|"
    r"Merge commit from fork)\b",
    re.IGNORECASE,
)


def commit_key(row: Mapping[str, Any]) -> tuple[str, str, str, str]:
    """Identity of a bundle row: ``(ghsa_id, host, repo, sha)``.

    The advisory id is part of the key because one commit legitimately fixes
    several advisories, and each pairing is a distinct row for grouping and for
    ``n_in_advisory``/``ordinal`` bookkeeping.
    """
    return (
        str(row.get("ghsa_id") or ""),
        str(row.get("host") or "github.com"),
        str(row.get("repo") or ""),
        str(row.get("sha") or "").lower(),
    )


def content_key(row: Mapping[str, Any]) -> tuple[str, str, str]:
    """Identity of the underlying *commit*, ignoring which advisory cites it.

    Used for diff caching and for de-duplicating model calls, never for
    grouping or for counting advisories.
    """
    return (
        str(row.get("host") or "github.com"),
        str(row.get("repo") or ""),
        str(row.get("sha") or "").lower(),
    )


def extract_github_commit_refs(text: str) -> list[dict[str, str]]:
    """Return unique GitHub commit references found in ``text``."""
    refs: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for match in GITHUB_COMMIT_URL_RE.finditer(text or ""):
        repo = f"{match.group('owner').lower()}/{match.group('repo').lower()}"
        sha = match.group("sha").lower()
        key = ("github.com", repo, sha)
        if key in seen:
            continue
        seen.add(key)
        refs.append({"host": "github.com", "repo": repo, "sha": sha, "url": match.group(0)})
    return refs


def advisory_commit_refs(advisory: Mapping[str, Any]) -> list[dict[str, str]]:
    """Extract GitHub commit refs from an advisory's details and references."""
    chunks: list[str] = [str(advisory.get("details") or "")]
    for ref in advisory.get("references") or []:
        if isinstance(ref, Mapping) and ref.get("url"):
            chunks.append(str(ref["url"]))
        elif isinstance(ref, str):
            chunks.append(ref)
    return extract_github_commit_refs("\n".join(chunks))


def classify_msg_class(message: str | None, *, is_merge: bool = False) -> str:
    """Assign ``announced|quiet|empty|merge_noise`` from a commit message.

    ``announced`` requires a full CVE/GHSA identifier or two distinct
    boundary-matched security keywords. One keyword alone stays ``quiet``,
    deliberately: contamination is accepted only in the direction that makes
    the headline stratum *harder*, not easier.
    """
    text = (message or "").strip()
    if not text:
        return MSG_CLASS_EMPTY
    subject = text.splitlines()[0].strip()
    if is_merge and MERGE_SUBJECT_RE.match(subject):
        return MSG_CLASS_MERGE_NOISE
    if CVE_OR_GHSA_RE.search(text):
        return MSG_CLASS_ANNOUNCED
    if count_matches(text) >= 2:
        return MSG_CLASS_ANNOUNCED
    return MSG_CLASS_QUIET


def diff_leaks_disclosure(diff: str) -> bool:
    """``True`` if an *added* diff line names a CVE or GHSA identifier.

    A commit whose message is quiet can still announce itself in a CHANGELOG
    hunk. Recall on such rows is not silent-fix recall, so they are reported
    separately as a leak-excluded rate.
    """
    for line in (diff or "").splitlines():
        if line.startswith("+") and not line.startswith("+++") and CVE_OR_GHSA_RE.search(line):
            return True
    return False


@dataclass(frozen=True, slots=True)
class CommitRow:
    """One (advisory, commit) pairing with its labels and enrichment."""

    ghsa_id: str
    host: str
    repo: str
    sha: str
    source: str
    role: str | None
    msg_class: str
    announcement_strength: str
    subject: str
    message: str
    diff_path: str | None
    diff_bytes: int
    is_merge: bool
    parent_count: int
    resolved: bool
    ordinal: int
    n_in_advisory: int
    lag_days: int | None
    raw: Mapping[str, Any] = field(repr=False, default_factory=dict)

    @property
    def key(self) -> tuple[str, str, str, str]:
        return (self.ghsa_id, self.host, self.repo, self.sha)

    @property
    def content_key(self) -> tuple[str, str, str]:
        return (self.host, self.repo, self.sha)

    @property
    def ghsa_referenced(self) -> bool:
        return self.source == "ghsa"

    def read_diff(self, root: Path) -> str:
        if not self.diff_path:
            return ""
        candidate = root / self.diff_path
        if not candidate.is_file():
            return ""
        return candidate.read_text(encoding="utf-8", errors="replace")


def _read_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    if not path.is_file():
        return
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                yield json.loads(line)


@dataclass(slots=True)
class Bundle:
    """An on-disk GHSA evaluation bundle."""

    root: Path
    advisories: list[dict[str, Any]]
    commits: list[CommitRow]

    @classmethod
    def load(cls, root: str | Path, *, reclassify: bool = True) -> Bundle:
        """Load a bundle, optionally recomputing ``msg_class``.

        Args:
            root: Directory holding ``advisories.jsonl`` and ``commits.jsonl``.
            reclassify: Recompute ``msg_class`` with the current keyword table
                rather than trusting the value frozen at build time. Defaults
                to ``True`` because the stored values were produced by the
                substring matcher.
        """
        base = Path(root)
        advisories = list(_read_jsonl(base / "advisories.jsonl"))
        raw_rows = list(_read_jsonl(base / "commits.jsonl"))

        # Recompute ordinal / n_in_advisory from the rows actually present so
        # the values stay consistent with the (ghsa_id, ...) key.
        per_advisory: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in raw_rows:
            per_advisory[str(row.get("ghsa_id") or "")].append(row)

        commits: list[CommitRow] = []
        for advisory_id, group in per_advisory.items():
            for ordinal, row in enumerate(group):
                message = str(row.get("message") or "")
                subject = str(row.get("subject") or (message.splitlines() or [""])[0])
                is_merge = bool(row.get("is_merge"))
                msg_class = (
                    classify_msg_class(message or subject, is_merge=is_merge)
                    if reclassify
                    else str(row.get("msg_class") or MSG_CLASS_QUIET)
                )
                commits.append(
                    CommitRow(
                        ghsa_id=advisory_id,
                        host=str(row.get("host") or "github.com"),
                        repo=str(row.get("repo") or ""),
                        sha=str(row.get("sha") or "").lower(),
                        source=str(row.get("source") or "ghsa"),
                        role=row.get("role"),
                        msg_class=msg_class,
                        announcement_strength=announcement_strength(message or subject),
                        subject=subject,
                        message=message,
                        diff_path=row.get("diff_path"),
                        diff_bytes=int(row.get("diff_bytes") or 0),
                        is_merge=is_merge,
                        parent_count=int(row.get("parent_count") or 1),
                        resolved=bool(row.get("resolved")),
                        ordinal=ordinal,
                        n_in_advisory=len(group),
                        lag_days=row.get("lag_days"),
                        raw=row,
                    )
                )
        return cls(root=base, advisories=advisories, commits=commits)

    # -- queries ---------------------------------------------------------

    @property
    def advisory_ids(self) -> set[str]:
        return {str(a.get("ghsa_id") or a.get("id") or "") for a in self.advisories} - {""}

    def advisories_without_commits(self) -> list[str]:
        """Advisory ids present in the index but carrying no commit row.

        A non-empty result means references were dropped during construction —
        the grouping bug this module exists to prevent.
        """
        with_rows = {row.ghsa_id for row in self.commits}
        return sorted(self.advisory_ids - with_rows)

    def labelled(self) -> list[CommitRow]:
        return [row for row in self.commits if row.role]

    def by_role(self, *roles: str) -> list[CommitRow]:
        wanted = set(roles)
        return [row for row in self.commits if row.role in wanted]

    def unique_commits(self) -> list[CommitRow]:
        """One row per underlying commit, keeping the first advisory pairing."""
        seen: set[tuple[str, str, str]] = set()
        out: list[CommitRow] = []
        for row in self.commits:
            if row.content_key in seen:
                continue
            seen.add(row.content_key)
            out.append(row)
        return out

    def stratum_counts(self) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        for row in self.commits:
            counts[row.msg_class] += 1
        return dict(counts)

    def reclassification_diff(self) -> list[dict[str, Any]]:
        """Rows whose stored ``msg_class`` disagrees with the current table.

        Each entry names the keywords responsible, so a stratum boundary change
        is reviewable rather than a silent shift in the denominator.
        """
        changes: list[dict[str, Any]] = []
        for row in self.commits:
            stored = str(row.raw.get("msg_class") or "")
            if stored and stored != row.msg_class:
                text = row.message or row.subject
                changes.append(
                    {
                        "ghsa_id": row.ghsa_id,
                        "repo": row.repo,
                        "sha": row.sha,
                        "subject": row.subject[:100],
                        "was": stored,
                        "now": row.msg_class,
                        "keywords": list(matched_keywords(text)),
                        "has_identifier": bool(CVE_OR_GHSA_RE.search(text)),
                    }
                )
        return changes


def apply_labels(
    commits: Sequence[CommitRow],
    labels: Iterable[Mapping[str, Any]],
) -> dict[tuple[str, str, str], str]:
    """Resolve an append-only label log to one role per commit.

    Last write wins, matching the documented behaviour of the label file. The
    returned mapping is keyed on the *content* key because a human decides
    about a commit, not about an (advisory, commit) pairing.
    """
    resolved: dict[tuple[str, str, str], str] = {}
    for record in labels:
        role = record.get("role")
        if not role:
            continue
        key = (
            str(record.get("host") or "github.com"),
            str(record.get("repo") or ""),
            str(record.get("sha") or "").lower(),
        )
        resolved[key] = str(role)
    return resolved
