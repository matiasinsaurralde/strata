"""Attribute findings to the commit that made the change, and collapse duplicates.

Three of five false positives in the four-repository matrix came from merge
commits, and one pair was the *same one-line change* counted twice — a merge and
the commit it brought in, both emitted as separate findings. The data needed to
prevent that was already being computed and thrown away: ``GitCommit.patch_id``
is a stable hash of the diff content, independent of SHA, author and date.

Two operations here, in order:

``resolve_attribution``
    When a finding lands on a merge, walk into the branch it merged and find the
    commit that actually carries the change. A merge subject
    (``Merge pull request #213 from techjanitor/develop``) tells a reviewer
    nothing and makes the finding's provenance point at integration rather than
    at authorship.

``deduplicate``
    Collapse findings whose patches are identical. Cherry-picks, backports and
    merge/original pairs all share a patch-id.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

LOGGER = logging.getLogger(__name__)

__all__ = ["Attribution", "deduplicate", "resolve_attribution"]

#: A merge that brought in more than this many commits is a release or
#: long-running-branch integration. Picking "the" substantive commit out of it
#: is guesswork, so attribution is declined rather than guessed.
MAX_MERGE_FANIN = 25


@dataclass(frozen=True, slots=True)
class Attribution:
    """Where a finding should point, and why."""

    sha: str
    original_sha: str
    method: str
    note: str = ""

    @property
    def moved(self) -> bool:
        return self.sha != self.original_sha

    def to_dict(self) -> dict[str, Any]:
        return {
            "sha": self.sha,
            "original_sha": self.original_sha,
            "method": self.method,
            "note": self.note,
        }


def _paths_of(finding: Mapping[str, Any]) -> set[str]:
    paths = {str(p) for p in finding.get("affected_paths") or () if str(p).strip()}
    for anchor in finding.get("evidence") or ():
        if isinstance(anchor, Mapping) and anchor.get("path"):
            paths.add(str(anchor["path"]))
    return paths


def resolve_attribution(
    finding: Mapping[str, Any],
    repository: Any,
) -> Attribution:
    """Point a finding at the commit that carries its change.

    For a merge, ``git rev-list <first-parent>..<merge>`` yields the commits it
    brought in. When exactly one of them touches the finding's anchored paths,
    that is the author's commit and the finding moves there. Ambiguity — zero
    candidates, several, or a large integration merge — leaves the finding where
    it is, with the reason recorded.

    Returns:
        An :class:`Attribution`; check ``.moved`` to see whether it changed.
    """
    sha = str(finding.get("commit_sha") or "")
    if not sha or repository is None:
        return Attribution(sha, sha, "unchanged", "no repository available")

    try:
        commit = repository.get_commit_metadata(sha)
    except Exception as exc:  # a broken object must not lose the finding
        LOGGER.debug("attribution: cannot read %s: %s", sha[:12], exc)
        return Attribution(sha, sha, "unchanged", "commit metadata unavailable")

    parents = tuple(getattr(commit, "parents", ()) or ())
    if len(parents) < 2:
        return Attribution(sha, sha, "direct", "not a merge")

    try:
        brought_in = repository.enumerate_shas(revision_range=f"{parents[0]}..{sha}")
    except Exception as exc:
        LOGGER.debug("attribution: cannot walk %s: %s", sha[:12], exc)
        return Attribution(sha, sha, "unchanged", "merge range unavailable")

    candidates = [candidate for candidate in brought_in if candidate != sha]
    if not candidates:
        return Attribution(sha, sha, "unchanged", "merge brought in no commits")
    if len(candidates) > MAX_MERGE_FANIN:
        return Attribution(
            sha,
            sha,
            "declined",
            f"integration merge of {len(candidates)} commits; attribution would be a guess",
        )

    wanted = _paths_of(finding)
    if not wanted:
        return Attribution(sha, sha, "unchanged", "finding has no anchored paths")

    matches: list[str] = []
    for candidate in candidates:
        try:
            touched = {p.path for p in repository.changed_paths(candidate)}
        except Exception:
            continue
        if touched & wanted:
            matches.append(candidate)

    if len(matches) == 1:
        return Attribution(
            matches[0],
            sha,
            "merge_first_parent_walk",
            f"the one commit in {sha[:12]} touching {sorted(wanted)[0]}",
        )
    if not matches:
        return Attribution(sha, sha, "unchanged", "no merged commit touches the anchored paths")

    # Several commits in the merge touch the same file, which is the common
    # case for a pull request: one substantive commit plus a cleanup. Paths
    # cannot separate them, but the evidence can — exactly one of them added
    # the line the finding cites.
    author = _disambiguate_by_content(finding, matches, repository)
    if author is not None:
        return Attribution(
            author,
            sha,
            "merge_evidence_content",
            f"the one commit in {sha[:12]} that added the cited line",
        )
    return Attribution(
        sha,
        sha,
        "ambiguous",
        f"{len(matches)} merged commits touch the anchored paths",
    )


def _added_lines(patch: bytes | str) -> set[str]:
    """Whitespace-normalised text of every line a patch adds."""
    text = patch.decode("utf-8", "replace") if isinstance(patch, bytes) else patch
    return {
        " ".join(line[1:].split())
        for line in text.splitlines()
        if line.startswith("+") and not line.startswith("+++") and line[1:].strip()
    }


def _disambiguate_by_content(
    finding: Mapping[str, Any],
    candidates: Sequence[str],
    repository: Any,
) -> str | None:
    """Pick the merged commit that actually introduced the cited code.

    Line numbers cannot decide this: the candidates are sequential, so a
    range anchored in the merge's tree has already drifted relative to the
    earlier of them. The quoted span has not drifted — it is content. So the
    question becomes "whose patch contains this line as an addition?", which
    is drift-proof and is the same signal ``git log -S`` uses.

    Returns the sole candidate accounting for the commit-side evidence, or
    ``None`` when zero or several do.
    """
    spans = {
        " ".join(str(anchor.get("quoted_span", "")).split())
        for anchor in finding.get("evidence") or ()
        if isinstance(anchor, Mapping)
        and str(anchor.get("revision") or "commit") == "commit"
        and str(anchor.get("quoted_span", "")).strip()
    }
    if not spans:
        return None

    authors: set[str] = set()
    for candidate in candidates:
        try:
            added = _added_lines(repository.get_commit(candidate).patch)
        except Exception as exc:
            LOGGER.debug("attribution: no patch for %s: %s", candidate[:12], exc)
            return None
        if any(span in added for span in spans):
            authors.add(candidate)
    return authors.pop() if len(authors) == 1 else None


def deduplicate(
    findings: Sequence[Mapping[str, Any]],
    repository: Any,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Collapse findings whose patches are byte-identical.

    ``git patch-id --stable`` hashes the diff content only, so a merge and the
    commit it brought in — or a cherry-pick and its original — produce the same
    id despite different SHAs. Grouping on it removes an entire class of double
    count that no amount of prompt work would catch.

    Returns:
        ``(kept, dropped)``. Each dropped entry records the survivor it folded
        into, so the artifact can report duplicates rather than hide them.
    """
    kept: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []
    by_patch: dict[str, dict[str, Any]] = {}

    for finding in findings:
        row = dict(finding)
        sha = str(row.get("commit_sha") or "")
        patch_id: str | None = None
        if repository is not None and sha:
            try:
                patch_id = repository.get_commit(sha).patch_id
            except Exception as exc:
                LOGGER.debug("dedup: no patch-id for %s: %s", sha[:12], exc)

        if not patch_id:
            kept.append(row)
            continue

        winner = by_patch.get(patch_id)
        if winner is None:
            row["patch_id"] = patch_id
            by_patch[patch_id] = row
            kept.append(row)
            continue

        # Same change, two commits. Prefer the one with more verified anchors,
        # then the one that was NOT re-attributed -- its anchors were verified
        # against this commit's own tree rather than rebased onto it -- and on
        # a remaining tie the earlier SHA, so the choice is deterministic.
        #
        # The un-moved preference also keeps the audit readable. Without it,
        # dropping the native finding in favour of a re-pointed merge produces
        # a record that says "tip is a duplicate of tip", because only the
        # survivor carries `attributed_from`.
        def rank(finding: Mapping[str, Any], finding_sha: str) -> tuple[int, int, str]:
            return (
                len(finding.get("evidence") or ()),
                0 if finding.get("attributed_from") else 1,
                # Reversed via the comparison below: earlier SHA wins ties.
                finding_sha,
            )

        challenger = rank(row, sha)
        incumbent = rank(winner, str(winner.get("commit_sha")))
        if (challenger[0], challenger[1], incumbent[2]) > (
            incumbent[0],
            incumbent[1],
            challenger[2],
        ):
            kept[kept.index(winner)] = row
            row["patch_id"] = patch_id
            by_patch[patch_id] = row
            dropped.append(_duplicate_record(winner, row, patch_id))
        else:
            dropped.append(_duplicate_record(row, winner, patch_id))

    kept, ancestry_dropped = _collapse_merge_ancestry(kept, repository)
    return kept, dropped + ancestry_dropped


def _collapse_merge_ancestry(
    findings: Sequence[Mapping[str, Any]],
    repository: Any,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Fold a merge finding into a finding on a commit that merge brought in.

    Patch-id cannot catch this pair and never will: a pull request usually
    carries more than one commit, so the merge's combined diff genuinely
    differs from any single child's, and the two ids are correctly different.
    Both were observed shipping in the jsonparser artifact — ``49146d0820``
    (a merge) alongside ``837dfaa128`` (the commit it merged), counted twice.

    The child wins. It carries the author's subject line rather than
    "Merge pull request #216", which is what a reviewer needs to see.
    """
    rows = [dict(f) for f in findings]
    if len(rows) < 2 or repository is None:
        return rows, []

    by_sha = {str(row.get("commit_sha") or ""): row for row in rows}
    superseded: dict[str, str] = {}

    for row in rows:
        sha = str(row.get("commit_sha") or "")
        if not sha or sha in superseded:
            continue
        try:
            parents = tuple(repository.get_commit_metadata(sha).parents or ())
            if len(parents) < 2:
                continue
            brought_in = set(repository.enumerate_shas(revision_range=f"{parents[0]}..{sha}"))
        except Exception as exc:
            LOGGER.debug("ancestry dedup: cannot walk %s: %s", sha[:12], exc)
            continue

        children = [other for other in by_sha if other != sha and other in brought_in]
        if not children:
            continue
        # Require a shared path so an unrelated fix that happened to ride the
        # same merge is not silently swallowed.
        wanted = _paths_of(row)
        for child in children:
            if not wanted or (wanted & _paths_of(by_sha[child])):
                superseded[sha] = child
                break

    if not superseded:
        return rows, []

    kept = [row for row in rows if str(row.get("commit_sha") or "") not in superseded]
    dropped = [
        _duplicate_record(by_sha[merge], by_sha[child], patch_id="")
        | {"reason": "merge_of_emitted_child"}
        for merge, child in superseded.items()
    ]
    return kept, dropped


def _rebase_anchors(
    finding: Mapping[str, Any],
    attribution: Attribution,
    repository: Any,
) -> dict[str, Any] | None:
    """Re-point ``commit``-side anchors at the destination and re-verify them.

    Returns ``None`` when any quoted span no longer matches at the new
    revision, which is the signal to abandon the move.
    """
    row = dict(finding)
    anchors = row.get("evidence") or ()
    if not anchors:
        return row

    try:
        parent = repository.get_commit_metadata(attribution.sha).parents[0]
    except Exception:
        parent = None

    rebased: list[dict[str, Any]] = []
    for anchor in anchors:
        if not isinstance(anchor, Mapping):
            return None
        item = dict(anchor)
        kind = str(item.get("revision") or "commit")
        if kind == "commit":
            item["revision_sha"] = attribution.sha
        elif kind == "parent":
            if parent is None:
                return None
            item["revision_sha"] = parent
        else:  # a head anchor is revision-independent of this move
            rebased.append(item)
            continue

        try:
            text = repository.read_range(
                item["revision_sha"],
                item["path"],
                int(item["start_line"]),
                int(item["end_line"]),
            )
        except Exception:
            return None
        body = text.decode("utf-8", "replace") if isinstance(text, bytes) else str(text)
        needle = " ".join(str(item.get("quoted_span", "")).split())
        if not needle or needle not in " ".join(body.split()):
            return None
        rebased.append(item)

    row["evidence"] = rebased
    return row


def _duplicate_record(
    loser: Mapping[str, Any],
    winner: Mapping[str, Any],
    patch_id: str,
) -> dict[str, Any]:
    """Describe a collapsed duplicate.

    ``attributed_from`` is carried through so a merge that was re-pointed onto
    its own child does not read as "X folded into X".
    """
    return {
        "commit_sha": loser.get("commit_sha"),
        "attributed_from": loser.get("attributed_from"),
        "duplicate_of": winner.get("commit_sha"),
        "patch_id": patch_id,
    }


def apply(
    findings: Iterable[Mapping[str, Any]],
    repository: Any,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Re-attribute then de-duplicate.

    Order matters: attribution can move two findings onto the same underlying
    commit, and dedup then collapses them. Doing it the other way round leaves
    the pair intact.

    Returns:
        ``(findings, moves, duplicates)``.
    """
    moved: list[dict[str, Any]] = []
    rewritten: list[dict[str, Any]] = []
    for finding in findings:
        attribution = resolve_attribution(finding, repository)
        row = dict(finding)
        if attribution.moved:
            # Anchors were verified against the ORIGINAL commit's tree. Moving
            # commit_sha without moving them leaves a finding whose evidence
            # cites a different revision -- observed in production output as a
            # 48-line offset once the anchor was re-based onto the real parent.
            # Re-verify at the destination and decline the move if it does not
            # hold: a correctly attributed finding with broken provenance is
            # worse than a well-evidenced one pointing at a merge.
            rebased = _rebase_anchors(row, attribution, repository)
            if rebased is None:
                row["attribution_method"] = "declined_anchor_mismatch"
                rewritten.append(row)
                continue
            row = rebased
            row["commit_sha"] = attribution.sha
            row["attributed_from"] = attribution.original_sha
            moved.append(attribution.to_dict())
        row["attribution_method"] = attribution.method
        rewritten.append(row)
    kept, dropped = deduplicate(rewritten, repository)
    return kept, moved, dropped
