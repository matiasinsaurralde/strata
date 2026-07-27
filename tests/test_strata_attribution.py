"""Attribution and de-duplication.

Both defects this module exists to prevent were observed in shipped artifacts,
so each has a named test here:

* a finding left pointing at ``Merge pull request #216`` instead of the commit
  that wrote the code;
* the same one-line change emitted twice, once on a merge and once on the
  commit that merge brought in, which ``patch-id`` structurally cannot catch.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from strata.attribution import apply, deduplicate, resolve_attribution


@dataclass
class _Change:
    path: str


@dataclass
class _Commit:
    sha: str
    parents: tuple[str, ...] = ()
    patch: bytes = b""
    patch_id: str | None = None
    message: str = ""

    @property
    def parent_sha(self) -> str | None:
        return self.parents[0] if self.parents else None


@dataclass
class FakeRepo:
    """A commit graph small enough to reason about, with the same API surface."""

    commits: dict[str, _Commit] = field(default_factory=dict)
    paths: dict[str, list[str]] = field(default_factory=dict)
    ranges: dict[str, list[str]] = field(default_factory=dict)
    blobs: dict[tuple[str, str], str] = field(default_factory=dict)

    def get_commit_metadata(self, sha: str) -> _Commit:
        return self.commits[sha]

    def get_commit(self, sha: str) -> _Commit:
        return self.commits[sha]

    def changed_paths(self, sha: str) -> list[_Change]:
        return [_Change(p) for p in self.paths.get(sha, [])]

    def enumerate_shas(self, *, revision_range: str) -> list[str]:
        return list(self.ranges.get(revision_range, []))

    def read_range(self, sha: str, path: str, start: int, end: int) -> str:
        return self.blobs.get((sha, path), "")


def _patch(*added: str) -> bytes:
    body = "--- a/parser.go\n+++ b/parser.go\n@@ -1 +1 @@\n"
    return (body + "".join(f"+{line}\n" for line in added)).encode()


@pytest.fixture
def pull_request() -> FakeRepo:
    """A merge carrying two commits that both touch the same file.

    This is the ordinary pull-request shape — one substantive commit plus a
    cleanup — and the shape that defeats path-based attribution.
    """
    return FakeRepo(
        commits={
            "merge": _Commit(
                "merge", parents=("base", "tip"), patch=_patch("cleanup()", "fix()")
            ),
            "cleanup": _Commit("cleanup", parents=("base",), patch=_patch("cleanup()")),
            "tip": _Commit("tip", parents=("cleanup",), patch=_patch("fix()")),
        },
        paths={"merge": ["parser.go"], "cleanup": ["parser.go"], "tip": ["parser.go"]},
        ranges={"base..merge": ["merge", "cleanup", "tip"]},
    )


class TestResolveAttribution:
    def test_a_non_merge_stays_put(self, pull_request):
        result = resolve_attribution(
            {"commit_sha": "tip", "affected_paths": ["parser.go"]}, pull_request
        )
        assert not result.moved
        assert result.method == "direct"

    def test_a_merge_moves_to_the_single_commit_touching_the_path(self):
        repo = FakeRepo(
            commits={
                "merge": _Commit("merge", parents=("base", "tip")),
                "tip": _Commit("tip", parents=("base",)),
                "docs": _Commit("docs", parents=("base",)),
            },
            paths={"tip": ["parser.go"], "docs": ["README.md"]},
            ranges={"base..merge": ["merge", "tip", "docs"]},
        )
        result = resolve_attribution(
            {"commit_sha": "merge", "affected_paths": ["parser.go"]}, repo
        )
        assert result.sha == "tip"
        assert result.method == "merge_first_parent_walk"

    def test_two_commits_on_one_path_are_split_by_the_cited_content(self, pull_request):
        """Line numbers cannot decide this; the quoted span can.

        The candidates are sequential, so a range anchored in the merge's tree
        has already drifted relative to the earlier one. Content has not
        drifted.
        """
        finding = {
            "commit_sha": "merge",
            "affected_paths": ["parser.go"],
            "evidence": [{"revision": "commit", "path": "parser.go", "quoted_span": "fix()"}],
        }
        result = resolve_attribution(finding, pull_request)
        assert result.sha == "tip"
        assert result.method == "merge_evidence_content"

    def test_content_disambiguation_picks_the_cleanup_when_that_is_what_was_cited(
        self, pull_request
    ):
        finding = {
            "commit_sha": "merge",
            "affected_paths": ["parser.go"],
            "evidence": [
                {"revision": "commit", "path": "parser.go", "quoted_span": "cleanup()"}
            ],
        }
        assert resolve_attribution(finding, pull_request).sha == "cleanup"

    def test_ambiguity_without_usable_evidence_declines_the_move(self, pull_request):
        finding = {"commit_sha": "merge", "affected_paths": ["parser.go"]}
        result = resolve_attribution(finding, pull_request)
        assert not result.moved
        assert result.method == "ambiguous"

    def test_parent_side_anchors_do_not_disambiguate(self, pull_request):
        # A parent-side anchor quotes code the commit REMOVED, so it appears in
        # no candidate's additions and proves nothing about authorship.
        finding = {
            "commit_sha": "merge",
            "affected_paths": ["parser.go"],
            "evidence": [{"revision": "parent", "path": "parser.go", "quoted_span": "fix()"}],
        }
        assert resolve_attribution(finding, pull_request).method == "ambiguous"

    def test_a_large_integration_merge_is_declined_rather_than_guessed(self):
        repo = FakeRepo(
            commits={"merge": _Commit("merge", parents=("base", "tip"))},
            ranges={"base..merge": ["merge"] + [f"c{i}" for i in range(30)]},
        )
        result = resolve_attribution({"commit_sha": "merge", "affected_paths": ["a.go"]}, repo)
        assert result.method == "declined"
        assert "30 commits" in result.note

    def test_a_broken_object_loses_neither_the_finding_nor_the_run(self):
        class Broken:
            def get_commit_metadata(self, sha):
                raise OSError("packfile corrupt")

        result = resolve_attribution({"commit_sha": "x"}, Broken())
        assert result.sha == "x"
        assert not result.moved


class TestDeduplicate:
    def test_identical_patch_ids_collapse(self):
        repo = FakeRepo(
            commits={
                "a": _Commit("a", parents=("base",), patch_id="same"),
                "b": _Commit("b", parents=("base",), patch_id="same"),
            }
        )
        kept, dropped = deduplicate([{"commit_sha": "a"}, {"commit_sha": "b"}], repo)
        assert len(kept) == 1
        assert len(dropped) == 1
        assert dropped[0]["duplicate_of"] == kept[0]["commit_sha"]

    def test_distinct_patches_both_survive(self):
        repo = FakeRepo(
            commits={
                "a": _Commit("a", parents=("base",), patch_id="one"),
                "b": _Commit("b", parents=("base",), patch_id="two"),
            }
        )
        kept, dropped = deduplicate([{"commit_sha": "a"}, {"commit_sha": "b"}], repo)
        assert len(kept) == 2
        assert not dropped

    def test_a_merge_folds_into_a_child_it_brought_in(self, pull_request):
        """patch-id cannot catch this and never will.

        A pull request usually carries more than one commit, so the merge's
        combined diff genuinely differs from any single child's and the two
        ids are correctly different. Observed shipping in the jsonparser
        artifact as 49146d0820 alongside 837dfaa128.
        """
        pull_request.commits["merge"].patch_id = "merge-id"
        pull_request.commits["tip"].patch_id = "tip-id"
        kept, dropped = deduplicate(
            [
                {"commit_sha": "merge", "affected_paths": ["parser.go"]},
                {"commit_sha": "tip", "affected_paths": ["parser.go"]},
            ],
            pull_request,
        )
        assert [f["commit_sha"] for f in kept] == ["tip"]
        assert dropped[0]["commit_sha"] == "merge"
        assert dropped[0]["reason"] == "merge_of_emitted_child"

    def test_the_child_wins_because_it_carries_the_authors_subject(self, pull_request):
        pull_request.commits["merge"].patch_id = "merge-id"
        pull_request.commits["tip"].patch_id = "tip-id"
        kept, _ = deduplicate(
            [
                {"commit_sha": "tip", "affected_paths": ["parser.go"]},
                {"commit_sha": "merge", "affected_paths": ["parser.go"]},
            ],
            pull_request,
        )
        assert [f["commit_sha"] for f in kept] == ["tip"]

    def test_an_unrelated_fix_riding_the_same_merge_is_not_swallowed(self, pull_request):
        pull_request.commits["merge"].patch_id = "merge-id"
        pull_request.commits["tip"].patch_id = "tip-id"
        pull_request.paths["tip"] = ["other.go"]
        kept, dropped = deduplicate(
            [
                {"commit_sha": "merge", "affected_paths": ["parser.go"]},
                {"commit_sha": "tip", "affected_paths": ["other.go"]},
            ],
            pull_request,
        )
        assert len(kept) == 2
        assert not dropped

    def test_a_merge_with_no_emitted_child_survives(self, pull_request):
        pull_request.commits["merge"].patch_id = "merge-id"
        kept, dropped = deduplicate(
            [{"commit_sha": "merge", "affected_paths": ["parser.go"]}], pull_request
        )
        assert len(kept) == 1
        assert not dropped


class TestApply:
    def test_attribution_runs_before_dedup_so_the_pair_collapses(self):
        """Order matters: attribution can land two findings on one commit.

        Doing it the other way round leaves the pair intact.
        """
        repo = FakeRepo(
            commits={
                "merge": _Commit("merge", parents=("base", "tip"), patch_id="merge-id"),
                "tip": _Commit("tip", parents=("base",), patch_id="tip-id"),
            },
            paths={"merge": ["parser.go"], "tip": ["parser.go"]},
            ranges={"base..merge": ["merge", "tip"]},
        )
        kept, moves, dropped = apply(
            [
                {"commit_sha": "merge", "affected_paths": ["parser.go"]},
                {"commit_sha": "tip", "affected_paths": ["parser.go"]},
            ],
            repo,
        )
        assert [f["commit_sha"] for f in kept] == ["tip"]
        assert moves and moves[0]["sha"] == "tip"
        # The fold is reported, not silently discarded -- and it reads
        # correctly. The dropped entry keeps `attributed_from` so the record
        # says "the finding that came from `merge` folded into `tip`" rather
        # than the uninformative "tip is a duplicate of tip".
        assert len(dropped) == 1
        assert dropped[0]["attributed_from"] == "merge"
        assert dropped[0]["duplicate_of"] == "tip"

    def test_a_move_that_breaks_an_anchor_is_declined(self):
        """Correct attribution with broken provenance is worse than a merge.

        Observed in production as a 48-line offset once the anchor was
        re-based onto the real parent.
        """
        repo = FakeRepo(
            commits={
                "merge": _Commit("merge", parents=("base", "tip")),
                "tip": _Commit("tip", parents=("base",)),
            },
            paths={"tip": ["parser.go"]},
            ranges={"base..merge": ["merge", "tip"]},
            blobs={("tip", "parser.go"): "something else entirely"},
        )
        finding = {
            "commit_sha": "merge",
            "affected_paths": ["parser.go"],
            "evidence": [
                {
                    "revision": "commit",
                    "revision_sha": "merge",
                    "path": "parser.go",
                    "start_line": 1,
                    "end_line": 1,
                    "quoted_span": "the cited line",
                }
            ],
        }
        kept, moves, _ = apply([finding], repo)
        assert kept[0]["commit_sha"] == "merge"
        assert kept[0]["attribution_method"] == "declined_anchor_mismatch"
        assert not moves

    def test_a_move_whose_anchor_still_matches_is_taken(self):
        repo = FakeRepo(
            commits={
                "merge": _Commit("merge", parents=("base", "tip")),
                "tip": _Commit("tip", parents=("base",)),
            },
            paths={"tip": ["parser.go"]},
            ranges={"base..merge": ["merge", "tip"]},
            blobs={("tip", "parser.go"): "the cited line"},
        )
        finding = {
            "commit_sha": "merge",
            "affected_paths": ["parser.go"],
            "evidence": [
                {
                    "revision": "commit",
                    "revision_sha": "merge",
                    "path": "parser.go",
                    "start_line": 1,
                    "end_line": 1,
                    "quoted_span": "the cited line",
                }
            ],
        }
        kept, moves, _ = apply([finding], repo)
        assert kept[0]["commit_sha"] == "tip"
        assert kept[0]["attributed_from"] == "merge"
        assert kept[0]["evidence"][0]["revision_sha"] == "tip"
        assert moves
