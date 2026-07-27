"""Deterministic introduced-to-fixed span attribution.

Blame the pre-fix lines a fix touched, take the oldest last-touch as the
introduction, and report the span in days -- declining (null span) rather than
guessing when there is no signal or the code predates the file. Each behaviour
the stage promises has a named test here.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from strata.introduction import attribute_introductions


@dataclass
class _BlameLine:
    revision: str


@dataclass
class _Commit:
    sha: str
    committer_time: str
    is_root: bool = False


@dataclass
class FakeRepo:
    """A minimal repo exposing just blame + get_commit.

    ``blame_map`` maps ``(parent_sha, path, start, end)`` to a list of
    last-touch SHAs; ``commits`` dates them. A ``raise_blame`` set forces a
    blame failure for a span, to exercise the broken-object decline path.
    """

    blame_map: dict[tuple[str, str, int, int], list[str]] = field(default_factory=dict)
    commits: dict[str, _Commit] = field(default_factory=dict)
    raise_blame: set[tuple[str, str, int, int]] = field(default_factory=set)

    def blame(self, revision, path, *, start_line=1, end_line=None, max_lines=400):
        key = (revision, path, start_line, end_line)
        if key in self.raise_blame:
            raise RuntimeError("missing git object")
        return [_BlameLine(sha) for sha in self.blame_map.get(key, [])]

    def get_commit(self, revision):
        return self.commits[revision]


def _finding(fix_date, *anchors):
    """A finding dict with parent-revision evidence rows (the pre-fix lines)."""
    evidence = [
        {
            "revision": "parent",
            "revision_sha": p,
            "path": path,
            "start_line": s,
            "end_line": e,
        }
        for (p, path, s, e) in anchors
    ]
    return {"commit_sha": "fixsha", "commit_date": fix_date, "evidence": evidence}


def _one(repo, finding):
    return attribute_introductions([finding], repo)[0]


def test_clean_span_from_a_single_blamed_commit():
    repo = FakeRepo(
        blame_map={("parent", "a.go", 10, 10): ["intro"]},
        commits={"intro": _Commit("intro", "2021-01-01T00:00:00+00:00")},
    )
    result = _one(repo, _finding("2024-01-01T00:00:00+00:00", ("parent", "a.go", 10, 10)))
    assert result["introduced_to_fixed"]["method"] == "blame"
    assert result["introduced_to_fixed"]["sha"] == "intro"
    # 2021-01-01 -> 2024-01-01 is 1095 days.
    assert result["introduced_to_fixed_days"] == 1095


def test_oldest_wins_across_multiple_anchors():
    repo = FakeRepo(
        blame_map={
            ("parent", "a.go", 10, 10): ["newer"],
            ("parent", "b.go", 20, 20): ["older"],
        },
        commits={
            "newer": _Commit("newer", "2023-01-01T00:00:00+00:00"),
            "older": _Commit("older", "2020-01-01T00:00:00+00:00"),
        },
    )
    result = _one(
        repo,
        _finding(
            "2024-01-01T00:00:00+00:00",
            ("parent", "a.go", 10, 10),
            ("parent", "b.go", 20, 20),
        ),
    )
    assert result["introduced_to_fixed"]["sha"] == "older"
    assert result["introduced_to_fixed_days"] > 1400  # ~4 years, the longer span


def test_file_genesis_is_declined_not_dated():
    repo = FakeRepo(
        blame_map={("parent", "a.go", 1, 1): ["genesis"]},
        commits={"genesis": _Commit("genesis", "2015-01-01T00:00:00+00:00", is_root=True)},
    )
    result = _one(repo, _finding("2024-01-01T00:00:00+00:00", ("parent", "a.go", 1, 1)))
    assert result["introduced_to_fixed"]["method"] == "declined_file_genesis"
    assert result["introduced_to_fixed_days"] is None


def test_no_parent_anchor_declines():
    # A fix with only commit-revision evidence (a pure guard addition): nothing older to blame.
    finding = {
        "commit_sha": "fixsha",
        "commit_date": "2024-01-01T00:00:00+00:00",
        "evidence": [{"revision": "commit", "revision_sha": "fixsha", "path": "a.go",
                      "start_line": 5, "end_line": 5}],
    }
    result = _one(FakeRepo(), finding)
    assert result["introduced_to_fixed"]["method"] == "declined_no_signal"
    assert result["introduced_to_fixed_days"] is None


def test_broken_git_object_declines_without_dropping_finding():
    repo = FakeRepo(raise_blame={("parent", "a.go", 10, 10)})
    result = _one(repo, _finding("2024-01-01T00:00:00+00:00", ("parent", "a.go", 10, 10)))
    assert result["introduced_to_fixed_days"] is None
    assert result["commit_sha"] == "fixsha"  # finding survives


def test_introduction_after_fix_declines_negative_span():
    # A rebased/backported "introduction" dated after the fix must not yield a negative span.
    repo = FakeRepo(
        blame_map={("parent", "a.go", 10, 10): ["intro"]},
        commits={"intro": _Commit("intro", "2025-01-01T00:00:00+00:00")},
    )
    result = _one(repo, _finding("2024-01-01T00:00:00+00:00", ("parent", "a.go", 10, 10)))
    assert result["introduced_to_fixed_days"] is None
    assert result["introduced_to_fixed"]["method"] == "declined_no_signal"


def test_stage_preserves_all_findings():
    repo = FakeRepo(
        blame_map={("parent", "a.go", 10, 10): ["intro"]},
        commits={"intro": _Commit("intro", "2021-01-01T00:00:00+00:00")},
    )
    findings = [
        _finding("2024-01-01T00:00:00+00:00", ("parent", "a.go", 10, 10)),
        _finding("2024-01-01T00:00:00+00:00"),  # no anchors -> declined
    ]
    out = attribute_introductions(findings, repo)
    assert len(out) == 2
    assert out[0]["introduced_to_fixed_days"] == 1095
    assert out[1]["introduced_to_fixed_days"] is None
