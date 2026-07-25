"""Tests for label load/merge and eval recall metrics."""

from __future__ import annotations

import json
import os
from pathlib import Path

from eval import diff_leaks_disclosure, load_dotenv, summarize_by_role, summarize_recall
from main import apply_labels, build_commit_rows, load_labels


def _refs(*shas: str) -> list[dict[str, str]]:
    return [
        {"host": "github.com", "repo": "o/r", "sha": s, "url": f"https://github.com/o/r/commit/{s}"}
        for s in shas
    ]


def test_new_commit_rows_carry_provenance_and_null_role() -> None:
    rows = build_commit_rows("GHSA-x", _refs("aaa1111"))
    assert rows[0]["source"] == "ghsa"
    assert rows[0]["ghsa_referenced"] is True
    assert rows[0]["role"] is None


def test_load_and_apply_labels(tmp_path: Path) -> None:
    labels_file = tmp_path / "labels.jsonl"
    labels_file.write_text(
        json.dumps({"host": "github.com", "repo": "o/r", "sha": "AAA1111", "role": "fix", "notes": "x"})
        + "\n"
        + json.dumps({"host": "github.com", "repo": "o/r", "sha": "bbb2222", "role": None})
        + "\n",
        encoding="utf-8",
    )
    labels = load_labels(labels_file)
    # Keyed lowercased.
    assert ("github.com", "o/r", "aaa1111") in labels

    rows = build_commit_rows("GHSA-x", _refs("aaa1111", "bbb2222", "ccc3333"))
    applied = apply_labels(rows, labels)
    assert applied == 1  # only the non-null role
    assert rows[0]["role"] == "fix"
    assert rows[0]["label_notes"] == "x"
    assert rows[1]["role"] is None  # explicit-null label does not overwrite
    assert rows[2]["role"] is None  # unlabelled untouched


def test_load_labels_missing_file(tmp_path: Path) -> None:
    assert load_labels(tmp_path / "nope.jsonl") == {}


def test_diff_leaks_disclosure() -> None:
    leak = "diff --git a/CHANGELOG.md b/CHANGELOG.md\n+ - [Critical] fixed GHSA-fwj3-42wh-8673\n"
    assert diff_leaks_disclosure(leak) is True
    # CVE only on a context (unchanged) line is not a leak.
    ctx = "diff --git a/x b/x\n Some CVE-2021-1111 mention on context line\n+real code\n"
    assert diff_leaks_disclosure(ctx) is False
    # Removed line with an id is not an added-line leak.
    removed = "diff --git a/x b/x\n-old CVE-2020-9999 note\n+clean\n"
    assert diff_leaks_disclosure(removed) is False


def test_summarize_recall_advisory_and_commit_level() -> None:
    # Advisory A: 3 commits, only one flagged -> advisory caught.
    # Advisory B: 1 commit, not flagged -> advisory missed.
    results = [
        {"ghsa_id": "A", "msg_class": "quiet", "flagged": False, "diff_leaks_disclosure": False},
        {"ghsa_id": "A", "msg_class": "quiet", "flagged": True, "diff_leaks_disclosure": False},
        {"ghsa_id": "A", "msg_class": "announced", "flagged": False, "diff_leaks_disclosure": True},
        {"ghsa_id": "B", "msg_class": "quiet", "flagged": False, "diff_leaks_disclosure": False},
    ]
    s = summarize_recall(results)
    # Commit-level overall: 1 of 4 flagged.
    assert s["commit_level"]["overall"] == {"n": 4, "flagged": 1, "flag_rate": 0.25}
    # quiet: 3 commits, 1 flagged.
    assert s["commit_level"]["quiet"]["flag_rate"] == round(1 / 3, 4)
    # Advisory-level: A caught, B missed -> 1/2.
    assert s["advisory_level"] == {"n": 2, "caught": 1, "recall": 0.5}


def test_load_dotenv_sets_and_respects_precedence(tmp_path: Path, monkeypatch) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "# a comment\n"
        "\n"
        "export OPENAI_BASE_URL=https://from.file/v1\n"
        'OPENAI_MODEL="quoted-model"\n'
        "OPENAI_API_KEY=filekey\n",
        encoding="utf-8",
    )
    # Real env var must win over the file value.
    monkeypatch.setenv("OPENAI_API_KEY", "realkey")
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("OPENAI_MODEL", raising=False)

    n = load_dotenv(env_file)
    assert n == 2  # BASE_URL + MODEL set from file; API_KEY skipped (already set)
    assert os.environ["OPENAI_BASE_URL"] == "https://from.file/v1"
    assert os.environ["OPENAI_MODEL"] == "quoted-model"  # quotes stripped
    assert os.environ["OPENAI_API_KEY"] == "realkey"  # real env preserved


def test_load_dotenv_missing_file(tmp_path: Path) -> None:
    assert load_dotenv(tmp_path / "nope.env") == 0


def test_sampler_plan_counts_per_repo_and_total() -> None:
    from sample_negatives import build_negative_row, plan_counts

    repos = [("github.com", f"o/r{i}") for i in range(4)]
    # per-repo: N for every repo
    assert plan_counts(repos, 3, None) == {r: 3 for r in repos}
    # total: even split, remainder on the first repos, sums exactly to total
    counts = plan_counts(repos, None, 10)
    assert sum(counts.values()) == 10
    assert sorted(counts.values()) == [2, 2, 3, 3]

    row = build_negative_row("github.com", "o/r", "ABC123")
    assert row["source"] == "sampler"
    assert row["ghsa_referenced"] is False
    assert row["role"] is None
    assert row["ghsa_id"] is None
    assert row["n_in_advisory"] == 0


def test_sampler_excludes_existing_keys() -> None:
    from sample_negatives import bundle_repos, existing_keys

    commits = [
        {"host": "github.com", "repo": "o/r", "sha": "AAA"},
        {"host": "github.com", "repo": "o/r", "sha": "bbb"},
        {"host": "github.com", "repo": "o/other", "sha": "ccc"},
    ]
    assert bundle_repos(commits) == [("github.com", "o/other"), ("github.com", "o/r")]
    keys = existing_keys(commits)
    assert ("github.com", "o/r", "aaa") in keys  # lowercased
    assert ("github.com", "o/r", "bbb") in keys


def test_summarize_by_role_none_when_unlabelled() -> None:
    results = [{"role": None, "flagged": True}, {"role": None, "flagged": False}]
    assert summarize_by_role(results) is None


def test_summarize_by_role_fix_recall_and_false_positives() -> None:
    # Mirrors the real n=11 run: 7 fix (all flagged), 3 other (1 wrongly flagged),
    # 1 unlabelled. fix-recall should be perfect; one non-fix false positive.
    results = (
        [{"role": "fix", "flagged": True, "repo": "r", "sha": f"f{i}", "msg_class": "quiet"} for i in range(7)]
        + [{"role": "other", "flagged": False, "repo": "r", "sha": "o1"}]
        + [{"role": "other", "flagged": False, "repo": "r", "sha": "o2"}]
        + [{"role": "other", "flagged": True, "repo": "siyuan", "sha": "o3"}]  # false positive
        + [{"role": None, "flagged": True, "repo": "r", "sha": "u1"}]
    )
    s = summarize_by_role(results)
    assert s is not None
    assert s["labelled"] == 10 and s["unlabelled"] == 1
    assert s["fix_recall"] == {"n": 7, "flagged": 7, "recall": 1.0, "missed": []}
    fp = s["nonfix_false_positives"]
    assert fp["n"] == 3 and fp["flagged"] == 1 and fp["fp_rate"] == round(1 / 3, 4)
    assert fp["flagged_detail"] == [{"repo": "siyuan", "sha": "o3", "role": "other"}]


def test_summarize_by_role_backport_excluded_from_recall() -> None:
    results = [
        {"role": "fix", "flagged": True, "repo": "r", "sha": "a", "msg_class": "quiet"},
        {"role": "backport", "flagged": True, "repo": "r", "sha": "b"},
    ]
    s = summarize_by_role(results)
    assert s["fix_recall"]["n"] == 1  # backport not counted as a fix
    assert s["backport"] == {"n": 1, "flagged": 1}
    assert s["nonfix_false_positives"]["n"] == 0  # backport not an FP either


def test_summarize_recall_quiet_clean_excludes_leaks() -> None:
    results = [
        {"ghsa_id": "A", "msg_class": "quiet", "flagged": True, "diff_leaks_disclosure": True},
        {"ghsa_id": "B", "msg_class": "quiet", "flagged": False, "diff_leaks_disclosure": False},
    ]
    s = summarize_recall(results)
    qc = s["commit_level"]["quiet_clean"]
    assert qc["n"] == 1  # the leaking one excluded
    assert qc["excluded_leaking"] == 1
    assert qc["flagged"] == 0  # only the clean (unflagged) one remains
    assert qc["flag_rate"] == 0.0
