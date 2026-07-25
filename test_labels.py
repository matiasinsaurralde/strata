"""Tests for label load/merge and eval recall metrics."""

from __future__ import annotations

import json
import os
from pathlib import Path

from eval import diff_leaks_disclosure, load_dotenv, parse_reset_duration, retry_wait_seconds, summarize_by_role, summarize_recall
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


def test_parse_reset_duration_openai_forms() -> None:
    assert parse_reset_duration("1s") == 1.0
    assert parse_reset_duration("6m0s") == 360.0
    assert parse_reset_duration("1h2m3s") == 3723.0
    assert parse_reset_duration("1.5s") == 1.5
    assert parse_reset_duration("2") == 2.0
    assert parse_reset_duration("") is None
    assert parse_reset_duration(None) is None


def test_retry_wait_seconds_prefers_retry_after() -> None:
    assert retry_wait_seconds({"retry-after": "7"}) == 7.0
    assert retry_wait_seconds(
        {
            "retry-after": "2",
            "x-ratelimit-reset-requests": "6m0s",
        }
    ) == 2.0
    assert retry_wait_seconds({"x-ratelimit-reset-requests": "1s"}) == 1.0
    assert retry_wait_seconds({}) == 5.0


def test_rate_limit_backoff_uses_exponential_floor() -> None:
    from eval import rate_limit_backoff_seconds

    # Short Retry-After must not keep attempt 4 at 1s.
    assert rate_limit_backoff_seconds({"retry-after": "1"}, 1) == 1.0
    assert rate_limit_backoff_seconds({"retry-after": "1"}, 4) == 8.0
    assert rate_limit_backoff_seconds({"retry-after": "1"}, 8) == 120.0  # capped

    # Header wins when longer than the floor.
    assert rate_limit_backoff_seconds({"retry-after": "30"}, 3) == 30.0


def test_skip_oversize_diff() -> None:
    from eval import DIFF_SKIP_MAX_BYTES, is_request_too_large, skip_oversize_diff

    small = "x" * 100
    assert skip_oversize_diff({"diff_bytes": 100}, small) is None
    assert skip_oversize_diff({}, small) is None

    # Meta alone can trigger skip even if we pass a short string (stale path).
    reason = skip_oversize_diff({"diff_bytes": DIFF_SKIP_MAX_BYTES + 1}, "tiny")
    assert reason is not None and "too large" in reason

    # On-disk length alone can trigger skip when meta is missing/understated.
    big = "y" * (DIFF_SKIP_MAX_BYTES + 10)
    reason = skip_oversize_diff({"diff_bytes": 1}, big)
    assert reason is not None and "too large" in reason

    assert is_request_too_large(
        "Request too large for gpt-4o-mini on tokens per min (TPM): Limit 200000, Requested 228721"
    )
    # Transient TPM exhaustion — must NOT be treated as oversized.
    assert not is_request_too_large(
        "Rate limit reached for gpt-4o-mini in organization org-x on tokens per "
        "min (TPM): Limit 200000, Used 195000, Requested 8000. Please try again in 1s."
    )
    assert not is_request_too_large("Rate limit reached for requests")


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


def test_apply_labels_only_merges_into_bundle(tmp_path: Path) -> None:
    import main

    out = tmp_path / "ghsa-commits"
    out.mkdir()
    (out / "diffs").mkdir()
    # a minimal bundle with two commits, roles null
    (out / "commits.jsonl").write_text(
        json.dumps({"ghsa_id": "G1", "host": "github.com", "repo": "o/r", "sha": "aaa",
                    "url": "https://github.com/o/r/commit/aaa", "role": None})
        + "\n"
        + json.dumps({"ghsa_id": "G1", "host": "github.com", "repo": "o/r", "sha": "bbb",
                      "url": "https://github.com/o/r/commit/bbb", "role": None})
        + "\n",
        encoding="utf-8",
    )
    (out / "advisories.jsonl").write_text(json.dumps({"ghsa_id": "G1"}) + "\n", encoding="utf-8")
    (out / "manifest.json").write_text(json.dumps({"schema_version": 2}) + "\n", encoding="utf-8")
    labels = tmp_path / "labels.jsonl"
    labels.write_text(
        json.dumps({"host": "github.com", "repo": "o/r", "sha": "aaa", "role": "fix"}) + "\n",
        encoding="utf-8",
    )

    # point the module's LABELS_PATH at our temp labels file
    monkey_prev = main.LABELS_PATH
    main.LABELS_PATH = labels
    try:
        main.apply_labels_only(out)
    finally:
        main.LABELS_PATH = monkey_prev

    rows = [json.loads(l) for l in (out / "commits.jsonl").read_text().splitlines() if l.strip()]
    by_sha = {r["sha"]: r for r in rows}
    assert by_sha["aaa"]["role"] == "fix"  # merged
    assert by_sha["bbb"]["role"] is None   # untouched
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["labels_applied"] == 1
    assert manifest["unlabelled"] == 1
    # diffs/ preserved
    assert (out / "diffs").is_dir()


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


def test_stage2_candidate_join_and_metrics(tmp_path: Path) -> None:
    from stage2 import (
        build_s2_targets,
        build_user_content,
        end_to_end,
        load_stage1_yes,
        s2_prompt_hash,
        summarize_s2,
    )

    assert s2_prompt_hash("a") != s2_prompt_hash("b")
    assert "Diff" in build_user_content({"message": "x"}, "diffbody", include_message=False)
    with_msg = build_user_content({"message": "fix auth"}, "diffbody", include_message=True)
    assert "fix auth" in with_msg and "diffbody" in with_msg

    s1 = tmp_path / "s1.json"
    s1.write_text(
        json.dumps(
            {
                "kind": "recall",
                "commits": [
                    {"repo": "o/r", "sha": "aaa", "flagged": True, "role": "fix"},
                    {"repo": "o/r", "sha": "zzz", "flagged": False, "role": "fix"},
                    {"repo": "o/r", "sha": "bbb", "flagged": True, "role": "other"},
                ],
            }
        ),
        encoding="utf-8",
    )
    stage1_yes = load_stage1_yes([s1])
    assert set(stage1_yes) == {("o/r", "aaa"), ("o/r", "bbb")}

    commits = [
        {"repo": "o/r", "sha": "aaa", "diff_path": "d/a.diff", "role": "fix", "source": "ghsa"},
        {"repo": "o/r", "sha": "bbb", "diff_path": "d/b.diff", "role": "other", "source": "sampler"},
        {"repo": "o/r", "sha": "ccc", "diff_path": "d/c.diff", "role": "fix", "source": "ghsa"},
    ]
    targets = build_s2_targets(commits, stage1_yes)
    assert len(targets) == 2
    assert {t["sha"] for t in targets} == {"aaa", "bbb"}

    summary = summarize_s2(
        [
            {"role": "fix", "flagged": True},
            {"role": "fix", "flagged": False},
            {"role": "other", "flagged": False},
            {"role": "other", "flagged": True},
        ]
    )
    assert summary["stage1_true_positives"]["survived"] == 1
    assert summary["stage1_true_positives"]["survival_rate"] == 0.5
    assert summary["stage1_false_positives"]["killed"] == 1
    assert summary["stage1_false_positives"]["kill_rate"] == 0.5

    e2e = end_to_end(s1_fix_recall=0.9, s1_sampler_fpr=0.1, s2=summary)
    assert e2e["e2e_recall"] == 0.45  # 0.9 * 0.5
    assert e2e["e2e_fpr"] == 0.05  # 0.1 * 0.5 remaining
