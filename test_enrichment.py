"""Tests for msg_class, enrichment, diffs, and audit queue."""

from __future__ import annotations

import json
from pathlib import Path

from main import (
    MSG_CLASS_ANNOUNCED,
    MSG_CLASS_EMPTY,
    MSG_CLASS_MERGE_NOISE,
    MSG_CLASS_QUIET,
    SCHEMA_VERSION,
    build_audit_queue,
    classify_msg_class,
    enrich_commit_rows,
    lag_days,
    noise_flags_for,
    write_ghsa_commits,
)


def test_classify_msg_class_empty() -> None:
    assert classify_msg_class(None) == MSG_CLASS_EMPTY
    assert classify_msg_class("   ") == MSG_CLASS_EMPTY


def test_classify_msg_class_merge_noise() -> None:
    assert (
        classify_msg_class("Merge pull request #21 from paypal/gitattributes", is_merge=True)
        == MSG_CLASS_MERGE_NOISE
    )
    assert (
        classify_msg_class("Merge commit from fork", is_merge=True) == MSG_CLASS_MERGE_NOISE
    )
    # Non-merge with merge-like subject stays quiet/announced path, not merge_noise.
    assert (
        classify_msg_class("Merge pull request #21 from paypal/gitattributes", is_merge=False)
        == MSG_CLASS_QUIET
    )


def test_classify_msg_class_announced_via_cve() -> None:
    assert (
        classify_msg_class("security #cve-2021-32693 fix auth")
        == MSG_CLASS_ANNOUNCED
    )
    assert classify_msg_class("Fixes GHSA-xxxx-yyyy-zzzz") == MSG_CLASS_ANNOUNCED


def test_classify_msg_class_announced_via_two_keywords() -> None:
    assert (
        classify_msg_class("sanitize input to prevent XSS")
        == MSG_CLASS_ANNOUNCED
    )


def test_classify_msg_class_quiet() -> None:
    assert classify_msg_class("replace pickle with json") == MSG_CLASS_QUIET
    assert classify_msg_class("fix: cleanup content before sending") == MSG_CLASS_QUIET
    # Single keyword is not enough.
    assert classify_msg_class("security hardening for cookies") == MSG_CLASS_QUIET


def test_lag_days() -> None:
    assert lag_days("2026-02-10T00:00:00Z", "2026-02-01T12:00:00Z") == 9
    assert lag_days(None, "2026-02-01T00:00:00Z") is None


def test_noise_flags() -> None:
    assert noise_flags_for(resolved=False, is_merge=None, diff_bytes=None) == [
        "unresolved"
    ]
    assert noise_flags_for(resolved=True, is_merge=False, diff_bytes=0) == ["empty_diff"]
    assert noise_flags_for(resolved=True, is_merge=True, diff_bytes=0) == [
        "empty_diff",
        "merge_empty_diff",
    ]
    assert noise_flags_for(resolved=True, is_merge=False, diff_bytes=12) == []


def test_enrich_commit_rows_writes_diff_and_msg_class(tmp_path: Path) -> None:
    commit_json = {
        "sha": "abcdef0123456789abcdef0123456789abcdef01",
        "commit": {
            "message": "replace pickle with json\n\nbody",
            "committer": {"date": "2026-01-05T00:00:00Z"},
        },
        "parents": [{"sha": "1111111111111111111111111111111111111111"}],
    }
    diff_body = b"diff --git a/a.go b/a.go\n+safe\n"

    def fake_get(url: str, accept: str | None = None) -> tuple[int, bytes, dict[str, str]]:
        if accept == "application/vnd.github.diff":
            return 200, diff_body, {}
        if url.endswith("/commits/abc1234") or "/commits/abc1234" in url:
            return 200, json.dumps(commit_json).encode(), {}
        return 404, b"{}", {}

    advisories = [
        {
            "ghsa_id": "GHSA-aaaa-bbbb-cccc",
            "published_at": "2026-01-20T00:00:00Z",
        }
    ]
    commits = [
        {
            "ghsa_id": "GHSA-aaaa-bbbb-cccc",
            "host": "github.com",
            "repo": "owner/repo",
            "sha": "abc1234",
            "url": "https://github.com/owner/repo/commit/abc1234",
            "ordinal": 1,
            "n_in_advisory": 1,
        }
    ]
    out = tmp_path / "ghsa-commits"
    out.mkdir()
    (out / "diffs").mkdir()

    stats = enrich_commit_rows(commits, advisories, out, http_get=fake_get)
    assert stats["resolved"] == 1
    assert stats["diffs_written"] == 1
    assert stats["msg_class"][MSG_CLASS_QUIET] == 1

    row = commits[0]
    assert row["resolved"] is True
    assert row["msg_class"] == MSG_CLASS_QUIET
    assert row["subject"] == "replace pickle with json"
    assert row["lag_days"] == 15
    assert row["noise_flags"] == []
    assert row["diff_path"] == (
        "diffs/github.com/owner/repo/abcdef0123456789abcdef0123456789abcdef01.diff"
    )
    assert (out / row["diff_path"]).read_bytes() == diff_body

    queue = build_audit_queue(commits)
    assert len(queue) == 1
    assert queue[0]["audit_status"] == "pending"
    assert queue[0]["audit_label"] is None
    assert queue[0]["ghsa_ids"] == ["GHSA-aaaa-bbbb-cccc"]


def test_enrich_unresolved_commit(tmp_path: Path) -> None:
    def fake_get(url: str, accept: str | None = None) -> tuple[int, bytes, dict[str, str]]:
        return 404, b'{"message":"Not Found"}', {}

    commits = [
        {
            "ghsa_id": "GHSA-aaaa-bbbb-cccc",
            "host": "github.com",
            "repo": "owner/missing",
            "sha": "deadbeef",
            "url": "https://github.com/owner/missing/commit/deadbeef",
            "ordinal": 1,
            "n_in_advisory": 1,
        }
    ]
    out = tmp_path / "ghsa-commits"
    out.mkdir()
    (out / "diffs").mkdir()
    stats = enrich_commit_rows(commits, [], out, http_get=fake_get)
    assert stats["unresolved"] == 1
    assert commits[0]["resolved"] is False
    assert commits[0]["noise_flags"] == ["unresolved"]
    assert commits[0]["diff_path"] is None
    assert list((out / "diffs").rglob("*.diff")) == []


def test_enrich_merge_uses_compare_diff(tmp_path: Path) -> None:
    commit_json = {
        "sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "commit": {
            "message": "Merge pull request #9 from fork\n",
            "committer": {"date": "2026-03-01T00:00:00Z"},
        },
        "parents": [
            {"sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
            {"sha": "cccccccccccccccccccccccccccccccccccccccc"},
        ],
    }
    compare_diff = b"diff --git a/x b/x\n+fix\n"

    def fake_get(url: str, accept: str | None = None) -> tuple[int, bytes, dict[str, str]]:
        if "compare/" in url and accept == "application/vnd.github.diff":
            return 200, compare_diff, {}
        if accept == "application/vnd.github.diff":
            return 200, b"", {}
        return 200, json.dumps(commit_json).encode(), {}

    commits = [
        {
            "ghsa_id": "GHSA-mmmm-nnnn-oooo",
            "host": "github.com",
            "repo": "o/r",
            "sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "url": "https://github.com/o/r/commit/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "ordinal": 1,
            "n_in_advisory": 1,
        }
    ]
    out = tmp_path / "bundle"
    out.mkdir()
    (out / "diffs").mkdir()
    enrich_commit_rows(commits, [], out, http_get=fake_get)
    assert commits[0]["is_merge"] is True
    assert commits[0]["msg_class"] == MSG_CLASS_MERGE_NOISE
    assert (out / commits[0]["diff_path"]).read_bytes() == compare_diff


def test_write_ghsa_commits_preserves_diffs(tmp_path: Path) -> None:
    out = tmp_path / "ghsa-commits"
    out.mkdir()
    diff = out / "diffs/github.com/o/r/abc.diff"
    diff.parent.mkdir(parents=True)
    diff.write_text("patch", encoding="utf-8")

    write_ghsa_commits(
        out,
        advisories=[],
        commits=[],
        manifest={"schema_version": SCHEMA_VERSION},
        audit_queue=[],
        preserve_diffs=True,
    )
    assert (out / "diffs/github.com/o/r/abc.diff").read_text(encoding="utf-8") == "patch"
    assert (out / "audit_queue.jsonl").exists()
