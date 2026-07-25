"""Tests for ghsa-commits bundle writing."""

from __future__ import annotations

import json
from pathlib import Path

from main import (
    DIFFS_LAYOUT,
    SCHEMA_VERSION,
    advisory_commit_refs,
    build_advisory_row,
    build_commit_rows,
    extract_github_commit_refs,
    write_ghsa_commits,
)


def test_extract_github_commit_refs_structured() -> None:
    text = "https://github.com/Owner/Repo/commit/ABCDEF0"
    assert extract_github_commit_refs(text) == [
        {
            "host": "github.com",
            "repo": "owner/repo",
            "sha": "abcdef0",
            "url": "https://github.com/owner/repo/commit/abcdef0",
        }
    ]


def test_build_advisory_and_commit_rows() -> None:
    advisory = {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "aliases": ["CVE-2026-1234", "GHSA-xxxx-yyyy-zzzz"],
        "published": "2026-01-15T00:00:00Z",
        "modified": "2026-01-16T00:00:00Z",
        "summary": "Example",
        "database_specific": {"severity": "high"},
        "affected": [{"package": {"ecosystem": "Go", "name": "example.com/mod"}}],
        "details": "",
        "references": [
            {"url": "https://github.com/o/r/commit/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
            {"url": "https://github.com/o/r/commit/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        ],
    }
    refs = advisory_commit_refs(advisory)
    row = build_advisory_row(
        advisory,
        source_path="advisories/github-reviewed/2026/01/GHSA-xxxx-yyyy-zzzz/GHSA-xxxx-yyyy-zzzz.json",
        reviewed=True,
        n_commits=len(refs),
    )
    assert row == {
        "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
        "cve_id": "CVE-2026-1234",
        "reviewed": True,
        "published_at": "2026-01-15T00:00:00Z",
        "updated_at": "2026-01-16T00:00:00Z",
        "severity": "high",
        "ecosystems": ["Go"],
        "summary": "Example",
        "source_path": (
            "advisories/github-reviewed/2026/01/GHSA-xxxx-yyyy-zzzz/"
            "GHSA-xxxx-yyyy-zzzz.json"
        ),
        "n_commits": 2,
    }
    assert build_commit_rows("GHSA-xxxx-yyyy-zzzz", refs) == [
        {
            "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
            "host": "github.com",
            "repo": "o/r",
            "sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "url": "https://github.com/o/r/commit/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "ordinal": 1,
            "n_in_advisory": 2,
        },
        {
            "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
            "host": "github.com",
            "repo": "o/r",
            "sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "url": "https://github.com/o/r/commit/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "ordinal": 2,
            "n_in_advisory": 2,
        },
    ]


def test_write_ghsa_commits_creates_bundle(tmp_path: Path) -> None:
    out = tmp_path / "ghsa-commits"
    # Prior contents should be replaced.
    out.mkdir()
    (out / "stale.txt").write_text("old", encoding="utf-8")
    (out / "diffs").mkdir()
    (out / "diffs" / "stale.diff").write_text("x", encoding="utf-8")

    advisories = [
        {
            "ghsa_id": "GHSA-aaaa-bbbb-cccc",
            "cve_id": None,
            "reviewed": True,
            "published_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-02T00:00:00Z",
            "severity": "medium",
            "ecosystems": ["Go"],
            "summary": "One",
            "source_path": "advisories/github-reviewed/2026/01/GHSA-aaaa-bbbb-cccc/GHSA-aaaa-bbbb-cccc.json",
            "n_commits": 1,
        }
    ]
    commits = [
        {
            "ghsa_id": "GHSA-aaaa-bbbb-cccc",
            "host": "github.com",
            "repo": "owner/repo",
            "sha": "abcdef0",
            "url": "https://github.com/owner/repo/commit/abcdef0",
            "ordinal": 1,
            "n_in_advisory": 1,
        }
    ]
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "advisories": 1,
        "commit_refs": 1,
        "diffs_layout": DIFFS_LAYOUT,
    }
    write_ghsa_commits(out, advisories=advisories, commits=commits, manifest=manifest)

    assert not (out / "stale.txt").exists()
    assert (out / "diffs").is_dir()
    assert list((out / "diffs").iterdir()) == []

    assert json.loads((out / "manifest.json").read_text(encoding="utf-8")) == manifest

    adv_lines = (out / "advisories.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(adv_lines) == 1
    assert json.loads(adv_lines[0])["ghsa_id"] == "GHSA-aaaa-bbbb-cccc"

    commit_lines = (out / "commits.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(commit_lines) == 1
    assert json.loads(commit_lines[0])["sha"] == "abcdef0"
