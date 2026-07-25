"""Tests for GitHub commit URL extraction."""

from __future__ import annotations

from main import advisory_commit_urls, extract_github_commit_urls


def test_extracts_basic_commit_url() -> None:
    text = (
        "Fixed in https://github.com/webmin/webmin/commit/"
        "39ea464f0c40b325decd6a5bfb7833fa4a142e38"
    )
    assert extract_github_commit_urls(text) == [
        "https://github.com/webmin/webmin/commit/39ea464f0c40b325decd6a5bfb7833fa4a142e38"
    ]


def test_extracts_short_sha() -> None:
    text = "see https://github.com/owner/repo/commit/abc1234 for the fix"
    assert extract_github_commit_urls(text) == [
        "https://github.com/owner/repo/commit/abc1234"
    ]


def test_extracts_pull_request_commit_url() -> None:
    text = "https://github.com/owner/repo/pull/42/commits/deadbeefcafebabe0123456789abcdef01234567"
    assert extract_github_commit_urls(text) == [
        "https://github.com/owner/repo/commit/deadbeefcafebabe0123456789abcdef01234567"
    ]


def test_normalizes_http_www_and_lowercases_repo() -> None:
    text = "http://www.github.com/Owner/Repo/commit/ABCDEF0"
    assert extract_github_commit_urls(text) == [
        "https://github.com/owner/repo/commit/abcdef0"
    ]


def test_strips_markdown_trailing_punctuation() -> None:
    text = (
        "See [fix](https://github.com/o/r/commit/abcdef0123456789)."
        " Also https://github.com/o/r/commit/fedcba9876543210),"
    )
    assert extract_github_commit_urls(text) == [
        "https://github.com/o/r/commit/abcdef0123456789",
        "https://github.com/o/r/commit/fedcba9876543210",
    ]


def test_ignores_non_commit_github_urls() -> None:
    text = """
    https://github.com/advisories/GHSA-vw87-2p2h-8rp3
    https://github.com/owner/repo/issues/1
    https://github.com/owner/repo/pull/2
    https://github.com/owner/repo
    https://gitlab.com/owner/repo/commit/abcdef0
    """
    assert extract_github_commit_urls(text) == []


def test_deduplicates_preserving_order() -> None:
    text = """
    https://github.com/a/b/commit/1111111
    https://github.com/a/b/commit/2222222
    https://github.com/a/b/commit/1111111
    http://github.com/a/b/commit/1111111
    """
    assert extract_github_commit_urls(text) == [
        "https://github.com/a/b/commit/1111111",
        "https://github.com/a/b/commit/2222222",
    ]


def test_empty_and_none_like_input() -> None:
    assert extract_github_commit_urls("") == []


def test_advisory_commit_urls_from_details_and_references() -> None:
    advisory = {
        "details": (
            "Patched here: https://github.com/org/pkg/commit/"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ),
        "references": [
            {
                "type": "FIX",
                "url": "https://github.com/org/pkg/commit/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            },
            {"type": "WEB", "url": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz"},
            {"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-1"},
            "https://github.com/org/pkg/pull/9/commits/cccccccccccccccccccccccccccccccccccccccc",
        ],
    }
    assert advisory_commit_urls(advisory) == [
        "https://github.com/org/pkg/commit/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "https://github.com/org/pkg/commit/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "https://github.com/org/pkg/commit/cccccccccccccccccccccccccccccccccccccccc",
    ]


def test_advisory_without_commit_urls() -> None:
    advisory = {
        "details": "No commits here, only https://github.com/org/pkg/issues/1",
        "references": [{"type": "WEB", "url": "https://example.com"}],
    }
    assert advisory_commit_urls(advisory) == []
