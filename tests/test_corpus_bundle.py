"""Corpus construction: URL extraction, stratification, grouping, leak detection."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from strata_eval.corpus.bundle import (
    MSG_CLASS_ANNOUNCED,
    MSG_CLASS_EMPTY,
    MSG_CLASS_MERGE_NOISE,
    MSG_CLASS_QUIET,
    Bundle,
    advisory_commit_refs,
    apply_labels,
    classify_msg_class,
    commit_key,
    content_key,
    diff_leaks_disclosure,
    extract_github_commit_refs,
)
from strata_eval.corpus.keywords import (
    SECURITY_KEYWORDS,
    announcement_strength,
    count_matches,
    matched_keywords,
    table_manifest,
)


class TestCommitUrlExtraction:
    def test_extracts_and_normalises_commit_urls(self) -> None:
        text = (
            "See https://github.com/Gin-Gonic/Gin/commit/ABCDEF1234567890 and "
            "https://github.com/owner/repo/pull/12/commits/0123456789abcdef"
        )
        refs = extract_github_commit_refs(text)
        assert [(r["repo"], r["sha"]) for r in refs] == [
            ("gin-gonic/gin", "abcdef1234567890"),
            ("owner/repo", "0123456789abcdef"),
        ]

    def test_deduplicates_repeated_references(self) -> None:
        url = "https://github.com/o/r/commit/aaaaaaa"
        assert len(extract_github_commit_refs(f"{url} {url}")) == 1

    def test_ignores_non_commit_github_urls(self) -> None:
        assert extract_github_commit_refs("https://github.com/o/r/issues/4") == []

    def test_reads_details_and_references(self) -> None:
        advisory = {
            "details": "fixed in https://github.com/o/r/commit/1111111",
            "references": [
                {"url": "https://github.com/o/r/commit/2222222"},
                "https://github.com/o/r/commit/3333333",
            ],
        }
        assert [r["sha"] for r in advisory_commit_refs(advisory)] == [
            "1111111",
            "2222222",
            "3333333",
        ]


class TestKeywordTable:
    def test_rce_no_longer_matches_inside_ordinary_words(self) -> None:
        """The substring bug: `rce` fired inside enforce/source/resource/coerce."""
        for word in ("enforce", "source", "resources", "coerce"):
            assert matched_keywords(f"refactor to {word} the value") == ()

    def test_phrases_do_not_double_count_their_parts(self) -> None:
        """One `sql injection` is one signal, not `injection` plus `sql injection`."""
        assert matched_keywords("Fix SQL injection in reports") == ("sql injection",)
        assert count_matches("Fix SQL injection in reports") == 1

    def test_separate_occurrences_still_count_separately(self) -> None:
        text = "Fix SQL injection and add path traversal checks"
        assert set(matched_keywords(text)) == {"sql injection", "path traversal"}

    def test_hyphen_and_underscore_variants_match(self) -> None:
        for variant in ("path traversal", "path-traversal", "path_traversal"):
            assert "path traversal" in matched_keywords(f"blocked {variant} here")

    def test_removed_terms_are_absent(self) -> None:
        for term in ("rce", "fixme", "cve-", "ghsa-", "vulnerab", "unauth"):
            assert term not in SECURITY_KEYWORDS

    def test_manifest_is_versioned(self) -> None:
        manifest = table_manifest()
        assert manifest["keyword_table_version"]
        assert manifest["keyword_count"] == len(SECURITY_KEYWORDS)


class TestMsgClass:
    @pytest.mark.parametrize(
        ("message", "expected"),
        [
            ("Fix CVE-2023-29401 in file handling", MSG_CLASS_ANNOUNCED),
            ("Addresses GHSA-abcd-efgh-ijkl", MSG_CLASS_ANNOUNCED),
            ("fix: prevent path traversal (ZipSlip) in Untar", MSG_CLASS_ANNOUNCED),
            ("Bump golang.org/x/crypto from 0.52.0 to 0.53.0", MSG_CLASS_QUIET),
            ("security: enforce repo access on attachment download", MSG_CLASS_QUIET),
            ("", MSG_CLASS_EMPTY),
            ("   \n  ", MSG_CLASS_EMPTY),
        ],
    )
    def test_classification(self, message: str, expected: str) -> None:
        assert classify_msg_class(message) == expected

    def test_merge_noise_requires_a_merge_commit(self) -> None:
        subject = "Merge pull request #12 from fork/branch"
        assert classify_msg_class(subject, is_merge=True) == MSG_CLASS_MERGE_NOISE
        assert classify_msg_class(subject, is_merge=False) == MSG_CLASS_QUIET

    def test_single_keyword_stays_quiet(self) -> None:
        """Contamination is accepted only toward the *harder* stratum."""
        assert classify_msg_class("fix: Various security fixes") == MSG_CLASS_QUIET


class TestAnnouncementStrength:
    @pytest.mark.parametrize(
        ("message", "expected"),
        [
            ("Fix CVE-2023-29401", "identifier"),
            ("fix: prevent path traversal (ZipSlip)", "multi_keyword"),
            ("security: enforce repo access on downloads", "subject_signal"),
            ("Fix possible SSRF via unverified JWT claims", "subject_signal"),
            ("fix: Various security fixes", "single_keyword"),
            ("Bump dependency to 1.2.3", "none"),
        ],
    )
    def test_grades(self, message: str, expected: str) -> None:
        assert announcement_strength(message) == expected

    def test_strength_never_alters_msg_class(self) -> None:
        message = "security: enforce repo access on downloads"
        assert announcement_strength(message) == "subject_signal"
        assert classify_msg_class(message) == MSG_CLASS_QUIET


class TestDiffLeakDetection:
    def test_added_line_naming_a_cve_is_a_leak(self) -> None:
        assert diff_leaks_disclosure("+ - Fixes CVE-2023-1234\n") is True

    def test_removed_or_context_lines_are_not_leaks(self) -> None:
        assert diff_leaks_disclosure("- old CVE-2023-1234 note\n") is False
        assert diff_leaks_disclosure("  context CVE-2023-1234\n") is False

    def test_file_header_is_not_a_leak(self) -> None:
        assert diff_leaks_disclosure("+++ b/CVE-2023-1234.md\n") is False


class TestBundleGrouping:
    """The (ghsa_id, host, repo, sha) key: one commit may fix several advisories."""

    @staticmethod
    def _write(root: Path, advisories: list[dict], commits: list[dict]) -> None:
        root.mkdir(parents=True, exist_ok=True)
        for name, rows in (("advisories", advisories), ("commits", commits)):
            (root / f"{name}.jsonl").write_text(
                "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8"
            )

    def test_shared_commit_keeps_a_row_per_advisory(self, tmp_path: Path) -> None:
        shared = "a" * 40
        self._write(
            tmp_path,
            [{"ghsa_id": "GHSA-1111-1111-1111"}, {"ghsa_id": "GHSA-2222-2222-2222"}],
            [
                {
                    "ghsa_id": "GHSA-1111-1111-1111",
                    "repo": "o/r",
                    "sha": shared,
                    "message": "fix thing",
                    "source": "ghsa",
                },
                {
                    "ghsa_id": "GHSA-2222-2222-2222",
                    "repo": "o/r",
                    "sha": shared,
                    "message": "fix thing",
                    "source": "ghsa",
                },
            ],
        )
        bundle = Bundle.load(tmp_path)
        assert len(bundle.commits) == 2
        assert bundle.advisories_without_commits() == []
        assert len(bundle.unique_commits()) == 1

    def test_missing_rows_are_reported_not_hidden(self, tmp_path: Path) -> None:
        self._write(
            tmp_path,
            [{"ghsa_id": "GHSA-1111-1111-1111"}, {"ghsa_id": "GHSA-3333-3333-3333"}],
            [
                {
                    "ghsa_id": "GHSA-1111-1111-1111",
                    "repo": "o/r",
                    "sha": "b" * 40,
                    "message": "m",
                    "source": "ghsa",
                }
            ],
        )
        bundle = Bundle.load(tmp_path)
        assert bundle.advisories_without_commits() == ["GHSA-3333-3333-3333"]

    def test_ordinal_and_n_in_advisory_follow_the_rows_present(self, tmp_path: Path) -> None:
        self._write(
            tmp_path,
            [{"ghsa_id": "GHSA-1111-1111-1111"}],
            [
                {
                    "ghsa_id": "GHSA-1111-1111-1111",
                    "repo": "o/r",
                    "sha": "c" * 40,
                    "message": "a",
                },
                {
                    "ghsa_id": "GHSA-1111-1111-1111",
                    "repo": "o/r",
                    "sha": "d" * 40,
                    "message": "b",
                },
            ],
        )
        rows = Bundle.load(tmp_path).commits
        assert [(r.ordinal, r.n_in_advisory) for r in rows] == [(0, 2), (1, 2)]

    def test_keys_separate_pairing_identity_from_commit_identity(self) -> None:
        row = {"ghsa_id": "GHSA-1111-1111-1111", "repo": "o/r", "sha": "E" * 40}
        assert commit_key(row) == ("GHSA-1111-1111-1111", "github.com", "o/r", "e" * 40)
        assert content_key(row) == ("github.com", "o/r", "e" * 40)


class TestLabelApplication:
    def test_last_write_wins_on_the_content_key(self) -> None:
        labels = [
            {"host": "github.com", "repo": "o/r", "sha": "F" * 40, "role": "other"},
            {"host": "github.com", "repo": "o/r", "sha": "f" * 40, "role": "fix"},
        ]
        resolved = apply_labels([], labels)
        assert resolved[("github.com", "o/r", "f" * 40)] == "fix"

    def test_rows_without_a_role_are_ignored(self) -> None:
        assert apply_labels([], [{"repo": "o/r", "sha": "a" * 40}]) == {}
