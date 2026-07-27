"""Pre-filter admission rules and the M0/M1/M2 message conditions."""

from __future__ import annotations

import pytest

from strata.prefilter import PrefilterReason, PrefilterStats, prefilter_commit
from strata_eval.redaction import (
    MessageCondition,
    apply_condition,
    redact_message,
    table_manifest,
)


def _paths(*names: str) -> list[dict[str, str]]:
    return [{"path": name} for name in names]


_DIFF = "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-old\n+new\n"


class TestPrefilterAdmission:
    def test_source_change_is_admitted(self) -> None:
        decision = prefilter_commit(_paths("internal/server.go"), _DIFF)
        assert decision.admit is True
        assert decision.reason is None
        assert decision.first_party_paths == ("internal/server.go",)

    @pytest.mark.parametrize(
        ("paths", "reason"),
        [
            (["README.md", "docs/guide.md"], PrefilterReason.DOCS_ONLY),
            (["go.mod", "go.sum"], PrefilterReason.DEPENDENCY_ONLY),
            (["vendor/x/y.go"], PrefilterReason.GENERATED_VENDOR_ONLY),
        ],
    )
    def test_non_source_only_commits_are_rejected_with_a_reason(
        self, paths: list[str], reason: PrefilterReason
    ) -> None:
        decision = prefilter_commit(_paths(*paths), _DIFF)
        assert decision.admit is False
        assert decision.reason is reason

    def test_source_alongside_docs_still_admits(self) -> None:
        decision = prefilter_commit(_paths("README.md", "server.go"), _DIFF)
        assert decision.admit is True

    def test_tests_are_flagged_not_silently_dropped(self) -> None:
        """A security test beside a fix is evidence."""
        mixed = prefilter_commit(_paths("server.go", "server_test.go"), _DIFF)
        assert mixed.admit is True
        assert mixed.touches_tests is True

    def test_test_only_is_rejected_but_recorded_as_such(self) -> None:
        only = prefilter_commit(_paths("server_test.go"), _DIFF)
        assert only.admit is False
        assert only.reason is PrefilterReason.TEST_ONLY
        assert only.touches_tests is True

    def test_empty_diff_is_rejected(self) -> None:
        assert prefilter_commit(_paths("a.go"), "").reason is PrefilterReason.EMPTY_DIFF
        assert prefilter_commit([], _DIFF).reason is PrefilterReason.EMPTY_DIFF

    def test_oversize_only_applies_when_a_cap_is_set(self) -> None:
        big = "x" * 5000
        assert prefilter_commit(_paths("a.go"), big, max_diff_bytes=100).reason is (
            PrefilterReason.OVERSIZE
        )
        assert prefilter_commit(_paths("a.go"), big).admit is True

    def test_bytes_and_str_patches_agree(self) -> None:
        as_text = prefilter_commit(_paths("a.go"), _DIFF)
        as_bytes = prefilter_commit(_paths("a.go"), _DIFF.encode())
        assert as_text.diff_bytes == as_bytes.diff_bytes == len(_DIFF.encode())


class TestPrefilterStats:
    def test_reduction_rate_is_reported(self) -> None:
        stats = PrefilterStats()
        stats.record(prefilter_commit(_paths("a.go"), _DIFF))
        for _ in range(3):
            stats.record(prefilter_commit(_paths("README.md"), _DIFF))
        assert stats.seen == 4
        assert stats.admitted == 1
        assert stats.reduction_rate == pytest.approx(0.75)
        assert stats.to_dict()["rejected_by_reason"]["docs_only"] == 3

    def test_empty_stats_do_not_divide_by_zero(self) -> None:
        assert PrefilterStats().reduction_rate == 0.0


class TestMessageConditions:
    def test_m0_is_the_message_unchanged(self) -> None:
        message = "security: fix CVE-2023-29401"
        result = apply_condition(message, MessageCondition.M0)
        assert result.text == message
        assert result.changed is False

    def test_m1_redacts_but_does_not_delete(self) -> None:
        """An empty message is itself a tell."""
        message = "security: fix CVE-2023-29401 path traversal in FileAttachment"
        result = apply_condition(message, MessageCondition.M1)
        assert "CVE-2023-29401" not in result.text
        assert "path traversal" not in result.text.lower()
        assert "FileAttachment" in result.text, "ordinary prose must survive"
        assert result.text.strip()

    def test_m1_records_what_it_removed(self) -> None:
        result = redact_message("Fix GHSA-abcd-efgh-ijkl XSS in the renderer")
        assert "GHSA-abcd-efgh-ijkl" in result.removed_identifiers
        assert "xss" in [k.lower() for k in result.removed_keywords]

    def test_m1_leaves_non_security_messages_untouched(self) -> None:
        message = "Bump golang.org/x/crypto from 0.52.0 to 0.53.0"
        result = apply_condition(message, MessageCondition.M1)
        assert result.text == message
        assert result.changed is False

    def test_m2_is_a_neutral_stub(self) -> None:
        result = apply_condition("security: anything", MessageCondition.M2)
        assert result.text == "Update implementation."

    @pytest.mark.parametrize(
        "identifier",
        ["CVE-2023-1234", "GHSA-abcd-efgh-ijkl", "CWE-79", "GO-2023-1737", "OSV-2021-889"],
    )
    def test_every_identifier_family_is_stripped(self, identifier: str) -> None:
        assert identifier not in redact_message(f"see {identifier} for detail").text

    def test_advisory_urls_are_stripped(self) -> None:
        text = redact_message("ref https://nvd.nist.gov/vuln/detail/CVE-2023-1 here").text
        assert "nvd.nist.gov" not in text
        assert "here" in text

    def test_manifest_pins_both_tables(self) -> None:
        manifest = table_manifest()
        assert manifest["redaction_table_version"]
        assert manifest["keyword_table_version"]
        assert set(manifest["conditions"]) == {"M0", "M1", "M2"}
