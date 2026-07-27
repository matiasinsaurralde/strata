"""Security-context compilation: aggregation is code, not a model."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from strata.context import (
    RepoRef,
    ScanStats,
    build_agent_brief,
    compile_context,
    component_of,
    normalise_component,
    recency_weight,
    write_narrative,
)

NOW = datetime(2026, 7, 26, tzinfo=UTC)

REPO = RepoRef(
    owner="gin-gonic",
    name="gin",
    url="https://github.com/gin-gonic/gin",
    ref="master",
    head_sha="d" * 40,
)
SCAN = ScanStats(
    commits_scanned=100,
    commits_triaged=60,
    triage_candidates=8,
    adjudicated=8,
    findings=3,
    abstained=2,
    rejected=3,
)


def _finding(
    sha: str,
    *,
    l0_class: str = "injection",
    path: str = "context.go",
    date: str = "2026-01-02T00:00:00Z",
    invariant: str | None = "Filenames must be escaped before use in a header.",
    quote: str = "escapeQuotes(filename)",
    severity: str = "medium",
    cwe: str | None = "CWE-113",
) -> dict[str, Any]:
    return {
        "commit_sha": sha,
        "commit_date": date,
        "commit_subject": f"fix something in {path}",
        "l0_class": l0_class,
        "cwe_id": cwe,
        "severity": {"level": severity, "source": "model_estimate"},
        "affected_paths": [path],
        "fix_completeness": "complete",
        "invariant": invariant,
        "root_cause": "Unescaped input reached a header.",
        "impact": "Header injection.",
        "fix_effect": "Escapes the value first.",
        "evidence": [
            {
                "revision": "commit",
                "revision_sha": sha,
                "path": path,
                "start_line": 10,
                "end_line": 10,
                "quoted_span": quote,
                "supports": ["root_cause", "fix_effect"],
            }
        ],
    }


class _RepoWithHead:
    """Head content used for Theseus folding."""

    def __init__(self, content: str) -> None:
        self.content = content

    def read_blob(self, revision: str, path: str, **_: Any) -> bytes:
        return self.content.encode()


class TestComponentNormalisation:
    """An uncanonicalised tally emits Context / context / context.go as three keys."""

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("context.go", "context.go"),
            ("Context.GO", "context.go"),
            ("a/context.go", "context.go"),
            ("b/context.go", "context.go"),
            ("./context.go", "context.go"),
            ("internal\\pkg\\ctx.go", "internal/pkg/ctx.go"),
            ("", ""),
        ],
    )
    def test_canonical_forms(self, value: str, expected: str) -> None:
        assert normalise_component(value) == expected

    def test_one_component_yields_one_count(self) -> None:
        context = compile_context(
            [
                _finding("a" * 40, path="context.go"),
                _finding("b" * 40, path="a/context.go"),
                _finding("c" * 40, path="./Context.GO"),
            ],
            repo_ref=REPO,
            scan=SCAN,
            provenance={},
            now=NOW,
        )
        assert context.component_counts == {"context.go": 3}

    def test_component_of_is_path_based(self) -> None:
        assert component_of("a/internal/ctx.go") == "internal/ctx.go"


class TestRecencyWeighting:
    """Hotspots weight by recency, not raw count."""

    def test_recent_outweighs_old(self) -> None:
        recent = recency_weight("2026-06-01T00:00:00Z", now=NOW)
        old = recency_weight("2014-12-21T00:00:00Z", now=NOW)
        assert recent > old > 0

    def test_half_life_is_two_years(self) -> None:
        assert recency_weight("2024-07-26T00:00:00Z", now=NOW) == pytest.approx(0.5, abs=0.02)

    def test_unparseable_dates_do_not_raise(self) -> None:
        assert 0 < recency_weight("not-a-date", now=NOW) <= 1
        assert 0 < recency_weight(None, now=NOW) <= 1

    def test_ranking_prefers_the_fresher_hotspot(self) -> None:
        context = compile_context(
            [
                _finding("a" * 40, path="old.go", date="2014-01-01T00:00:00Z"),
                _finding("b" * 40, path="old.go", date="2014-02-01T00:00:00Z"),
                _finding("c" * 40, path="new.go", date="2026-06-01T00:00:00Z"),
            ],
            repo_ref=REPO,
            scan=SCAN,
            provenance={},
            now=NOW,
        )
        assert context.top_risks[0].component == "new.go", (
            "two ancient fixes should not outrank a recent one"
        )


class TestFingerprints:
    def test_anchors_survive_compilation(self) -> None:
        context = compile_context(
            [_finding("a" * 40)], repo_ref=REPO, scan=SCAN, provenance={}, now=NOW
        )
        anchors = context.fingerprints[0].anchors
        assert len(anchors) == 1
        assert anchors[0].path == "context.go"
        assert anchors[0].quoted_span == "escapeQuotes(filename)"
        assert anchors[0].revision_sha == "a" * 40

    def test_sink_symbols_come_only_from_verified_quotes(self) -> None:
        context = compile_context(
            [_finding("a" * 40, quote="c.Writer.Header().Set(key, value)")],
            repo_ref=REPO,
            scan=SCAN,
            provenance={},
            now=NOW,
        )
        symbols = context.fingerprints[0].sink_symbols
        assert any("Set" in symbol or "Header" in symbol for symbol in symbols)

    def test_fingerprints_are_newest_first(self) -> None:
        context = compile_context(
            [
                _finding("a" * 40, date="2019-01-01T00:00:00Z"),
                _finding("b" * 40, date="2026-01-01T00:00:00Z"),
            ],
            repo_ref=REPO,
            scan=SCAN,
            provenance={},
            now=NOW,
        )
        assert [f.commit_sha[0] for f in context.fingerprints] == ["b", "a"]

    def test_findings_without_a_sha_are_dropped(self) -> None:
        context = compile_context(
            [{"l0_class": "injection"}], repo_ref=REPO, scan=SCAN, provenance={}, now=NOW
        )
        assert context.fingerprints == ()


class TestTheseusFolding:
    """Is the anchored code still at HEAD?"""

    def test_present_at_head(self) -> None:
        context = compile_context(
            [_finding("a" * 40, quote="escapeQuotes(filename)")],
            repo_ref=REPO,
            scan=SCAN,
            provenance={},
            repository=_RepoWithHead("x := escapeQuotes(filename)\n"),
            now=NOW,
        )
        assert context.fingerprints[0].still_applies is True

    def test_absent_from_head(self) -> None:
        context = compile_context(
            [_finding("a" * 40, quote="escapeQuotes(filename)")],
            repo_ref=REPO,
            scan=SCAN,
            provenance={},
            repository=_RepoWithHead("this subsystem was deleted\n"),
            now=NOW,
        )
        assert context.fingerprints[0].still_applies is False

    def test_unknown_without_a_repository(self) -> None:
        context = compile_context(
            [_finding("a" * 40)], repo_ref=REPO, scan=SCAN, provenance={}, now=NOW
        )
        assert context.fingerprints[0].still_applies is None


class TestRemediation:
    """The coverage number ships with its own formula."""

    def test_formula_and_definition_are_present(self) -> None:
        context = compile_context(
            [_finding("a" * 40)], repo_ref=REPO, scan=SCAN, provenance={}, now=NOW
        )
        assert context.remediation.formula
        assert "measurable_fixes" in context.remediation.definition

    def test_deleted_code_is_excluded_not_counted_as_remediated(self) -> None:
        context = compile_context(
            [_finding("a" * 40, quote="gone")],
            repo_ref=REPO,
            scan=SCAN,
            provenance={},
            repository=_RepoWithHead("nothing here"),
            now=NOW,
        )
        assert context.remediation.measurable_fixes == 0
        assert context.remediation.coverage is None

    def test_coverage_is_reproducible_from_its_own_fields(self) -> None:
        context = compile_context(
            [_finding("a" * 40, quote="present"), _finding("b" * 40, quote="present")],
            repo_ref=REPO,
            scan=SCAN,
            provenance={},
            repository=_RepoWithHead("present"),
            now=NOW,
        )
        remediation = context.remediation
        expected = 100.0 * remediation.guarded_fixes / remediation.measurable_fixes
        assert remediation.coverage == pytest.approx(expected)


class TestSharedSurfaces:
    def test_a_surface_needs_more_than_one_entry_point(self) -> None:
        single = compile_context(
            [_finding("a" * 40)], repo_ref=REPO, scan=SCAN, provenance={}, now=NOW
        )
        assert single.shared_surfaces == ()

        multiple = compile_context(
            [_finding("a" * 40, path="context.go"), _finding("b" * 40, path="gin.go")],
            repo_ref=REPO,
            scan=SCAN,
            provenance={},
            now=NOW,
        )
        assert multiple.shared_surfaces
        assert set(multiple.shared_surfaces[0].entry_points) == {"context.go", "gin.go"}

    def test_findings_without_an_invariant_form_no_surface(self) -> None:
        context = compile_context(
            [
                _finding("a" * 40, path="context.go", invariant=None),
                _finding("b" * 40, path="gin.go", invariant=None),
            ],
            repo_ref=REPO,
            scan=SCAN,
            provenance={},
            now=NOW,
        )
        assert context.shared_surfaces == ()


class TestNarrative:
    def test_agent_brief_is_deterministic_without_a_model(self) -> None:
        context = compile_context(
            [_finding("a" * 40, path="context.go"), _finding("b" * 40, path="gin.go")],
            repo_ref=REPO,
            scan=SCAN,
            provenance={},
            now=NOW,
        )
        assert build_agent_brief(context) == build_agent_brief(context)

    def test_brief_names_the_repo_and_the_hunting_rules(self) -> None:
        context = compile_context(
            [_finding("a" * 40)], repo_ref=REPO, scan=SCAN, provenance={}, now=NOW
        )
        brief = build_agent_brief(context)
        assert "gin-gonic/gin" in brief
        assert "Re-confirming an already-fixed issue is NOT a finding" in brief
        assert "VERIFY before reporting" in brief

    def test_narrative_survives_a_model_failure(self) -> None:
        class Broken:
            def complete(self, *_a: Any, **_k: Any):
                raise RuntimeError("endpoint down")

        context = compile_context(
            [_finding("a" * 40)], repo_ref=REPO, scan=SCAN, provenance={}, now=NOW
        )
        written = write_narrative(context, client=Broken())
        assert written.summary, "a narrative failure must not void the artifact"
        assert written.agent_brief

    def test_empty_scan_says_so_plainly(self) -> None:
        context = compile_context([], repo_ref=REPO, scan=SCAN, provenance={}, now=NOW)
        assert "No confirmed security fixes" in write_narrative(context).summary


class TestSerialisation:
    def test_leads_are_withheld_by_default(self) -> None:
        from strata.context import Lead

        lead = Lead(
            path="x.go",
            line=1,
            symbol=None,
            matched_sink="s",
            origin_fingerprint="fp_1",
            rationale="r",
        )
        context = compile_context(
            [_finding("a" * 40)], repo_ref=REPO, scan=SCAN, provenance={}, leads=[lead], now=NOW
        )
        default = context.to_dict()
        assert "leads" not in default
        assert default["leads_withheld"] == 1
        assert len(context.to_dict(include_leads=True)["leads"]) == 1

    def test_document_carries_schema_and_provenance(self) -> None:
        context = compile_context(
            [_finding("a" * 40)],
            repo_ref=REPO,
            scan=SCAN,
            provenance={"model": "gpt-5.4", "cwe_catalog": "4.20"},
            now=NOW,
        )
        document = context.to_dict()
        assert document["schema_version"] == "security-context-v1"
        assert document["provenance"]["model"] == "gpt-5.4"
        assert document["scan"]["commits_scanned"] == 100
