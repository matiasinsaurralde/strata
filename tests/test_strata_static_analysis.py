from __future__ import annotations

from strata.static_analysis import (
    AblationRunner,
    AnalysisRequest,
    CodeQLAnalyzer,
    TextBaselineAnalyzer,
    TreeSitterAnalyzer,
    filter_comment_whitespace_hunks,
    hunk_to_symbol,
    parse_unified_diff,
    probe_availability,
    search_similar_call_sites,
)

GO_SOURCE = """\
package service

func Handle(input string) string {
    return Render(input)
}

func Preview(input string) string {
    return Render(input)
}
"""

DIFF = """\
diff --git a/service.go b/service.go
--- a/service.go
+++ b/service.go
@@ -3,3 +3,3 @@
 func Handle(input string) string {
-    return input
+    return Render(input)
 }
"""


def test_hunk_parser_symbol_fallback_and_similar_calls() -> None:
    hunks = parse_unified_diff(DIFF)
    assert len(hunks) == 1
    assert hunks[0].path == "service.go"
    anchor = hunk_to_symbol(GO_SOURCE, 4, path="service.go")
    assert anchor.symbol == "Handle"
    mapped = TextBaselineAnalyzer().analyze(
        AnalysisRequest(
            diff=DIFF,
            before_files={"service.go": GO_SOURCE.replace("Render(input)", "input", 1)},
            after_files={"service.go": GO_SOURCE},
        )
    )
    assert mapped.status == "ok"
    assert mapped.findings["hunk_symbols"][0]["symbol"]["symbol"] == "Handle"
    calls = search_similar_call_sites(hunks, {"service.go": GO_SOURCE})
    assert any(call["symbol"] == "Preview" for call in calls)
    assert mapped.metrics["estimated_cost_usd"] == 0.0


def test_comment_and_whitespace_filtering_is_conservative() -> None:
    cosmetic = """\
diff --git a/a.go b/a.go
--- a/a.go
+++ b/a.go
@@ -1,2 +1,2 @@
-// old explanation
+// clearer explanation
 func f() {}
"""
    substantive, metrics = filter_comment_whitespace_hunks(cosmetic)
    assert substantive == []
    assert metrics["filtered_hunks"] == 1

    directive = cosmetic.replace(
        "-// old explanation\n+// clearer explanation",
        "-//go:build linux\n+//go:build darwin",
    )
    substantive, _ = filter_comment_whitespace_hunks(directive)
    assert len(substantive) == 1


def test_availability_probes_do_not_claim_missing_tools() -> None:
    missing = probe_availability(
        "codeql",
        executable_names=("codeql",),
        which=lambda _name: None,
        find_spec=lambda _name: None,
    )
    assert missing.available is False
    assert "not installed" in missing.reason

    installed = probe_availability(
        "codeql",
        executable_names=("codeql",),
        which=lambda _name: "/opt/bin/codeql",
        find_spec=lambda _name: None,
    )
    assert installed.available is True
    assert installed.executable == "/opt/bin/codeql"


def test_ablation_reports_available_unavailable_and_probe_only_arms() -> None:
    def no_tools(_name):
        return None

    def no_modules(_name):
        return None

    baseline = TextBaselineAnalyzer()
    tree = TreeSitterAnalyzer(which=no_tools, find_spec=no_modules)
    unavailable_codeql = CodeQLAnalyzer(which=no_tools, find_spec=no_modules)
    found_codeql = CodeQLAnalyzer(
        which=lambda name: "/bin/codeql" if name == "codeql" else None,
        find_spec=no_modules,
    )
    found_codeql.name = "codeql_probe_only"
    report = AblationRunner((baseline, tree, unavailable_codeql, found_codeql)).run(
        DIFF, after_files={"service.go": GO_SOURCE}
    )
    data = report.to_dict()
    assert data["arms"]["text_baseline"]["status"] == "ok"
    assert data["arms"]["tree_sitter"]["status"] == "unavailable"
    assert data["arms"]["codeql"]["availability"]["available"] is False
    assert data["arms"]["codeql_probe_only"]["status"] == "available_not_run"
    assert data["summary"]["total_external_processes"] == 0
