"""Tests for the parser-backed symbol resolver and its ablation arm.

These pin the behaviours that make tree-sitter better than the regex baseline
(receivers, generics, nested scopes, doc-comment attachment) and the two known
blind spots of the token-based cosmetic classifier, so a regression in either
direction is caught.
"""

from __future__ import annotations

from strata.static_analysis import AnalysisRequest, hunk_to_symbol, run_ablation
from strata.tree_sitter_symbols import (
    enclosing_symbol,
    enumerate_symbols,
    is_cosmetic_change,
    language_for_path,
)

GO = """\
package service

type Server struct {
    addr string
}

// Handle serves one request.
func (s *Server) Handle(w int) error {
    cb := func(v int) int { return v + 1 }
    return cb(w)
}

func getTyped[T any](s *Server, key string) (res T) {
    res, _ = s.lookup(key).(T)
    return
}
"""

PY = """\
class HTTPDigestAuth:
    def build_header(self, method, url):
        def md5_utf8(x):
            return hash(x)

        hash_utf8 = md5_utf8
        path = url or "/"
        return path
"""


def test_language_detection() -> None:
    assert language_for_path("a/b/c.go") == "go"
    assert language_for_path("x.py") == "python"
    assert language_for_path("x.ts") == "typescript"
    assert language_for_path("README.md") is None


def test_go_method_receiver_is_recovered() -> None:
    # A line inside the method body resolves to the qualified (receiver, name).
    anchor = enclosing_symbol(GO, 10, path="service.go")
    assert anchor is not None
    assert anchor.symbol == "(*Server).Handle"
    assert anchor.kind == "method"
    assert anchor.method == "tree_sitter"
    # The regex baseline drops the receiver on the same line.
    assert hunk_to_symbol(GO, 10, path="service.go").symbol == "Handle"


def test_line_inside_closure_maps_to_enclosing_method() -> None:
    # The func literal on line 9 is anonymous; its body still belongs to Handle.
    anchor = enclosing_symbol(GO, 9, path="service.go")
    assert anchor is not None
    assert anchor.symbol == "(*Server).Handle"


def test_go_generic_function_is_resolved_where_regex_fails() -> None:
    # Line 14 is inside getTyped[T any]; the regex cannot match a generic
    # signature and mislabels it as the previous function.
    anchor = enclosing_symbol(GO, 14, path="service.go")
    assert anchor is not None
    assert anchor.symbol == "getTyped"
    baseline = hunk_to_symbol(GO, 14, path="service.go").symbol
    assert baseline != "getTyped"  # the regex is wrong here


def test_doc_comment_attaches_to_following_symbol() -> None:
    # Line 7 is Handle's doc comment, above the func node's span.
    anchor = enclosing_symbol(GO, 7, path="service.go")
    assert anchor is not None
    assert anchor.symbol == "(*Server).Handle"
    assert anchor.method == "tree_sitter_doc"


def test_python_nested_scope_attributed_to_enclosing_method() -> None:
    # `hash_utf8 = md5_utf8` (line 6) runs in build_header, not in the closed
    # nested md5_utf8 -- the classic indentation-heuristic failure.
    anchor = enclosing_symbol(PY, 6, path="auth.py")
    assert anchor is not None
    assert anchor.symbol == "HTTPDigestAuth.build_header"
    assert hunk_to_symbol(PY, 6, path="auth.py").symbol != "HTTPDigestAuth.build_header"


def test_enumerate_symbols_reports_spans_and_receivers() -> None:
    spans = enumerate_symbols(GO, "service.go")
    assert spans is not None
    by_name = {s.name: s for s in spans}
    assert by_name["(*Server).Handle"].receiver == "*Server"
    assert by_name["(*Server).Handle"].kind == "method"
    assert by_name["Server"].kind == "type"
    assert by_name["getTyped"].kind == "function"


def test_unsupported_language_returns_none() -> None:
    assert enclosing_symbol("x = 1", 1, path="notes.txt") is None
    assert enumerate_symbols("x", "notes.txt") is None
    assert is_cosmetic_change("a", "b", path="notes.txt") is None


def test_cosmetic_classifier_ignores_comments_but_sees_code() -> None:
    before = "func f() int {\n  return 1 // one\n}\n"
    comment_only = "func f() int {\n  return 1 // uno\n}\n"
    real_change = "func f() int {\n  return 2 // one\n}\n"
    assert is_cosmetic_change(before, comment_only, path="x.go") is True
    assert is_cosmetic_change(before, real_change, path="x.go") is False


def test_cosmetic_classifier_known_blind_spot_behavioral_directive() -> None:
    # Documented limitation: a //go:build directive is a comment to the grammar,
    # so a pure token comparison cannot see that it is behavioural. A production
    # classifier must keep the regex's behavioural-directive guard on top.
    before = "//go:build linux\npackage p\n"
    after = "//go:build darwin\npackage p\n"
    assert is_cosmetic_change(before, after, path="x.go") is True  # blind spot


def test_ablation_arm_recovers_receiver_over_text_baseline() -> None:
    diff = """\
diff --git a/service.go b/service.go
--- a/service.go
+++ b/service.go
@@ -8,3 +8,4 @@
 func (s *Server) Handle(w int) error {
+    audit(w)
     cb := func(v int) int { return v + 1 }
     return cb(w)
 }
"""
    report = run_ablation(
        AnalysisRequest(diff=diff, after_files={"service.go": GO}),
    ).to_dict()
    arm = report["arms"]["tree_sitter_symbols"]
    assert arm["status"] == "ok"
    assert arm["metrics"]["parsed_hunks"] == 1
    symbol = arm["findings"]["hunk_symbols"][0]["symbol"]
    assert symbol["symbol"] == "(*Server).Handle"
    # text baseline on the same hunk cannot name the receiver
    text_symbol = report["arms"]["text_baseline"]["findings"]["hunk_symbols"][0]["symbol"]
    assert text_symbol["symbol"] == "Handle"
