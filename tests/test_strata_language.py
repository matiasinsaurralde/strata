"""Language detection and the prompt appendices it selects."""

from __future__ import annotations

import json

import pytest

from strata.language import (
    APPENDIX_DIR,
    detect_language,
    language_appendix,
    paths_of_candidate,
)


class TestDetectLanguage:
    @pytest.mark.parametrize(
        ("paths", "expected"),
        [
            (["context.go"], "go"),
            (["src/pkg/handler.go", "src/pkg/handler_test.go"], "go"),
            (["app/views.py"], "python"),
            (["lib/parse.ts", "lib/parse.tsx"], "javascript"),
            (["server.mjs"], "javascript"),
            ([], None),
        ],
    )
    def test_reads_the_majority_language(self, paths, expected):
        assert detect_language(paths) == expected

    def test_documentation_and_lockfiles_do_not_vote(self):
        assert detect_language(["README.md", "go.sum", "go.mod", "data.json"]) is None

    def test_source_outvotes_a_pile_of_tests_in_another_language(self):
        # A Go fix shipped with generated JS test fixtures is still a Go fix.
        paths = ["router.go", "testdata/a_test.js", "testdata/b_test.js", "testdata/c_test.js"]
        assert detect_language(paths) == "go"

    def test_unknown_extensions_are_ignored_rather_than_guessed(self):
        assert detect_language(["main.rs", "lib.rb", "app.ex"]) is None


class TestPathsOfCandidate:
    def test_collects_from_every_field_without_duplicates(self):
        candidate = {
            "affected_paths": ["a.go", "b.go"],
            "evidence": [{"path": "b.go"}, {"path": "c.go"}],
            "diff_files": [{"path": "d.go"}],
        }
        assert paths_of_candidate(candidate) == ("a.go", "b.go", "c.go", "d.go")

    def test_tolerates_objects_with_a_path_attribute(self):
        class Change:
            path = "e.go"

        assert paths_of_candidate({"changed_paths": [Change()]}) == ("e.go",)

    def test_empty_candidate_yields_nothing(self):
        assert paths_of_candidate({}) == ()


class TestLanguageAppendix:
    def test_go_candidate_gets_the_go_appendix(self):
        appendix = language_appendix({"affected_paths": ["context.go"]})
        assert "recover()" in appendix
        assert "concurrent map writes" in appendix

    def test_python_candidate_does_not_get_go_advice(self):
        appendix = language_appendix({"affected_paths": ["views.py"]})
        assert "recover()" not in appendix
        assert "C extension" in appendix

    def test_unknown_language_gets_no_appendix(self):
        # A generic prompt beats a wrong one: better to say nothing about
        # containment in Rust than to hand the model Go's rules for it.
        assert language_appendix({"affected_paths": ["main.rs"]}) == ""

    def test_appendix_is_separated_so_callers_can_concatenate_blindly(self):
        appendix = language_appendix({"affected_paths": ["context.go"]})
        assert appendix.startswith("\n\n")
        assert appendix.endswith("\n")

    def test_every_shipped_appendix_is_reachable_from_some_extension(self):
        from strata.language import _EXTENSIONS

        shipped = {p.stem for p in APPENDIX_DIR.glob("*.md")}
        assert shipped, "no appendices found"
        assert shipped <= set(_EXTENSIONS.values()), (
            "an appendix exists that no file extension maps to, so it can never load"
        )


class TestBasePromptsStayLanguageNeutral:
    """The Go specifics live in the appendix; the base prompt must not re-learn them.

    This is the regression guard for the split. If somebody re-adds
    Go vocabulary to the shared prompt, every Python and JavaScript
    adjudication silently inherits advice that is wrong for it.
    """

    @pytest.mark.parametrize("manifest", ["a0-v1.json", "a1-v1.json"])
    def test_no_go_specifics_in_the_shared_prompt(self, manifest):
        from strata.resources import repo_root

        prompt = json.loads((repo_root() / "prompts" / "adjudicator" / manifest).read_text())[
            "system_prompt"
        ]
        for term in ("recover()", "goroutine", "concurrent map writes", "sync.Pool"):
            assert term not in prompt, f"{term!r} belongs in lang/go.md, not the base prompt"

    @pytest.mark.parametrize("manifest", ["a0-v1.json", "a1-v1.json"])
    def test_the_generic_containment_test_survives(self, manifest):
        from strata.resources import repo_root

        prompt = json.loads((repo_root() / "prompts" / "adjudicator" / manifest).read_text())[
            "system_prompt"
        ]
        assert "CONTAINMENT" in prompt
        assert "failure_containment" in prompt


class TestV8WasRevertedFromTheSharedPrompt:
    """v8's two paragraphs regressed chat and must not return to the base prompt.

    MEASURED: 78%/78% -> 63%/74%. Six non-fixes flipped to YES, every one
    answering reachability=narrows, including grpc-go 39f16539d2 which is an
    INTRODUCING commit. Telling a model that only sees a diff that "an
    exported argument is attacker-controlled" removes the reachability test
    rather than correcting it.

    The paragraphs address real codex failures and live in the sandboxed
    backend's own guide, where the model can actually check a call graph.
    """

    @pytest.mark.parametrize("manifest", ["a0-v1.json", "a1-v1.json"])
    def test_library_reachability_is_not_in_the_shared_prompt(self, manifest):
        from strata.resources import repo_root

        prompt = json.loads((repo_root() / "prompts" / "adjudicator" / manifest).read_text())[
            "system_prompt"
        ]
        assert "TRUST BOUNDARY IS THIS REPOSITORY'S OWN API" not in prompt
        assert "AVAILABILITY only" not in prompt

    @pytest.mark.parametrize("manifest", ["a0-v1.json", "a1-v1.json"])
    def test_the_reason_is_recorded_in_the_manifest(self, manifest):
        # A future reader must be able to see this was tried and measured,
        # not merely never considered.
        from strata.resources import repo_root

        notes = json.loads((repo_root() / "prompts" / "adjudicator" / manifest).read_text())[
            "notes"
        ]
        assert "63%" in notes and "39f16539d2" in notes
