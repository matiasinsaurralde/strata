"""The sandboxed stage-2 backend, exercised without touching the network.

The parts worth testing offline are the ones that have already broken once:
the strict-mode schema (the API rejected the first version), null pruning
(strict mode forces every optional field to be present), and the promise that
a sandbox failure degrades to an abstention rather than losing the candidate.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from strata.codex_adjudicator import (
    DECISION_SCHEMA,
    CodexAdjudicator,
    _available_tools,
    _commands_of,
    _prune_nulls,
    _usage_of,
    codex_available,
)

pytestmark = pytest.mark.skipif(not codex_available(), reason="openai-codex not installed")


def _walk_objects(node: Any):
    if isinstance(node, dict):
        if node.get("type") == "object":
            yield node
        for value in node.values():
            yield from _walk_objects(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk_objects(value)


class TestDecisionSchema:
    """Strict structured output has rules the first draft of this schema broke."""

    def test_every_object_lists_all_its_properties_as_required(self):
        # The API rejects a strict schema whose `required` omits any declared
        # property: "'required' is required to be supplied and to be an array
        # including every key in properties."
        for node in _walk_objects(DECISION_SCHEMA):
            assert set(node["required"]) == set(node["properties"]), (
                f"required/properties mismatch on {sorted(node['properties'])}"
            )

    def test_every_object_forbids_additional_properties(self):
        for node in _walk_objects(DECISION_SCHEMA):
            assert node["additionalProperties"] is False

    def test_optional_fields_are_expressed_as_nullable_not_absent(self):
        properties = DECISION_SCHEMA["properties"]
        for name in ("cwe_id", "invariant", "severity", "reachability_delta"):
            assert "anyOf" in properties[name], f"{name} must be nullable, not omitted"
            assert {"type": "null"} in properties[name]["anyOf"]

    def test_required_verdict_fields_are_not_nullable(self):
        for name in ("verdict", "confidence", "rationale"):
            assert "anyOf" not in DECISION_SCHEMA["properties"][name]

    def test_schema_is_json_serialisable(self):
        json.dumps(DECISION_SCHEMA)

    def test_verdict_enum_matches_the_contract(self):
        assert DECISION_SCHEMA["properties"]["verdict"]["enum"] == ["YES", "NO", "ABSTAIN"]


class TestPruneNulls:
    def test_drops_nulls_the_strict_schema_forced_the_model_to_emit(self):
        payload = {"verdict": "NO", "confidence": "high", "cwe_id": None, "severity": None}
        assert _prune_nulls(payload) == {"verdict": "NO", "confidence": "high"}

    def test_recurses_into_nested_objects_and_arrays(self):
        payload = {"evidence": [{"path": "a.go", "note": None}], "severity": {"level": None}}
        assert _prune_nulls(payload) == {"evidence": [{"path": "a.go"}], "severity": {}}

    def test_keeps_falsy_values_that_are_not_null(self):
        # 0, "" and False are answers; only null means "absent".
        assert _prune_nulls({"a": 0, "b": "", "c": False}) == {"a": 0, "b": "", "c": False}


class TestToolAdvertisement:
    def test_read_only_never_advertises_tools_that_need_to_write(self):
        # Advertising `go vet` to a read-only sandbox costs a turn on a
        # command that cannot succeed.
        advertised = " ".join(_available_tools(writes_allowed=False))
        assert "go build" not in advertised
        assert "semgrep" not in advertised

    def test_writable_sandbox_may_advertise_them_when_installed(self):
        import shutil

        advertised = " ".join(_available_tools(writes_allowed=True))
        if shutil.which("semgrep"):
            assert "semgrep" in advertised

    def test_only_installed_tools_are_advertised(self):
        import shutil

        for line in _available_tools(writes_allowed=True):
            name = line.split()[0]
            assert shutil.which(name), f"advertised {name} is not on PATH"


class _Wrapper:
    """Stands in for the SDK's pydantic RootModel item wrapper."""

    def __init__(self, root: Any) -> None:
        self.root = root


class _Command:
    def __init__(self, command: str, exit_code: int | None) -> None:
        self.command = command
        self.exit_code = exit_code


class TestAuditExtraction:
    def test_reads_commands_through_the_root_wrapper(self):
        # Items arrive as RootModel wrappers; reading `.command` off the
        # wrapper silently yields nothing, which is how the first version
        # reported zero commands on a run that made dozens.
        result = type("R", (), {"items": [_Wrapper(_Command("rg -n foo", 0))]})()
        assert _commands_of(result) == (("rg -n foo", 0),)

    def test_records_a_failing_exit_code(self):
        result = type("R", (), {"items": [_Wrapper(_Command("cat nope", 1))]})()
        assert _commands_of(result) == (("cat nope", 1),)

    def test_skips_items_that_are_not_commands(self):
        result = type(
            "R", (), {"items": [_Wrapper(object()), _Wrapper(_Command("git log", 0))]}
        )()
        assert _commands_of(result) == (("git log", 0),)

    def test_joins_list_style_commands(self):
        result = type("R", (), {"items": [_Wrapper(_Command(["sed", "-n", "1p"], 0))]})()  # type: ignore[arg-type]
        assert _commands_of(result) == (("sed -n 1p", 0),)

    def test_usage_descends_into_the_total_breakdown(self):
        breakdown = type(
            "B",
            (),
            {
                "input_tokens": 900,
                "output_tokens": 100,
                "total_tokens": 1000,
                "cached_input_tokens": 400,
                "reasoning_output_tokens": 60,
            },
        )()
        result = type("R", (), {"usage": type("U", (), {"total": breakdown, "last": None})()})()
        usage = _usage_of(result)
        assert (usage.prompt_tokens, usage.completion_tokens) == (900, 100)
        assert usage.cached_tokens == 400
        assert usage.reasoning_tokens == 60

    def test_missing_usage_is_zero_not_an_error(self):
        assert _usage_of(type("R", (), {"usage": None})()).total_tokens == 0


class TestConstruction:
    def test_rejects_an_unknown_sandbox_mode(self):
        with pytest.raises(ValueError, match="unknown sandbox mode"):
            CodexAdjudicator(
                object(), model="m", base_url="http://x", api_key="k", sandbox="yolo"
            )

    @pytest.mark.parametrize("mode", ["read-only", "workspace-write", "full-access"])
    def test_accepts_the_three_codex_modes(self, mode):
        adjudicator = CodexAdjudicator(
            object(), model="m", base_url="http://x", api_key="k", sandbox=mode
        )
        assert adjudicator.sandbox == mode


class TestFailureDegradesToAbstention:
    def test_a_sandbox_crash_abstains_rather_than_losing_the_candidate(self, monkeypatch):
        adjudicator = CodexAdjudicator(object(), model="m", base_url="http://x", api_key="k")

        def explode(*_args, **_kwargs):
            raise RuntimeError("provider exploded")

        monkeypatch.setattr(CodexAdjudicator, "_worktree", explode)
        result = adjudicator.adjudicate({"commit_sha": "a" * 40, "parent_sha": "b" * 40})
        assert result.verdict == "ABSTAIN"
        assert result.decision["abstain_reason"] == "codex_error"
        assert result.validation_errors == ("codex_error:RuntimeError",)

    def test_non_json_output_abstains(self, monkeypatch):
        from strata.codex_adjudicator import _CodexRun

        adjudicator = CodexAdjudicator(object(), model="m", base_url="http://x", api_key="k")

        class _NullWorktree:
            def __enter__(self):
                return "/tmp/nope"

            def __exit__(self, *_exc):
                return False

        monkeypatch.setattr(CodexAdjudicator, "_worktree", lambda self, sha: _NullWorktree())
        monkeypatch.setattr(
            CodexAdjudicator,
            "_run_codex",
            lambda self, *a: _CodexRun(text="I looked at the diff and", elapsed_ms=1.0),
        )
        result = adjudicator.adjudicate({"commit_sha": "a" * 40, "parent_sha": "b" * 40})
        assert result.verdict == "ABSTAIN"
        assert result.decision["abstain_reason"] == "malformed_output"


class TestPromptAssembly:
    def test_go_candidate_receives_the_go_appendix(self, monkeypatch):
        """The language appendix must reach the sandbox, not just exist on disk."""
        from strata.codex_adjudicator import _CodexRun

        adjudicator = CodexAdjudicator(object(), model="m", base_url="http://x", api_key="k")
        seen: dict[str, str] = {}

        class _NullWorktree:
            def __enter__(self):
                return "/tmp/nope"

            def __exit__(self, *_exc):
                return False

        def capture(self, worktree, instructions, task):
            seen["instructions"] = instructions
            return _CodexRun(text="", elapsed_ms=1.0)

        monkeypatch.setattr(CodexAdjudicator, "_worktree", lambda self, sha: _NullWorktree())
        monkeypatch.setattr(CodexAdjudicator, "_run_codex", capture)
        adjudicator.adjudicate(
            {"commit_sha": "a" * 40, "parent_sha": "b" * 40, "affected_paths": ["context.go"]}
        )
        assert "concurrent map writes" in seen["instructions"]
        assert "a" * 40 in seen["instructions"]

    def test_python_candidate_does_not_receive_go_advice(self, monkeypatch):
        from strata.codex_adjudicator import _CodexRun

        adjudicator = CodexAdjudicator(object(), model="m", base_url="http://x", api_key="k")
        seen: dict[str, str] = {}

        class _NullWorktree:
            def __enter__(self):
                return "/tmp/nope"

            def __exit__(self, *_exc):
                return False

        monkeypatch.setattr(CodexAdjudicator, "_worktree", lambda self, sha: _NullWorktree())
        monkeypatch.setattr(
            CodexAdjudicator,
            "_run_codex",
            lambda self, w, i, t: (
                seen.__setitem__("i", i),
                _CodexRun(text="", elapsed_ms=1.0),
            )[1],
        )
        adjudicator.adjudicate(
            {"commit_sha": "a" * 40, "parent_sha": "b" * 40, "affected_paths": ["views.py"]}
        )
        assert "recover()" not in seen["i"]


class TestAuditTrailIsConstructible:
    """Every earlier mock returned zero commands, so nothing built a ToolAudit.

    The result was that the whole 50-commit A/B errored on the first row that
    actually ran a shell command -- ``ToolAudit.__init__() missing 4 required
    positional arguments`` -- after the run had been going for twenty minutes.
    """

    def test_a_run_with_commands_produces_a_populated_audit(self, monkeypatch):
        from strata.codex_adjudicator import _CodexRun

        adjudicator = CodexAdjudicator(object(), model="m", base_url="http://x", api_key="k")

        class _NullWorktree:
            def __enter__(self):
                return "/tmp/nope"

            def __exit__(self, *_exc):
                return False

        monkeypatch.setattr(CodexAdjudicator, "_worktree", lambda self, sha: _NullWorktree())
        monkeypatch.setattr(
            CodexAdjudicator,
            "_run_codex",
            lambda self, *a: _CodexRun(
                text="not json",
                elapsed_ms=5.0,
                commands=(("rg -n foo", 0), ("cat missing", 1)),
            ),
        )
        result = adjudicator.adjudicate({"commit_sha": "a" * 40, "parent_sha": "b" * 40})
        assert result.tool_calls == 2
        assert [a.ok for a in result.tool_audit] == [True, False]
        assert result.tool_audit[1].error == "exit 1"
        assert [a.call_index for a in result.tool_audit] == [0, 1]

    def test_usage_reaches_the_result(self, monkeypatch):
        from strata.codex_adjudicator import _CodexRun
        from strata.llm import TokenUsage

        adjudicator = CodexAdjudicator(object(), model="m", base_url="http://x", api_key="k")

        class _NullWorktree:
            def __enter__(self):
                return "/tmp/nope"

            def __exit__(self, *_exc):
                return False

        monkeypatch.setattr(CodexAdjudicator, "_worktree", lambda self, sha: _NullWorktree())
        monkeypatch.setattr(
            CodexAdjudicator,
            "_run_codex",
            lambda self, *a: _CodexRun(
                text="", elapsed_ms=5.0, usage=TokenUsage(prompt_tokens=10, completion_tokens=2)
            ),
        )
        result = adjudicator.adjudicate({"commit_sha": "a" * 40, "parent_sha": "b" * 40})
        assert result.usage.prompt_tokens == 10
        assert result.elapsed_ms == 5.0


class TestWallClockDeadline:
    """A wedged turn must not hold a worker slot for the rest of the scan.

    AdjudicationLimits.max_time_s is 120s, tuned for the chat backend; a
    sandbox run legitimately takes ~200s, so codex carries its own budget.
    """

    def test_a_run_past_the_deadline_abstains(self, monkeypatch):
        from strata.codex_adjudicator import CodexTimeout

        adjudicator = CodexAdjudicator(
            object(), model="m", base_url="http://x", api_key="k", max_wall_clock_s=0.01
        )

        class _NullWorktree:
            def __enter__(self):
                return "/tmp/nope"

            def __exit__(self, *_exc):
                return False

        def stall(*_args, **_kwargs):
            raise CodexTimeout("no answer within 1s")

        monkeypatch.setattr(CodexAdjudicator, "_worktree", lambda self, sha: _NullWorktree())
        monkeypatch.setattr(CodexAdjudicator, "_run_codex", stall)
        result = adjudicator.adjudicate({"commit_sha": "a" * 40, "parent_sha": "b" * 40})
        assert result.verdict == "ABSTAIN"
        assert result.decision["abstain_reason"] == "timeout"
        assert result.validation_errors == ("timeout",)

    def test_the_deadline_is_configurable_and_defaults_above_a_real_run(self):
        # Observed sandbox runs take ~200s; a default below that would abort
        # healthy work.
        assert (
            CodexAdjudicator(
                object(), model="m", base_url="http://x", api_key="k"
            ).max_wall_clock_s
            >= 300
        )


class TestSandboxOnlyGuidance:
    """Two paragraphs that help the sandboxed backend and hurt the chat one.

    MEASURED. In the shared prompt: chat 78%/78% -> 63%/74%, six non-fixes
    flipped to YES including an introducing commit, every one of them
    answering reachability=narrows. In the codex shell guide: codex
    93%/61% -> 89%/70%, recovering CVE-2023-29401 (2d4bbec941), 81ac7d55a0
    and f9de6049cb, and lifting the veto cascade to 94%/74%.

    The difference is what each model can verify. Codex can trace a call
    graph; chat sees a diff and simply stops applying the test.
    """

    def test_library_reachability_lives_in_the_shell_guide(self):
        from strata.codex_adjudicator import _SHELL_GUIDE

        assert "TRUST BOUNDARY IS THIS REPOSITORY'S OWN API" in _SHELL_GUIDE
        assert "EXPORTED" in _SHELL_GUIDE

    def test_containment_is_scoped_to_availability_in_the_shell_guide(self):
        from strata.codex_adjudicator import _SHELL_GUIDE

        assert "AVAILABILITY ONLY" in _SHELL_GUIDE

    def test_it_is_absent_from_the_shared_prompt(self):
        """The regression guard: this text must not leak back to chat."""
        import json as _json

        from strata.resources import repo_root

        for manifest in ("a0-v1.json", "a1-v1.json"):
            prompt = _json.loads(
                (repo_root() / "prompts" / "adjudicator" / manifest).read_text()
            )["system_prompt"]
            assert "TRUST BOUNDARY IS THIS REPOSITORY'S OWN API" not in prompt

    def test_the_guide_still_formats_with_its_placeholders(self):
        from strata.codex_adjudicator import _SHELL_GUIDE

        rendered = _SHELL_GUIDE.format(commit="a" * 40, parent="b" * 40, tools="  rg")
        assert "a" * 40 in rendered and "{" not in rendered.replace("{}", "")


class TestCliExposesTheBackend:
    """The best-measured configuration must be reachable from the CLI.

    ``ScanConfig`` has carried ``adjudicator``/``sandbox`` since the sandboxed
    backend landed, but nothing on the ``strata scan`` command line set them —
    so a fresh clone could only ever run the chat adjudicator, and the
    sandboxed backend was dead code from a user's point of view.
    """

    def _scan_args(self, argv: list[str]):
        from strata.__main__ import build_parser

        return build_parser().parse_args(["scan", "--repo", ".", *argv])

    def test_adjudicator_defaults_to_chat(self):
        assert self._scan_args([]).adjudicator == "chat"

    def test_codex_is_selectable(self):
        assert self._scan_args(["--adjudicator", "codex"]).adjudicator == "codex"

    def test_sandbox_defaults_to_read_only(self):
        assert self._scan_args([]).sandbox == "read-only"

    @pytest.mark.parametrize("mode", ["read-only", "workspace-write", "full-access"])
    def test_every_sandbox_mode_the_adjudicator_accepts_is_selectable(self, mode):
        from strata.codex_adjudicator import _SANDBOX_MODES

        assert mode in _SANDBOX_MODES
        assert self._scan_args(["--sandbox", mode]).sandbox == mode

    def test_the_flags_reach_scan_config(self):
        """Parsing them is not enough; they have to be threaded through."""
        import inspect

        from strata import __main__

        source = inspect.getsource(__main__._run_scan)
        assert "adjudicator=arguments.adjudicator" in source
        assert "sandbox=arguments.sandbox" in source
