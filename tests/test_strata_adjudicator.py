from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from strata.adjudicator import (
    REQUIRED_ON_YES,
    AdjudicationLimits,
    AdjudicationValidationError,
    Adjudicator,
    Profile,
    RepositoryTools,
    validate_adjudication,
)
from strata.contracts import FindingV1
from strata.llm import LLMConfig, OpenAIChatClient

COMMIT = "a" * 40
PARENT = "b" * 40
PATH = "src/handler.py"
SOURCE = "def handle(value):\n    return escape(value)\n"
ALL_CLAIMS = [
    "reachability_delta",
    "failure_containment",
    "root_cause",
    "attacker_preconditions",
    "impact",
    "fix_effect",
    "l0_class",
    "cwe_id",
    "severity",
    "affected_paths",
    "fix_completeness",
]


class FakeRepo:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    def get_commit_metadata(self, revision: str) -> dict:
        self.calls.append(("show_commit", revision))
        return {"sha": revision, "parents": [PARENT], "message": "escape output"}

    def diff_for_commit(self, revision: str) -> bytes:
        self.calls.append(("show_diff", revision))
        return b"+    return escape(value)\n"

    def read_blob(self, revision: str, path: str, *, max_bytes: int = 1_000_000) -> bytes:
        self.calls.append(("read_blob", (revision, path, max_bytes)))
        return SOURCE.encode()

    def read_range(
        self,
        revision: str,
        path: str,
        start_line: int,
        end_line: int,
        **_kwargs,
    ) -> str:
        self.calls.append(("read_range", (revision, path, start_line, end_line)))
        assert path == PATH
        return "".join(SOURCE.splitlines(keepends=True)[start_line - 1 : end_line])

    def search_text(
        self,
        revision: str,
        query: str,
        *,
        path: str | None = None,
        max_results: int = 100,
    ) -> list[dict]:
        self.calls.append(("search", (revision, query, path, max_results)))
        return [{"path": PATH, "line": 2, "text": "return escape(value)"}]

    def resolve_revision(self, revision: str) -> str:
        return revision


class FakeLLM:
    def __init__(self, *responses: object) -> None:
        self.responses = list(responses)
        self.requests: list[dict] = []

    def complete(self, messages: list[dict], **kwargs):
        self.requests.append({"messages": messages, **kwargs})
        return self.responses.pop(0)


def _sdk_returning(responses: list[dict]):
    """Minimal stand-in for ``openai.OpenAI`` that replays dict payloads.

    ``OpenAIChatClient`` reads the SDK's attribute-shaped response objects, so
    the recorded dicts are wrapped in namespaces rather than passed through.
    """

    def wrap(payload: dict) -> SimpleNamespace:
        choice = payload["choices"][0]
        message = choice["message"]
        calls = [
            SimpleNamespace(
                id=call["id"],
                function=SimpleNamespace(
                    name=call["function"]["name"],
                    arguments=call["function"]["arguments"],
                ),
            )
            for call in message.get("tool_calls") or []
        ]
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content=message.get("content"), tool_calls=calls),
                    finish_reason=choice.get("finish_reason", "stop"),
                )
            ],
            usage=None,
            model="fake",
            id="resp",
        )

    class _Completions:
        def create(self, **_kwargs):
            return wrap(responses.pop(0))

    return SimpleNamespace(chat=SimpleNamespace(completions=_Completions()))


def _tool_call(name: str, arguments: dict, call_id: str = "call-1") -> dict:
    return {
        "content": None,
        "tool_calls": [
            {
                "id": call_id,
                "type": "function",
                "function": {
                    "name": name,
                    "arguments": json.dumps(arguments),
                },
            }
        ],
    }


def _yes() -> dict:
    return {
        "verdict": "YES",
        "confidence": "high",
        "rationale": "The added escaping blocks attacker-controlled markup.",
        "root_cause": "Untrusted markup was returned without output encoding.",
        "attacker_preconditions": "An attacker can control value.",
        "impact": "Script execution in another user's browser.",
        "fix_effect": "The output is encoded before use.",
        "l0_class": "injection",
        "cwe_id": "CWE-79",
        "severity": {"level": "high", "source": "model_estimate"},
        "affected_paths": [PATH],
        "fix_completeness": "complete",
        "invariant": None,
        "reachability_delta": {
            "verdict": "narrows",
            "before": "Any caller could reach the unescaped sink.",
            "after": "The value is encoded before it reaches the sink.",
        },
        "failure_containment": "n/a",
        "evidence": [
            {
                "revision": "commit",
                "revision_sha": COMMIT,
                "path": PATH,
                "start_line": 2,
                "end_line": 2,
                "quoted_span": "return escape(value)",
                "supports": ALL_CLAIMS,
            }
        ],
    }


def _candidate() -> dict:
    return {
        "repository": "https://example.test/owner/repo",
        "commit_sha": COMMIT,
        "parent_sha": PARENT,
        "message": "render value",
        "diff": "+ return escape(value)",
        "advisory": {"cve": "CVE-hidden"},
    }


def test_tool_loop_validates_evidence_and_records_only_hashes() -> None:
    """Evidence must come from `cite`; the tool layer builds the anchor."""
    repo = FakeRepo()
    llm = FakeLLM(
        _tool_call("search", {"query": "escape(", "revision": COMMIT}),
        _tool_call(
            "cite",
            {
                "revision": "commit",
                "path": PATH,
                "start_line": 2,
                "end_line": 2,
                "supports": ALL_CLAIMS,
            },
            "call-2",
        ),
        {"content": json.dumps(_yes())},
    )
    result = Adjudicator(llm, repo, profile=Profile.A0).adjudicate(_candidate())
    assert result.verdict == "YES", result.validation_errors
    assert result.turns == 3
    assert result.tool_calls == 2
    assert result.tool_audit[0].request_hash.startswith("sha256:")
    assert result.tool_audit[0].result_hash.startswith("sha256:")
    assert "result" not in result.tool_audit[0].to_dict()
    assert repo.calls[0][0] == "search"
    # A0 strips retrospective advisory input from the initial prompt.
    assert "CVE-hidden" not in llm.requests[0]["messages"][1]["content"]
    finding = result.to_finding_contract(_candidate())
    assert isinstance(finding, FindingV1)
    assert finding.l0_class.value == "injection"


def test_hand_written_anchors_are_rejected_with_an_instruction() -> None:
    """The defect this prevents: correct text cited at a wrong line number."""
    llm = FakeLLM({"content": json.dumps(_yes())}, {"content": json.dumps(_yes())})
    result = Adjudicator(llm, FakeRepo(), profile=Profile.A0).adjudicate(_candidate())
    assert result.verdict == "ABSTAIN"
    assert any("`cite` tool" in error for error in result.validation_errors)


def test_cite_builds_the_anchor_from_repository_bytes() -> None:
    """The model supplies a location; the quote and SHA come from git."""
    tools = RepositoryTools(
        FakeRepo(),
        _candidate(),
        AdjudicationLimits(),
        profile=Profile.A0,
        linked_artifact=None,
    )
    issued = tools.execute(
        "cite",
        {
            "revision": "commit",
            "path": PATH,
            "start_line": 2,
            "end_line": 2,
            "supports": ["root_cause", "fix_effect"],
        },
    )["anchor"]
    assert issued["revision"] == "commit"
    assert issued["revision_sha"] == COMMIT
    assert issued["quoted_span"] == "return escape(value)"
    assert issued["supports"] == ["root_cause", "fix_effect"]
    assert tools.issued_citations, "the anchor must be registered for validation"


def test_cite_rejects_oversized_spans_and_unknown_claims() -> None:
    tools = RepositoryTools(
        FakeRepo(),
        _candidate(),
        AdjudicationLimits(),
        profile=Profile.A0,
        linked_artifact=None,
    )
    with pytest.raises(ValueError, match="at most"):
        tools.execute(
            "cite",
            {"path": PATH, "start_line": 1, "end_line": 90, "supports": ["impact"]},
        )
    with pytest.raises(ValueError, match="unknown claim"):
        tools.execute(
            "cite",
            {"path": PATH, "start_line": 1, "end_line": 1, "supports": ["nonsense"]},
        )


def test_read_range_returns_numbered_lines() -> None:
    """No offset arithmetic: the model reads a number and passes it to cite."""
    tools = RepositoryTools(
        FakeRepo(),
        _candidate(),
        AdjudicationLimits(),
        profile=Profile.A0,
        linked_artifact=None,
    )
    result = tools.execute("read_range", {"path": PATH, "start_line": 1, "end_line": 2})
    assert [line["n"] for line in result["lines"]] == [1, 2]
    assert "escape(value)" in result["lines"][1]["text"]


def test_one_bounded_repair_attempt() -> None:
    llm = FakeLLM(
        {"content": '{"verdict":"MAYBE"}'},
        {
            "content": json.dumps(
                {
                    "verdict": "NO",
                    "confidence": "medium",
                    "rationale": "This is ordinary output formatting.",
                }
            )
        },
    )
    result = Adjudicator(llm, FakeRepo()).adjudicate(_candidate())
    assert result.verdict == "NO"
    assert result.repaired is True
    assert result.turns == 2
    assert len(llm.requests) == 2
    assert "json_schema" in llm.requests[1]


def test_tool_call_and_result_byte_limits_are_strict() -> None:
    repo = FakeRepo()
    llm = FakeLLM(
        _tool_call("read_blob", {"revision": COMMIT, "path": PATH}, "one"),
        _tool_call("read_blob", {"revision": COMMIT, "path": PATH}, "two"),
    )
    result = Adjudicator(
        llm,
        repo,
        limits=AdjudicationLimits(
            max_turns=3,
            max_tool_calls=1,
            max_result_bytes=20,
            max_tool_result_bytes=20,
        ),
    ).adjudicate(_candidate())
    assert result.verdict == "ABSTAIN"
    assert result.limit_reason == "max_tool_calls"
    assert result.tool_calls == 1
    assert result.tool_result_bytes <= 20
    assert result.tool_audit[0].truncated is True


def test_turn_limit_returns_abstain_without_extra_model_call() -> None:
    llm = FakeLLM(
        _tool_call("show_commit", {"revision": COMMIT}),
        {"content": json.dumps(_yes())},
    )
    result = Adjudicator(
        llm,
        FakeRepo(),
        limits=AdjudicationLimits(max_turns=1),
    ).adjudicate(_candidate())
    assert result.verdict == "ABSTAIN"
    assert result.limit_reason == "max_turns"
    assert result.turns == 1
    assert len(llm.requests) == 1


def test_negative_and_abstain_conditional_fields() -> None:
    repo = FakeRepo()
    # A NO that also filled in positive-only fields is still a NO. Those
    # fields are never read for a negative verdict, so rejecting only
    # converted a decided NO into an abstention -- a candidate nobody ruled
    # on, which is strictly worse. They are stripped instead.
    stripped = validate_adjudication(
        {
            "verdict": "NO",
            "confidence": "high",
            "rationale": "Not a security fix.",
            "l0_class": "other",
        },
        repo=repo,
        candidate=_candidate(),
    )
    assert stripped["verdict"] == "NO"
    assert "l0_class" not in stripped
    valid = validate_adjudication(
        {
            "verdict": "ABSTAIN",
            "confidence": "low",
            "rationale": "The changed behavior cannot be established.",
            "abstain_reason": "Missing generated source.",
        },
        repo=repo,
        candidate=_candidate(),
    )
    assert valid["verdict"] == "ABSTAIN"
    assert "l0_class" not in valid


def test_rejects_bad_quote_and_unknown_cwe() -> None:
    repo = FakeRepo()
    bad_quote = _yes()
    bad_quote["evidence"][0]["quoted_span"] = "not in source"
    with pytest.raises(AdjudicationValidationError, match="absent"):
        validate_adjudication(bad_quote, repo=repo, candidate=_candidate())

    bad_cwe = _yes()
    bad_cwe["cwe_id"] = "CWE-999999"
    with pytest.raises(AdjudicationValidationError, match="pinned CWE"):
        validate_adjudication(bad_cwe, repo=repo, candidate=_candidate())


def test_a1_exposes_only_configured_linked_artifact_tool() -> None:
    seen: list[dict] = []

    def linked(candidate: dict, request: dict) -> dict:
        seen.append(request)
        return {"kind": "issue", "title": "security report"}

    llm = FakeLLM(
        _tool_call("linked_artifact", {"kind": "issue", "identifier": "7"}),
        {
            "content": json.dumps(
                {
                    "verdict": "NO",
                    "confidence": "medium",
                    "rationale": "The linked report describes unrelated code.",
                }
            )
        },
    )
    result = Adjudicator(
        llm,
        FakeRepo(),
        profile="A1",
        linked_artifact=linked,
    ).adjudicate(_candidate())
    assert result.verdict == "NO"
    assert seen == [{"kind": "issue", "identifier": "7"}]
    names = {tool["function"]["name"] for tool in llm.requests[0]["tools"]}
    assert "linked_artifact" in names


def test_openai_compatible_client_drives_tool_loop() -> None:
    responses = [
        {
            "choices": [
                {
                    "message": _tool_call("show_commit", {"revision": COMMIT}),
                    "finish_reason": "tool_calls",
                }
            ]
        },
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": json.dumps(
                            {
                                "verdict": "NO",
                                "confidence": "high",
                                "rationale": "The metadata and patch show a refactor.",
                            }
                        ),
                    },
                    "finish_reason": "stop",
                }
            ]
        },
    ]

    client = OpenAIChatClient(
        LLMConfig("https://example.test/v1", "fake", "secret", max_retries=0),
        client=_sdk_returning(responses),
    )
    result = Adjudicator(client, FakeRepo()).adjudicate(_candidate())
    assert result.verdict == "NO"
    assert result.tool_calls == 1


def _yes_with(**overrides: object) -> dict:
    payload = _yes()
    payload.update(overrides)
    return payload


def _cite_then(payload: dict) -> FakeLLM:
    return FakeLLM(
        _tool_call(
            "cite",
            {
                "revision": "commit",
                "path": PATH,
                "start_line": 2,
                "end_line": 2,
                "supports": ALL_CLAIMS,
            },
        ),
        {"content": json.dumps(payload)},
        {"content": json.dumps(payload)},
    )


class TestReachabilityGate:
    """Only a commit that shrinks the attacker-reachable set can be a fix."""

    def test_widens_is_rejected(self) -> None:
        payload = _yes_with(
            reachability_delta={
                "verdict": "widens",
                "before": "A loopback peer could not influence the client IP.",
                "after": "A loopback peer's X-Forwarded-For is now trusted.",
            }
        )
        result = Adjudicator(_cite_then(payload), FakeRepo()).adjudicate(_candidate())
        assert result.verdict == "ABSTAIN"
        assert any("does not shrink" in e for e in result.validation_errors)

    def test_unchanged_is_rejected(self) -> None:
        payload = _yes_with(
            reachability_delta={
                "verdict": "unchanged",
                "before": "same",
                "after": "same",
            }
        )
        result = Adjudicator(_cite_then(payload), FakeRepo()).adjudicate(_candidate())
        assert result.verdict == "ABSTAIN"

    def test_missing_delta_is_rejected(self) -> None:
        payload = _yes()
        payload.pop("reachability_delta")
        result = Adjudicator(_cite_then(payload), FakeRepo()).adjudicate(_candidate())
        assert result.verdict == "ABSTAIN"
        assert any("reachability_delta" in e for e in result.validation_errors)


class TestContainmentGate:
    """A panic the framework absorbs is hardening, not a fix."""

    def test_contained_is_rejected(self) -> None:
        payload = _yes_with(failure_containment="contained")
        result = Adjudicator(_cite_then(payload), FakeRepo()).adjudicate(_candidate())
        assert result.verdict == "ABSTAIN"
        assert any("hardening, not a security fix" in e for e in result.validation_errors)

    def test_unrecoverable_is_accepted(self) -> None:
        payload = _yes_with(failure_containment="unrecoverable")
        result = Adjudicator(_cite_then(payload), FakeRepo()).adjudicate(_candidate())
        assert result.verdict == "YES", result.validation_errors
        assert result.decision["failure_containment"] == "unrecoverable"

    def test_not_applicable_is_accepted(self) -> None:
        result = Adjudicator(_cite_then(_yes()), FakeRepo()).adjudicate(_candidate())
        assert result.verdict == "YES", result.validation_errors
        assert result.decision["reachability_delta"]["verdict"] == "narrows"


def test_gate_failures_are_terminal_not_repairable() -> None:
    """A gate states a fact about the commit; a retry must not reverse it."""
    widening = _yes_with(
        reachability_delta={
            "verdict": "widens",
            "before": "loopback could not influence the client IP",
            "after": "loopback X-Forwarded-For is now trusted",
        }
    )
    # If the gate were repairable the model could answer 'narrows' second time.
    reversed_answer = _yes_with(
        reachability_delta={"verdict": "narrows", "before": "b", "after": "a"}
    )
    llm = FakeLLM(
        _tool_call(
            "cite",
            {
                "revision": "commit",
                "path": PATH,
                "start_line": 2,
                "end_line": 2,
                "supports": ALL_CLAIMS,
            },
        ),
        {"content": json.dumps(widening)},
        {"content": json.dumps(reversed_answer)},
    )
    result = Adjudicator(llm, FakeRepo()).adjudicate(_candidate())
    assert result.verdict == "ABSTAIN"
    assert result.decision["abstain_reason"] == "gate_rejected"
    assert result.repaired is False, "a gate must not consume the repair attempt"
    assert len(llm.responses) == 1, "the second answer must never be requested"


def test_cite_resolves_the_revision_vocabulary() -> None:
    """`revision="parent"` is contract vocabulary; git has no such ref."""
    repo = FakeRepo()
    tools = RepositoryTools(
        repo, _candidate(), AdjudicationLimits(), profile=Profile.A0, linked_artifact=None
    )
    tools.execute(
        "cite",
        {
            "revision": "parent",
            "path": PATH,
            "start_line": 1,
            "end_line": 1,
            "supports": ["root_cause"],
        },
    )
    revisions = [call[1][0] for call in repo.calls if call[0] == "read_range"]
    assert PARENT in revisions, f"expected the parent SHA, got {revisions}"


class TestFinalSchemaCoversTheValidator:
    """The repair schema must be able to express every field the validator demands.

    ``FINAL_JSON_SCHEMA`` carries ``additionalProperties: false`` and is what
    constrains the repair call. A field the validator requires but the schema
    does not declare is an unrecoverable abstention: the repair prompt asks
    for it and the schema forbids emitting it. That happened for both gate
    fields and cost seven of fifty candidates in the A/B, four of them real
    fixes.
    """

    def test_every_field_required_on_a_yes_is_declarable(self):
        from strata.adjudicator import FINAL_JSON_SCHEMA, REQUIRED_ON_YES

        declared = set(FINAL_JSON_SCHEMA["schema"]["properties"])
        missing = REQUIRED_ON_YES - declared
        assert not missing, (
            f"{sorted(missing)} are required on a YES but the repair schema "
            "forbids them, so a repair can never satisfy the validator"
        )

    @pytest.mark.parametrize("field", sorted(REQUIRED_ON_YES))
    def test_the_validator_really_rejects_each_omission(self, field):
        """Keeps REQUIRED_ON_YES honest.

        Without this, a field could be dropped from the validator and the
        coverage test above would still pass while silently guarding nothing.
        """
        payload = _yes()
        payload.pop(field)
        with pytest.raises(AdjudicationValidationError) as excinfo:
            validate_adjudication(payload, repo=FakeRepo(), candidate=_candidate())
        assert any(field in error for error in excinfo.value.errors), (
            f"omitting {field} did not produce an error naming it; "
            "REQUIRED_ON_YES is out of date"
        )

    def test_the_gate_fields_are_declared_with_their_enums(self):
        from strata.adjudicator import (
            FAILURE_CONTAINMENTS,
            FINAL_JSON_SCHEMA,
            REACHABILITY_DELTAS,
        )

        properties = FINAL_JSON_SCHEMA["schema"]["properties"]
        assert set(properties["failure_containment"]["enum"]) == set(FAILURE_CONTAINMENTS)
        delta = properties["reachability_delta"]
        assert set(delta["properties"]["verdict"]["enum"]) == set(REACHABILITY_DELTAS)
        assert set(delta["required"]) == {"verdict", "before", "after"}


class TestListPaths:
    """Discovery, not just reading.

    Without this the model could read any file but not find one: it had to
    infer a package layout from the diff and spend a turn on a read that
    failed. Being able to run `ls` was much of the sandboxed backend's edge.
    """

    def _tools(self):
        return RepositoryTools(
            FakeRepo(),
            _candidate(),
            AdjudicationLimits(),
            profile=Profile.A0,
            linked_artifact=None,
        )

    def test_the_tool_is_advertised(self):
        names = {s["function"]["name"] for s in self._tools().schemas}
        assert "list_paths" in names

    def test_the_prompt_mentions_it(self):
        import json as _json

        from strata.resources import repo_root

        for manifest in ("a0-v1.json", "a1-v1.json"):
            prompt = _json.loads(
                (repo_root() / "prompts" / "adjudicator" / manifest).read_text()
            )["system_prompt"]
            assert "list_paths" in prompt, f"{manifest} does not advertise list_paths"

    def test_a_repository_without_listing_support_reports_a_tool_error(self):
        # Same contract as search/history/blame: an unsupported tool raises,
        # the tool loop records it as a failed call, and the adjudication
        # continues with one fewer avenue rather than dying.
        class NoListing(FakeRepo):
            list_paths = None

        tools = RepositoryTools(
            NoListing(),
            _candidate(),
            AdjudicationLimits(),
            profile=Profile.A0,
            linked_artifact=None,
        )
        with pytest.raises(AttributeError, match="does not implement list_paths"):
            tools.execute("list_paths", {"revision": "commit"})

    def test_unknown_arguments_are_rejected(self):
        # The allowlist is the point: an argument the tool does not model must
        # not be silently ignored, or a model can believe it filtered when it
        # did not.
        with pytest.raises(ValueError, match="glob"):
            self._tools().execute("list_paths", {"revision": "commit", "glob": "*.go"})
