"""Chat client: retry classification, usage accounting, redaction, limiter.

The client is exercised through an injected stand-in for ``openai.OpenAI``
rather than a socket, so the tests assert *policy* — which failures repeat and
which are terminal — without a network.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest
from openai import APIConnectionError, APIStatusError, RateLimitError

from strata.env import ProfileConflictError, resolve_endpoint_profile
from strata.llm import (
    LLMConfig,
    LLMHTTPError,
    LLMOversizeError,
    LLMQuotaError,
    LLMResponseError,
    LLMTransportError,
    ModelPricing,
    OpenAIChatClient,
    TokenUsage,
    TokenWindowRateLimiter,
    classify_rate_limit,
    estimate_chat_tokens,
)

CONFIG = LLMConfig(
    base_url="https://example.test/v1",
    model="gpt-5.4",
    api_key="secret-key-value",
    max_retries=3,
    initial_backoff_s=0.01,
    max_backoff_s=0.02,
)


# --- SDK stand-ins -------------------------------------------------------


@dataclass
class _Function:
    name: str
    arguments: str


@dataclass
class _ToolCall:
    id: str
    function: _Function


@dataclass
class _Message:
    content: str | None = None
    tool_calls: list[_ToolCall] = field(default_factory=list)


@dataclass
class _Choice:
    message: _Message
    finish_reason: str = "stop"


@dataclass
class _Details:
    cached_tokens: int = 0
    reasoning_tokens: int = 0


@dataclass
class _Usage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    prompt_tokens_details: _Details = field(default_factory=_Details)
    completion_tokens_details: _Details = field(default_factory=_Details)


@dataclass
class _Completion:
    choices: list[_Choice]
    usage: _Usage = field(default_factory=_Usage)
    model: str = "gpt-5.4"
    id: str = "resp-1"


class _Completions:
    def __init__(self, script: list[Any]) -> None:
        self.script = list(script)
        self.calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if not self.script:
            raise AssertionError("unexpected extra model call")
        outcome = self.script.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class _FakeSDK:
    def __init__(self, *script: Any) -> None:
        self.completions = _Completions(list(script))
        self.chat = self

    @property
    def calls(self) -> list[dict[str, Any]]:
        return self.completions.calls


def _status_error(status: int, message: str) -> APIStatusError:
    request = httpx.Request("POST", "https://example.test/v1/chat/completions")
    response = httpx.Response(status, request=request, json={"error": {"message": message}})
    cls = RateLimitError if status == 429 else APIStatusError
    return cls(message, response=response, body=None)


def _ok(content: str = "YES", **usage: int) -> _Completion:
    return _Completion(
        choices=[_Choice(message=_Message(content=content))],
        usage=_Usage(
            prompt_tokens=usage.get("prompt", 100),
            completion_tokens=usage.get("completion", 5),
            total_tokens=usage.get("total", 105),
            prompt_tokens_details=_Details(cached_tokens=usage.get("cached", 0)),
            completion_tokens_details=_Details(reasoning_tokens=usage.get("reasoning", 0)),
        ),
    )


def _client(*script: Any) -> tuple[OpenAIChatClient, _FakeSDK]:
    sdk = _FakeSDK(*script)
    return (
        OpenAIChatClient(CONFIG, client=sdk, sleep=lambda _: None, jitter=lambda: 0.5),
        sdk,
    )


# --- 429 classification --------------------------------------------------


class TestRateLimitClassification:
    """HTTP 429 carries two opposite meanings."""

    def test_request_too_large_is_terminal(self) -> None:
        detail = (
            "Request too large for gpt-5.4 on tokens per min (TPM): "
            "Limit 200000, Requested 228721"
        )
        assert isinstance(classify_rate_limit(detail), LLMOversizeError)
        assert classify_rate_limit(detail).retryable is False

    def test_quota_exhaustion_is_terminal(self) -> None:
        detail = "You exceeded your current quota, please check your plan"
        assert isinstance(classify_rate_limit(detail), LLMQuotaError)

    def test_bucket_exhaustion_is_retryable(self) -> None:
        detail = (
            "Rate limit reached for gpt-5.4 on TPM: Limit 200000, Used 195000, Requested 8000"
        )
        error = classify_rate_limit(detail)
        assert error.retryable is True
        assert not isinstance(error, (LLMOversizeError, LLMQuotaError))

    def test_oversize_does_not_burn_the_retry_budget(self) -> None:
        client, sdk = _client(_status_error(429, "Request too large for gpt-5.4"))
        with pytest.raises(LLMOversizeError):
            client.complete([{"role": "user", "content": "x"}])
        assert len(sdk.calls) == 1, "a terminal 429 must not be repeated"

    def test_quota_does_not_burn_the_retry_budget(self) -> None:
        client, sdk = _client(_status_error(429, "You exceeded your current quota"))
        with pytest.raises(LLMQuotaError):
            client.complete([{"role": "user", "content": "x"}])
        assert len(sdk.calls) == 1

    def test_transient_rate_limit_is_retried_then_succeeds(self) -> None:
        client, sdk = _client(
            _status_error(429, "Rate limit reached. Used 195000, Requested 8000"),
            _ok("NO"),
        )
        assert client.complete([{"role": "user", "content": "x"}]).content == "NO"
        assert len(sdk.calls) == 2


class TestTransportRetries:
    def test_connection_errors_retry_then_give_up(self) -> None:
        request = httpx.Request("POST", "https://example.test/v1/chat/completions")
        errors = [APIConnectionError(request=request) for _ in range(CONFIG.max_retries + 1)]
        client, sdk = _client(*errors)
        with pytest.raises(LLMTransportError):
            client.complete([{"role": "user", "content": "x"}])
        assert len(sdk.calls) == CONFIG.max_retries + 1

    def test_server_errors_are_retryable(self) -> None:
        client, sdk = _client(_status_error(503, "upstream unavailable"), _ok())
        assert client.complete([{"role": "user", "content": "x"}]).content == "YES"
        assert len(sdk.calls) == 2

    def test_client_errors_are_not_retryable(self) -> None:
        client, sdk = _client(_status_error(400, "bad request"))
        # A 4xx is the caller's fault and must surface as a terminal
        # LLMError, not be retried into the budget.
        with pytest.raises(LLMHTTPError) as excinfo:
            client.complete([{"role": "user", "content": "x"}])
        assert excinfo.value.status == 400
        assert len(sdk.calls) == 1


class TestResponseHandling:
    def test_usage_captures_cached_and_reasoning_tokens(self) -> None:
        client, _ = _client(_ok(prompt=1000, completion=50, cached=800, reasoning=40))
        usage = client.complete([{"role": "user", "content": "x"}]).usage
        assert usage.cached_tokens == 800
        assert usage.reasoning_tokens == 40
        assert usage.billable_input_tokens == 200

    def test_truncation_is_distinguishable_from_an_empty_answer(self) -> None:
        """A reasoning model that ran out of budget must not read as a verdict."""
        completion = _Completion(
            choices=[_Choice(message=_Message(content=""), finish_reason="length")]
        )
        client, _ = _client(completion)
        response = client.complete([{"role": "user", "content": "x"}])
        assert response.truncated is True
        assert response.content == ""

    def test_tool_calls_round_trip(self) -> None:
        completion = _Completion(
            choices=[
                _Choice(
                    message=_Message(
                        content=None,
                        tool_calls=[
                            _ToolCall("call_1", _Function("read_blob", '{"path":"a.go"}'))
                        ],
                    ),
                    finish_reason="tool_calls",
                )
            ]
        )
        client, _ = _client(completion)
        response = client.complete([{"role": "user", "content": "x"}])
        assert response.tool_calls[0].name == "read_blob"
        assert response.tool_calls[0].arguments == {"path": "a.go"}
        assert response.as_message()["tool_calls"][0]["function"]["name"] == "read_blob"

    def test_malformed_tool_arguments_raise(self) -> None:
        completion = _Completion(
            choices=[
                _Choice(
                    message=_Message(
                        content=None,
                        tool_calls=[_ToolCall("c", _Function("t", "{not json"))],
                    )
                )
            ]
        )
        client, _ = _client(completion)
        with pytest.raises(LLMResponseError):
            client.complete([{"role": "user", "content": "x"}])

    def test_json_helper_rejects_blank_content(self) -> None:
        client, _ = _client(_ok(""))
        with pytest.raises(LLMResponseError):
            client.complete([{"role": "user", "content": "x"}]).json()

    def test_json_helper_parses_content(self) -> None:
        client, _ = _client(_ok(json.dumps({"verdict": "YES"})))
        assert client.complete([{"role": "user", "content": "x"}]).json() == {"verdict": "YES"}


class TestParameterShaping:
    def test_gpt5_uses_the_new_token_name_but_still_takes_temperature(self) -> None:
        """The two properties are unrelated; conflating them lost determinism."""
        client, sdk = _client(_ok())
        client.complete([{"role": "user", "content": "x"}], max_tokens=64, temperature=0)
        call = sdk.calls[0]
        assert call["max_completion_tokens"] == 64
        assert "max_tokens" not in call
        assert call["temperature"] == 0, (
            "gpt-5.x accepts temperature=0; omitting it silently ran every call "
            "at the provider default of 1.0"
        )

    def test_reasoning_models_omit_temperature(self) -> None:
        config = LLMConfig(base_url="https://x.test/v1", model="o3-mini", api_key="k")
        sdk = _FakeSDK(_ok())
        OpenAIChatClient(config, client=sdk, sleep=lambda _: None).complete(
            [{"role": "user", "content": "x"}], max_tokens=64, temperature=0
        )
        assert "temperature" not in sdk.calls[0]
        assert sdk.calls[0]["max_completion_tokens"] == 64

    def test_older_models_use_max_tokens_and_temperature(self) -> None:
        config = LLMConfig(base_url="https://x.test/v1", model="gpt-4o-mini", api_key="k")
        sdk = _FakeSDK(_ok())
        OpenAIChatClient(config, client=sdk, sleep=lambda _: None).complete(
            [{"role": "user", "content": "x"}], max_tokens=4, temperature=0
        )
        assert sdk.calls[0]["max_tokens"] == 4
        assert sdk.calls[0]["temperature"] == 0

    def test_json_schema_response_format(self) -> None:
        client, sdk = _client(_ok())
        client.complete(
            [{"role": "user", "content": "x"}],
            json_schema={"name": "finding", "schema": {"type": "object"}},
        )
        assert sdk.calls[0]["response_format"]["type"] == "json_schema"


class TestRedaction:
    def test_api_key_never_reaches_the_error_message(self) -> None:
        client, _ = _client(_status_error(401, f"bad key {CONFIG.api_key} for org-ABCDEFGH123"))
        with pytest.raises(Exception) as excinfo:
            client.complete([{"role": "user", "content": "x"}])
        message = str(excinfo.value)
        assert CONFIG.api_key not in message
        assert "org-ABCDEFGH123" not in message
        assert "<redacted>" in message


class TestTokenAccounting:
    def test_estimate_grows_with_content(self) -> None:
        small = estimate_chat_tokens("gpt-5.4", [{"role": "user", "content": "hi"}])
        large = estimate_chat_tokens("gpt-5.4", [{"role": "user", "content": "hi " * 500}])
        assert 0 < small < large

    def test_unknown_models_fall_back_to_a_known_encoding(self) -> None:
        assert estimate_chat_tokens("private-model", [{"role": "user", "content": "x"}]) > 0

    def test_usage_addition(self) -> None:
        total = TokenUsage(10, 2, 12) + TokenUsage(5, 1, 6)
        assert (total.prompt_tokens, total.completion_tokens, total.total_tokens) == (15, 3, 18)

    def test_pricing_discounts_cached_input(self) -> None:
        usage = TokenUsage(
            prompt_tokens=1_000_000, completion_tokens=0, cached_tokens=1_000_000
        )
        pricing = ModelPricing(
            input_per_million=10.0, output_per_million=30.0, cached_input_per_million=1.0
        )
        assert pricing.estimate(usage) == pytest.approx(1.0)


class TestRateLimiter:
    def test_reservations_expire_with_the_window(self) -> None:
        now = [0.0]
        limiter = TokenWindowRateLimiter(
            1000,
            window_s=60.0,
            headroom=1.0,
            monotonic=lambda: now[0],
            sleep=lambda s: now.__setitem__(0, now[0] + s),
        )
        assert limiter.acquire(600) == 0.0
        assert limiter.acquire(300) == 0.0
        limiter.acquire(400)  # forces a wait for the window to roll
        assert now[0] >= 60.0

    def test_oversized_reservation_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            TokenWindowRateLimiter(100, headroom=1.0).acquire(101)

    @pytest.mark.parametrize("value", [0, -1, True])
    def test_invalid_token_counts_rejected(self, value: object) -> None:
        with pytest.raises(ValueError):
            TokenWindowRateLimiter(100).acquire(value)  # type: ignore[arg-type]


class TestEndpointProfile:
    """(base_url, api_key) must come from one source; a half-override is a 401."""

    def test_dotenv_profile_wins_over_a_stray_shell_key(self) -> None:
        merged = resolve_endpoint_profile(
            environ={"OPENAI_API_KEY": "sk-proj-shell", "PATH": "/bin"},
            dotenv={
                "OPENAI_BASE_URL": "https://azure.test/openai/v1",
                "OPENAI_API_KEY": "azure-key",
                "OPENAI_MODEL": "gpt-5.4",
            },
        )
        assert merged["OPENAI_API_KEY"] == "azure-key"
        assert merged["OPENAI_BASE_URL"] == "https://azure.test/openai/v1"

    def test_complete_shell_profile_wins(self) -> None:
        merged = resolve_endpoint_profile(
            environ={"OPENAI_BASE_URL": "https://shell.test/v1", "OPENAI_API_KEY": "shell-key"},
            dotenv={"OPENAI_BASE_URL": "https://file.test/v1", "OPENAI_API_KEY": "file-key"},
        )
        assert merged["OPENAI_API_KEY"] == "shell-key"

    def test_partial_profile_on_both_sides_is_an_error(self) -> None:
        with pytest.raises(ProfileConflictError):
            resolve_endpoint_profile(
                environ={"OPENAI_API_KEY": "sk-proj-shell"},
                dotenv={"OPENAI_BASE_URL": "https://azure.test/openai/v1"},
            )

    def test_non_profile_keys_still_follow_shell_wins(self) -> None:
        merged = resolve_endpoint_profile(
            environ={"OPENAI_MODEL": "gpt-5.4"}, dotenv={"OPENAI_MODEL": "gpt-4o-mini"}
        )
        assert merged["OPENAI_MODEL"] == "gpt-5.4"


class TestConfig:
    def test_missing_credentials_are_reported_without_leaking(self) -> None:
        with pytest.raises(Exception) as excinfo:
            LLMConfig.from_env(environ={"OPENAI_BASE_URL": "https://x.test/v1"})
        assert "OPENAI_MODEL" in str(excinfo.value)
        assert "OPENAI_API_KEY" in str(excinfo.value)

    @pytest.mark.parametrize(
        ("model", "expected"),
        [("gpt-5.4", True), ("gpt-4o-mini", False), ("o3-mini", True), ("gpt-6", True)],
    )
    def test_token_parameter_family(self, model: str, expected: bool) -> None:
        config = LLMConfig(base_url="https://x.test/v1", model=model, api_key="k")
        assert config.uses_max_completion_tokens is expected
