"""Chat client built on the official ``openai`` SDK.

Why a retry loop still lives here, on top of a library that has one: the SDK
retries every 429 identically, and this workload has two 429s that mean
opposite things:

* ``Rate limit reached ... Used N, Requested M`` — the token bucket is empty.
  Waiting works, and the ``Retry-After`` header says how long.
* ``Request too large ... Limit 200000, Requested 228721`` — a *single* prompt
  exceeds the per-request ceiling. Retrying the identical body can never
  succeed; it burns the retry budget and ~30s of wall clock per commit.

``insufficient_quota`` is a third terminal case: treating it as retryable is
what produced 305 of 306 ``backend_error`` rows in one measured triage arm.

So: the SDK owns transport, pooling, timeouts, typed responses and Azure
compatibility (constructed with ``max_retries=0``), and this module owns
*classification* — which failures are worth repeating.
"""

from __future__ import annotations

import json
import logging
import math
import os
import random
import re
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import tiktoken
from openai import APIConnectionError, APIStatusError, APITimeoutError, OpenAI

from .env import resolve_endpoint_profile

DEFAULT_BASE_URL = "https://api.openai.com/v1"

#: HTTP statuses worth repeating with an identical body. 429 is deliberately
#: absent: its retryability depends on the body, not the status.
RETRYABLE_STATUS = frozenset({408, 409, 425, 500, 502, 503, 504})

LOGGER = logging.getLogger(__name__)

_OVERSIZE_PATTERNS = (
    re.compile(r"request too large", re.IGNORECASE),
    re.compile(r"maximum context length", re.IGNORECASE),
    re.compile(r"reduce the length of the messages", re.IGNORECASE),
)
_QUOTA_PATTERNS = (
    re.compile(r"insufficient[_ ]quota", re.IGNORECASE),
    re.compile(r"exceeded your current quota", re.IGNORECASE),
    re.compile(r"billing", re.IGNORECASE),
)

_RESET_DURATION = re.compile(
    r"^(?:(?P<h>\d+(?:\.\d+)?)h)?(?:(?P<m>\d+(?:\.\d+)?)m(?!s))?"
    r"(?:(?P<s>\d+(?:\.\d+)?)s)?(?:(?P<ms>\d+(?:\.\d+)?)ms)?$"
)


class LLMError(RuntimeError):
    """Base class for chat-client failures."""


class LLMConfigError(LLMError):
    """Configuration is missing or malformed."""


class LLMTransportError(LLMError):
    """Network failure after the retry budget was exhausted."""


class LLMHTTPError(LLMError):
    """Non-success HTTP status from the endpoint."""

    def __init__(self, status: int, detail: str, *, retryable: bool = False) -> None:
        super().__init__(f"chat endpoint returned HTTP {status}: {detail}")
        self.status = status
        self.detail = detail
        self.retryable = retryable


class LLMOversizeError(LLMHTTPError):
    """One request exceeded the provider's per-request ceiling.

    Kept distinct from a transient rate limit so callers record ``oversize``
    instead of pretending the commit was classified.
    """

    def __init__(self, detail: str) -> None:
        super().__init__(429, detail, retryable=False)


class LLMQuotaError(LLMHTTPError):
    """The account or deployment is out of quota. Never retryable."""

    def __init__(self, detail: str) -> None:
        super().__init__(429, detail, retryable=False)


class LLMResponseError(LLMError):
    """The endpoint returned a structurally unusable payload."""


def classify_rate_limit(detail: str) -> LLMHTTPError:
    """Map a 429 body onto a terminal or retryable error instance."""
    if any(pattern.search(detail) for pattern in _OVERSIZE_PATTERNS):
        return LLMOversizeError(detail)
    if any(pattern.search(detail) for pattern in _QUOTA_PATTERNS):
        return LLMQuotaError(detail)
    return LLMHTTPError(429, detail, retryable=True)


def estimate_chat_tokens(
    model: str,
    messages: Sequence[Mapping[str, Any]],
    *,
    output_tokens: int = 0,
) -> int:
    """Conservatively estimate tokens for scheduling, not billing."""
    try:
        encoding = tiktoken.encoding_for_model(model)
    except KeyError:
        encoding = tiktoken.get_encoding("o200k_base")
    total = 0
    for message in messages:
        total += 4
        for value in message.values():
            if isinstance(value, str):
                total += len(encoding.encode(value))
            elif value is not None:
                total += len(encoding.encode(json.dumps(value, ensure_ascii=False)))
    return total + max(0, int(output_tokens))


class TokenWindowRateLimiter:
    """Pre-emptive token reservation over a sliding window.

    Reserving *before* the call stops concurrent workers from collectively
    overshooting a tokens-per-minute ceiling, which a purely reactive
    header-driven throttle cannot do.
    """

    def __init__(
        self,
        tokens_per_window: int,
        *,
        window_s: float = 60.0,
        headroom: float = 0.8,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if isinstance(tokens_per_window, bool) or not isinstance(tokens_per_window, int):
            raise ValueError("tokens_per_window must be an integer")
        if tokens_per_window < 1:
            raise ValueError("tokens_per_window must be a positive integer")
        if not 0 < headroom <= 1:
            raise ValueError("headroom must be in (0, 1]")
        self.tokens_per_window = tokens_per_window
        self.window_s = window_s
        self.capacity = max(1, int(tokens_per_window * headroom))
        self._monotonic = monotonic
        self._sleep = sleep
        self._lock = threading.Lock()
        self._reservations: deque[tuple[float, int]] = deque()
        self._reserved_tokens = 0

    def _prune(self, now: float) -> None:
        while self._reservations and now - self._reservations[0][0] >= self.window_s:
            _, tokens = self._reservations.popleft()
            self._reserved_tokens -= tokens

    def acquire(self, tokens: int) -> float:
        """Block until ``tokens`` fit in the window; return seconds waited."""
        if isinstance(tokens, bool) or not isinstance(tokens, int) or tokens < 1:
            raise ValueError("tokens must be a positive integer")
        if tokens > self.capacity:
            raise ValueError(
                f"request estimate {tokens} exceeds limiter capacity {self.capacity}"
            )
        waited = 0.0
        while True:
            with self._lock:
                now = self._monotonic()
                self._prune(now)
                if self._reserved_tokens + tokens <= self.capacity:
                    self._reservations.append((now, tokens))
                    self._reserved_tokens += tokens
                    return waited
                wait = max(0.0, self.window_s - (now - self._reservations[0][0]))
            LOGGER.debug("token queue wait tokens=%d wait_s=%.3f", tokens, wait)
            self._sleep(wait)
            waited += wait


@dataclass(frozen=True, slots=True)
class LLMConfig:
    """Endpoint configuration for an OpenAI-compatible deployment."""

    base_url: str
    model: str
    api_key: str = field(repr=False)
    timeout_s: float = 180.0
    max_retries: int = 4
    initial_backoff_s: float = 1.0
    max_backoff_s: float = 60.0
    max_wait_s: float = 300.0

    def __post_init__(self) -> None:
        for name in ("base_url", "model"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise LLMConfigError(f"{name} must not be empty")
        if not isinstance(self.api_key, str) or not self.api_key:
            raise LLMConfigError("api_key must not be empty")
        for name in ("timeout_s", "initial_backoff_s", "max_backoff_s", "max_wait_s"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise LLMConfigError(f"{name} must be a number")
            if not math.isfinite(value) or value < 0:
                raise LLMConfigError(f"{name} must be finite and non-negative")
        if self.timeout_s <= 0:
            raise LLMConfigError("timeout_s must be positive")
        if isinstance(self.max_retries, bool) or not isinstance(self.max_retries, int):
            raise LLMConfigError("max_retries must be an integer")
        if self.max_retries < 0:
            raise LLMConfigError("max_retries must be non-negative")

    @property
    def endpoint(self) -> str:
        return self.base_url.rstrip("/")

    @property
    def uses_max_completion_tokens(self) -> bool:
        """gpt-5+/o-series reject ``max_tokens`` in favour of the newer name."""
        return self.model.lower().startswith(("gpt-5", "gpt-6", "o1", "o3", "o4"))

    @property
    def supports_temperature(self) -> bool:
        """Whether the deployment accepts an explicit ``temperature``.

        This was previously conflated with :attr:`uses_max_completion_tokens`,
        and the conflation was expensive. The two properties are unrelated:
        the *reasoning* models (o1/o3/o4) genuinely reject a non-default
        temperature, but gpt-5.x accepts ``temperature=0`` normally. Treating
        the whole family as temperature-less meant every gpt-5.4 call silently
        ran at the provider default of 1.0.

        The consequences were visible and were misread as model behaviour:
        triage returned YES for a commit on one run and NO on the next, and the
        adjudicator returned YES with five verified anchors for CVE-2023-29401
        run alone but ABSTAIN for the same commit in a batch. Reports also
        recorded ``decoding: {"temperature": 0}`` while sending nothing, so the
        provenance was wrong in the direction that hides the problem.
        """
        return not self.model.lower().startswith(("o1", "o3", "o4"))

    @classmethod
    def from_env(
        cls,
        environ: Mapping[str, str] | None = None,
        *,
        prefix: str = "OPENAI_",
        dotenv_path: str | os.PathLike[str] = ".env",
    ) -> LLMConfig:
        """Load configuration, keeping ``(base_url, api_key)`` atomic.

        See :mod:`strata.env` for why the credential pair resolves together
        rather than variable by variable.
        """
        env = (
            resolve_endpoint_profile(dotenv_path=dotenv_path)
            if environ is None
            else dict(environ)
        )
        model = env.get(f"{prefix}MODEL", "").strip()
        api_key = env.get(f"{prefix}API_KEY", "")
        missing = [
            name for name, value in (("MODEL", model), ("API_KEY", api_key)) if not value
        ]
        if missing:
            names = ", ".join(f"{prefix}{name}" for name in missing)
            raise LLMConfigError(f"missing required environment variable(s): {names}")

        def number(name: str, default: str, convert: Callable[[str], Any]) -> Any:
            raw = env.get(f"{prefix}{name}", default)
            try:
                return convert(raw)
            except (TypeError, ValueError) as exc:
                raise LLMConfigError(f"{prefix}{name} has an invalid value") from exc

        return cls(
            base_url=env.get(f"{prefix}BASE_URL", DEFAULT_BASE_URL),
            model=model,
            api_key=api_key,
            timeout_s=number("TIMEOUT_S", "180", float),
            max_retries=number("MAX_RETRIES", "4", int),
            initial_backoff_s=number("INITIAL_BACKOFF_S", "1", float),
            max_backoff_s=number("MAX_BACKOFF_S", "60", float),
            max_wait_s=number("MAX_WAIT_S", "300", float),
        )


#: Name used by the earliest prototypes; kept so archived scripts still import.
EndpointConfig = LLMConfig


@dataclass(frozen=True, slots=True)
class TokenUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cached_tokens: int = 0
    reasoning_tokens: int = 0

    @property
    def input_tokens(self) -> int:
        return self.prompt_tokens

    @property
    def output_tokens(self) -> int:
        return self.completion_tokens

    @property
    def billable_input_tokens(self) -> int:
        """Prompt tokens excluding the cache-hit portion."""
        return max(0, self.prompt_tokens - self.cached_tokens)

    @classmethod
    def from_sdk(cls, usage: Any) -> TokenUsage:
        if usage is None:
            return cls()

        def integer(value: Any) -> int:
            try:
                return max(0, int(value))
            except TypeError, ValueError:
                return 0

        prompt_details = getattr(usage, "prompt_tokens_details", None)
        completion_details = getattr(usage, "completion_tokens_details", None)
        return cls(
            prompt_tokens=integer(getattr(usage, "prompt_tokens", 0)),
            completion_tokens=integer(getattr(usage, "completion_tokens", 0)),
            total_tokens=integer(getattr(usage, "total_tokens", 0)),
            cached_tokens=integer(getattr(prompt_details, "cached_tokens", 0)),
            reasoning_tokens=integer(getattr(completion_details, "reasoning_tokens", 0)),
        )

    @classmethod
    def from_payload(cls, value: Any) -> TokenUsage:
        """Build from a raw ``usage`` mapping.

        Kept alongside :meth:`from_sdk` because the adjudicator's tool loop
        also accepts plain dicts — from test doubles and from replayed JSON
        transcripts — not only typed SDK objects.
        """
        if isinstance(value, TokenUsage):
            return value
        if not isinstance(value, Mapping):
            return cls()

        def integer(item: Any) -> int:
            try:
                return max(0, int(item))
            except TypeError, ValueError:
                return 0

        prompt_details = value.get("prompt_tokens_details")
        completion_details = value.get("completion_tokens_details")
        return cls(
            prompt_tokens=integer(value.get("prompt_tokens")),
            completion_tokens=integer(value.get("completion_tokens")),
            total_tokens=integer(value.get("total_tokens")),
            cached_tokens=integer(
                (prompt_details or {}).get("cached_tokens")
                if isinstance(prompt_details, Mapping)
                else 0
            ),
            reasoning_tokens=integer(
                (completion_details or {}).get("reasoning_tokens")
                if isinstance(completion_details, Mapping)
                else 0
            ),
        )

    def to_dict(self) -> dict[str, int]:
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "cached_tokens": self.cached_tokens,
            "reasoning_tokens": self.reasoning_tokens,
        }

    def __add__(self, other: TokenUsage) -> TokenUsage:
        return TokenUsage(
            prompt_tokens=self.prompt_tokens + other.prompt_tokens,
            completion_tokens=self.completion_tokens + other.completion_tokens,
            total_tokens=self.total_tokens + other.total_tokens,
            cached_tokens=self.cached_tokens + other.cached_tokens,
            reasoning_tokens=self.reasoning_tokens + other.reasoning_tokens,
        )


@dataclass(frozen=True, slots=True)
class ToolCall:
    id: str
    name: str
    arguments: Mapping[str, Any]
    raw_arguments: str

    @classmethod
    def from_sdk(cls, value: Any, *, index: int = 0) -> ToolCall:
        function = getattr(value, "function", None)
        name = getattr(function, "name", None)
        if not isinstance(name, str) or not name:
            raise LLMResponseError("tool call has no function name")
        raw_arguments = getattr(function, "arguments", "") or "{}"
        try:
            arguments = json.loads(raw_arguments)
        except json.JSONDecodeError as exc:
            raise LLMResponseError(f"tool call {name!r} arguments are not valid JSON") from exc
        if not isinstance(arguments, Mapping):
            raise LLMResponseError(f"tool call {name!r} arguments are not an object")
        return cls(
            id=str(getattr(value, "id", "") or f"call_{index}"),
            name=name,
            arguments=dict(arguments),
            raw_arguments=raw_arguments,
        )

    @classmethod
    def from_payload(cls, value: Any, *, index: int = 0) -> ToolCall:
        """Build from a raw tool-call mapping.

        The counterpart to :meth:`from_sdk` for dict-shaped input; ``arguments``
        may arrive as a JSON string or as an already-decoded object.
        """
        if isinstance(value, ToolCall):
            return value
        if not isinstance(value, Mapping):
            raise LLMResponseError("tool call is not an object")
        function = value.get("function")
        function = function if isinstance(function, Mapping) else value
        name = function.get("name")
        if not isinstance(name, str) or not name:
            raise LLMResponseError("tool call has no function name")
        supplied = function.get("arguments", {})
        if isinstance(supplied, str):
            raw_arguments = supplied
            try:
                arguments = json.loads(supplied or "{}")
            except json.JSONDecodeError as exc:
                raise LLMResponseError(
                    f"tool call {name!r} arguments are not valid JSON"
                ) from exc
        elif isinstance(supplied, Mapping):
            arguments = dict(supplied)
            raw_arguments = json.dumps(
                arguments, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            )
        else:
            raise LLMResponseError(f"tool call {name!r} arguments are not an object")
        if not isinstance(arguments, Mapping):
            raise LLMResponseError(f"tool call {name!r} arguments are not an object")
        return cls(
            id=str(value.get("id") or f"call_{index}"),
            name=name,
            arguments=dict(arguments),
            raw_arguments=raw_arguments,
        )

    def to_message_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": "function",
            "function": {"name": self.name, "arguments": self.raw_arguments},
        }


@dataclass(slots=True)
class ChatResponse:
    content: str | None
    tool_calls: tuple[ToolCall, ...]
    usage: TokenUsage
    model: str | None = None
    finish_reason: str | None = None
    response_id: str | None = None
    latency_ms: float = 0.0
    retries: int = 0

    @property
    def truncated(self) -> bool:
        """``True`` when the model ran out of output budget mid-answer.

        Previously indistinguishable from an empty answer — which is how a
        reasoning model that exhausted its budget got scored as a confident NO.
        """
        return self.finish_reason == "length"

    def as_message(self) -> dict[str, Any]:
        message: dict[str, Any] = {"role": "assistant", "content": self.content}
        if self.tool_calls:
            message["tool_calls"] = [call.to_message_payload() for call in self.tool_calls]
        return message

    def json(self) -> Any:
        if not isinstance(self.content, str) or not self.content.strip():
            raise LLMResponseError("assistant response has no JSON content")
        try:
            return json.loads(self.content)
        except json.JSONDecodeError as exc:
            raise LLMResponseError("assistant response content is not valid JSON") from exc


def _parse_reset_duration(value: str | None) -> float | None:
    """Parse OpenAI reset headers (``1s``, ``6m0s``, ``250ms``) or plain seconds."""
    if not value:
        return None
    text = value.strip()
    try:
        return max(0.0, float(text))
    except ValueError:
        pass
    match = _RESET_DURATION.fullmatch(text)
    if not match or not any(match.groupdict().values()):
        return None
    parts = match.groupdict()
    return (
        float(parts["h"] or 0) * 3600.0
        + float(parts["m"] or 0) * 60.0
        + float(parts["s"] or 0)
        + float(parts["ms"] or 0) / 1000.0
    )


def _retry_after_seconds(headers: Mapping[str, str]) -> float | None:
    lowered = {str(k).lower(): str(v) for k, v in headers.items()}
    for key in ("retry-after", "x-ratelimit-reset-tokens", "x-ratelimit-reset-requests"):
        parsed = _parse_reset_duration(lowered.get(key))
        if parsed is not None:
            return parsed
    return None


def _redact(detail: str, api_key: str) -> str:
    if api_key and api_key in detail:
        detail = detail.replace(api_key, "<redacted>")
    detail = re.sub(r"sk-[A-Za-z0-9_\-]{8,}", "sk-<redacted>", detail)
    return re.sub(r"org-[A-Za-z0-9]{8,}", "org-<redacted>", detail)


class OpenAIChatClient:
    """Chat client with domain-aware retry classification.

    Args:
        config: Endpoint settings; loaded from the environment when omitted.
        client: An ``openai.OpenAI`` instance, or any object exposing
            ``chat.completions.create``. Injected by tests.
        rate_limiter: Optional pre-emptive token reservation.
    """

    def __init__(
        self,
        config: LLMConfig | None = None,
        *,
        client: Any | None = None,
        rate_limiter: TokenWindowRateLimiter | None = None,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        jitter: Callable[[], float] = random.random,
    ) -> None:
        self.config = config or LLMConfig.from_env()
        self.rate_limiter = rate_limiter
        self._sleep = sleep
        self._monotonic = monotonic
        self._jitter = jitter
        self._client = client if client is not None else self._build_client()

    def _build_client(self) -> Any:
        # max_retries=0: this class owns retry policy so a terminal 429
        # (oversize / quota) fails immediately instead of burning the budget.
        return OpenAI(
            base_url=self.config.endpoint,
            api_key=self.config.api_key,
            timeout=self.config.timeout_s,
            max_retries=0,
        )

    def _backoff(self, attempt: int, headers: Mapping[str, str] | None) -> float:
        floor = min(self.config.max_backoff_s, self.config.initial_backoff_s * (2**attempt))
        suggested = _retry_after_seconds(headers or {}) or 0.0
        # Full jitter on the exponential floor; the server's hint is a lower
        # bound we never undercut.
        jittered = floor * (0.5 + self._jitter() / 2)
        return min(self.config.max_wait_s, max(suggested, jittered))

    def _classify(self, exc: APIStatusError) -> LLMHTTPError:
        detail = _redact(str(getattr(exc, "message", "") or exc), self.config.api_key)
        status = int(getattr(exc, "status_code", 0) or 0)
        if status == 429:
            return classify_rate_limit(detail)
        return LLMHTTPError(status, detail, retryable=status in RETRYABLE_STATUS)

    @staticmethod
    def _headers(exc: APIStatusError) -> Mapping[str, str]:
        response = getattr(exc, "response", None)
        headers = getattr(response, "headers", None)
        return dict(headers) if headers else {}

    def complete(
        self,
        messages: Sequence[Mapping[str, Any]],
        *,
        tools: Sequence[Mapping[str, Any]] | None = None,
        tool_choice: str | Mapping[str, Any] | None = None,
        response_format: bool | Mapping[str, Any] | None = None,
        json_schema: Mapping[str, Any] | None = None,
        temperature: float | None = 0,
        max_tokens: int | None = None,
        timeout_s: float | None = None,
        **parameters: Any,
    ) -> ChatResponse:
        """Send one chat completion, retrying only genuinely transient failures."""
        if not messages:
            raise ValueError("messages must not be empty")

        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": [dict(message) for message in messages],
        }
        if tools:
            payload["tools"] = [dict(tool) for tool in tools]
        if tool_choice is not None:
            payload["tool_choice"] = tool_choice
        if json_schema is not None:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": dict(json_schema),
            }
        elif response_format is True:
            payload["response_format"] = {"type": "json_object"}
        elif isinstance(response_format, Mapping):
            payload["response_format"] = dict(response_format)

        if temperature is not None and self.config.supports_temperature:
            payload["temperature"] = temperature
        if max_tokens is not None:
            payload[
                "max_completion_tokens"
                if self.config.uses_max_completion_tokens
                else "max_tokens"
            ] = max_tokens
        payload.update(parameters)

        timeout = self.config.timeout_s if timeout_s is None else float(timeout_s)
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout_s must be positive")

        if self.rate_limiter is not None:
            estimate = estimate_chat_tokens(
                self.config.model, payload["messages"], output_tokens=max_tokens or 0
            )
            self.rate_limiter.acquire(max(1, min(estimate, self.rate_limiter.capacity)))

        started = self._monotonic()
        last_error: Exception | None = None

        for attempt in range(self.config.max_retries + 1):
            try:
                completion = self._client.chat.completions.create(timeout=timeout, **payload)
            except APIStatusError as exc:
                error = self._classify(exc)
                last_error = error
                if not error.retryable or attempt >= self.config.max_retries:
                    LOGGER.error(
                        "request failed model=%s status=%s attempts=%d terminal=%s",
                        self.config.model,
                        error.status,
                        attempt + 1,
                        not error.retryable,
                    )
                    raise error from exc
                wait = self._backoff(attempt, self._headers(exc))
                LOGGER.warning(
                    "retrying model=%s status=%s attempt=%d/%d wait_s=%.2f",
                    self.config.model,
                    error.status,
                    attempt + 1,
                    self.config.max_retries + 1,
                    wait,
                )
                self._sleep(wait)
            except (APIConnectionError, APITimeoutError, TimeoutError, OSError) as exc:
                last_error = exc
                if attempt >= self.config.max_retries:
                    raise LLMTransportError(
                        f"chat transport failed after {attempt + 1} attempt(s)"
                    ) from exc
                wait = self._backoff(attempt, None)
                LOGGER.warning(
                    "retrying model=%s reason=transport error=%s attempt=%d wait_s=%.2f",
                    self.config.model,
                    type(exc).__name__,
                    attempt + 1,
                    wait,
                )
                self._sleep(wait)
            else:
                return self._to_response(
                    completion,
                    latency_ms=(self._monotonic() - started) * 1000.0,
                    retries=attempt,
                )

        raise LLMTransportError("chat request exhausted its retry budget") from last_error

    def _to_response(self, completion: Any, *, latency_ms: float, retries: int) -> ChatResponse:
        choices = getattr(completion, "choices", None) or ()
        if not choices:
            raise LLMResponseError("chat endpoint returned no choices")
        choice = choices[0]
        message = getattr(choice, "message", None)
        if message is None:
            raise LLMResponseError("chat choice has no message")
        raw_calls = getattr(message, "tool_calls", None) or ()
        return ChatResponse(
            content=getattr(message, "content", None),
            tool_calls=tuple(
                ToolCall.from_sdk(call, index=index) for index, call in enumerate(raw_calls)
            ),
            usage=TokenUsage.from_sdk(getattr(completion, "usage", None)),
            model=getattr(completion, "model", None),
            finish_reason=getattr(choice, "finish_reason", None),
            response_id=getattr(completion, "id", None),
            latency_ms=latency_ms,
            retries=retries,
        )


@dataclass(frozen=True, slots=True)
class ModelPricing:
    """USD per million tokens. Cached input is billed at a reduced rate."""

    input_per_million: float
    output_per_million: float
    cached_input_per_million: float | None = None

    def __post_init__(self) -> None:
        for name in ("input_per_million", "output_per_million"):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} must be non-negative")

    def estimate(
        self,
        usage: TokenUsage | int,
        output_tokens: int | None = None,
    ) -> float:
        """Cost in USD for a call.

        Accepts a :class:`TokenUsage` (preferred — it knows how much of the
        prompt was a cache hit) or a bare ``(input_tokens, output_tokens)``
        pair, which cannot express the cache discount and so slightly
        over-estimates.
        """
        if not isinstance(usage, TokenUsage):
            usage = TokenUsage(
                prompt_tokens=int(usage),
                completion_tokens=int(output_tokens or 0),
            )
        cached_rate = (
            self.input_per_million
            if self.cached_input_per_million is None
            else self.cached_input_per_million
        )
        return (
            usage.billable_input_tokens * self.input_per_million
            + usage.cached_tokens * cached_rate
            + usage.completion_tokens * self.output_per_million
        ) / 1_000_000
