"""Network-free pass-1 runner with an injected model backend."""

from __future__ import annotations

import inspect
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .contracts import (
    TRIAGE_DECISION_SCHEMA_VERSION,
    ContractErrorV1,
    ErrorKind,
    InputProfile,
    ParserStatus,
    ProviderSettingsV1,
    RunProvenanceV1,
    TokenUsageV1,
    TriageChunkResultV1,
    TriageDecisionV1,
    TriageVerdict,
    sha256_bytes,
)
from .diffing import InputBuildStatus, InputLimits, TriageInput, build_input_profile
from .llm import estimate_chat_tokens
from .resources import SCHEMAS_DIR

CURRENT_DIFF_ONLY_SYSTEM_PROMPT = (
    "You are a security engineer reviewing a single git commit diff. "
    "Decide whether the diff fixes a real, pre-existing, exploitable security "
    "vulnerability (as opposed to an ordinary bug fix, feature, refactor, test, "
    "or documentation change). "
    'Answer with exactly one word: "YES" or "NO".'
)
CURRENT_DIFF_ONLY_USER_TEMPLATE = "Does this git diff patch a security vulnerability?\n\n{diff}"


@dataclass(frozen=True, slots=True)
class PromptSpec:
    prompt_id: str
    system_prompt: str
    user_template: str

    def __post_init__(self) -> None:
        if not self.prompt_id.strip():
            raise ValueError("prompt_id must be non-empty")
        if not self.system_prompt.strip():
            raise ValueError("system_prompt must be non-empty")
        if self.user_template.count("{diff}") != 1:
            raise ValueError("user_template must contain exactly one {diff} placeholder")

    @property
    def prompt_hash(self) -> str:
        payload = (
            self.system_prompt.encode("utf-8") + b"\x00" + self.user_template.encode("utf-8")
        )
        return sha256_bytes(payload)

    def render(self, input_text: str) -> str:
        return self.user_template.replace("{diff}", input_text)


CURRENT_DIFF_ONLY_PROMPT = PromptSpec(
    prompt_id="current-diff-only-v1",
    system_prompt=CURRENT_DIFF_ONLY_SYSTEM_PROMPT,
    user_template=CURRENT_DIFF_ONLY_USER_TEMPLATE,
)


@dataclass(frozen=True, slots=True)
class TriageRequest:
    repository: str
    commit_sha: str
    parent_sha: str | None
    input_profile: InputProfile
    input_hash: str
    chunk_index: int
    chunk_count: int
    prompt_id: str
    system_prompt: str
    user_prompt: str


@dataclass(frozen=True, slots=True)
class BackendResponse:
    text: str
    # `field(default_factory=...)` rather than a shared instance: the default
    # is evaluated once at class creation and would otherwise be the same
    # object on every response.
    usage: TokenUsageV1 = field(default_factory=TokenUsageV1)
    request_id: str | None = None
    retry_count: int = 0
    cache_hit: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.text, str):
            raise TypeError("backend response text must be str")
        if not isinstance(self.usage, TokenUsageV1):
            object.__setattr__(
                self,
                "usage",
                TokenUsageV1.from_dict(self.usage)
                if isinstance(self.usage, Mapping)
                else self.usage,
            )
        if not isinstance(self.usage, TokenUsageV1):
            raise TypeError("backend response usage must be TokenUsageV1")
        if self.request_id is not None and (
            not isinstance(self.request_id, str) or not self.request_id.strip()
        ):
            raise ValueError("request_id must be null or a non-empty string")
        if (
            isinstance(self.retry_count, bool)
            or not isinstance(self.retry_count, int)
            or self.retry_count < 0
        ):
            raise ValueError("retry_count must be a non-negative integer")
        if not isinstance(self.cache_hit, bool):
            raise TypeError("cache_hit must be boolean")


@runtime_checkable
class TriageBackend(Protocol):
    def __call__(self, request: TriageRequest) -> BackendResponse | str | Mapping[str, Any]: ...


BackendCallable = Callable[[TriageRequest], BackendResponse | str | Mapping[str, Any]]


def parse_strict_yes_no(text: str) -> TriageVerdict:
    """Parse only the exact protocol tokens; prose and empty output are errors."""

    if not isinstance(text, str):
        raise ValueError("model output must be text")
    token = text.strip()
    if token == "YES":
        return TriageVerdict.YES
    if token == "NO":
        return TriageVerdict.NO
    raise ValueError('expected exactly "YES" or "NO"')


def _usage_from_mapping(value: object) -> TokenUsageV1:
    if value is None:
        return TokenUsageV1()
    if isinstance(value, TokenUsageV1):
        return value
    if not isinstance(value, Mapping):
        attributes = {
            name: getattr(value, name)
            for name in (
                "input_tokens",
                "prompt_tokens",
                "output_tokens",
                "completion_tokens",
                "total_tokens",
                "estimated_cost_usd",
                "estimated_cost",
                "cost_usd",
            )
            if hasattr(value, name)
        }
        if not attributes:
            raise TypeError("backend usage must be an object")
        value = attributes
    input_tokens = value.get("input_tokens", value.get("prompt_tokens"))
    output_tokens = value.get("output_tokens", value.get("completion_tokens"))
    total_tokens = value.get("total_tokens")
    if total_tokens is None and (input_tokens is not None or output_tokens is not None):
        total_tokens = int(input_tokens or 0) + int(output_tokens or 0)
    return TokenUsageV1(
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        total_tokens=total_tokens,
        estimated_cost_usd=value.get(
            "estimated_cost_usd",
            value.get("estimated_cost", value.get("cost_usd")),
        ),
    )


def coerce_backend_response(value: object) -> BackendResponse:
    if isinstance(value, BackendResponse):
        return value
    if isinstance(value, str):
        return BackendResponse(text=value)
    if not isinstance(value, Mapping):
        content = getattr(value, "content", None)
        if content is None:
            content = getattr(value, "text", None)
        if not isinstance(content, str):
            raise TypeError(
                "backend must return BackendResponse, text, a mapping, "
                "or an object with textual content"
            )
        return BackendResponse(
            text=content,
            usage=_usage_from_mapping(getattr(value, "usage", None)),
            request_id=getattr(value, "response_id", getattr(value, "request_id", None)),
            retry_count=getattr(value, "retries", getattr(value, "retry_count", 0)),
            cache_hit=getattr(value, "cache_hit", False),
        )
    allowed_text_fields = ("text", "content", "output")
    text = next((value[key] for key in allowed_text_fields if key in value), None)
    return BackendResponse(
        text=text,
        usage=_usage_from_mapping(value.get("usage")),
        request_id=value.get("request_id", value.get("id")),
        retry_count=value.get("retry_count", value.get("retries", 0)),
        cache_hit=value.get("cache_hit", value.get("cached", False)),
    )


def triage_schema_hash(path: Path | None = None) -> str:
    """Hash the exact schema file used by a source checkout."""

    schema_path = path or (SCHEMAS_DIR / "triage-decision-v1.schema.json")
    if schema_path.is_file():
        return sha256_bytes(schema_path.read_bytes())
    # Installed minimal distributions can still record a stable contract marker.
    return sha256_bytes(TRIAGE_DECISION_SCHEMA_VERSION.encode("utf-8"))


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("runner clock must return a timezone-aware datetime")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _error_status_from_input(status: InputBuildStatus) -> tuple[ParserStatus, ErrorKind]:
    if status is InputBuildStatus.OVERSIZE:
        return ParserStatus.INPUT_ERROR, ErrorKind.OVERSIZE
    return ParserStatus.INPUT_ERROR, ErrorKind.INPUT


def _aggregate_error(
    chunks: tuple[TriageChunkResultV1, ...],
) -> tuple[ParserStatus, ContractErrorV1]:
    failures = [chunk for chunk in chunks if chunk.parser_status is not ParserStatus.VALID]
    if any(chunk.parser_status is ParserStatus.BACKEND_ERROR for chunk in failures):
        status = ParserStatus.BACKEND_ERROR
        kind = ErrorKind.BACKEND
    else:
        status = ParserStatus.MALFORMED
        kind = ErrorKind.MALFORMED_OUTPUT
    indexes = ", ".join(str(chunk.index) for chunk in failures)
    return status, ContractErrorV1(
        kind=kind,
        message=f"triage failed for chunk(s): {indexes}",
        retryable=any(chunk.error is not None and chunk.error.retryable for chunk in failures),
    )


class TriageRunner:
    """Execute pass 1 without coupling the package to a provider or network."""

    def __init__(
        self,
        backend: TriageBackend | BackendCallable | object,
        *,
        provider: ProviderSettingsV1,
        prompt: PromptSpec = CURRENT_DIFF_ONLY_PROMPT,
        schema_hash: str | None = None,
        clock: Callable[[], datetime] = _utc_now,
        timer_ns: Callable[[], int] = time.perf_counter_ns,
    ) -> None:
        if not isinstance(provider, ProviderSettingsV1):
            raise TypeError("provider must be ProviderSettingsV1")
        if not callable(backend) and not callable(getattr(backend, "complete", None)):
            raise TypeError("backend must be callable or expose complete(request)")
        self._backend = backend
        self.provider = provider
        self.prompt = prompt
        self.schema_hash = schema_hash or triage_schema_hash()
        self._clock = clock
        self._timer_ns = timer_ns

    def _invoke(self, request: TriageRequest) -> BackendResponse:
        complete = getattr(self._backend, "complete", None)
        if callable(complete):
            try:
                parameters = tuple(inspect.signature(complete).parameters.values())
            except TypeError, ValueError:
                parameters = ()
            first_name = parameters[0].name if parameters else ""
            if first_name in {"messages", "chat", "conversation"}:
                raw = complete(
                    [
                        {"role": "system", "content": request.system_prompt},
                        {"role": "user", "content": request.user_prompt},
                    ],
                    **dict(self.provider.decoding),
                )
            else:
                raw = complete(request)
        else:
            raw = self._backend(request)  # type: ignore[operator]
        return coerce_backend_response(raw)

    def run(
        self,
        triage_input: TriageInput,
        *,
        repository: str,
        commit_sha: str,
        parent_sha: str | None,
    ) -> TriageDecisionV1:
        created_at = _timestamp(self._clock())
        if not triage_input.ready:
            status, kind = _error_status_from_input(triage_input.status)
            error = ContractErrorV1(
                kind=kind,
                message=triage_input.error or f"input status is {triage_input.status.value}",
                retryable=False,
            )
            return TriageDecisionV1(
                repository=repository,
                commit_sha=commit_sha,
                parent_sha=parent_sha,
                input_profile=triage_input.profile,
                raw_input_hash=triage_input.raw_diff_hash,
                input_hash=triage_input.input_hash,
                verdict=None,
                parser_status=status,
                provider=self.provider,
                usage=TokenUsageV1(),
                latency_ms=0,
                provenance=RunProvenanceV1(
                    prompt_id=self.prompt.prompt_id,
                    prompt_hash=self.prompt.prompt_hash,
                    schema_hash=self.schema_hash,
                    created_at=created_at,
                ),
                chunks=(),
                error=error,
            )

        chunk_results: list[TriageChunkResultV1] = []
        request_ids: list[str] = []
        retries = 0
        cache_flags: list[bool] = []
        for chunk in triage_input.chunks:
            request = TriageRequest(
                repository=repository,
                commit_sha=commit_sha,
                parent_sha=parent_sha,
                input_profile=triage_input.profile,
                input_hash=chunk.input_hash,
                chunk_index=chunk.index,
                chunk_count=len(triage_input.chunks),
                prompt_id=self.prompt.prompt_id,
                system_prompt=self.prompt.system_prompt,
                user_prompt=self.prompt.render(chunk.text),
            )
            started = self._timer_ns()
            try:
                response = self._invoke(request)
            except Exception as exc:
                latency_ms = max(0, (self._timer_ns() - started) // 1_000_000)
                chunk_results.append(
                    TriageChunkResultV1(
                        index=chunk.index,
                        input_hash=chunk.input_hash,
                        verdict=None,
                        parser_status=ParserStatus.BACKEND_ERROR,
                        raw_output=None,
                        usage=TokenUsageV1(),
                        latency_ms=latency_ms,
                        error=ContractErrorV1(
                            kind=ErrorKind.BACKEND,
                            message=f"{type(exc).__name__}: {exc}",
                            retryable=True,
                        ),
                    )
                )
                cache_flags.append(False)
                continue

            latency_ms = max(0, (self._timer_ns() - started) // 1_000_000)
            retries += response.retry_count
            cache_flags.append(response.cache_hit)
            if response.request_id is not None:
                request_ids.append(response.request_id)
            try:
                verdict = parse_strict_yes_no(response.text)
            except ValueError as exc:
                chunk_results.append(
                    TriageChunkResultV1(
                        index=chunk.index,
                        input_hash=chunk.input_hash,
                        verdict=None,
                        parser_status=ParserStatus.MALFORMED,
                        raw_output=response.text,
                        usage=response.usage,
                        latency_ms=latency_ms,
                        error=ContractErrorV1(
                            kind=ErrorKind.MALFORMED_OUTPUT,
                            message=str(exc),
                            retryable=False,
                        ),
                        backend_request_id=response.request_id,
                    )
                )
            else:
                chunk_results.append(
                    TriageChunkResultV1(
                        index=chunk.index,
                        input_hash=chunk.input_hash,
                        verdict=verdict,
                        parser_status=ParserStatus.VALID,
                        raw_output=response.text,
                        usage=response.usage,
                        latency_ms=latency_ms,
                        backend_request_id=response.request_id,
                    )
                )

        chunks = tuple(chunk_results)
        valid = tuple(chunk for chunk in chunks if chunk.parser_status is ParserStatus.VALID)
        any_yes = any(chunk.verdict is TriageVerdict.YES for chunk in valid)
        all_valid = bool(chunks) and len(valid) == len(chunks)
        error: ContractErrorV1 | None = None
        if any_yes:
            verdict: TriageVerdict | None = TriageVerdict.YES
            if all_valid:
                parser_status = ParserStatus.VALID
            else:
                _, error = _aggregate_error(chunks)
                parser_status = ParserStatus.PARTIAL
        elif all_valid:
            verdict = TriageVerdict.NO
            parser_status = ParserStatus.VALID
        else:
            verdict = None
            parser_status, error = _aggregate_error(chunks)

        usage = TokenUsageV1()
        for chunk in chunks:
            usage = usage + chunk.usage
        return TriageDecisionV1(
            repository=repository,
            commit_sha=commit_sha,
            parent_sha=parent_sha,
            input_profile=triage_input.profile,
            raw_input_hash=triage_input.raw_diff_hash,
            input_hash=triage_input.input_hash,
            verdict=verdict,
            parser_status=parser_status,
            provider=self.provider,
            usage=usage,
            latency_ms=sum(chunk.latency_ms for chunk in chunks),
            provenance=RunProvenanceV1(
                prompt_id=self.prompt.prompt_id,
                prompt_hash=self.prompt.prompt_hash,
                schema_hash=self.schema_hash,
                created_at=created_at,
                backend_request_ids=tuple(request_ids),
                retry_count=retries,
                cache_hit=bool(cache_flags) and all(cache_flags),
            ),
            chunks=chunks,
            error=error,
        )

    def run_raw(
        self,
        raw_diff: str,
        *,
        repository: str,
        commit_sha: str,
        parent_sha: str | None,
        profile: InputProfile | str = InputProfile.D0,
        subject: str = "",
        message: str = "",
        limits: InputLimits | None = None,
    ) -> TriageDecisionV1:
        triage_input = build_input_profile(
            profile,
            raw_diff,
            subject=subject,
            message=message,
            limits=limits,
        )
        return self.run(
            triage_input,
            repository=repository,
            commit_sha=commit_sha,
            parent_sha=parent_sha,
        )

    def __call__(self, commit: Mapping[str, Any]) -> TriageDecisionV1:
        """Use a configured runner directly as an importer stage callable."""

        raw_diff = commit.get("diff", commit.get("raw_diff", commit.get("patch")))
        if isinstance(raw_diff, bytes):
            raw_diff = raw_diff.decode("utf-8", errors="replace")
        if not isinstance(raw_diff, str):
            raise TypeError("commit mapping must contain textual diff or raw_diff")
        repository = commit.get("repository", commit.get("repo"))
        commit_sha = commit.get("commit_sha", commit.get("sha"))
        parent_sha = commit.get("parent_sha", commit.get("first_parent_sha"))
        message = str(commit.get("message") or "")
        subject = commit.get("subject")
        if not subject and message:
            subject = message.splitlines()[0]
        return self.run_raw(
            raw_diff,
            repository=str(repository or ""),
            commit_sha=str(commit_sha or ""),
            parent_sha=str(parent_sha) if parent_sha else None,
            profile=commit.get("input_profile", InputProfile.D0),
            subject=str(subject or ""),
            message=message,
        )


@dataclass(frozen=True, slots=True)
class ModelPricing:
    """Optional provider pricing in USD per million tokens."""

    input_per_million: float
    output_per_million: float

    def __post_init__(self) -> None:
        if self.input_per_million < 0 or self.output_per_million < 0:
            raise ValueError("model prices must be non-negative")

    def estimate(self, input_tokens: int, output_tokens: int) -> float:
        return (
            input_tokens * self.input_per_million + output_tokens * self.output_per_million
        ) / 1_000_000


class OpenAICompatibleTriageBackend:
    """Adapt :class:`strata.llm.OpenAIChatClient` to ``TriageRunner``."""

    def __init__(
        self,
        client: Any,
        *,
        pricing: ModelPricing | None = None,
        max_output_tokens: int = 3,
        request_parameters: Mapping[str, Any] | None = None,
        rate_limiter: Any | None = None,
    ) -> None:
        if max_output_tokens < 1:
            raise ValueError("max_output_tokens must be positive")
        self.client = client
        self.pricing = pricing
        self.max_output_tokens = max_output_tokens
        self.request_parameters = dict(request_parameters or {})
        self.rate_limiter = rate_limiter

    def __call__(self, request: TriageRequest) -> BackendResponse:
        messages = [
            {"role": "system", "content": request.system_prompt},
            {"role": "user", "content": request.user_prompt},
        ]
        if self.rate_limiter is not None:
            model = str(getattr(getattr(self.client, "config", None), "model", ""))
            estimated_tokens = estimate_chat_tokens(
                messages,
                model=model,
                output_tokens=self.max_output_tokens,
            )
            self.rate_limiter.acquire(estimated_tokens)
        response = self.client.complete(
            messages,
            temperature=0,
            max_tokens=self.max_output_tokens,
            **self.request_parameters,
        )
        usage_value = response.usage
        input_tokens = int(getattr(usage_value, "prompt_tokens", 0) or 0)
        output_tokens = int(getattr(usage_value, "completion_tokens", 0) or 0)
        total_tokens = int(
            getattr(usage_value, "total_tokens", 0) or input_tokens + output_tokens
        )
        estimated_cost = (
            self.pricing.estimate(input_tokens, output_tokens)
            if self.pricing is not None
            else None
        )
        return BackendResponse(
            text=response.content or "",
            usage=TokenUsageV1(
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                total_tokens=total_tokens,
                estimated_cost_usd=estimated_cost,
            ),
            request_id=response.response_id,
            retry_count=response.retries,
        )


# Compatibility spelling for callers migrating from the prototype.
parse_yes_no = parse_strict_yes_no
