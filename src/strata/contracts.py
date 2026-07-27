"""Versioned, dependency-free contracts used by the Strata pipeline.

The dataclasses in this module are deliberately strict.  Invalid model output,
input failures, and backend failures have an explicit status and cannot be
coerced into a negative decision.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime
from enum import Enum, StrEnum
from typing import Any, Self, TypeVar

TRIAGE_DECISION_SCHEMA_VERSION = "triage-decision-v1"
FINDING_SCHEMA_VERSION = "finding-v1"
CWE_CATALOG_VERSION = "CWE-4.20"

_SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CWE_RE = re.compile(r"^CWE-[1-9][0-9]{0,5}$")


class ContractValidationError(ValueError):
    """Raised when a versioned contract is structurally invalid."""


class InputProfile(StrEnum):
    D0 = "D0"
    D1 = "D1"
    D2 = "D2"
    D3 = "D3"


class TriageVerdict(StrEnum):
    YES = "YES"
    NO = "NO"


class FindingVerdict(StrEnum):
    YES = "YES"
    NO = "NO"
    ABSTAIN = "ABSTAIN"


class ParserStatus(StrEnum):
    VALID = "valid"
    PARTIAL = "partial"
    MALFORMED = "malformed"
    BACKEND_ERROR = "backend_error"
    INPUT_ERROR = "input_error"


class ErrorKind(StrEnum):
    MALFORMED_OUTPUT = "malformed_output"
    BACKEND = "backend"
    INPUT = "input"
    OVERSIZE = "oversize"


class L0Class(StrEnum):
    """Closed, stable top-level security taxonomy."""

    MEMORY_SAFETY = "memory_safety"
    INPUT_VALIDATION = "input_validation"
    INJECTION = "injection"
    PATH_TRAVERSAL = "path_traversal"
    ACCESS_CONTROL = "access_control"
    AUTHENTICATION = "authentication"
    CRYPTOGRAPHY = "cryptography"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    CONCURRENCY_TOCTOU = "concurrency_toctou"
    DESERIALIZATION = "deserialization"
    INFORMATION_DISCLOSURE = "information_disclosure"
    LOGIC_FLAW = "logic_flaw"
    SUPPLY_CHAIN = "supply_chain"
    OTHER = "other"


class SeverityLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class SeveritySource(StrEnum):
    CVSS = "cvss"
    ADVISORY = "advisory"
    REPOSITORY = "repository"
    HUMAN = "human"
    MODEL_ESTIMATE = "model_estimate"


class FixCompleteness(StrEnum):
    """How much of the vulnerability this one commit repairs.

    ``MULTI`` records that the fix spans several commits (21% of reviewed
    GHSA advisories). It must stay distinct from ``COMPLETE``: collapsing the
    two is what erased the signal.
    """

    COMPLETE = "complete"
    MULTI = "multi"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


class ReachabilityDelta(StrEnum):
    NARROWS = "narrows"
    WIDENS = "widens"
    UNCHANGED = "unchanged"


class FailureContainment(StrEnum):
    """Who catches the fault a patch repairs.

    Measured over 23 availability-flavoured findings from two independent
    tools, this separated correct from incorrect perfectly: every
    ``UNRECOVERABLE`` one was a real fix, every ``CONTAINED`` one was not.
    """

    UNRECOVERABLE = "unrecoverable"
    CONTAINED = "contained"
    NOT_APPLICABLE = "n/a"


class EvidenceRevision(StrEnum):
    PARENT = "parent"
    COMMIT = "commit"
    HEAD = "head"


class EvidenceClaim(StrEnum):
    """Assertions that each require at least one anchored citation.

    ``REACHABILITY_DELTA`` and ``FAILURE_CONTAINMENT`` are the two gates: a
    finding must show, against repository bytes, that it shrinks the
    attacker-reachable set and that any fault it repairs is not already
    absorbed by the runtime.
    """

    REACHABILITY_DELTA = "reachability_delta"
    FAILURE_CONTAINMENT = "failure_containment"
    ROOT_CAUSE = "root_cause"
    ATTACKER_PRECONDITIONS = "attacker_preconditions"
    IMPACT = "impact"
    FIX_EFFECT = "fix_effect"
    L0_CLASS = "l0_class"
    CWE = "cwe_id"
    SEVERITY = "severity"
    AFFECTED_PATHS = "affected_paths"
    FIX_COMPLETENESS = "fix_completeness"
    INVARIANT = "invariant"


_E = TypeVar("_E", bound=Enum)
_D = TypeVar("_D")


def _fail(path: str, message: str) -> None:
    raise ContractValidationError(f"{path}: {message}")


def _nonempty(value: object, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _fail(path, "must be a non-empty string")
    return value


def _optional_nonempty(value: object, path: str) -> str | None:
    if value is None:
        return None
    return _nonempty(value, path)


def _integer(value: object, path: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        _fail(path, f"must be an integer >= {minimum}")
    return value


def _finite_number(value: object, path: str, *, minimum: float | None = None) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _fail(path, "must be a finite number")
    result = float(value)
    if not math.isfinite(result):
        _fail(path, "must be a finite number")
    if minimum is not None and result < minimum:
        _fail(path, f"must be >= {minimum}")
    return result


def _sha(value: object, path: str) -> str:
    if not isinstance(value, str) or not _SHA_RE.fullmatch(value):
        _fail(path, "must be a lowercase full Git SHA (40 or 64 hex characters)")
    return value


def _hash(value: object, path: str) -> str:
    if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
        _fail(path, "must have the form sha256:<64 lowercase hex characters>")
    return value


def _relative_path(value: object, path: str) -> str:
    result = _nonempty(value, path)
    if "\x00" in result or result.startswith("/") or "\\" in result:
        _fail(path, "must be a NUL-free relative POSIX path")
    if any(part == ".." for part in result.split("/")):
        _fail(path, "must not traverse a parent directory")
    return result


def _enum(value: object, enum_type: type[_E], path: str) -> _E:
    if isinstance(value, enum_type):
        return value
    if not isinstance(value, str):
        _fail(path, f"must be one of {[item.value for item in enum_type]}")
    try:
        return enum_type(value)
    except ValueError:
        _fail(path, f"must be one of {[item.value for item in enum_type]}")


def _tuple(value: object, path: str) -> tuple[Any, ...]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Iterable):
        _fail(path, "must be an array")
    return tuple(value)


def _check_keys(data: Mapping[str, Any], allowed: set[str], path: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        _fail(path, f"unknown fields: {', '.join(unknown)}")


def _coerce_dataclass(value: object, cls: type[_D], path: str) -> _D:
    if isinstance(value, cls):
        return value
    if isinstance(value, Mapping) and hasattr(cls, "from_dict"):
        return cls.from_dict(value)
    _fail(path, f"must be a {cls.__name__} object")


def _json_primitive(value: Any) -> Any:
    """Convert supported values to a deterministic JSON-compatible tree."""

    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {item.name: _json_primitive(getattr(value, item.name)) for item in fields(value)}
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("canonical JSON object keys must be strings")
            result[key] = _json_primitive(item)
        return result
    if isinstance(value, (list, tuple)):
        return [_json_primitive(item) for item in value]
    if isinstance(value, (set, frozenset)):
        converted = [_json_primitive(item) for item in value]
        return sorted(converted, key=lambda item: canonical_json(item))
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise TypeError("canonical JSON datetimes must be timezone-aware")
        return value.isoformat()
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("canonical JSON does not support NaN or infinity")
        return value
    raise TypeError(f"unsupported canonical JSON type: {type(value).__name__}")


def canonical_json(value: Any) -> str:
    """Serialize *value* as canonical UTF-8 JSON.

    Keys are sorted, insignificant whitespace is omitted, Unicode is preserved,
    and non-finite numbers are rejected.
    """

    return json.dumps(
        _json_primitive(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def canonical_json_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def sha256_text(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("sha256_text requires str")
    return sha256_bytes(value.encode("utf-8"))


def canonical_hash(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


class ContractMixin:
    def validate(self) -> Self:
        """Return this instance; construction has already performed validation."""

        return self

    def to_dict(self) -> dict[str, Any]:
        result = _json_primitive(self)
        if not isinstance(result, dict):  # pragma: no cover - defensive
            raise TypeError("contract did not serialize to an object")
        return result

    def to_json(self) -> str:
        return canonical_json(self)

    def content_hash(self) -> str:
        return canonical_hash(self)


@dataclass(frozen=True, slots=True)
class ProviderSettingsV1(ContractMixin):
    provider: str
    model: str
    model_version: str | None = None
    decoding: Mapping[str, str | int | float | bool | None] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _nonempty(self.provider, "provider.provider")
        _nonempty(self.model, "provider.model")
        _optional_nonempty(self.model_version, "provider.model_version")
        if not isinstance(self.decoding, Mapping):
            _fail("provider.decoding", "must be an object")
        copied: dict[str, str | int | float | bool | None] = {}
        for key, value in self.decoding.items():
            _nonempty(key, "provider.decoding key")
            if not (value is None or isinstance(value, (str, int, float, bool))):
                _fail(f"provider.decoding.{key}", "must be a JSON scalar")
            if isinstance(value, float) and not math.isfinite(value):
                _fail(f"provider.decoding.{key}", "must be finite")
            copied[key] = value
        # Copy caller-owned state.  A regular dict keeps the contract compatible
        # with dataclasses.asdict() used by persistence adapters.
        object.__setattr__(self, "decoding", copied)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Self:
        _check_keys(data, {"provider", "model", "model_version", "decoding"}, "provider")
        return cls(
            provider=data.get("provider"),
            model=data.get("model"),
            model_version=data.get("model_version"),
            decoding=data.get("decoding", {}),
        )


@dataclass(frozen=True, slots=True)
class TokenUsageV1(ContractMixin):
    input_tokens: int | None = None
    output_tokens: int | None = None
    total_tokens: int | None = None
    estimated_cost_usd: float | None = None

    def __post_init__(self) -> None:
        for name in ("input_tokens", "output_tokens", "total_tokens"):
            value = getattr(self, name)
            if value is not None:
                _integer(value, f"usage.{name}")
        if self.estimated_cost_usd is not None:
            object.__setattr__(
                self,
                "estimated_cost_usd",
                _finite_number(
                    self.estimated_cost_usd, "usage.estimated_cost_usd", minimum=0.0
                ),
            )
        if (
            self.input_tokens is not None
            and self.output_tokens is not None
            and self.total_tokens is not None
            and self.total_tokens < self.input_tokens + self.output_tokens
        ):
            _fail("usage.total_tokens", "must include input_tokens + output_tokens")

    def __add__(self, other: TokenUsageV1) -> TokenUsageV1:
        def add_optional(left: int | None, right: int | None) -> int | None:
            return None if left is None and right is None else (left or 0) + (right or 0)

        cost = (
            None
            if self.estimated_cost_usd is None and other.estimated_cost_usd is None
            else (self.estimated_cost_usd or 0.0) + (other.estimated_cost_usd or 0.0)
        )
        return TokenUsageV1(
            input_tokens=add_optional(self.input_tokens, other.input_tokens),
            output_tokens=add_optional(self.output_tokens, other.output_tokens),
            total_tokens=add_optional(self.total_tokens, other.total_tokens),
            estimated_cost_usd=cost,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Self:
        allowed = {"input_tokens", "output_tokens", "total_tokens", "estimated_cost_usd"}
        _check_keys(data, allowed, "usage")
        return cls(**{key: data.get(key) for key in allowed})


@dataclass(frozen=True, slots=True)
class RunProvenanceV1(ContractMixin):
    prompt_id: str
    prompt_hash: str
    schema_hash: str
    created_at: str
    tool_policy_hash: str | None = None
    backend_request_ids: tuple[str, ...] = ()
    retry_count: int = 0
    cache_hit: bool = False

    def __post_init__(self) -> None:
        _nonempty(self.prompt_id, "provenance.prompt_id")
        _hash(self.prompt_hash, "provenance.prompt_hash")
        _hash(self.schema_hash, "provenance.schema_hash")
        _optional_nonempty(self.tool_policy_hash, "provenance.tool_policy_hash")
        if self.tool_policy_hash is not None:
            _hash(self.tool_policy_hash, "provenance.tool_policy_hash")
        _nonempty(self.created_at, "provenance.created_at")
        try:
            parsed = datetime.fromisoformat(self.created_at.replace("Z", "+00:00"))
        except ValueError:
            _fail("provenance.created_at", "must be an ISO-8601 timestamp")
        if parsed.tzinfo is None:
            _fail("provenance.created_at", "must include a timezone")
        request_ids = _tuple(self.backend_request_ids, "provenance.backend_request_ids")
        for index, request_id in enumerate(request_ids):
            _nonempty(request_id, f"provenance.backend_request_ids[{index}]")
        object.__setattr__(self, "backend_request_ids", request_ids)
        _integer(self.retry_count, "provenance.retry_count")
        if not isinstance(self.cache_hit, bool):
            _fail("provenance.cache_hit", "must be boolean")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Self:
        allowed = {
            "prompt_id",
            "prompt_hash",
            "schema_hash",
            "created_at",
            "tool_policy_hash",
            "backend_request_ids",
            "retry_count",
            "cache_hit",
        }
        _check_keys(data, allowed, "provenance")
        return cls(
            prompt_id=data.get("prompt_id"),
            prompt_hash=data.get("prompt_hash"),
            schema_hash=data.get("schema_hash"),
            created_at=data.get("created_at"),
            tool_policy_hash=data.get("tool_policy_hash"),
            backend_request_ids=data.get("backend_request_ids", ()),
            retry_count=data.get("retry_count", 0),
            cache_hit=data.get("cache_hit", False),
        )


@dataclass(frozen=True, slots=True)
class ContractErrorV1(ContractMixin):
    kind: ErrorKind
    message: str
    retryable: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _enum(self.kind, ErrorKind, "error.kind"))
        _nonempty(self.message, "error.message")
        if not isinstance(self.retryable, bool):
            _fail("error.retryable", "must be boolean")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Self:
        _check_keys(data, {"kind", "message", "retryable"}, "error")
        return cls(
            kind=data.get("kind"),
            message=data.get("message"),
            retryable=data.get("retryable", False),
        )


@dataclass(frozen=True, slots=True)
class TriageChunkResultV1(ContractMixin):
    index: int
    input_hash: str
    verdict: TriageVerdict | None
    parser_status: ParserStatus
    raw_output: str | None
    usage: TokenUsageV1
    latency_ms: int
    error: ContractErrorV1 | None = None
    backend_request_id: str | None = None

    def __post_init__(self) -> None:
        _integer(self.index, "chunk.index")
        _hash(self.input_hash, "chunk.input_hash")
        if self.verdict is not None:
            object.__setattr__(
                self, "verdict", _enum(self.verdict, TriageVerdict, "chunk.verdict")
            )
        object.__setattr__(
            self,
            "parser_status",
            _enum(self.parser_status, ParserStatus, "chunk.parser_status"),
        )
        if self.parser_status is ParserStatus.PARTIAL:
            _fail("chunk.parser_status", "partial is only valid for an aggregate")
        if self.raw_output is not None and not isinstance(self.raw_output, str):
            _fail("chunk.raw_output", "must be a string or null")
        object.__setattr__(
            self, "usage", _coerce_dataclass(self.usage, TokenUsageV1, "chunk.usage")
        )
        _integer(self.latency_ms, "chunk.latency_ms")
        if self.error is not None:
            object.__setattr__(
                self, "error", _coerce_dataclass(self.error, ContractErrorV1, "chunk.error")
            )
        _optional_nonempty(self.backend_request_id, "chunk.backend_request_id")
        if self.parser_status is ParserStatus.VALID:
            if self.verdict is None or self.error is not None:
                _fail("chunk", "valid output requires a verdict and no error")
        elif self.verdict is not None or self.error is None:
            _fail("chunk", "non-valid output requires null verdict and an error")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Self:
        allowed = {
            "index",
            "input_hash",
            "verdict",
            "parser_status",
            "raw_output",
            "usage",
            "latency_ms",
            "error",
            "backend_request_id",
        }
        _check_keys(data, allowed, "chunk")
        usage = data.get("usage")
        error = data.get("error")
        return cls(
            index=data.get("index"),
            input_hash=data.get("input_hash"),
            verdict=data.get("verdict"),
            parser_status=data.get("parser_status"),
            raw_output=data.get("raw_output"),
            usage=TokenUsageV1.from_dict(usage) if isinstance(usage, Mapping) else usage,
            latency_ms=data.get("latency_ms"),
            error=ContractErrorV1.from_dict(error) if isinstance(error, Mapping) else error,
            backend_request_id=data.get("backend_request_id"),
        )


@dataclass(frozen=True, slots=True)
class TriageDecisionV1(ContractMixin):
    repository: str
    commit_sha: str
    parent_sha: str | None
    input_profile: InputProfile
    raw_input_hash: str
    input_hash: str
    verdict: TriageVerdict | None
    parser_status: ParserStatus
    provider: ProviderSettingsV1
    usage: TokenUsageV1
    latency_ms: int
    provenance: RunProvenanceV1
    chunks: tuple[TriageChunkResultV1, ...] = ()
    error: ContractErrorV1 | None = None
    schema_version: str = TRIAGE_DECISION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != TRIAGE_DECISION_SCHEMA_VERSION:
            _fail("schema_version", f"must equal {TRIAGE_DECISION_SCHEMA_VERSION!r}")
        _nonempty(self.repository, "repository")
        _sha(self.commit_sha, "commit_sha")
        if self.parent_sha is not None:
            _sha(self.parent_sha, "parent_sha")
            if self.parent_sha == self.commit_sha:
                _fail("parent_sha", "must differ from commit_sha")
        object.__setattr__(
            self, "input_profile", _enum(self.input_profile, InputProfile, "input_profile")
        )
        _hash(self.raw_input_hash, "raw_input_hash")
        _hash(self.input_hash, "input_hash")
        if self.verdict is not None:
            object.__setattr__(self, "verdict", _enum(self.verdict, TriageVerdict, "verdict"))
        object.__setattr__(
            self, "parser_status", _enum(self.parser_status, ParserStatus, "parser_status")
        )
        object.__setattr__(
            self,
            "provider",
            _coerce_dataclass(self.provider, ProviderSettingsV1, "provider"),
        )
        object.__setattr__(self, "usage", _coerce_dataclass(self.usage, TokenUsageV1, "usage"))
        _integer(self.latency_ms, "latency_ms")
        object.__setattr__(
            self,
            "provenance",
            _coerce_dataclass(self.provenance, RunProvenanceV1, "provenance"),
        )
        chunks = _tuple(self.chunks, "chunks")
        converted_chunks: list[TriageChunkResultV1] = []
        for index, chunk in enumerate(chunks):
            converted = _coerce_dataclass(chunk, TriageChunkResultV1, f"chunks[{index}]")
            if converted.index != index:
                _fail(f"chunks[{index}].index", "must equal its zero-based array position")
            converted_chunks.append(converted)
        object.__setattr__(self, "chunks", tuple(converted_chunks))
        if self.error is not None:
            object.__setattr__(
                self, "error", _coerce_dataclass(self.error, ContractErrorV1, "error")
            )

        valid_chunks = [
            chunk for chunk in converted_chunks if chunk.parser_status is ParserStatus.VALID
        ]
        yes_chunks = [chunk for chunk in valid_chunks if chunk.verdict is TriageVerdict.YES]
        if self.parser_status is ParserStatus.VALID:
            if self.verdict is None or self.error is not None:
                _fail("triage decision", "valid status requires a verdict and no error")
            if not converted_chunks or len(valid_chunks) != len(converted_chunks):
                _fail("chunks", "a valid aggregate requires only valid chunks")
            expected = TriageVerdict.YES if yes_chunks else TriageVerdict.NO
            if self.verdict is not expected:
                _fail("verdict", "does not match conservative chunk aggregation")
        elif self.parser_status is ParserStatus.PARTIAL:
            if self.verdict is not TriageVerdict.YES or self.error is None:
                _fail("triage decision", "partial status is allowed only for YES with an error")
            if not yes_chunks or len(valid_chunks) == len(converted_chunks):
                _fail("chunks", "partial status requires YES and at least one failed chunk")
        elif self.verdict is not None or self.error is None:
            _fail("triage decision", "failure status requires null verdict and an error")

    @property
    def is_candidate(self) -> bool:
        return self.verdict is TriageVerdict.YES

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Self:
        allowed = {
            "repository",
            "commit_sha",
            "parent_sha",
            "input_profile",
            "raw_input_hash",
            "input_hash",
            "verdict",
            "parser_status",
            "provider",
            "usage",
            "latency_ms",
            "provenance",
            "chunks",
            "error",
            "schema_version",
        }
        _check_keys(data, allowed, "triage decision")
        provider = data.get("provider")
        usage = data.get("usage")
        provenance = data.get("provenance")
        error = data.get("error")
        chunks = data.get("chunks", ())
        return cls(
            repository=data.get("repository"),
            commit_sha=data.get("commit_sha"),
            parent_sha=data.get("parent_sha"),
            input_profile=data.get("input_profile"),
            raw_input_hash=data.get("raw_input_hash"),
            input_hash=data.get("input_hash"),
            verdict=data.get("verdict"),
            parser_status=data.get("parser_status"),
            provider=ProviderSettingsV1.from_dict(provider)
            if isinstance(provider, Mapping)
            else provider,
            usage=TokenUsageV1.from_dict(usage) if isinstance(usage, Mapping) else usage,
            latency_ms=data.get("latency_ms"),
            provenance=RunProvenanceV1.from_dict(provenance)
            if isinstance(provenance, Mapping)
            else provenance,
            chunks=tuple(
                TriageChunkResultV1.from_dict(chunk) if isinstance(chunk, Mapping) else chunk
                for chunk in _tuple(chunks, "chunks")
            ),
            error=ContractErrorV1.from_dict(error) if isinstance(error, Mapping) else error,
            schema_version=data.get("schema_version", TRIAGE_DECISION_SCHEMA_VERSION),
        )


@dataclass(frozen=True, slots=True)
class SeverityV1(ContractMixin):
    level: SeverityLevel
    source: SeveritySource
    score: float | None = None
    vector: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "level", _enum(self.level, SeverityLevel, "severity.level"))
        object.__setattr__(
            self, "source", _enum(self.source, SeveritySource, "severity.source")
        )
        if self.score is not None:
            score = _finite_number(self.score, "severity.score", minimum=0.0)
            if score > 10.0:
                _fail("severity.score", "must be <= 10")
            object.__setattr__(self, "score", score)
        _optional_nonempty(self.vector, "severity.vector")
        if self.vector is not None and self.source is not SeveritySource.CVSS:
            _fail("severity.vector", "is only valid when source is cvss")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Self:
        _check_keys(data, {"level", "source", "score", "vector"}, "severity")
        return cls(
            level=data.get("level"),
            source=data.get("source"),
            score=data.get("score"),
            vector=data.get("vector"),
        )


@dataclass(frozen=True, slots=True)
class EvidenceAnchorV1(ContractMixin):
    revision: EvidenceRevision
    revision_sha: str
    path: str
    start_line: int
    end_line: int
    quoted_span: str
    supports: tuple[EvidenceClaim, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "revision", _enum(self.revision, EvidenceRevision, "evidence.revision")
        )
        _sha(self.revision_sha, "evidence.revision_sha")
        _relative_path(self.path, "evidence.path")
        _integer(self.start_line, "evidence.start_line", minimum=1)
        _integer(self.end_line, "evidence.end_line", minimum=1)
        if self.end_line < self.start_line:
            _fail("evidence.end_line", "must be >= start_line")
        quoted = _nonempty(self.quoted_span, "evidence.quoted_span")
        if len(quoted) > 500:
            _fail("evidence.quoted_span", "must contain at most 500 characters")
        raw_supports = _tuple(self.supports, "evidence.supports")
        supports = tuple(
            _enum(item, EvidenceClaim, f"evidence.supports[{index}]")
            for index, item in enumerate(raw_supports)
        )
        if not supports:
            _fail("evidence.supports", "must contain at least one claim")
        if len(set(supports)) != len(supports):
            _fail("evidence.supports", "must not contain duplicates")
        object.__setattr__(self, "supports", supports)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Self:
        allowed = {
            "revision",
            "revision_sha",
            "path",
            "start_line",
            "end_line",
            "quoted_span",
            "supports",
        }
        _check_keys(data, allowed, "evidence")
        return cls(
            revision=data.get("revision"),
            revision_sha=data.get("revision_sha"),
            path=data.get("path"),
            start_line=data.get("start_line"),
            end_line=data.get("end_line"),
            quoted_span=data.get("quoted_span"),
            supports=data.get("supports", ()),
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class ReachabilityDeltaV1(ContractMixin):
    """Whether the patch shrinks what an attacker can reach.

    Only ``narrows`` can be a fix. A commit that widens a trust set, or that
    first introduces a dangerous read, is the origin of the issue rather than
    its remedy — a distinction that cost this pipeline and its comparator one
    false positive each before it was recorded explicitly.
    """

    verdict: ReachabilityDelta
    before: str
    after: str

    def __post_init__(self) -> None:
        for name in ("before", "after"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                _fail(f"reachability_delta.{name}", "must be non-empty text")
            if len(value) > 400:
                _fail(f"reachability_delta.{name}", "must be at most 400 characters")

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "before": self.before,
            "after": self.after,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ReachabilityDeltaV1:
        _check_keys(data, {"verdict", "before", "after"}, "reachability_delta")
        return cls(
            verdict=_enum(data.get("verdict"), ReachabilityDelta, "reachability_delta.verdict"),
            before=str(data.get("before", "")),
            after=str(data.get("after", "")),
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class FindingV1(ContractMixin):
    repository: str
    commit_sha: str
    parent_sha: str | None
    verdict: FindingVerdict
    provenance: RunProvenanceV1
    root_cause: str | None = None
    attacker_preconditions: str | None = None
    impact: str | None = None
    fix_effect: str | None = None
    l0_class: L0Class | None = None
    cwe_id: str | None = None
    severity: SeverityV1 | None = None
    affected_paths: tuple[str, ...] = ()
    evidence: tuple[EvidenceAnchorV1, ...] = ()
    fix_completeness: FixCompleteness | None = None
    invariant: str | None = None
    reachability_delta: ReachabilityDeltaV1 | None = None
    failure_containment: FailureContainment | None = None
    decision_reason: str | None = None
    schema_version: str = FINDING_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != FINDING_SCHEMA_VERSION:
            _fail("schema_version", f"must equal {FINDING_SCHEMA_VERSION!r}")
        _nonempty(self.repository, "repository")
        _sha(self.commit_sha, "commit_sha")
        if self.parent_sha is not None:
            _sha(self.parent_sha, "parent_sha")
            if self.parent_sha == self.commit_sha:
                _fail("parent_sha", "must differ from commit_sha")
        object.__setattr__(self, "verdict", _enum(self.verdict, FindingVerdict, "verdict"))
        object.__setattr__(
            self,
            "provenance",
            _coerce_dataclass(self.provenance, RunProvenanceV1, "provenance"),
        )
        for name in (
            "root_cause",
            "attacker_preconditions",
            "impact",
            "fix_effect",
            "invariant",
            "decision_reason",
        ):
            _optional_nonempty(getattr(self, name), name)
        # The two gates are structured, not prose: coerce them rather than
        # running the non-empty-string check over them.
        if self.reachability_delta is not None:
            object.__setattr__(
                self,
                "reachability_delta",
                _coerce_dataclass(
                    self.reachability_delta, ReachabilityDeltaV1, "reachability_delta"
                ),
            )
        if self.failure_containment is not None:
            object.__setattr__(
                self,
                "failure_containment",
                _enum(self.failure_containment, FailureContainment, "failure_containment"),
            )
        if self.decision_reason is None:
            _fail("decision_reason", "must explain the adjudicator decision")
        if self.l0_class is not None:
            object.__setattr__(self, "l0_class", _enum(self.l0_class, L0Class, "l0_class"))
        if self.cwe_id is not None:
            if not isinstance(self.cwe_id, str) or not _CWE_RE.fullmatch(self.cwe_id):
                _fail("cwe_id", "must be null or have canonical form CWE-<positive integer>")
        if self.severity is not None:
            object.__setattr__(
                self, "severity", _coerce_dataclass(self.severity, SeverityV1, "severity")
            )
        paths = tuple(
            _relative_path(item, f"affected_paths[{index}]")
            for index, item in enumerate(_tuple(self.affected_paths, "affected_paths"))
        )
        if len(set(paths)) != len(paths):
            _fail("affected_paths", "must not contain duplicates")
        object.__setattr__(self, "affected_paths", paths)
        anchors = tuple(
            _coerce_dataclass(item, EvidenceAnchorV1, f"evidence[{index}]")
            for index, item in enumerate(_tuple(self.evidence, "evidence"))
        )
        object.__setattr__(self, "evidence", anchors)
        if self.fix_completeness is not None:
            object.__setattr__(
                self,
                "fix_completeness",
                _enum(self.fix_completeness, FixCompleteness, "fix_completeness"),
            )

        positive_values = (
            self.root_cause,
            self.attacker_preconditions,
            self.impact,
            self.fix_effect,
            self.l0_class,
            self.cwe_id,
            self.severity,
            self.fix_completeness,
            self.invariant,
        )
        if self.verdict is not FindingVerdict.YES:
            if any(value is not None for value in positive_values) or paths or anchors:
                _fail(
                    "finding",
                    "positive-only fields must be null/empty for NO and ABSTAIN",
                )
            return

        required = {
            "root_cause": self.root_cause,
            "attacker_preconditions": self.attacker_preconditions,
            "impact": self.impact,
            "fix_effect": self.fix_effect,
            "l0_class": self.l0_class,
            "severity": self.severity,
            "fix_completeness": self.fix_completeness,
        }
        missing = [name for name, value in required.items() if value is None]
        if missing:
            _fail("finding", f"YES requires: {', '.join(missing)}")
        if not paths:
            _fail("affected_paths", "YES requires at least one affected path")
        if not anchors:
            _fail("evidence", "YES requires at least one evidence anchor")

        supported = {claim for anchor in anchors for claim in anchor.supports}
        required_claims = {
            EvidenceClaim.ROOT_CAUSE,
            EvidenceClaim.ATTACKER_PRECONDITIONS,
            EvidenceClaim.IMPACT,
            EvidenceClaim.FIX_EFFECT,
            EvidenceClaim.L0_CLASS,
            EvidenceClaim.SEVERITY,
            EvidenceClaim.AFFECTED_PATHS,
            EvidenceClaim.FIX_COMPLETENESS,
        }
        if self.cwe_id is not None:
            required_claims.add(EvidenceClaim.CWE)
        if self.invariant is not None:
            required_claims.add(EvidenceClaim.INVARIANT)
        unsupported = sorted(claim.value for claim in required_claims - supported)
        if unsupported:
            _fail("evidence", f"missing anchors for claims: {', '.join(unsupported)}")

        anchor_paths = {anchor.path for anchor in anchors}
        missing_paths = sorted(set(paths) - anchor_paths)
        if missing_paths:
            _fail("evidence", f"missing anchors for affected paths: {', '.join(missing_paths)}")
        for index, anchor in enumerate(anchors):
            if (
                anchor.revision is EvidenceRevision.COMMIT
                and anchor.revision_sha != self.commit_sha
            ):
                _fail(f"evidence[{index}].revision_sha", "must equal commit_sha")
            if anchor.revision is EvidenceRevision.PARENT:
                if self.parent_sha is None:
                    _fail(f"evidence[{index}].revision", "root commits have no parent")
                if anchor.revision_sha != self.parent_sha:
                    _fail(f"evidence[{index}].revision_sha", "must equal parent_sha")

    @property
    def cwe(self) -> str | None:
        """Compatibility spelling for callers that use ``cwe``."""

        return self.cwe_id

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Self:
        allowed = {
            "repository",
            "commit_sha",
            "parent_sha",
            "verdict",
            "provenance",
            "root_cause",
            "attacker_preconditions",
            "impact",
            "fix_effect",
            "l0_class",
            "cwe_id",
            "severity",
            "affected_paths",
            "evidence",
            "fix_completeness",
            "invariant",
            "reachability_delta",
            "failure_containment",
            "decision_reason",
            "schema_version",
        }
        _check_keys(data, allowed, "finding")
        provenance = data.get("provenance")
        severity = data.get("severity")
        return cls(
            repository=data.get("repository"),
            commit_sha=data.get("commit_sha"),
            parent_sha=data.get("parent_sha"),
            verdict=data.get("verdict"),
            provenance=RunProvenanceV1.from_dict(provenance)
            if isinstance(provenance, Mapping)
            else provenance,
            root_cause=data.get("root_cause"),
            attacker_preconditions=data.get("attacker_preconditions"),
            impact=data.get("impact"),
            fix_effect=data.get("fix_effect"),
            l0_class=data.get("l0_class"),
            cwe_id=data.get("cwe_id"),
            severity=SeverityV1.from_dict(severity)
            if isinstance(severity, Mapping)
            else severity,
            affected_paths=data.get("affected_paths", ()),
            evidence=tuple(
                EvidenceAnchorV1.from_dict(anchor) if isinstance(anchor, Mapping) else anchor
                for anchor in _tuple(data.get("evidence", ()), "evidence")
            ),
            fix_completeness=data.get("fix_completeness"),
            invariant=data.get("invariant"),
            reachability_delta=(
                ReachabilityDeltaV1.from_dict(data["reachability_delta"])
                if isinstance(data.get("reachability_delta"), Mapping)
                else None
            ),
            failure_containment=(
                _enum(data["failure_containment"], FailureContainment, "failure_containment")
                if data.get("failure_containment") is not None
                else None
            ),
            decision_reason=data.get("decision_reason"),
            schema_version=data.get("schema_version", FINDING_SCHEMA_VERSION),
        )


def validate_triage_decision(data: Mapping[str, Any] | TriageDecisionV1) -> TriageDecisionV1:
    return data if isinstance(data, TriageDecisionV1) else TriageDecisionV1.from_dict(data)


def validate_finding(data: Mapping[str, Any] | FindingV1) -> FindingV1:
    return data if isinstance(data, FindingV1) else FindingV1.from_dict(data)


# Concise aliases for callers that do not need the version suffix on nested types.
TokenUsage = TokenUsageV1
ProviderSettings = ProviderSettingsV1
RunProvenance = RunProvenanceV1
EvidenceAnchor = EvidenceAnchorV1
Severity = SeverityV1
