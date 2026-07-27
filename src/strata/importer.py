"""Resumable two-stage repository import orchestration."""

from __future__ import annotations

import inspect
import math
import time
from collections.abc import Callable, Mapping
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import asdict, dataclass, field, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .git_repo import GitCommit, GitRepository
from .store import Store, canonical_json, config_hash

PIPELINE_VERSION = 1
_TRIAGE_CANDIDATES = {"YES", "CANDIDATE", "ABSTAIN", "ERROR"}


@runtime_checkable
class TriageCallable(Protocol):
    def __call__(self, commit: Mapping[str, Any]) -> Any: ...


@runtime_checkable
class AdjudicationCallable(Protocol):
    def __call__(
        self,
        commit: Mapping[str, Any],
        repository: GitRepository,
    ) -> Any: ...


@dataclass(frozen=True, slots=True)
class ImportLimits:
    max_commits: int | None = None
    max_candidates: int | None = None
    max_calls: int | None = None
    max_tokens: int | None = None
    max_cost: float | None = None
    max_wall_seconds: float | None = None

    def __post_init__(self) -> None:
        integer_fields = (
            "max_commits",
            "max_candidates",
            "max_calls",
            "max_tokens",
        )
        for name in integer_fields:
            value = getattr(self, name)
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int) or value < 0
            ):
                raise ValueError(f"{name} must be a non-negative integer or None")
        for name in ("max_cost", "max_wall_seconds"):
            value = getattr(self, name)
            if value is not None and (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or value < 0
            ):
                raise ValueError(f"{name} must be non-negative or None")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


PipelineLimits = ImportLimits


@dataclass(frozen=True, slots=True)
class ImportSummary:
    run_id: str
    status: str
    repository_id: int
    snapshot_id: int
    head_sha: str
    planned_commits: int
    counters: dict[str, Any] = field(default_factory=dict)
    budget_reason: str | None = None
    dry_run: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]


@dataclass(slots=True)
class _CommitState:
    position: int
    commit: GitCommit
    commit_id: int
    patch_blob_hash: str
    payload: dict[str, Any]
    input_blob_hash: str
    triage: dict[str, Any] | None = None
    adjudication: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class _StageOutcome:
    result: dict[str, Any]
    verdict: str
    usage: dict[str, Any]
    error: dict[str, Any] | None


def _callable_identity(function: Callable[..., Any] | None) -> str | None:
    if function is None:
        return None
    module = getattr(function, "__module__", function.__class__.__module__)
    name = getattr(function, "__qualname__", function.__class__.__qualname__)
    return f"{module}.{name}"


def _to_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, bool):
        return {"verdict": "YES" if value else "NO"}
    if isinstance(value, str):
        return {"verdict": value}
    if hasattr(value, "model_dump"):
        converted = value.model_dump(mode="json")
        if isinstance(converted, Mapping):
            return dict(converted)
    if hasattr(value, "to_dict"):
        converted = value.to_dict()
        if isinstance(converted, Mapping):
            return dict(converted)
    if is_dataclass(value):
        return asdict(value)
    if hasattr(value, "__dict__"):
        return {key: item for key, item in vars(value).items() if not key.startswith("_")}
    raise TypeError(f"unsupported model result type: {type(value).__name__}")


def _normalise_verdict(result: Mapping[str, Any], *, stage: str) -> str:
    raw: Any = None
    for key in ("verdict", "decision", "label"):
        if result.get(key) is not None:
            raw = result[key]
            break
    if raw is None and isinstance(result.get("flagged"), bool):
        raw = "YES" if result["flagged"] else "NO"
    if raw is None and isinstance(result.get("candidate"), bool):
        raw = "YES" if result["candidate"] else "NO"
    if isinstance(raw, bool):
        raw = "YES" if raw else "NO"
    if isinstance(raw, Enum):
        raw = raw.value
    verdict = str(raw or "").strip().upper()
    aliases = {
        "TRUE": "YES",
        "FIX": "YES",
        "SECURITY_FIX": "YES",
        "SECURITY-FIX": "YES",
        "FALSE": "NO",
        "NOT_A_FIX": "NO",
        "NOT-A-FIX": "NO",
        "SKIP": "NO",
        "FALLBACK": "ERROR",
    }
    verdict = aliases.get(verdict, verdict)
    accepted = (
        {"YES", "NO", "CANDIDATE", "ABSTAIN", "ERROR"}
        if stage == "triage"
        else {"YES", "NO", "ABSTAIN", "ERROR"}
    )
    return verdict if verdict in accepted else "ERROR"


def _usage_from_result(result: Mapping[str, Any]) -> dict[str, Any]:
    usage_value = result.get("usage")
    if usage_value is None:
        adjudication = result.get("adjudication")
        if isinstance(adjudication, Mapping):
            usage_value = adjudication.get("usage")
    if isinstance(usage_value, Mapping):
        usage = dict(usage_value)
    elif usage_value is not None and is_dataclass(usage_value):
        usage = asdict(usage_value)
    else:
        usage = {}
    for key in (
        "input_tokens",
        "prompt_tokens",
        "output_tokens",
        "completion_tokens",
        "total_tokens",
        "estimated_cost",
        "estimated_cost_usd",
        "cost_usd",
        "cost",
    ):
        if key in result and key not in usage:
            usage[key] = result[key]
    return usage


def _usage_totals(usage: Mapping[str, Any]) -> tuple[int, float]:
    tokens = usage.get("total_tokens")
    if not isinstance(tokens, int):
        input_tokens = usage.get("input_tokens", usage.get("prompt_tokens", 0))
        output_tokens = usage.get("output_tokens", usage.get("completion_tokens", 0))
        if isinstance(input_tokens, int) or isinstance(output_tokens, int):
            tokens = int(input_tokens or 0) + int(output_tokens or 0)
        else:
            tokens = 0
    cost = usage.get(
        "estimated_cost",
        usage.get(
            "estimated_cost_usd",
            usage.get("cost_usd", usage.get("cost", 0.0)),
        ),
    )
    finite_cost = (
        float(cost)
        if isinstance(cost, (int, float))
        and not isinstance(cost, bool)
        and math.isfinite(float(cost))
        else 0.0
    )
    return max(tokens, 0), max(finite_cost, 0.0)


def _error_payload(error: BaseException, *, kind: str | None = None) -> dict[str, Any]:
    return {
        "kind": kind or error.__class__.__name__,
        "message": str(error)[:4096],
    }


def _invoke_triage(
    function: TriageCallable,
    payload: Mapping[str, Any],
) -> _StageOutcome:
    try:
        result = _to_mapping(function(payload))
        verdict = _normalise_verdict(result, stage="triage")
        usage = _usage_from_result(result)
        error = None
        if verdict == "ERROR":
            error_value = result.get("error")
            if isinstance(error_value, Mapping):
                error = dict(error_value)
            else:
                error = {
                    "kind": "invalid_triage_result",
                    "message": "triage result did not contain a recognized verdict",
                }
        return _StageOutcome(result, verdict, usage, error)
    except Exception as exc:
        error = _error_payload(exc)
        return _StageOutcome(
            result={"verdict": "ERROR", "error": error},
            verdict="ERROR",
            usage={},
            error=error,
        )


def _adjudicator_accepts_repository(function: Callable[..., Any]) -> bool:
    try:
        signature = inspect.signature(function)
    except TypeError, ValueError:
        return True
    positional = [
        parameter
        for parameter in signature.parameters.values()
        if parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD)
    ]
    return (
        any(
            parameter.kind is parameter.VAR_POSITIONAL
            for parameter in signature.parameters.values()
        )
        or len(positional) >= 2
    )


def _invoke_adjudication(
    function: Any,
    payload: Mapping[str, Any],
    repository: GitRepository,
) -> _StageOutcome:
    try:
        target = function
        if not callable(target):
            target = next(
                (
                    method
                    for name in ("adjudicate", "run")
                    if callable(method := getattr(function, name, None))
                ),
                None,
            )
        if target is None:
            raise TypeError("adjudicator must be callable or expose adjudicate/run")
        if _adjudicator_accepts_repository(target):
            raw = target(payload, repository)
        else:
            raw = target(payload)
        result = _to_mapping(raw)
        verdict = _normalise_verdict(result, stage="adjudication")
        usage = _usage_from_result(result)
        error = None
        if verdict == "ERROR":
            error_value = result.get("error")
            if isinstance(error_value, Mapping):
                error = dict(error_value)
            else:
                error = {
                    "kind": "invalid_adjudication_result",
                    "message": "adjudication result did not contain a recognized verdict",
                }
        return _StageOutcome(result, verdict, usage, error)
    except Exception as exc:
        error = _error_payload(exc)
        return _StageOutcome(
            result={"verdict": "ERROR", "error": error},
            verdict="ERROR",
            usage={},
            error=error,
        )


class Importer:
    """Run extraction, triage, and candidate-only adjudication."""

    def __init__(
        self,
        store: Store,
        *,
        triage: TriageCallable | None = None,
        adjudicator: AdjudicationCallable | Callable[..., Any] | None = None,
        adjudication: AdjudicationCallable | Callable[..., Any] | None = None,
        config: Mapping[str, Any] | None = None,
        limits: ImportLimits | None = None,
        max_workers: int = 1,
        cache_root: str | Path | None = None,
        repository_factory: Callable[..., GitRepository] = GitRepository,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if adjudicator is not None and adjudication is not None:
            raise ValueError("provide adjudicator or adjudication, not both")
        if max_workers < 1 or max_workers > 32:
            raise ValueError("max_workers must be between 1 and 32")
        self.store = store
        self.triage = triage
        self.adjudicator = adjudicator or adjudication
        self.user_config = dict(config or {})
        self.limits = limits or ImportLimits()
        self.max_workers = max_workers
        self.cache_root = Path(cache_root or (store.path.parent / "repos"))
        self.repository_factory = repository_factory
        self.clock = clock

    def _pipeline_config(self) -> dict[str, Any]:
        def stage_config(stage: Any) -> Any:
            value = getattr(stage, "strata_config", None)
            if isinstance(value, Mapping):
                return dict(value)
            provider = getattr(stage, "provider", None)
            prompt = getattr(stage, "prompt", None)
            derived: dict[str, Any] = {}
            if provider is not None and callable(getattr(provider, "to_dict", None)):
                derived["provider"] = provider.to_dict()
            if prompt is not None:
                for name in ("prompt_id", "prompt_hash"):
                    if hasattr(prompt, name):
                        derived[name] = getattr(prompt, name)
            return derived or None

        return {
            "pipeline_version": PIPELINE_VERSION,
            "triage_callable": _callable_identity(self.triage),
            "adjudication_callable": _callable_identity(self.adjudicator),
            "triage_config": stage_config(self.triage),
            "adjudication_config": stage_config(self.adjudicator),
            "settings": self.user_config,
        }

    @staticmethod
    def _initial_counters(existing: Mapping[str, Any] | None = None) -> dict[str, Any]:
        counters: dict[str, Any] = {
            "planned_commits": 0,
            "extracted_commits": 0,
            "extraction_errors": 0,
            "triage_calls": 0,
            "adjudication_calls": 0,
            "model_calls": 0,
            "tokens": 0,
            "estimated_cost": 0.0,
            "candidates": 0,
            "findings": 0,
            "errors": 0,
            "reused_triage": 0,
            "reused_adjudication": 0,
            "wall_seconds": 0.0,
        }
        if existing:
            for key in counters:
                if key in existing:
                    counters[key] = existing[key]
        # Reuse counts describe this invocation, not lifetime call usage.
        counters["reused_triage"] = 0
        counters["reused_adjudication"] = 0
        return counters

    def _elapsed(
        self,
        counters_at_start: Mapping[str, Any],
        started: float,
    ) -> float:
        previous = float(counters_at_start.get("wall_seconds") or 0.0)
        return previous + max(self.clock() - started, 0.0)

    def _budget_reason(
        self,
        counters: Mapping[str, Any],
        *,
        elapsed: float,
    ) -> str | None:
        limits = self.limits
        if limits.max_wall_seconds is not None and elapsed >= limits.max_wall_seconds:
            return "max_wall_seconds"
        if limits.max_calls is not None and counters["model_calls"] >= limits.max_calls:
            return "max_calls"
        if limits.max_tokens is not None and counters["tokens"] >= limits.max_tokens:
            return "max_tokens"
        if limits.max_cost is not None and counters["estimated_cost"] >= limits.max_cost:
            return "max_cost"
        return None

    def _persist_counters(
        self,
        run_id: str,
        counters: dict[str, Any],
        counters_at_start: Mapping[str, Any],
        started: float,
    ) -> None:
        counters["wall_seconds"] = round(self._elapsed(counters_at_start, started), 6)
        self.store.update_run(run_id, counters=counters)

    def _run_batch(
        self,
        calls: list[Callable[[], _StageOutcome]],
    ) -> list[_StageOutcome]:
        if self.max_workers == 1 or len(calls) == 1:
            return [call() for call in calls]
        with ThreadPoolExecutor(
            max_workers=min(self.max_workers, len(calls)),
            thread_name_prefix="strata-model",
        ) as executor:
            futures: list[Future[_StageOutcome]] = [executor.submit(call) for call in calls]
            # Preserve commit order even if calls finish out of order.
            return [future.result() for future in futures]

    def _available_call_slots(self, counters: Mapping[str, Any]) -> int:
        """Concurrency for the next batch, bounded by *every* remaining budget.

        ``max_calls`` is exact. ``max_tokens`` and ``max_cost`` are not knowable
        before the call, so they are projected from the mean spend so far and
        the batch is narrowed as the ceiling approaches. Checking budgets only
        between batches let ``--max-cost 10 --parallel 8`` spend roughly $80:
        eight workers each cleared the same pre-batch check. Overshoot is now
        bounded by one in-flight call per budget rather than by ``max_workers``.
        """
        slots = self.max_workers
        calls = int(counters["model_calls"])

        if self.limits.max_calls is not None:
            slots = min(slots, self.limits.max_calls - calls)

        def project(spent: float, ceiling: float | None) -> int:
            if ceiling is None:
                return slots
            remaining = ceiling - spent
            if remaining <= 0:
                return 0
            if calls <= 0:
                # No observation yet: admit a single call to measure with.
                return 1
            mean = spent / calls
            if mean <= 0:
                return slots
            return max(1, int(remaining // mean))

        slots = min(slots, project(float(counters["tokens"]), self.limits.max_tokens))
        slots = min(slots, project(float(counters["estimated_cost"]), self.limits.max_cost))
        return max(slots, 0)

    def import_repository(
        self,
        repository: str | Path | GitRepository,
        *,
        last: int | None = None,
        since: str | None = None,
        revision_range: str | None = None,
        dry_run: bool = False,
        resume_run_id: str | None = None,
    ) -> ImportSummary:
        operation_started = self.clock()
        if not dry_run and self.triage is None:
            raise ValueError("a triage callable is required")
        if not dry_run and self.adjudicator is None:
            raise ValueError("an adjudication callable is required")
        resume_record = self.store.get_run(resume_run_id) if resume_run_id is not None else None
        if resume_run_id is not None and resume_record is None:
            raise KeyError(f"unknown run: {resume_run_id}")

        git_repository = (
            repository
            if isinstance(repository, GitRepository)
            else self.repository_factory(repository, cache_root=self.cache_root)
        )
        snapshot = git_repository.fetch()
        repository_id = self.store.register_repository(
            source=snapshot.source,
            canonical_source=snapshot.canonical_source,
            repository_hash=snapshot.repository_hash,
            mirror_path=snapshot.mirror_path,
        )
        snapshot_id = self.store.create_snapshot(
            repository_id,
            head_sha=snapshot.head_sha,
            default_branch=snapshot.default_branch,
        )
        active_head_sha = snapshot.head_sha

        pipeline_config = self._pipeline_config()
        pipeline_config_hash = config_hash(pipeline_config)
        request = {
            "last": last,
            "since": since,
            "revision_range": revision_range,
            "limits": self.limits.to_dict(),
        }
        request_hash = config_hash(request)
        if resume_record is not None:
            if str(resume_record["canonical_source"]) != snapshot.canonical_source:
                raise ValueError("resume run belongs to a different repository")
            if int(resume_record["repository_id"]) != repository_id:
                raise ValueError("resume run repository identity changed")
            if bool(resume_record["dry_run"]) != dry_run:
                raise ValueError("resume run dry-run mode does not match")
            if str(resume_record["config_hash"]) != pipeline_config_hash:
                raise ValueError("resume run pipeline configuration does not match")
            if str(resume_record["request_hash"]) != request_hash:
                raise ValueError("resume run selection or limits do not match")
            # Resume the immutable old snapshot even when fetch discovered a new
            # default-branch head in the meantime.
            snapshot_id = int(resume_record["snapshot_id"])
            active_head_sha = str(resume_record["head_sha"])
        run_id, created = self.store.create_or_resume_run(
            repository_id,
            snapshot_id,
            config_hash=pipeline_config_hash,
            config=pipeline_config,
            request_hash=request_hash,
            request=request,
            limits=self.limits.to_dict(),
            dry_run=dry_run,
        )
        if resume_run_id is not None and run_id != resume_run_id:
            raise ValueError(
                f"run {resume_run_id} does not match this repository, head, and request"
            )
        run = self.store.get_run(run_id)
        assert run is not None
        if not created and run["status"] in {
            "completed",
            "dry_run",
        }:
            return ImportSummary(
                run_id=run_id,
                status=str(run["status"]),
                repository_id=repository_id,
                snapshot_id=snapshot_id,
                head_sha=active_head_sha,
                planned_commits=int((run.get("counters") or {}).get("planned_commits") or 0),
                counters=dict(run.get("counters") or {}),
                dry_run=dry_run,
            )
        if not created:
            self.store.update_run(run_id, status="running")

        effective_last = last
        if self.limits.max_commits is not None:
            effective_last = (
                self.limits.max_commits
                if effective_last is None
                else min(effective_last, self.limits.max_commits)
            )
        if effective_last == 0:
            shas: list[str] = []
        else:
            shas = git_repository.enumerate_shas(
                last=effective_last,
                since=since,
                revision_range=revision_range,
                revision=active_head_sha if revision_range is None else None,
            )

        counters_at_start = dict(run.get("counters") or {})
        counters = self._initial_counters(counters_at_start)
        counters["planned_commits"] = len(shas)
        started = operation_started
        self._persist_counters(run_id, counters, counters_at_start, started)

        if dry_run:
            counters["wall_seconds"] = round(self._elapsed(counters_at_start, started), 6)
            self.store.update_run(
                run_id,
                status="dry_run",
                counters=counters,
                completed=True,
            )
            return ImportSummary(
                run_id=run_id,
                status="dry_run",
                repository_id=repository_id,
                snapshot_id=snapshot_id,
                head_sha=active_head_sha,
                planned_commits=len(shas),
                counters=counters,
                dry_run=True,
            )

        states: list[_CommitState] = []
        extraction_errors = 0
        try:
            for position, sha in enumerate(shas):
                try:
                    commit = git_repository.get_commit(sha)
                    patch_blob_hash = self.store.put_blob(commit.patch)
                    commit_id = self.store.upsert_commit(
                        repository_id,
                        commit,
                        patch_blob_hash=patch_blob_hash,
                    )
                    payload = {
                        "repository": snapshot.canonical_source,
                        "repo": snapshot.canonical_source,
                        "snapshot_head": active_head_sha,
                        **commit.to_dict(include_patch=True),
                        "commit_sha": commit.sha,
                        "first_parent_sha": commit.parent_sha,
                        "subject": commit.message.splitlines()[0] if commit.message else "",
                        "diff": commit.patch_text,
                        "raw_diff": commit.patch_text,
                        "patch_blob_hash": patch_blob_hash,
                    }
                    input_blob_hash = self.store.put_blob(canonical_json(payload))
                    state = _CommitState(
                        position=position,
                        commit=commit,
                        commit_id=commit_id,
                        patch_blob_hash=patch_blob_hash,
                        payload=payload,
                        input_blob_hash=input_blob_hash,
                    )
                    states.append(state)
                    self.store.checkpoint_commit(
                        run_id,
                        commit_id,
                        position=position,
                        status="extracted",
                    )
                except Exception as exc:
                    extraction_errors += 1
                    error = _error_payload(exc)
                    self.store.record_error(
                        stage="extraction",
                        repository_id=repository_id,
                        run_id=run_id,
                        config_hash=pipeline_config_hash,
                        kind=error["kind"],
                        message=error["message"],
                        details={"sha": sha, "position": position},
                    )
            counters["extracted_commits"] = len(states)
            counters["extraction_errors"] = extraction_errors
            counters["errors"] = extraction_errors
            self._persist_counters(run_id, counters, counters_at_start, started)

            missing_triage: list[_CommitState] = []
            for state in states:
                result = self.store.get_triage_result(
                    repository_id, state.commit_id, pipeline_config_hash
                )
                if result is None:
                    missing_triage.append(state)
                    continue
                state.triage = result
                counters["reused_triage"] += 1
                self.store.checkpoint_commit(
                    run_id,
                    state.commit_id,
                    position=state.position,
                    status="triaged",
                    triage_status=result["verdict"],
                )

            budget_reason: str | None = None
            while missing_triage:
                elapsed = self._elapsed(counters_at_start, started)
                budget_reason = self._budget_reason(counters, elapsed=elapsed)
                slots = self._available_call_slots(counters)
                if budget_reason is not None or slots == 0:
                    budget_reason = budget_reason or "max_calls"
                    break
                batch = missing_triage[:slots]
                del missing_triage[:slots]
                assert self.triage is not None
                outcomes = self._run_batch(
                    [
                        lambda state=state: _invoke_triage(self.triage, state.payload)
                        for state in batch
                    ]
                )
                for state, outcome in zip(batch, outcomes, strict=True):
                    counters["triage_calls"] += 1
                    counters["model_calls"] += 1
                    tokens, cost = _usage_totals(outcome.usage)
                    counters["tokens"] += tokens
                    counters["estimated_cost"] = round(
                        float(counters["estimated_cost"]) + cost, 12
                    )
                    if outcome.error is not None:
                        counters["errors"] += 1
                        self.store.record_error(
                            stage="triage",
                            repository_id=repository_id,
                            commit_id=state.commit_id,
                            run_id=run_id,
                            config_hash=pipeline_config_hash,
                            kind=str(outcome.error.get("kind") or "triage_error"),
                            message=str(outcome.error.get("message") or "")[:4096],
                            details={"sha": state.commit.sha},
                        )
                    state.triage = self.store.save_triage_result(
                        repository_id=repository_id,
                        commit_id=state.commit_id,
                        run_id=run_id,
                        config_hash=pipeline_config_hash,
                        verdict=outcome.verdict,
                        result=outcome.result,
                        usage=outcome.usage,
                        input_blob_hash=state.input_blob_hash,
                        error=outcome.error,
                    )
                    self.store.checkpoint_commit(
                        run_id,
                        state.commit_id,
                        position=state.position,
                        status="triaged",
                        triage_status=outcome.verdict,
                    )
                    self._persist_counters(run_id, counters, counters_at_start, started)

            candidates = [
                state
                for state in states
                if state.triage is not None
                and str(state.triage["verdict"]).upper() in _TRIAGE_CANDIDATES
            ]
            counters["candidates"] = len(candidates)
            missing_adjudication: list[_CommitState] = []
            for state in candidates:
                result = self.store.get_adjudication_result(
                    repository_id, state.commit_id, pipeline_config_hash
                )
                if result is None:
                    missing_adjudication.append(state)
                    continue
                state.adjudication = result
                counters["reused_adjudication"] += 1
                self.store.checkpoint_commit(
                    run_id,
                    state.commit_id,
                    position=state.position,
                    status="adjudicated",
                    triage_status=state.triage["verdict"],
                    adjudication_status=result["verdict"],
                )

            while missing_adjudication and not missing_triage:
                elapsed = self._elapsed(counters_at_start, started)
                budget_reason = self._budget_reason(counters, elapsed=elapsed)
                slots = self._available_call_slots(counters)
                if self.limits.max_candidates is not None:
                    candidate_slots = (
                        self.limits.max_candidates - counters["adjudication_calls"]
                    )
                    if candidate_slots <= 0:
                        budget_reason = budget_reason or "max_candidates"
                        break
                    slots = min(slots, candidate_slots)
                if budget_reason is not None or slots == 0:
                    budget_reason = budget_reason or "max_calls"
                    break
                batch = missing_adjudication[:slots]
                del missing_adjudication[:slots]
                assert self.adjudicator is not None
                calls: list[Callable[[], _StageOutcome]] = []
                for state in batch:
                    adjudication_payload = dict(state.payload)
                    assert state.triage is not None
                    adjudication_payload["triage"] = state.triage["result"]
                    calls.append(
                        lambda payload=adjudication_payload: _invoke_adjudication(
                            self.adjudicator,
                            payload,
                            git_repository,
                        )
                    )
                outcomes = self._run_batch(calls)
                for state, outcome in zip(batch, outcomes, strict=True):
                    counters["adjudication_calls"] += 1
                    counters["model_calls"] += 1
                    tokens, cost = _usage_totals(outcome.usage)
                    counters["tokens"] += tokens
                    counters["estimated_cost"] = round(
                        float(counters["estimated_cost"]) + cost, 12
                    )
                    if outcome.error is not None:
                        counters["errors"] += 1
                        self.store.record_error(
                            stage="adjudication",
                            repository_id=repository_id,
                            commit_id=state.commit_id,
                            run_id=run_id,
                            config_hash=pipeline_config_hash,
                            kind=str(outcome.error.get("kind") or "adjudication_error"),
                            message=str(outcome.error.get("message") or "")[:4096],
                            details={"sha": state.commit.sha},
                        )
                    finding_value = outcome.result.get("finding")
                    finding = (
                        dict(finding_value)
                        if isinstance(finding_value, Mapping)
                        else dict(outcome.result)
                        if outcome.verdict == "YES"
                        else None
                    )
                    state.adjudication = self.store.save_adjudication_result(
                        repository_id=repository_id,
                        commit_id=state.commit_id,
                        run_id=run_id,
                        config_hash=pipeline_config_hash,
                        verdict=outcome.verdict,
                        result=outcome.result,
                        usage=outcome.usage,
                        input_blob_hash=state.input_blob_hash,
                        error=outcome.error,
                        finding=finding,
                    )
                    if outcome.verdict == "YES":
                        counters["findings"] += 1
                    self.store.checkpoint_commit(
                        run_id,
                        state.commit_id,
                        position=state.position,
                        status="adjudicated",
                        triage_status=state.triage["verdict"],
                        adjudication_status=outcome.verdict,
                    )
                    self._persist_counters(run_id, counters, counters_at_start, started)

            counters["findings"] = sum(
                1
                for state in states
                if state.adjudication is not None and state.adjudication["verdict"] == "YES"
            )
            counters["errors"] = extraction_errors + sum(
                1
                for state in states
                for result in (state.triage, state.adjudication)
                if result is not None and result.get("error") is not None
            )
            if missing_triage or missing_adjudication:
                status = "budget_exhausted"
                budget_reason = budget_reason or "budget"
            elif (
                any(
                    state.adjudication is not None and state.adjudication["verdict"] == "ERROR"
                    for state in states
                )
                or extraction_errors
            ):
                status = "completed_with_errors"
            else:
                status = "completed"
            counters["wall_seconds"] = round(self._elapsed(counters_at_start, started), 6)
            self.store.update_run(
                run_id,
                status=status,
                counters=counters,
                error={"kind": "budget_exhausted", "reason": budget_reason}
                if status == "budget_exhausted"
                else None,
                completed=status != "running",
            )
            return ImportSummary(
                run_id=run_id,
                status=status,
                repository_id=repository_id,
                snapshot_id=snapshot_id,
                head_sha=active_head_sha,
                planned_commits=len(shas),
                counters=counters,
                budget_reason=budget_reason,
                dry_run=False,
            )
        except BaseException as exc:
            counters["wall_seconds"] = round(self._elapsed(counters_at_start, started), 6)
            self.store.update_run(
                run_id,
                status="interrupted",
                counters=counters,
                error=_error_payload(exc),
            )
            raise

    run = import_repository

    def resume(self, run_id: str) -> ImportSummary:
        run = self.store.get_run(run_id)
        if run is None:
            raise KeyError(f"unknown run: {run_id}")
        request = run.get("request") or {}
        return self.import_repository(
            str(run["repository_source"]),
            last=request.get("last"),
            since=request.get("since"),
            revision_range=request.get("revision_range"),
            dry_run=bool(run["dry_run"]),
            resume_run_id=run_id,
        )


RepositoryImporter = Importer


def import_repository(
    repository: str | Path | GitRepository,
    *,
    store: Store,
    triage: TriageCallable,
    adjudicator: AdjudicationCallable | Callable[..., Any],
    last: int | None = None,
    since: str | None = None,
    revision_range: str | None = None,
    dry_run: bool = False,
    limits: ImportLimits | None = None,
    max_workers: int = 1,
    config: Mapping[str, Any] | None = None,
) -> ImportSummary:
    """Convenience wrapper for a one-shot import."""
    return Importer(
        store,
        triage=triage,
        adjudicator=adjudicator,
        limits=limits,
        max_workers=max_workers,
        config=config,
    ).import_repository(
        repository,
        last=last,
        since=since,
        revision_range=revision_range,
        dry_run=dry_run,
    )
