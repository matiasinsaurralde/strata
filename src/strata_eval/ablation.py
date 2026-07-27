"""Run and report the controlled D0-D3 pass-1 development ablation."""

from __future__ import annotations

import argparse
import json
import logging
import os
import random
import tempfile
import threading
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from strata.contracts import (
    InputProfile,
    ProviderSettingsV1,
    TriageDecisionV1,
    canonical_hash,
)
from strata.diffing import InputLimits, build_input_profile
from strata.llm import LLMConfig, OpenAIChatClient, TokenWindowRateLimiter
from strata.triage import (
    ModelPricing,
    OpenAICompatibleTriageBackend,
    TriageRunner,
)

from .metrics import (
    alerts_per_1000,
    candidate_disagreement_sets,
    candidate_rate_at_prevalence,
    expected_cascade_cost,
    per_stratum_summaries,
    precision_at_prevalence,
    precision_interval_at_prevalence,
    summarize_binary,
)

DEFAULT_PREVALENCES = (0.002, 0.015, 0.05)
LEGACY_MAX_INPUT_BYTES = 200_000
LOGGER = logging.getLogger(__name__)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as source:
        for line_number, raw in enumerate(source, start=1):
            if not raw.strip():
                continue
            value = json.loads(raw)
            if not isinstance(value, Mapping):
                raise ValueError(f"{path}:{line_number}: row is not an object")
            rows.append(dict(value))
    return rows


def _key(row: Mapping[str, Any]) -> tuple[str, str, str]:
    return (
        str(row.get("host") or ""),
        str(row.get("repo") or row.get("repository") or ""),
        str(row.get("sha") or row.get("commit_sha") or "").lower(),
    )


def load_development_rows(
    bundle_dir: Path,
    labels_path: Path,
) -> list[dict[str, Any]]:
    """Join the latest role label to each unique enriched commit."""

    latest_labels = {_key(row): row for row in read_jsonl(labels_path)}
    unique: dict[tuple[str, str, str], dict[str, Any]] = {}
    for source in read_jsonl(bundle_dir / "commits.jsonl"):
        key = _key(source)
        if not all(key):
            continue
        existing = unique.get(key)
        if existing is None or (
            not existing.get("resolved_sha") and source.get("resolved_sha")
        ):
            unique[key] = source

    rows: list[dict[str, Any]] = []
    for key in sorted(unique):
        source = unique[key]
        label = latest_labels.get(key, {})
        role = str(label.get("role") or source.get("role") or "").lower()
        if not role:
            continue
        diff_path_value = source.get("diff_path")
        diff_path = (
            bundle_dir / str(diff_path_value)
            if diff_path_value
            else bundle_dir / "diffs" / key[0] / key[1] / f"{key[2]}.diff"
        )
        diff = diff_path.read_text(encoding="utf-8", errors="replace")
        parents = source.get("parents")
        parent_sha = None
        if isinstance(parents, Sequence) and not isinstance(parents, (str, bytes)):
            first = parents[0] if parents else None
            parent_sha = (
                str(first.get("sha"))
                if isinstance(first, Mapping) and first.get("sha")
                else str(first)
                if first
                else None
            )
        message = str(source.get("message") or "")
        subject = str(source.get("subject") or "")
        repository = f"{key[0]}/{key[1]}"
        rows.append(
            {
                "id": f"{repository}@{key[2]}",
                "repository": repository,
                "host": key[0],
                "repo": key[1],
                "commit_sha": key[2],
                "parent_sha": parent_sha.lower() if parent_sha else None,
                "subject": subject or (message.splitlines()[0] if message else ""),
                "message": message,
                "message_class": str(
                    source.get("message_class") or source.get("msg_class") or "unknown"
                ),
                "role": role,
                "diff": diff,
            }
        )
    return rows


@dataclass(frozen=True, slots=True)
class AblationSettings:
    max_input_bytes: int = InputLimits().max_input_bytes
    workers: int = 4
    adjudicator_token_equivalent: float = 20_000.0
    adjudicator_cost_usd: float | None = None
    tokens_per_minute: int | None = None
    rate_limit_headroom: float = 0.9


class DecisionCache:
    def __init__(self, root: Path) -> None:
        self.root = root
        self._lock = threading.Lock()

    def _path(self, key: str) -> Path:
        digest = key.removeprefix("sha256:")
        return self.root / digest[:2] / f"{digest[2:]}.json"

    def get(self, key: str) -> TriageDecisionV1 | None:
        path = self._path(key)
        if not path.is_file():
            return None
        decision = TriageDecisionV1.from_dict(json.loads(path.read_text(encoding="utf-8")))
        if not _cacheable_decision(decision):
            return None
        return replace(
            decision,
            provenance=replace(decision.provenance, cache_hit=True),
        )

    def put(self, key: str, decision: TriageDecisionV1) -> None:
        if not _cacheable_decision(decision):
            return
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{path.name}-", dir=path.parent
            )
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                    json.dump(
                        decision.to_dict(),
                        output,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    output.write("\n")
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(temporary_name, path)
            finally:
                try:
                    os.unlink(temporary_name)
                except FileNotFoundError:
                    pass


def _cacheable_decision(decision: TriageDecisionV1) -> bool:
    return (
        decision.parser_status.value != "backend_error"
        and not (decision.error is not None and decision.error.retryable)
        and all(chunk.parser_status.value != "backend_error" for chunk in decision.chunks)
    )


def _matches_input(decision: TriageDecisionV1, triage_input: Any) -> bool:
    return (
        decision.input_profile is triage_input.profile
        and decision.raw_input_hash == triage_input.raw_diff_hash
        and decision.input_hash == triage_input.input_hash
        and tuple(chunk.input_hash for chunk in decision.chunks)
        == tuple(chunk.input_hash for chunk in triage_input.chunks)
    )


def _decision_cache_key(
    row: Mapping[str, Any],
    profile: InputProfile,
    runner: TriageRunner,
    limits: InputLimits,
) -> str:
    return canonical_hash(
        {
            "repository": row["repository"],
            "commit_sha": row["commit_sha"],
            "profile": profile.value,
            "diff": row["diff"],
            "subject": row["subject"],
            "message": row["message"],
            "limits": {
                "max_input_bytes": limits.max_input_bytes,
                "max_subject_bytes": limits.max_subject_bytes,
                "max_message_bytes": limits.max_message_bytes,
            },
            "provider": runner.provider.to_dict(),
            "prompt_hash": runner.prompt.prompt_hash,
            "schema_hash": runner.schema_hash,
        }
    )


def run_profile(
    rows: Sequence[Mapping[str, Any]],
    profile: InputProfile,
    runner: TriageRunner,
    *,
    cache: DecisionCache | None = None,
    limits: InputLimits | None = None,
    workers: int = 4,
) -> list[TriageDecisionV1]:
    limits = limits or InputLimits()

    def classify(row: Mapping[str, Any]) -> TriageDecisionV1:
        triage_input = build_input_profile(
            profile,
            str(row["diff"]),
            subject=str(row.get("subject") or ""),
            message=str(row.get("message") or ""),
            limits=limits,
        )
        key = _decision_cache_key(row, profile, runner, limits)
        if cache is not None and (cached := cache.get(key)) is not None:
            LOGGER.debug(
                "cache hit profile=%s commit=%s status=%s verdict=%s",
                profile.value,
                row["id"],
                cached.parser_status.value,
                cached.verdict.value if cached.verdict is not None else "-",
            )
            return cached
        if cache is not None and limits.max_input_bytes != LEGACY_MAX_INPUT_BYTES:
            legacy_limits = replace(limits, max_input_bytes=LEGACY_MAX_INPUT_BYTES)
            legacy_key = _decision_cache_key(row, profile, runner, legacy_limits)
            legacy = cache.get(legacy_key)
            if legacy is not None and _matches_input(legacy, triage_input):
                cache.put(key, legacy)
                LOGGER.debug(
                    "cache migrated profile=%s commit=%s from_max_input_bytes=%d",
                    profile.value,
                    row["id"],
                    LEGACY_MAX_INPUT_BYTES,
                )
                return legacy
        LOGGER.info(
            "triage start profile=%s commit=%s diff_bytes=%d",
            profile.value,
            row["id"],
            len(str(row["diff"]).encode("utf-8")),
        )
        decision = runner.run(
            triage_input,
            repository=str(row["repository"]),
            commit_sha=str(row["commit_sha"]),
            parent_sha=(str(row["parent_sha"]) if row.get("parent_sha") is not None else None),
        )
        if cache is not None:
            cache.put(key, decision)
        malformed_outputs = [
            repr((chunk.raw_output or "")[:160])
            for chunk in decision.chunks
            if chunk.parser_status.value == "malformed"
        ]
        LOGGER.info(
            "triage complete profile=%s commit=%s status=%s verdict=%s "
            "chunks=%d latency_ms=%d retries=%d error_kind=%s error=%s "
            "malformed_outputs=%s",
            profile.value,
            row["id"],
            decision.parser_status.value,
            decision.verdict.value if decision.verdict is not None else "-",
            len(decision.chunks),
            decision.latency_ms,
            decision.provenance.retry_count,
            decision.error.kind.value if decision.error is not None else "-",
            decision.error.message if decision.error is not None else "-",
            malformed_outputs or "-",
        )
        return decision

    LOGGER.info(
        "profile start profile=%s rows=%d workers=%d max_input_bytes=%d",
        profile.value,
        len(rows),
        workers,
        limits.max_input_bytes,
    )
    if workers <= 1:
        decisions = [classify(row) for row in rows]
    else:
        with ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="strata-triage"
        ) as pool:
            decisions = list(pool.map(classify, rows))
    LOGGER.info("profile complete profile=%s rows=%d", profile.value, len(decisions))
    return decisions


def _quantile(values: list[float], probability: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = round((len(ordered) - 1) * probability)
    return ordered[index]


def repository_block_bootstrap(
    scored_rows: Sequence[Mapping[str, Any]],
    *,
    samples: int = 2_000,
    seed: int = 7,
) -> dict[str, list[float | None]]:
    """Percentile intervals from repository-block resampling."""

    groups: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in scored_rows:
        groups[str(row["repository"])].append(row)
    names = sorted(groups)
    if not names or samples < 1:
        return {"recall": [None, None], "false_positive_rate": [None, None]}
    rng = random.Random(seed)
    recalls: list[float] = []
    fprs: list[float] = []
    for _ in range(samples):
        sampled = [row for _ in names for row in groups[rng.choice(names)]]
        summary = summarize_binary(sampled)
        if summary.recall is not None:
            recalls.append(summary.recall)
        if summary.false_positive_rate is not None:
            fprs.append(summary.false_positive_rate)
    return {
        "recall": [_quantile(recalls, 0.025), _quantile(recalls, 0.975)],
        "false_positive_rate": [_quantile(fprs, 0.025), _quantile(fprs, 0.975)],
    }


def summarize_profile(
    rows: Sequence[Mapping[str, Any]],
    decisions: Sequence[TriageDecisionV1],
    *,
    prevalences: Iterable[float] = DEFAULT_PREVALENCES,
    adjudicator_token_equivalent: float = 20_000.0,
    adjudicator_cost_usd: float | None = None,
) -> dict[str, Any]:
    if len(rows) != len(decisions):
        raise ValueError("rows and decisions must have equal length")
    scored = []
    candidates: list[str] = []
    total_input_tokens = 0
    total_output_tokens = 0
    total_tokens = 0
    total_cost: float | None = 0.0
    model_calls = 0
    retries = 0
    parser_statuses: dict[str, int] = defaultdict(int)
    error_kinds: dict[str, int] = defaultdict(int)
    for row, decision in zip(rows, decisions, strict=True):
        parser_statuses[decision.parser_status.value] += 1
        if decision.error is not None:
            error_kinds[decision.error.kind.value] += 1
        prediction = decision.verdict.value if decision.verdict is not None else None
        scored_row = {
            "id": row["id"],
            "repository": row["repository"],
            "truth": row["role"],
            "prediction": prediction,
            "message_class": row["message_class"],
        }
        scored.append(scored_row)
        if prediction == "YES":
            candidates.append(str(row["id"]))
        total_input_tokens += decision.usage.input_tokens or 0
        total_output_tokens += decision.usage.output_tokens or 0
        total_tokens += decision.usage.total_tokens or 0
        model_calls += len(decision.chunks)
        retries += decision.provenance.retry_count
        if decision.usage.estimated_cost_usd is None:
            total_cost = None
        elif total_cost is not None:
            total_cost += decision.usage.estimated_cost_usd

    overall = summarize_binary(scored)
    strata = per_stratum_summaries(scored, "message_class")
    quiet = strata.get("quiet")
    eligible = overall.eligible
    # Divide by rows that actually produced a call, not by rows that were
    # merely eligible: an errored row contributes no tokens, so the old mean
    # made a profile that failed more often look cheaper *and* — through the
    # uncorrected FPR below — more precise. That combination is what let the
    # fully-failed gpt-5.4 D3 arm rank best on the cost objective.
    evaluated = overall.evaluated
    mean_tokens = total_tokens / evaluated if evaluated else 0.0
    operational: dict[str, Any] = {}

    # Operational figures use the *coverage-corrected* FPR. Dividing false
    # positives by all negatives, including ones the backend never scored,
    # biases the rate toward zero — optimistic, which is the dangerous
    # direction for a precision estimate.
    operating_fpr = overall.false_positive_rate_covered
    if overall.recall is not None and operating_fpr is not None and overall.coverage > 0:
        for prevalence in prevalences:
            rate = candidate_rate_at_prevalence(overall.recall, operating_fpr, prevalence)
            precision_bounds = (
                precision_interval_at_prevalence(
                    overall.recall_interval,
                    overall.false_positive_rate_covered_interval,
                    prevalence,
                )
                if overall.recall_interval and overall.false_positive_rate_covered_interval
                else (None, None, None)
            )
            operational[str(prevalence)] = {
                "precision": precision_at_prevalence(overall.recall, operating_fpr, prevalence),
                # A point estimate built from two interval-valued inputs is how
                # "P@1.5% = 0.082" acquired three significant figures it never
                # had. The envelope ships alongside it.
                "precision_interval_95": {
                    "lower": precision_bounds[0],
                    "point": precision_bounds[1],
                    "upper": precision_bounds[2],
                },
                "alerts_per_1000": alerts_per_1000(overall.recall, operating_fpr, prevalence),
                "candidate_rate": rate,
                "relative_token_cost_per_commit": (
                    mean_tokens + rate * adjudicator_token_equivalent
                ),
                "estimated_cost_usd_per_commit": (
                    expected_cascade_cost(
                        triage_cost_per_commit=(total_cost / evaluated),
                        adjudicator_cost_per_candidate=adjudicator_cost_usd,
                        candidate_rate=rate,
                    )
                    if total_cost is not None and evaluated and adjudicator_cost_usd is not None
                    else None
                ),
            }
    quiet_recall = quiet.recall if quiet is not None else None
    qualifies = (
        overall.recall is not None
        and overall.recall >= 0.95
        and quiet_recall is not None
        and quiet_recall >= 0.90
        and overall.unevaluated == 0
    )
    return {
        "profile": decisions[0].input_profile.value if decisions else None,
        "metrics": overall.to_dict(),
        "strata": {str(key): value.to_dict() for key, value in strata.items()},
        "repository_block_bootstrap_95": repository_block_bootstrap(scored),
        "usage": {
            "model_calls": model_calls,
            "input_tokens": total_input_tokens,
            "output_tokens": total_output_tokens,
            "total_tokens": total_tokens,
            "mean_tokens_per_evaluated_commit": mean_tokens,
            "estimated_cost_usd": total_cost,
            "retries": retries,
        },
        "outcomes": {
            "parser_statuses": dict(sorted(parser_statuses.items())),
            "error_kinds": dict(sorted(error_kinds.items())),
        },
        "operational": operational,
        "candidate_ids": sorted(candidates),
        "gate": {
            "overall_recall_at_least_0_95": bool(
                overall.recall is not None and overall.recall >= 0.95
            ),
            "quiet_recall_at_least_0_90": bool(
                quiet_recall is not None and quiet_recall >= 0.90
            ),
            "no_silent_input_failures": overall.unevaluated == 0,
            "qualifies": qualifies,
        },
    }


def build_matrix_report(
    rows: Sequence[Mapping[str, Any]],
    decisions_by_profile: Mapping[str, Sequence[TriageDecisionV1]],
    *,
    settings: AblationSettings,
) -> dict[str, Any]:
    profiles = {
        name: summarize_profile(
            rows,
            decisions,
            adjudicator_token_equivalent=settings.adjudicator_token_equivalent,
            adjudicator_cost_usd=settings.adjudicator_cost_usd,
        )
        for name, decisions in sorted(decisions_by_profile.items())
    }
    qualifying = [result for result in profiles.values() if result["gate"]["qualifies"]]

    def relative_cost(result: Mapping[str, Any]) -> float:
        value = result["operational"].get("0.015", {}).get("relative_token_cost_per_commit")
        return float(value) if value is not None else float("inf")

    selected = min(qualifying, key=relative_cost)["profile"] if qualifying else None
    fallback = None
    if profiles:
        fallback = max(
            profiles.values(),
            key=lambda result: (
                result["metrics"]["recall"] or -1.0,
                result["strata"].get("quiet", {}).get("recall") or -1.0,
                result["metrics"]["coverage"],
                -relative_cost(result),
            ),
        )["profile"]
    candidates = {name: result["candidate_ids"] for name, result in profiles.items()}
    return {
        "schema_version": "triage-ablation-report-v1",
        "development_only": True,
        "rows": len(rows),
        "settings": {
            "max_input_bytes": settings.max_input_bytes,
            "workers": settings.workers,
            "adjudicator_token_equivalent": settings.adjudicator_token_equivalent,
            "adjudicator_cost_usd": settings.adjudicator_cost_usd,
            "tokens_per_minute": settings.tokens_per_minute,
            "rate_limit_headroom": settings.rate_limit_headroom,
        },
        "profiles": profiles,
        "candidate_disagreements": candidate_disagreement_sets(candidates),
        "selected_profile": selected,
        "best_development_fallback": fallback,
        "freeze_allowed": selected is not None,
        "selection_note": (
            "Lowest expected cascade cost among profiles meeting all gates."
            if selected is not None
            else "No profile met all gates; fallback is diagnostic and must not be frozen."
        ),
    }


def _load_dotenv(path: Path = Path(".env")) -> None:
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


def _configure_logging(verbosity: int, log_file: Path | None) -> None:
    level = (
        logging.DEBUG
        if verbosity >= 2
        else logging.INFO
        if verbosity == 1 or log_file is not None
        else logging.WARNING
    )
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    logging.basicConfig(
        level=level,
        format=("%(asctime)s %(levelname)s %(name)s [%(threadName)s] %(message)s"),
        handlers=handlers,
        force=True,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, default=Path("ghsa-commits"))
    parser.add_argument("--labels", type=Path, default=Path("labels.jsonl"))
    parser.add_argument(
        "--profiles",
        nargs="+",
        choices=[profile.value for profile in InputProfile],
        default=[profile.value for profile in InputProfile],
    )
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument(
        "--max-input-bytes",
        type=int,
        default=InputLimits().max_input_bytes,
    )
    parser.add_argument("--cache", type=Path, default=Path(".cache/triage-ablation-v1"))
    parser.add_argument("--out", type=Path, default=Path("results/triage-ablation-v1.json"))
    parser.add_argument("--input-usd-per-million", type=float)
    parser.add_argument("--output-usd-per-million", type=float)
    parser.add_argument(
        "--model",
        help="override OPENAI_MODEL for this ablation",
    )
    parser.add_argument(
        "--max-output-tokens",
        type=int,
        help="bounded completion allowance (default: 32 for GPT-5+, otherwise 3)",
    )
    parser.add_argument(
        "--max-rows",
        type=int,
        help="development smoke-test limit; never eligible for freezing",
    )
    parser.add_argument(
        "--tokens-per-minute",
        type=int,
        help="shared provider TPM limit for token-aware request scheduling",
    )
    parser.add_argument(
        "--rate-limit-headroom",
        type=float,
        default=0.9,
        help="fraction of the TPM limit the local queue may reserve",
    )
    parser.add_argument("--adjudicator-cost-usd", type=float)
    parser.add_argument("--adjudicator-token-equivalent", type=float, default=20_000)
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="show per-commit progress; repeat for cache hits and provider attempts",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        help="also append timestamped diagnostics to this file",
    )
    arguments = parser.parse_args(argv)
    if arguments.workers < 1:
        parser.error("--workers must be positive")
    if arguments.max_output_tokens is not None and arguments.max_output_tokens < 1:
        parser.error("--max-output-tokens must be positive")
    if arguments.max_rows is not None and arguments.max_rows < 1:
        parser.error("--max-rows must be positive")
    if arguments.tokens_per_minute is not None and arguments.tokens_per_minute < 1:
        parser.error("--tokens-per-minute must be positive")
    if not 0 < arguments.rate_limit_headroom <= 1:
        parser.error("--rate-limit-headroom must be in (0, 1]")
    if (arguments.input_usd_per_million is None) != (arguments.output_usd_per_million is None):
        parser.error("provide both input and output pricing, or neither")
    _configure_logging(arguments.verbose, arguments.log_file)
    _load_dotenv()
    config = LLMConfig.from_env()
    if arguments.model:
        config = replace(config, model=arguments.model)
    is_gpt5_plus = config.model.lower().startswith(("gpt-5", "gpt-6"))
    max_output_tokens = arguments.max_output_tokens or (32 if is_gpt5_plus else 3)
    request_parameters = {"reasoning_effort": "none"} if is_gpt5_plus else {}
    pricing = (
        ModelPricing(
            arguments.input_usd_per_million,
            arguments.output_usd_per_million,
        )
        if arguments.input_usd_per_million is not None
        else None
    )
    client = OpenAIChatClient(config)
    rate_limiter = (
        TokenWindowRateLimiter(
            arguments.tokens_per_minute,
            headroom=arguments.rate_limit_headroom,
        )
        if arguments.tokens_per_minute is not None
        else None
    )
    backend = OpenAICompatibleTriageBackend(
        client,
        pricing=pricing,
        max_output_tokens=max_output_tokens,
        request_parameters=request_parameters,
        rate_limiter=rate_limiter,
    )
    decoding = {
        "temperature": 0,
        "max_output_tokens": max_output_tokens,
        **request_parameters,
    }
    runner = TriageRunner(
        backend,
        provider=ProviderSettingsV1(
            provider="openai-compatible",
            model=config.model,
            decoding=decoding,
        ),
    )
    rows = load_development_rows(arguments.bundle, arguments.labels)
    full_row_count = len(rows)
    if arguments.max_rows is not None:
        rows = rows[: arguments.max_rows]
    LOGGER.info(
        "ablation start rows=%d profiles=%s workers=%d cache=%s output=%s",
        len(rows),
        ",".join(arguments.profiles),
        arguments.workers,
        arguments.cache,
        arguments.out,
    )
    limits = InputLimits(max_input_bytes=arguments.max_input_bytes)
    cache = DecisionCache(arguments.cache)
    decisions_by_profile = {
        name: run_profile(
            rows,
            InputProfile(name),
            runner,
            cache=cache,
            limits=limits,
            workers=arguments.workers,
        )
        for name in arguments.profiles
    }
    settings = AblationSettings(
        max_input_bytes=arguments.max_input_bytes,
        workers=arguments.workers,
        adjudicator_token_equivalent=arguments.adjudicator_token_equivalent,
        adjudicator_cost_usd=arguments.adjudicator_cost_usd,
        tokens_per_minute=arguments.tokens_per_minute,
        rate_limit_headroom=arguments.rate_limit_headroom,
    )
    report = build_matrix_report(rows, decisions_by_profile, settings=settings)
    if arguments.max_rows is not None:
        report["smoke_test"] = {
            "rows": len(rows),
            "full_rows": full_row_count,
        }
        report["selected_profile"] = None
        report["freeze_allowed"] = False
        report["selection_note"] = "Smoke-test subsets are never eligible for freezing."
    report["provider"] = runner.provider.to_dict()
    report["prompt"] = {
        "id": runner.prompt.prompt_id,
        "hash": runner.prompt.prompt_hash,
    }
    report["config_hash"] = canonical_hash(
        {
            "settings": report["settings"],
            "provider": report["provider"],
            "prompt": report["prompt"],
            "profiles": arguments.profiles,
        }
    )
    report["decisions"] = {
        name: [decision.to_dict() for decision in decisions]
        for name, decisions in decisions_by_profile.items()
    }
    arguments.out.parent.mkdir(parents=True, exist_ok=True)
    arguments.out.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    LOGGER.info(
        "ablation complete selected_profile=%s fallback=%s freeze_allowed=%s output=%s",
        report["selected_profile"] or "-",
        report["best_development_fallback"] or "-",
        report["freeze_allowed"],
        arguments.out,
    )
    summary = {
        "rows": report["rows"],
        "selected_profile": report["selected_profile"],
        "best_development_fallback": report["best_development_fallback"],
        "freeze_allowed": report["freeze_allowed"],
        "profiles": {
            name: {
                "recall": result["metrics"]["recall"],
                "fpr": result["metrics"]["false_positive_rate"],
                "coverage": result["metrics"]["coverage"],
                "quiet_recall": result["strata"].get("quiet", {}).get("recall"),
                "qualifies": result["gate"]["qualifies"],
            }
            for name, result in report["profiles"].items()
        },
        "out": str(arguments.out),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
