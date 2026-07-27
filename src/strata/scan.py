"""End-to-end repository scan: prefilter → triage → adjudicate → compile.

This wires the full cascade together. Its shape is dictated by base rates: at
~1.5% prevalence a single-stage classifier needs an FPR roughly 10x better than
published SOTA to be usable, so stage 1 is tuned
for recall and stage 2 — which only ever sees the survivors — does the precision
work and can afford 30-100x the per-commit spend.

Three gates sit in front of the model, cheapest first:

1. :mod:`strata.prefilter` — local, free, and the largest cost lever.
2. Triage — one cheap call per admitted commit, recall-first.
3. Adjudication — the tool-using subagent, precision-first, with abstain.

Every stage records what it dropped and why, so the funnel in the report is
reconcilable and a silent failure cannot masquerade as a clean scan.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .adjudicator import Adjudicator, Profile
from .attribution import apply as apply_attribution
from .codex_adjudicator import CodexAdjudicator
from .context import RepoRef, ScanStats, SecurityContext, compile_context, write_narrative
from .contracts import InputProfile, ProviderSettingsV1
from .git_repo import GitCommit, GitRepository
from .llm import LLMOversizeError, ModelPricing, OpenAIChatClient, TokenUsage
from .prefilter import PrefilterStats, prefilter_commit
from .triage import OpenAICompatibleTriageBackend, TriageRunner

LOGGER = logging.getLogger(__name__)

__all__ = ["ScanConfig", "ScanOutcome", "scan_repository"]


@dataclass(frozen=True, slots=True)
class ScanConfig:
    """Knobs for one scan."""

    #: Cap on commits examined; ``None`` walks the full default branch.
    last: int | None = None
    #: Pin the scan to a specific revision instead of current HEAD. Needed for
    #: reproducible head-to-head comparisons: a baseline captured last month
    #: read a different history than today's default branch.
    revision: str | None = None
    #: Stage-1 input profile. D0 (normalised diff only) is production.
    #: Measured on the gin ground-truth set at temperature=0, N=3: D0 caught
    #: 6/10 known fixes with every verdict stable; D3 (message + diff) caught
    #: 4/10 and destabilised a third. A routine-sounding conventional-commit
    #: subject demonstrably suppresses a YES the diff alone produces.
    triage_profile: InputProfile = InputProfile.D0
    #: Reject commits above this many diff bytes before triage.
    max_diff_bytes: int = 400_000
    #: Adjudication profile. A0 hides advisory context; A1 permits linked issues.
    profile: Profile = Profile.A0
    #: Concurrency for both model stages.
    workers: int = 6
    #: Hard ceiling on estimated spend, in USD. ``None`` disables.
    max_cost_usd: float | None = None
    #: Pricing used for the ceiling and for the reported cost.
    pricing: ModelPricing | None = None
    #: Cap on adjudications; useful for bounded pilots.
    max_candidates: int | None = None
    #: Stage-2 backend. ``"chat"`` is the eight-tool JSON adjudicator;
    #: ``"codex"`` runs the same contract inside a sandboxed shell with a real
    #: worktree, which is what lets it answer containment and reachability by
    #: looking rather than by inference. Triage is deliberately not switchable:
    #: it is a one-bit decision over a diff and gains nothing from a shell.
    adjudicator: str = "chat"
    #: Sandbox mode when ``adjudicator="codex"``. Writes unlock semgrep,
    #: ``go vet`` and gopls; ``read-only`` is the production default.
    sandbox: str = "read-only"


@dataclass(slots=True)
class ScanOutcome:
    """A completed scan and everything needed to explain its numbers."""

    context: SecurityContext
    prefilter: PrefilterStats
    triage_yes: list[str] = field(default_factory=list)
    triage_no: list[str] = field(default_factory=list)
    triage_errors: list[tuple[str, str]] = field(default_factory=list)
    adjudication_yes: list[dict[str, Any]] = field(default_factory=list)
    adjudication_no: list[str] = field(default_factory=list)
    adjudication_abstain: list[tuple[str, str]] = field(default_factory=list)
    attribution_moves: list[dict[str, Any]] = field(default_factory=list)
    duplicates_dropped: list[dict[str, Any]] = field(default_factory=list)
    usage: TokenUsage = field(default_factory=TokenUsage)
    cost_usd: float = 0.0
    wall_clock_s: float = 0.0

    def funnel(self) -> dict[str, Any]:
        """The scan as a reconcilable funnel."""
        return {
            "prefilter": self.prefilter.to_dict(),
            "triage": {
                "yes": len(self.triage_yes),
                "no": len(self.triage_no),
                "errors": len(self.triage_errors),
            },
            "attribution": {
                "re_pointed": len(self.attribution_moves),
                "duplicates_collapsed": len(self.duplicates_dropped),
            },
            "adjudication": {
                "yes": len(self.adjudication_yes),
                "no": len(self.adjudication_no),
                "abstain": len(self.adjudication_abstain),
                "abstain_reasons": _counted(r for _, r in self.adjudication_abstain),
            },
            "usage": self.usage.to_dict(),
            "estimated_cost_usd": round(self.cost_usd, 4),
            "wall_clock_s": round(self.wall_clock_s, 1),
        }


def _counted(values: Iterable[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


def _repo_ref(repository: GitRepository, head_sha: str, branch: str) -> RepoRef:
    slug = repository.canonical_source.rstrip("/")
    for suffix in (".git",):
        if slug.endswith(suffix):
            slug = slug[: -len(suffix)]
    parts = [p for p in slug.split("/") if p]
    owner, name = (parts[-2], parts[-1]) if len(parts) >= 2 else ("", slug)
    return RepoRef(
        owner=owner,
        name=name,
        url=repository.canonical_source,
        ref=branch,
        head_sha=head_sha,
    )


def _candidate_from(commit: GitCommit, repository_url: str) -> dict[str, Any]:
    return {
        "repository": repository_url,
        "commit_sha": commit.sha,
        "parent_sha": commit.parent_sha,
        "message": commit.message,
        "diff": commit.patch.decode("utf-8", errors="replace"),
    }


def scan_repository(
    source: str,
    *,
    client: OpenAIChatClient,
    config: ScanConfig | None = None,
    cache_root: str = ".strata/repos",
    progress: Callable[[str], None] | None = None,
) -> ScanOutcome:
    """Scan a repository and compile its security context.

    Args:
        source: Local path or remote URL.
        client: Chat client used by both model stages.
        config: Scan knobs; defaults are suitable for a mid-sized repository.
        cache_root: Where the bare mirror lives.
        progress: Optional callback for human-readable progress lines.

    Returns:
        A :class:`ScanOutcome` whose ``context`` is the compiled artifact.
    """
    settings = config or ScanConfig()
    pricing = settings.pricing or ModelPricing(1.25, 10.0, 0.125)
    say = progress or (lambda _message: None)
    started = time.monotonic()

    repository = GitRepository(source, cache_root=cache_root)
    snapshot = repository.fetch()
    say(f"mirror ready: {snapshot.head_sha[:12]} on {snapshot.default_branch}")

    shas = repository.enumerate_shas(last=settings.last, revision=settings.revision)
    say(f"enumerated {len(shas)} commits")

    # --- stage 0: deterministic prefilter (free) -------------------------
    prefilter = PrefilterStats()
    admitted: list[GitCommit] = []
    for sha in shas:
        try:
            commit = repository.get_commit(sha)
        except Exception as exc:  # a broken object must not abort the scan
            LOGGER.warning("extraction failed for %s: %s", sha[:12], exc)
            continue
        decision = prefilter_commit(
            commit.changed_paths, commit.patch, max_diff_bytes=settings.max_diff_bytes
        )
        prefilter.record(decision)
        if decision.admit:
            admitted.append(commit)
    say(
        f"prefilter admitted {prefilter.admitted}/{prefilter.seen} "
        f"({prefilter.reduction_rate:.1%} rejected, $0)"
    )

    outcome = ScanOutcome(context=None, prefilter=prefilter)  # type: ignore[arg-type]
    usage = TokenUsage()

    # --- stage 1: triage (cheap, recall-first) ---------------------------
    #
    # Production uses D3 (capped commit message + normalised first-party diff).
    # The diff-only profiles exist to *simulate* silent fixes for the eval;
    # withholding a message the reviewer would really have would be measuring
    # the wrong thing here: M0 is always the production configuration.
    runner = TriageRunner(
        OpenAICompatibleTriageBackend(
            client,
            pricing=pricing,
            # Reasoning models spend output tokens before emitting the verdict;
            # a 3-token ceiling truncates them into an unparseable answer.
            max_output_tokens=(256 if client.config.uses_max_completion_tokens else 4),
        ),
        provider=ProviderSettingsV1(provider="openai-compatible", model=client.config.model),
    )
    by_sha = {commit.sha: commit for commit in admitted}

    def triage_one(commit: GitCommit) -> tuple[str, str | None, str | None, TokenUsage]:
        try:
            decision = runner.run_raw(
                commit.patch.decode("utf-8", errors="replace"),
                repository=repository.canonical_source,
                commit_sha=commit.sha,
                parent_sha=commit.parent_sha,
                subject=commit.message.splitlines()[0] if commit.message else "",
                message=commit.message,
                profile=settings.triage_profile,
            )
        except LLMOversizeError:
            return commit.sha, None, "oversize", TokenUsage()
        except Exception as exc:
            return commit.sha, None, type(exc).__name__, TokenUsage()
        verdict = decision.verdict.value if decision.verdict else None
        error = (
            None if verdict else (decision.error.kind.value if decision.error else "unknown")
        )
        return commit.sha, verdict, error, _usage_of(decision)

    with ThreadPoolExecutor(max_workers=settings.workers) as pool:
        for future in as_completed(pool.submit(triage_one, c) for c in admitted):
            sha, verdict, error, call_usage = future.result()
            usage = usage + call_usage
            if verdict == "YES":
                outcome.triage_yes.append(sha)
            elif verdict == "NO":
                outcome.triage_no.append(sha)
            else:
                outcome.triage_errors.append((sha, error or "unknown"))
    say(
        f"triage: {len(outcome.triage_yes)} candidates, "
        f"{len(outcome.triage_no)} rejected, {len(outcome.triage_errors)} errors "
        f"(${pricing.estimate(usage):.2f})"
    )

    # --- stage 2: adjudication (expensive, precision-first) --------------
    candidates = sorted(outcome.triage_yes)
    if settings.max_candidates is not None:
        dropped = max(0, len(candidates) - settings.max_candidates)
        if dropped:
            say(f"NOTE: capping adjudication at {settings.max_candidates}; {dropped} dropped")
        candidates = candidates[: settings.max_candidates]

    if settings.adjudicator == "codex":
        adjudicator: Any = CodexAdjudicator(
            repository,
            model=client.config.model,
            base_url=client.config.endpoint,
            api_key=client.config.api_key,
            profile=settings.profile,
            sandbox=settings.sandbox,
        )
    else:
        adjudicator = Adjudicator(client, repository, profile=settings.profile)

    def adjudicate_one(sha: str) -> tuple[str, Any]:
        commit = by_sha[sha]
        return sha, adjudicator.adjudicate(_candidate_from(commit, repository.canonical_source))

    with ThreadPoolExecutor(max_workers=settings.workers) as pool:
        futures = [pool.submit(adjudicate_one, sha) for sha in candidates]
        for future in as_completed(futures):
            try:
                sha, result = future.result()
            except Exception as exc:
                LOGGER.warning("adjudication failed: %s", exc)
                continue
            usage = usage + result.usage
            if result.verdict == "YES":
                commit = by_sha[sha]
                finding = dict(result.decision)
                finding.update(
                    {
                        "commit_sha": sha,
                        "commit_date": commit.committer_time,
                        "commit_subject": (commit.message.splitlines() or [""])[0],
                    }
                )
                outcome.adjudication_yes.append(finding)
            elif result.verdict == "NO":
                outcome.adjudication_no.append(sha)
            else:
                reason = str(result.decision.get("abstain_reason") or "unspecified")
                outcome.adjudication_abstain.append((sha, reason))
            if (
                settings.max_cost_usd is not None
                and pricing.estimate(usage) >= settings.max_cost_usd
            ):
                say("cost ceiling reached; stopping adjudication")
                for pending in futures:
                    pending.cancel()
                break

    outcome.usage = usage
    outcome.cost_usd = pricing.estimate(usage)
    outcome.wall_clock_s = time.monotonic() - started
    say(
        f"adjudication: {len(outcome.adjudication_yes)} findings, "
        f"{len(outcome.adjudication_no)} rejected, "
        f"{len(outcome.adjudication_abstain)} abstained (${outcome.cost_usd:.2f})"
    )

    # --- attribution and de-duplication -----------------------------------
    #
    # Before compiling: point findings at the commit that made the change, then
    # collapse any that share a patch-id. A merge and the commit it brought in
    # are one change, and emitting both is a double count, not two findings.
    findings, moves, duplicates = apply_attribution(outcome.adjudication_yes, repository)
    outcome.adjudication_yes = findings
    outcome.attribution_moves = moves
    outcome.duplicates_dropped = duplicates
    if moves or duplicates:
        say(
            f"attribution: {len(moves)} finding(s) re-pointed past a merge, "
            f"{len(duplicates)} duplicate(s) collapsed"
        )

    # --- compile ----------------------------------------------------------
    stats = ScanStats(
        commits_scanned=prefilter.seen,
        commits_triaged=len(admitted),
        triage_candidates=len(outcome.triage_yes),
        adjudicated=len(candidates),
        findings=len(outcome.adjudication_yes),
        abstained=len(outcome.adjudication_abstain),
        rejected=len(outcome.adjudication_no),
        triage_errors=len(outcome.triage_errors),
        tokens=usage.total_tokens,
        estimated_cost_usd=round(outcome.cost_usd, 4),
        wall_clock_s=round(outcome.wall_clock_s, 1),
    )
    context = compile_context(
        findings,
        repo_ref=_repo_ref(
            repository,
            repository.resolve_revision(settings.revision)
            if settings.revision
            else snapshot.head_sha,
            snapshot.default_branch,
        ),
        scan=stats,
        provenance={
            "model": client.config.model,
            "endpoint": client.config.endpoint,
            "adjudicator_profile": settings.profile.value,
            "adjudicator_prompt_id": adjudicator.manifest.get("id"),
            "triage_profile": settings.triage_profile.value,
            "triage_prompt_id": runner.prompt.prompt_id,
            "triage_prompt_hash": runner.prompt.prompt_hash,
            "prefilter": prefilter.to_dict(),
            "generated_by": "strata.scan",
        },
        repository=repository,
        now=datetime.now(UTC),
    )
    outcome.context = write_narrative(context, client=client)
    return outcome


def _usage_of(decision: Any) -> TokenUsage:
    usage = getattr(decision, "usage", None)
    if isinstance(usage, TokenUsage):
        return usage
    if usage is None:
        return TokenUsage()
    return TokenUsage(
        prompt_tokens=int(getattr(usage, "input_tokens", 0) or 0),
        completion_tokens=int(getattr(usage, "output_tokens", 0) or 0),
        total_tokens=int(getattr(usage, "total_tokens", 0) or 0),
    )
