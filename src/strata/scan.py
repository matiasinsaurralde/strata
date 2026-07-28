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

import json
import logging
import re
import time
import traceback
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
from .git_repo import DEFAULT_FETCH_TIMEOUT, GitCommit, GitRepository
from .introduction import attribute_introductions
from .llm import LLMOversizeError, ModelPricing, OpenAIChatClient, TokenUsage
from .prefilter import PrefilterStats, prefilter_commit
from .progress import DEFAULT_INTERVAL, CallbackSink, InFlight, ProgressSink, Reporter
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
    #: Timeout, in seconds, for network Git operations (clone, fetch,
    #: ls-remote). Mirroring a large remote can exceed the 120s default over a
    #: slow link; raise this instead of letting the clone abort mid-transfer.
    fetch_timeout: float = DEFAULT_FETCH_TIMEOUT
    #: Compute the introduced-to-fixed span per fingerprint (deterministic,
    #: blame-only; see :mod:`strata.introduction`). Off by default while the
    #: heuristic stabilises; it adds only local git-blame calls, no LLM.
    attribute_introductions: bool = False


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
    #: Commits whose adjudication raised (SHA -> formatted traceback). These are
    #: distinct from ABSTAIN verdicts: the call never produced a decision at all.
    #: Previously swallowed by a bare warning; retained here for the debug report.
    adjudication_errors: list[tuple[str, str]] = field(default_factory=list)
    #: Per-commit adjudication detail for offline debugging. One entry per
    #: adjudicated commit, in completion order, capturing the verdict, the raw
    #: abstain/validation reason, and any validation errors — the record the
    #: aggregate counts throw away.
    adjudication_records: list[dict[str, Any]] = field(default_factory=list)
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


def _legacy_sink(progress: Callable[[str], None] | None) -> ProgressSink | None:
    return None if progress is None else CallbackSink(progress)


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
    progress_sink: ProgressSink | None = None,
    progress_interval: float = DEFAULT_INTERVAL,
) -> ScanOutcome:
    """Scan a repository and compile its security context.

    Args:
        source: Local path or remote URL.
        client: Chat client used by both model stages.
        config: Scan knobs; defaults are suitable for a mid-sized repository.
        cache_root: Where the bare mirror lives.
        progress: Optional callback receiving stage summaries as strings. Kept
            for callers written against the original signature; ``progress_sink``
            supersedes it and takes precedence when both are given.
        progress_sink: Structured progress consumer -- see :mod:`strata.progress`.
            This is the one that reports *during* a stage rather than after it.
        progress_interval: Seconds between per-item progress events.

    Returns:
        A :class:`ScanOutcome` whose ``context`` is the compiled artifact.
    """
    settings = config or ScanConfig()
    pricing = settings.pricing or ModelPricing(1.25, 10.0, 0.125)
    sink = progress_sink if progress_sink is not None else _legacy_sink(progress)
    reporter = Reporter(sink, interval=progress_interval)
    say = reporter.note
    started = time.monotonic()

    # The mirror clone and the rev-list are the first place a scan can sit
    # silently for minutes, so they are timed like any other stage even though
    # neither can be counted.
    with reporter.stage("git") as git_stage:
        repository = GitRepository(
            source,
            cache_root=cache_root,
            fetch_timeout=settings.fetch_timeout,
            in_place=True,
        )
        snapshot = repository.fetch()
        origin = "grounded on local checkout" if repository.in_place else "mirror ready"
        say(f"{origin}: {snapshot.head_sha[:12]} on {snapshot.default_branch}", stage="git")

        shas = repository.enumerate_shas(last=settings.last, revision=settings.revision)
        git_stage.finish(f"enumerated {len(shas)} commits")

    # --- stage 0: deterministic prefilter (free) -------------------------
    #
    # Extraction is the dominant cost of this stage, and per-commit ``get_commit``
    # spends five to six Git subprocesses each -- most of them fetching a patch the
    # prefilter is about to reject. A single streaming ``git log -p`` pass yields the
    # same fully-hydrated commits in one process instead, turning a many-minute walk
    # over a large history into seconds. Patch-ids are deliberately not computed here:
    # the prefilter never reads them, and attribution derives them later for just the
    # handful of admitted commits.
    prefilter = PrefilterStats()
    admitted: list[GitCommit] = []
    with reporter.stage("prefilter", total=len(shas)) as prefilter_stage:
        stream = repository.stream_commits(
            last=settings.last, revision=settings.revision, compute_patch_id=False
        )
        while True:
            try:
                commit = next(stream)
            except StopIteration:
                break
            except Exception as exc:  # a broken object must not abort the scan
                # A per-commit extraction fault is logged and skipped, as with the
                # per-``get_commit`` path; the counter still advances so the bar does
                # not read as stalled short of its total.
                LOGGER.warning("streamed extraction failed: %s", exc)
                prefilter_stage.advance()
                continue
            decision = prefilter_commit(
                commit.changed_paths, commit.patch, max_diff_bytes=settings.max_diff_bytes
            )
            prefilter.record(decision)
            if decision.admit:
                admitted.append(commit)
            prefilter_stage.advance()
        prefilter_stage.finish(
            f"admitted {prefilter.admitted}/{prefilter.seen} "
            f"({prefilter.reduction_rate:.1%} rejected, $0)"
        )

    outcome = ScanOutcome(context=None, prefilter=prefilter)  # type: ignore[arg-type]
    usage = TokenUsage()

    # Both model stages run a bounded pool of long calls, so the useful progress
    # detail is the same for each: what is in flight, how long the oldest has
    # been running, and what has been spent against any ceiling.
    in_flight = InFlight()

    def model_stage_detail() -> dict[str, Any]:
        detail = in_flight.snapshot()
        detail["cost_usd"] = pricing.estimate(usage)
        if settings.max_cost_usd is not None:
            detail["cost_ceiling_usd"] = settings.max_cost_usd
        return detail

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
        with in_flight.track(commit.sha):
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

    with reporter.stage(
        "triage", total=len(admitted), detail=model_stage_detail
    ) as triage_stage:
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
                triage_stage.advance()
        triage_stage.finish(
            f"{len(outcome.triage_yes)} candidates, "
            f"{len(outcome.triage_no)} rejected, {len(outcome.triage_errors)} errors "
            f"(${pricing.estimate(usage):.2f})"
        )

    # --- stage 2: adjudication (expensive, precision-first) --------------
    candidates = sorted(outcome.triage_yes)
    if settings.max_candidates is not None:
        dropped = max(0, len(candidates) - settings.max_candidates)
        if dropped:
            say(
                f"NOTE: capping adjudication at {settings.max_candidates}; {dropped} dropped",
                stage="adjudicate",
            )
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
        with in_flight.track(sha):
            commit = by_sha[sha]
            candidate = _candidate_from(commit, repository.canonical_source)
            return sha, adjudicator.adjudicate(candidate)

    # No ETA: per-candidate cost spans an order of magnitude (mean ~25s against a
    # 240s ceiling, and codex is several times that), so a linear projection would
    # manufacture a finish time it cannot support. The in-flight count and the age
    # of the oldest candidate answer the question actually being asked here --
    # whether anything is wedged -- and they answer it against a known ceiling.
    with reporter.stage(
        "adjudicate", total=len(candidates), detail=model_stage_detail, eta=False
    ) as adjudicate_stage:
        with ThreadPoolExecutor(max_workers=settings.workers) as pool:
            # Keep the future->sha map so a raised adjudication can still be attributed
            # to its commit: future.result() re-raises before returning the (sha, result)
            # tuple, so the SHA is otherwise lost.
            future_to_sha = {pool.submit(adjudicate_one, sha): sha for sha in candidates}
            futures = list(future_to_sha)
            for future in as_completed(futures):
                # Counted here rather than per verdict: the future has completed
                # either way, and the error path below returns early.
                adjudicate_stage.advance()
                failed_sha = future_to_sha[future]
                try:
                    sha, result = future.result()
                except Exception as exc:
                    # Previously swallowed by a bare warning. Retain the SHA and full
                    # traceback so the debug report can show exactly what blew up.
                    tb = traceback.format_exc()
                    LOGGER.warning("adjudication failed for %s: %s", failed_sha[:12], exc)
                    outcome.adjudication_errors.append((failed_sha, tb))
                    commit = by_sha.get(failed_sha)
                    outcome.adjudication_records.append(
                        {
                            "sha": failed_sha,
                            "subject": (commit.message.splitlines() or [""])[0]
                            if commit
                            else "",
                            "verdict": "ERROR",
                            "reason": f"{type(exc).__name__}: {exc}",
                            "validation_errors": [],
                            "raw_output": None,
                        }
                    )
                    continue
                usage = usage + result.usage
                commit = by_sha[sha]
                subject = (commit.message.splitlines() or [""])[0]
                if result.verdict == "YES":
                    finding = dict(result.decision)
                    finding.update(
                        {
                            "commit_sha": sha,
                            "commit_date": commit.committer_time,
                            "commit_subject": subject,
                        }
                    )
                    outcome.adjudication_yes.append(finding)
                elif result.verdict == "NO":
                    outcome.adjudication_no.append(sha)
                else:
                    reason = str(result.decision.get("abstain_reason") or "unspecified")
                    outcome.adjudication_abstain.append((sha, reason))
                # One debug record per adjudicated commit, capturing what the counts drop:
                # the verdict, the raw reason string (garbled ones included, verbatim), any
                # validation errors, and the raw model text when the backend exposes it.
                outcome.adjudication_records.append(
                    {
                        "sha": sha,
                        "subject": subject,
                        "verdict": result.verdict,
                        "reason": str(result.decision.get("abstain_reason") or "")
                        if result.verdict == "ABSTAIN"
                        else "",
                        "validation_errors": list(
                            getattr(result, "validation_errors", ()) or ()
                        ),
                        "raw_output": getattr(result, "raw_output", None),
                    }
                )
                if (
                    settings.max_cost_usd is not None
                    and pricing.estimate(usage) >= settings.max_cost_usd
                ):
                    say("cost ceiling reached; stopping adjudication", stage="adjudicate")
                    for pending in futures:
                        pending.cancel()
                    break

        outcome.usage = usage
        outcome.cost_usd = pricing.estimate(usage)
        outcome.wall_clock_s = time.monotonic() - started
        adjudicate_stage.finish(
            f"{len(outcome.adjudication_yes)} findings, "
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
            f"{len(duplicates)} duplicate(s) collapsed",
            stage="compile",
        )

    # Introduced-to-fixed span: blame the pre-fix lines each fix touched and
    # record how long the vulnerable code lived. Deterministic, opt-in, no LLM.
    # Runs here -- after findings are finalized (re-pointed, de-duplicated) and
    # while they are still mutable dicts the compiler reads by key.
    if settings.attribute_introductions:
        findings = attribute_introductions(outcome.adjudication_yes, repository)
        outcome.adjudication_yes = findings
        attributed = sum(1 for f in findings if f.get("introduced_to_fixed_days") is not None)
        say(
            f"introductions: {attributed}/{len(findings)} finding(s) got a span",
            stage="compile",
        )

    # --- compile ----------------------------------------------------------
    #
    # Announced before the fact because the narrative is one more model call:
    # without this line the run's last output is the adjudication summary, and
    # the wait that follows looks like a hang rather than the tail of the scan.
    say("compiling security context", stage="compile")
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
    say(
        f"done · {len(outcome.adjudication_yes)} finding(s) · "
        f"${outcome.cost_usd:.2f} · {outcome.wall_clock_s:.1f}s"
    )
    return outcome


# A reason string is "suspect" when it does not look like a short machine tag: it is
# long, multi-line, or carries non-ASCII / control-channel markers. These are the
# degenerate/garbled model outputs worth eyeballing. This flags them for review; it
# does not change any verdict.
_TAG_RE = re.compile(r"^[a-z0-9_]{1,48}$")
_CHANNEL_MARKERS = ("to=functions.", "```", "badjson")


def _reason_is_suspect(reason: str) -> bool:
    reason = reason or ""
    if _TAG_RE.match(reason):
        return False
    if len(reason) > 80 or "\n" in reason:
        return True
    if any(marker in reason for marker in _CHANNEL_MARKERS):
        return True
    # any non-ASCII (e.g. CJK/Cyrillic/Armenian) in a reason field is a red flag
    return any(ord(ch) > 127 for ch in reason)


def build_debug_report(outcome: ScanOutcome) -> dict[str, Any]:
    """Assemble a structured, per-commit debug view of an adjudication run.

    Everything the aggregate counts drop: which commit produced each verdict, the raw
    abstain/validation reason (garbled ones verbatim), validation errors, the raw model
    text when available, and any exception traceback. Pure reporting — reads the outcome,
    changes nothing.
    """
    records = outcome.adjudication_records
    by_verdict: dict[str, list[dict[str, Any]]] = {}
    for rec in records:
        by_verdict.setdefault(rec.get("verdict", "?"), []).append(rec)

    abstains = by_verdict.get("ABSTAIN", [])
    suspect = [r for r in abstains if _reason_is_suspect(r.get("reason", ""))]

    return {
        "generated_by": "strata.scan.debug",
        "summary": {
            "adjudicated": len(records),
            "findings": len(by_verdict.get("YES", [])),
            "rejected": len(by_verdict.get("NO", [])),
            "abstained": len(abstains),
            "errors": len(outcome.adjudication_errors),
            "triage_errors": len(outcome.triage_errors),
            "suspect_reasons": len(suspect),
            "abstain_reasons": _counted(r.get("reason", "") for r in abstains),
            "estimated_cost_usd": round(outcome.cost_usd, 4),
            "wall_clock_s": round(outcome.wall_clock_s, 1),
        },
        "findings": [
            {"sha": r["sha"], "subject": r["subject"]} for r in by_verdict.get("YES", [])
        ],
        "abstained": [
            {
                "sha": r["sha"],
                "subject": r["subject"],
                "reason": r.get("reason", ""),
                "suspect": _reason_is_suspect(r.get("reason", "")),
                "validation_errors": r.get("validation_errors", []),
                "raw_output": r.get("raw_output"),
            }
            for r in abstains
        ],
        "rejected": [
            {"sha": r["sha"], "subject": r["subject"]} for r in by_verdict.get("NO", [])
        ],
        "errors": [{"sha": sha, "traceback": tb} for sha, tb in outcome.adjudication_errors],
        "triage_errors": [{"sha": sha, "error": err} for sha, err in outcome.triage_errors],
    }


def _debug_markdown(report: dict[str, Any]) -> str:
    """Render the debug report as human-readable Markdown for manual evaluation."""
    s = report["summary"]
    out: list[str] = []
    out.append("# Strata scan — adjudication debug report\n")
    out.append(
        f"Adjudicated **{s['adjudicated']}** commits: "
        f"**{s['findings']}** findings, **{s['rejected']}** rejected, "
        f"**{s['abstained']}** abstained, **{s['errors']}** errors "
        f"(+{s['triage_errors']} triage errors). "
        f"${s['estimated_cost_usd']} · {s['wall_clock_s']}s\n"
    )
    if s["suspect_reasons"]:
        out.append(
            f"> ⚠️ **{s['suspect_reasons']} abstain reason(s) look garbled/degenerate** "
            f"— non-tag text, non-ASCII, or leaked tool-channel markers. Inspect the "
            f"raw model output below.\n"
        )

    def sha(x: str) -> str:
        return f"`{(x or '')[:12]}`"

    if report["findings"]:
        out.append("\n## Findings (YES)\n")
        for r in report["findings"]:
            out.append(f"- {sha(r['sha'])} — {r['subject']}")
    if report["abstained"]:
        out.append("\n## Abstained\n")
        for r in report["abstained"]:
            flag = " ⚠️ **suspect**" if r["suspect"] else ""
            out.append(f"- {sha(r['sha'])} — {r['subject']}{flag}")
            out.append(f"    - reason: `{r['reason'][:300]}`")
            if r["validation_errors"]:
                out.append(f"    - validation_errors: {r['validation_errors']}")
            if r["suspect"] and r.get("raw_output"):
                snippet = r["raw_output"][:600].replace("\n", " ")
                out.append(f"    - raw_output (600 chars): `{snippet}`")
    if report["errors"]:
        out.append("\n## Adjudication errors (raised, no verdict)\n")
        for r in report["errors"]:
            first = (r["traceback"].strip().splitlines() or [""])[-1]
            out.append(f"- {sha(r['sha'])} — {first}")
    if report["rejected"]:
        out.append("\n## Rejected (NO)\n")
        for r in report["rejected"]:
            out.append(f"- {sha(r['sha'])} — {r['subject']}")
    return "\n".join(out) + "\n"


def write_debug_report(outcome: ScanOutcome, path: Any) -> None:
    """Write the per-commit debug report to ``path`` (JSON) and a sibling ``.md``.

    ``path`` is a path-like; a ``.md`` companion is written alongside it. Best-effort:
    a failure here must never fail the scan, so exceptions are logged and swallowed.
    """
    from pathlib import Path

    try:
        report = build_debug_report(outcome)
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        p.with_suffix(".md").write_text(_debug_markdown(report), encoding="utf-8")
    except Exception as exc:  # pragma: no cover - diagnostics must not break the run
        LOGGER.warning("failed to write debug report to %s: %s", path, exc)


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
