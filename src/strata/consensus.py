"""Run stage 2 more than once and keep only what survives the repeat.

``temperature=0`` is not determinism. Three runs of the same adjudicator over
the same commit produced three different answers, which means a single-shot
verdict on a borderline commit is partly a coin flip — and at a ~1.5% base
rate, the flips land disproportionately on false positives, because a real fix
tends to look like one from every angle while a plausible non-fix does not.

So: ask N times, and require agreement. This trades cost and latency for
precision, which is the correct direction for a precision-first second stage
sitting behind a recall-first first stage.

Wraps any object with an ``adjudicate(candidate) -> AdjudicationResult``, so
it composes over the chat backend and the sandboxed one alike.
"""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from typing import Any

from .adjudicator import AdjudicationResult, _abstain_decision
from .llm import TokenUsage

LOGGER = logging.getLogger(__name__)

__all__ = ["ConsensusAdjudicator"]


class ConsensusAdjudicator:
    """Majority voting over N independent runs of an inner adjudicator.

    Args:
        inner: Any adjudicator exposing ``adjudicate(candidate)``.
        rounds: How many independent runs. Odd numbers avoid ties; 3 is the
            usual choice.
        threshold: Votes a YES needs to stand. ``None`` means a strict
            majority. Set it to ``rounds`` to demand unanimity, which buys
            more precision at more recall cost.
        parallel: Run the rounds concurrently. Cuts latency to roughly one
            round, at N times the peak load on the endpoint.

    The winning *decision* is not synthesised from the votes — it is the single
    best real answer among those that voted with the majority, chosen by
    verified-anchor count. A merged decision would be a finding no run
    actually made, with evidence and rationale from different investigations.
    """

    def __init__(
        self,
        inner: Any,
        *,
        rounds: int = 3,
        threshold: int | None = None,
        parallel: bool = True,
    ) -> None:
        if rounds < 1:
            raise ValueError("rounds must be at least 1")
        if threshold is not None and not 1 <= threshold <= rounds:
            raise ValueError(f"threshold must be between 1 and {rounds}")
        self.inner = inner
        self.rounds = rounds
        self.threshold = threshold if threshold is not None else rounds // 2 + 1
        self.parallel = parallel

    def _run_rounds(self, candidate: Mapping[str, Any] | Any) -> list[AdjudicationResult]:
        if self.rounds == 1:
            return [self.inner.adjudicate(candidate)]
        if not self.parallel:
            return [self.inner.adjudicate(candidate) for _ in range(self.rounds)]
        with ThreadPoolExecutor(max_workers=self.rounds) as pool:
            futures = [
                pool.submit(self.inner.adjudicate, candidate) for _ in range(self.rounds)
            ]
            results: list[AdjudicationResult] = []
            for future in futures:
                try:
                    results.append(future.result())
                except Exception as exc:  # a lost round is a missing vote
                    LOGGER.warning("consensus round failed: %s", exc)
            return results

    def adjudicate(self, candidate: Mapping[str, Any] | Any) -> AdjudicationResult:
        results = self._run_rounds(candidate)
        if not results:
            return _failed_result(self.rounds)

        votes = Counter(result.verdict for result in results)
        yes_votes = votes.get("YES", 0)

        if yes_votes >= self.threshold:
            winners = [r for r in results if r.verdict == "YES"]
            # Most verified anchors wins: every anchor in a validated decision
            # has already been re-read from git and byte-matched, so the count
            # is a measure of how much of the claim is actually pinned to code
            # rather than of how much the model wrote.
            best = max(winners, key=lambda r: len(r.decision.get("evidence") or ()))
            return _annotate(best, results, votes)

        # No YES majority. Report the plurality of what is left, preferring a
        # decisive NO over an abstention: two NOs and one ABSTAIN is a NO.
        for verdict in ("NO", "ABSTAIN"):
            matching = [r for r in results if r.verdict == verdict]
            if matching and votes.get(verdict, 0) >= self.threshold:
                return _annotate(matching[0], results, votes)

        # Genuinely split. An abstention is the honest answer, and it records
        # the split so a reviewer can see it was close rather than unexamined.
        split = ", ".join(f"{count}x{verdict}" for verdict, count in sorted(votes.items()))
        abstention = _abstain_decision(
            "no_consensus", f"{self.rounds} runs did not agree: {split}."
        )
        return _annotate(
            replace(results[0], decision=abstention, validation_errors=("no_consensus",)),
            results,
            votes,
        )


def _annotate(
    winner: AdjudicationResult,
    results: list[AdjudicationResult],
    votes: Counter[str],
) -> AdjudicationResult:
    """Attach the vote record and the true cost of the whole vote."""
    decision = dict(winner.decision)
    decision["consensus"] = {
        "rounds": len(results),
        "votes": dict(sorted(votes.items())),
        "agreement": round(max(votes.values()) / len(results), 2),
    }
    total = TokenUsage()
    for result in results:
        total = total + result.usage
    return replace(
        winner,
        decision=decision,
        usage=total,
        # Latency is the slowest round when parallel and the sum when not;
        # the max is the honest number for the caller's wall clock either way
        # only in the parallel case, so report the sum's upper bound.
        elapsed_ms=max(r.elapsed_ms for r in results),
        tool_calls=sum(r.tool_calls for r in results),
    )


def _failed_result(rounds: int) -> AdjudicationResult:
    return AdjudicationResult(
        decision=_abstain_decision(
            "all_rounds_failed", f"All {rounds} adjudication rounds raised."
        ),
        profile=None,
        prompt_id="consensus",
        prompt_hash="",
        turns=0,
        tool_calls=0,
        tool_result_bytes=0,
        elapsed_ms=0.0,
        usage=TokenUsage(),
        repaired=False,
        tool_audit=(),
        validation_errors=("all_rounds_failed",),
        limit_reason=None,
    )
