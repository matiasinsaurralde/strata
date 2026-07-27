"""Majority voting over repeated adjudications.

``temperature=0`` is not determinism — three runs over the same commit gave
three different answers. These tests pin the voting rules that turn that
variance into precision rather than noise.
"""

from __future__ import annotations

import pytest

from strata.adjudicator import AdjudicationResult
from strata.consensus import ConsensusAdjudicator
from strata.llm import TokenUsage


def _result(verdict: str, *, anchors: int = 0, tokens: int = 100) -> AdjudicationResult:
    decision: dict = {"verdict": verdict, "confidence": "high", "rationale": "…"}
    if verdict == "YES":
        decision["evidence"] = [{"path": f"a{i}.go"} for i in range(anchors)]
    return AdjudicationResult(
        decision=decision,
        profile=None,
        prompt_id="test",
        prompt_hash="",
        turns=1,
        tool_calls=2,
        tool_result_bytes=0,
        elapsed_ms=10.0,
        usage=TokenUsage(prompt_tokens=tokens, completion_tokens=10),
        repaired=False,
        tool_audit=(),
        validation_errors=(),
        limit_reason=None,
    )


class _Scripted:
    """Returns a fixed sequence of verdicts, one per call."""

    def __init__(self, *results: AdjudicationResult) -> None:
        self._results = list(results)
        self.calls = 0

    def adjudicate(self, _candidate):
        result = self._results[self.calls % len(self._results)]
        self.calls += 1
        return result


class _Exploding:
    def __init__(self, fail_first: int) -> None:
        self.fail_first = fail_first
        self.calls = 0

    def adjudicate(self, _candidate):
        self.calls += 1
        if self.calls <= self.fail_first:
            raise RuntimeError("round died")
        return _result("YES", anchors=1)


class TestMajority:
    def test_two_of_three_yes_carries(self):
        inner = _Scripted(_result("YES", anchors=1), _result("NO"), _result("YES", anchors=2))
        assert ConsensusAdjudicator(inner, rounds=3).adjudicate({}).verdict == "YES"

    def test_one_of_three_yes_does_not_carry(self):
        inner = _Scripted(_result("YES", anchors=1), _result("NO"), _result("NO"))
        assert ConsensusAdjudicator(inner, rounds=3).adjudicate({}).verdict == "NO"

    def test_a_decisive_no_beats_an_abstention(self):
        # Two NOs and one ABSTAIN is a NO, not a shrug.
        inner = _Scripted(_result("NO"), _result("ABSTAIN"), _result("NO"))
        assert ConsensusAdjudicator(inner, rounds=3).adjudicate({}).verdict == "NO"

    def test_a_genuine_three_way_split_abstains(self):
        inner = _Scripted(_result("YES", anchors=1), _result("NO"), _result("ABSTAIN"))
        result = ConsensusAdjudicator(inner, rounds=3).adjudicate({})
        assert result.verdict == "ABSTAIN"
        assert result.decision["abstain_reason"] == "no_consensus"
        assert "1xABSTAIN" in result.decision["rationale"]

    def test_unanimity_can_be_demanded(self):
        inner = _Scripted(_result("YES", anchors=1), _result("YES", anchors=1), _result("NO"))
        strict = ConsensusAdjudicator(inner, rounds=3, threshold=3)
        assert strict.adjudicate({}).verdict == "ABSTAIN"

    def test_rounds_of_one_is_a_passthrough(self):
        inner = _Scripted(_result("YES", anchors=1))
        result = ConsensusAdjudicator(inner, rounds=1).adjudicate({})
        assert result.verdict == "YES"
        assert inner.calls == 1


class TestWinnerSelection:
    def test_the_best_evidenced_yes_is_returned_verbatim(self):
        """The winner is a real answer, not a synthesis of several.

        A merged decision would be a finding no run actually made, carrying
        evidence and rationale from different investigations.
        """
        inner = _Scripted(
            _result("YES", anchors=1), _result("YES", anchors=4), _result("YES", anchors=2)
        )
        result = ConsensusAdjudicator(inner, rounds=3).adjudicate({})
        assert len(result.decision["evidence"]) == 4

    def test_the_vote_record_is_attached(self):
        inner = _Scripted(_result("YES", anchors=1), _result("NO"), _result("YES", anchors=1))
        consensus = ConsensusAdjudicator(inner, rounds=3).adjudicate({}).decision["consensus"]
        assert consensus["votes"] == {"NO": 1, "YES": 2}
        assert consensus["rounds"] == 3
        assert consensus["agreement"] == pytest.approx(0.67, abs=0.01)

    def test_cost_reported_is_the_whole_vote_not_one_round(self):
        inner = _Scripted(_result("YES", anchors=1, tokens=100))
        result = ConsensusAdjudicator(inner, rounds=3).adjudicate({})
        assert result.usage.prompt_tokens == 300
        assert result.tool_calls == 6


class TestResilience:
    def test_a_failed_round_is_a_missing_vote_not_a_lost_candidate(self):
        inner = _Exploding(fail_first=1)
        result = ConsensusAdjudicator(inner, rounds=3).adjudicate({})
        assert result.verdict == "YES"
        assert result.decision["consensus"]["rounds"] == 2

    def test_every_round_failing_abstains(self):
        inner = _Exploding(fail_first=3)
        result = ConsensusAdjudicator(inner, rounds=3).adjudicate({})
        assert result.verdict == "ABSTAIN"
        assert result.decision["abstain_reason"] == "all_rounds_failed"

    def test_threshold_counts_votes_cast_not_rounds_requested(self):
        # Two rounds survive and both say YES, so the finding stands even
        # though the third never voted.
        inner = _Exploding(fail_first=1)
        assert ConsensusAdjudicator(inner, rounds=3).adjudicate({}).verdict == "YES"


class TestConfiguration:
    def test_rejects_zero_rounds(self):
        with pytest.raises(ValueError, match="at least 1"):
            ConsensusAdjudicator(object(), rounds=0)

    @pytest.mark.parametrize("threshold", [0, 4])
    def test_rejects_an_unreachable_threshold(self, threshold):
        with pytest.raises(ValueError, match="threshold"):
            ConsensusAdjudicator(object(), rounds=3, threshold=threshold)

    def test_serial_mode_runs_the_same_number_of_rounds(self):
        inner = _Scripted(_result("NO"))
        ConsensusAdjudicator(inner, rounds=3, parallel=False).adjudicate({})
        assert inner.calls == 3
