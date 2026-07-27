"""Small, explicit evaluation metrics for low-prevalence classifiers."""

from __future__ import annotations

import math
from collections.abc import Callable, Hashable, Iterable, Mapping
from dataclasses import dataclass
from itertools import combinations
from statistics import NormalDist
from typing import Any


@dataclass(frozen=True, slots=True)
class ConfidenceInterval:
    point: float
    lower: float
    upper: float
    confidence: float
    method: str
    events: int
    trials: int

    def __iter__(self):
        """Allow ``low, high = interval`` while retaining metadata."""

        yield self.lower
        yield self.upper


def _count_inputs(events: int, trials: int) -> None:
    if (
        isinstance(events, bool)
        or isinstance(trials, bool)
        or not isinstance(events, int)
        or not isinstance(trials, int)
    ):
        raise TypeError("events and trials must be integers")
    if trials < 1:
        raise ValueError("trials must be positive")
    if events < 0 or events > trials:
        raise ValueError("events must satisfy 0 <= events <= trials")


def _confidence(value: float) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise TypeError("confidence must be numeric")
    result = float(value)
    if not 0.0 < result < 1.0:
        raise ValueError("confidence must be between 0 and 1")
    return result


def wilson_interval(
    events: int,
    trials: int,
    *,
    confidence: float = 0.95,
) -> ConfidenceInterval:
    """Two-sided Wilson score interval for a binomial proportion."""

    _count_inputs(events, trials)
    confidence = _confidence(confidence)
    z = NormalDist().inv_cdf(0.5 + confidence / 2.0)
    p = events / trials
    z2 = z * z
    denominator = 1.0 + z2 / trials
    centre = (p + z2 / (2.0 * trials)) / denominator
    margin = z * math.sqrt(p * (1.0 - p) / trials + z2 / (4.0 * trials * trials)) / denominator
    return ConfidenceInterval(
        point=p,
        lower=max(0.0, centre - margin),
        upper=min(1.0, centre + margin),
        confidence=confidence,
        method="wilson",
        events=events,
        trials=trials,
    )


def zero_event_upper_bound(trials: int, *, confidence: float = 0.95) -> float:
    """Exact one-sided Clopper-Pearson upper bound after zero events.

    This is ``1 - alpha ** (1/n)``.  It is exact under the independent binomial
    model and intentionally more conservative than reporting an observed zero.
    """

    _count_inputs(0, trials)
    confidence = _confidence(confidence)
    return 1.0 - (1.0 - confidence) ** (1.0 / trials)


exact_zero_event_upper_bound = zero_event_upper_bound


def _probability(value: float, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be numeric")
    result = float(value)
    if not math.isfinite(result) or not 0.0 <= result <= 1.0:
        raise ValueError(f"{name} must be between 0 and 1")
    return result


def candidate_rate_at_prevalence(
    true_positive_rate: float,
    false_positive_rate: float,
    prevalence: float,
) -> float:
    tpr = _probability(true_positive_rate, "true_positive_rate")
    fpr = _probability(false_positive_rate, "false_positive_rate")
    base = _probability(prevalence, "prevalence")
    return base * tpr + (1.0 - base) * fpr


def precision_at_prevalence(
    true_positive_rate: float,
    false_positive_rate: float,
    prevalence: float,
) -> float | None:
    """Bayes-corrected precision; ``None`` means the model emits no alerts."""

    tpr = _probability(true_positive_rate, "true_positive_rate")
    base = _probability(prevalence, "prevalence")
    candidate_rate = candidate_rate_at_prevalence(tpr, false_positive_rate, base)
    if candidate_rate == 0.0:
        return None
    return base * tpr / candidate_rate


def alerts_per_1000(
    true_positive_rate: float,
    false_positive_rate: float,
    prevalence: float,
) -> float:
    return 1_000.0 * candidate_rate_at_prevalence(
        true_positive_rate, false_positive_rate, prevalence
    )


#: ``clopper_pearson_zero_upper`` is the exact one-sided bound for a zero-event
#: observation. Kept as an alias under its conventional statistical name.
clopper_pearson_zero_upper = zero_event_upper_bound


def coverage_corrected_rate(events: int, trials: int, uncovered: int) -> float | None:
    """Rate over rows that were actually evaluated, not merely eligible.

    An uncovered row (backend error, oversize skip) cannot produce an event, so
    including it in the denominator biases the rate toward zero. For a false
    positive rate that bias is optimistic, which is the dangerous direction.
    """
    denominator = trials - uncovered
    if denominator <= 0:
        return None
    return events / denominator


def precision_interval_at_prevalence(
    recall_interval: ConfidenceInterval,
    fpr_interval: ConfidenceInterval,
    prevalence: float,
) -> tuple[float | None, float | None, float | None]:
    """Propagate recall and FPR intervals into a precision range.

    Returns ``(lower, point, upper)``. Precision rises with recall and falls
    with FPR, so the bounds pair the extremes crosswise. This is a conservative
    envelope, not an exact joint interval — the two estimates come from
    different samples and are treated as independent.

    Reporting a single precision number from two interval-valued inputs is how
    ``P@1.5% = 0.082`` acquired three significant figures it never had.
    """
    base = _probability(prevalence, "prevalence")

    def precision(recall: float, fpr: float) -> float | None:
        denominator = base * recall + (1.0 - base) * fpr
        if denominator == 0.0:
            return None
        return base * recall / denominator

    lower = precision(recall_interval.lower, fpr_interval.upper)
    point = precision(recall_interval.point, fpr_interval.point)
    upper = precision(recall_interval.upper, fpr_interval.lower)
    return lower, point, upper


def expected_cascade_cost(
    *,
    triage_cost_per_commit: float,
    adjudicator_cost_per_candidate: float,
    candidate_rate: float | None = None,
    true_positive_rate: float | None = None,
    false_positive_rate: float | None = None,
    prevalence: float | None = None,
) -> float:
    """Expected cost per commit for the two-pass cascade."""

    for value, name in (
        (triage_cost_per_commit, "triage_cost_per_commit"),
        (adjudicator_cost_per_candidate, "adjudicator_cost_per_candidate"),
    ):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise TypeError(f"{name} must be numeric")
        if not math.isfinite(float(value)) or value < 0:
            raise ValueError(f"{name} must be finite and non-negative")
    if candidate_rate is None:
        if true_positive_rate is None or false_positive_rate is None or prevalence is None:
            raise ValueError(
                "provide candidate_rate or all of true_positive_rate, "
                "false_positive_rate, and prevalence"
            )
        candidate_rate = candidate_rate_at_prevalence(
            true_positive_rate, false_positive_rate, prevalence
        )
    else:
        candidate_rate = _probability(candidate_rate, "candidate_rate")
    return float(triage_cost_per_commit) + candidate_rate * float(
        adjudicator_cost_per_candidate
    )


@dataclass(frozen=True, slots=True)
class BinarySummary:
    total: int
    eligible: int
    excluded: int
    evaluated: int
    unevaluated: int
    positives: int
    negatives: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    uncovered_positives: int
    uncovered_negatives: int
    recall: float | None
    false_positive_rate: float | None
    observed_precision: float | None
    coverage: float
    recall_interval: ConfidenceInterval | None
    false_positive_rate_interval: ConfidenceInterval | None
    recall_covered: float | None = None
    false_positive_rate_covered: float | None = None
    recall_covered_interval: ConfidenceInterval | None = None
    false_positive_rate_covered_interval: ConfidenceInterval | None = None

    @property
    def evaluated_positives(self) -> int:
        return self.positives - self.uncovered_positives

    @property
    def evaluated_negatives(self) -> int:
        return self.negatives - self.uncovered_negatives

    def to_dict(self) -> dict[str, Any]:
        def interval(value: ConfidenceInterval | None) -> dict[str, Any] | None:
            if value is None:
                return None
            return {
                "point": value.point,
                "lower": value.lower,
                "upper": value.upper,
                "confidence": value.confidence,
                "method": value.method,
                "events": value.events,
                "trials": value.trials,
            }

        return {
            "total": self.total,
            "eligible": self.eligible,
            "excluded": self.excluded,
            "evaluated": self.evaluated,
            "unevaluated": self.unevaluated,
            "positives": self.positives,
            "negatives": self.negatives,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "uncovered_positives": self.uncovered_positives,
            "uncovered_negatives": self.uncovered_negatives,
            "evaluated_positives": self.evaluated_positives,
            "evaluated_negatives": self.evaluated_negatives,
            "recall": self.recall,
            "false_positive_rate": self.false_positive_rate,
            "recall_covered": self.recall_covered,
            "false_positive_rate_covered": self.false_positive_rate_covered,
            "observed_precision": self.observed_precision,
            "coverage": self.coverage,
            "recall_interval": interval(self.recall_interval),
            "false_positive_rate_interval": interval(self.false_positive_rate_interval),
            "recall_covered_interval": interval(self.recall_covered_interval),
            "false_positive_rate_covered_interval": interval(
                self.false_positive_rate_covered_interval
            ),
        }


def _ground_truth(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"yes", "positive", "fix", "true", "1"}:
            return True
        if normalized in {
            "no",
            "negative",
            "context",
            "introduce",
            "other",
            "false",
            "0",
        }:
            return False
        if normalized in {"backport", "abstain", "unknown", "excluded"}:
            return None
    raise ValueError(f"unsupported ground-truth value: {value!r}")


def _prediction(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    raw = getattr(value, "value", value)
    if isinstance(raw, str):
        normalized = raw.strip().upper()
        if normalized == "YES":
            return True
        if normalized == "NO":
            return False
        if normalized in {"ABSTAIN", "ERROR", "MALFORMED", "SKIPPED"}:
            return None
    raise ValueError(f"unsupported prediction value: {value!r}")


def summarize_binary(
    rows: Iterable[Mapping[str, Any]],
    *,
    truth_key: str = "truth",
    prediction_key: str = "prediction",
    confidence: float = 0.95,
) -> BinarySummary:
    """Summarize rows without converting missing/error predictions to ``NO``."""

    counts = {
        "total": 0,
        "excluded": 0,
        "evaluated": 0,
        "positives": 0,
        "negatives": 0,
        "true_positives": 0,
        "false_positives": 0,
        "true_negatives": 0,
        "false_negatives": 0,
        "uncovered_positives": 0,
        "uncovered_negatives": 0,
    }
    for row in rows:
        truth = _ground_truth(row[truth_key])
        counts["total"] += 1
        if truth is None:
            counts["excluded"] += 1
            continue
        prediction = _prediction(row.get(prediction_key))
        counts["positives" if truth else "negatives"] += 1
        if prediction is None:
            counts["uncovered_positives" if truth else "uncovered_negatives"] += 1
            continue
        counts["evaluated"] += 1
        if truth and prediction:
            counts["true_positives"] += 1
        elif truth:
            counts["false_negatives"] += 1
        elif prediction:
            counts["false_positives"] += 1
        else:
            counts["true_negatives"] += 1

    total = counts["total"]
    eligible = total - counts["excluded"]
    positives = counts["positives"]
    negatives = counts["negatives"]
    tp = counts["true_positives"]
    fp = counts["false_positives"]
    alerts = tp + fp
    evaluated_positives = positives - counts["uncovered_positives"]
    evaluated_negatives = negatives - counts["uncovered_negatives"]

    # Two denominators, deliberately both reported.
    #
    # `recall` divides by ALL positives, so an uncovered row counts as a miss:
    # conservative, and the number to quote.
    #
    # `false_positive_rate` divides by ALL negatives for continuity with the
    # frozen baseline — but it is *anti-conservative* for exactly the same
    # reason: an uncovered negative cannot produce a false positive, so backend
    # failures silently depress it. A run that failed on a quarter of its
    # negatives looks a quarter cleaner than it is. `*_covered` divides by what
    # was actually evaluated; that is the honest FPR, and the one downstream
    # precision should use.
    recall = tp / positives if positives else None
    fpr = fp / negatives if negatives else None
    recall_covered = tp / evaluated_positives if evaluated_positives else None
    fpr_covered = fp / evaluated_negatives if evaluated_negatives else None
    precision = tp / alerts if alerts else None
    return BinarySummary(
        total=total,
        eligible=eligible,
        excluded=counts["excluded"],
        evaluated=counts["evaluated"],
        unevaluated=eligible - counts["evaluated"],
        positives=positives,
        negatives=negatives,
        true_positives=tp,
        false_positives=fp,
        true_negatives=counts["true_negatives"],
        false_negatives=counts["false_negatives"],
        uncovered_positives=counts["uncovered_positives"],
        uncovered_negatives=counts["uncovered_negatives"],
        recall=recall,
        false_positive_rate=fpr,
        observed_precision=precision,
        coverage=counts["evaluated"] / eligible if eligible else 0.0,
        recall_interval=wilson_interval(tp, positives, confidence=confidence)
        if positives
        else None,
        false_positive_rate_interval=wilson_interval(fp, negatives, confidence=confidence)
        if negatives
        else None,
        recall_covered=recall_covered,
        false_positive_rate_covered=fpr_covered,
        recall_covered_interval=wilson_interval(tp, evaluated_positives, confidence=confidence)
        if evaluated_positives
        else None,
        false_positive_rate_covered_interval=wilson_interval(
            fp, evaluated_negatives, confidence=confidence
        )
        if evaluated_negatives
        else None,
    )


def per_stratum_summaries(
    rows: Iterable[Mapping[str, Any]],
    stratum_key: str | Callable[[Mapping[str, Any]], Hashable],
    *,
    truth_key: str = "truth",
    prediction_key: str = "prediction",
    confidence: float = 0.95,
) -> dict[Hashable, BinarySummary]:
    grouped: dict[Hashable, list[Mapping[str, Any]]] = {}
    for row in rows:
        key = stratum_key(row) if callable(stratum_key) else row[stratum_key]
        grouped.setdefault(key, []).append(row)
    return {
        key: summarize_binary(
            grouped[key],
            truth_key=truth_key,
            prediction_key=prediction_key,
            confidence=confidence,
        )
        for key in sorted(grouped, key=lambda item: (type(item).__name__, repr(item)))
    }


@dataclass(frozen=True, slots=True)
class CandidateDisagreement:
    both: tuple[Hashable, ...]
    only_left: tuple[Hashable, ...]
    only_right: tuple[Hashable, ...]


def _stable_candidates(values: Iterable[Hashable]) -> tuple[Hashable, ...]:
    return tuple(sorted(set(values), key=lambda item: (type(item).__name__, repr(item))))


def candidate_disagreements(
    left: Iterable[Hashable], right: Iterable[Hashable]
) -> CandidateDisagreement:
    left_set = set(left)
    right_set = set(right)
    return CandidateDisagreement(
        both=_stable_candidates(left_set & right_set),
        only_left=_stable_candidates(left_set - right_set),
        only_right=_stable_candidates(right_set - left_set),
    )


def candidate_disagreement_sets(
    candidates_by_run: Mapping[str, Iterable[Hashable]],
) -> dict[str, Any]:
    """Return deterministic exact candidate sets for any number of runs."""

    names = sorted(candidates_by_run)
    sets = {name: set(candidates_by_run[name]) for name in names}
    union = set().union(*(sets.values())) if sets else set()
    intersection = set.intersection(*(sets[name] for name in names)) if names else set()
    only = {
        name: _stable_candidates(
            sets[name] - set().union(*(sets[other] for other in names if other != name))
        )
        for name in names
    }
    pairwise: dict[str, dict[str, tuple[Hashable, ...]]] = {}
    for left, right in combinations(names, 2):
        compared = candidate_disagreements(sets[left], sets[right])
        pairwise[f"{left}|{right}"] = {
            "both": compared.both,
            "left_only": compared.only_left,
            "right_only": compared.only_right,
        }
    return {
        "union": _stable_candidates(union),
        "intersection": _stable_candidates(intersection),
        "only": only,
        "pairwise": pairwise,
    }


# Discoverable aliases used by notebooks and older evaluation scripts.
summarize_by_stratum = per_stratum_summaries
expected_alerts_per_1000 = alerts_per_1000
