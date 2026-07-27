"""Strata evaluation harness.

This package *measures* the pipeline in :mod:`strata`. The dependency direction
is one-way and enforced by ``tests/test_layering.py``: ``strata_eval`` may
import ``strata``, but ``strata`` must never import ``strata_eval``. That
boundary keeps the Go migration surface (:mod:`strata`) free of evaluation-only
concerns — GHSA ingest, human labelling, bootstrap intervals.
"""

from .manifest import (
    EvaluationManifestV1,
    build_grouped_manifest,
    build_temporal_manifest,
)
from .metrics import (
    BinarySummary,
    ConfidenceInterval,
    alerts_per_1000,
    candidate_disagreement_sets,
    candidate_disagreements,
    candidate_rate_at_prevalence,
    clopper_pearson_zero_upper,
    coverage_corrected_rate,
    expected_cascade_cost,
    per_stratum_summaries,
    precision_at_prevalence,
    precision_interval_at_prevalence,
    summarize_binary,
    wilson_interval,
    zero_event_upper_bound,
)
from .splits import (
    Split,
    assignment_map,
    dataset_content_hash,
    grouped_holdout_assignments,
    linked_record_groups,
    temporal_holdout_assignments,
)

__all__ = [
    "BinarySummary",
    "ConfidenceInterval",
    "EvaluationManifestV1",
    "Split",
    "alerts_per_1000",
    "assignment_map",
    "build_grouped_manifest",
    "build_temporal_manifest",
    "candidate_disagreement_sets",
    "candidate_disagreements",
    "candidate_rate_at_prevalence",
    "clopper_pearson_zero_upper",
    "coverage_corrected_rate",
    "dataset_content_hash",
    "expected_cascade_cost",
    "grouped_holdout_assignments",
    "linked_record_groups",
    "per_stratum_summaries",
    "precision_at_prevalence",
    "precision_interval_at_prevalence",
    "summarize_binary",
    "temporal_holdout_assignments",
    "wilson_interval",
    "zero_event_upper_bound",
]
