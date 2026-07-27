from __future__ import annotations

import math
from copy import deepcopy
from datetime import UTC, datetime

import pytest

from strata_eval import (
    Split,
    alerts_per_1000,
    assignment_map,
    build_grouped_manifest,
    build_temporal_manifest,
    candidate_disagreement_sets,
    candidate_disagreements,
    dataset_content_hash,
    expected_cascade_cost,
    grouped_holdout_assignments,
    linked_record_groups,
    per_stratum_summaries,
    precision_at_prevalence,
    summarize_binary,
    temporal_holdout_assignments,
    wilson_interval,
    zero_event_upper_bound,
)


def test_wilson_interval_and_exact_zero_event_bound() -> None:
    interval = wilson_interval(50, 100)
    assert interval.point == 0.5
    assert interval.lower == pytest.approx(0.4038, abs=0.0002)
    assert interval.upper == pytest.approx(0.5962, abs=0.0002)
    low, high = interval
    assert (low, high) == (interval.lower, interval.upper)

    exact = zero_event_upper_bound(100)
    assert exact == pytest.approx(1 - 0.05 ** (1 / 100))
    assert exact < 0.03


def test_prevalence_corrected_operational_metrics() -> None:
    precision = precision_at_prevalence(0.95, 0.01, 0.015)
    expected = (0.015 * 0.95) / (0.015 * 0.95 + 0.985 * 0.01)
    assert precision == pytest.approx(expected)
    assert alerts_per_1000(0.95, 0.01, 0.015) == pytest.approx(24.1)
    assert precision_at_prevalence(0, 0, 0.01) is None
    assert expected_cascade_cost(
        triage_cost_per_commit=0.002,
        candidate_rate=0.02,
        adjudicator_cost_per_candidate=0.2,
    ) == pytest.approx(0.006)
    assert expected_cascade_cost(
        triage_cost_per_commit=0.002,
        adjudicator_cost_per_candidate=0.2,
        true_positive_rate=0.95,
        false_positive_rate=0.01,
        prevalence=0.015,
    ) == pytest.approx(0.002 + 0.0241 * 0.2)


def test_binary_summary_keeps_errors_out_of_no_bucket() -> None:
    rows = [
        {"truth": True, "prediction": "YES"},
        {"truth": True, "prediction": "NO"},
        {"truth": True, "prediction": None},
        {"truth": False, "prediction": "YES"},
        {"truth": False, "prediction": "NO"},
        {"truth": False, "prediction": "ABSTAIN"},
    ]
    summary = summarize_binary(rows)
    assert summary.total == 6
    assert summary.evaluated == 4
    assert summary.false_negatives == 1
    assert summary.uncovered_positives == 1
    assert summary.uncovered_negatives == 1
    assert summary.recall == pytest.approx(1 / 3)
    assert summary.false_positive_rate == pytest.approx(1 / 3)
    assert summary.coverage == pytest.approx(2 / 3)


def test_duplicate_backports_and_abstain_labels_are_excluded() -> None:
    summary = summarize_binary(
        [
            {"truth": "fix", "prediction": "YES"},
            {"truth": "backport", "prediction": "YES"},
            {"truth": "ABSTAIN", "prediction": "NO"},
            {"truth": "other", "prediction": "NO"},
        ]
    )
    assert summary.total == 4
    assert summary.eligible == 2
    assert summary.excluded == 2
    assert summary.coverage == 1.0


def test_per_stratum_summaries_are_deterministic() -> None:
    rows = [
        {"kind": "quiet", "truth": True, "prediction": "YES"},
        {"kind": "announced", "truth": False, "prediction": "NO"},
        {"kind": "quiet", "truth": True, "prediction": None},
    ]
    summaries = per_stratum_summaries(rows, "kind")
    assert list(summaries) == ["announced", "quiet"]
    assert summaries["quiet"].recall == 0.5
    assert summaries["quiet"].coverage == 0.5


def test_candidate_disagreement_sets_are_exact_and_sorted() -> None:
    pair = candidate_disagreements({"b", "a"}, {"b", "c"})
    assert pair.both == ("b",)
    assert pair.only_left == ("a",)
    assert pair.only_right == ("c",)
    result = candidate_disagreement_sets({"z-run": {"a", "b"}, "a-run": {"b", "c"}})
    assert result["union"] == ("a", "b", "c")
    assert result["intersection"] == ("b",)
    assert result["only"]["a-run"] == ("c",)
    assert result["only"]["z-run"] == ("a",)
    assert list(result["pairwise"]) == ["a-run|z-run"]


def linked_rows():
    return [
        {
            "id": "a",
            "advisory_id": "ADV-1",
            "patch_group_id": "P-1",
            "committed_at": "2024-01-01T00:00:00Z",
        },
        {
            "id": "b",
            "advisory_id": "ADV-1",
            "committed_at": "2024-02-01T00:00:00Z",
        },
        {
            "id": "c",
            "patch_group_id": "P-1",
            "committed_at": "2024-03-01T00:00:00Z",
        },
        {
            "id": "d",
            "advisory_id": "ADV-2",
            "committed_at": "2025-01-01T00:00:00Z",
        },
        {
            "id": "e",
            "advisory_id": "ADV-2",
            "committed_at": "2025-02-01T00:00:00Z",
        },
    ]


def test_linked_advisory_and_patch_groups_are_transitive() -> None:
    groups = linked_record_groups(linked_rows())
    member_sets = {group.record_ids for group in groups}
    assert ("a", "b", "c") in member_sets
    assert ("d", "e") in member_sets

    assignments = grouped_holdout_assignments(
        reversed(linked_rows()), holdout_fraction=0.5, seed="fixed"
    )
    split_by_id = assignment_map(assignments)
    assert split_by_id["a"] is split_by_id["b"] is split_by_id["c"]
    assert split_by_id["d"] is split_by_id["e"]
    repeat = grouped_holdout_assignments(linked_rows(), holdout_fraction=0.5, seed="fixed")
    assert assignments == repeat


def test_temporal_holdout_uses_newest_whole_group() -> None:
    assignments = temporal_holdout_assignments(linked_rows(), holdout_fraction=0.4)
    split_by_id = assignment_map(assignments)
    assert split_by_id["d"] is Split.HOLDOUT
    assert split_by_id["e"] is Split.HOLDOUT
    assert split_by_id["a"] is Split.DEVELOPMENT
    assert split_by_id["b"] is split_by_id["a"]
    assert split_by_id["c"] is split_by_id["a"]

    cutoff = assignment_map(
        temporal_holdout_assignments(linked_rows(), cutoff="2025-01-15T00:00:00Z")
    )
    # Group timestamp is its newest member; the entire advisory stays together.
    assert cutoff["d"] is cutoff["e"] is Split.HOLDOUT


def test_manifest_builders_are_immutable_and_stably_identified() -> None:
    rows = linked_rows()
    before = deepcopy(rows)
    created_a = datetime(2026, 1, 1, tzinfo=UTC)
    created_b = datetime(2026, 2, 1, tzinfo=UTC)
    first = build_grouped_manifest(
        rows,
        dataset_id="dev-v1",
        seed="fixed",
        created_at=created_a,
    )
    second = build_grouped_manifest(
        reversed(rows),
        dataset_id="dev-v1",
        seed="fixed",
        created_at=created_b,
    )
    assert rows == before
    assert first.dataset_hash == second.dataset_hash
    assert first.manifest_id == second.manifest_id
    assert first.created_at != second.created_at
    assert first.to_json() == first.to_json()
    assert first.to_dict()["counts"]["development"] + first.to_dict()["counts"][
        "holdout"
    ] == len(rows)

    temporal = build_temporal_manifest(
        rows,
        dataset_id="dev-v1",
        holdout_fraction=0.4,
        created_at=created_a,
    )
    assert temporal.method.value == "temporal"
    assert temporal.seed is None


def test_dataset_hash_is_order_independent_and_validates_inputs() -> None:
    rows = linked_rows()
    assert dataset_content_hash(rows) == dataset_content_hash(reversed(rows))
    assert dataset_content_hash(rows).startswith("sha256:")
    with pytest.raises(ValueError):
        wilson_interval(2, 1)
    with pytest.raises(ValueError):
        zero_event_upper_bound(0)
    with pytest.raises(ValueError):
        expected_cascade_cost(
            triage_cost_per_commit=0,
            adjudicator_cost_per_candidate=1,
            candidate_rate=math.nan,
        )
