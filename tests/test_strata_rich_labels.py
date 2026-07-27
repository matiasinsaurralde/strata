from __future__ import annotations

from pathlib import Path

from strata_eval.labeling.rich_labels import (
    append_adjudication,
    append_rich_label,
    build_candidate_queue,
    build_rich_pilot_queue,
    disagreement,
    disagreement_report,
    load_latest_labels,
    read_rich_labels,
    validate_rich_label,
)

SHA1 = "1" * 40
SHA2 = "2" * 40
SHA3 = "3" * 40


def _label(sha: str, annotator: str, verdict: str, **extra) -> dict:
    return {
        "repository": "owner/repo",
        "commit_sha": sha,
        "annotator_id": annotator,
        "verdict": verdict,
        "label_version": 1,
        "rationale": "independent review",
        **extra,
    }


def _positive_fields(sha: str) -> dict:
    return {
        "status": "frozen",
        "role": "fix",
        "rationale": "The commit closes an attacker-reachable injection path.",
        "root_cause": "Untrusted input reached an interpreter without validation.",
        "attacker_preconditions": "An unauthenticated attacker controls the input.",
        "impact": "The attacker can execute injected operations.",
        "fix_effect": "The patch validates the value before interpretation.",
        "l0_class": "injection",
        "cwe_id": "CWE-74",
        "severity": {"level": "high", "source": "human"},
        "affected_paths": ["app.go"],
        "evidence": [
            {
                "revision": "commit",
                "revision_sha": sha,
                "path": "app.go",
                "start_line": 1,
                "end_line": 1,
                "quoted_span": "validate(input)",
                "supports": [
                    "root_cause",
                    "attacker_preconditions",
                    "impact",
                    "fix_effect",
                    "l0_class",
                    "cwe_id",
                    "severity",
                    "affected_paths",
                    "fix_completeness",
                ],
            }
        ],
        "fix_completeness": "complete",
    }


def test_append_only_latest_wins_per_independent_annotator(tmp_path: Path) -> None:
    path = tmp_path / "rich.jsonl"
    first = append_rich_label(path, _label(SHA1, "alice", "NO"))
    append_rich_label(path, _label(SHA1, "bob", "YES", **{"class": "injection"}))
    latest_alice = append_rich_label(
        path,
        _label(SHA1, "alice", "ABSTAIN", abstain_reason="insufficient context"),
    )
    rows = read_rich_labels(path)
    assert len(rows) == 3
    assert rows[0]["record_id"] == first["record_id"]
    latest = load_latest_labels(path)
    assert latest[("owner/repo", SHA1, "alice")]["record_id"] == latest_alice["record_id"]
    assert latest[("owner/repo", SHA1, "bob")]["verdict"] == "YES"


def test_disagreement_and_adjudication_resolution(tmp_path: Path) -> None:
    path = tmp_path / "rich.jsonl"
    alice = append_rich_label(path, _label(SHA1, "alice", "YES", **{"class": "injection"}))
    bob = append_rich_label(path, _label(SHA1, "bob", "NO", role="other"))
    details = disagreement([alice, bob])
    assert details["has_disagreement"] is True
    assert details["needs_adjudication"] is True
    assert "verdict" in details["disagreed_fields"]

    append_adjudication(
        path,
        "owner/repo",
        SHA1,
        "carol",
        {"verdict": "YES", **_positive_fields(SHA1)},
        [alice, bob],
        notes="Repository evidence resolves the disagreement.",
    )
    report = disagreement_report(path)
    assert report[0]["adjudicated"] is True
    assert report[0]["unresolved"] is False


def test_frozen_rich_label_has_stable_valid_contract(tmp_path: Path) -> None:
    record = append_rich_label(
        tmp_path / "rich.jsonl",
        _label(SHA1, "alice", "YES", **_positive_fields(SHA1)),
    )

    assert validate_rich_label(record, require_frozen=True) == record
    assert record["severity"] == {
        "level": "high",
        "source": "human",
        "score": None,
        "vector": None,
    }


def test_candidate_queue_tracks_missing_annotators() -> None:
    commits = [
        {"repository": "owner/repo", "commit_sha": SHA1, "subject": "one"},
        {"repository": "owner/repo", "commit_sha": SHA2, "subject": "two"},
        {"repository": "owner/repo", "commit_sha": SHA3, "subject": "three"},
    ]
    triage = [
        {"repository": "owner/repo", "commit_sha": SHA1, "verdict": "YES"},
        {"repository": "owner/repo", "commit_sha": SHA2, "verdict": "NO"},
        {
            "repository": "owner/repo",
            "commit_sha": SHA3,
            "verdict": None,
            "error": "backend",
        },
    ]
    labels = [_label(SHA1, "alice", "YES")]
    queue = build_candidate_queue(
        commits,
        triage,
        labels,
        annotators=("alice", "bob"),
    )
    assert [row["commit_sha"] for row in queue] == [SHA1, SHA3]
    assert queue[0]["queue"]["annotators_missing"] == ["bob"]
    assert queue[1]["queue"]["reason"] == "triage_error"


def test_rich_pilot_queue_is_deterministic_and_balanced() -> None:
    candidates = [
        {
            "repository": "owner/repo",
            "commit_sha": SHA1,
            "role": "fix",
        },
        {
            "repository": "owner/repo",
            "commit_sha": SHA2,
            "role": "other",
        },
        {
            "repository": "owner/repo",
            "commit_sha": SHA3,
        },
    ]
    first = build_rich_pilot_queue(candidates, size=2, positive_fraction=0.5, seed="fixed")
    second = build_rich_pilot_queue(
        reversed(candidates), size=2, positive_fraction=0.5, seed="fixed"
    )
    assert [row["commit_sha"] for row in first] == [row["commit_sha"] for row in second]
    assert {row["pilot"]["stratum"] for row in first} == {
        "positive",
        "hard_negative",
    }
