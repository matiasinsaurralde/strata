"""Regressions for the Tier-0 defects.

Each test names the failure it prevents, so a future refactor that reintroduces
one fails with an explanation rather than a diff.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from strata.adjudicator import (
    DEFAULT_CWE_CATALOG,
    FIX_COMPLETENESS,
    load_cwe_catalog,
    validate_adjudication,
)
from strata.contracts import FixCompleteness
from strata.importer import Importer, ImportLimits
from strata.resources import repo_root
from strata.store import Store, config_hash


class TestCweCatalog:
    """The runtime default was a 62-entry subset that rejected real CWEs."""

    def test_default_is_the_pinned_full_catalog(self) -> None:
        assert DEFAULT_CWE_CATALOG.name == "cwe-catalog-4.20.json"
        assert len(load_cwe_catalog()) > 900

    @pytest.mark.parametrize("cwe", ["CWE-1321", "CWE-444", "CWE-680", "CWE-113", "CWE-348"])
    def test_real_identifiers_from_the_gin_artifact_validate(self, cwe: str) -> None:
        """Every CWE observed on real gin findings must be accepted."""
        assert cwe in load_cwe_catalog()

    def test_catalog_records_its_upstream_source(self) -> None:
        payload = json.loads(DEFAULT_CWE_CATALOG.read_text(encoding="utf-8"))
        assert payload.get("source_sha256", "").startswith("sha256:")
        assert payload.get("version") == "4.20"


class TestFixCompleteness:
    """`multi` is the state E7 scores; folding it into `complete` erased it."""

    def test_multi_is_a_distinct_value_everywhere(self) -> None:
        assert "multi" in FIX_COMPLETENESS
        assert FixCompleteness.MULTI.value == "multi"
        for name in ("finding-v1.schema.json", "rich-label-v1.schema.json"):
            document = json.loads((repo_root() / "schemas" / name).read_text(encoding="utf-8"))
            enums = json.dumps(document)
            assert '"multi"' in enums, f"{name} still lacks the multi enum value"

    def test_single_still_aliases_to_complete(self) -> None:
        """Upstream vocabulary calls it `single`; the contract calls it `complete`."""
        payload = _minimal_yes(fix_completeness="single")
        decision = validate_adjudication(payload, repo=_FakeRepo(), candidate=_candidate())
        assert decision["fix_completeness"] == "complete"

    def test_multi_survives_validation_unchanged(self) -> None:
        payload = _minimal_yes(fix_completeness="multi")
        decision = validate_adjudication(payload, repo=_FakeRepo(), candidate=_candidate())
        assert decision["fix_completeness"] == "multi"


class TestRunCommitsPositions:
    """A sliding --since window renumbers commits; that must not be fatal."""

    def test_renumbering_a_run_does_not_raise(self, tmp_path: Path) -> None:
        with Store(tmp_path / "s.db") as store:
            repository_id = store.register_repository(
                source="/tmp/source",
                canonical_source="file:///tmp/source",
                repository_hash="c" * 64,
                mirror_path="/tmp/mirror.git",
            )
            snapshot_id = store.create_snapshot(
                repository_id, head_sha="a" * 40, default_branch="main"
            )
            configuration = {"pipeline": 1}
            run_id, _ = store.create_or_resume_run(
                repository_id,
                snapshot_id,
                config_hash=config_hash(configuration),
                config=configuration,
                request={"since": "1 month ago"},
            )
            ids = [
                store.upsert_commit(repository_id, _StubCommit(sha), patch_blob_hash=None)
                for sha in ("a" * 40, "b" * 40)
            ]
            store.checkpoint_commit(run_id, ids[0], position=0, status="extracted")
            store.checkpoint_commit(run_id, ids[1], position=1, status="extracted")
            # The --since window slid: the oldest commit dropped out and the
            # second one is now first. Under v1 this raised IntegrityError and
            # left the run permanently unresumable.
            store.checkpoint_commit(run_id, ids[1], position=0, status="extracted")

    def test_schema_dropped_the_position_uniqueness(self, tmp_path: Path) -> None:
        with Store(tmp_path / "s.db") as store:
            sql = store.connection.execute(
                "SELECT sql FROM sqlite_master WHERE name='run_commits'"
            ).fetchone()[0]
            assert "UNIQUE(run_id, position)" not in sql
            assert store.schema_version >= 2


class TestBudgetSlots:
    """Budgets were checked between batches, so N workers each overspent."""

    @pytest.fixture
    def make_importer(self, tmp_path: Path):
        stores: list[Store] = []

        def factory(limits: ImportLimits, workers: int) -> Importer:
            store = Store(tmp_path / f"s{len(stores)}.db")
            stores.append(store)
            return Importer(
                store,
                triage=lambda _c: None,
                adjudicator=lambda _c, _r: None,
                limits=limits,
                max_workers=workers,
            )

        yield factory
        for store in stores:
            store.close()

    def test_cost_headroom_narrows_the_batch(self, make_importer) -> None:
        importer = make_importer(ImportLimits(max_cost=10.0), workers=8)
        # 9 calls at $1.00 each: only ~1 more fits, not 8.
        counters = {"model_calls": 9, "tokens": 0, "estimated_cost": 9.0}
        assert importer._available_call_slots(counters) == 1

    def test_token_headroom_narrows_the_batch(self, make_importer) -> None:
        importer = make_importer(ImportLimits(max_tokens=1000), workers=8)
        counters = {"model_calls": 9, "tokens": 900, "estimated_cost": 0.0}
        assert importer._available_call_slots(counters) == 1

    def test_exhausted_budget_yields_no_slots(self, make_importer) -> None:
        importer = make_importer(ImportLimits(max_cost=10.0), workers=8)
        counters = {"model_calls": 10, "tokens": 0, "estimated_cost": 10.0}
        assert importer._available_call_slots(counters) == 0

    def test_ample_headroom_keeps_full_concurrency(self, make_importer) -> None:
        importer = make_importer(ImportLimits(max_cost=1000.0), workers=8)
        counters = {"model_calls": 4, "tokens": 0, "estimated_cost": 4.0}
        assert importer._available_call_slots(counters) == 8

    def test_first_call_is_admitted_to_measure_with(self, make_importer) -> None:
        importer = make_importer(ImportLimits(max_cost=10.0), workers=8)
        counters = {"model_calls": 0, "tokens": 0, "estimated_cost": 0.0}
        assert importer._available_call_slots(counters) == 1

    def test_unbounded_limits_do_not_restrict(self, make_importer) -> None:
        importer = make_importer(ImportLimits(), workers=8)
        counters = {"model_calls": 100, "tokens": 10**9, "estimated_cost": 10**6}
        assert importer._available_call_slots(counters) == 8


# --- helpers -------------------------------------------------------------

_COMMIT = "a" * 40
_PARENT = "b" * 40
_PATH = "src/handler.go"
_SOURCE = "func handle(v string) string {\n\treturn escape(v)\n}\n"
_CLAIMS = [
    "reachability_delta",
    "failure_containment",
    "root_cause",
    "attacker_preconditions",
    "impact",
    "fix_effect",
    "l0_class",
    "cwe_id",
    "severity",
    "affected_paths",
    "fix_completeness",
]


class _FakeRepo:
    def read_range(
        self, revision: str, path: str, start_line: int, end_line: int, **_: Any
    ) -> str:
        return "".join(_SOURCE.splitlines(keepends=True)[start_line - 1 : end_line])

    def resolve_revision(self, revision: str) -> str:
        return revision


def _candidate() -> dict[str, Any]:
    return {
        "repository": "https://example.test/o/r",
        "commit_sha": _COMMIT,
        "parent_sha": _PARENT,
        "message": "escape output",
        "diff": "+\treturn escape(v)",
    }


def _minimal_yes(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "verdict": "YES",
        "confidence": "high",
        "rationale": "Output encoding was added on the reflected path.",
        "root_cause": "Untrusted markup was returned without output encoding.",
        "attacker_preconditions": "An attacker controls v.",
        "impact": "Script execution in another user's browser.",
        "fix_effect": "The value is encoded before it is returned.",
        "l0_class": "injection",
        "cwe_id": "CWE-79",
        "severity": {"level": "high", "source": "model_estimate"},
        "affected_paths": [_PATH],
        "fix_completeness": "complete",
        "invariant": None,
        "reachability_delta": {
            "verdict": "narrows",
            "before": "Untrusted markup reached the response unencoded.",
            "after": "The value is encoded before it is returned.",
        },
        "failure_containment": "n/a",
        "evidence": [
            {
                "revision": "commit",
                "revision_sha": _COMMIT,
                "path": _PATH,
                "start_line": 2,
                "end_line": 2,
                "quoted_span": "return escape(v)",
                "supports": _CLAIMS,
            }
        ],
    }
    payload.update(overrides)
    return payload


class _StubCommit:
    """Minimal GitCommit-shaped record for store round-trips."""

    def __init__(self, sha: str) -> None:
        self.sha = sha

    def to_dict(self, *, include_patch: bool = True) -> dict[str, Any]:
        return {
            "sha": self.sha,
            "parents": [_PARENT],
            "parent_sha": _PARENT,
            "message": "m",
            "author_name": "a",
            "author_email": "a@example.test",
            "author_time": "2026-01-01T00:00:00Z",
            "committer_name": "a",
            "committer_email": "a@example.test",
            "committer_time": "2026-01-01T00:00:00Z",
            "changed_paths": [],
            "patch_id": None,
            "is_root": False,
            "is_merge": False,
        }
