from __future__ import annotations

import json
from pathlib import Path

import pytest

from strata.store import SCHEMA_VERSION, Store, config_hash


def sample_commit(sha: str = "a" * 40) -> dict:
    return {
        "sha": sha,
        "parents": [],
        "message": "sample",
        "author_name": "Author",
        "author_email": "author@example.test",
        "author_time": "2026-01-01T00:00:00+00:00",
        "committer_name": "Committer",
        "committer_email": "committer@example.test",
        "committer_time": "2026-01-01T00:00:00+00:00",
        "changed_paths": [{"status": "A", "path": "sample.txt", "old_path": None}],
        "patch_id": "b" * 40,
    }


def seed_store(store: Store) -> tuple[int, int, str, int, str]:
    repository_id = store.register_repository(
        source="/tmp/source",
        canonical_source="file:///tmp/source",
        repository_hash="c" * 64,
        mirror_path="/tmp/mirror.git",
    )
    snapshot_id = store.create_snapshot(
        repository_id,
        head_sha="a" * 40,
        default_branch="main",
    )
    configuration = {"pipeline": 1}
    configuration_hash = config_hash(configuration)
    run_id, created = store.create_or_resume_run(
        repository_id,
        snapshot_id,
        config_hash=configuration_hash,
        config=configuration,
        request={"last": 1},
    )
    assert created
    patch_hash = store.put_blob(b"patch")
    commit_id = store.upsert_commit(
        repository_id,
        sample_commit(),
        patch_blob_hash=patch_hash,
    )
    store.checkpoint_commit(
        run_id,
        commit_id,
        position=0,
        status="extracted",
    )
    return repository_id, snapshot_id, run_id, commit_id, configuration_hash


def test_wal_migrations_transactions_and_content_addressed_blobs(
    tmp_path: Path,
) -> None:
    with Store(tmp_path / "strata.db") as store:
        assert store.schema_version == SCHEMA_VERSION
        assert store.connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"

        first = store.put_blob(b"same content")
        second = store.put_blob(b"same content")
        assert first == second
        assert store.get_blob(first) == b"same content"
        with pytest.raises(ValueError):
            store.get_blob(first, max_bytes=2)

        with pytest.raises(RuntimeError), store.transaction() as connection:
            connection.execute(
                """
                    INSERT INTO repositories(
                        source, canonical_source, repository_hash, mirror_path,
                        created_at, updated_at
                    ) VALUES ('x', 'x', 'x', 'x', 'x', 'x')
                    """
            )
            raise RuntimeError("rollback")
        assert store.status()["counts"]["repositories"] == 0


def test_idempotent_stage_results_status_and_exports(tmp_path: Path) -> None:
    with Store(tmp_path / "strata.db") as store:
        repository_id, _, run_id, commit_id, configuration_hash = seed_store(store)
        triage = store.save_triage_result(
            repository_id=repository_id,
            commit_id=commit_id,
            run_id=run_id,
            config_hash=configuration_hash,
            verdict="YES",
            result={"verdict": "YES", "reason": "candidate"},
            usage={"input_tokens": 3, "output_tokens": 2, "total_tokens": 5},
            input_blob_hash=store.put_blob("triage input"),
        )
        duplicate = store.save_triage_result(
            repository_id=repository_id,
            commit_id=commit_id,
            run_id=run_id,
            config_hash=configuration_hash,
            verdict="NO",
            result={"verdict": "NO"},
        )
        assert duplicate["id"] == triage["id"]
        assert duplicate["verdict"] == "YES"

        store.save_adjudication_result(
            repository_id=repository_id,
            commit_id=commit_id,
            run_id=run_id,
            config_hash=configuration_hash,
            verdict="YES",
            result={"verdict": "YES", "finding": {"class": "injection"}},
            usage={"total_tokens": 7, "estimated_cost": 0.01},
            finding={"class": "injection"},
        )
        store.checkpoint_commit(
            run_id,
            commit_id,
            position=0,
            status="adjudicated",
            triage_status="YES",
            adjudication_status="YES",
        )
        store.update_run(
            run_id,
            status="completed",
            counters={"model_calls": 2},
            completed=True,
        )

        status = store.status(run_id)
        assert status["status"] == "completed"
        assert status["triaged"] == 1
        assert status["adjudicated"] == 1
        assert store.status()["counts"]["triage_results"] == 1
        assert store.status()["counts"]["adjudication_results"] == 1
        assert store.status()["counts"]["usage_records"] == 2

        triage_path = tmp_path / "triage.jsonl"
        findings_path = tmp_path / "findings.jsonl"
        manifests_path = tmp_path / "manifests.jsonl"
        assert store.export_triage(triage_path, run_id=run_id) == 1
        assert store.export_findings(findings_path, run_id=run_id) == 1
        assert store.export_manifests(manifests_path, run_id=run_id) == 1

        triage_row = json.loads(triage_path.read_text(encoding="utf-8"))
        finding_row = json.loads(findings_path.read_text(encoding="utf-8"))
        manifest_row = json.loads(manifests_path.read_text(encoding="utf-8"))
        assert triage_row["verdict"] == "YES"
        assert finding_row["finding"]["class"] == "injection"
        assert manifest_row["id"] == run_id


def test_changed_heads_create_distinct_snapshots(tmp_path: Path) -> None:
    with Store(tmp_path / "strata.db") as store:
        repository_id = store.register_repository(
            source="/tmp/source",
            canonical_source="file:///tmp/source",
            repository_hash="d" * 64,
            mirror_path="/tmp/mirror.git",
        )
        first = store.create_snapshot(repository_id, head_sha="1" * 40, default_branch="main")
        same = store.create_snapshot(repository_id, head_sha="1" * 40, default_branch="main")
        changed = store.create_snapshot(repository_id, head_sha="2" * 40, default_branch="main")
        assert first == same
        assert changed != first
