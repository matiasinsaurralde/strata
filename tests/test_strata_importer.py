from __future__ import annotations

import json
import os
import subprocess
import threading
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from strata.__main__ import main as cli_main
from strata.importer import Importer, ImportLimits
from strata.store import Store


def git(repository: Path, *arguments: str) -> str:
    environment = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Test Author",
        "GIT_AUTHOR_EMAIL": "author@example.test",
        "GIT_COMMITTER_NAME": "Test Committer",
        "GIT_COMMITTER_EMAIL": "committer@example.test",
    }
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
        timeout=10,
    )
    return result.stdout.strip()


def commit_all(repository: Path, message: str) -> str:
    git(repository, "add", "-A")
    git(repository, "commit", "-m", message)
    return git(repository, "rev-parse", "HEAD")


@pytest.fixture
def import_repository_source(tmp_path: Path) -> Path:
    repository = tmp_path / "source"
    repository.mkdir()
    subprocess.run(
        ["git", "-C", str(repository), "init", "-b", "main"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    )
    (repository / "app.txt").write_text("safe root\n", encoding="utf-8")
    commit_all(repository, "root")
    (repository / "app.txt").write_text("safe root\nSECURITY candidate\n", encoding="utf-8")
    commit_all(repository, "security fix")
    (repository / "notes.txt").write_text("ordinary notes\n", encoding="utf-8")
    commit_all(repository, "ordinary")
    return repository


class FakeTriage:
    def __init__(self, *, tokens: int = 3) -> None:
        self.calls: list[str] = []
        self.tokens = tokens
        self._lock = threading.Lock()

    def __call__(self, commit: Mapping[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.calls.append(str(commit["sha"]))
        assert commit["commit_sha"] == commit["sha"]
        assert commit["diff"] == commit["patch"] == commit["raw_diff"]
        candidate = "SECURITY" in str(commit["patch"])
        return {
            "verdict": "YES" if candidate else "NO",
            "usage": {"total_tokens": self.tokens, "estimated_cost": 0.001},
        }


class FakeAdjudicator:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def __call__(self, commit: Mapping[str, Any], repository: Any) -> dict[str, Any]:
        self.calls.append(str(commit["sha"]))
        source = repository.read_blob(commit["sha"], "app.txt").decode("utf-8")
        assert "SECURITY" in source
        return {
            "verdict": "YES",
            "finding": {
                "class": "injection",
                "affected_paths": ["app.txt"],
            },
            "usage": {"total_tokens": 5, "estimated_cost": 0.01},
        }


def test_end_to_end_rerun_changed_head_dry_run_and_exports(
    import_repository_source: Path,
    tmp_path: Path,
) -> None:
    triage = FakeTriage()
    adjudicator = FakeAdjudicator()
    with Store(tmp_path / "state" / "strata.db") as store:
        importer = Importer(
            store,
            triage=triage,
            adjudicator=adjudicator,
            max_workers=2,
        )
        first = importer.import_repository(import_repository_source, last=10)
        assert first.status == "completed"
        assert len(triage.calls) == 3
        assert len(adjudicator.calls) == 1
        assert first.counters["model_calls"] == 4
        assert first.counters["tokens"] == 14

        rerun = importer.import_repository(import_repository_source, last=10)
        assert rerun.run_id == first.run_id
        assert len(triage.calls) == 3
        assert len(adjudicator.calls) == 1

        (import_repository_source / "later.txt").write_text("later\n", encoding="utf-8")
        commit_all(import_repository_source, "changed head")
        changed = importer.import_repository(import_repository_source, last=10)
        assert changed.run_id != first.run_id
        assert changed.head_sha != first.head_sha
        assert len(triage.calls) == 4
        assert len(adjudicator.calls) == 1
        assert changed.counters["reused_triage"] == 3
        assert changed.counters["reused_adjudication"] == 1
        assert store.status()["counts"]["snapshots"] == 2

        dry_run = importer.import_repository(
            import_repository_source,
            last=2,
            dry_run=True,
        )
        assert dry_run.status == "dry_run"
        assert dry_run.planned_commits == 2
        assert len(triage.calls) == 4
        assert len(adjudicator.calls) == 1

        triage_path = tmp_path / "triage.jsonl"
        findings_path = tmp_path / "findings.jsonl"
        assert store.export_triage(triage_path, run_id=changed.run_id) == 4
        assert store.export_findings(findings_path, run_id=changed.run_id) == 1
        finding = json.loads(findings_path.read_text(encoding="utf-8"))
        assert finding["finding"]["class"] == "injection"


class MethodOnlyAdjudicator:
    def __init__(self) -> None:
        self.calls = 0

    def adjudicate(self, _: Mapping[str, Any]) -> dict[str, str]:
        self.calls += 1
        return {"verdict": "NO"}


def test_concurrent_triage_contract_and_method_adjudicator_integration(
    import_repository_source: Path,
    tmp_path: Path,
) -> None:
    from strata.contracts import ProviderSettingsV1
    from strata.triage import TriageRunner

    runner = TriageRunner(
        lambda request: "YES" if "SECURITY" in request.user_prompt else "NO",
        provider=ProviderSettingsV1(provider="fake", model="fake-model"),
    )
    adjudicator = MethodOnlyAdjudicator()
    with Store(tmp_path / "contracts" / "strata.db") as store:
        summary = Importer(
            store,
            triage=runner,
            adjudicator=adjudicator,
        ).import_repository(import_repository_source, last=3)
        assert summary.status == "completed"
        assert summary.counters["triage_calls"] == 3
        assert summary.counters["candidates"] == 1
        assert adjudicator.calls == 1


class InterruptingTriage:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, _: Mapping[str, Any]) -> dict[str, Any]:
        self.calls += 1
        if self.calls == 1:
            raise KeyboardInterrupt
        return {"verdict": "NO"}


def test_resume_after_interruption(
    import_repository_source: Path,
    tmp_path: Path,
) -> None:
    triage = InterruptingTriage()
    with Store(tmp_path / "strata.db") as store:
        importer = Importer(
            store,
            triage=triage,
            adjudicator=lambda _: {"verdict": "NO"},
        )
        with pytest.raises(KeyboardInterrupt):
            importer.import_repository(import_repository_source, last=3)
        run_id = store.status()["runs"][0]["id"]
        interrupted = store.status(run_id)
        assert interrupted["status"] == "interrupted"
        original_head = interrupted["head_sha"]

        (import_repository_source / "after-interrupt.txt").write_text(
            "new head\n", encoding="utf-8"
        )
        commit_all(import_repository_source, "head changed while interrupted")

        resumed = importer.resume(run_id)
        assert resumed.status == "completed"
        assert resumed.head_sha == original_head
        assert triage.calls == 4
        assert resumed.counters["triage_calls"] == 3
        assert store.status()["counts"]["snapshots"] == 2


@pytest.mark.parametrize(
    ("limits", "expected_calls", "reason"),
    [
        (ImportLimits(max_calls=2), 2, "max_calls"),
        (ImportLimits(max_tokens=1), 1, "max_tokens"),
        (ImportLimits(max_candidates=0), 3, "max_candidates"),
    ],
)
def test_per_run_budgets(
    import_repository_source: Path,
    tmp_path: Path,
    limits: ImportLimits,
    expected_calls: int,
    reason: str,
) -> None:
    triage = FakeTriage(tokens=5)
    adjudicator = FakeAdjudicator()
    database = tmp_path / reason / "strata.db"
    with Store(database) as store:
        summary = Importer(
            store,
            triage=triage,
            adjudicator=adjudicator,
            limits=limits,
        ).import_repository(import_repository_source, last=3)
        assert summary.status == "budget_exhausted"
        assert summary.budget_reason == reason
        assert len(triage.calls) == expected_calls
        assert not adjudicator.calls


def test_cli_dry_run_status_and_export(
    import_repository_source: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / "cli" / "strata.db"
    assert (
        cli_main(
            [
                "import",
                "--repo",
                str(import_repository_source),
                "--last",
                "2",
                "--db",
                str(database),
                "--dry-run",
            ]
        )
        == 0
    )
    imported = json.loads(capsys.readouterr().out)
    assert imported["status"] == "dry_run"

    assert cli_main(["status", "--db", str(database)]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["counts"]["pipeline_runs"] == 1

    output = tmp_path / "exports"
    assert (
        cli_main(
            [
                "export",
                "--db",
                str(database),
                "--kind",
                "all",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert (output / "triage.jsonl").exists()
    assert (output / "findings.jsonl").exists()
    assert (output / "manifests.jsonl").exists()
