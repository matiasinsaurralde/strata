"""Tests for the ``scan`` command wiring and repository grounding.

These cover the two operational knobs the CLI exposes on top of the scan
pipeline: a configurable network timeout and the ability to ground a scan on an
existing local checkout instead of cloning it.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from strata.__main__ import _scan_config_from_arguments, _scan_target, build_parser
from strata.git_repo import DEFAULT_FETCH_TIMEOUT
from strata.llm import ChatResponse, TokenUsage
from strata.scan import ScanConfig, scan_repository


def _scan_arguments(*extra: str) -> Any:
    return build_parser().parse_args(
        ["scan", "--repo", "https://example.test/owner/repo.git", *extra]
    )


def _parse_scan(*argv: str) -> Any:
    return build_parser().parse_args(["scan", *argv])


# --- configurable fetch timeout -----------------------------------------


def test_scan_config_defaults_to_120s_fetch_timeout() -> None:
    assert ScanConfig().fetch_timeout == DEFAULT_FETCH_TIMEOUT == 120.0


def test_scan_cli_defaults_and_overrides_fetch_timeout() -> None:
    assert _scan_config_from_arguments(_scan_arguments()).fetch_timeout == 120.0
    overridden = _scan_config_from_arguments(_scan_arguments("--fetch-timeout", "450"))
    assert overridden.fetch_timeout == 450.0


@pytest.mark.parametrize("value", ["0", "-5", "abc"])
def test_scan_cli_rejects_non_positive_fetch_timeout(value: str) -> None:
    with pytest.raises(SystemExit):
        _scan_arguments("--fetch-timeout", value)


def test_scan_repository_threads_fetch_timeout_into_git_repository(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class _StopFetch(RuntimeError):
        pass

    class _SpyRepository:
        def __init__(self, source: str, **kwargs: Any) -> None:
            captured["source"] = source
            captured.update(kwargs)

        def fetch(self) -> None:
            # Halt before the pipeline needs a real model client.
            raise _StopFetch

    monkeypatch.setattr("strata.scan.GitRepository", _SpyRepository)
    with pytest.raises(_StopFetch):
        scan_repository(
            "https://example.test/owner/repo.git",
            client=object(),
            config=ScanConfig(fetch_timeout=321.0),
        )
    assert captured["fetch_timeout"] == 321.0


# --- repository target resolution ---------------------------------------


def test_scan_target_accepts_the_positional_form() -> None:
    assert _scan_target(_parse_scan(".")) == "."
    assert _scan_target(_parse_scan("/path/to/repo")) == "/path/to/repo"


def test_scan_target_accepts_the_repo_flag_form() -> None:
    assert _scan_target(_parse_scan("--repo", "https://example.test/o/r.git")) == (
        "https://example.test/o/r.git"
    )


def test_scan_target_allows_matching_positional_and_flag() -> None:
    assert _scan_target(_parse_scan("x", "--repo", "x")) == "x"


def test_scan_target_rejects_a_missing_repository() -> None:
    with pytest.raises(ValueError, match="requires a repository"):
        _scan_target(_parse_scan())


def test_scan_target_rejects_conflicting_repositories() -> None:
    with pytest.raises(ValueError, match="once"):
        _scan_target(_parse_scan("here", "--repo", "there"))


# --- grounding a scan on a local checkout (offline end-to-end) -----------

_GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "Test",
    "GIT_AUTHOR_EMAIL": "test@example.test",
    "GIT_COMMITTER_NAME": "Test",
    "GIT_COMMITTER_EMAIL": "test@example.test",
}


def _git_out(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
        env=_GIT_ENV,
        timeout=15,
    )
    return result.stdout.strip()


def _init_local_repo(path: Path) -> None:
    path.mkdir()
    subprocess.run(
        ["git", "-C", str(path), "init", "-b", "main"],
        check=True,
        capture_output=True,
        timeout=15,
    )
    source = path / "app.py"
    source.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    _git_out(path, "add", "-A")
    _git_out(path, "commit", "-m", "add app")
    source.write_text("def add(a, b):\n    return a + b  # note\n", encoding="utf-8")
    _git_out(path, "add", "-A")
    _git_out(path, "commit", "-m", "annotate app")


class _FakeClient:
    """Offline stand-in that rejects every commit at triage.

    The verdict keeps the pipeline from ever reaching a real model call while
    still exercising git enumeration, extraction, the prefilter and triage.
    """

    def __init__(self) -> None:
        self.config = SimpleNamespace(
            model="fake-model",
            endpoint="https://fake.invalid/v1",
            api_key="fake-key",
            uses_max_completion_tokens=False,
            supports_temperature=True,
        )
        self.calls = 0

    def complete(self, messages: Any, **kwargs: Any) -> ChatResponse:
        self.calls += 1
        return ChatResponse(
            content="NO",
            tool_calls=(),
            usage=TokenUsage(prompt_tokens=5, completion_tokens=1, total_tokens=6),
            response_id="fake-1",
        )


def test_scan_repository_grounds_local_repo_without_cloning(tmp_path: Path) -> None:
    source = tmp_path / "repo"
    _init_local_repo(source)
    head_before = _git_out(source, "rev-parse", "HEAD")
    refs_before = _git_out(source, "for-each-ref")
    cache = tmp_path / "cache"

    client = _FakeClient()
    outcome = scan_repository(
        str(source),
        client=client,
        config=ScanConfig(last=10, fetch_timeout=5.0),
        cache_root=str(cache),
    )

    assert outcome.context is not None
    # No mirror was created: the scan read the checkout in place.
    assert not cache.exists()
    # The scanned repository was not mutated in any way.
    assert _git_out(source, "rev-parse", "HEAD") == head_before
    assert _git_out(source, "for-each-ref") == refs_before
    assert _git_out(source, "status", "--porcelain") == ""
    # The pipeline actually walked the commits and ran triage over them.
    funnel = outcome.funnel()
    assert funnel["prefilter"]["seen"] == 2
    assert client.calls >= 1
