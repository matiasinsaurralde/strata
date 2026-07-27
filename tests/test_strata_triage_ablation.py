from __future__ import annotations

from pathlib import Path

from strata.contracts import InputProfile, ProviderSettingsV1
from strata.diffing import InputLimits
from strata.triage import TriageRunner
from strata_eval.ablation import (
    AblationSettings,
    DecisionCache,
    build_matrix_report,
    repository_block_bootstrap,
    run_profile,
)

DIFF = """\
diff --git a/auth.py b/auth.py
--- a/auth.py
+++ b/auth.py
@@ -1 +1,2 @@
 allow()
+check()
"""


def _rows() -> list[dict[str, object]]:
    return [
        {
            "id": "example.test/o/r@a",
            "repository": "example.test/o/r",
            "commit_sha": "a" * 40,
            "parent_sha": "b" * 40,
            "subject": "fix",
            "message": "fix",
            "message_class": "quiet",
            "role": "fix",
            "diff": DIFF + "+security-marker\n",
        },
        {
            "id": "example.test/o/r@c",
            "repository": "example.test/o/r",
            "commit_sha": "c" * 40,
            "parent_sha": "d" * 40,
            "subject": "refactor",
            "message": "refactor",
            "message_class": "quiet",
            "role": "other",
            "diff": DIFF,
        },
    ]


def _runner(backend) -> TriageRunner:
    return TriageRunner(
        backend,
        provider=ProviderSettingsV1(provider="fake", model="test"),
    )


def test_profile_run_is_cached_and_report_selects_qualifying_profile(
    tmp_path: Path,
) -> None:
    calls = 0

    def backend(request):
        nonlocal calls
        calls += 1
        return "YES" if "security-marker" in request.user_prompt else "NO"

    rows = _rows()
    cache = DecisionCache(tmp_path / "cache")
    decisions = run_profile(
        rows,
        InputProfile.D0,
        _runner(backend),
        cache=cache,
        limits=InputLimits(max_input_bytes=200_000),
        workers=2,
    )
    assert calls == 2

    cached = run_profile(
        rows,
        InputProfile.D0,
        _runner(lambda _request: (_ for _ in ()).throw(AssertionError("cache miss"))),
        cache=cache,
        workers=1,
    )
    assert [decision.verdict for decision in cached] == [
        decision.verdict for decision in decisions
    ]
    assert all(decision.provenance.cache_hit for decision in cached)

    report = build_matrix_report(
        rows,
        {"D0": decisions},
        settings=AblationSettings(workers=1),
    )
    assert report["selected_profile"] == "D0"
    assert report["freeze_allowed"] is True
    assert report["profiles"]["D0"]["metrics"]["recall"] == 1.0
    assert report["profiles"]["D0"]["metrics"]["false_positive_rate"] == 0.0


def test_repository_bootstrap_is_grouped_and_deterministic() -> None:
    rows = [
        {
            "repository": "r1",
            "truth": "fix",
            "prediction": "YES",
        },
        {
            "repository": "r1",
            "truth": "other",
            "prediction": "NO",
        },
        {
            "repository": "r2",
            "truth": "fix",
            "prediction": "NO",
        },
        {
            "repository": "r2",
            "truth": "other",
            "prediction": "YES",
        },
    ]
    first = repository_block_bootstrap(rows, samples=100, seed=19)
    second = repository_block_bootstrap(rows, samples=100, seed=19)
    assert first == second
    assert first["recall"] == [0.0, 1.0]
    assert first["false_positive_rate"] == [0.0, 1.0]
