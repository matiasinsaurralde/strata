"""``strata-eval`` — score compiled artifacts against the frozen ground truth.

    uv run strata-eval score
    uv run strata-eval score --label anchors-fix --save results/scores/anchors.json
    uv run strata-eval score --against results/scores/baseline.json

Scoring is free and takes milliseconds, so a pipeline change can be measured on
its own rather than batched with three others and evaluated jointly.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from strata.resources import repo_root

from .truth import DEFAULT_TRUTH_PATH, RepoScore, ScoreReport, TruthSet, score_artifacts

ARTIFACT_DIR = repo_root() / "results" / "context"

SLUG_TO_FILE = {
    "gin-gonic/gin": "gin-gonic-gin.json",
    "grpc/grpc-go": "grpc-grpc-go.json",
    "buger/jsonparser": "buger-jsonparser.json",
    "getkin/kin-openapi": "getkin-kin-openapi.json",
}


def _load_artifacts(directory: Path) -> dict[str, dict]:
    loaded: dict[str, dict] = {}
    for slug, name in SLUG_TO_FILE.items():
        path = directory / name
        if path.is_file():
            loaded[slug] = json.loads(path.read_text(encoding="utf-8"))
    return loaded


def _report_from_dict(payload: dict) -> ScoreReport:
    return ScoreReport(
        per_repo=[
            RepoScore(
                repo=r["repo"],
                emitted=r["emitted"],
                true_positives=list(r["true_positives"]),
                false_positives=list(r["false_positives"]),
                missed=list(r["missed"]),
                unscored=list(r["unscored"]),
            )
            for r in payload["per_repo"]
        ],
        label=payload.get("label", ""),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="strata-eval", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    score = commands.add_parser("score", help="score artifacts against the fixture")
    score.add_argument("--artifacts", type=Path, default=ARTIFACT_DIR)
    score.add_argument("--truth", type=Path, default=DEFAULT_TRUTH_PATH)
    score.add_argument("--label", default="")
    score.add_argument("--save", type=Path, help="write the report as JSON")
    score.add_argument("--against", type=Path, help="diff against a saved report")
    score.add_argument("--json", action="store_true", help="emit JSON only")

    arguments = parser.parse_args(argv)
    if arguments.command != "score":
        parser.error("unknown command")

    truth = TruthSet.load(arguments.truth)
    artifacts = _load_artifacts(arguments.artifacts)
    if not artifacts:
        print(f"error: no artifacts found under {arguments.artifacts}", file=sys.stderr)
        return 2

    report = score_artifacts(artifacts, truth, label=arguments.label)

    if arguments.json:
        print(json.dumps(report.to_dict(), indent=1))
    else:
        print(report.render())
        if report.unscored:
            print(
                f"\nnote: {report.unscored} finding(s) are outside the fixture and "
                "cannot be scored either way"
            )

    if arguments.against and arguments.against.is_file():
        previous = _report_from_dict(json.loads(arguments.against.read_text()))
        print(f"\n=== vs {previous.label or arguments.against.name} ===")
        print(report.diff_against(previous))

    if arguments.save:
        arguments.save.parent.mkdir(parents=True, exist_ok=True)
        arguments.save.write_text(json.dumps(report.to_dict(), indent=1) + "\n")
        print(f"\nwrote {arguments.save}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
