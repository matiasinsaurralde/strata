#!/usr/bin/env python
"""Compile a security context for gin-gonic/gin and save it for comparison.

Run:
    uv run python scripts/scan_gin.py [--last N] [--workers N]

Writes ``results/context/gin-gonic-gin.json`` (the artifact) alongside
``...-funnel.json`` (what the pipeline did, so the artifact's coverage claims
can be checked against it).
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from strata.adjudicator import Profile
from strata.llm import LLMConfig, ModelPricing, OpenAIChatClient
from strata.resources import repo_root
from strata.scan import ScanConfig, scan_repository

REPO = "https://github.com/gin-gonic/gin.git"
OUTPUT_DIR = repo_root() / "results" / "context"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--last", type=int, default=None, help="cap commits examined")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--max-cost", type=float, default=60.0)
    parser.add_argument("--repo", default=REPO)
    parser.add_argument("--name", default=None, help="output basename")
    arguments = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s"
    )

    started = datetime.now(timezone.utc)
    outcome = scan_repository(
        arguments.repo,
        client=OpenAIChatClient(LLMConfig.from_env()),
        config=ScanConfig(
            last=arguments.last,
            workers=arguments.workers,
            profile=Profile.A0,
            max_cost_usd=arguments.max_cost,
            # gpt-5.4 on Azure, standard tier.
            pricing=ModelPricing(1.25, 10.0, 0.125),
        ),
        progress=lambda message: print(f"[{_elapsed(started)}] {message}", flush=True),
    )

    slug = arguments.name or f"{outcome.context.repo.owner}-{outcome.context.repo.name}"
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    artifact = OUTPUT_DIR / f"{slug}.json"
    funnel = OUTPUT_DIR / f"{slug}-funnel.json"

    artifact.write_text(
        json.dumps(outcome.context.to_dict(), indent=1, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    funnel.write_text(
        json.dumps(
            {
                "funnel": outcome.funnel(),
                "triage_candidates": sorted(outcome.triage_yes),
                "adjudication_rejected": sorted(outcome.adjudication_no),
                "adjudication_abstained": [
                    {"sha": sha, "reason": reason}
                    for sha, reason in sorted(outcome.adjudication_abstain)
                ],
                "triage_errors": [
                    {"sha": sha, "error": error}
                    for sha, error in sorted(outcome.triage_errors)
                ],
            },
            indent=1,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    print(f"\nartifact -> {artifact}")
    print(f"funnel   -> {funnel}")
    print(json.dumps(outcome.funnel(), indent=1))
    return 0


def _elapsed(started: datetime) -> str:
    seconds = int((datetime.now(timezone.utc) - started).total_seconds())
    return f"{seconds // 60:02d}:{seconds % 60:02d}"


if __name__ == "__main__":
    sys.exit(main())
