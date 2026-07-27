"""A/B the two stage-2 backends over the frozen truth fixture.

This deliberately skips triage. Every commit in ``matrix-truth.json`` already
carries an adjudicated role, so feeding them straight to stage 2 measures the
adjudicator and nothing else — a triage change cannot flatter or spoil the
result, and the run costs a fraction of a full scan.

What is measured, per backend:

precision
    of the commits it answered YES on, how many are really fixes
recall
    of the real fixes in the fixture, how many it answered YES on
abstain rate
    an abstention is not a wrong answer, but a backend that abstains on half
    the corpus is not usable, so it is reported alongside

Usage::

    uv run python -m scripts.ab_adjudicator --backend chat --out results/ab/chat.json
    uv run python -m scripts.ab_adjudicator --backend codex --out results/ab/codex.json
    uv run python -m scripts.ab_adjudicator --compare results/ab/chat.json results/ab/codex.json
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from strata.adjudicator import Adjudicator, Profile
from strata.codex_adjudicator import CodexAdjudicator
from strata.consensus import ConsensusAdjudicator
from strata.env import resolve_endpoint_profile
from strata.git_repo import GitRepository
from strata.llm import LLMConfig, ModelPricing, OpenAIChatClient
from strata_eval.truth import TruthSet

LOGGER = logging.getLogger("ab")

MIRRORS = {
    "gin-gonic/gin": "https://github.com/gin-gonic/gin.git",
    "grpc/grpc-go": "https://github.com/grpc/grpc-go.git",
    "buger/jsonparser": "https://github.com/buger/jsonparser.git",
    "getkin/kin-openapi": "https://github.com/getkin/kin-openapi.git",
}


def _make_backend(
    name: str,
    repository: GitRepository,
    env: dict[str, str],
    sandbox: str,
    consensus: int = 1,
) -> Any:
    model = env.get("STRATA_MODEL", "gpt-5.4")
    if name == "codex":
        backend: Any = CodexAdjudicator(
            repository,
            model=model,
            base_url=env["OPENAI_BASE_URL"],
            api_key=env["OPENAI_API_KEY"],
            profile=Profile.A0,
            sandbox=sandbox,
        )
        return _wrap_consensus(backend, consensus)
    client = OpenAIChatClient(
        LLMConfig(
            base_url=env["OPENAI_BASE_URL"],
            model=model,
            api_key=env["OPENAI_API_KEY"],
        )
    )
    backend = Adjudicator(client, repository, profile=Profile.A0)
    return _wrap_consensus(backend, consensus)


def _wrap_consensus(backend: Any, rounds: int) -> Any:
    """Wrap in N-of-M voting when asked, otherwise return the bare backend."""
    if rounds <= 1:
        return backend
    return ConsensusAdjudicator(backend, rounds=rounds)


def run_backend(
    backend: str,
    *,
    workers: int,
    sandbox: str,
    consensus: int = 1,
    repos: tuple[str, ...] | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    env = resolve_endpoint_profile()
    truth = TruthSet.load()
    entries = [e for e in truth.entries if repos is None or e.repo in repos]
    if limit:
        entries = entries[:limit]

    # One mirror and one backend instance per repository; both are shared
    # across worker threads, which is safe because git reads are independent
    # processes and each adjudication opens its own Codex thread.
    mirrors: dict[str, GitRepository] = {}
    backends: dict[str, Any] = {}
    for repo in {e.repo for e in entries}:
        mirrors[repo] = GitRepository(MIRRORS[repo], cache_root=".strata/repos")
        mirrors[repo].fetch()
        backends[repo] = _make_backend(backend, mirrors[repo], env, sandbox, consensus)

    def one(entry: Any) -> dict[str, Any]:
        repository = mirrors[entry.repo]
        started = time.monotonic()
        try:
            commit = repository.get_commit(entry.sha)
            candidate = {
                "repository": repository.canonical_source,
                "commit_sha": commit.sha,
                "parent_sha": commit.parent_sha,
                "message": commit.message,
                "diff": commit.patch.decode("utf-8", errors="replace"),
                "affected_paths": [p.path for p in repository.changed_paths(commit.sha)],
            }
            result = backends[entry.repo].adjudicate(candidate)
        except Exception as exc:  # one bad commit must not lose the run
            LOGGER.warning("%s %s: %s", entry.repo, entry.sha[:10], exc)
            return {
                "sha": entry.sha,
                "repo": entry.repo,
                "truth_role": entry.role,
                "verdict": "ERROR",
                "error": f"{type(exc).__name__}: {exc}"[:300],
                "elapsed_s": round(time.monotonic() - started, 1),
            }
        decision = result.decision
        return {
            "sha": entry.sha,
            "repo": entry.repo,
            "truth_role": entry.role,
            "truth_is_fix": entry.is_fix,
            "verdict": result.verdict,
            "confidence": decision.get("confidence"),
            "l0_class": decision.get("l0_class"),
            "cwe_id": decision.get("cwe_id"),
            "reachability": (decision.get("reachability_delta") or {}).get("verdict"),
            "containment": decision.get("failure_containment"),
            "abstain_reason": decision.get("abstain_reason"),
            "rationale": str(decision.get("rationale") or "")[:400],
            "anchors": len(decision.get("evidence") or ()),
            "consensus": decision.get("consensus"),
            "tool_calls": result.tool_calls,
            "validation_errors": list(result.validation_errors),
            "elapsed_s": round(result.elapsed_ms / 1000, 1),
            "prompt_tokens": result.usage.prompt_tokens,
            "completion_tokens": result.usage.completion_tokens,
        }

    rows: list[dict[str, Any]] = []
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(one, e): e for e in entries}
        for done, future in enumerate(as_completed(futures), start=1):
            row = future.result()
            rows.append(row)
            print(
                f"  [{done}/{len(entries)}] {row['repo']:20} {row['sha'][:10]} "
                f"truth={row['truth_role']:12} -> {row['verdict']:8} "
                f"({row['elapsed_s']}s)",
                flush=True,
            )
    return summarise(backend, rows, wall_clock_s=time.monotonic() - started, sandbox=sandbox)


def summarise(
    backend: str, rows: list[dict[str, Any]], *, wall_clock_s: float, sandbox: str = ""
) -> dict[str, Any]:
    yes = [r for r in rows if r["verdict"] == "YES"]
    tp = [r for r in yes if r.get("truth_is_fix")]
    fp = [r for r in yes if not r.get("truth_is_fix")]
    fixes = [r for r in rows if r.get("truth_is_fix")]
    missed = [r for r in fixes if r["verdict"] != "YES"]
    pricing = ModelPricing(1.25, 10.0, 0.125)
    prompt = sum(r.get("prompt_tokens") or 0 for r in rows)
    completion = sum(r.get("completion_tokens") or 0 for r in rows)
    return {
        "backend": backend,
        "sandbox": sandbox,
        "mean_agreement": round(
            sum((r.get("consensus") or {}).get("agreement", 1.0) for r in rows) / max(1, len(rows)), 3
        ),
        "n": len(rows),
        "precision": len(tp) / len(yes) if yes else None,
        "recall": len(tp) / len(fixes) if fixes else None,
        "true_positives": len(tp),
        "false_positives": len(fp),
        "missed": len(missed),
        "verdicts": dict(Counter(r["verdict"] for r in rows)),
        "abstain_reasons": dict(
            Counter(r.get("abstain_reason") for r in rows if r["verdict"] == "ABSTAIN")
        ),
        "mean_elapsed_s": round(sum(r["elapsed_s"] for r in rows) / max(1, len(rows)), 1),
        "wall_clock_s": round(wall_clock_s, 1),
        "mean_tool_calls": round(sum(r.get("tool_calls") or 0 for r in rows) / max(1, len(rows)), 1),
        "estimated_cost_usd": round(pricing.estimate(prompt, completion), 2),
        "fp_shas": sorted(r["sha"][:12] for r in fp),
        "missed_shas": sorted(r["sha"][:12] for r in missed),
        "rows": sorted(rows, key=lambda r: (r["repo"], r["sha"])),
    }


def render(summary: dict[str, Any]) -> str:
    def pct(value: float | None) -> str:
        return f"{value:.0%}" if value is not None else "-"

    return (
        f"{summary['backend']:8} n={summary['n']:<3} "
        f"precision={pct(summary['precision']):>5} recall={pct(summary['recall']):>5}  "
        f"TP={summary['true_positives']:<3} FP={summary['false_positives']:<3} "
        f"miss={summary['missed']:<3}  "
        f"verdicts={summary['verdicts']}  "
        f"{summary['mean_elapsed_s']}s/commit  ${summary['estimated_cost_usd']}"
    )


def compare(paths: list[str]) -> None:
    summaries = [json.loads(Path(p).read_text()) for p in paths]
    for summary in summaries:
        print(render(summary))
    if len(summaries) != 2:
        return
    a, b = summaries
    by_sha_a = {r["sha"]: r for r in a["rows"]}
    print(f"\nper-commit changes, {a['backend']} -> {b['backend']}:")
    for row in b["rows"]:
        before = by_sha_a.get(row["sha"])
        if before is None or before["verdict"] == row["verdict"]:
            continue
        truth = "FIX" if row.get("truth_is_fix") else "not-a-fix"
        better = (row["verdict"] == "YES") == bool(row.get("truth_is_fix"))
        print(
            f"  {'+' if better else '-'} {row['repo']:20} {row['sha'][:10]} "
            f"[{truth:9}] {before['verdict']} -> {row['verdict']}"
        )


def cascade(proposer_path: str, confirmer_path: str) -> None:
    """Simulate a third stage: one backend proposes, the other confirms.

    Both backends already answered every commit in the fixture independently,
    so composing them costs nothing to evaluate. A candidate is emitted only
    when the proposer says YES *and* the confirmer does not overturn it.

    Two confirmation rules are reported, because they trade differently:

    strict
        the confirmer must also say YES. Maximum precision; every abstention
        the confirmer makes costs a true positive.
    veto
        the confirmer only has to not say NO. An abstention means "I could not
        show it either way", which is weaker grounds for discarding a finding
        the proposer evidenced.
    """
    proposer = json.loads(Path(proposer_path).read_text())
    confirmer = json.loads(Path(confirmer_path).read_text())
    verdicts = {r["sha"]: r["verdict"] for r in confirmer["rows"]}
    fixes = {r["sha"] for r in proposer["rows"] if r.get("truth_is_fix")}

    print(f"proposer: {render(proposer)}")
    print(f"confirmer: {render(confirmer)}")
    print()
    for rule, keep in (
        ("strict (confirmer must say YES)", lambda v: v == "YES"),
        ("veto   (confirmer must not say NO)", lambda v: v != "NO"),
    ):
        emitted = [
            r
            for r in proposer["rows"]
            if r["verdict"] == "YES" and keep(verdicts.get(r["sha"], "ABSTAIN"))
        ]
        tp = [r for r in emitted if r.get("truth_is_fix")]
        precision = len(tp) / len(emitted) if emitted else None
        recall = len(tp) / len(fixes) if fixes else None
        print(
            f"  {rule:36} precision={precision or 0:.0%} recall={recall or 0:.0%}  "
            f"TP={len(tp)} FP={len(emitted) - len(tp)} of {len(emitted)} emitted"
        )
        lost = [
            r["sha"][:10]
            for r in proposer["rows"]
            if r["verdict"] == "YES" and r.get("truth_is_fix") and not keep(verdicts.get(r["sha"], "ABSTAIN"))
        ]
        killed = [
            r["sha"][:10]
            for r in proposer["rows"]
            if r["verdict"] == "YES" and not r.get("truth_is_fix") and not keep(verdicts.get(r["sha"], "ABSTAIN"))
        ]
        print(f"     false positives killed: {killed or 'none'}")
        print(f"     true positives LOST:    {lost or 'none'}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=["chat", "codex"])
    parser.add_argument("--sandbox", default="read-only",
                        choices=["read-only", "workspace-write", "full-access"])
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--repo", action="append", dest="repos")
    parser.add_argument("--limit", type=int)
    parser.add_argument(
        "--consensus",
        type=int,
        default=1,
        help="run each candidate N times and take the majority verdict",
    )
    parser.add_argument("--out")
    parser.add_argument("--compare", nargs="+")
    parser.add_argument("--cascade", nargs=2, metavar=("PROPOSER", "CONFIRMER"))
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    if args.cascade:
        cascade(*args.cascade)
        return 0
    if args.compare:
        compare(args.compare)
        return 0
    if not args.backend:
        parser.error("--backend is required unless --compare is given")

    summary = run_backend(
        args.backend,
        workers=args.workers,
        sandbox=args.sandbox,
        consensus=args.consensus,
        repos=tuple(args.repos) if args.repos else None,
        limit=args.limit,
    )
    print("\n" + render(summary))
    if summary["fp_shas"]:
        print(f"  false positives: {summary['fp_shas']}")
    if summary["missed_shas"]:
        print(f"  missed:          {summary['missed_shas']}")
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(summary, indent=2) + "\n")
        print(f"  wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
