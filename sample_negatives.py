"""Sample non-fix ("negative") commits from repos already in the bundle.

These are the FPR arm: ordinary commits (refactors, features, typo fixes) that
are NOT GHSA-referenced. Running the same classifier over them measures how often
it wrongly cries "security fix" — the false-positive rate that makes recall
interpretable. Negatives MUST come from the same repos as the positives, so the
classifier faces the same code distribution (else FPR is artificially low).

Design:
  - Repos are DERIVED from the bundle's commits.jsonl (not configurable): the
    primary advisory dataset defines the universe. We never introduce a new repo.
  - Skips any (host, repo, sha) already in the bundle — both GHSA fixes AND
    negatives pulled on a prior run — so reruns add only new commits and are
    idempotent (belt-and-suspenders with merge_rows' frozen-row merge).
  - Appends rows with source="sampler", ghsa_referenced=False, role=None,
    reusing main.py's enrichment + merge + write. Positives are never touched.

Negatives sampled at random could secretly be a real silent fix GHSA never
caught — that is the project's premise. So label them (mostly `other`, sometimes
`fix`); an unlabelled negative counted as a true negative biases FPR upward
(pessimistic, the safe direction). See labelling-rubric.md.

Source: GitHub API (lists commits via /repos/{repo}/commits, newest-first,
paginated). Good for a first pass at tens-to-low-hundreds of negatives.

  TODO: clone-based sampling for scale. The API paginates from HEAD, so "uniform
  random over ALL history" is approximate (we sample from the first K pages). For
  the real ~3,000-commit FPR arm, shallow-clone each repo, `git log` the full SHA
  list, sample uniformly, and diff locally (git diff <sha>^1 <sha> for merges) —
  no rate limit and true uniform sampling. Reuse fetch_commit_enrichment's merge
  handling as the model.

Usage:
    python sample_negatives.py                     # --per-repo 10 (default)
    python sample_negatives.py --per-repo 1        # 1 per repo — smallest test pull
    python sample_negatives.py --total 50          # ~50 overall, even split across repos
    python sample_negatives.py --dry-run           # list what would be pulled, no writes
    python sample_negatives.py --pages 10          # deepen history pool (100 commits/page)

Requires GITHUB_TOKEN (env or .env) — without it the unauthenticated 60/hr limit
makes multi-repo listing fail and every repo reports +0.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
from pathlib import Path
from typing import Any

from eval import load_dotenv
from main import (
    GHSA_COMMITS_DIR,
    LABELS_PATH,
    SCHEMA_VERSION,
    apply_labels,
    build_audit_queue,
    commit_key,
    enrich_commit_rows,
    github_http_get,
    load_labels,
    merge_rows,
    read_jsonl,
    write_ghsa_commits,
)

COMMITS_PATH = GHSA_COMMITS_DIR / "commits.jsonl"
ADVISORIES_PATH = GHSA_COMMITS_DIR / "advisories.jsonl"
# GitHub returns up to 100 commits/page; we draw the random sample from the first
# --pages of history. More pages = deeper (older) reach, more API calls.
PER_PAGE = 100


def bundle_repos(commits: list[dict[str, Any]]) -> list[tuple[str, str]]:
    """Distinct (host, repo) pairs present in the bundle, sorted for determinism."""
    repos = {(str(c["host"]), str(c["repo"])) for c in commits}
    return sorted(repos)


def existing_keys(commits: list[dict[str, Any]]) -> set[tuple[str, str, str]]:
    """All (host, repo, sha) already in the bundle — fixes and prior negatives."""
    return {commit_key(c) for c in commits}


def list_repo_commit_shas(
    host: str, repo: str, pages: int
) -> tuple[list[str], str | None]:
    """Return (SHAs from first `pages` of history, error_or_None).

    github.com only. On API failure returns ([], reason) so the caller can
    surface rate-limits instead of silently reporting +0.
    """
    if host != "github.com":
        return [], f"unsupported host {host}"
    shas: list[str] = []
    for page in range(1, pages + 1):
        url = (
            f"https://api.github.com/repos/{repo}/commits"
            f"?per_page={PER_PAGE}&page={page}"
        )
        status, body, headers = github_http_get(url, "application/vnd.github+json")
        if status != 200:
            remaining = headers.get("x-ratelimit-remaining")
            detail = body.decode("utf-8", errors="replace")[:160].replace("\n", " ")
            reason = f"HTTP {status}"
            if remaining is not None:
                reason += f" (rate-limit remaining={remaining})"
            if detail:
                reason += f": {detail}"
            return shas, reason
        try:
            payload = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            return shas, f"invalid JSON on page {page}"
        if not payload:
            break
        for entry in payload:
            sha = entry.get("sha")
            if sha:
                shas.append(str(sha).lower())
        if len(payload) < PER_PAGE:
            break  # last page
    return shas, None


def sample_shas_for_repo(
    host: str,
    repo: str,
    n: int,
    existing: set[tuple[str, str, str]],
    pages: int,
) -> tuple[list[str], str | None]:
    """Pick up to n random SHAs from the repo, excluding any already in the bundle.

    Returns (shas, note). note is set when the pool is empty or the API failed.
    """
    listed, err = list_repo_commit_shas(host, repo, pages)
    if err and not listed:
        return [], err
    candidates = [s for s in listed if (host, repo, s) not in existing]
    if not candidates:
        note = f"0 candidates in first {pages} page(s) ({len(listed)} listed, all already in bundle)"
        if err:
            note += f"; also: {err}"
        return [], note
    if len(candidates) <= n:
        return candidates, err  # partial page fetch still usable
    return random.sample(candidates, n), err


def build_negative_row(host: str, repo: str, sha: str) -> dict[str, Any]:
    """A negative commit row: same shape as a positive, minus the advisory link."""
    return {
        "ghsa_id": None,           # belongs to no advisory
        "host": host,
        "repo": repo,
        "sha": sha,
        "url": f"https://{host}/{repo}/commit/{sha}",
        "ordinal": 1,
        "n_in_advisory": 0,
        "source": "sampler",
        "ghsa_referenced": False,
        "role": None,
    }


def plan_counts(
    repos: list[tuple[str, str]],
    per_repo: int | None,
    total: int | None,
) -> dict[tuple[str, str], int]:
    """How many negatives to target per repo. --total overrides --per-repo with an
    even split (remainder spread over the first repos); small repos cap themselves
    at what they actually have during sampling."""
    if total is not None:
        base, extra = divmod(total, len(repos))
        return {r: base + (1 if i < extra else 0) for i, r in enumerate(repos)}
    return {r: (per_repo or 0) for r in repos}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--per-repo", type=int, default=None, help="negatives per repo (default 10)")
    group.add_argument("--total", type=int, default=None, help="approx total, split evenly across repos")
    parser.add_argument("--pages", type=int, default=2, help="API pages of history to sample from (100/page)")
    parser.add_argument("--dry-run", action="store_true", help="show plan, no API writes")
    args = parser.parse_args()

    # Same as main.py / eval.py: GITHUB_TOKEN often lives in .env, not the shell.
    load_dotenv()
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        print(
            "Warning: no GITHUB_TOKEN/GH_TOKEN (env or .env). "
            "Unauthenticated GitHub API is 60 req/hr — listing 37 repos × pages "
            "will fail and look like +0 everywhere.",
            file=sys.stderr,
        )

    per_repo = args.per_repo
    if per_repo is None and args.total is None:
        per_repo = 10  # default knob

    commits = read_jsonl(COMMITS_PATH)
    if not commits:
        raise SystemExit(f"No bundle at {COMMITS_PATH}. Run main.py first.")

    repos = bundle_repos(commits)
    existing = existing_keys(commits)
    targets = plan_counts(repos, per_repo, args.total)

    mode = f"--total {args.total}" if args.total is not None else f"--per-repo {per_repo}"
    print(f"{len(repos)} repo(s) in bundle; sampling negatives ({mode}, {args.pages} page(s)/repo).")

    new_rows: list[dict[str, Any]] = []
    api_failures = 0
    for host, repo in repos:
        want = targets[(host, repo)]
        if want <= 0:
            continue
        shas, note = sample_shas_for_repo(host, repo, want, existing, args.pages)
        for sha in shas:
            new_rows.append(build_negative_row(host, repo, sha))
            existing.add((host, repo, sha))  # avoid dupes within this run
        line = f"  {repo:40} +{len(shas)} (wanted {want})"
        if note and not shas:
            api_failures += 1
            line += f"  — {note}"
        elif note:
            line += f"  — {note}"
        print(line)

    if not new_rows:
        print("\nNothing new to sample (all candidates already in the bundle, or repos unreachable).")
        if api_failures:
            print(
                f"  {api_failures} repo(s) failed API listing — set GITHUB_TOKEN in .env "
                f"(or export it), or raise --pages once auth works."
            )
        else:
            print(
                "  Tip: deepen the pool with e.g. `--pages 10` (100 commits/page, newest-first)."
            )
        return

    if args.dry_run:
        print(f"\nDry run: would add {len(new_rows)} negative(s). No API diffs fetched, no writes.")
        return

    # Enrich the new negatives (diffs + metadata). Empty advisories list → lag_days
    # resolves to None for these rows, which is correct (a negative has no advisory).
    enrich_stats = enrich_commit_rows(new_rows, [], GHSA_COMMITS_DIR)

    all_commits, added = merge_rows(commits, new_rows, commit_key)

    # Re-merge labels across the whole set (unchanged positives keep their roles;
    # new negatives stay role=None until you label them).
    labels = load_labels(LABELS_PATH)
    labels_applied = apply_labels(all_commits, labels)

    advisories = read_jsonl(ADVISORIES_PATH)
    audit_queue = build_audit_queue(all_commits)

    manifest = json.loads((GHSA_COMMITS_DIR / "manifest.json").read_text(encoding="utf-8"))
    manifest["schema_version"] = SCHEMA_VERSION
    manifest["negatives_added_this_run"] = added
    manifest["negatives_total"] = sum(
        1 for c in all_commits if c.get("source") == "sampler"
    )
    manifest["commit_refs"] = len(all_commits)
    manifest["labels_applied"] = labels_applied
    manifest["unlabelled"] = sum(1 for c in all_commits if c.get("role") is None)
    manifest["audit_queue"] = len(audit_queue)

    write_ghsa_commits(
        GHSA_COMMITS_DIR,
        advisories=advisories,
        commits=all_commits,
        manifest=manifest,
        audit_queue=audit_queue,
        preserve_diffs=True,  # keep the diffs/ tree; merge, never wipe
    )

    print(
        f"\nAdded {added} negative(s). Bundle now: {len(all_commits)} commits "
        f"({manifest['negatives_total']} negatives, {manifest['unlabelled']} unlabelled)."
    )
    print(
        f"Enrichment: {enrich_stats['resolved']}/{enrich_stats['unique_commits']} resolved, "
        f"{enrich_stats['diffs_written']} diffs."
    )
    print("Next: `python label.py` to label them, then `python eval.py`.")


if __name__ == "__main__":
    main()
