"""Stage-2 adjudicator: re-score stage-1 YES commits with a precision-oriented prompt.

Stage 1 (eval.py) is a cheap diff-only triage net. Stage 2 only sees commits that
stage 1 flagged YES, and asks a stricter question. Variants:

  S2-A  stricter prompt, diff only
  S2-B  same stricter prompt, diff + commit message

No new labels required — reuse role from commits.jsonl / stage-1 result rows.

Usage:
    # After freezing stage-1 results:
    python stage2.py --variant a -j 4 \\
        --stage1 results/first.json results/fpr.json \\
        --out results/s2a.json

    python stage2.py --variant b -j 4 \\
        --stage1 results/first.json results/fpr.json \\
        --out results/s2b.json

    python stage2.py --compare results/s2a.json results/s2b.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from eval import (
    COMMITS_PATH,
    DEFAULT_PARALLEL,
    DIFF_SKIP_MAX_BYTES,
    FIX_ROLES,
    GHSA_COMMITS_DIR,
    MANIFEST_PATH,
    MAX_PARALLEL,
    NONFIX_ROLES,
    EndpointConfig,
    RateLimitGate,
    _PRINT_LOCK,
    load_dotenv,
    openai_chat_completion,
    parse_yes_no,
    pct,
    read_jsonl,
    skip_oversize_diff,
)

# Stricter than stage-1: demand an exploitable vuln fix; reject dep-bump bait.
S2_SYSTEM_PROMPT = (
    "You are a security engineer adjudicating whether a git commit is a genuine "
    "security-vulnerability fix. Be conservative: answer YES only if the change "
    "clearly removes or blocks a real, pre-existing, exploitable vulnerability "
    "(for example auth bypass, injection, path traversal, SSRF, RCE, privilege "
    "escalation, or crypto/protocol weakness with a concrete attack path visible "
    "in the first-party code of the diff). "
    "Answer NO for ordinary bugs, refactors, features, tests, docs, UI changes, "
    "network-policy or hardening that does not close a specific exploitable flaw, "
    "and anything ambiguous. "
    "Dependency / module / lockfile bumps are NO even when the commit message "
    "mentions security, CVE, or 'security dependencies', unless the diff also "
    "shows first-party code changes that clearly close an exploitable path in "
    "this repository. A version bump alone is not enough. "
    'Answer with exactly one word: "YES" or "NO".'
)
S2_USER_DIFF_ONLY = (
    "Is this commit a genuine security-vulnerability fix?\n\n"
    "### Diff\n{diff}"
)
S2_USER_DIFF_MESSAGE = (
    "Is this commit a genuine security-vulnerability fix?\n\n"
    "### Commit message\n{message}\n\n"
    "### Diff\n{diff}"
)

VARIANTS = {
    "a": {
        "id": "S2-A",
        "message_condition": "M2_none",
        "include_message": False,
        "description": "stricter prompt, diff only",
    },
    "b": {
        "id": "S2-B",
        "message_condition": "M1_message",
        "include_message": True,
        "description": "stricter prompt, diff + commit message",
    },
}


def s2_prompt_hash(variant: str) -> str:
    meta = VARIANTS[variant]
    user_tmpl = S2_USER_DIFF_MESSAGE if meta["include_message"] else S2_USER_DIFF_ONLY
    h = hashlib.sha256()
    h.update(S2_SYSTEM_PROMPT.encode("utf-8"))
    h.update(b"\x00")
    h.update(user_tmpl.encode("utf-8"))
    h.update(b"\x00")
    h.update(meta["id"].encode("utf-8"))
    return "sha256:" + h.hexdigest()


def commit_key(row: dict[str, Any]) -> tuple[str, str]:
    return (str(row.get("repo") or ""), str(row.get("sha") or "").lower())


def load_stage1_yes(
    paths: list[Path],
) -> dict[tuple[str, str], dict[str, Any]]:
    """Union of stage-1 commits with flagged=True, keyed by (repo, sha)."""
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for path in paths:
        payload = json.loads(path.read_text(encoding="utf-8"))
        for row in payload.get("commits") or []:
            if row.get("flagged") is not True:
                continue
            out[commit_key(row)] = row
    return out


def build_s2_targets(
    commits: list[dict[str, Any]],
    stage1_yes: dict[tuple[str, str], dict[str, Any]],
) -> list[dict[str, Any]]:
    """Join bundle rows onto stage-1 YESes (need diff_path + message)."""
    by_key = {commit_key(c): c for c in commits}
    targets: list[dict[str, Any]] = []
    for key, s1 in stage1_yes.items():
        bundle = by_key.get(key)
        if not bundle or not bundle.get("diff_path"):
            continue
        row = dict(bundle)
        row["stage1_flagged"] = True
        row["stage1_arm_role"] = s1.get("role")
        row["stage1_source"] = s1.get("source")
        targets.append(row)
    targets.sort(key=lambda r: (str(r.get("repo")), str(r.get("sha"))))
    return targets


def build_user_content(row: dict[str, Any], diff_text: str, *, include_message: bool) -> str:
    if include_message:
        message = (row.get("message") or row.get("subject") or "").strip() or "(empty)"
        return S2_USER_DIFF_MESSAGE.format(message=message, diff=diff_text)
    return S2_USER_DIFF_ONLY.format(diff=diff_text)


def classify_s2(
    targets: list[dict[str, Any]],
    cfg: EndpointConfig,
    *,
    variant: str,
    parallel: int,
    max_diff_bytes: int,
) -> list[dict[str, Any]]:
    meta = VARIANTS[variant]
    include_message = bool(meta["include_message"])
    gate = RateLimitGate()
    total = len(targets)
    results: list[dict[str, Any] | None] = [None] * total

    def one(i: int, row: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        diff_path = GHSA_COMMITS_DIR / row["diff_path"]
        diff_text = diff_path.read_text(encoding="utf-8", errors="replace")
        rec: dict[str, Any] = {
            "ghsa_id": row.get("ghsa_id"),
            "repo": row.get("repo"),
            "sha": row.get("sha"),
            "msg_class": row.get("msg_class"),
            "role": row.get("role"),
            "source": row.get("source"),
            "diff_bytes": row.get("diff_bytes"),
            "stage1_flagged": True,
            "skipped_oversize": False,
            "flagged": None,
            "error": None,
        }
        skip_reason = skip_oversize_diff(row, diff_text, max_diff_bytes)
        if skip_reason:
            rec["skipped_oversize"] = True
            rec["error"] = skip_reason
            with _PRINT_LOCK:
                print(
                    f"[{i}/{total}] SKIP {row['repo']} {str(row['sha'])[:12]} "
                    f"({skip_reason})",
                    flush=True,
                )
            return i - 1, rec

        user_content = build_user_content(row, diff_text, include_message=include_message)
        try:
            content = openai_chat_completion(
                cfg,
                gate,
                user_content=user_content,
                system_prompt=S2_SYSTEM_PROMPT,
            )
            rec["flagged"] = parse_yes_no(content)
        except Exception as exc:  # noqa: BLE001
            rec["error"] = str(exc)[:400]
            with _PRINT_LOCK:
                print(
                    f"[{i}/{total}] ERR {row['repo']} {str(row['sha'])[:12]} "
                    f"({rec['error'][:120]})",
                    flush=True,
                )
            return i - 1, rec

        mark = "YES" if rec["flagged"] else "no "
        with _PRINT_LOCK:
            print(
                f"[{i}/{total}] {mark} {row['repo']} {str(row['sha'])[:12]} "
                f"(role={row.get('role')}, source={row.get('source')})",
                flush=True,
            )
        return i - 1, rec

    workers = max(1, min(parallel, total, MAX_PARALLEL))
    if workers == 1:
        for i, row in enumerate(targets, start=1):
            idx, rec = one(i, row)
            results[idx] = rec
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = [pool.submit(one, i, row) for i, row in enumerate(targets, start=1)]
            for fut in as_completed(futs):
                idx, rec = fut.result()
                results[idx] = rec

    assert all(r is not None for r in results)
    return results  # type: ignore[return-value]


def summarize_s2(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Survival on stage-1 TP fixes; FP kill on stage-1 false positives."""
    scored = [r for r in results if r.get("flagged") is not None]
    s1_tp = [r for r in scored if r.get("role") in FIX_ROLES]
    s1_fp = [r for r in scored if r.get("role") in NONFIX_ROLES]
    survived = [r for r in s1_tp if r["flagged"]]
    killed = [r for r in s1_fp if not r["flagged"]]
    remaining_fp = [r for r in s1_fp if r["flagged"]]
    return {
        "candidates_scored": len(scored),
        "stage1_true_positives": {
            "n": len(s1_tp),
            "survived": len(survived),
            "survival_rate": pct(len(survived), len(s1_tp)),
            "dropped": [
                {"repo": r.get("repo"), "sha": r.get("sha"), "msg_class": r.get("msg_class")}
                for r in s1_tp
                if not r["flagged"]
            ],
        },
        "stage1_false_positives": {
            "n": len(s1_fp),
            "killed": len(killed),
            "kill_rate": pct(len(killed), len(s1_fp)),
            "remaining": len(remaining_fp),
            "remaining_rate": pct(len(remaining_fp), len(s1_fp)),
            "remaining_detail": [
                {
                    "repo": r.get("repo"),
                    "sha": r.get("sha"),
                    "role": r.get("role"),
                    "source": r.get("source"),
                    "msg_class": r.get("msg_class"),
                }
                for r in remaining_fp
            ],
        },
        "errors": sum(1 for r in results if r.get("error") and not r.get("skipped_oversize")),
        "skipped_oversize": sum(1 for r in results if r.get("skipped_oversize")),
    }


def end_to_end(
    *,
    s1_fix_recall: float | None,
    s1_sampler_fpr: float | None,
    s2: dict[str, Any],
    prevalence: float = 0.015,
) -> dict[str, Any]:
    """Approximate cascade metrics from stage-1 headlines × stage-2 survival/kill."""
    surv = (s2.get("stage1_true_positives") or {}).get("survival_rate")
    rem = (s2.get("stage1_false_positives") or {}).get("remaining_rate")
    e2e_r = round(s1_fix_recall * surv, 4) if s1_fix_recall is not None and surv is not None else None
    e2e_fpr = (
        round(s1_sampler_fpr * rem, 4) if s1_sampler_fpr is not None and rem is not None else None
    )
    prec = None
    if e2e_r is not None and e2e_fpr is not None:
        denom = e2e_r * prevalence + e2e_fpr * (1.0 - prevalence)
        prec = round(e2e_r * prevalence / denom, 4) if denom else None
    return {
        "prevalence": prevalence,
        "stage1_fix_recall": s1_fix_recall,
        "stage1_sampler_fpr": s1_sampler_fpr,
        "stage2_survival": surv,
        "stage2_fp_remaining_rate": rem,
        "e2e_recall": e2e_r,
        "e2e_fpr": e2e_fpr,
        "e2e_precision": prec,
    }


def load_stage1_headlines(paths: list[Path]) -> tuple[float | None, float | None]:
    fix_recall = None
    sampler_fpr = None
    for path in paths:
        payload = json.loads(path.read_text(encoding="utf-8"))
        kind = payload.get("kind") or payload.get("config", {}).get("arm")
        if kind == "recall":
            fr = ((payload.get("by_role") or {}).get("fix_recall") or {}).get("recall")
            if fr is not None:
                fix_recall = fr
        if kind == "fpr":
            by_src = (payload.get("fpr") or {}).get("by_source") or {}
            samp = by_src.get("sampler") or {}
            if samp.get("fpr") is not None:
                sampler_fpr = samp["fpr"]
    return fix_recall, sampler_fpr


def print_s2_summary(variant: str, summary: dict[str, Any], e2e: dict[str, Any]) -> None:
    meta = VARIANTS[variant]
    tp = summary["stage1_true_positives"]
    fp = summary["stage1_false_positives"]
    print("\n" + "=" * 60)
    print(f"{meta['id']}  ({meta['description']})")
    print(f"prompt={s2_prompt_hash(variant)[:19]}…")
    print("-" * 60)
    print(
        f"  fix survival (S1 TPs kept) : {tp['survived']}/{tp['n']} = {tp['survival_rate']}"
    )
    for d in tp["dropped"][:12]:
        print(f"        DROPPED fix: {d['repo']} {str(d['sha'])[:12]}")
    if len(tp["dropped"]) > 12:
        print(f"        … {len(tp['dropped']) - 12} more")
    print(
        f"  FP kill (S1 FPs → NO)     : {fp['killed']}/{fp['n']} = {fp['kill_rate']}"
    )
    print(
        f"  FP remaining               : {fp['remaining']}/{fp['n']} = {fp['remaining_rate']}"
    )
    for d in fp["remaining_detail"][:12]:
        print(
            f"        STILL FP: {d['repo']} {str(d['sha'])[:12]} "
            f"(role={d['role']}, source={d['source']})"
        )
    if e2e.get("e2e_recall") is not None:
        print("-" * 60)
        print(
            f"  e2e recall≈ {e2e['e2e_recall']}  e2e FPR≈ {e2e['e2e_fpr']}  "
            f"precision@{e2e['prevalence']}≈ {e2e['e2e_precision']}"
        )
        print("  (e2e = S1 headline × S2 survival / remaining-FP rate)")
    print("=" * 60)


def compare_runs(paths: list[Path]) -> None:
    rows = []
    for path in paths:
        payload = json.loads(path.read_text(encoding="utf-8"))
        s = payload.get("stage2") or {}
        e = payload.get("end_to_end") or {}
        cfg = payload.get("config") or {}
        tp = s.get("stage1_true_positives") or {}
        fp = s.get("stage1_false_positives") or {}
        rows.append(
            {
                "path": str(path),
                "variant": cfg.get("variant"),
                "survival": tp.get("survival_rate"),
                "kill": fp.get("kill_rate"),
                "fp_rem": fp.get("remaining_rate"),
                "e2e_r": e.get("e2e_recall"),
                "e2e_fpr": e.get("e2e_fpr"),
                "e2e_p": e.get("e2e_precision"),
            }
        )
    print("Stage-2 comparison")
    print("=" * 72)
    print(
        f"{'variant':8} {'survive':>8} {'fp_kill':>8} {'fp_rem':>8} "
        f"{'e2e_R':>8} {'e2e_FPR':>8} {'e2e_P@1.5%':>10}  file"
    )
    for r in rows:
        print(
            f"{str(r['variant'] or '?'):8} "
            f"{_fmt(r['survival']):>8} {_fmt(r['kill']):>8} {_fmt(r['fp_rem']):>8} "
            f"{_fmt(r['e2e_r']):>8} {_fmt(r['e2e_fpr']):>8} {_fmt(r['e2e_p']):>10}  "
            f"{r['path']}"
        )
    print("=" * 72)
    print("Higher survival + higher fp_kill is better; e2e_P@1.5% is the cascade headline.")


def _fmt(v: Any) -> str:
    if v is None:
        return "-"
    if isinstance(v, float):
        return f"{v:.4f}"
    return str(v)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--variant",
        choices=sorted(VARIANTS),
        help="a=diff-only stricter; b=diff+message stricter",
    )
    parser.add_argument(
        "--stage1",
        nargs="+",
        type=Path,
        default=[Path("results/first.json"), Path("results/fpr.json")],
        help="stage-1 result JSON(s) whose flagged=YES rows become candidates",
    )
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--parallel", "-j", type=int, default=DEFAULT_PARALLEL)
    parser.add_argument("--max-diff-bytes", type=int, default=DIFF_SKIP_MAX_BYTES)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--env-file", type=Path, default=Path(".env"))
    parser.add_argument(
        "--compare",
        nargs="+",
        type=Path,
        default=None,
        help="compare existing stage-2 result JSON files and exit",
    )
    args = parser.parse_args()

    if args.compare:
        compare_runs(args.compare)
        return

    if not args.variant:
        sys.exit("pass --variant a|b (or --compare FILE…)")

    if args.parallel < 1 or args.parallel > MAX_PARALLEL:
        sys.exit(f"--parallel must be 1..{MAX_PARALLEL}")
    if args.max_diff_bytes < 1:
        sys.exit("--max-diff-bytes must be >= 1")

    load_dotenv(args.env_file)
    for path in args.stage1:
        if not path.exists():
            sys.exit(f"stage-1 result not found: {path}")

    commits = read_jsonl(COMMITS_PATH)
    if not commits:
        sys.exit(f"No commits at {COMMITS_PATH}")
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8")) if MANIFEST_PATH.exists() else {}

    stage1_yes = load_stage1_yes(args.stage1)
    targets = build_s2_targets(commits, stage1_yes)
    if args.limit:
        targets = targets[: args.limit]
    if not targets:
        sys.exit("No stage-1 YES candidates joined to the bundle.")

    meta = VARIANTS[args.variant]
    if args.dry_run:
        for i, row in enumerate(targets, start=1):
            print(
                f"[{i}/{len(targets)}] would adjudicate {row['repo']} {str(row['sha'])[:12]} "
                f"(role={row.get('role')}, source={row.get('source')})"
            )
        print(
            f"\nDry run: {len(targets)} stage-1 YES candidate(s), "
            f"variant={meta['id']} ({meta['description']})."
        )
        return

    cfg = EndpointConfig.from_env()
    workers = max(1, min(args.parallel, len(targets), MAX_PARALLEL))
    print(
        f"Stage-2 {meta['id']} on {len(targets)} stage-1 YES(s) "
        f"parallel={workers} model={cfg.model}…"
    )
    try:
        results = classify_s2(
            targets,
            cfg,
            variant=args.variant,
            parallel=workers,
            max_diff_bytes=args.max_diff_bytes,
        )
    except (urllib.error.HTTPError, urllib.error.URLError, RuntimeError) as exc:
        sys.exit(str(exc))

    summary = summarize_s2(results)
    s1_r, s1_fpr = load_stage1_headlines(args.stage1)
    e2e = end_to_end(s1_fix_recall=s1_r, s1_sampler_fpr=s1_fpr, s2=summary)

    result: dict[str, Any] = {
        "kind": "stage2",
        "run_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "config": {
            "model": cfg.model,
            "base_url": cfg.base_url,
            "variant": meta["id"],
            "variant_key": args.variant,
            "description": meta["description"],
            "prompt_hash": s2_prompt_hash(args.variant),
            "message_condition": meta["message_condition"],
            "temperature": 0,
            "parallel": workers,
            "max_diff_bytes": args.max_diff_bytes,
            "stage1_files": [str(p) for p in args.stage1],
        },
        "corpus": {
            "dir": str(GHSA_COMMITS_DIR),
            "schema_version": manifest.get("schema_version"),
            "built_at": manifest.get("built_at"),
            "labels_applied": manifest.get("labels_applied"),
            "stage1_yes_candidates": len(targets),
            "classified": summary["candidates_scored"],
            "skipped_oversize": summary["skipped_oversize"],
            "errors": summary["errors"],
        },
        "stage2": summary,
        "end_to_end": e2e,
        "commits": results,
    }

    print_s2_summary(args.variant, summary, e2e)

    out = args.out
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"\nWrote {out}")
    else:
        print("\n(no --out given; result not persisted)")


if __name__ == "__main__":
    main()
