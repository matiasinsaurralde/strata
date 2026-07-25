"""Recall-only eval: does the classifier flag GHSA-referenced commits as security fixes?

Reads the built bundle (ghsa-commits/), runs a diff-only boolean classifier over
each referenced commit, and reports recall two ways:

  - commit-level flag-rate : raw fraction of referenced diffs flagged (noisy; its
    ceiling is the corpus contamination rate — some referenced commits are not
    actually the fix, so a "no" may be correct).
  - advisory-level recall  : fraction of advisories with >=1 referenced commit
    flagged. Robust to multi-commit / backport / context noise; the honest
    headline.

Diff-only, no commit message — a silent-fix simulation. The diff still sometimes
leaks disclosure language (CVE ids in CHANGELOG hunks, etc.), so `quiet` recall
is also reported with the leaking diffs excluded.

This is the recall arm only. FPR (random negatives) and precision-at-prevalence
come next, once negatives are in the bundle.

Endpoint is fully env-driven — no baked-in defaults. Values are read from the
environment, or from a .env file in the working directory (real env vars win):
  OPENAI_BASE_URL   e.g. https://api.openai.com/v1   (required)
  OPENAI_MODEL      e.g. gpt-4o-mini                  (required)
  OPENAI_API_KEY    bearer token                      (required)
See .env.example. The .env file is gitignored; do not commit secrets.

Output is a self-describing JSON result stamped with model + prompt_hash +
corpus version, so runs from different models/prompts can be compared later
(benchcmp-style) by grouping on the config block.

Usage:
    python eval.py                         # run, print summary, write result JSON
    python eval.py --out results/run.json  # choose output path
    python eval.py --limit 5               # only classify N commits (smoke test)
    python eval.py --dry-run               # no API calls; show what would run
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

GHSA_COMMITS_DIR = Path("ghsa-commits")
COMMITS_PATH = GHSA_COMMITS_DIR / "commits.jsonl"
MANIFEST_PATH = GHSA_COMMITS_DIR / "manifest.json"

# --- The classifier prompt. A plain string so it ports to Go byte-for-byte. ---
# Diff-only. Strict yes/no. Keep this stable; its sha256 stamps every result.
SYSTEM_PROMPT = (
    "You are a security engineer reviewing a single git commit diff. "
    "Decide whether the diff fixes a real, pre-existing, exploitable security "
    "vulnerability (as opposed to an ordinary bug fix, feature, refactor, test, "
    "or documentation change). "
    'Answer with exactly one word: "YES" or "NO".'
)
USER_PROMPT_TEMPLATE = "Does this git diff patch a security vulnerability?\n\n{diff}"

# Detects disclosure language leaking into a diff via CHANGELOG/docs-type hunks.
_DISCLOSURE_RE = re.compile(
    r"CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", re.IGNORECASE
)


def load_dotenv(path: Path = Path(".env")) -> int:
    """Load KEY=VALUE lines from .env into os.environ. Zero-dependency.

    Real environment variables win over file values (standard precedence), so
    `OPENAI_MODEL=x python eval.py` overrides whatever the .env says. Supports
    `#` comments, blank lines, optional `export ` prefix, and quoted values.
    Returns the number of keys set from the file.
    """
    if not path.exists():
        return 0
    set_count = 0
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key and key not in os.environ:  # do not override the real environment
            os.environ[key] = val
            set_count += 1
    return set_count


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def prompt_hash() -> str:
    h = hashlib.sha256()
    h.update(SYSTEM_PROMPT.encode("utf-8"))
    h.update(b"\x00")
    h.update(USER_PROMPT_TEMPLATE.encode("utf-8"))
    return "sha256:" + h.hexdigest()


def diff_leaks_disclosure(diff_text: str) -> bool:
    """True if an *added* line carries a CVE/GHSA id (announcement leak)."""
    for line in diff_text.splitlines():
        if line.startswith("+") and not line.startswith("+++") and _DISCLOSURE_RE.search(line):
            return True
    return False


# --- Endpoint --------------------------------------------------------------

class EndpointConfig:
    def __init__(self, base_url: str, model: str, api_key: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key

    @classmethod
    def from_env(cls) -> "EndpointConfig":
        base_url = os.environ.get("OPENAI_BASE_URL")
        model = os.environ.get("OPENAI_MODEL")
        api_key = os.environ.get("OPENAI_API_KEY")
        missing = [
            name
            for name, val in (
                ("OPENAI_BASE_URL", base_url),
                ("OPENAI_MODEL", model),
                ("OPENAI_API_KEY", api_key),
            )
            if not val
        ]
        if missing:
            raise SystemExit(
                "Missing required env var(s): "
                + ", ".join(missing)
                + "\nSet OPENAI_BASE_URL (e.g. https://api.openai.com/v1), "
                "OPENAI_MODEL, and OPENAI_API_KEY."
            )
        return cls(base_url, model, api_key)  # type: ignore[arg-type]


Classifier = Callable[[str], bool]


def openai_classify(cfg: EndpointConfig, diff_text: str) -> bool:
    """One /chat/completions call, temperature 0, strict YES/NO parse."""
    body = json.dumps(
        {
            "model": cfg.model,
            "temperature": 0,
            "max_tokens": 4,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": USER_PROMPT_TEMPLATE.format(diff=diff_text)},
            ],
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        f"{cfg.base_url}/chat/completions",
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {cfg.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "strata-eval",
        },
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    content = payload["choices"][0]["message"]["content"].strip().upper()
    # Lenient parse: first YES/NO token wins; unparseable → NO (conservative).
    for token in re.findall(r"[A-Z]+", content):
        if token in ("YES", "NO"):
            return token == "YES"
    return False


# --- Metrics ---------------------------------------------------------------

def pct(n: int, d: int) -> float | None:
    return round(n / d, 4) if d else None


def summarize_recall(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute commit-level flag-rate and advisory-level recall from scored rows."""
    scored = [r for r in results if r.get("flagged") is not None]

    # Commit-level, overall and per msg_class.
    by_class: dict[str, dict[str, int]] = {}
    for r in scored:
        c = r.get("msg_class") or "unknown"
        b = by_class.setdefault(c, {"n": 0, "flagged": 0})
        b["n"] += 1
        b["flagged"] += 1 if r["flagged"] else 0

    commit_level = {
        c: {"n": b["n"], "flagged": b["flagged"], "flag_rate": pct(b["flagged"], b["n"])}
        for c, b in sorted(by_class.items())
    }
    n_all = len(scored)
    flagged_all = sum(1 for r in scored if r["flagged"])
    commit_level["overall"] = {
        "n": n_all,
        "flagged": flagged_all,
        "flag_rate": pct(flagged_all, n_all),
    }

    # `quiet` with disclosure-leaking diffs excluded (clean silent-fix proxy).
    quiet = [r for r in scored if r.get("msg_class") == "quiet"]
    quiet_clean = [r for r in quiet if not r.get("diff_leaks_disclosure")]
    quiet_clean_flagged = sum(1 for r in quiet_clean if r["flagged"])
    commit_level["quiet_clean"] = {
        "n": len(quiet_clean),
        "flagged": quiet_clean_flagged,
        "flag_rate": pct(quiet_clean_flagged, len(quiet_clean)),
        "excluded_leaking": len(quiet) - len(quiet_clean),
    }

    # Advisory-level: an advisory is caught if >=1 of its scored commits flagged.
    by_adv: dict[str, bool] = {}
    for r in scored:
        gid = r.get("ghsa_id")
        by_adv[gid] = by_adv.get(gid, False) or bool(r["flagged"])
    adv_caught = sum(1 for v in by_adv.values() if v)
    advisory_level = {
        "n": len(by_adv),
        "caught": adv_caught,
        "recall": pct(adv_caught, len(by_adv)),
    }

    return {"commit_level": commit_level, "advisory_level": advisory_level}


# Roles that represent a genuine security fix (the ground-truth positive).
FIX_ROLES = ("fix",)
# Roles that are NOT the fix — a "YES" on these is a false positive. `backport`
# is intentionally excluded from both: it IS a real fix (so not an FPR case) but
# a duplicate one (so not counted in fix-recall either); it's reported on its own.
NONFIX_ROLES = ("context", "introduce", "other")


def summarize_by_role(results: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Label-aware scoring. Returns None if no commit carries a role.

    Uses the human `role` as ground truth instead of GHSA provenance:
      - fix_recall: of role==fix commits, how many were flagged (the honest headline)
      - nonfix false positives: of non-fix commits, how many were wrongly flagged
        (a proto-FPR signal — real FPR needs the random-negative arm)
    """
    scored = [r for r in results if r.get("flagged") is not None]
    labelled = [r for r in scored if r.get("role")]
    if not labelled:
        return None

    fixes = [r for r in labelled if r["role"] in FIX_ROLES]
    fix_flagged = sum(1 for r in fixes if r["flagged"])
    fix_missed = [
        {"repo": r.get("repo"), "sha": r.get("sha"), "msg_class": r.get("msg_class")}
        for r in fixes if not r["flagged"]
    ]

    nonfix = [r for r in labelled if r["role"] in NONFIX_ROLES]
    nonfix_flagged = [
        {"repo": r.get("repo"), "sha": r.get("sha"), "role": r.get("role")}
        for r in nonfix if r["flagged"]
    ]

    backports = [r for r in labelled if r["role"] == "backport"]
    backport_flagged = sum(1 for r in backports if r["flagged"])

    role_counts: dict[str, int] = {}
    for r in labelled:
        role_counts[r["role"]] = role_counts.get(r["role"], 0) + 1

    return {
        "labelled": len(labelled),
        "unlabelled": len(scored) - len(labelled),
        "role_counts": role_counts,
        "fix_recall": {
            "n": len(fixes),
            "flagged": fix_flagged,
            "recall": pct(fix_flagged, len(fixes)),
            "missed": fix_missed,
        },
        "nonfix_false_positives": {
            "n": len(nonfix),
            "flagged": len(nonfix_flagged),
            "fp_rate": pct(len(nonfix_flagged), len(nonfix)),
            "flagged_detail": nonfix_flagged,
        },
        "backport": {
            "n": len(backports),
            "flagged": backport_flagged,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=None, help="write result JSON here")
    parser.add_argument("--limit", type=int, default=0, help="classify at most N commits")
    parser.add_argument("--dry-run", action="store_true", help="no API calls")
    parser.add_argument("--env-file", type=Path, default=Path(".env"), help="dotenv path")
    args = parser.parse_args()

    load_dotenv(args.env_file)

    commits = read_jsonl(COMMITS_PATH)
    if not commits:
        sys.exit(f"No commits at {COMMITS_PATH}. Run main.py first.")
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8")) if MANIFEST_PATH.exists() else {}

    # Recall arm scores GHSA-referenced commits that resolved to a diff.
    targets = [
        r for r in commits
        if r.get("ghsa_referenced") and r.get("resolved") and r.get("diff_path")
    ]
    if args.limit:
        targets = targets[: args.limit]

    cfg = None if args.dry_run else EndpointConfig.from_env()

    results: list[dict[str, Any]] = []
    for i, row in enumerate(targets, start=1):
        diff_path = GHSA_COMMITS_DIR / row["diff_path"]
        diff_text = diff_path.read_text(encoding="utf-8", errors="replace")
        leaks = diff_leaks_disclosure(diff_text)
        rec = {
            "ghsa_id": row.get("ghsa_id"),
            "repo": row.get("repo"),
            "sha": row.get("sha"),
            "msg_class": row.get("msg_class"),
            "role": row.get("role"),
            "diff_bytes": row.get("diff_bytes"),
            "diff_leaks_disclosure": leaks,
            "flagged": None,
        }
        if args.dry_run:
            print(f"[{i}/{len(targets)}] would classify {row['repo']} {str(row['sha'])[:12]} "
                  f"({row.get('diff_bytes')} B, msg_class={row.get('msg_class')}, leak={leaks})")
        else:
            assert cfg is not None
            try:
                rec["flagged"] = openai_classify(cfg, diff_text)
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode("utf-8", errors="replace")[:200] if exc.fp else ""
                sys.exit(f"HTTP {exc.code} from endpoint on {row['repo']} {row['sha']}: {detail}")
            except urllib.error.URLError as exc:
                sys.exit(f"Endpoint unreachable: {exc.reason}")
            mark = "YES" if rec["flagged"] else "no "
            print(f"[{i}/{len(targets)}] {mark} {row['repo']} {str(row['sha'])[:12]} "
                  f"(msg_class={row.get('msg_class')}{', leak' if leaks else ''})")
        results.append(rec)

    if args.dry_run:
        print(f"\nDry run: {len(targets)} commit(s) would be classified.")
        return

    recall = summarize_recall(results)
    by_role = summarize_by_role(results)  # None if nothing labelled
    result: dict[str, Any] = {
        "kind": "recall",
        "run_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "config": {
            "model": cfg.model if cfg else None,
            "base_url": cfg.base_url if cfg else None,
            "prompt_hash": prompt_hash(),
            "message_condition": "M2_none",  # diff-only, no commit message
            "temperature": 0,
        },
        "corpus": {
            "dir": str(GHSA_COMMITS_DIR),
            "schema_version": manifest.get("schema_version"),
            "built_at": manifest.get("built_at"),
            "ecosystem": manifest.get("ecosystem"),
            "labels_applied": manifest.get("labels_applied"),
            "targets_scored": len(results),
        },
        "recall": recall,
        "by_role": by_role,
        "commits": results,
    }

    # --- Human-readable summary ---
    cl = recall["commit_level"]
    al = recall["advisory_level"]
    print("\n" + "=" * 60)
    print(f"model={result['config']['model']}  prompt={prompt_hash()[:19]}…")
    print(f"scored {len(results)} commit(s) across {al['n']} advisory(ies)")
    print("-" * 60)
    print(f"  commit flag-rate (overall) : {cl['overall']['flagged']}/{cl['overall']['n']} = {cl['overall']['flag_rate']}")
    for c in ("quiet", "announced", "empty", "merge_noise"):
        if c in cl:
            print(f"    {c:12} : {cl[c]['flagged']}/{cl[c]['n']} = {cl[c]['flag_rate']}")
    qc = cl["quiet_clean"]
    print(f"    quiet (clean): {qc['flagged']}/{qc['n']} = {qc['flag_rate']}  (excluded {qc['excluded_leaking']} leaking)")
    print(f"  advisory-level recall       : {al['caught']}/{al['n']} = {al['recall']}")
    if by_role is None:
        print(f"  {'(no role labels — headline is advisory-level above)':<44}")
    else:
        fr = by_role["fix_recall"]
        fp = by_role["nonfix_false_positives"]
        print("-" * 60)
        print(f"  LABEL-AWARE ({by_role['labelled']} labelled, {by_role['unlabelled']} not)  roles={by_role['role_counts']}")
        print(f"    fix recall            : {fr['flagged']}/{fr['n']} = {fr['recall']}   <- headline")
        if fr["missed"]:
            for m in fr["missed"]:
                print(f"        MISSED fix: {m['repo']} {str(m['sha'])[:12]} (msg_class={m['msg_class']})")
        print(f"    non-fix false positives: {fp['flagged']}/{fp['n']} = {fp['fp_rate']}  (proto-FPR)")
        for d in fp["flagged_detail"]:
            print(f"        FALSE POSITIVE: {d['repo']} {str(d['sha'])[:12]} (role={d['role']})")
        if by_role["backport"]["n"]:
            bp = by_role["backport"]
            print(f"    backports             : {bp['flagged']}/{bp['n']} flagged (dup fixes; excluded from recall)")
    print("=" * 60)

    out = args.out
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"\nWrote {out}")
    else:
        print("\n(no --out given; result not persisted)")


if __name__ == "__main__":
    main()
