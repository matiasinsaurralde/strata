"""Minimal CLI to hand-label commit roles into labels.jsonl.

Reads the built bundle (ghsa-commits/commits.jsonl), walks commits that are not
yet labelled, shows subject + advisory summary + local diff path, and records a
role per commit. Labels are keyed by (host, repo, sha) and appended to
labels.jsonl, which main.py merges back into `role` on every rebuild.

This is deliberately tiny — enough to label 5-10 commits for an E2E test. A
richer diff-rendering surface (see the HTML labeller idea) is for the real
~150-250 item run, not this slice.

Usage:
    python label.py                 # label everything unlabelled
    python label.py --relabel       # also revisit already-labelled commits
    python label.py --limit 10      # stop after N
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

GHSA_COMMITS_DIR = Path("ghsa-commits")
COMMITS_PATH = GHSA_COMMITS_DIR / "commits.jsonl"
ADVISORIES_PATH = GHSA_COMMITS_DIR / "advisories.jsonl"
LABELS_PATH = Path("labels.jsonl")

# Single-key → role. 's' skips (no label written); 'q' quits.
ROLE_KEYS: dict[str, str] = {
    "f": "fix",          # the substantive security fix
    "c": "context",      # discussion/changelog/docs-only, not the fix itself
    "b": "backport",     # same logical fix ported to another branch
    "i": "introduce",    # the commit that introduced the flaw
    "o": "other",        # none of the above / bump / unrelated
}

MENU = "  ".join(f"[{k}]{v}" for k, v in ROLE_KEYS.items()) + "  [s]kip  [q]uit"


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


def commit_key(row: dict[str, Any]) -> tuple[str, str, str]:
    return (str(row["host"]), str(row["repo"]), str(row["sha"]).lower())


def load_label_keys(path: Path) -> set[tuple[str, str, str]]:
    """Keys already present in labels.jsonl (any role, including None-skips)."""
    return {commit_key(r) for r in read_jsonl(path)}


def append_label(
    path: Path, row: dict[str, Any], role: str, notes: str | None
) -> None:
    record = {
        "host": row["host"],
        "repo": row["repo"],
        "sha": str(row["sha"]).lower(),
        "role": role,
        "notes": notes,
    }
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def show(row: dict[str, Any], advisory: dict[str, Any] | None, idx: int, total: int) -> None:
    print("\n" + "=" * 72)
    print(f"[{idx}/{total}]  {row['repo']}  {str(row['sha'])[:12]}")
    print(f"  ghsa       : {row.get('ghsa_id')}  ({row.get('ordinal')}/{row.get('n_in_advisory')} commits)")
    if advisory:
        summary = (advisory.get("summary") or "").replace("\n", " ").strip()
        print(f"  advisory   : {advisory.get('severity') or '?'} | {summary}")
    print(f"  subject    : {row.get('subject')}")
    print(f"  msg_class  : {row.get('msg_class')}   noise={row.get('noise_flags')}")
    diff_path = row.get("diff_path")
    if diff_path:
        print(f"  diff       : {(GHSA_COMMITS_DIR / diff_path)}")
    else:
        print("  diff       : (unresolved — no diff)")
    print(f"  url        : {row.get('url')}")


def prompt_role() -> tuple[str | None, bool]:
    """Return (role_or_None, quit). role None with quit False means skip."""
    while True:
        try:
            choice = input(f"\n  {MENU}\n  > ").strip().lower()
        except EOFError:
            return None, True
        if choice == "q":
            return None, True
        if choice == "s" or choice == "":
            return None, False
        if choice in ROLE_KEYS:
            return ROLE_KEYS[choice], False
        print(f"  ? unrecognized: {choice!r}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--relabel", action="store_true", help="revisit labelled commits")
    parser.add_argument("--limit", type=int, default=0, help="stop after N (0 = no limit)")
    args = parser.parse_args()

    commits = read_jsonl(COMMITS_PATH)
    if not commits:
        sys.exit(f"No commits found at {COMMITS_PATH}. Run main.py first.")
    advisories = {a.get("ghsa_id"): a for a in read_jsonl(ADVISORIES_PATH)}

    labelled = set() if args.relabel else load_label_keys(LABELS_PATH)
    todo = [r for r in commits if commit_key(r) not in labelled]

    done = len(commits) - len([r for r in commits if commit_key(r) not in load_label_keys(LABELS_PATH)])
    pct = f"{done / len(commits) * 100:.0f}%" if commits else "0%"
    print(f"Progress: {done}/{len(commits)} labelled ({pct}).")
    if not todo:
        print("Nothing to label. (Use --relabel to revisit.)")
        return

    print(f"{len(todo)} commit(s) to go this session.")
    written = 0
    for i, row in enumerate(todo, start=1):
        if args.limit and written >= args.limit:
            print(f"\nReached --limit {args.limit}.")
            break
        show(row, advisories.get(row.get("ghsa_id")), i, len(todo))
        role, quit_now = prompt_role()
        if quit_now:
            print("\nQuit.")
            break
        if role is None:
            print("  skipped")
            continue
        notes = input("  notes (optional): ").strip() or None
        append_label(LABELS_PATH, row, role, notes)
        written += 1
        print(f"  → {role}")

    print(f"\nWrote {written} label(s) to {LABELS_PATH}.")
    print("Re-run main.py to merge them into commits.jsonl (role field).")


if __name__ == "__main__":
    main()
