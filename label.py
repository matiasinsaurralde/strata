"""Hand-label commit roles into labels.jsonl (CLI or local web UI).

Reads the built bundle (ghsa-commits/commits.jsonl), walks commits that are not
yet labelled, and records a role per commit. Labels are keyed by (host, repo, sha)
and appended to labels.jsonl, which main.py merges back into `role` on every rebuild.

Usage:
    python label.py                 # CLI: label everything unlabelled
    python label.py --relabel       # also revisit already-labelled commits
    python label.py --limit 10      # stop after N
    python label.py --web           # browser UI (same labels.jsonl)
    python label.py --ui            # alias for --web
    python label.py --web --port 9000
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import threading
import urllib.error
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

GHSA_COMMITS_DIR = Path("ghsa-commits")
COMMITS_PATH = GHSA_COMMITS_DIR / "commits.jsonl"
ADVISORIES_PATH = GHSA_COMMITS_DIR / "advisories.jsonl"
LABELS_PATH = Path("labels.jsonl")
UI_PATH = Path("ui.html")
ENV_PATH = Path(".env")

# Single-key → role. 's' skips (no label written); 'q' quits.
ROLE_KEYS: dict[str, str] = {
    "f": "fix",  # the substantive security fix
    "c": "context",  # discussion/changelog/docs-only, not the fix itself
    "b": "backport",  # same logical fix ported to another branch
    "i": "introduce",  # the commit that introduced the flaw
    "o": "other",  # none of the above / bump / unrelated
}
ROLES = tuple(ROLE_KEYS.values())

MENU = "  ".join(f"[{k}]{v}" for k, v in ROLE_KEYS.items()) + "  [s]kip  [q]uit"

# Cap huge diffs for the browser + LLM hint (bytes of text).
DIFF_UI_MAX = 200_000
DIFF_HINT_MAX = 80_000

DEFAULT_HINT_MODEL = "gpt-4o-mini"

SUGGEST_SYSTEM = """\
You assist a human labelling git commits for a security-fix detection eval.
The human will verify your suggestion; be concise and honest about uncertainty.

Roles (pick exactly one):
- fix: the substantive code change that closes a real, pre-existing, exploitable
  vulnerability. Partial fixes still count. Test-only or changelog-only is NOT fix.
- context: related to the advisory but not the fixing code (docs, changelog,
  tests that only verify a fix living elsewhere, discussion refs).
- backport: the same logical fix as another commit, ported to another branch/release.
  Use only when you can tell it duplicates a fix; otherwise prefer fix.
- introduce: the commit that caused the flaw (rare; needs clear evidence).
- other: unrelated, dependency bump, chore, or genuinely undecidable.

Decision rule (revert test): if reverting this commit would bring the vulnerability
back → fix; otherwise not fix. For sampler negatives (no advisory), the usual
label is other unless the diff clearly closes an exploitable vuln.

Reply with JSON only, no markdown:
{"role":"fix|context|backport|introduce|other","confidence":"high|medium|low","rationale":"1-2 sentences"}
"""


def load_dotenv(path: Path = ENV_PATH) -> int:
    """Load KEY=VALUE from .env into os.environ. Real env vars win."""
    if not path.exists():
        return 0
    set_count = 0
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export ") :]
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key and key not in os.environ:
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


def commit_key(row: dict[str, Any]) -> tuple[str, str, str]:
    return (str(row["host"]), str(row["repo"]), str(row["sha"]).lower())


def load_labels(path: Path) -> dict[tuple[str, str, str], dict[str, Any]]:
    """Latest label per key (file may have duplicates if relabelled)."""
    out: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in read_jsonl(path):
        out[commit_key(row)] = row
    return out


def load_label_keys(path: Path) -> set[tuple[str, str, str]]:
    return set(load_labels(path))


def append_label(
    path: Path, row: dict[str, Any], role: str, notes: str | None
) -> dict[str, Any]:
    record = {
        "host": row["host"],
        "repo": row["repo"],
        "sha": str(row["sha"]).lower(),
        "role": role,
        "notes": notes,
    }
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return record


def read_diff(row: dict[str, Any], *, max_chars: int | None = None) -> str | None:
    rel = row.get("diff_path")
    if not rel:
        return None
    path = GHSA_COMMITS_DIR / str(rel)
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8", errors="replace")
    if max_chars is not None and len(text) > max_chars:
        omitted = len(text) - max_chars
        text = text[:max_chars] + f"\n\n… [truncated {omitted} chars]\n"
    return text


def build_queue(
    commits: list[dict[str, Any]],
    labels: dict[tuple[str, str, str], dict[str, Any]],
    *,
    relabel: bool,
    limit: int,
) -> list[dict[str, Any]]:
    if relabel:
        todo = list(commits)
    else:
        todo = [r for r in commits if commit_key(r) not in labels]
    if limit > 0:
        todo = todo[:limit]
    return todo


def show(row: dict[str, Any], advisory: dict[str, Any] | None, idx: int, total: int) -> None:
    print("\n" + "=" * 72)
    print(f"[{idx}/{total}]  {row['repo']}  {str(row['sha'])[:12]}")
    print(
        f"  ghsa       : {row.get('ghsa_id')}  "
        f"({row.get('ordinal')}/{row.get('n_in_advisory')} commits)"
    )
    if advisory:
        summary = (advisory.get("summary") or "").replace("\n", " ").strip()
        print(f"  advisory   : {advisory.get('severity') or '?'} | {summary}")
    elif row.get("source") == "sampler":
        print("  advisory   : (none — sampler negative)")
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


def run_cli(
    commits: list[dict[str, Any]],
    advisories: dict[Any, dict[str, Any]],
    *,
    relabel: bool,
    limit: int,
) -> None:
    labels = load_labels(LABELS_PATH)
    todo = build_queue(commits, labels, relabel=relabel, limit=limit)
    done = sum(1 for c in commits if commit_key(c) in labels and labels[commit_key(c)].get("role"))
    pct = f"{done / len(commits) * 100:.0f}%" if commits else "0%"
    print(f"Progress: {done}/{len(commits)} labelled ({pct}).")
    if not todo:
        print("Nothing to label. (Use --relabel to revisit.)")
        return

    print(f"{len(todo)} commit(s) to go this session.")
    written = 0
    for i, row in enumerate(todo, start=1):
        if limit and written >= limit:
            print(f"\nReached --limit {limit}.")
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
        labels[commit_key(row)] = {"role": role, "notes": notes}
        written += 1
        print(f"  → {role}")

    print(f"\nWrote {written} label(s) to {LABELS_PATH}.")
    print("Re-run main.py --apply-labels-only (or a normal rebuild) to merge into commits.jsonl.")


# --- Web UI ----------------------------------------------------------------


def _is_next_gen(model: str) -> bool:
    m = model.lower()
    return m.startswith(("gpt-5", "gpt-6", "o1", "o3", "o4")) or m.startswith("gpt-5.")


def suggest_role(
    row: dict[str, Any],
    advisory: dict[str, Any] | None,
    diff_text: str | None,
    *,
    model: str,
    base_url: str,
    api_key: str,
) -> dict[str, Any]:
    """Ask the LLM for a role hint. Returns {role, confidence, rationale, model}."""
    if advisory:
        adv_block = (
            f"GHSA: {advisory.get('ghsa_id')}\n"
            f"CVE: {advisory.get('cve_id')}\n"
            f"Severity: {advisory.get('severity')}\n"
            f"Ecosystems: {', '.join(advisory.get('ecosystems') or [])}\n"
            f"Summary: {advisory.get('summary')}\n"
            f"Commit ordinal in advisory: {row.get('ordinal')}/{row.get('n_in_advisory')}"
        )
    else:
        adv_block = (
            "No advisory (source=sampler, ghsa_referenced=false). "
            "This is a sampled negative for the FPR arm."
        )

    diff_block = diff_text if diff_text is not None else "(no diff available)"
    if len(diff_block) > DIFF_HINT_MAX:
        omitted = len(diff_block) - DIFF_HINT_MAX
        diff_block = diff_block[:DIFF_HINT_MAX] + f"\n\n… [truncated {omitted} chars]\n"

    user = (
        f"## Advisory\n{adv_block}\n\n"
        f"## Commit\n"
        f"repo: {row.get('repo')}\n"
        f"sha: {row.get('sha')}\n"
        f"source: {row.get('source')}\n"
        f"msg_class: {row.get('msg_class')}\n"
        f"subject: {row.get('subject')}\n"
        f"message:\n{row.get('message') or ''}\n\n"
        f"## Diff\n```\n{diff_block}\n```\n"
    )

    payload_obj: dict[str, Any] = {
        "model": model,
        "messages": [
            {"role": "system", "content": SUGGEST_SYSTEM},
            {"role": "user", "content": user},
        ],
    }
    if _is_next_gen(model):
        payload_obj["max_completion_tokens"] = 1024
    else:
        payload_obj["temperature"] = 0
        payload_obj["max_tokens"] = 300
        payload_obj["response_format"] = {"type": "json_object"}

    body = json.dumps(payload_obj).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url.rstrip('/')}/chat/completions",
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "strata-label",
        },
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    content = (payload["choices"][0]["message"]["content"] or "").strip()
    # Tolerate accidental markdown fences.
    if content.startswith("```"):
        content = re.sub(r"^```(?:json)?\s*", "", content)
        content = re.sub(r"\s*```$", "", content)
    parsed = json.loads(content)
    role = str(parsed.get("role") or "").strip().lower()
    if role not in ROLES:
        raise ValueError(f"model returned invalid role: {role!r}")
    confidence = str(parsed.get("confidence") or "medium").strip().lower()
    if confidence not in ("high", "medium", "low"):
        confidence = "medium"
    rationale = str(parsed.get("rationale") or "").strip() or None
    return {
        "role": role,
        "confidence": confidence,
        "rationale": rationale,
        "model": model,
    }


class LabelStore:
    """In-memory bundle + labels for the web UI."""

    def __init__(
        self,
        commits: list[dict[str, Any]],
        advisories: dict[Any, dict[str, Any]],
        *,
        relabel: bool,
        limit: int,
    ) -> None:
        self.commits = commits
        self.advisories = advisories
        self.relabel = relabel
        self.limit = limit
        self.lock = threading.Lock()
        self.labels = load_labels(LABELS_PATH)
        self.queue = build_queue(commits, self.labels, relabel=relabel, limit=limit)
        self.session_written = 0
        self._by_key = {commit_key(r): r for r in commits}

    def refresh_queue(self) -> None:
        self.queue = build_queue(
            self.commits, self.labels, relabel=self.relabel, limit=self.limit
        )

    def progress(self) -> dict[str, Any]:
        labelled = sum(
            1 for c in self.commits if self.labels.get(commit_key(c), {}).get("role")
        )
        total = len(self.commits)
        return {
            "total": total,
            "labelled": labelled,
            "queue_len": len(self.queue),
            "session_written": self.session_written,
            "relabel": self.relabel,
            "limit": self.limit,
        }

    def queue_summaries(self) -> list[dict[str, Any]]:
        out = []
        for r in self.queue:
            out.append(
                {
                    "host": r["host"],
                    "repo": r["repo"],
                    "sha": str(r["sha"]).lower(),
                    "ghsa_id": r.get("ghsa_id"),
                    "subject": r.get("subject"),
                    "source": r.get("source"),
                    "ghsa_referenced": r.get("ghsa_referenced"),
                    "msg_class": r.get("msg_class"),
                    "ordinal": r.get("ordinal"),
                    "n_in_advisory": r.get("n_in_advisory"),
                }
            )
        return out

    def get_row(self, host: str, repo: str, sha: str) -> dict[str, Any] | None:
        return self._by_key.get((host, repo, sha.lower()))

    def siblings(self, row: dict[str, Any]) -> list[dict[str, Any]]:
        gid = row.get("ghsa_id")
        if not gid:
            return []
        sibs = [c for c in self.commits if c.get("ghsa_id") == gid]
        sibs.sort(key=lambda c: (c.get("ordinal") or 0, str(c.get("sha"))))
        out = []
        for c in sibs:
            lab = self.labels.get(commit_key(c))
            out.append(
                {
                    "ordinal": c.get("ordinal"),
                    "sha": str(c["sha"]).lower(),
                    "subject": c.get("subject"),
                    "role": (lab or {}).get("role"),
                }
            )
        return out

    def item_payload(self, row: dict[str, Any]) -> dict[str, Any]:
        advisory = self.advisories.get(row.get("ghsa_id"))
        diff = read_diff(row, max_chars=DIFF_UI_MAX)
        lab = self.labels.get(commit_key(row))
        return {
            "host": row["host"],
            "repo": row["repo"],
            "sha": str(row["sha"]).lower(),
            "url": row.get("url"),
            "ordinal": row.get("ordinal"),
            "n_in_advisory": row.get("n_in_advisory") or 0,
            "committed_at": row.get("committed_at"),
            "subject": row.get("subject"),
            "message": row.get("message"),
            "is_merge": row.get("is_merge"),
            "parent_count": row.get("parent_count"),
            "msg_class": row.get("msg_class"),
            "lag_days": row.get("lag_days"),
            "diff_bytes": row.get("diff_bytes"),
            "noise_flags": row.get("noise_flags") or [],
            "ghsa_id": row.get("ghsa_id"),
            "source": row.get("source"),
            "ghsa_referenced": row.get("ghsa_referenced"),
            "diff_path": row.get("diff_path"),
            "diff": diff,
            "advisory": advisory,
            "siblings": self.siblings(row),
            "existing_label": (
                {"role": lab.get("role"), "notes": lab.get("notes")} if lab else None
            ),
        }

    def write_label(self, row: dict[str, Any], role: str, notes: str | None) -> dict[str, Any]:
        with self.lock:
            record = append_label(LABELS_PATH, row, role, notes)
            self.labels[commit_key(row)] = record
            self.session_written += 1
            if not self.relabel:
                self.queue = [r for r in self.queue if commit_key(r) != commit_key(row)]
            return record


def make_handler(store: LabelStore) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

        def _send(self, code: int, body: bytes, content_type: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, obj: Any) -> None:
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self._send(code, body, "application/json; charset=utf-8")

        def _read_json(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length") or "0")
            raw = self.rfile.read(length) if length else b"{}"
            return json.loads(raw.decode("utf-8") or "{}")

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            path = parsed.path

            if path in ("/", "/ui.html", "/index.html"):
                if not UI_PATH.is_file():
                    self._json(500, {"error": f"missing {UI_PATH}"})
                    return
                body = UI_PATH.read_bytes()
                self._send(200, body, "text/html; charset=utf-8")
                return

            if path == "/api/session":
                with store.lock:
                    self._json(
                        200,
                        {
                            **store.progress(),
                            "roles": list(ROLES),
                            "role_keys": ROLE_KEYS,
                            "queue": store.queue_summaries(),
                            "hint_model": os.environ.get("OPENAI_MODEL")
                            or DEFAULT_HINT_MODEL,
                        },
                    )
                return

            if path == "/api/item":
                qs = parse_qs(parsed.query)
                host = (qs.get("host") or [None])[0]
                repo = (qs.get("repo") or [None])[0]
                sha = (qs.get("sha") or [None])[0]
                if not host or not repo or not sha:
                    self._json(400, {"error": "host, repo, sha required"})
                    return
                with store.lock:
                    row = store.get_row(host, repo, sha)
                    if not row:
                        self._json(404, {"error": "commit not found"})
                        return
                    self._json(200, store.item_payload(row))
                return

            self._json(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            path = parsed.path

            if path == "/api/label":
                try:
                    data = self._read_json()
                except json.JSONDecodeError:
                    self._json(400, {"error": "invalid JSON"})
                    return
                host = data.get("host")
                repo = data.get("repo")
                sha = data.get("sha")
                role = data.get("role")
                notes = data.get("notes")
                if notes == "":
                    notes = None
                if not host or not repo or not sha or role not in ROLES:
                    self._json(400, {"error": "host, repo, sha, and valid role required"})
                    return
                with store.lock:
                    row = store.get_row(str(host), str(repo), str(sha))
                if not row:
                    self._json(404, {"error": "commit not found"})
                    return
                record = store.write_label(row, str(role), notes if notes is None else str(notes))
                with store.lock:
                    prog = store.progress()
                self._json(200, {"ok": True, "label": record, **prog})
                return

            if path == "/api/suggest":
                try:
                    data = self._read_json()
                except json.JSONDecodeError:
                    self._json(400, {"error": "invalid JSON"})
                    return
                host = data.get("host")
                repo = data.get("repo")
                sha = data.get("sha")
                if not host or not repo or not sha:
                    self._json(400, {"error": "host, repo, sha required"})
                    return
                with store.lock:
                    row = store.get_row(str(host), str(repo), str(sha))
                    if not row:
                        self._json(404, {"error": "commit not found"})
                        return
                    advisory = store.advisories.get(row.get("ghsa_id"))
                diff = read_diff(row, max_chars=DIFF_HINT_MAX)
                load_dotenv()
                base_url = os.environ.get("OPENAI_BASE_URL")
                api_key = os.environ.get("OPENAI_API_KEY")
                model = os.environ.get("OPENAI_MODEL") or DEFAULT_HINT_MODEL
                if not base_url or not api_key:
                    self._json(
                        503,
                        {
                            "error": "OPENAI_BASE_URL and OPENAI_API_KEY required for hints "
                            "(see .env.example). OPENAI_MODEL defaults to "
                            f"{DEFAULT_HINT_MODEL}."
                        },
                    )
                    return
                try:
                    suggestion = suggest_role(
                        row,
                        advisory,
                        diff,
                        model=model,
                        base_url=base_url,
                        api_key=api_key,
                    )
                except urllib.error.HTTPError as e:
                    detail = e.read().decode("utf-8", errors="replace")[:500]
                    self._json(502, {"error": f"LLM HTTP {e.code}: {detail}"})
                    return
                except Exception as e:  # noqa: BLE001 — surface to UI
                    self._json(502, {"error": str(e)})
                    return
                self._json(200, suggestion)
                return

            self._json(404, {"error": "not found"})

    return Handler


def run_web(
    commits: list[dict[str, Any]],
    advisories: dict[Any, dict[str, Any]],
    *,
    relabel: bool,
    limit: int,
    host: str,
    port: int,
    open_browser: bool,
) -> None:
    if not UI_PATH.is_file():
        sys.exit(f"UI file not found: {UI_PATH}")
    load_dotenv()
    store = LabelStore(commits, advisories, relabel=relabel, limit=limit)
    prog = store.progress()
    print(
        f"Progress: {prog['labelled']}/{prog['total']} labelled. "
        f"Queue: {prog['queue_len']}."
    )
    if prog["queue_len"] == 0:
        print("Nothing to label. (Use --relabel to revisit.)")
        # Still serve UI so the empty state is visible.
    handler = make_handler(store)
    server = ThreadingHTTPServer((host, port), handler)
    url = f"http://{host}:{port}/"
    print(f"Web labeller at {url}")
    print(f"Writing labels to {LABELS_PATH.resolve()}")
    print("Ctrl-C to stop.")
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--relabel", action="store_true", help="revisit labelled commits")
    parser.add_argument("--limit", type=int, default=0, help="stop after N (0 = no limit)")
    parser.add_argument(
        "--web",
        "--ui",
        action="store_true",
        dest="web",
        help="run the browser labelling UI instead of the CLI",
    )
    parser.add_argument("--host", default="127.0.0.1", help="web UI bind host")
    parser.add_argument("--port", type=int, default=8765, help="web UI port")
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="with --web, do not open a browser tab",
    )
    args = parser.parse_args()

    commits = read_jsonl(COMMITS_PATH)
    if not commits:
        sys.exit(f"No commits found at {COMMITS_PATH}. Run main.py first.")
    advisories = {a.get("ghsa_id"): a for a in read_jsonl(ADVISORIES_PATH)}

    if args.web:
        run_web(
            commits,
            advisories,
            relabel=args.relabel,
            limit=args.limit,
            host=args.host,
            port=args.port,
            open_browser=not args.no_browser,
        )
        return

    run_cli(commits, advisories, relabel=args.relabel, limit=args.limit)


if __name__ == "__main__":
    main()
