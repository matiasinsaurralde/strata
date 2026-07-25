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
    python eval.py --parallel 8            # concurrent API calls (default 8)
    python eval.py --arm fpr               # labelled non-fix commits (FPR arm)
    python eval.py --max-diff-bytes 500000 # raise oversize skip for bigger-context models
    python eval.py --dry-run               # no API calls; show what would run
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

GHSA_COMMITS_DIR = Path("ghsa-commits")
COMMITS_PATH = GHSA_COMMITS_DIR / "commits.jsonl"
MANIFEST_PATH = GHSA_COMMITS_DIR / "manifest.json"

# Concurrent /chat/completions. 8 is a solid default for gpt-4o-mini on a
# standard tier; drop to 4 for heavier/reasoning models, try up to ~16 if your
# org RPM allows. Higher than ~16 rarely helps on small corpora and worsens 429s.
DEFAULT_PARALLEL = 8
MAX_PARALLEL = 32
MAX_RETRIES = 12
HTTP_TIMEOUT_S = 120
# Cap a single shared pause so one bad header cannot stall the run for hours.
MAX_BACKOFF_S = 120.0
# Floor for attempt n after a 429: max(header_wait, min(2^(n-1), MAX_BACKOFF_S)).
# Stops burning retries on 1s Retry-After while the TPM bucket is still empty.

# Skip (do not classify) diffs larger than this. Tuned for the default model
# gpt-4o-mini: 128k context + org TPM often ~200k. Dense code is ~2.5–3 chars/token,
# so 200_000 bytes ≈ 65–80k tokens — fits with headroom for the prompt and avoids
# the "Request too large / context length" failures we saw on ~900KB vendor-heavy
# commits (e.g. minio/minio@7c14cdb). Larger-context models can raise this via
# --max-diff-bytes; we keep the full raw diff on disk either way (no corpus filter).
DIFF_SKIP_MAX_BYTES = 200_000

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
# OpenAI x-ratelimit-reset-* values look like "1s", "6m0s", "1h2m3.5s".
_RESET_DUR_RE = re.compile(
    r"^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+(?:\.\d+)?)s)?$"
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


def _is_next_gen(model: str) -> bool:
    """gpt-5+ and o-series use max_completion_tokens and reject temperature!=1."""
    m = model.lower()
    return m.startswith(("gpt-5", "gpt-6", "o1", "o3", "o4")) or m.startswith("gpt-5.")


def parse_reset_duration(value: str | None) -> float | None:
    """Parse OpenAI reset header ("1s", "6m0s") or plain seconds into a float delay."""
    if value is None:
        return None
    s = value.strip().lower()
    if not s:
        return None
    try:
        return max(0.0, float(s))
    except ValueError:
        pass
    m = _RESET_DUR_RE.match(s)
    if not m or not any(m.groups()):
        return None
    hours = int(m.group(1) or 0)
    mins = int(m.group(2) or 0)
    secs = float(m.group(3) or 0)
    return hours * 3600 + mins * 60 + secs


def retry_wait_seconds(headers: dict[str, str], *, default: float = 5.0) -> float:
    """Seconds to sleep after a 429, preferring Retry-After then reset-* headers."""
    ra = headers.get("retry-after")
    if ra is not None:
        try:
            return max(1.0, float(ra.strip()))
        except ValueError:
            parsed = parse_reset_duration(ra)
            if parsed is not None:
                return max(1.0, parsed)
    waits = []
    for key in ("x-ratelimit-reset-requests", "x-ratelimit-reset-tokens"):
        parsed = parse_reset_duration(headers.get(key))
        if parsed is not None:
            waits.append(parsed)
    if waits:
        return max(1.0, min(waits))
    return default


def rate_limit_backoff_seconds(headers: dict[str, str], attempt: int) -> float:
    """Combine API headers with an exponential floor so short Retry-After cannot burn retries."""
    header_wait = retry_wait_seconds(headers)
    floor = min(2.0 ** max(0, attempt - 1), MAX_BACKOFF_S)
    return min(MAX_BACKOFF_S, max(header_wait, floor))


class RateLimitGate:
    """Shared pause across worker threads when any call hits a rate limit."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._wait_until = 0.0

    def wait_turn(self) -> None:
        while True:
            with self._lock:
                delay = self._wait_until - time.monotonic()
            if delay <= 0:
                return
            time.sleep(min(delay, 1.0))

    def backoff(self, seconds: float, *, why: str = "rate limit") -> None:
        seconds = max(1.0, min(float(seconds), MAX_BACKOFF_S))
        with self._lock:
            until = time.monotonic() + seconds
            if until > self._wait_until:
                self._wait_until = until
                print(
                    f"  … {why}: backing off {seconds:.1f}s (all workers pause)",
                    file=sys.stderr,
                    flush=True,
                )


_PRINT_LOCK = threading.Lock()


def _header_map(headers: Any) -> dict[str, str]:
    if not headers:
        return {}
    return {str(k).lower(): str(v) for k, v in headers.items()}


def skip_oversize_diff(
    row: dict[str, Any],
    diff_text: str,
    max_bytes: int = DIFF_SKIP_MAX_BYTES,
) -> str | None:
    """Return a skip reason if this diff should not be sent to the model, else None.

    Uses max(diff_bytes meta, on-disk length) so a stale meta cannot sneak a huge
    file past the gate. See DIFF_SKIP_MAX_BYTES for the gpt-4o-mini rationale.
    """
    meta = row.get("diff_bytes")
    try:
        meta_n = int(meta) if meta is not None else 0
    except (TypeError, ValueError):
        meta_n = 0
    n = max(meta_n, len(diff_text.encode("utf-8")))
    if n > max_bytes:
        return f"diff too large ({n} B > {max_bytes} B skip cap)"
    return None


def is_request_too_large(detail: str) -> bool:
    """True only for single-request overflow, not transient TPM bucket exhaustion.

    OpenAI uses HTTP 429 for both:
      - "Request too large … Requested 228721" (this call alone > Limit) → do not retry
      - "Rate limit reached … Used 195000, Requested 8000" (bucket empty) → backoff/retry
    """
    d = detail.lower()
    if "request too large" in d:
        return True
    # Fallback: Requested exceeds Limit in the message (single-call overflow).
    m = re.search(
        r"limit\s+(\d+).*?requested\s+(\d+)",
        d,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if m:
        limit_n, requested_n = int(m.group(1)), int(m.group(2))
        return requested_n > limit_n
    return False


def openai_chat_completion(cfg: EndpointConfig, diff_text: str, gate: RateLimitGate) -> str:
    """POST /chat/completions; return message content. Honours 429 + RL headers."""
    payload_obj: dict[str, Any] = {
        "model": cfg.model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": USER_PROMPT_TEMPLATE.format(diff=diff_text)},
        ],
    }
    if _is_next_gen(cfg.model):
        payload_obj["max_completion_tokens"] = 2048  # room for reasoning + answer
    else:
        payload_obj["temperature"] = 0
        payload_obj["max_tokens"] = 4
    body = json.dumps(payload_obj).encode("utf-8")

    last_err: Exception | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        gate.wait_turn()
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
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_S) as resp:
                headers = _header_map(resp.headers)
                # Soft throttle: if the bucket is empty, pause before the next call.
                rem = headers.get("x-ratelimit-remaining-requests")
                if rem is not None:
                    try:
                        if int(float(rem)) <= 0:
                            wait = retry_wait_seconds(headers, default=1.0)
                            gate.backoff(wait, why="x-ratelimit-remaining-requests=0")
                    except ValueError:
                        pass
                return json.loads(resp.read().decode("utf-8"))["choices"][0]["message"][
                    "content"
                ]
        except urllib.error.HTTPError as exc:
            last_err = exc
            headers = _header_map(exc.headers)
            detail = exc.read().decode("utf-8", errors="replace")[:500] if exc.fp else ""
            # Oversized single request — retrying the same body will never succeed.
            if exc.code == 429 and is_request_too_large(detail):
                raise RuntimeError(f"request too large: {detail}") from exc
            if exc.code == 429 or (exc.code == 503 and "rate" in detail.lower()):
                wait = rate_limit_backoff_seconds(headers, attempt)
                gate.backoff(
                    wait,
                    why=f"HTTP {exc.code} (attempt {attempt}/{MAX_RETRIES})",
                )
                continue
            raise RuntimeError(f"HTTP {exc.code} from endpoint: {detail or exc.reason}") from exc
        except urllib.error.URLError as exc:
            last_err = exc
            # Transient network blip — short backoff, then retry.
            gate.backoff(min(2.0 * attempt, 15.0), why=f"network ({exc.reason})")
            continue
    assert last_err is not None
    raise last_err


def openai_classify(
    cfg: EndpointConfig,
    diff_text: str,
    gate: RateLimitGate | None = None,
) -> bool:
    """One /chat/completions call, strict YES/NO parse.

    Newer models (gpt-5+/o-series) rename max_tokens -> max_completion_tokens and
    only accept the default temperature, so branch on the model family. They may
    also emit reasoning tokens, so give them more headroom before the answer.
    """
    content = openai_chat_completion(cfg, diff_text, gate or RateLimitGate()).strip().upper()
    # Lenient parse: first YES/NO token wins; unparseable → NO (conservative).
    for token in re.findall(r"[A-Z]+", content):
        if token in ("YES", "NO"):
            return token == "YES"
    return False


def classify_targets(
    targets: list[dict[str, Any]],
    cfg: EndpointConfig,
    *,
    parallel: int,
    max_diff_bytes: int = DIFF_SKIP_MAX_BYTES,
) -> list[dict[str, Any]]:
    """Classify each target; preserve input order. parallel=1 is sequential."""
    gate = RateLimitGate()
    total = len(targets)
    results: list[dict[str, Any] | None] = [None] * total

    def one(i: int, row: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        diff_path = GHSA_COMMITS_DIR / row["diff_path"]
        diff_text = diff_path.read_text(encoding="utf-8", errors="replace")
        leaks = diff_leaks_disclosure(diff_text)
        rec: dict[str, Any] = {
            "ghsa_id": row.get("ghsa_id"),
            "repo": row.get("repo"),
            "sha": row.get("sha"),
            "msg_class": row.get("msg_class"),
            "role": row.get("role"),
            "source": row.get("source"),
            "diff_bytes": row.get("diff_bytes"),
            "diff_leaks_disclosure": leaks,
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

        try:
            rec["flagged"] = openai_classify(cfg, diff_text, gate)
        except Exception as exc:  # noqa: BLE001 — one bad commit must not abort the run
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
                f"(msg_class={row.get('msg_class')}{', leak' if leaks else ''})",
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


def summarize_fpr(results: list[dict[str, Any]]) -> dict[str, Any]:
    """False-positive rate on labelled non-fix commits (sampler + GHSA context/other)."""
    scored = [r for r in results if r.get("flagged") is not None]
    nonfix = [r for r in scored if r.get("role") in NONFIX_ROLES]
    flagged = [r for r in nonfix if r["flagged"]]
    by_source: dict[str, dict[str, int]] = {}
    for r in nonfix:
        src = str(r.get("source") or "unknown")
        b = by_source.setdefault(src, {"n": 0, "flagged": 0})
        b["n"] += 1
        b["flagged"] += 1 if r["flagged"] else 0
    by_role: dict[str, dict[str, int]] = {}
    for r in nonfix:
        role = str(r.get("role"))
        b = by_role.setdefault(role, {"n": 0, "flagged": 0})
        b["n"] += 1
        b["flagged"] += 1 if r["flagged"] else 0
    return {
        "n": len(nonfix),
        "flagged": len(flagged),
        "fpr": pct(len(flagged), len(nonfix)),
        "errors": sum(1 for r in results if r.get("error") and not r.get("skipped_oversize")),
        "skipped_oversize": sum(1 for r in results if r.get("skipped_oversize")),
        "by_source": {
            s: {**b, "fpr": pct(b["flagged"], b["n"])} for s, b in sorted(by_source.items())
        },
        "by_role": {
            s: {**b, "fpr": pct(b["flagged"], b["n"])} for s, b in sorted(by_role.items())
        },
        "flagged_detail": [
            {
                "repo": r.get("repo"),
                "sha": r.get("sha"),
                "role": r.get("role"),
                "source": r.get("source"),
                "msg_class": r.get("msg_class"),
            }
            for r in flagged
        ],
    }


def select_targets(commits: list[dict[str, Any]], arm: str) -> list[dict[str, Any]]:
    """Pick commits for an eval arm."""
    resolved = [
        r for r in commits if r.get("resolved") and r.get("diff_path")
    ]
    if arm == "recall":
        return [r for r in resolved if r.get("ghsa_referenced")]
    if arm == "fpr":
        # Labelled non-fixes only — mostly sampler negatives; GHSA context/other included.
        return [r for r in resolved if r.get("role") in NONFIX_ROLES]
    raise ValueError(f"unknown arm: {arm}")


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
    parser.add_argument(
        "--arm",
        choices=("recall", "fpr"),
        default="recall",
        help="recall=GHSA-referenced commits; fpr=labelled non-fix commits (sampler + context/other)",
    )
    parser.add_argument(
        "--parallel",
        "-j",
        type=int,
        default=DEFAULT_PARALLEL,
        metavar="N",
        help=(
            f"concurrent API calls (default {DEFAULT_PARALLEL}; "
            f"suggest 4 for heavy/reasoning models, up to 16 for gpt-4o-mini; "
            f"max {MAX_PARALLEL})"
        ),
    )
    parser.add_argument(
        "--max-diff-bytes",
        type=int,
        default=DIFF_SKIP_MAX_BYTES,
        metavar="N",
        help=(
            f"skip (do not classify) diffs larger than N bytes "
            f"(default {DIFF_SKIP_MAX_BYTES}; tuned for gpt-4o-mini 128k context)"
        ),
    )
    parser.add_argument("--dry-run", action="store_true", help="no API calls")
    parser.add_argument("--env-file", type=Path, default=Path(".env"), help="dotenv path")
    args = parser.parse_args()

    if args.parallel < 1:
        sys.exit("--parallel must be >= 1")
    if args.parallel > MAX_PARALLEL:
        sys.exit(f"--parallel max is {MAX_PARALLEL}")
    if args.max_diff_bytes < 1:
        sys.exit("--max-diff-bytes must be >= 1")

    load_dotenv(args.env_file)

    commits = read_jsonl(COMMITS_PATH)
    if not commits:
        sys.exit(f"No commits at {COMMITS_PATH}. Run main.py first.")
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8")) if MANIFEST_PATH.exists() else {}

    targets = select_targets(commits, args.arm)
    if args.limit:
        targets = targets[: args.limit]
    if not targets:
        sys.exit(
            f"No targets for --arm {args.arm}. "
            "For fpr: need labelled non-fix roles in commits.jsonl "
            "(run main.py --apply-labels-only after labelling)."
        )

    if args.dry_run:
        n_would_skip = 0
        for i, row in enumerate(targets, start=1):
            db = row.get("diff_bytes") or 0
            skip = isinstance(db, int) and db > args.max_diff_bytes
            if skip:
                n_would_skip += 1
            verb = "would skip" if skip else "would classify"
            print(
                f"[{i}/{len(targets)}] {verb} {row['repo']} {str(row['sha'])[:12]} "
                f"(role={row.get('role')}, source={row.get('source')}, "
                f"{row.get('diff_bytes')} B)"
            )
        print(
            f"\nDry run: {len(targets)} commit(s), {n_would_skip} oversize skip "
            f"(--arm {args.arm}, --parallel {args.parallel}, "
            f"--max-diff-bytes {args.max_diff_bytes})."
        )
        return

    cfg = EndpointConfig.from_env()
    workers = max(1, min(args.parallel, len(targets) or 1, MAX_PARALLEL))
    print(
        f"Classifying {len(targets)} commit(s) arm={args.arm} parallel={workers} "
        f"max_diff_bytes={args.max_diff_bytes} (model={cfg.model})…"
    )
    try:
        results = classify_targets(
            targets, cfg, parallel=workers, max_diff_bytes=args.max_diff_bytes
        )
    except urllib.error.HTTPError as exc:
        detail = ""
        if exc.fp is not None:
            detail = exc.read().decode("utf-8", errors="replace")[:300]
        sys.exit(f"HTTP {exc.code} from endpoint: {detail or exc.reason}")
    except urllib.error.URLError as exc:
        sys.exit(f"Endpoint unreachable: {exc.reason}")
    except RuntimeError as exc:
        sys.exit(str(exc))

    n_skip = sum(1 for r in results if r.get("skipped_oversize"))
    n_err = sum(1 for r in results if r.get("error") and not r.get("skipped_oversize"))
    n_scored = sum(1 for r in results if r.get("flagged") is not None)

    result: dict[str, Any] = {
        "kind": args.arm,
        "run_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "config": {
            "model": cfg.model,
            "base_url": cfg.base_url,
            "prompt_hash": prompt_hash(),
            "message_condition": "M2_none",
            "temperature": 0,
            "parallel": workers,
            "arm": args.arm,
            "max_diff_bytes": args.max_diff_bytes,
        },
        "corpus": {
            "dir": str(GHSA_COMMITS_DIR),
            "schema_version": manifest.get("schema_version"),
            "built_at": manifest.get("built_at"),
            "ecosystem": manifest.get("ecosystem"),
            "labels_applied": manifest.get("labels_applied"),
            "targets_scored": len(results),
            "classified": n_scored,
            "skipped_oversize": n_skip,
            "errors": n_err,
        },
        "commits": results,
    }

    print("\n" + "=" * 60)
    print(
        f"model={cfg.model}  prompt={prompt_hash()[:19]}…  "
        f"parallel={workers}  arm={args.arm}  max_diff_bytes={args.max_diff_bytes}"
    )
    print(f"scored {len(results)} commit(s)")
    if n_skip or n_err:
        print(
            f"  ({n_scored} classified, {n_skip} skipped oversize, {n_err} errors)"
        )
    print("-" * 60)

    if args.arm == "recall":
        recall = summarize_recall(results)
        by_role = summarize_by_role(results)
        result["recall"] = recall
        result["by_role"] = by_role
        cl = recall["commit_level"]
        al = recall["advisory_level"]
        print(
            f"  commit flag-rate (overall) : {cl['overall']['flagged']}/"
            f"{cl['overall']['n']} = {cl['overall']['flag_rate']}"
        )
        for c in ("quiet", "announced", "empty", "merge_noise"):
            if c in cl:
                print(
                    f"    {c:12} : {cl[c]['flagged']}/{cl[c]['n']} = {cl[c]['flag_rate']}"
                )
        qc = cl["quiet_clean"]
        print(
            f"    quiet (clean): {qc['flagged']}/{qc['n']} = {qc['flag_rate']}  "
            f"(excluded {qc['excluded_leaking']} leaking)"
        )
        print(f"  advisory-level recall       : {al['caught']}/{al['n']} = {al['recall']}")
        if by_role is None:
            print("  (no role labels — headline is advisory-level above)")
        else:
            fr = by_role["fix_recall"]
            fp = by_role["nonfix_false_positives"]
            print("-" * 60)
            print(
                f"  LABEL-AWARE ({by_role['labelled']} labelled, "
                f"{by_role['unlabelled']} not)  roles={by_role['role_counts']}"
            )
            print(
                f"    fix recall            : {fr['flagged']}/{fr['n']} = "
                f"{fr['recall']}   <- headline"
            )
            for m in fr["missed"]:
                print(
                    f"        MISSED fix: {m['repo']} {str(m['sha'])[:12]} "
                    f"(msg_class={m['msg_class']})"
                )
            print(
                f"    non-fix false positives: {fp['flagged']}/{fp['n']} = "
                f"{fp['fp_rate']}  (proto-FPR on GHSA arm only)"
            )
            for d in fp["flagged_detail"]:
                print(
                    f"        FALSE POSITIVE: {d['repo']} {str(d['sha'])[:12]} "
                    f"(role={d['role']})"
                )
    else:
        fpr = summarize_fpr(results)
        result["fpr"] = fpr
        print(f"  FPR (non-fix flagged) : {fpr['flagged']}/{fpr['n']} = {fpr['fpr']}   <- headline")
        for src, b in fpr["by_source"].items():
            print(f"    source={src:8} : {b['flagged']}/{b['n']} = {b['fpr']}")
        for role, b in fpr["by_role"].items():
            print(f"    role={role:8} : {b['flagged']}/{b['n']} = {b['fpr']}")
        if fpr["flagged_detail"]:
            print("-" * 60)
            print(f"  FALSE POSITIVES ({len(fpr['flagged_detail'])}):")
            for d in fpr["flagged_detail"]:
                print(
                    f"        {d['repo']} {str(d['sha'])[:12]} "
                    f"(role={d['role']}, source={d['source']}, msg_class={d['msg_class']})"
                )

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
