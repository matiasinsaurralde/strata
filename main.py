"""Sample GitHub Security Advisories and write an enriched ghsa-commits index.

Append-only by default: each run adds new advisories/commits to the existing
bundle and never touches rows already present — their diffs, enrichment, and
merged `role` are frozen (GHSA advisories don't change once published). This is
what lets you label incrementally without the ground truth shifting under you.
Pass --fresh to deliberately rebuild from scratch.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import shutil
import urllib.error
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Callable

ADVISORY_DATABASE = Path("advisory-database")
# Advisory corpus under advisories/: "github-reviewed" or "unreviewed".
ADVISORY_SOURCE = "github-reviewed"
# Random sample size. Set to 0 to take every matching advisory (no limit).
SAMPLE_SIZE = 10
# In append mode (default), SAMPLE_SIZE means "add up to N advisories NOT already
# in the bundle" per run. 0 = add every new match. With --fresh it means "take N
# total" as before.
# Ecosystem filter (e.g. "Go", "npm"). Set to None to disable.
ECOSYSTEM: str | None = "Go"
# Inclusive published-date range. None → defaults: start=first of current month, end=today.
START_DATE: date | None = date(2026, 1, 1)
END_DATE: date | None = None
# Output bundle under this directory.
GHSA_COMMITS_DIR = Path("ghsa-commits")
SCHEMA_VERSION = 2
DIFFS_LAYOUT = "diffs/{host}/{owner}/{repo}/{sha}.diff"
# Durable human labels, merged into commit rows on every build. Hand-edited (or
# written by label.py); keyed by (host, repo, sha). Survives the destructive
# rebuild that regenerates GHSA_COMMITS_DIR — that is the whole point.
LABELS_PATH = Path("labels.jsonl")
# Resolve commit metadata + diffs via the GitHub API (uses GITHUB_TOKEN if set).
ENRICH = True

# Matches github.com commit URLs, including pull request commit links.
GITHUB_COMMIT_URL_RE = re.compile(
    r"https?://(?:www\.)?github\.com/"
    r"(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)/"
    r"(?:commit|pull/\d+/commits)/(?P<sha>[0-9a-fA-F]{7,40})"
    r"(?:[/?#][^\s\"'<>)\]}>]*)?",
    re.IGNORECASE,
)

CVE_OR_GHSA_RE = re.compile(
    r"\b(?:CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})\b",
    re.IGNORECASE,
)
MERGE_SUBJECT_RE = re.compile(
    r"^(?:Merge(?:\s+(?:pull request|branch|commit|remote-tracking))?|"
    r"Merge commit from fork)\b",
    re.IGNORECASE,
)
# Independent security keywords for msg_class=announced (≥2 matches, or a CVE/GHSA id).
SECURITY_KEYWORDS: tuple[str, ...] = (
    "security",
    "vulnerab",
    "cve-",
    "ghsa-",
    "xss",
    "csrf",
    "ssrf",
    "rce",
    "auth bypass",
    "authentication bypass",
    "privilege escalation",
    "injection",
    "overflow",
    "sanitiz",
    "exploit",
    "advisory",
    "cwe-",
    "unauth",
    "path traversal",
    "directory traversal",
    "remote code",
    "arbitrary code",
    "fixme",
)

MSG_CLASS_ANNOUNCED = "announced"
MSG_CLASS_QUIET = "quiet"
MSG_CLASS_EMPTY = "empty"
MSG_CLASS_MERGE_NOISE = "merge_noise"

GithubGet = Callable[[str, str | None], tuple[int, bytes, dict[str, str]]]


def resolve_date_range(
    start: date | None,
    end: date | None,
    today: date | None = None,
) -> tuple[date, date]:
    """Resolve START/END defaults: end=today, start=first day of end's month."""
    today = today or date.today()
    resolved_end = end or today
    resolved_start = start or resolved_end.replace(day=1)
    if resolved_start > resolved_end:
        raise ValueError(
            f"START_DATE ({resolved_start}) must be on or before END_DATE ({resolved_end})"
        )
    return resolved_start, resolved_end


def iter_month_dirs(
    root: Path,
    start: date,
    end: date,
    source: str = "github-reviewed",
) -> list[Path]:
    """Return existing year/month dirs under advisories/<source> overlapping [start, end]."""
    if source not in {"github-reviewed", "unreviewed"}:
        raise ValueError(
            f"ADVISORY_SOURCE must be 'github-reviewed' or 'unreviewed', got {source!r}"
        )
    dirs: list[Path] = []
    year, month = start.year, start.month
    while (year, month) <= (end.year, end.month):
        month_dir = root / "advisories" / source / f"{year:04d}" / f"{month:02d}"
        if month_dir.is_dir():
            dirs.append(month_dir)
        if month == 12:
            year, month = year + 1, 1
        else:
            month += 1
    return dirs


def list_advisory_files(month_dirs: list[Path]) -> list[Path]:
    files: list[Path] = []
    for month_dir in month_dirs:
        files.extend(sorted(month_dir.glob("GHSA-*/GHSA-*.json")))
    return files


def parse_advisory(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def advisory_published_date(advisory: dict) -> date | None:
    published = advisory.get("published")
    if not published or not isinstance(published, str):
        return None
    try:
        return datetime.fromisoformat(published.replace("Z", "+00:00")).date()
    except ValueError:
        return None


def in_date_range(advisory: dict, start: date, end: date) -> bool:
    published = advisory_published_date(advisory)
    if published is None:
        return True
    return start <= published <= end


def is_ecosystem(advisory: dict, ecosystem: str) -> bool:
    for entry in advisory.get("affected") or []:
        pkg = entry.get("package") or {}
        if pkg.get("ecosystem") == ecosystem:
            return True
    return False


def extract_github_commit_refs(text: str) -> list[dict[str, str]]:
    """Return unique GitHub commit refs found in text, preserving first-seen order."""
    if not text:
        return []

    seen: set[tuple[str, str, str]] = set()
    refs: list[dict[str, str]] = []
    for match in GITHUB_COMMIT_URL_RE.finditer(text):
        owner = match.group("owner").lower()
        repo_name = match.group("repo").lower()
        sha = match.group("sha").lower()
        repo = f"{owner}/{repo_name}"
        key = ("github.com", repo, sha)
        if key in seen:
            continue
        seen.add(key)
        refs.append(
            {
                "host": "github.com",
                "repo": repo,
                "sha": sha,
                "url": f"https://github.com/{repo}/commit/{sha}",
            }
        )
    return refs


def extract_github_commit_urls(text: str) -> list[str]:
    """Return unique GitHub commit URLs found in text, preserving first-seen order."""
    return [ref["url"] for ref in extract_github_commit_refs(text)]


def advisory_commit_refs(advisory: dict) -> list[dict[str, str]]:
    """Extract GitHub commit refs from advisory details and references."""
    chunks: list[str] = [advisory.get("details") or ""]
    for ref in advisory.get("references") or []:
        if isinstance(ref, dict) and ref.get("url"):
            chunks.append(str(ref["url"]))
        elif isinstance(ref, str):
            chunks.append(ref)
    return extract_github_commit_refs("\n".join(chunks))


def advisory_commit_urls(advisory: dict) -> list[str]:
    """Extract GitHub commit URLs from advisory details and references."""
    return [ref["url"] for ref in advisory_commit_refs(advisory)]


def advisory_ecosystems(advisory: dict) -> list[str]:
    ecosystems: set[str] = set()
    for entry in advisory.get("affected") or []:
        pkg = entry.get("package") or {}
        ecosystem = pkg.get("ecosystem")
        if ecosystem:
            ecosystems.add(str(ecosystem))
    return sorted(ecosystems)


def first_cve_id(advisory: dict) -> str | None:
    for alias in advisory.get("aliases") or []:
        if isinstance(alias, str) and alias.upper().startswith("CVE-"):
            return alias
    return None


def classify_msg_class(
    message: str | None,
    *,
    is_merge: bool = False,
) -> str:
    """Assign announced|quiet|empty|merge_noise from a commit message."""
    text = (message or "").strip()
    if not text:
        return MSG_CLASS_EMPTY

    subject = text.splitlines()[0].strip()
    if is_merge and MERGE_SUBJECT_RE.match(subject):
        return MSG_CLASS_MERGE_NOISE

    if CVE_OR_GHSA_RE.search(text):
        return MSG_CLASS_ANNOUNCED

    lower = text.lower()
    hits = sum(1 for kw in SECURITY_KEYWORDS if kw in lower)
    if hits >= 2:
        return MSG_CLASS_ANNOUNCED
    return MSG_CLASS_QUIET


def build_advisory_row(
    advisory: dict,
    *,
    source_path: str,
    reviewed: bool,
    n_commits: int,
) -> dict[str, Any]:
    return {
        "ghsa_id": advisory.get("id"),
        "cve_id": first_cve_id(advisory),
        "reviewed": reviewed,
        "published_at": advisory.get("published"),
        "updated_at": advisory.get("modified") or advisory.get("updated"),
        "severity": (advisory.get("database_specific") or {}).get("severity"),
        "ecosystems": advisory_ecosystems(advisory),
        "summary": advisory.get("summary"),
        "source_path": source_path,
        "n_commits": n_commits,
    }


def build_commit_rows(
    ghsa_id: str,
    refs: list[dict[str, str]],
) -> list[dict[str, Any]]:
    n = len(refs)
    rows: list[dict[str, Any]] = []
    for ordinal, ref in enumerate(refs, start=1):
        rows.append(
            {
                "ghsa_id": ghsa_id,
                "host": ref["host"],
                "repo": ref["repo"],
                "sha": ref["sha"],
                "url": ref["url"],
                "ordinal": ordinal,
                "n_in_advisory": n,
                # Provenance: this SHA was cited by a GHSA advisory. The only hard
                # fact we have. Whether it is *the fix* is unknown until labelled.
                "source": "ghsa",
                "ghsa_referenced": True,
                # Ground-truth role (fix | context | backport | introduce | other).
                # Never auto-derived from GHSA; filled in only by manual labelling.
                "role": None,
            }
        )
    return rows


def diff_relpath(host: str, repo: str, sha: str) -> str:
    owner, _, name = repo.partition("/")
    return f"diffs/{host}/{owner}/{name}/{sha}.diff"


def parse_iso_datetime(value: str | None) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def lag_days(published_at: str | None, committed_at: str | None) -> int | None:
    pub = parse_iso_datetime(published_at)
    com = parse_iso_datetime(committed_at)
    if pub is None or com is None:
        return None
    return (pub.date() - com.date()).days


def noise_flags_for(
    *,
    resolved: bool,
    is_merge: bool | None,
    diff_bytes: int | None,
) -> list[str]:
    flags: list[str] = []
    if not resolved:
        flags.append("unresolved")
        return flags
    if diff_bytes is not None and diff_bytes == 0:
        flags.append("empty_diff")
        if is_merge:
            flags.append("merge_empty_diff")
    return flags


def github_http_get(url: str, accept: str | None = None) -> tuple[int, bytes, dict[str, str]]:
    """GET url; returns (status, body, response headers). Uses GITHUB_TOKEN if set."""
    headers = {
        "User-Agent": "strata-ghsa-commits",
        "Accept": accept or "application/vnd.github+json",
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = resp.read()
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            return int(resp.status), body, resp_headers
    except urllib.error.HTTPError as exc:
        body = exc.read() if exc.fp is not None else b""
        resp_headers = {k.lower(): v for k, v in (exc.headers or {}).items()}
        return int(exc.code), body, resp_headers


def fetch_commit_enrichment(
    host: str,
    repo: str,
    sha: str,
    *,
    http_get: GithubGet | None = None,
) -> dict[str, Any]:
    """Fetch commit metadata and unified diff from GitHub. Only github.com is supported."""
    get = http_get or (
        lambda url, accept=None: github_http_get(url, accept=accept)  # type: ignore[misc]
    )
    empty: dict[str, Any] = {
        "resolved": False,
        "committed_at": None,
        "subject": None,
        "message": None,
        "is_merge": None,
        "parent_count": None,
        "diff": None,
        "full_sha": None,
    }
    if host != "github.com":
        return empty

    api_url = f"https://api.github.com/repos/{repo}/commits/{sha}"
    status, body, _ = get(api_url, "application/vnd.github+json")
    if status != 200:
        return empty

    payload = json.loads(body.decode("utf-8"))
    parents = payload.get("parents") or []
    message = (payload.get("commit") or {}).get("message") or ""
    subject = message.splitlines()[0].strip() if message.strip() else ""
    committed_at = (
        ((payload.get("commit") or {}).get("committer") or {}).get("date")
        or ((payload.get("commit") or {}).get("author") or {}).get("date")
    )
    full_sha = str(payload.get("sha") or sha).lower()
    parent_count = len(parents)
    is_merge = parent_count > 1

    diff_text: str | None = None
    if is_merge and parents:
        base = parents[0].get("sha")
        if base:
            compare_url = f"https://api.github.com/repos/{repo}/compare/{base}...{full_sha}"
            d_status, d_body, _ = get(compare_url, "application/vnd.github.diff")
            if d_status == 200:
                diff_text = d_body.decode("utf-8", errors="replace")
    if diff_text is None:
        d_status, d_body, _ = get(api_url, "application/vnd.github.diff")
        if d_status == 200:
            diff_text = d_body.decode("utf-8", errors="replace")

    return {
        "resolved": True,
        "committed_at": committed_at,
        "subject": subject or None,
        "message": message or None,
        "is_merge": is_merge,
        "parent_count": parent_count,
        "diff": diff_text if diff_text is not None else "",
        "full_sha": full_sha,
    }


def enrich_commit_rows(
    commit_rows: list[dict[str, Any]],
    advisory_rows: list[dict[str, Any]],
    out_dir: Path,
    *,
    http_get: GithubGet | None = None,
) -> dict[str, int]:
    """Enrich commit rows in place, write diffs/, return summary counters."""
    published_by_ghsa = {
        str(row["ghsa_id"]): row.get("published_at") for row in advisory_rows
    }
    cache: dict[tuple[str, str, str], dict[str, Any]] = {}
    stats = {
        "unique_commits": 0,
        "resolved": 0,
        "unresolved": 0,
        "diffs_written": 0,
        "empty_diffs": 0,
        "msg_class": {
            MSG_CLASS_ANNOUNCED: 0,
            MSG_CLASS_QUIET: 0,
            MSG_CLASS_EMPTY: 0,
            MSG_CLASS_MERGE_NOISE: 0,
        },
    }

    for row in commit_rows:
        key = (str(row["host"]), str(row["repo"]), str(row["sha"]))
        if key not in cache:
            stats["unique_commits"] += 1
            meta = fetch_commit_enrichment(
                key[0], key[1], key[2], http_get=http_get
            )
            sha_for_path = meta.get("full_sha") or key[2]
            rel = diff_relpath(key[0], key[1], sha_for_path)
            diff_bytes: int | None = None
            if meta["resolved"]:
                stats["resolved"] += 1
                diff_text = meta.get("diff")
                if diff_text is None:
                    diff_text = ""
                abs_path = out_dir / rel
                abs_path.parent.mkdir(parents=True, exist_ok=True)
                data = diff_text.encode("utf-8")
                abs_path.write_bytes(data)
                diff_bytes = len(data)
                stats["diffs_written"] += 1
                if diff_bytes == 0:
                    stats["empty_diffs"] += 1
            else:
                stats["unresolved"] += 1
                rel = None

            msg_class = (
                classify_msg_class(
                    meta.get("message"),
                    is_merge=bool(meta.get("is_merge")),
                )
                if meta["resolved"]
                else None
            )
            if msg_class:
                stats["msg_class"][msg_class] += 1

            flags = noise_flags_for(
                resolved=bool(meta["resolved"]),
                is_merge=meta.get("is_merge"),
                diff_bytes=diff_bytes,
            )
            cache[key] = {
                "resolved": meta["resolved"],
                "committed_at": meta.get("committed_at"),
                "subject": meta.get("subject"),
                "message": meta.get("message"),
                "is_merge": meta.get("is_merge"),
                "parent_count": meta.get("parent_count"),
                "msg_class": msg_class,
                "diff_path": rel,
                "diff_bytes": diff_bytes,
                "noise_flags": flags,
                "sha": sha_for_path if meta["resolved"] else key[2],
            }

        enriched = cache[key]
        row.update(
            {
                "sha": enriched["sha"],
                "resolved": enriched["resolved"],
                "committed_at": enriched["committed_at"],
                "subject": enriched["subject"],
                "message": enriched["message"],
                "is_merge": enriched["is_merge"],
                "parent_count": enriched["parent_count"],
                "msg_class": enriched["msg_class"],
                "lag_days": lag_days(
                    published_by_ghsa.get(str(row["ghsa_id"])),
                    enriched["committed_at"],
                ),
                "diff_path": enriched["diff_path"],
                "diff_bytes": enriched["diff_bytes"],
                "noise_flags": list(enriched["noise_flags"]),
            }
        )
        if enriched["resolved"] and enriched["sha"] != key[2]:
            row["url"] = f"https://github.com/{key[1]}/commit/{enriched['sha']}"

    return stats


def build_audit_queue(commit_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One pending audit row per unique commit, for human noise review."""
    by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in commit_rows:
        key = (str(row["host"]), str(row["repo"]), str(row["sha"]))
        if key not in by_key:
            by_key[key] = {
                "host": row["host"],
                "repo": row["repo"],
                "sha": row["sha"],
                "url": row["url"],
                "ghsa_ids": [],
                "resolved": row.get("resolved"),
                "subject": row.get("subject"),
                "msg_class": row.get("msg_class"),
                "is_merge": row.get("is_merge"),
                "diff_path": row.get("diff_path"),
                "diff_bytes": row.get("diff_bytes"),
                "noise_flags": list(row.get("noise_flags") or []),
                "role": row.get("role"),
                "audit_status": "pending",
                # Human label: fix | context | introduce | bump | other | nonexistent
                "audit_label": None,
                "audit_notes": None,
            }
        ghsa_id = str(row["ghsa_id"])
        ids: list[str] = by_key[key]["ghsa_ids"]
        if ghsa_id not in ids:
            ids.append(ghsa_id)
    return list(by_key.values())


def load_labels(path: Path) -> dict[tuple[str, str, str], dict[str, Any]]:
    """Read labels.jsonl into a {(host, repo, sha): label} map. Missing file → {}."""
    labels: dict[tuple[str, str, str], dict[str, Any]] = {}
    if not path.exists():
        return labels
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            key = (str(row["host"]), str(row["repo"]), str(row["sha"]).lower())
            labels[key] = row
    return labels


def apply_labels(
    commit_rows: list[dict[str, Any]],
    labels: dict[tuple[str, str, str], dict[str, Any]],
) -> int:
    """Set role/label_notes on commit rows from labels. Returns count applied."""
    applied = 0
    for row in commit_rows:
        key = (str(row["host"]), str(row["repo"]), str(row["sha"]).lower())
        label = labels.get(key)
        if label and label.get("role") is not None:
            row["role"] = label["role"]
            if label.get("notes"):
                row["label_notes"] = label["notes"]
            applied += 1
    return applied


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    """Read a .jsonl file into a list of dicts. Missing file → []."""
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


def load_existing_bundle(
    out_dir: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return (existing_advisories, existing_commits) from a prior bundle."""
    return (
        read_jsonl(out_dir / "advisories.jsonl"),
        read_jsonl(out_dir / "commits.jsonl"),
    )


def merge_rows(
    existing: list[dict[str, Any]],
    new: list[dict[str, Any]],
    key_fn: Callable[[dict[str, Any]], Any],
) -> tuple[list[dict[str, Any]], int]:
    """Union existing + new by key. Existing rows are kept as-is (frozen);
    only genuinely new keys are appended. Returns (merged, n_added)."""
    seen = {key_fn(r) for r in existing}
    merged = list(existing)
    added = 0
    for row in new:
        k = key_fn(row)
        if k not in seen:
            seen.add(k)
            merged.append(row)
            added += 1
    return merged, added


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def write_ghsa_commits(
    out_dir: Path,
    *,
    advisories: list[dict[str, Any]],
    commits: list[dict[str, Any]],
    manifest: dict[str, Any],
    audit_queue: list[dict[str, Any]] | None = None,
    preserve_diffs: bool = False,
) -> None:
    """Write ghsa-commits bundle. If preserve_diffs, keep an existing diffs/ tree."""
    if preserve_diffs and out_dir.exists():
        for name in ("advisories.jsonl", "commits.jsonl", "audit_queue.jsonl", "manifest.json"):
            path = out_dir / name
            if path.exists():
                path.unlink()
    else:
        if out_dir.exists():
            shutil.rmtree(out_dir)
        out_dir.mkdir(parents=True)
        (out_dir / "diffs").mkdir()

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "diffs").mkdir(exist_ok=True)

    write_jsonl(out_dir / "advisories.jsonl", advisories)
    write_jsonl(out_dir / "commits.jsonl", commits)
    if audit_queue is not None:
        write_jsonl(out_dir / "audit_queue.jsonl", audit_queue)
    with (out_dir / "manifest.json").open("w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
        f.write("\n")


def summarize(advisory: dict, commit_urls: list[str] | None = None) -> str:
    ghsa_id = advisory.get("id", "?")
    summary = (advisory.get("summary") or "").replace("\n", " ").strip()
    severity = (advisory.get("database_specific") or {}).get("severity", "?")
    aliases = ", ".join(advisory.get("aliases") or []) or "-"

    packages: list[str] = []
    ecosystems: set[str] = set()
    for entry in advisory.get("affected") or []:
        pkg = entry.get("package") or {}
        ecosystem = pkg.get("ecosystem")
        name = pkg.get("name")
        if ecosystem:
            ecosystems.add(ecosystem)
        if ecosystem and name:
            packages.append(f"{ecosystem}:{name}")

    seen: set[str] = set()
    unique_packages: list[str] = []
    for package in packages:
        if package not in seen:
            seen.add(package)
            unique_packages.append(package)

    ecosystem = ", ".join(sorted(ecosystems)) or "?"
    package = ", ".join(unique_packages[:3]) or "?"
    if len(unique_packages) > 3:
        package += f" (+{len(unique_packages) - 3} more)"

    line = (
        f"{ghsa_id} | {severity:8} | {ecosystem:12} | {package} | "
        f"aliases={aliases} | {summary}"
    )
    if commit_urls is not None:
        line += f" | commits={len(commit_urls)} {', '.join(commit_urls)}"
    return line


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fresh",
        action="store_true",
        help="rebuild from scratch (destructive); default is append-only",
    )
    args = parser.parse_args()
    append = not args.fresh

    start, end = resolve_date_range(START_DATE, END_DATE)
    month_dirs = iter_month_dirs(ADVISORY_DATABASE, start, end, source=ADVISORY_SOURCE)
    if not month_dirs:
        raise SystemExit(
            f"No advisory month directories found for {start.isoformat()}..{end.isoformat()} "
            f"under {ADVISORY_DATABASE / 'advisories' / ADVISORY_SOURCE}"
        )

    # Load the existing bundle so we can add only what is new (append mode).
    existing_advisories, existing_commits = (
        load_existing_bundle(GHSA_COMMITS_DIR) if append else ([], [])
    )
    existing_ghsa_ids = {str(a.get("ghsa_id")) for a in existing_advisories}
    existing_commit_keys = {commit_key(c) for c in existing_commits}

    files = list_advisory_files(month_dirs)
    matches: list[tuple[Path, dict, list[dict[str, str]]]] = []
    for path in files:
        advisory = parse_advisory(path)
        if not in_date_range(advisory, start, end):
            continue
        if ECOSYSTEM is not None and not is_ecosystem(advisory, ECOSYSTEM):
            continue
        refs = advisory_commit_refs(advisory)
        if refs:
            matches.append((path, advisory, refs))

    ecosystem_label = ECOSYSTEM or "all-ecosystem"
    range_label = f"{start.isoformat()}..{end.isoformat()}"
    if not matches:
        raise SystemExit(
            f"No {ecosystem_label} {ADVISORY_SOURCE} advisories with GitHub commit URLs "
            f"found for {range_label}"
        )

    # In append mode, only consider advisories not already in the bundle so
    # SAMPLE_SIZE means "add up to N NEW ones" and reruns keep making progress.
    candidates = matches
    if append:
        candidates = [
            m for m in matches if str(m[1].get("id")) not in existing_ghsa_ids
        ]
    if append and not candidates:
        print(
            f"Nothing new to add: all {len(matches)} matching advisories for "
            f"{range_label} are already in {GHSA_COMMITS_DIR}/ "
            f"({len(existing_advisories)} advisories, {len(existing_commits)} commits)."
        )
        return

    if SAMPLE_SIZE == 0:
        samples = candidates
        label = f"Adding all {len(samples)} new" if append else f"Listing all {len(samples)}"
    else:
        sample_size = min(SAMPLE_SIZE, len(candidates))
        samples = random.sample(candidates, sample_size)
        label = (
            f"Adding {len(samples)} new (of {len(candidates)} not yet in bundle)"
            if append
            else f"Sampling {len(samples)} of {len(candidates)}"
        )

    reviewed = ADVISORY_SOURCE == "github-reviewed"
    advisory_rows: list[dict[str, Any]] = []
    commit_rows: list[dict[str, Any]] = []
    for path, advisory, refs in samples:
        try:
            source_path = path.relative_to(ADVISORY_DATABASE).as_posix()
        except ValueError:
            source_path = path.as_posix()
        ghsa_id = str(advisory.get("id") or path.stem)
        advisory_rows.append(
            build_advisory_row(
                advisory,
                source_path=source_path,
                reviewed=reviewed,
                n_commits=len(refs),
            )
        )
        commit_rows.extend(build_commit_rows(ghsa_id, refs))

    # In append mode the diffs/ tree already holds prior diffs; only create the
    # skeleton when starting fresh. Never rmtree in append mode.
    if not append and GHSA_COMMITS_DIR.exists():
        shutil.rmtree(GHSA_COMMITS_DIR)
    GHSA_COMMITS_DIR.mkdir(parents=True, exist_ok=True)
    (GHSA_COMMITS_DIR / "diffs").mkdir(exist_ok=True)

    # Enrich only the NEW commits — existing ones are frozen, so we never re-hit
    # the API for a SHA we already resolved. This is what keeps daily reruns cheap.
    new_commit_rows = (
        [c for c in commit_rows if commit_key(c) not in existing_commit_keys]
        if append
        else commit_rows
    )

    enrich_stats: dict[str, Any] | None = None
    if ENRICH:
        enrich_stats = enrich_commit_rows(
            new_commit_rows, advisory_rows, GHSA_COMMITS_DIR
        )

    # Merge new rows into the frozen existing set (union by key; existing wins).
    all_advisories, adv_added = merge_rows(
        existing_advisories, advisory_rows, lambda a: str(a.get("ghsa_id"))
    )
    all_commits, com_added = merge_rows(
        existing_commits, new_commit_rows, commit_key
    )

    # Merge durable human labels across the WHOLE set so `role` is populated on
    # every commit (old and new) without touching diffs or enrichment.
    labels = load_labels(LABELS_PATH)
    labels_applied = apply_labels(all_commits, labels)

    audit_queue = build_audit_queue(all_commits) if ENRICH else []

    manifest: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "built_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "mode": "append" if append else "fresh",
        "advisory_database": ADVISORY_DATABASE.as_posix(),
        "advisory_source": ADVISORY_SOURCE,
        "ecosystem": ECOSYSTEM,
        "start_date": start.isoformat(),
        "end_date": end.isoformat(),
        "sample_size": SAMPLE_SIZE,
        "files_scanned": len(files),
        "matches_total": len(matches),
        "added_this_run": {"advisories": adv_added, "commits": com_added},
        "advisories": len(all_advisories),
        "commit_refs": len(all_commits),
        "diffs_layout": DIFFS_LAYOUT,
        "enriched": bool(ENRICH),
        "labels_applied": labels_applied,
        "unlabelled": sum(1 for c in all_commits if c.get("role") is None),
    }
    if enrich_stats is not None:
        manifest["enrichment_this_run"] = enrich_stats
        manifest["audit_queue"] = len(audit_queue)

    write_ghsa_commits(
        GHSA_COMMITS_DIR,
        advisories=all_advisories,
        commits=all_commits,
        manifest=manifest,
        audit_queue=audit_queue if ENRICH else None,
        preserve_diffs=True,  # always keep the diffs/ tree; we merge, never wipe
    )

    print(
        f"{label} {ecosystem_label} {ADVISORY_SOURCE} advisories with GitHub commit URLs "
        f"({len(files)} scanned) for {range_label} "
        f"across {len(month_dirs)} month dir(s)"
    )
    print(
        f"Added {adv_added} advisory(ies), {com_added} commit(s). "
        f"Bundle now: {len(all_advisories)} advisories, {len(all_commits)} commits "
        f"({manifest['unlabelled']} unlabelled)."
    )
    if enrich_stats is not None:
        print(
            f"Enrichment (new only): {enrich_stats['resolved']}/{enrich_stats['unique_commits']} resolved, "
            f"{enrich_stats['diffs_written']} diffs, "
            f"msg_class={enrich_stats['msg_class']}"
        )
    print()
    for _, advisory, refs in samples:
        print(summarize(advisory, [ref["url"] for ref in refs]))


if __name__ == "__main__":
    main()
