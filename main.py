"""Sample GitHub Security Advisories and write a ghsa-commits index."""

from __future__ import annotations

import json
import random
import re
import shutil
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

ADVISORY_DATABASE = Path("advisory-database")
# Advisory corpus under advisories/: "github-reviewed" or "unreviewed".
ADVISORY_SOURCE = "github-reviewed"
# Random sample size. Set to 0 to take every matching advisory (no limit).
SAMPLE_SIZE = 10
# Ecosystem filter (e.g. "Go", "npm"). Set to None to disable.
ECOSYSTEM: str | None = "Go"
# Inclusive published-date range. None → defaults: start=first of current month, end=today.
# Examples: date(2025, 1, 1), date(2026, 7, 25)
START_DATE: date | None = date(2026, 1, 1)
END_DATE: date | None = None
# Output bundle: advisories.jsonl, commits.jsonl, manifest.json, diffs/ (layout only for now).
GHSA_COMMITS_DIR = Path("ghsa-commits")
SCHEMA_VERSION = 1
# Future diff cache layout (not written yet): diffs/{host}/{owner}/{repo}/{sha}.diff
DIFFS_LAYOUT = "diffs/{host}/{owner}/{repo}/{sha}.diff"

# Matches github.com commit URLs, including pull request commit links.
# Captures owner/repo/sha; trailing markdown punctuation is not included.
GITHUB_COMMIT_URL_RE = re.compile(
    r"https?://(?:www\.)?github\.com/"
    r"(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)/"
    r"(?:commit|pull/\d+/commits)/(?P<sha>[0-9a-fA-F]{7,40})"
    r"(?:[/?#][^\s\"'<>)\]}>]*)?",
    re.IGNORECASE,
)


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
        # Keep advisories without a published date if they live in a selected month dir.
        return True
    return start <= published <= end


def is_ecosystem(advisory: dict, ecosystem: str) -> bool:
    for entry in advisory.get("affected") or []:
        pkg = entry.get("package") or {}
        if pkg.get("ecosystem") == ecosystem:
            return True
    return False


def extract_github_commit_refs(text: str) -> list[dict[str, str]]:
    """Return unique GitHub commit refs found in text, preserving first-seen order.

    Each ref: {host, repo, sha, url} with repo as lowercased owner/name.
    """
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
            }
        )
    return rows


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
) -> None:
    """Write ghsa-commits bundle: manifest, advisories.jsonl, commits.jsonl, empty diffs/."""
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    (out_dir / "diffs").mkdir()

    write_jsonl(out_dir / "advisories.jsonl", advisories)
    write_jsonl(out_dir / "commits.jsonl", commits)
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

    # Deduplicate while preserving order
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
    start, end = resolve_date_range(START_DATE, END_DATE)
    month_dirs = iter_month_dirs(ADVISORY_DATABASE, start, end, source=ADVISORY_SOURCE)
    if not month_dirs:
        raise SystemExit(
            f"No advisory month directories found for {start.isoformat()}..{end.isoformat()} "
            f"under {ADVISORY_DATABASE / 'advisories' / ADVISORY_SOURCE}"
        )

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

    if SAMPLE_SIZE == 0:
        samples = matches
        label = f"Listing all {len(samples)}"
    else:
        sample_size = min(SAMPLE_SIZE, len(matches))
        samples = random.sample(matches, sample_size)
        label = f"Sampling {len(samples)} of {len(matches)}"

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

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "built_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "advisory_database": ADVISORY_DATABASE.as_posix(),
        "advisory_source": ADVISORY_SOURCE,
        "ecosystem": ECOSYSTEM,
        "start_date": start.isoformat(),
        "end_date": end.isoformat(),
        "sample_size": SAMPLE_SIZE,
        "files_scanned": len(files),
        "matches_total": len(matches),
        "advisories": len(advisory_rows),
        "commit_refs": len(commit_rows),
        "diffs_layout": DIFFS_LAYOUT,
    }
    write_ghsa_commits(
        GHSA_COMMITS_DIR,
        advisories=advisory_rows,
        commits=commit_rows,
        manifest=manifest,
    )

    print(
        f"{label} {ecosystem_label} {ADVISORY_SOURCE} advisories with GitHub commit URLs "
        f"({len(files)} scanned) for {range_label} "
        f"across {len(month_dirs)} month dir(s)"
    )
    print(
        f"Wrote {GHSA_COMMITS_DIR}/ "
        f"({len(advisory_rows)} advisories, {len(commit_rows)} commit refs)"
    )
    print()
    for _, advisory, refs in samples:
        print(summarize(advisory, [ref["url"] for ref in refs]))


if __name__ == "__main__":
    main()
