"""Sample random GitHub Security Advisories from the local advisory-database clone."""

from __future__ import annotations

import json
import random
import re
from datetime import date, datetime
from pathlib import Path

ADVISORY_DATABASE = Path("advisory-database")
# Random sample size. Set to 0 to take every matching advisory (no limit).
SAMPLE_SIZE = 0
# Ecosystem filter (e.g. "Go", "npm"). Set to None to disable.
# ECOSYSTEM: str | None = None  # "Go"
ECOSYSTEM = "Go"
# Inclusive published-date range. None → defaults: start=first of current month, end=today.
# Examples: date(2025, 1, 1), date(2026, 7, 25)
START_DATE: date = date(2026,1,1)
END_DATE: date | None = None

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


def iter_month_dirs(root: Path, start: date, end: date) -> list[Path]:
    """Return existing github-reviewed year/month dirs overlapping [start, end]."""
    dirs: list[Path] = []
    year, month = start.year, start.month
    while (year, month) <= (end.year, end.month):
        month_dir = (
            root / "advisories" / "github-reviewed" / f"{year:04d}" / f"{month:02d}"
        )
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


def extract_github_commit_urls(text: str) -> list[str]:
    """Return unique GitHub commit URLs found in text, preserving first-seen order."""
    if not text:
        return []

    seen: set[str] = set()
    urls: list[str] = []
    for match in GITHUB_COMMIT_URL_RE.finditer(text):
        # Normalize to a canonical https://github.com/owner/repo/commit/<sha> form.
        owner = match.group("owner")
        repo = match.group("repo")
        sha = match.group("sha").lower()
        canonical = f"https://github.com/{owner}/{repo}/commit/{sha}"
        if canonical not in seen:
            seen.add(canonical)
            urls.append(canonical)
    return urls


def advisory_commit_urls(advisory: dict) -> list[str]:
    """Extract GitHub commit URLs from advisory details and references."""
    chunks: list[str] = [advisory.get("details") or ""]
    for ref in advisory.get("references") or []:
        if isinstance(ref, dict) and ref.get("url"):
            chunks.append(str(ref["url"]))
        elif isinstance(ref, str):
            chunks.append(ref)
    return extract_github_commit_urls("\n".join(chunks))


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
    month_dirs = iter_month_dirs(ADVISORY_DATABASE, start, end)
    if not month_dirs:
        raise SystemExit(
            f"No advisory month directories found for {start.isoformat()}..{end.isoformat()} "
            f"under {ADVISORY_DATABASE / 'advisories' / 'github-reviewed'}"
        )

    files = list_advisory_files(month_dirs)
    matches: list[tuple[Path, dict, list[str]]] = []
    for path in files:
        advisory = parse_advisory(path)
        if not in_date_range(advisory, start, end):
            continue
        if ECOSYSTEM is not None and not is_ecosystem(advisory, ECOSYSTEM):
            continue
        commit_urls = advisory_commit_urls(advisory)
        if commit_urls:
            matches.append((path, advisory, commit_urls))

    ecosystem_label = ECOSYSTEM or "all-ecosystem"
    range_label = f"{start.isoformat()}..{end.isoformat()}"
    if not matches:
        raise SystemExit(
            f"No {ecosystem_label} advisories with GitHub commit URLs found "
            f"for {range_label}"
        )

    if SAMPLE_SIZE == 0:
        samples = matches
        label = f"Listing all {len(samples)}"
    else:
        sample_size = min(SAMPLE_SIZE, len(matches))
        samples = random.sample(matches, sample_size)
        label = f"Sampling {len(samples)} of {len(matches)}"

    print(
        f"{label} {ecosystem_label} advisories with GitHub commit URLs "
        f"({len(files)} scanned) for {range_label} "
        f"across {len(month_dirs)} month dir(s)"
    )
    print()
    for _, advisory, commit_urls in samples:
        print(summarize(advisory, commit_urls))


if __name__ == "__main__":
    main()
