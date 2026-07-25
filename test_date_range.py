"""Tests for advisory date-range helpers."""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from main import (
    advisory_published_date,
    in_date_range,
    iter_month_dirs,
    resolve_date_range,
)


def test_resolve_date_range_defaults_to_current_month_through_today() -> None:
    today = date(2026, 7, 25)
    assert resolve_date_range(None, None, today=today) == (
        date(2026, 7, 1),
        date(2026, 7, 25),
    )


def test_resolve_date_range_custom_bounds() -> None:
    assert resolve_date_range(date(2025, 1, 15), date(2026, 3, 10)) == (
        date(2025, 1, 15),
        date(2026, 3, 10),
    )


def test_resolve_date_range_rejects_inverted_bounds() -> None:
    with pytest.raises(ValueError, match="START_DATE"):
        resolve_date_range(date(2026, 8, 1), date(2026, 7, 1))


def test_iter_month_dirs_includes_overlapping_months(tmp_path: Path) -> None:
    root = tmp_path
    for year, month in [(2025, 12), (2026, 1), (2026, 2), (2026, 3)]:
        (root / "advisories" / "github-reviewed" / f"{year:04d}" / f"{month:02d}").mkdir(
            parents=True
        )
    # Missing month should be skipped.
    dirs = iter_month_dirs(root, date(2025, 12, 20), date(2026, 3, 5))
    assert [p.as_posix() for p in dirs] == [
        (root / "advisories/github-reviewed/2025/12").as_posix(),
        (root / "advisories/github-reviewed/2026/01").as_posix(),
        (root / "advisories/github-reviewed/2026/02").as_posix(),
        (root / "advisories/github-reviewed/2026/03").as_posix(),
    ]


def test_advisory_published_date_parses_iso() -> None:
    assert advisory_published_date({"published": "2026-07-02T20:31:26Z"}) == date(
        2026, 7, 2
    )


def test_in_date_range_filters_by_published_day() -> None:
    advisory = {"published": "2026-07-15T12:00:00Z"}
    assert in_date_range(advisory, date(2026, 7, 1), date(2026, 7, 31))
    assert not in_date_range(advisory, date(2026, 7, 1), date(2026, 7, 10))
    assert in_date_range({"published": None}, date(2026, 7, 1), date(2026, 7, 10))
