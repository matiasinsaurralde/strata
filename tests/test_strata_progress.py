"""Tests for structured scan progress and the plain renderer.

Two behaviours carry the design and are asserted directly rather than through
rendered text: painting is throttled on a clock (so a stage with thousands of
items does not emit thousands of lines) and painting is *not* driven by
completions alone (so a stage that is busy but has finished nothing still
reports). Everything else here guards the stdout/stderr split and the line
format.
"""

from __future__ import annotations

import io
import threading
from datetime import UTC, datetime
from typing import Any

import pytest

from strata.progress import (
    NOTE,
    STAGE_FINISHED,
    STAGE_PROGRESS,
    STAGE_STARTED,
    CallbackSink,
    Event,
    InFlight,
    NullSink,
    PlainRenderer,
    Reporter,
)


class _RecordingSink:
    """Collects events so tests can assert on them instead of on bytes."""

    def __init__(self) -> None:
        self.events: list[Event] = []

    def emit(self, event: Event) -> None:
        self.events.append(event)

    def kinds(self, stage: str | None = None) -> list[str]:
        return [e.kind for e in self.events if stage is None or e.stage == stage]


class _FakeClock:
    """A monotonic clock the test advances by hand."""

    def __init__(self) -> None:
        self.value = 1_000.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def _reporter(sink: Any, clock: _FakeClock, *, interval: float = 5.0) -> Reporter:
    # Heartbeats are threads; these tests drive tick() explicitly instead so
    # that throttling is asserted deterministically.
    return Reporter(
        sink,
        interval=interval,
        clock=clock,
        now=lambda: datetime(2026, 7, 28, 12, 34, 56, tzinfo=UTC),
        heartbeat=False,
    )


# --- throttling ---------------------------------------------------------


def test_stage_announces_itself_once_when_the_total_is_known() -> None:
    sink = _RecordingSink()
    _reporter(sink, _FakeClock()).stage("prefilter", total=500)
    assert sink.kinds() == [STAGE_STARTED]
    assert sink.events[0].total == 500
    assert sink.events[0].done == 0


def test_indeterminate_stage_announces_nothing_up_front() -> None:
    sink = _RecordingSink()
    _reporter(sink, _FakeClock()).stage("git")
    assert sink.events == []


def test_advance_paints_at_most_once_per_interval() -> None:
    clock = _FakeClock()
    sink = _RecordingSink()
    stage = _reporter(sink, clock, interval=5.0).stage("prefilter", total=1_000)

    for _ in range(400):
        clock.advance(0.01)  # 4s of work: inside the window
        stage.advance()
    assert sink.kinds() == [STAGE_STARTED]

    clock.advance(1.5)
    stage.advance()
    assert sink.kinds() == [STAGE_STARTED, STAGE_PROGRESS]
    assert sink.events[-1].done == 401
    assert sink.events[-1].total == 1_000


def test_finish_always_paints_even_inside_the_throttle_window() -> None:
    clock = _FakeClock()
    sink = _RecordingSink()
    stage = _reporter(sink, clock).stage("triage", total=3)
    stage.advance()
    stage.finish("all done")

    assert sink.kinds() == [STAGE_STARTED, STAGE_FINISHED]
    assert sink.events[-1].message == "all done"
    assert sink.events[-1].done == 1


def test_finish_is_idempotent() -> None:
    sink = _RecordingSink()
    stage = _reporter(sink, _FakeClock()).stage("triage", total=1)
    stage.finish("first")
    stage.finish("second")
    assert sink.kinds().count(STAGE_FINISHED) == 1
    assert sink.events[-1].message == "first"


def test_advance_after_finish_counts_but_does_not_paint() -> None:
    clock = _FakeClock()
    sink = _RecordingSink()
    stage = _reporter(sink, clock).stage("triage", total=2)
    stage.finish()
    clock.advance(60.0)
    stage.advance()
    assert sink.kinds().count(STAGE_PROGRESS) == 0


# --- reporting a stage that has completed nothing -----------------------


def test_tick_reports_a_stage_with_no_completions() -> None:
    """The hung-versus-slow case: no item has finished, so nothing advanced."""
    clock = _FakeClock()
    sink = _RecordingSink()
    stage = _reporter(sink, clock, interval=5.0).stage("adjudicate", total=12)

    clock.advance(1.0)
    stage.tick()
    assert sink.kinds() == [STAGE_STARTED]  # still inside the window

    clock.advance(30.0)
    stage.tick()
    assert sink.kinds() == [STAGE_STARTED, STAGE_PROGRESS]
    assert sink.events[-1].done == 0
    assert sink.events[-1].stage_elapsed_s == pytest.approx(31.0)


def test_heartbeat_thread_paints_without_any_completions() -> None:
    """Same contract as above, driven by the real thread rather than by hand."""
    sink = _RecordingSink()
    reporter = Reporter(sink, interval=0.05, heartbeat=True)
    painted = threading.Event()

    original_emit = sink.emit

    def emit(event: Event) -> None:
        original_emit(event)
        if event.kind == STAGE_PROGRESS:
            painted.set()

    sink.emit = emit  # type: ignore[method-assign]
    stage = reporter.stage("adjudicate", total=4)
    try:
        assert painted.wait(timeout=5.0), "heartbeat never painted"
    finally:
        stage.finish("stopped")
    assert sink.events[-1].kind == STAGE_FINISHED


def test_abandoning_a_stage_claims_no_completion() -> None:
    sink = _RecordingSink()
    reporter = _reporter(sink, _FakeClock())
    with pytest.raises(RuntimeError), reporter.stage("triage", total=2):
        raise RuntimeError("boom")
    assert STAGE_FINISHED not in sink.kinds()


# --- detail providers ---------------------------------------------------


def test_detail_is_sampled_at_paint_time_not_at_advance_time() -> None:
    clock = _FakeClock()
    sink = _RecordingSink()
    cost = 0.0
    stage = _reporter(sink, clock).stage("triage", total=10, detail=lambda: {"cost_usd": cost})
    for _ in range(9):
        cost += 1.0
        stage.advance()
    clock.advance(10.0)
    cost = 99.0
    stage.advance()
    assert sink.events[-1].detail["cost_usd"] == 99.0


def test_a_broken_detail_provider_cannot_break_the_scan() -> None:
    sink = _RecordingSink()

    def detail() -> dict[str, Any]:
        raise ValueError("no")

    stage = _reporter(sink, _FakeClock()).stage("triage", total=1, detail=detail)
    stage.finish("survived")
    assert sink.events[-1].detail == {}


# --- in-flight tracking -------------------------------------------------


def test_in_flight_reports_count_and_the_age_of_the_oldest() -> None:
    clock = _FakeClock()
    tracker = InFlight(clock=clock)
    assert tracker.snapshot() == {"in_flight": 0}

    with tracker.track("a"):
        clock.advance(30.0)
        with tracker.track("b"):
            snapshot = tracker.snapshot()
            assert snapshot["in_flight"] == 2
            assert snapshot["oldest_in_flight_s"] == pytest.approx(30.0)
    assert tracker.snapshot() == {"in_flight": 0}


def test_in_flight_releases_an_item_that_raised() -> None:
    tracker = InFlight()
    with pytest.raises(ValueError), tracker.track("a"):
        raise ValueError("boom")
    assert tracker.snapshot()["in_flight"] == 0


# --- the plain renderer -------------------------------------------------


def _render(event: Event) -> str:
    stream = io.StringIO()
    PlainRenderer(stream).emit(event)
    return stream.getvalue()


def _event(kind: str, **overrides: Any) -> Event:
    fields: dict[str, Any] = {
        "kind": kind,
        "stage": "triage",
        "timestamp": datetime(2026, 7, 28, 3, 4, 5, tzinfo=UTC),
    }
    fields.update(overrides)
    return Event(**fields)


def test_plain_line_carries_elapsed_and_wall_clock_stamps() -> None:
    line = _render(_event(STAGE_PROGRESS, done=38, total=96, elapsed_s=125.0))
    assert line.startswith("[02:05] 03:04:05Z triage     ")
    assert "38/96" in line
    assert "40%" in line


def test_plain_elapsed_widens_past_an_hour() -> None:
    assert _render(_event(NOTE, message="hi", elapsed_s=3_725.0)).startswith("[1:02:05]")


def test_plain_progress_shows_rate_and_eta() -> None:
    line = _render(_event(STAGE_PROGRESS, done=50, total=100, stage_elapsed_s=100.0))
    assert "0.5/s" not in line  # under one per second reads better per minute
    assert "30.0/min" in line
    assert "eta 01:40" in line


def test_plain_progress_suppresses_a_dishonest_eta() -> None:
    """Adjudication opts out: per-candidate cost varies by an order of magnitude."""
    line = _render(
        _event(
            STAGE_PROGRESS,
            stage="adjudicate",
            done=7,
            total=12,
            stage_elapsed_s=60.0,
            eta=False,
            detail={"in_flight": 5, "oldest_in_flight_s": 61.0, "cost_usd": 4.125},
        )
    )
    assert "eta" not in line
    assert "7/12" in line
    assert "5 in flight" in line
    assert "oldest 01:01" in line
    assert "$4.12" in line


def test_plain_progress_shows_a_cost_ceiling_when_one_is_set() -> None:
    detail = {"cost_usd": 4.125, "cost_ceiling_usd": 60.0}
    assert "$4.12/$60.00" in _render(_event(STAGE_PROGRESS, done=1, total=2, detail=detail))


def test_plain_progress_omits_an_eta_that_rounds_to_nothing() -> None:
    line = _render(_event(STAGE_PROGRESS, done=24, total=25, stage_elapsed_s=2.3))
    assert "eta" not in line


def test_plain_progress_omits_a_sub_second_oldest_item() -> None:
    detail = {"in_flight": 4, "oldest_in_flight_s": 0.4}
    line = _render(_event(STAGE_PROGRESS, done=16, total=22, detail=detail))
    assert "4 in flight" in line
    assert "oldest" not in line


def test_plain_progress_reports_an_uncountable_stage_as_working() -> None:
    assert "working" in _render(_event(STAGE_PROGRESS, stage="git", stage_elapsed_s=30.0))


def test_plain_finish_reports_the_stage_duration() -> None:
    line = _render(
        _event(
            STAGE_FINISHED,
            stage="prefilter",
            done=500,
            total=500,
            stage_elapsed_s=23.42,
            message="admitted 96/500",
        )
    )
    assert "done 500/500 · admitted 96/500 · 23.4s" in line


def test_plain_finish_does_not_repeat_cost_the_summary_already_states() -> None:
    line = _render(
        _event(
            STAGE_FINISHED,
            done=22,
            total=22,
            stage_elapsed_s=2.4,
            message="0 candidates, 22 rejected ($0.02)",
            detail={"cost_usd": 0.02, "cost_ceiling_usd": 5.0},
        )
    )
    assert line.count("$") == 1
    assert "$0.02/$5.00" not in line


def test_plain_renderer_says_nothing_about_an_empty_stage_up_front() -> None:
    assert _render(_event(STAGE_STARTED, stage="adjudicate", total=0)) == ""


def test_plain_renderer_emits_nothing_for_an_empty_message() -> None:
    assert _render(_event(NOTE, message="")) == ""


def test_plain_renderer_never_writes_to_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    """stdout is the funnel JSON's channel; a progress line there breaks parsers."""
    PlainRenderer(io.StringIO()).emit(_event(STAGE_PROGRESS, done=1, total=2))
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_plain_renderer_writes_one_line_per_event() -> None:
    stream = io.StringIO()
    renderer = PlainRenderer(stream)
    renderer.emit(_event(NOTE, message="first"))
    renderer.emit(_event(NOTE, message="second"))
    assert stream.getvalue().splitlines() == [
        "[00:00] 03:04:05Z triage     first",
        "[00:00] 03:04:05Z triage     second",
    ]


# --- sinks --------------------------------------------------------------


def test_null_sink_drops_everything() -> None:
    assert NullSink().emit(_event(STAGE_PROGRESS, done=1, total=2)) is None


def test_callback_sink_gets_summaries_but_not_per_item_progress() -> None:
    """The legacy string callback asked for stage summaries, not hundreds of lines."""
    lines: list[str] = []
    sink = CallbackSink(lines.append)
    sink.emit(_event(STAGE_STARTED, total=96))
    sink.emit(_event(STAGE_PROGRESS, done=38, total=96))
    sink.emit(_event(NOTE, message="mirror ready"))
    sink.emit(_event(STAGE_FINISHED, done=96, total=96, message="12 candidates"))
    assert lines == ["mirror ready", "triage: 12 candidates"]


def test_reporter_defaults_to_dropping_events() -> None:
    reporter = Reporter(heartbeat=False)
    reporter.note("nothing listens to this")
    stage = reporter.stage("triage", total=1)
    stage.advance()
    stage.finish("done")


def test_reporter_serialises_writes_from_several_threads() -> None:
    """The heartbeat and the pipeline share one stream; writes must not interleave."""
    sink = _RecordingSink()
    reporter = Reporter(sink, interval=0.0, heartbeat=False)
    stage = reporter.stage("triage", total=800)

    def work() -> None:
        for _ in range(100):
            stage.advance()

    threads = [threading.Thread(target=work) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    stage.finish("counted")
    assert stage.done == 800
    assert sink.events[-1].done == 800
