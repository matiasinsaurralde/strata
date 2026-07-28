"""Progress reporting for long-running scans.

Progress here is a structured event stream, not a set of print statements: the
pipeline emits events and a renderer decides how -- and how often -- to show
them. That split is what lets one scan drive a throttled log in CI, a bar on a
TTY, or a JSONL stream for a wrapper without the pipeline knowing which is
attached, and it lets tests assert on events rather than on formatted bytes.

Two properties are load-bearing rather than cosmetic:

1. **Throttling is time-based, never per-item.** The prefilter walks thousands
   of commits; a line each would be unreadable on a terminal and would bloat a
   CI log. Every paint is gated on a clock comparison, which is cheaper than
   the work it describes.
2. **Painting is not driven by completions alone.** A single adjudication runs
   for tens of seconds against a 240s ceiling, so a stage can go a long time
   without completing anything. A heartbeat repaints on the interval regardless,
   which is what makes "slow" distinguishable from "hung".

Everything here writes to stderr. stdout carries the funnel JSON, which is a
machine-readable contract no progress line may interleave with.
"""

from __future__ import annotations

import contextlib
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol, TextIO

__all__ = [
    "DEFAULT_INTERVAL",
    "CallbackSink",
    "Event",
    "InFlight",
    "NullSink",
    "PlainRenderer",
    "ProgressSink",
    "Reporter",
    "StageTracker",
]

#: Event kinds. A renderer may ignore any of them.
STAGE_STARTED = "stage_started"
STAGE_PROGRESS = "stage_progress"
STAGE_FINISHED = "stage_finished"
NOTE = "note"

#: Seconds between progress lines. One interval serves every stage: during
#: adjudication a repaint is still informative because the in-flight count, the
#: age of the oldest candidate and the running cost all move between paints.
DEFAULT_INTERVAL = 5.0


@dataclass(frozen=True, slots=True)
class Event:
    """One observation about a running scan.

    Attributes:
        kind: One of the module-level event-kind constants.
        stage: Pipeline stage the event belongs to (``git``, ``triage``, ...).
        done: Items completed so far in this stage.
        total: Items the stage expects, or ``None`` when it cannot be counted.
        elapsed_s: Seconds since the scan started.
        stage_elapsed_s: Seconds since this stage started.
        message: Human-readable text; the summary on ``stage_finished``.
        detail: Extra measurements a renderer may show (``cost_usd``,
            ``in_flight``, ``oldest_in_flight_s``, ``cost_ceiling_usd``).
        eta: Whether projecting linearly to completion is honest for this
            stage. False where per-item cost varies by an order of magnitude,
            as adjudication's does: an ETA there would invent confidence.
        timestamp: Wall-clock time of the observation.
    """

    kind: str
    stage: str
    done: int = 0
    total: int | None = None
    elapsed_s: float = 0.0
    stage_elapsed_s: float = 0.0
    message: str = ""
    detail: Mapping[str, Any] = field(default_factory=dict)
    eta: bool = True
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


class ProgressSink(Protocol):
    """Anything that can consume progress events."""

    def emit(self, event: Event) -> None: ...


class NullSink:
    """Discards every event; the shape ``--quiet`` takes internally."""

    def emit(self, event: Event) -> None:
        return None


@dataclass(frozen=True, slots=True)
class CallbackSink:
    """Adapts the legacy ``progress=Callable[[str], None]`` callback.

    Per-item events are dropped on purpose: a caller that asked for strings
    asked for the stage summaries it used to receive, not several hundred lines
    of them.
    """

    callback: Callable[[str], None]

    def emit(self, event: Event) -> None:
        if event.kind == NOTE:
            if event.message:
                self.callback(event.message)
        elif event.kind == STAGE_FINISHED and event.message:
            self.callback(f"{event.stage}: {event.message}")


class InFlight:
    """Thread-safe record of the work items currently in progress.

    Its reason for existing is the ambiguity a bare counter leaves during
    adjudication: ``7/12`` cannot distinguish a stage making slow progress from
    one wedged on a hung request. The number in flight and the age of the oldest
    can, and both are readable against the known per-candidate ceiling.
    """

    __slots__ = ("_clock", "_lock", "_started")

    def __init__(self, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._started: dict[str, float] = {}

    @contextlib.contextmanager
    def track(self, key: str) -> Iterator[None]:
        """Mark ``key`` in flight for the duration of the block."""
        with self._lock:
            self._started[key] = self._clock()
        try:
            yield
        finally:
            with self._lock:
                self._started.pop(key, None)

    def snapshot(self) -> dict[str, Any]:
        """Current in-flight count, plus the oldest item's age when non-empty."""
        with self._lock:
            count = len(self._started)
            oldest = min(self._started.values()) if self._started else None
        if oldest is None:
            return {"in_flight": count}
        return {"in_flight": count, "oldest_in_flight_s": self._clock() - oldest}


class Reporter:
    """Owns the scan clock and the sink, and hands out per-stage trackers."""

    def __init__(
        self,
        sink: ProgressSink | None = None,
        *,
        interval: float = DEFAULT_INTERVAL,
        clock: Callable[[], float] = time.monotonic,
        now: Callable[[], datetime] | None = None,
        heartbeat: bool = True,
    ) -> None:
        self._sink = sink if sink is not None else NullSink()
        self._interval = interval
        self._clock = clock
        self._now = now or (lambda: datetime.now(UTC))
        # Serialises writes: the heartbeat thread and the pipeline thread share
        # one stream, and unsynchronised writes would interleave mid-line.
        self._write_lock = threading.Lock()
        self.heartbeat = heartbeat
        self.started_at = clock()

    def monotonic(self) -> float:
        return self._clock()

    def timestamp(self) -> datetime:
        return self._now()

    @property
    def elapsed_s(self) -> float:
        return self._clock() - self.started_at

    def emit(self, event: Event) -> None:
        with self._write_lock:
            self._sink.emit(event)

    def note(self, message: str, *, stage: str = "scan") -> None:
        """Report a one-off message outside any per-item counting."""
        self.emit(
            Event(
                kind=NOTE,
                stage=stage,
                message=message,
                elapsed_s=self.elapsed_s,
                timestamp=self._now(),
            )
        )

    def stage(
        self,
        name: str,
        *,
        total: int | None = None,
        interval: float | None = None,
        detail: Callable[[], Mapping[str, Any]] | None = None,
        eta: bool = True,
    ) -> StageTracker:
        """Begin a stage.

        Args:
            name: Stage label, used as the renderer's second column.
            total: Item count when known; ``None`` reports indeterminately.
            interval: Override the reporter's paint interval.
            detail: Called *at paint time only*, so a hot loop pays nothing for
                measurements that are usually thrown away, and a heartbeat
                paint reads fresh values rather than those of the last item.
            eta: See :attr:`Event.eta`.
        """
        return StageTracker(
            self,
            name,
            total=total,
            interval=self._interval if interval is None else interval,
            detail=detail,
            eta=eta,
        )


class StageTracker:
    """Counts one stage's items and decides when to paint.

    Construct through :meth:`Reporter.stage`. Usable as a context manager, which
    guarantees the heartbeat is reaped even if the stage raises.
    """

    def __init__(
        self,
        reporter: Reporter,
        name: str,
        *,
        total: int | None,
        interval: float,
        detail: Callable[[], Mapping[str, Any]] | None,
        eta: bool,
    ) -> None:
        self._reporter = reporter
        self.name = name
        self.total = total
        self.done = 0
        self._interval = max(0.0, interval)
        self._detail = detail
        self._eta = eta
        self._lock = threading.Lock()
        self._started = reporter.monotonic()
        self._last_paint = self._started
        self._finished = False
        self._heartbeat: _Heartbeat | None = None
        # An indeterminate stage has nothing to announce up front; its first
        # useful line is the heartbeat's "still working".
        if total is not None:
            with self._lock:
                self._emit(STAGE_STARTED)
        if reporter.heartbeat and self._interval > 0:
            self._heartbeat = _Heartbeat(self, self._interval)
            self._heartbeat.start()

    def advance(self, count: int = 1) -> None:
        """Record ``count`` completed items, painting if the throttle allows.

        The clock comparison comes before any formatting: on a stage with
        thousands of items, deciding *not* to paint must cost less than the work
        being described.
        """
        with self._lock:
            self.done += count
            self._maybe_paint()

    def tick(self) -> None:
        """Paint the current state if the interval has elapsed.

        Driven by the heartbeat. This is what reports a stage that is busy but
        has completed nothing -- the case a completion-driven renderer misses
        entirely, and the one where the user most wants to know it is alive.
        """
        with self._lock:
            self._maybe_paint()

    def finish(self, message: str = "") -> None:
        """Emit the stage's closing line with its duration. Idempotent."""
        with self._lock:
            if self._finished:
                return
            self._finished = True
            self._emit(STAGE_FINISHED, message=message)
            heartbeat, self._heartbeat = self._heartbeat, None
        # Joined outside the lock: the heartbeat may be blocked on it in tick().
        if heartbeat is not None:
            heartbeat.stop()

    def abandon(self) -> None:
        """Stop reporting without claiming the stage completed."""
        with self._lock:
            self._finished = True
            heartbeat, self._heartbeat = self._heartbeat, None
        if heartbeat is not None:
            heartbeat.stop()

    def __enter__(self) -> StageTracker:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        # A stage that raised did not finish, and must not print a line saying
        # it did; reap the heartbeat and let the exception through.
        self.abandon() if exc_type is not None else self.finish()
        return False

    # -- internals (callers hold ``self._lock``) --------------------------

    def _maybe_paint(self) -> None:
        if self._finished:
            return
        if self._reporter.monotonic() - self._last_paint < self._interval:
            return
        self._emit(STAGE_PROGRESS)

    def _emit(self, kind: str, *, message: str = "") -> None:
        now = self._reporter.monotonic()
        self._last_paint = now
        self._reporter.emit(
            Event(
                kind=kind,
                stage=self.name,
                done=self.done,
                total=self.total,
                elapsed_s=now - self._reporter.started_at,
                stage_elapsed_s=now - self._started,
                message=message,
                detail=self._snapshot_detail(),
                eta=self._eta,
                timestamp=self._reporter.timestamp(),
            )
        )

    def _snapshot_detail(self) -> Mapping[str, Any]:
        if self._detail is None:
            return {}
        try:
            return dict(self._detail())
        except Exception:  # pragma: no cover - a display must not break a scan
            return {}


class _Heartbeat:
    """Daemon thread that pokes a tracker so a stalled stage still reports."""

    __slots__ = ("_stop", "_thread")

    def __init__(self, tracker: StageTracker, interval: float) -> None:
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            args=(tracker, interval),
            name=f"strata-progress-{tracker.name}",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=1.0)

    def _run(self, tracker: StageTracker, interval: float) -> None:
        # Poll finer than the interval so the line after a stall lands roughly
        # on time instead of up to a full interval late.
        step = min(1.0, max(0.05, interval / 4))
        while not self._stop.wait(step):
            tracker.tick()


# --- rendering ----------------------------------------------------------

_KNOWN_DETAIL = frozenset({"cost_ceiling_usd", "cost_usd", "in_flight", "oldest_in_flight_s"})


def _hms(seconds: float) -> str:
    """``mm:ss``, widening to ``h:mm:ss`` past the hour."""
    total = max(0, int(seconds))
    hours, rest = divmod(total, 3600)
    minutes, secs = divmod(rest, 60)
    return f"{hours}:{minutes:02d}:{secs:02d}" if hours else f"{minutes:02d}:{secs:02d}"


def _throughput(done: int, seconds: float) -> str | None:
    if done <= 0 or seconds <= 0:
        return None
    per_second = done / seconds
    # Adjudication runs well under one item per second, where a rounded "0/s"
    # would read as stalled.
    return f"{per_second:.1f}/s" if per_second >= 1 else f"{per_second * 60:.1f}/min"


def _eta(done: int, total: int | None, seconds: float) -> str | None:
    if not total or done <= 0 or done >= total or seconds <= 0:
        return None
    remaining = (total - done) * (seconds / done)
    # "eta 00:00" is worse than no estimate: it claims a precision the next
    # rounding step contradicts.
    return _hms(remaining) if remaining >= 1.0 else None


def _detail_parts(detail: Mapping[str, Any]) -> list[str]:
    parts: list[str] = []
    in_flight = detail.get("in_flight")
    if in_flight:
        parts.append(f"{in_flight} in flight")
    oldest = detail.get("oldest_in_flight_s")
    # Below a second there is nothing to worry about, which is what this number
    # is for; reporting "oldest 00:00" only adds noise.
    if oldest and oldest >= 1.0:
        parts.append(f"oldest {_hms(oldest)}")
    cost = detail.get("cost_usd")
    if cost is not None:
        ceiling = detail.get("cost_ceiling_usd")
        parts.append(f"${cost:.2f}/${ceiling:.2f}" if ceiling else f"${cost:.2f}")
    for key in sorted(set(detail) - _KNOWN_DETAIL):
        parts.append(f"{key}={detail[key]}")
    return parts


class PlainRenderer:
    """One timestamped line per event, for a log file, a pipe or CI.

    Deliberately append-only: nothing is rewritten in place, so the output
    survives being redirected to a file and stays readable when interleaved
    with anything else on the stream.
    """

    __slots__ = ("stage_width", "stream")

    def __init__(self, stream: TextIO, *, stage_width: int = 10) -> None:
        self.stream = stream
        self.stage_width = stage_width

    def emit(self, event: Event) -> None:
        body = self._body(event)
        if not body:
            return
        # Elapsed for reading a run top to bottom; wall clock for lining a stall
        # up against provider-side rate limiting or an incident timeline.
        stamp = f"[{_hms(event.elapsed_s)}] {event.timestamp:%H:%M:%S}Z"
        self.stream.write(f"{stamp} {event.stage:<{self.stage_width}} {body}\n")
        self.stream.flush()

    def _body(self, event: Event) -> str:
        if event.kind == NOTE:
            return event.message
        if event.kind == STAGE_STARTED:
            # An empty stage has nothing to announce; its summary says it all.
            return f"0/{event.total}" if event.total else ""
        if event.kind == STAGE_FINISHED:
            # No detail here: the stage's own summary is authoritative about what
            # it did, and appending the running cost to it only repeats the
            # figure the summary already carries.
            parts = [f"done {event.done}/{event.total}" if event.total else "done"]
            if event.message:
                parts.append(event.message)
            parts.append(f"{event.stage_elapsed_s:.1f}s")
            return " · ".join(parts)
        if event.kind != STAGE_PROGRESS:
            return ""

        if event.total:
            parts = [f"{event.done}/{event.total}", f"{event.done / event.total:.0%}"]
        elif event.done:
            parts = [str(event.done)]
        else:
            # Indeterminate and nothing counted yet: a long clone or rev-list.
            parts = ["working"]
        rate = _throughput(event.done, event.stage_elapsed_s)
        if rate is not None:
            parts.append(rate)
        parts.extend(_detail_parts(event.detail))
        if event.eta:
            remaining = _eta(event.done, event.total, event.stage_elapsed_s)
            if remaining is not None:
                parts.append(f"eta {remaining}")
        return " · ".join(parts)
