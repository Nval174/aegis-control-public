"""Atomic bounded synthetic batches; declared delivery is not verified delivery."""

from dataclasses import dataclass

from .config import METRICS, OPTIONAL_INTEGRATIONS, SERVICE_ID
from .counters import CounterDelta, CounterError, CounterSample, advance_counter
from .coverage import identity
from .telemetry import MAX_TIME, TelemetryError, normalize_route, validate_clock

MAX_EVENTS = 256
MAX_KEYS = 64


class SequenceError(ValueError):
    """Fatal batch/envelope error with no input values or partial report."""


@dataclass(frozen=True, order=True)
class StreamKey:
    service_id: str
    source: str
    metric: str
    route: str


@dataclass(frozen=True)
class SequenceEvent:
    key: StreamKey
    sequence: int
    at: int
    sample: CounterSample | None
    continuous: bool = False
    kind: str = "sample"


@dataclass(frozen=True)
class SequenceRow:
    key: StreamKey
    sequence: int
    at: int
    delivery: str
    state: str
    reason: str
    count: int | None
    elapsed_seconds: int | None
    baseline_present: bool
    expired_count: int
    evicted: StreamKey | None


@dataclass(frozen=True)
class RetainedStream:
    key: StreamKey
    last_sequence: int
    last_seen: int
    baseline_present: bool


@dataclass(frozen=True)
class SequenceReport:
    results: tuple[SequenceRow, ...]
    retained: tuple[RetainedStream, ...]
    peak_streams: int
    delivery_scope: str = "declared_sequence_only"


@dataclass(frozen=True)
class _Entry:
    baseline: CounterSample | None
    high_water: int
    last_seen: int


def _validate_key(key):
    if (type(key) is not StreamKey
            or any(type(v) is not str for v in identity(key))
            or SERVICE_ID.fullmatch(key.service_id) is None
            or key.source not in ({"proxy"} | OPTIONAL_INTEGRATIONS) or key.metric not in METRICS):
        raise SequenceError("event requires a valid explicit logical stream key")
    if key.route != "OTHER":
        try:
            normalize_route(key.route, (key.route,))
        except TelemetryError:
            raise SequenceError("stream key requires a normalized route") from None


def _preflight(events, max_keys, retention_seconds, max_age):
    if type(events) not in (list, tuple) or len(events) > MAX_EVENTS:
        raise SequenceError("batch requires a finite list/tuple of at most 256 events")
    # Freeze a bounded shallow snapshot before validation and processing.
    events = tuple(events[:MAX_EVENTS + 1])
    if len(events) > MAX_EVENTS:
        raise SequenceError("batch exceeds the 256-event limit")
    if type(max_keys) is not int or not 1 <= max_keys <= MAX_KEYS:
        raise SequenceError("max_keys requires an integer in 1-64")
    if type(retention_seconds) is not int or not 1 <= retention_seconds <= 86400:
        raise SequenceError("retention_seconds requires an integer in 1-86400")
    last_at = None
    try:
        validate_clock(0, max_age)
        for event in events:
            if type(event) is not SequenceEvent:
                raise SequenceError("batch contains an unidentifiable event envelope")
            _validate_key(event.key)
            if type(event.sequence) is not int or not 1 <= event.sequence <= MAX_TIME:
                raise SequenceError("declared sequence requires a positive bounded integer")
            validate_clock(event.at, max_age)
            if last_at is not None and event.at < last_at:
                raise SequenceError("event evaluation time moved backward")
            last_at = event.at
    except TelemetryError:
        raise SequenceError("event evaluation requires Unix seconds and max_age in 1-86400") from None
    return events


def _delivery(sequence, entry):
    if entry is None:
        return "unanchored"
    if sequence == entry.high_water + 1:
        return "adjacent"
    if sequence > entry.high_water:
        return "gap"
    return "duplicate" if sequence == entry.high_water else "out_of_order"


def validate_stream_key(key):
    """Validate a normalized logical identity without processing a stream."""
    _validate_key(key)


def validate_sequence_events(events, *, max_keys=16, retention_seconds=60, max_age=60):
    """Return the same bounded envelope snapshot used by the runner, without state."""
    return _preflight(events, max_keys, retention_seconds, max_age)


def _transition(event, entry, delivery, max_age):
    try:
        if type(event.kind) is not str or event.kind not in {"sample", "break"}:
            raise CounterError("invalid event kind")
        previous = entry.baseline if delivery == "adjacent" else None
        result = advance_counter(previous, event.sample, as_of=event.at,
                                 max_age=max_age, continuous=event.continuous)
        if event.sample is not None and identity(event.sample.observation) != identity(event.key):
            raise CounterError("payload identity conflicts with destination")
        if event.kind == "break":
            if event.sample is not None:
                raise CounterError("break cannot retain a payload")
            return CounterDelta("UNAVAILABLE", "declared_discontinuity")
        if delivery in {"gap", "duplicate", "out_of_order"}:
            return CounterDelta("UNAVAILABLE", "delivery_" + delivery)
        return result
    except CounterError:
        # Never retain malformed payloads or arbitrary exception text.
        return CounterDelta("UNAVAILABLE", "invalid_payload")


def run_counter_sequence(events, *, max_keys=16, retention_seconds=60, max_age=60):
    """Process one atomic list/tuple in supplied order with no cross-call state.

    A gap check establishes only declared-sequence consistency. continuous remains
    caller testimony. Expiration/eviction discards baseline AND delivery metadata.
    See COUNTER_SEQUENCES.md for failure scope, boundaries and bounded output.
    """
    events = _preflight(events, max_keys, retention_seconds, max_age)
    entries = {}
    rows = []
    peak = 0
    for event in events:
        expired = [key for key, entry in entries.items()
                   if event.at - entry.last_seen > retention_seconds]
        for key in expired:
            del entries[key]
        evicted = None
        if event.key not in entries and len(entries) >= max_keys:
            evicted = min(entries, key=lambda key: (entries[key].last_seen, key))
            del entries[evicted]
        previous = entries.get(event.key)
        delivery = _delivery(event.sequence, previous)
        result = _transition(event, previous, delivery, max_age)
        high_water = max(event.sequence, previous.high_water) if previous else event.sequence
        entries[event.key] = _Entry(result.next_baseline, high_water, event.at)
        peak = max(peak, len(entries))
        rows.append(SequenceRow(event.key, event.sequence, event.at, delivery,
                                result.state, result.reason, result.count, result.elapsed_seconds,
                                result.next_baseline is not None, len(expired), evicted))
    retained = tuple(RetainedStream(key, entries[key].high_water, entries[key].last_seen,
                                    entries[key].baseline is not None) for key in sorted(entries))
    return SequenceReport(tuple(rows), retained, peak)
