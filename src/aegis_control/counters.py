"""Pure caller-owned counter transitions; no I/O, retained history or rates."""

from dataclasses import dataclass
import math

from .config import METRICS, OPTIONAL_INTEGRATIONS, SERVICE_ID
from .coverage import identity
from .telemetry import (MAX_TIME, MAX_VALUE, Observation, TelemetryError,
                        normalize_route, validate_clock)


class CounterError(ValueError):
    """Malformed API input; diagnostics omit endpoint values and metadata."""


@dataclass(frozen=True)
class CounterSample:
    observation: Observation
    counter_id: str
    generation: str


@dataclass(frozen=True)
class CounterDelta:
    state: str
    reason: str
    count: int | None = None
    elapsed_seconds: int | None = None
    next_baseline: CounterSample | None = None


def _time(value):
    return type(value) is int and 0 <= value <= MAX_TIME


def _validate(sample, as_of):
    if sample is None:
        return
    if type(sample) is not CounterSample or type(sample.observation) is not Observation:
        raise CounterError("counter endpoint requires CounterSample with Observation or None")
    for token in (sample.counter_id, sample.generation):
        if type(token) is not str or SERVICE_ID.fullmatch(token) is None:
            raise CounterError("counter metadata requires 1-64 character ASCII identifiers")
    o = sample.observation
    if (any(type(v) is not str for v in (o.service_id, o.source, o.metric, o.state, o.route))
            or SERVICE_ID.fullmatch(o.service_id) is None
            or o.source not in ({"proxy"} | OPTIONAL_INTEGRATIONS) or o.metric not in METRICS):
        raise CounterError("counter observation identity is invalid")
    if o.route != "OTHER":
        try:
            normalize_route(o.route, (o.route,))
        except TelemetryError:
            raise CounterError("counter observation requires a normalized route") from None
    if not _time(o.collected_at) or o.collected_at > as_of:
        raise CounterError("counter collection time is invalid or future")
    allowed = {"NOT_APPLICABLE"} if o.source in OPTIONAL_INTEGRATIONS else {"OBSERVED", "UNKNOWN", "STALE"}
    if o.state not in allowed:
        raise CounterError("counter observation validity conflicts with source")
    if o.state in {"OBSERVED", "STALE"}:
        if not _time(o.observed_at) or o.observed_at > o.collected_at:
            raise CounterError("counter observation time is invalid or after collection")
        if o.state == "STALE":
            if o.value is not None:
                raise CounterError("discarded stale values must remain unavailable")
        elif (type(o.value) not in (int, float) or not 0 <= o.value <= MAX_VALUE
              or not math.isfinite(o.value)
              or (o.metric == "requests_total" and type(o.value) is not int)):
            raise CounterError("counter observation requires a bounded typed finite value")
    elif o.observed_at is not None or o.value is not None:
        raise CounterError("unavailable observations require null observation time and value")


def _ineligible(sample, as_of, max_age):
    if sample is None:
        return "missing"
    o = sample.observation
    if o.state != "OBSERVED":
        return o.state.lower()
    if as_of - o.observed_at > max_age:
        return "stale"
    if o.source != "proxy" or o.metric != "requests_total":
        return "not_counter"
    if o.route == "OTHER":
        return "ambiguous_route"
    return None


def advance_counter(previous, current, *, as_of, max_age=60, continuous=False):
    """Validate one transition and return the sole baseline the caller may retain.

    continuous=True is caller testimony of uninterrupted same-counter semantics,
    not something inferred from labels, tokens or nondecreasing endpoint values.
    Feed every event; clear caller state on CounterError. See COUNTER_DELTAS.md.
    """
    try:
        validate_clock(as_of, max_age)
    except TelemetryError:
        raise CounterError("counter evaluation requires Unix seconds and max_age in 1-86400") from None
    if type(continuous) is not bool:
        raise CounterError("continuous requires an explicit Boolean assertion")
    _validate(previous, as_of)
    _validate(current, as_of)
    reason = _ineligible(current, as_of, max_age)
    if reason:
        return CounterDelta("UNAVAILABLE", "current_" + reason)
    if previous is None:
        return CounterDelta("BASELINE", "no_prior_baseline", next_baseline=current)
    reason = _ineligible(previous, as_of, max_age)
    if reason:
        return CounterDelta("UNAVAILABLE", "previous_" + reason)
    a, b = previous.observation, current.observation
    if identity(a) != identity(b):
        return CounterDelta("UNAVAILABLE", "identity_changed")
    if previous.counter_id != current.counter_id:
        return CounterDelta("UNAVAILABLE", "counter_changed")
    if previous.generation != current.generation:
        return CounterDelta("UNAVAILABLE", "generation_changed")
    if not continuous:
        return CounterDelta("UNAVAILABLE", "continuity_unconfirmed")
    if b.observed_at == a.observed_at:
        reason = "duplicate_time" if b.value == a.value else "conflicting_time"
        return CounterDelta("UNAVAILABLE", reason)
    if b.observed_at < a.observed_at:
        return CounterDelta("UNAVAILABLE", "out_of_order")
    if b.value < a.value:
        return CounterDelta("UNAVAILABLE", "counter_decreased")
    return CounterDelta("AVAILABLE", "difference", b.value - a.value,
                        b.observed_at - a.observed_at, current)
