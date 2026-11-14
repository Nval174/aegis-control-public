"""Pure current coverage of validated declarations and selected observations."""

from dataclasses import asdict

import math

from .config import MAX_REQUIREMENTS, METRICS, OPTIONAL_INTEGRATIONS, RequiredObservation, SERVICE_ID
from .telemetry import (MAX_VALUE, Observation, TelemetryError, _time,
                        normalize_route, validate_clock)

MAX_SELECTED = 128


def identity(item):
    return item.service_id, item.source, item.metric, item.route


def _validate_identity(item):
    if (any(type(v) is not str for v in identity(item))
            or SERVICE_ID.fullmatch(item.service_id) is None
            or item.source not in ({"proxy"} | OPTIONAL_INTEGRATIONS) or item.metric not in METRICS):
        raise TelemetryError("coverage identity is invalid")
    if item.route != "OTHER":
        # Validate normalized syntax, without normalizing or asserting catalog membership.
        normalize_route(item.route, (item.route,))


def _validate_observation(item, as_of):
    if type(item) is not Observation:
        raise TelemetryError("coverage selected items require Observation values")
    _validate_identity(item)
    if not _time(item.collected_at) or item.collected_at > as_of:
        raise TelemetryError("coverage collection time is invalid or future")
    allowed = ({"NOT_APPLICABLE"} if item.source in OPTIONAL_INTEGRATIONS
               else {"OBSERVED", "UNKNOWN", "STALE"})
    if type(item.state) is not str or item.state not in allowed:
        raise TelemetryError("coverage validity conflicts with source")
    if item.state in {"OBSERVED", "STALE"}:
        if not _time(item.observed_at) or item.observed_at > item.collected_at:
            raise TelemetryError("coverage observation time is invalid or after collection")
        if item.state == "STALE":
            if item.value is not None:
                raise TelemetryError("coverage discarded stale values must remain unavailable")
        elif (type(item.value) not in (int, float) or not 0 <= item.value <= MAX_VALUE
              or not math.isfinite(item.value)
              or (item.metric == "requests_total" and type(item.value) is not int)):
            raise TelemetryError("coverage metric requires a bounded typed finite value")
    elif item.observed_at is not None or item.value is not None:
        raise TelemetryError("coverage unavailable observations require null time and value")


def _selected_observations(selected, as_of):
    try:
        iterator = iter(selected)
    except Exception:
        raise TelemetryError("coverage selected input requires an iterable") from None
    latest = {}
    for count in range(MAX_SELECTED + 1):
        try:
            item = next(iterator)
        except StopIteration:
            return latest
        except Exception:
            raise TelemetryError("coverage selected iteration failed") from None
        if count == MAX_SELECTED:
            raise TelemetryError("coverage exceeds the 128-observation limit")
        _validate_observation(item, as_of)
        key = identity(item)
        if key in latest:
            raise TelemetryError("coverage selected identities must be unique")
        latest[key] = item


def assess_coverage(requirements, selected, *, as_of, max_age):
    """Validate declarations and unique selected values; never select history.

    Requirements are a tuple/list; selected is a once-consumed iterable (including
    dict_values). None requirements skip selected validation after clock validation.
    Re-evaluation cannot resurrect STALE values. No I/O or wall clock.
    """
    validate_clock(as_of, max_age)
    if requirements is None:
        return "not_assessed", None
    if type(requirements) not in (tuple, list) or not 1 <= len(requirements) <= MAX_REQUIREMENTS:
        raise TelemetryError("coverage requires a tuple/list of 1-64 requirements")
    seen, routes = set(), set()
    for item in requirements:
        if type(item) is not RequiredObservation:
            raise TelemetryError("coverage requirements require RequiredObservation values")
        _validate_identity(item)
        if item.source != "proxy":
            raise TelemetryError("coverage requirements support only proxy")
        key = identity(item)
        if key in seen:
            raise TelemetryError("coverage required identities must be unique")
        seen.add(key)
        if item.route != "OTHER":
            routes.add(item.route)
    if len(routes) > 32:
        raise TelemetryError("coverage requirements exceed the 32-path catalog limit")
    latest = _selected_observations(selected, as_of)
    rows = []
    satisfied = 0
    for required in sorted(requirements, key=identity):
        item = latest.get(identity(required))
        if item is None:
            reason = "missing"
        elif item.state == "UNKNOWN":
            reason = "unknown"
        elif item.state == "STALE" or (item.state == "OBSERVED"
                                      and as_of - item.observed_at > max_age):
            reason = "stale"
        elif item.state == "OBSERVED":
            reason = "satisfied"
        else:
            # Impossible for validated proxy requirements/records; never treat N/A as usable.
            raise TelemetryError("selected observation contradicts required proxy source")
        satisfied += reason == "satisfied"
        rows.append(dict(asdict(required), reason=reason))
    details = dict(required_count=len(rows), satisfied_count=satisfied, requirements=rows)
    return ("complete" if satisfied == len(rows) else "incomplete"), details
