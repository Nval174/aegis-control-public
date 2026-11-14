"""Pure synthetic observations; no native collection or identity attribution."""

from dataclasses import dataclass
import math

from .config import METRICS, OPTIONAL_INTEGRATIONS

MAX_TIME = 2**63 - 1
MAX_VALUE = 10**12
FIELDS = frozenset({"service_id", "source", "metric", "state", "value",
                    "observed_at", "collected_at", "route"})


class TelemetryError(ValueError):
    """Fixed diagnostics without input values, paths or parser excerpts."""


@dataclass(frozen=True)
class Observation:
    service_id: str
    source: str
    metric: str
    state: str
    value: int | float | None
    observed_at: int | None
    collected_at: int
    route: str


def _time(value):
    return type(value) is int and 0 <= value <= MAX_TIME


def validate_clock(as_of, max_age):
    if not _time(as_of) or type(max_age) is not int or not 1 <= max_age <= 86400:
        raise TelemetryError("evaluation requires Unix seconds and max_age in 1-86400")


def _path(value):
    return (type(value) is str and 1 <= len(value) <= 2048
            and value.startswith("/") and not value.startswith("//")
            and not any(ord(c) < 32 or ord(c) == 127 for c in value))


def normalize_route(route, catalog):
    """Conservative exact matching; no decoding, templating or raw-key retention."""
    if (not isinstance(catalog, (tuple, list)) or not 1 <= len(catalog) <= 32
            or any(not _path(p) or "?" in p or "#" in p for p in catalog)
            or len(set(catalog)) != len(catalog)):
        raise TelemetryError("route catalog requires 1-32 unique origin paths")
    if not _path(route):
        raise TelemetryError("route requires a bounded origin path")
    path = route.split("?", 1)[0].split("#", 1)[0]
    return path if path in catalog else "OTHER"


def parse_observation(data, service_ids, catalog, *, as_of, max_age):
    """Evaluate immutable observation validity at an explicit synthetic clock."""
    validate_clock(as_of, max_age)
    if type(data) is not dict or set(data) != FIELDS:
        raise TelemetryError("observation requires exactly the documented fields")
    service = data["service_id"]
    source = data["source"]
    metric = data["metric"]
    if type(service) is not str or service not in service_ids:
        raise TelemetryError("observation references an undeclared service")
    if type(source) is not str or source not in ({"proxy"} | OPTIONAL_INTEGRATIONS):
        raise TelemetryError("observation source is unsupported")
    if type(metric) is not str or metric not in METRICS:
        raise TelemetryError("observation metric is unsupported")
    collected = data["collected_at"]
    observed = data["observed_at"]
    state = data["state"]
    value = data["value"]
    if not _time(collected) or collected > as_of:
        raise TelemetryError("collection time is invalid or future")
    if source in OPTIONAL_INTEGRATIONS:
        allowed = state == "NOT_APPLICABLE"
    else:
        allowed = state in ("OBSERVED", "UNKNOWN")
    if not allowed:
        raise TelemetryError("validity conflicts with the disabled-source contract")
    if state == "OBSERVED":
        if not _time(observed) or observed > collected:
            raise TelemetryError("observation time is invalid or after collection")
        if (type(value) not in (int, float) or not 0 <= value <= MAX_VALUE
                or not math.isfinite(value)
                or (metric == "requests_total" and type(value) is not int)):
            raise TelemetryError("metric requires a bounded finite nonnegative value")
        if as_of - observed > max_age:
            state, value = "STALE", None
    elif observed is not None or value is not None:
        raise TelemetryError("unavailable observations require null time and value")
    return Observation(service, source, metric, state, value, observed, collected,
                       normalize_route(data["route"], catalog))
