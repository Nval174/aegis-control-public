"""Strict synthetic wire fixtures; pure bytes boundary, no file I/O or repair."""

from dataclasses import asdict, dataclass
import json
import math

from .config import SERVICE_ID
from .counter_sequence import (MAX_EVENTS, SequenceError, SequenceEvent, StreamKey,
                               run_counter_sequence, validate_sequence_events, validate_stream_key)
from .counters import CounterSample
from .telemetry import FIELDS, MAX_TIME, MAX_VALUE, Observation

MAX_FIXTURE_BYTES = 1024 * 1024
MAX_DEPTH = 5
MAX_FIELDS = 8
MAX_STRING_CHARS = 2048
MAX_NAME_CHARS = 64


class FixtureError(ValueError):
    """Fatal bounded wire diagnostic with no input values or parser excerpts."""


@dataclass(frozen=True)
class SequenceSettings:
    max_keys: int
    retention_seconds: int
    max_age: int


@dataclass(frozen=True)
class DecodedSequenceFixture:
    settings: SequenceSettings
    events: tuple[SequenceEvent, ...]


def _object(pairs):
    if len(pairs) > MAX_FIELDS:
        raise FixtureError("fixture object exceeds field limit")
    result = {}
    for key, value in pairs:
        if len(key) > MAX_NAME_CHARS or key in result:
            raise FixtureError("fixture has oversized or duplicate field names")
        result[key] = value
    return result


def _constant(_value):
    raise FixtureError("fixture requires finite JSON numbers")


def _integer_token(token):
    if len(token) > 20:
        raise FixtureError("fixture integer token exceeds limit")
    return int(token)


def _depth(text):
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise FixtureError("fixture exceeds nesting limit")
        elif char in "]}":
            depth -= 1
            if depth < 0:
                raise FixtureError("fixture has unbalanced or unfinished containers/strings")
    if depth != 0 or quoted or escaped:
        raise FixtureError("fixture has unbalanced or unfinished containers/strings")


def _tree(value):
    if type(value) is str:
        if len(value) > MAX_STRING_CHARS or any(0xD800 <= ord(c) <= 0xDFFF for c in value):
            raise FixtureError("fixture string exceeds limit or contains invalid Unicode")
    elif type(value) is float and not math.isfinite(value):
        raise FixtureError("fixture requires finite JSON numbers")
    elif type(value) is list:
        if len(value) > MAX_EVENTS:
            raise FixtureError("fixture array exceeds event limit")
        for item in value:
            _tree(item)
    elif type(value) is dict:
        for name, item in value.items():
            _tree(name)
            _tree(item)


def _fields(value, names):
    if type(value) is not dict or set(value) != set(names):
        raise FixtureError("fixture object has missing, unknown or invalid fields")


def _int(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise FixtureError("fixture integer has invalid type or range")


def _key(data):
    _fields(data, ("service_id", "source", "metric", "route"))
    key = StreamKey(**data)
    validate_stream_key(key)
    return key


def _sample(data):
    _fields(data, ("counter_id", "generation", "observation"))
    for token in (data["counter_id"], data["generation"]):
        if type(token) is not str or SERVICE_ID.fullmatch(token) is None:
            raise FixtureError("fixture counter metadata requires bounded ASCII identifiers")
    obs = data["observation"]
    _fields(obs, FIELDS)
    _key({name: obs[name] for name in ("service_id", "source", "metric", "route")})
    if type(obs["state"]) is not str or obs["state"] not in {"OBSERVED", "UNKNOWN", "STALE", "NOT_APPLICABLE"}:
        raise FixtureError("fixture observation state is unsupported")
    _int(obs["collected_at"], 0, MAX_TIME)
    if obs["observed_at"] is not None:
        _int(obs["observed_at"], 0, MAX_TIME)
    value = obs["value"]
    if value is not None and (type(value) not in (int, float) or not 0 <= value <= MAX_VALUE
                              or (obs["metric"] == "requests_total" and type(value) is not int)):
        raise FixtureError("fixture value has invalid type or range")
    # Do not repair state/value/time contradictions: the runner invalidates them.
    return CounterSample(Observation(**obs), data["counter_id"], data["generation"])


def decode_sequence_fixture(raw):
    """Decode the complete schema-1 document into immutable inputs; never run it."""
    if type(raw) is not bytes:
        raise FixtureError("fixture input requires bytes")
    if len(raw) > MAX_FIXTURE_BYTES:
        raise FixtureError("fixture exceeds the 1-MiB byte limit")
    try:
        text = raw.decode("utf-8")
        _depth(text)
        data = json.loads(text, object_pairs_hook=_object, parse_constant=_constant,
                          parse_int=_integer_token)
    except FixtureError:
        raise
    except (ValueError, RecursionError):
        raise FixtureError("fixture is invalid UTF-8 or malformed JSON") from None
    _tree(data)
    try:
        _fields(data, ("schema_version", "settings", "events"))
        if type(data["schema_version"]) is not int or data["schema_version"] != 1:
            raise FixtureError("fixture schema_version requires integer 1")
        _fields(data["settings"], ("max_keys", "retention_seconds", "max_age"))
        settings = SequenceSettings(**data["settings"])
        if type(data["events"]) is not list or len(data["events"]) > MAX_EVENTS:
            raise FixtureError("fixture requires an array of at most 256 events")
        events = []
        for item in data["events"]:
            _fields(item, ("key", "sequence", "at", "sample", "continuous", "kind"))
            key = _key(item["key"])
            if type(item["continuous"]) is not bool or type(item["kind"]) is not str or item["kind"] not in {"sample", "break"}:
                raise FixtureError("fixture requires Boolean continuity and sample/break kind")
            if item["kind"] == "break" and item["sample"] is not None:
                raise FixtureError("fixture break requires a null sample")
            sample = _sample(item["sample"]) if item["sample"] is not None else None
            events.append(SequenceEvent(key, item["sequence"], item["at"], sample,
                                        item["continuous"], item["kind"]))
        snapshot = validate_sequence_events(events, **asdict(settings))
    except SequenceError:
        raise FixtureError("fixture key, settings or event envelope is invalid") from None
    return DecodedSequenceFixture(settings, snapshot)


def run_sequence_fixture(raw):
    """Decode atomically before delegating all execution to the existing runner."""
    decoded = decode_sequence_fixture(raw)
    return run_counter_sequence(decoded.events, **asdict(decoded.settings))
