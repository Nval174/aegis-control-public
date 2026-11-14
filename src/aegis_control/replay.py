"""Bounded trusted-local synthetic replay, without target or network activity."""

from dataclasses import asdict
import json
from pathlib import Path
import stat

from .telemetry import TelemetryError, normalize_route, parse_observation, validate_clock
from .coverage import assess_coverage, identity

MAX_RECORD_BYTES = 16 * 1024
MAX_FILE_BYTES = 1024 * 1024
MAX_RECORDS = 1000
MAX_KEYS = 128


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _constant(value):
    raise ValueError("nonfinite JSON constant")


def replay_stream(stream, config, *, as_of, max_age=60, catalog=("/",)):
    """Reject whole input on overflow; never emit a successful truncated report."""
    validate_clock(as_of, max_age)
    normalize_route("/", catalog)
    if config.required_observations is not None and any(
            r.route != "OTHER" and r.route not in catalog for r in config.required_observations):
        raise TelemetryError("required known routes must be present in the replay catalog")
    services = {s.id for s in config.services}
    counts = dict(OBSERVED=0, UNKNOWN=0, STALE=0, NOT_APPLICABLE=0)
    latest = {}
    records = total = 0
    while True:
        raw = stream.readline(MAX_RECORD_BYTES + 1)
        if not raw:
            break
        total += len(raw)
        if len(raw) > MAX_RECORD_BYTES or total > MAX_FILE_BYTES or records >= MAX_RECORDS:
            raise TelemetryError("replay exceeds the record, file or record-count development limit")
        try:
            data = json.loads(raw.decode("utf-8"), object_pairs_hook=_object,
                              parse_constant=_constant)
        except (ValueError, RecursionError):
            raise TelemetryError("replay input is invalid UTF-8 or malformed JSON") from None
        item = parse_observation(data, services, catalog, as_of=as_of, max_age=max_age)
        key = identity(item)
        if key not in latest and len(latest) >= MAX_KEYS:
            raise TelemetryError("replay exceeds the 128-key development limit")
        previous = latest.get(key)
        if previous is None or item.collected_at >= previous.collected_at:
            latest[key] = item
        counts[item.state] += 1
        records += 1
    status = ("UNKNOWN" if not records else
              "DEGRADED" if counts["UNKNOWN"] or counts["STALE"] else "COMPLETE")
    coverage, details = assess_coverage(config.required_observations, latest.values(),
                                       as_of=as_of, max_age=max_age)
    return dict(scope="synthetic offline replay only", enforcement=False,
                input_validated=True, runtime_readiness="untested",
                coverage=coverage, coverage_details=details, status=status, as_of=as_of,
                max_age=max_age, records=records, counts=counts,
                latest=[asdict(latest[key]) for key in sorted(latest)])


def replay_file(path, config, *, as_of, max_age=60, catalog=("/",)):
    """Regular local paths only; same trusted-filesystem limitations as config-check."""
    name = str(path)
    if "://" in name or name.replace("\\", "/").startswith("//"):
        raise TelemetryError("replay requires a filesystem path, not URL or UNC syntax")
    target = Path(path)
    try:
        metadata = target.stat()
        if not stat.S_ISREG(metadata.st_mode):
            raise TelemetryError("replay input must be a regular file")
        if metadata.st_size > MAX_FILE_BYTES:
            raise TelemetryError("replay exceeds the 1-MiB development limit")
        with target.open("rb") as stream:
            return replay_stream(stream, config, as_of=as_of,
                                 max_age=max_age, catalog=catalog)
    except OSError as error:
        raise TelemetryError(f"cannot read replay input ({type(error).__name__})") from None
