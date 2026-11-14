"""Conditional eligibility for saved kernel counters; no arithmetic or retained state."""

from dataclasses import dataclass

from ._comparison_core import EndpointFacts, reading_reason, shared_reason
from .netstat_snapshot import Capture, CounterValue, LABEL, NetstatSnapshot

MAX_TIME = 2**63 - 1


class ComparisonError(ValueError):
    """Malformed inputs; fixed diagnostics omit supplied labels, values and paths."""


@dataclass(frozen=True)
class SnapshotSample:
    snapshot: NetstatSnapshot
    observed_at: int


@dataclass(frozen=True)
class Eligibility:
    eligible: bool
    reason: str


@dataclass(frozen=True)
class ComparisonResult:
    ListenDrops: Eligibility
    ListenOverflows: Eligibility


def _time(value):
    return type(value) is int and 0 <= value <= MAX_TIME


def _validate(sample):
    if sample is None:
        return
    if type(sample) is not SnapshotSample or type(sample.snapshot) is not NetstatSnapshot:
        raise ComparisonError("comparison endpoint requires SnapshotSample or None")
    if not _time(sample.observed_at):
        raise ComparisonError("observation time requires bounded integer Unix seconds")
    snapshot = sample.snapshot
    capture = snapshot.capture
    if type(capture) is not Capture:
        raise ComparisonError("comparison requires capture metadata")
    for name in ("source", "namespace", "generation"):
        token = getattr(capture, name)
        if name == "generation" and token is None:
            continue
        if type(token) is not str or not 1 <= len(token) <= 64 or LABEL.fullmatch(token) is None:
            raise ComparisonError("capture labels require bounded ASCII identifiers")
    if type(capture.word_bits) is not int or capture.word_bits not in (32, 64):
        raise ComparisonError("declared TcpExt width must be 32 or 64")
    for counter in (snapshot.ListenDrops, snapshot.ListenOverflows):
        if type(counter) is not CounterValue or type(counter.reason) is not str:
            raise ComparisonError("comparison counter requires a typed value and reason")
        if counter.reason == "observed":
            if type(counter.value) is not int or not 0 <= counter.value < (1 << capture.word_bits):
                raise ComparisonError("observed counter exceeds declared unsigned domain")
        elif counter.reason in ("field_missing", "section_missing"):
            if counter.value is not None:
                raise ComparisonError("missing counters require unavailable values")
        else:
            raise ComparisonError("unsupported counter validity reason")
    if ((snapshot.ListenDrops.reason == "section_missing") !=
            (snapshot.ListenOverflows.reason == "section_missing")):
        raise ComparisonError("missing section requires both counters unavailable")


def _facts(sample):
    if sample is None:
        return None
    capture = sample.snapshot.capture
    return EndpointFacts(sample.observed_at, capture.source, capture.namespace,
                         capture.generation, capture.word_bits)


def _counter_result(previous, current, name, shared_reason):
    a = getattr(previous.snapshot, name) if previous is not None else None
    b = getattr(current.snapshot, name) if current is not None else None
    reason = reading_reason(previous_reason=a.reason if a is not None else None,
                            current_reason=b.reason if b is not None else None,
                            previous_value=a.value if a is not None else None,
                            current_value=b.value if b is not None else None,
                            shared=shared_reason)
    return Eligibility(reason == "prerequisites_declared", reason)


def compare_snapshots(previous, current, *, as_of, max_age=60, continuous=False):
    """Check two declared captures per counter; never authenticate continuity.

    continuous=True attests the whole interval, including no omitted invalid,
    missing or discontinuous events. Default false. No state or baseline escapes;
    callers must not bridge a failure with an older sample. See KERNEL_COMPARISONS.md.
    """
    if not _time(as_of) or type(max_age) is not int or not 1 <= max_age <= 86400:
        raise ComparisonError("evaluation requires Unix seconds and max_age in 1-86400")
    if type(continuous) is not bool:
        raise ComparisonError("continuous requires an explicit Boolean assertion")
    _validate(previous)
    _validate(current)
    reason = shared_reason(_facts(previous), _facts(current), as_of, max_age, continuous)
    return ComparisonResult(
        _counter_result(previous, current, "ListenDrops", reason),
        _counter_result(previous, current, "ListenOverflows", reason),
    )
