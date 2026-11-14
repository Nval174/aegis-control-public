"""Conditional SNMP interval eligibility; no arithmetic, I/O or retained baseline."""
from dataclasses import dataclass

from ._comparison_core import EndpointFacts, reading_reason, shared_reason
from .kernel_comparison import ComparisonError, Eligibility, MAX_TIME
from .netstat_snapshot import LABEL
from .snmp_snapshot import SnmpReading, TcpSnmpSnapshot


@dataclass(frozen=True)
class SnmpSample:
    snapshot: TcpSnmpSnapshot
    observed_at: int
    source: str
    namespace: str
    generation: str | None


@dataclass(frozen=True)
class SnmpComparisonResult:
    InSegs: Eligibility
    OutSegs: Eligibility
    RetransSegs: Eligibility


def _time(value):
    return type(value) is int and 0 <= value <= MAX_TIME


def _validate(sample):
    if sample is None:
        return
    if type(sample) is not SnmpSample or type(sample.snapshot) is not TcpSnmpSnapshot:
        raise ComparisonError("SNMP comparison requires SnmpSample or None")
    if not _time(sample.observed_at):
        raise ComparisonError("SNMP observation time requires bounded integer Unix seconds")
    for name in ("source", "namespace", "generation"):
        token = getattr(sample, name)
        if name == "generation" and token is None:
            continue
        if type(token) is not str or not 1 <= len(token) <= 64 or LABEL.fullmatch(token) is None:
            raise ComparisonError("SNMP labels require bounded ASCII identifiers")
    snapshot = sample.snapshot
    if type(snapshot.word_bits) is not int or snapshot.word_bits not in (32, 64):
        raise ComparisonError("SNMP declared width must be integer 32 or 64")
    readings = (snapshot.InSegs, snapshot.OutSegs, snapshot.RetransSegs)
    for counter in readings:
        if type(counter) is not SnmpReading or type(counter.reason) is not str:
            raise ComparisonError("SNMP comparison requires typed readings and reasons")
        if counter.reason == "observed":
            if type(counter.value) is not int or not 0 <= counter.value < (1 << snapshot.word_bits):
                raise ComparisonError("SNMP observed value exceeds declared unsigned domain")
        elif counter.reason in ("field_missing", "section_missing"):
            if counter.value is not None:
                raise ComparisonError("SNMP missing readings require unavailable values")
        else:
            raise ComparisonError("unsupported SNMP reading validity reason")
    if any(r.reason == "section_missing" for r in readings) and not all(r.reason == "section_missing" for r in readings):
        raise ComparisonError("missing SNMP section requires all three readings unavailable")


def _facts(sample):
    if sample is None:
        return None
    return EndpointFacts(sample.observed_at, sample.source, sample.namespace,
                         sample.generation, sample.snapshot.word_bits)


def compare_snmp_snapshots(previous, current, *, as_of, max_age=60, continuous=False):
    """Validate both endpoints, then apply shared reasons independently per reading.

    Continuity is whole-interval caller testimony. No state is cleared or retained;
    callers must discard invalid baselines. See SNMP_COMPARISONS.md.
    """
    if not _time(as_of) or type(max_age) is not int or not 1 <= max_age <= 86400:
        raise ComparisonError("evaluation requires Unix seconds and max_age in 1-86400")
    if type(continuous) is not bool:
        raise ComparisonError("continuous requires an explicit Boolean assertion")
    _validate(previous)
    _validate(current)
    shared = shared_reason(_facts(previous), _facts(current), as_of, max_age, continuous)

    def result(name):
        a = getattr(previous.snapshot, name) if previous is not None else None
        b = getattr(current.snapshot, name) if current is not None else None
        reason = reading_reason(previous_reason=a.reason if a is not None else None,
                                current_reason=b.reason if b is not None else None,
                                previous_value=a.value if a is not None else None,
                                current_value=b.value if b is not None else None,
                                shared=shared)
        return Eligibility(reason == "prerequisites_declared", reason)

    return SnmpComparisonResult(result("InSegs"), result("OutSegs"), result("RetransSegs"))
