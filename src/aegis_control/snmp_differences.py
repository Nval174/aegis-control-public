"""Exact saved SNMP count differences; no rates, clock, I/O or retained state."""
from dataclasses import dataclass

from .kernel_differences import CountDifference
from .snmp_comparison import compare_snmp_snapshots


@dataclass(frozen=True)
class SnmpDifferences:
    InSegs: CountDifference
    OutSegs: CountDifference
    RetransSegs: CountDifference


def difference_snmp_snapshots(previous, current, *, as_of, max_age=60, continuous=False):
    """Revalidate original samples/settings before independent eligible subtraction.

    ComparisonError propagates atomically. No prior report authorizes arithmetic;
    callers must discard failed baselines themselves. See SNMP_DIFFERENCES.md.
    """
    comparison = compare_snmp_snapshots(previous, current, as_of=as_of,
                                        max_age=max_age, continuous=continuous)

    def difference(name):
        eligibility = getattr(comparison, name)
        if not eligibility.eligible:
            return CountDifference("UNAVAILABLE", eligibility.reason, None)
        before = getattr(previous.snapshot, name).value
        after = getattr(current.snapshot, name).value
        return CountDifference("AVAILABLE", "difference", after - before)

    return SnmpDifferences(difference("InSegs"), difference("OutSegs"), difference("RetransSegs"))
