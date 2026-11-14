"""Pure count differences for declared saved kernel intervals; no rates or state."""

from dataclasses import dataclass

from .kernel_comparison import compare_snapshots


@dataclass(frozen=True)
class CountDifference:
    state: str
    reason: str
    count: int | None


@dataclass(frozen=True)
class SnapshotDifferences:
    ListenDrops: CountDifference
    ListenOverflows: CountDifference


def difference_snapshots(previous, current, *, as_of, max_age=60, continuous=False):
    """Revalidate the original pair on every call, then subtract eligible counters.

    ComparisonError propagates atomically for malformed inputs. No prior eligibility
    report is accepted, and no caller state is cleared. Continuity remains testimony;
    callers must abandon invalid baselines rather than bridge an omitted event.
    """
    comparison = compare_snapshots(previous, current, as_of=as_of,
                                   max_age=max_age, continuous=continuous)

    def difference(name):
        eligibility = getattr(comparison, name)
        if not eligibility.eligible:
            return CountDifference("UNAVAILABLE", eligibility.reason, None)
        # Validation and eligibility guarantee exact nondecreasing unsigned integers.
        before = getattr(previous.snapshot, name).value
        after = getattr(current.snapshot, name).value
        return CountDifference("AVAILABLE", "difference", after - before)

    return SnapshotDifferences(difference("ListenDrops"), difference("ListenOverflows"))
