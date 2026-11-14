"""Exact synthetic counts; physical continuity remains caller testimony."""
from dataclasses import FrozenInstanceError, asdict, replace
from pathlib import Path
import unittest

from aegis_control.kernel_comparison import ComparisonError, SnapshotSample, compare_snapshots
from aegis_control.kernel_differences import difference_snapshots
from aegis_control.netstat_snapshot import Capture, CounterValue, parse_netstat

FIXTURES = Path(__file__).with_name("fixtures")


def sample(drops=0, overflows=17, at=100, capture=None):
    capture = capture or Capture("synthetic", "lab-ns", "epoch-a", 64)
    raw = f"TcpExt: ListenDrops ListenOverflows\nTcpExt: {drops} {overflows}\n".encode()
    return SnapshotSample(parse_netstat(raw, capture), at)


class KernelDifferenceTests(unittest.TestCase):
    def assert_available(self, result, count):
        self.assertEqual(asdict(result), dict(state="AVAILABLE", reason="difference", count=count))
        self.assertIs(type(result.count), int)

    def assert_unavailable(self, result, reason):
        self.assertEqual(asdict(result), dict(state="UNAVAILABLE", reason=reason, count=None))

    def assert_both_unavailable(self, result, reason):
        self.assert_unavailable(result.ListenDrops, reason)
        self.assert_unavailable(result.ListenOverflows, reason)

    def test_saved_fixture_exact_increases(self):
        capture = Capture("synthetic", "lab-ns", "epoch-a", 64)
        previous = SnapshotSample(parse_netstat((FIXTURES / "netstat-normal.txt").read_bytes(), capture), 100)
        current = SnapshotSample(parse_netstat((FIXTURES / "netstat-comparison-next.txt").read_bytes(), capture), 101)
        result = difference_snapshots(previous, current, as_of=101, continuous=True)
        self.assert_available(result.ListenDrops, 3)
        self.assert_available(result.ListenOverflows, 1)

    def test_equal_positive_and_zero_are_available_zero(self):
        for drops, overflows in ((0, 0), (7, 19)):
            result = difference_snapshots(sample(drops, overflows), sample(drops, overflows, 101),
                                          as_of=101, continuous=True)
            self.assert_available(result.ListenDrops, 0)
            self.assert_available(result.ListenOverflows, 0)

    def test_maximum_differences_and_precision_for_both_widths(self):
        for bits, maximum in ((32, 4294967295), (64, 18446744073709551615)):
            capture = Capture("synthetic", "lab-ns", "epoch-a", bits)
            result = difference_snapshots(sample(0, 0, capture=capture),
                                          sample(maximum, maximum, 101, capture),
                                          as_of=101, continuous=True)
            self.assert_available(result.ListenDrops, maximum)
            self.assert_available(result.ListenOverflows, maximum)
            result = difference_snapshots(sample(maximum - 2, maximum - 1, capture=capture),
                                          sample(maximum - 1, maximum, 101, capture),
                                          as_of=101, continuous=True)
            self.assert_available(result.ListenDrops, 1)
            self.assert_available(result.ListenOverflows, 1)

    def test_each_missing_counter_is_independent_and_missing_is_not_zero(self):
        previous = sample(4, 17)
        for name, sibling in (("ListenDrops", "ListenOverflows"), ("ListenOverflows", "ListenDrops")):
            current = sample(7, 20, 101)
            current = replace(current, snapshot=replace(current.snapshot, **{
                name: CounterValue(None, "field_missing")}))
            result = difference_snapshots(previous, current, as_of=101, continuous=True)
            self.assert_unavailable(getattr(result, name), "current_field_missing")
            self.assert_available(getattr(result, sibling), 3)
            result = difference_snapshots(replace(current, observed_at=100), sample(8, 21, 101),
                                          as_of=101, continuous=True)
            self.assert_unavailable(getattr(result, name), "previous_field_missing")
            self.assert_available(getattr(result, sibling), 1)
        absent = parse_netstat((FIXTURES / "netstat-absent.txt").read_bytes(), previous.snapshot.capture)
        self.assert_both_unavailable(difference_snapshots(previous, SnapshotSample(absent, 101),
                                                         as_of=101, continuous=True), "current_section_missing")
        self.assert_both_unavailable(difference_snapshots(SnapshotSample(absent, 100), sample(at=101),
                                                         as_of=101, continuous=True), "previous_section_missing")

    def test_each_decrease_is_independent_without_wrap_or_negative_count(self):
        for drops, overflows, want_drops, want_overflows in (
            (9, 23, None, 3), (13, 19, 3, None), (9, 19, None, None),
        ):
            result = difference_snapshots(sample(10, 20), sample(drops, overflows, 101),
                                          as_of=101, continuous=True)
            for counter, expected in ((result.ListenDrops, want_drops), (result.ListenOverflows, want_overflows)):
                if expected is None:
                    self.assert_unavailable(counter, "counter_decreased")
                else:
                    self.assert_available(counter, expected)

    def test_metadata_changes_and_unknown_generation_never_produce_counts(self):
        a = sample()
        for field, value, reason in (
            ("source", "other", "source_changed"), ("namespace", "other", "namespace_changed"),
            ("word_bits", 32, "width_changed"), ("generation", "epoch-b", "generation_changed"),
            ("generation", None, "generation_unknown"),
        ):
            b = sample(3, 18, 101, replace(a.snapshot.capture, **{field: value}))
            self.assert_both_unavailable(difference_snapshots(a, b, as_of=101, continuous=True), reason)
        unknown = replace(a.snapshot.capture, generation=None)
        self.assert_both_unavailable(difference_snapshots(sample(capture=unknown),
                                                         sample(3, 18, 101, unknown),
                                                         as_of=101, continuous=True), "generation_unknown")

    def test_timing_failures_and_freshness_boundary_preserve_reasons(self):
        for a, b, as_of, reason in (
            (sample(), sample(3, 18, 101), 161, "previous_stale"),
            (sample(), sample(3, 18, 101), 162, "current_stale"),
            (sample(), sample(3, 18, 102), 101, "current_future"),
            (sample(at=102), sample(3, 18, 101), 101, "previous_future"),
            (sample(), sample(3, 18, 100), 101, "duplicate_time"),
            (sample(), sample(3, 18, 99), 101, "out_of_order"),
        ):
            self.assert_both_unavailable(difference_snapshots(a, b, as_of=as_of, continuous=True), reason)
        self.assert_available(difference_snapshots(sample(), sample(3, 18, 101), as_of=160,
                                                  continuous=True).ListenDrops, 3)

    def test_prior_eligibility_cannot_authorize_later_invocation(self):
        a, b = sample(), sample(3, 18, 101)
        earlier = compare_snapshots(a, b, as_of=101, continuous=True)
        self.assertTrue(earlier.ListenDrops.eligible)
        self.assert_both_unavailable(difference_snapshots(a, b, as_of=161, continuous=True), "previous_stale")
        self.assert_both_unavailable(difference_snapshots(a, b, as_of=101), "continuity_unconfirmed")
        self.assert_both_unavailable(difference_snapshots(a, b, as_of=102, max_age=1, continuous=True),
                                     "previous_stale")
        with self.assertRaises(ComparisonError):
            difference_snapshots(earlier, b, as_of=101, continuous=True)

    def test_direct_malformed_objects_and_settings_are_atomic_sanitized_errors(self):
        a, b = sample(), sample(3, 18, 101)
        bad = [None, CounterValue(True, "observed"), CounterValue(1.0, "observed"),
               CounterValue(-1, "observed"), CounterValue(2**64, "observed"),
               CounterValue(None, "observed"), CounterValue(0, "field_missing"),
               CounterValue(None, "section_missing"), CounterValue(None, "PRIVATE/path")]
        # ListenDrops would be eligible; invalid second counter must prevent any result.
        for value in bad:
            malformed = replace(b, snapshot=replace(b.snapshot, ListenOverflows=value))
            with self.assertRaises(ComparisonError) as helper_error:
                difference_snapshots(a, malformed, as_of=101, continuous=True)
            with self.assertRaises(ComparisonError) as comparison_error:
                compare_snapshots(a, malformed, as_of=101, continuous=True)
            self.assertEqual(str(helper_error.exception), str(comparison_error.exception))
            self.assertNotIn("PRIVATE", str(helper_error.exception))
        for capture in (Capture("PRIVATE/path", "n", "g", 64), Capture("a", "n", "g", True),
                        Capture("a", "n", "g", 16)):
            with self.assertRaises(ComparisonError):
                difference_snapshots(a, replace(b, snapshot=replace(b.snapshot, capture=capture)), as_of=101)
        for settings in ({"as_of": True}, {"as_of": -1}, {"as_of": 2**63},
                         {"as_of": 101, "max_age": True}, {"as_of": 101, "max_age": 0},
                         {"as_of": 101, "max_age": 86401}, {"as_of": 101, "continuous": 1}):
            with self.assertRaises(ComparisonError):
                difference_snapshots(a, b, **settings)
        for at in (True, -1, 2**63, 100.0):
            with self.assertRaises(ComparisonError):
                difference_snapshots(a, replace(b, observed_at=at), as_of=101)

    def test_caller_recovers_after_missing_and_malformed_without_bridging(self):
        for malformed in (False, True):
            baseline = sample()
            invalid = None if not malformed else replace(sample(at=101), snapshot=None)
            if malformed:
                try:
                    difference_snapshots(baseline, invalid, as_of=101, continuous=True)
                except ComparisonError:
                    baseline = None  # Explicit caller clearing, never library state.
                else:
                    self.fail("malformed input must not return a report")
            else:
                result = difference_snapshots(baseline, invalid, as_of=101, continuous=True)
                self.assert_both_unavailable(result, "current_unavailable")
                baseline = None
            b, c = sample(3, 18, 102), sample(5, 21, 103)
            self.assert_both_unavailable(difference_snapshots(baseline, b, as_of=102, continuous=True),
                                         "previous_unavailable")
            baseline = b
            result = difference_snapshots(baseline, c, as_of=103, continuous=True)
            self.assert_available(result.ListenDrops, 2)
            self.assert_available(result.ListenOverflows, 3)
        # Undisclosed invalid events + false testimony cannot be detected by a pair API.
        self.assert_available(difference_snapshots(sample(), sample(3, 18, 102), as_of=102,
                                                  continuous=True).ListenDrops, 3)
        self.assert_both_unavailable(difference_snapshots(None, None, as_of=101), "current_unavailable")

    def test_results_frozen_inputs_unchanged_repeatable_no_implicit_clearing(self):
        a, b = sample(), sample(3, 18, 101)
        before = asdict(a), asdict(b)
        first = difference_snapshots(a, b, as_of=101, continuous=True)
        difference_snapshots(a, None, as_of=102, continuous=True)
        self.assertEqual(first, difference_snapshots(a, b, as_of=101, continuous=True))
        self.assertEqual(before, (asdict(a), asdict(b)))
        with self.assertRaises(FrozenInstanceError):
            first.ListenDrops.count = 7
        with self.assertRaises(FrozenInstanceError):
            first.ListenDrops = first.ListenOverflows
