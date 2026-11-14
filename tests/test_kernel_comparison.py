"""Synthetic eligibility controls; no physical continuity claims or arithmetic."""
from dataclasses import FrozenInstanceError, asdict, replace
from pathlib import Path
import unittest

from aegis_control.kernel_comparison import (
    ComparisonError, SnapshotSample, compare_snapshots,
)
from aegis_control.netstat_snapshot import (
    Capture, CounterValue, NetstatSnapshot, parse_netstat,
)

MAX_TIME = 2**63 - 1
FIXTURES = Path(__file__).with_name("fixtures")


def sample(drops=0, overflows=17, at=100, capture=None):
    capture = capture or Capture("saved", "lab-ns", "epoch-a", 64)
    raw = f"TcpExt: ListenDrops ListenOverflows\nTcpExt: {drops} {overflows}\n".encode()
    return SnapshotSample(parse_netstat(raw, capture), at)


class KernelComparisonTests(unittest.TestCase):
    def assert_both(self, result, reason):
        for counter in (result.ListenDrops, result.ListenOverflows):
            self.assertFalse(counter.eligible)
            self.assertEqual(counter.reason, reason)

    def test_positive_equal_increase_and_real_zero(self):
        a = sample()
        for b in (sample(at=101), sample(4, 18, at=101)):
            result = compare_snapshots(a, b, as_of=101, continuous=True)
            self.assertEqual(asdict(result), {
                "ListenDrops": {"eligible": True, "reason": "prerequisites_declared"},
                "ListenOverflows": {"eligible": True, "reason": "prerequisites_declared"},
            })

    def test_attestation_defaults_false_even_for_matching_increases(self):
        self.assert_both(compare_snapshots(sample(), sample(1, 18, 101), as_of=101),
                         "continuity_unconfirmed")

    def test_each_identity_dimension_and_unknown_generation(self):
        a = sample()
        for field, value, reason in (
            ("source", "other", "source_changed"),
            ("namespace", "other", "namespace_changed"),
            ("word_bits", 32, "width_changed"),
            ("generation", "epoch-b", "generation_changed"),
            ("generation", None, "generation_unknown"),
        ):
            with self.subTest(field=field):
                b = sample(at=101, capture=replace(a.snapshot.capture, **{field: value}))
                self.assert_both(compare_snapshots(a, b, as_of=101, continuous=True), reason)
        unknown = replace(a.snapshot.capture, generation=None)
        for previous, current in (
            (sample(capture=unknown), sample(at=101)),
            (sample(capture=unknown), sample(at=101, capture=unknown)),
        ):
            self.assert_both(compare_snapshots(previous, current, as_of=101, continuous=True),
                             "generation_unknown")

    def test_saved_missing_counter_does_not_certify_its_sibling(self):
        capture = Capture("saved", "lab-ns", "epoch-a", 64)
        a = sample(6, 17)
        b = SnapshotSample(parse_netstat((FIXTURES / "netstat-missing.txt").read_bytes(), capture), 101)
        r = compare_snapshots(a, b, as_of=101, continuous=True)
        self.assertTrue(r.ListenDrops.eligible)
        self.assertEqual(r.ListenOverflows.reason, "current_field_missing")
        self.assertFalse(r.ListenOverflows.eligible)
        # Reverse which supported field is missing, independently of value zero.
        c = SnapshotSample(parse_netstat(b"TcpExt: ListenOverflows\nTcpExt: 17", capture), 101)
        r = compare_snapshots(a, c, as_of=101, continuous=True)
        self.assertEqual(r.ListenDrops.reason, "current_field_missing")
        self.assertFalse(r.ListenDrops.eligible)
        self.assertTrue(r.ListenOverflows.eligible)
        r = compare_snapshots(b, sample(8, 18, 102), as_of=102, continuous=True)
        self.assertTrue(r.ListenDrops.eligible)
        self.assertEqual(r.ListenOverflows.reason, "previous_field_missing")
        absent = SnapshotSample(parse_netstat((FIXTURES / "netstat-absent.txt").read_bytes(), capture), 101)
        self.assert_both(compare_snapshots(a, absent, as_of=101, continuous=True), "current_section_missing")
        self.assert_both(compare_snapshots(absent, sample(at=102), as_of=102, continuous=True),
                         "previous_section_missing")

    def test_decrease_is_per_counter_with_no_diagnosis_or_numeric_result(self):
        result = compare_snapshots(sample(8, 17), sample(7, 18, 101), as_of=101, continuous=True)
        self.assertEqual(asdict(result), {
            "ListenDrops": {"eligible": False, "reason": "counter_decreased"},
            "ListenOverflows": {"eligible": True, "reason": "prerequisites_declared"},
        })

    def test_time_order_and_future_are_explicit(self):
        for a, b, reason in (
            (sample(), sample(at=100), "duplicate_time"),
            (sample(), sample(2, 18, 100), "duplicate_time"),
            (sample(), sample(at=99), "out_of_order"),
            (sample(), sample(at=102), "current_future"),
            (sample(at=102), sample(at=101), "previous_future"),
        ):
            self.assert_both(compare_snapshots(a, b, as_of=101, continuous=True), reason)

    def test_freshness_equality_and_just_beyond(self):
        self.assertTrue(compare_snapshots(sample(), sample(at=101), as_of=160,
                                         max_age=60, continuous=True).ListenDrops.eligible)
        self.assert_both(compare_snapshots(sample(), sample(at=101), as_of=161,
                                           max_age=60, continuous=True), "previous_stale")
        self.assert_both(compare_snapshots(sample(), sample(at=101), as_of=162,
                                           max_age=60, continuous=True), "current_stale")
        for age in (1, 86400):
            self.assertTrue(compare_snapshots(sample(at=0), sample(at=1), as_of=age,
                                             max_age=age, continuous=True).ListenDrops.eligible)
        self.assertTrue(compare_snapshots(sample(at=MAX_TIME - 1), sample(at=MAX_TIME),
                                         as_of=MAX_TIME, continuous=True).ListenDrops.eligible)

    def test_unavailable_interval_and_recovery_do_not_bridge(self):
        a, b, c = sample(), sample(1, 18, 102), sample(2, 19, 103)
        self.assert_both(compare_snapshots(a, None, as_of=101, continuous=True), "current_unavailable")
        self.assert_both(compare_snapshots(None, b, as_of=102, continuous=True), "previous_unavailable")
        self.assert_both(compare_snapshots(None, None, as_of=102), "current_unavailable")
        self.assert_both(compare_snapshots(a, b, as_of=102), "continuity_unconfirmed")
        self.assertTrue(compare_snapshots(b, c, as_of=103, continuous=True).ListenDrops.eligible)
        # A pair API cannot detect a caller who omits an invalid event AND lies.
        self.assertTrue(compare_snapshots(a, b, as_of=102, continuous=True).ListenDrops.eligible)

    def test_generation_reappearance_has_no_retrieved_baseline(self):
        a, b = sample(), sample(at=101, capture=Capture("saved", "lab-ns", "epoch-b", 64))
        c = sample(at=102)
        for previous, current in ((a, b), (b, c)):
            self.assert_both(compare_snapshots(previous, current, as_of=102, continuous=True),
                             "generation_changed")
        self.assert_both(compare_snapshots(a, c, as_of=102), "continuity_unconfirmed")

    def test_caller_clears_malformed_endpoint_before_recovery(self):
        baseline = sample()
        bad = SnapshotSample(replace(baseline.snapshot, ListenDrops=CounterValue(True, "observed")), 101)
        try:
            compare_snapshots(baseline, bad, as_of=101, continuous=True)
        except ComparisonError:
            baseline = None  # Explicit caller action, not hidden library state.
        else:
            self.fail("malformed endpoint must raise before a result")
        good = sample(2, 19, 102)
        self.assert_both(compare_snapshots(baseline, good, as_of=102, continuous=True),
                         "previous_unavailable")
        baseline = good
        self.assertTrue(compare_snapshots(baseline, sample(3, 20, 103), as_of=103,
                                         continuous=True).ListenDrops.eligible)

    def test_malformed_settings_and_times_reject_boolean_integers(self):
        a, b = sample(), sample(at=101)
        for settings in (
            {"as_of": True}, {"as_of": -1}, {"as_of": MAX_TIME + 1}, {"as_of": 101.0},
            {"as_of": 101, "max_age": True}, {"as_of": 101, "max_age": 0},
            {"as_of": 101, "max_age": 86401}, {"as_of": 101, "continuous": 1},
        ):
            with self.subTest(settings=settings), self.assertRaises(ComparisonError):
                compare_snapshots(a, b, **settings)
        for at in (None, True, -1, MAX_TIME + 1, 100.0):
            with self.assertRaises(ComparisonError):
                compare_snapshots(replace(a, observed_at=at), b, as_of=101)

    def test_direct_values_and_metadata_cannot_bypass_validation(self):
        a, b = sample(), sample(at=101)
        bad_values = (
            CounterValue(True, "observed"), CounterValue(-1, "observed"),
            CounterValue(2**64, "observed"), CounterValue(0.0, "observed"),
            CounterValue(None, "observed"), CounterValue(0, "field_missing"),
            CounterValue(None, "UNKNOWN"), CounterValue(None, ["observed"]),
            CounterValue(None, "section_missing"), None,
        )
        for value in bad_values:
            with self.subTest(value=value), self.assertRaises(ComparisonError):
                compare_snapshots(a, replace(b, snapshot=replace(b.snapshot, ListenDrops=value)),
                                  as_of=101, continuous=True)
        for capture in (
            None, Capture("PRIVATE/path", "n", "g", 64), Capture(None, "n", None, 64),
            Capture("a", "n", "g", True), Capture("a", "n", "g", 16),
            Capture("a", "n", 1, 64), Capture("a" * 65, "n", "g", 64),
        ):
            with self.assertRaises(ComparisonError) as error:
                compare_snapshots(a, replace(b, snapshot=replace(b.snapshot, capture=capture)), as_of=101)
            self.assertNotIn("PRIVATE", str(error.exception))
            self.assertLess(len(str(error.exception)), 100)
        for malformed in (object(), replace(b, snapshot=None)):
            with self.assertRaises(ComparisonError):
                compare_snapshots(malformed, None, as_of=101)
        # Entire input is validated even if another counter is missing.
        malformed = NetstatSnapshot(a.snapshot.capture, CounterValue(None, "field_missing"),
                                   CounterValue(True, "observed"))
        with self.assertRaises(ComparisonError):
            compare_snapshots(a, SnapshotSample(malformed, 101), as_of=101)

    def test_declared_width_domains_are_not_the_proxy_value_ceiling(self):
        for bits in (32, 64):
            capture = Capture("saved", "lab-ns", "epoch-a", bits)
            upper = (1 << bits) - 1
            a = sample(upper - 1, upper, capture=capture)
            b = sample(upper, upper, 101, capture=capture)
            self.assertTrue(compare_snapshots(a, b, as_of=101, continuous=True).ListenDrops.eligible)
            bad = replace(b.snapshot, ListenDrops=CounterValue(upper + 1, "observed"))
            with self.assertRaises(ComparisonError):
                compare_snapshots(a, SnapshotSample(bad, 101), as_of=101)

    def test_results_are_repeatable_frozen_and_do_not_mutate_inputs(self):
        a, b = sample(), sample(1, 18, 101)
        before = asdict(a), asdict(b)
        first = compare_snapshots(a, b, as_of=101, continuous=True)
        self.assertEqual(first, compare_snapshots(a, b, as_of=101, continuous=True))
        self.assertEqual(before, (asdict(a), asdict(b)))
        with self.assertRaises(FrozenInstanceError):
            first.ListenDrops.eligible = False
        with self.assertRaises(FrozenInstanceError):
            first.ListenDrops = first.ListenOverflows


class NetstatPolicyCharacterizationTests(unittest.TestCase):
    """Literal policy controls first executed before the shared extraction."""

    def test_shared_priority_literal_table(self):
        a, b = sample(), sample(at=101)

        def metadata(item, **changes):
            return replace(item, snapshot=replace(item.snapshot, capture=replace(item.snapshot.capture, **changes)))

        cases = (
            (None, None, 161, True, "current_unavailable"),
            (None, b, 161, True, "previous_unavailable"),
            (sample(at=162), sample(at=163), 161, True, "current_future"),
            (sample(at=162), sample(at=160), 161, True, "previous_future"),
            (sample(at=120), sample(at=0), 110, True, "previous_future"),
            (sample(at=0), sample(at=1), 161, True, "current_stale"),
            (a, sample(at=160), 161, True, "previous_stale"),
            (sample(at=0), metadata(sample(at=110), source="other"), 110, True, "previous_stale"),
            (a, metadata(b, source="other", namespace="other", word_bits=32, generation=None), 101, False, "source_changed"),
            (a, metadata(b, namespace="other", word_bits=32, generation=None), 101, False, "namespace_changed"),
            (a, metadata(b, word_bits=32, generation=None), 101, False, "width_changed"),
            (a, metadata(a, generation=None), 101, False, "generation_unknown"),
            (a, metadata(a, generation="epoch-b"), 101, False, "generation_changed"),
            (a, a, 101, False, "duplicate_time"),
            (b, a, 101, False, "out_of_order"),
            (sample(8, 17), sample(7, 16, 101), 101, False, "continuity_unconfirmed"),
            (sample(8, 17), sample(7, 16, 101), 101, True, "counter_decreased"),
        )
        for previous, current, as_of, continuous, reason in cases:
            with self.subTest(reason=reason):
                result = compare_snapshots(previous, current, as_of=as_of, continuous=continuous)
                self.assertEqual(asdict(result), {
                    "ListenDrops": {"eligible": False, "reason": reason},
                    "ListenOverflows": {"eligible": False, "reason": reason},
                })

    def test_missing_priority_and_validation_before_unavailability(self):
        a = sample()
        b = sample(at=170, capture=Capture("saved", "lab-ns", "epoch-b", 64))
        missing = replace(b, snapshot=replace(b.snapshot, ListenDrops=CounterValue(None, "field_missing")))
        result = compare_snapshots(a, missing, as_of=160, continuous=True)
        self.assertEqual((result.ListenDrops.reason, result.ListenOverflows.reason),
                         ("current_field_missing", "current_future"))
        previous_missing = replace(a, snapshot=replace(a.snapshot, ListenDrops=CounterValue(None, "field_missing")))
        result = compare_snapshots(previous_missing, b, as_of=160)
        self.assertEqual((result.ListenDrops.reason, result.ListenOverflows.reason),
                         ("previous_field_missing", "current_future"))
        result = compare_snapshots(previous_missing, missing, as_of=160)
        self.assertEqual(result.ListenDrops.reason, "current_field_missing")
        with self.assertRaisesRegex(ComparisonError, "observed counter exceeds declared unsigned domain"):
            bad = replace(a, snapshot=replace(a.snapshot, ListenOverflows=CounterValue(True, "observed")))
            compare_snapshots(bad, None, as_of=160)

    def test_literal_errors_and_public_type_origins(self):
        from aegis_control import kernel_comparison as api
        from aegis_control import kernel_differences as differences

        self.assertEqual(api.Eligibility.__module__, "aegis_control.kernel_comparison")
        self.assertEqual(ComparisonError.__module__, "aegis_control.kernel_comparison")
        self.assertIs(differences.compare_snapshots, api.compare_snapshots)
        for previous, settings, message in (
            (None, dict(as_of=True), "evaluation requires Unix seconds and max_age in 1-86400"),
            (None, dict(as_of=160, continuous=1), "continuous requires an explicit Boolean assertion"),
            (object(), dict(as_of=160), "comparison endpoint requires SnapshotSample or None"),
            (replace(sample(), observed_at=True), dict(as_of=160), "observation time requires bounded integer Unix seconds"),
        ):
            with self.subTest(message=message), self.assertRaises(ComparisonError) as caught:
                compare_snapshots(previous, None, **settings)
            self.assertEqual(str(caught.exception), message)
