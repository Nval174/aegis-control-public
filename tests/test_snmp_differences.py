"""Exact count oracles, real comparison delegation and explicit caller discipline."""
from dataclasses import FrozenInstanceError, asdict, replace
from pathlib import Path
import unittest
from unittest.mock import patch

from aegis_control import snmp_differences as api
from aegis_control.kernel_comparison import ComparisonError
from aegis_control.kernel_differences import CountDifference
from aegis_control.snmp_comparison import SnmpSample, compare_snmp_snapshots
from aegis_control.snmp_snapshot import SnmpReading, TcpSnmpSnapshot, parse_snmp

NAMES = ("InSegs", "OutSegs", "RetransSegs")


def sample(values=(10, 20, 2), at=100, bits=64, **metadata):
    snapshot = TcpSnmpSnapshot(bits, *(SnmpReading(v, "observed") for v in values))
    return SnmpSample(snapshot, at, **(dict(source="saved", namespace="lab-ns", generation="epoch-a") | metadata))


def reading(item, name, value):
    return replace(item, snapshot=replace(item.snapshot, **{name: value}))


class SnmpDifferenceTests(unittest.TestCase):
    def diff(self, a, b, **settings):
        result = api.difference_snmp_snapshots(a, b, **(dict(as_of=110) | settings))
        self.assertIsInstance(result, api.SnmpDifferences)
        self.assertEqual(set(asdict(result)), set(NAMES))
        for name in NAMES:
            self.assertIs(type(getattr(result, name)), CountDifference)
        return result

    def available(self, item, count):
        self.assertEqual(asdict(item), dict(state="AVAILABLE", reason="difference", count=count))
        self.assertIs(type(item.count), int)

    def unavailable(self, item, reason):
        self.assertEqual(asdict(item), dict(state="UNAVAILABLE", reason=reason, count=None))

    def counts(self, result, counts):
        for name, count in zip(NAMES, counts):
            self.available(getattr(result, name), count)

    def all_unavailable(self, result, reason):
        for name in NAMES:
            self.unavailable(getattr(result, name), reason)

    def reject(self, a, b, **settings):
        settings = dict(as_of=110) | settings
        with self.assertRaises(ComparisonError) as helper_error:
            api.difference_snmp_snapshots(a, b, **settings)
        with self.assertRaises(ComparisonError) as comparison_error:
            compare_snmp_snapshots(a, b, **settings)
        self.assertEqual(str(helper_error.exception), str(comparison_error.exception))
        self.assertLess(len(str(helper_error.exception)), 160)
        for marker in ("PRIVATE", "secret", "Traceback"):
            self.assertNotIn(marker, str(helper_error.exception))

    def test_saved_fixtures_exact_independent_counts(self):
        root = Path(__file__).with_name("fixtures")
        before = parse_snmp((root / "snmp.synthetic.difference-before.txt").read_bytes(), word_bits=64)
        after = parse_snmp((root / "snmp.synthetic.difference-after.txt").read_bytes(), word_bits=64)
        a = SnmpSample(before, 100, "synthetic", "lab-ns", "epoch-a")
        b = replace(a, snapshot=after, observed_at=110)
        self.counts(self.diff(a, b, continuous=True), (3, 5, 1))

    def test_equal_and_zero_are_available_zero_with_reused_type(self):
        self.assertIs(api.CountDifference, CountDifference)
        for values in ((0, 0, 0), (10, 20, 2)):
            self.counts(self.diff(sample(values), sample(values, at=110), continuous=True), (0, 0, 0))

    def test_unsigned_maximum_differences_and_above_float_precision(self):
        for bits, maximum in ((32, 4294967295), (64, 18446744073709551615)):
            self.counts(self.diff(sample((0, 0, 0), bits=bits), sample((maximum,) * 3, at=110, bits=bits),
                                  continuous=True), (maximum,) * 3)
        a = sample((9007199254740993, 18446744073709551612, 2))
        b = sample((9007199254740996, 18446744073709551615, 3), at=110)
        self.counts(self.diff(a, b, continuous=True), (3, 3, 1))

    def test_each_current_and_previous_missing_reading_keeps_siblings_independent(self):
        a, b = sample(), sample((13, 25, 3), at=110)
        for name in NAMES:
            for previous, current, reason in (
                (a, reading(b, name, SnmpReading(None, "field_missing")), "current_field_missing"),
                (reading(a, name, SnmpReading(None, "field_missing")), b, "previous_field_missing"),
            ):
                result = self.diff(previous, current, continuous=True)
                for n, count in zip(NAMES, (3, 5, 1)):
                    if n == name:
                        self.unavailable(getattr(result, n), reason)
                    else:
                        self.available(getattr(result, n), count)
        absent = replace(b, snapshot=TcpSnmpSnapshot(64, *(SnmpReading(None, "section_missing") for _ in NAMES)))
        self.all_unavailable(self.diff(a, absent, continuous=True), "current_section_missing")
        self.all_unavailable(self.diff(replace(absent, observed_at=100), b, continuous=True), "previous_section_missing")

    def test_decreases_never_wrap_or_block_eligible_siblings(self):
        for values, expected in (((9, 25, 3), (None, 5, 1)), ((13, 19, 3), (3, None, 1)),
                                 ((13, 25, 1), (3, 5, None)), ((9, 19, 3), (None, None, 1)),
                                 ((9, 19, 1), (None, None, None))):
            result = self.diff(sample(), sample(values, at=110), continuous=True)
            for name, count in zip(NAMES, expected):
                if count is None:
                    self.unavailable(getattr(result, name), "counter_decreased")
                else:
                    self.available(getattr(result, name), count)

    def test_metadata_and_default_attestation_keep_unavailable_reasons(self):
        a, b = sample(), sample((13, 25, 3), at=110)
        for field, value, reason in (("source", "other", "source_changed"),
                                     ("namespace", "other", "namespace_changed"),
                                     ("generation", None, "generation_unknown"),
                                     ("generation", "epoch-b", "generation_changed")):
            self.all_unavailable(self.diff(a, replace(b, **{field: value}), continuous=True), reason)
        self.all_unavailable(self.diff(a, sample((13, 25, 3), at=110, bits=32), continuous=True), "width_changed")
        self.all_unavailable(self.diff(replace(a, generation=None), b, continuous=True), "generation_unknown")
        self.all_unavailable(self.diff(a, b), "continuity_unconfirmed")

    def test_time_conditions_and_shared_freshness_boundary(self):
        for a, b, as_of, reason in (
            (sample(), sample(at=120), 110, "current_future"),
            (sample(at=120), sample(at=110), 110, "previous_future"),
            (sample(at=0), sample(at=1), 110, "current_stale"),
            (sample(), sample(at=110), 170, "previous_stale"),
            (sample(), sample((13, 25, 3)), 110, "duplicate_time"),
            (sample(), sample((13, 25, 3), at=99), 110, "out_of_order"),
        ):
            self.all_unavailable(self.diff(a, b, as_of=as_of, continuous=True), reason)
        a, b = sample(at=100), sample((13, 25, 3), at=160)
        self.counts(self.diff(a, b, as_of=160, continuous=True), (3, 5, 1))
        self.all_unavailable(self.diff(a, b, as_of=161, continuous=True), "previous_stale")
        self.counts(self.diff(a, b, as_of=161, max_age=61, continuous=True), (3, 5, 1))

    def test_prior_success_is_not_authorization_for_new_settings_or_metadata(self):
        a, b = sample(), sample((13, 25, 3), at=110)
        earlier = compare_snmp_snapshots(a, b, as_of=110, continuous=True)
        self.assertTrue(earlier.InSegs.eligible)
        self.counts(self.diff(a, b, continuous=True), (3, 5, 1))
        self.all_unavailable(self.diff(a, b, as_of=170, continuous=True), "previous_stale")
        self.all_unavailable(self.diff(a, b, max_age=9, continuous=True), "previous_stale")
        self.all_unavailable(self.diff(a, b), "continuity_unconfirmed")
        self.all_unavailable(self.diff(a, replace(b, generation="epoch-b"), continuous=True), "generation_changed")
        self.reject(earlier, b, continuous=True)

    def test_every_call_forwards_original_objects_and_settings_with_real_validation(self):
        a, b = sample(), sample((13, 25, 3), at=110)
        with patch.object(api, "compare_snmp_snapshots", wraps=compare_snmp_snapshots) as dependency:
            self.counts(self.diff(a, b, max_age=10, continuous=True), (3, 5, 1))
            self.all_unavailable(self.diff(a, b, as_of=170, max_age=60, continuous=True), "previous_stale")
            self.all_unavailable(self.diff(a, b), "continuity_unconfirmed")
        self.assertEqual(dependency.call_count, 3)
        for call, settings in zip(dependency.call_args_list, (
                dict(as_of=110, max_age=10, continuous=True),
                dict(as_of=170, max_age=60, continuous=True),
                dict(as_of=110, max_age=60, continuous=False))):
            self.assertIs(call.args[0], a)
            self.assertIs(call.args[1], b)
            self.assertEqual(call.kwargs, settings)

    def test_malformed_third_reading_is_atomic_and_diagnostics_propagate(self):
        a, b = sample(), sample((13, 25, 3), at=110)
        for value in (None, SnmpReading(True, "observed"), SnmpReading(1.0, "observed"),
                      SnmpReading(-1, "observed"), SnmpReading(2**64, "observed"),
                      SnmpReading(None, "observed"), SnmpReading(0, "field_missing"),
                      SnmpReading(None, "section_missing"), SnmpReading(None, "PRIVATE/path")):
            bad = reading(b, "RetransSegs", value)
            self.reject(a, bad, continuous=True)
            self.reject(None, bad, continuous=True)
            self.reject(bad, None, continuous=True)
            self.reject(reading(a, "InSegs", SnmpReading(None, "field_missing")), bad, continuous=True)

    def test_invalid_integer_subclass_rejects_before_any_subtraction(self):
        class InvalidInteger(int):
            def __sub__(self, other):
                raise AssertionError("arithmetic before validation")

            def __rsub__(self, other):
                raise AssertionError("arithmetic before validation")

        a, b = sample(), sample((13, 25, 3), at=110)
        self.reject(a, reading(b, "InSegs", SnmpReading(InvalidInteger(13), "observed")), continuous=True)
        self.reject(reading(a, "InSegs", SnmpReading(InvalidInteger(10), "observed")), b, continuous=True)

    def test_malformed_samples_settings_and_boolean_integers_reject_with_unavailable_opposite(self):
        a, b = sample(), sample((13, 25, 3), at=110)
        bad = [object(), replace(b, snapshot=None), replace(b, observed_at=True),
               replace(b, source="PRIVATE/path"), replace(b, namespace=[]), replace(b, generation=1),
               replace(b, snapshot=replace(b.snapshot, word_bits=True)), sample((2**32, 0, 0), bits=32)]
        for item in bad:
            self.reject(a, item)
            self.reject(item, None)
            self.reject(None, item)
        for settings in (dict(as_of=True), dict(as_of=-1), dict(as_of=2**63), dict(as_of=110.0),
                         dict(max_age=True), dict(max_age=0), dict(max_age=86401), dict(continuous=1)):
            self.reject(a, b, **settings)
            self.reject(None, None, **settings)

    def test_missing_before_shared_policy_and_whole_input_validation(self):
        a = sample()
        b = reading(sample((13, 25, 3), at=200, generation="epoch-b"), "OutSegs", SnmpReading(None, "field_missing"))
        result = self.diff(a, b, continuous=True)
        self.unavailable(result.OutSegs, "current_field_missing")
        self.unavailable(result.InSegs, "current_future")
        self.unavailable(result.RetransSegs, "current_future")
        self.reject(a, reading(b, "RetransSegs", SnmpReading(True, "observed")), continuous=True)
        self.all_unavailable(self.diff(None, None), "current_unavailable")

    def test_explicit_caller_recovery_after_missing_or_malformed_counts_only_new_interval(self):
        a, b, c = sample(), sample((13, 25, 3), at=120), sample((15, 28, 7), at=130)
        for malformed in (False, True):
            baseline = a
            if malformed:
                try:
                    api.difference_snmp_snapshots(baseline, reading(b, "RetransSegs", SnmpReading(True, "observed")),
                                                  as_of=120, continuous=True)
                except ComparisonError:
                    baseline = None
                else:
                    self.fail("malformed input must return no result")
            else:
                self.all_unavailable(self.diff(baseline, None, continuous=True), "current_unavailable")
                self.assertIs(baseline, a)
                baseline = None
            self.all_unavailable(self.diff(baseline, b, as_of=120, continuous=True), "previous_unavailable")
            baseline = b
            self.counts(self.diff(baseline, c, as_of=130, continuous=True), (2, 3, 4))
        # Skipping X while falsely attesting A/C is undetectable; API does not clear old data.
        self.all_unavailable(self.diff(a, c, as_of=130), "continuity_unconfirmed")
        self.counts(self.diff(a, c, as_of=130, continuous=True), (5, 8, 5))

    def test_caller_recovery_after_decrease_and_generation_reappearance(self):
        a, b, c = sample(), sample((13, 25, 3), at=120), sample((15, 28, 7), at=130)
        for bad, reason in ((sample((9, 19, 1), at=110), "counter_decreased"),
                            (sample(at=110, generation="epoch-b"), "generation_changed")):
            baseline = a
            self.all_unavailable(self.diff(baseline, bad, continuous=True), reason)
            if reason == "generation_changed":
                self.all_unavailable(self.diff(bad, b, as_of=120, continuous=True), "generation_changed")
            baseline = None
            self.all_unavailable(self.diff(baseline, b, as_of=120, continuous=True), "previous_unavailable")
            baseline = b
            self.counts(self.diff(baseline, c, as_of=130, continuous=True), (2, 3, 4))

    def test_frozen_results_repeatability_and_input_nonmutation(self):
        a, b = sample(), sample((13, 25, 3), at=110)
        before = asdict(a), asdict(b)
        result = self.diff(a, b, continuous=True)
        self.all_unavailable(self.diff(a, None), "current_unavailable")
        self.assertEqual(result, self.diff(a, b, continuous=True))
        self.assertEqual((asdict(a), asdict(b)), before)
        for obj, attr in ((result, "InSegs"), (result.InSegs, "count"), (result.InSegs, "state")):
            with self.assertRaises(FrozenInstanceError):
                setattr(obj, attr, None)
