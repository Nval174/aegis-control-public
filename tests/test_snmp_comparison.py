"""Literal SNMP eligibility/recovery oracles; continuity is only caller testimony."""
from dataclasses import FrozenInstanceError, asdict, replace
from pathlib import Path
import unittest

from aegis_control import snmp_comparison as api
from aegis_control.kernel_comparison import ComparisonError, Eligibility
from aegis_control.snmp_snapshot import SnmpReading, TcpSnmpSnapshot, parse_snmp

NAMES = ("InSegs", "OutSegs", "RetransSegs")
MAX_TIME = 2**63 - 1


def sample(values=(0, 0, 0), at=100, bits=64, **metadata):
    snapshot = TcpSnmpSnapshot(bits, *(SnmpReading(v, "observed") for v in values))
    return api.SnmpSample(snapshot, at, **(dict(source="saved", namespace="lab-ns", generation="epoch-a") | metadata))


def reading(item, name, value):
    return replace(item, snapshot=replace(item.snapshot, **{name: value}))


class SnmpComparisonTests(unittest.TestCase):
    def compare(self, previous, current, **settings):
        result = api.compare_snmp_snapshots(previous, current, **(dict(as_of=110) | settings))
        self.assertIsInstance(result, api.SnmpComparisonResult)
        self.assertEqual(set(asdict(result)), set(NAMES))
        for name in NAMES:
            self.assertIs(type(getattr(result, name)), Eligibility)
        return result

    def all_reason(self, result, reason, eligible=False):
        self.assertEqual(asdict(result), {n: dict(eligible=eligible, reason=reason) for n in NAMES})

    def reject(self, previous, current, **settings):
        with self.assertRaises(ComparisonError) as caught:
            api.compare_snmp_snapshots(previous, current, **(dict(as_of=110) | settings))
        self.assertLess(len(str(caught.exception)), 160)
        self.assertNotIn("PRIVATE", str(caught.exception))
        self.assertNotIn("secret", str(caught.exception))

    def test_saved_zero_to_normal_and_literal_result_shape(self):
        root = Path(__file__).with_name("fixtures")
        a = api.SnmpSample(parse_snmp((root / "snmp.synthetic.zero.txt").read_bytes(), word_bits=64),
                           100, "synthetic", "lab-ns", "epoch-a")
        b = replace(a, snapshot=parse_snmp((root / "snmp.synthetic.normal.txt").read_bytes(), word_bits=64), observed_at=110)
        self.all_reason(self.compare(a, b, continuous=True), "prerequisites_declared", True)

    def test_zero_equal_increasing_and_exact_unsigned_endpoints(self):
        for bits, maximum in ((32, 4294967295), (64, 18446744073709551615)):
            for before, after in (((0, 0, 0), (0, 0, 0)), ((7, 8, 9), (7, 8, 9)),
                                  ((0, 0, 0), (maximum, maximum, maximum))):
                self.all_reason(self.compare(sample(before, bits=bits), sample(after, at=110, bits=bits),
                                             continuous=True), "prerequisites_declared", True)

    def test_default_false_explicit_false_and_public_type_identity(self):
        self.assertIs(api.ComparisonError, ComparisonError)
        self.assertIs(api.Eligibility, Eligibility)
        a, b = sample(), sample((1, 2, 3), at=110)
        self.all_reason(self.compare(a, b), "continuity_unconfirmed")
        self.all_reason(self.compare(a, b, continuous=False), "continuity_unconfirmed")
        for flag in (1, 0, None, "PRIVATE", [], {}):
            self.reject(a, b, continuous=flag)

    def test_independent_identity_and_generation_declarations(self):
        a, b = sample(), sample(at=110)
        for field, value, reason in (("source", "other", "source_changed"),
                                     ("namespace", "other", "namespace_changed"),
                                     ("generation", None, "generation_unknown"),
                                     ("generation", "epoch-b", "generation_changed")):
            self.all_reason(self.compare(a, replace(b, **{field: value}), continuous=True), reason)
        self.all_reason(self.compare(a, sample(at=110, bits=32), continuous=True), "width_changed")
        self.all_reason(self.compare(replace(a, generation=None), b, continuous=True), "generation_unknown")
        self.all_reason(self.compare(replace(a, generation=None), replace(b, generation=None), continuous=True), "generation_unknown")

    def test_literal_shared_priority_combinations(self):
        a, b = sample(), sample(at=110)
        cases = (
            (None, None, 110, True, "current_unavailable"),
            (None, sample(at=200), 110, False, "previous_unavailable"),
            (sample(at=120), sample(at=130), 110, True, "current_future"),
            (sample(at=120), b, 110, True, "previous_future"),
            (sample(at=120), sample(at=0), 110, True, "previous_future"),
            (sample(at=0), sample(at=1), 110, True, "current_stale"),
            (sample(at=40), b, 110, True, "previous_stale"),
            (sample(at=0), replace(b, source="other"), 110, True, "previous_stale"),
            (a, sample(at=110, bits=32, source="other", namespace="other", generation=None), 110, False, "source_changed"),
            (a, sample(at=110, bits=32, namespace="other", generation=None), 110, False, "namespace_changed"),
            (a, sample(at=110, bits=32, generation=None), 110, False, "width_changed"),
            (a, replace(a, generation=None), 110, False, "generation_unknown"),
            (a, replace(a, generation="epoch-b"), 110, False, "generation_changed"),
            (a, a, 110, False, "duplicate_time"),
            (b, a, 110, False, "out_of_order"),
            (sample((9, 9, 9)), sample((8, 8, 8), at=110), 110, False, "continuity_unconfirmed"),
        )
        for previous, current, as_of, continuous, reason in cases:
            with self.subTest(reason=reason):
                self.all_reason(self.compare(previous, current, as_of=as_of, continuous=continuous), reason)

    def test_shared_age_boundary_and_extreme_clocks(self):
        a, b = sample(at=100), sample(at=160)
        self.all_reason(self.compare(a, b, as_of=160, max_age=60, continuous=True), "prerequisites_declared", True)
        self.all_reason(self.compare(a, b, as_of=161, max_age=60, continuous=True), "previous_stale")
        self.all_reason(self.compare(a, b, as_of=161, max_age=61, continuous=True), "prerequisites_declared", True)
        for age in (1, 86400):
            self.all_reason(self.compare(sample(at=0), sample(at=1), as_of=age, max_age=age,
                                         continuous=True), "prerequisites_declared", True)
        self.all_reason(self.compare(sample(at=MAX_TIME - 1), sample(at=MAX_TIME), as_of=MAX_TIME,
                                     continuous=True), "prerequisites_declared", True)

    def test_duplicate_timestamp_ignores_value_equality(self):
        for values in ((0, 0, 0), (1, 2, 3)):
            self.all_reason(self.compare(sample(), sample(values), continuous=True), "duplicate_time")

    def test_each_missing_reading_and_section_are_independent(self):
        a, b = sample(), sample(at=110)
        for name in NAMES:
            for previous, current, prefix in (
                (a, reading(b, name, SnmpReading(None, "field_missing")), "current_"),
                (reading(a, name, SnmpReading(None, "field_missing")), b, "previous_"),
            ):
                result = self.compare(previous, current, continuous=True)
                for n in NAMES:
                    want = dict(eligible=False, reason=prefix + "field_missing") if n == name else dict(eligible=True, reason="prerequisites_declared")
                    self.assertEqual(asdict(getattr(result, n)), want)
        for reason in ("field_missing", "section_missing"):
            missing = replace(b, snapshot=TcpSnmpSnapshot(64, *(SnmpReading(None, reason) for _ in NAMES)))
            self.all_reason(self.compare(a, missing, continuous=True), "current_" + reason)
            self.all_reason(self.compare(replace(missing, observed_at=100), b, continuous=True), "previous_" + reason)

    def test_missing_before_shared_reasons_after_validation(self):
        a, b = sample(), sample(at=200, generation="epoch-b")
        missing = reading(b, "OutSegs", SnmpReading(None, "field_missing"))
        result = self.compare(a, missing, as_of=110, continuous=True)
        self.assertEqual((result.InSegs.reason, result.OutSegs.reason, result.RetransSegs.reason),
                         ("current_future", "current_field_missing", "current_future"))
        result = self.compare(reading(a, "OutSegs", SnmpReading(None, "field_missing")), b)
        self.assertEqual(result.OutSegs.reason, "previous_field_missing")
        result = self.compare(reading(a, "OutSegs", SnmpReading(None, "field_missing")), missing)
        self.assertEqual(result.OutSegs.reason, "current_field_missing")
        stale = reading(sample(at=0, generation="epoch-b"), "OutSegs", SnmpReading(None, "field_missing"))
        result = self.compare(a, stale, continuous=True)
        self.assertEqual((result.InSegs.reason, result.OutSegs.reason), ("current_stale", "current_field_missing"))

    def test_per_counter_decreases_do_not_authorize_siblings(self):
        a, b = sample((7, 8, 9)), sample((7, 8, 9), at=110)
        for name in NAMES:
            result = self.compare(a, reading(b, name, SnmpReading(getattr(a.snapshot, name).value - 1, "observed")), continuous=True)
            for n in NAMES:
                self.assertEqual(asdict(getattr(result, n)), dict(eligible=n != name,
                                 reason="counter_decreased" if n == name else "prerequisites_declared"))

    def test_rechecks_freshness_and_attestation_after_earlier_eligibility(self):
        a, b = sample(), sample(at=110)
        self.all_reason(self.compare(a, b, continuous=True), "prerequisites_declared", True)
        self.all_reason(self.compare(a, b, as_of=170, continuous=True), "previous_stale")
        self.all_reason(self.compare(a, b), "continuity_unconfirmed")

    def test_malformed_settings_and_domain_times(self):
        a, b = sample(), sample(at=110)
        for settings in (dict(as_of=True), dict(as_of=-1), dict(as_of=MAX_TIME + 1), dict(as_of=110.0),
                         dict(max_age=True), dict(max_age=0), dict(max_age=86401), dict(max_age=60.0)):
            self.reject(a, b, **settings)
            self.reject(None, None, **settings)
        self.reject(None, None, continuous=1)
        for at in (None, True, -1, MAX_TIME + 1, 100.0, "PRIVATE", []):
            self.reject(replace(a, observed_at=at), b)
            self.reject(None, replace(b, observed_at=at))

    def test_direct_wrapper_snapshot_width_and_labels_validate_with_none_opposite(self):
        a = sample()
        for bad in (object(), {}, a.snapshot, replace(a, snapshot=None), replace(a, snapshot={})):
            self.reject(bad, None)
            self.reject(None, bad)
        for bits in (True, 32.0, "64", 16, None, []):
            self.reject(replace(a, snapshot=replace(a.snapshot, word_bits=bits)), None)
        for field in ("source", "namespace", "generation"):
            for value in ("", "x" * 65, "PRIVATE/path", "secret space", "é", [], {}, 1):
                self.reject(replace(a, **{field: value}), None)
            if field != "generation":
                self.reject(replace(a, **{field: None}), None)
            good = replace(a, **{field: "x" * 64})
            self.all_reason(self.compare(good, replace(good, observed_at=110), continuous=True), "prerequisites_declared", True)

    def test_direct_reading_invariants_and_exact_types(self):
        a, b = sample(), sample(at=110)
        bad = (None, {}, SnmpReading(True, "observed"), SnmpReading(-1, "observed"),
               SnmpReading(2**64, "observed"), SnmpReading(0.0, "observed"), SnmpReading(None, "observed"),
               SnmpReading(0, "field_missing"), SnmpReading(0, "section_missing"),
               SnmpReading(None, "PRIVATE"), SnmpReading(None, []), SnmpReading(None, "section_missing"))
        for name in NAMES:
            for value in bad:
                self.reject(None, reading(b, name, value))
                self.reject(reading(a, name, value), None)
            all_missing = replace(b, snapshot=TcpSnmpSnapshot(64, *(SnmpReading(None, "section_missing") for _ in NAMES)))
            self.reject(None, reading(all_missing, name, SnmpReading(0, "section_missing")))
        self.reject(None, sample((4294967296, 0, 0), bits=32))

    def test_missing_sibling_cannot_hide_malformed_reading(self):
        a = sample()
        for missing in NAMES:
            for malformed in NAMES:
                if malformed == missing:
                    continue
                bad = reading(reading(a, missing, SnmpReading(None, "field_missing")),
                              malformed, SnmpReading(True, "observed"))
                self.reject(a, bad)
                self.reject(bad, None)

    def test_exact_dataclass_and_integer_subclasses_reject(self):
        class SampleSubclass(api.SnmpSample):
            pass

        class SnapshotSubclass(TcpSnmpSnapshot):
            pass

        class ReadingSubclass(SnmpReading):
            pass

        class IntSubclass(int):
            pass

        a = sample()
        self.reject(SampleSubclass(a.snapshot, 100, "saved", "lab-ns", "epoch-a"), None)
        self.reject(replace(a, snapshot=SnapshotSubclass(64, a.snapshot.InSegs, a.snapshot.OutSegs, a.snapshot.RetransSegs)), None)
        self.reject(reading(a, "InSegs", ReadingSubclass(0, "observed")), None)
        self.reject(reading(a, "InSegs", SnmpReading(IntSubclass(0), "observed")), None)
        self.reject(replace(a, observed_at=IntSubclass(100)), None)
        self.reject(a, None, as_of=IntSubclass(110))

    def test_explicit_caller_recovery_after_missing_and_malformed(self):
        a, b, c = sample(), sample((1, 2, 3), at=120), sample((2, 3, 4), at=130)
        baseline = a
        self.all_reason(self.compare(baseline, None, continuous=True), "current_unavailable")
        self.assertIs(baseline, a)  # The API did not clear the caller's variable.
        baseline = None
        self.all_reason(self.compare(baseline, b, as_of=120, continuous=True), "previous_unavailable")
        baseline = b
        self.all_reason(self.compare(baseline, c, as_of=130, continuous=True), "prerequisites_declared", True)
        baseline = a
        try:
            api.compare_snmp_snapshots(baseline, reading(b, "InSegs", SnmpReading(True, "observed")),
                                       as_of=120, continuous=True)
        except ComparisonError:
            baseline = None
        else:
            self.fail("malformed sample must reject")
        self.all_reason(self.compare(baseline, b, as_of=120, continuous=True), "previous_unavailable")
        baseline = b
        self.all_reason(self.compare(baseline, c, as_of=130, continuous=True), "prerequisites_declared", True)
        # Omitted X plus a false attestation is undetectable by this pair API.
        self.all_reason(self.compare(a, b, as_of=120), "continuity_unconfirmed")
        self.all_reason(self.compare(a, b, as_of=120, continuous=True), "prerequisites_declared", True)

    def test_recovery_after_decrease_and_generation_reappearance(self):
        a, b, c = sample((10, 10, 10)), sample((20, 20, 20), at=120), sample((21, 21, 21), at=130)
        for bad, reason in ((sample((9, 9, 9), at=110), "counter_decreased"),
                            (sample(at=110, generation="epoch-b"), "generation_changed")):
            baseline = a
            self.all_reason(self.compare(baseline, bad, continuous=True), reason)
            if reason == "generation_changed":
                self.all_reason(self.compare(bad, b, as_of=120, continuous=True), "generation_changed")
            baseline = None
            self.all_reason(self.compare(baseline, b, as_of=120, continuous=True), "previous_unavailable")
            baseline = b
            self.all_reason(self.compare(baseline, c, as_of=130, continuous=True), "prerequisites_declared", True)

    def test_frozen_repeatable_results_and_input_nonmutation(self):
        a, b = sample(), sample(at=110)
        before = asdict(a), asdict(b)
        result = self.compare(a, b, continuous=True)
        self.assertEqual(result, self.compare(a, b, continuous=True))
        self.assertEqual((asdict(a), asdict(b)), before)
        for obj, attr in ((a, "source"), (result, "InSegs"), (result.InSegs, "eligible"), (result.InSegs, "reason")):
            with self.assertRaises(FrozenInstanceError):
                setattr(obj, attr, None)
