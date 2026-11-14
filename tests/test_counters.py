"""Synthetic counter arithmetic; no continuity inferred from endpoint labels."""

from dataclasses import FrozenInstanceError, replace
import json
from pathlib import Path
import unittest

from aegis_control.config import validate_config
from aegis_control.coverage import assess_coverage
from aegis_control.telemetry import MAX_TIME, MAX_VALUE, parse_observation
from test_coverage_config import declared, requirement
from test_telemetry import sample


class CounterTests(unittest.TestCase):
    def setUp(self):
        from aegis_control import counters
        self.api = counters

    def point(self, value=10, observed_at=100, collected_at=None,
              counter_id="counter-1", generation="epoch-1", **changes):
        data = sample(value=value, observed_at=observed_at,
                      collected_at=observed_at if collected_at is None else collected_at,
                      route="/login") | changes
        obs = parse_observation(data, {"fixture-web", "other", "lab-web"},
                                ("/", "/login"), as_of=160, max_age=60)
        return self.api.CounterSample(obs, counter_id, generation)

    def advance(self, previous, current, **changes):
        return self.api.advance_counter(previous, current,
                                        **(dict(as_of=160, max_age=60, continuous=True) | changes))

    def unavailable(self, result, reason):
        self.assertEqual((result.state, result.reason), ("UNAVAILABLE", reason))
        self.assertIsNone(result.count)
        self.assertIsNone(result.elapsed_seconds)
        self.assertIsNone(result.next_baseline)

    def test_first_sample_establishes_baseline_without_invented_zero(self):
        current = self.point()
        result = self.advance(None, current, continuous=False)
        self.assertEqual((result.state, result.reason), ("BASELINE", "no_prior_baseline"))
        self.assertIsNone(result.count)
        self.assertIsNone(result.elapsed_seconds)
        self.assertEqual(result.next_baseline, current)
        self.unavailable(self.advance(None, None), "current_missing")

    def test_increase_and_genuine_zero_use_observation_interval_seconds(self):
        previous = self.point(10, 100, 125)
        for value, count in ((17, 7), (10, 0)):
            current = self.point(value, 110, 140)
            result = self.advance(previous, current)
            self.assertEqual((result.state, result.reason, result.count, result.elapsed_seconds),
                             ("AVAILABLE", "difference", count, 10))
            self.assertEqual(result.next_baseline, current)

    def test_continuity_must_be_explicit_not_inferred_from_matching_tokens(self):
        a, b = self.point(), self.point(20, 110)
        self.unavailable(self.api.advance_counter(a, b, as_of=160), "continuity_unconfirmed")
        self.unavailable(self.advance(a, b, continuous=False), "continuity_unconfirmed")
        for value in (None, 0, 1, "true", []):
            with self.subTest(value=value), self.assertRaises(self.api.CounterError):
                self.advance(a, b, continuous=value)

    def test_decrease_is_unavailable_without_diagnosing_reset_or_wrap(self):
        result = self.advance(self.point(10), self.point(3, 110))
        self.unavailable(result, "counter_decreased")
        self.assertNotIn("reset", result.reason)
        self.assertNotIn("wrap", result.reason)

    def test_declared_generation_or_producer_changes_with_lower_equal_higher_values(self):
        for field, reason in (("generation", "generation_changed"), ("counter_id", "counter_changed")):
            for value in (3, 10, 20):
                with self.subTest(field=field, value=value):
                    current = self.point(value, 110, **{field: "different-1"})
                    self.unavailable(self.advance(self.point(), current), reason)

    def test_duplicate_conflicting_and_out_of_order_observation_times(self):
        previous = self.point(10, 110, 120)
        for value, time, reason in ((10, 110, "duplicate_time"), (11, 110, "conflicting_time"),
                                    (12, 100, "out_of_order")):
            self.unavailable(self.advance(previous, self.point(value, time, 150)), reason)

    def test_valid_observation_order_can_have_reversed_collection_order(self):
        result = self.advance(self.point(10, 100, 150), self.point(17, 110, 120))
        self.assertEqual((result.state, result.count, result.elapsed_seconds), ("AVAILABLE", 7, 10))

    def test_unknown_stale_not_applicable_at_either_endpoint(self):
        good = self.point(20, 110)
        bad = ((self.point(value=None, observed_at=None, collected_at=120, state="UNKNOWN"), "unknown"),
               (self.point(10, 99), "stale"),
               (self.point(value=None, observed_at=None, collected_at=120,
                           source="cloudfront_waf", state="NOT_APPLICABLE"), "not_applicable"))
        for item, reason in bad:
            with self.subTest(reason=reason):
                self.unavailable(self.advance(good, item), "current_" + reason)
                self.unavailable(self.advance(item, good), "previous_" + reason)

    def test_wrong_labels_gauge_and_optional_source_cannot_substitute(self):
        previous = self.point()
        for change, reason in ((dict(service_id="other"), "identity_changed"),
                               (dict(route="/"), "identity_changed"),
                               (dict(metric="latency_ms"), "current_not_counter"),
                               (dict(source="flask_to_ad", state="NOT_APPLICABLE", value=None,
                                     observed_at=None, collected_at=120), "current_not_applicable")):
            self.unavailable(self.advance(previous, self.point(**change)), reason)
        self.unavailable(self.advance(self.point(metric="latency_ms"), self.point(20, 110)), "previous_not_counter")

    def test_other_rejects_different_raw_paths_with_identical_metadata(self):
        a = self.point(route="/unknown-A?secret=never-retain")
        b = self.point(17, 110, route="/unknown-B?secret=never-retain")
        self.assertEqual((a.observation.route, b.observation.route), ("OTHER", "OTHER"))
        self.unavailable(self.advance(a, b), "current_ambiguous_route")
        self.unavailable(self.advance(a, self.point(20, 110)), "previous_ambiguous_route")
        self.assertNotIn("unknown-A", repr(a))
        self.assertNotIn("secret", repr(b))

    def test_freshness_is_rechecked_and_stale_value_never_resurrects(self):
        a, b = self.point(), self.point(17, 110)
        self.assertEqual(self.advance(a, b).state, "AVAILABLE")
        self.unavailable(self.advance(a, b, as_of=161), "previous_stale")
        discarded = self.point(4, 99)
        self.assertIsNone(discarded.observation.value)
        self.unavailable(self.advance(discarded, b, as_of=159), "previous_stale")
        self.unavailable(self.advance(b, a, as_of=171), "current_stale")

    def test_boundary_values_times_and_metadata_are_exact(self):
        result = self.advance(self.point(0), self.point(MAX_VALUE, 101))
        self.assertEqual((result.count, result.elapsed_seconds), (MAX_VALUE, 1))
        obs = self.point().observation
        a = self.api.CounterSample(replace(obs, observed_at=MAX_TIME-1, collected_at=MAX_TIME), "x"*64, "y"*64)
        b = replace(a, observation=replace(a.observation, value=11, observed_at=MAX_TIME))
        result = self.advance(a, b, as_of=MAX_TIME)
        self.assertEqual((result.count, result.elapsed_seconds), (1, 1))
        for field in ("counter_id", "generation"):
            for value in ("", "x"*65, "private/path", "-a", True, 1, None, "\u00e9"):
                with self.subTest(field=field, value=value), self.assertRaises(self.api.CounterError) as caught:
                    self.advance(None, replace(self.point(), **{field: value}))
                self.assertNotIn("private", str(caught.exception))

    def test_direct_constructed_bad_endpoint_fields_and_clocks_are_rejected(self):
        a, b = self.point(), self.point(17, 110)
        invalid = (("value", True), ("value", 1.0), ("value", -1), ("value", MAX_VALUE+1),
                   ("value", float("nan")), ("value", None), ("observed_at", True),
                   ("observed_at", -1), ("observed_at", 120), ("collected_at", 109),
                   ("collected_at", True), ("collected_at", 110.0),
                   ("collected_at", 161), ("collected_at", MAX_TIME+1), ("state", "bad"),
                   ("state", "UNKNOWN"), ("state", "STALE"), ("source", "private-source"),
                   ("metric", "private-metric"), ("service_id", "private/path"),
                   ("route", "/private?secret"), ("route", "//host"), ("route", ["/"]))
        for field, value in invalid:
            bad = replace(b, observation=replace(b.observation, **{field: value}))
            for previous, current in ((a, bad), (bad, b)):
                with self.subTest(field=field), self.assertRaises(self.api.CounterError) as caught:
                    self.advance(previous, current)
                self.assertNotIn("private", str(caught.exception))
        for as_of, age in ((True, 60), (-1, 60), (MAX_TIME+1, 60), (160, True), (160, 0), (160, 86401)):
            with self.assertRaises(self.api.CounterError): self.advance(a, b, as_of=as_of, max_age=age)
        for bad in (False, {}, a.observation, replace(a, observation=None)):
            with self.assertRaises(self.api.CounterError): self.advance(None, bad)

    def test_all_unavailable_transitions_force_baseline_only_before_recovery(self):
        start, later = self.point(), self.point(30, 140)
        broken = (None, self.point(value=None, observed_at=None, collected_at=120, state="UNKNOWN"),
                  self.point(10, 99), self.point(3, 110), self.point(10, 100),
                  self.point(30, 110, generation="epoch-2"), self.point(30, 110, route="/"))
        for item in broken:
            result = self.advance(start, item)
            self.assertEqual(result.state, "UNAVAILABLE")
            self.assertIsNone(result.next_baseline)
            new = self.advance(result.next_baseline, later)
            self.assertEqual(new.state, "BASELINE")
            self.assertIsNone(new.count)
            final = self.point(34, 150)
            resumed = self.advance(new.next_baseline, final)
            self.assertEqual((resumed.state, resumed.count, resumed.elapsed_seconds), ("AVAILABLE", 4, 10))
            self.assertEqual(resumed.next_baseline, final)
        # Caller clears on structural error too; exceptions cannot update caller-owned state.
        baseline = start
        try:
            self.advance(baseline, replace(later, observation=replace(later.observation, value=True)))
        except self.api.CounterError:
            baseline = None
        self.assertIsNone(baseline)
        self.assertEqual(self.advance(baseline, later).state, "BASELINE")

    def test_immutable_inputs_results_and_determinism(self):
        a, b = self.point(), self.point(17, 110)
        before = repr((a, b))
        first = self.advance(a, b)
        self.assertEqual(first, self.advance(a, b))
        self.assertEqual(repr((a, b)), before)
        for obj, field, value in ((a, "generation", "changed"), (first, "count", 99)):
            with self.assertRaises(FrozenInstanceError): setattr(obj, field, value)

    def test_raw_coverage_can_be_complete_while_delta_has_only_a_baseline(self):
        current = self.point(service_id="lab-web", route="/")
        config = validate_config(declared(requirement()))
        coverage, _ = assess_coverage(config.required_observations, (current.observation,), as_of=160, max_age=60)
        self.assertEqual(coverage, "complete")
        result = self.advance(None, current)
        self.assertEqual(result.state, "BASELINE")
        self.assertIsNone(result.count)

    def test_synthetic_fixture_does_not_bridge_a_decrease(self):
        path = Path(__file__).with_name("fixtures") / "counter.sequence.json"
        raw = path.read_bytes()
        fixture = json.loads(raw)
        baseline = None
        for step in fixture["steps"]:
            current = self.point(step["value"], step["observed_at"],
                                 counter_id=fixture["counter_id"], generation=fixture["generation"])
            result = self.advance(baseline, current)
            self.assertEqual([result.state, result.reason, result.count, result.elapsed_seconds], step["expected"])
            baseline = result.next_baseline
        self.assertEqual(path.read_bytes(), raw)
