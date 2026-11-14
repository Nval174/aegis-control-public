"""Delivery/retention controls with otherwise fresh ordered synthetic samples."""

from dataclasses import FrozenInstanceError, replace
import json
from pathlib import Path
import unittest

from aegis_control.counters import CounterSample
from aegis_control.telemetry import MAX_TIME, parse_observation


class SequenceTests(unittest.TestCase):
    def setUp(self):
        from aegis_control import counter_sequence
        self.api = counter_sequence
        self.a = self.api.StreamKey("a", "proxy", "requests_total", "/")
        self.b = replace(self.a, service_id="b")

    def event(self, seq, at, value=10, key=None, **changes):
        key = self.a if key is None else key
        obs = parse_observation(dict(service_id=key.service_id, source=key.source,
                                     metric=key.metric, route=key.route, state="OBSERVED",
                                     value=value, observed_at=at, collected_at=at),
                                {key.service_id}, ("/", "/login"), as_of=at, max_age=60)
        return self.api.SequenceEvent(key, seq, at, CounterSample(obs, "producer-1", "epoch-1"),
                                      **(dict(continuous=True) | changes))

    def run_events(self, *events, **settings):
        return self.api.run_counter_sequence(events, **settings)

    def unavailable(self, row, reason):
        self.assertEqual((row.state, row.reason), ("UNAVAILABLE", reason))
        self.assertIsNone(row.count)
        self.assertIsNone(row.elapsed_seconds)
        self.assertFalse(row.baseline_present)

    def test_valid_increase_zero_and_explicit_default_false_continuity(self):
        report = self.run_events(self.event(1, 100), self.event(2, 110, 17), self.event(3, 120, 17))
        self.assertEqual([(r.state, r.count, r.elapsed_seconds) for r in report.results],
                         [("BASELINE", None, None), ("AVAILABLE", 7, 10), ("AVAILABLE", 0, 10)])
        self.assertEqual([r.delivery for r in report.results], ["unanchored", "adjacent", "adjacent"])
        self.assertEqual(report.delivery_scope, "declared_sequence_only")
        second = self.event(2, 110, 17)
        default = self.api.SequenceEvent(second.key, 2, 110, second.sample)
        self.unavailable(self.run_events(self.event(1, 100), default).results[-1], "continuity_unconfirmed")

    def test_interleaved_missing_and_malformed_do_not_contaminate_other_stream(self):
        events = [self.event(1, 100), self.event(1, 100, key=self.b),
                  replace(self.event(2, 110), sample=None), self.event(2, 110, 20, key=self.b),
                  self.event(3, 120, 30), replace(self.event(4, 130), sample={"PRIVATE": "secret"}),
                  self.event(3, 130, 25, key=self.b), self.event(5, 140, 40), self.event(6, 150, 44)]
        report = self.api.run_counter_sequence(events)
        self.unavailable(report.results[2], "current_missing")
        self.unavailable(report.results[5], "invalid_payload")
        self.assertEqual([report.results[i].count for i in (3, 6, 8)], [10, 5, 4])
        self.assertEqual([report.results[i].state for i in (4, 7)], ["BASELINE", "BASELINE"])
        self.assertNotIn("PRIVATE", repr(report))
        self.assertNotIn("secret", repr(report))

    def test_unknown_stale_break_and_counter_error_invalidate_then_rebaseline(self):
        middle = self.event(2, 110, 17)
        unknown = replace(middle.sample.observation, state="UNKNOWN", value=None, observed_at=None)
        stale = replace(middle.sample.observation, state="STALE", value=None)
        bad = replace(middle.sample.observation, value=True)
        cases = ((replace(middle, sample=replace(middle.sample, observation=unknown)), "current_unknown"),
                 (replace(middle, sample=replace(middle.sample, observation=stale)), "current_stale"),
                 (replace(middle, kind="break", sample=None), "declared_discontinuity"),
                 (replace(middle, sample=replace(middle.sample, observation=bad)), "invalid_payload"),
                 (replace(middle, continuous=1), "invalid_payload"),
                 (replace(middle, kind="PRIVATE"), "invalid_payload"))
        for event, reason in cases:
            with self.subTest(reason=reason):
                r = self.run_events(self.event(1, 100), event, self.event(3, 120, 30), self.event(4, 130, 34))
                self.unavailable(r.results[1], reason)
                self.assertEqual((r.results[2].state, r.results[2].count), ("BASELINE", None))
                self.assertEqual((r.results[3].count, r.results[3].elapsed_seconds), (4, 10))

    def test_payload_identity_mismatch_invalidates_explicit_destination(self):
        wrong = replace(self.event(2, 110), sample=self.event(2, 110, key=self.b).sample)
        report = self.run_events(self.event(1, 100), wrong, self.event(3, 120, 25))
        self.unavailable(report.results[1], "invalid_payload")
        self.assertEqual(report.results[2].state, "BASELINE")
        self.assertEqual(len(report.retained), 1)

    def test_gap_duplicate_and_backward_sequences_consume_high_water_without_sorting(self):
        for bad_seq, delivery in ((4, "gap"), (2, "duplicate"), (1, "out_of_order")):
            high = max(2, bad_seq)
            report = self.run_events(self.event(1, 100), self.event(2, 110, 17),
                                     self.event(bad_seq, 120, 25), self.event(high+1, 130, 30),
                                     self.event(high+2, 140, 34))
            self.assertEqual(report.results[2].delivery, delivery)
            self.unavailable(report.results[2], "delivery_" + delivery)
            self.assertEqual(report.results[3].state, "BASELINE")
            self.assertEqual((report.results[4].count, report.results[4].elapsed_seconds), (4, 10))
            self.assertEqual(report.retained[0].last_sequence, high+2)

    def test_invalid_known_payload_consumes_sequence_and_never_rewinds_high_water(self):
        report = self.run_events(self.event(10, 100), replace(self.event(9, 110), sample=[]),
                                 self.event(10, 120, 30), self.event(11, 130, 40), self.event(12, 140, 44))
        self.unavailable(report.results[1], "invalid_payload")
        self.assertEqual(report.results[1].delivery, "out_of_order")
        self.unavailable(report.results[2], "delivery_duplicate")
        self.assertEqual(report.results[3].state, "BASELINE")
        self.assertEqual(report.results[4].count, 4)

    def test_generation_and_producer_changes_never_lookup_old_generation_state(self):
        for field in ("generation", "counter_id"):
            change = self.event(2, 110, 30)
            change = replace(change, sample=replace(change.sample, **{field: "different-2"}))
            report = self.run_events(self.event(1, 100), change, self.event(3, 120, 50), self.event(4, 130, 54))
            self.unavailable(report.results[1], "generation_changed" if field == "generation" else "counter_changed")
            self.assertEqual((report.results[2].state, report.results[2].count), ("BASELINE", None))
            self.assertEqual(report.results[3].count, 4)
            self.assertEqual(len(report.retained), 1)

    def test_decrease_other_gauge_and_optional_source_remain_unavailable(self):
        report = self.run_events(self.event(1, 100), self.event(2, 110, 3), self.event(3, 120, 5), self.event(4, 130, 9))
        self.unavailable(report.results[1], "counter_decreased")
        self.assertEqual((report.results[2].state, report.results[3].count), ("BASELINE", 4))
        for key, reason in ((replace(self.a, route="OTHER"), "current_ambiguous_route"),
                            (replace(self.a, metric="latency_ms"), "current_not_counter")):
            event = self.event(1, 100)
            obs = replace(event.sample.observation, route=key.route, metric=key.metric)
            self.unavailable(self.run_events(replace(event, key=key, sample=replace(event.sample, observation=obs))).results[0], reason)
        event = self.event(1, 100)
        key = replace(self.a, source="cloudfront_waf")
        obs = replace(event.sample.observation, source=key.source, state="NOT_APPLICABLE", value=None, observed_at=None)
        self.unavailable(self.run_events(replace(event, key=key, sample=replace(event.sample, observation=obs))).results[0], "current_not_applicable")

    def test_retention_before_equal_after_boundary_and_expired_reappearance(self):
        for at, expected, expired in ((109, "AVAILABLE", 0), (110, "AVAILABLE", 0), (111, "BASELINE", 1)):
            report = self.run_events(self.event(1, 100), self.event(2, at, 17), retention_seconds=10)
            self.assertEqual((report.results[1].state, report.results[1].expired_count), (expected, expired))
        report = self.run_events(self.event(99, 100), self.event(1, 111, 17), self.event(2, 120, 20), retention_seconds=10)
        self.assertEqual([r.delivery for r in report.results], ["unanchored", "unanchored", "adjacent"])
        self.assertEqual([r.state for r in report.results], ["BASELINE", "BASELINE", "AVAILABLE"])
        self.assertEqual(report.retained[0].last_sequence, 2)

    def test_entry_retention_and_baseline_observation_freshness_are_distinct(self):
        report = self.run_events(self.event(1, 100), self.event(2, 161, 17), retention_seconds=100, max_age=60)
        self.unavailable(report.results[1], "previous_stale")
        self.assertEqual((report.results[1].expired_count, report.results[1].delivery), (0, "adjacent"))
        # Missing refreshes bounded delivery retention, never old baseline freshness.
        report = self.run_events(self.event(1, 100), replace(self.event(2, 110), sample=None),
                                 self.event(3, 120, 30), retention_seconds=10)
        self.assertEqual(report.results[-1].state, "BASELINE")
        self.assertEqual(report.results[-1].expired_count, 0)
        aged = self.event(1, 100)
        aged = replace(aged, sample=replace(aged.sample, observation=replace(aged.sample.observation, observed_at=40)))
        other = self.event(1, 160, key=self.b)
        stored = self.run_events(aged, other, retention_seconds=60)
        self.assertTrue(next(s for s in stored.retained if s.key == self.a).baseline_present)
        self.assertEqual(160 - aged.sample.observation.observed_at, 60 + 60)
        checked = self.run_events(aged, other, self.event(2, 160, 30), retention_seconds=60)
        self.unavailable(checked.results[-1], "previous_stale")

    def test_capacity_exact_plus_one_lexical_tie_and_reappearance(self):
        c = replace(self.a, service_id="c")
        report = self.run_events(self.event(1, 100, key=self.b), self.event(1, 100),
                                 self.event(1, 100, key=c), self.event(2, 101, 17), max_keys=2)
        self.assertEqual((report.peak_streams, len(report.retained)), (2, 2))
        self.assertEqual(report.results[2].evicted, self.a)
        self.assertEqual((report.results[3].state, report.results[3].delivery), ("BASELINE", "unanchored"))
        self.assertEqual(report.results[3].evicted, self.b)
        oldest = self.run_events(self.event(1, 100, key=self.b), self.event(1, 101),
                                 self.event(1, 102, key=c), max_keys=2)
        self.assertEqual(oldest.results[-1].evicted, self.b)

    def test_expire_before_admission_and_churn_bound_all_metadata_and_output(self):
        report = self.run_events(self.event(1, 100), self.event(1, 111, key=self.b), max_keys=1, retention_seconds=10)
        self.assertEqual(report.results[1].expired_count, 1)
        self.assertIsNone(report.results[1].evicted)
        events = [self.event(1, 100, key=replace(self.a, service_id=f"s{i}")) for i in range(256)]
        report = self.api.run_counter_sequence(events, max_keys=2)
        self.assertEqual((report.peak_streams, len(report.retained), len(report.results)), (2, 2, 256))
        self.assertEqual(sum(r.evicted is not None for r in report.results), 254)
        self.assertEqual(sum(r.baseline_present for r in report.retained), 2)
        ceiling = self.api.run_counter_sequence(events[:65], max_keys=64)
        self.assertEqual((ceiling.peak_streams, len(ceiling.retained)), (64, 64))
        self.assertIsNotNone(ceiling.results[64].evicted)
        with self.assertRaises(self.api.SequenceError): self.api.run_counter_sequence(events + [self.event(1, 100)])

    def test_envelope_errors_clock_reversal_and_limits_reject_whole_batch_sanitized(self):
        good = self.event(1, 100)
        bad = (None, {"PRIVATE": "secret"}, replace(good, key=None),
               replace(good, key=replace(self.a, route="/PRIVATE?secret")),
               replace(good, key=replace(self.a, source="PRIVATE")),
               replace(good, sequence=True), replace(good, sequence=0),
               replace(good, sequence=MAX_TIME+1), replace(good, at=99),
               replace(good, at=True), replace(good, at=MAX_TIME+1))
        for item in bad:
            with self.subTest(item=repr(item)[:60]), self.assertRaises(self.api.SequenceError) as caught:
                self.run_events(good, item)
            self.assertNotIn("PRIVATE", str(caught.exception))
            self.assertNotIn("secret", str(caught.exception))
        for settings in (dict(max_keys=0), dict(max_keys=65), dict(max_keys=True),
                         dict(retention_seconds=0), dict(retention_seconds=True), dict(retention_seconds=86401),
                         dict(max_age=True), dict(max_age=0)):
            with self.assertRaises(self.api.SequenceError): self.run_events(good, **settings)
        for value in ({}, iter((good,)), "PRIVATE"):
            with self.assertRaises(self.api.SequenceError): self.api.run_counter_sequence(value)
        # No external state exists to resume after failed or successful calls.
        self.assertEqual(self.run_events(self.event(2, 110, 17)).results[0].state, "BASELINE")
        self.assertEqual(len(self.api.run_counter_sequence(()).results), 0)

    def test_clock_and_sequence_ceiling_equal_instants_no_stale_resurrection(self):
        first = self.event(1, 100)
        a = replace(first, sequence=MAX_TIME-1, at=MAX_TIME,
                    sample=replace(first.sample, observation=replace(first.sample.observation,
                                   observed_at=MAX_TIME-1, collected_at=MAX_TIME)))
        b = replace(a, sequence=MAX_TIME, sample=replace(a.sample, observation=replace(a.sample.observation,
                    observed_at=MAX_TIME, value=17)))
        self.assertEqual(self.run_events(a, b).results[1].count, 7)
        stale = replace(first, sample=replace(first.sample, observation=replace(first.sample.observation, state="STALE", value=None)))
        self.unavailable(self.run_events(stale).results[0], "current_stale")

    def test_adjacent_declared_delivery_does_not_prove_disclosed_real_events(self):
        # Synthetic caller hides a restart/omission but supplies adjacent numbers + same tokens.
        report = self.run_events(self.event(50, 100), self.event(51, 110, 17))
        self.assertEqual((report.results[1].delivery, report.results[1].count), ("adjacent", 7))
        self.assertEqual(report.delivery_scope, "declared_sequence_only")

    def test_input_nonmutation_repeatability_and_immutable_bounded_summaries(self):
        events = [self.event(1, 100), self.event(2, 110, 17)]
        before = repr(events)
        report = self.api.run_counter_sequence(events)
        self.assertEqual(report, self.api.run_counter_sequence(events))
        self.assertEqual(repr(events), before)
        self.assertEqual(set(report.retained[0].__dataclass_fields__),
                         {"key", "last_sequence", "last_seen", "baseline_present"})
        for obj, field in ((report, "peak_streams"), (report.results[0], "count"), (report.retained[0], "last_sequence")):
            with self.assertRaises(FrozenInstanceError): setattr(obj, field, 0)

    def test_saved_synthetic_delivery_fixture(self):
        path = Path(__file__).with_name("fixtures") / "counter.delivery.json"
        raw = path.read_bytes()
        data = json.loads(raw)
        events = [replace(self.event(s["sequence"], s["at"], s["value"]), sample=None)
                  if s.get("missing") else self.event(s["sequence"], s["at"], s["value"]) for s in data]
        report = self.api.run_counter_sequence(events)
        self.assertEqual([[r.delivery, r.state, r.reason, r.count] for r in report.results], [s["expected"] for s in data])
        self.assertEqual(path.read_bytes(), raw)
