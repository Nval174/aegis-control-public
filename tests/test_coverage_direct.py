"""Direct-call invariants, independent of replay's wire validation/selection."""

from dataclasses import replace
import unittest

from aegis_control.config import RequiredObservation
from aegis_control.coverage import assess_coverage
from aegis_control.telemetry import MAX_TIME, MAX_VALUE, Observation, TelemetryError

REQ = RequiredObservation("lab-web", "proxy", "requests_total", "/")
OBS = Observation("lab-web", "proxy", "requests_total", "OBSERVED", 0, 100, 150, "/")


class DirectCoverageTests(unittest.TestCase):
    def assess(self, selected, requirements=(REQ,), **settings):
        return assess_coverage(requirements, selected, **(dict(as_of=160, max_age=60) | settings))

    def reject(self, selected, requirements=(REQ,), **settings):
        with self.assertRaises(TelemetryError) as caught:
            self.assess(selected, requirements, **settings)
        self.assertLess(len(str(caught.exception)), 180)
        self.assertNotIn("PRIVATE", str(caught.exception))

    def test_supported_iterables_zero_and_nonmutation(self):
        for selected in ((OBS,), [OBS], {"key": OBS}.values(), iter([OBS])):
            state, details = self.assess(selected, [REQ])
            self.assertEqual(state, "complete")
            self.assertEqual(details, dict(required_count=1, satisfied_count=1, requirements=[
                dict(service_id="lab-web", source="proxy", metric="requests_total", route="/", reason="satisfied")]))
        self.assertEqual((OBS.value, OBS.state, REQ.route), (0, "OBSERVED", "/"))
        requirements = [replace(REQ, route="/z"), REQ]
        selected = [replace(OBS, route="/z"), OBS]
        before_requirements, before_selected = list(requirements), list(selected)
        state, details = self.assess(selected, requirements)
        self.assertEqual((state, [r["route"] for r in details["requirements"]]), ("complete", ["/", "/z"]))
        self.assertEqual((requirements, selected), (before_requirements, before_selected))

    def test_missing_unknown_and_stale_remain_distinct(self):
        for selected, reason in (((), "missing"),
                                 ((replace(OBS, state="UNKNOWN", value=None, observed_at=None),), "unknown"),
                                 ((replace(OBS, state="STALE", value=None),), "stale"),
                                 ((replace(OBS, observed_at=99),), "stale")):
            state, details = self.assess(selected, max_age=60)
            self.assertEqual((state, details["satisfied_count"], details["requirements"][0]["reason"]),
                             ("incomplete", 0, reason))
        stale = replace(OBS, state="STALE", value=None)
        self.assertEqual(self.assess([stale], max_age=86400)[1]["requirements"][0]["reason"], "stale")

    def test_optional_na_is_valid_but_never_satisfies_proxy(self):
        optional = replace(OBS, source="cloudfront_waf", state="NOT_APPLICABLE", value=None, observed_at=None)
        self.assertEqual(self.assess([optional])[1]["requirements"][0]["reason"], "missing")
        self.assertEqual(self.assess([optional, OBS])[0], "complete")

    def test_duplicate_selected_rejected_in_both_orders_not_history_selection(self):
        unknown = replace(OBS, state="UNKNOWN", value=None, observed_at=None, collected_at=120)
        for selected in ((OBS, OBS), (OBS, unknown), (unknown, OBS)):
            self.reject(selected)

    def test_128_selected_and_129th_stops_traversal(self):
        items = [replace(OBS, service_id=f"s{i}") for i in range(128)]
        self.assertEqual(self.assess(items, [replace(REQ, service_id="s127")])[0], "complete")

        class Guarded:
            consumed = 0

            def __iter__(self):
                return self

            def __next__(self):
                self.consumed += 1
                if self.consumed > 129:
                    raise AssertionError("continued beyond boundary")
                return replace(OBS, service_id=f"s{self.consumed}")

        selected = Guarded()
        self.reject(selected)
        self.assertEqual(selected.consumed, 129)

    def test_requirements_cardinality_paths_and_duplicates(self):
        items = [replace(REQ, route=f"/{i}", metric=m) for i in range(32)
                 for m in ("requests_total", "latency_ms")]
        state, details = self.assess([], items)
        self.assertEqual((state, details["required_count"], details["satisfied_count"]), ("incomplete", 64, 0))
        self.assess([], [replace(REQ, route="/" + "x" * 2047), replace(REQ, route="OTHER")])
        state, details = self.assess([], [replace(REQ, route=f"/{i}") for i in range(32)]
                                    + [replace(REQ, route="OTHER")])
        self.assertEqual((state, details["required_count"]), ("incomplete", 33))
        for reqs in ([], items + [replace(REQ, route="OTHER")], [REQ, REQ],
                     [replace(REQ, route=f"/{i}") for i in range(33)],
                     [replace(REQ, route="/" + "x" * 2048)], {}, "PRIVATE", iter([REQ])):
            self.reject([], reqs)

    def test_requirement_and_observation_identity_checked_before_hashing(self):
        for field, values in (("service_id", ([], {}, None, True, "PRIVATE/path", "x" * 65)),
                              ("source", ([], None, "PRIVATE", "cloudfront_waf")),
                              ("metric", ({}, None, "PRIVATE")),
                              ("route", ([], None, "other", "//PRIVATE", "/x?PRIVATE", "/x#PRIVATE", "/x\n"))):
            for value in values:
                with self.subTest(field=field, value=value):
                    self.reject([], [replace(REQ, **{field: value})])
                    if field != "source" or value != "cloudfront_waf":
                        self.reject([replace(OBS, **{field: value})])
        for bad in (None, {}, "PRIVATE", 1):
            self.reject([bad])
            self.reject([], [bad])
        self.reject(None)

    def test_times_boolean_bounds_order_and_future_collection(self):
        for field in ("observed_at", "collected_at"):
            for value in (True, False, None, -1, 1.0, MAX_TIME + 1, "PRIVATE"):
                self.reject([replace(OBS, **{field: value})])
        self.reject([replace(OBS, collected_at=161)])
        self.reject([replace(OBS, observed_at=151)])
        for settings in (dict(as_of=True), dict(as_of=-1), dict(as_of=MAX_TIME + 1),
                         dict(max_age=True), dict(max_age=0), dict(max_age=86401)):
            self.reject([OBS], **settings)
        self.assertEqual(self.assess([replace(OBS, observed_at=0, collected_at=0)], as_of=0)[0], "complete")
        self.assertEqual(self.assess([replace(OBS, observed_at=MAX_TIME, collected_at=MAX_TIME)], as_of=MAX_TIME)[0], "complete")

    def test_numeric_profiles_and_state_combinations(self):
        for value in (None, True, -1, 1.0, MAX_VALUE + 1, float("nan"), float("inf"), "PRIVATE", []):
            self.reject([replace(OBS, value=value)])
        for value in (0, MAX_VALUE):
            self.assertEqual(self.assess([replace(OBS, value=value)])[0], "complete")
        latency_req = replace(REQ, metric="latency_ms")
        self.assertEqual(self.assess([replace(OBS, metric="latency_ms", value=1.25)], [latency_req])[0], "complete")
        for value in (float("nan"), float("inf"), True, -1, MAX_VALUE + 1):
            self.reject([replace(OBS, metric="latency_ms", value=value)], [latency_req])
        for value in (0, MAX_VALUE):
            self.assertEqual(self.assess([replace(OBS, metric="latency_ms", value=value)], [latency_req])[0], "complete")
        for state in ([], None, True, "PRIVATE", "NOT_APPLICABLE"):
            self.reject([replace(OBS, state=state)])
        for state in ("UNKNOWN", "STALE"):
            self.reject([replace(OBS, state=state)])  # retained numeric value invalid
        self.reject([replace(OBS, state="UNKNOWN", value=None)])  # time must be null
        self.reject([replace(OBS, state="STALE", value=None, observed_at=None)])
        self.reject([replace(OBS, state="NOT_APPLICABLE", value=None, observed_at=None)])
        for state in ("OBSERVED", "UNKNOWN", "STALE"):
            self.reject([replace(OBS, source="cloudfront_waf", state=state)])
        self.reject([replace(OBS, source="cloudfront_waf", state="NOT_APPLICABLE", value=None)])
        self.reject([replace(OBS, source="cloudfront_waf", state="UNKNOWN", value=None, observed_at=None)])
        self.reject([replace(OBS, source="cloudfront_waf", state="STALE", value=None)])

    def test_whole_set_validated_including_unrelated_final_item(self):
        selected = [OBS, replace(OBS, service_id="unrelated", value=-1)]
        before = list(selected)
        self.reject(selected)
        self.assertEqual(selected, before)
        self.reject([OBS, "PRIVATE"])

    def test_identity_is_literal_other_and_membership_remains_a_precondition(self):
        self.assertEqual(self.assess([replace(OBS, route="OTHER")])[1]["requirements"][0]["reason"], "missing")
        self.assertEqual(self.assess([replace(OBS, route="OTHER")], [replace(REQ, route="OTHER")])[0], "complete")
        # No full config/catalog is available to this API: valid syntax cannot prove membership.
        self.assertEqual(self.assess([replace(OBS, service_id="declared", route="/exact")],
                                    [replace(REQ, service_id="declared", route="/exact")])[0], "complete")

    def test_legacy_does_not_iterate_selected_but_still_validates_clock(self):
        class Unreadable:
            def __iter__(self):
                raise AssertionError("legacy consumed selected")

        self.assertEqual(self.assess(Unreadable(), None), ("not_assessed", None))
        self.reject(Unreadable(), None, as_of=True)

    def test_iterator_failure_has_no_partial_report_or_private_diagnostic(self):
        def broken():
            yield OBS
            raise RuntimeError("PRIVATE iterator failure")

        self.reject(broken())
