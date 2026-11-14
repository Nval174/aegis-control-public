import unittest
from dataclasses import FrozenInstanceError

from aegis_control.telemetry import TelemetryError, normalize_route, parse_observation


def sample(**changes):
    result = dict(service_id="fixture-web", source="proxy", metric="requests_total",
                  state="OBSERVED", value=0, observed_at=100, collected_at=101,
                  route="/login?secret=never-retain")
    result.update(changes)
    return result


class TelemetryTests(unittest.TestCase):
    def setUp(self):
        self.ids = {"fixture-web"}

    def parse(self, data, **kw):
        return parse_observation(data, self.ids, ("/", "/login"), as_of=160,
                                 max_age=60, **kw)

    def test_zero_is_observed_and_exact_freshness_boundary_is_inclusive(self):
        o = self.parse(sample())
        self.assertEqual((o.state, o.value, o.route), ("OBSERVED", 0, "/login"))
        with self.assertRaises(FrozenInstanceError):
            o.value = 9

    def test_stale_value_is_unavailable_not_zero(self):
        o = self.parse(sample(observed_at=99))
        self.assertEqual((o.state, o.value, o.observed_at), ("STALE", None, 99))

    def test_unknown_and_disabled_optional_source(self):
        o = self.parse(sample(state="UNKNOWN", observed_at=None, value=None))
        self.assertEqual((o.state, o.value), ("UNKNOWN", None))
        o = self.parse(sample(source="cloudfront_waf", state="NOT_APPLICABLE",
                              observed_at=None, value=None))
        self.assertEqual(o.state, "NOT_APPLICABLE")
        for data in (sample(state="NOT_APPLICABLE", observed_at=None, value=None),
                     sample(source="cloudfront_waf"), sample(state="UNKNOWN")):
            with self.assertRaises(TelemetryError): self.parse(data)

    def test_time_order_and_exact_types(self):
        for field, value in (("observed_at", True), ("observed_at", -1),
                             ("observed_at", 102), ("collected_at", 161),
                             ("collected_at", 1.0), ("observed_at", 2**63)):
            with self.subTest(field=field, value=value):
                with self.assertRaises(TelemetryError): self.parse(sample(**{field:value}))

    def test_metric_values_are_finite_typed_and_bounded(self):
        for value in (True, -1, float("nan"), float("inf"), "secret", None, 1.5, 10**13):
            with self.subTest(value=value):
                with self.assertRaises(TelemetryError): self.parse(sample(value=value))
        self.assertEqual(self.parse(sample(metric="latency_ms", value=1.5)).value, 1.5)
        self.assertEqual(self.parse(sample(value=10**12)).value, 10**12)

    def test_exact_schema_known_service_source_and_metric(self):
        for change in ({"service_id":"unknown"}, {"source":"magic"},
                       {"metric":"queue_from_health_url"}, {"state":"STALE"},
                       {"extra":"private"}):
            with self.assertRaises(TelemetryError): self.parse(sample(**change))
        data=sample(); del data["value"]
        with self.assertRaises(TelemetryError): self.parse(data)

    def test_normalization_discards_queries_and_caps_unknown_cardinality(self):
        self.assertEqual(normalize_route("/login?a=private#fragment", ("/login",)), "/login")
        self.assertEqual({normalize_route(f"/unknown/{i}?private", ("/",))
                          for i in range(5000)}, {"OTHER"})
        self.assertEqual(normalize_route("/%6cogin", ("/login",)), "OTHER")
        for route in ("https://example.invalid/x", "//host/x", "relative", "\x00/x"):
            with self.assertRaises(TelemetryError): normalize_route(route, ("/",))
        self.assertNotIn("private", repr(self.parse(sample(route="/unknown?private"))))

    def test_catalog_and_evaluation_arguments_are_checked(self):
        for catalog in ((), ("OTHER",), ("/?secret",), ("/", "/"), tuple(f"/{i}" for i in range(33))):
            with self.assertRaises(TelemetryError): normalize_route("/", catalog)
        for now, age in ((True,60),(-1,60),(160,0),(160,True),(160,86401)):
            with self.assertRaises(TelemetryError):
                parse_observation(sample(), self.ids, ("/",), as_of=now, max_age=age)
