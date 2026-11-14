"""Schema-2 contract tests, separate from unchanged schema-1 controls."""

from dataclasses import FrozenInstanceError
import tomllib
import unittest

from aegis_control.config import ConfigError, validate_config
from test_config import BASE


def requirement(**changes):
    return dict(service_id="lab-web", source="proxy", metric="requests_total", route="/") | changes


def declared(*requirements):
    data = tomllib.loads(BASE)
    data.update(schema_version=2, required_observations=list(requirements or (requirement(),)))
    return data


class CoverageConfigTests(unittest.TestCase):
    def test_schema_two_exact_identity_and_immutable_values(self):
        config = validate_config(declared())
        self.assertEqual(config.schema_version, 2)
        item = config.required_observations[0]
        self.assertEqual((item.service_id, item.source, item.metric, item.route),
                         ("lab-web", "proxy", "requests_total", "/"))
        with self.assertRaises(FrozenInstanceError):
            item.route = "/login"

    def test_legacy_absence_is_unassessed_but_no_schema_one_extension(self):
        self.assertIsNone(validate_config(tomllib.loads(BASE)).required_observations)
        data = declared()
        data["schema_version"] = 1
        with self.assertRaises(ConfigError): validate_config(data)

    def test_version_two_absent_empty_wrong_type_and_unknown_root(self):
        for value in (None, [], {}, "proxy", True):
            data = declared()
            if value is None: del data["required_observations"]
            else: data["required_observations"] = value
            with self.subTest(value=value), self.assertRaises(ConfigError):
                validate_config(data)
        data = declared()
        data["private-marker"] = "secret"
        with self.assertRaises(ConfigError) as caught: validate_config(data)
        self.assertNotIn("private-marker", str(caught.exception))

    def test_requirement_fields_types_service_sources_and_metrics(self):
        bad = [None, [], "proxy", requirement(extra="secret")]
        for field in requirement():
            missing = requirement()
            del missing[field]
            bad.append(missing)
            for value in (None, True, [], {}):
                bad.append(requirement(**{field: value}))
        bad.extend([requirement(service_id="other"), requirement(metric="rate")])
        bad.extend(requirement(source=s) for s in
                   ("flask_to_ad", "windows_event_forwarding", "cloudfront_waf",
                    "home_gateway_api", "unsupported"))
        for item in bad:
            data = declared()
            data["required_observations"] = [item]
            with self.subTest(item=item), self.assertRaises(ConfigError): validate_config(data)
        self.assertEqual(validate_config(declared(requirement(metric="latency_ms")))
                         .required_observations[0].metric, "latency_ms")

    def test_routes_are_exact_bounded_paths_or_literal_other(self):
        for route in ("OTHER", "/", "/login", "/" + "x" * 2047):
            self.assertEqual(validate_config(declared(requirement(route=route)))
                             .required_observations[0].route, route)
        for route in ("", "*", "other", "//host", "https://secret", "/a?private=1",
                      "/a#secret", "/a\n", "/a\x7f", "/" + "x" * 2048):
            with self.subTest(route=route), self.assertRaises(ConfigError):
                validate_config(declared(requirement(route=route)))

    def test_unique_identity_bounds_and_possible_catalog_size(self):
        with self.assertRaises(ConfigError): validate_config(declared(requirement(), requirement()))
        items = [requirement(route=f"/{i}", metric=m)
                 for i in range(32) for m in ("requests_total", "latency_ms")]
        self.assertEqual(len(validate_config(declared(*items)).required_observations), 64)
        with self.assertRaises(ConfigError):
            validate_config(declared(*items, requirement(route="OTHER")))
        with self.assertRaises(ConfigError):
            validate_config(declared(*(requirement(route=f"/{i}") for i in range(33))))
        other = [requirement(route=f"/{i}") for i in range(32)]
        other.append(requirement(route="OTHER"))
        self.assertEqual(len(validate_config(declared(*other)).required_observations), 33)
