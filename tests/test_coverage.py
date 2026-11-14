"""Current coverage assertions independent of historical record summaries."""

import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from aegis_control.config import validate_config
from aegis_control.replay import replay_stream
from aegis_control.telemetry import TelemetryError, parse_observation
from test_coverage_config import declared, requirement
from test_config import BASE
from test_telemetry import sample

ROOT = Path(__file__).resolve().parents[1]


def encoded(**changes):
    return json.dumps(sample(service_id="lab-web", route="/") | changes).encode() + b"\n"


class CoverageTests(unittest.TestCase):
    def replay(self, raw, requirements=None, catalog=("/", "/login"), data=None):
        config = validate_config(data or declared(*(requirements or (requirement(),))))
        return replay_stream(io.BytesIO(raw), config, as_of=160, max_age=60, catalog=catalog)

    def reasons(self, report):
        return [row["reason"] for row in report["coverage_details"]["requirements"]]

    def test_all_exact_requirements_fresh_zero_and_sorted_deterministic_details(self):
        reqs = (requirement(route="/login", metric="latency_ms"), requirement())
        raw = encoded(metric="latency_ms", route="/login?private=secret") + encoded()
        report = self.replay(raw, reqs)
        self.assertEqual((report["input_validated"], report["status"], report["coverage"],
                          report["runtime_readiness"]), (True, "COMPLETE", "complete", "untested"))
        details = report["coverage_details"]
        self.assertEqual((details["required_count"], details["satisfied_count"]), (2, 2))
        self.assertEqual(self.reasons(report), ["satisfied", "satisfied"])
        self.assertEqual([r["metric"] for r in details["requirements"]], ["latency_ms", "requests_total"])
        self.assertEqual(report, self.replay(raw, tuple(reversed(reqs))))
        self.assertEqual([row["value"] for row in report["latest"]], [0, 0])
        self.assertNotIn("secret", json.dumps(report))

    def test_one_missing_and_all_missing_do_not_manufacture_values(self):
        reqs = (requirement(), requirement(route="/login"))
        one = self.replay(encoded(), reqs)
        self.assertEqual(one["status"], "COMPLETE")
        self.assertEqual(one["coverage"], "incomplete")
        self.assertEqual(self.reasons(one), ["satisfied", "missing"])
        self.assertEqual(one["coverage_details"]["satisfied_count"], 1)
        empty = self.replay(b"", reqs)
        self.assertEqual((empty["status"], empty["coverage"]), ("UNKNOWN", "incomplete"))
        self.assertEqual(self.reasons(empty), ["missing", "missing"])
        for row in empty["coverage_details"]["requirements"]:
            self.assertEqual(set(row), {"service_id", "source", "metric", "route", "reason"})

    def test_stale_unknown_and_exact_freshness_boundary(self):
        for changes, reason in ((dict(observed_at=99), "stale"),
                                (dict(state="UNKNOWN", observed_at=None, value=None), "unknown")):
            with self.subTest(reason=reason):
                report = self.replay(encoded(**changes))
                self.assertEqual((report["status"], report["coverage"]), ("DEGRADED", "incomplete"))
                self.assertEqual(self.reasons(report), [reason])
                self.assertIsNone(report["latest"][0]["value"])
        self.assertEqual(self.replay(encoded(observed_at=100))["coverage"], "complete")

    def test_each_wrong_identity_component_is_valid_but_missing(self):
        data = declared()
        data["services"].append(dict(id="other", ingress_profile="direct_host", protected_ports=[443]))
        changes = (dict(service_id="other"), dict(metric="latency_ms"), dict(route="/login"),
                   dict(source="cloudfront_waf", state="NOT_APPLICABLE", value=None, observed_at=None))
        for change in changes:
            with self.subTest(change=change):
                report = self.replay(encoded(**change), data=data)
                self.assertEqual(report["records"], 1)
                self.assertEqual(report["status"], "COMPLETE")
                self.assertEqual(report["coverage"], "incomplete")
                self.assertEqual(self.reasons(report), ["missing"])

    def test_multiple_services_have_independent_requirements(self):
        data = declared(requirement(), requirement(service_id="other", metric="latency_ms", route="/login"))
        data["services"].append(dict(id="other", ingress_profile="direct_host", protected_ports=[443]))
        self.assertEqual(self.replay(encoded(), data=data)["coverage_details"]["satisfied_count"], 1)
        report = self.replay(encoded() + encoded(service_id="other", metric="latency_ms", route="/login"), data=data)
        self.assertEqual(report["coverage"], "complete")

    def test_other_only_matches_its_bucket_never_a_known_route(self):
        reqs = (requirement(route="OTHER"), requirement(route="/login"))
        unknown = self.replay(encoded(route="/unknown?private=secret"), reqs)
        self.assertEqual(self.reasons(unknown), ["missing", "satisfied"])
        known = self.replay(encoded(route="/login"), reqs)
        self.assertEqual(self.reasons(known), ["satisfied", "missing"])
        self.assertNotIn("unknown?", json.dumps(unknown))
        self.assertEqual(self.replay(encoded(route="/unknown") + encoded(route="/login"), reqs)["coverage"], "complete")

    def test_required_known_route_must_be_in_catalog_before_read(self):
        class Unreadable:
            def readline(self, size): raise AssertionError("input read before contract check")
        config = validate_config(declared(requirement(route="/login")))
        with self.assertRaises(TelemetryError):
            replay_stream(Unreadable(), config, as_of=160, catalog=("/",))

    def test_latest_collection_time_wins_in_both_orders(self):
        fresh = encoded(observed_at=120, collected_at=130)
        unknown = encoded(state="UNKNOWN", value=None, observed_at=None, collected_at=140)
        for raw in (fresh + unknown, unknown + fresh):
            report = self.replay(raw)
            self.assertEqual(self.reasons(report), ["unknown"])
            self.assertIsNone(report["latest"][0]["value"])
            self.assertEqual(report["counts"], dict(OBSERVED=1, UNKNOWN=1, STALE=0, NOT_APPLICABLE=0))
        later_fresh = encoded(observed_at=140, collected_at=150)
        for raw in (unknown + later_fresh, later_fresh + unknown):
            report = self.replay(raw)
            self.assertEqual((report["status"], report["coverage"]), ("DEGRADED", "complete"))
            self.assertEqual(report["counts"]["UNKNOWN"], 1)

    def test_stale_history_and_current_coverage_are_separate_in_both_orders(self):
        stale = encoded(observed_at=99, collected_at=101)
        fresh = encoded(observed_at=140, collected_at=150)
        for raw in (stale + fresh, fresh + stale):
            report = self.replay(raw)
            self.assertEqual((report["status"], report["coverage"]), ("DEGRADED", "complete"))
            self.assertEqual(report["counts"], dict(OBSERVED=1, UNKNOWN=0, STALE=1, NOT_APPLICABLE=0))
        later_stale = encoded(observed_at=99, collected_at=155)
        for raw in (fresh + later_stale, later_stale + fresh):
            self.assertEqual(self.reasons(self.replay(raw)), ["stale"])

    def test_equal_time_tie_order_can_remove_or_restore_coverage(self):
        fresh = encoded(collected_at=150)
        unknown = encoded(state="UNKNOWN", observed_at=None, value=None, collected_at=150)
        self.assertEqual(self.reasons(self.replay(fresh + unknown)), ["unknown"])
        self.assertEqual(self.replay(unknown + fresh)["coverage"], "complete")

    def test_pure_evaluator_uses_explicit_clock_without_mutation(self):
        from aegis_control.coverage import assess_coverage
        config = validate_config(declared())
        observation = parse_observation(sample(service_id="lab-web", route="/"), {"lab-web"},
                                        ("/",), as_of=160, max_age=60)
        state, details = assess_coverage(config.required_observations, (observation,), as_of=160, max_age=60)
        self.assertEqual((state, details["satisfied_count"]), ("complete", 1))
        state, details = assess_coverage(config.required_observations, (observation,), as_of=161, max_age=60)
        self.assertEqual((state, details["requirements"][0]["reason"]), ("incomplete", "stale"))
        self.assertEqual((observation.state, observation.value), ("OBSERVED", 0))

    def test_exact_requirement_output_bound_is_deterministic(self):
        reqs = tuple(requirement(route=f"/{i}", metric=metric) for i in range(32)
                     for metric in ("requests_total", "latency_ms"))
        routes = tuple(f"/{i}" for i in range(32))
        raw = b"".join(encoded(route=r["route"], metric=r["metric"]) for r in reqs)
        report = self.replay(raw, reqs, catalog=routes)
        self.assertEqual((report["coverage"], len(report["latest"])), ("complete", 64))
        details = report["coverage_details"]
        self.assertEqual((details["required_count"], details["satisfied_count"], len(details["requirements"])), (64, 64, 64))
        self.assertEqual(len(self.replay(b"", reqs, catalog=routes)["coverage_details"]["requirements"]), 64)
        self.assertEqual(report, self.replay(raw, tuple(reversed(reqs)), catalog=routes))

    def test_cli_truth_table_legacy_static_check_usage_and_no_partial_output(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "input.jsonl"
            prefix = [sys.executable, "-B", "-m", "aegis_control"]
            args = prefix + ["replay", str(ROOT / "configs/coverage.example.toml"), str(path), "--as-of", "160"]
            cases = ((encoded(), 0, "COMPLETE", "complete"),
                     (encoded(metric="latency_ms"), 1, "COMPLETE", "incomplete"),
                     (b"", 1, "UNKNOWN", "incomplete"),
                     (encoded(source="cloudfront_waf", state="NOT_APPLICABLE", value=None, observed_at=None), 1, "COMPLETE", "incomplete"),
                     (encoded(observed_at=99) + encoded(observed_at=140, collected_at=150), 1, "DEGRADED", "complete"),
                     (encoded() + encoded(state="UNKNOWN", observed_at=None, value=None, collected_at=150), 1, "DEGRADED", "incomplete"))
            for raw, code, status, coverage in cases:
                path.write_bytes(raw)
                result = subprocess.run(args, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, code, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual((report["status"], report["coverage"]), (status, coverage))
                self.assertEqual(result.stderr, "")
            for tail in (b'{"PRIVATE":', encoded() * 1000):
                path.write_bytes(encoded() + tail)
                result = subprocess.run(args, capture_output=True, text=True, timeout=10)
                self.assertEqual((result.returncode, result.stdout), (1, ""))
                self.assertNotIn("PRIVATE", result.stderr)
                self.assertNotIn("Traceback", result.stderr)
            static = subprocess.run(prefix + ["config-check", args[5]], capture_output=True, text=True, timeout=10)
            self.assertEqual(static.returncode, 0, static.stderr)
            self.assertIn("1 required observation(s); coverage not assessed", static.stdout)
            self.assertEqual(subprocess.run(args + ["--help"], capture_output=True, timeout=10).returncode, 0)
            self.assertEqual(subprocess.run(args[:-2], capture_output=True, timeout=10).returncode, 2)
            path.write_bytes(encoded())
            legacy = args.copy()
            legacy[5] = str(ROOT / "configs/observe.example.toml")
            result = subprocess.run(legacy, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIsNone(json.loads(result.stdout)["coverage_details"])

    def test_cli_new_contract_errors_reject_without_partial_or_private_output(self):
        example = (ROOT / "configs/coverage.example.toml").read_text(encoding="utf-8")
        absent = BASE.replace("schema_version = 1", "schema_version = 2")
        cases = (absent, "required_observations = []\n" + absent,
                 example.replace('route = "/"', 'route = "/PRIVATE"'),
                 'PRIVATE = "secret"\n' + example,
                 example + example[example.index("[[required_observations]]"):])
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / "config.toml"
            path = Path(folder) / "input.jsonl"
            path.write_bytes(encoded())
            for content in cases:
                config.write_text(content, encoding="utf-8")
                result = subprocess.run([sys.executable, "-B", "-m", "aegis_control", "replay",
                                         str(config), str(path), "--as-of", "160"],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual((result.returncode, result.stdout), (1, ""))
                self.assertIn("ERROR:", result.stderr)
                self.assertNotIn("PRIVATE", result.stderr)
                self.assertNotIn("secret", result.stderr)
                self.assertNotIn("Traceback", result.stderr)
