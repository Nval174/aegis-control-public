"""Offline config acceptance through real CLI processes; synthetic inputs only."""

import contextlib
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from aegis_control import __main__ as cli

BASE = """schema_version = 1
mode = "observe"

[optional_integrations]
flask_to_ad = false
windows_event_forwarding = false
cloudfront_waf = false
home_gateway_api = false

[[services]]
id = "lab-web"
ingress_profile = "direct_host"
protected_ports = [80, 443]
"""
SERVICE = """
[[services]]
id = "other"
ingress_profile = "cdn_origin"
protected_ports = [443]
"""


class ConfigTests(unittest.TestCase):
    def run_config(self, content):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.toml"
            raw = content.encode("utf-8") if isinstance(content, str) else content
            path.write_bytes(raw)
            result = subprocess.run(
                [sys.executable, "-B", "-m", "aegis_control", "config-check", str(path)],
                capture_output=True, text=True, timeout=10, check=False,
            )
            self.assertEqual(path.read_bytes(), raw)
            self.assertEqual({p.name for p in Path(directory).iterdir()}, {"input.toml"})
            return result

    def assert_invalid(self, content):
        result = self.run_config(content)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("ERROR:", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_valid_observe_config_reports_static_scope(self):
        result = self.run_config(BASE)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for phrase in ("1 service", "observe", "enforcement disabled", "not checked"):
            self.assertIn(phrase, result.stdout)
        self.assertEqual(result.stderr, "")

    def test_all_declared_profiles_can_be_recorded_without_adapter_activation(self):
        for profile in ("direct_host", "linux_gateway", "cdn_origin", "opnsense_gateway"):
            with self.subTest(profile=profile):
                result = self.run_config(BASE.replace("direct_host", profile))
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_only_observe_mode_is_supported(self):
        for mode in ("active", "enforce", "paused", "OBSERVE", ""):
            with self.subTest(mode=mode):
                self.assert_invalid(BASE.replace('"observe"', f'"{mode}"'))

    def test_schema_version_is_exact_integer_one(self):
        for value in ("true", "false", "0", "2", "1.0", '"1"'):
            with self.subTest(value=value):
                self.assert_invalid(BASE.replace("schema_version = 1", "schema_version = " + value))

    def test_missing_and_unknown_root_fields_are_rejected(self):
        self.assert_invalid(BASE.replace('mode = "observe"\n', ""))
        self.assert_invalid('password = "sensitive-marker"\n' + BASE)

    def test_optional_integrations_must_all_be_present_and_disabled(self):
        for key in ("flask_to_ad", "windows_event_forwarding", "cloudfront_waf", "home_gateway_api"):
            for value in ("true", '"false"', "0"):
                with self.subTest(key=key, value=value):
                    self.assert_invalid(BASE.replace(key + " = false", key + " = " + value))
            self.assert_invalid(BASE.replace(key + " = false\n", ""))
        self.assert_invalid(BASE.replace("flask_to_ad = false", "flask_to_ad = false\nextra = false"))
        self.assert_invalid(BASE.replace("[optional_integrations]\n", 'optional_integrations = "false"\n'))

    def test_services_require_exact_fields(self):
        self.assert_invalid(BASE.replace('id = "lab-web"\n', ""))
        self.assert_invalid(BASE.replace('id = "lab-web"', 'id = "lab-web"\ncommand = "sensitive-marker"'))
        self.assert_invalid(BASE[:BASE.index("[[services]]")])
        self.assert_invalid(BASE.replace("[[services]]", "[services]"))

    def test_ids_are_unique_and_bounded_ascii_identifiers(self):
        for value in ('""', '"a/b"', '"white space"', '"\u00e9"', '"-first"', '"' + "x" * 65 + '"', "42"):
            with self.subTest(value=value):
                self.assert_invalid(BASE.replace('"lab-web"', value))
        self.assert_invalid(BASE + SERVICE.replace('"other"', '"lab-web"'))
        self.assertEqual(self.run_config(BASE.replace('"lab-web"', '"' + "x" * 64 + '"')).returncode, 0)

    def test_profile_must_be_exactly_one_known_value(self):
        for value in ('"unknown"', '""', "true", '["direct_host", "cdn_origin"]'):
            with self.subTest(value=value):
                self.assert_invalid(BASE.replace('"direct_host"', value))

    def test_ports_are_unique_bounded_integers(self):
        for value in ("[]", "[0]", "[65536]", "[true]", '["443"]', "[443.0]", "[443, 443]", '"443"'):
            with self.subTest(value=value):
                self.assert_invalid(BASE.replace("[80, 443]", value))
        for ports in ("[1, 65535]", str(list(range(1, 17)))):
            self.assertEqual(self.run_config(BASE.replace("[80, 443]", ports)).returncode, 0)
        self.assert_invalid(BASE.replace("[80, 443]", str(list(range(1, 18)))))

    def test_service_count_ceiling(self):
        sixteen = BASE + "".join(SERVICE.replace('"other"', f'"service-{i}"') for i in range(15))
        self.assertEqual(self.run_config(sixteen).returncode, 0)
        self.assert_invalid(sixteen + SERVICE)

    def test_file_byte_limit_including_exact_boundary(self):
        raw = BASE.encode() + b"\n#" + b"x" * (65536 - len(BASE.encode()) - 2)
        self.assertEqual(len(raw), 65536)
        self.assertEqual(self.run_config(raw).returncode, 0)
        self.assert_invalid(raw + b"x")

    def test_parse_and_encoding_failures_do_not_echo_input(self):
        for content in (b"\xffsensitive-marker", 'sensitive-marker = "unterminated', BASE + '\n[services]\n'):
            with self.subTest(content=repr(content[:20])):
                result = self.run_config(content)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("ERROR:", result.stderr)
                self.assertNotIn("sensitive-marker", result.stdout + result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_missing_file_and_directory_fail_cleanly(self):
        with tempfile.TemporaryDirectory() as directory:
            for path in (Path(directory) / "missing.toml", Path(directory)):
                result = subprocess.run(
                    [sys.executable, "-B", "-m", "aegis_control", "config-check", str(path)],
                    capture_output=True, text=True, timeout=10, check=False,
                )
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("ERROR:", result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_url_and_unc_syntax_are_rejected(self):
        for path in ("https://example.invalid/config.toml", r"\\fixture.invalid\share\config.toml"):
            result = subprocess.run(
                [sys.executable, "-B", "-m", "aegis_control", "config-check", path],
                capture_output=True, text=True, timeout=10, check=False,
            )
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("not a URL or UNC path", result.stderr)
            self.assertNotIn("fixture.invalid", result.stderr)

    def test_extreme_parser_inputs_fail_without_raw_details(self):
        inputs = (
            'value = ' + '[' * 2000 + '"sensitive-marker"' + ']' * 2000,
            'sensitive-marker = ' + '9' * 5000,
        )
        for content in inputs:
            result = self.run_config(content)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("ERROR:", result.stderr)
            self.assertNotIn("sensitive-marker", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_read_permission_error_is_sanitized(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.toml"
            path.write_text(BASE, encoding="utf-8")
            output = io.StringIO()
            with patch.object(Path, "open", side_effect=PermissionError("sensitive-marker")):
                with contextlib.redirect_stderr(output):
                    self.assertEqual(cli.main(["config-check", str(path)]), 1)
            self.assertIn("PermissionError", output.getvalue())
            self.assertNotIn("sensitive-marker", output.getvalue())

    def test_usage_errors_and_no_activation_command(self):
        for args in (["config-check"], ["config-check", "--apply"], ["enforce"]):
            result = subprocess.run(
                [sys.executable, "-B", "-m", "aegis_control", *args],
                capture_output=True, text=True, timeout=10, check=False,
            )
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_config_check_does_not_run_doctor_collectors(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.toml"
            path.write_text(BASE, encoding="utf-8")
            with patch.object(cli, "collect_report", side_effect=AssertionError("collector invoked")):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(cli.main(["config-check", str(path)]), 0)


if __name__ == "__main__":
    unittest.main()
