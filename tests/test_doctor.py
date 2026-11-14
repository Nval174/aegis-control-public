"""Local diagnostics: real CLI coverage and controlled collection failures."""

import contextlib
import io
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

from aegis_control import __main__ as doctor


class DoctorTests(unittest.TestCase):
    def test_real_report_contains_local_runtime_observations(self):
        report = doctor.collect_report()
        self.assertEqual(report["python"], ("OBSERVED", sys.version.split()[0]))
        self.assertEqual(report["os"][0], "OBSERVED")
        self.assertTrue(report["os"][1])
        self.assertEqual(set(report), {"os", "python", "sqlite", "git", "ssh", "nginx", "nft"})

    def test_windows_missing_tools_are_absent_but_nft_is_inapplicable(self):
        with patch.object(doctor.platform, "system", return_value="Windows"), patch.object(
            doctor.shutil, "which", return_value=None
        ):
            report = doctor.collect_report()
        for tool in ("git", "ssh", "nginx"):
            self.assertEqual(report[tool][0], "ABSENT")
        self.assertEqual(report["nft"][0], "NOT_APPLICABLE")

    def test_linux_tool_presence_is_only_path_discovery(self):
        with patch.object(doctor.platform, "system", return_value="Linux"), patch.object(
            doctor.shutil, "which", return_value="/fixture/bin/tool"
        ):
            report = doctor.collect_report()
        for tool in ("git", "ssh", "nginx", "nft"):
            self.assertEqual(report[tool][0], "PRESENT")
            self.assertIn("execution not verified", report[tool][1])

    def test_linux_missing_nft_is_absent(self):
        with patch.object(doctor.platform, "system", return_value="Linux"), patch.object(
            doctor.shutil, "which", return_value=None
        ):
            self.assertEqual(doctor.collect_report()["nft"][0], "ABSENT")

    def test_failed_tool_lookup_is_unknown_and_other_checks_survive(self):
        def lookup(name):
            if name == "git":
                raise PermissionError("private path must not leak")
            return None

        with patch.object(doctor.shutil, "which", side_effect=lookup):
            report = doctor.collect_report()
        self.assertEqual(report["git"], ("UNKNOWN", "collection failed (PermissionError)"))
        self.assertEqual(report["ssh"][0], "ABSENT")
        self.assertEqual(report["python"][0], "OBSERVED")

    def test_os_failure_does_not_guess_nft_applicability(self):
        with patch.object(doctor.platform, "system", side_effect=OSError("unavailable")):
            report = doctor.collect_report()
        self.assertEqual(report["os"][0], "UNKNOWN")
        self.assertEqual(report["nft"][0], "UNKNOWN")
        self.assertEqual(report["python"][0], "OBSERVED")

    def test_empty_os_is_unknown(self):
        with patch.object(doctor.platform, "system", return_value=""):
            self.assertEqual(doctor.collect_report()["os"][0], "UNKNOWN")

    def test_linked_sqlite_version_is_reported_without_opening_a_database(self):
        module = types.SimpleNamespace(sqlite_version="3.99.1")
        with patch.object(doctor.importlib, "import_module", return_value=module):
            self.assertEqual(doctor.collect_report()["sqlite"], ("OBSERVED", "3.99.1"))

    def test_missing_sqlite_module_or_extension_is_absent(self):
        for name in ("sqlite3", "_sqlite3"):
            with self.subTest(name=name), patch.object(
                doctor.importlib, "import_module",
                side_effect=ModuleNotFoundError("missing", name=name),
            ):
                self.assertEqual(doctor.collect_report()["sqlite"][0], "ABSENT")

    def test_broken_sqlite_collection_is_unknown(self):
        for error in (ImportError("broken extension"), ModuleNotFoundError(name="other")):
            with self.subTest(error=type(error).__name__), patch.object(
                doctor.importlib, "import_module", side_effect=error
            ):
                self.assertEqual(doctor.collect_report()["sqlite"][0], "UNKNOWN")

    def test_unknown_yields_partial_report_and_nonzero_exit(self):
        with patch.object(doctor.platform, "system", side_effect=OSError("private detail")):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = doctor.main(["doctor"])
        self.assertEqual(result, 1)
        self.assertIn("UNKNOWN", output.getvalue())
        self.assertIn("python: OBSERVED", output.getvalue())
        self.assertNotIn("private detail", output.getvalue())

    def test_absence_is_informational_and_output_states_scope(self):
        with patch.object(doctor.shutil, "which", return_value=None):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = doctor.main(["doctor"])
        self.assertEqual(result, 0)
        for phrase in ("local development machine only", "remote targets", "patch compliance", "ABSENT"):
            self.assertIn(phrase, output.getvalue())

    def test_module_entry_point_runs_and_rejects_invalid_command(self):
        for args, expected in ((["doctor"], 0), (["--help"], 0), (["enforce"], 2), ([], 2)):
            with self.subTest(args=args):
                result = subprocess.run(
                    [sys.executable, "-B", "-m", "aegis_control", *args],
                    capture_output=True, text=True, timeout=10, check=False,
                )
                if args == ["doctor"]:
                    # Collector fixtures above pin each SQLite state. This real
                    # process may lack SQLite or encounter collection failures.
                    self.assertRegex(result.stdout, r"(?m)^sqlite: (OBSERVED|ABSENT|UNKNOWN) - .+$")
                    expected = int(any(": UNKNOWN - " in line for line in result.stdout.splitlines()))
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
