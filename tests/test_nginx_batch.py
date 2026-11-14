"""Real API checks against separate literal oracles and isolated fatal bounds."""
from dataclasses import FrozenInstanceError, asdict
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from aegis_control import nginx_batch
from aegis_control.nginx_access import NginxAccessRecord, NginxLogError, parse_nginx_record
from aegis_control.nginx_batch import NginxBatchEntry, NginxBatchError, NginxBatchReport, parse_nginx_batch

FOLDER = Path(__file__).parent / "fixtures/nginx-batch-design"
ROW = b'{"schema_version":1,"msec":"100.000","uri":"/login","status":"200","request_time":"0.025"}\n'
VALUE = dict(service_id="lab-web", route="/login", status=200, logged_at_ms=100000, request_time_ms=25)
SETTINGS = dict(service_id="lab-web", catalog=("/", "/login"))


def padded(size, ending=b"\n"):
    return ROW[:-1] + b" " * (size - len(ROW[:-1]) - len(ending)) + ending


class NginxBatchTests(unittest.TestCase):
    def parse(self, raw, **changes):
        result = parse_nginx_batch(raw, **(SETTINGS | changes))
        self.assertIs(type(result), NginxBatchReport)
        self.assertIs(type(result.entries), tuple)
        for name in ("total", "valid", "invalid"):
            self.assertIs(type(getattr(result, name)), int)
        self.assertEqual(result.total, len(result.entries))
        self.assertEqual(result.valid + result.invalid, result.total)
        self.assertEqual(result.state, "EMPTY" if not result.total else "HAS_INVALID" if result.invalid else "ALL_VALID")
        for number, entry in enumerate(result.entries, 1):
            self.assertIs(type(entry), NginxBatchEntry)
            self.assertIs(type(entry.record_number), int)
            self.assertEqual(entry.record_number, number)
            if entry.state == "VALID":
                self.assertIs(type(entry.record), NginxAccessRecord)
                self.assertEqual(entry.reason, "record_validated")
            else:
                self.assertEqual(entry.state, "INVALID")
                self.assertIsNone(entry.record)
                self.assertEqual(entry.reason, "record_rejected")
        return result

    def fatal(self, raw, reason, **changes):
        # Patch by create=True also works with the typed, no-behavior RED scaffold.
        with patch.object(nginx_batch, "parse_nginx_record", create=True,
                          side_effect=AssertionError("decoder must not run")) as decoder:
            with self.assertRaises(NginxBatchError) as caught:
                parse_nginx_batch(raw, **(SETTINGS | changes))
            decoder.assert_not_called()
        self.assertEqual(str(caught.exception), "NGINX batch rejected: " + reason)
        self.assertLessEqual(len(str(caught.exception)), 64)
        self.assertNotIn("SYNTHETIC_PRIVATE", str(caught.exception))

    def test_all_saved_fixtures_match_literal_manifest(self):
        manifest = json.loads((FOLDER / "expectations.json").read_text(encoding="utf-8"))
        self.assertEqual(len(manifest["fixtures"]), 11)
        for case in manifest["fixtures"]:
            with self.subTest(case=case["id"]):
                raw = (FOLDER / (case["id"] + ".synthetic.batch")).read_bytes()
                expected = case["future_expectation"]
                if expected.get("fatal"):
                    self.fatal(raw, case["failed_predicates"][0])
                else:
                    actual = json.loads(json.dumps(asdict(self.parse(raw))))
                    self.assertEqual(actual, expected)

    def test_empty_and_valid_settings(self):
        self.assertEqual(asdict(self.parse(b"")), dict(entries=(), total=0, valid=0, invalid=0, state="EMPTY"))

    def test_invalid_settings_are_fatal_even_empty_or_bad_rows(self):
        for service in (None, True, "", "bad!SYNTHETIC_PRIVATE", "a"*65):
            for raw in (b"", ROW, b"\xff\n"):
                with self.subTest(service=service, raw=raw):
                    self.fatal(raw, "invalid_settings", service_id=service)
        for catalog in ((), [], ("/", "/"), ("//bad",), ("/x?private",), ("/x\ud800",),
                        ("/"+"a"*2048,), ["/"+str(i) for i in range(33)], {"/"}, iter(["/"])):
            for raw in (b"", ROW):
                self.fatal(raw, "invalid_settings", catalog=catalog)

    def test_exact_bytes_only_and_type_priority(self):
        class ByteChild(bytes):
            pass
        for raw in (None, False, 1, "", bytearray(ROW), memoryview(ROW), ByteChild(ROW), ByteChild(b"x"*1048577)):
            with self.subTest(type=type(raw)):
                self.fatal(raw, "raw_type", service_id="bad!")

    def test_record_count_exact_and_one_over(self):
        result = self.parse(ROW*256)
        self.assertEqual((result.total, result.valid, result.invalid), (256, 256, 0))
        self.assertEqual(asdict(result.entries[255].record), VALUE)
        self.fatal(ROW*257, "record_count")
        self.fatal(b"\n"*257, "record_count")

    def test_row_byte_limit_lf_and_crlf_includes_terminator(self):
        for ending in (b"\n", b"\r\n"):
            exact, over = padded(16384, ending), padded(16385, ending)
            self.assertEqual((len(exact), len(over)), (16384, 16385))
            self.assertEqual(asdict(self.parse(exact).entries[0].record), VALUE)
            self.fatal(over, "record_bytes")
            self.fatal(ROW+over, "record_bytes")

    def test_total_byte_limit_exact_and_one_over_isolated(self):
        exact = padded(16384)*64
        self.assertEqual(len(exact), 1048576)
        result = self.parse(exact)
        self.assertEqual((result.total, result.valid, result.invalid), (64, 64, 0))
        over = exact+b"\n"  # 65 rows, each within its cap, complete framing.
        self.assertEqual(len(over), 1048577)
        self.fatal(over, "total_bytes")

    def test_competing_fatal_conditions_follow_exact_priority(self):
        cases = ((b"\n"*257+b"\r"+b"x"*1048576, "total_bytes"),
                 (b"\n"*257+b"\rX", "record_count"),
                 (b"x"*16385+b"\r", "unterminated_tail"),
                 (b"\r"+b"x"*16384+b"\n", "bare_cr"),
                 (padded(16385), "record_bytes"))
        for raw, reason in cases:
            with self.subTest(reason=reason):
                self.fatal(raw, reason, service_id="bad!", catalog=[])

    def test_complete_envelope_preflight_no_prefix_decoding(self):
        self.fatal(ROW+ROW[:-1], "unterminated_tail")
        self.fatal(ROW+b"bad\rvalue\n", "bare_cr")
        self.fatal(ROW+padded(16385), "record_bytes")
        result = self.parse(ROW+b"\xff\n"+ROW)
        self.assertEqual((result.state, result.valid, result.invalid), ("HAS_INVALID", 2, 1))
        self.assertEqual([e.state for e in result.entries], ["VALID", "INVALID", "VALID"])

    def test_only_lf_delimits_and_escaped_control_is_row_rejection(self):
        for bad in (b"\v\n", b"\f\n", ROW.replace(b"/login", b"/x\\rSYNTHETIC_PRIVATE")):
            result = self.parse(ROW+bad)
            self.assertEqual((result.total, result.valid, result.invalid), (2, 1, 1))
        self.fatal(ROW+b"\rX\n", "bare_cr")

    def test_real_decoder_receives_original_rows_and_frozen_catalog(self):
        catalog = ["/", "/login"]
        first, second = ROW.replace(b"\n", b"\r\n"), ROW
        def observed(row, *, service_id, catalog):
            self.assertIs(type(catalog), tuple)
            self.assertEqual(catalog, ("/", "/login"))
            original_catalog.clear()  # After validation, not a public callback API.
            return parse_nginx_record(row, service_id=service_id, catalog=catalog)
        original_catalog = catalog
        with patch.object(nginx_batch, "parse_nginx_record", create=True, side_effect=observed) as decoder:
            result = self.parse(first+second, catalog=catalog)
        self.assertEqual(result.valid, 2)
        self.assertEqual([c.args[0] for c in decoder.call_args_list], [first, second])

    def test_unexpected_decoder_exceptions_do_not_become_invalid_or_prefix(self):
        for error in (RuntimeError, ValueError, OSError):
            with self.subTest(error=error):
                calls = 0
                injected = error("unexpected synthetic failure")
                def failing(row, **settings):
                    nonlocal calls
                    calls += 1
                    if calls == 2:
                        raise injected
                    return parse_nginx_record(row, **settings)
                sentinel = object()
                result = sentinel
                with patch.object(nginx_batch, "parse_nginx_record", create=True, side_effect=failing):
                    with self.assertRaises(error) as caught:
                        result = parse_nginx_batch(ROW*3, **SETTINGS)
                self.assertIs(caught.exception, injected)
                self.assertIs(result, sentinel)
                self.assertEqual(calls, 2)

    def test_output_shape_privacy_and_no_extra_normalization(self):
        raw = (FOLDER / "mixed.synthetic.batch").read_bytes()
        raw += ROW.replace(b"/login", b"/login?SYNTHETIC_SECRET")
        raw += ROW.replace(b"/login", b"/login#SYNTHETIC_SECRET")
        raw += ROW.replace(b"/login", b"/log%69n")
        result = self.parse(raw)
        self.assertEqual([e.record.route if e.record else None for e in result.entries],
                         ["/login", None, "OTHER", "OTHER", "OTHER", "OTHER"])
        self.assertEqual(set(asdict(result)), {"entries", "total", "valid", "invalid", "state"})
        for entry in result.entries:
            self.assertEqual(set(asdict(entry)), {"record_number", "state", "record", "reason"})
        rendered = json.dumps(asdict(result))+repr(result)+repr(result.entries)
        for marker in ("SYNTHETIC_PRIVATE", "SYNTHETIC_SECRET"):
            self.assertNotIn(marker, rendered)

    def test_frozen_outputs_nonmutation_and_repeatability(self):
        raw = ROW*2
        original = bytes(raw)
        catalog = ["/", "/login"]
        result = self.parse(raw, catalog=catalog)
        self.assertEqual(result, self.parse(raw, catalog=catalog))
        self.assertEqual((raw, catalog), (original, ["/", "/login"]))
        with self.assertRaises(FrozenInstanceError):
            result.total = 0
        with self.assertRaises(FrozenInstanceError):
            result.entries[0].state = "INVALID"
        with self.assertRaises(FrozenInstanceError):
            result.entries[0].record.route = "OTHER"
        with self.assertRaises(TypeError):
            result.entries[0] = result.entries[1]

    def test_standalone_error_priority_and_literal_diagnostics_unchanged(self):
        self.assertEqual(asdict(parse_nginx_record(ROW[:-1], **SETTINGS)), VALUE)
        cases = ((None, {}, "invalid bytes"), (b"x"*16385, {}, "byte limit"),
                 (b"", {}, "invalid service"), (b"\n\n", {}, "invalid service"),
                 (b"", dict(service_id="lab-web"), "invalid catalog"))
        for raw, changes, reason in cases:
            with self.assertRaises(NginxLogError) as caught:
                parse_nginx_record(raw, **(dict(service_id="bad!", catalog=[]) | changes))
            self.assertEqual(str(caught.exception), reason)


if __name__ == "__main__":
    unittest.main()
