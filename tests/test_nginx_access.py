"""Synthetic single-record controls: privacy, exact integers and isolated limits."""
from dataclasses import FrozenInstanceError, asdict
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from aegis_control.nginx_access import (
    MAX_BYTES, NginxAccessRecord, NginxLogError, parse_nginx_record,
)

FIELDS = dict(schema_version=1, msec="100.000", uri="/login", status="200",
              request_time="0.025")
CATALOG = ("/", "/login")


def encoded(**changes):
    return json.dumps(FIELDS | changes, ensure_ascii=True, separators=(",", ":")).encode()


class AccessRecordTests(unittest.TestCase):
    def parse(self, raw=None, **settings):
        result = parse_nginx_record(encoded() if raw is None else raw,
                                    **(dict(service_id="lab-web", catalog=CATALOG) | settings))
        self.assertIs(type(result), NginxAccessRecord)
        for field in ("status", "logged_at_ms", "request_time_ms"):
            self.assertIs(type(getattr(result, field)), int)
        return result

    def rejects(self, raw, reason=None, **settings):
        with self.assertRaises(NginxLogError) as caught:
            parse_nginx_record(raw, **(dict(service_id="lab-web", catalog=CATALOG) | settings))
        text = str(caught.exception)
        self.assertLessEqual(len(text), 100)
        self.assertNotIn("SYNTHETIC_PRIVATE", text)
        self.assertNotIn("SYNTHETIC_SECRET", text)
        if reason:
            self.assertEqual(text, reason)

    def test_literal_output_and_minimal_frozen_shape(self):
        value = self.parse()
        self.assertEqual(asdict(value), dict(service_id="lab-web", route="/login", status=200,
                                            logged_at_ms=100000, request_time_ms=25))
        self.assertEqual(set(value.__dataclass_fields__),
                         {"service_id", "route", "status", "logged_at_ms", "request_time_ms"})
        with self.assertRaises(FrozenInstanceError):
            value.route = "/other"

    def test_exact_times_zero_maximum_and_precision(self):
        for token, expected in (("0.000", 0), ("0001.005", 1005),
                                ("9007199254740.993", 9007199254740993),
                                ("9223372036854775.807", 2**63-1),
                                ("0000000000000000.000", 0)):
            for name in ("msec", "request_time"):
                with self.subTest(name=name, token=token):
                    result = self.parse(encoded(**{name: token}))
                    self.assertEqual(getattr(result, "logged_at_ms" if name == "msec" else "request_time_ms"), expected)

    def test_invalid_times_do_not_become_zero(self):
        invalid = ("9223372036854775.808", "00000000000000000.000", "1.00", "1.0000",
                   ".001", "1", "", "-", "+1.000", "-1.000", "1e1.000", " 1.000",
                   "1.000 ", "NaN", "Infinity", "１.000", "1.٠٠٠", None, 0, True)
        for name in ("msec", "request_time"):
            for value in invalid:
                with self.subTest(name=name, value=value):
                    self.rejects(encoded(**{name: value}), "invalid time")

    def test_status_domain_and_exact_type(self):
        for token, expected in (("100", 100), ("599", 599), ("200", 200)):
            self.assertEqual(self.parse(encoded(status=token)).status, expected)
        for token in ("000", "009", "099", "600", "20", "0200", "+200", "２００",
                      " 200", "200 ", "", "-", 200, True, None):
            with self.subTest(token=token):
                self.rejects(encoded(status=token), "invalid status")

    def test_privacy_exact_routes_and_no_query_stripping(self):
        variants = ("/users/SYNTHETIC_PRIVATE_ID", "/login?SYNTHETIC_SECRET",
                    "/login#SYNTHETIC_SECRET", "/Login", "/log%69n", "/login/",
                    "/./login", "/a/../login", '/quote"back\\brace{[x]}', "/café")
        for uri in variants:
            with self.subTest(uri=uri):
                value = self.parse(encoded(uri=uri))
                self.assertEqual(value.route, "OTHER")
                rendered = json.dumps(asdict(value)) + repr(value)
                self.assertNotIn(uri, rendered)
                self.assertNotIn("SYNTHETIC_PRIVATE", rendered)
                self.assertNotIn("SYNTHETIC_SECRET", rendered)
        for uri in ("/", "/login", "/café"):
            self.assertEqual(self.parse(encoded(uri=uri), catalog=(uri,)).route, uri)
        # Unicode spelling is literal too; no normalization of decomposed text.
        self.assertEqual(self.parse(encoded(uri="/cafe\u0301"), catalog=("/café",)).route, "OTHER")

    def test_paths_at_limit_and_invalid_origin_forms(self):
        path = "/" + "a" * 2047
        self.assertEqual(self.parse(encoded(uri=path), catalog=[path]).route, path)
        multibyte = "/" + "é" * 2047
        raw = json.dumps(FIELDS | dict(uri=multibyte), ensure_ascii=False).encode("utf-8")
        self.assertLess(len(raw), MAX_BYTES)
        self.assertEqual(self.parse(raw, catalog=(multibyte,)).route, multibyte)
        over = json.dumps(FIELDS | dict(uri=multibyte+"é"), ensure_ascii=False).encode("utf-8")
        self.rejects(over, "invalid uri")
        for uri in ("", "login", "//authority", "https://example.invalid/x", path+"a",
                    "/bad\x00", "/bad\x1f", "/bad\x7f", "/bad\x85", "/bad\ud800"):
            with self.subTest(uri=repr(uri)):
                self.rejects(encoded(uri=uri), "invalid uri")

    def test_service_and_catalog_boundaries(self):
        for identifier in ("a", "A_1-" + "a"*60):
            self.assertEqual(self.parse(service_id=identifier).service_id, identifier)
        for identifier in (None, True, 1, "", "a"*65, "bad id", "_bad", "é", "SYNTHETIC_PRIVATE!"):
            self.rejects(encoded(), "invalid service", service_id=identifier)
        paths = ["/"+str(n) for n in range(32)]
        self.assertEqual(self.parse(encoded(uri="/31"), catalog=paths).route, "/31")
        for catalog in ((), [], paths+["/32"], ("/", "/"), {"/"}, iter(["/"]), "/",
                        (None,), ("/bad?secret",), ("/bad#secret",), ("//bad",),
                        ("/bad\udfff",), ("/bad\x85",), ("/"+"a"*2048,)):
            self.rejects(encoded(), "invalid catalog", catalog=catalog)

    def test_exact_schema_keys_versions_and_duplicates(self):
        for version in (True, False, 1.0, "1", 0, 2, None):
            self.rejects(encoded(schema_version=version))
        for name in FIELDS:
            obj = dict(FIELDS)
            del obj[name]
            self.rejects(json.dumps(obj).encode(), "invalid fields")
        self.rejects(encoded(SYNTHETIC_PRIVATE_FIELD="SYNTHETIC_SECRET"), "invalid fields")
        for duplicate in ('"uri":"/x"', '"u\\u0072i":"/x"'):
            self.rejects(encoded()[:-1]+b","+duplicate.encode()+b"}", "duplicate field")
        self.assertEqual(self.parse(encoded().replace(b'"uri"', b'"u\\u0072i"')).route, "/login")

    def test_field_name_limit_isolated_from_unknown_field(self):
        for size, reason in ((32, "invalid fields"), (33, "field name limit")):
            obj = dict(FIELDS)
            del obj["uri"]
            obj["x"*size] = "/x"
            self.rejects(json.dumps(obj).encode(), reason)
            escaped = ('"' + "\\u0078"*size + '"').encode()
            self.rejects(encoded().replace(b'"uri"', escaped), reason)

    def test_raw_type_encoding_controls_and_bom(self):
        for raw in (None, bytearray(encoded()), memoryview(encoded()), "text", 1, True):
            self.rejects(raw, "invalid bytes")
        for raw in (b"", b" \t", b"\xff", b"\xef\xbb\xbf"+encoded(), encoded()+b"\x00",
                    encoded(uri="/bad\udfff"), encoded(uri="/bad\r"), encoded(uri="/bad\n")):
            self.rejects(raw)

    def test_single_record_framing_and_whitespace(self):
        for suffix in (b"", b"\n", b"\r\n"):
            self.assertEqual(self.parse(b" \t"+encoded()+b"\t "+suffix).route, "/login")
        for raw in (encoded()+b"\r", encoded()+b"\n\n", encoded()+b"\r\n\r\n",
                    b"\n"+encoded(), encoded().replace(b",", b",\n", 1), encoded()+b"\n"+encoded()):
            self.rejects(raw, "invalid framing")
        for raw in (encoded()+b" {}", encoded()+b"SYNTHETIC_PRIVATE", encoded()[:-1]):
            self.rejects(raw)

    def test_flat_guard_rejects_nesting_before_json(self):
        for raw in (b"[]", encoded(uri=[]), encoded(uri={}), b'{"x":'+b"["*1000):
            with patch("json.loads", side_effect=AssertionError("must reject before JSON")):
                self.rejects(raw, "invalid structure")
        self.assertEqual(self.parse(encoded(uri='/quoted{["x"]}')).route, "OTHER")

    def test_numeric_hooks_are_bounded_even_in_rejected_fields(self):
        for length, reason in ((20, "invalid time"), (21, "numeric token limit")):
            raw = encoded().replace(b'"100.000"', b"1"*length)
            self.rejects(raw, reason)
        for token in (b"NaN", b"Infinity", b"-Infinity", b"1.0", b"1e9"):
            self.rejects(encoded().replace(b'"100.000"', token), "invalid number")
        self.rejects(encoded().replace(b'"100.000"', b"1"*21+b".0"), "numeric token limit")

    def test_exact_raw_cap_precedes_decode(self):
        raw = encoded()+b" "*(MAX_BYTES-len(encoded()))
        self.assertEqual(len(raw), 16384)
        self.assertEqual(self.parse(raw).request_time_ms, 25)
        self.assertEqual(self.parse(raw[:-2]+b"\r\n").status, 200)
        self.rejects(raw+b" ", "byte limit")
        self.rejects(raw+b"\n", "byte limit")
        self.rejects(raw+b"\r\n", "byte limit")
        self.rejects(b"\xff"*(MAX_BYTES+1), "byte limit")

    def test_saved_synthetic_controls_and_nonmutation(self):
        root = Path(__file__).parent / "fixtures"
        for case, route, timing in (("known", "/login", 25), ("private", "OTHER", 25),
                                    ("zero", "/login", 0), ("query", "OTHER", 25),
                                    ("fragment", "OTHER", 25)):
            raw = (root / ("nginx.synthetic."+case+".json")).read_bytes()
            original = bytes(raw)
            catalog = list(CATALOG)
            first = self.parse(raw, catalog=catalog)
            self.assertEqual(first, self.parse(raw, catalog=catalog))
            self.assertEqual((first.route, first.request_time_ms), (route, timing))
            self.assertEqual(raw, original)
            self.assertEqual(catalog, list(CATALOG))
        for case in ("malformed", "trailing"):
            self.rejects((root / ("nginx.synthetic."+case+".json")).read_bytes())


if __name__ == "__main__":
    unittest.main()
