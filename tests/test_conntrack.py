"""Synthetic saved sysctl readings, not live measurements or counter intervals."""
from dataclasses import FrozenInstanceError, asdict
from pathlib import Path
import unittest

from aegis_control.conntrack import ConntrackError, parse_conntrack

FIXTURES = Path(__file__).with_name("fixtures")


class ConntrackTests(unittest.TestCase):
    def test_saved_native_fixture_values_and_malformed_second_input(self):
        normal_max = (FIXTURES / "conntrack-max.normal.txt").read_bytes()
        for name, expected in (("normal", 123), ("zero", 0), ("above", 2048)):
            result = parse_conntrack(count=(FIXTURES / f"conntrack-count.{name}.txt").read_bytes(),
                                     maximum=normal_max)
            self.assertEqual(result.nf_conntrack_count.value, expected)
            self.assertEqual(result.nf_conntrack_count.reason, "parsed")
            self.assertEqual(result.nf_conntrack_max.value, 1024)
        self.assertEqual(parse_conntrack(count=b"123", maximum=(FIXTURES / "conntrack-max.zero.txt").read_bytes())
                         .nf_conntrack_max.value, 0)
        with self.assertRaises(ConntrackError):
            parse_conntrack(count=(FIXTURES / "conntrack-count.normal.txt").read_bytes(),
                            maximum=(FIXTURES / "conntrack-max.malformed.txt").read_bytes())

    def test_normal_exact_identity_and_values_without_doubling(self):
        self.assertEqual(asdict(parse_conntrack(count=b"123\n", maximum=b"1024\n")), {
            "nf_conntrack_count": {"state": "OBSERVED", "reason": "parsed", "value": 123},
            "nf_conntrack_max": {"state": "OBSERVED", "reason": "parsed", "value": 1024},
        })

    def test_single_decimal_grammar_leading_zeros_and_line_endings(self):
        for raw, want in ((b"7", 7), (b"7\n", 7), (b"7\r\n", 7),
                          (b"0000000007", 7), (b"0000000000\r\n", 0)):
            with self.subTest(raw=raw):
                result = parse_conntrack(count=raw, maximum=raw)
                self.assertEqual(result.nf_conntrack_count.value, want)
                self.assertEqual(result.nf_conntrack_max.value, want)
                self.assertIs(type(result.nf_conntrack_count.value), int)

    def test_exact_byte_token_and_numeric_bounds(self):
        # Ten digits + CRLF = exact12-byte cap. Token overrun fits the byte cap,
        # so token validation cannot be accidentally replaced by a byte-only check.
        result = parse_conntrack(count=b"2147483647\r\n", maximum=b"2147483647\r\n")
        self.assertEqual(result.nf_conntrack_count.value, 2147483647)
        self.assertEqual(result.nf_conntrack_max.value, 2147483647)
        for raw in (b"2147483647\r\n0", b"00000000000", b"2147483648", b"9999999999"):
            for field in ("count", "maximum"):
                values = dict(count=b"1", maximum=b"2")
                values[field] = raw
                with self.subTest(raw=raw, field=field), self.assertRaises(ConntrackError):
                    parse_conntrack(**values)
        # Byte cap must win even when the oversized input could not decode as ASCII.
        with self.assertRaisesRegex(ConntrackError, "byte limit"):
            parse_conntrack(count=b"\xff" * 13, maximum=b"1")

    def test_zero_max_zero_and_above_max_remain_raw_observed_values(self):
        for count, maximum in ((b"0", b"0"), (b"0", b"1024"), (b"123", b"0"), (b"2048", b"1024")):
            result = parse_conntrack(count=count, maximum=maximum)
            for reading, raw in ((result.nf_conntrack_count, count), (result.nf_conntrack_max, maximum)):
                self.assertEqual(asdict(reading), dict(state="OBSERVED", reason="parsed", value=int(raw)))
        # Explicit concrete above-max control independent of helper-derived expectations.
        above = parse_conntrack(count=b"2048", maximum=b"1024")
        self.assertEqual((above.nf_conntrack_count.value, above.nf_conntrack_max.value), (2048, 1024))

    def test_none_is_explicitly_not_supplied_and_each_field_is_independent(self):
        result = parse_conntrack(count=None, maximum=b"0\n")
        self.assertEqual(asdict(result), {
            "nf_conntrack_count": {"state": "UNAVAILABLE", "reason": "not_supplied", "value": None},
            "nf_conntrack_max": {"state": "OBSERVED", "reason": "parsed", "value": 0},
        })
        result = parse_conntrack(count=b"0", maximum=None)
        self.assertEqual(result.nf_conntrack_count.value, 0)
        self.assertEqual(asdict(result.nf_conntrack_max), dict(state="UNAVAILABLE", reason="not_supplied", value=None))
        result = parse_conntrack(count=None, maximum=None)
        self.assertEqual(asdict(result.nf_conntrack_count), asdict(result.nf_conntrack_max))
        self.assertIsNone(result.nf_conntrack_count.value)
        self.assertEqual(result.nf_conntrack_count.reason, "not_supplied")

    def test_empty_malformed_controls_and_encoding_are_fatal(self):
        malformed = (
            b"", b"\n", b"\r\n", b" ", b" 1", b"1 ", b"\t1", b"1\t", b"1\r",
            b"1\n\n", b"1\r\n\r\n", b"1 2", b"1\n2", b"1\n2\n", b"1\r2",
            b"+1", b"-1", b"-0", b"1.0", b"1e3", b"0x10", b"PRIVATE", b"1x",
            b"\x001", b"1\x00", b"1\x0b", b"1\x0c", b"1\x7f", b"\xff", b"\xef\xbb\xbf1",
            "١".encode(), "１".encode(), "1\u00a0".encode(),
        )
        for raw in malformed:
            for field in ("count", "maximum"):
                values = dict(count=b"123\n", maximum=b"1024\n")
                values[field] = raw
                with self.subTest(raw=raw, field=field), self.assertRaises(ConntrackError) as error:
                    parse_conntrack(**values)
                self.assertNotIn("PRIVATE", str(error.exception))
                self.assertLess(len(str(error.exception)), 100)

    def test_invalid_types_are_not_coerced_to_bytes_or_missing(self):
        for invalid in (True, False, 0, 123, 1.0, "1", bytearray(b"1"), memoryview(b"1"), [], {}):
            for values in (dict(count=invalid, maximum=b"1"), dict(count=b"1", maximum=invalid)):
                with self.subTest(invalid=type(invalid).__name__), self.assertRaises(ConntrackError):
                    parse_conntrack(**values)

    def test_malformed_pair_is_atomic_even_with_valid_or_unavailable_sibling(self):
        for count, maximum in ((b"123\n", b"PRIVATE"), (None, b"bad"), (b"bad", None)):
            result = None
            with self.assertRaises(ConntrackError):
                result = parse_conntrack(count=count, maximum=maximum)
            self.assertIsNone(result)
        # Positive control: two independent valid captures still produce a report.
        self.assertEqual(parse_conntrack(count=b"123\n", maximum=b"1024\n").nf_conntrack_count.value, 123)

    def test_lower_later_count_is_valid_occupancy_not_counter_discontinuity(self):
        first = parse_conntrack(count=b"9\n", maximum=b"1024\n")
        later = parse_conntrack(count=b"4\n", maximum=b"1024\n")
        self.assertEqual(first.nf_conntrack_count.value, 9)
        self.assertEqual(asdict(later.nf_conntrack_count), dict(state="OBSERVED", reason="parsed", value=4))

    def test_results_frozen_repeatable_and_inputs_unchanged(self):
        count, maximum = b"0000123\n", b"1024\r\n"
        before = count, maximum
        result = parse_conntrack(count=count, maximum=maximum)
        self.assertEqual(result, parse_conntrack(count=count, maximum=maximum))
        self.assertEqual(before, (count, maximum))
        with self.assertRaises(FrozenInstanceError):
            result.nf_conntrack_count.value = 5
        with self.assertRaises(FrozenInstanceError):
            result.nf_conntrack_count = result.nf_conntrack_max
