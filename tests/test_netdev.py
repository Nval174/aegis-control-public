"""Synthetic native text with independent selection, layout and boundary controls."""
from dataclasses import FrozenInstanceError, asdict
from pathlib import Path
import unittest

from aegis_control.netdev import NetdevError, parse_netdev

FIXTURES = Path(__file__).with_name("fixtures")
H1 = b"Inter-| Receive | Transmit"
H2 = b"face | bytes packets errs drop fifo frame compressed multicast | bytes packets errs drop fifo colls carrier compressed"
HEADERS = H1 + b"\n" + H2 + b"\n"


def row(name="eth0", values=tuple(range(1, 17))):
    return name.encode("ascii") + b": " + b" ".join(str(v).encode("ascii") for v in values)


def document(*rows):
    return HEADERS + b"\n".join(rows) + (b"\n" if rows else b"")


class NetdevTests(unittest.TestCase):
    def assert_missing(self, result, interface):
        self.assertEqual(asdict(result), dict(interface=interface, state="UNAVAILABLE",
                                             reason="interface_missing", rx_bytes=None,
                                             rx_packets=None, tx_bytes=None, tx_packets=None))

    def test_saved_nonfirst_interface_exact_values_and_row_order_independence(self):
        raw = (FIXTURES / "netdev.synthetic.normal.txt").read_bytes()
        result = parse_netdev(raw, interface="wan0.100")
        self.assertEqual(asdict(result), dict(interface="wan0.100", state="OBSERVED", reason="parsed",
                                             rx_bytes=1001, rx_packets=101, tx_bytes=2002, tx_packets=202))
        lines = raw.splitlines()
        reordered = b"\n".join(lines[:2] + list(reversed(lines[2:]))) + b"\n"
        self.assertEqual(result, parse_netdev(reordered, interface="wan0.100"))

    def test_exact_selector_case_and_punctuation_are_literal(self):
        raw = document(row("eth.1"), row("eth-1", (99,) * 16), row("Eth.1", (88,) * 16))
        self.assertEqual(parse_netdev(raw, interface="eth.1").rx_bytes, 1)
        self.assertEqual(parse_netdev(raw, interface="eth-1").rx_bytes, 99)
        self.assertEqual(parse_netdev(raw, interface="Eth.1").rx_bytes, 88)
        for name in ("eth", "ETH.1", "eth.10"):
            self.assert_missing(parse_netdev(raw, interface=name), name)
        name = "a_B-1.2@3"
        self.assertEqual(parse_netdev(document(row(name)), interface=name).interface, name)

    def test_zero_and_exact_unsigned64_without_float_precision_loss(self):
        raw = (FIXTURES / "netdev.synthetic.zero.txt").read_bytes()
        result = parse_netdev(raw, interface="zero0")
        self.assertEqual(asdict(result), dict(interface="zero0", state="OBSERVED", reason="parsed",
                                             rx_bytes=0, rx_packets=0, tx_bytes=0, tx_packets=0))
        maximum = 18446744073709551615
        values = [maximum] * 16
        values[1], values[9] = maximum - 1, maximum - 2
        result = parse_netdev(document(row(values=values)), interface="eth0")
        self.assertEqual((result.rx_bytes, result.rx_packets, result.tx_bytes, result.tx_packets),
                         (18446744073709551615, 18446744073709551614,
                          18446744073709551615, 18446744073709551613))
        for value in (result.rx_bytes, result.rx_packets, result.tx_bytes, result.tx_packets):
            self.assertIs(type(value), int)
        zeros = row().split(b":", 1)[0] + b": " + b" ".join([b"0" * 20] * 16)
        self.assertEqual(parse_netdev(document(zeros), interface="eth0").tx_packets, 0)

    def test_missing_header_only_empty_and_truncated_are_distinct(self):
        raw = (FIXTURES / "netdev.synthetic.header-only.txt").read_bytes()
        self.assert_missing(parse_netdev(raw, interface="eth0"), "eth0")
        self.assert_missing(parse_netdev(document(row("other0")), interface="eth0"), "eth0")
        for raw in (b"", b" \t\n\n"):
            with self.assertRaisesRegex(NetdevError, "empty"):
                parse_netdev(raw, interface="eth0")
        with self.assertRaisesRegex(NetdevError, "truncated"):
            parse_netdev(H1 + b"\n", interface="eth0")

    def test_spaces_tabs_crlf_blank_lines_and_optional_final_newline(self):
        raw = b"\n\t\n" + HEADERS.replace(b" ", b"\t") + b" \n\teth0 \t: \t" + b"\t".join(str(i).encode() for i in range(1, 17))
        result = parse_netdev(raw.replace(b"\n", b"\r\n"), interface="eth0")
        self.assertEqual((result.rx_bytes, result.rx_packets, result.tx_bytes, result.tx_packets), (1, 2, 9, 10))

    def test_headers_are_ordered_distinct_groups_not_guessed_offsets(self):
        for header in (
            HEADERS.replace(b"Receive", b"Transmit"),
            HEADERS.replace(b"Receive | Transmit", b"Transmit | Receive"),
            HEADERS.replace(b"bytes packets", b"packets bytes", 1),
            HEADERS.replace(b"multicast", b"compressed"),
            HEADERS.replace(b"face", b"interface"),
            HEADERS.replace(b"Inter-", b"Inter"),
            HEADERS.replace(b"|", b"||", 1),
            H1 + b"\nface | bytes packets errs drop fifo colls carrier compressed | bytes packets errs drop fifo frame compressed multicast\n",
        ):
            with self.subTest(header=header), self.assertRaises(NetdevError):
                parse_netdev(header + row() + b"\n", interface="eth0")
        # Repeated bytes/packets/etc across the two correct groups are valid.
        self.assertEqual(parse_netdev(document(row()), interface="eth0").tx_bytes, 9)

    def test_names_exact_length_and_supported_subset(self):
        for name in ("a", "a" * 15):
            self.assertEqual(parse_netdev(document(row(name)), interface=name).interface, name)
        for name in ("", ".", "..", "a" * 16, "eth+1", "eth/1", "eth:1", "a b", "a\tb", "é"):
            with self.subTest(selector=name), self.assertRaises(NetdevError):
                parse_netdev(HEADERS, interface=name)
            if name.isascii():
                with self.subTest(row=name), self.assertRaises(NetdevError):
                    parse_netdev(document(row("eth0"), row(name)), interface="eth0")
        for invalid in (None, True, 1, b"eth0"):
            with self.assertRaises(NetdevError):
                parse_netdev(HEADERS, interface=invalid)

    def test_row_token_counts_separators_and_duplicates_are_atomic(self):
        for bad in (row("eth1", range(15)), row("eth1", range(17)), b"eth1 1 2", row("eth1") + b":",
                    b"eth1:: " + b" ".join([b"0"] * 16), row("eth0")):
            with self.subTest(bad=bad), self.assertRaises(NetdevError):
                parse_netdev(document(row("eth0"), bad), interface="eth0")
        with self.assertRaises(NetdevError):
            parse_netdev(document(row("eth0"), row("other0"), row("other0")), interface="eth0")

    def test_all_numeric_positions_in_unselected_rows_are_checked(self):
        for position in range(16):
            for bad in ("-1", "+1", "1.0", "1e3", "nan", "PRIVATE", "18446744073709551616", "0" * 21):
                values = ["0"] * 16
                values[position] = bad
                with self.subTest(position=position, bad=bad), self.assertRaises(NetdevError) as error:
                    parse_netdev(document(row("eth0"), row("other0", values)), interface="eth0")
                self.assertNotIn("PRIVATE", str(error.exception))
                self.assertLess(len(str(error.exception)), 100)

    def test_saved_selected_row_then_malformed_unselected_tail_returns_no_report(self):
        raw = (FIXTURES / "netdev.synthetic.bad-tail.txt").read_bytes()
        result = None
        with self.assertRaises(NetdevError):
            result = parse_netdev(raw, interface="wan0.100")
        self.assertIsNone(result)

    def test_encoding_controls_wrong_types_and_sanitized_errors(self):
        for suffix in (b"\x00", b"\r", b"\x0b", b"\x0c", b"\x7f", b"\xff", "١".encode()):
            with self.assertRaises(NetdevError):
                parse_netdev(document(row()) + suffix, interface="eth0")
        for raw in (None, True, "text", bytearray(HEADERS), memoryview(HEADERS)):
            with self.assertRaises(NetdevError):
                parse_netdev(raw, interface="eth0")
        with self.assertRaises(NetdevError) as error:
            parse_netdev(HEADERS, interface="PRIVATE/path")
        self.assertNotIn("PRIVATE", str(error.exception))

    def test_independent_exact_and_over_byte_bound(self):
        lines = [H1, H2] + [b" "] * 254
        remaining = 65536 - len(b"\n".join(lines) + b"\n")
        for i in range(2, len(lines)):
            extra = min(512 - len(lines[i]), remaining)
            lines[i] += b" " * extra
            remaining -= extra
        self.assertEqual(remaining, 0)
        raw = b"\n".join(lines) + b"\n"
        self.assertEqual(len(raw), 65536)
        self.assertEqual(len(raw.splitlines()), 256)
        self.assertLessEqual(max(map(len, raw.splitlines())), 512)
        self.assert_missing(parse_netdev(raw, interface="eth0"), "eth0")
        over = raw[:-1] + b" \n"  # Inside an existing short blank line; no extra physical line.
        self.assertEqual(len(over), 65537)
        self.assertEqual(len(over.splitlines()), 256)
        self.assertLessEqual(max(map(len, over.splitlines())), 512)
        for bad in (over, b"\xff" * 65537):
            with self.assertRaisesRegex(NetdevError, "byte limit"):
                parse_netdev(bad, interface="eth0")

    def test_independent_physical_line_and_content_bounds(self):
        raw = b"\n".join([H1, H2] + [b" "] * 254)
        self.assert_missing(parse_netdev(raw, interface="eth0"), "eth0")
        with self.assertRaisesRegex(NetdevError, "line limit"):
            parse_netdev(raw + b"\n ", interface="eth0")
        exact = H1.ljust(512) + b"\n" + H2 + b"\n" + row() + b"\n"
        self.assertEqual(parse_netdev(exact, interface="eth0").rx_bytes, 1)
        self.assertEqual(parse_netdev(exact.replace(b"\n", b"\r\n"), interface="eth0").rx_bytes, 1)
        with self.assertRaisesRegex(NetdevError, "line limit"):
            parse_netdev(H1.ljust(513) + b"\n" + H2 + b"\n" + row(), interface="eth0")

    def test_exact_row_capacity_and_one_beyond_without_line_overflow(self):
        rows = [row("n" + str(i)) for i in range(128)]
        self.assertEqual(parse_netdev(document(*rows), interface="n127").tx_packets, 10)
        raw = document(*rows, row("n128"))
        self.assertEqual(len(raw.splitlines()), 131)
        with self.assertRaisesRegex(NetdevError, "row limit"):
            parse_netdev(raw, interface="n127")

    def test_input_result_nonmutation_and_repeatability(self):
        raw = document(row())
        before = raw
        first = parse_netdev(raw, interface="eth0")
        self.assertEqual(first, parse_netdev(raw, interface="eth0"))
        self.assertEqual(before, raw)
        with self.assertRaises(FrozenInstanceError):
            first.rx_bytes = 7
        with self.assertRaises(FrozenInstanceError):
            first.interface = "other0"
