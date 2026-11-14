"""Synthetic saved SNMP inputs: independent oracles, whole-document rejection."""

from dataclasses import asdict, FrozenInstanceError
from pathlib import Path
import unittest

from aegis_control.snmp_snapshot import SnmpError, TcpSnmpSnapshot, parse_snmp

FIXTURES = Path(__file__).with_name("fixtures")
TARGETS = ("InSegs", "OutSegs", "RetransSegs")
GOOD = b"Tcp: InSegs OutSegs RetransSegs\nTcp: 12 23 4\n"


def pair(section, names, values):
    return (section + ": " + " ".join(names) + "\n" + section + ": "
            + " ".join(str(v) for v in values) + "\n").encode("ascii")


class SnmpTests(unittest.TestCase):
    def parse(self, raw, bits=64):
        result = parse_snmp(raw, word_bits=bits)
        self.assertIsInstance(result, TcpSnmpSnapshot)
        self.assertEqual(result.word_bits, bits)
        return result

    def values(self, result):
        return tuple((getattr(result, n).value, getattr(result, n).reason) for n in TARGETS)

    def reject(self, raw, reason=None, bits=64):
        with self.assertRaises(SnmpError) as caught:
            parse_snmp(raw, word_bits=bits)
        message = str(caught.exception)
        self.assertLess(len(message), 160)
        for secret in ("PRIVATE", "secret", "Traceback"):
            self.assertNotIn(secret, message)
        if reason:
            self.assertIn(reason, message)

    def test_saved_normal_multisection_and_declared_width(self):
        raw = (FIXTURES / "snmp.synthetic.normal.txt").read_bytes()
        for bits in (32, 64):
            result = self.parse(raw, bits)
            self.assertEqual(self.values(result), ((12345, "observed"), (23456, "observed"), (17, "observed")))
            self.assertEqual(set(asdict(result)), {"word_bits", *TARGETS})
            self.assertEqual(set(asdict(result.InSegs)), {"value", "reason"})

    def test_name_matching_reorder_extra_fields_and_section_order(self):
        raw = pair("Tcp", ["OutSegs", "InSegsExtra", "RetransSegs", "InSegs", "CurrEstab", "NewField"],
                   [23, 999, 4, 12, 7, 42])
        self.assertEqual(self.values(self.parse(raw)), ((12, "observed"), (23, "observed"), (4, "observed")))
        self.assertEqual(self.parse(raw + pair("Udp", ["InSegs"], [99])),
                         self.parse(pair("Udp", ["InSegs"], [99]) + raw))
        similar = pair("Tcp", ["InSegsExtra", "OutSegs1", "retransSegs"], [12, 23, 4])
        self.assertEqual(self.values(self.parse(similar)), ((None, "field_missing"),) * 3)

    def test_zero_and_independent_missing_fields(self):
        self.assertEqual(self.values(self.parse((FIXTURES / "snmp.synthetic.zero.txt").read_bytes())),
                         ((0, "observed"),) * 3)
        for missing in TARGETS:
            names = [n for n in TARGETS if n != missing]
            result = self.parse(pair("Tcp", names, [5, 5]))
            self.assertEqual(self.values(result), tuple((None, "field_missing") if n == missing
                                                       else (5, "observed") for n in TARGETS))
        self.assertEqual(self.values(self.parse(pair("Tcp", ["MaxConn", "CurrEstab"], [-1, 0]))),
                         ((None, "field_missing"),) * 3)
        self.assertEqual(self.values(self.parse((FIXTURES / "snmp.synthetic.missing.txt").read_bytes())),
                         ((8, "observed"), (None, "field_missing"), (2, "observed")))

    def test_absent_tcp_and_no_icmp_traffic_required(self):
        self.assertEqual(self.values(self.parse((FIXTURES / "snmp.synthetic.absent.txt").read_bytes())),
                         ((None, "section_missing"),) * 3)
        self.assertEqual(self.values(self.parse(GOOD)), ((12, "observed"), (23, "observed"), (4, "observed")))

    def test_selected_unsigned_width_boundaries_exact_integer_precision(self):
        for bits, maximum in ((32, 4294967295), (64, 18446744073709551615)):
            result = self.parse(pair("Tcp", TARGETS, [maximum, maximum, maximum]), bits)
            self.assertEqual(self.values(result), ((maximum, "observed"),) * 3)
            self.assertIs(type(result.InSegs.value), int)
            for target in TARGETS:
                self.reject(pair("Tcp", [target], [maximum + 1]), "domain", bits)
        self.assertEqual(self.parse(pair("Tcp", ["InSegs"], [9007199254740993])).InSegs.value, 9007199254740993)

    def test_signed_maxconn_endpoints_and_only_exact_name_permits_minus(self):
        for bits, low, high in ((32, -2147483648, 2147483647),
                                (64, -9223372036854775808, 9223372036854775807)):
            for value in (low, -1, 0, high):
                result = self.parse(GOOD.replace(b"RetransSegs", b"RetransSegs MaxConn")
                                    .replace(b"12 23 4", f"12 23 4 {value}".encode()), bits)
                self.assertEqual(result.InSegs.value, 12)
            for value in (low - 1, high + 1):
                self.reject(pair("Tcp", ["MaxConn"], [value]), "domain", bits)
        for name in (*TARGETS, "CurrEstab", "Maxconn", "Future"):
            self.reject(pair("Tcp", [name], [-1]), "token")
        for section in ("Ip", "Icmp", "IcmpMsg", "Udp", "UdpLite"):
            self.reject(GOOD + pair(section, ["MaxConn"], [-1]), "token")
        for token in ("+1", "-", "--1", "-+1", "1.0", "1e3", "0x10"):
            self.reject(pair("Tcp", ["MaxConn"], [token]), "token")

    def test_section_numeric_profiles_and_structural_ip_special_fields(self):
        for field in ("CurrEstab", "Future"):
            for bits, maximum in ((32, 4294967295), (64, 18446744073709551615)):
                raw = pair("Tcp", [*TARGETS, field], [12, 23, 4, maximum])
                self.assertEqual(self.parse(raw, bits).InSegs.value, 12)
                self.reject(pair("Tcp", [field], [maximum + 1]), "domain", bits)
        for field in ("Forwarding", "DefaultTTL"):
            for value in (0, 2147483647):
                self.assertEqual(self.parse(GOOD + pair("Ip", [field], [value]), 32).InSegs.value, 12)
            for value in (-1, 2147483648):
                self.reject(GOOD + pair("Ip", [field], [value]), "token" if value < 0 else "domain", 64)
        self.assertEqual(self.parse(GOOD + pair("Ip", ["InReceives"], [18446744073709551615]), 32).InSegs.value, 12)
        self.reject(GOOD + pair("Ip", ["InReceives"], [18446744073709551616]), "domain", 32)
        for section in ("Icmp", "IcmpMsg", "Udp", "UdpLite"):
            for bits, maximum in ((32, 4294967295), (64, 18446744073709551615)):
                self.assertEqual(self.parse(GOOD + pair(section, ["Extra"], [maximum]), bits).InSegs.value, 12)
                self.reject(GOOD + pair(section, ["Extra"], [maximum + 1]), "domain", bits)
                self.reject(GOOD + pair(section, ["Extra"], [-1]), "token", bits)

    def test_leading_zeros_numeric_token_boundary_and_bad_tokens(self):
        self.assertEqual(self.parse(pair("Tcp", ["InSegs", "MaxConn"], ["0" * 20, "-" + "0" * 19])).InSegs.value, 0)
        for name, token in (("InSegs", "0" * 21), ("MaxConn", "-" + "0" * 20)):
            self.reject(pair("Tcp", [name], [token]), "token")
        for token in ("+0", "-0", "1.0", "1e0", "nan", "inf", "0x1", "PRIVATE"):
            self.reject(pair("Tcp", ["InSegs"], [token]), "token")

    def test_icmp_groups_disjoint_duplicates_and_cross_section_identity(self):
        groups = pair("IcmpMsg", ["InType0", "InType8"], [1, 2]) + pair("IcmpMsg", ["OutType8"], [3])
        self.assertEqual(self.parse(groups + GOOD), self.parse(GOOD + groups))
        self.reject(GOOD + pair("IcmpMsg", ["InType8", "InType8"], [1, 2]), "duplicate field")
        self.reject(GOOD + groups + pair("IcmpMsg", ["InType8"], [3]), "duplicate IcmpMsg")
        self.assertEqual(self.parse(GOOD + pair("Udp", ["InSegs"], [9])).InSegs.value, 12)
        self.reject(GOOD + b"IcmpMsg:\nIcmpMsg:\n", "token count")

    def test_duplicate_sections_and_unknown_section_are_not_silently_skipped(self):
        for section in ("Ip", "Icmp", "Tcp", "Udp", "UdpLite"):
            block = pair(section, ["Extra"], [0])
            self.reject(block + block, "repeated section")
        for section in ("PRIVATE", "TcpExt", "tcp", "A" * 64):
            self.reject(GOOD + pair(section, ["Extra"], [0]), "unsupported section")

    def test_complete_document_including_malformed_unselected_tail(self):
        self.reject((FIXTURES / "snmp.synthetic.bad-tail.txt").read_bytes(), "token")
        for tail in (b"Udp: InDatagrams\n", b"Udp: A\nUdp: 0 1\n", b"Udp: A\nIp: 1\n"):
            self.reject(GOOD + tail)
        # Omitting an entire complete pair cannot be diagnosed from a valid prefix.
        self.assertEqual(self.parse(GOOD).OutSegs.value, 23)

    def test_labels_counts_names_and_truncation(self):
        for raw in (b"Tcp InSegs\nTcp 1", b"Tcp:: A\nTcp:: 1", b"Tcp : A\nTcp : 1",
                    b"Tcp:InSegs\nTcp:1", b"Tcp: A\nUdp: 1", b"Tcp: A B\nTcp: 1",
                    b"Tcp: A\nTcp: 1 2", b"Tcp:\nTcp:", b"Tcp: A A\nTcp: 1 2"):
            self.reject(raw)
        for name in ("A" * 65, "_bad", "1bad", "bad-name", "bad:name", "PRIVATE-name"):
            self.reject(pair("Tcp", [name], [0]), "field name")
        self.reject(pair("Tcp", ["secret"], [-1]), "token")
        self.parse(pair("Tcp", ["A", "A" * 64], [0, 0]))
        self.reject(pair("A" * 65, ["A"], [0]), "label")
        for raw in (b"", b" \t\n", b"\r\n\r\n"):
            self.reject(raw, "empty")
        self.reject(b"Tcp: InSegs", "truncated")

    def test_types_ascii_controls_and_whitespace(self):
        class BytesSubclass(bytes):
            pass

        class IntSubclass(int):
            pass

        for raw in (None, "PRIVATE", bytearray(GOOD), memoryview(GOOD), True, BytesSubclass(GOOD)):
            self.reject(raw, "bytes")
        for bits in (None, True, False, 32.0, "64", 16, 128, [], IntSubclass(32)):
            self.reject(GOOD, "width", bits)
        for suffix in (b"\x00", b"\x7f", b"\x0b", b"\x0c", b"\x1b", b"\r"):
            self.reject(GOOD + suffix, "controls")
        self.reject(GOOD + b"\xff", "ASCII")
        self.reject(GOOD + "é".encode(), "ASCII")
        spaced = b" \n\tTcp:\t InSegs OutSegs RetransSegs \t\n\n Tcp: 12\t23 4 \n\n"
        self.assertEqual(self.parse(spaced), self.parse(GOOD))
        self.assertEqual(self.parse(spaced.replace(b"\n", b"\r\n")), self.parse(GOOD.rstrip(b"\n")))

    def test_byte_cap_exact_and_one_over_before_decode(self):
        # Valid selected data plus eight bounded blank physical lines; all other caps hold.
        remaining = 65536 - len(GOOD)
        padding = []
        while remaining:
            size = min(remaining, 8192)
            padding.append(b" " * (size - 1) + b"\n")
            remaining -= size
        raw = GOOD + b"".join(padding)
        self.assertEqual(len(raw), 65536)
        self.assertEqual(self.parse(raw).InSegs.value, 12)
        self.reject(raw + b" ", "byte limit")
        self.reject(b"\xff" * 65537, "byte limit")

    def test_physical_line_and_nonblank_content_limits_independently(self):
        raw = GOOD + b"\n" * 126  # 128 physical lines; one terminal LF adds no extra line.
        self.assertEqual(raw.count(b"\n"), 128)
        self.parse(raw)
        self.reject(raw + b"\n", "physical line limit")
        line = b"Tcp: 0" + b" " * (8192 - len(b"Tcp: 0"))
        raw = b"Tcp: InSegs\n" + line + b"\n"
        self.assertEqual(self.parse(raw).InSegs.value, 0)
        self.assertEqual(self.parse(raw.replace(b"\n", b"\r\n")).InSegs.value, 0)
        self.reject(b"Tcp: InSegs\n" + line + b" ", "line content limit")

    def test_token_and_icmp_aggregate_bounds_independently(self):
        raw = pair("Tcp", [f"A{i}" for i in range(512)], [0] * 512)
        self.assertEqual(self.values(self.parse(raw)), ((None, "field_missing"),) * 3)
        self.reject(pair("Tcp", [f"A{i}" for i in range(513)], [0] * 513), "token count")
        groups = pair("IcmpMsg", [f"A{i}" for i in range(256)], [0] * 256)
        groups += pair("IcmpMsg", [f"A{i}" for i in range(256, 512)], [0] * 256)
        self.assertEqual(self.parse(GOOD + groups).InSegs.value, 12)
        self.reject(GOOD + groups + pair("IcmpMsg", ["Extra"], [0]), "IcmpMsg field limit")

    def test_immutable_repeatable_and_input_unchanged(self):
        raw = (FIXTURES / "snmp.synthetic.normal.txt").read_bytes()
        before = bytes(raw)
        result = self.parse(raw)
        self.assertEqual(result, self.parse(raw))
        self.assertEqual(raw, before)
        for obj, attr in ((result, "word_bits"), (result, "InSegs"), (result.InSegs, "value"), (result.InSegs, "reason")):
            with self.assertRaises(FrozenInstanceError):
                setattr(obj, attr, None)
