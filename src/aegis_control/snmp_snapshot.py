"""Pure bounded saved SNMP text; no collection, provenance or counter arithmetic."""

from dataclasses import dataclass
import re

MAX_BYTES = 65536
MAX_LINES = 128
MAX_LINE = 8192
MAX_TOKENS = 513
MAX_NUMERIC_CHARS = 20
MAX_ICMP_FIELDS = 512
_NAME = re.compile(r"[A-Za-z][A-Za-z0-9]{0,63}", re.ASCII)
_SECTIONS = frozenset({"Ip", "Icmp", "IcmpMsg", "Tcp", "Udp", "UdpLite"})


class SnmpError(ValueError):
    """Sanitized fatal saved-input/profile error."""


@dataclass(frozen=True)
class SnmpReading:
    value: int | None
    reason: str


@dataclass(frozen=True)
class TcpSnmpSnapshot:
    word_bits: int
    InSegs: SnmpReading
    OutSegs: SnmpReading
    RetransSegs: SnmpReading


def _number(token, section, name, word_bits):
    signed = section == "Tcp" and name == "MaxConn"
    digits = token[1:] if signed and token.startswith("-") else token
    if (not 1 <= len(token) <= MAX_NUMERIC_CHARS or not digits
            or any(c not in "0123456789" for c in digits)):
        raise SnmpError("SNMP numeric token is unsupported")
    value = int(token)
    if signed:
        low, high = -(1 << (word_bits - 1)), (1 << (word_bits - 1)) - 1
    elif section == "Ip":
        low, high = 0, (2147483647 if name in ("Forwarding", "DefaultTTL") else (1 << 64) - 1)
    else:
        low, high = 0, (1 << word_bits) - 1
    if not low <= value <= high:
        raise SnmpError("SNMP value exceeds supported numeric domain")
    return value


def parse_snmp(raw, *, word_bits):
    """Validate every pair before returning three independent named readings.

    word_bits declares a saved-text profile, not authenticated target architecture.
    No collection/freshness/lifecycle/continuity is established. See SNMP_SNAPSHOTS.md.
    """
    if type(raw) is not bytes:
        raise SnmpError("SNMP input requires exact bytes")
    if len(raw) > MAX_BYTES:
        raise SnmpError("SNMP byte limit exceeded")
    if type(word_bits) is not int or word_bits not in (32, 64):
        raise SnmpError("SNMP declared width must be integer 32 or 64")
    try:
        text = raw.decode("ascii")
    except UnicodeError:
        raise SnmpError("SNMP input requires ASCII") from None
    text = text.replace("\r\n", "\n")
    if any(ord(c) < 32 and c not in "\t\n" or ord(c) == 127 for c in text):
        raise SnmpError("SNMP input contains unsupported controls")
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    if len(lines) > MAX_LINES:
        raise SnmpError("SNMP physical line limit exceeded")
    if any(len(line) > MAX_LINE for line in lines):
        raise SnmpError("SNMP line content limit exceeded")
    lines = [line for line in lines if line.strip(" \t")]
    if not lines:
        raise SnmpError("empty SNMP input")
    if len(lines) % 2:
        raise SnmpError("truncated SNMP pair")
    seen, icmp_fields = set(), set()
    selected = None
    for index in range(0, len(lines), 2):
        header, values = lines[index].split(), lines[index + 1].split()
        if not 2 <= len(header) <= MAX_TOKENS or len(header) != len(values):
            raise SnmpError("SNMP token count invalid")
        label = header[0]
        if not label.endswith(":") or _NAME.fullmatch(label[:-1]) is None or values[0] != label:
            raise SnmpError("SNMP pair labels invalid")
        section = label[:-1]
        if section not in _SECTIONS:
            raise SnmpError("unsupported section in SNMP profile")
        names = header[1:]
        if any(_NAME.fullmatch(name) is None for name in names):
            raise SnmpError("SNMP field name is unsupported")
        unique = set(names)
        if len(unique) != len(names):
            raise SnmpError("duplicate field in SNMP pair")
        if section == "IcmpMsg":
            if icmp_fields & unique:
                raise SnmpError("duplicate IcmpMsg field across pairs")
            if len(icmp_fields) + len(unique) > MAX_ICMP_FIELDS:
                raise SnmpError("IcmpMsg field limit exceeded")
            icmp_fields.update(unique)
        elif section in seen:
            raise SnmpError("repeated section in SNMP input")
        seen.add(section)
        if section == "Tcp":
            selected = {}
        for name, token in zip(names, values[1:]):
            value = _number(token, section, name, word_bits)
            if section == "Tcp" and name in ("InSegs", "OutSegs", "RetransSegs"):
                selected[name] = value

    def reading(name):
        if selected is None:
            return SnmpReading(None, "section_missing")
        if name not in selected:
            return SnmpReading(None, "field_missing")
        return SnmpReading(selected[name], "observed")

    return TcpSnmpSnapshot(word_bits, reading("InSegs"), reading("OutSegs"), reading("RetransSegs"))
