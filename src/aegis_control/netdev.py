"""Pure saved /proc/net/dev parsing; one explicitly selected primary interface."""

from dataclasses import dataclass
import re

MAX_BYTES = 65536
MAX_LINES = 256
MAX_LINE = 512
MAX_ROWS = 128
MAX_DIGITS = 20
MAX_VALUE = 2**64 - 1
_NAME = re.compile(r"[A-Za-z0-9_.@-]{1,15}", re.ASCII)
_HEADERS = (
    (("Inter-",), ("Receive",), ("Transmit",)),
    (("face",), tuple("bytes packets errs drop fifo frame compressed multicast".split()),
     tuple("bytes packets errs drop fifo colls carrier compressed".split())),
)


class NetdevError(ValueError):
    """Fatal input/profile error; diagnostics omit raw records, names and paths."""


@dataclass(frozen=True)
class InterfaceReading:
    interface: str
    state: str
    reason: str
    rx_bytes: int | None
    rx_packets: int | None
    tx_bytes: int | None
    tx_packets: int | None


def _supported_name(name):
    return (type(name) is str and 1 <= len(name) <= 15 and name not in (".", "..")
            and _NAME.fullmatch(name) is not None)


def parse_netdev(raw, *, interface):
    """Validate the whole saved document before returning four values or missing.

    Names match literally, with a deliberately narrow project ASCII profile.
    No source/namespace/generation/freshness or usable counter interval is inferred.
    See NETDEV_SNAPSHOTS.md for header/layout and finite support limits.
    """
    if type(raw) is not bytes:
        raise NetdevError("netdev input requires exact bytes")
    if len(raw) > MAX_BYTES:
        raise NetdevError("netdev byte limit exceeded")
    if not _supported_name(interface):
        raise NetdevError("interface selector is outside supported name profile")
    try:
        text = raw.decode("ascii")
    except UnicodeError:
        raise NetdevError("netdev input requires ASCII") from None
    text = text.replace("\r\n", "\n")
    if any(ord(c) < 32 and c not in "\t\n" or ord(c) == 127 for c in text):
        raise NetdevError("netdev input contains unsupported controls")
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    if len(lines) > MAX_LINES or any(len(line) > MAX_LINE for line in lines):
        raise NetdevError("netdev line limit exceeded")
    lines = [line for line in lines if line.strip(" \t")]
    if not lines:
        raise NetdevError("empty netdev input")
    if len(lines) < 2:
        raise NetdevError("truncated netdev headers")
    for line, expected in zip(lines[:2], _HEADERS):
        if line.count("|") != 2 or tuple(tuple(group.split()) for group in line.split("|")) != expected:
            raise NetdevError("unsupported netdev headers")
    seen = set()
    selected = None
    for line in lines[2:]:
        if line.count(":") != 1:
            raise NetdevError("netdev row requires one separator")
        name, data = line.split(":", 1)
        name = name.strip(" \t")
        if not _supported_name(name):
            raise NetdevError("netdev row name is outside supported profile")
        if name in seen:
            raise NetdevError("duplicate netdev interface row")
        if len(seen) >= MAX_ROWS:
            raise NetdevError("netdev row limit exceeded")
        seen.add(name)
        tokens = data.split()
        if len(tokens) != 16:
            raise NetdevError("netdev row requires sixteen numeric fields")
        values = []
        for token in tokens:
            if not 1 <= len(token) <= MAX_DIGITS or any(c not in "0123456789" for c in token):
                raise NetdevError("netdev numeric token is unsupported")
            value = int(token)
            if value > MAX_VALUE:
                raise NetdevError("netdev value exceeds supported unsigned64 domain")
            values.append(value)
        if name == interface:
            selected = values[0], values[1], values[8], values[9]
    if selected is None:
        return InterfaceReading(interface, "UNAVAILABLE", "interface_missing", None, None, None, None)
    return InterfaceReading(interface, "OBSERVED", "parsed", *selected)
