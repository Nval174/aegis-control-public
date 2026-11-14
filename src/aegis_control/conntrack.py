"""Pure saved scalar occupancy/limit readings, separate from cumulative counters."""

from dataclasses import dataclass
import re

MAX_SCALAR_BYTES = 12
MAX_DIGITS = 10
MAX_VALUE = 2147483647
_SCALAR = re.compile(rf"[0-9]{{1,{MAX_DIGITS}}}(?:\r?\n)?", re.ASCII)


class ConntrackError(ValueError):
    """Fatal pair error with fixed diagnostics, never raw inputs or access diagnoses."""


@dataclass(frozen=True)
class ScalarReading:
    state: str
    reason: str
    value: int | None


@dataclass(frozen=True)
class ConntrackReadings:
    nf_conntrack_count: ScalarReading
    nf_conntrack_max: ScalarReading


def _scalar(raw):
    if raw is None:
        return ScalarReading("UNAVAILABLE", "not_supplied", None)
    if type(raw) is not bytes:
        raise ConntrackError("conntrack scalar requires exact bytes or None")
    if len(raw) > MAX_SCALAR_BYTES:
        raise ConntrackError("conntrack scalar byte limit exceeded")
    try:
        text = raw.decode("ascii")
    except UnicodeError:
        raise ConntrackError("conntrack scalar requires ASCII") from None
    if _SCALAR.fullmatch(text) is None:
        raise ConntrackError("unsupported conntrack scalar format")
    value = int(text)
    if value > MAX_VALUE:
        raise ConntrackError("conntrack scalar exceeds supported nonnegative signed32 domain")
    return ScalarReading("OBSERVED", "parsed", value)


def parse_conntrack(*, count, maximum):
    """Parse independent saved captures atomically, without ratios or provenance.

    None means explicitly not supplied, not an absent file/module or read failure.
    Max zero and count above max remain raw values; no simultaneity is asserted.
    See CONNTRACK_SCALARS.md for grammar, scope and upstream-profile limitations.
    """
    return ConntrackReadings(_scalar(count), _scalar(maximum))
