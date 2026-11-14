# Saved conntrack scalar readings

`aegis_control.conntrack.parse_conntrack(*, count, maximum)` requires both keyword
arguments, each exact bytes or explicit None. Frozen `ConntrackReadings` contains
`nf_conntrack_count` and `nf_conntrack_max`, each a frozen
`ScalarReading(state, reason, value)`.

Each supplied scalar accepts `[0-9]{1,10}` followed by no terminator or exactly one
LF/CRLF, at most 12 bytes before parsing. Leading zeros are allowed within ten
digits. Values are `0..2147483647`, a nonnegative signed-32 support profile. Reject
signs, whitespace, extra lines/tokens, BOM, Unicode digits, fractions, exponents,
other controls and type coercion. The pair accepts at most 24 supplied bytes.

| Field input | Result |
| --- | --- |
| Valid bytes, including zero | OBSERVED / parsed / exact integer |
| Explicit None | UNAVAILABLE / not_supplied / None |
| Empty, malformed, unsupported or wrong type | ConntrackError; no pair returned |

Both supplied fields validate before return. One unavailable field does not discard
the other's valid reading; any malformed provided field rejects atomically. Bytes
cannot diagnose absent files/modules, read failure or timeout. No timestamps,
capture identity, simultaneity, namespace provenance or freshness are established.

## Interpretation and references

The [kernel conntrack sysctl documentation](https://docs.kernel.org/networking/nf_conntrack-sysctl.html)
describes count as allocated flow entries, not an ever-increasing counter. Pinned
[v6.8 registration](https://github.com/torvalds/linux/blob/v6.8/net/netfilter/nf_conntrack_standalone.c)
uses a per-network-namespace count and global maximum; the maximum is read-only
from noninitial namespaces. It is not an independently configured per-namespace cap.

The [signed sysctl formatter](https://github.com/torvalds/linux/blob/v6.8/kernel/sysctl.c)
can print a minus sign; this parser's nonnegative range is an explicit support
choice, not proof that negative kernel output is impossible. The
[allocation path](https://github.com/torvalds/linux/blob/v6.8/net/netfilter/nf_conntrack_core.c)
increments before its guarded maximum check. Preserve count greater than max,
raw max zero and lower later occupancy; do not clamp, double flow counts, invent
a denominator or diagnose a reset. Maximum zero bypasses that particular threshold,
not every other resource constraint.

No subtraction, ratio, threshold, capacity/attack classification, native collection
or enforcement follows. These grammar/domain limits do not establish measured
capacity or every distribution's producer behavior.
