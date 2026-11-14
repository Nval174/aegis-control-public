# Saved TCP SNMP snapshots

`aegis_control.snmp_snapshot.parse_snmp(raw, *, word_bits)` accepts exact bytes and
an exact integer width 32 or 64. Width declares a saved unsigned/signed-long profile,
not the executing machine's architecture. Frozen
`TcpSnmpSnapshot(word_bits, InSegs, OutSegs, RetransSegs)` contains three frozen
`SnmpReading(value, reason)` values, not arbitrary counter maps or raw text.

| Complete document | Reading / outcome |
| --- | --- |
| Selected exact Tcp name present | observed / exact integer, including zero |
| Valid Tcp lacks selected name | field_missing / None, independently by field |
| Valid supported pairs lack Tcp | All three section_missing / None |
| Wrong type/width, empty input, malformed pair/tail or overflow | SnmpError; no snapshot |

Matching is case-sensitive by name, not position or fuzzy equivalence. Every pair
and numeric token validates before return. A valid prefix cannot prove complete
physical delivery; bytes cannot diagnose file absence/permissions/timeouts or
authenticate a namespace/lifetime. No live read, time, gauge output or arithmetic.

## Supported section domains

| Section / exact field | Accepted domain |
| --- | --- |
| Tcp.MaxConn | Signed declared width: `-2**(word_bits-1)..2**(word_bits-1)-1` |
| Other Tcp fields | Unsigned declared width |
| Ip.Forwarding / Ip.DefaultTTL | Nonnegative signed-32: `0..2147483647` |
| Other Ip fields | Unsigned-64 |
| Icmp / IcmpMsg / Udp / UdpLite fields | Unsigned declared width |
| Other section | Unsupported-section error |

Tokens are ASCII decimal digits; only MaxConn permits one leading minus. Leading
zeros and MaxConn negative zero are accepted within token/range limits. No plus,
fraction, exponent, hex, coercion, rounding, wrapping or clamping. Unknown fields
within supported sections follow that section's rule.

Adjacent nonblank header/value rows require matching section labels, at least one
field, equal counts and unique valid names. Repeat sections reject except IcmpMsg,
whose field names must remain disjoint across its pairs. The same field name in
different sections is valid; IcmpMsg may be absent, but an empty pair rejects.
Its structural support permits up to 512 fields rather than requiring upstream
producer groups of 16; that does not claim larger/arbitrary groups are emitted.

| Boundary | Limit |
| --- | --- |
| Raw bytes before ASCII decode/split | 65,536 |
| Physical lines including blanks | 128 |
| Line content excluding LF/CRLF | 8,192 bytes |
| Tokens including section label | 513 |
| Section/field name excluding colon | 1-64 ASCII `[A-Za-z][A-Za-z0-9]*` |
| Numeric token including minus | 1-20 characters |
| Distinct IcmpMsg names across all pairs | 512 |

Space/tab padding/separators, LF/CRLF and optional final newline are supported.
Bare CR, DEL, other controls and non-ASCII reject. A terminal LF is not an extra
line; additional trailing blanks count. Storage remains bounded to section/name
validation, one pair and three returned values, not a historical all-counter map.

## Interpretation and primary references

Pinned [v6.8 proc.c](https://github.com/torvalds/linux/blob/v6.8/net/ipv4/proc.c)
uses distinct section formatters, including signed MaxConn and grouped IcmpMsg.
[Storage](https://github.com/torvalds/linux/blob/v6.8/include/net/snmp.h),
[namespace declarations](https://github.com/torvalds/linux/blob/v6.8/include/net/netns/mib.h)
and [ICMP indices](https://github.com/torvalds/linux/blob/v6.8/include/uapi/linux/snmp.h)
explain those distinct profiles. IcmpMsg uses atomic_long_t; its unsigned text
profile is not a claim of unsigned storage.

[TCP initialization](https://github.com/torvalds/linux/blob/v6.8/include/net/tcp.h)
sets MaxConn to -1. Full signed-range acceptance is structural, not an operational
meaning for every negative value. The Ip profile is deliberately broader than
[emitted/configured policy values](https://github.com/torvalds/linux/blob/v6.8/net/ipv4/sysctl_net_ipv4.c).
CurrEstab is a gauge: its token validates but it is not exposed as a cumulative
reading; see [state accounting](https://github.com/torvalds/linux/blob/v6.8/net/ipv4/tcp.c).

[Counter documentation](https://docs.kernel.org/networking/snmp_counter.html)
describes GRO/GSO accounting effects. These are not interchangeable physical wire
packets, per-service counts, capacity or attack proof. [Namespace scope](https://man7.org/linux/man-pages/man5/proc_pid_net.5.html)
and upstream source do not authenticate supplied captures or establish every
distribution's behavior. Bounds are support choices, not measured capacity.
