# Saved interface statistics

`aegis_control.netdev.parse_netdev(raw, *, interface)` accepts exact bytes and an
explicit literal interface selector. Frozen `InterfaceReading` contains interface,
state, reason and exactly rx_bytes, rx_packets, tx_bytes, tx_packets.

| Complete input | Outcome |
| --- | --- |
| Supported headers/rows, exact selector present | OBSERVED / parsed / four exact integers |
| Valid document without selector, including header-only | UNAVAILABLE / interface_missing / four None values |
| Empty/blank, truncated headers, wrong type or any unsupported/malformed row | NetdevError; no report |

Selectors and every row name use `[A-Za-z0-9_.@-]{1,15}`, excluding exact `.` and
`..`. This is narrower than the complete Linux name grammar. No normalization,
prefix/glob, default-route selection, case folding, truncation or summation occurs.
Space/tab padding around names is structural; embedded whitespace rejects.

## Grammar and bounds

The first two nonblank lines must have exact pipe-separated token groups and
column order; spacing/tabs may vary:

```text
Inter-| Receive | Transmit
face | bytes packets errs drop fifo frame compressed multicast | bytes packets errs drop fifo colls carrier compressed
```

Each nonblank data row has exactly one colon and 16 unsigned-64 decimal tokens.
Validate all 16 values of every row, including unselected/trailing rows, before
returning. Only after header validation are values 1, 2, 9 and 10 selected.
Leading zeros within 20 digits are allowed. Signs, exponents, fractions, Unicode
digits, overflow, duplicate exact names and malformed tails reject atomically.

| Resource | Limit |
| --- | --- |
| Raw input before decode/split | 65,536 bytes |
| Physical lines including blanks/headers | 256 |
| Line content excluding LF/CRLF | 512 ASCII bytes |
| Interface rows / duplicate-name set | 128 |
| Names | 1-15 supported ASCII characters |
| Numeric tokens | Exactly 16 per row; 1-20 digits; `0..2**64-1` |

LF/CRLF, blank lines and optional final newline are supported; a terminal newline
is not an additional physical line. Bare CR, DEL, non-ASCII and other controls
reject. Blank lines count toward limits. Keep only four selected values, a bounded
duplicate-name set and a current row, not an arbitrary interface-statistics map.

## Meaning and references

OBSERVED means valid supplied bytes, not a live/fresh measurement. Missing means
only that the exact selector was absent from a structurally valid document. None
is a wrong input type, not an absence extension. No permission/timeout/device-loss
diagnosis, namespace/generation identity, speed/utilization or usable arithmetic
interval is inferred. An interface name can be reused after rename/recreation.

References: [kernel interface statistics](https://docs.kernel.org/networking/statistics.html),
[proc namespace scope](https://man7.org/linux/man-pages/man5/proc_pid_net.5.html),
pinned [v6.8 output](https://github.com/torvalds/linux/blob/v6.8/net/core/net-procfs.c),
[u64 fields](https://github.com/torvalds/linux/blob/v6.8/include/uapi/linux/if_link.h),
[name size](https://github.com/torvalds/linux/blob/v6.8/include/uapi/linux/if.h)
and [name validation](https://github.com/torvalds/linux/blob/v6.8/net/core/dev.c).
The parser's support bounds are not measured capacity or universal driver/counter
lifecycle guarantees; no rates, live collection or enforcement are performed.
