# Saved netstat snapshots

`aegis_control.netstat_snapshot.parse_netstat(raw, capture)` accepts exact bytes
and `Capture(source, namespace, generation, word_bits)`. Labels are declared
1-64 character ASCII identifiers; generation=None means unknown. Exact integer
word_bits is 32 or 64, declaring the captured TcpExt unsigned-long profile, not
the executing Python process's width.

Frozen `NetstatSnapshot(capture, ListenDrops, ListenOverflows)` returns only the
two named `CounterValue(value, reason)` readings. TcpExt fields accept unsigned
declared-width values; unrelated sections accept uint64. No arbitrary field map,
timestamps, subtraction or telemetry-schema integration is returned.

| Parsing boundary | Limit / rule |
| --- | --- |
| Raw input | 65,536 bytes before ASCII decode/split |
| Physical lines | 128; one terminal newline is not an extra line |
| Line content | 8,192 bytes, LF/CRLF terminator excluded |
| Tokens including label | 513 per line |
| Section/field names | 1-64 ASCII alphanumeric characters, letter first; section colon excluded |
| Numeric tokens | 1-20 ASCII digits, then section-specific unsigned range |

LF/CRLF, space/tab separators and blank lines are accepted. Bare CR, controls and
non-ASCII reject. Ignore blanks, then require adjacent header/value pairs with
matching labels, unique section names and unique header fields. Validate every
pair, including unknown well-formed fields and trailing data.

Empty/whitespace input, odd pair count or any malformed/overflowing content raises
sanitized `NetstatError` atomically. A valid document without TcpExt returns
section_missing for both readings; a missing named field returns field_missing
independently. Missing values are None; observed zero remains zero. Unknown
generation does not invalidate a well-formed raw value.

These are namespace-wide supplied counts, not service attribution or attack proof.
ListenDrops and ListenOverflows are distinct events. Bytes cannot diagnose file
absence/permissions/timeouts or prove physical completeness of a valid prefix.
Capture labels do not authenticate provenance or continuity. Limits are parser
support choices, not measured capacity or universal producer compatibility.

References: [kernel counter meanings](https://docs.kernel.org/networking/snmp_counter.html),
[proc namespace scope](https://man7.org/linux/man-pages/man5/proc_pid_net.5.html),
and pinned [v6.8 proc.c](https://github.com/torvalds/linux/blob/v6.8/net/ipv4/proc.c)
(`TcpExt` unsigned-long and `IpExt` u64 formatting).

The separate [comparison contract](KERNEL_COMPARISONS.md) adds explicit time and
whole-interval prerequisites without changing raw parser availability.
