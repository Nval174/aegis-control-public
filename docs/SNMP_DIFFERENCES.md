# Exact saved SNMP count differences

```text
difference_snmp_snapshots(previous, current, *, as_of, max_age=60, continuous=False)
```

`aegis_control.snmp_differences` accepts the original None/exact `SnmpSample`
endpoints and settings defined by [SNMP comparison](SNMP_COMPARISONS.md). Every
call forwards the same endpoints/current settings to comparison before reading
values for arithmetic. No cached eligibility or skip-validation argument exists.

Frozen `SnmpDifferences(InSegs, OutSegs, RetransSegs)` uses existing
`kernel_differences.CountDifference(state, reason, count)` values:

| Comparison for this reading | Result |
| --- | --- |
| Eligible | AVAILABLE / difference / exact current-minus-previous integer |
| Ineligible | UNAVAILABLE / unchanged reason / None |
| Any malformed endpoint/reading/settings | ComparisonError; no result |

Equal values, including zero, produce real available zero counts over a valid
interval. Missing/decreased siblings are independent. Unsigned 32/64-bit inputs
permit differences through `2**word_bits-1`, including integers above `2**53` or
the proxy telemetry ceiling. No float conversion, clamping, absolute-value/wrap
correction, invented zero, reset diagnosis, rate or elapsed-time field is added.

Comparison owns all full structural, clock, freshness, identity, generation and
continuity validation and reason priority. A malformed third reading cannot hide
behind eligible first readings, missing siblings or an unavailable opposite.
Re-evaluation can invalidate previously eligible endpoints as they age or settings
change; a prior eligibility result is no permission to bypass checks.

Source/namespace/generation/width and continuous remain caller declarations,
not authenticated lifecycle evidence. False is the default. After an unusable
interval or `ComparisonError`, explicitly drop the caller baseline and start
from a new good sample before a later interval. Never bridge a break using an
older saved good endpoint; the stateless pair helper cannot detect that omission.

Two fixed-size samples/three readings produce one immutable result. No retained
history, clock, file I/O, sequence framework, telemetry integration or enforcement
is performed. Support bounds do not establish measured capacity or live readiness.
