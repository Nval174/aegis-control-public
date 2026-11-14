# Exact saved netstat count differences

```text
difference_snapshots(previous, current, *, as_of, max_age=60, continuous=False)
```

Supply the original `SnapshotSample`-or-None endpoints supported by
[compare_snapshots](KERNEL_COMPARISONS.md). Every invocation revalidates those
endpoints and current settings through comparison before arithmetic. A previously
returned eligibility object cannot authorize a later calculation.

Frozen `SnapshotDifferences(ListenDrops, ListenOverflows)` contains frozen
`CountDifference(state, reason, count)` readings:

| Comparison outcome for this counter | Difference result |
| --- | --- |
| Eligible | AVAILABLE / difference / exact current-minus-previous integer |
| Ineligible | UNAVAILABLE / original comparison reason / None |
| Malformed endpoint or settings anywhere | ComparisonError; no result |

Zero is real AVAILABLE data for equal values over a valid interval, including
0 to 0. Missing/decreased siblings remain independent. Unsigned 32/64-bit inputs
permit differences through `2**word_bits-1`, without float conversion, clamping,
absolute-value correction, wrapping or the proxy telemetry value ceiling.

All identity, time, freshness, reason-priority and whole-interval continuity rules
remain in comparison. Changing max_age, metadata or testimony can invalidate a
previously eligible pair. A decrease is never subtracted or diagnosed as a reset.

No rate, division, elapsed-time field, clock, I/O, retained history, returned
baseline or automatic caller-state clearing exists. On an unavailable/malformed
interval, abandon the unusable endpoint and start from a later good sample;
never retrieve an older one to bridge a missing/invalid event. Caller declarations
cannot authenticate physical continuity or detect omitted events. Raw parsed
values, eligibility and derived counts remain separate concepts.
