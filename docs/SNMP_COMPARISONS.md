# Saved SNMP comparison eligibility

```text
compare_snmp_snapshots(previous, current, *, as_of, max_age=60, continuous=False)
```

`aegis_control.snmp_comparison` accepts None or exact frozen
`SnmpSample(snapshot, observed_at, source, namespace, generation)`. Snapshot is an
exact `TcpSnmpSnapshot`; its word_bits is the only declared width. Source/namespace
are nonsecret 1-64 ASCII alphanumeric/underscore/hyphen identifiers, beginning
alphanumeric. Generation follows that profile or is None (unknown).

Frozen `SnmpComparisonResult(InSegs, OutSegs, RetransSegs)` uses the shared public
`kernel_comparison.Eligibility(eligible, reason)` values. Malformed input raises
that module's `ComparisonError`. No MaxConn/CurrEstab, numeric differences, rates,
duration, baseline or confidence is returned.

## Validation and priority

Fully validate settings and both endpoints before outcomes, even with absent
opposites/missing siblings. Require exact wrapper/snapshot/reading types, string
reasons and unsigned observed integers in exact declared width 32/64. Missing
reasons require None; section_missing must apply to all three if any is. A Tcp
snapshot with all three field_missing is valid. Booleans/inconsistent dataclasses
reject atomically; comparison does not reparse text or infer file completeness.

Observed_at/as_of are exact Unix-second integers `0..2**63-1`, max_age an exact
integer `1..86400`, continuous an exact Boolean. Valid future/stale timestamps
yield reasons, not malformed-type errors. Both endpoints must be nonfuture/fresh
at evaluation; age equality is fresh, and current observation time must be later.

After full validation, each reading uses the first applicable condition:

| Condition | Ineligible reason |
| --- | --- |
| Current None, including both None | current_unavailable |
| Previous None | previous_unavailable |
| Current reading missing | current_field_missing / current_section_missing |
| Previous reading missing | previous_field_missing / previous_section_missing |
| Current / previous time after as_of | current_future / previous_future |
| Current / previous age greater than max_age | current_stale / previous_stale |
| Source differs | source_changed |
| Namespace differs | namespace_changed |
| Declared width differs | width_changed |
| Either generation None | generation_unknown |
| Known generations differ | generation_changed |
| Equal observation times, any values | duplicate_time |
| Current observation time earlier | out_of_order |
| continuity flag false | continuity_unconfirmed |
| This reading decreased | counter_decreased |
| Every prerequisite supplied | Eligible / prerequisites_declared |

Missing precedes shared timing/identity separately for each reading, but cannot
hide malformed data. Equal counts/zero can be eligible. One freshness budget
covers both endpoints: previous=100/current=160/as_of=161 needs at least max_age=61
for that freshness boundary, subject to the other prerequisites.

## Meaning and recovery

`continuous=True` attests the whole interval has the same physical source/counter
scope, namespace and uninterrupted lifetime, with no reset/wrap/change or omitted
missing/invalid event. Matching labels/generation are necessary but cannot prove
that testimony. Nondecreasing values prove no continuity; decrease identifies no cause.

Caller recovery is explicit: drop unusable endpoints after missing, invalid,
decreased or generation-changed intervals. None to a fresh sample remains
previous_unavailable; that fresh sample may start a new interval with a later one.
Never reconnect an older good sample when values/generation reappear. The helper
retains/clears no state and cannot detect false testimony or omitted events.

Only validated scalar reason policy is shared privately with netstat; the public
wrappers preserve parser-specific type/domain checks. Two endpoints, three fixed
readings and bounded labels produce one fixed result. No I/O, clocks, sorting,
maps, native collection or measured capacity is implied. For arithmetic see
[SNMP_DIFFERENCES](SNMP_DIFFERENCES.md).
