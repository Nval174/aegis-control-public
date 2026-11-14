# Saved netstat comparison eligibility

```text
compare_snapshots(previous, current, *, as_of, max_age=60, continuous=False)
```

`aegis_control.kernel_comparison` accepts None or exact frozen
`SnapshotSample(snapshot, observed_at)`, where snapshot is a `NetstatSnapshot`.
It returns frozen `ComparisonResult(ListenDrops, ListenOverflows)`, each an
`Eligibility(eligible, reason)`. True uses reason `prerequisites_declared`.
There are no returned values, duration, difference, baseline or inferred provenance.

Validate settings and both supplied objects before selecting any outcome, even
when the opposite endpoint is None. Malformed/inconsistent direct dataclasses
raise sanitized `ComparisonError` atomically. Observed readings require exact
unsigned integers in the declared width; missing readings require None and
section_missing must apply to both fields together.

Times are caller-declared exact Unix-second integers `0..2**63-1`;
max_age is exact integer `1..86400`, continuous exact Boolean. Freshness checks
both endpoints at as_of; equality is fresh. Current observation time must be
strictly later. No filename/mtime inference, clock read, sorting or arithmetic.

## First-match reason priority

Each counter is independent after full input validation. Shared checks apply to
both, but missing readings precede timing/identity checks.

| Condition | Ineligible reason |
| --- | --- |
| Current endpoint None | current_unavailable |
| Previous endpoint None | previous_unavailable |
| Current field/section missing | current_field_missing / current_section_missing |
| Previous field/section missing | previous_field_missing / previous_section_missing |
| Current / previous time after as_of | current_future / previous_future |
| Current / previous age greater than max_age | current_stale / previous_stale |
| Source differs | source_changed |
| Namespace differs | namespace_changed |
| Declared width differs | width_changed |
| Either generation unknown | generation_unknown |
| Known generations differ | generation_changed |
| Equal observation times, any values | duplicate_time |
| Current observation time earlier | out_of_order |
| continuous is false | continuity_unconfirmed |
| This counter decreased | counter_decreased |
| All prerequisites supplied | Eligible / prerequisites_declared |

Equal counts, including zero, may be eligible over a valid interval. A decrease
identifies no cause. One max_age applies to both endpoints: previous=100,
current=160, as_of=161 and max_age=60 gives previous_stale; max_age=61 passes that
boundary subject to every other prerequisite.

## Continuity and caller recovery

Capture source/namespace/generation/width are declarations. `continuous=True`
attests the entire interval has the same physical counter, scope and uninterrupted
lifecycle, with no reset/wrap/semantic change or omitted missing/invalid event.
Matching labels, generation, boot ID or nondecreasing values cannot authenticate
that testimony. Unknown generation remains insufficient even with the flag.

After an unavailable or malformed interval, discard the caller's endpoint and
begin a new interval from a later good sample. Do not bridge a missing/invalid
event using an older good endpoint. This stateless API cannot detect an omitted
event or false attestation, and never clears caller state automatically.

Only two fixed endpoints/two counters are examined; no history or stream map is
retained. Numeric widths remain those of the [parser](NETSTAT_SNAPSHOTS.md), not
the proxy telemetry ceiling. Bounded inputs are not measured capacity or verified
physical continuity. See [exact differences](KERNEL_DIFFERENCES.md) for arithmetic.
