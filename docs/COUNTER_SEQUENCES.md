# Bounded synthetic counter sequences

```text
run_counter_sequence(events, *, max_keys=16, retention_seconds=60, max_age=60)
validate_sequence_events(events, *, max_keys=16, retention_seconds=60, max_age=60)
validate_stream_key(key)
```

These `aegis_control.counter_sequence` APIs use existing counter/telemetry rules.
The runner snapshots a finite exact list/tuple of frozen
`SequenceEvent(key, sequence, at, sample, continuous=False, kind="sample")` objects
and processes them in supplied order. No arbitrary iterator, callback or I/O.
`validate_sequence_events` returns the bounded envelope snapshot without processing
state; `validate_stream_key` validates a key without processing a stream.

`StreamKey(service_id, source, metric, route)` is exact logical identity, separate
from payload counter_id/generation. A payload must match its destination key.
Generation/producer changes use the same slot, preventing old-generation lookup.
Optional sources, gauges and OTHER may be valid keys but cannot yield differences.

## Delivery and failures

Sequence numbers are exact positive integers `1..2**63-1` per key, across generation
changes. The first retained event is `unanchored`; only high-water+1 is `adjacent`.
A higher gap, duplicate or lower number clears the baseline and discards the current
candidate. High-water never decreases while retained; the next adjacent good event
is baseline-only. Do not sort, deduplicate or omit relevant events.

`sample=None` declares missing data. `kind="break"` requires sample=None and clears
that stream. Malformed payload/kind/continuous or mismatched payload identity with
a valid envelope returns UNAVAILABLE/invalid_payload, consumes valid delivery
metadata and clears only that baseline. Envelope/key/sequence/time/settings errors,
backward global evaluation time or overflow raise sanitized `SequenceError` and
return no batch report.

`continuous=True` remains separate physical-continuity testimony under the
[counter contract](COUNTER_DELTAS.md). Adjacent declared numbers cannot authenticate
delivery or detect an undisclosed restart. Reports state
`delivery_scope="declared_sequence_only"`.

## Retention, clocks and bounds

Event `at` is an explicit Unix-second evaluation time, globally nondecreasing;
equal instants are allowed. Observation/collection times remain distinct and
validate against each event's at. Arithmetic orders observation times, not sequence
numbers or evaluation/collection time.

Before every event, expire whole entries when `at-last_seen > retention_seconds`;
equality is retained. Delete baseline, sequence high-water and last_seen together.
Purge before admission. At capacity, a new key evicts minimum
`(last_seen, lexicographic StreamKey)`. Reappearance after expiry/eviction is
unanchored and baseline-only. Missing/invalid events refresh delivery retention
while clearing the sample, not extending sample freshness.

| Resource | Limit |
| --- | --- |
| Events/results | At most 256, one row per event |
| Entire retained map | max_keys 1-64, default 16 |
| Delivery retention | 1-86,400 seconds, default 60 |
| Arithmetic freshness | 1-86,400 seconds, default 60 |
| Sequence and time domains | Existing bounded exact integer rules |
| Discard diagnostics per row | expired_count and at most one evicted key |

An inactive stored baseline may reach retention_seconds+max_age at processing
boundaries; it never remains arithmetically usable beyond max_age. Presence means
storage only. The next transition applies normal reason priority and clears an
unusable baseline. A generation sequence A-B-A never restores the first A sample.

Frozen `SequenceReport(results, retained, peak_streams, delivery_scope)` contains
tuple rows with key/sequence/at, delivery, state/reason/count/elapsed_seconds,
baseline_present, expired_count and evicted key. Sorted `RetainedStream` summaries
hold key, last_sequence, last_seen and baseline_present, not samples. Outputs do
not retain arbitrary payloads or next_baseline objects. Summaries reflect the last
event's at, without subsequent wall-clock aging.

All state is local to one invocation; no cross-batch checkpoint or resume exists.
Fatal failures are atomic. These bounds are support limits, not measured capacity.
The [fixture codec](SEQUENCE_FIXTURES.md) is the separate strict bytes boundary.
