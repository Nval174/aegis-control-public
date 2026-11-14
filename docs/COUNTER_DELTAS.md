# Pure counter transitions

```text
advance_counter(previous, current, *, as_of, max_age=60, continuous=False)
```

`aegis_control.counters` accepts `None` or exact frozen
`CounterSample(observation, counter_id, generation)` endpoints. `observation` is
an exact frozen `Observation`. Metadata tokens use 1-64 ASCII alphanumeric,
underscore or hyphen characters, beginning alphanumeric; supply nonsecret labels.

Only fresh `proxy/requests_total` on a known route can produce arithmetic.
`latency_ms` is gauge-like; `OTHER` merges paths and is ineligible. Disabled sources
remain NOT_APPLICABLE. Counts are exact integers `0..10**12`, never Booleans.
Times are exact Unix-second integers `0..2**63-1`, with
`observed_at <= collected_at <= as_of`; `max_age` is `1..86400` seconds.
Both observation ages must be within the same max_age, including equality.
Current observation time must strictly exceed previous observation time;
inter-endpoint collection-time order does not define arithmetic chronology.

## Continuity and result priority

`continuous=True` attests the entire interval uses the same physical counter and
scope, uninterrupted lifetime and measurement semantics, without restart, wrap,
change or omitted missing/invalid event. Identity, counter_id and generation must
also match. Labels and nondecreasing values cannot prove that testimony.

All settings and supplied endpoints validate before result selection. Malformed
input raises sanitized `CounterError` with no result. For valid inputs, first
matching condition wins:

| Condition | Outcome |
| --- | --- |
| Current missing, unknown, stale, N/A, not a counter or OTHER | UNAVAILABLE / corresponding current reason |
| No prior baseline | BASELINE / no_prior_baseline |
| Previous unknown, stale, N/A, not a counter or OTHER | UNAVAILABLE / corresponding previous reason |
| Different service/source/metric/route identity | UNAVAILABLE / identity_changed |
| Different counter_id | UNAVAILABLE / counter_changed |
| Different generation | UNAVAILABLE / generation_changed |
| No explicit continuity assertion | UNAVAILABLE / continuity_unconfirmed |
| Equal observation times and equal values | UNAVAILABLE / duplicate_time |
| Equal observation times and different values | UNAVAILABLE / conflicting_time |
| Current observation time earlier | UNAVAILABLE / out_of_order |
| Current value decreased | UNAVAILABLE / counter_decreased |
| All prerequisites supplied | AVAILABLE / difference |

Frozen `CounterDelta(state, reason, count, elapsed_seconds, next_baseline)` carries
exact nonnegative count and positive observation-time difference only when AVAILABLE.
BASELINE carries the current sample but no numeric difference. UNAVAILABLE has
null count, elapsed time and next_baseline. Decrease has unknown cause; no wrap,
reset or attack diagnosis is invented. Equal values, including zero, can produce
a genuine available zero difference over a valid interval.

## Caller recovery

Retain only `result.next_baseline`. Feed every relevant event, including missing
ones; clear the caller's baseline on `CounterError`. After a break, the next good
sample establishes a baseline and only a later good interval yields arithmetic.
Never retrieve an older good endpoint to bridge a failure.

The one shared freshness budget covers both endpoints: previous=100, current=160,
as_of=161 and max_age=60 rejects the previous age of 61; max_age=61 passes that
boundary subject to all other prerequisites. Stored presence is not usability.

This stateless API cannot detect omitted events, false testimony or resurrect
discarded STALE values. It computes counts, not rates, and performs no I/O or clock
reads. Raw [coverage](OFFLINE_REPLAY.md) does not imply an available delta. The
[sequence API](COUNTER_SEQUENCES.md) adds bounded declared-delivery discipline.
