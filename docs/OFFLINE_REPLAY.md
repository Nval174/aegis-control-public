# Synthetic telemetry, replay and coverage

These APIs process synthetic saved observations. They do not read live sensors,
calculate rates, infer service health or apply controls.

## Observation and route contract

`telemetry.parse_observation(data, service_ids, catalog, *, as_of, max_age)` returns
a frozen `Observation(service_id, source, metric, state, value, observed_at,
collected_at, route)`. Input has exactly those eight fields; no extras or raw IPs.
The service must be declared. Source is `proxy` or a disabled optional integration.

- `requests_total` is an exact cumulative integer; `latency_ms` is a finite
  nonnegative integer/float. Values are at most `10**12`; Booleans reject.
- Times are exact Unix-second integers in `0..2**63-1`. Collection must not be
  later than explicit `as_of`; observation must not follow collection.
- `OBSERVED` requires a value and observation time. `UNKNOWN` requires both null.
  Disabled optional sources require `NOT_APPLICABLE` and both null; `proxy` cannot
  use that state. Age greater than `max_age` becomes `STALE` with null value;
  equality remains fresh. `max_age` is `1..86400` seconds.

`normalize_route(route, catalog)` uses a catalog of 1-32 unique origin paths.
Paths are at most 2,048 characters, start with `/` rather than `//`, and contain no
controls. Catalog entries contain no query/fragment. Input queries/fragments are
stripped, matching is exact and case-sensitive, and unknown paths become `OTHER`.
There is no percent decoding, guessed template or retained original query/path.

## Replay APIs and limits

```text
replay_stream(stream, config, *, as_of, max_age=60, catalog=("/",))
replay_file(path, config, *, as_of, max_age=60, catalog=("/",))
```

Both live in `aegis_control.replay`. Use a validated observe-only TOML
[configuration](../configs/README.md). JSONL has one observation per line.

| Resource | Limit |
| --- | --- |
| Record, including its newline | 16,384 bytes |
| Complete input | 1,048,576 bytes |
| Records | 1,000 |
| Aggregate identities | 128 service/source/metric/normalized-route keys |

Duplicate JSON fields, invalid UTF-8/JSON, nonfinite values, schema errors or any
overflow reject the entire replay with sanitized `TelemetryError`; no successful
partial report. Blank lines are invalid records. Empty input returns `UNKNOWN`.
`replay_file` accepts regular local files, rejecting URL/UNC syntax. It assumes a
trusted local filesystem; path checks do not constitute a race/link sandbox.

Counts include all records. `latest` chooses greatest `collected_at`, with later
file order winning ties. Earlier degraded observations remain in historical counts.

| Report status | Meaning |
| --- | --- |
| UNKNOWN | Empty input |
| DEGRADED | Any supplied UNKNOWN or STALE observation |
| COMPLETE | Nonempty input without UNKNOWN/STALE observations |

Successful reports set `enforcement=false`, `input_validated=true` and
`runtime_readiness="untested"`. The CLI returns 0 only for COMPLETE with coverage
other than incomplete; 1 for degraded/empty/incomplete coverage or input error;
2 for usage errors. These are input-summary outcomes, not readiness certificates.

## Declared coverage

Schema 1 configuration reports `coverage=not_assessed`, `coverage_details=null`.
Schema 2 declares 1-64 unique required identities. Only `proxy` and the two metrics
above are supported. Each requirement names an exact catalog path or literal
`OTHER`; OTHER is not a wildcard. At most 32 distinct known paths are permitted,
and required known paths must be in the replay catalog before stream reads begin.

`coverage.assess_coverage(requirements, selected, *, as_of, max_age)` returns
coverage and bounded details. A selected fresh OBSERVED value, including zero,
satisfies only its exact identity. Missing, UNKNOWN and STALE remain distinct
unsatisfied reasons. A newer UNKNOWN supersedes an older usable value. Historical
status and current coverage are independent: DEGRADED/complete still exits 1;
COMPLETE/incomplete also exits 1.

Direct calls require an exact tuple/list of 1-64 exact `RequiredObservation`
values, unique by identity. A supplied selection may be an iterable; it is consumed
once and every item is validated, including unrelated observations. At most 128
unique selections are retained; a 129th item rejects without requesting a 130th.
Malformed/duplicate values or iteration failures raise sanitized `TelemetryError`.
With `requirements=None`, clocks still validate but selection is not consumed.
Trusted Python iterator code is not sandboxed and can block in `next()`.

Direct dataclasses are revalidated before hashing/sorting/arithmetic. Valid STALE
objects retain a bounded observation time and null value; re-evaluation cannot
restore discarded values. Details contain counts and lexically sorted identity
rows with `satisfied`, `missing`, `unknown` or `stale`, never fabricated readings.

The [counter API](COUNTER_DELTAS.md) is separate: replay's collection-time selection
and OTHER bucketing cannot establish ordered physical counter continuity. Limits
are support choices, not measured memory, throughput or live compatibility.
