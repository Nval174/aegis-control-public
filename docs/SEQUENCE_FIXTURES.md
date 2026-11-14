# Synthetic sequence fixture schema

`aegis_control.sequence_fixture.decode_sequence_fixture(raw)` accepts exact bytes
and returns frozen `DecodedSequenceFixture(settings, events)`, where settings is
`SequenceSettings(max_keys, retention_seconds, max_age)` and events is a tuple of
existing immutable sequence objects. `run_sequence_fixture(raw)` fully decodes
before invoking `run_counter_sequence`. Neither API reads files or clocks.

## Required wire shape

Every field is mandatory; unknown fields, defaults and coercion are rejected.

```text
root = {schema_version: 1, settings, events}
settings = {max_keys, retention_seconds, max_age}
events = [event, ...]
event = {key, sequence, at, sample, continuous, kind}
key = {service_id, source, metric, route}
sample = null | {counter_id, generation, observation}
observation = {service_id, source, metric, state, value,
               observed_at, collected_at, route}
```

Version is exact integer 1. Settings use the [sequence bounds](COUNTER_SEQUENCES.md).
Sequence is `1..2**63-1`; at/collected_at are Unix-second integers `0..2**63-1`;
observed_at is null or that integer domain. continuous is Boolean. kind is `sample`
or `break`; break requires null sample. A sample-kind null means missing data.

IDs/tokens are 1-64 ASCII alphanumeric/underscore/hyphen, beginning alphanumeric.
Sources are proxy or the four disabled optional names; metrics are requests_total
or latency_ms. Routes must already be canonical bounded paths or literal OTHER:
query/fragment-bearing paths reject rather than normalize. States are OBSERVED,
UNKNOWN, STALE or NOT_APPLICABLE. Values are null or finite nonnegative numbers
at most `10**12`; requests_total requires an integer. Booleans are not integers.

## Bounds and atomic failures

| Boundary | Limit |
| --- | --- |
| Raw bytes before decode | 1,048,576 |
| Encoding | Strict UTF-8, no BOM or unpaired escaped surrogates |
| Container nesting | 5 |
| Object fields / decoded field-name length | 8 / 64 Unicode scalar characters |
| String length | 2,048 Unicode scalar characters, plus tighter ID rules |
| Arrays/events | 256 |
| Integer token | 20 characters before field-specific range checking |

A quote/escape-aware depth preflight precedes JSON parsing; negative depth or an
unfinished depth/string/escape state rejects. JSON parsing still validates full
syntax and matching bracket types. Duplicate names, including escape-equivalent
ones, reject at every object. Nonfinite constants, overflowing floats, trailing
documents, malformed encoding/types/schema or out-of-range fields raise sanitized
`FixtureError`, with no values, paths or parser excerpts in public diagnostics.

Malformed keys/settings/envelopes and backward global evaluation chronology are
fatal, including errors late in an otherwise valid prefix. No decoded batch or
successful partial report escapes, and the runner is not called on decode failure.

Well-typed semantic contradictions are preserved for the runner: OBSERVED/null,
bad time ordering, future collection, STALE/non-null, source/state conflict or a
payload identity differing from its key produces invalid_payload, consumes declared
delivery and clears that known stream. They are not repaired into missing, zero
or usable observations. Missing, UNKNOWN, STALE and N/A remain distinct.

The codec adds no second counter engine, sorting, deduplication or cross-call state.
Sequence adjacency/continuous are declarations, not provenance or reset detection.
Bounds do not establish measured memory/CPU capacity.

## Examples

[Minimal](../tests/fixtures/sequence-v1.minimal.json) has one fresh zero sample;
[recovery](../tests/fixtures/sequence-v1.recovery.json) exercises invalidation and
recovery. [Invalid](../tests/fixtures/sequence-v1.invalid.json) has a Boolean final
sequence and must return no successful report. Older direct-API oracle files are
not this wire schema.

```python
from aegis_control.sequence_fixture import MAX_FIXTURE_BYTES, run_sequence_fixture

with open("../tests/fixtures/sequence-v1.recovery.json", "rb") as stream:
    raw = stream.read(MAX_FIXTURE_BYTES + 1)
report = run_sequence_fixture(raw)
```

The example assumes a trusted local regular fixture. See
[COUNTER_SEQUENCES](COUNTER_SEQUENCES.md) for result and retention semantics.
