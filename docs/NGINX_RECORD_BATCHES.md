# Saved NGINX record batches

```text
parse_nginx_batch(raw, *, service_id, catalog)
```

`aegis_control.nginx_batch` accepts exact saved bytes, not a path/stream/iterator.
It validates the complete physical envelope and caller settings before decoding
any row through the [single-record API](NGINX_ACCESS_RECORDS.md). Expected row
rejections remain visible; global failures return no report. Unexpected exceptions
propagate rather than being disguised as rejected records.

## Bounds, framing and fatal priority

| Resource | Support limit |
| --- | --- |
| Total input | 1,048,576 bytes before split/decode |
| Physical records | At most 256 LF delimiters |
| Each row | 16,384 bytes including its LF/CRLF |
| Result rows | Exactly one per supplied physical record |

Empty bytes is the only zero-record envelope. Nonempty input must end in LF;
CRLF is allowed. Its final LF completes a record without creating another entry.
An additional LF is a real blank record: `b"\n"` produces one INVALID position.
A final unterminated row is fatal even if standalone JSON would be accepted.

Only physical LF delimits rows. CR is allowed only immediately before LF; any
bare CR is fatal, including in malformed JSON. JSON backslash-r escape bytes are
not a physical CR. Do not decode the whole document before row handling: a
conforming invalid-UTF-8 row must remain a visible rejection. Preserve duplicate
rows and timestamp order; do not sort or deduplicate.

First failing preflight selects a fixed `NginxBatchError` message
`NGINX batch rejected: <token>`:

| Priority | Token |
| --- | --- |
| Exact raw type | raw_type |
| Total byte cap | total_bytes |
| LF-count cap, before constructing a split/offset list | record_count |
| Final LF completeness | unterminated_tail |
| Physical CR placement | bare_cr |
| Every row's terminator-inclusive length | record_bytes |
| Service/catalog validation, including empty input | invalid_settings |

All envelope checks finish before any decoder call. Caller settings use the record
profile and are snapshotted to a tuple before row handling. Invalid settings are
fatal, not INVALID rows; no dummy record is used to validate an empty batch.

## Immutable result contract

`NginxBatchEntry(record_number, state, record, reason)` is frozen, with one-based
consecutive physical positions:

| Row outcome | Entry |
| --- | --- |
| Accepted by real record decoder | VALID / NginxAccessRecord / record_validated |
| Expected row-level NginxLogError | INVALID / None / record_rejected |
| Unexpected programming/system exception | Propagates; no prefix report |

Blank rows, malformed encoding/JSON, unsupported schema/status/time/URI values are
row-level rejections only when their physical envelope conforms. Supported unknown
or query/fragment-bearing paths are accepted as OTHER, not invalid.

Frozen `NginxBatchReport(entries, total, valid, invalid, state)` has tuple entries,
total=len(entries), valid+invalid=total, and EMPTY for zero entries, ALL_VALID for
nonzero/all-valid entries, or HAS_INVALID whenever any row rejects. An all-invalid
batch remains nonempty HAS_INVALID, not empty/no traffic. These are decode
diagnostics, not HTTP traffic measurements or an application CLI exit policy.

## Privacy and limits

Accepted entries preserve exactly the five bounded record-result fields. Invalid
positions retain no bytes, partial object, field name, URI, hash or exception text.
Only trusted catalog routes or OTHER appear. The API does not sanitize producer
files, erase caller bytes, authenticate the catalog or guarantee complete delivery.
LF framing cannot detect a wholly omitted complete record.

No cross-call state, queue, clock, history, aggregation, rates, native ingestion or
enforcement exists. Bounds are development support choices, not measured RSS,
throughput or universal producer compatibility. Synthetic fixtures in
[nginx-batch-design](../tests/fixtures/nginx-batch-design/) retain literal expected
results separately from the actual batch bytes; intentionally malformed inputs
must not be normalized or treated as executable data.
