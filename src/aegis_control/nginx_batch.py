"""Bounded saved-byte NGINX batches; no live ingestion or delivery assurance."""
from dataclasses import dataclass

from .nginx_access import (
    MAX_BYTES as MAX_RECORD_BYTES,
    NginxAccessRecord,
    NginxLogError,
    _validate_settings,
    parse_nginx_record,
)

MAX_BYTES = 1048576
MAX_RECORDS = 256


class NginxBatchError(ValueError):
    """Fatal batch envelope or declared settings failure."""


@dataclass(frozen=True)
class NginxBatchEntry:
    record_number: int
    state: str
    record: NginxAccessRecord | None
    reason: str


@dataclass(frozen=True)
class NginxBatchReport:
    entries: tuple[NginxBatchEntry, ...]
    total: int
    valid: int
    invalid: int
    state: str


def parse_nginx_batch(raw, *, service_id, catalog):
    """Decode independent records only after complete envelope preflight."""
    if type(raw) is not bytes:
        _fatal("raw_type")
    if len(raw) > MAX_BYTES:
        _fatal("total_bytes")
    count = raw.count(b"\n")
    if count > MAX_RECORDS:
        _fatal("record_count")
    if raw and not raw.endswith(b"\n"):
        _fatal("unterminated_tail")
    if b"\r" in raw.replace(b"\r\n", b""):
        _fatal("bare_cr")
    # Count was bounded before this list; retain at most 256 byte offsets.
    ends, start = [], 0
    for _ in range(count):
        end = raw.find(b"\n", start) + 1
        if end - start > MAX_RECORD_BYTES:
            _fatal("record_bytes")
        ends.append(end)
        start = end
    try:
        trusted = _validate_settings(service_id, catalog)
    except NginxLogError:
        raise NginxBatchError("NGINX batch rejected: invalid_settings") from None
    entries, valid, start = [], 0, 0
    for number, end in enumerate(ends, 1):
        row = raw[start:end]
        start = end
        try:
            record = parse_nginx_record(row, service_id=service_id, catalog=trusted)
        except NginxLogError:
            entries.append(NginxBatchEntry(number, "INVALID", None, "record_rejected"))
        else:
            entries.append(NginxBatchEntry(number, "VALID", record, "record_validated"))
            valid += 1
    invalid = count - valid
    state = "EMPTY" if not count else "HAS_INVALID" if invalid else "ALL_VALID"
    return NginxBatchReport(tuple(entries), count, valid, invalid, state)


def _fatal(token):
    raise NginxBatchError("NGINX batch rejected: " + token)
