"""Pure saved access-record boundary; project profile 1 (not a live collector)."""
from dataclasses import dataclass
import json
import re

from .config import SERVICE_ID

MAX_BYTES = 16384
MAX_PATH = 2048
MAX_CATALOG = 32
MAX_FIELD_NAME = 32
MAX_NUMBER_TOKEN = 20
MAX_MILLISECONDS = 2**63 - 1
_FIELDS = frozenset(("schema_version", "msec", "uri", "status", "request_time"))
_TIME = re.compile(r"[0-9]{1,16}\.[0-9]{3}", re.ASCII)
_STATUS = re.compile(r"[0-9]{3}", re.ASCII)


class NginxLogError(ValueError):
    """The supplied record or declared settings do not meet the project profile."""


@dataclass(frozen=True)
class NginxAccessRecord:
    service_id: str
    route: str
    status: int
    logged_at_ms: int
    request_time_ms: int


def _supported_text(value):
    return not any(ord(char) < 32 or 127 <= ord(char) <= 159
                   or 0xD800 <= ord(char) <= 0xDFFF for char in value)


def _path(value):
    return (type(value) is str and 1 <= len(value) <= MAX_PATH
            and value.startswith("/") and not value.startswith("//")
            and _supported_text(value))


def _flat_object(text):
    """Bound nesting before JSON parsing; quoted containers remain contents."""
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char == "[" or char == "]":
            raise NginxLogError("invalid structure")
        elif char == "{":
            depth += 1
            if depth > 1:
                raise NginxLogError("invalid structure")
        elif char == "}":
            depth -= 1
            if depth < 0:
                raise NginxLogError("invalid structure")
    if quoted or depth:
        raise NginxLogError("invalid structure")


def _object(pairs):
    result = {}
    for name, value in pairs:
        if len(name) > MAX_FIELD_NAME:
            raise NginxLogError("field name limit")
        if not _supported_text(name):
            raise NginxLogError("invalid fields")
        if name in result:
            raise NginxLogError("duplicate field")
        if len(result) == len(_FIELDS):
            raise NginxLogError("invalid fields")
        result[name] = value
    return result


def _integer(token):
    if len(token) > MAX_NUMBER_TOKEN:
        raise NginxLogError("numeric token limit")
    return int(token)


def _number_rejected(token):
    if len(token) > MAX_NUMBER_TOKEN:
        raise NginxLogError("numeric token limit")
    raise NginxLogError("invalid number")


def _milliseconds(value):
    if type(value) is not str or len(value) > 20 or not _TIME.fullmatch(value):
        raise NginxLogError("invalid time")
    seconds, fraction = value.split(".")
    result = int(seconds) * 1000 + int(fraction)
    if result > MAX_MILLISECONDS:
        raise NginxLogError("invalid time")
    return result


def _validate_settings(service_id, catalog):
    """Validate trusted declarations and snapshot the bounded catalog."""
    if type(service_id) is not str or not SERVICE_ID.fullmatch(service_id):
        raise NginxLogError("invalid service")
    if type(catalog) not in (tuple, list) or not 1 <= len(catalog) <= MAX_CATALOG:
        raise NginxLogError("invalid catalog")
    paths = tuple(catalog)
    trusted = set()
    for path in paths:
        if not _path(path) or "?" in path or "#" in path or path in trusted:
            raise NginxLogError("invalid catalog")
        trusted.add(path)
    return paths


def parse_nginx_record(raw, *, service_id, catalog):
    """Decode one record without retaining private URI content."""
    if type(raw) is not bytes:
        raise NginxLogError("invalid bytes")
    if len(raw) > MAX_BYTES:
        raise NginxLogError("byte limit")
    trusted = _validate_settings(service_id, catalog)
    if raw.endswith(b"\r\n"):
        raw = raw[:-2]
    elif raw.endswith(b"\n"):
        raw = raw[:-1]
    if b"\r" in raw or b"\n" in raw:
        raise NginxLogError("invalid framing")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise NginxLogError("invalid encoding") from None
    _flat_object(text)
    try:
        fields = json.loads(text, object_pairs_hook=_object, parse_int=_integer,
                            parse_float=_number_rejected, parse_constant=_number_rejected)
    except json.JSONDecodeError:
        raise NginxLogError("invalid JSON") from None
    if type(fields) is not dict or fields.keys() != _FIELDS:
        raise NginxLogError("invalid fields")
    if type(fields["schema_version"]) is not int or fields["schema_version"] != 1:
        raise NginxLogError("invalid version")
    logged_at_ms = _milliseconds(fields["msec"])
    request_time_ms = _milliseconds(fields["request_time"])
    status = fields["status"]
    if type(status) is not str or not _STATUS.fullmatch(status) or not 100 <= int(status) <= 599:
        raise NginxLogError("invalid status")
    uri = fields["uri"]
    if not _path(uri):
        raise NginxLogError("invalid uri")
    route = uri if "?" not in uri and "#" not in uri and uri in trusted else "OTHER"
    return NginxAccessRecord(service_id, route, int(status), logged_at_ms, request_time_ms)
