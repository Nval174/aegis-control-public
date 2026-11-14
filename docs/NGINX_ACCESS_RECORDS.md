# Saved NGINX access-record profile

`aegis_control.nginx_access.parse_nginx_record(raw, *, service_id, catalog)`
accepts exact bytes, a trusted nonsecret service ID and an exact tuple/list of
trusted nonsecret catalog routes. It returns frozen
`NginxAccessRecord(service_id, route, status, logged_at_ms, request_time_ms)`.
`NginxLogError` rejects atomically with fixed diagnostics; raw URI/object/bytes and
unknown fields are not retained.

The exact wire object has five fields:

```json
{"schema_version":1,"msec":"100.000","uri":"/login","status":"200","request_time":"0.025"}
```

Schema_version is exact integer 1; the other fields are exact strings. Missing,
extra, duplicate/escape-equivalent, empty, hyphen or wrong-type fields reject.
This profile accepts no IP, request line, upstream timing or additional fields.

| Boundary | Limit / grammar |
| --- | --- |
| Raw bytes including final terminator | 16,384 before decoding |
| Structure | One flat JSON object, exactly five unique fields |
| Decoded field name | At most 32 characters |
| JSON numeric token | At most 20 characters before integer conversion; floats/constants reject |
| URI/catalog path | 1-2,048 Unicode characters |
| Service ID | `[A-Za-z0-9][A-Za-z0-9_-]{0,63}` |
| Catalog | Exact tuple/list of 1-32 unique entries |
| Time token | 1-16 ASCII seconds digits, dot, exactly three ASCII fraction digits |
| Converted time | Exact integer `0..2**63-1` milliseconds |
| Status | Exactly three ASCII digits, 100-599 |

Leading time zeros are accepted within bounds. Convert with integer
seconds*1000+fraction; no floating point. Maximum is `9223372036854775.807`;
`.808` exceeds it. Zero remains observed zero. Status 000/009 are unsupported even
though a producer can emit them. Limits describe support, not measured capacity.

## Framing and privacy

Accept no terminator or exactly one final LF/CRLF within the byte cap, then reject
physical CR/LF inside. Outer/token space-tab is accepted; whitespace-only rejects.
Decode strict UTF-8 without BOM, unpaired surrogates or decoded C0/C1 controls
(U+0000-001F and U+007F-009F). A quote/escape-aware flat-container preflight rejects
nesting/arrays; JSON parsing validates complete syntax and trailing content. All
bytes validate; a good prefix plus malformed suffix is not a successful record.

Catalog paths start with `/`, not `//`, and contain no query/fragment, controls or
surrogates. Supported input URIs containing `?` or `#` become OTHER. Otherwise an
exact catalog match returns that route; every other supported path becomes OTHER.
Unsupported path forms are fatal. No percent decoding, case folding, path/template
matching, dot/slash resolution or Unicode normalization occurs.

This intentionally differs from [telemetry's query stripping](OFFLINE_REPLAY.md).
Returned records retain only catalog routes or OTHER. Trusted service/catalog
values are not authenticated or secret-scanned. This does not sanitize raw logs,
erase caller bytes or establish universal memory secrecy. Diagnostics omit input
names/values/paths and parser excerpts; raw URI values disappear from result repr
and serialization. A queryless producer path can still contain private data.

## Producer mapping and source references

The profile maps literal schema_version=1 and quoted `$msec`, `$uri`, `$status`,
`$request_time`. `escape=json` escapes variable contents; log_format must supply
the surrounding structure and quotes. This document does not provide a deployed
or runtime-validated logging configuration.

[Log module documentation](https://nginx.org/en/docs/http/ngx_http_log_module.html)
describes buffered/conditional writes, logging time and request completion/client
transfer. Request_time is not origin-only latency; neither time is collector arrival
or proof of freshness/delivery completeness. [URI semantics](https://nginx.org/en/docs/http/ngx_http_core_module.html#var_uri)
include normalization/internal redirects. [Upstream timings](https://nginx.org/en/docs/http/ngx_http_upstream_module.html#var_upstream_response_time)
can represent multiple attempts and are outside this profile.

Pinned [log-module source](https://github.com/nginx/nginx/blob/release-1.24.0/src/http/modules/ngx_http_log_module.c)
and [JSON escaping](https://github.com/nginx/nginx/blob/release-1.24.0/src/core/ngx_string.c)
explain why empty variables, special status values and byte-oriented escaping
cannot be silently treated as this parser's narrower UTF-8/status profile.
No live collection, delivery trust, count/rate, health or protection result follows.
