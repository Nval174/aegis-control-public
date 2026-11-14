# AegisControl

An experimental defensive control-plane prototype built with the Python standard library.
It validates bounded synthetic observations and saved Linux/NGINX data. It does **not**
currently collect live traffic, detect attacks operationally or apply mitigation.

Python is intended to coordinate native controls outside packet forwarding and request proxying.
This public edition contains the application, synthetic examples, tests and API contracts;
it contains no deployed configuration, personal inventory or recorded machine output.

## What works

| Area | Implemented behavior |
| --- | --- |
| Diagnostics/configuration | Read-only local doctor; strict observe-only TOML validation |
| Telemetry/replay | Immutable observations, route normalization, freshness and required-source coverage |
| Counter processing | Exact conditional differences, baseline invalidation, bounded sequence/fixture APIs |
| Saved Linux inputs | TcpExt, TCP SNMP, conntrack occupancy/max and selected-interface statistics |
| Saved NGINX inputs | Privacy-bucketed JSON records and bounded batches with visible rejected rows |

These are separate building blocks. Saved parsers are not automatically wired into replay
or a live collector. See [architecture](docs/ARCHITECTURE.md) for data flow and source navigation,
[status/roadmap](docs/STATUS.md) for remaining work, and the linked API contracts for exact rules.

## Run locally

Use a working Python 3.12 interpreter. No third-party runtime packages are required.
Create the environment from the repository root:

```sh
python -m venv .venv
```

PowerShell:

```powershell
Set-Location src
& ..\.venv\Scripts\python.exe -B -m aegis_control doctor
& ..\.venv\Scripts\python.exe -B -m aegis_control config-check ..\configs\observe.example.toml
& ..\.venv\Scripts\python.exe -B -m aegis_control replay ..\configs\observe.example.toml ..\tests\fixtures\replay.example.jsonl --as-of 160 --route / --route /login
```

POSIX shell:

```sh
cd src
../.venv/bin/python -B -m aegis_control config-check ../configs/observe.example.toml
../.venv/bin/python -B -m aegis_control replay ../configs/observe.example.toml ../tests/fixtures/replay.example.jsonl --as-of 160 --route / --route /login
```

The doctor reports the machine where **you run it**. Review its output before sharing.
Configuration success means static validity; optional integrations and enforcement stay disabled.

## Verify

From `src/`, use the same environment interpreter:

```powershell
& ..\.venv\Scripts\python.exe -B -m unittest discover -s ..\tests -v
& ..\.venv\Scripts\python.exe -B ..\checks\contract_regressions.py
```

POSIX equivalents are `../.venv/bin/python -B -m unittest discover -s ../tests -v`
and `../.venv/bin/python -B ../checks/contract_regressions.py`.
The second command is a separate set of contract checks, not part of normal test discovery.
Fixtures are synthetic, including intentionally malformed records and explicit fake secret markers.

## Boundaries

There is no operational detector, lease ledger, enforcer, daemon, dashboard or provider adapter.
Missing/UNKNOWN/STALE data never becomes a fabricated zero. Counter continuity remains caller
testimony; saved metadata cannot authenticate it. Resource bounds are design limits, not measured
production capacity. NGINX output bucketing does not erase raw producer logs.

Runtime connectivity, recovery, fairness and load gates remain pending. A local filter cannot
restore already-saturated upstream bandwidth, and CDN origins must not kernel-ban viewer IPs
based on proxy transport addresses. See [usage rights](NOTICE.md).
