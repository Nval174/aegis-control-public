# Status and roadmap

The current implementation is an offline prototype. The application, normal regression suite
and synthetic fixtures are included here so readers can reproduce the behavior themselves.
The initial public snapshot's verification is recorded in [verification](VERIFICATION.md).

## Known test improvements

Four regression-suite improvements remain pending; they are not current production defects:

| ID | Next improvement |
| --- | --- |
| T1 | Assert literal codec byte/telemetry value limits independently of production constants |
| T2 | Require exact integer types for zero count and its available elapsed interval |
| T3 | Assert unrelated uint64 netstat values under declared 32-bit TcpExt width |
| T4 | Assert exact replay whole-file byte-limit acceptance and isolated +1 rejection |

The separate [contract checks](../checks/contract_regressions.py) demonstrate the stronger
assertions. They have not been integrated into the normal test modules. After those focused
improvements, the next design task is one bounded saved-input integration slice.

## Development phases

| Phase | Remaining objective |
| --- | --- |
| R0 - Discover | Resolve target profiles, topology, dependencies, availability/load/cost limits and recovery |
| R1 - Isolated baseline | Establish disposable target environment, legitimate connectivity and tested rollback |
| R2 - Observe | Integrate bounded collectors, observe-only detection and resource/fairness measurements |
| R3 - Local actions | Implement expiring leases, a single serialized writer, panic clear and independent recovery |
| R4 - Cloud edge | Validate supported provider controls, origin protection and remote-failure recovery |
| R5 - Gateway profile | Verify control placement, gateway compatibility, connectivity and rollback |
| R6 - Pilot/release | Run a narrow measured pilot with operating/recovery documentation |
| R7 - Optional extensions | Evaluate one justified extension at a time with independent benefit/rollback evidence |

R0 is incomplete. Portable code prepares later observation work; it does not complete R1-R7.
All runtime gates remain pending: inventory/configuration, syntax compatibility, legitimate
connectivity, IPv6/PMTUD, trusted attribution, control placement, operational modes, private-cache
isolation/fairness, actual recovery, API/release failure, panic-clear races and resource bounds.

There is no deployment or live protection claim. Future control-plane work must keep Python
outside forwarding, preserve original expiry, maintain one writer per target and distinguish
controller, writer, whole-host and remote-API failures.
