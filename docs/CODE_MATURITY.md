# Code maturity assessment

Assessment date: 2026-08-27. Scale: 0 absent, 1 initial, 2 developing, 3 established, 4 strong. This is a conservative
maintainer self-assessment of the checked-in Launch Policy repository, not an independent audit. It does not assess the
private Custom Launch API implementation, production operations, deployed contracts, wallets, or providers. Historical
GitHub application and disabled Universal Admission evidence do not raise the maturity score of the current V3 path.

| Category | Score | Current evidence | Remaining gap |
| --- | ---: | --- | --- |
| Arithmetic and precision | 2 | Closed schemas bound integer ranges; the policy and V3 admission descriptor project the exact `1000 / 1,000,000` rate and keep runtime fee-behavior claims false without private executable evidence | No published coverage, fuzz, or differential proof covers every arithmetic path, and this repository does not prove project or private API runtime economics |
| Auditing and observability | 2 | Canonical hashes, generated-projection checks, append-only Registry verification, and private vulnerability reporting provide repository-level traceability | No independent Launch Policy audit is recorded here; production API monitoring, alerts, incident exercises, and runtime evidence are outside this repository |
| Authentication and access control | 2 | Repository ownership is explicit; the V3 descriptor denies client, CLI, and agent admission authority and assigns executable evidence to the private API | Private API authentication, role separation, revocation, key-compromise handling, and wallet-controller enforcement are not implemented or proven in this repository; repository ownership remains centralized |
| Complexity management | 3 | Closed schemas, bounded inputs, generated projections, and the authority/import graph separate business policy, public V3 disclosure, private executable evidence, Registry, and historical compatibility | The legacy validator and disabled queue reference remain substantial, and no published complexity or differential result covers the private API implementation |
| Decentralization and governance | 1 | Central policy, Registry maintenance, and the private executable admission authority are named rather than hidden | Repository ownership and admission authority remain centralized; no independent quorum, timelock, or public governance process is established here |
| Documentation | 3 | Current docs separate V3 discovery/API creation, policy, admission disclosure, wallet action, promotion, and historical GitHub compatibility | Live external API surfaces can drift independently; operational implementation and incident runbooks are outside this repository and require separate evidence |
| Ordering and race resistance | 2 | The public V3 contract defines idempotent request handling and durable lifecycle states; the disabled queue reference tests replay, leases, fencing, and atomic events | The current private API's multi-node ordering, clock, retry, wallet, and finality behavior is not proven here; the checked-in queue remains `reference-only-disabled` |
| Low-level and unsafe operations | 3 | Historical Git readers use bounded process and byte handling without candidate execution; the SQLite reference checks CAS, snapshot, and garbage-collection integrity; the V3 descriptor exposes low-level hard-block and evidence boundaries | The private exact-source scanner and Router simulator are outside this repository; no independent differential or penetration evidence covers them, and one resource-limit path remains Linux-only |
| Testing and verification | 3 | The repository gate covers policy, schema, authority, Registry, historical compatibility, disabled queue conformance, and V3 descriptor cross-projections | No coverage or mutation report is published; current private API, runtime scanner, Router simulation, deployment, monitoring, and end-to-end wallet flows are not exercised by this repository |

Current launch creation starts at
[`https://programmable.market/.well-known/programmable.json`](https://programmable.market/.well-known/programmable.json),
follows its advertised V3 capabilities, checksum-bound CLI, guide, and OpenAPI, and submits CLI-produced request bytes
to `POST https://api.programmable.market/v3/custom-launches`. V1 creation is historical read-only compatibility and
returns non-retryable `409 CUSTOM_LAUNCH_V1_READ_ONLY`. GitHub application and Workflow Canary intake is closed.

Workflow Canary, Application V3.2 and V3.1, the six-file V2 transport, and their GitHub identity bindings remain only
historical compatibility evidence. The authenticated Universal Admission protocol and SQLite backend are
`reference-only-disabled`; their contract publishes no endpoint, audience, trust snapshot, or live service. Local
checks, public endpoint metadata, offline throughput, or single-host invariants do not prove protected-main status,
private API behavior, deployment, availability, audit, funds authority, or launch finality.

The next maturity step requires separately attributable evidence: an independent review of the public repository and
private execution boundary, tested production monitoring and incident response, documented key-compromise and role
recovery, and coverage, mutation, and end-to-end results for the exact current V3 state and wallet handoff paths.
