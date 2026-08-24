# Code maturity assessment

Assessment date: 2026-08-18. Scale: 0 absent, 1 initial, 2 developing, 3 established, 4 strong. This is a maintainer
self-assessment, not an independent audit.

| Category | Score | Current evidence | Remaining gap |
| --- | ---: | --- | --- |
| Arithmetic and precision | 4 | Registry values use safe integers; the production-route 10 bps identity is exact and tested | Economic correctness of submitted projects remains outside Registry arithmetic |
| Auditing and observability | 3 | Exact source, record hashes, immutable history, deterministic review receipts, CI receipts, and public review threads | No independent Launch Policy audit yet |
| Authentication and access control | 3 | Candidate identity binds to GitHub's immutable user id; the disabled Admission reference verifies audience-bound detached Ed25519 commands against a public trust snapshot and persists no credentials | Initial acceptance authority remains one maintainer; no public Admission key provisioning or remote worker/admin authorization plane exists |
| Complexity management | 3 | Closed schemas, bounded files, generated indexes, separate application and maintenance paths, one small dependency-free public review engine, and a separately bound Admission protocol | The vendored intake validator and SQLite reference are intentionally substantial and need continued differential testing |
| Decentralization and governance | 1 | Decisions are public and append-only | Initial acceptance authority is one maintainer; no independent quorum is established |
| Documentation | 4 | Architecture, discovery, open review rules, schemas, migration, contribution, support, and security contracts are explicit | Operational runbooks must stay synchronized with future website integration |
| Ordering and race resistance | 4 | PR merge parents, base/head commits, repository ids, trees, and stale-base behavior are bound; the Admission reference adds tenant/audience idempotency, revision equivocation checks, durable command replay, atomic events, and lease fencing | External GitHub availability remains a dependency; the queue has no multi-node serializability or clock proof |
| Low-level and unsafe operations | 4 | Blobless bounded Git handling, disabled hooks/filters/submodules, byte/time/process limits, no candidate execution under privileged CI, and bounded SQLite CAS/snapshot/GC integrity checks | OS resource hard stops retain one Linux-only test path; SQLite requires Node 24.12 and remains single-host |
| Testing and verification | 4 | Deterministic registry and decision tests, the complete trusted intake adversarial suite, store conformance tests, and an honest offline reference benchmark | Hidden mutation corpora, sustained/burst distributed load, production runner evidence, and an independent penetration review remain outstanding |

The repository release has public CI and protected-main evidence. Workflow Canary and the receipt-bound Hookbuilder
v0.10.3 six-file V2 transport remain only as historical compatibility surfaces. The checked-in intake state is
`closed`, and those records cannot satisfy Canary or Website eligibility. Local green
checks alone do not prove any deployed Website, production, funds, audit, or launch authority.

The authenticated Universal Admission protocol and SQLite backend are `reference-only-disabled`. Their discovery
contract binds exact same-tree bytes but publishes no endpoint, audience, trust snapshot, or live service. Offline
throughput and single-host invariants do not prove multi-node behavior, production capacity, availability, or one
million submissions per day.
