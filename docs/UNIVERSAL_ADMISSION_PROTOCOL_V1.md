# Universal Admission Protocol V1

This document defines the authenticated reference transport around the project-neutral
[Universal Admission envelope](UNIVERSAL_ADMISSION_V1.md). It is an operational queue protocol, not a second launch
policy, project allowlist, security review, scam decision, or launch authority.

## Current status

The protocol and its Node SQLite implementation are checked-in reference code only. The public discovery contract at
`.programmable/universal-admission-contract.v1.json` binds the exact schemas and implementation bytes and states:

- `deployment.state` is `reference-only-disabled`;
- `deployment.enabled` is false;
- endpoint, audience, and trust snapshot are null;
- the topology is `single-host-single-writer`; and
- every review, audit, safety, approval, deployment, and launch authority flag is false.

No public service is claimed. The reference benchmark is not multi-node, not an uptime or burst test, and not evidence
that one million submissions per day are supported in production.

## Closed public surface

The discovery contract binds these roles at one exact Launch Policy commit:

- the Universal Admission envelope;
- detached-Ed25519 enqueue command and public trust snapshot;
- runtime-capacity policy;
- immutable queue event receipt;
- trusted-service transport readback;
- worker result;
- bounded snapshot; and
- command, protocol, service, and SQLite reference artifacts.

Consumers must resolve every path from the same exact commit and verify every SHA-256 binding before interpreting it.
The legacy active contract, Applicant Compatibility V1, and Application V3.1 are independent contracts and are not
silently extended by this protocol.

## Authenticated enqueue

The reference service performs one closed journey:

```text
canonical envelope bytes
        + detached Ed25519 command and signature
        + exact public trust snapshot
        -> bounded byte snapshots
        -> command, audience, lifetime, signer, tenant, subject, request, revision,
           envelope digest, and capacity-policy verification
        -> one atomic queue-store submit
        -> immutable queued event plus trusted-service readback
```

The command is short-lived and binds one operation, `enqueue`. The verified signer becomes a provenance-sealed
principal context; caller-shaped JSON cannot manufacture that service context. Credentials and private keys are never
part of an envelope, trust snapshot, store record, event, or public readback.

The returned transport receipt is intentionally `independentlyVerifiable: false`: it binds the authenticated command
to the immutable queue event the store returned atomically, but it carries no service signature or transparency anchor.
It reports `QUEUED` or an exact `DUPLICATE`; neither status means reviewed, accepted, safe, approved, deployed, or live.

## Identity, replay, and capacity

Application revision identity is bound to tenant, audience, application id, revision, and envelope digest. A different
digest for the same bound revision fails as equivocation. Idempotency is tenant- and audience-scoped, so identical
public envelope bytes from different tenants do not collide.

An exact request-id replay returns its prior bounded response without a second transition. A request id reused with a
different command or principal fails closed. New authenticated request ids consume bounded request-count and byte
budgets even when the underlying revision is a duplicate, preventing replay metadata from becoming an unbounded bypass.

The signed command pins the exact runtime-capacity-policy SHA-256. The store checks that precondition before any replay,
quota, CAS, job, or receipt mutation. Runtime limits cover authenticated ingress, replay retention and bytes, new jobs,
outstanding and leased work, durable commands, lease duration and renewal, retry, redrive, terminal payloads, dead-letter
payloads, snapshots, garbage collection, CAS bytes, and total database bytes. These are provider protections, not
semantic reasons to reject a project category.

## Queue state machine

Each state transition appends one immutable, hash-linked event receipt. The reference state machine includes:

```text
queued -> leased -> completed
                  -> retry scheduled -> leased
                  -> dead-lettered -> redriven -> queued
```

Claims and renewals use lease ids plus monotonic fence tokens. A stale, expired, or differently bound worker cannot
complete or fail the current lease. Retry delays and attempts are bounded; redrive requires the expected dead-letter
receipt and is available only inside the configured payload-retention window. Expired terminal and dead-letter payloads
may become garbage-collection candidates without rewriting the immutable event history.

Every mutating worker or maintenance operation uses a caller-supplied command id with durable replay semantics. The
private reference API still accepts in-process worker and administrative contexts; it does not publish a network
authentication scheme for them. A future remote adapter must add protected worker/admin commands, audience checks,
authorization, revocation, rate limits, and audit attribution before exposure.

## Snapshots and garbage collection

A snapshot commits a bounded root over GC-control records and a bounded candidate manifest. It is not a full database
backup, queue-consensus checkpoint, review decision, or public transparency proof. Garbage collection rechecks the
snapshot, candidate digest, byte length, generation, and current live references before deletion. Conflicts are skipped
and reported rather than forced.

SQLite integrity checks recompute stored object digests and lengths inside one consistent read transaction. Snapshot,
audit, CAS, command, and database budgets remain hard limits so the reference cannot silently accumulate unbounded
metadata.

Those checks prove structural self-consistency inside the trusted local store; they are not a MAC, service signature,
append-only transparency log, or external authenticity anchor. Durable errors are limited to a closed vocabulary for
their command kind and remain bound to the exact request preimage, but the reference does not independently prove the
historical cause of an error after later state changes. A production adapter that treats storage as hostile must add an
authenticated append log or equivalent externally anchored integrity mechanism before making such a claim.

## SQLite reference boundary

The SQLite backend requires Node.js 24.12 or later and uses one local database owned by one trusted process. It is suited
to deterministic conformance testing and offline measurement. It is not a distributed queue, hosted service,
cross-region failover design, or evidence of production reliability.

Run the focused local checks and an explicitly offline measurement with:

```bash
npm run test:admission
npm run admission:reference:benchmark -- --count 1000
```

The CLI under `scripts/universal-admission-sqlite.mjs` is an owner-private diagnostic adapter. Do not expose it directly
over HTTP, accept applicant-selected database paths, or treat its in-process principal/worker objects as remote
authentication.

## Production requirements

Enabling a real transport requires a new reviewed contract state with an exact endpoint, audience, public trust
snapshot, deployment evidence, authenticated remote worker/admin plane, multi-node serializability and clock behavior,
fair tenant controls, failure recovery, monitoring, retention operations, abuse handling, sustained and burst load
evidence, and signed or transparently anchored public receipts if independent verification is claimed.

That future activation must remain separate from review and launch authority. A transport can reliably enqueue any
project while still making no claim that the project is safe, non-scam, approved, deployed, routed, or launchable.
