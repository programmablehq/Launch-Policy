# Universal Admission V1

> [!NOTE]
> This is disabled reference code, not the current launch front door. Current launches use the
> [Custom Launch API](https://programmable.market/developers/custom-launch-api-v1.md).

Universal Admission is the small front door for an open-world project. It is deliberately separate from the
Programmable launch policy and from the later security/review package.

## What it does

An envelope can be filed when it has:

1. declared exact public source coordinates (`repositoryUrl`, commit, tree, path, and package digest);
2. an explicit execution-surface list;
3. an explicit value-flow list, including an honest `kind: "none"` entry for a no-market/no-token project;
4. an explicit privilege and dependency list; and
5. truthful transport attestations: no candidate code executed, no external write, no approval/safety claim, and
   unknowns marked as `unknown`.

The source URL is canonical public HTTPS metadata. User info, passwords, query parameters, and fragments are rejected so
tokens or other private values cannot be smuggled into the public envelope. Admission validates the declaration; it does
not fetch the repository or prove those coordinates. A later trusted source resolver must establish that evidence.

The project kind is intentionally a bounded label, not an allowlist. A hook, game, NFT, prediction market, API-backed
service, research prototype, or a new category uses the same envelope. Empty semantics are declared explicitly rather
than inferred from a missing field.

## What it does not do

The envelope is not an audit, scam certificate, safety certificate, Uniswap endorsement, frontend routing decision,
deployment, approval, or launch authorization. An unknown oracle, provider, token standard, hook architecture, chain,
or review result is `analysis_pending`, not a categorical rejection. A provider warning is retained with its source and
timestamp by a later consumer; it must not be rewritten as `scam`.

The JSON Schema closes field shapes, resource bounds, and byte-identical duplicate disclosure entries. The trusted
runtime additionally requires each `id` to be unique inside its disclosure section; standard JSON Schema cannot express
that keyed-array relationship. Schema acceptance is therefore a structural preflight, not the final admission result.

The current central rule `LAUNCH.ETHEREUM_AND_TREASURY_10_BPS` is not a universal admission rule. If an applicant selects
`programmable-ethereum-mainnet`, this front door returns `platform-route-pending`; the protected route/launch reviewer
must resolve the exact current policy and its policy binding later. No applicant-authored envelope can self-certify that
route.

This separation follows the protocol boundary in the official Uniswap material: v4 hooks are permissionless protocol
extensions, while frontend hook routing is a separate interface policy. Uniswap's hook security guidance is voluntary
and informational, not a certification or endorsement. See the official [hook concepts](https://developers.uniswap.org/docs/protocols/v4/concepts/hooks),
[hook routing](https://developers.uniswap.org/docs/protocols/v4/concepts/hook-routing), and
[security guidance](https://developers.uniswap.org/docs/protocols/v4/security).

## States

| Result | Meaning |
| --- | --- |
| `ADMITTED_FOR_REVIEW` | The bounded envelope is internally complete and has no declared unknowns. It is still unreviewed. |
| `ADMITTED_FOR_REVIEW_ANALYSIS_PENDING` | The envelope is admissible, but one or more surfaces, flows, privileges, or dependencies are explicitly unknown, or a platform route needs later review. |
| hard validation error | Only malformed/oversized/duplicate/unsafe transport or a false authority attestation is rejected at this layer. |

Every result keeps `approvalGranted`, `launchAuthorized`, and `externalWritesPerformed` false. A green result means
`admitted for review`, never `safe`, `approved`, `deployed`, `routed`, or `live`.

## Transport and scale boundary

The retired GitHub PR/Actions adapter remains only for compatibility and historical reproduction. It was not a million-submissions-per-
day ingress: repeated full-tree scans, uncached GitHub reads, workflow fan-out, and a monolithic registry create a
capacity and fairness bottleneck.

The repository retains a deliberately small, local reference ingress spool. It validates the complete canonical
envelope before touching storage, uses the envelope SHA-256 as its idempotency key, and derives two fixed-depth shard
paths from lowercase digest bytes: one read-only CAS object and one read-only queue marker. Files are created with
temp-file `fsync` plus an atomic no-clobber link. Each digest has a closed 256-entry staging directory, so a retry can
remove only an exact same-inode temp hardlink left in the publish crash window; unrelated hardlinks fail closed. A retry
can also repair a CAS object left before a missing queue marker. Same-content races produce exactly one `QUEUED` first
writer and `DUPLICATE` receipts for the rest, without a global directory scan.

This is a single-filesystem reference spool, not a deployed million-submission ingress or an operational worker queue.
It does not implement authentication, authorization, tenant quotas, rate limiting, fairness, job claim/lease/retry,
multi-node consensus, garbage collection, or worker execution. An external authenticated ingress must own those
controls before production use. The required `--actor` value is only a bounded, public attribution label supplied by
that trusted caller; the receipt explicitly records `authenticated: false`. Credentials and other private data must
never be used as actor ids or envelope content.

The separate [authenticated queue protocol](UNIVERSAL_ADMISSION_PROTOCOL_V1.md) closes the next reference layer. It
binds a canonical envelope to a short-lived detached-Ed25519 enqueue command, an audience, a public trust snapshot,
tenant and subject identifiers, a request id, and the exact runtime-capacity-policy digest. The service validates the
same snapshotted envelope bytes used by the store, and a new queue event plus its public transport readback are committed
atomically. Tenant-scoped request replay, revision equivocation, queue capacity, leases, retry, dead-letter redrive,
terminal retention, snapshots, and garbage collection are bounded protocol concerns, never project-type rules.

The included Node SQLite implementation is an owner-private, single-host, single-writer reference. It is disabled for
public use, has no endpoint or published trust snapshot, and proves neither multi-node correctness nor production
capacity. Its public readback is a trusted-service statement, not a service signature or transparency proof. Worker and
administrative contexts are accepted only inside this private reference boundary; no remote worker/admin API is
published. A future network adapter must authenticate and authorize those operations separately.

The exact same-tree reference surface is published at
`.programmable/universal-admission-contract.v1.json`. Consumers must read it at one exact Launch Policy commit and
verify every bound digest. `deployment.state: "reference-only-disabled"`, `enabled: false`, and null endpoint, audience,
and trust-snapshot fields mean the queue cannot be selected as a live transport. The older active contract,
Applicant Compatibility V1, and Application V3.1 remain separate and unchanged.

The production-scale path remains a separate transport plane:

```text
canonical envelope + size/hash
        -> dedupe/CAS + tenant quota
        -> durable sharded queue
        -> bounded workers + shared (repo, commit, tree, path) cache
        -> semantic/review evidence
        -> optional GitHub draft adapter / maintainer decision
```

The local reference spool returns only `QUEUED` or `DUPLICATE`. A future production ingress may also need bounded
`THROTTLED`, `QUARANTINED`, or `MALFORMED` transport/abuse states; none is a project-type or launch-policy judgment. A
tenant- and audience-scoped digest is the authenticated protocol's idempotency key. GitHub could later anchor bounded
snapshot roots for public audit, while
the protected repository remains the authority for policy and review rules. Per-job byte, request, retry, and
candidate-execution limits remain necessary on every future worker.

## CLI

```bash
npm run admission -- path/to/admission.json
npm run admission -- queue --root /absolute/owner-controlled/queue-root --actor public-actor-id path/to/admission.json
```

Validation mode is offline and read-only. Queue mode is also offline: it performs only the explicitly reported local
filesystem writes under an existing owner-controlled root. Validation is deterministic; queue receipts are canonical
and explicitly state whether this call won the first-writer race or observed a duplicate. Neither mode fetches a
repository, uses a network, runs applicant code, opens a pull request, signs, deploys, approves, or launches.

Maintainers can verify the separate disabled discovery contract and run the reference tests with:

```bash
npm run admission:contract:check
npm run test:admission
```

`npm run admission:reference:benchmark -- --count 1000` is an offline single-process measurement only. Its output keeps
`productionClaim`, `multiNodeProven`, and million-per-day production proof false. Node.js 24.12 or later is required for
the built-in SQLite reference backend.
