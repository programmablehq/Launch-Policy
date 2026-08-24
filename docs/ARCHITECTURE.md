# Architecture

> [!IMPORTANT]
> GitHub launch intake and Workflow Canary intake are retired. Current launch preparation uses the
> [Custom Launch API](https://programmable.market/developers/custom-launch-api-v1.md). Application and Canary sections
> below describe preserved compatibility contracts and historical provenance.

Programmable Launch Policy keeps project source, admission policy, checking, API preparation, Registry promotion, and
production facts as separate authorities.

1. An applicant-owned public repository is the source authority for a project.
2. [`policy/launch-policy.v1.json`](../policy/launch-policy.v1.json) is the sole authored source of current
   Programmable-specific launch requirements. Its stable Rule IDs, profiles, outcomes, and parameters are consumed
   from one exact protected-base Git identity.
3. [`policy/launch-policy-authority-ownership.v1.json`](../policy/launch-policy-authority-ownership.v1.json) carries no
   requirement values. It closes every repository path and hash, admission entrypoint and local import closure,
   Rule-ID-to-handler owner, public projection, and the exact receipt-bound vendor exclusion. New YAML, code, config,
   or indirect imported gates fail the repository check until explicitly classified and reviewed.
4. The deterministic reviewer projects findings from those Rule IDs. Analyzer observations cannot add requirements,
   severity, enforcement, or approval authority.
5. [`intake/schemas/universal-admission-v1.schema.json`](../intake/schemas/universal-admission-v1.schema.json) is the
   cheap, project-agnostic front door. It records declared source coordinates and truthful disclosure without requiring
   an audit, a category allowlist, or a fabricated market/fee artifact. It emits only `ADMITTED_FOR_REVIEW` or
   `ADMITTED_FOR_REVIEW_ANALYSIS_PENDING` (plus bounded transport errors). Its optional local CAS/spool reference
   validates first and then creates fixed-depth digest shards with an atomic first-writer marker. It provides neither
   caller authentication nor production quota, fairness, worker, or deployment infrastructure.
6. [Universal Admission Protocol V1](UNIVERSAL_ADMISSION_PROTOCOL_V1.md) adds a detached-Ed25519 enqueue command,
   public trust snapshot, audience and tenant binding, capacity-policy precondition, durable replay, queue state machine,
   leases, retries, dead-letter handling, snapshots, and garbage collection. Its same-tree discovery contract is
   `.programmable/universal-admission-contract.v1.json`. The checked-in SQLite implementation is disabled,
   single-host, single-writer reference code: it publishes no endpoint or trust configuration and makes no distributed
   or production-capacity claim.
7. [`intake/schemas/public-pr-application-v3.2.schema.json`](../intake/schemas/public-pr-application-v3.2.schema.json)
   is the complete Application V3.2 launch contract. It binds applicant identity, exact public source, intent, evidence,
   policy-neutral Submission 2.1 and, for each selected tradable market, Trade Capability Manifest V2, selected policy,
   and review-package records without a project-type or capability allowlist. No-market projects attach no trade
   manifest.
8. The Application V3.1 compatibility contract remains byte-unchanged for historical reproduction. Its revisions are
   never reinterpreted as V3.2 and cannot establish `launch-readiness` or the official
   Programmable Router route.
9. The preserved protected-base validator validates one bounded revision as inert untrusted data. It may emit only a valid or invalid
   draft-for-review result; it cannot record review completion, acceptance, approval, deployment, or launch.
10. For a selected Programmable Ethereum market, a separate precommit preparation step embeds the current official
    manifest projection in `.programmable/launch-router-readiness.v1.json`. The offline checker consumes only that
    document and verifies its supplied bytes against the pinned official Developer artifact; it does not fetch the
    endpoint or independently prove endpoint freshness. Separately, the protected policy compiler combines the exact
    verified V3.2 package, source closure, readiness record, and current protected policy. Before it may mint a
    readiness decision, the platform must independently recheck trust and required freshness. None of these grants
    signing, launch, discovery, routing, audit, or funds authority.
11. A historical one-file Workflow Canary proved only the hidden, non-production GitHub handoff against that policy.
12. A signed audience-bound Website eligibility envelope may expose that exact Canary result only to the Website
   environment named by protected deployment configuration. It grants no public, production, funds, audit, or launch
   authority.
13. After an independently authorized launch, a finalized canonical Router stamp and proof are required before a future
    Ethereum v4 market can be promoted to Registry, API, or terminal classification. Deployment, runtime verification,
    provider support, third-party terminal adoption, and public availability remain separate facts.

The current launch flow is: API key → closed contract bundle and required evidence → Custom Launch API preparation →
wallet review and signature → broadcast and finality → indexing. Canonical Router verification still precedes any
Registry or terminal promotion. The Universal Admission queue and GitHub application paths remain disabled or
historical reference surfaces and are not production ingress.

The V1 `.programmable/active-contract.json` compatibility envelope retains every prior direct legacy binding and binds
the complete same-tree `.programmable/active-contract.v2.json` through its policy role. The V2 manifest closes the
current validators, schemas, compatibility contract, Router-readiness and finalized-promotion surfaces. The current
`.programmable/applicant-compatibility.v2.json` content-binds Application V3.2, Submission 2.1, Trade
Capability Manifest V2, the Router-readiness schema and validator closure, and legacy V3.1. Applicant Compatibility V1
remains a legacy discovery contract. The Universal Admission contract is intentionally separate from both of those and
both active-contract versions; it cannot change Application V3.2 or the bytes and meaning of V3.1 compatibility.
A future live queue activation requires a new exact contract state; a URL or local benchmark alone cannot enable it.

Project source never moves into this repository. The historical application namespaces are immutable and cannot edit
policy, workflows, schemas, project records, or another record. The receipt-bound
`vendor/programmable-v4-hook-builder/` tree is frozen validation data for retired six-file V2 records, not a current
central-policy requirement source. No new V2 application is accepted.

Application V3.2 does not replace or reinterpret V3.1, legacy V2, or Canary bytes. New V3.2 revisions are add-only under
`submissions/<application-id>/v3/revisions/<revision>/`. The manifest closes its own application-package file set while
content-addressed source-repository records remain at the exact pinned source revision. Required semantic review kinds
establish a common review floor; additional slug-named records preserve novel capabilities and evidence without making
them new launch-policy requirements. Submission 2.1 and the conditional per-market Trade Capability Manifest V2
describe tradability without embedding Programmable treasury, Router, label, approval, or promotion policy.

A source-backed `proposal` may enter only as an unreviewed draft with unresolved trade capability,
no trade manifest or result, and an `architecture-review-required` compatibility result. This transport state is not
prototype evidence and grants no review, approval, deployment, or launch authority.

## Launch provenance boundary

No-market and non-Programmable routes remain outside the Router rule. Unknown route state remains `analysis-pending`
instead of being rejected or treated as exempt. An official Programmable Ethereum market must use Application V3.2 and
bind the exact 10 bps fee tuple plus `.programmable/launch-router-readiness.v1.json` before readiness can pass.

Before the applicant pins the source commit, a separate preparation step resolves the Router from the current official
Developer discovery document and exact manifest and embeds that projection. The offline checker verifies the supplied
bound snapshot. Before it may mint a protected readiness decision, the platform must independently recheck trust and
required freshness. Programmable Launch Policy does not expose a fetch or mutation server. The binding does not permanently copy
one Router address into policy or documentation. The trust binding includes chain, active
block range, Router address, runtime-code hash, ABI URL and digest, immutable dependencies, route commitments, launch
kind, permit commitments, and launch-wallet late-binding constraints. The public wallet address is supplied before
permit signing and becomes immutable when the permit is signed.

Only the Router's atomic `launchAndStampV1` path can create canonical V1 provenance. Direct Classic Factory, Graph
Factory, or Single Factory calls cannot be relabeled afterward. Following finality, promotion binds one canonical block
and consistent identity `chainId + Router address + launchId`, `launchStamp`, both token and pool lookups, required
`stampProof` values, launch kind, source, application, policy, plan, fee, and manifest evidence. The receipt embeds the
full canonical passed launch-readiness decision, exact readiness bytes, the exact canonical Application V3 root bytes,
the decision subject's `applicationSha256` and `packageSha256`, and the closed promotion evidence projection. Trusted
Registry validation re-derives the application/package binding from those root bytes, matches it to acceptance, and
cross-checks every binding rather than trusting digest-only assertions.

This boundary proves documented Router provenance only. It does not prove an audit, safety, current liquidity,
sellability, tradability, provider support, Uniswap endorsement, or third-party terminal adoption. Read the
[complete launch requirements](COMPLETE_LAUNCH_REQUIREMENTS.md) for the exact Rule IDs and commands.

Strict JSON, path safety, size limits, Git identity, authentication, signatures, and key or audience pinning are
implementation security controls. They protect the policy path but do not create separate semantic admission rules.
The private SQLite reference accepts in-process worker and administrative contexts only. Exposing those methods over a
network would require a separately reviewed worker/admin authentication and authorization protocol.

## Generated data

`registry/config.json` lists every canonical project record. The generator reads only closed, bounded, duplicate-free,
non-executable regular JSON files. It emits:

- `registry/index.json`, the small entry point;
- `registry/search-index.json`, bounded discovery metadata; and
- one append-only `registry/history/<version>.json` snapshot.

Every index entry contains the SHA-256 of its full project record. A consumer must fetch a record from the same exact
Registry commit and verify that digest before using it.

## Trust boundary

Names, summaries, tags, outcomes, application prose, repository content, issue text, and pull-request content are data,
not instructions. Search similarity does not establish originality, compatibility, acceptance, safety, audit status,
deployment, provider support, or availability.
