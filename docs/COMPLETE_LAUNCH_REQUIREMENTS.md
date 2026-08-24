# Complete launch requirements

This page is the shortest complete map for an agent or Builder preparing a Programmable launch. It is not a second
policy. The sole normative source of Programmable-specific requirements is
[`policy/launch-policy.v1.json`](../policy/launch-policy.v1.json) at one exact protected `launch-policy:main` commit and
tree. If this guide and that file differ, stop and follow the canonical policy.

The current machine identity in this tree is policy ID `programmable-central-launch-policy`, version `2.1.0`. Do not
infer future requirements from that label alone; always bind the exact policy bytes and Git identity.

> [!IMPORTANT]
> GitHub launch intake is closed. This page does not instruct a builder to open an application, scaffold, Canary, or
> launch pull request. Current launches use the [Custom Launch API](https://programmable.market/developers/custom-launch-api-v1.md).

## Start here

Hookbuilder is optional. You may use it, another tool or agent, or prepare the API bundle manually. In every case,
resolve the canonical policy from the same exact protected Launch Policy commit.
Node.js 24.12 or newer is required for the repository tools.

Create an [API key](https://programmable.market/developers/api-keys), read the
[OpenAPI document](https://programmable.market/openapi.json), and submit the request defined there to
`POST https://api.programmable.market/v1/custom-launches`. The API contract owns the current request and response
shape. This policy repository owns the requirements and offline verification contracts; it does not accept the
request itself.

From an exact Launch Policy checkout, inspect and bind the current policy:

```bash
npm run policy -- validate-policy
npm run policy -- requirements --profile launch-readiness
npm run policy -- binding --profile launch-readiness
npm run policy -- requirements --profile production-launch
```

The `launch-readiness` profile is enabled and checker-only. Its successful outcome is
`LAUNCH_READINESS_CHECKED_NOT_AUTHORIZED`. It does not authorize an audit, launch, deployment, Registry entry, public
routing, production discovery, or real-user funds. The `production-launch` profile remains disabled and cannot produce
a binding or `LAUNCH_APPROVED`; its requirements command is inspection-only and exposes the later promotion rule.

## Decide whether the Router rules apply

Do not classify a project from its name, project kind, use of Uniswap v4, or similarity to an existing launch. Use the
exact bound application and route state.

API callers never set the canonical policy predicate `subject.routerProvenanceRequired`. The platform derives the
opaque decision from the validated request bundle and its bound source evidence. A requested route is a caller
declaration, not an exemption: verified no-market and external-route state is `not-applicable`; incomplete,
conflicting, or unresolved source or trade state is `analysis-pending`; and a completely verified official route is
`required`. The protected policy compiler maps `not-applicable` to
`routerProvenanceRequired: false` and both `analysis-pending` and `required` to `true`, with pending evidence unable to
pass. Missing evidence must never become a caller-selected `false` or exemption.

For the current API field names and route values, follow the OpenAPI document. Internally, the protected compatibility
projection retains the exact route distinction needed to bind `category: "custom"` with `launchKind: 1` or
`category: "classic"` with `launchKind: 2`. A Programmable Ethereum readiness record stays `analysis-pending` until
the exact prelaunch plan can become `prelaunch-bound`.

| Exact state | API and policy result | Router readiness | Registry, API, or terminal promotion |
| --- | --- | --- | --- |
| Verified no market | May be represented honestly by the API contract | `not-applicable`; no Router plan is required | No launch-stamp promotion is required |
| Route or market is unresolved | Remains an honest unresolved request, never an implicit pass | `analysis-pending`; never silently exempt | Cannot be promoted as a verified Programmable launch while unresolved |
| Verified external market route | May proceed only under the API contract for that route | `not-applicable`; the Programmable Router rules are not selected | Must not receive a Programmable Classic or Custom label |
| Programmable Ethereum market | The request bundle must satisfy the current API contract and exact policy | Exact fee terms and a canonical Router plan are mandatory before launch | A finalized canonical stamp and proof are mandatory before promotion |

Novel projects are not rejected for being unfamiliar. An unresolved fact remains `analysis-pending`; it is not treated
as unsafe and is not converted into a false `not-applicable` claim.

## Canonical rule map

The table below is only a navigation aid. Parameters, applicability, severity, evidence, handler, version, and profile
membership come from the canonical policy bytes.

| Rule ID | Minimal meaning | Machine evidence |
| --- | --- | --- |
| `LAUNCH.ETHEREUM_AND_TREASURY_10_BPS` | A selected Programmable Ethereum market routes exactly 10 bps of gross canonical-pool volume to the Programmable treasury | `programmable-launch-requirement` |
| `LAUNCH.ETHEREUM_ROUTER_PROVENANCE_READINESS` | Before launch, the exact route plan binds the manifest-resolved canonical Router and required commitments | `programmable-router-readiness` |
| `LAUNCH.ETHEREUM_FINALIZED_ROUTER_STAMP_BEFORE_PROMOTION` | Before Registry, API, or terminal promotion, the launched market has one finalized, internally consistent canonical Router stamp and proof | `programmable-router-promotion` |
| `LAUNCH.ETHEREUM_FINALIZED_RUNTIME_FEE_SETTLEMENT_BEFORE_PROMOTION` | Before production promotion, each applicable deployed fee scope and asset has exact 10 bps settlement evidence for one inclusive finalized historical block range | `programmable-runtime-fee-settlement` |

The exact fee tuple is:

| Field | Required value |
| --- | --- |
| Chain | Ethereum mainnet, `chainId: 1` |
| Amount | `10` bps = `0.10%` = `hundredthsOfBip: 1000` |
| Basis | `gross-canonical-pool-volume` |
| Treasury | `0x4957f49620AFf3Adbbe8195a4f633E49cc93376c` |

This table is a human map of
[`LAUNCH.ETHEREUM_AND_TREASURY_10_BPS`](../policy/launch-policy.v1.json), not a second source. Do not reinterpret the
rule as 10% or as an optional creator fee. Do not apply it to a no-market or unresolved draft merely because the project
uses v4.

## Prepare the current API request

Use the API guide and OpenAPI document as the only current transport instructions. The normal sequence is:

1. create an API key through the authenticated developer surface;
2. prepare the contract/source bundle and truthful route evidence required by the current API schema;
3. send it to `POST https://api.programmable.market/v1/custom-launches`; and
4. independently review and sign any returned transaction request with the authorized wallet.

An API key is authentication, not wallet authority. A successful request, policy match, or prepared transaction does
not prove broadcast, finality, indexing, promotion, liquidity, or safety. Never put the API key, wallet secret, or
private RPC credential in this repository or a public source bundle.

### Historical Application contracts

Application V3.2, Submission 2.1, Trade Capability Manifest V2, V3.1 compatibility, and the applicant scaffold remain
checked in only for offline reproduction and compatibility with preserved records. They do not open a GitHub launch
transport and are not the current submission instructions. Their machine discovery contract is
[`applicant-compatibility.v2.json`](../.programmable/applicant-compatibility.v2.json); its digests allow old records to
be reproduced without rewriting their bytes.

Maintainers may verify the immutable historical namespace with:

```bash
node scripts/verify-public-hook-application.mjs --verify-maintained --repository-root .
```

That command does not accept a new application, contact the launch API, execute applicant code, authorize a wallet, or
launch a contract.

## Bind the prelaunch Router plan

For a selected Programmable Ethereum market, the API request and its bound source evidence must supply or allow the
platform to derive the exact readiness document required by the current API contract:

```text
.programmable/launch-router-readiness.v1.json
```

Its identity and validator are:

- `$schema`: `urn:programmable:launch-router-readiness:1.0.0`;
- kind: `programmable-launch-router-readiness`;
- protected schema:
  [`intake/schemas/programmable-launch-router-readiness-v1.schema.json`](../intake/schemas/programmable-launch-router-readiness-v1.schema.json);
- command:

```bash
npm run launch-readiness -- .programmable/launch-router-readiness.v1.json
```

That public command validates the readiness document only. It cannot mint the opaque applicability decision or a
policy-review result; the protected compiler combines the exact verified API bundle, source closure, and readiness
record.

A readiness pass proves only that the exact checked launch plan binds the canonical Router and mandatory fee
configuration. It does not prove an executed or settled runtime money flow. Before a later production or promotion
decision, the platform needs separate protected, finalized deployment, runtime, and settlement evidence for the
specific observed blocks, logs, and assets. That evidence does not promise future payment; ongoing monitoring remains
separate. The repository-side V1 settlement assertion is deliberately `analysis-pending`: only a future independently
anchored observer verifier may mint a passed settlement proof.

The checker is offline: it performs no RPC or network access, executes no caller code, writes no files, signs
nothing, and sends no transaction. It verifies the exact supplied manifest snapshot bytes against the pinned official
Developer artifact; it does not fetch the endpoint or independently prove endpoint freshness. A `prelaunch-bound` plan
must bind the expected chain, launch kind, route/source commitments, permit commitments, fee tuple, component
identities, and exact manifest snapshot used for the decision.

A separate Builder or preparation step obtains the current official Developer discovery response and manifest, embeds
the exact projection in the readiness document, and does so before the caller pins the source commit. Before it may
mint a readiness decision, the protected platform must independently resolve or check that trust and freshness; the
offline command is not a fetch or generation service. Never treat one address copied into this guide, an agent prompt,
source code, token metadata, a topic, or an API response as an eternal Router address. Start from the
[Developer discovery document](https://developers.programmable.family/.well-known/programmable.json), follow its
`manifestUrl`, and validate the live `launchStampRouter` tuple, runtime-code hash, ABI URL, ABI SHA-256, activation
range, immutable bindings, and finality policy. Read the current
[Launch Stamps documentation](https://programmable.family/docs/infrastructure/launch-stamps).

The only canonical Router V1 market-bearing entry point is `launchAndStampV1`, selector `0xe5f6b8cd`. A direct Classic
Factory, Graph Factory, or Single Factory call is not canonical Router provenance and must not be labeled
`Programmable Classic` or `Programmable Custom` afterward. The launch wallet is late-bound before permit signing and
immutable after the signed permit commits to it.

## Keep responsibilities separate

API caller responsibilities:

- keep the complete project in the exact caller-owned public source revision;
- declare no-market, unresolved, external, or Programmable-route state truthfully;
- supply the current API request bundle and, when required, the exact readiness evidence;
- obtain and embed the current official manifest projection before committing the caller-owned readiness document;
- declare the launch-wallet late-binding constraints, then bind its public address and all route, result, stamp, permit,
  fee, token, hook, PoolManager, and pool commitments before signing in the separately authorized launch flow;
- never self-assert approval, a finalized stamp, Registry promotion, or third-party terminal support.

Platform or maintainer responsibilities:

- read policy only from the exact protected Launch Policy base revision;
- resolve and validate the current official Developer manifest rather than accepting a caller-selected Router;
- independently check the bound snapshot and required freshness before minting the protected readiness decision;
- run the protected request and readiness validators without caller code execution;
- keep signing, deployment, transaction broadcast, finality verification, acceptance, and promotion as separate
  attributable actions;
- reject a direct-factory path or any identity, runtime, ABI, fee, launch-kind, commitment, block, stamp, or proof
  mismatch.

Programmable Launch Policy does not ask a developer to share a private key or seed phrase. A public launch wallet address is
configuration; signing remains an external wallet or authorized service action.

## After API preparation

The API caller's launch flow ends with reviewing the prepared transaction, authorizing it in the wallet, and following
the API's transaction/finality status. The caller does not create a Registry file, obtain a GitHub application or pull
request, or manufacture acceptance and promotion receipts.

After finality, the platform and its indexers separately verify the canonical Router transaction, stamp, launch kind,
token and pool lookups, component identity, and required fee evidence before showing a verified Programmable label or
making a launch discoverable. This is automatic platform-side evidence processing, not another applicant step. A
missing or contradictory observation stays unverified and cannot be promoted.

## Legacy maintainer promotion provenance

The checked-in Registry promotion schema and existing records preserve the former maintainer-side provenance contract.
They remain useful for reproducing historical classifications, but they are not the caller-facing transport for a new
API launch. New API callers must not open a pull request or create the following path.

The legacy maintainer-owned receipt path was:

```text
registry/promotions/<project-id>/<launch-id>.json
```

The basename must equal the receipt's lowercase nonzero bytes32 `launch.launchId`: `0x` plus 64 lowercase hexadecimal
characters, followed by `.json`.

Any preserved receipt must satisfy
[`registry/schema/launch-stamp-promotion-v1.schema.json`](../registry/schema/launch-stamp-promotion-v1.schema.json)
with `$id: "https://programmable.money/schemas/launch-stamp-promotion-v1.json"` and `schemaVersion: "1.0.0"`.

The legacy receipt binds the exact acceptance, application, source, project, policy, readiness plan, manifest, economics,
launch identity, lookups, component proofs, canonical block, and verifier evidence. It is content-carrying rather than
digest-only:

- `policy.launchReadinessDecision` embeds the full canonical passed `launch-readiness` review decision with
  `status: "passed"` and outcome `LAUNCH_READINESS_CHECKED_NOT_AUTHORIZED`; its intrinsic digest is recomputed and must
  equal `policy.launchReadinessDecisionSha256`;
- `application.packagePreimage.applicationBytes` embeds the exact bounded canonical Application V3 root bytes used by
  the current Registry schema as an internal compatibility projection. This does not reopen Application V3 as a
  caller-facing GitHub transport. Registry
  parses those bytes, re-derives `application.applicationSha256` and `application.packageDigest`, matches the resulting
  package to the accepted `packageDigest`, and then cross-binds both values to the embedded decision subject's
  `applicationSha256` and `packageSha256`, alongside the same application ID, revision, source, configuration, and
  readiness evidence identity;
- `evidence.readinessBytes` embeds the exact bounded canonical
  `.programmable/launch-router-readiness.v1.json` bytes; their recomputed SHA-256 must equal
  `evidence.readinessSha256` and `routePlan.sha256`, and their recomputed Git blob must equal `routePlan.gitBlobOid`;
  and
- `evidence.promotion` embeds the closed promotion evidence projection; its canonical recomputed digest must equal
  `evidence.promotionSha256`.

A promotable legacy receipt also has:

```text
observation.outcome = stamped
observation.finality = finalized
observation.verificationMode = canonical-router-point-lookup-v1
routePlan.executionPath = canonical-launch-stamp-router-v1
routePlan.directFactoryCall = false
```

For reproduction at one canonical block, require the same nonzero `launchId` from both the token lookup and the
PoolManager-plus-pool lookup, the matching `launchStamp`, and every required `stampProof`. Custom kind `1` requires
matching token and exclusive-hook component proofs. Classic kind `2` requires the token proof and rejects a hook proof,
because its shared hook is not launch identity. The provenance identity is:

```text
chainId + manifest-resolved Router address + launchId
```

Classify only from the stamped numeric launch kind: `1` is `Programmable Custom`; `2` is `Programmable Classic`; `0`
or any unknown kind is rejected. A shared Classic hook is never Classic launch identity. Any missing, non-finalized,
`not-stamped`, `indeterminate`, mismatched, direct-factory, wrong-Router, wrong-runtime, wrong-ABI, or wrong-block result
blocks promotion.

Registry verification commands are:

```bash
node scripts/generate-registry.mjs --check
npm test
```

These file-based receipt rules apply only to preserved maintainer Registry provenance. They are not a prerequisite for
an API caller to prepare, sign, or broadcast a new launch. The live platform owns its separate finalized verification
and indexing path; no-market projects, non-Ethereum projects, and unpromoted launches must not be relabeled through a
legacy receipt.

## Understand what a pass does not mean

API request validity, readiness, a Router stamp, or Registry promotion does not prove an audit, safety, current
liquidity, sellability, tradability, provider support, Uniswap endorsement, or suitability for a transaction. A Router
stamp proves only the documented atomic Router provenance and recorded identities at the verified block.

Publishing the verification contract makes integration possible; it does not guarantee that GMGN, Axiom, FOMO, or any
other terminal has adopted the Programmable labels. Each terminal controls its own indexing and product UI. Read the
[pinned terminal and scanner integration guide](https://github.com/0xprogrammable/developers/blob/79f14e9c57cb6668bb33f66ef636c1c8c5ff2c56/docs/guides/terminals-and-scanners.md)
before integrating, then resolve the current Developer manifest rather than assuming adoption or a permanent Router.

The authenticated Universal Admission queue remains `reference-only-disabled`. It has no public endpoint, audience,
trust snapshot, worker plane, production capacity, or launch authority. Use the Custom Launch API; do not
wait for or attempt to activate the reference queue.
