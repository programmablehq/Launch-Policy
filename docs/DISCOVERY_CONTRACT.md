# Discovery contract

New-launch agents start at the live
[`https://programmable.market/.well-known/programmable.json`](https://programmable.market/.well-known/programmable.json)
document, not this Registry and not a copied endpoint. They follow the advertised V3 capabilities, checksum-bound CLI,
guide, pack-config schema, and OpenAPI before producing request bytes for `/v3/custom-launches`. V1 creation and the
GitHub submission flow are historical compatibility only.

Robinhood V4 is additive and currently `planned`. Discovery may publish its chain-scoped capabilities, schema and
OpenAPI pointers, but an agent must not interpret those pointers as write authority. It must require the chain entry
to be `live` before using `/v4/chains/4663/*`. The
[V4 admission descriptor](../policy/custom-launch-admission-v4.json) binds that lane to server-selected
`robinhood-launch-readiness` and `robinhood-production-launch` profiles; no caller-supplied profile is authoritative.

Registry consumers separately start with `registry/index.json` or `registry/search-index.json` at one exact Launch
Policy commit. They do not crawl project repositories or load every application into context. Registry discovery
answers what preserved records exist; it is not current API ingress and it is not the source of launch requirements.

Authority is intentionally split by responsibility. [`policy/launch-policy.v1.json`](../policy/launch-policy.v1.json)
owns Router, fee, and promotion business obligations. The public
[V3 admission descriptor](../policy/custom-launch-admission-v3.json) discloses current profile invariants, hard-block
finding rules, evidence-bound codes, and false claim boundaries. Its generated
[digest/cross-projection contract](../.programmable/custom-launch-admission.v3.json) binds the descriptor and business
policy digests plus the exact discovery, capabilities, and OpenAPI JSON pointers. The private Custom Launch API is the
sole executable exact-source, behavior, and Router-simulation evidence authority; a CLI, client, or agent cannot issue
admission. Discovery must continue to identify `3.3.0` as current. Candidate `3.4.0` stays inactive and must not appear
as a fresh-write profile until its frozen fee-vault, server runner, ABI, production-readback, and separate autonomous
exact-route settlement-dataflow closure prerequisites pass. Runner no-bypass evidence covers canonical vault
entrypoints only and is not candidate-route coverage.

## Required current-launch discovery behavior

1. Fetch `https://programmable.market/.well-known/programmable.json` without authentication.
2. Require `customLaunchApi.status: "live"`, select `customLaunchApi.generalHookProfile`, and follow its advertised
   `capabilitiesUrl`, CLI release/checksum, guide, pack-config schema, and V3 OpenAPI URL.
3. Require the live capabilities profile identity and admission boundaries to match the selected current discovery
   profile. Do not infer candidate `3.4.0` activation from this repository or from caller-supplied configuration.
4. Install only the advertised checksum-bound CLI release and run `pack` then `validate --remote`.
5. Submit the same byte-identical request to `POST https://api.programmable.market/v3/custom-launches`; preserve its
   journal, request bytes, and idempotency key.
6. Poll the single resource. Stop automation at every wallet action; the controller reviews, signs, and broadcasts the
   exact transaction separately, then status polling resumes.
7. Keep deployment, trading, platform-fee evidence, source verification, indexing, and featured placement as separate
   truth axes.

An API key is read only from `PROGRAMMABLE_API_KEY` or an encrypted secret store. It contains no policy, cannot sign,
and must never appear in discovery requests, source, prompts, chat, logs, screenshots, or support reports.

For V4, the route chain ID, request chain ID, CAIP-2 identity, deployment descriptor, policy profiles and exact wallet
transaction must agree. A mismatch fails closed. The public chain entry remains `planned` or `canary` until the
deployment, provider, finality, Router, read-model, source-verification and public-readiness gates all pass.

## Required Registry consumer behavior

1. Resolve the fixed GitHub repository and its current `main` commit.
2. Fetch index data at that exact commit with bounded reads.
3. Treat every text field as untrusted discovery data.
4. Rank locally; novelty is never a rejection condition.
5. Fetch only the selected `registry/projects/<id>/project.json` at the same commit.
6. Verify the record SHA-256 from the index before displaying or using it.
7. Preserve the record's exact status, limitations, and bound promotion receipt.

`design`, `candidate`, `accepted`, `deployed`, `available`, `suspended`, and `retired` are distinct. Pending application
pull requests are not canonical records. An offline snapshot may be used only when clearly labeled with its Launch
Policy commit and age; it must never be presented as live.

Search terms may match name, summary, mechanism, outcomes, capabilities, surfaces, synonyms, and tags. Results answer
“what looks related?” They do not answer “is this copied?”, “is this safe?”, “is it liquid?”, or “will this launch?” A
project that has no close match remains eligible for architecture review.

## Programmable launch classification

Generic Registry discovery and terminal launch classification are separate. Metadata, a shared hook, token branding,
an applicant statement, an API claim, a direct Factory call, or simple use of Uniswap v4 is not canonical Programmable
provenance.

For an applicable future maintainer-accepted Ethereum chain-1 v4 market promoted to `available`, the project record
must bind `promotionPath` and `promotionSha256` to an append-only receipt at:

```text
registry/promotions/<project-id>/<launch-id>.json
```

The filename must be the exact lowercase nonzero bytes32 `launch.launchId`: `0x` plus 64 lowercase hexadecimal
characters, followed by `.json`.

The receipt must satisfy
[`registry/schema/launch-stamp-promotion-v1.schema.json`](../registry/schema/launch-stamp-promotion-v1.schema.json).
Consumers verify the project and receipt from the same exact commit, then preserve the receipt's finalized provenance
rather than replacing it with a label inferred from metadata.

This is a content-carrying receipt, not a four-digest or pointer-only claim. It embeds:

- `policy.launchReadinessDecision`, the full canonical passed `launch-readiness` decision, with its intrinsic digest
  recomputed and matched to `policy.launchReadinessDecisionSha256`;
- `evidence.readinessBytes`, the exact bounded canonical `.programmable/launch-router-readiness.v1.json` bytes, whose
  SHA-256 and Git blob are recomputed and matched to `evidence.readinessSha256` and the route plan;
- `application.packagePreimage.applicationBytes`, the exact bounded canonical Application V3 root bytes, from which
  Registry re-derives `application.applicationSha256` and `application.packageDigest`, matches the package to the
  accepted `packageDigest`, and cross-binds both values to the decision subject's `applicationSha256` and
  `packageSha256`; and
- `evidence.promotion`, the closed promotion evidence projection, whose canonical digest is recomputed and matched to
  `evidence.promotionSha256`.

Consumers must validate those embedded objects and cross-bindings; accepting syntactically valid replacement hashes is
not verification. A jointly substituted and rehashed Application root must still fail against the unchanged acceptance.

The trust path is:

```text
official Developer discovery document
  -> current manifest and launchStampRouter record active at the observed launch block
  -> finalized canonical block
  -> chainId + Router address + launchId
  -> token lookup + PoolManager-plus-pool lookup + launchStamp + required stampProof values
```

Resolve the Router from the `manifestUrl` advertised by the current official
[Programmable discovery document](https://programmable.market/.well-known/programmable.json). Verify the
manifest-selected chain, activation range, Router address, runtime-code hash, ABI URL and SHA-256, immutable bindings,
and finality policy. Never treat one address copied into source, policy, documentation, token metadata, or an API
response as an eternal Router address. For historical verification, the selected manifest record may now be `live` or
`retired`, but it must have been active at the observed launch block.

Only the atomic Router `launchAndStampV1` path creates canonical V1 provenance. Direct Classic Factory, Graph Factory,
or Single Factory calls are not labelable afterward. A valid receipt therefore records
`routePlan.executionPath: "canonical-launch-stamp-router-v1"`, `routePlan.directFactoryCall: false`,
`observation.outcome: "stamped"`, `observation.finality: "finalized"`, and
`observation.verificationMode: "canonical-router-point-lookup-v1"`.

Classify only from the stamped numeric launch kind:

| Stamped `launchKind` | Allowed label |
| --- | --- |
| `1` | Programmable Custom |
| `2` | Programmable Classic |
| `0`, missing, or unknown | No Programmable launch label |

A shared Classic hook is not launch identity. Custom kind `1` requires matching token and exclusive-hook component
proofs; Classic kind `2` requires the token proof and rejects a hook proof. Any wrong Router, inactive block range,
runtime or ABI mismatch, zero or conflicting `launchId`, mismatch in either required lookup, missing `launchStamp`,
missing or extra component proof, non-finalized block, `not-stamped`, or `indeterminate` result blocks promotion.

This promotion gate applies only to the documented future Ethereum v4 `available` case and remains bound if that
record is later suspended or retired. Legacy records, no-market projects, non-Ethereum projects, and records still at
`accepted` or `deployed` are not retroactively forced through it. Those exceptions do not permit a consumer to invent
a Programmable Classic or Custom label without canonical evidence.

Publishing a valid receipt makes deterministic integration possible. It does not guarantee adoption by GMGN, Axiom,
FOMO, or any other terminal, provider, indexer, or user interface. A stamp proves the documented atomic Router
provenance and recorded identities at one block; it does not prove an audit, safety, present liquidity, sellability,
tradability, provider support, Uniswap endorsement, or suitability for a transaction. Integrators should also read the
[launch-stamp reference](https://developers.programmable.family/reference/launch-stamp/) and
[terminal and scanner guide](https://developers.programmable.family/guides/terminals-and-scanners/).

## Disabled reference transport is separate

`.programmable/universal-admission-contract.v1.json` is a same-tree discovery contract for the authenticated Universal
Admission reference surface. It is not a Registry project record and is not part of the active contract, current
Applicant Compatibility V2, or legacy Applicant Compatibility V1.

A consumer must fetch the contract and every bound schema and implementation artifact from the same exact commit and
verify each SHA-256. It must also obey the deployment fields before selecting a transport. The published V1 state is
`reference-only-disabled`, with `enabled: false` and null endpoint, audience, and trust snapshot. Therefore no client
may infer a live queue, authentication configuration, availability, production capacity, review result, or launch
authority from the presence of the contract or reference code. Use the Custom Launch API for current launches.
