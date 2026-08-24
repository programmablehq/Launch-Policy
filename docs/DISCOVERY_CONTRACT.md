# Discovery contract

Agents and applications start with `registry/index.json` or `registry/search-index.json` at one exact Launch Policy
commit. They do not crawl project repositories or load every application into context. Discovery answers what records
exist; it is not the source of launch requirements. The sole normative source of Programmable-specific requirements is
[`policy/launch-policy.v1.json`](../policy/launch-policy.v1.json).

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

Resolve the Router through the current official
[Developer discovery document](https://developers.programmable.family/.well-known/programmable.json) and its
`manifestUrl`. Verify the manifest-selected chain, activation range, Router address, runtime-code hash, ABI URL and
SHA-256, immutable bindings, and finality policy. Never treat one address copied into source, policy, documentation,
token metadata, or an API response as an eternal Router address. For historical verification, the selected manifest
record may now be `live` or `retired`, but it must have been active at the observed launch block.

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

## Transport discovery is separate

`.programmable/universal-admission-contract.v1.json` is a same-tree discovery contract for the authenticated Universal
Admission reference surface. It is not a Registry project record and is not part of the active contract, current
Applicant Compatibility V2, or legacy Applicant Compatibility V1.

A consumer must fetch the contract and every bound schema and implementation artifact from the same exact commit and
verify each SHA-256. It must also obey the deployment fields before selecting a transport. The published V1 state is
`reference-only-disabled`, with `enabled: false` and null endpoint, audience, and trust snapshot. Therefore no client
may infer a live queue, authentication configuration, availability, production capacity, review result, or launch
authority from the presence of the contract or reference code. Use the Custom Launch API for current launches.
