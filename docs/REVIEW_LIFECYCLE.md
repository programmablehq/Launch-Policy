# Review and promotion lifecycle

> [!IMPORTANT]
> GitHub application intake is closed. Application states below remain as historical and compatibility evidence; new
> launch preparation uses the [Custom Launch API](https://programmable.market/developers/custom-launch-api-v1.md).

Every Programmable-specific launch requirement comes from
[`policy/launch-policy.v1.json`](../policy/launch-policy.v1.json). Application schemas define inert transport and
evidence contracts; the [policy-bound reviewer](OPEN_REVIEW_STANDARD.md), readiness checker, Workflow Canary, and
Website eligibility verifier consume one exact protected-base policy binding. None may maintain a second requirement
list. See the [complete launch requirements](COMPLETE_LAUNCH_REQUIREMENTS.md) for the Rule-ID and command map.

## Keep every state distinct

| State | Exact evidence | Meaning |
| --- | --- | --- |
| Admission envelope prepared | Canonical Universal Admission V1 bytes | Source coordinates and disclosures are declared; they are not remotely verified or reviewed |
| Application V3.2 valid | One immutable V3.2 revision plus protected package-validator result | The current full application package is valid for review; no review, readiness, or launch right exists |
| Application V3.1 compatible | V3.1 revision validated only under the unchanged compatibility contract | A new or existing compatibility draft is valid for review; it cannot establish `launch-readiness` or the official Programmable route |
| Built | `BUILT_NOT_REVIEWED` under the bound `build` profile | The Builder completed declared checks; no review or launch right exists |
| Reviewed | Policy-bound decision for the exact application, source, policy, and subject | Review findings are attributable; missing facts remain `analysis_pending` |
| Launch readiness checked | Exact `LAUNCH_READINESS_CHECKED_NOT_AUTHORIZED` result under `launch-readiness` | Conditional fee and Router-plan checks passed; signing, deployment, broadcast, routing, promotion, and funds authority remain false |
| Accepted | Separate exact maintainer acceptance bound to the application and source | The application is accepted; signing, deployment, launch, indexing, and promotion authority are not implied |
| Launch authorized | Separate external owner or service authority | An authorized actor may prepare signing or broadcast; Launch Policy readiness never creates this authority |
| Deployed | Deployment evidence | Contracts or services were deployed; they are not automatically available |
| Launched and finalized | Canonical transaction and finalized block evidence | A transaction is final; this alone does not prove canonical Programmable provenance |
| Canonical stamp verified | Maintainer receipt matching the exact acceptance and manifest-selected Router active at the observed launch block, `chainId + Router address + launchId`, both lookups, stamp, and proofs | Router provenance is proven at one finalized canonical block; no audit or terminal adoption is implied |
| Registry, API, or public promotion | Project binding to the exact receipt path and SHA-256 | Eligible consumers may expose the verified classification; third-party adoption remains separate |
| Available | Platform release evidence and, for an applicable future Ethereum v4 market, the bound promotion receipt | Programmable currently exposes the project; provider and third-party terminal support remain separate facts |
| Suspended or retired | Maintainer lifecycle record retaining any required promotion binding | Availability is intentionally restricted or ended |

For an official Programmable Ethereum market, Application V3.2 and Submission 2.1 are required before readiness.
No-market is `not-applicable`; an unresolved route remains `analysis-pending`; a tradable route outside the official
Programmable path must not receive a Programmable Classic or Programmable Custom label. Application V3.1 remains a
historical compatibility contract and its bytes must not be rewritten.

The readiness result binds the exact 10 bps fee tuple and the applicant-owned
`.programmable/launch-router-readiness.v1.json` plan. A separate precommit preparation step embeds the current official
Developer manifest projection. The offline checker verifies those supplied bytes against the pinned official artifact
but does not fetch the endpoint or independently prove freshness. Before it may mint a protected readiness decision,
the platform must recheck trust and required freshness. It never makes one copied Router address permanent, and a
direct Classic Factory, Graph Factory, or Single Factory call cannot be relabeled as canonical Router provenance.

After an independently authorized launch, promotion requires the separate maintainer receipt
`registry/promotions/<project-id>/<launch-id>.json`, valid under
[`registry/schema/launch-stamp-promotion-v1.schema.json`](../registry/schema/launch-stamp-promotion-v1.schema.json).
The receipt must show `observation.outcome: "stamped"`, `observation.finality: "finalized"`, and internally consistent
manifest, runtime, ABI, fee, launch-kind, transaction, block, both lookups, `launchStamp`, and `stampProof` evidence.
It must also embed the full canonical passed launch-readiness decision, exact readiness bytes, the exact canonical
Application V3 root bytes, the decision subject's `applicationSha256` and `packageSha256`, and the closed promotion
evidence projection. The verifier re-derives the application/package binding from those root bytes, matches it to the
accepted package, and recomputes all remaining digests and cross-bindings; a well-formed jointly rehashed replacement
cannot substitute for the accepted content. Missing, indeterminate, non-finalized, direct-factory, or mismatched
evidence blocks Registry, API, and terminal promotion.

Policy, application, source, subject, manifest, or prior-result drift stops the chain before a semantic pass. The
Website must independently pin its signer and exact policy binding.
It must pin the expected Website audience from protected deployment configuration,
current time, and protected replay state; copying those values from an envelope is not authority.

## Disabled queue and compatibility paths

The checked-in Universal Admission queue is not a lifecycle entrypoint. Its discovery contract is
`reference-only-disabled`, and the SQLite implementation is single-host reference code with no public endpoint,
audience, trust snapshot, remote worker or admin plane, or production capacity. `QUEUED`, `DUPLICATE`, lease, retry,
dead-letter, completion, and snapshot states describe transport processing only. They never imply `Built`, review
completion, readiness, acceptance, Registry promotion, deployment, Website eligibility, availability, or launch
authority. Use the Custom Launch API for current launches.

The six-file V2 application is a frozen historical transport and the checked-in intake state is `closed`.
Its compatibility checks, green checks, merge, or old [launch-entitlement
bridge](ACCEPTANCE_ENTITLEMENT_BRIDGE_V1.md) cannot satisfy Workflow Canary, Website eligibility, readiness, or current
launch-policy requirements. The `production-launch` profile is disabled and no path emits `LAUNCH_APPROVED`.

Application validity, review, readiness, a Router stamp, acceptance, or availability is not an independent audit,
safety finding, liquidity or sellability guarantee, deployment authorization, provider guarantee, Uniswap
endorsement, or promise that GMGN, Axiom, FOMO, or another terminal will adopt the label. Each claim needs its own
attributable evidence.
