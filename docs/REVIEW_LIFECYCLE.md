# Review and promotion lifecycle

> [!IMPORTANT]
> GitHub application intake is closed. Application states below remain as historical and compatibility evidence; new
> launch preparation starts at
> [`/.well-known/programmable.json`](https://programmable.market/.well-known/programmable.json) and follows its
> advertised V3 capabilities, CLI, guide, and OpenAPI to `POST https://api.programmable.market/v3/custom-launches`.
> V1 creation is historical read-only compatibility and returns non-retryable `409 CUSTOM_LAUNCH_V1_READ_ONLY`.

[`policy/launch-policy.v1.json`](../policy/launch-policy.v1.json) owns Programmable Router, fee, and promotion business
obligations. The separate public
[`policy/custom-launch-admission-v3.json`](../policy/custom-launch-admission-v3.json) discloses the current V3 profile,
finding rules, evidence duties, and false-claim boundaries without adding business requirements. The private Custom
Launch API exact-source scanner and Router simulation are the sole executable admission-evidence authorities.

The application schemas, [policy-bound reviewer](OPEN_REVIEW_STANDARD.md), Workflow Canary, and Website eligibility
verifier described below remain historical or compatibility consumers. They cannot accept a current API request or
maintain a second requirement list. See the
[complete launch requirements](COMPLETE_LAUNCH_REQUIREMENTS.md) for the current authority and Rule-ID map.

## Current Custom Launch API lifecycle

Resolve the current transport from public
[`discovery`](https://programmable.market/.well-known/programmable.json), require the advertised
[`/v3/capabilities`](https://api.programmable.market/v3/capabilities) profile, and use its checksum-bound CLI to
`pack`, `validate --remote`, and `submit` the byte-identical request. A repository application or pull request cannot
enter this lifecycle.

The API contract owns the current request states:

```text
received -> validating
             |-> awaiting_funding_authorization -> funding_authorization_verified
             |                                             |
             +--------------------> pending_review <-> action_required
                                           |
                                      prepared -> simulating -> authorized -> submitted -> finalized
```

`failed` and `cancelled` are terminal alternatives. The funding-authorization branch applies only when the selected
funding mode requires it. `action_required` carries deterministic remediation for an exact blocking condition; it is
not a wallet action or a request for manual approval. Only `awaiting_funding_authorization` and `authorized` expose
separate controller-wallet handoffs. The API never signs or broadcasts for the wallet.

## Preserved compatibility and promotion evidence states

| State | Exact evidence | Meaning |
| --- | --- | --- |
| Historical Universal Admission envelope prepared | Canonical Universal Admission V1 bytes | A preserved reference declaration is structurally valid; it is not current API ingress and its source coordinates are not remotely verified or reviewed |
| Historical Application V3.2 valid | One immutable V3.2 revision plus protected package-validator result | A preserved full application package was valid for review under the retired GitHub flow; no current launch right exists |
| Historical Application V3.1 compatible | V3.1 revision validated only under the unchanged compatibility contract | A preserved compatibility draft remains reproducible; it cannot establish a current launch or the official Programmable route |
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

Current API launches do not create or update Application V3.2 records. They bind the applicable policy, fee and Router
plan through the API artifact and remain separate from wallet authorization. For historical readiness reproduction,
the original Application V3.2 and Submission 2.1 bytes remain required. Application V3.1 remains a historical
compatibility contract and its bytes must not be rewritten.

The readiness result binds the exact 10 bps fee tuple and the applicant-owned
`.programmable/launch-router-readiness.v1.json` plan. A separate precommit preparation step embeds the current official
Developer manifest projection. The offline checker verifies those supplied bytes against the pinned official artifact
but does not fetch the endpoint or independently prove freshness. Before it may mint a protected readiness decision,
the platform must recheck trust and required freshness. It never makes one copied Router address permanent, and a
direct Classic Factory, Graph Factory, or Single Factory call cannot be relabeled as canonical Router provenance.

For preserved application-bound promotion evidence, an independently authorized launch required the separate
maintainer receipt
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

For preserved Canary and Website-envelope verification, policy, application, source, subject, manifest, or prior-result
drift stops the chain before a semantic pass. The Website must independently pin its signer and exact policy binding.
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
launch-policy requirements. The current `production-launch` profile is enabled only as a non-authorizing checker and
emits `PRODUCTION_REQUIREMENTS_CHECKED_NOT_AUTHORIZED`; no path emits `LAUNCH_APPROVED`.

Application validity, review, readiness, a Router stamp, acceptance, or availability is not an independent audit,
safety finding, liquidity or sellability guarantee, deployment authorization, provider guarantee, Uniswap
endorsement, or promise that GMGN, Axiom, FOMO, or another terminal will adopt the label. Each claim needs its own
attributable evidence.
