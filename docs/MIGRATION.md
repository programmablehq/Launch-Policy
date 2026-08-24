# Legacy intake migration

> [!IMPORTANT]
> GitHub intake is retired. This document preserves migration history; new launches use the
> [Custom Launch API](https://programmable.market/developers/custom-launch-api-v1.md).

The version 1 review schemas retain their original `0xprogrammable/apply` and `submit-launch` identifiers for backward
compatibility. These are stable legacy protocol names, not the current repository location. Current policy links use
`0xprogrammable/launch-policy`. A protocol identifier change requires a new schema version and explicit migration coverage.

## Application V3.2 and V3.1 compatibility

Application V3.2 is the complete current launch contract, not an in-place rewrite of V3.1, legacy V2, or Workflow
Canary data. The central schema owner is
[`intake/schemas/public-pr-application-v3.2.schema.json`](../intake/schemas/public-pr-application-v3.2.schema.json).
Historical pull requests added one revision under `submissions/<application-id>/v3/revisions/<positive-decimal-revision>/`;
those bytes now remain unchanged.

The current machine discovery record is
[`applicant-compatibility.v2.json`](../.programmable/applicant-compatibility.v2.json), validated by
[`intake/schemas/applicant-compatibility-v2.schema.json`](../intake/schemas/applicant-compatibility-v2.schema.json). It
content-binds V3.2 and its supporting Submission 2.1, Trade Capability Manifest V2, and Router-readiness contracts while
retaining V3.1 as legacy compatibility. Applicant Compatibility V1 remains legacy discovery only.

The V3.1 compatibility contract remains byte-unchanged for historical reproduction. Those revisions are never
revalidated or reinterpreted as V3.2 and cannot establish `launch-readiness` or the official Programmable Router route.
Do not copy, delete, relabel, or infer approval from the old package or pull request.

V3.2 remains project-agnostic. No-market, tradable, hook, token, app, game, service, hybrid, and previously unknown
project shapes use the same contract. Required review records remain the common review floor, while novel capability
evidence can remain in the pinned source closure or additional review records. This preserves information without
turning an unrecognized capability into an intake rejection or an implicit approval rule.

V3.2 binds Submission 2.1 through
[`open-world-submission-v2.1.schema.json`](../intake/schemas/open-world-submission-v2.1.schema.json) and the
policy-neutral [`Trade Capability Manifest V2`](../intake/schemas/trade-capability-manifest-v2.schema.json) for each
selected tradable market. A no-market project or proposal with no selected tradable market attaches none. The source
filename remains `submission.v2.json`, but its exact bytes identify schema `urn:programmable:v4-hook-submission:2.1.0`
and `standardVersion: "2.1.0"`. Each trade manifest uses
`$schema: "urn:programmable:trade-capability-manifest:2.0.0"`, contract ID `trade-capability-manifest-v2`, and version
`2.0.0`; it describes tradability and tests without embedding Programmable fee, Router, approval, label, or promotion
policy.

No-market remains `not-applicable`; an unknown or unresolved route remains `analysis-pending`. A selected Programmable
Ethereum market additionally binds `.programmable/launch-router-readiness.v1.json` and the exact `launch-readiness`
policy binding. Before pinning the source commit, a separate Builder or preparation step obtains and embeds the current
official manifest projection. The offline readiness checker verifies its exact bytes against the pinned official
Developer artifact without fetching the endpoint or independently proving endpoint freshness. Before it may mint a
protected readiness decision, the platform must separately recheck trust and required freshness. Launch Policy
exposes no fetch or mutation server. This does not turn a copied Router address into a permanent trust root. A direct
Classic Factory, Graph Factory, or Single Factory path cannot be converted into canonical provenance after launch.

After finality, a separate maintainer promotion record under
`registry/promotions/<project-id>/<launch-id>.json` must bind the canonical identity
`chainId + Router address + launchId`, record, both token and pool lookups, matching stamp, and required proofs before
Registry, API, or terminal promotion. It embeds the full canonical passed launch-readiness decision, exact readiness
bytes, the exact canonical Application V3 root bytes, the decision subject's `applicationSha256` and `packageSha256`,
and the closed promotion evidence projection. Registry validation re-derives the application/package binding from the
embedded root bytes, matches it to acceptance, and recomputes every digest and cross-binding. This postlaunch evidence
is never fabricated inside an earlier application revision.

A V3.1 or V3.2 pass proves only that the bound draft is valid for review. Readiness adds no signing or launch authority,
and a Router stamp adds no audit or safety guarantee. No migration inherits acceptance, Canary or Website eligibility,
review completion, deployment permission, Registry promotion, public routing, or real-funds authority.

## Legacy V2 and Canary continuity

Submit a Launch 1.4.0 historically activated the Hookbuilder 0.5.1 bridge. The final frozen V2 transport used the
receipt-bound Hookbuilder v0.10.3 tree, Submission 1.6.0, and intake status schema 2. The checked-in intake state is now
`closed`; its old `0xprogrammable/submit-launch` name and numeric repository ID remain historical provenance. The newer
receipt binding does not rewrite the historical 1.3.0 or 1.4.0 release or older applications.
It cannot satisfy Workflow Canary or Website eligibility.

Application pull request `0xprogrammable/programmable#62` remains on its original review thread. It is recorded in
`registry/config.json` as a continuing legacy pull request and is never silently copied, renumbered, closed, or claimed
as accepted. A Builder status client may read that original thread with the Builder version that created it.

Hookbuilder application pull requests `#10`, `#11`, `#12`, `#14`, `#15`, `#18`, `#19`, and `#20` also remain on their
original Hookbuilder review threads. They are recorded as legacy intake and are never copied or renumbered here.

The historical activation was valid only while all of the following remained true:

1. this repository is public at the exact tested commit;
2. the protected branch required `Node 24`, `public-intake`, and `CodeQL` before merge;
3. the receipt-bound Hookbuilder v0.10.3 tree targets `0xprogrammable/submit-launch` with Submission 1.6.0;
4. the vendored intake validator and receipt match that exact Builder release; and
5. `docs/builder/intake-status.json` and `registry/config.json` both reported `open`.

That legacy binding is now retired. Existing legacy review threads remain untouched. The historical one-file Workflow
Canary remains separate from V2 acceptance and does not accept new records.
