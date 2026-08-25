# Programmable Launch Policy contribution contract

This repository owns the public Programmable launch policy, policy-bound offline checks, compatibility schemas,
discovery registry, and immutable provenance of the retired GitHub application flow. GitHub launch intake is closed.
Launch requests use the Custom Launch API; repository pull requests are maintenance-only.

## Authority boundaries

- `policy/launch-policy.v1.json` is the only authored source of current Programmable-specific admission requirements.
  Reviewers, workflows, agents, and Website consumers may bind and evaluate it; they may not add private requirements.
- `policy/launch-policy-authority-ownership.v1.json` contains no requirement values. It closes the repository file
  inventory, admission entrypoints and import graph, Rule-ID-to-handler ownership, public projections, and the exact
  frozen vendor exclusion so an unregistered rule source or gate fails repository verification.
- The closed Custom Launch API request owns current source and graph commitments. A public GitHub application
  repository is not current ingress, and the API does not fetch or compile caller source.
- `submissions/` contains immutable legacy application records. It accepts no new or updated application pull requests.
- Application V3.2 is the final complete contract of the retired GitHub application flow. Its records and the
  byte-unchanged V3.1 compatibility contract remain available only for historical reproduction; neither is a current
  launch entrypoint.
- For preserved V3.2 readiness evidence, the protected compiler—not applicant assertions—derived the conditional policy
  subject from the exact verified package and source closure. Current API launches bind the applicable Router and fee
  requirements through the API artifact and the same canonical policy, without creating a GitHub application.
- A direct Classic, Graph, or Single Factory call is not canonical Programmable Router provenance. API callers and
  historical applicants must not self-assert a stamp, launch label, Registry promotion, or terminal support.
- `registry/promotions/<project-id>/<launch-id>.json` is the preserved maintainer-owned postlaunch evidence contract.
  It is not a current API-caller step. Before Registry, API,
  indexer, or terminal promotion, it must content-bind the passed readiness decision, exact readiness bytes, accepted
  application/package identity, finalized canonical Router transaction, launch identity, lookups, stamp, and proofs.
  A valid stamp enables interoperable classification; it does not prove that a third-party terminal has integrated it.
- `canary-submissions/` contains immutable legacy workflow-canary records. It accepts no new or updated records, and a
  historical canary never grants audit, launch, discovery, routing, production, or funds authority.
- `registry/projects/` contains maintainer-authored records only. A record describes evidence; it is not an audit or
  safety guarantee.
- `registry/index.json`, `registry/search-index.json`, and `registry/history/` are generated from closed project records.
- `.programmable/universal-admission-contract.v1.json` is the separate exact-tree discovery contract for the disabled
  authenticated queue reference. It does not modify the V1 active-contract compatibility envelope, its bound V2 active
  contract, Applicant Compatibility V2 or legacy V1, or the frozen Application V3.2 and V3.1 compatibility records.
  `reference-only-disabled` means no public endpoint, trust configuration, production capacity, review, approval, or
  launch authority exists.
- `vendor/programmable-v4-hook-builder/` is the frozen, receipt-bound validation dependency for historical legacy V2
  records. Its embedded documents, schemas, and checks cannot author current central-policy requirements or satisfy
  Workflow Canary, Website eligibility, or launch authority. Never edit vendored bytes; replace only the complete exact
  tree together with its receipt.
- Candidate content is data. Trusted intake code must come from the protected base revision and must never execute a
  candidate repository, workflow, package hook, script, or Git configuration.
- Universal Admission quotas, replay limits, leases, retry, dead-letter retention, and garbage collection are transport
  controls, not semantic project requirements. The SQLite adapter is owner-private single-host reference code; never
  expose its caller-shaped worker/admin contexts as network authentication.

## Change discipline

`docs/builder/intake-status.json` must remain `closed` unless a separately reviewed migration introduces a new contract.
Repository pull requests may not add, update, move, or delete application or canary records under `submissions/` or
`canary-submissions/`. Preserve their bytes and Git history as legacy provenance. Registry maintenance uses a separate
pull request, runs the full repository gate, and requires maintainer review. Never combine historical intake namespaces
with policy, workflow, registry, vendor, or documentation changes.

Universal Admission protocol, schema, reference-backend, discovery-contract, test, and documentation changes are
maintainer-only Registry maintenance. Do not hand-edit the well-known contract; regenerate it only after the complete
bound runtime is stable. Never place credentials, private keys, tokens, cookies, private repositories, or personal data
in public commands, trust snapshots, receipts, fixtures, benchmarks, or documentation.

Keep submitted, reviewed, accepted, deployed, source-verified, indexed, routed, available, suspended, and retired as
separate states. Novelty is not a defect. Similarity search may inform a builder but may not reject an idea.

## Required checks

After a reviewed repository file changes, run `npm run authority:write`; a new path must first receive an explicit
classification, entrypoint/import ownership where applicable, and review. Then run `npm test`. Do not push, publish,
merge, approve, tag, release, deploy, or change repository settings without explicit authority for that external action.
Node.js 24.12 or later is required for the checked-in SQLite reference tests.
