<p align="center">
  <img src="assets/repository-cover.jpg" alt="Programmable islands connected by streams, representing composable projects" width="100%">
</p>

<h1 align="center">Programmable Launch Policy</h1>

<p align="center">
  Versioned requirements, schemas, offline checks, and historical provenance for Programmable launches.
</p>

<p align="center">
  <a href="https://github.com/0xprogrammable/Launch-Policy/actions/workflows/verify.yml"><img src="https://github.com/0xprogrammable/Launch-Policy/actions/workflows/verify.yml/badge.svg?branch=main" alt="Repository verification"></a>
  <a href="https://github.com/0xprogrammable/Launch-Policy/actions/workflows/codeql.yml"><img src="https://github.com/0xprogrammable/Launch-Policy/actions/workflows/codeql.yml/badge.svg?branch=main" alt="CodeQL analysis"></a>
  <a href="https://github.com/0xprogrammable/Launch-Policy/releases/latest"><img src="https://img.shields.io/github/v/release/0xprogrammable/Launch-Policy?label=release" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/0xprogrammable/Launch-Policy" alt="MIT License"></a>
</p>

> [!IMPORTANT]
> **GitHub launch intake is closed.** Do not open a pull request to submit a launch, application, template, or workflow
> canary. Start at [`/.well-known/programmable.json`](https://programmable.market/.well-known/programmable.json),
> follow its live V3 capabilities, CLI, guide, and OpenAPI links, then create through
> `POST https://api.programmable.market/v3/custom-launches` with a wallet-bound API key.

This repository is the public owner of Programmable launch requirements. It keeps the canonical policy, schemas,
deterministic offline checks, generated policy projections, discovery records, and the immutable history of the former
GitHub application flow. It does not accept or launch projects.

## API-first launch path

Agents and developers should use these public surfaces:

- [Resolve current discovery](https://programmable.market/.well-known/programmable.json)
- [Read live V3 capabilities](https://api.programmable.market/v3/capabilities)
- [Create and manage API keys](https://programmable.market/developers/api-keys)
- Install the exact checksum-bound CLI release advertised by discovery
- [Read the current Custom Launch guide](https://programmable.market/docs/developers/custom-launch)
- [Read the V3 OpenAPI document](https://programmable.market/openapi/custom-launch-v3.json)
- Submit the CLI-produced request bytes to `POST https://api.programmable.market/v3/custom-launches`

Use the order discovery → capabilities → advertised CLI → `pack` → `validate --remote` → `submit` → status/wallet
handoff. The API prepares an exact launch transaction; the controller wallet reviews, signs, and broadcasts separately.
Finality, indexing, source verification, trading evidence, fee-behavior evidence, and later promotion remain separate
states. An API response, local checker pass, or policy match does not authorize a wallet or prove an onchain launch.

V1 creation is permanently read-only compatibility and returns non-retryable `409 CUSTOM_LAUNCH_V1_READ_ONLY`. V1 and
V2 resources remain readable or byte-identical retryable only under their published compatibility contracts. Neither
legacy API versions nor the retired GitHub flow are current creation instructions.

## Launch policy

The canonical business-policy source for Programmable Router, fee, and promotion obligations is
[`policy/launch-policy.v1.json`](policy/launch-policy.v1.json). Its
[`JSON Schema`](policy/schemas/launch-policy.v1.schema.json) closes the authored format, and
[`docs/LAUNCH_POLICY.md`](docs/LAUNCH_POLICY.md) is a generated, digest-bound human projection.

The separate public [V3 admission descriptor](policy/custom-launch-admission-v3.json) declares the current profile,
hard-block finding rules, evidence-bound codes, executable-evidence duties, and false claim boundaries. Its generated
[digest and cross-projection contract](.programmable/custom-launch-admission.v3.json) binds those values to the JSON
pointers exposed by discovery, capabilities, and V3 OpenAPI. This descriptor does not implement admission and does not
add a second business-policy authority: the private Custom Launch API is the sole executable exact-source, static,
behavior-execution, and Router-simulation evidence authority. A CLI, agent, or client cannot mint an admission receipt.

The [complete launch requirements guide](docs/COMPLETE_LAUNCH_REQUIREMENTS.md) maps stable Rule IDs to the current
request, readiness, and promotion evidence. It explains the rules; it does not create additional requirements.

For a selected Programmable Ethereum market, the current policy covers:

- the request-bound policy obligation for the 10 bps Programmable share;
- an inactive `3.4.0` exact-fee execution contract whose activation is separately gated on server runtime proof and
  an autonomous exact-route settlement-dataflow closure receipt;
- an exact plan for the manifest-resolved canonical Router;
- finalized matching Router stamp evidence before public promotion; and
- the evidence boundary required before any later fee-behavior claim.

The 10 bps tuple is a business and request-binding obligation, not a blanket statement that every deployed runtime has
already paid it. Profile `3.3.0` remains current; the public V3 profile keeps `feeBehaviorClaim: false`. Candidate `3.4.0` is explicitly
inactive: it accepts no fresh writes until the frozen fee-vault release, server action and observation ABIs, configured
signed runner identity, production runtime readback, and separate trusted closure receipt match exactly. Runner
no-bypass evidence covers only canonical vault entrypoints, so candidate-route coverage must come from the closure
authority. Its future gate covers only the four fee vectors; all other custom behavior remains unclaimed unless
separately executed.

Verified no-market and external-route states are not applicable to Router-specific rules. Incomplete or contradictory
evidence remains `analysis-pending`. Unknown project types are not rejected merely because they are unfamiliar.

## Inspect and validate the policy

Node.js 24.12 or newer is required.

```bash
git clone --depth 1 https://github.com/0xprogrammable/submit-launch.git
cd submit-launch
npm run policy -- validate-policy
npm run policy -- requirements --profile build
npm run policy -- requirements --profile launch-readiness
npm run policy -- binding --profile launch-readiness
npm run policy -- render
npm run admission:v3 -- --check
```

These commands read the fixed repository-owned policy path, emit deterministic output, and never import or execute
project code. `launch-readiness` is checker-only and returns
`LAUNCH_READINESS_CHECKED_NOT_AUTHORIZED`; it does not sign, deploy, broadcast, promote, or authorize funds.

Run the complete repository gate with:

```bash
npm test
```

## Open Review Standard

The policy-bound reviewer consumes the same canonical policy as every other consumer. Analyzer input can name a Rule
ID, state, evidence references, and analyzer identity. Requirement text, enforcement, and outcome come from the exact
trusted policy. Unknown Rule IDs are advisory, and missing evidence remains pending.

The public checker does not fetch private repositories, execute project code, reproduce an audit, sign a platform
decision, deploy contracts, route traffic, handle funds, or issue launch permission. Read the
[Policy-Bound Review Standard](docs/OPEN_REVIEW_STANDARD.md).

## Historical GitHub records

The former application namespaces remain public and immutable for provenance:

- [`submissions/`](submissions) preserves former V2, V3.1, and V3.2 application records.
- [`canary-submissions/`](canary-submissions) preserves former Workflow Canary records.
- [Legacy GitHub intake documentation](docs/builder/PUBLIC_GITHUB_PR_BETA.md) records the retired transport contract.
- [`registry/history/`](registry/history) is append-only release history.

The legacy validators remain available for reproducing historical records, but no GitHub application path is active.
Pull requests that modify the historical application namespaces fail closed and point to the API.

The repository was formerly named `0xprogrammable/submit-launch`. That name remains only in versioned legacy protocol
identifiers, frozen vendor bytes, historical snapshots, and old provenance links where changing it would rewrite the
record. Current public links use `0xprogrammable/Launch-Policy`; protected bindings retain the case-normalized machine
identity `0xprogrammable/launch-policy`.

## Discovery registry

Agents and integrations may read [`registry/index.json`](registry/index.json) or
[`registry/search-index.json`](registry/search-index.json) at one exact commit, then verify each selected record digest.
Registry evidence does not prove safety, acceptance, deployment, liquidity, provider support, or current availability.

Maintainer-authored promotions remain separate from launch submission. A future market may be promoted only after the
required finalized Router, component, policy, and source bindings exist. A valid promotion record does not guarantee
third-party terminal adoption.

Read the [discovery contract](docs/DISCOVERY_CONTRACT.md) before integrating.

## Repository maintenance

Pull requests are accepted only for policy, schema, checker, documentation, workflow, or registry maintenance. Read
[`CONTRIBUTING.md`](CONTRIBUTING.md) before proposing a change. Never mix policy maintenance with historical submission
records.

## Report a problem

- [Report a non-sensitive policy, checker, schema, or registry problem](https://github.com/0xprogrammable/Launch-Policy/issues/new/choose).
- [Discuss a policy or architecture idea](https://github.com/0xprogrammable/Launch-Policy/discussions).
- [Report an exploitable vulnerability privately](https://github.com/0xprogrammable/Launch-Policy/security/advisories/new).

Launch Policy issues cover policy, checker, schema, Registry, and documentation defects. They do not provide project
construction, API operation, project approval, wallet authorization, deployment, investment advice, or guaranteed
implementation support.
