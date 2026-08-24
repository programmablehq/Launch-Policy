<p align="center">
  <img src="assets/repository-cover.jpg" alt="Programmable islands connected by streams, representing composable projects" width="100%">
</p>

<h1 align="center">Programmable Launch Policy</h1>

<p align="center">
  Versioned requirements, schemas, offline checks, and historical provenance for Programmable launches.
</p>

<p align="center">
  <a href="https://github.com/0xprogrammable/launch-policy/actions/workflows/verify.yml"><img src="https://github.com/0xprogrammable/launch-policy/actions/workflows/verify.yml/badge.svg?branch=main" alt="Repository verification"></a>
  <a href="https://github.com/0xprogrammable/launch-policy/actions/workflows/codeql.yml"><img src="https://github.com/0xprogrammable/launch-policy/actions/workflows/codeql.yml/badge.svg?branch=main" alt="CodeQL analysis"></a>
  <a href="https://github.com/0xprogrammable/launch-policy/releases/latest"><img src="https://img.shields.io/github/v/release/0xprogrammable/launch-policy?label=release" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/0xprogrammable/launch-policy" alt="MIT License"></a>
</p>

> [!IMPORTANT]
> **GitHub launch intake is closed.** Do not open a pull request to submit a launch, application, template, or workflow
> canary. Create an [API key](https://programmable.market/developers/api-keys) and use the
> [Custom Launch API](https://programmable.market/developers/custom-launch-api-v1.md). The write endpoint is
> `https://api.programmable.market/v1/custom-launches`.

This repository is the public owner of Programmable launch requirements. It keeps the canonical policy, schemas,
deterministic offline checks, generated policy projections, discovery records, and the immutable history of the former
GitHub application flow. It does not accept or launch projects.

## API-first launch path

Agents and developers should use these public surfaces:

- [Create and manage API keys](https://programmable.market/developers/api-keys)
- [Read the Custom Launch API guide](https://programmable.market/developers/custom-launch-api-v1.md)
- [Read the OpenAPI document](https://programmable.market/openapi.json)
- Submit prepared launch requests to `POST https://api.programmable.market/v1/custom-launches`

The API prepares a launch transaction. Wallet review, signing, broadcast, finality, indexing, and later promotion remain
separate states. An API response, local checker pass, or policy match does not authorize a wallet or prove an onchain
launch.

## Launch policy

The only authored source of Programmable-specific launch requirements is
[`policy/launch-policy.v1.json`](policy/launch-policy.v1.json). Its
[`JSON Schema`](policy/schemas/launch-policy.v1.schema.json) closes the authored format, and
[`docs/LAUNCH_POLICY.md`](docs/LAUNCH_POLICY.md) is a generated, digest-bound human projection.

The [complete launch requirements guide](docs/COMPLETE_LAUNCH_REQUIREMENTS.md) maps stable Rule IDs to the current
request, readiness, and promotion evidence. It explains the rules; it does not create additional requirements.

For a selected Programmable Ethereum market, the current policy covers:

- the policy-defined 10 bps Programmable share of gross canonical-pool volume;
- an exact plan for the manifest-resolved canonical Router;
- finalized matching Router stamp evidence before public promotion; and
- protected finalized fee-settlement evidence before production promotion.

Verified no-market and external-route states are not applicable to Router-specific rules. Incomplete or contradictory
evidence remains `analysis-pending`. Unknown project types are not rejected merely because they are unfamiliar.

## Inspect and validate the policy

Node.js 24.12 or newer is required.

```bash
git clone --depth 1 https://github.com/0xprogrammable/launch-policy.git
cd launch-policy
npm run policy -- validate-policy
npm run policy -- requirements --profile build
npm run policy -- requirements --profile launch-readiness
npm run policy -- binding --profile launch-readiness
npm run policy -- render
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
record. Current repository and policy references use `0xprogrammable/launch-policy`.

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

- [Report a non-sensitive policy, checker, schema, or registry problem](https://github.com/0xprogrammable/launch-policy/issues/new/choose).
- [Discuss a policy or architecture idea](https://github.com/0xprogrammable/launch-policy/discussions).
- [Report an exploitable vulnerability privately](https://github.com/0xprogrammable/launch-policy/security/advisories/new).

Use [Hookbuilder issues](https://github.com/0xprogrammable/hookbuilder/issues/new/choose) for builder installation or
project-construction support. Repository issues do not provide project approval, wallet authorization, deployment,
investment advice, or guaranteed implementation support.
