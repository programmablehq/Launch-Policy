![Programmable](https://raw.githubusercontent.com/programmablehq/PROGRAMMABLE/903b3741a6cd2981788cb09c039f0c47994c5d62/public/brand/programmable-cover.png)

# Programmable Launch Policy

Versioned requirements, schemas and deterministic checks for Programmable Custom Launches. This repository owns the public policy sources and preserves the historical records of the former GitHub application flow. Launch requests use the Custom Launch API; pull requests here are for repository maintenance.

## Launch a project

Start with the [Custom Launch quickstart](https://programmable.market/docs/developers/custom-launch-quickstart), then read [live discovery](https://programmable.market/.well-known/programmable.json) for the selected chain and contract layout.

| Project | API |
| --- | --- |
| Robinhood Chain, separate token and hook contracts | V4 profile and immutable client advertised by discovery |
| Robinhood Chain, one contract implementing token and hook roles | [MultiRole V2](https://api.programmable.market/v4/chains/4663/multi-role-custom-launches/guide.md) |
| Ethereum Mainnet | [V3 integration](https://programmable.market/developer-reference/custom-launch#quickstart) |

Create a scoped, wallet-bound key in the [API-key manager](https://programmable.market/developers/api-keys). Package and validate the exact project, submit its canonical bytes, and follow the returned status. The API prepares an authorized transaction for the controller wallet to review and sign. A policy check, API key or local build does not sign or broadcast a transaction.

Keep unchanged request bytes and their idempotency key when recovering from a timeout. Use the selected API's error code and remediation instead of switching to another chain or historical profile. GitHub launch intake is closed; opening an application pull request does not submit a launch.

## Policy sources

| Source | Responsibility |
| --- | --- |
| [Launch policy v1](policy/launch-policy.v1.json) | Preserved Router, fee and promotion business obligations |
| [Robinhood economics v1](policy/robinhood-custom-launch-economics-v1.json) | Scoped economics for fresh Robinhood profile 4.1 launches |
| [V3 admission descriptor](policy/custom-launch-admission-v3.json) | Ethereum admission fields, finding codes and evidence duties |
| [V4 admission descriptor](policy/custom-launch-admission-v4.json) | Historical Robinhood V4.0 admission contract |
| [V4.1 admission descriptor](policy/custom-launch-admission-v4.1.json) | Robinhood successor profile bound to its economics source |
| [Authority ownership](policy/launch-policy-authority-ownership.v1.json) | File, rule and entrypoint ownership inventory |

The [generated launch-policy guide](docs/LAUNCH_POLICY.md) projects the canonical policy. [Complete launch requirements](docs/COMPLETE_LAUNCH_REQUIREMENTS.md) maps its rule IDs to request and release evidence. Generated bindings in `.programmable/` connect descriptors to their exact digests; they do not create another policy authority.

Robinhood Native20 requires the full **20 bps (0.20%)** Programmable fee on the covered native ETH buy and sell paths, separately from project creator fees and pool fees. Ethereum keeps the request-bound policy obligation for the 10 bps Programmable share. The public V3 profile keeps `feeBehaviorClaim: false`; the selected profile determines its exact enforcement boundary. A policy requirement does not retroactively change an older deployment or prove a fee was earned. [Product fees and revenue](https://programmable.market/docs/economics) explains the user-facing rates, recipient accounting and allocation policy.

## Evidence and compatibility

The protected Custom Launch API is the executable authority for source, build, economic evidence and transaction simulation required by its selected profile. Caller attestations identify submitted evidence but cannot mint an admission receipt. Novel architecture alone is not a defect; missing or contradictory evidence is handled under the profile's published rules.

Preparation, wallet signing, deployment, finality, source verification, indexing and trading support are separate results. A canonical Router stamp establishes origin for its exact launch, not an audit, safe behavior, current liquidity or adoption by a third-party terminal.

Read active creation capabilities from the live API. Versioned documents and historical descriptors preserve their original status and bytes. The V4.0 descriptor's recorded status does not override a separately released V4.1 or MultiRole context. Ethereum V1 and V2 preserve historical reads and reject fresh creation with their documented read-only errors.

## Inspect and validate

Node.js 24.12 or newer is required:

```sh
git clone --depth 1 https://github.com/programmablehq/Launch-Policy.git
cd Launch-Policy
npm run policy -- validate-policy
npm run policy -- requirements --profile launch-readiness
npm run policy -- requirements --profile robinhood-launch-readiness
npm run policy -- binding --profile robinhood-production-launch
npm test
```

The checker reads fixed repository-owned policy files and emits deterministic results. It does not execute a candidate project, authorize a wallet or provide launch permission. The `launch-readiness` mode is checker-only and returns `LAUNCH_READINESS_CHECKED_NOT_AUTHORIZED`. See the [Policy-Bound Review Standard](docs/OPEN_REVIEW_STANDARD.md) for evidence interpretation.

## Historical GitHub records and discovery

The [submissions/](submissions/) directory preserves former V2, V3.1, and V3.2 application records. The [canary-submissions/](canary-submissions/) directory preserves former Workflow Canary records. [Registry history](registry/history/) retains its append-only records. Historical namespaces and frozen vendor bytes are not current launch entry points.

Integrations can read [registry/index.json](registry/index.json) or [registry/search-index.json](registry/search-index.json) at an exact commit and verify each record digest. Read the [discovery contract](docs/DISCOVERY_CONTRACT.md) before consuming them. The repository was formerly named `0xprogrammable/submit-launch`. That name remains in versioned legacy protocol identifiers, frozen vendor bytes, historical snapshots, and old provenance links. The legacy validators remain available for reproducing historical records. Pull requests that modify the historical application namespaces fail closed.

## Contribute and report issues

Read [CONTRIBUTING.md](CONTRIBUTING.md) for policy, schema, checker, workflow and documentation changes. Regenerate the authority inventory and run the complete repository gate for reviewed changes. Keep historical application records separate from maintenance work.

Use [issues](https://github.com/programmablehq/Launch-Policy/issues/new/choose) for reproducible defects and [private security reporting](https://github.com/programmablehq/Launch-Policy/security/advisories/new) for vulnerabilities. Never publish credentials, signing material or private project data.

[Platform](https://programmable.market) · [Docs](https://programmable.market/docs) · [Discord](https://discord.com/invite/programmable) · [X](https://x.com/ProgrammableHQ) · [Dune](https://dune.com/programmablehq/analytics)
