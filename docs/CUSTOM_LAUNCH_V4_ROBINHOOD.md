# Robinhood Custom Launch V4 policy

Robinhood Chain support is a separate V4 admission lane. It does not widen or reinterpret Ethereum Custom Launch V1,
V2 or V3. The current public status is `planned`. A policy file, local checker result or HTTP response does not make
the chain live.

The machine contracts are:

- [`policy/custom-launch-admission-v4.json`](../policy/custom-launch-admission-v4.json), the authored V4 admission
  disclosure;
- [`policy/schemas/custom-launch-admission-v4.schema.json`](../policy/schemas/custom-launch-admission-v4.schema.json),
  its closed JSON Schema;
- [`.programmable/custom-launch-admission.v4.json`](../.programmable/custom-launch-admission.v4.json), the generated
  binding to the canonical business-policy digest; and
- [`policy/launch-policy.v1.json`](../policy/launch-policy.v1.json), the only authored source of Router, readiness and
  promotion obligations.

## Server-selected profiles

The authenticated API server selects the policy profile from the chain-bound request. The client, CLI, applicant and
agent cannot select or override it.

| Purpose | Profile | Result boundary |
| --- | --- | --- |
| Pre-wallet readiness | `robinhood-launch-readiness` | Checks requirements; never authorizes a launch or funds |
| Production promotion | `robinhood-production-launch` | Checks production evidence; never creates onchain evidence or a live declaration |

Both profiles bind chain ID `4663` and CAIP-2 `eip155:4663`. Every `LAUNCH.ROBINHOOD_*` rule applies only to these
profiles. Existing `LAUNCH.ETHEREUM_*` rules retain their prior profile membership and semantics.

## V4 admission boundary

The planned lane supports a bounded graph of 3 to 16 new targets, project-owned tokens, project-owned hooks and all 14
Uniswap v4 permission bits structurally. Structural support is not approval of invalid, unreproducible or malicious
contracts. The private Custom Launch API remains the executable authority for exact-source checks, permission-address
matching, callback implementation and PoolManager authentication, CREATE2 predictions, accounting, settlement,
chain-specific simulation and exact wallet-transaction preparation.

A V4 graph may use an external contract reference only as a bounded, exact dependency. Before either server-selected
profile can pass, protected server evidence must bind the reference's `eip155:4663` address, live runtime hash,
source-verification evidence, declared graph role and verification checkpoint. An arbitrary, cross-chain,
missing-code, stale-hash or otherwise unbound reference remains untrusted and blocks admission with
`UNBOUND_EXTERNAL_CONTRACT_REFERENCE`. This rule does not claim that Robinhood V4 or the referenced contract is live.

The foundation source closure is pinned by commitment
`0xe87f5edc2dc839bd87a26a80cb53f14b021e603a1753d27aae3a02862058d730`. That commitment identifies reviewed source;
it is not deployment evidence. Sourcify v2 exact match is the required supported source-verification path. Robinhood
Blockscout is optional, currently unproven and degraded: it cannot support an exact-source claim or block or revise
finality until separate evidence proves that provider path.

There is no manual project allowlist. Novelty is not a rejection reason. Objective failures such as wrong-chain
binding, wrong trust roots, missing callback authentication, non-reproducible bytecode, cross-chain replay,
unbalanced settlement or mutated wallet calldata remain hard failures.

The initial advertised funding modes are only `none` and `wallet-transaction-value`. ERC-20, Permit2 or EIP-3009 modes
must remain absent until their exact Robinhood token, authorization, nonce, replay and settlement semantics have
separate evidence.

## Public pointers

Public discovery may advertise these stable contracts while Robinhood remains planned. Canary discovery begins only
after the deployment gate has passed:

- capabilities: `/v4/chains/4663/capabilities`
- preflight: `/v4/chains/4663/custom-launches/preflight`
- create: `/v4/chains/4663/custom-launches`
- single-resource status: `/v4/chains/4663/custom-launches/{launchId}`
- finalized launches: `/v4/chains/4663/finalized-custom-launches`
- OpenAPI: `https://programmable.market/openapi/custom-launch-v4.json`
- pack schema: `https://programmable.market/schemas/custom-launch/v4/pack-config.json`

These pointers describe the V4 contract. Clients must still check the chain status in live discovery and must not send
Robinhood writes while it is `planned`.

The descriptor publishes one reviewed, code-owned promotion anchor even while status is `planned`. Callers cannot fill
or replace its fields. It fixes deployment ID `robinhood-mainnet-custom-launch-v1`, finality-policy digest
`sha256:537d531423d1285a3808556a57303ec68f1e6bdeea3c9aaf6320f9e5a0e47153`, the foundation source commitment and every
currently known address and runtime code hash. The machine descriptor is authoritative for the hashes; the deployment
roots and currently reviewed start blocks are:

| Root | Address | Start block |
| --- | --- | ---: |
| GraphFactory | `0x0B6b3F40f84Df25D3bd69238f937096177DD09Bd` | `null`, pending reviewed broadcast evidence |
| Permit2 | `0x000000000022D473030F116dDEE9F6B43aC78BA3` | `null`, provenance unresolved |
| PermitAuthority Safe | `0xeD617CE7f82e2AB589aDeFFD319D1D872Bc8De06` | `null`, pending reviewed broadcast evidence |
| PoolManager | `0x8366a39CC670B4001A1121B8F6A443A643e40951` | `9070` |
| PositionManager | `0x58daec3116aae6D93017bAAea7749052E8a04fA7` | `9073` |
| Programmable Launch Stamp Router | `0x34965F2A2ee9254522232C32F02056E92BE0C98a` | `null`, pending reviewed broadcast evidence |
| StateView | `0xF3334192D15450CdD385c8B70e03f9A6bD9E673b` | `9075` |
| Universal Router | `0x06AfBA43Fd06227fA663b0DAecF536f6EaA6bf99` | `3347899` |
| V4 Quoter | `0x8Dc178eFB8111BB0973Dd9d722ebeFF267c98F94` | `9074` |

Permit2 is deliberately not assigned a deployment block. Official Uniswap material establishes its canonical address
and the pinned Uniswap registry calls it a pre-existing deployment, but neither supplies its deployment transaction or
date. One archive provider returned code at block `0`; a second independent provider was unavailable. That cannot
establish deployment provenance, so the anchor preserves the reviewed address and runtime hash while keeping its start
block `null`.

Only seven evidence fields remain `null`: the chain-deployment descriptor digest, finalized block, finalized evidence
reference and the four start blocks identified above. The first three and the three Programmable start blocks are
post-broadcast evidence. Permit2 is the bounded provenance exception. The schema requires all of them before `canary`,
does not permit `live`, and the checker rejects every caller mutation. Promotion therefore remains fail-closed until a
reviewed code update replaces the legitimate nulls with exact evidence and advances the status.

## Promotion truth

Robinhood can move from `planned` to `canary` only after the chain deployment descriptor binds the exact Programmable
Router, GraphFactory and PermitAuthority deployments and live runtime hashes. It can move to `live` only after all
production gates pass, including provider/finality health, server validation and simulation, exact wallet handoff,
finalized Router evidence, Router-backed read-model projection, source-verification jobs and matching public
discovery.

Fee certification stays separate from launch validity. The V4 descriptor keeps `feeBehaviorClaim`,
`universalFeeBehaviorClaim`, generic claiming and buybacks false. External terminals and indexers decide whether to
integrate published metadata and feeds; Programmable does not guarantee their indexing.
