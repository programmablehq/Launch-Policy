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
roots, provenance and currently reviewed start blocks are:

| Root | Address | Provenance | Start block |
| --- | --- | --- | ---: |
| GraphFactory | `0x0B6b3F40f84Df25D3bd69238f937096177DD09Bd` | `null`, unbroadcast | `null` |
| Permit2 | `0x000000000022D473030F116dDEE9F6B43aC78BA3` | `genesis-allocation` | `0` |
| PermitAuthority Safe | `0xeD617CE7f82e2AB589aDeFFD319D1D872Bc8De06` | `null`, unbroadcast | `null` |
| PoolManager | `0x8366a39CC670B4001A1121B8F6A443A643e40951` | `deployment-transaction` `0x4fb28d4935866f462582c6c931c6f2705e55f5be5eb178c7d8d9329a95c44c41` | `9070` |
| PositionManager | `0x58daec3116aae6D93017bAAea7749052E8a04fA7` | `deployment-transaction` `0x228c18ada6cb46b4fbcc18f4ec1519953415393e256fa8349aafbd5a2db037c8` | `9073` |
| Programmable Launch Stamp Router | `0x34965F2A2ee9254522232C32F02056E92BE0C98a` | `null`, unbroadcast | `null` |
| StateView | `0xF3334192D15450CdD385c8B70e03f9A6bD9E673b` | `deployment-transaction` `0x3d61e2c9eeb482385b1aa436b9e8f812167ea579cc390e4f93bc5abde00582f4` | `9075` |
| Universal Router | `0x06AfBA43Fd06227fA663b0DAecF536f6EaA6bf99` | `deployment-transaction` `0xdfb76494e158d8dea4376160315239271636a18515207fd4526e574bc7eeb456` | `3347899` |
| V4 Quoter | `0x8Dc178eFB8111BB0973Dd9d722ebeFF267c98F94` | `deployment-transaction` `0x6bf436d72a17f87284ddcab43094689bd320dfb39b535213b9a0b669fabc4ab4` | `9074` |

Robinhood's official [full-node instructions](https://docs.robinhood.com/chain/run-a-full-node/) require the Mainnet
[genesis file](https://cdn.robinhood.com/assets/generated_assets/hoodchain_docsite/chain-node-configs/robinhood-genesis.json).
The exact file is bound as
`sha256:353e6f6441b47695b41cee0c3645cde8dd7492d2f7f574bfb6aa4371e41bb6ba`. Its allocation at the
canonical Permit2 address contains 9,152 runtime-code bytes whose Keccak-256 is the pinned
`0x5208783f52488f7d3493e5e38311ab707c1d75457fe472a19b0b4d57d66a7fca`. Permit2 therefore has exact
`genesis-allocation` provenance and start block `0`; it is not an inferred transaction deployment.

The five positive start blocks use `deployment-transaction` provenance from the commit-pinned official
[Uniswap registry](https://raw.githubusercontent.com/Uniswap/contracts/4cfc406c8e34da3ce04e60657a7825075b64fd22/deployments/json/4663.json),
bound as `sha256:21964cefbfc24b0ee89e7427acf74d223ce5a50aeb4216a9bac361a6148dea15`. The schema permits block `0`
only with the exact genesis allocation, requires a positive block and transaction hash for a transaction deployment,
and requires provenance and start block to be jointly `null` for an unbroadcast root.

Only nine evidence leaves remain `null`: the chain-deployment descriptor digest, finalized block, finalized evidence
reference, and both provenance and start block for the three unbroadcast Programmable roots. The schema requires all of
them before `canary`, does not permit `live`, and the checker rejects every caller mutation. Its current completion
schema also marks each unbroadcast root unsatisfiable, so copying a generic deployment transaction, the Uniswap
registry, block `0` or another root's source proof can never certify it. Promotion therefore remains fail-closed until
a reviewed code update replaces the legitimate nulls, introduces exact per-root evidence contracts and advances the
status.

That future update must bind GraphFactory and the Programmable Router to their own finalized deployment transaction,
positive start block and per-address Sourcify v2 exact match. PermitAuthority Safe needs a distinct finalized proxy and
configuration receipt, not generic transaction or Sourcify evidence: two independent provider readbacks must bind the
proxy runtime, singleton/master-copy address and runtime/version, handler, owners, threshold, nonce, modules, guard and
the relevant handler slots. The receipt must also pin the reviewed Safe deployment source. None of those future shapes
is accepted by the current schema; defining them is part of the reviewed promotion code change.

## Promotion truth

Robinhood can move from `planned` to `canary` only after the chain deployment descriptor binds the exact Programmable
Router, GraphFactory and PermitAuthority deployments and live runtime hashes. It can move to `live` only after all
production gates pass, including provider/finality health, server validation and simulation, exact wallet handoff,
finalized Router evidence, Router-backed read-model projection, source-verification jobs and matching public
discovery.

Fee certification stays separate from launch validity. The V4 descriptor keeps `feeBehaviorClaim`,
`universalFeeBehaviorClaim`, generic claiming and buybacks false. External terminals and indexers decide whether to
integrate published metadata and feeds; Programmable does not guarantee their indexing.
