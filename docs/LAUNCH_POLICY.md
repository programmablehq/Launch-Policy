# Programmable Launch Policy

Generated from the canonical policy at `policy/launch-policy.v1.json`. Digest: `sha256:31e6b286ca839b31cb1edfe30c05d9f334892f3d84377961dc10b93959c7e216`.

This document is a generated projection. The canonical JSON is authoritative.

## Build

Outcome: `BUILT_NOT_REVIEWED`.


## Launch Readiness

Outcome: `LAUNCH_READINESS_CHECKED_NOT_AUTHORIZED`.

- `LAUNCH.ETHEREUM_AND_TREASURY_10_BPS`: A market-bearing Programmable Ethereum-mainnet launch plan must bind the policy-defined 10 bps of gross canonical-pool trading volume to the Programmable treasury at its exact reviewed revision; launch-readiness proves this prelaunch commitment, not deployed runtime payment or settlement.
- `LAUNCH.ETHEREUM_ROUTER_PROVENANCE_READINESS`: A market-bearing Programmable Ethereum-mainnet launch must be compatible at its exact reviewed revision with the live canonical Launch Stamp Router resolved through official discovery; unknown or unsupported hook integration remains analysis-pending, and direct factory calls do not establish Programmable provenance.

## Production Launch

Outcome: `PRODUCTION_REQUIREMENTS_CHECKED_NOT_AUTHORIZED`.

- `LAUNCH.ETHEREUM_AND_TREASURY_10_BPS`: A market-bearing Programmable Ethereum-mainnet launch plan must bind the policy-defined 10 bps of gross canonical-pool trading volume to the Programmable treasury at its exact reviewed revision; launch-readiness proves this prelaunch commitment, not deployed runtime payment or settlement.
- `LAUNCH.ETHEREUM_EXACT_FEE_TEMPLATE_BEFORE_AUTHORIZATION`: Before production authorization, the exact reviewed profile must bind source, build, creation, runtime, composition and treasury-only ERC-6909 accrual semantics that enforce 1000/1000000 on every successful swap. Template conformance does not claim a funded trade or treasury withdrawal, and an owner-signed claim is not a launch prerequisite.
- `LAUNCH.ETHEREUM_FINALIZED_ROUTER_STAMP_BEFORE_PROMOTION`: Before Registry, API, indexer, or public promotion, a market-bearing Programmable Ethereum-mainnet launch must have finalized manifest-resolved canonical Router evidence that binds its exact reviewed revision, launch identity, route, components, pool, and stamp; direct factory calls do not qualify.
- `LAUNCH.ETHEREUM_ROUTER_PROVENANCE_READINESS`: A market-bearing Programmable Ethereum-mainnet launch must be compatible at its exact reviewed revision with the live canonical Launch Stamp Router resolved through official discovery; unknown or unsupported hook integration remains analysis-pending, and direct factory calls do not establish Programmable provenance.

## Robinhood Launch Readiness

Outcome: `ROBINHOOD_LAUNCH_READINESS_CHECKED_NOT_AUTHORIZED`.

- `LAUNCH.ROBINHOOD_FUNDING_AND_SETTLEMENT_READINESS`: Robinhood wallet handoff may advertise only funding modes whose exact token, authorization, replay and settlement behavior the server has proven. The initial bounded modes are none and wallet-transaction-value; unproven ERC-20 modes must be absent.
- `LAUNCH.ROBINHOOD_NETWORK_AND_POOL_MANAGER_PROVENANCE`: A Robinhood Custom Launch must bind chain ID 4663, CAIP-2 eip155:4663 and the exact official Uniswap PoolManager deployment at the pinned registry revision, with live chain ID, bytecode and runtime-hash evidence.
- `LAUNCH.ROBINHOOD_PROGRAMMABLE_TRUST_ROOTS`: The server must resolve Robinhood Router, GraphFactory and PermitAuthority only from the chain deployment descriptor bound to foundation source commitment 0xe87f5edc2dc839bd87a26a80cb53f14b021e603a1753d27aae3a02862058d730, exact programmablehq/PROGRAMMABLE production source and live runtime hashes. The commitment binds reviewed source, not deployment. Ethereum addresses or direct factory calls cannot substitute.
- `LAUNCH.ROBINHOOD_SERVER_VALIDATION_AND_SIMULATION`: The private API must independently rebuild canonical bytes and commitments, bind route and body to chain 4663, run deterministic validation and Robinhood fork simulation, and reject client or model verdicts as authorization evidence.
- `LAUNCH.ROBINHOOD_SOURCE_VERIFICATION_BINDING`: Every exclusive component and bounded external-contract reference needs server evidence. Sourcify v2 exact match is the required source path. Robinhood Blockscout is optional, unproven and degraded; it cannot support an exact-source claim or block or revise finality. An external reference is admissible only when the server binds its exact eip155:4663 address, live runtime hash, source evidence, declared role and checkpoint; arbitrary or unbound references confer no trust.
- `LAUNCH.ROBINHOOD_WALLET_HANDOFF_CHAIN_BINDING`: The server-selected Robinhood lane must return an exact chain-bound transaction envelope. Immediately before a separate wallet signature, the client must recheck chain 4663, controller, destination runtime hash, value, selector, calldata, commitments and expiry.

## Robinhood Production Launch

Outcome: `ROBINHOOD_PRODUCTION_REQUIREMENTS_CHECKED_NOT_AUTHORIZED`.

- `LAUNCH.ROBINHOOD_FINALIZED_ROUTER_EVIDENCE_BEFORE_PROMOTION`: Before Robinhood production promotion, protected platform evidence must bind the finalized canonical Programmable Router transaction, exact launch identity, chain deployment descriptor, source graph, metadata, runtime hashes and Robinhood finality checkpoint.
- `LAUNCH.ROBINHOOD_FUNDING_AND_SETTLEMENT_READINESS`: Robinhood wallet handoff may advertise only funding modes whose exact token, authorization, replay and settlement behavior the server has proven. The initial bounded modes are none and wallet-transaction-value; unproven ERC-20 modes must be absent.
- `LAUNCH.ROBINHOOD_HONEST_FEE_CAPABILITY`: Robinhood production capability must keep feeBehaviorClaim, universalFeeBehaviorClaim, generic claiming and buybacks false unless separately proven and activated. Launch validity must remain separate from exact per-launch fee certification.
- `LAUNCH.ROBINHOOD_INDEXING_AND_READINESS`: Robinhood production discovery requires chain-scoped Router and ledger projection, bounded reconciliation, a last-known-good snapshot, per-chain quality and failure isolation so a Robinhood outage cannot hide Ethereum identities.
- `LAUNCH.ROBINHOOD_NETWORK_AND_POOL_MANAGER_PROVENANCE`: A Robinhood Custom Launch must bind chain ID 4663, CAIP-2 eip155:4663 and the exact official Uniswap PoolManager deployment at the pinned registry revision, with live chain ID, bytecode and runtime-hash evidence.
- `LAUNCH.ROBINHOOD_PROGRAMMABLE_TRUST_ROOTS`: The server must resolve Robinhood Router, GraphFactory and PermitAuthority only from the chain deployment descriptor bound to foundation source commitment 0xe87f5edc2dc839bd87a26a80cb53f14b021e603a1753d27aae3a02862058d730, exact programmablehq/PROGRAMMABLE production source and live runtime hashes. The commitment binds reviewed source, not deployment. Ethereum addresses or direct factory calls cannot substitute.
- `LAUNCH.ROBINHOOD_SERVER_VALIDATION_AND_SIMULATION`: The private API must independently rebuild canonical bytes and commitments, bind route and body to chain 4663, run deterministic validation and Robinhood fork simulation, and reject client or model verdicts as authorization evidence.
- `LAUNCH.ROBINHOOD_SOURCE_VERIFICATION_BINDING`: Every exclusive component and bounded external-contract reference needs server evidence. Sourcify v2 exact match is the required source path. Robinhood Blockscout is optional, unproven and degraded; it cannot support an exact-source claim or block or revise finality. An external reference is admissible only when the server binds its exact eip155:4663 address, live runtime hash, source evidence, declared role and checkpoint; arbitrary or unbound references confer no trust.
- `LAUNCH.ROBINHOOD_WALLET_HANDOFF_CHAIN_BINDING`: The server-selected Robinhood lane must return an exact chain-bound transaction envelope. Immediately before a separate wallet signature, the client must recheck chain 4663, controller, destination runtime hash, value, selector, calldata, commitments and expiry.

## Workflow Canary

Outcome: `CANARY_WORKFLOW_PASSED`.
