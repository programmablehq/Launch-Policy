# Programmable Launch Policy

Generated from the canonical policy at `policy/launch-policy.v1.json`. Digest: `sha256:9f081e02b626b421bcdc38d84f25b5cf3cfb92bd77f27a987520fa0bae675b67`.

This document is a generated projection. The canonical JSON is authoritative.

## Build

Outcome: `BUILT_NOT_REVIEWED`.


## Launch Readiness

Outcome: `LAUNCH_READINESS_CHECKED_NOT_AUTHORIZED`.

- `LAUNCH.ETHEREUM_AND_TREASURY_10_BPS`: A market-bearing Programmable Ethereum-mainnet launch plan must bind the policy-defined 10 bps of gross canonical-pool trading volume to the Programmable treasury at its exact reviewed revision; launch-readiness proves this prelaunch commitment, not deployed runtime payment or settlement.
- `LAUNCH.ETHEREUM_ROUTER_PROVENANCE_READINESS`: A market-bearing Programmable Ethereum-mainnet launch must be compatible at its exact reviewed revision with the live canonical Launch Stamp Router resolved through official discovery; unknown or unsupported hook integration remains analysis-pending, and direct factory calls do not establish Programmable provenance.

## Production Launch (disabled)

Outcome: none.

- `LAUNCH.ETHEREUM_AND_TREASURY_10_BPS`: A market-bearing Programmable Ethereum-mainnet launch plan must bind the policy-defined 10 bps of gross canonical-pool trading volume to the Programmable treasury at its exact reviewed revision; launch-readiness proves this prelaunch commitment, not deployed runtime payment or settlement.
- `LAUNCH.ETHEREUM_FINALIZED_ROUTER_STAMP_BEFORE_PROMOTION`: Before Registry, API, indexer, or public promotion, a market-bearing Programmable Ethereum-mainnet launch must have finalized manifest-resolved canonical Router evidence that binds its exact reviewed revision, launch identity, route, components, pool, and stamp; direct factory calls do not qualify.
- `LAUNCH.ETHEREUM_FINALIZED_RUNTIME_FEE_SETTLEMENT_BEFORE_PROMOTION`: Before production promotion, each applicable exact fee scope and asset of a market-bearing Programmable Ethereum-mainnet launch must have protected platform evidence binding the reviewed deployed runtime and proving integer-exact 10 bps treasury settlement for one inclusive consensus-finalized historical block range; this receipt makes no future-payment or ongoing-monitoring claim.
- `LAUNCH.ETHEREUM_ROUTER_PROVENANCE_READINESS`: A market-bearing Programmable Ethereum-mainnet launch must be compatible at its exact reviewed revision with the live canonical Launch Stamp Router resolved through official discovery; unknown or unsupported hook integration remains analysis-pending, and direct factory calls do not establish Programmable provenance.

## Workflow Canary

Outcome: `CANARY_WORKFLOW_PASSED`.
