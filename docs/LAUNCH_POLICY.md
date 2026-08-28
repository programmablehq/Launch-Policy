# Programmable Launch Policy

Generated from the canonical policy at `policy/launch-policy.v1.json`. Digest: `sha256:247cf234e84e543426efb6c1cb39bdb82779fe0f3ae4bae0a9add97a66d82947`.

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

## Workflow Canary

Outcome: `CANARY_WORKFLOW_PASSED`.
