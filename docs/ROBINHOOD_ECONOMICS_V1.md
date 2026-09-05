# Robinhood custom-launch economics 1.0 and admission 4.1

These are candidate source contracts for new chain 4663 launches. Publishing them does not activate a runtime, deploy a contract, establish an audit or demonstrate collected revenue. The exact protected API, immutable client, provider tuple, per-launch source and executable fee evidence must agree before fresh writes select profile 4.1.0/revision 2.

`policy/robinhood-custom-launch-economics-v1.json` is the sole authored source for this successor's economics. The descriptor binds its path and generated discovery binds exact source digests. `policy/schemas/custom-launch-admission-v4.1.schema.json` is generated from the authored descriptor and policy; its economics definition is a validation projection, not another independently maintained policy. Existing policy 2.4.0 and admission 4.0 bytes remain unchanged. All existing Robinhood obligations are inherited except `LAUNCH.ROBINHOOD_HONEST_FEE_CAPABILITY`: every fresh 4.1 launch must prove its exact platform-fee path before authorization.

## Platform allocation

The fixed platform allocation is 20 / 10000 = 0.2% of the executed trade's gross native ETH. Each successful buy or sell counts once. ETH-valued volume of 2 million USD corresponds to 4,000 USD of platform allocation before gas, rounding and ETH price changes. There is no dollar-denominated debt or exchange-rate guarantee.

Let `G` be gross native wei, `c` immutable directional creator basis points, and `N` required net native wei:

- `totalFee = ceil(G * (20 + c) / 10000)`
- `platformFee = ceil(G * 20 / 10000)`
- `creatorFee = totalFee - platformFee`
- `grossForNet(N) = ceil(N * 10000 / (10000 - 20 - c))`

The platform charge is independent of creator rate, including zero. Rounding is per trade, upward to one wei; the excess is less than one wei for each platform allocation. This is a new profile, not the historical cumulative-floor profile. Treasury is fixed to `0xD88539d3c4C460136a733A3Fd60cf6BF269079da`. Creator configuration cannot waive, lower or redirect this allocation.

| Trade | Native basis | Mandatory kernel phase |
| --- | --- | --- |
| Native exact-input buy | Gross ETH input budget including hook fees | beforeSwap |
| Token exact-output buy | Actual core ETH cost grossed up for hook fees | afterSwap |
| Token exact-input sell | Actual core ETH output before hook fees | afterSwap |
| Native exact-output sell | Requested net ETH output grossed up | beforeSwap |

Native-specified partial fills revert the whole swap and accrual. Native-unspecified trades charge actual executed notional. `NativeFeesAccrued.grossNative` records this basis: on buys it differs from the core Swap event's native input after hook fees. Core LP fees are reflected in trade price and do not become platform revenue.

## Backing and claim

The kernel accrues native ERC-6909 claims backed by PoolManager into separate vault ledgers. `claimPlatform()` is permissionless to trigger but always sends only the platform bucket as native ETH to the fixed Treasury. Creator claims use a distinct bucket and immutable recipient. No caller can redirect a claim. Accrual does not automatically transfer ETH to the Treasury EOA during a swap: a successful claim transaction is required. The fee vault does not hold or certify pool principal.

## Financing before building

Profile 4.1 requires the distinct `programmable.robinhood-funding-plan.v1` client contract, bound into launch intent and durable state. It captures declared capital source and pricing mechanism separately, four allocations of exact native transaction value, a launch-value ceiling and a separate gas budget. Initial buys are counted once. Build-only plans cannot create a launch. Current native balance and network gas estimate must be checked against the exact transaction before sending.

A buyer-funded launch still needs gas, token inventory, real reserve and redemption design. A creator-funded launch needs the actual quoted native capital. A declaration, available token supply, virtual reserve or accepted budget is not proof of actual native funds, solvent redemptions or operating liquidity. Financing purpose never waives the platform fee.

## Flexibility and bounded evidence

The first kernel supports native ETH/token concentrated-liquidity pools and optional STATICCALL-only bounded LP-fee calculation or swap validation. One-sided token liquidity and seeded liquidity are possible funding shapes, not automatic economic approvals. Exact deployed kernel/vault source, constructor values, PoolKey, four fee quadrants, alternate routers, backing and claim destinations need protected evidence. The guarantee is confined to that official PoolKey; it does not tax arbitrary token transfers or other independently created pools.

Stateful modules, custom return deltas, no-op core swaps and other settlement models need a typed settlement proof with authenticated actual native cashflows and complete fee-path coverage. They remain `needs-evidence` when that capability is missing; a new architecture label is not a reason to call a project unsafe. A fee proof also cannot replace token authority, liquidity ownership, reserve, exit or user-rights proofs. There is no universal compatibility or safety claim.

Existing launches and accepted historical profile reads/replays remain bound to their old contracts. The successor cannot retroactively change an existing pool or authorization. A fresh request under an activated successor must satisfy the new fee and financing duties. No Ethereum policy or deployment changes are included.
