# Policy-Bound Review Standard v1

This standard covers repository policy-checker decisions, not current V3 API admission. The canonical
[`policy/launch-policy.v1.json`](../policy/launch-policy.v1.json) owns Router, fee, and promotion business obligations;
the separate public
[`custom-launch-admission-v3.json`](../policy/custom-launch-admission-v3.json) discloses current admission findings,
evidence duties, and claim boundaries. Only the private Custom Launch API exact-source scanner and Router simulation
can issue executable admission evidence. The reviewer, an LLM, a local scanner, and the legacy Open Review adapter
cannot add requirements, change severity or enforcement, select a policy file, or create an approval outcome.

The protected evaluator reads the policy only from the exact trusted Launch Policy base commit at the fixed repository
and path. It compares all eleven fields of the recorded policy binding before it considers rule evaluations. A changed
repository, commit, tree, policy blob, version, profile, or digest returns `policy_drift`.

## Closed evaluation contract

An evaluation contains only:

```json
{
  "ruleId": "LAUNCH.ETHEREUM_AND_TREASURY_10_BPS",
  "state": "passed",
  "evidenceRefs": ["sha256:..."],
  "analyzer": { "kind": "deterministic", "id": "ethereum-treasury-10-bps-v1" }
}
```

For an active rule, the analyzer kind and id must match the current policy enforcement record. Requirement text,
severity, owner, enforcement and outcome are projected from the trusted policy, never copied from analyzer input.
Missing applicable rules and explicit `analysis_pending` states remain pending. Unknown, inactive and out-of-profile
Rule IDs can produce only non-authoritative advisories. LLM observations are always advisories and cannot pass, violate,
close or hard-block a deterministic rule.

Applicability is derived from the closed subject. In particular, a caller cannot mark an always-applicable rule as not
applicable. Expected and current subject identity bind repository id, repository, commit, tree, configuration hash and
the declared Uniswap v4 context.

## Decisions

| Status | Meaning |
| --- | --- |
| `passed` | Every applicable active rule has a policy-bound passing evaluation. The outcome is still checker-only. |
| `analysis_pending` | At least one applicable active rule is missing or pending. Unknown does not mean unsafe. |
| `changes_requested` | At least one policy-bound deterministic evaluation reports a violation. |
| `policy_drift` | The recorded eleven-field policy binding differs from the exact trusted policy. |
| `subject_drift` | The current closed subject differs from the subject that was reviewed. |
| `profile_disabled` | The selected profile is disabled and has no outcome. |

`build` may return `BUILT_NOT_REVIEWED`. `workflow-canary` may return `CANARY_WORKFLOW_PASSED` while remaining hidden,
non-production and without real funds. The enabled `production-launch` profile may return
`PRODUCTION_REQUIREMENTS_CHECKED_NOT_AUTHORIZED` only after every applicable current rule passes. No profile authorizes
a launch.

Every decision has this fixed authority:

```json
{
  "checkerOnly": true,
  "independentAudit": false,
  "launchAuthorized": false,
  "publicRoutingAuthorized": false,
  "realFundsAuthorized": false
}
```

Decisions contain no timestamps. Their digest covers the deterministic canonical decision bytes, including exact
policy and subject identity. Canonical validation and digest recomputation additionally require the exact trusted policy
record returned by the fixed Git reader. They re-derive binding drift, subject drift, applicability, analyzer identity,
pending rules, findings, status, and outcome from those trusted bytes; a digest by itself is not authenticity.

## Schemas and examples

- [`launch-policy-review-input.v1.schema.json`](../review/schemas/launch-policy-review-input.v1.schema.json)
- [`launch-policy-review-decision.v1.schema.json`](../review/schemas/launch-policy-review-decision.v1.schema.json)
- [`canary-passed.json`](../review/examples/canary-passed.json)
- [`canary-analysis-pending.json`](../review/examples/canary-analysis-pending.json)
- [`production-disabled.json`](../review/examples/production-disabled.json)

The enabled-profile examples are immutable snapshot fixtures. They bind exact Launch Policy commit
`599cbb7f9e6c6daf8a1aeca85340429db5a4f134` and policy 1.1.0 in their eleven-field binding; they are not current-HEAD
bindings. A protected consumer never treats those example fields as current. It resolves the live exact protected base
it was invoked for and requires the applicant's binding to match it. Reusing a snapshot fixture against a later base
correctly returns `policy_drift`.

The generic protected interface is `evaluateTrustedLaunchPolicyReview({ input, repositoryRoot, expectedBaseCommit })`.
The surrounding protected workflow owns those trusted checkout arguments; applicant input does not.
Downstream consumers use `canonicalLaunchPolicyDecision(decision, trustedPolicyRecord)` and
`digestLaunchPolicyDecision(decision, trustedPolicyRecord)`. Neither accepts a caller-fabricated policy-shaped object.

## Legacy Open Review compatibility

The old `programmable.open-review-input.v1` files remain accepted by the one-file CLI so existing examples and callers
fail closed. Because that legacy format cannot bind the current policy or prove the current launch requirement, the
adapter projects into the enabled checker-only `production-launch` profile with no caller-supplied current-rule
evaluations. It therefore remains `analysis_pending` with a null outcome. Old obligations and witnesses remain bounded,
explicitly unbound compatibility advisories; they are not central-policy Rule IDs and never become findings or
approval.

```bash
npm run review -- review/examples/disclosed-high-fee.json
```

This command reads the exact local Launch Policy `HEAD` policy blob. Its result is a deterministic local snapshot, not
proof of protected main, an independent audit, a signature, Website eligibility, routing, deployment, funds authority,
or launch authorization.
