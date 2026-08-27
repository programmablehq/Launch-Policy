# Central Programmable Launch Policy Design

> Historical design record. It describes the retired GitHub application transport and its authority model at the time.
> Current launches start at `https://programmable.market/.well-known/programmable.json`, follow the advertised V3
> capabilities, CLI, guide, and OpenAPI, and submit to `POST https://api.programmable.market/v3/custom-launches`.

## Goal

Make `0xprogrammable/submit-launch` the complete public source of every Programmable-specific launch requirement so an
applicant may use the Programmable Hookbuilder, another agent, or no agent at all and still produce the same reviewable
application.

## Product boundary

The Hookbuilder is optional build tooling. It may retain general Uniswap v4, EVM, compiler, testing, and secure-coding
knowledge, but it must not own additional Programmable admission requirements.

`submit-launch` owns the launch policy, its schema, validation implementation, public rendering, and version history.
No Builder, LLM reviewer, website gate, or intake validator may invent an unlisted Programmable launch requirement.

## Canonical policy

The single authored source is `policy/launch-policy.v1.json`. It is closed canonical JSON and contains:

- repository identity, schema version, policy id, semantic version, and effective state;
- review profiles: `build`, `workflow-canary`, and `production-launch`;
- stable rule ids with plain-language requirement, applicability, evidence, enforcement owner, severity, and status;
- allowed outcomes and their authority boundaries;
- migration behavior for open applications and previously accepted revisions.

Supporting schemas, validators, tests, generated Markdown, and generated indexes implement this file. They are not
independent policy sources. The public human document is generated from the canonical JSON and must byte-bind its policy
digest.

## Initial profiles

### Build

The Builder's normal job is to create the requested hook. It requires only engineering closure: preserve intent,
compile, run declared tests, bind PoolManager and hook permissions correctly, and disclose privileged or value-moving
behavior. It does not require launch admission, independent audit, Registry acceptance, website support, deployment,
or provider evidence. Its outcome is `BUILT_NOT_REVIEWED`.

### Workflow canary

This profile tests the complete GitHub application to website handoff without claiming production safety. It requires
exact application identity, a reproducible canonical inert application record bound to the current protected policy,
and confinement to a hidden canary namespace with no public routing, production discovery, or real-user funds. It does
not claim a built or reproducible source artifact. Its outcome is `CANARY_WORKFLOW_PASSED`, never launch approval.

### Production launch

The profile remains disabled until an owner-approved rule set is published. Enabling it requires a semantic policy
version change and complete validator coverage. Until then, no automated system may issue `LAUNCH_APPROVED`.

## Consumer contract

Any client can obtain the policy directly from protected `submit-launch:main`; using the Hookbuilder is never required.

- The Hookbuilder resolves the protected policy at `submit` or `launch`, validates canonical bytes, and records the
  repository id, base commit, path, policy version, and SHA-256 in the application.
- The protected PR workflow reads policy bytes only from the trusted base revision and rejects candidate policy edits
  mixed with an application.
- A future LLM security reviewer receives the same canonical policy and must return rule-id-addressed findings. An LLM
  cannot create a hard block or approval without the enforcement and evidence specified by that rule.
- The website consumes only an acceptance or canary entitlement that binds the same application and policy digest.

## Drift and versioning

New applications use the current protected policy. Open applications are re-evaluated before decision; a different
current digest produces `POLICY_DRIFT` and no inherited result. Previously accepted revisions are not retroactively
changed unless the new policy declares an explicit emergency or migration action.

Text-only clarifications that do not change behavior increment the patch version. Rule applicability, evidence,
severity, enforcement, outcome, or profile changes increment at least the minor version. Incompatible artifact or
consumer changes require a new schema or major policy version.

Changing policy prose alone cannot claim enforcement. Every deterministic rule must name its validator and negative
test. LLM-only and human-only rules must say so explicitly.

## Data flow

```text
submit-launch/policy/launch-policy.v1.json
              |
              +--> generated public Markdown
              +--> Hookbuilder submit or launch preflight
              +--> protected GitHub intake validator
              +--> future LLM security reviewer
              +--> website canary or launch entitlement gate
```

## Safety and authority

Candidate repositories and application PRs are untrusted data. They cannot edit the policy used to judge themselves.
Passing `build` or `workflow-canary` does not prove safety, audit status, deployment, acceptance, or public launch
authorization. Production credentials, signatures, deployment, public routing, and real funds remain separately
authorized actions.

## Acceptance criteria

1. A developer using no Programmable tooling can discover the policy, validate it, and prepare the documented package.
2. Every Programmable-specific finding emitted by Builder or reviewer maps to one current policy rule id.
3. An application cannot pass when its policy binding differs from trusted protected-base bytes.
4. No hidden Programmable requirement exists only in Hookbuilder prose, a validator constant, an LLM prompt, or website
   code.
5. The workflow-canary path proves the handoff without enabling production visibility, funds, or launch authority.
6. Policy changes are independently reviewable, versioned, tested, and reflected in the generated public document.
