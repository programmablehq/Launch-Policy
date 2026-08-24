# Contributing

GitHub launch intake is closed. Do not submit a launch, application, template, or Workflow Canary through this
repository. Use the [Custom Launch API](https://programmable.market/developers/custom-launch-api-v1.md) with an
[API key](https://programmable.market/developers/api-keys).

Repository pull requests are for maintenance only. Keep one pull request to one of these paths:

1. launch policy or policy-bound checker maintenance;
2. schema or compatibility maintenance;
3. discovery Registry maintenance; or
4. documentation, workflow, security, or test maintenance.

Changes under `submissions/` or `canary-submissions/` are rejected. Those namespaces preserve the immutable history of
the retired GitHub intake and must not be rewritten, extended, or repurposed.

## Launch policy maintenance

`policy/launch-policy.v1.json` is the authored source for Programmable launch requirements. Do not copy a requirement
into generated Markdown, a workflow, validator prose, or an API request. Keep stable Rule IDs, update the policy version
when rule semantics change, add a focused regression, then run:

```bash
npm run policy:generate
npm run policy:check
npm run authority:write
npm run authority:check
npm test
```

Do not hand-edit `docs/LAUNCH_POLICY.md`, `.programmable/active-contract.json`, or
`.programmable/active-contract.v2.json`. The authority-ownership manifest records the exact reviewed file inventory,
entrypoints, import closures, Rule-ID handlers, public projections, and frozen legacy vendor exclusion.

## Registry maintenance

Registry changes use a separate maintainer pull request and must bind exact public evidence. Never hand-edit generated
indexes. Change the source config or project record, advance the release version when required, and run
`npm run generate`. Existing files under `registry/history/` are append-only and byte-immutable.

Acceptance, deployment, source verification, indexing, routing, availability, suspension, and retirement are distinct
states. A policy match or API launch request does not create a Registry promotion.

## Compatibility and historical records

The V2, V3.1, V3.2, Workflow Canary, Universal Admission, and entitlement contracts remain in this repository only for
compatibility, offline reproduction, or historical evidence unless a document explicitly says otherwise. Do not
reinterpret a legacy record under a newer contract or replace an old `submit-launch` identifier inside frozen bytes.

The frozen vendored Hookbuilder trees must never be edited in place. Replace a complete tree only with an independently
verified receipt-bound release and the required compatibility evidence.

## Review standard maintenance

Changes to `review/`, its schemas, or decision semantics require public regression fixtures for both unusual legitimate
behavior and proven failures. A model score or private assertion is not sufficient test evidence. Reviewer output stays
checker-only unless a separate protected authority explicitly says otherwise.

## Universal Admission reference maintenance

Universal Admission is a disabled reference surface, not an applicant transport. Keep its command, trust, protocol,
service, store, schemas, tests, and discovery contract in one separately reviewed maintenance change. Do not describe a
public endpoint, production capacity, or authorization system that has not been independently deployed and verified.

## Pull request checklist

- Explain the exact maintenance purpose and affected contract or policy version.
- Identify generated files and the command that produced them.
- List the smallest relevant checks and their observed results.
- Confirm that no historical submission or released history file was rewritten.
- Confirm that no secret, private RPC URL, wallet material, personal data, or unpatched exploit is included.

## Security

Report exploitable findings through [private vulnerability reporting](SECURITY.md). Do not publish credentials, wallet
material, private repositories, personal data, or an unpatched exploit in a pull request or issue.
