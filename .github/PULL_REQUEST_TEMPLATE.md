<!--
Programmable Launch Policy accepts maintenance pull requests only.
GitHub launch intake is closed. Start launches at:
https://programmable.market/.well-known/programmable.json
Follow its V3 capabilities, CLI, guide, and OpenAPI to POST https://api.programmable.market/v3/custom-launches.
V1 creation is historical read-only compatibility and returns non-retryable 409 CUSTOM_LAUNCH_V1_READ_ONLY.
Do not include secrets, private RPC URLs, wallet material, or personal data.
-->

## Maintenance area

- [ ] Launch policy or policy-bound checker
- [ ] Schema or compatibility contract
- [ ] Registry or generated projection
- [ ] Documentation, workflow, security, or tests

## Exact change

Describe the contract, policy version, source revision, generated files, and reason for this maintenance change.

## Verification

List the smallest relevant commands and their observed results.

## Checklist

- [ ] This pull request does not submit a launch, application, template, or Workflow Canary.
- [ ] It does not add, update, move, or delete historical records under `submissions/` or `canary-submissions/`.
- [ ] It does not rewrite an existing file under `registry/history/`.
- [ ] It contains no secret, private RPC URL, wallet material, personal data, or unpatched exploit.
