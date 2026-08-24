<!--
Programmable Launch Policy accepts maintenance pull requests only.
GitHub launch intake is closed. Submit launches through:
https://programmable.market/developers/custom-launch-api-v1.md
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
