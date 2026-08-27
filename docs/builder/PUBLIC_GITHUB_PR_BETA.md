# Retired GitHub application transport

> [!IMPORTANT]
> GitHub launch intake is closed. This document preserves the former transport contract for historical reproduction;
> it is not a submission guide. Current launches start at
> [`/.well-known/programmable.json`](https://programmable.market/.well-known/programmable.json), follow its advertised
> V3 capabilities, CLI, guide, and OpenAPI, then submit to
> `POST https://api.programmable.market/v3/custom-launches` with an
> [API key](https://programmable.market/developers/api-keys).

The former `0xprogrammable/submit-launch` repository accepted bounded application records under `submissions/` and
one-file Workflow Canary records under `canary-submissions/`. The repository is now named
`0xprogrammable/launch-policy`, and those namespaces are immutable legacy provenance.

## Preserved contracts

The following contracts remain available for offline inspection of existing records:

- Application V3.2 and its Submission 2.1 and Trade Capability Manifest V2 bindings;
- byte-unchanged Application V3.1 compatibility;
- the frozen six-file V2 transport and its receipt-bound validator;
- Workflow Canary V1; and
- Applicant Compatibility V1 and V2 discovery records.

No contract in that list opens GitHub intake, approves a project, authorizes a wallet, or launches a contract. A legacy
validation result means only that the historical bytes satisfy the contract that applied to them.

## Historical namespaces

Former V3 records used:

```text
submissions/<application-id>/v3/revisions/<positive-decimal-revision>/
├── application.v3.json
└── <content-addressed application-package records>
```

Former V2 records used six files directly under `submissions/<application-id>/`. Former Workflow Canary records used
`canary-submissions/<application-id>/application.json`.

These paths must not be added to, changed, moved, or deleted. Their Git history, immutable revisions, exact source
coordinates, and old pull-request URLs remain the provenance record. Old `submit-launch` names inside frozen protocol
identifiers, receipts, snapshots, or released history are legacy identifiers and must not be rewritten.

## Offline historical verification

Maintainers may reproduce a preserved record with the checked-in legacy validators. The validators treat project
content as inert untrusted data and never turn a historical pass into current review, acceptance, readiness, deployment,
promotion, or launch authority.

The canonical current requirements remain in
[`policy/launch-policy.v1.json`](../../policy/launch-policy.v1.json). Inspect them with:

```bash
npm run policy -- validate-policy
npm run policy -- requirements --profile launch-readiness
```

## Current launch path

Start at public
[`discovery`](https://programmable.market/.well-known/programmable.json), require the advertised
[`/v3/capabilities`](https://api.programmable.market/v3/capabilities) profile, install its exact checksum-bound CLI,
and follow the advertised [guide](https://programmable.market/docs/developers/custom-launch), pack-config schema, and
[V3 OpenAPI](https://programmable.market/openapi/custom-launch-v3.json). Submit the CLI-produced request bytes to
`POST https://api.programmable.market/v3/custom-launches`.

V1 creation is historical read-only compatibility and returns non-retryable
`409 CUSTOM_LAUNCH_V1_READ_ONLY`. Wallet review and signing remain separate from API authentication and cannot be
performed by a repository pull request.
