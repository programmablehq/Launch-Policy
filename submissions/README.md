# Historical application records

This namespace preserves immutable records from the retired GitHub application transport. It is not an active intake.
Do not add, update, move, or delete files under `submissions/`.

The former transport supported Application V3.2, compatible V3.1 revisions, and a frozen six-file V2 package. Existing
records keep their exact source repository IDs, commits, trees, package digests, policy bindings, and pull-request
history. A historical validation pass is not current review, acceptance, approval, deployment, availability, safety,
audit, launch, or funds authority.

New launches start at
[`/.well-known/programmable.json`](https://programmable.market/.well-known/programmable.json), follow its advertised
V3 capabilities, CLI, guide, and OpenAPI, then submit to
`POST https://api.programmable.market/v3/custom-launches` with an
[API key](https://programmable.market/developers/api-keys). V1 creation is historical read-only compatibility and
returns non-retryable `409 CUSTOM_LAUNCH_V1_READ_ONLY`.
