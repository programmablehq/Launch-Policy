# Historical Workflow Canary records

This namespace preserves immutable records from the retired GitHub Workflow Canary transport. It is not an active
handoff or launch path. Do not add, update, move, or delete files under `canary-submissions/`.

A preserved Canary result remains checker-only, unaudited, non-production, unrouted, and unauthorized for real-user
funds. New launches start at
[`/.well-known/programmable.json`](https://programmable.market/.well-known/programmable.json), follow its advertised
V3 capabilities, CLI, guide, and OpenAPI, then submit to
`POST https://api.programmable.market/v3/custom-launches`. V1 creation is historical read-only compatibility and
returns non-retryable `409 CUSTOM_LAUNCH_V1_READ_ONLY`.
