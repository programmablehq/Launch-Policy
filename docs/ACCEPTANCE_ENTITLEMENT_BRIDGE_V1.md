# Acceptance entitlement bridge v1

## Current status: production disabled

The central `production-launch` profile is disabled. The legacy
`programmable.protected-acceptance-command.v1` and `programmable.launch-entitlement-envelope.v1` schemas remain frozen
historical contracts, but the compiler cannot currently emit a production entitlement.

After validating the command's closed shape, pinned Ed25519 key, signature, and time window, the compiler requires the
exact WeakSet-bound policy record read from the fixed protected Launch Policy checkout. It checks the current
`production-launch` profile before reading a package directory or launch-plan file and returns
`PRODUCTION_LAUNCH_DISABLED`. The command's old opaque `review.policyBundleDigest` is not policy authority and cannot
enable the path.

Enabling production requires an owner-approved central policy update and a new policy-bound command/schema/signing
domain with complete validator coverage. The old v1 command will not silently gain new authority.

## Preserved historical transport

The six-file V2 application remains unchanged. Local inspection is explicitly non-authoritative and requires the
explicit frozen V2 transport adapter. Its old fee grammar is compatibility data, not a current central-policy Rule ID.
The checked-in command and envelope schemas are not loosened, and historical bytes are not reinterpreted as Workflow
Canary eligibility.

The separate [Hidden Canary eligibility contract](CANARY_ELIGIBILITY_V1.md) is the active non-production Website
handoff. It accepts only an exact passing Workflow Canary result and always keeps discovery, routing, real funds, audit,
and launch authority false.

## Legacy signing boundary

Legacy signing bytes remain UTF-8 `programmable.submit-launch.protected-acceptance-command.v1`, one zero byte, then
canonical JSON of the legacy inner command. Commands are valid for at most 15 minutes and use a pinned Ed25519 public
key. This domain is intentionally distinct from the Hidden Canary eligibility domain.

The fixed-purpose compiler now also requires the protected checkout and exact authenticated base commit:

```bash
npm run compile:entitlement -- \
  --signed-command /trusted/input/signed-command.json \
  --package-directory /trusted/launch-policy/submissions/example-hook \
  --launch-plan-file /trusted/resolved-source/launch-plan.json \
  --trusted-authority-public-key /trusted/config/acceptance-ed25519-public.pem \
  --trusted-policy-repository-root /trusted/launch-policy \
  --expected-policy-base-commit <40-hex-base-commit>
```

Under the current v1 policy this exits nonzero with `PRODUCTION_LAUNCH_DISABLED` before either source path is read. No
private key, policy path, policy bytes, URL, repository override, or profile override is accepted.

The preserved schemas are
[`protected-acceptance-command-v1.schema.json`](../acceptance/schemas/protected-acceptance-command-v1.schema.json) and
[`launch-entitlement-envelope-v1.schema.json`](../acceptance/schemas/launch-entitlement-envelope-v1.schema.json).

Nothing in these local contracts proves that a signer, Website flow, state store, permit service, Registry consumer, or
public launch path is deployed or live.
