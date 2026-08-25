# Hidden Canary eligibility v1

This contract turns one exact, passing Workflow Canary result into a short-lived Website-facing eligibility envelope.
It is only for a hidden canary surface. It cannot enable public discovery, production routing, real funds, an audit
claim, or launch authorization.

## Authority chain

The compiler accepts all of the following as separate inputs:

1. canonical raw bytes of the original one-file Workflow Canary application;
2. canonical raw bytes of the complete `programmable.workflow-canary-result.v1` result;
3. a signed `programmable.protected-canary-eligibility-command.v1` command;
4. a pinned Ed25519 authority public key; and
5. the exact trusted policy record read from the fixed protected Launch Policy checkout.

The Task 5 parsers semantically revalidate the application, result, embedded review decision, Rule IDs, authority
flags, result digest, and current policy binding. The eligibility compiler then cross-checks the complete application,
pull-request base/head/merge identity, source identity, and policy identity against the signed command. A label, comment,
merge, green CI status, build result, unsigned result, legacy launch entitlement, or caller-provided policy object cannot
substitute for this chain.

## Signing and deterministic identity

Signing bytes are UTF-8
`programmable.submit-launch.protected-canary-eligibility-command.v1`, one zero byte, then canonical JSON of the inner
command. This domain is distinct from the legacy production-entitlement domain. The signature is canonical unpadded
base64url Ed25519 and `keyId` is SHA-256 of the pinned public key's SPKI DER bytes.
A dedicated Canary key is recommended operationally even though the separate domain prevents cross-protocol signature
reuse when one physical key is shared.

The command includes the full current workflow-canary policy binding. Its validity window must be positive, no longer
than 900,000 milliseconds, and the compiler and Website both require `issuedAt <= now <= validUntil`.

It also signs one closed Website audience: `programmable.market:hidden-canary:preview`,
`programmable.market:hidden-canary:staging`, or `programmable.market:hidden-canary:production`. The Website verifier
must receive its exact expected audience from trusted deployment configuration. An audience copied from the envelope
is never authority, and a command signed for one environment is rejected in every other environment. The word
`production` here names the Website environment only; all production routing, real-funds, and launch-authority flags
remain false.

`eligibilityId` is SHA-256 of the separate eligibility-id domain plus the canonical immutable audience, application,
PR, source, policy, Workflow Canary result, and eligibility objects. Reissuing the same exact result for the same
audience deduplicates to the same id; changing audience, application bytes/revision, PR head or merge, source, policy,
result, or review decision changes the id.
Issuer display metadata, timestamps, key, and signature are excluded from that id.

## Envelope meaning

The output is `programmable.canary-eligibility-envelope.v1` and always contains:

```json
{
  "surface": "hidden-canary",
  "publicDiscovery": false,
  "productionRouting": false,
  "realFunds": false,
  "launchAuthorized": false
}
```

The envelope embeds the signed audience, full application, and full Workflow Canary result so the Website can
reconstruct their exact canonical bytes and rerun the same parsers against its own expected audience, pinned key, and
exact trusted policy record. Neither the envelope's audience nor its policy binding is used as the source of authority.

Compile without writing repository state:

```bash
npm run compile:canary-eligibility -- \
  --signed-command /trusted/input/signed-canary-command.json \
  --application /trusted/input/application.json \
  --workflow-canary-result /trusted/input/workflow-canary-result.json \
  --trusted-authority-public-key /trusted/config/canary-ed25519-public.pem \
  --trusted-policy-repository-root /trusted/launch-policy \
  --expected-policy-base-commit <40-hex-base-commit>
```

The command accepts no private key, policy bytes, policy path, URL, repository override, or profile override. Canonical
output is written to standard output; canonical errors are written to standard error.

## Replay and supersession limit

Pure verification is intentionally idempotent and replayable during the signed validity window. Cryptography alone
cannot prove single use, revocation, the latest PR head, or external ordering. A real Website consumer must maintain a
protected, atomic active/consumed `eligibilityId` store and re-resolve the latest eligible head. V1 therefore requires
`supersedes: null` and makes no stateless supersession claim.

The schemas are
[`protected-canary-eligibility-command-v1.schema.json`](../acceptance/schemas/protected-canary-eligibility-command-v1.schema.json)
and [`canary-eligibility-envelope-v1.schema.json`](../acceptance/schemas/canary-eligibility-envelope-v1.schema.json).
