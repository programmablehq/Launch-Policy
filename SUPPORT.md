# Support

Use the [issue chooser](https://github.com/0xprogrammable/Launch-Policy/issues/new/choose) for reproducible checker defects,
review-rule gaps, legacy-validation failures, registry or schema problems, and documentation errors. Include the affected Launch Policy
release or commit, exact command, sanitized output, and a minimal public reproduction when possible.

Use [Launch Policy Discussions](https://github.com/0xprogrammable/Launch-Policy/discussions) for architecture questions and unfamiliar
product ideas. Novelty is not a security report and not a reason to force an idea into an existing template.

For current launch and API usage, start at the public
[`/.well-known/programmable.json`](https://programmable.market/.well-known/programmable.json), follow its advertised
[V3 capabilities](https://api.programmable.market/v3/capabilities), checksum-bound CLI,
[guide](https://programmable.market/docs/developers/custom-launch), and
[OpenAPI](https://programmable.market/openapi/custom-launch-v3.json), then submit the CLI-produced request bytes to
`POST https://api.programmable.market/v3/custom-launches`. V1 creation is historical read-only compatibility and
returns non-retryable `409 CUSTOM_LAUNCH_V1_READ_ONLY`.

Use [private vulnerability reporting](https://github.com/0xprogrammable/Launch-Policy/security/advisories/new) for
security-sensitive findings. Do not post wallet material, credentials, private repositories, personal data, or
unannounced vulnerabilities in public issues.

Project approval, deployment, provider routing, investment advice and guaranteed implementation support are not
provided through repository issues. Repository issues do not accept launch requests; use the V3 flow above.
