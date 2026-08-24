# Workflow Canary

> [!IMPORTANT]
> Workflow Canary intake is retired. This document preserves the historical contract; do not submit a Canary pull
> request. Current launches use the [Custom Launch API](https://programmable.market/developers/custom-launch-api-v1.md).

The workflow canary was a one-file, hidden test of the GitHub application path. It did not approve a launch, publish a
project, create a Registry record, claim an audit, enable production routing, or permit real-user funds.

## Historical applicant file

Historical records used exactly:

```text
canary-submissions/<application-id>/application.json
```

The file must be canonical JSON with one trailing LF and must satisfy
[`canary/schemas/workflow-canary-application-v1.schema.json`](../canary/schemas/workflow-canary-application-v1.schema.json).
No second file and no fee, audit artifact, security approval, Registry, or production field is accepted.

The application binds:

- the authenticated GitHub builder and application revision;
- one exact public source repository numeric ID, commit, and tree;
- the exact `workflow-canary` binding from the protected repository revision active at the time;
- explicit hidden, unaudited, unrouted, non-production, and no-real-user-funds declarations.

The schema defines transport only. Every Programmable-specific requirement is authored once in
[`policy/launch-policy.v1.json`](../policy/launch-policy.v1.json).

## Protected result

Protected base code hydrates only the single JSON blob, resolves source as inert public Git data, and never installs,
imports, or executes applicant code. A pass is canonical
`programmable.workflow-canary-result.v1` JSON conforming to
[`canary/schemas/workflow-canary-result-v1.schema.json`](../canary/schemas/workflow-canary-result-v1.schema.json).

The canary reproduces only the exact canonical application record and its current policy binding. It does not claim that
source code was built or that a reproducible build artifact exists. The `workflow-canary` profile intentionally has no
semantic launch-policy rules. Its canonical bytes, path, identity, source, and no-authority checks are transport and
security controls, not additional launch requirements.

The result binds the exact application bytes and Git blob, authenticated pull request, public source, protected policy,
the empty Canary Rule-ID set, and the canonical policy-review decision. The review subject's `configurationHash` is a
domain-separated canonical commitment to the complete result application, pull-request, and source objects. It therefore
closes over the PR number and author, exact base and head repository IDs/commits/trees, and merge commit as well as the
application blob and source identity. The application-byte SHA-256 remains independently recorded under
`application.blob.sha256`.

`CANARY_WORKFLOW_PASSED` is checker-only and all audit, launch, discovery, routing, production, and funds authority
remains false.

The separate [Hidden Canary eligibility v1](CANARY_ELIGIBILITY_V1.md) contract can sign this exact result for a
short-lived Website test surface. It revalidates the original application and complete result against the same trusted
policy and does not add production authority.
