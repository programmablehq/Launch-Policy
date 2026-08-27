# Historical Application V3.2 scaffold

> [!NOTE]
> This scaffold remains only for offline compatibility and historical inspection. GitHub application intake is
> closed. New launches start at
> [`/.well-known/programmable.json`](https://programmable.market/.well-known/programmable.json), follow its advertised
> V3 capabilities, CLI, guide, and OpenAPI, then submit to
> `POST https://api.programmable.market/v3/custom-launches`. V1 creation is historical read-only compatibility and
> returns non-retryable `409 CUSTOM_LAUNCH_V1_READ_ONLY`.

For reproduction of a preserved V3.2 record, this command creates a small local compatibility workspace:

```sh
npm run applicant:scaffold -- \
  --route no-market \
  --application-id my-project \
  --output my-project-application
```

When reproducing an existing record, select the legacy route declaration already bound by that record:

- `no-market`: exact Submission 2.1 evidence must establish that no tradable market exists.
- `external`: a tradable route exists outside the official Programmable Router path.
- `unresolved`: route analysis is still pending; use a proposal, not a prototype claim.
- `official`: the preserved record requested the official Programmable Ethereum route under the retired GitHub
  contract. Pass the `custom` or `classic` category already bound by that record.

Without `--output`, the script prints canonical scaffold JSON to stdout. Use the silent npm form when another tool consumes those bytes:

```sh
npm run --silent applicant:scaffold -- \
  --route no-market \
  --application-id my-project
```

With `--output`, it creates one new directory containing only:

```text
applicant-scaffold.v3.2.json
README.md
```

It never overwrites an existing directory or file. The initial result is always `draft-pending`. It does not fabricate source hashes, trade tests, fee handling, Router readiness, deployment evidence, stamps, review, or approval.

For an existing preserved record, copy its exact Application V3.2 package under `application-package/` and its exact
public source snapshots under `source-repositories/<repository-ref>/`. Do not author a new launch request in this
workspace. Then run:

```sh
npm run --silent applicant:scaffold -- --check my-project-application
```

The check resolves the checked-in legacy Applicant Compatibility V2 contract and passes preserved artifacts to the
Application V3.2, Submission 2.1, Trade Manifest V2, and Router-readiness validation path. It reads bounded regular
files as data. It does not authenticate a GitHub author, execute Applicant code, access a network or RPC, prepare or
submit a current V3 API request, submit a pull request, review the project, or authorize a launch.
