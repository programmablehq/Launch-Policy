# Application V3.2 scaffold

> [!NOTE]
> This scaffold remains for offline compatibility and historical inspection. GitHub application intake is closed; new
> launches use the [Custom Launch API](https://programmable.market/developers/custom-launch-api-v1.md).

This command creates a small, local draft workspace for people and agents that do not use Hookbuilder:

```sh
npm run applicant:scaffold -- \
  --route no-market \
  --application-id my-project \
  --output my-project-application
```

The four route declarations are:

- `no-market`: exact Submission 2.1 evidence must establish that no tradable market exists.
- `external`: a tradable route exists outside the official Programmable Router path.
- `unresolved`: route analysis is still pending; use a proposal, not a prototype claim.
- `official`: the official Programmable Ethereum route is requested. Add `--category custom` or `--category classic`.

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

Add the complete Application V3.2 package under `application-package/`. Add each exact public source snapshot under `source-repositories/<repository-ref>/`. Then run:

```sh
npm run --silent applicant:scaffold -- --check my-project-application
```

The check resolves the repository's current Applicant Compatibility V2 contract and passes present artifacts to the existing Application V3.2, Submission 2.1, Trade Manifest V2, and Router-readiness validation path. It reads bounded regular files as data. It does not authenticate a GitHub author, execute Applicant code, access a network or RPC, submit a pull request, review the project, or authorize a launch.
