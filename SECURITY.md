# Security policy

## Report privately

Report security-sensitive findings through [GitHub private vulnerability
reporting](https://github.com/0xprogrammable/launch-policy/security/advisories/new). Do not open a public issue for a legacy
validator bypass, path-confusion defect, source-binding failure, registry-integrity problem, prompt-injection path, credential
exposure, or unpublished exploit.

Include the affected commit, files, minimal reproduction, impact, and preconditions. Never include real private keys,
seed phrases, access tokens, production secrets, personal data, or user funds.

## In scope

- the preserved application validators and their repository, revision, tree, and source binding;
- the public checker, policy, schemas, and decision integrity;
- generated registry records, indexes, history, and discovery boundaries;
- repository workflows and their permission boundaries;
- Universal Admission command authentication, audience/tenant/replay binding, capacity preconditions, queue state,
  lease fencing, retention, snapshot/GC integrity, and the private SQLite reference boundary; and
- the pinned Hookbuilder provenance receipt and vendored-byte verification.

## Out of scope

Applicant projects, Hookbuilder itself, Uniswap, wallets, RPC or infrastructure providers, the live Programmable
platform, Custom Launch API, deployed contracts, and third-party systems retain their own security processes. No public Universal Admission
service is claimed; a future deployment, remote worker plane, key-provisioning system, hosting provider, or distributed
store would require its own reviewed scope. A weakness in one of those systems is not automatically a vulnerability in
Programmable Launch Policy.

## Responsible testing

Test only in a local clone, a fork you control, or another environment containing synthetic data you control. Do not
test against production repositories, workflows, runners, registries, websites, contracts, wallets, providers, user
projects, or third-party systems without separate written authorization.

Do not access, change, retain, or destroy data you do not own. Do not move funds, obtain credentials, submit malicious
applications, exhaust GitHub Actions or other resources, perform denial-of-service testing, use social engineering, or
publish an unpatched exploit. Stop testing and report privately if you encounter non-public data.

Run queue and load tests only against an owner-controlled local database with synthetic public data. The offline SQLite
benchmark is not authorization to probe a future endpoint or claim production throughput. Do not place credentials,
private key material, bearer tokens, cookies, private repository coordinates, or personal data in an Admission envelope,
command, trust snapshot, receipt, fixture, benchmark, or bug report.

## Safe harbor

Research conducted in good faith and within this policy will be considered authorized for the limited purpose of this
policy. Programmable will not initiate legal action solely because of research that follows these rules. This does not
authorize activity against third parties or protect conduct outside this policy. If you are unsure whether a test is
permitted, ask through private vulnerability reporting before continuing.

## No bounty or guarantee

This is not a standing bug bounty program. A report does not create an obligation to pay a reward or meet a response or
remediation deadline. No audit, safety, or remediation guarantee is implied.
