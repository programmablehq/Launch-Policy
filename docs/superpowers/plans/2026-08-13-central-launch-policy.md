# Central Launch Policy Implementation Plan

> Historical implementation plan. It records the retired GitHub application transport and must not be used as current
> launch instructions. Current launches start at `https://programmable.market/.well-known/programmable.json` and use
> the advertised V3 capabilities, CLI, guide, OpenAPI, and `POST https://api.programmable.market/v3/custom-launches`.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `0xprogrammable/submit-launch` the single authored source of every Programmable-specific build, canary, review, and future production-launch requirement, with Hookbuilder, third-party agents, trusted intake, the future Security Bot, and Website eligibility acting only as bound consumers.

**Architecture:** `policy/launch-policy.v1.json` is the only authored requirement source. Focused code validates and executes named rule handlers, generated Markdown renders the same bytes, trusted-base Git identity creates the policy binding, and all decisions cite stable Rule IDs. The existing six-file V2 package remains a legacy transport; a separate one-file workflow-canary contract provides the requested lightweight hidden test path without pretending to authorize production.

**Tech Stack:** Node.js 24 ESM, canonical JSON, Git object identity, SHA-256, JSON Schema 2020-12 with the repository's pinned Ajv test dependency, `node:test`, GitHub Actions trusted-base execution.

## Global Constraints

- Candidate repositories and pull requests are inert, untrusted data; protected intake never imports or executes candidate code.
- Policy is loaded only from `0xprogrammable/submit-launch` repository ID `1320171831`, branch `main`, fixed path `policy/launch-policy.v1.json`, at the exact trusted base commit/tree.
- No protected API or CLI accepts caller-selected policy bytes, policy path, repository, profile, severity, enforcement, or outcome.
- `build` is enabled and may emit only `BUILT_NOT_REVIEWED`.
- `workflow-canary` is enabled and may emit only `CANARY_WORKFLOW_PASSED` with public routing, real funds, production routing, and launch authorization all false.
- `production-launch` remains disabled and cannot emit `LAUNCH_APPROVED`.
- Stable Rule IDs are never reused; retired rules remain recorded.
- General Uniswap v4, EVM, compiler, testing, and secure-coding knowledge remains Hookbuilder-owned; only Programmable admission policy moves.
- Transport/security invariants such as strict JSON, path safety, resource bounds, Git identity, authentication, signatures, and authority separation remain implementation controls, not independently authored launch requirements.
- Current V2 application bytes and historical v0.6.0 Hookbuilder/release artifacts remain unchanged.
- No push, pull request, tag, release, Website mutation, deployment, signing, or publication is part of this implementation.

---

## File Structure

### Submit Launch authored source and generated projections

- `policy/launch-policy.v1.json`: only authored Programmable requirement source.
- `policy/schemas/launch-policy.v1.schema.json`: closed syntax contract for the authored policy.
- `policy/schemas/launch-policy-binding.v1.schema.json`: exact protected-base policy identity.
- `docs/LAUNCH_POLICY.md`: generated human rendering; never normative by itself.
- `.programmable/active-contract.json`: generated consumer discovery manifest binding workflow, package, validator, and policy roles.

### Submit Launch implementation owners

- `scripts/launch-policy-core.mjs`: canonical parsing, semantic validation, digest, binding, profile/rule selection, handler closure, Markdown rendering.
- `scripts/launch-policy-handlers.mjs`: deterministic rule handler registry; values come from the policy, never private constants.
- `scripts/launch-policy.mjs`: read-only public CLI for third-party agents.
- `scripts/generate-launch-policy-artifacts.mjs`: generated docs and active-contract manifest.
- `review/launch-policy-review-core.mjs`: deterministic Security Bot/reviewer adapter.
- `review/schemas/launch-policy-review-input.v1.schema.json`: closed analyzer input.
- `review/schemas/launch-policy-review-decision.v1.schema.json`: closed checker-only decision.
- `scripts/workflow-canary-core.mjs`: new one-file canary application validation against trusted policy.
- `scripts/verify-workflow-canary.mjs`: trusted-base canary CLI.
- `canary/schemas/workflow-canary-application-v1.schema.json`: applicant canary contract.
- `canary/schemas/workflow-canary-result-v1.schema.json`: trusted deterministic result.
- `scripts/canary-eligibility-core.mjs`: signed hidden-Website eligibility compilation/verification.
- `acceptance/schemas/protected-canary-eligibility-command-v1.schema.json`: signed command.
- `acceptance/schemas/canary-eligibility-envelope-v1.schema.json`: Website-facing non-production envelope.

### Existing Submit Launch integrations

- `scripts/verify-public-hook-application-core.mjs`: legacy V2 trusted-base policy binding and policy-driven adapter values.
- `review/open-review-engine.mjs`: compatibility adapter; no injectable policy and no `launch_ready` authority.
- `scripts/acceptance-entitlement-core.mjs`: production entitlement disabled unless exact central policy permits it.
- `scripts/verify-repository.mjs`, `package.json`, `.github/CODEOWNERS`, `.github/workflows/verify-hook-builder.yml`: repository closure.

### Hookbuilder consumer

- `scripts/submit-launch-policy-contract.mjs`: strict local contract validation and stable binding type.
- `scripts/submit-launch-policy-github.mjs`: bounded exact Git-object policy retrieval.
- `scripts/cli-central-base.mjs`: resolve central base plus fixed policy record.
- `scripts/cli-prepare-pr-command.mjs`, `scripts/cli-prepare-pr-report.mjs`, `scripts/github-application-prepared-core.mjs`, `scripts/github-application-remote-core.mjs`: bind and recheck policy without owning its meaning.
- `references/approval-criteria.md`, `references/builder-reviewer-alignment.md`: short non-normative consumer guidance.
- Generated plugin mirror and contract registry: regenerated mechanically.

---

### Task 1: Canonical launch-policy contract

**Files:**
- Create: `policy/launch-policy.v1.json`
- Create: `policy/schemas/launch-policy.v1.schema.json`
- Create: `policy/schemas/launch-policy-binding.v1.schema.json`
- Create: `scripts/launch-policy-core.mjs`
- Create: `scripts/launch-policy-handlers.mjs`
- Create: `test/launch-policy.test.mjs`

**Interfaces:**
- Produces: `parseLaunchPolicyBytes(bytes)`, `validateLaunchPolicy(policy)`, `digestLaunchPolicyBytes(bytes)`, `readTrustedLaunchPolicyFromGit({ repositoryRoot, expectedBaseCommit })`, `buildLaunchPolicyBinding(policyRecord, profileId)`, `compareLaunchPolicyBindings(expected, observed)`, `selectLaunchPolicyProfile(policy, profileId)`, `rulesForProfile(policy, profileId)`, `evaluateLaunchPolicyRules({ policyRecord, profileId, subject, evidence })`, `renderLaunchPolicyMarkdown(policyRecord)`.
- Produces binding shape: `{ schemaVersion, repository, numericRepositoryId, baseCommit, baseTree, path, gitBlobOid, policyId, policyVersion, profileId, sha256 }`.
- Consumes no caller-selected path, origin, repository ID, or profile in the protected Git reader.

- [ ] **Step 1: Write failing canonical-policy tests**

```js
test("canonical policy exposes exactly build canary and disabled production profiles", () => {
  const record = parseLaunchPolicyBytes(fs.readFileSync("policy/launch-policy.v1.json"));
  assert.deepEqual(record.policy.profiles.map(({ id }) => id), ["build", "production-launch", "workflow-canary"]);
  assert.equal(selectLaunchPolicyProfile(record.policy, "production-launch").enabled, false);
  assert.doesNotMatch(JSON.stringify(record.policy), /LAUNCH_APPROVED/u);
});

test("policy rejects duplicate keys noncanonical bytes duplicate rule ids and unbound handlers", () => {
  assert.throws(() => parseLaunchPolicyBytes(Buffer.from('{"policyId":"a","policyId":"b"}\n')), hasCode("LAUNCH_POLICY_JSON_INVALID"));
  const mutated = structuredClone(validPolicy);
  mutated.rules.push(structuredClone(mutated.rules[0]));
  assert.throws(() => validateLaunchPolicy(mutated), hasCode("LAUNCH_POLICY_RULE_ID_INVALID"));
});
```

- [ ] **Step 2: Run tests and verify the contract is absent**

Run: `node --test test/launch-policy.test.mjs`

Expected: FAIL because `scripts/launch-policy-core.mjs` and the canonical policy do not exist.

- [ ] **Step 3: Author the closed policy and minimal handlers**

The initial active rules are exact and small:

```json
{
  "id": "BUILD.EXACT_SOURCE",
  "profiles": ["build"],
  "requirement": "Bind the exact source revision and declared build inputs.",
  "applicability": { "mode": "always" },
  "evidence": ["source-identity"],
  "severity": "blocker",
  "status": "active",
  "enforcement": { "owner": "applicant", "mode": "deterministic", "handlerId": "exact-source-v1" },
  "introducedIn": "1.0.0",
  "retiredIn": null
}
```

Include active build rules for exact source, truthful declared build/test evidence, v4 identity/permissions when applicable, and privileged/value-flow disclosure. Include active canary rules for authenticated application identity, exact public source, reproducible inert artifact, hidden namespace, no public routing, and no real-user funds. Record prior Programmable fee/admission rules as inactive production-only rules, not active canary blockers.

- [ ] **Step 4: Implement strict canonical parsing and semantic closure**

`parseLaunchPolicyBytes` must decode UTF-8 fatally, reject duplicate JSON keys with the vendored lossless parser, require `canonicalJson(policy) + "\n"` byte equality, enforce 512 KiB, validate exact fields and UTF-8 ordering, and return frozen `{ bytes, policy, sha256 }`.

`assertDeterministicValidatorCoverage` must prove a bijection between active deterministic `handlerId` values and `RULE_HANDLERS`; no active handler may be absent and no handler may be orphaned.

- [ ] **Step 5: Run focused policy tests**

Run: `node --test test/launch-policy.test.mjs`

Expected: PASS; disabled production and no-approval authority assertions remain green.

- [ ] **Step 6: Commit canonical policy contract**

```bash
git add policy scripts/launch-policy-core.mjs scripts/launch-policy-handlers.mjs test/launch-policy.test.mjs
git commit -m "feat: add canonical launch policy contract"
```

### Task 2: Generated public policy and third-party CLI

**Files:**
- Create: `scripts/generate-launch-policy-artifacts.mjs`
- Create: `scripts/launch-policy.mjs`
- Create: `docs/LAUNCH_POLICY.md`
- Create: `.programmable/active-contract.json`
- Create: `test/launch-policy-cli.test.mjs`
- Modify: `package.json`
- Modify: `scripts/verify-repository.mjs`
- Modify: `README.md`
- Modify: `CONTRIBUTING.md`
- Modify: `.github/CODEOWNERS`

**Interfaces:**
- Consumes Task 1 parsing, binding, selection, rendering.
- Produces CLI commands `requirements --profile`, `binding --profile`, `validate-policy`, and `render`.
- Produces generated active contract with fixed roles `workflow`, `validator`, `package`, and `policy`.

- [ ] **Step 1: Write failing generated-artifact and CLI tests**

```js
test("generated Markdown is byte-exact and binds the canonical policy digest", () => {
  const record = readRepositoryLaunchPolicy({ repositoryRoot: root });
  assert.equal(read("docs/LAUNCH_POLICY.md"), renderLaunchPolicyMarkdown(record));
  assert.match(read("docs/LAUNCH_POLICY.md"), new RegExp(record.sha256.replace(":", "\\:"), "u"));
});

test("third-party requirements CLI needs no Hookbuilder", () => {
  const result = run(["requirements", "--profile", "workflow-canary"]);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).profile.id, "workflow-canary");
});
```

- [ ] **Step 2: Verify tests fail before generators exist**

Run: `node --test test/launch-policy.test.mjs test/launch-policy-cli.test.mjs`

Expected: FAIL on missing generator, CLI, and generated files.

- [ ] **Step 3: Implement generator and public CLI**

The CLI emits canonical JSON, reads only repository-owned policy, never executes applicant code, and uses semantic exits: `0` valid/result, `1` applicant/policy finding, `2` system/operational failure. `--profile` accepts only policy-declared profiles; it is not accepted by protected Git readers.

- [ ] **Step 4: Add generation and verification scripts**

```json
{
  "policy:generate": "node scripts/generate-launch-policy-artifacts.mjs --write",
  "policy:check": "node scripts/generate-launch-policy-artifacts.mjs --check",
  "policy": "node scripts/launch-policy.mjs"
}
```

`scripts/verify-repository.mjs` calls the in-process artifact verifier before tests, so stale Markdown or manifest bytes fail the repository gate.

- [ ] **Step 5: Generate and run focused tests**

Run: `npm run policy:generate && npm run policy:check && node --test test/launch-policy.test.mjs test/launch-policy-cli.test.mjs test/public-surface.test.mjs`

Expected: PASS; public docs link the JSON as canonical and call Markdown generated.

- [ ] **Step 6: Commit public policy surface**

```bash
git add .programmable .github/CODEOWNERS CONTRIBUTING.md README.md docs/LAUNCH_POLICY.md package.json scripts/generate-launch-policy-artifacts.mjs scripts/launch-policy.mjs scripts/verify-repository.mjs test
git commit -m "feat: publish bound launch policy interface"
```

### Task 3: Generic policy-bound reviewer and Security Bot contract

**Files:**
- Create: `review/launch-policy-review-core.mjs`
- Create: `review/schemas/launch-policy-review-input.v1.schema.json`
- Create: `review/schemas/launch-policy-review-decision.v1.schema.json`
- Create: `review/examples/canary-passed.json`
- Create: `review/examples/canary-analysis-pending.json`
- Create: `review/examples/production-disabled.json`
- Create: `test/launch-policy-review.test.mjs`
- Modify: `review/open-review-engine.mjs`
- Modify: `review/cli.mjs`
- Delete: `review/policy.v1.json`
- Modify: `test/open-review-standard.test.mjs`
- Modify: `docs/OPEN_REVIEW_STANDARD.md`

**Interfaces:**
- Consumes `readTrustedLaunchPolicyFromGit` and canonical Rule IDs.
- Produces `validateLaunchPolicyReviewInput(input)`, `evaluateTrustedLaunchPolicyReview({ input, repositoryRoot, expectedBaseCommit })`, `canonicalLaunchPolicyDecision(decision)`, `digestLaunchPolicyDecision(decision)`.
- Decision authority is always `{ checkerOnly: true, independentAudit: false, launchAuthorized: false, publicRoutingAuthorized: false, realFundsAuthorized: false }`.

- [ ] **Step 1: Write failing reviewer authority tests**

```js
test("LLM observations cannot invent requirements severity or approval", () => {
  const input = validCanaryInput();
  input.observations.push({ analyzerId: "llm-1", ruleId: "MADE.UP", summary: "block this" });
  const decision = evaluateTrusted(input);
  assert.equal(decision.advisories.length, 1);
  assert.equal(decision.findings.length, 0);
  assert.equal(decision.authority.launchAuthorized, false);
});

test("disabled production profile never yields approval", () => {
  const decision = evaluateTrusted(productionInput());
  assert.equal(decision.status, "profile_disabled");
  assert.equal(decision.outcome, null);
});
```

- [ ] **Step 2: Verify tests fail with the existing injectable policy**

Run: `node --test test/launch-policy-review.test.mjs test/open-review-standard.test.mjs`

Expected: FAIL because central reviewer contracts do not exist and Open Review can inject `policy`.

- [ ] **Step 3: Implement closed evaluation semantics**

Rule evaluations contain only `{ ruleId, state, evidenceRefs, analyzer: { kind, id } }`. Severity, owner, requirement, enforcement, and outcome are projected from the current trusted policy. Missing active rules yield `analysis_pending`; binding mismatch yields `policy_drift`; subject mismatch yields `subject_drift`; disabled profile yields `profile_disabled`; violations yield `changes_requested`; complete build/canary rules yield the profile's non-authoritative outcome.

- [ ] **Step 4: Retire the second authored policy**

Remove `review/policy.v1.json`. `open-review-engine.mjs` becomes a compatibility adapter that internally loads the central policy, exposes no `policy` parameter, emits no `launch_ready`, and maps all surviving rationale/finding entries to central Rule IDs.

- [ ] **Step 5: Run reviewer/schema tests**

Run: `node --test test/launch-policy-review.test.mjs test/open-review-standard.test.mjs`

Expected: PASS; Ajv validates every example and decision; identical inputs emit byte-identical digests.

- [ ] **Step 6: Commit reviewer contract**

```bash
git add review docs/OPEN_REVIEW_STANDARD.md test/launch-policy-review.test.mjs test/open-review-standard.test.mjs
git commit -m "feat: bind reviews to central launch policy"
```

### Task 4: Legacy V2 trusted-intake adapter

**Files:**
- Modify: `scripts/verify-public-hook-application-core.mjs`
- Modify: `scripts/verify-public-hook-application.mjs`
- Modify: `.github/workflows/verify-hook-builder.yml`
- Modify: `scripts/test/verify-public-hook-application.test.mjs`
- Modify: `scripts/test/verify-public-hook-application-workflow.test.mjs`
- Modify: `scripts/test/verify-public-hook-application-maintained.test.mjs`

**Interfaces:**
- Consumes Task 1 trusted Git policy record and policy handler parameters.
- Produces successful legacy report fields `policyBinding`, `policyProfile: "legacy-v2-transport"`, and `evaluatedRuleIds`.
- Does not modify V2 candidate files or claim workflow-canary pass.
- Changes the pure adapter signature to `validatePublicApplicationPackageFiles({ applicationId, packageFiles, legacyPolicyAdapter })`; protected intake constructs `legacyPolicyAdapter` only from its trusted policy record, while historical local inspection remains explicitly non-authoritative.

- [ ] **Step 1: Write failing trusted-base binding regressions**

```js
test("unchanged V2 package is preserved but result binds the trusted base policy", async () => {
  const result = await verifyFixture();
  assert.equal(result.policyBinding.path, "policy/launch-policy.v1.json");
  assert.equal(result.policyBinding.baseCommit, fixture.baseCommit);
  assert.match(result.policyBinding.sha256, /^sha256:[0-9a-f]{64}$/u);
});

test("application plus policy edit is never classified as application", () => {
  assert.throws(() => classifyMixedFixture(), hasCode("APPLICATION_PATH_INVALID"));
});
```

- [ ] **Step 2: Run focused intake tests and confirm missing binding behavior**

Run: `npm run test:intake`

Expected: FAIL only on new policy-binding assertions.

- [ ] **Step 3: Read policy from the exact protected base**

After `classifyPublicIntakePullRequest`, call `readTrustedLaunchPolicyFromGit({ repositoryRoot: baseRoot, expectedBaseCommit })`. Never read `candidateRoot/policy`, working-tree policy, environment policy, CLI policy, or URL policy.

- [ ] **Step 4: Convert hidden fee literals into the frozen legacy adapter rule parameters**

Keep the existing V2 projection checks for compatibility, but consume fee owner, rate, policy ID/version, modes, and evidence ID from a central policy rule such as `LEGACY_V2.FEE_PROJECTION`. The function names may remain transport validators; they no longer author values.

- [ ] **Step 5: Add policy maintenance classification**

Add `policy/` and `.programmable/` to trusted maintenance prefixes/CODEOWNERS. Preserve the property that any PR mixing `submissions/` or `canary-submissions/` with policy changes cannot enter candidate application validation.

- [ ] **Step 6: Run full intake matrix**

Run: `npm run test:intake`

Expected: 0 failures; unchanged V2 fixture bytes still validate; malformed trusted policy is system-blocked; candidate substitution is ineffective.

- [ ] **Step 7: Commit trusted intake integration**

```bash
git add .github/workflows/verify-hook-builder.yml scripts/verify-public-hook-application*.mjs scripts/test/verify-public-hook-application*.test.mjs
git commit -m "feat: bind trusted intake to central policy"
```

### Task 5: Lightweight one-file workflow canary

**Files:**
- Create: `canary/schemas/workflow-canary-application-v1.schema.json`
- Create: `canary/schemas/workflow-canary-result-v1.schema.json`
- Create: `scripts/workflow-canary-core.mjs`
- Create: `scripts/verify-workflow-canary.mjs`
- Create: `test/workflow-canary.test.mjs`
- Create: `docs/WORKFLOW_CANARY.md`
- Modify: `scripts/verify-public-hook-application-core.mjs`
- Modify: `.github/workflows/verify-hook-builder.yml`

**Interfaces:**
- Consumes trusted policy profile `workflow-canary`.
- Applicant input is exactly `canary-submissions/<application-id>/application.json` with identity, exact public source, expected policy binding, and four non-production declarations.
- Produces `programmable.workflow-canary-result.v1` with `result: "CANARY_WORKFLOW_PASSED"` only when all active canary rules pass.

- [ ] **Step 1: Write failing one-file canary tests**

```js
test("one inert exact-source canary application passes without fee or audit fields", async () => {
  const result = await verifyWorkflowCanary(validFixture());
  assert.equal(result.result, "CANARY_WORKFLOW_PASSED");
  assert.equal(result.authority.launchAuthorized, false);
  assert.equal(result.authority.realFundsAllowed, false);
});

test("V2 package and production claims are forbidden in canary namespace", async () => {
  await assert.rejects(() => verifyWorkflowCanary(extraFeeFixture()), hasCode("CANARY_FIELDS_INVALID"));
});
```

- [ ] **Step 2: Run and observe missing canary implementation**

Run: `node --test test/workflow-canary.test.mjs`

Expected: FAIL on missing module/schema.

- [ ] **Step 3: Implement exact one-file validation**

Resolve source repository ID, commit, and tree as inert public Git data. Do not install dependencies or execute source. Require hidden/non-production/no-real-funds/non-audit declarations. Compare the applicant's expected binding to the current protected policy and return `POLICY_DRIFT` before any pass result.

- [ ] **Step 4: Route the new namespace in trusted workflow**

The classifier recognizes exactly one of `submissions/`, `canary-submissions/`, or maintenance. Mixed namespaces and policy edits fail. Hydration stays bounded to the single canary JSON blob.

- [ ] **Step 5: Run canary and intake tests**

Run: `node --test test/workflow-canary.test.mjs && npm run test:intake`

Expected: PASS; no fee/audit/approval/production requirement appears in canary input.

- [ ] **Step 6: Commit workflow-canary transport**

```bash
git add canary canary-submissions docs/WORKFLOW_CANARY.md scripts/workflow-canary-core.mjs scripts/verify-workflow-canary.mjs scripts/verify-public-hook-application-core.mjs .github/workflows/verify-hook-builder.yml test/workflow-canary.test.mjs
git commit -m "feat: add hidden workflow canary contract"
```

### Task 6: Signed hidden-Website canary eligibility

**Files:**
- Create: `acceptance/schemas/protected-canary-eligibility-command-v1.schema.json`
- Create: `acceptance/schemas/canary-eligibility-envelope-v1.schema.json`
- Create: `scripts/canary-eligibility-core.mjs`
- Create: `scripts/compile-canary-eligibility.mjs`
- Create: `test/canary-eligibility.test.mjs`
- Create: `docs/CANARY_ELIGIBILITY_V1.md`
- Modify: `scripts/acceptance-entitlement-core.mjs`
- Modify: `test/acceptance-entitlement.test.mjs`
- Modify: `package.json`

**Interfaces:**
- Consumes exact canonical Task 5 review-result bytes, package/source/PR identity, and protected-base policy binding.
- Produces `compileCanaryEligibilityEnvelope({ signedCommand, decisionBytes, applicationBytes, trustedAuthorityPublicKey, trustedPolicyRecord, now })`, `verifyWebsiteCanaryEligibility({ envelope, trustedAuthorityPublicKey, expectedPolicyBinding, now })`, and `canaryEligibilitySigningBytes(command)`.
- Envelope always declares hidden canary, no public discovery, no production routing, no real funds, no launch authorization.

- [ ] **Step 1: Write failing cross-authority tests**

```js
test("signed canary pass produces only hidden non-production eligibility", () => {
  const envelope = compileFixture();
  assert.deepEqual(envelope.eligibility, {
    surface: "hidden-canary",
    publicDiscovery: false,
    productionRouting: false,
    realFunds: false,
    launchAuthorized: false
  });
});

test("legacy entitlement and build result cannot satisfy canary gate", () => {
  assert.throws(() => verifyWebsiteCanaryEligibility(legacyEnvelope), hasCode("CANARY_ENVELOPE_UNSUPPORTED"));
});
```

- [ ] **Step 2: Run tests before implementation**

Run: `node --test test/canary-eligibility.test.mjs test/acceptance-entitlement.test.mjs`

Expected: FAIL on missing canary compiler.

- [ ] **Step 3: Implement separate signing domain and exact result inspection**

The command must include the full policy binding, not an arbitrary digest. The compiler reads exact decision bytes and verifies `status: passed`, `profile: workflow-canary`, and `outcome: CANARY_WORKFLOW_PASSED`. Green CI, labels, comments, merges, unsigned JSON, or the legacy entitlement schema cannot substitute.

- [ ] **Step 4: Disable production entitlement under current policy**

Change the legacy signature to `compileLaunchEntitlementEnvelope({ signedCommand, packageDirectory, launchPlanFile, trustedAuthorityPublicKey, trustedPolicyRecord, now })`. Before it accepts a production command, prove that `trustedPolicyRecord` came from the fixed local protected checkout and that `production-launch.enabled === true`. With v1 policy it returns `PRODUCTION_LAUNCH_DISABLED`; the old opaque `policyBundleDigest` alone is insufficient authority.

- [ ] **Step 5: Run acceptance matrices**

Run: `node --test test/canary-eligibility.test.mjs test/acceptance-entitlement.test.mjs`

Expected: PASS; existing cryptographic drift tests remain green and no production path is enabled.

- [ ] **Step 6: Commit canary eligibility contract**

```bash
git add acceptance docs/CANARY_ELIGIBILITY_V1.md package.json scripts/canary-eligibility-core.mjs scripts/compile-canary-eligibility.mjs scripts/acceptance-entitlement-core.mjs test
git commit -m "feat: add non-production canary eligibility"
```

### Task 7: Hookbuilder becomes a pure policy consumer

**Files:**
- Create in Hookbuilder: `skills/programmable-v4-hook-builder/scripts/submit-launch-policy-contract.mjs`
- Create in Hookbuilder: `skills/programmable-v4-hook-builder/scripts/submit-launch-policy-github.mjs`
- Create in Hookbuilder: `skills/programmable-v4-hook-builder/scripts/workflow-canary-application-client.mjs`
- Create in Hookbuilder: `skills/programmable-v4-hook-builder/scripts/prepare-canary.mjs`
- Create in Hookbuilder: `skills/programmable-v4-hook-builder/scripts/test/submit-launch-policy-client.test.mjs`
- Create in Hookbuilder: `skills/programmable-v4-hook-builder/scripts/test/prepare-canary.test.mjs`
- Modify: `skills/programmable-v4-hook-builder/scripts/registry-intake-contract.mjs`
- Modify: `skills/programmable-v4-hook-builder/scripts/cli-central-base.mjs`
- Modify: `skills/programmable-v4-hook-builder/scripts/cli-prepare-pr-command.mjs`
- Modify: `skills/programmable-v4-hook-builder/scripts/cli-prepare-pr-report.mjs`
- Modify: `skills/programmable-v4-hook-builder/scripts/github-application-prepared-core.mjs`
- Modify: `skills/programmable-v4-hook-builder/scripts/github-application-remote-core.mjs`
- Modify: `skills/programmable-v4-hook-builder/references/approval-criteria.md`
- Modify: `skills/programmable-v4-hook-builder/references/builder-reviewer-alignment.md`
- Modify: generated plugin mirror and `contract-registry-v1.json`

**Interfaces:**
- Consumes Submit Launch fixed repository ID, branch, policy path, policy schema, and exact Git bytes.
- Produces `{ repositoryId, baseCommit, baseTree, path, policyId, policyVersion, profileId, sha256, schemaSha256 }` for `workflow-canary`.
- Emits `POLICY_DRIFT` if central policy changes between resolution, package preparation, or final remote write preflight.
- Produces a separate `prepare-canary` command that writes only `canary-submissions/<application-id>/application.json`; existing `prepare-pr` remains the historical V2 command and is not reinterpreted.

- [ ] **Step 1: Create a new isolated Hookbuilder worktree from exact public main**

```bash
git worktree add /Users/hazar/Documents/Codex/2026-08-12/de/work/hookbuilder-central-policy-consumer-20260813 -b codex/hookbuilder-central-policy-consumer-20260813 dae8b507c6213abc2a91000b5c08e8b7d52e6e04
```

- [ ] **Step 2: Write failing policy-client and race tests**

```js
test("prepare-pr resolves workflow-canary policy from exact protected main", async () => {
  const result = await resolveSubmitLaunchPolicy(fixtureTransport());
  assert.equal(result.profileId, "workflow-canary");
  assert.equal(result.repositoryId, "1320171831");
});

test("remote policy drift blocks before any write", async () => {
  await assert.rejects(() => prepareWithDrift(), hasCode("POLICY_DRIFT"));
  assert.deepEqual(writes, []);
});
```

- [ ] **Step 3: Implement strict local and Git policy clients**

Only bootstrap anchors stay local: repository owner/name/ID, branch, policy path, and schema path. Mutable rule meaning, fee values, evidence, severity, and outcomes come from exact central bytes. No `--policy`, arbitrary path, arbitrary repository, or production profile option is exposed.

- [ ] **Step 4: Thread binding through preparation and remote rechecks**

`cli-central-base.mjs` returns base and policy together. `cli-prepare-pr-command.mjs` compares them after source/package construction. Prepared metadata records the binding. `github-application-remote-core.mjs` resolves the central base/policy again immediately before any branch/PR write and blocks on any byte or identity drift.

`workflow-canary-application-client.mjs` exports `buildWorkflowCanaryApplication({ applicationId, applicationRevision, builder, source, expectedPolicyBinding, title, summary })` and validates its own output against the Submit-owned schema bytes fetched from the same protected tree. `prepare-canary.mjs` is read-only by default and writes the one-file package only with the existing explicit output/write acknowledgement boundary; it never modifies source or performs a GitHub write.

- [ ] **Step 5: Remove hidden normative Programmable prose**

Replace `approval-criteria.md` and `builder-reviewer-alignment.md` with short consumer guides pointing to exact protected policy resolution. Keep universal v4/EVM knowledge and explicitly label fee kernels/templates as optional implementation assets selected only when the central policy requires them. No active route may call the local documents launch authority.

- [ ] **Step 6: Regenerate mirrors and run focused tests**

Run from Hookbuilder worktree:

```bash
node --test skills/programmable-v4-hook-builder/scripts/test/submit-launch-policy-client.test.mjs \
  skills/programmable-v4-hook-builder/scripts/test/prepare-canary.test.mjs \
  skills/programmable-v4-hook-builder/scripts/test/cli-central-base.test.mjs \
  skills/programmable-v4-hook-builder/scripts/test/cli-prepare-pr.test.mjs \
  skills/programmable-v4-hook-builder/scripts/test/github-application.test.mjs
npm run plugin:write
npm run plugin:check
node skills/programmable-v4-hook-builder/scripts/validate-contract-registry.mjs --check
git diff --check
```

Expected: PASS; canonical/plugin mirrors are byte-identical; no active module owns a hidden Programmable admission rule.

- [ ] **Step 7: Commit Hookbuilder consumer**

```bash
git add skills plugins config test
git commit -m "feat: consume submit launch policy"
```

### Task 8: Single-source audit, full verification, and handoff

**Files:**
- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/REVIEW_LIFECYCLE.md`
- Modify: `docs/builder/PUBLIC_GITHUB_PR_BETA.md`
- Modify: `AGENTS.md`
- Create: `test/launch-policy-single-source.test.mjs`
- Modify: `scripts/verify-repository.mjs`

**Interfaces:**
- Consumes all prior tasks.
- Produces a repository gate that fails when a Programmable admission requirement is authored outside central policy or a semantic failure lacks a current Rule ID.

- [ ] **Step 1: Write failing single-source ownership test**

```js
test("all Programmable semantic findings map to current policy Rule IDs", () => {
  const policyIds = new Set(readPolicy().rules.map(({ id }) => id));
  for (const finding of enumerateSemanticFixtures()) assert.equal(policyIds.has(finding.ruleId), true, finding.code);
});

test("there is no second authored launch-policy JSON or normative admission document", () => {
  assert.deepEqual(findAuthoredPolicyCandidates(), ["policy/launch-policy.v1.json"]);
});
```

- [ ] **Step 2: Run the ownership test and remove remaining duplicates**

Run: `node --test test/launch-policy-single-source.test.mjs`

Expected initially: FAIL with exact remaining duplicate owners; convert them to generated projections, compatibility adapters, universal engineering knowledge, or implementation handlers whose values are policy-derived.

- [ ] **Step 3: Run complete Submit Launch verification**

Run:

```bash
npm ci --ignore-scripts
npm test
npm run policy:check
git diff --check
git status --short
```

Expected: all tests pass; generated bytes current; worktree clean after commit.

- [ ] **Step 4: Run complete Hookbuilder verification**

Run in the Hookbuilder consumer worktree:

```bash
npm ci --ignore-scripts
npm test
gh skill publish --dry-run
git diff --check
git status --short
```

Expected: all repository, portable-skill, plugin, publication-shape, and consumer tests pass; no remote write occurs.

- [ ] **Step 5: Perform final threat-boundary review**

Check every spec acceptance criterion:

1. A non-Hookbuilder developer can find JSON, generated Markdown, schema, CLI, and package format.
2. Every semantic finding carries a current Rule ID.
3. Trusted intake and canary compare exact protected policy identity and bytes.
4. Hookbuilder contains no hidden Programmable admission authority.
5. Canary is hidden, no funds, no public routing, and no launch approval.
6. Policy changes are versioned, generated, tested, and drift-detected.

- [ ] **Step 6: Commit documentation and final gate**

```bash
git add AGENTS.md docs scripts/verify-repository.mjs test/launch-policy-single-source.test.mjs
git commit -m "docs: centralize launch policy ownership"
```

- [ ] **Step 7: Produce local-only handoff**

Report exact Submit Launch and Hookbuilder worktree paths, branches, commits, trees, changed files, focused/full checks, generated digests, remaining external dependencies, and explicitly state that nothing was pushed, published, deployed, signed, or made live.
