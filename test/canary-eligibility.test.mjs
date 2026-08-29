import assert from "node:assert/strict";
import childProcess from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import Ajv2020 from "../scripts/test/schema-validator/node_modules/ajv/dist/2020.js";
import addFormats from "../scripts/test/schema-validator/node_modules/ajv-formats/dist/index.js";

import {
  CANARY_ELIGIBILITY_COMMAND_VERSION,
  CANARY_ELIGIBILITY_ENVELOPE_VERSION,
  SIGNED_CANARY_ELIGIBILITY_COMMAND_VERSION,
  CanaryEligibilityError,
  canaryEligibilityAuthorityKeyId,
  canaryEligibilitySigningBytes,
  compileCanaryEligibilityEnvelope,
  readCanaryEligibilityApplicationFile,
  verifyWebsiteCanaryEligibility
} from "../scripts/canary-eligibility-core.mjs";
import {
  buildLaunchPolicyBinding,
  canonicalJson,
  readTrustedLaunchPolicyFromGit
} from "../scripts/launch-policy-core.mjs";
import {
  canonicalWorkflowCanaryResult,
  verifyWorkflowCanary
} from "../scripts/workflow-canary-core.mjs";
import {
  acceptanceCommandSigningBytes,
  authorityKeyId
} from "../scripts/acceptance-entitlement-core.mjs";
import { classifyPublicIntakePullRequest } from "../scripts/verify-public-hook-application-core.mjs";

const root = path.resolve(import.meta.dirname, "..");
const NOW = new Date("2026-08-13T10:05:00.000Z");
const STAGING_AUDIENCE = "programmable.market:hidden-canary:staging";
const PRODUCTION_AUDIENCE = "programmable.market:hidden-canary:production";
const SOURCE = Object.freeze({
  repository: "alice/example-hook",
  numericRepositoryId: "123456789",
  commit: "a".repeat(40),
  tree: "b".repeat(40)
});

test("signed canary pass produces only deterministic hidden non-production eligibility", async (t) => {
  const fixture = await createEligibilityFixture(t);
  const first = compileFixture(fixture);
  const second = compileFixture(fixture);

  assert.deepEqual(first, second);
  assert.equal(first.schemaVersion, CANARY_ELIGIBILITY_ENVELOPE_VERSION);
  assert.equal(first.state, "eligible");
  assert.equal(first.audience, STAGING_AUDIENCE);
  assert.equal(first.canaryCommand.audience, STAGING_AUDIENCE);
  assert.deepEqual(first.eligibility, {
    surface: "hidden-canary",
    publicDiscovery: false,
    productionRouting: false,
    realFunds: false,
    launchAuthorized: false
  });
  assert.match(first.eligibilityId, /^sha256:[0-9a-f]{64}$/u);
  assert.deepEqual(first.applicationDocument, fixture.application);
  assert.deepEqual(first.workflowCanaryResult, fixture.result);
  assert.equal(
    verifyWebsiteCanaryEligibility({
      envelope: first,
      trustedAuthorityPublicKey: fixture.publicKey,
      trustedPolicyRecord: fixture.policyRecord,
      expectedAudience: STAGING_AUDIENCE,
      expectedPolicyBinding: fixture.policyBinding,
      now: NOW
    }).eligibilityId,
    first.eligibilityId
  );
});

test("signed audience prevents Canary eligibility reuse across Website environments", async (t) => {
  const fixture = await createEligibilityFixture(t);
  const staging = compileFixture(fixture);
  assert.equal(verifyWebsite(fixture, staging, NOW, STAGING_AUDIENCE).state, "eligible");
  assert.throws(
    () => verifyWebsite(fixture, staging, NOW, PRODUCTION_AUDIENCE),
    hasCode("CANARY_AUDIENCE_MISMATCH")
  );

  const productionCommand = makeCommand(fixture, { audience: PRODUCTION_AUDIENCE });
  const production = compileFixture(fixture, {
    signedCommand: signFixtureCommand(fixture, productionCommand)
  });
  assert.equal(verifyWebsite(fixture, production, NOW, PRODUCTION_AUDIENCE).audience, PRODUCTION_AUDIENCE);
  assert.throws(
    () => verifyWebsite(fixture, production, NOW, STAGING_AUDIENCE),
    hasCode("CANARY_AUDIENCE_MISMATCH")
  );
  assert.notEqual(production.eligibilityId, staging.eligibilityId);

  const unsupported = makeCommand(fixture, { audience: "programmable.market:hidden-canary:local" });
  assert.throws(() => canaryEligibilitySigningBytes(unsupported), hasCode("CANARY_AUDIENCE_INVALID"));

  assert.throws(
    () => verifyWebsiteCanaryEligibility({
      envelope: staging,
      trustedAuthorityPublicKey: fixture.publicKey,
      trustedPolicyRecord: fixture.policyRecord,
      expectedPolicyBinding: fixture.policyBinding,
      now: NOW
    }),
    hasCode("CANARY_EXPECTED_AUDIENCE_INVALID")
  );

  const transplanted = structuredClone(staging);
  transplanted.audience = PRODUCTION_AUDIENCE;
  assert.throws(
    () => verifyWebsite(fixture, transplanted, NOW, PRODUCTION_AUDIENCE),
    hasCode("CANARY_ENVELOPE_INVALID")
  );
});

test("strict command and envelope schemas compile and validate runtime output", async (t) => {
  const fixture = await createEligibilityFixture(t);
  const signedCommand = signFixtureCommand(fixture, makeCommand(fixture));
  const envelope = compileFixture(fixture, { signedCommand });
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  const applicationSchema = readJson("canary/schemas/workflow-canary-application-v1.schema.json");
  const reviewSchema = readJson("review/schemas/launch-policy-review-decision.v1.schema.json");
  const resultSchema = readJson("canary/schemas/workflow-canary-result-v1.schema.json");
  const commandSchema = readJson("acceptance/schemas/protected-canary-eligibility-command-v1.schema.json");
  const envelopeSchema = readJson("acceptance/schemas/canary-eligibility-envelope-v1.schema.json");
  addFormats(ajv, { mode: "full" });
  ajv.addSchema(applicationSchema);
  ajv.addSchema(reviewSchema);
  ajv.addSchema(resultSchema);
  ajv.addSchema(commandSchema);
  const validateEnvelope = ajv.compile(envelopeSchema);
  const validateCommand = ajv.getSchema(commandSchema.$id);
  assert.equal(validateCommand(signedCommand), true, JSON.stringify(validateCommand.errors));
  assert.equal(validateEnvelope(envelope), true, JSON.stringify(validateEnvelope.errors));

  const extra = structuredClone(signedCommand);
  extra.command.eligibility.public = true;
  assert.equal(validateCommand(extra), false);
  assert.throws(() => canaryEligibilitySigningBytes(extra.command), hasCode("CANARY_COMMAND_INVALID"));

  const missing = structuredClone(envelope);
  delete missing.canaryCommand.source;
  assert.equal(validateEnvelope(missing), false);
  assert.throws(
    () => verifyWebsite(fixture, missing),
    hasCode("CANARY_ENVELOPE_INVALID")
  );

  for (const [label, value] of [
    ["valid RFC3339 without milliseconds", "2026-08-13T10:00:00Z"],
    ["UTC offset instead of Z", "2026-08-13T10:00:00.000+00:00"],
    ["two fractional digits", "2026-08-13T10:00:00.00Z"],
    ["lowercase RFC3339 separators", "2026-08-13t10:00:00.000z"]
  ]) {
    for (const field of ["issuedAt", "validUntil"]) {
      const noncanonical = structuredClone(signedCommand);
      noncanonical.command[field] = value;
      assert.equal(
        validateCommand(noncanonical),
        false,
        `${field} schema must reject ${label}: ${JSON.stringify(validateCommand.errors)}`
      );
      assert.throws(
        () => canaryEligibilitySigningBytes(noncanonical.command),
        hasCode("CANARY_COMMAND_TIME_INVALID"),
        `${field} runtime must reject ${label}`
      );
    }
  }
});

test("exact reissue deduplicates eligibility while authorization digest changes", async (t) => {
  const fixture = await createEligibilityFixture(t);
  const original = compileFixture(fixture);
  const reissuedCommand = makeCommand(fixture, {
    issuedAt: "2026-08-13T10:01:00.000Z",
    validUntil: "2026-08-13T10:11:00.000Z"
  });
  reissuedCommand.issuedBy.mode = "automation-review";
  const reissued = compileFixture(fixture, {
    signedCommand: signFixtureCommand(fixture, reissuedCommand)
  });
  assert.equal(reissued.eligibilityId, original.eligibilityId);
  assert.notEqual(reissued.authorization.signedCommandDigest, original.authorization.signedCommandDigest);
});

test("legacy entitlement signature domain cannot authorize a canary command", async (t) => {
  const fixture = await createEligibilityFixture(t);
  const command = makeCommand(fixture);
  const legacySignature = crypto.sign(
    null,
    Buffer.concat([
      Buffer.from("programmable.submit-launch.protected-acceptance-command.v1\0", "utf8"),
      Buffer.from(canonicalJson(command), "utf8")
    ]),
    fixture.privateKey
  ).toString("base64url");
  const signedCommand = {
    authorization: {
      algorithm: "ed25519",
      keyId: canaryEligibilityAuthorityKeyId(fixture.publicKey),
      signature: legacySignature
    },
    command,
    schemaVersion: SIGNED_CANARY_ELIGIBILITY_COMMAND_VERSION
  };
  assert.throws(() => compileFixture(fixture, { signedCommand }), hasCode("CANARY_SIGNATURE_INVALID"));

  const canarySignature = crypto.sign(null, canaryEligibilitySigningBytes(command), fixture.privateKey).toString("base64url");
  const legacyShaped = makeLegacyCommand();
  assert.notDeepEqual(canaryEligibilitySigningBytes(command), acceptanceCommandSigningBytes(legacyShaped));
  assert.equal(
    crypto.verify(null, acceptanceCommandSigningBytes(legacyShaped), fixture.publicKey, Buffer.from(canarySignature, "base64url")),
    false
  );
  assert.notEqual(canaryEligibilityAuthorityKeyId(fixture.publicKey), undefined);
  assert.equal(canaryEligibilityAuthorityKeyId(fixture.publicKey), authorityKeyId(fixture.publicKey));
});

test("compiler rejects wrong key signature tamper and all time-window violations", async (t) => {
  const fixture = await createEligibilityFixture(t);
  const attacker = crypto.generateKeyPairSync("ed25519");
  const command = makeCommand(fixture);
  assert.throws(
    () => compileFixture(fixture, { signedCommand: signCommand(command, attacker.privateKey, attacker.publicKey) }),
    hasCode("CANARY_AUTHORITY_KEY_MISMATCH")
  );

  const tampered = signFixtureCommand(fixture, command);
  tampered.command.pullRequest.head.commit = "f".repeat(40);
  assert.throws(() => compileFixture(fixture, { signedCommand: tampered }), hasCode("CANARY_SIGNATURE_INVALID"));

  for (const [issuedAt, validUntil, now, code] of [
    ["2026-08-13T10:00:00.000Z", "2026-08-13T10:15:00.001Z", NOW, "CANARY_COMMAND_LIFETIME_INVALID"],
    ["2026-08-13T10:00:00.000Z", "2026-08-13T10:00:00.000Z", NOW, "CANARY_COMMAND_LIFETIME_INVALID"],
    ["2026-08-13T10:00:00.000Z", "2026-08-13T10:10:00.000Z", new Date("2026-08-13T09:59:59.999Z"), "CANARY_COMMAND_NOT_CURRENT"],
    ["2026-08-13T10:00:00.000Z", "2026-08-13T10:10:00.000Z", new Date("2026-08-13T10:10:00.001Z"), "CANARY_COMMAND_NOT_CURRENT"]
  ]) {
    const dated = makeCommand(fixture, { issuedAt, validUntil });
    assert.throws(
      () => compileFixture(fixture, { signedCommand: signFixtureCommand(fixture, dated), now }),
      hasCode(code)
    );
  }

  const boundary = compileFixture(fixture, {
    signedCommand: signFixtureCommand(fixture, makeCommand(fixture)),
    now: new Date("2026-08-13T10:00:00.000Z")
  });
  assert.equal(verifyWebsite(fixture, boundary, new Date("2026-08-13T10:10:00.000Z")).state, "eligible");
});

test("raw application and result bytes are canonical authority and cross-bound", async (t) => {
  const fixture = await createEligibilityFixture(t);
  const signedCommand = signFixtureCommand(fixture, makeCommand(fixture));
  for (const [key, bytes, code] of [
    ["application CRLF", Buffer.from(fixture.applicationBytes.toString("utf8").replace(/\n$/u, "\r\n")), "CANARY_JSON_NONCANONICAL"],
    ["application duplicate", Buffer.from('{"applicationId":"x","applicationId":"y"}\n'), "CANARY_JSON_INVALID"],
    ["result trailing", Buffer.concat([fixture.resultBytes, Buffer.from(" ")]), "CANARY_RESULT_JSON_NONCANONICAL"]
  ]) {
    const options = { signedCommand };
    if (key.startsWith("application")) options.applicationBytes = bytes;
    else options.decisionBytes = bytes;
    assert.throws(() => compileFixture(fixture, options), hasCode(code), key);
  }

  const driftedApplication = structuredClone(fixture.application);
  driftedApplication.summary = "Different exact application bytes.";
  assert.throws(
    () => compileFixture(fixture, { signedCommand, applicationBytes: jsonBytes(driftedApplication) }),
    hasCode("CANARY_APPLICATION_BINDING_MISMATCH")
  );

  const rawTask3Decision = jsonBytes(fixture.result.reviewDecision);
  assert.throws(
    () => compileFixture(fixture, { signedCommand, decisionBytes: rawTask3Decision }),
    hasCode("CANARY_RESULT_FIELDS_INVALID")
  );
});

test("stable Canary file reads reject replacements between lstat and open", (t) => {
  const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), "canary-stable-file-race-"));
  t.after(() => fs.rmSync(fixtureRoot, { recursive: true, force: true }));
  const target = path.join(fixtureRoot, "application.json");
  const originalOpenSync = fs.openSync;

  for (const [name, replace] of [
    ["oversized", () => replaceWithFile(target, Buffer.alloc(64 * 1024 + 1, 0x61), 0o600)],
    ["executable", () => replaceWithFile(target, Buffer.from("{}\n", "utf8"), 0o700)],
    ["nonregular", () => {
      fs.unlinkSync(target);
      fs.mkdirSync(target);
    }]
  ]) {
    fs.rmSync(target, { recursive: true, force: true });
    fs.writeFileSync(target, Buffer.from("{}\n", "utf8"), { mode: 0o600 });
    let intercepted = false;
    fs.openSync = function interceptedOpen(filePath, flags, ...args) {
      if (!intercepted && path.resolve(filePath) === path.resolve(target)) {
        intercepted = true;
        replace();
      }
      return originalOpenSync.call(fs, filePath, flags, ...args);
    };
    try {
      assert.throws(
        () => readCanaryEligibilityApplicationFile(target),
        hasCode("CANARY_APPLICATION_FILE_INVALID"),
        `${name} path replacement must fail before bytes are trusted`
      );
      assert.equal(intercepted, true, `${name} regression must replace the path between lstat and open`);
    } finally {
      fs.openSync = originalOpenSync;
    }
  }
});

test("command and current trusted policy must close over every identity", async (t) => {
  const fixture = await createEligibilityFixture(t);
  const mutations = [
    ["applicationRevision", (value) => { value.application.applicationRevision += 1; }, "CANARY_APPLICATION_BINDING_MISMATCH"],
    ["head commit", (value) => { value.pullRequest.head.commit = "e".repeat(40); }, "CANARY_PULL_REQUEST_BINDING_MISMATCH"],
    ["source tree", (value) => { value.source.tree = "e".repeat(40); }, "CANARY_SOURCE_BINDING_MISMATCH"],
    ["policy hash", (value) => { value.policyBinding.sha256 = `sha256:${"0".repeat(64)}`; }, "CANARY_POLICY_BINDING_MISMATCH"],
    ["result byte digest", (value) => { value.workflowCanaryResult.sha256 = `sha256:${"0".repeat(64)}`; }, "CANARY_RESULT_BINDING_MISMATCH"],
    ["eligibility escalation", (value) => { value.eligibility.realFunds = true; }, "CANARY_ELIGIBILITY_INVALID"]
  ];
  for (const [name, mutate, code] of mutations) {
    const command = makeCommand(fixture);
    mutate(command);
    assert.throws(
      () => compileFixture(fixture, { signedCommand: signFixtureCommand(fixture, command) }),
      hasCode(code),
      name
    );
  }

  const copiedRecord = { ...fixture.policyRecord };
  assert.throws(
    () => compileFixture(fixture, { trustedPolicyRecord: copiedRecord }),
    hasCode("CANARY_POLICY_TRUST_INVALID")
  );
});

test("Website verifier rejects legacy build unsigned and tampered envelopes", async (t) => {
  const fixture = await createEligibilityFixture(t);
  const envelope = compileFixture(fixture);
  for (const value of [
    { schemaVersion: "programmable.launch-entitlement-envelope.v1" },
    { schemaVersion: "programmable.workflow-canary-result.v1", ...fixture.result },
    { schemaVersion: "programmable.build-result.v1", outcome: "BUILT_NOT_REVIEWED" },
    { schemaVersion: CANARY_ELIGIBILITY_ENVELOPE_VERSION, state: "eligible" },
    { conclusion: "success", label: "approved", merged: true }
  ]) {
    assert.throws(() => verifyWebsite(fixture, value), hasCode("CANARY_ENVELOPE_UNSUPPORTED"));
  }

  const cases = [
    ["eligibility", (value) => { value.eligibility.publicDiscovery = true; }],
    ["id", (value) => { value.eligibilityId = `sha256:${"0".repeat(64)}`; }],
    ["signed digest", (value) => { value.authorization.signedCommandDigest = `sha256:${"0".repeat(64)}`; }],
    ["embedded app", (value) => { value.applicationDocument.summary = "tampered"; }],
    ["embedded result", (value) => { value.workflowCanaryResult.digest = `sha256:${"0".repeat(64)}`; }]
  ];
  for (const [name, mutate] of cases) {
    const changed = structuredClone(envelope);
    mutate(changed);
    assert.throws(() => verifyWebsite(fixture, changed), (error) => error instanceof CanaryEligibilityError, name);
  }

  const staleBinding = structuredClone(fixture.policyBinding);
  staleBinding.sha256 = `sha256:${"0".repeat(64)}`;
  assert.throws(
    () => verifyWebsiteCanaryEligibility({
      envelope,
      trustedAuthorityPublicKey: fixture.publicKey,
      trustedPolicyRecord: fixture.policyRecord,
      expectedAudience: STAGING_AUDIENCE,
      expectedPolicyBinding: staleBinding,
      now: NOW
    }),
    hasCode("CANARY_EXPECTED_POLICY_BINDING_MISMATCH")
  );
});

test("actual application revision and source drift produce different eligibility ids", async (t) => {
  const baseline = await createEligibilityFixture(t);
  const revised = await createEligibilityFixture(t, { applicationRevision: 2 });
  const changedSource = await createEligibilityFixture(t, {
    source: {
      ...SOURCE,
      commit: "c".repeat(40),
      tree: "d".repeat(40)
    }
  });
  const baselineId = compileFixture(baseline).eligibilityId;
  assert.notEqual(compileFixture(revised).eligibilityId, baselineId);
  assert.notEqual(compileFixture(changedSource).eligibilityId, baselineId);
});

test("protected canary compiler CLI emits one canonical envelope without repository writes", async (t) => {
  const fixture = await createEligibilityFixture(t);
  const clock = new Date();
  const command = makeCommand(fixture, {
    issuedAt: new Date(clock.getTime() - 60_000).toISOString(),
    validUntil: new Date(clock.getTime() + 10 * 60_000).toISOString()
  });
  const signedCommand = signFixtureCommand(fixture, command);
  const commandFile = path.join(fixture.fixtureRoot, "signed-canary-command.json");
  const applicationFile = path.join(fixture.fixtureRoot, "canary-application.json");
  const resultFile = path.join(fixture.fixtureRoot, "workflow-canary-result.json");
  const publicKeyFile = path.join(fixture.fixtureRoot, "canary-public-key.pem");
  fs.writeFileSync(commandFile, jsonBytes(signedCommand), { mode: 0o600 });
  fs.writeFileSync(applicationFile, fixture.applicationBytes, { mode: 0o600 });
  fs.writeFileSync(resultFile, fixture.resultBytes, { mode: 0o600 });
  fs.writeFileSync(publicKeyFile, fixture.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o600 });
  const before = git(fixture.base, ["status", "--short"]);
  const output = childProcess.spawnSync(process.execPath, [
    path.resolve("scripts/compile-canary-eligibility.mjs"),
    "--signed-command", commandFile,
    "--application", applicationFile,
    "--workflow-canary-result", resultFile,
    "--trusted-authority-public-key", publicKeyFile,
    "--trusted-policy-repository-root", fixture.base,
    "--expected-policy-base-commit", fixture.baseCommit
  ], { encoding: "utf8", shell: false, env: { ...process.env, TZ: "UTC" } });
  assert.equal(output.status, 0, output.stderr);
  const envelope = JSON.parse(output.stdout);
  assert.equal(output.stdout, `${canonicalJson(envelope)}\n`);
  assert.equal(envelope.schemaVersion, CANARY_ELIGIBILITY_ENVELOPE_VERSION);
  assert.equal(git(fixture.base, ["status", "--short"]), before);
});

test("exact canary and Applicant compatibility maintenance paths are bounded while nearby paths and mixed applicant PRs fail", (t) => {
  const fixture = createPolicyRepository(t);
  for (const script of [
    "scripts/canary-eligibility-core.mjs",
    "scripts/compile-canary-eligibility.mjs",
    "scripts/applicant-compatibility-core.mjs"
  ]) {
    git(fixture.candidate, ["checkout", "--quiet", "--detach", fixture.baseCommit]);
    writeFile(fixture.candidate, script, "maintenance\n");
    const head = commitAll(fixture.candidate, `maintain ${script}`);
    const merge = createMergeCommit(fixture.candidate, fixture.baseCommit, head);
    assert.equal(classifyPublicIntakePullRequest(classificationInput(fixture, head, merge)).mode, "registry-maintenance");
  }

  for (const entryPath of [
    ".programmable/applicant-compatibility.v1.json",
    ".programmable/applicant-compatibility.v2.json",
    "vendor/programmable-applicant-validator/scripts/public-applicant-validator.mjs"
  ]) {
    git(fixture.candidate, ["checkout", "--quiet", "--detach", fixture.baseCommit]);
    writeFile(fixture.candidate, entryPath, "maintenance\n");
    const head = commitAll(fixture.candidate, `maintain ${entryPath}`);
    const merge = createMergeCommit(fixture.candidate, fixture.baseCommit, head);
    assert.equal(classifyPublicIntakePullRequest(classificationInput(fixture, head, merge)).mode, "registry-maintenance");
  }

  git(fixture.candidate, ["checkout", "--quiet", "--detach", fixture.baseCommit]);
  writeFile(fixture.candidate, "scripts/canary-eligibility-helper.mjs", "untrusted\n");
  const nearbyHead = commitAll(fixture.candidate, "nearby script");
  const nearbyMerge = createMergeCommit(fixture.candidate, fixture.baseCommit, nearbyHead);
  assert.throws(
    () => classifyPublicIntakePullRequest(classificationInput(fixture, nearbyHead, nearbyMerge)),
    hasCode("CHANGED_PATH_NOT_ALLOWED")
  );

  for (const entryPath of [
    "vendor/programmable-applicant-validator-private/scripts/public-applicant-validator.mjs"
  ]) {
    git(fixture.candidate, ["checkout", "--quiet", "--detach", fixture.baseCommit]);
    writeFile(fixture.candidate, entryPath, "untrusted\n");
    const head = commitAll(fixture.candidate, `nearby ${entryPath}`);
    const merge = createMergeCommit(fixture.candidate, fixture.baseCommit, head);
    assert.throws(
      () => classifyPublicIntakePullRequest(classificationInput(fixture, head, merge)),
      hasCode("CHANGED_PATH_NOT_ALLOWED")
    );
  }

  git(fixture.candidate, ["checkout", "--quiet", "--detach", fixture.baseCommit]);
  writeFile(fixture.candidate, "scripts/canary-eligibility-core.mjs", "maintenance\n");
  writeFile(fixture.candidate, "canary-submissions/example/application.json", "{}\n");
  const mixedHead = commitAll(fixture.candidate, "mixed canary and maintenance");
  const mixedMerge = createMergeCommit(fixture.candidate, fixture.baseCommit, mixedHead);
  assert.throws(
    () => classifyPublicIntakePullRequest(classificationInput(fixture, mixedHead, mixedMerge)),
    hasCode("APPLICATION_PATH_INVALID")
  );
});

test("exact Universal Admission maintenance paths are closed while adjacent paths fail", (t) => {
  const exactPaths = [
    ".programmable/universal-admission-contract.v1.json",
    "scripts/benchmark-universal-admission-sqlite.mjs",
    "scripts/universal-admission-command-core.mjs",
    "scripts/universal-admission-contract-core.mjs",
    "scripts/universal-admission-contract.mjs",
    "scripts/universal-admission-core.mjs",
    "scripts/universal-admission-protocol-core.mjs",
    "scripts/universal-admission-service-core.mjs",
    "scripts/universal-admission-sqlite-store.mjs",
    "scripts/universal-admission-sqlite.mjs",
    "scripts/universal-admission.mjs"
  ];
  for (const entryPath of exactPaths) {
    const fixture = createPolicyRepository(t);
    writeFile(fixture.candidate, entryPath, `maintenance fixture for ${entryPath}\n`);
    const head = commitAll(fixture.candidate, `maintain ${entryPath}`);
    const merge = createMergeCommit(fixture.candidate, fixture.baseCommit, head);
    assert.equal(
      classifyPublicIntakePullRequest(classificationInput(fixture, head, merge)).mode,
      "registry-maintenance",
      entryPath
    );
  }

  for (const entryPath of [
    ".programmable/universal-admission-contract.v2.json",
    ".programmable/universal-admission-private.json",
    "scripts/benchmark-universal-admission-private.mjs",
    "scripts/universal-admission-command-helper.mjs",
    "scripts/universal-admission-core-private.mjs",
    "scripts/universal-admission-private.mjs"
  ]) {
    const fixture = createPolicyRepository(t);
    writeFile(fixture.candidate, entryPath, "unreviewed Universal Admission maintenance path\n");
    const head = commitAll(fixture.candidate, `reject ${entryPath}`);
    const merge = createMergeCommit(fixture.candidate, fixture.baseCommit, head);
    assert.throws(
      () => classifyPublicIntakePullRequest(classificationInput(fixture, head, merge)),
      hasCode("CHANGED_PATH_NOT_ALLOWED"),
      entryPath
    );
  }
});

async function createEligibilityFixture(t, { applicationRevision = 1, source = SOURCE } = {}) {
  const repository = createPolicyRepository(t);
  const application = makeApplication(repository.policyBinding, { applicationRevision, source });
  const applicationBytes = jsonBytes(application);
  writeFile(repository.candidate, "canary-submissions/example-hook/application.json", applicationBytes);
  const candidateCommit = commitAll(repository.candidate, "workflow canary");
  const candidateTree = git(repository.candidate, ["rev-parse", `${candidateCommit}^{tree}`]);
  const mergeCommit = createMergeCommit(repository.candidate, repository.baseCommit, candidateCommit);
  const result = await verifyWorkflowCanary({
    baseRoot: repository.base,
    candidateRoot: repository.candidate,
    expectedBaseCommit: repository.baseCommit,
    expectedCandidateCommit: candidateCommit,
    expectedMergeCommit: mergeCommit,
    pullRequestNumber: "7",
    expectedBuilderLogin: "Alice",
    expectedBuilderUserId: "9007199254740993",
    expectedBaseRepository: "programmablehq/Launch-Policy",
    expectedBaseRepositoryId: "1320171831",
    expectedHeadRepository: "alice/submit-launch-fork",
    expectedHeadRepositoryId: "88001"
  }, {
    resolveSource: async () => exactSourceObservation(source)
  });
  const resultBytes = Buffer.from(canonicalWorkflowCanaryResult(result, repository.policyRecord), "utf8");
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  return {
    ...repository,
    application,
    applicationBytes,
    candidateCommit,
    candidateTree,
    mergeCommit,
    privateKey,
    publicKey,
    result,
    resultBytes
  };
}

function createPolicyRepository(t) {
  const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), "canary-eligibility-"));
  t.after(() => fs.rmSync(fixtureRoot, { recursive: true, force: true }));
  const base = path.join(fixtureRoot, "base");
  const candidate = path.join(fixtureRoot, "candidate");
  fs.mkdirSync(base);
  git(base, ["init", "--initial-branch=main"]);
  git(base, ["remote", "add", "origin", "https://github.com/0xprogrammable/launch-policy.git"]);
  writeFile(base, "policy/launch-policy.v1.json", fs.readFileSync(path.join(root, "policy/launch-policy.v1.json")));
  writeFile(base, "README.md", "trusted base\n");
  const baseCommit = commitAll(base, "trusted base");
  const baseTree = git(base, ["rev-parse", `${baseCommit}^{tree}`]);
  const policyRecord = readTrustedLaunchPolicyFromGit({ repositoryRoot: base, expectedBaseCommit: baseCommit });
  const policyBinding = structuredClone(buildLaunchPolicyBinding(policyRecord, "workflow-canary"));
  git(fixtureRoot, ["clone", "--quiet", base, candidate]);
  return { base, baseCommit, baseTree, candidate, fixtureRoot, policyBinding, policyRecord };
}

function makeApplication(policyBinding, { applicationRevision = 1, source = SOURCE } = {}) {
  return {
    schemaVersion: "programmable.workflow-canary-application.v1",
    applicationId: "example-hook",
    applicationRevision,
    builder: { githubLogin: "Alice", githubUserId: "9007199254740993" },
    source: structuredClone(source),
    expectedPolicyBinding: structuredClone(policyBinding),
    title: "Example Hook",
    summary: "A hidden workflow-only canary.",
    declarations: {
      hiddenFromPublicRoutingAndDiscovery: true,
      independentAudit: false,
      productionRouting: false,
      realUserFunds: false
    }
  };
}

function makeCommand(fixture, overrides = {}) {
  return {
    schemaVersion: CANARY_ELIGIBILITY_COMMAND_VERSION,
    action: "issue-hidden-canary-eligibility",
    audience: overrides.audience ?? STAGING_AUDIENCE,
    issuedAt: overrides.issuedAt ?? "2026-08-13T10:00:00.000Z",
    issuedBy: {
      githubLogin: "programmable-maintainer",
      githubUserId: "1000001",
      mode: "human-review"
    },
    validUntil: overrides.validUntil ?? "2026-08-13T10:10:00.000Z",
    application: structuredClone(fixture.result.application),
    pullRequest: structuredClone(fixture.result.pullRequest),
    source: structuredClone(fixture.result.source),
    policyBinding: structuredClone(fixture.result.policyBinding),
    workflowCanaryResult: {
      schemaVersion: fixture.result.schemaVersion,
      profileId: fixture.result.profileId,
      status: fixture.result.status,
      result: fixture.result.result,
      outcome: fixture.result.outcome,
      digest: fixture.result.digest,
      reviewDecisionDigest: fixture.result.reviewDecisionDigest,
      byteLength: fixture.resultBytes.length,
      sha256: sha256(fixture.resultBytes)
    },
    eligibility: {
      surface: "hidden-canary",
      publicDiscovery: false,
      productionRouting: false,
      realFunds: false,
      launchAuthorized: false
    },
    supersedes: null
  };
}

function signFixtureCommand(fixture, command) {
  return signCommand(command, fixture.privateKey, fixture.publicKey);
}

function signCommand(command, privateKey, publicKey) {
  return {
    schemaVersion: SIGNED_CANARY_ELIGIBILITY_COMMAND_VERSION,
    authorization: {
      algorithm: "ed25519",
      keyId: canaryEligibilityAuthorityKeyId(publicKey),
      signature: crypto.sign(null, canaryEligibilitySigningBytes(command), privateKey).toString("base64url")
    },
    command
  };
}

function compileFixture(fixture, overrides = {}) {
  return compileCanaryEligibilityEnvelope({
    signedCommand: overrides.signedCommand ?? signFixtureCommand(fixture, makeCommand(fixture)),
    decisionBytes: overrides.decisionBytes ?? fixture.resultBytes,
    applicationBytes: overrides.applicationBytes ?? fixture.applicationBytes,
    trustedAuthorityPublicKey: overrides.trustedAuthorityPublicKey ?? fixture.publicKey,
    trustedPolicyRecord: overrides.trustedPolicyRecord ?? fixture.policyRecord,
    now: overrides.now ?? NOW
  });
}

function verifyWebsite(fixture, envelope, now = NOW, expectedAudience = STAGING_AUDIENCE) {
  return verifyWebsiteCanaryEligibility({
    envelope,
    trustedAuthorityPublicKey: fixture.publicKey,
    trustedPolicyRecord: fixture.policyRecord,
    expectedAudience,
    expectedPolicyBinding: fixture.policyBinding,
    now
  });
}

function exactSourceObservation(source = SOURCE) {
  return {
    schemaVersion: "1.0.0",
    kind: "github-public-source",
    canonicalProviderOrigin: "https://github.com",
    githubApiVersion: "2026-03-10",
    primary: {
      role: "primary",
      authority: {
        numericRepositoryId: source.numericRepositoryId,
        revisionObjectId: source.commit,
        treeObjectId: source.tree
      },
      display: {
        repositoryUri: `https://github.com/${source.repository}`,
        owner: "alice",
        repository: "example-hook",
        defaultBranch: "main"
      },
      visibility: "public",
      sourcePaths: [],
      contractPaths: [],
      githubActionsEvidence: []
    },
    companions: []
  };
}

function makeLegacyCommand() {
  return {
    acceptedAt: "2026-08-13T10:00:00.000Z",
    acceptedBy: { githubLogin: "a", githubUserId: "1", mode: "human-review" },
    action: "issue-launch-entitlement",
    application: {
      applicationId: "x", applicationRevision: 1, builderGitHubUserId: "1",
      packageContract: "public-pr-application-v2-six-file-v1", packageDigest: `sha256:${"1".repeat(64)}`
    },
    entitlement: {
      chainId: 1, claimPrincipalPolicy: "application-builder-github-user-v1", launchCount: 1,
      permitPolicy: "jit-single-use-v1", repositoryKeyPolicy: "numeric-github-repository-v1"
    },
    launchPlan: {
      byteLength: 2, gitBlobOid: "1".repeat(40), path: "launch.json", repositoryRole: "primary",
      sha256: `sha256:${"2".repeat(64)}`
    },
    pullRequest: {
      authorGitHubUserId: "1", baseCommitOid: "1".repeat(40), baseRepository: "0xprogrammable/launch-policy",
      baseRepositoryId: "1320171831", baseTreeOid: "2".repeat(40), headCommitOid: "3".repeat(40),
      headRepositoryId: "2", headTreeOid: "4".repeat(40), number: 1
    },
    review: {
      decision: "accepted", finalVerificationDigest: `sha256:${"3".repeat(64)}`,
      policyBundleDigest: `sha256:${"4".repeat(64)}`, reviewEvidenceDigest: `sha256:${"5".repeat(64)}`,
      supersedes: null
    },
    schemaVersion: "programmable.protected-acceptance-command.v1",
    source: {
      companions: [], primary: {
        numericRepositoryId: "3", repositoryUri: "https://github.com/a/b", revisionObjectId: "5".repeat(40), treeObjectId: "6".repeat(40)
      }, schemaVersion: "1.0.0"
    },
    validUntil: "2026-08-13T10:10:00.000Z"
  };
}

function classificationInput(fixture, expectedCandidateCommit, expectedMergeCommit) {
  return {
    baseRoot: fixture.base,
    candidateRoot: fixture.candidate,
    expectedBaseCommit: fixture.baseCommit,
    expectedCandidateCommit,
    expectedMergeCommit
  };
}

function createMergeCommit(repositoryRoot, baseCommit, candidateCommit) {
  git(repositoryRoot, ["checkout", "--quiet", "--detach", baseCommit]);
  git(repositoryRoot, ["merge", "--quiet", "--no-ff", "--no-commit", candidateCommit]);
  git(repositoryRoot, ["commit", "--quiet", "-m", "GitHub pull request merge"]);
  return git(repositoryRoot, ["rev-parse", "HEAD^{commit}"]);
}

function commitAll(repositoryRoot, message) {
  git(repositoryRoot, ["add", "-A"]);
  git(repositoryRoot, ["commit", "--quiet", "-m", message]);
  return git(repositoryRoot, ["rev-parse", "HEAD^{commit}"]);
}

function git(repositoryRoot, args) {
  return childProcess.execFileSync("git", args, {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      GIT_AUTHOR_EMAIL: "canary-eligibility@example.invalid",
      GIT_AUTHOR_NAME: "Canary Eligibility",
      GIT_COMMITTER_EMAIL: "canary-eligibility@example.invalid",
      GIT_COMMITTER_NAME: "Canary Eligibility"
    }
  }).trim();
}

function writeFile(repositoryRoot, relativePath, contents) {
  const target = path.join(repositoryRoot, relativePath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, contents);
}

function replaceWithFile(target, bytes, mode) {
  const replacement = `${target}.replacement`;
  fs.writeFileSync(replacement, bytes, { mode });
  fs.chmodSync(replacement, mode);
  fs.renameSync(replacement, target);
}

function jsonBytes(value) {
  return Buffer.from(`${canonicalJson(value)}\n`, "utf8");
}

function sha256(bytes) {
  return `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
}

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(root, relativePath), "utf8"));
}

function hasCode(code) {
  return (error) => error?.code === code;
}
