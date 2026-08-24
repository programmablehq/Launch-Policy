import assert from "node:assert/strict";
import childProcess from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import Ajv2020 from "../scripts/test/schema-validator/node_modules/ajv/dist/2020.js";
import addFormats from "../scripts/test/schema-validator/node_modules/ajv-formats/dist/index.js";

import { canonicalJson, readTrustedLaunchPolicyFromGit } from "../scripts/launch-policy-core.mjs";
import {
  ACCEPTANCE_COMMAND_VERSION,
  acceptanceCommandSigningBytes,
  authorityKeyId,
  compileLaunchEntitlementEnvelope,
  inspectSixFileApplicationPackage,
  LaunchEntitlementError,
  SIGNED_ACCEPTANCE_COMMAND_VERSION
} from "../scripts/acceptance-entitlement-core.mjs";
import {
  createHistoricalLegacyV2PolicyAdapterForLocalInspection
} from "../scripts/verify-public-hook-application-core.mjs";
import {
  FIXTURE_BUILDER_USER_ID,
  makeAcceptancePackageFixture
} from "./helpers/acceptance-package-fixture.mjs";

const root = path.resolve(import.meta.dirname, "..");
const NOW = new Date("2026-08-13T10:05:00.000Z");

test("legacy command and envelope schemas remain strict historical contracts", () => {
  const commandSchema = readJson("acceptance/schemas/protected-acceptance-command-v1.schema.json");
  const envelopeSchema = readJson("acceptance/schemas/launch-entitlement-envelope-v1.schema.json");
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv, { mode: "full" });
  ajv.addSchema(commandSchema);
  assert.doesNotThrow(() => ajv.compile(envelopeSchema));
});

test("historical six-file package inspection remains explicit and non-authoritative", (t) => {
  const fixture = createFixture(t);
  const inspection = inspectSixFileApplicationPackage({
    packageDirectory: fixture.packageDirectory,
    legacyPolicyAdapter: fixture.legacyPolicyAdapter
  });
  assert.equal(inspection.binding.contract, "public-pr-application-v2-six-file-v1");
  assert.equal(inspection.binding.fileCount, 6);
  assert.equal(inspection.application.applicationId, fixture.data.application.applicationId);
});

test("current trusted v1 policy disables production before package or launch-plan I/O", (t) => {
  const fixture = createFixture(t);
  const signedCommand = signFixtureCommand(fixture, makeCommand(fixture));
  assert.throws(
    () => compileLaunchEntitlementEnvelope({
      signedCommand,
      packageDirectory: path.join(fixture.root, "does-not-exist"),
      launchPlanFile: path.join(fixture.root, "also-does-not-exist.json"),
      trustedAuthorityPublicKey: fixture.publicKey,
      trustedPolicyRecord: fixture.policyRecord,
      now: NOW
    }),
    hasCode("PRODUCTION_LAUNCH_DISABLED")
  );
});

test("opaque policyBundleDigest cannot enable production and copied policy records are rejected", (t) => {
  const fixture = createFixture(t);
  const command = makeCommand(fixture);
  command.review.policyBundleDigest = `sha256:${"f".repeat(64)}`;
  assert.throws(
    () => compileFixture(fixture, { signedCommand: signFixtureCommand(fixture, command) }),
    hasCode("PRODUCTION_LAUNCH_DISABLED")
  );
  assert.throws(
    () => compileFixture(fixture, { trustedPolicyRecord: { ...fixture.policyRecord } }),
    hasCode("PRODUCTION_POLICY_TRUST_INVALID")
  );
});

test("legacy signature key and time validation still fail before the disabled production gate", (t) => {
  const fixture = createFixture(t);
  const attacker = crypto.generateKeyPairSync("ed25519");
  assert.throws(
    () => compileFixture(fixture, {
      signedCommand: signCommand(makeCommand(fixture), attacker.privateKey, attacker.publicKey)
    }),
    hasCode("AUTHORITY_KEY_MISMATCH")
  );

  const tampered = signFixtureCommand(fixture, makeCommand(fixture));
  tampered.command.pullRequest.headCommitOid = "f".repeat(40);
  assert.throws(() => compileFixture(fixture, { signedCommand: tampered }), hasCode("SIGNATURE_INVALID"));

  const expired = makeCommand(fixture, {
    acceptedAt: "2026-08-13T09:40:00.000Z",
    validUntil: "2026-08-13T09:50:00.000Z"
  });
  assert.throws(
    () => compileFixture(fixture, { signedCommand: signFixtureCommand(fixture, expired) }),
    hasCode("COMMAND_NOT_CURRENT")
  );

  const excessive = makeCommand(fixture, {
    acceptedAt: "2026-08-13T10:00:00.000Z",
    validUntil: "2026-08-13T10:15:00.001Z"
  });
  assert.throws(
    () => compileFixture(fixture, { signedCommand: signFixtureCommand(fixture, excessive) }),
    hasCode("COMMAND_LIFETIME_INVALID")
  );
});

test("legacy protected CLI loads only fixed protected policy identity and exits disabled before source I/O", (t) => {
  const fixture = createFixture(t);
  const clock = new Date();
  const command = makeCommand(fixture, {
    acceptedAt: new Date(clock.getTime() - 60_000).toISOString(),
    validUntil: new Date(clock.getTime() + 10 * 60_000).toISOString()
  });
  const commandFile = path.join(fixture.root, "signed-command.json");
  const keyFile = path.join(fixture.root, "trusted-public-key.pem");
  fs.writeFileSync(commandFile, `${canonicalJson(signFixtureCommand(fixture, command))}\n`, { mode: 0o600 });
  fs.writeFileSync(keyFile, fixture.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o600 });
  const result = childProcess.spawnSync(process.execPath, [
    path.resolve("scripts/compile-launch-entitlement.mjs"),
    "--signed-command", commandFile,
    "--package-directory", path.join(fixture.root, "missing-package"),
    "--launch-plan-file", path.join(fixture.root, "missing-plan.json"),
    "--trusted-authority-public-key", keyFile,
    "--trusted-policy-repository-root", fixture.policyRepository,
    "--expected-policy-base-commit", fixture.policyBaseCommit
  ], { encoding: "utf8", shell: false, env: { ...process.env, TZ: "UTC" } });
  assert.equal(result.status, 1);
  assert.deepEqual(JSON.parse(result.stderr), {
    code: "PRODUCTION_LAUNCH_DISABLED",
    error: "The current central launch policy keeps production launch disabled.",
    status: "rejected"
  });
  assert.equal(result.stdout, "");
});

function createFixture(t) {
  const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), "submit-launch-entitlement-disabled-"));
  t.after(() => fs.rmSync(fixtureRoot, { recursive: true, force: true }));
  const data = makeAcceptancePackageFixture();
  const packageDirectory = path.join(fixtureRoot, data.application.applicationId);
  fs.mkdirSync(packageDirectory);
  for (const [fileName, bytes] of data.files) fs.writeFileSync(path.join(packageDirectory, fileName), bytes);
  const launchPlanFile = path.join(fixtureRoot, "launch-plan.json");
  fs.writeFileSync(launchPlanFile, data.launchPlanBytes);
  const legacyPolicyAdapter = createHistoricalLegacyV2PolicyAdapterForLocalInspection({
    policyBytes: fs.readFileSync(path.join(root, "policy/launch-policy.v1.json"))
  });
  const inspection = inspectSixFileApplicationPackage({ packageDirectory, legacyPolicyAdapter });
  const policyRepository = path.join(fixtureRoot, "policy-repository");
  fs.mkdirSync(policyRepository);
  git(policyRepository, ["init", "--initial-branch=main"]);
  git(policyRepository, ["remote", "add", "origin", "https://github.com/0xprogrammable/launch-policy.git"]);
  writeFile(policyRepository, "policy/launch-policy.v1.json", fs.readFileSync(path.join(root, "policy/launch-policy.v1.json")));
  writeFile(policyRepository, "README.md", "trusted policy base\n");
  const policyBaseCommit = commitAll(policyRepository, "trusted policy base");
  const policyRecord = readTrustedLaunchPolicyFromGit({ repositoryRoot: policyRepository, expectedBaseCommit: policyBaseCommit });
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  return {
    data,
    fixtureRoot,
    inspection,
    launchPlanFile,
    legacyPolicyAdapter,
    packageDirectory,
    policyBaseCommit,
    policyRecord,
    policyRepository,
    privateKey,
    publicKey,
    root: fixtureRoot
  };
}

function makeCommand(fixture, overrides = {}) {
  const planBytes = fixture.data.launchPlanBytes;
  return {
    acceptedAt: overrides.acceptedAt ?? "2026-08-13T10:00:00.000Z",
    acceptedBy: { githubLogin: "programmable-maintainer", githubUserId: "1000001", mode: "human-review" },
    action: "issue-launch-entitlement",
    application: {
      applicationId: fixture.data.application.applicationId,
      applicationRevision: fixture.data.application.applicationRevision,
      builderGitHubUserId: FIXTURE_BUILDER_USER_ID,
      packageContract: "public-pr-application-v2-six-file-v1",
      packageDigest: fixture.inspection.binding.digest
    },
    entitlement: {
      chainId: 1,
      claimPrincipalPolicy: "application-builder-github-user-v1",
      launchCount: 1,
      permitPolicy: "jit-single-use-v1",
      repositoryKeyPolicy: "numeric-github-repository-v1"
    },
    launchPlan: {
      byteLength: planBytes.length,
      gitBlobOid: gitBlobOid(planBytes),
      path: fixture.data.launchPlanPath,
      repositoryRole: "primary",
      sha256: sha256(planBytes)
    },
    pullRequest: {
      authorGitHubUserId: FIXTURE_BUILDER_USER_ID,
      baseCommitOid: "1".repeat(40),
      baseRepository: "0xprogrammable/launch-policy",
      baseRepositoryId: "1320171831",
      baseTreeOid: "2".repeat(40),
      headCommitOid: "3".repeat(40),
      headRepositoryId: "987654321",
      headTreeOid: "4".repeat(40),
      number: 12
    },
    review: {
      decision: "accepted",
      finalVerificationDigest: `sha256:${"5".repeat(64)}`,
      policyBundleDigest: `sha256:${"6".repeat(64)}`,
      reviewEvidenceDigest: `sha256:${"7".repeat(64)}`,
      supersedes: null
    },
    schemaVersion: ACCEPTANCE_COMMAND_VERSION,
    source: {
      companions: [],
      primary: {
        numericRepositoryId: fixture.data.primary.numericRepositoryId,
        repositoryUri: fixture.data.primary.repositoryUri,
        revisionObjectId: fixture.data.primary.revisionObjectId,
        treeObjectId: fixture.data.primary.treeObjectId
      },
      schemaVersion: "1.0.0"
    },
    validUntil: overrides.validUntil ?? "2026-08-13T10:10:00.000Z"
  };
}

function signFixtureCommand(fixture, command) {
  return signCommand(command, fixture.privateKey, fixture.publicKey);
}

function signCommand(command, privateKey, publicKey) {
  return {
    authorization: {
      algorithm: "ed25519",
      keyId: authorityKeyId(publicKey),
      signature: crypto.sign(null, acceptanceCommandSigningBytes(command), privateKey).toString("base64url")
    },
    command,
    schemaVersion: SIGNED_ACCEPTANCE_COMMAND_VERSION
  };
}

function compileFixture(fixture, overrides = {}) {
  return compileLaunchEntitlementEnvelope({
    signedCommand: overrides.signedCommand ?? signFixtureCommand(fixture, makeCommand(fixture)),
    packageDirectory: overrides.packageDirectory ?? fixture.packageDirectory,
    launchPlanFile: overrides.launchPlanFile ?? fixture.launchPlanFile,
    trustedAuthorityPublicKey: overrides.trustedAuthorityPublicKey ?? fixture.publicKey,
    trustedPolicyRecord: overrides.trustedPolicyRecord ?? fixture.policyRecord,
    now: overrides.now ?? NOW
  });
}

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(root, relativePath), "utf8"));
}

function sha256(bytes) {
  return `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
}

function gitBlobOid(bytes) {
  return crypto.createHash("sha1")
    .update(Buffer.from(`blob ${bytes.length}\0`, "utf8"))
    .update(bytes)
    .digest("hex");
}

function writeFile(repositoryRoot, relativePath, contents) {
  const target = path.join(repositoryRoot, relativePath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, contents);
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
      GIT_AUTHOR_EMAIL: "acceptance-disabled@example.invalid",
      GIT_AUTHOR_NAME: "Acceptance Disabled",
      GIT_COMMITTER_EMAIL: "acceptance-disabled@example.invalid",
      GIT_COMMITTER_NAME: "Acceptance Disabled"
    }
  }).trim();
}

function hasCode(code) {
  return (error) => error instanceof LaunchEntitlementError && error.code === code;
}
