import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import Ajv2020 from "../scripts/test/schema-validator/node_modules/ajv/dist/2020.js";

import {
  APPLICANT_COMPATIBILITY_PATH,
  APPLICANT_COMPATIBILITY_V2_PATH,
  APPLICANT_VALIDATOR_RECEIPT_PATH,
  ApplicantCompatibilityError,
  buildApplicantCompatibilityContractV2,
  canonicalApplicantJson,
  parseApplicantCompatibilityBytesV1,
  parseApplicantCompatibilityBytesV2,
  verifyApplicantCompatibilityContract,
  verifyApplicantCompatibilityReadback,
  verifyApplicantCompatibilityReadbackV1,
  verifyApplicantCompatibilityReadbackV2
} from "../scripts/applicant-compatibility-core.mjs";

const repositoryRoot = path.resolve(import.meta.dirname, "..");

test("Applicant Compatibility V2 is a deterministic projection of its bound contracts", () => {
  const generated = `${canonicalApplicantJson(buildApplicantCompatibilityContractV2({ repositoryRoot }))}\n`;
  assert.equal(fs.readFileSync(path.join(repositoryRoot, APPLICANT_COMPATIBILITY_V2_PATH), "utf8"), generated);
});

test("published compatibility and compact receipt schemas accept only the closed contracts", (t) => {
  const fixture = createCompactFixture(t);
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  const validateCompatibility = ajv.compile(readJson(repositoryRoot, "intake/schemas/applicant-compatibility-v1.schema.json"));
  const validateReceipt = ajv.compile(readJson(repositoryRoot, "intake/schemas/applicant-validator-package-receipt-v1.schema.json"));
  const compatibility = readJson(fixture.root, APPLICANT_COMPATIBILITY_PATH);
  const receipt = readJson(fixture.root, APPLICANT_VALIDATOR_RECEIPT_PATH);
  assert.equal(validateCompatibility(compatibility), true, JSON.stringify(validateCompatibility.errors));
  assert.equal(validateReceipt(receipt), true, JSON.stringify(validateReceipt.errors));
  compatibility.approvalAuthorized = true;
  receipt.files[0].command = "npm test";
  assert.equal(validateCompatibility(compatibility), false);
  assert.equal(validateReceipt(receipt), false);
});

test("Applicant Compatibility V2 binds current V3.2 and immutable legacy V3.1 without authority", (t) => {
  const fixture = createV2Fixture(t);
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  const validate = ajv.compile(readJson(repositoryRoot, "intake/schemas/applicant-compatibility-v2.schema.json"));
  const compatibility = readJson(fixture.root, APPLICANT_COMPATIBILITY_V2_PATH);
  assert.equal(validate(compatibility), true, JSON.stringify(validate.errors));
  assert.equal(compatibility.application.current.contractId, "public-pr-application-v3.2");
  assert.equal(compatibility.application.legacy[0].contractId, "public-pr-application-v3.1");
  assert.equal(compatibility.capabilities.launchReadiness, "offline-check-only");
  for (const value of Object.values(compatibility.authority)) assert.equal(value, false);

  const result = verifyApplicantCompatibilityContract({ allowLegacyFallback: false, repositoryRoot: fixture.root });
  assert.equal(result.mode, "declared-readiness-contract-v2");
  assert.equal(result.compatibility.supportingContracts.routerReadiness.schema.contractId, "programmable-launch-router-readiness-v1");
});

test("V2 is preferred for a current protected base and its exact-base readback remains draft/readiness only", (t) => {
  const fixture = createV2Fixture(t);
  const selected = verifyApplicantCompatibilityContract({ allowLegacyFallback: true, repositoryRoot: fixture.root });
  assert.equal(selected.mode, "declared-readiness-contract-v2");
  const options = {
    builderProtocolVersion: "1.0.0",
    bytes: fs.readFileSync(path.join(fixture.root, APPLICANT_COMPATIBILITY_V2_PATH)),
    exactBaseCommit: "c".repeat(40),
    expectedDefaultBranch: "main",
    expectedRepositoryNumericId: "1320171831",
    requiredCapabilities: ["draft-transport:create", "launch-readiness:offline-check", "unreviewed-draft-only"]
  };
  const v2 = verifyApplicantCompatibilityReadbackV2(options);
  const generic = verifyApplicantCompatibilityReadback(options);
  assert.equal(v2.result, "compatible-protected-applicant-readiness-contract-v2");
  assert.deepEqual(generic, v2);
  assert.throws(
    () => verifyApplicantCompatibilityReadbackV2({ ...options, requiredCapabilities: ["launch:submit"] }),
    hasCode("APPLICANT_COMPATIBILITY_V2_CAPABILITY_UNSUPPORTED")
  );
});

test("V2 fails closed on protected artifact substitution, stale digest, and added authority", (t) => {
  const fixture = createV2Fixture(t);
  fs.appendFileSync(path.join(fixture.root, "intake/schemas/open-world-submission-v2.1.schema.json"), " ");
  assert.throws(
    () => verifyApplicantCompatibilityContract({ allowLegacyFallback: false, repositoryRoot: fixture.root }),
    hasCode("APPLICANT_COMPATIBILITY_V2_SUBMISSION_SCHEMA_MISMATCH")
  );

  const manifestPath = path.join(fixture.root, APPLICANT_COMPATIBILITY_V2_PATH);
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  manifest.authority.launchAuthorized = true;
  assert.throws(
    () => parseApplicantCompatibilityBytesV2(Buffer.from(`${canonicalApplicantJson(manifest)}\n`)),
    hasCode("APPLICANT_COMPATIBILITY_V2_AUTHORITY_INVALID")
  );
  const closureFixture = createV2Fixture(t);
  const closureManifestPath = path.join(closureFixture.root, APPLICANT_COMPATIBILITY_V2_PATH);
  const closureManifest = JSON.parse(fs.readFileSync(closureManifestPath, "utf8"));
  closureManifest.supportingContracts.routerReadiness.validatorClosure.files[0].sha256 = `sha256:${"0".repeat(64)}`;
  fs.writeFileSync(closureManifestPath, `${canonicalApplicantJson(closureManifest)}\n`);
  assert.throws(
    () => verifyApplicantCompatibilityContract({ allowLegacyFallback: false, repositoryRoot: closureFixture.root }),
    hasCode("APPLICANT_COMPATIBILITY_V2_ROUTER_VALIDATOR_FILE_MISMATCH")
  );
});

test("published V1 bytes remain the exact V3.1 compatibility contract", () => {
  const bytes = fs.readFileSync(path.join(repositoryRoot, APPLICANT_COMPATIBILITY_PATH));
  assert.equal(digest(bytes), "sha256:4242db08c54c6a3ef698cfc34634fb7f21c0e1f6cce7a91e5dd472087db31d0d");
  assert.equal(parseApplicantCompatibilityBytesV1(bytes).compatibility.application.contractId, "public-pr-application-v3.1");
});

test("a closed compact package produces an exact compatible base readback without executing package code", (t) => {
  const fixture = createCompactFixture(t);
  const result = verifyApplicantCompatibilityContract({
    allowLegacyFallback: false,
    repositoryRoot: fixture.root
  });

  assert.equal(result.mode, "declared-compact-validator-v1");
  assert.equal(result.validatorPackage.closureSha256, fixture.closureSha256);
  assert.equal(result.validatorPackage.fileCount, 3);
  assert.equal(result.validatorPackage.authority.candidateCodeExecuted, false);
  assert.equal(fs.existsSync(fixture.executionMarker), false);

  const readback = verifyApplicantCompatibilityReadbackV1({
    builderProtocolVersion: "1.0.0",
    bytes: fs.readFileSync(path.join(fixture.root, APPLICANT_COMPATIBILITY_PATH)),
    exactBaseCommit: "a".repeat(40),
    expectedDefaultBranch: "main",
    expectedRepositoryNumericId: "1320171831",
    requiredCapabilities: [
      "draft-transport:create",
      "source-closure:manifest",
      "missing-object-recovery",
      "unreviewed-draft-only"
    ]
  });
  assert.equal(readback.result, "compatible-protected-applicant-contract");
  assert.equal(readback.exactBaseCommit, "a".repeat(40));
  assert.equal(readback.validatorPackage.closureSha256, fixture.closureSha256);
  assert.deepEqual(verifyApplicantCompatibilityReadback({
    builderProtocolVersion: "1.0.0",
    bytes: fs.readFileSync(path.join(fixture.root, APPLICANT_COMPATIBILITY_PATH)),
    exactBaseCommit: "a".repeat(40),
    expectedDefaultBranch: "main",
    expectedRepositoryNumericId: "1320171831",
    requiredCapabilities: ["draft-transport:create"]
  }).application, readback.application);
});

test("compact package substitution fails before any package module is executed", (t) => {
  const fixture = createCompactFixture(t);
  fs.writeFileSync(
    path.join(fixture.root, "vendor/programmable-applicant-validator/scripts/support.mjs"),
    "export const closed = false;\n"
  );

  assert.throws(
    () => verifyApplicantCompatibilityContract({ allowLegacyFallback: false, repositoryRoot: fixture.root }),
    hasCode("APPLICANT_VALIDATOR_PACKAGE_FILE_SIZE_MISMATCH")
  );
  assert.equal(fs.existsSync(fixture.executionMarker), false);
});

test("unknown capabilities and an old Builder protocol fail closed", (t) => {
  const fixture = createCompactFixture(t);
  const bytes = fs.readFileSync(path.join(fixture.root, APPLICANT_COMPATIBILITY_PATH));
  const baseOptions = {
    builderProtocolVersion: "1.0.0",
    bytes,
    exactBaseCommit: "b".repeat(40),
    expectedDefaultBranch: "main",
    expectedRepositoryNumericId: "1320171831",
    requiredCapabilities: []
  };

  assert.throws(
    () => verifyApplicantCompatibilityReadbackV1({
      ...baseOptions,
      requiredCapabilities: ["review:auto-approve"]
    }),
    hasCode("APPLICANT_COMPATIBILITY_CAPABILITY_UNSUPPORTED")
  );
  assert.throws(
    () => verifyApplicantCompatibilityReadbackV1({
      ...baseOptions,
      builderProtocolVersion: "0.9.9"
    }),
    hasCode("APPLICANT_COMPATIBILITY_PROTOCOL_UNSUPPORTED")
  );
});

test("compatibility and receipt contracts reject extra authority or substitution fields", (t) => {
  const fixture = createCompactFixture(t);
  const manifestPath = path.join(fixture.root, APPLICANT_COMPATIBILITY_PATH);
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  manifest.reviewAuthorized = true;
  const bytes = Buffer.from(`${canonicalApplicantJson(manifest)}\n`);
  assert.throws(
    () => parseApplicantCompatibilityBytesV1(bytes),
    hasCode("APPLICANT_COMPATIBILITY_INVALID")
  );

  const receiptPath = path.join(fixture.root, APPLICANT_VALIDATOR_RECEIPT_PATH);
  const receipt = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
  receipt.authority.networkAccessed = true;
  fs.writeFileSync(receiptPath, `${canonicalApplicantJson(receipt)}\n`);
  assert.throws(
    () => verifyApplicantCompatibilityContract({ allowLegacyFallback: false, repositoryRoot: fixture.root }),
    hasCode("APPLICANT_VALIDATOR_RECEIPT_AUTHORITY_INVALID")
  );
});

test("released v1.6.3 remains the only compatibility-less full-vendor fallback", (t) => {
  const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), "applicant-compat-legacy-"));
  t.after(() => fs.rmSync(fixtureRoot, { recursive: true, force: true }));
  for (const relativePath of [
    "intake/schemas/public-pr-application-v3.schema.json",
    "vendor/receipt.json"
  ]) copyFixtureFile(repositoryRoot, fixtureRoot, relativePath);
  copyFixtureFile(repositoryRoot, fixtureRoot, "test/fixtures/submit-launch-v1.6.3-active-contract.json", ".programmable/active-contract.json");

  const result = verifyApplicantCompatibilityContract({
    allowLegacyFallback: true,
    repositoryRoot: fixtureRoot
  });
  assert.equal(result.mode, "legacy-full-vendor-v0.10.3");
  assert.equal(result.builder.release, "v0.10.3");
  assert.equal(result.applicationSchemaSha256, "sha256:2d51837bbbfe52672ecca334596243bebcec78e8e0a885d67084dfd98955bcb7");

  fs.appendFileSync(path.join(fixtureRoot, "intake/schemas/public-pr-application-v3.schema.json"), " ");
  assert.throws(
    () => verifyApplicantCompatibilityContract({ allowLegacyFallback: true, repositoryRoot: fixtureRoot }),
    hasCode("APPLICANT_COMPATIBILITY_LEGACY_SCHEMA_MISMATCH")
  );
});

test("a missing declaration cannot silently select legacy fallback when it is disabled", (t) => {
  const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), "applicant-compat-required-"));
  t.after(() => fs.rmSync(fixtureRoot, { recursive: true, force: true }));
  assert.throws(
    () => verifyApplicantCompatibilityContract({ allowLegacyFallback: false, repositoryRoot: fixtureRoot }),
    hasCode("APPLICANT_COMPATIBILITY_MISSING")
  );
});

function createCompactFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "applicant-compat-compact-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const executionMarker = path.join(root, "package-code-executed");
  const packageFiles = new Map([
    [
      "data/application-contract.json",
      Buffer.from("{\"contractId\":\"public-pr-application-v3.1\"}\n")
    ],
    [
      "scripts/public-applicant-validator.mjs",
      Buffer.from(`import fs from "node:fs";\nfs.writeFileSync(${JSON.stringify(executionMarker)}, "executed");\n`)
    ],
    [
      "scripts/support.mjs",
      Buffer.from("export const closed = true;\n")
    ]
  ]);
  const records = [...packageFiles].map(([relativePath, bytes]) => ({
    byteLength: bytes.byteLength,
    path: relativePath,
    role: relativePath === "scripts/public-applicant-validator.mjs"
      ? "entrypoint"
      : relativePath.endsWith(".mjs") ? "module" : "data",
    sha256: digest(bytes)
  })).sort((left, right) => compareUtf8(left.path, right.path));
  const closureSha256 = closureDigest(records, packageFiles);
  const totalBytes = records.reduce((sum, record) => sum + record.byteLength, 0);
  for (const [relativePath, bytes] of packageFiles) {
    writeFile(root, `vendor/programmable-applicant-validator/${relativePath}`, bytes);
  }
  const receipt = {
    $schema: "urn:programmable:applicant-validator-package-receipt:1.0.0",
    algorithm: "sha256-path-nul-size-nul-content-nul-v1",
    authority: {
      candidateCodeExecuted: false,
      credentialsUsed: false,
      externalWritesPerformed: false,
      networkAccessed: false
    },
    closureSha256,
    entrypoint: "scripts/public-applicant-validator.mjs",
    fileCount: records.length,
    files: records,
    kind: "programmable-applicant-validator-package-receipt",
    schemaVersion: "1.0.0",
    totalBytes
  };
  writeFile(root, APPLICANT_VALIDATOR_RECEIPT_PATH, Buffer.from(`${canonicalApplicantJson(receipt)}\n`));

  const applicationSchemaBytes = Buffer.from("{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\",\"type\":\"object\"}\n");
  writeFile(root, "intake/schemas/public-pr-application-v3.schema.json", applicationSchemaBytes);
  const compatibility = {
    $schema: "urn:programmable:applicant-compatibility:1.0.0",
    application: {
      contractId: "public-pr-application-v3.1",
      schemaPath: "intake/schemas/public-pr-application-v3.schema.json",
      schemaSha256: digest(applicationSchemaBytes)
    },
    capabilities: {
      draftTransportOperations: ["create", "update"],
      missingObjectRecovery: true,
      sourceClosureModes: ["inline", "manifest"],
      unreviewedDraftOnly: true
    },
    kind: "programmable-applicant-compatibility",
    minimumBuilderProtocolVersion: "1.0.0",
    schemaVersion: "1.0.0",
    trustedRepository: {
      defaultBranch: "main",
      numericId: "1320171831"
    },
    validatorPackage: {
      closureSha256,
      entrypointPath: "vendor/programmable-applicant-validator/scripts/public-applicant-validator.mjs",
      receiptPath: "vendor/programmable-applicant-validator/validator-package-receipt.v1.json",
      rootPath: "vendor/programmable-applicant-validator"
    }
  };
  writeFile(root, APPLICANT_COMPATIBILITY_PATH, Buffer.from(`${canonicalApplicantJson(compatibility)}\n`));
  return { closureSha256, executionMarker, root };
}

function createV2Fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "applicant-compat-v2-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const relativePath of [
    "intake/schemas/open-world-submission-v2.1.schema.json",
    "intake/schemas/programmable-launch-router-readiness-v1.schema.json",
    "intake/schemas/public-pr-application-v3.schema.json",
    "intake/schemas/public-pr-application-v3.2.schema.json",
    "intake/schemas/trade-capability-manifest-v2.schema.json",
    "scripts/programmable-launch-router-readiness-core.mjs",
    "scripts/programmable-launch-router-readiness.mjs",
    "vendor/programmable-applicant-validator/scripts/evm-encoding-core.mjs",
    "vendor/programmable-v4-hook-builder/scripts/github-public-source-lossless-json.mjs"
  ]) copyFixtureFile(repositoryRoot, root, relativePath);
  const artifact = (contractId, relativePath) => ({
    contractId,
    path: relativePath,
    sha256: digest(fs.readFileSync(path.join(root, relativePath)))
  });
  const validatorPaths = [
    "scripts/programmable-launch-router-readiness-core.mjs",
    "scripts/programmable-launch-router-readiness.mjs",
    "vendor/programmable-applicant-validator/scripts/evm-encoding-core.mjs",
    "vendor/programmable-v4-hook-builder/scripts/github-public-source-lossless-json.mjs"
  ].sort(compareUtf8);
  const validatorFiles = validatorPaths.map((relativePath) => ({
    path: relativePath,
    sha256: digest(fs.readFileSync(path.join(root, relativePath)))
  }));
  const validatorBytes = new Map(validatorPaths.map((relativePath) => [relativePath, fs.readFileSync(path.join(root, relativePath))]));
  const validatorRecords = validatorFiles.map(({ path: relativePath, sha256 }) => ({
    byteLength: validatorBytes.get(relativePath).length,
    path: relativePath,
    role: "module",
    sha256
  }));
  const compatibility = {
    $schema: "urn:programmable:applicant-compatibility:2.0.0",
    application: {
      current: artifact("public-pr-application-v3.2", "intake/schemas/public-pr-application-v3.2.schema.json"),
      legacy: [artifact("public-pr-application-v3.1", "intake/schemas/public-pr-application-v3.schema.json")]
    },
    authority: {
      candidateCodeExecuted: false,
      credentialsUsed: false,
      externalWritesPerformed: false,
      launchAuthorized: false,
      networkAccessed: false,
      promotionAuthorized: false,
      reviewAuthorized: false,
      rpcAccessed: false
    },
    capabilities: {
      draftTransportOperations: ["create", "update"],
      launchReadiness: "offline-check-only",
      unreviewedDraftOnly: true
    },
    kind: "programmable-applicant-compatibility",
    minimumBuilderProtocolVersion: "1.0.0",
    schemaVersion: "2.0.0",
    supportingContracts: {
      routerReadiness: {
        schema: artifact("programmable-launch-router-readiness-v1", "intake/schemas/programmable-launch-router-readiness-v1.schema.json"),
        validatorClosure: {
          algorithm: "sha256-path-nul-size-nul-content-nul-v1",
          closureSha256: closureDigest(validatorRecords, validatorBytes),
          files: validatorFiles
        }
      },
      submission: artifact("open-world-submission-v2.1", "intake/schemas/open-world-submission-v2.1.schema.json"),
      tradeCapabilityManifest: artifact("trade-capability-manifest-v2", "intake/schemas/trade-capability-manifest-v2.schema.json")
    },
    trustedRepository: { defaultBranch: "main", numericId: "1320171831" }
  };
  writeFile(root, APPLICANT_COMPATIBILITY_V2_PATH, Buffer.from(`${canonicalApplicantJson(compatibility)}\n`));
  return { root };
}

function closureDigest(records, packageFiles) {
  const hash = crypto.createHash("sha256");
  for (const record of records) {
    const bytes = packageFiles.get(record.path);
    hash.update(Buffer.from(record.path));
    hash.update(Buffer.from([0]));
    hash.update(Buffer.from(String(record.byteLength), "ascii"));
    hash.update(Buffer.from([0]));
    hash.update(bytes);
    hash.update(Buffer.from([0]));
  }
  return `sha256:${hash.digest("hex")}`;
}

function digest(bytes) {
  return `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
}

function writeFile(root, relativePath, bytes) {
  const target = path.join(root, ...relativePath.split("/"));
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, bytes);
}

function copyFixtureFile(sourceRoot, targetRoot, relativePath, targetRelativePath = relativePath) {
  const target = path.join(targetRoot, ...targetRelativePath.split("/"));
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.copyFileSync(path.join(sourceRoot, ...relativePath.split("/")), target);
}

function readJson(root, relativePath) {
  return JSON.parse(fs.readFileSync(path.join(root, ...relativePath.split("/")), "utf8"));
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left), Buffer.from(right));
}

function hasCode(code) {
  return (error) => error instanceof ApplicantCompatibilityError && error.code === code;
}
