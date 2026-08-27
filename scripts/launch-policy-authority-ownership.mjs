#!/usr/bin/env node

import childProcess from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { TextDecoder } from "node:util";
import { fileURLToPath } from "node:url";

import { parseBoundedLosslessJson } from "../vendor/programmable-v4-hook-builder/scripts/github-public-source-lossless-json.mjs";
import {
  canonicalJson,
  parseLaunchPolicyBytes
} from "./launch-policy-core.mjs";
import { ruleHandlersForPolicyVersion } from "./launch-policy-handlers.mjs";

export const AUTHORITY_OWNERSHIP_MANIFEST_PATH = "policy/launch-policy-authority-ownership.v1.json";

const SCHEMA_VERSION = "programmable.launch-policy-authority-ownership.v1";
const POLICY_PATH = "policy/launch-policy.v1.json";
const POLICY_SCHEMA_PATH = "policy/schemas/launch-policy.v1.schema.json";
const CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_PATH = "policy/custom-launch-admission-v3.json";
const CUSTOM_LAUNCH_ADMISSION_SCHEMA_PATH = "policy/schemas/custom-launch-admission-v3.schema.json";
const CUSTOM_LAUNCH_ADMISSION_BINDING_PATH = ".programmable/custom-launch-admission.v3.json";
const MANIFEST_SCHEMA_PATH = "policy/schemas/launch-policy-authority-ownership.v1.schema.json";
const REPOSITORY_NAME = "0xprogrammable/launch-policy";
const LEGACY_REPOSITORY_NAME = "0xprogrammable/submit-launch";
const REPOSITORY_ID = "1320171831";
const REPOSITORY_BRANCH = "main";
const CURRENT_RELEASE_DOCUMENT = "docs/releases/v1.11.0.md";
const CURRENT_RELEASE_HISTORY = "registry/history/1.11.0.json";
const VENDOR_ROOT = "vendor/programmable-v4-hook-builder";
const VENDOR_PREFIX = `${VENDOR_ROOT}/`;
const APPLICANT_VALIDATOR_ROOT = "vendor/programmable-applicant-validator";
const APPLICANT_VALIDATOR_PREFIX = `${APPLICANT_VALIDATOR_ROOT}/`;
const APPLICANT_COMPATIBILITY_PATHS = Object.freeze([
  ".programmable/applicant-compatibility.v1.json",
  ".programmable/applicant-compatibility.v2.json"
]);
const PROGRAMMABLE_ROUTER_READINESS_ENTRYPOINT = Object.freeze({
  id: "programmable-router-readiness-cli",
  path: "scripts/programmable-launch-router-readiness.mjs",
  role: "launch-readiness"
});
const FROZEN_VENDOR_PREFIXES = Object.freeze([APPLICANT_VALIDATOR_PREFIX, VENDOR_PREFIX]);
const VENDOR_RECEIPT_PATH = "vendor/receipt.json";
const MAXIMUM_MANIFEST_BYTES = 2 * 1024 * 1024;
const MAXIMUM_INSPECTOR_OUTPUT_BYTES = 8 * 1024 * 1024;
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
const SHA256 = /^sha256:[0-9a-f]{64}$/u;
const OBJECT_ID = /^[0-9a-f]{40}$/u;
const SAFE_ID = /^[a-z0-9][a-z0-9.-]{1,79}$/u;
const RULE_ID = /^[A-Z][A-Z0-9_]*(?:\.[A-Z][A-Z0-9_]*)+$/u;
const HANDLER_ID = /^[a-z0-9][a-z0-9.-]{1,79}$/u;
const APPLICATION_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const FILE_CLASS_NAMES = Object.freeze([
  "admission-entrypoint",
  "authority-ownership-control",
  "authority-ownership-manifest",
  "canonical-admission-policy",
  "current-admission-disclosure",
  "current-admission-implementation",
  "current-admission-support",
  "frozen-legacy-compatibility",
  "generated-public-projection",
  "historical-design-record",
  "repository-support",
  "test-evidence"
]);
const ENTRYPOINT_ROLES = new Set([
  "current-policy-read",
  "current-review",
  "frozen-legacy-review",
  "historical-intake",
  "launch-readiness",
  "public-intake",
  "disabled-reference",
  "workflow-canary",
  "website-canary-eligibility",
  "disabled-legacy-entitlement",
  "policy-projection",
  "repository-integrity"
]);
const PROJECTION_KINDS = new Set([
  "generated-discovery",
  "generated-policy-document",
  "public-contract",
  "public-documentation",
  "public-schema",
  "trusted-workflow"
]);
const MODULE_OWNERSHIP_ROLES = new Set([
  "pure-support",
  "runtime-control",
  "semantic-consumer"
]);
const CONTROL_IMPLEMENTATION_PATHS = new Set([
  "scripts/active-contract-manifest-core.mjs",
  "scripts/applicant-compatibility-core.mjs",
  "scripts/applicant-v3_2-scaffold-core.mjs",
  "scripts/applicant-v3_2-scaffold.mjs",
  "review/cli.mjs",
  "review/open-review-engine.mjs",
  "scripts/acceptance-entitlement-core.mjs",
  "scripts/canary-eligibility-core.mjs",
  "scripts/compile-canary-eligibility.mjs",
  "scripts/compile-launch-entitlement.mjs",
  "scripts/custom-launch-admission-v3.mjs",
  "scripts/generate-launch-policy-artifacts.mjs",
  "scripts/launch-policy-authority-ownership.mjs",
  "scripts/launch-policy.mjs",
  "scripts/programmable-launch-router-readiness.mjs",
  "scripts/release-version-core.mjs",
  "scripts/universal-admission-command-core.mjs",
  "scripts/universal-admission-contract-core.mjs",
  "scripts/universal-admission-contract.mjs",
  "scripts/universal-admission-protocol-core.mjs",
  "scripts/universal-admission-service-core.mjs",
  "scripts/universal-admission-sqlite-store.mjs",
  "scripts/universal-admission-sqlite.mjs",
  "scripts/verify-open-world-v2-contracts.mjs",
  "scripts/verify-open-world-v2-package.mjs",
  "scripts/verify-open-world-v2-trade-manifest-v2.mjs",
  "scripts/verify-open-world-v2-validation-fee.mjs",
  "scripts/verify-open-world-v2-validation-intake.mjs",
  "scripts/verify-open-world-v2-validation-intent.mjs",
  "scripts/verify-public-application-v3-generation.mjs",
  "scripts/verify-public-application-v3-shared.mjs",
  "scripts/verify-public-hook-application.mjs",
  "scripts/verify-public-hook-application-core.mjs",
  "scripts/verify-repository.mjs",
  "scripts/universal-admission-core.mjs",
  "scripts/universal-admission.mjs",
  "scripts/verify-workflow-canary.mjs",
  "scripts/workflow-canary-core.mjs"
]);
const PURE_SUPPORT_MODULES = new Set();
const EXPECTED_VENDOR = Object.freeze({
  commit: "7869f44aa8dcc7cefeb379b76118407d53384558",
  receiptPath: VENDOR_RECEIPT_PATH,
  release: "v0.10.3",
  repository: "0xprogrammable/hookbuilder",
  rootPath: VENDOR_ROOT,
  schemaVersion: "1.0.0",
  skillTree: "3b974b0bcb006e08d8f2504c783ac81f2ee3bd74",
  source: "https://github.com/0xprogrammable/hookbuilder/tree/7869f44aa8dcc7cefeb379b76118407d53384558/skills/programmable-v4-hook-builder"
});
const EXPECTED_BOUNDED_APPLICANT_DATA = Object.freeze([
  Object.freeze({
    contract: "workflow-canary-application-v1",
    files: Object.freeze(["application.json"]),
    rootPath: "canary-submissions"
  }),
  Object.freeze({
    contract: "public-pr-application-v2-six-file-v1",
    files: Object.freeze([
      "PROPOSAL.md",
      "TEST_PLAN.md",
      "THREAT_MODEL.md",
      "application.json",
      "compatibility-report.json",
      "evidence-index.json"
    ]),
    rootPath: "submissions"
  }),
  Object.freeze({
    contract: "public-pr-application-v3.1-immutable-revision-v1",
    layout: "application-v3-revision-tree",
    maximumFileBytes: 4 * 1024 * 1024,
    maximumFiles: 100,
    maximumPackageBytes: 12 * 1024 * 1024,
    rootFile: "application.v3.json",
    rootMaximumBytes: 256 * 1024,
    rootPath: "submissions"
  }),
  Object.freeze({
    contract: "public-pr-application-v3.2-immutable-revision-v1",
    layout: "application-v3-revision-tree",
    maximumFileBytes: 4 * 1024 * 1024,
    maximumFiles: 100,
    maximumPackageBytes: 12 * 1024 * 1024,
    rootFile: "application.v3.json",
    rootMaximumBytes: 256 * 1024,
    rootPath: "submissions"
  })
]);
const STATIC_IMPORT_INSPECTOR = String.raw`
const acorn = require("internal/deps/acorn/acorn/dist/acorn");
const fs = require("node:fs");
const path = require("node:path");
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const result = Object.create(null);
for (const relativePath of input.paths) {
  const moduleSource = fs.readFileSync(path.join(input.repositoryRoot, relativePath), "utf8");
  const ast = acorn.parse(moduleSource, {
    allowHashBang: true,
    ecmaVersion: "latest",
    sourceType: "module"
  });
  const specifiers = [];
  let hasDynamicImport = false;
  walk(ast);
  const pureSupport = ast.body.every((node) =>
    node.type === "ImportDeclaration"
    || node.type === "ExportAllDeclaration"
    || (node.type === "ExportNamedDeclaration" && node.declaration === null)
  );
  result[relativePath] = {
    hasDynamicImport,
    pureSupport,
    specifiers: [...new Set(specifiers)]
  };

  function walk(node) {
    if (!node || typeof node !== "object") return;
    if (node.type === "ImportExpression") hasDynamicImport = true;
    if (
      (node.type === "ImportDeclaration" || node.type === "ExportAllDeclaration" || node.type === "ExportNamedDeclaration")
      && typeof node.source?.value === "string"
    ) specifiers.push(node.source.value);
    for (const [key, child] of Object.entries(node)) {
      if (key === "start" || key === "end" || key === "loc") continue;
      if (Array.isArray(child)) for (const item of child) walk(item);
      else walk(child);
    }
  }
}
process.stdout.write(JSON.stringify(result));
`;

export class LaunchPolicyAuthorityOwnershipError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.name = "LaunchPolicyAuthorityOwnershipError";
    this.code = code;
  }
}

export function canonicalAuthorityJson(value) {
  return canonicalJson(value);
}

export function readLaunchPolicyAuthorityOwnership(options) {
  const repositoryRoot = requireRepositoryRoot(options);
  const manifest = readManifest(repositoryRoot, { requireCompleteHashes: true });
  return deepFreeze(manifest);
}

export function verifyLaunchPolicyAuthorityOwnership(options) {
  const repositoryRoot = requireRepositoryRoot(options);
  const manifest = readManifest(repositoryRoot, { requireCompleteHashes: true });
  const { observedFiles: _observedFiles, ...report } = verifyManifestAgainstRepository({ manifest, repositoryRoot, verifyHashes: true });
  return Object.freeze(report);
}

export function writeLaunchPolicyAuthorityOwnershipHashes(options) {
  const repositoryRoot = requireRepositoryRoot(options);
  const manifest = readManifest(repositoryRoot, {
    allowLegacyRepositoryName: true,
    requireCompleteHashes: false
  });
  migrateLaunchPolicyCutoverManifest({ manifest, repositoryRoot });
  verifyFrozenVendor({ manifest, repositoryRoot });
  const repositoryFiles = listRepositoryFiles(repositoryRoot);
  const observedFiles = repositoryFiles.filter((relativePath) => !isBoundedApplicantDataPath(manifest, relativePath));
  const classifiedFiles = classifiedFilePaths(manifest);
  assertSameStringSet(
    observedFiles,
    classifiedFiles,
    "AUTHORITY_OWNERSHIP_FILE_SET_MISMATCH",
    "Every non-vendor repository file must have one exact authority-ownership classification."
  );
  verifyOwnedFileShapes(repositoryRoot, repositoryFiles);
  verifyCentralPolicyMapping({ manifest, repositoryRoot });
  verifyProjectionOwnership({ manifest, classifiedFiles });
  verifyEntrypointClosures({ manifest, observedFiles, repositoryRoot });
  manifest.fileSha256 = Object.fromEntries(
    observedFiles
      .filter((relativePath) => relativePath !== AUTHORITY_OWNERSHIP_MANIFEST_PATH)
      .map((relativePath) => [relativePath, digestFile(repositoryRoot, relativePath)])
      .sort(([left], [right]) => compareUtf8(left, right))
  );
  const manifestPath = resolveRepositoryPath(repositoryRoot, AUTHORITY_OWNERSHIP_MANIFEST_PATH);
  fs.writeFileSync(manifestPath, `${canonicalAuthorityJson(manifest)}\n`, { encoding: "utf8", mode: 0o644 });
  return verifyLaunchPolicyAuthorityOwnership({ repositoryRoot });
}

function verifyManifestAgainstRepository({ manifest, repositoryRoot, verifyHashes }) {
  verifyFrozenVendor({ manifest, repositoryRoot });
  const repositoryFiles = listRepositoryFiles(repositoryRoot);
  const observedFiles = repositoryFiles.filter((relativePath) => !isBoundedApplicantDataPath(manifest, relativePath));
  const classifiedFiles = classifiedFilePaths(manifest);
  assertSameStringSet(
    observedFiles,
    classifiedFiles,
    "AUTHORITY_OWNERSHIP_FILE_SET_MISMATCH",
    "Every non-vendor repository file must have one exact authority-ownership classification."
  );
  verifyOwnedFileShapes(repositoryRoot, repositoryFiles);
  if (verifyHashes) verifyFileHashes({ manifest, observedFiles, repositoryRoot });
  verifyCentralPolicyMapping({ manifest, repositoryRoot });
  verifyProjectionOwnership({ manifest, classifiedFiles });
  verifyEntrypointClosures({ manifest, observedFiles, repositoryRoot });
  const report = {
    canonicalPolicyPath: POLICY_PATH,
    entrypoints: manifest.entrypoints.length,
    files: repositoryFiles.length,
    frozenVendorTree: manifest.frozenVendor.skillTree,
    ok: true,
    rules: manifest.semanticRuleMap.length
  };
  return Object.freeze({ ...report, observedFiles: Object.freeze(observedFiles) });
}

function readManifest(repositoryRoot, { allowLegacyRepositoryName = false, requireCompleteHashes }) {
  const manifestPath = resolveRepositoryPath(repositoryRoot, AUTHORITY_OWNERSHIP_MANIFEST_PATH);
  const bytes = readRegularFile(manifestPath, MAXIMUM_MANIFEST_BYTES, "AUTHORITY_OWNERSHIP_MANIFEST_INVALID");
  let source;
  try {
    source = UTF8_DECODER.decode(bytes);
    parseBoundedLosslessJson(source);
  } catch (error) {
    fail("AUTHORITY_OWNERSHIP_MANIFEST_JSON_INVALID", "The authority-ownership manifest must be duplicate-free UTF-8 JSON.", error);
  }
  let manifest;
  try {
    manifest = JSON.parse(source);
  } catch (error) {
    fail("AUTHORITY_OWNERSHIP_MANIFEST_JSON_INVALID", "The authority-ownership manifest is not valid JSON.", error);
  }
  if (source !== `${canonicalAuthorityJson(manifest)}\n`) {
    fail("AUTHORITY_OWNERSHIP_MANIFEST_NONCANONICAL", "The authority-ownership manifest must be canonical JSON with one trailing newline.");
  }
  validateManifestShape(manifest, { allowLegacyRepositoryName, requireCompleteHashes });
  return manifest;
}

function validateManifestShape(manifest, { allowLegacyRepositoryName = false, requireCompleteHashes }) {
  assertPlainObject(manifest, "AUTHORITY_OWNERSHIP_MANIFEST_INVALID", "Manifest");
  assertExactKeys(manifest, [
    "boundedApplicantData",
    "canonicalPolicy",
    "entrypoints",
    "fileClasses",
    "fileSha256",
    "frozenVendor",
    "orchestrationEntrypoints",
    "publicProjections",
    "repository",
    "schemaVersion",
    "semanticRuleMap",
    "moduleOwnership"
  ], "AUTHORITY_OWNERSHIP_MANIFEST_INVALID", "Manifest");
  assertEqual(manifest.schemaVersion, SCHEMA_VERSION, "AUTHORITY_OWNERSHIP_SCHEMA_UNSUPPORTED", "Manifest schemaVersion");

  assertPlainObject(manifest.repository, "AUTHORITY_OWNERSHIP_MANIFEST_INVALID", "repository");
  assertExactKeys(manifest.repository, ["branch", "name", "numericRepositoryId"], "AUTHORITY_OWNERSHIP_MANIFEST_INVALID", "repository");
  if (
    manifest.repository.name !== REPOSITORY_NAME
    && !(allowLegacyRepositoryName && manifest.repository.name === LEGACY_REPOSITORY_NAME)
  ) {
    fail("AUTHORITY_OWNERSHIP_REPOSITORY_INVALID", "repository.name is invalid.");
  }
  assertEqual(manifest.repository.numericRepositoryId, REPOSITORY_ID, "AUTHORITY_OWNERSHIP_REPOSITORY_INVALID", "repository.numericRepositoryId");
  assertEqual(manifest.repository.branch, REPOSITORY_BRANCH, "AUTHORITY_OWNERSHIP_REPOSITORY_INVALID", "repository.branch");

  assertPlainObject(manifest.canonicalPolicy, "AUTHORITY_OWNERSHIP_MANIFEST_INVALID", "canonicalPolicy");
  assertExactKeys(manifest.canonicalPolicy, ["path", "schemaPath"], "AUTHORITY_OWNERSHIP_MANIFEST_INVALID", "canonicalPolicy");
  assertEqual(manifest.canonicalPolicy.path, POLICY_PATH, "AUTHORITY_OWNERSHIP_POLICY_INVALID", "canonicalPolicy.path");
  assertEqual(manifest.canonicalPolicy.schemaPath, POLICY_SCHEMA_PATH, "AUTHORITY_OWNERSHIP_POLICY_INVALID", "canonicalPolicy.schemaPath");

  validateBoundedApplicantData(manifest.boundedApplicantData);
  validateFrozenVendorShape(manifest.frozenVendor);
  validateFileClasses(manifest.fileClasses);
  validateFileHashes(manifest.fileSha256, { requireCompleteHashes });
  validateEntrypoints(manifest.entrypoints);
  validateOrchestrationEntrypoints(manifest.orchestrationEntrypoints);
  validatePublicProjections(manifest.publicProjections);
  validateSemanticRuleMap(manifest.semanticRuleMap);
  validateModuleOwnership(manifest.moduleOwnership);
}

function migrateLaunchPolicyCutoverManifest({ manifest, repositoryRoot }) {
  manifest.repository.name = REPOSITORY_NAME;
  for (const releasePath of [CURRENT_RELEASE_DOCUMENT, CURRENT_RELEASE_HISTORY]) {
    if (!manifest.fileClasses["repository-support"].includes(releasePath)) {
      manifest.fileClasses["repository-support"].push(releasePath);
    }
  }
  manifest.fileClasses["repository-support"].sort(compareUtf8);

  const historicalEntrypointIds = new Set([
    "application-v3.2-scaffold-cli",
    "public-intake-validator"
  ]);
  const disabledReferenceEntrypointIds = new Set([
    "universal-admission-cli",
    "universal-admission-service-api",
    "universal-admission-sqlite-reference-cli"
  ]);
  for (const entrypoint of manifest.entrypoints) {
    if (historicalEntrypointIds.has(entrypoint.id)) entrypoint.role = "historical-intake";
    if (disabledReferenceEntrypointIds.has(entrypoint.id)) entrypoint.role = "disabled-reference";
  }

  const repositoryFiles = listRepositoryFiles(repositoryRoot);
  const observedFiles = repositoryFiles.filter((relativePath) => !isBoundedApplicantDataPath(manifest, relativePath));
  const importGraph = inspectStaticImports({
    modulePaths: observedFiles.filter((relativePath) => relativePath.endsWith(".mjs")),
    repositoryRoot
  });
  const ownedFiles = new Set(observedFiles);
  const generatorEntrypoint = manifest.entrypoints.find(({ id }) => id === "policy-projection-generator");
  const observedClosure = resolveEntrypointClosure({
    entrypointPath: generatorEntrypoint.path,
    importGraph,
    ownedFiles,
    repositoryRoot
  });
  generatorEntrypoint.moduleClosure = observedClosure.moduleClosure;
  generatorEntrypoint.frozenVendorImports = observedClosure.frozenVendorImports;

  for (const projectionPath of [".programmable/active-contract.json", ".programmable/active-contract.v2.json"]) {
    const projection = manifest.publicProjections.find(({ path: candidatePath }) => candidatePath === projectionPath);
    for (const sourcePath of [
      ".programmable/applicant-compatibility.v2.json",
      "scripts/applicant-compatibility-core.mjs"
    ]) {
      if (!projection.sourcePaths.includes(sourcePath)) projection.sourcePaths.push(sourcePath);
    }
    projection.sourcePaths.sort(compareUtf8);
  }
}

function validateBoundedApplicantData(value) {
  if (canonicalAuthorityJson(value) !== canonicalAuthorityJson(EXPECTED_BOUNDED_APPLICANT_DATA)) {
    fail("AUTHORITY_OWNERSHIP_BOUNDED_DATA_INVALID", "boundedApplicantData must preserve the exact inert V2, Workflow Canary, and Application V3.1/V3.2 revision package surfaces.");
  }
}

function validateFrozenVendorShape(frozenVendor) {
  assertPlainObject(frozenVendor, "AUTHORITY_OWNERSHIP_VENDOR_INVALID", "frozenVendor");
  assertExactKeys(frozenVendor, Object.keys(EXPECTED_VENDOR), "AUTHORITY_OWNERSHIP_VENDOR_INVALID", "frozenVendor");
  for (const [key, expected] of Object.entries(EXPECTED_VENDOR)) {
    assertEqual(frozenVendor[key], expected, "AUTHORITY_OWNERSHIP_VENDOR_INVALID", `frozenVendor.${key}`);
  }
}

function validateFileClasses(fileClasses) {
  assertPlainObject(fileClasses, "AUTHORITY_OWNERSHIP_CLASSES_INVALID", "fileClasses");
  assertExactKeys(fileClasses, FILE_CLASS_NAMES, "AUTHORITY_OWNERSHIP_CLASSES_INVALID", "fileClasses");
  const seen = new Set();
  for (const className of FILE_CLASS_NAMES) {
    const paths = fileClasses[className];
    assertSortedUniquePaths(paths, "AUTHORITY_OWNERSHIP_CLASSES_INVALID", `fileClasses.${className}`);
    for (const relativePath of paths) {
      if (seen.has(relativePath)) fail("AUTHORITY_OWNERSHIP_CLASS_DUPLICATE", `${relativePath} has more than one authority-ownership classification.`);
      seen.add(relativePath);
    }
  }
  assertSameStringSet(fileClasses["canonical-admission-policy"], [POLICY_PATH], "AUTHORITY_OWNERSHIP_POLICY_INVALID", "Only the canonical policy may be classified as authored admission policy.");
  assertSameStringSet(fileClasses["current-admission-disclosure"], [CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_PATH], "AUTHORITY_OWNERSHIP_POLICY_INVALID", "The V3 admission disclosure must remain separate from the canonical business policy.");
  assertSameStringSet(fileClasses["authority-ownership-manifest"], [AUTHORITY_OWNERSHIP_MANIFEST_PATH], "AUTHORITY_OWNERSHIP_MANIFEST_INVALID", "The ownership manifest must classify only itself as the ownership manifest.");
  if (!seen.has(MANIFEST_SCHEMA_PATH)) fail("AUTHORITY_OWNERSHIP_SCHEMA_MISSING", "The ownership schema must be in the closed repository inventory.");
}

function validateFileHashes(fileSha256, { requireCompleteHashes }) {
  assertPlainObject(fileSha256, "AUTHORITY_OWNERSHIP_HASHES_INVALID", "fileSha256");
  for (const [relativePath, digest] of Object.entries(fileSha256)) {
    assertSafeRepositoryPath(relativePath, "AUTHORITY_OWNERSHIP_HASHES_INVALID", "fileSha256 path");
    if (!SHA256.test(digest)) fail("AUTHORITY_OWNERSHIP_HASHES_INVALID", `${relativePath} has an invalid SHA-256 binding.`);
    if (relativePath === AUTHORITY_OWNERSHIP_MANIFEST_PATH) fail("AUTHORITY_OWNERSHIP_HASHES_INVALID", "The canonical manifest cannot recursively hash itself.");
  }
  if (requireCompleteHashes && Object.keys(fileSha256).length === 0) {
    fail("AUTHORITY_OWNERSHIP_HASHES_INVALID", "The authority-ownership hash inventory is empty.");
  }
}

function validateEntrypoints(entrypoints) {
  if (!Array.isArray(entrypoints) || entrypoints.length < 1 || entrypoints.length > 32) {
    fail("AUTHORITY_OWNERSHIP_ENTRYPOINTS_INVALID", "entrypoints must be a bounded non-empty array.");
  }
  const ids = new Set();
  const paths = new Set();
  for (const entrypoint of entrypoints) {
    assertPlainObject(entrypoint, "AUTHORITY_OWNERSHIP_ENTRYPOINTS_INVALID", "entrypoint");
    assertExactKeys(entrypoint, ["frozenVendorImports", "id", "moduleClosure", "path", "role"], "AUTHORITY_OWNERSHIP_ENTRYPOINTS_INVALID", "entrypoint");
    if (!SAFE_ID.test(entrypoint.id ?? "")) fail("AUTHORITY_OWNERSHIP_ENTRYPOINTS_INVALID", "An entrypoint id is invalid.");
    assertSafeRepositoryPath(entrypoint.path, "AUTHORITY_OWNERSHIP_ENTRYPOINTS_INVALID", "entrypoint.path");
    if (!entrypoint.path.endsWith(".mjs")) fail("AUTHORITY_OWNERSHIP_ENTRYPOINTS_INVALID", `${entrypoint.path} is not an ESM entrypoint.`);
    if (!ENTRYPOINT_ROLES.has(entrypoint.role)) fail("AUTHORITY_OWNERSHIP_ENTRYPOINTS_INVALID", `${entrypoint.id} has an unsupported role.`);
    assertSortedUniquePaths(entrypoint.moduleClosure, "AUTHORITY_OWNERSHIP_ENTRYPOINTS_INVALID", `${entrypoint.id}.moduleClosure`);
    assertSortedUniquePaths(entrypoint.frozenVendorImports, "AUTHORITY_OWNERSHIP_ENTRYPOINTS_INVALID", `${entrypoint.id}.frozenVendorImports`);
    if (!entrypoint.moduleClosure.includes(entrypoint.path)) fail("AUTHORITY_OWNERSHIP_ENTRYPOINTS_INVALID", `${entrypoint.id} does not include itself in its module closure.`);
    for (const vendorImport of entrypoint.frozenVendorImports) {
      if (!FROZEN_VENDOR_PREFIXES.some((prefix) => vendorImport.startsWith(prefix)) || !vendorImport.endsWith(".mjs")) {
        fail("AUTHORITY_OWNERSHIP_ENTRYPOINTS_INVALID", `${entrypoint.id} has an invalid frozen-vendor import.`);
      }
    }
    if (paths.has(entrypoint.path)) fail("AUTHORITY_OWNERSHIP_ENTRYPOINTS_INVALID", `${entrypoint.path} is registered as more than one entrypoint.`);
    paths.add(entrypoint.path);
    if (ids.has(entrypoint.id)) fail("AUTHORITY_OWNERSHIP_ENTRYPOINTS_INVALID", `${entrypoint.id} is registered more than once.`);
    ids.add(entrypoint.id);
  }
  const readinessEntrypoint = entrypoints.find(({ path: entrypointPath }) => (
    entrypointPath === PROGRAMMABLE_ROUTER_READINESS_ENTRYPOINT.path
  ));
  if (
    readinessEntrypoint?.id !== PROGRAMMABLE_ROUTER_READINESS_ENTRYPOINT.id
    || readinessEntrypoint?.role !== PROGRAMMABLE_ROUTER_READINESS_ENTRYPOINT.role
  ) {
    fail(
      "AUTHORITY_OWNERSHIP_ENTRYPOINTS_INVALID",
      "The protected Router-readiness CLI must retain its exact checker-only entrypoint identity and role."
    );
  }
}

function validateOrchestrationEntrypoints(paths) {
  assertSortedUniquePaths(paths, "AUTHORITY_OWNERSHIP_ORCHESTRATION_INVALID", "orchestrationEntrypoints");
  if (paths.length < 1) fail("AUTHORITY_OWNERSHIP_ORCHESTRATION_INVALID", "At least one trusted orchestration entrypoint is required.");
}

function validatePublicProjections(projections) {
  if (!Array.isArray(projections) || projections.length < 1 || projections.length > 128) {
    fail("AUTHORITY_OWNERSHIP_PROJECTIONS_INVALID", "publicProjections must be a bounded non-empty array.");
  }
  const paths = [];
  for (const projection of projections) {
    assertPlainObject(projection, "AUTHORITY_OWNERSHIP_PROJECTIONS_INVALID", "projection");
    assertExactKeys(projection, ["kind", "path", "sourcePaths"], "AUTHORITY_OWNERSHIP_PROJECTIONS_INVALID", "projection");
    if (!PROJECTION_KINDS.has(projection.kind)) fail("AUTHORITY_OWNERSHIP_PROJECTIONS_INVALID", `${projection.path} has an unsupported projection kind.`);
    assertSafeRepositoryPath(projection.path, "AUTHORITY_OWNERSHIP_PROJECTIONS_INVALID", "projection.path");
    assertSortedUniquePaths(projection.sourcePaths, "AUTHORITY_OWNERSHIP_PROJECTIONS_INVALID", `${projection.path}.sourcePaths`);
    if (projection.sourcePaths.length < 1) fail("AUTHORITY_OWNERSHIP_PROJECTIONS_INVALID", `${projection.path} has no declared source.`);
    paths.push(projection.path);
  }
  assertSortedUniqueStrings(paths, "AUTHORITY_OWNERSHIP_PROJECTIONS_INVALID", "projection paths");
}

function validateSemanticRuleMap(ruleMap) {
  if (!Array.isArray(ruleMap) || ruleMap.length < 1 || ruleMap.length > 256) {
    fail("AUTHORITY_OWNERSHIP_RULE_MAP_INVALID", "semanticRuleMap must be a bounded non-empty array.");
  }
  const ruleIds = new Set();
  for (const mapping of ruleMap) {
    assertPlainObject(mapping, "AUTHORITY_OWNERSHIP_RULE_MAP_INVALID", "semantic rule mapping");
    assertExactKeys(mapping, ["consumers", "handlerId", "profiles", "ruleId", "status"], "AUTHORITY_OWNERSHIP_RULE_MAP_INVALID", "semantic rule mapping");
    if (!RULE_ID.test(mapping.ruleId ?? "")) fail("AUTHORITY_OWNERSHIP_RULE_MAP_INVALID", "A mapped Rule ID is invalid.");
    if (mapping.handlerId !== null && !HANDLER_ID.test(mapping.handlerId ?? "")) fail("AUTHORITY_OWNERSHIP_RULE_MAP_INVALID", `${mapping.ruleId} has an invalid handler id.`);
    if (!new Set(["active", "inactive"]).has(mapping.status)) fail("AUTHORITY_OWNERSHIP_RULE_MAP_INVALID", `${mapping.ruleId} has an invalid status.`);
    assertSortedUniqueStrings(mapping.profiles, "AUTHORITY_OWNERSHIP_RULE_MAP_INVALID", `${mapping.ruleId}.profiles`);
    assertSortedUniquePaths(mapping.consumers, "AUTHORITY_OWNERSHIP_RULE_MAP_INVALID", `${mapping.ruleId}.consumers`);
    if (mapping.profiles.length < 1 || mapping.consumers.length < 1) fail("AUTHORITY_OWNERSHIP_RULE_MAP_INVALID", `${mapping.ruleId} must bind profiles and consumers.`);
    if (ruleIds.has(mapping.ruleId)) fail("AUTHORITY_OWNERSHIP_RULE_MAP_INVALID", `${mapping.ruleId} is mapped more than once.`);
    ruleIds.add(mapping.ruleId);
  }
}

function validateModuleOwnership(moduleOwnership) {
  if (!Array.isArray(moduleOwnership) || moduleOwnership.length < 1 || moduleOwnership.length > 128) {
    fail("AUTHORITY_OWNERSHIP_MODULE_MAP_INVALID", "moduleOwnership must be a bounded non-empty array.");
  }
  const paths = [];
  for (const ownership of moduleOwnership) {
    assertPlainObject(ownership, "AUTHORITY_OWNERSHIP_MODULE_MAP_INVALID", "module ownership");
    assertExactKeys(ownership, ["path", "role", "semanticRuleIds"], "AUTHORITY_OWNERSHIP_MODULE_MAP_INVALID", "module ownership");
    assertSafeRepositoryPath(ownership.path, "AUTHORITY_OWNERSHIP_MODULE_MAP_INVALID", "module ownership path");
    if (!MODULE_OWNERSHIP_ROLES.has(ownership.role)) {
      fail("AUTHORITY_OWNERSHIP_MODULE_MAP_INVALID", `${ownership.path} has an unsupported module ownership role.`);
    }
    assertSortedUniqueStrings(ownership.semanticRuleIds, "AUTHORITY_OWNERSHIP_MODULE_MAP_INVALID", `${ownership.path}.semanticRuleIds`);
    for (const ruleId of ownership.semanticRuleIds) {
      if (!RULE_ID.test(ruleId)) fail("AUTHORITY_OWNERSHIP_MODULE_MAP_INVALID", `${ownership.path} owns an invalid central Rule ID.`);
    }
    if (ownership.role === "semantic-consumer" && ownership.semanticRuleIds.length === 0) {
      fail("AUTHORITY_OWNERSHIP_MODULE_MAP_INVALID", `${ownership.path} is a semantic consumer without a central Rule ID.`);
    }
    if (ownership.role !== "semantic-consumer" && ownership.semanticRuleIds.length !== 0) {
      fail("AUTHORITY_OWNERSHIP_MODULE_MAP_INVALID", `${ownership.path} is not a semantic consumer and cannot own central Rule IDs.`);
    }
    paths.push(ownership.path);
  }
  assertSortedUniqueStrings(paths, "AUTHORITY_OWNERSHIP_MODULE_MAP_INVALID", "module ownership paths");
}

function verifyFrozenVendor({ manifest, repositoryRoot }) {
  const receiptPath = resolveRepositoryPath(repositoryRoot, VENDOR_RECEIPT_PATH);
  const receiptBytes = readRegularFile(receiptPath, 64 * 1024, "AUTHORITY_OWNERSHIP_VENDOR_INVALID");
  let receipt;
  try {
    const source = UTF8_DECODER.decode(receiptBytes);
    parseBoundedLosslessJson(source);
    receipt = JSON.parse(source);
    if (source !== `${canonicalAuthorityJson(receipt)}\n`) throw new Error("noncanonical receipt");
  } catch (error) {
    fail("AUTHORITY_OWNERSHIP_VENDOR_INVALID", "The frozen Hookbuilder receipt is invalid.", error);
  }
  const expectedReceipt = Object.fromEntries(
    Object.entries(EXPECTED_VENDOR).filter(([key]) => !new Set(["receiptPath", "rootPath"]).has(key))
  );
  if (canonicalAuthorityJson(receipt) !== canonicalAuthorityJson(expectedReceipt)) {
    fail("AUTHORITY_OWNERSHIP_VENDOR_INVALID", "The frozen Hookbuilder receipt does not match the exact v0.10.3 identity.");
  }
  if (canonicalAuthorityJson(manifest.frozenVendor) !== canonicalAuthorityJson(EXPECTED_VENDOR)) {
    fail("AUTHORITY_OWNERSHIP_VENDOR_INVALID", "The ownership manifest does not bind the exact frozen Hookbuilder identity.");
  }

  const vendorRoot = resolveRepositoryPath(repositoryRoot, VENDOR_ROOT);
  let vendorStatus;
  try {
    vendorStatus = fs.lstatSync(vendorRoot);
  } catch (error) {
    fail("AUTHORITY_OWNERSHIP_VENDOR_INVALID", "The frozen Hookbuilder tree is missing.", error);
  }
  if (!vendorStatus.isDirectory() || vendorStatus.isSymbolicLink()) {
    fail("AUTHORITY_OWNERSHIP_VENDOR_INVALID", "The frozen Hookbuilder root must be a real directory.");
  }

  const temporaryIndex = path.join(os.tmpdir(), `launch-policy-vendor-index-${process.pid}-${crypto.randomBytes(8).toString("hex")}`);
  try {
    const environment = { ...process.env, GIT_INDEX_FILE: temporaryIndex };
    runGit(repositoryRoot, ["read-tree", "--empty"], { environment });
    runGit(repositoryRoot, ["add", "-f", "--", VENDOR_ROOT], { environment });
    const tree = runGit(repositoryRoot, ["write-tree"], { environment });
    const entry = runGit(repositoryRoot, ["ls-tree", tree, VENDOR_ROOT], { environment });
    const match = /^040000 tree ([0-9a-f]{40})\tvendor\/programmable-v4-hook-builder$/u.exec(entry);
    if (match?.[1] !== EXPECTED_VENDOR.skillTree) {
      fail("AUTHORITY_OWNERSHIP_VENDOR_TREE_MISMATCH", "The frozen Hookbuilder bytes do not match the receipt-bound tree.");
    }
  } finally {
    fs.rmSync(temporaryIndex, { force: true });
    fs.rmSync(`${temporaryIndex}.lock`, { force: true });
  }
}

function listRepositoryFiles(repositoryRoot) {
  const result = childProcess.spawnSync(
    "git",
    ["ls-files", "-z", "--cached", "--others", "--exclude-standard"],
    { cwd: repositoryRoot, encoding: "buffer", env: { ...process.env }, shell: false, maxBuffer: 64 * 1024 * 1024 }
  );
  if (result.status !== 0) fail("AUTHORITY_OWNERSHIP_GIT_FAILED", "The closed repository file inventory could not be read.");
  const paths = result.stdout.toString("utf8").split("\0").filter(Boolean);
  for (const relativePath of paths) assertSafeRepositoryPath(relativePath, "AUTHORITY_OWNERSHIP_FILE_SET_INVALID", "repository path");
  const compactContractsPresent = APPLICANT_COMPATIBILITY_PATHS.every((relativePath) => paths.includes(relativePath));
  return [...new Set(paths.filter((relativePath) => (
    !relativePath.startsWith(VENDOR_PREFIX)
    && !(compactContractsPresent && relativePath.startsWith(APPLICANT_VALIDATOR_PREFIX))
  )))].sort(compareUtf8);
}

function isBoundedApplicantDataPath(manifest, relativePath) {
  const segments = relativePath.split("/");
  if (!APPLICATION_ID.test(segments[1] ?? "")) return false;
  return manifest.boundedApplicantData.some((binding) => {
    if (segments[0] !== binding.rootPath) return false;
    if (Array.isArray(binding.files)) {
      return segments.length === 3 && binding.files.includes(segments[2]);
    }
    return binding.layout === "application-v3-revision-tree"
      && segments.length >= 6
      && segments[2] === "v3"
      && segments[3] === "revisions"
      && /^[1-9][0-9]*$/u.test(segments[4])
      && segments.slice(5).every((segment) => segment.length > 0 && segment !== "." && segment !== ".." && segment !== ".git");
  });
}

function classifiedFilePaths(manifest) {
  return FILE_CLASS_NAMES.flatMap((className) => manifest.fileClasses[className]).sort(compareUtf8);
}

function verifyOwnedFileShapes(repositoryRoot, observedFiles) {
  for (const relativePath of observedFiles) {
    const absolutePath = resolveRepositoryPath(repositoryRoot, relativePath);
    let status;
    try {
      status = fs.lstatSync(absolutePath);
    } catch (error) {
      fail("AUTHORITY_OWNERSHIP_FILE_INVALID", `${relativePath} disappeared during authority verification.`, error);
    }
    if (!status.isFile() || status.isSymbolicLink()) {
      fail("AUTHORITY_OWNERSHIP_FILE_INVALID", `${relativePath} must be a regular non-symlink file.`);
    }
  }
}

function verifyFileHashes({ manifest, observedFiles, repositoryRoot }) {
  const expectedHashPaths = observedFiles.filter((relativePath) => relativePath !== AUTHORITY_OWNERSHIP_MANIFEST_PATH);
  assertSameStringSet(
    Object.keys(manifest.fileSha256),
    expectedHashPaths,
    "AUTHORITY_OWNERSHIP_HASH_SET_MISMATCH",
    "Every classified repository file except the manifest itself must have one exact SHA-256 binding."
  );
  for (const relativePath of expectedHashPaths) {
    const observedDigest = digestFile(repositoryRoot, relativePath);
    if (manifest.fileSha256[relativePath] !== observedDigest) {
      fail("AUTHORITY_OWNERSHIP_HASH_MISMATCH", `${relativePath} changed without a reviewed authority-ownership manifest refresh.`);
    }
  }
}

function verifyCentralPolicyMapping({ manifest, repositoryRoot }) {
  const policyBytes = readRegularFile(resolveRepositoryPath(repositoryRoot, POLICY_PATH), 512 * 1024, "AUTHORITY_OWNERSHIP_POLICY_INVALID");
  let policy;
  try {
    policy = parseLaunchPolicyBytes(policyBytes).policy;
  } catch (error) {
    fail("AUTHORITY_OWNERSHIP_POLICY_INVALID", "The canonical policy could not be validated.", error);
  }
  const policyMap = policy.rules.map((rule) => ({
    handlerId: rule.enforcement.handlerId,
    profiles: [...rule.profiles].sort(compareUtf8),
    ruleId: rule.id,
    status: rule.status
  })).sort((left, right) => compareUtf8(left.ruleId, right.ruleId));
  const ownershipMap = manifest.semanticRuleMap.map(({ consumers: _consumers, ...mapping }) => mapping);
  if (canonicalAuthorityJson(policyMap) !== canonicalAuthorityJson(ownershipMap)) {
    fail("AUTHORITY_OWNERSHIP_RULE_MAP_MISMATCH", "The independently authored handler-to-Rule-ID map is not bijective with the central policy.");
  }

  const activeMappings = manifest.semanticRuleMap.filter(({ status }) => status === "active");
  if (activeMappings.some(({ handlerId }) => handlerId === null)) {
    fail("AUTHORITY_OWNERSHIP_HANDLER_MAP_MISMATCH", "Every active central rule must bind one implementation handler.");
  }
  const mappedHandlers = activeMappings.map(({ handlerId }) => handlerId).sort(compareUtf8);
  assertSortedUniqueStrings(mappedHandlers, "AUTHORITY_OWNERSHIP_HANDLER_MAP_MISMATCH", "active handler ids");
  const implementedHandlers = Object.keys(ruleHandlersForPolicyVersion(policy.policyVersion)).sort(compareUtf8);
  assertSameStringSet(
    mappedHandlers,
    implementedHandlers,
    "AUTHORITY_OWNERSHIP_HANDLER_MAP_MISMATCH",
    "The current implementation handler registry must map bijectively to active central Rule IDs."
  );

  const closurePaths = new Set(manifest.entrypoints.flatMap(({ moduleClosure }) => moduleClosure));
  for (const mapping of manifest.semanticRuleMap) {
    for (const consumer of mapping.consumers) {
      if (!closurePaths.has(consumer)) {
        fail("AUTHORITY_OWNERSHIP_RULE_CONSUMER_INVALID", `${mapping.ruleId} names ${consumer} outside the closed admission implementation.`);
      }
    }
  }
  const knownRuleIds = new Set(manifest.semanticRuleMap.map(({ ruleId }) => ruleId));
  const consumerRules = new Map();
  for (const mapping of manifest.semanticRuleMap) {
    for (const consumer of mapping.consumers) {
      if (!consumerRules.has(consumer)) consumerRules.set(consumer, []);
      consumerRules.get(consumer).push(mapping.ruleId);
    }
  }
  const ownershipByPath = new Map(manifest.moduleOwnership.map((ownership) => [ownership.path, ownership]));
  for (const [modulePath, ownership] of ownershipByPath) {
    const ownedRuleIds = ownership.semanticRuleIds;
    for (const ruleId of ownedRuleIds) {
      if (!knownRuleIds.has(ruleId)) fail("AUTHORITY_OWNERSHIP_MODULE_RULE_INVALID", `${modulePath} owns unknown central Rule ID ${ruleId}.`);
    }
    const expected = [...new Set(consumerRules.get(modulePath) ?? [])].sort(compareUtf8);
    if (canonicalAuthorityJson(ownedRuleIds) !== canonicalAuthorityJson(expected)) {
      fail("AUTHORITY_OWNERSHIP_MODULE_RULE_MISMATCH", `${modulePath} module ownership is not bijective with semanticRuleMap consumers.`);
    }
  }
}

function verifyProjectionOwnership({ manifest, classifiedFiles }) {
  const classified = new Set(classifiedFiles);
  const projectionPaths = manifest.publicProjections.map(({ path: projectionPath }) => projectionPath);
  const projectionClass = [
    ...manifest.fileClasses["current-admission-disclosure"],
    ...manifest.fileClasses["generated-public-projection"]
  ];
  assertSameStringSet(
    projectionPaths,
    projectionClass,
    "AUTHORITY_OWNERSHIP_PROJECTIONS_INVALID",
    "Every generated or public policy projection must be declared exactly once."
  );
  for (const projection of manifest.publicProjections) {
    if (!classified.has(projection.path)) fail("AUTHORITY_OWNERSHIP_PROJECTIONS_INVALID", `${projection.path} is not in the closed file inventory.`);
    for (const sourcePath of projection.sourcePaths) {
      if (!classified.has(sourcePath)) fail("AUTHORITY_OWNERSHIP_PROJECTIONS_INVALID", `${projection.path} names an unclassified source ${sourcePath}.`);
    }
  }
  const projectionsByPath = new Map(manifest.publicProjections.map((projection) => [projection.path, projection]));
  for (const compatibilityPath of APPLICANT_COMPATIBILITY_PATHS) {
    if (projectionsByPath.get(compatibilityPath)?.kind !== "public-contract") {
      fail(
        "AUTHORITY_OWNERSHIP_PROJECTIONS_INVALID",
        `${compatibilityPath} must remain an exact public compatibility contract projection.`
      );
    }
  }
  if (projectionsByPath.get(CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_PATH)?.kind !== "public-contract") {
    fail("AUTHORITY_OWNERSHIP_PROJECTIONS_INVALID", `${CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_PATH} must remain the public declarative V3 admission contract.`);
  }
  if (projectionsByPath.get(CUSTOM_LAUNCH_ADMISSION_SCHEMA_PATH)?.kind !== "public-schema") {
    fail("AUTHORITY_OWNERSHIP_PROJECTIONS_INVALID", `${CUSTOM_LAUNCH_ADMISSION_SCHEMA_PATH} must remain the public V3 admission schema.`);
  }
  if (projectionsByPath.get(CUSTOM_LAUNCH_ADMISSION_BINDING_PATH)?.kind !== "generated-discovery") {
    fail("AUTHORITY_OWNERSHIP_PROJECTIONS_INVALID", `${CUSTOM_LAUNCH_ADMISSION_BINDING_PATH} must remain the generated V3 admission digest binding.`);
  }
  for (const entrypointPath of manifest.orchestrationEntrypoints) {
    if (!classified.has(entrypointPath)) fail("AUTHORITY_OWNERSHIP_ORCHESTRATION_INVALID", `${entrypointPath} is not in the closed file inventory.`);
  }
}

function verifyEntrypointClosures({ manifest, observedFiles, repositoryRoot }) {
  const modulePaths = observedFiles.filter((relativePath) => relativePath.endsWith(".mjs"));
  const importGraph = inspectStaticImports({ modulePaths, repositoryRoot });
  const ownedFiles = new Set(observedFiles);
  const declaredEntrypoints = new Set(manifest.entrypoints.map(({ path: entrypointPath }) => entrypointPath));
  const compactContractsPresent = APPLICANT_COMPATIBILITY_PATHS.every((relativePath) => observedFiles.includes(relativePath));
  for (const entrypointPath of manifest.fileClasses["admission-entrypoint"]) {
    if (!declaredEntrypoints.has(entrypointPath)) {
      fail("AUTHORITY_OWNERSHIP_ENTRYPOINTS_INVALID", `${entrypointPath} is classified as an admission entrypoint but has no closure declaration.`);
    }
  }

  for (const entrypoint of manifest.entrypoints) {
    const actual = resolveEntrypointClosure({ entrypointPath: entrypoint.path, importGraph, ownedFiles, repositoryRoot });
    if (!compactContractsPresent && actual.frozenVendorImports.some((relativePath) => relativePath.startsWith(APPLICANT_VALIDATOR_PREFIX))) {
      fail(
        "AUTHORITY_OWNERSHIP_COMPACT_VENDOR_UNBOUND",
        `${entrypoint.id} imports a compact Applicant validator without both closed protected V1 and V2 compatibility contracts.`
      );
    }
    if (
      canonicalAuthorityJson(actual.moduleClosure) !== canonicalAuthorityJson(entrypoint.moduleClosure)
      || canonicalAuthorityJson(actual.frozenVendorImports) !== canonicalAuthorityJson(entrypoint.frozenVendorImports)
    ) {
      fail(
        "AUTHORITY_OWNERSHIP_IMPORT_CLOSURE_MISMATCH",
        `${entrypoint.id} imports a module outside its reviewed first-party or receipt-bound vendor closure.`
      );
    }
  }

  const firstPartyModules = new Set(manifest.entrypoints.flatMap(({ moduleClosure }) => moduleClosure));
  const moduleOwnershipPaths = manifest.moduleOwnership.map(({ path: modulePath }) => modulePath);
  assertSameStringSet(
    moduleOwnershipPaths,
    [...firstPartyModules],
    "AUTHORITY_OWNERSHIP_MODULE_SET_MISMATCH",
    "Every first-party admission runtime module must have one explicit ownership record."
  );
  const allowedModules = new Set([
    ...manifest.fileClasses["admission-entrypoint"],
    ...manifest.fileClasses["current-admission-implementation"],
    ...manifest.fileClasses["current-admission-support"],
    ...CONTROL_IMPLEMENTATION_PATHS
  ]);
  for (const modulePath of firstPartyModules) {
    if (!allowedModules.has(modulePath)) {
      fail("AUTHORITY_OWNERSHIP_IMPLEMENTATION_ORPHANED", `${modulePath} entered an admission closure without an approved implementation classification.`);
    }
  }
  for (const implementationPath of manifest.fileClasses["current-admission-implementation"]) {
    if (!firstPartyModules.has(implementationPath)) {
      fail("AUTHORITY_OWNERSHIP_IMPLEMENTATION_ORPHANED", `${implementationPath} is admission implementation outside every declared entrypoint closure.`);
    }
  }
  const ownershipByPath = new Map(manifest.moduleOwnership.map((ownership) => [ownership.path, ownership]));
  const runtimeControlPaths = [];
  const pureSupportPaths = [];
  for (const modulePath of firstPartyModules) {
    const ownership = ownershipByPath.get(modulePath);
    const inspection = importGraph[modulePath];
    if (!inspection || typeof inspection.pureSupport !== "boolean") {
      fail("AUTHORITY_OWNERSHIP_IMPORT_PARSE_FAILED", `${modulePath} is absent from the parsed module contract.`);
    }
    if (ownership.role === "runtime-control") {
      runtimeControlPaths.push(modulePath);
      continue;
    }
    if (ownership.role === "pure-support") {
      pureSupportPaths.push(modulePath);
    }
    if (ownership.role === "pure-support" && inspection.pureSupport !== true) {
      fail("AUTHORITY_OWNERSHIP_SUPPORT_SEMANTICS_FORBIDDEN", `${modulePath} has no Rule ID ownership and therefore may only re-export reviewed modules without executable statements.`);
    }
  }
  assertSameStringSet(
    runtimeControlPaths,
    [...CONTROL_IMPLEMENTATION_PATHS],
    "AUTHORITY_OWNERSHIP_CONTROL_MODULE_INVALID",
    "Runtime control ownership is an exact reviewed code boundary; a new module cannot self-classify as control logic."
  );
  assertSameStringSet(
    pureSupportPaths,
    [...PURE_SUPPORT_MODULES],
    "AUTHORITY_OWNERSHIP_SUPPORT_MODULE_INVALID",
    "Pure support ownership is an exact reviewed module boundary."
  );
}

function inspectStaticImports({ modulePaths, repositoryRoot }) {
  const result = childProcess.spawnSync(
    process.execPath,
    ["--expose-internals", "--eval", STATIC_IMPORT_INSPECTOR],
    {
      cwd: repositoryRoot,
      encoding: "utf8",
      env: { ...process.env },
      input: JSON.stringify({ paths: modulePaths, repositoryRoot }),
      maxBuffer: MAXIMUM_INSPECTOR_OUTPUT_BYTES,
      shell: false
    }
  );
  if (result.status !== 0) {
    fail("AUTHORITY_OWNERSHIP_IMPORT_PARSE_FAILED", "The admission ESM import graph could not be parsed.");
  }
  let graph;
  try {
    graph = JSON.parse(result.stdout);
  } catch (error) {
    fail("AUTHORITY_OWNERSHIP_IMPORT_PARSE_FAILED", "The admission ESM import graph returned invalid data.", error);
  }
  assertPlainObject(graph, "AUTHORITY_OWNERSHIP_IMPORT_PARSE_FAILED", "import graph");
  return graph;
}

function resolveEntrypointClosure({ entrypointPath, importGraph, ownedFiles, repositoryRoot }) {
  const firstParty = new Set();
  const vendorImports = new Set();
  const pending = [entrypointPath];
  while (pending.length > 0) {
    const relativePath = pending.pop();
    if (firstParty.has(relativePath)) continue;
    if (!ownedFiles.has(relativePath) || !relativePath.endsWith(".mjs")) {
      fail("AUTHORITY_OWNERSHIP_IMPORT_TARGET_INVALID", `${relativePath} is not an owned ESM implementation module.`);
    }
    firstParty.add(relativePath);
    const inspection = importGraph[relativePath];
    if (!inspection || !Array.isArray(inspection.specifiers) || typeof inspection.hasDynamicImport !== "boolean") {
      fail("AUTHORITY_OWNERSHIP_IMPORT_PARSE_FAILED", `${relativePath} is absent from the parsed import graph.`);
    }
    if (inspection.hasDynamicImport) {
      fail("AUTHORITY_OWNERSHIP_DYNAMIC_IMPORT_UNSUPPORTED", `${relativePath} uses dynamic import, which is outside the closed static admission graph.`);
    }
    for (const specifier of inspection.specifiers) {
      if (typeof specifier !== "string" || specifier.length < 1) fail("AUTHORITY_OWNERSHIP_IMPORT_PARSE_FAILED", `${relativePath} has an invalid import specifier.`);
      if (specifier.startsWith("node:")) continue;
      if (!specifier.startsWith(".")) {
        fail("AUTHORITY_OWNERSHIP_EXTERNAL_IMPORT_UNSUPPORTED", `${relativePath} imports unowned package ${specifier}.`);
      }
      const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(relativePath), specifier));
      assertSafeRepositoryPath(resolved, "AUTHORITY_OWNERSHIP_IMPORT_TARGET_INVALID", "resolved import");
      if (!resolved.endsWith(".mjs")) fail("AUTHORITY_OWNERSHIP_IMPORT_TARGET_INVALID", `${relativePath} imports a non-ESM local target ${resolved}.`);
      if (FROZEN_VENDOR_PREFIXES.some((prefix) => resolved.startsWith(prefix))) {
        vendorImports.add(resolved);
        continue;
      }
      if (!ownedFiles.has(resolved)) fail("AUTHORITY_OWNERSHIP_IMPORT_TARGET_INVALID", `${relativePath} imports unclassified module ${resolved}.`);
      pending.push(resolved);
    }
  }
  return {
    frozenVendorImports: [...vendorImports].sort(compareUtf8),
    moduleClosure: [...firstParty].sort(compareUtf8)
  };
}

function digestFile(repositoryRoot, relativePath) {
  return `sha256:${crypto.createHash("sha256").update(fs.readFileSync(resolveRepositoryPath(repositoryRoot, relativePath))).digest("hex")}`;
}

function requireRepositoryRoot(options) {
  if (!isPlainObject(options) || Object.keys(options).length !== 1 || typeof options.repositoryRoot !== "string" || options.repositoryRoot.length < 1) {
    fail("AUTHORITY_OWNERSHIP_ARGUMENTS_INVALID", "repositoryRoot is required.");
  }
  const repositoryRoot = path.resolve(options.repositoryRoot);
  let status;
  try {
    status = fs.lstatSync(repositoryRoot);
  } catch (error) {
    fail("AUTHORITY_OWNERSHIP_ARGUMENTS_INVALID", "repositoryRoot is unavailable.", error);
  }
  if (!status.isDirectory() || status.isSymbolicLink()) fail("AUTHORITY_OWNERSHIP_ARGUMENTS_INVALID", "repositoryRoot must be a real directory.");
  return repositoryRoot;
}

function resolveRepositoryPath(repositoryRoot, relativePath) {
  assertSafeRepositoryPath(relativePath, "AUTHORITY_OWNERSHIP_PATH_INVALID", "repository path");
  const resolved = path.resolve(repositoryRoot, ...relativePath.split("/"));
  if (!resolved.startsWith(`${repositoryRoot}${path.sep}`)) fail("AUTHORITY_OWNERSHIP_PATH_INVALID", `${relativePath} escapes the repository.`);
  return resolved;
}

function assertSafeRepositoryPath(relativePath, code, label) {
  if (
    typeof relativePath !== "string"
    || relativePath.length < 1
    || relativePath.length > 512
    || relativePath.includes("\\")
    || relativePath.includes("\0")
    || relativePath.includes("\n")
    || path.posix.normalize(relativePath) !== relativePath
    || path.posix.isAbsolute(relativePath)
    || relativePath === "."
    || relativePath.startsWith("../")
    || relativePath === ".git"
    || relativePath.startsWith(".git/")
  ) {
    fail(code, `${label} is not a canonical repository-relative path.`);
  }
}

function readRegularFile(absolutePath, maximumBytes, code) {
  let before;
  try {
    before = fs.lstatSync(absolutePath);
  } catch (error) {
    fail(code, `${absolutePath} is unavailable.`, error);
  }
  if (!before.isFile() || before.isSymbolicLink() || before.size < 1 || before.size > maximumBytes) {
    fail(code, `${absolutePath} must be a bounded regular file.`);
  }
  let bytes;
  try {
    bytes = fs.readFileSync(absolutePath);
  } catch (error) {
    fail(code, `${absolutePath} could not be read.`, error);
  }
  const after = fs.lstatSync(absolutePath);
  if (after.size !== before.size || after.mtimeMs !== before.mtimeMs || bytes.length !== before.size) {
    fail(code, `${absolutePath} changed while it was read.`);
  }
  return bytes;
}

function runGit(repositoryRoot, args, { environment = process.env } = {}) {
  const result = childProcess.spawnSync("git", args, {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: environment,
    maxBuffer: 64 * 1024 * 1024,
    shell: false
  });
  if (result.status !== 0) fail("AUTHORITY_OWNERSHIP_GIT_FAILED", `git ${args[0]} failed during authority verification.`);
  return result.stdout.trim();
}

function assertSortedUniquePaths(value, code, label) {
  if (!Array.isArray(value)) fail(code, `${label} must be an array.`);
  for (const relativePath of value) assertSafeRepositoryPath(relativePath, code, label);
  assertSortedUniqueStrings(value, code, label);
}

function assertSortedUniqueStrings(value, code, label) {
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) fail(code, `${label} must contain strings.`);
  const sorted = [...new Set(value)].sort(compareUtf8);
  if (canonicalAuthorityJson(value) !== canonicalAuthorityJson(sorted)) fail(code, `${label} must be sorted and duplicate-free.`);
}

function assertSameStringSet(actual, expected, code, message) {
  const actualSorted = [...new Set(actual)].sort(compareUtf8);
  const expectedSorted = [...new Set(expected)].sort(compareUtf8);
  if (actual.length !== actualSorted.length || expected.length !== expectedSorted.length || canonicalAuthorityJson(actualSorted) !== canonicalAuthorityJson(expectedSorted)) {
    fail(code, message);
  }
}

function assertPlainObject(value, code, label) {
  if (!isPlainObject(value)) fail(code, `${label} must be an object.`);
}

function assertExactKeys(value, expected, code, label) {
  assertPlainObject(value, code, label);
  assertSameStringSet(Object.keys(value), expected, code, `${label} must contain exactly the supported fields.`);
}

function assertEqual(actual, expected, code, label) {
  if (actual !== expected) fail(code, `${label} is invalid.`);
}

function compareUtf8(left, right) {
  return Buffer.from(left, "utf8").compare(Buffer.from(right, "utf8"));
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function fail(code, message, cause) {
  throw new LaunchPolicyAuthorityOwnershipError(code, message, cause ? { cause } : undefined);
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  try {
    const arguments_ = process.argv.slice(2);
    let result;
    if (arguments_.length === 1 && arguments_[0] === "--check") {
      result = verifyLaunchPolicyAuthorityOwnership({ repositoryRoot });
    } else if (arguments_.length === 1 && arguments_[0] === "--write") {
      result = writeLaunchPolicyAuthorityOwnershipHashes({ repositoryRoot });
    } else {
      fail("AUTHORITY_OWNERSHIP_CLI_USAGE_INVALID", "Usage: node scripts/launch-policy-authority-ownership.mjs --check | --write");
    }
    const { observedFiles: _observedFiles, ...publicResult } = result;
    process.stdout.write(`${canonicalAuthorityJson(publicResult)}\n`);
  } catch (error) {
    const code = error instanceof LaunchPolicyAuthorityOwnershipError ? error.code : "AUTHORITY_OWNERSHIP_CHECK_FAILED";
    const message = String(error?.message ?? "Authority-ownership verification failed.").slice(0, 1000);
    process.stdout.write(`${canonicalAuthorityJson({ error: { code, message }, ok: false })}\n`);
    process.exitCode = 1;
  }
}
