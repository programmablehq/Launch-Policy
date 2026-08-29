#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import {
  validateActiveContractManifestV1,
  validateActiveContractManifestV2
} from "./active-contract-manifest-core.mjs";
import {
  APPLICANT_COMPATIBILITY_V2_PATH,
  buildApplicantCompatibilityContractV2,
  canonicalApplicantJson
} from "./applicant-compatibility-core.mjs";
import {
  CUSTOM_LAUNCH_ADMISSION_BINDING_V3_PATH,
  buildCustomLaunchAdmissionBindingV3,
  verifyCustomLaunchAdmissionBindingV3
} from "./custom-launch-admission-v3-core.mjs";
import {
  CUSTOM_LAUNCH_ADMISSION_BINDING_V4_PATH,
  buildCustomLaunchAdmissionBindingV4,
  verifyCustomLaunchAdmissionBindingV4
} from "./custom-launch-admission-v4-core.mjs";
import {
  canonicalJson,
  parseLaunchPolicyBytes,
  renderLaunchPolicyMarkdown
} from "./launch-policy-core.mjs";

const POLICY_PATH = "policy/launch-policy.v1.json";
const RENDERED_POLICY_PATH = "docs/LAUNCH_POLICY.md";
const ACTIVE_CONTRACT_PATH = ".programmable/active-contract.json";
const ACTIVE_CONTRACT_V2_PATH = ".programmable/active-contract.v2.json";
const MAXIMUM_ARTIFACT_BYTES = 2 * 1024 * 1024;
export const ACTIVE_CONTRACT_ROLE_PATHS_V2 = Object.freeze({
  workflow: Object.freeze([".github/workflows/verify-hook-builder.yml"]),
  validator: Object.freeze([
    "review/launch-policy-review-core.mjs",
    "scripts/active-contract-manifest-core.mjs",
    "scripts/applicant-compatibility-core.mjs",
    "scripts/applicant-v3_2-scaffold-core.mjs",
    "scripts/applicant-v3_2-scaffold.mjs",
    "scripts/programmable-launch-router-readiness-core.mjs",
    "scripts/programmable-launch-router-readiness.mjs",
    "scripts/programmable-runtime-fee-settlement-proof-core.mjs",
    "scripts/programmable-runtime-fee-settlement-proof-validation.mjs",
    "scripts/registry-core.mjs",
    "scripts/verify-open-world-v2-contracts.mjs",
    "scripts/verify-open-world-v2-trade-manifest-v2.mjs",
    "scripts/verify-public-hook-application.mjs",
    "scripts/verify-public-application-v3-core.mjs",
    "scripts/verify-public-application-v3-shared.mjs",
    "scripts/verify-workflow-canary.mjs"
  ]),
  package: Object.freeze([
    ".programmable/applicant-compatibility.v2.json",
    "canary/schemas/workflow-canary-application-v1.schema.json",
    "canary/schemas/workflow-canary-result-v1.schema.json",
    "intake/schemas/active-contract-manifest-v2.schema.json",
    "intake/schemas/applicant-compatibility-v2.schema.json",
    "intake/schemas/open-world-submission-v2.1.schema.json",
    "intake/schemas/programmable-launch-router-readiness-v1.schema.json",
    "intake/schemas/public-pr-application-v3.2.schema.json",
    "intake/schemas/public-pr-application-v3.schema.json",
    "intake/schemas/trade-capability-manifest-v2.schema.json",
    "policy/schemas/launch-policy-binding.v1.schema.json",
    "policy/schemas/launch-policy.v1.schema.json",
    "policy/schemas/programmable-runtime-fee-settlement-proof-v1.schema.json",
    "registry/schema/launch-stamp-promotion-v1.schema.json",
    "review/schemas/launch-policy-review-decision.v1.schema.json",
    "review/schemas/launch-policy-review-input.v1.schema.json",
    "vendor/programmable-v4-hook-builder/references/public-pr-application.schema.json"
  ]),
  policy: Object.freeze([POLICY_PATH])
});
export const ACTIVE_CONTRACT_ROLE_PATHS_V1 = Object.freeze({
  workflow: Object.freeze([".github/workflows/verify-hook-builder.yml"]),
  validator: Object.freeze([
    "scripts/verify-public-hook-application.mjs",
    "scripts/verify-public-application-v3-core.mjs",
    "scripts/verify-public-application-v3-shared.mjs",
    "scripts/verify-workflow-canary.mjs"
  ]),
  package: Object.freeze([
    "canary/schemas/workflow-canary-application-v1.schema.json",
    "canary/schemas/workflow-canary-result-v1.schema.json",
    "intake/schemas/public-pr-application-v3.schema.json",
    "vendor/programmable-v4-hook-builder/references/public-pr-application.schema.json"
  ]),
  policy: Object.freeze([POLICY_PATH, ACTIVE_CONTRACT_V2_PATH])
});
const GENERATED_PATHS = Object.freeze([
  APPLICANT_COMPATIBILITY_V2_PATH,
  CUSTOM_LAUNCH_ADMISSION_BINDING_V3_PATH,
  CUSTOM_LAUNCH_ADMISSION_BINDING_V4_PATH,
  RENDERED_POLICY_PATH,
  ACTIVE_CONTRACT_PATH,
  ACTIVE_CONTRACT_V2_PATH
]);

export class LaunchPolicyArtifactError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.name = "LaunchPolicyArtifactError";
    this.code = code;
  }
}

export function readRepositoryLaunchPolicy(options) {
  const repositoryRoot = requireRepositoryRootOptions(options);
  return parseLaunchPolicyBytes(readRegularFile(repositoryRoot, POLICY_PATH, 512 * 1024));
}

export function buildLaunchPolicyArtifacts(options) {
  const repositoryRoot = requireRepositoryRootOptions(options);
  return buildArtifactState(repositoryRoot).artifacts;
}

function buildArtifactState(repositoryRoot) {
  const policyRecord = readRepositoryLaunchPolicy({ repositoryRoot });
  const applicantCompatibilityV2Source = `${canonicalApplicantJson(buildApplicantCompatibilityContractV2({ repositoryRoot }))}\n`;
  const customLaunchAdmissionBindingV3Source = `${canonicalJson(buildCustomLaunchAdmissionBindingV3({ repositoryRoot }))}\n`;
  const customLaunchAdmissionBindingV4Source = `${canonicalJson(buildCustomLaunchAdmissionBindingV4({ repositoryRoot }))}\n`;
  const activeContractV2 = validateActiveContractManifestV2({
    $schema: "urn:programmable:active-contract-manifest:2.0.0",
    schemaVersion: "2.0.0",
    kind: "programmable-active-contract",
    contractId: "launch-policy",
    defaultBranch: "main",
    artifacts: Object.fromEntries(Object.entries(ACTIVE_CONTRACT_ROLE_PATHS_V2).map(([role, paths]) => [
      role,
      paths.map((relativePath) => ({
        path: relativePath,
        sha256: relativePath === APPLICANT_COMPATIBILITY_V2_PATH
          ? digestBytes(Buffer.from(applicantCompatibilityV2Source, "utf8"))
          : digestBytes(readRegularFile(repositoryRoot, relativePath, MAXIMUM_ARTIFACT_BYTES))
      }))
    ]))
  }, { defaultBranch: "main" });
  const activeContractV2Source = `${canonicalJson(activeContractV2)}\n`;
  const activeContractV1 = validateActiveContractManifestV1({
    $schema: "urn:programmable:active-contract-manifest:1.0.0",
    schemaVersion: "1.0.0",
    kind: "programmable-active-contract",
    contractId: "launch-policy",
    defaultBranch: "main",
    artifacts: Object.fromEntries(Object.entries(ACTIVE_CONTRACT_ROLE_PATHS_V1).map(([role, paths]) => [
      role,
      paths.map((relativePath) => ({
        path: relativePath,
        sha256: relativePath === ACTIVE_CONTRACT_V2_PATH
          ? digestBytes(Buffer.from(activeContractV2Source, "utf8"))
          : digestBytes(readRegularFile(repositoryRoot, relativePath, MAXIMUM_ARTIFACT_BYTES))
      }))
    ]))
  }, { defaultBranch: "main" });

  return {
    artifacts: new Map([
      [APPLICANT_COMPATIBILITY_V2_PATH, applicantCompatibilityV2Source],
      [CUSTOM_LAUNCH_ADMISSION_BINDING_V3_PATH, customLaunchAdmissionBindingV3Source],
      [CUSTOM_LAUNCH_ADMISSION_BINDING_V4_PATH, customLaunchAdmissionBindingV4Source],
      [RENDERED_POLICY_PATH, renderLaunchPolicyMarkdown(policyRecord)],
      [ACTIVE_CONTRACT_V2_PATH, activeContractV2Source],
      [ACTIVE_CONTRACT_PATH, `${canonicalJson(activeContractV1)}\n`]
    ]),
    policyRecord
  };
}

export function verifyLaunchPolicyArtifacts(options) {
  const repositoryRoot = requireRepositoryRootOptions(options);
  const { artifacts: expectedArtifacts, policyRecord } = buildArtifactState(repositoryRoot);
  for (const [relativePath, expected] of expectedArtifacts) {
    let observed;
    try {
      observed = readRegularFile(repositoryRoot, relativePath, MAXIMUM_ARTIFACT_BYTES).toString("utf8");
    } catch (error) {
      if (error instanceof LaunchPolicyArtifactError) {
        throw new LaunchPolicyArtifactError(
          "LAUNCH_POLICY_ARTIFACT_STALE",
          `Generated launch-policy artifact ${relativePath} is missing or invalid. Run npm run policy:generate.`,
          { cause: error }
        );
      }
      throw error;
    }
    if (observed !== expected) {
      throw new LaunchPolicyArtifactError(
        "LAUNCH_POLICY_ARTIFACT_STALE",
        `Generated launch-policy artifact ${relativePath} is stale. Run npm run policy:generate.`
      );
    }
  }
  return Object.freeze({
    activeContractPath: ACTIVE_CONTRACT_PATH,
    customLaunchAdmission: verifyCustomLaunchAdmissionBindingV3({ repositoryRoot }),
    customLaunchAdmissionV4: verifyCustomLaunchAdmissionBindingV4({ repositoryRoot }),
    policyPath: POLICY_PATH,
    policySha256: policyRecord.sha256,
    renderedPolicyPath: RENDERED_POLICY_PATH
  });
}

export function writeLaunchPolicyArtifacts(options) {
  const repositoryRoot = requireRepositoryRootOptions(options);
  const artifacts = buildLaunchPolicyArtifacts({ repositoryRoot });
  for (const [relativePath, source] of artifacts) {
    writeGeneratedFile(repositoryRoot, relativePath, source);
  }
  return verifyLaunchPolicyArtifacts({ repositoryRoot });
}

function requireRepositoryRootOptions(options) {
  if (!isPlainObject(options) || !sameKeys(options, ["repositoryRoot"])) {
    throw new LaunchPolicyArtifactError(
      "LAUNCH_POLICY_ARTIFACT_ARGUMENTS_INVALID",
      "Launch-policy artifact operations accept only repositoryRoot."
    );
  }
  const { repositoryRoot } = options;
  if (typeof repositoryRoot !== "string" || !path.isAbsolute(repositoryRoot)) {
    throw new LaunchPolicyArtifactError(
      "LAUNCH_POLICY_ARTIFACT_ARGUMENTS_INVALID",
      "Launch-policy repositoryRoot must be an absolute path."
    );
  }
  let status;
  try {
    status = fs.lstatSync(repositoryRoot);
  } catch (error) {
    throw new LaunchPolicyArtifactError(
      "LAUNCH_POLICY_ARTIFACT_IO",
      "Launch-policy repository root is unavailable.",
      { cause: error }
    );
  }
  if (!status.isDirectory() || status.isSymbolicLink()) {
    throw new LaunchPolicyArtifactError(
      "LAUNCH_POLICY_ARTIFACT_IO",
      "Launch-policy repository root must be a regular directory."
    );
  }
  return repositoryRoot;
}

function readRegularFile(repositoryRoot, relativePath, maximumBytes) {
  const parentChain = snapshotRegularParentChain(repositoryRoot, relativePath);
  const absolutePath = path.join(repositoryRoot, relativePath);
  let status;
  try {
    status = fs.lstatSync(absolutePath);
  } catch (error) {
    throw new LaunchPolicyArtifactError(
      "LAUNCH_POLICY_ARTIFACT_IO",
      `Required repository file ${relativePath} is unavailable.`,
      { cause: error }
    );
  }
  if (!status.isFile() || status.isSymbolicLink() || status.size < 1 || status.size > maximumBytes) {
    throw new LaunchPolicyArtifactError(
      "LAUNCH_POLICY_ARTIFACT_IO",
      `Required repository file ${relativePath} must be a bounded regular file.`
    );
  }
  let descriptor;
  try {
    const noFollow = fs.constants.O_NOFOLLOW ?? 0;
    descriptor = fs.openSync(absolutePath, fs.constants.O_RDONLY | noFollow);
    const openedStatus = fs.fstatSync(descriptor);
    if (
      !openedStatus.isFile()
      || openedStatus.size < 1
      || openedStatus.size > maximumBytes
      || openedStatus.dev !== status.dev
      || openedStatus.ino !== status.ino
    ) {
      throw new LaunchPolicyArtifactError(
        "LAUNCH_POLICY_ARTIFACT_IO",
        `Required repository file ${relativePath} changed while it was read.`
      );
    }
    const bytes = fs.readFileSync(descriptor);
    if (bytes.length !== openedStatus.size) {
      throw new LaunchPolicyArtifactError(
        "LAUNCH_POLICY_ARTIFACT_IO",
        `Required repository file ${relativePath} changed while it was read.`
      );
    }
    assertRegularParentChain(parentChain, relativePath);
    return bytes;
  } catch (error) {
    if (error instanceof LaunchPolicyArtifactError) throw error;
    throw new LaunchPolicyArtifactError(
      "LAUNCH_POLICY_ARTIFACT_IO",
      `Required repository file ${relativePath} could not be read.`,
      { cause: error }
    );
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function snapshotRegularParentChain(repositoryRoot, relativePath) {
  const segments = relativePath.split("/");
  if (
    path.isAbsolute(relativePath)
    || segments.some((segment) => segment === "" || segment === "." || segment === "..")
  ) {
    throw new LaunchPolicyArtifactError(
      "LAUNCH_POLICY_ARTIFACT_IO",
      `Required repository file ${relativePath} has an invalid parent path.`
    );
  }
  const chain = [];
  let current = repositoryRoot;
  for (const segment of segments.slice(0, -1)) {
    current = path.join(current, segment);
    let status;
    try {
      status = fs.lstatSync(current);
    } catch (error) {
      throw new LaunchPolicyArtifactError(
        "LAUNCH_POLICY_ARTIFACT_IO",
        `Required repository file ${relativePath} has an unavailable parent directory.`,
        { cause: error }
      );
    }
    if (!status.isDirectory() || status.isSymbolicLink()) {
      throw new LaunchPolicyArtifactError(
        "LAUNCH_POLICY_ARTIFACT_IO",
        `Required repository file ${relativePath} must remain below regular repository directories.`
      );
    }
    chain.push(Object.freeze({ absolutePath: current, dev: status.dev, ino: status.ino }));
  }
  return Object.freeze(chain);
}

function assertRegularParentChain(chain, relativePath) {
  for (const expected of chain) {
    let observed;
    try {
      observed = fs.lstatSync(expected.absolutePath);
    } catch (error) {
      throw new LaunchPolicyArtifactError(
        "LAUNCH_POLICY_ARTIFACT_IO",
        `Required repository file ${relativePath} changed while it was read.`,
        { cause: error }
      );
    }
    if (
      !observed.isDirectory()
      || observed.isSymbolicLink()
      || observed.dev !== expected.dev
      || observed.ino !== expected.ino
    ) {
      throw new LaunchPolicyArtifactError(
        "LAUNCH_POLICY_ARTIFACT_IO",
        `Required repository file ${relativePath} changed while it was read.`
      );
    }
  }
}

function writeGeneratedFile(repositoryRoot, relativePath, source) {
  if (!GENERATED_PATHS.includes(relativePath)) {
    throw new LaunchPolicyArtifactError(
      "LAUNCH_POLICY_ARTIFACT_PATH_INVALID",
      "The launch-policy generator attempted to write outside its fixed artifact set."
    );
  }
  const parent = path.dirname(relativePath);
  ensureRegularDirectory(repositoryRoot, parent);
  const absolutePath = path.join(repositoryRoot, relativePath);
  if (fs.existsSync(absolutePath)) {
    const status = fs.lstatSync(absolutePath);
    if (!status.isFile() || status.isSymbolicLink()) {
      throw new LaunchPolicyArtifactError(
        "LAUNCH_POLICY_ARTIFACT_IO",
        `Generated artifact target ${relativePath} must be a regular file.`
      );
    }
  }
  const temporaryPath = `${absolutePath}.tmp-${process.pid}-${crypto.randomUUID()}`;
  try {
    fs.writeFileSync(temporaryPath, source, { encoding: "utf8", flag: "wx", mode: 0o644 });
    fs.renameSync(temporaryPath, absolutePath);
  } catch (error) {
    if (fs.existsSync(temporaryPath)) fs.unlinkSync(temporaryPath);
    if (error instanceof LaunchPolicyArtifactError) throw error;
    throw new LaunchPolicyArtifactError(
      "LAUNCH_POLICY_ARTIFACT_IO",
      `Generated artifact ${relativePath} could not be written.`,
      { cause: error }
    );
  }
}

function ensureRegularDirectory(repositoryRoot, relativeDirectory) {
  let current = repositoryRoot;
  for (const segment of relativeDirectory.split("/").filter(Boolean)) {
    current = path.join(current, segment);
    if (!fs.existsSync(current)) {
      fs.mkdirSync(current, { mode: 0o755 });
      continue;
    }
    const status = fs.lstatSync(current);
    if (!status.isDirectory() || status.isSymbolicLink()) {
      throw new LaunchPolicyArtifactError(
        "LAUNCH_POLICY_ARTIFACT_IO",
        `Generated artifact parent ${relativeDirectory} must be a regular directory.`
      );
    }
  }
}

function digestBytes(bytes) {
  return `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function sameKeys(value, expected) {
  return isPlainObject(value)
    && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort());
}

async function main() {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const arguments_ = process.argv.slice(2);
  if (arguments_.length !== 1 || !new Set(["--check", "--write"]).has(arguments_[0])) {
    throw new LaunchPolicyArtifactError(
      "LAUNCH_POLICY_GENERATOR_USAGE_INVALID",
      "Usage: node scripts/generate-launch-policy-artifacts.mjs --check|--write"
    );
  }
  const result = arguments_[0] === "--write"
    ? writeLaunchPolicyArtifacts({ repositoryRoot: root })
    : verifyLaunchPolicyArtifacts({ repositoryRoot: root });
  process.stdout.write(`${canonicalJson({ ...result, mode: arguments_[0].slice(2), ok: true })}\n`);
}

const isEntrypoint = process.argv[1]
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isEntrypoint) {
  main().catch((error) => {
    const code = typeof error?.code === "string" ? error.code : "LAUNCH_POLICY_GENERATOR_FAILED";
    const message = String(error?.message ?? "Launch-policy artifact generation failed.").slice(0, 1000);
    process.stderr.write(`${canonicalJson({ error: { code, message }, ok: false })}\n`);
    process.exitCode = 1;
  });
}
