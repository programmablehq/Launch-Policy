import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { TextDecoder } from "node:util";

import { parseBoundedLosslessJson } from "../vendor/programmable-v4-hook-builder/scripts/github-public-source-lossless-json.mjs";

export const APPLICANT_COMPATIBILITY_PATH = ".programmable/applicant-compatibility.v1.json";
export const APPLICANT_COMPATIBILITY_SCHEMA_PATH = "intake/schemas/applicant-compatibility-v1.schema.json";
export const APPLICANT_COMPATIBILITY_V2_PATH = ".programmable/applicant-compatibility.v2.json";
export const APPLICANT_COMPATIBILITY_V2_SCHEMA_PATH = "intake/schemas/applicant-compatibility-v2.schema.json";
export const APPLICANT_VALIDATOR_RECEIPT_SCHEMA_PATH = "intake/schemas/applicant-validator-package-receipt-v1.schema.json";
export const APPLICANT_VALIDATOR_ROOT = "vendor/programmable-applicant-validator";
export const APPLICANT_VALIDATOR_ENTRYPOINT = `${APPLICANT_VALIDATOR_ROOT}/scripts/public-applicant-validator.mjs`;
export const APPLICANT_VALIDATOR_RECEIPT_PATH = `${APPLICANT_VALIDATOR_ROOT}/validator-package-receipt.v1.json`;

const APPLICATION_SCHEMA_PATH = "intake/schemas/public-pr-application-v3.schema.json";
const V2_APPLICATION_SCHEMA_PATH = "intake/schemas/public-pr-application-v3.2.schema.json";
const V2_SUBMISSION_SCHEMA_PATH = "intake/schemas/open-world-submission-v2.1.schema.json";
const V2_TRADE_CAPABILITY_SCHEMA_PATH = "intake/schemas/trade-capability-manifest-v2.schema.json";
const V2_ROUTER_READINESS_SCHEMA_PATH = "intake/schemas/programmable-launch-router-readiness-v1.schema.json";
const V2_ROUTER_READINESS_CORE_PATH = "scripts/programmable-launch-router-readiness-core.mjs";
const V2_ROUTER_READINESS_CLI_PATH = "scripts/programmable-launch-router-readiness.mjs";
const V2_ROUTER_READINESS_EVM_ENCODING_PATH = "vendor/programmable-applicant-validator/scripts/evm-encoding-core.mjs";
const V2_ROUTER_READINESS_LOSSLESS_JSON_PATH = "vendor/programmable-v4-hook-builder/scripts/github-public-source-lossless-json.mjs";
const REPOSITORY_NAME = "0xprogrammable/launch-policy";
const REPOSITORY_NUMERIC_ID = "1320171831";
const DEFAULT_BRANCH = "main";
const COMPATIBILITY_SCHEMA = "urn:programmable:applicant-compatibility:1.0.0";
const V2_COMPATIBILITY_SCHEMA = "urn:programmable:applicant-compatibility:2.0.0";
const COMPATIBILITY_KIND = "programmable-applicant-compatibility";
const RECEIPT_SCHEMA = "urn:programmable:applicant-validator-package-receipt:1.0.0";
const RECEIPT_KIND = "programmable-applicant-validator-package-receipt";
const RECEIPT_ALGORITHM = "sha256-path-nul-size-nul-content-nul-v1";
const COMPACT_ENTRYPOINT = "scripts/public-applicant-validator.mjs";
const SCHEMA_VERSION = "1.0.0";
const V2_SCHEMA_VERSION = "2.0.0";
const MINIMUM_BUILDER_PROTOCOL_VERSION = "1.0.0";
const MAXIMUM_COMPATIBILITY_BYTES = 256 * 1024;
const MAXIMUM_RECEIPT_BYTES = 1024 * 1024;
const MAXIMUM_PACKAGE_FILE_BYTES = 4 * 1024 * 1024;
const MAXIMUM_PACKAGE_BYTES = 16 * 1024 * 1024;
const MAXIMUM_PACKAGE_FILES = 256;
const SHA256 = /^sha256:[0-9a-f]{64}$/u;
const OBJECT_ID = /^[0-9a-f]{40}$/u;
const SEMVER = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u;
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
const LEGACY_ACTIVE_CONTRACT_SHA256 = "sha256:b2a610c6e8e682df8dad0549827c1b8e7712299e1b523778cd6e34523244f7e0";
const LEGACY_APPLICATION_SCHEMA_SHA256 = "sha256:2d51837bbbfe52672ecca334596243bebcec78e8e0a885d67084dfd98955bcb7";
const LEGACY_VENDOR_RECEIPT = Object.freeze({
  commit: "7869f44aa8dcc7cefeb379b76118407d53384558",
  release: "v0.10.3",
  repository: "0xprogrammable/hookbuilder",
  schemaVersion: "1.0.0",
  skillTree: "3b974b0bcb006e08d8f2504c783ac81f2ee3bd74",
  source: "https://github.com/0xprogrammable/hookbuilder/tree/7869f44aa8dcc7cefeb379b76118407d53384558/skills/programmable-v4-hook-builder"
});
const CAPABILITY_IDS = Object.freeze([
  "draft-transport:create",
  "draft-transport:update",
  "missing-object-recovery",
  "source-closure:inline",
  "source-closure:manifest",
  "unreviewed-draft-only"
]);
const V2_CAPABILITY_IDS = Object.freeze([
  "draft-transport:create",
  "draft-transport:update",
  "launch-readiness:offline-check",
  "unreviewed-draft-only"
]);

export class ApplicantCompatibilityError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.name = "ApplicantCompatibilityError";
    this.code = code;
  }
}

export function canonicalApplicantJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) fail("APPLICANT_COMPATIBILITY_CANONICAL_JSON_INVALID", "Canonical Applicant JSON supports only safe integers.");
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map((item) => canonicalApplicantJson(item)).join(",")}]`;
  if (isPlainObject(value)) {
    return `{${Object.keys(value).sort(compareUtf8).map((key) => `${JSON.stringify(key)}:${canonicalApplicantJson(value[key])}`).join(",")}}`;
  }
  fail("APPLICANT_COMPATIBILITY_CANONICAL_JSON_INVALID", "Canonical Applicant JSON contains an unsupported value.");
}

export function buildApplicantCompatibilityContractV2(options) {
  assertExactKeys(options, ["repositoryRoot"], "APPLICANT_COMPATIBILITY_ARGUMENTS_INVALID", "options");
  const repositoryRoot = requireRepositoryRoot(options.repositoryRoot);
  const artifact = (contractId, relativePath) => ({
    contractId,
    path: relativePath,
    sha256: digestBytes(readRegularFile(
      resolveRepositoryPath(repositoryRoot, relativePath),
      MAXIMUM_PACKAGE_FILE_BYTES,
      "APPLICANT_COMPATIBILITY_V2_GENERATION_INPUT_INVALID"
    ))
  });
  const validatorPaths = [
    V2_ROUTER_READINESS_CORE_PATH,
    V2_ROUTER_READINESS_CLI_PATH,
    V2_ROUTER_READINESS_EVM_ENCODING_PATH,
    V2_ROUTER_READINESS_LOSSLESS_JSON_PATH
  ].sort(compareUtf8);
  const validatorBytes = new Map(validatorPaths.map((relativePath) => [
    relativePath,
    readRegularFile(
      resolveRepositoryPath(repositoryRoot, relativePath),
      MAXIMUM_PACKAGE_FILE_BYTES,
      "APPLICANT_COMPATIBILITY_V2_GENERATION_INPUT_INVALID"
    )
  ]));
  const validatorFiles = validatorPaths.map((relativePath) => ({
    path: relativePath,
    sha256: digestBytes(validatorBytes.get(relativePath))
  }));
  const closure = crypto.createHash("sha256");
  for (const { path: relativePath } of validatorFiles) {
    const bytes = validatorBytes.get(relativePath);
    closure.update(Buffer.from(relativePath, "utf8"));
    closure.update(Buffer.from([0]));
    closure.update(Buffer.from(String(bytes.byteLength), "ascii"));
    closure.update(Buffer.from([0]));
    closure.update(bytes);
    closure.update(Buffer.from([0]));
  }

  const compatibility = {
    $schema: V2_COMPATIBILITY_SCHEMA,
    application: {
      current: artifact("public-pr-application-v3.2", V2_APPLICATION_SCHEMA_PATH),
      legacy: [artifact("public-pr-application-v3.1", APPLICATION_SCHEMA_PATH)]
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
    capabilities: v2CapabilityShape(),
    kind: COMPATIBILITY_KIND,
    minimumBuilderProtocolVersion: MINIMUM_BUILDER_PROTOCOL_VERSION,
    schemaVersion: V2_SCHEMA_VERSION,
    supportingContracts: {
      routerReadiness: {
        schema: artifact("programmable-launch-router-readiness-v1", V2_ROUTER_READINESS_SCHEMA_PATH),
        validatorClosure: {
          algorithm: RECEIPT_ALGORITHM,
          closureSha256: `sha256:${closure.digest("hex")}`,
          files: validatorFiles
        }
      },
      submission: artifact("open-world-submission-v2.1", V2_SUBMISSION_SCHEMA_PATH),
      tradeCapabilityManifest: artifact("trade-capability-manifest-v2", V2_TRADE_CAPABILITY_SCHEMA_PATH)
    },
    trustedRepository: {
      defaultBranch: DEFAULT_BRANCH,
      numericId: REPOSITORY_NUMERIC_ID
    }
  };
  validateCompatibilityShapeV2(compatibility);
  return deepFreeze(compatibility);
}

export function parseApplicantCompatibilityBytesV1(bytes) {
  const { source, value } = parseCanonicalJsonBytes(bytes, MAXIMUM_COMPATIBILITY_BYTES, "APPLICANT_COMPATIBILITY");
  validateCompatibilityShape(value);
  return Object.freeze({
    compatibility: deepFreeze(value),
    manifestSha256: digestBytes(Buffer.from(source, "utf8"))
  });
}

export function parseApplicantCompatibilityBytesV2(bytes) {
  const { source, value } = parseCanonicalJsonBytes(bytes, MAXIMUM_COMPATIBILITY_BYTES, "APPLICANT_COMPATIBILITY_V2");
  validateCompatibilityShapeV2(value);
  return Object.freeze({
    compatibility: deepFreeze(value),
    manifestSha256: digestBytes(Buffer.from(source, "utf8"))
  });
}

export function parseApplicantValidatorReceiptBytesV1(bytes) {
  const { value } = parseCanonicalJsonBytes(bytes, MAXIMUM_RECEIPT_BYTES, "APPLICANT_VALIDATOR_RECEIPT");
  validateReceiptShape(value);
  return deepFreeze(value);
}

export function verifyApplicantCompatibilityContract(options) {
  assertExactKeys(options, ["allowLegacyFallback", "repositoryRoot"], "APPLICANT_COMPATIBILITY_ARGUMENTS_INVALID", "options");
  const repositoryRoot = requireRepositoryRoot(options.repositoryRoot);
  if (typeof options.allowLegacyFallback !== "boolean") {
    fail("APPLICANT_COMPATIBILITY_ARGUMENTS_INVALID", "allowLegacyFallback must be a boolean.");
  }
  const v2ManifestPath = resolveRepositoryPath(repositoryRoot, APPLICANT_COMPATIBILITY_V2_PATH);
  const v2ManifestStatus = lstatOptional(v2ManifestPath);
  if (v2ManifestStatus !== null) {
    assertRegularFileStatus(v2ManifestStatus, "APPLICANT_COMPATIBILITY_V2_FILE_INVALID", "The Applicant compatibility V2 contract");
    return verifyApplicantCompatibilityContractV2({ repositoryRoot });
  }
  const manifestPath = resolveRepositoryPath(repositoryRoot, APPLICANT_COMPATIBILITY_PATH);
  const manifestStatus = lstatOptional(manifestPath);
  if (manifestStatus === null) {
    if (!options.allowLegacyFallback) {
      fail("APPLICANT_COMPATIBILITY_MISSING", "The protected base does not publish the Applicant compatibility contract.");
    }
    return verifyLegacyFallback(repositoryRoot);
  }
  assertRegularFileStatus(manifestStatus, "APPLICANT_COMPATIBILITY_FILE_INVALID", "The Applicant compatibility contract");
  const parsed = parseApplicantCompatibilityBytesV1(fs.readFileSync(manifestPath));
  verifyApplicationSchemaBinding(repositoryRoot, parsed.compatibility.application);
  const validatorPackage = verifyApplicantValidatorPackageV1({
    compatibility: parsed.compatibility,
    repositoryRoot
  });
  return deepFreeze({
    compatibility: parsed.compatibility,
    manifestSha256: parsed.manifestSha256,
    mode: "declared-compact-validator-v1",
    validatorPackage
  });
}

export function verifyApplicantCompatibilityContractV2(options) {
  assertExactKeys(options, ["repositoryRoot"], "APPLICANT_COMPATIBILITY_V2_ARGUMENTS_INVALID", "options");
  const repositoryRoot = requireRepositoryRoot(options.repositoryRoot);
  const manifestPath = resolveRepositoryPath(repositoryRoot, APPLICANT_COMPATIBILITY_V2_PATH);
  const manifestStatus = lstatOptional(manifestPath);
  if (manifestStatus === null) {
    fail("APPLICANT_COMPATIBILITY_V2_MISSING", "The protected base does not publish the current Applicant compatibility V2 contract.");
  }
  assertRegularFileStatus(manifestStatus, "APPLICANT_COMPATIBILITY_V2_FILE_INVALID", "The Applicant compatibility V2 contract");
  const parsed = parseApplicantCompatibilityBytesV2(fs.readFileSync(manifestPath));
  verifyV2ApplicationAndSupportingContracts(repositoryRoot, parsed.compatibility);
  return deepFreeze({
    compatibility: parsed.compatibility,
    manifestSha256: parsed.manifestSha256,
    mode: "declared-readiness-contract-v2"
  });
}

export function verifyApplicantValidatorPackageV1(options) {
  assertExactKeys(options, ["compatibility", "repositoryRoot"], "APPLICANT_VALIDATOR_PACKAGE_ARGUMENTS_INVALID", "options");
  const repositoryRoot = requireRepositoryRoot(options.repositoryRoot);
  validateCompatibilityShape(options.compatibility);
  const binding = options.compatibility.validatorPackage;
  const packageRoot = resolveRepositoryPath(repositoryRoot, binding.rootPath);
  const rootStatus = lstatOptional(packageRoot);
  if (rootStatus === null || !rootStatus.isDirectory() || rootStatus.isSymbolicLink()) {
    fail("APPLICANT_VALIDATOR_PACKAGE_MISSING", "The receipt-bound compact Applicant validator package is missing.");
  }
  const receiptPath = resolveRepositoryPath(repositoryRoot, binding.receiptPath);
  const receiptStatus = lstatOptional(receiptPath);
  if (receiptStatus === null) fail("APPLICANT_VALIDATOR_RECEIPT_MISSING", "The compact Applicant validator receipt is missing.");
  assertRegularFileStatus(receiptStatus, "APPLICANT_VALIDATOR_RECEIPT_INVALID", "The compact Applicant validator receipt");
  const receipt = parseApplicantValidatorReceiptBytesV1(fs.readFileSync(receiptPath));
  if (receipt.closureSha256 !== binding.closureSha256) {
    fail("APPLICANT_VALIDATOR_CLOSURE_BINDING_MISMATCH", "The compatibility contract and compact validator receipt bind different closures.");
  }
  if (`${binding.rootPath}/${receipt.entrypoint}` !== binding.entrypointPath) {
    fail("APPLICANT_VALIDATOR_ENTRYPOINT_BINDING_MISMATCH", "The compatibility contract and compact validator receipt bind different entrypoints.");
  }

  const observedPaths = listPackageFiles(packageRoot).filter((relativePath) => relativePath !== "validator-package-receipt.v1.json");
  const declaredPaths = receipt.files.map((record) => record.path);
  if (!sameStringArray(observedPaths, declaredPaths)) {
    fail("APPLICANT_VALIDATOR_PACKAGE_FILE_SET_MISMATCH", "The compact Applicant validator package contains bytes outside its closed receipt.");
  }
  const closure = crypto.createHash("sha256");
  let totalBytes = 0;
  for (const record of receipt.files) {
    const absolutePath = resolvePackagePath(packageRoot, record.path);
    const status = fs.lstatSync(absolutePath);
    assertRegularFileStatus(status, "APPLICANT_VALIDATOR_PACKAGE_FILE_INVALID", `Compact validator file ${record.path}`);
    const bytes = fs.readFileSync(absolutePath);
    if (bytes.byteLength !== record.byteLength) {
      fail("APPLICANT_VALIDATOR_PACKAGE_FILE_SIZE_MISMATCH", `${record.path} does not match its receipt byte length.`);
    }
    if (digestBytes(bytes) !== record.sha256) {
      fail("APPLICANT_VALIDATOR_PACKAGE_FILE_SHA256_MISMATCH", `${record.path} does not match its receipt SHA-256.`);
    }
    totalBytes += bytes.byteLength;
    closure.update(Buffer.from(record.path, "utf8"));
    closure.update(Buffer.from([0]));
    closure.update(Buffer.from(String(bytes.byteLength), "ascii"));
    closure.update(Buffer.from([0]));
    closure.update(bytes);
    closure.update(Buffer.from([0]));
  }
  const closureSha256 = `sha256:${closure.digest("hex")}`;
  if (closureSha256 !== receipt.closureSha256) {
    fail("APPLICANT_VALIDATOR_PACKAGE_CLOSURE_MISMATCH", "The compact Applicant validator bytes do not match the receipt closure.");
  }
  if (receipt.fileCount !== receipt.files.length || receipt.totalBytes !== totalBytes) {
    fail("APPLICANT_VALIDATOR_PACKAGE_TOTAL_MISMATCH", "The compact Applicant validator receipt totals do not match its files.");
  }
  return deepFreeze({
    authority: receipt.authority,
    closureSha256,
    entrypointPath: binding.entrypointPath,
    fileCount: receipt.fileCount,
    receiptSha256: digestBytes(fs.readFileSync(receiptPath)),
    totalBytes
  });
}

export function verifyApplicantCompatibilityReadbackV1(options) {
  assertExactKeys(options, [
    "builderProtocolVersion",
    "bytes",
    "exactBaseCommit",
    "expectedDefaultBranch",
    "expectedRepositoryNumericId",
    "requiredCapabilities"
  ], "APPLICANT_COMPATIBILITY_READBACK_ARGUMENTS_INVALID", "options");
  if (!OBJECT_ID.test(options.exactBaseCommit ?? "")) {
    fail("APPLICANT_COMPATIBILITY_BASE_INVALID", "The compatibility readback must bind one exact lowercase base commit.");
  }
  if (!SEMVER.test(options.builderProtocolVersion ?? "")) {
    fail("APPLICANT_COMPATIBILITY_PROTOCOL_INVALID", "The Builder protocol version must be exact SemVer.");
  }
  if (!Array.isArray(options.requiredCapabilities)) {
    fail("APPLICANT_COMPATIBILITY_CAPABILITIES_INVALID", "requiredCapabilities must be an array.");
  }
  const parsed = parseApplicantCompatibilityBytesV1(options.bytes);
  const compatibility = parsed.compatibility;
  if (
    compatibility.trustedRepository.numericId !== options.expectedRepositoryNumericId
    || compatibility.trustedRepository.defaultBranch !== options.expectedDefaultBranch
  ) {
    fail("APPLICANT_COMPATIBILITY_REPOSITORY_MISMATCH", "The exact-base compatibility contract belongs to a different trusted repository.");
  }
  if (compareSemver(options.builderProtocolVersion, compatibility.minimumBuilderProtocolVersion) < 0) {
    fail("APPLICANT_COMPATIBILITY_PROTOCOL_UNSUPPORTED", "The installed Builder protocol is older than the protected base minimum.");
  }
  const required = [...new Set(options.requiredCapabilities)];
  if (required.length !== options.requiredCapabilities.length || required.some((value) => typeof value !== "string")) {
    fail("APPLICANT_COMPATIBILITY_CAPABILITIES_INVALID", "Required capabilities must be unique strings.");
  }
  for (const capability of required) {
    if (!CAPABILITY_IDS.includes(capability)) {
      fail("APPLICANT_COMPATIBILITY_CAPABILITY_UNSUPPORTED", `The protected base does not declare capability ${capability}.`);
    }
  }
  return deepFreeze({
    application: compatibility.application,
    capabilities: compatibility.capabilities,
    exactBaseCommit: options.exactBaseCommit,
    manifestSha256: parsed.manifestSha256,
    minimumBuilderProtocolVersion: compatibility.minimumBuilderProtocolVersion,
    result: "compatible-protected-applicant-contract",
    trustedRepository: compatibility.trustedRepository,
    validatorPackage: compatibility.validatorPackage
  });
}

export function verifyApplicantCompatibilityReadbackV2(options) {
  assertExactKeys(options, [
    "builderProtocolVersion",
    "bytes",
    "exactBaseCommit",
    "expectedDefaultBranch",
    "expectedRepositoryNumericId",
    "requiredCapabilities"
  ], "APPLICANT_COMPATIBILITY_V2_READBACK_ARGUMENTS_INVALID", "options");
  if (!OBJECT_ID.test(options.exactBaseCommit ?? "")) {
    fail("APPLICANT_COMPATIBILITY_V2_BASE_INVALID", "The compatibility V2 readback must bind one exact lowercase base commit.");
  }
  if (!SEMVER.test(options.builderProtocolVersion ?? "")) {
    fail("APPLICANT_COMPATIBILITY_V2_PROTOCOL_INVALID", "The Builder protocol version must be exact SemVer.");
  }
  if (!Array.isArray(options.requiredCapabilities)) {
    fail("APPLICANT_COMPATIBILITY_V2_CAPABILITIES_INVALID", "requiredCapabilities must be an array.");
  }
  const parsed = parseApplicantCompatibilityBytesV2(options.bytes);
  const compatibility = parsed.compatibility;
  if (
    compatibility.trustedRepository.numericId !== options.expectedRepositoryNumericId
    || compatibility.trustedRepository.defaultBranch !== options.expectedDefaultBranch
  ) {
    fail("APPLICANT_COMPATIBILITY_V2_REPOSITORY_MISMATCH", "The exact-base compatibility V2 contract belongs to a different trusted repository.");
  }
  if (compareSemver(options.builderProtocolVersion, compatibility.minimumBuilderProtocolVersion) < 0) {
    fail("APPLICANT_COMPATIBILITY_V2_PROTOCOL_UNSUPPORTED", "The installed Builder protocol is older than the protected base V2 minimum.");
  }
  const required = [...new Set(options.requiredCapabilities)];
  if (required.length !== options.requiredCapabilities.length || required.some((value) => typeof value !== "string")) {
    fail("APPLICANT_COMPATIBILITY_V2_CAPABILITIES_INVALID", "Required V2 capabilities must be unique strings.");
  }
  for (const capability of required) {
    if (!V2_CAPABILITY_IDS.includes(capability)) {
      fail("APPLICANT_COMPATIBILITY_V2_CAPABILITY_UNSUPPORTED", `The protected base does not declare V2 capability ${capability}.`);
    }
  }
  return deepFreeze({
    application: compatibility.application,
    capabilities: compatibility.capabilities,
    exactBaseCommit: options.exactBaseCommit,
    manifestSha256: parsed.manifestSha256,
    minimumBuilderProtocolVersion: compatibility.minimumBuilderProtocolVersion,
    result: "compatible-protected-applicant-readiness-contract-v2",
    supportingContracts: compatibility.supportingContracts,
    trustedRepository: compatibility.trustedRepository
  });
}

export function verifyApplicantCompatibilityReadback(options) {
  if (!isPlainObject(options) || !Buffer.isBuffer(options.bytes) && !(options.bytes instanceof Uint8Array)) {
    fail("APPLICANT_COMPATIBILITY_READBACK_ARGUMENTS_INVALID", "Compatibility readback requires an options object with bytes.");
  }
  const { value } = parseCanonicalJsonBytes(options.bytes, MAXIMUM_COMPATIBILITY_BYTES, "APPLICANT_COMPATIBILITY");
  if (value?.$schema === V2_COMPATIBILITY_SCHEMA) return verifyApplicantCompatibilityReadbackV2(options);
  if (value?.$schema === COMPATIBILITY_SCHEMA) return verifyApplicantCompatibilityReadbackV1(options);
  fail("APPLICANT_COMPATIBILITY_UNSUPPORTED_VERSION", "The compatibility readback accepts only exact V1 or V2 contracts.");
}

function verifyLegacyFallback(repositoryRoot) {
  const activeContractPath = resolveRepositoryPath(repositoryRoot, ".programmable/active-contract.json");
  const activeContractBytes = readRegularFile(activeContractPath, MAXIMUM_COMPATIBILITY_BYTES, "APPLICANT_COMPATIBILITY_LEGACY_ACTIVE_CONTRACT_INVALID");
  if (digestBytes(activeContractBytes) !== LEGACY_ACTIVE_CONTRACT_SHA256) {
    fail("APPLICANT_COMPATIBILITY_LEGACY_ACTIVE_CONTRACT_MISMATCH", "A compatibility-less base is allowed only for the exact released v1.6.3 active contract.");
  }
  const { value: activeContract } = parseCanonicalJsonBytes(activeContractBytes, MAXIMUM_COMPATIBILITY_BYTES, "APPLICANT_COMPATIBILITY_LEGACY_ACTIVE_CONTRACT");
  const applicationBinding = activeContract?.artifacts?.package?.find?.((artifact) => artifact?.path === APPLICATION_SCHEMA_PATH);
  if (applicationBinding?.sha256 !== LEGACY_APPLICATION_SCHEMA_SHA256) {
    fail("APPLICANT_COMPATIBILITY_LEGACY_SCHEMA_MISMATCH", "The compatibility-less base does not bind the exact fallback Application schema.");
  }
  const observedApplicationSchema = digestBytes(readRegularFile(
    resolveRepositoryPath(repositoryRoot, APPLICATION_SCHEMA_PATH),
    MAXIMUM_PACKAGE_FILE_BYTES,
    "APPLICANT_COMPATIBILITY_LEGACY_SCHEMA_INVALID"
  ));
  if (observedApplicationSchema !== LEGACY_APPLICATION_SCHEMA_SHA256) {
    fail("APPLICANT_COMPATIBILITY_LEGACY_SCHEMA_MISMATCH", "The fallback Application schema bytes do not match the active contract.");
  }
  const receiptBytes = readRegularFile(
    resolveRepositoryPath(repositoryRoot, "vendor/receipt.json"),
    MAXIMUM_RECEIPT_BYTES,
    "APPLICANT_COMPATIBILITY_LEGACY_VENDOR_INVALID"
  );
  const { value: receipt } = parseCanonicalJsonBytes(receiptBytes, MAXIMUM_RECEIPT_BYTES, "APPLICANT_COMPATIBILITY_LEGACY_VENDOR");
  if (canonicalApplicantJson(receipt) !== canonicalApplicantJson(LEGACY_VENDOR_RECEIPT)) {
    fail("APPLICANT_COMPATIBILITY_LEGACY_VENDOR_MISMATCH", "The compatibility-less base does not contain the exact released Hookbuilder v0.10.3 fallback.");
  }
  return deepFreeze({
    activeContractSha256: LEGACY_ACTIVE_CONTRACT_SHA256,
    applicationSchemaSha256: LEGACY_APPLICATION_SCHEMA_SHA256,
    builder: LEGACY_VENDOR_RECEIPT,
    capabilities: capabilityShape(),
    minimumBuilderProtocolVersion: MINIMUM_BUILDER_PROTOCOL_VERSION,
    mode: "legacy-full-vendor-v0.10.3"
  });
}

function verifyApplicationSchemaBinding(repositoryRoot, application) {
  const observed = digestBytes(readRegularFile(
    resolveRepositoryPath(repositoryRoot, application.schemaPath),
    MAXIMUM_PACKAGE_FILE_BYTES,
    "APPLICANT_COMPATIBILITY_APPLICATION_SCHEMA_INVALID"
  ));
  if (observed !== application.schemaSha256) {
    fail("APPLICANT_COMPATIBILITY_APPLICATION_SCHEMA_MISMATCH", "The Applicant compatibility contract does not bind the protected Application schema bytes.");
  }
}

function verifyV2ApplicationAndSupportingContracts(repositoryRoot, compatibility) {
  verifyBoundArtifact(repositoryRoot, compatibility.application.current, V2_APPLICATION_SCHEMA_PATH, "APPLICANT_COMPATIBILITY_V2_APPLICATION_SCHEMA_MISMATCH");
  verifyBoundArtifact(repositoryRoot, compatibility.application.legacy[0], APPLICATION_SCHEMA_PATH, "APPLICANT_COMPATIBILITY_V2_LEGACY_APPLICATION_SCHEMA_MISMATCH");
  verifyBoundArtifact(repositoryRoot, compatibility.supportingContracts.submission, V2_SUBMISSION_SCHEMA_PATH, "APPLICANT_COMPATIBILITY_V2_SUBMISSION_SCHEMA_MISMATCH");
  verifyBoundArtifact(repositoryRoot, compatibility.supportingContracts.tradeCapabilityManifest, V2_TRADE_CAPABILITY_SCHEMA_PATH, "APPLICANT_COMPATIBILITY_V2_TRADE_MANIFEST_SCHEMA_MISMATCH");
  verifyBoundArtifact(repositoryRoot, compatibility.supportingContracts.routerReadiness.schema, V2_ROUTER_READINESS_SCHEMA_PATH, "APPLICANT_COMPATIBILITY_V2_ROUTER_SCHEMA_MISMATCH");

  const closure = compatibility.supportingContracts.routerReadiness.validatorClosure;
  const hash = crypto.createHash("sha256");
  for (const binding of closure.files) {
    const bytes = readRegularFile(
      resolveRepositoryPath(repositoryRoot, binding.path),
      MAXIMUM_PACKAGE_FILE_BYTES,
      "APPLICANT_COMPATIBILITY_V2_ROUTER_VALIDATOR_FILE_INVALID"
    );
    if (digestBytes(bytes) !== binding.sha256) {
      fail("APPLICANT_COMPATIBILITY_V2_ROUTER_VALIDATOR_FILE_MISMATCH", `${binding.path} does not match the V2 router-readiness validator closure.`);
    }
    hash.update(Buffer.from(binding.path, "utf8"));
    hash.update(Buffer.from([0]));
    hash.update(Buffer.from(String(bytes.byteLength), "ascii"));
    hash.update(Buffer.from([0]));
    hash.update(bytes);
    hash.update(Buffer.from([0]));
  }
  const observedClosure = `sha256:${hash.digest("hex")}`;
  if (observedClosure !== closure.closureSha256) {
    fail("APPLICANT_COMPATIBILITY_V2_ROUTER_VALIDATOR_CLOSURE_MISMATCH", "The V2 router-readiness validator closure does not match its protected binding.");
  }
}

function verifyBoundArtifact(repositoryRoot, binding, expectedPath, code) {
  const bytes = readRegularFile(
    resolveRepositoryPath(repositoryRoot, expectedPath),
    MAXIMUM_PACKAGE_FILE_BYTES,
    `${code}_FILE_INVALID`
  );
  if (binding.path !== expectedPath || digestBytes(bytes) !== binding.sha256) {
    fail(code, `${expectedPath} does not match its V2 protected binding.`);
  }
}

function validateCompatibilityShapeV2(value) {
  assertPlainObject(value, "APPLICANT_COMPATIBILITY_V2_INVALID", "compatibility");
  assertExactKeys(value, [
    "$schema",
    "application",
    "authority",
    "capabilities",
    "kind",
    "minimumBuilderProtocolVersion",
    "schemaVersion",
    "supportingContracts",
    "trustedRepository"
  ], "APPLICANT_COMPATIBILITY_V2_INVALID", "compatibility");
  assertEqual(value.$schema, V2_COMPATIBILITY_SCHEMA, "APPLICANT_COMPATIBILITY_V2_INVALID", "$schema");
  assertEqual(value.kind, COMPATIBILITY_KIND, "APPLICANT_COMPATIBILITY_V2_INVALID", "kind");
  assertEqual(value.schemaVersion, V2_SCHEMA_VERSION, "APPLICANT_COMPATIBILITY_V2_INVALID", "schemaVersion");
  if (!SEMVER.test(value.minimumBuilderProtocolVersion ?? "")) {
    fail("APPLICANT_COMPATIBILITY_V2_INVALID", "minimumBuilderProtocolVersion must be exact SemVer.");
  }
  assertPlainObject(value.application, "APPLICANT_COMPATIBILITY_V2_INVALID", "application");
  assertExactKeys(value.application, ["current", "legacy"], "APPLICANT_COMPATIBILITY_V2_INVALID", "application");
  validateV2BoundArtifact(value.application.current, "public-pr-application-v3.2", V2_APPLICATION_SCHEMA_PATH, "application.current");
  if (!Array.isArray(value.application.legacy) || value.application.legacy.length !== 1) {
    fail("APPLICANT_COMPATIBILITY_V2_INVALID", "application.legacy must bind exactly the immutable V3.1 compatibility contract.");
  }
  validateV2BoundArtifact(value.application.legacy[0], "public-pr-application-v3.1", APPLICATION_SCHEMA_PATH, "application.legacy[0]");

  assertPlainObject(value.authority, "APPLICANT_COMPATIBILITY_V2_INVALID", "authority");
  assertExactKeys(value.authority, [
    "candidateCodeExecuted",
    "credentialsUsed",
    "externalWritesPerformed",
    "launchAuthorized",
    "networkAccessed",
    "promotionAuthorized",
    "reviewAuthorized",
    "rpcAccessed"
  ], "APPLICANT_COMPATIBILITY_V2_INVALID", "authority");
  for (const [key, observed] of Object.entries(value.authority)) {
    if (observed !== false) fail("APPLICANT_COMPATIBILITY_V2_AUTHORITY_INVALID", `authority.${key} must remain false.`);
  }

  assertPlainObject(value.capabilities, "APPLICANT_COMPATIBILITY_V2_INVALID", "capabilities");
  assertExactKeys(value.capabilities, ["draftTransportOperations", "launchReadiness", "unreviewedDraftOnly"], "APPLICANT_COMPATIBILITY_V2_INVALID", "capabilities");
  if (canonicalApplicantJson(value.capabilities) !== canonicalApplicantJson(v2CapabilityShape())) {
    fail("APPLICANT_COMPATIBILITY_V2_INVALID", "capabilities must be the exact draft-only and offline-readiness V2 capability set.");
  }

  assertPlainObject(value.supportingContracts, "APPLICANT_COMPATIBILITY_V2_INVALID", "supportingContracts");
  assertExactKeys(value.supportingContracts, ["routerReadiness", "submission", "tradeCapabilityManifest"], "APPLICANT_COMPATIBILITY_V2_INVALID", "supportingContracts");
  validateV2BoundArtifact(value.supportingContracts.submission, "open-world-submission-v2.1", V2_SUBMISSION_SCHEMA_PATH, "supportingContracts.submission");
  validateV2BoundArtifact(value.supportingContracts.tradeCapabilityManifest, "trade-capability-manifest-v2", V2_TRADE_CAPABILITY_SCHEMA_PATH, "supportingContracts.tradeCapabilityManifest");
  assertPlainObject(value.supportingContracts.routerReadiness, "APPLICANT_COMPATIBILITY_V2_INVALID", "supportingContracts.routerReadiness");
  assertExactKeys(value.supportingContracts.routerReadiness, ["schema", "validatorClosure"], "APPLICANT_COMPATIBILITY_V2_INVALID", "supportingContracts.routerReadiness");
  validateV2BoundArtifact(value.supportingContracts.routerReadiness.schema, "programmable-launch-router-readiness-v1", V2_ROUTER_READINESS_SCHEMA_PATH, "supportingContracts.routerReadiness.schema");
  validateV2ValidatorClosure(value.supportingContracts.routerReadiness.validatorClosure);

  assertPlainObject(value.trustedRepository, "APPLICANT_COMPATIBILITY_V2_INVALID", "trustedRepository");
  assertExactKeys(value.trustedRepository, ["defaultBranch", "numericId"], "APPLICANT_COMPATIBILITY_V2_INVALID", "trustedRepository");
  assertEqual(value.trustedRepository.numericId, REPOSITORY_NUMERIC_ID, "APPLICANT_COMPATIBILITY_V2_INVALID", "trustedRepository.numericId");
  assertEqual(value.trustedRepository.defaultBranch, DEFAULT_BRANCH, "APPLICANT_COMPATIBILITY_V2_INVALID", "trustedRepository.defaultBranch");
}

function validateV2BoundArtifact(value, expectedContractId, expectedPath, label) {
  assertPlainObject(value, "APPLICANT_COMPATIBILITY_V2_INVALID", label);
  assertExactKeys(value, ["contractId", "path", "sha256"], "APPLICANT_COMPATIBILITY_V2_INVALID", label);
  assertEqual(value.contractId, expectedContractId, "APPLICANT_COMPATIBILITY_V2_INVALID", `${label}.contractId`);
  assertEqual(value.path, expectedPath, "APPLICANT_COMPATIBILITY_V2_INVALID", `${label}.path`);
  assertSha256(value.sha256, `${label}.sha256`);
}

function validateV2ValidatorClosure(value) {
  assertPlainObject(value, "APPLICANT_COMPATIBILITY_V2_INVALID", "router-readiness validator closure");
  assertExactKeys(value, ["algorithm", "closureSha256", "files"], "APPLICANT_COMPATIBILITY_V2_INVALID", "router-readiness validator closure");
  assertEqual(value.algorithm, RECEIPT_ALGORITHM, "APPLICANT_COMPATIBILITY_V2_INVALID", "router-readiness validator closure.algorithm");
  assertSha256(value.closureSha256, "router-readiness validator closure.closureSha256");
  if (!Array.isArray(value.files) || value.files.length !== 4) {
    fail("APPLICANT_COMPATIBILITY_V2_INVALID", "The router-readiness validator closure must bind exactly its four public validator source files.");
  }
  const expectedPaths = [
    V2_ROUTER_READINESS_CORE_PATH,
    V2_ROUTER_READINESS_CLI_PATH,
    V2_ROUTER_READINESS_EVM_ENCODING_PATH,
    V2_ROUTER_READINESS_LOSSLESS_JSON_PATH
  ].sort(compareUtf8);
  const observedPaths = [];
  for (const binding of value.files) {
    assertPlainObject(binding, "APPLICANT_COMPATIBILITY_V2_INVALID", "router-readiness validator closure file");
    assertExactKeys(binding, ["path", "sha256"], "APPLICANT_COMPATIBILITY_V2_INVALID", "router-readiness validator closure file");
    assertSha256(binding.sha256, `router-readiness validator closure ${binding.path}.sha256`);
    observedPaths.push(binding.path);
  }
  if (!sameStringArray(observedPaths, expectedPaths)) {
    fail("APPLICANT_COMPATIBILITY_V2_INVALID", "The router-readiness validator closure must use the exact sorted static import closure.");
  }
}

function validateCompatibilityShape(value) {
  assertPlainObject(value, "APPLICANT_COMPATIBILITY_INVALID", "compatibility");
  assertExactKeys(value, [
    "$schema",
    "application",
    "capabilities",
    "kind",
    "minimumBuilderProtocolVersion",
    "schemaVersion",
    "trustedRepository",
    "validatorPackage"
  ], "APPLICANT_COMPATIBILITY_INVALID", "compatibility");
  assertEqual(value.$schema, COMPATIBILITY_SCHEMA, "APPLICANT_COMPATIBILITY_INVALID", "$schema");
  assertEqual(value.kind, COMPATIBILITY_KIND, "APPLICANT_COMPATIBILITY_INVALID", "kind");
  assertEqual(value.schemaVersion, SCHEMA_VERSION, "APPLICANT_COMPATIBILITY_INVALID", "schemaVersion");
  if (!SEMVER.test(value.minimumBuilderProtocolVersion ?? "")) {
    fail("APPLICANT_COMPATIBILITY_INVALID", "minimumBuilderProtocolVersion must be exact SemVer.");
  }

  assertPlainObject(value.application, "APPLICANT_COMPATIBILITY_INVALID", "application");
  assertExactKeys(value.application, ["contractId", "schemaPath", "schemaSha256"], "APPLICANT_COMPATIBILITY_INVALID", "application");
  assertEqual(value.application.contractId, "public-pr-application-v3.1", "APPLICANT_COMPATIBILITY_INVALID", "application.contractId");
  assertEqual(value.application.schemaPath, APPLICATION_SCHEMA_PATH, "APPLICANT_COMPATIBILITY_INVALID", "application.schemaPath");
  assertSha256(value.application.schemaSha256, "application.schemaSha256");

  assertPlainObject(value.capabilities, "APPLICANT_COMPATIBILITY_INVALID", "capabilities");
  assertExactKeys(value.capabilities, ["draftTransportOperations", "missingObjectRecovery", "sourceClosureModes", "unreviewedDraftOnly"], "APPLICANT_COMPATIBILITY_INVALID", "capabilities");
  if (canonicalApplicantJson(value.capabilities) !== canonicalApplicantJson(capabilityShape())) {
    fail("APPLICANT_COMPATIBILITY_INVALID", "capabilities must be the exact closed Applicant transport capability set.");
  }

  assertPlainObject(value.trustedRepository, "APPLICANT_COMPATIBILITY_INVALID", "trustedRepository");
  assertExactKeys(value.trustedRepository, ["defaultBranch", "numericId"], "APPLICANT_COMPATIBILITY_INVALID", "trustedRepository");
  assertEqual(value.trustedRepository.numericId, REPOSITORY_NUMERIC_ID, "APPLICANT_COMPATIBILITY_INVALID", "trustedRepository.numericId");
  assertEqual(value.trustedRepository.defaultBranch, DEFAULT_BRANCH, "APPLICANT_COMPATIBILITY_INVALID", "trustedRepository.defaultBranch");

  assertPlainObject(value.validatorPackage, "APPLICANT_COMPATIBILITY_INVALID", "validatorPackage");
  assertExactKeys(value.validatorPackage, ["closureSha256", "entrypointPath", "receiptPath", "rootPath"], "APPLICANT_COMPATIBILITY_INVALID", "validatorPackage");
  assertEqual(value.validatorPackage.rootPath, APPLICANT_VALIDATOR_ROOT, "APPLICANT_COMPATIBILITY_INVALID", "validatorPackage.rootPath");
  assertEqual(value.validatorPackage.entrypointPath, APPLICANT_VALIDATOR_ENTRYPOINT, "APPLICANT_COMPATIBILITY_INVALID", "validatorPackage.entrypointPath");
  assertEqual(value.validatorPackage.receiptPath, APPLICANT_VALIDATOR_RECEIPT_PATH, "APPLICANT_COMPATIBILITY_INVALID", "validatorPackage.receiptPath");
  assertSha256(value.validatorPackage.closureSha256, "validatorPackage.closureSha256");
}

function validateReceiptShape(value) {
  assertPlainObject(value, "APPLICANT_VALIDATOR_RECEIPT_INVALID", "receipt");
  assertExactKeys(value, ["$schema", "algorithm", "authority", "closureSha256", "entrypoint", "fileCount", "files", "kind", "schemaVersion", "totalBytes"], "APPLICANT_VALIDATOR_RECEIPT_INVALID", "receipt");
  assertEqual(value.$schema, RECEIPT_SCHEMA, "APPLICANT_VALIDATOR_RECEIPT_INVALID", "$schema");
  assertEqual(value.kind, RECEIPT_KIND, "APPLICANT_VALIDATOR_RECEIPT_INVALID", "kind");
  assertEqual(value.schemaVersion, SCHEMA_VERSION, "APPLICANT_VALIDATOR_RECEIPT_INVALID", "schemaVersion");
  assertEqual(value.algorithm, RECEIPT_ALGORITHM, "APPLICANT_VALIDATOR_RECEIPT_INVALID", "algorithm");
  assertEqual(value.entrypoint, COMPACT_ENTRYPOINT, "APPLICANT_VALIDATOR_RECEIPT_INVALID", "entrypoint");
  assertSha256(value.closureSha256, "closureSha256");

  assertPlainObject(value.authority, "APPLICANT_VALIDATOR_RECEIPT_INVALID", "authority");
  assertExactKeys(value.authority, ["candidateCodeExecuted", "credentialsUsed", "externalWritesPerformed", "networkAccessed"], "APPLICANT_VALIDATOR_RECEIPT_INVALID", "authority");
  for (const [key, observed] of Object.entries(value.authority)) {
    if (observed !== false) fail("APPLICANT_VALIDATOR_RECEIPT_AUTHORITY_INVALID", `receipt.authority.${key} must remain false.`);
  }
  if (!Array.isArray(value.files) || value.files.length < 1 || value.files.length > MAXIMUM_PACKAGE_FILES) {
    fail("APPLICANT_VALIDATOR_RECEIPT_INVALID", "receipt.files must be a bounded non-empty array.");
  }
  const paths = [];
  let entrypoints = 0;
  for (const record of value.files) {
    assertPlainObject(record, "APPLICANT_VALIDATOR_RECEIPT_INVALID", "file record");
    assertExactKeys(record, ["byteLength", "path", "role", "sha256"], "APPLICANT_VALIDATOR_RECEIPT_INVALID", "file record");
    assertSafePackagePath(record.path, "APPLICANT_VALIDATOR_RECEIPT_INVALID", "file path");
    if (!new Set(["data", "entrypoint", "module", "schema"]).has(record.role)) {
      fail("APPLICANT_VALIDATOR_RECEIPT_INVALID", `${record.path} has an unsupported role.`);
    }
    if (!Number.isSafeInteger(record.byteLength) || record.byteLength < 0 || record.byteLength > MAXIMUM_PACKAGE_FILE_BYTES) {
      fail("APPLICANT_VALIDATOR_RECEIPT_INVALID", `${record.path} has an invalid byteLength.`);
    }
    assertSha256(record.sha256, `${record.path}.sha256`);
    if (record.role === "entrypoint") entrypoints += 1;
    if (record.path === COMPACT_ENTRYPOINT && record.role !== "entrypoint") {
      fail("APPLICANT_VALIDATOR_RECEIPT_INVALID", "The public Applicant validator entrypoint must have the entrypoint role.");
    }
    paths.push(record.path);
  }
  if (!sameStringArray(paths, [...paths].sort(compareUtf8)) || new Set(paths).size !== paths.length) {
    fail("APPLICANT_VALIDATOR_RECEIPT_INVALID", "receipt.files must be unique and UTF-8 bytewise sorted.");
  }
  if (entrypoints !== 1 || !paths.includes(COMPACT_ENTRYPOINT)) {
    fail("APPLICANT_VALIDATOR_RECEIPT_INVALID", "The compact package must bind exactly one public Applicant validator entrypoint.");
  }
  if (!Number.isSafeInteger(value.fileCount) || value.fileCount !== value.files.length) {
    fail("APPLICANT_VALIDATOR_RECEIPT_INVALID", "receipt.fileCount must equal files.length.");
  }
  if (!Number.isSafeInteger(value.totalBytes) || value.totalBytes < 1 || value.totalBytes > MAXIMUM_PACKAGE_BYTES) {
    fail("APPLICANT_VALIDATOR_RECEIPT_INVALID", "receipt.totalBytes is invalid.");
  }
}

function capabilityShape() {
  return {
    draftTransportOperations: ["create", "update"],
    missingObjectRecovery: true,
    sourceClosureModes: ["inline", "manifest"],
    unreviewedDraftOnly: true
  };
}

function v2CapabilityShape() {
  return {
    draftTransportOperations: ["create", "update"],
    launchReadiness: "offline-check-only",
    unreviewedDraftOnly: true
  };
}

function parseCanonicalJsonBytes(bytes, maximumBytes, prefix) {
  if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) {
    fail(`${prefix}_BYTES_INVALID`, `${prefix} input must be bytes.`);
  }
  const buffer = Buffer.from(bytes);
  if (buffer.byteLength < 3 || buffer.byteLength > maximumBytes) {
    fail(`${prefix}_BYTES_INVALID`, `${prefix} bytes exceed the closed size boundary.`);
  }
  let source;
  let value;
  try {
    source = UTF8_DECODER.decode(buffer);
    parseBoundedLosslessJson(source);
    value = JSON.parse(source);
  } catch (error) {
    fail(`${prefix}_JSON_INVALID`, `${prefix} must be duplicate-free UTF-8 JSON.`, error);
  }
  if (source !== `${canonicalApplicantJson(value)}\n`) {
    fail(`${prefix}_NONCANONICAL`, `${prefix} must be canonical JSON with one trailing newline.`);
  }
  return { source, value };
}

function listPackageFiles(packageRoot) {
  const output = [];
  const pending = [""];
  while (pending.length > 0) {
    const relativeDirectory = pending.pop();
    const absoluteDirectory = relativeDirectory === "" ? packageRoot : resolvePackagePath(packageRoot, relativeDirectory);
    const entries = fs.readdirSync(absoluteDirectory, { withFileTypes: true }).sort((left, right) => compareUtf8(left.name, right.name));
    for (const entry of entries) {
      const relativePath = relativeDirectory === "" ? entry.name : `${relativeDirectory}/${entry.name}`;
      assertSafePackagePath(relativePath, "APPLICANT_VALIDATOR_PACKAGE_FILE_INVALID", "package path");
      const absolutePath = resolvePackagePath(packageRoot, relativePath);
      const status = fs.lstatSync(absolutePath);
      if (status.isSymbolicLink()) fail("APPLICANT_VALIDATOR_PACKAGE_FILE_INVALID", `${relativePath} must not be a symbolic link.`);
      if (status.isDirectory()) pending.push(relativePath);
      else if (status.isFile()) output.push(relativePath);
      else fail("APPLICANT_VALIDATOR_PACKAGE_FILE_INVALID", `${relativePath} must be a regular file or directory.`);
      if (output.length > MAXIMUM_PACKAGE_FILES + 1) fail("APPLICANT_VALIDATOR_PACKAGE_FILE_LIMIT_EXCEEDED", "The compact validator package has too many files.");
    }
  }
  return output.sort(compareUtf8);
}

function resolvePackagePath(packageRoot, relativePath) {
  assertSafePackagePath(relativePath, "APPLICANT_VALIDATOR_PACKAGE_PATH_INVALID", "package path");
  const resolved = path.resolve(packageRoot, ...relativePath.split("/"));
  if (!resolved.startsWith(`${packageRoot}${path.sep}`)) fail("APPLICANT_VALIDATOR_PACKAGE_PATH_INVALID", `${relativePath} escapes the package root.`);
  return resolved;
}

function assertSafePackagePath(relativePath, code, label) {
  if (
    typeof relativePath !== "string"
    || relativePath.length < 1
    || relativePath.length > 256
    || relativePath.includes("\\")
    || relativePath.includes("\0")
    || relativePath.includes("\n")
    || relativePath.includes("\r")
    || path.posix.normalize(relativePath) !== relativePath
    || path.posix.isAbsolute(relativePath)
    || relativePath === "."
    || relativePath.startsWith("../")
    || relativePath === ".git"
    || relativePath.startsWith(".git/")
  ) fail(code, `${label} is not a canonical package-relative path.`);
}

function requireRepositoryRoot(repositoryRoot) {
  if (typeof repositoryRoot !== "string" || !path.isAbsolute(repositoryRoot)) {
    fail("APPLICANT_COMPATIBILITY_ARGUMENTS_INVALID", "repositoryRoot must be an absolute path.");
  }
  const status = lstatOptional(repositoryRoot);
  if (status === null || !status.isDirectory() || status.isSymbolicLink()) {
    fail("APPLICANT_COMPATIBILITY_ARGUMENTS_INVALID", "repositoryRoot must be a real directory.");
  }
  return path.resolve(repositoryRoot);
}

function resolveRepositoryPath(repositoryRoot, relativePath) {
  assertSafePackagePath(relativePath, "APPLICANT_COMPATIBILITY_PATH_INVALID", "repository path");
  const resolved = path.resolve(repositoryRoot, ...relativePath.split("/"));
  if (!resolved.startsWith(`${repositoryRoot}${path.sep}`)) fail("APPLICANT_COMPATIBILITY_PATH_INVALID", `${relativePath} escapes the repository.`);
  return resolved;
}

function readRegularFile(absolutePath, maximumBytes, code) {
  const status = lstatOptional(absolutePath);
  if (status === null) fail(code, `${absolutePath} is missing.`);
  assertRegularFileStatus(status, code, absolutePath);
  if (status.size > maximumBytes) fail(code, `${absolutePath} exceeds its size limit.`);
  return fs.readFileSync(absolutePath);
}

function lstatOptional(absolutePath) {
  try {
    return fs.lstatSync(absolutePath);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

function assertRegularFileStatus(status, code, label) {
  if (!status.isFile() || status.isSymbolicLink()) fail(code, `${label} must be a regular non-symlink file.`);
}

function digestBytes(bytes) {
  return `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
}

function compareSemver(left, right) {
  const leftParts = SEMVER.exec(left)?.slice(1).map(Number);
  const rightParts = SEMVER.exec(right)?.slice(1).map(Number);
  if (!leftParts || !rightParts) fail("APPLICANT_COMPATIBILITY_PROTOCOL_INVALID", "Protocol versions must be exact SemVer.");
  for (let index = 0; index < 3; index += 1) {
    if (leftParts[index] !== rightParts[index]) return leftParts[index] < rightParts[index] ? -1 : 1;
  }
  return 0;
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function assertSha256(value, label) {
  if (!SHA256.test(value ?? "")) fail("APPLICANT_COMPATIBILITY_INVALID", `${label} must be a lowercase SHA-256 binding.`);
}

function assertEqual(observed, expected, code, label) {
  if (observed !== expected) fail(code, `${label} must equal ${JSON.stringify(expected)}.`);
}

function assertPlainObject(value, code, label) {
  if (!isPlainObject(value)) fail(code, `${label} must be a plain object.`);
}

function assertExactKeys(value, expectedKeys, code, label) {
  assertPlainObject(value, code, label);
  const observed = Object.keys(value).sort(compareUtf8);
  const expected = [...expectedKeys].sort(compareUtf8);
  if (!sameStringArray(observed, expected)) fail(code, `${label} must have the exact closed key set.`);
}

function sameStringArray(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function fail(code, message, cause) {
  throw new ApplicantCompatibilityError(code, message, cause ? { cause } : undefined);
}
