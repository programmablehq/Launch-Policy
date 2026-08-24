import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { TextDecoder } from "node:util";

import {
  canonicalJson,
  PUBLIC_APPLICATION_FILES,
  validatePublicApplicationPackageFiles
} from "./verify-public-hook-application-core.mjs";
import {
  buildLaunchPolicyBinding,
  selectLaunchPolicyProfile
} from "./launch-policy-core.mjs";
import {
  isCanonicalGitHubRepositoryPathV1
} from "../vendor/programmable-v4-hook-builder/scripts/github-public-source-core.mjs";

export const SIGNED_ACCEPTANCE_COMMAND_VERSION = "programmable.signed-protected-acceptance-command.v1";
export const ACCEPTANCE_COMMAND_VERSION = "programmable.protected-acceptance-command.v1";
export const LAUNCH_ENTITLEMENT_ENVELOPE_VERSION = "programmable.launch-entitlement-envelope.v1";
export const SIX_FILE_PACKAGE_CONTRACT = "public-pr-application-v2-six-file-v1";
export const SIX_FILE_ADAPTER_PROFILE = "submit-launch-six-file-source-plan-v1";
export const MAXIMUM_ACCEPTANCE_COMMAND_LIFETIME_MS = 15 * 60 * 1000;
export const MAXIMUM_LAUNCH_PLAN_BYTES = 1024 * 1024;

const LAUNCH_POLICY_REPOSITORY = "0xprogrammable/launch-policy";
const LAUNCH_POLICY_REPOSITORY_ID = "1320171831";
const SIGNING_DOMAIN = Buffer.from("programmable.submit-launch.protected-acceptance-command.v1\0", "utf8");
const PACKAGE_BINDING_DOMAIN = "programmable.submit-launch.six-file-package-binding.v1";
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });
const APPLICATION_ID_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const GIT_OID_PATTERN = /^[0-9a-f]{40}$/u;
const OPAQUE_ID_PATTERN = /^[1-9][0-9]{0,63}$/u;
const GITHUB_LOGIN_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/u;
const REPOSITORY_URI_PATTERN = /^https:\/\/github\.com\/[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?\/[a-z0-9._-]{1,100}$/u;

export class LaunchEntitlementError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "LaunchEntitlementError";
    this.code = code;
  }
}

function reject(code, message) {
  throw new LaunchEntitlementError(code, message);
}

export function acceptanceCommandSigningBytes(command) {
  validateAcceptanceCommand(command);
  return Buffer.concat([SIGNING_DOMAIN, Buffer.from(canonicalJson(command), "utf8")]);
}

export function authorityKeyId(publicKey) {
  const key = normalizeTrustedPublicKey(publicKey);
  const spki = key.export({ type: "spki", format: "der" });
  return `ed25519:sha256:${crypto.createHash("sha256").update(spki).digest("hex")}`;
}

export function inspectSixFileApplicationPackage({ packageDirectory, legacyPolicyAdapter }) {
  if (typeof packageDirectory !== "string" || packageDirectory.length === 0) {
    reject("PACKAGE_DIRECTORY_INVALID", "The six-file package directory must be an explicit path.");
  }
  const resolvedDirectory = path.resolve(packageDirectory);
  const applicationId = path.basename(resolvedDirectory);
  if (!APPLICATION_ID_PATTERN.test(applicationId)) {
    reject("PACKAGE_APPLICATION_ID_INVALID", "The six-file package directory name must be the application id.");
  }
  const status = lstat(resolvedDirectory, "PACKAGE_DIRECTORY_INVALID");
  if (status.isSymbolicLink() || !status.isDirectory()) {
    reject("PACKAGE_DIRECTORY_INVALID", "The six-file package path must be a regular directory, not a symlink.");
  }
  const entries = fs.readdirSync(resolvedDirectory, { withFileTypes: true });
  const observedNames = entries.map((entry) => entry.name).sort(compareUtf8);
  const expectedNames = [...PUBLIC_APPLICATION_FILES].sort(compareUtf8);
  if (!arraysEqual(observedNames, expectedNames)) {
    reject("PACKAGE_NOT_CLOSED", "The acceptance package must contain exactly the frozen six public application files.");
  }
  for (const entry of entries) {
    if (entry.isSymbolicLink() || !entry.isFile()) {
      reject("PACKAGE_FILE_INVALID", `Package entry ${entry.name} must be a regular non-symlink file.`);
    }
  }

  const packageFiles = new Map(PUBLIC_APPLICATION_FILES.map((fileName) => [
    fileName,
    readStableRegularFile(path.join(resolvedDirectory, fileName), 512 * 1024, "PACKAGE_FILE_INVALID")
  ]));
  let validated;
  try {
    validated = validatePublicApplicationPackageFiles({ applicationId, packageFiles, legacyPolicyAdapter });
  } catch (error) {
    reject("PACKAGE_VALIDATION_FAILED", `The frozen public application validator rejected the package: ${error.code ?? error.message}`);
  }
  const files = PUBLIC_APPLICATION_FILES.map((fileName) => {
    const bytes = packageFiles.get(fileName);
    return {
      byteLength: bytes.length,
      gitBlobOid: gitBlobOid(bytes),
      path: fileName,
      sha256: digestBytes(bytes)
    };
  });
  const directory = `submissions/${applicationId}`;
  const digest = domainDigest(PACKAGE_BINDING_DOMAIN, {
    contract: SIX_FILE_PACKAGE_CONTRACT,
    directory,
    files
  });
  return deepFreeze({
    application: structuredClone(validated.application),
    binding: {
      contract: SIX_FILE_PACKAGE_CONTRACT,
      digest,
      directory,
      fileCount: 6,
      files
    }
  });
}

export function compileLaunchEntitlementEnvelope({
  signedCommand,
  packageDirectory,
  launchPlanFile,
  trustedAuthorityPublicKey,
  trustedPolicyRecord,
  now = new Date()
}) {
  validateSignedCommand(signedCommand);
  const trustedKey = normalizeTrustedPublicKey(trustedAuthorityPublicKey);
  const expectedKeyId = authorityKeyId(trustedKey);
  if (signedCommand.authorization.keyId !== expectedKeyId) {
    reject("AUTHORITY_KEY_MISMATCH", "The protected acceptance command was not addressed to the pinned authority key.");
  }
  const signature = decodeSignature(signedCommand.authorization.signature);
  const signingBytes = acceptanceCommandSigningBytes(signedCommand.command);
  if (!crypto.verify(null, signingBytes, trustedKey, signature)) {
    reject("SIGNATURE_INVALID", "The protected acceptance command signature is invalid.");
  }
  validateCommandTimeWindow(signedCommand.command, now);

  let productionProfile;
  try {
    // The enabled build binding is used only as the existing WeakSet-backed
    // provenance probe. Caller-shaped policy objects cannot pass it.
    buildLaunchPolicyBinding(trustedPolicyRecord, "build");
    productionProfile = selectLaunchPolicyProfile(trustedPolicyRecord.policy, "production-launch");
  } catch (error) {
    reject("PRODUCTION_POLICY_TRUST_INVALID", "Production compilation requires the exact protected-base central policy record.");
  }
  if (productionProfile.enabled !== true) {
    reject("PRODUCTION_LAUNCH_DISABLED", "The current central launch policy keeps production launch disabled.");
  }
  // The v1 policy contract itself forbids an enabled production profile. If a
  // future policy changes that authority, it must introduce a new command and
  // signing domain rather than reviving the opaque v1 policyBundleDigest.
  reject("PRODUCTION_COMMAND_VERSION_UNSUPPORTED", "Production enablement requires a new policy-bound entitlement command version.");
}

export function parseCanonicalSignedCommand(source) {
  if (typeof source !== "string") reject("SIGNED_COMMAND_JSON_INVALID", "The signed command must be UTF-8 JSON text.");
  let value;
  try {
    value = JSON.parse(source);
  } catch {
    reject("SIGNED_COMMAND_JSON_INVALID", "The signed command is not valid JSON.");
  }
  const expected = `${canonicalJson(value)}\n`;
  if (source !== expected) {
    reject("SIGNED_COMMAND_JSON_NOT_CANONICAL", "The signed command file must be canonical JSON with one trailing newline.");
  }
  validateSignedCommand(value);
  return value;
}

export function readCanonicalSignedCommandFile(filePath) {
  const bytes = readStableRegularFile(filePath, 256 * 1024, "SIGNED_COMMAND_FILE_INVALID");
  let source;
  try {
    source = UTF8_DECODER.decode(bytes);
  } catch {
    reject("SIGNED_COMMAND_JSON_INVALID", "The signed command file must be valid UTF-8.");
  }
  return parseCanonicalSignedCommand(source);
}

export function readTrustedAuthorityPublicKeyFile(filePath) {
  return readStableRegularFile(filePath, 16 * 1024, "AUTHORITY_KEY_FILE_INVALID");
}

function validateSignedCommand(value) {
  assertPlainObject(value, "SIGNED_COMMAND_INVALID", "The signed command envelope must be an object.");
  assertExactKeys(value, ["authorization", "command", "schemaVersion"], "SIGNED_COMMAND_INVALID");
  assertEqual(value.schemaVersion, SIGNED_ACCEPTANCE_COMMAND_VERSION, "SIGNED_COMMAND_VERSION_UNSUPPORTED");
  assertPlainObject(value.authorization, "SIGNED_COMMAND_INVALID", "authorization must be an object.");
  assertExactKeys(value.authorization, ["algorithm", "keyId", "signature"], "SIGNED_COMMAND_INVALID");
  assertEqual(value.authorization.algorithm, "ed25519", "SIGNATURE_ALGORITHM_UNSUPPORTED");
  assertPattern(value.authorization.keyId, /^ed25519:sha256:[0-9a-f]{64}$/u, "AUTHORITY_KEY_ID_INVALID");
  assertPattern(value.authorization.signature, /^[A-Za-z0-9_-]{86}$/u, "SIGNATURE_ENCODING_INVALID");
  validateAcceptanceCommand(value.command);
}

function validateAcceptanceCommand(command) {
  assertPlainObject(command, "ACCEPTANCE_COMMAND_INVALID", "command must be an object.");
  assertExactKeys(command, [
    "acceptedAt", "acceptedBy", "action", "application", "entitlement", "launchPlan",
    "pullRequest", "review", "schemaVersion", "source", "validUntil"
  ], "ACCEPTANCE_COMMAND_INVALID");
  assertEqual(command.schemaVersion, ACCEPTANCE_COMMAND_VERSION, "ACCEPTANCE_COMMAND_VERSION_UNSUPPORTED");
  assertEqual(command.action, "issue-launch-entitlement", "ACCEPTANCE_COMMAND_ACTION_UNSUPPORTED");
  assertCanonicalDateTime(command.acceptedAt, "ACCEPTANCE_TIME_INVALID");
  assertCanonicalDateTime(command.validUntil, "ACCEPTANCE_TIME_INVALID");

  assertPlainObject(command.acceptedBy, "ACCEPTANCE_COMMAND_INVALID", "acceptedBy must be an object.");
  assertExactKeys(command.acceptedBy, ["githubLogin", "githubUserId", "mode"], "ACCEPTANCE_COMMAND_INVALID");
  assertPattern(command.acceptedBy.githubLogin, GITHUB_LOGIN_PATTERN, "ACCEPTED_BY_INVALID");
  assertPattern(command.acceptedBy.githubUserId, OPAQUE_ID_PATTERN, "ACCEPTED_BY_INVALID");
  assertOneOf(command.acceptedBy.mode, ["automation-review", "human-review"], "ACCEPTED_BY_INVALID");

  assertPlainObject(command.application, "ACCEPTANCE_COMMAND_INVALID", "application must be an object.");
  assertExactKeys(command.application, ["applicationId", "applicationRevision", "builderGitHubUserId", "packageContract", "packageDigest"], "ACCEPTANCE_COMMAND_INVALID");
  assertPattern(command.application.applicationId, APPLICATION_ID_PATTERN, "APPLICATION_BINDING_INVALID");
  assertInteger(command.application.applicationRevision, 1, 1_000_000, "APPLICATION_BINDING_INVALID");
  assertPattern(command.application.builderGitHubUserId, OPAQUE_ID_PATTERN, "APPLICATION_BINDING_INVALID");
  assertEqual(command.application.packageContract, SIX_FILE_PACKAGE_CONTRACT, "PACKAGE_CONTRACT_UNSUPPORTED");
  assertPattern(command.application.packageDigest, DIGEST_PATTERN, "APPLICATION_BINDING_INVALID");

  assertPlainObject(command.entitlement, "ACCEPTANCE_COMMAND_INVALID", "entitlement must be an object.");
  assertExactKeys(command.entitlement, ["chainId", "claimPrincipalPolicy", "launchCount", "permitPolicy", "repositoryKeyPolicy"], "ACCEPTANCE_COMMAND_INVALID");
  assertEqual(command.entitlement.chainId, 1, "ENTITLEMENT_POLICY_UNSUPPORTED");
  assertEqual(command.entitlement.claimPrincipalPolicy, "application-builder-github-user-v1", "ENTITLEMENT_POLICY_UNSUPPORTED");
  assertEqual(command.entitlement.launchCount, 1, "ENTITLEMENT_POLICY_UNSUPPORTED");
  assertEqual(command.entitlement.permitPolicy, "jit-single-use-v1", "ENTITLEMENT_POLICY_UNSUPPORTED");
  assertEqual(command.entitlement.repositoryKeyPolicy, "numeric-github-repository-v1", "ENTITLEMENT_POLICY_UNSUPPORTED");

  assertPlainObject(command.launchPlan, "ACCEPTANCE_COMMAND_INVALID", "launchPlan must be an object.");
  assertExactKeys(command.launchPlan, ["byteLength", "gitBlobOid", "path", "repositoryRole", "sha256"], "ACCEPTANCE_COMMAND_INVALID");
  assertInteger(command.launchPlan.byteLength, 2, MAXIMUM_LAUNCH_PLAN_BYTES, "LAUNCH_PLAN_BINDING_INVALID");
  assertPattern(command.launchPlan.gitBlobOid, GIT_OID_PATTERN, "LAUNCH_PLAN_BINDING_INVALID");
  assertRepositoryPath(command.launchPlan.path, "LAUNCH_PLAN_BINDING_INVALID");
  assertEqual(command.launchPlan.repositoryRole, "primary", "LAUNCH_PLAN_BINDING_INVALID");
  assertPattern(command.launchPlan.sha256, DIGEST_PATTERN, "LAUNCH_PLAN_BINDING_INVALID");

  assertPlainObject(command.pullRequest, "ACCEPTANCE_COMMAND_INVALID", "pullRequest must be an object.");
  assertExactKeys(command.pullRequest, ["authorGitHubUserId", "baseCommitOid", "baseRepository", "baseRepositoryId", "baseTreeOid", "headCommitOid", "headRepositoryId", "headTreeOid", "number"], "ACCEPTANCE_COMMAND_INVALID");
  assertPattern(command.pullRequest.authorGitHubUserId, OPAQUE_ID_PATTERN, "PULL_REQUEST_BINDING_INVALID");
  assertPattern(command.pullRequest.baseCommitOid, GIT_OID_PATTERN, "PULL_REQUEST_BINDING_INVALID");
  assertEqual(command.pullRequest.baseRepository, LAUNCH_POLICY_REPOSITORY, "PULL_REQUEST_BINDING_INVALID");
  assertEqual(command.pullRequest.baseRepositoryId, LAUNCH_POLICY_REPOSITORY_ID, "PULL_REQUEST_BINDING_INVALID");
  assertPattern(command.pullRequest.baseTreeOid, GIT_OID_PATTERN, "PULL_REQUEST_BINDING_INVALID");
  assertPattern(command.pullRequest.headCommitOid, GIT_OID_PATTERN, "PULL_REQUEST_BINDING_INVALID");
  assertPattern(command.pullRequest.headRepositoryId, OPAQUE_ID_PATTERN, "PULL_REQUEST_BINDING_INVALID");
  assertPattern(command.pullRequest.headTreeOid, GIT_OID_PATTERN, "PULL_REQUEST_BINDING_INVALID");
  assertInteger(command.pullRequest.number, 1, Number.MAX_SAFE_INTEGER, "PULL_REQUEST_BINDING_INVALID");

  assertPlainObject(command.review, "ACCEPTANCE_COMMAND_INVALID", "review must be an object.");
  assertExactKeys(command.review, ["decision", "finalVerificationDigest", "policyBundleDigest", "reviewEvidenceDigest", "supersedes"], "ACCEPTANCE_COMMAND_INVALID");
  assertEqual(command.review.decision, "accepted", "REVIEW_DECISION_INVALID");
  assertPattern(command.review.finalVerificationDigest, DIGEST_PATTERN, "REVIEW_BINDING_INVALID");
  assertPattern(command.review.policyBundleDigest, DIGEST_PATTERN, "REVIEW_BINDING_INVALID");
  assertPattern(command.review.reviewEvidenceDigest, DIGEST_PATTERN, "REVIEW_BINDING_INVALID");
  if (command.review.supersedes !== null) assertPattern(command.review.supersedes, DIGEST_PATTERN, "REVIEW_BINDING_INVALID");

  validateSource(command.source);
}

function validateSource(source) {
  assertPlainObject(source, "SOURCE_BINDING_INVALID", "source must be an object.");
  assertExactKeys(source, ["companions", "primary", "schemaVersion"], "SOURCE_BINDING_INVALID");
  assertEqual(source.schemaVersion, "1.0.0", "SOURCE_BINDING_INVALID");
  validateSourceRepository(source.primary);
  if (!Array.isArray(source.companions) || source.companions.length > 8) {
    reject("SOURCE_BINDING_INVALID", "source companions must be an array with at most eight entries.");
  }
  source.companions.forEach(validateSourceRepository);
  const identities = [source.primary, ...source.companions].map((entry) => entry.numericRepositoryId);
  if (new Set(identities).size !== identities.length) reject("SOURCE_BINDING_INVALID", "source repository ids must be unique.");
}

function validateSourceRepository(repository) {
  assertPlainObject(repository, "SOURCE_BINDING_INVALID", "source repository must be an object.");
  assertExactKeys(repository, ["numericRepositoryId", "repositoryUri", "revisionObjectId", "treeObjectId"], "SOURCE_BINDING_INVALID");
  assertPattern(repository.numericRepositoryId, OPAQUE_ID_PATTERN, "SOURCE_BINDING_INVALID");
  assertPattern(repository.repositoryUri, REPOSITORY_URI_PATTERN, "SOURCE_BINDING_INVALID");
  assertPattern(repository.revisionObjectId, GIT_OID_PATTERN, "SOURCE_BINDING_INVALID");
  assertPattern(repository.treeObjectId, GIT_OID_PATTERN, "SOURCE_BINDING_INVALID");
}

function validateCommandTimeWindow(command, now) {
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) reject("SYSTEM_TIME_INVALID", "The compiler clock must be a valid Date.");
  const acceptedAt = Date.parse(command.acceptedAt);
  const validUntil = Date.parse(command.validUntil);
  if (validUntil <= acceptedAt || validUntil - acceptedAt > MAXIMUM_ACCEPTANCE_COMMAND_LIFETIME_MS) {
    reject("COMMAND_LIFETIME_INVALID", "The protected acceptance command lifetime must be positive and no longer than fifteen minutes.");
  }
  if (now.getTime() < acceptedAt || now.getTime() > validUntil) {
    reject("COMMAND_NOT_CURRENT", "The protected acceptance command is not valid at the compiler clock time.");
  }
}

function readStableRegularFile(filePath, maximumBytes, code) {
  if (typeof filePath !== "string" || filePath.length === 0) reject(code, "An explicit file path is required.");
  const resolvedPath = path.resolve(filePath);
  const initial = lstat(resolvedPath, code);
  if (initial.isSymbolicLink() || !initial.isFile() || (initial.mode & 0o111) !== 0 || initial.nlink !== 1) {
    reject(code, "Input files must be non-executable, single-link regular files and not symlinks.");
  }
  if (initial.size > maximumBytes) reject(code, "An input file exceeds its byte limit.");
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_CLOEXEC ?? 0);
  let descriptor;
  try {
    descriptor = fs.openSync(resolvedPath, flags);
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || (before.mode & 0o111n) !== 0n || before.size > BigInt(maximumBytes)) {
      reject(code, "Input files must remain bounded single-link regular files while read.");
    }
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (!sameFileSnapshot(before, after) || BigInt(bytes.length) !== after.size) {
      reject(code, "An input file changed while it was read.");
    }
    return bytes;
  } catch (error) {
    if (error instanceof LaunchEntitlementError) throw error;
    reject(code, "An input file could not be read safely.");
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function lstat(target, code) {
  try {
    return fs.lstatSync(target);
  } catch {
    reject(code, "A required path does not exist or cannot be inspected.");
  }
}

function normalizeTrustedPublicKey(publicKey) {
  let key;
  try {
    key = publicKey instanceof crypto.KeyObject ? publicKey : crypto.createPublicKey(publicKey);
  } catch {
    reject("AUTHORITY_KEY_INVALID", "The trusted acceptance authority public key is invalid.");
  }
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") {
    reject("AUTHORITY_KEY_INVALID", "The trusted acceptance authority key must be an Ed25519 public key.");
  }
  return key;
}

function decodeSignature(value) {
  let bytes;
  try {
    bytes = Buffer.from(value, "base64url");
  } catch {
    reject("SIGNATURE_ENCODING_INVALID", "The acceptance signature is not canonical base64url.");
  }
  if (bytes.length !== 64 || bytes.toString("base64url") !== value) {
    reject("SIGNATURE_ENCODING_INVALID", "The acceptance signature is not a canonical Ed25519 signature.");
  }
  return bytes;
}

function sameFileSnapshot(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function gitBlobOid(bytes) {
  return crypto.createHash("sha1")
    .update(Buffer.from(`blob ${bytes.length}\0`, "utf8"))
    .update(bytes)
    .digest("hex");
}

function digestBytes(bytes) {
  return `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
}

function domainDigest(domain, value) {
  return digestBytes(Buffer.concat([
    Buffer.from(`${domain}\0`, "utf8"),
    Buffer.from(canonicalJson(value), "utf8")
  ]));
}

function assertPlainObject(value, code, message) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    reject(code, message);
  }
}

function assertExactKeys(value, keys, code) {
  const actual = Object.keys(value).sort(compareUtf8);
  const expected = [...keys].sort(compareUtf8);
  if (!arraysEqual(actual, expected)) reject(code, "A protected acceptance object contains missing or additional fields.");
}

function assertEqual(actual, expected, code) {
  if (actual !== expected) reject(code, "A protected acceptance constant or policy value is invalid.");
}

function assertPattern(value, pattern, code) {
  if (typeof value !== "string" || !pattern.test(value)) reject(code, "A protected acceptance identifier or digest is invalid.");
}

function assertInteger(value, minimum, maximum, code) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) reject(code, "A protected acceptance integer is out of range.");
}

function assertOneOf(value, options, code) {
  if (!options.includes(value)) reject(code, "A protected acceptance enum value is invalid.");
}

function assertCanonicalDateTime(value, code) {
  if (typeof value !== "string") reject(code, "A protected acceptance timestamp is invalid.");
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) {
    reject(code, "Protected acceptance timestamps must use canonical UTC ISO-8601 with milliseconds.");
  }
}

function assertRepositoryPath(value, code) {
  if (!isCanonicalGitHubRepositoryPathV1(value) || !value.endsWith(".json")) {
    reject(code, "The primary launch-plan repository path is invalid.");
  }
}

function arraysEqual(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}
