import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import {
  MAXIMUM_RUNTIME_FEE_SETTLEMENT_BUNDLE_BYTES,
  MAXIMUM_RUNTIME_FEE_SETTLEMENT_PROOF_BYTES,
  PROGRAMMABLE_RUNTIME_FEE_SETTLEMENT_PROOF_REASON_CODE,
  PROGRAMMABLE_RUNTIME_FEE_SETTLEMENT_PROOF_STATUS,
  RUNTIME_FEE_SETTLEMENT_SHA1,
  deepFreezeRuntimeFeeSettlementV1,
  failRuntimeFeeSettlementV1,
  isRuntimeFeeSettlementObjectV1,
  isSafeRuntimeFeeSettlementPathV1,
  parseCanonicalRuntimeFeeSettlementJsonBytesV1,
  parseProgrammableRuntimeFeeSettlementProofBytesV1,
  requireExactRuntimeFeeSettlementKeysV1,
  requireRuntimeFeeSettlementObjectV1,
  runtimeFeeSettlementSha256V1,
  validatePromotionBinding
} from "./programmable-runtime-fee-settlement-proof-validation.mjs";

export {
  PROGRAMMABLE_RUNTIME_FEE_SETTLEMENT_FINALITY_MODE,
  PROGRAMMABLE_RUNTIME_FEE_SETTLEMENT_OBSERVATION_SCOPE,
  PROGRAMMABLE_RUNTIME_FEE_SETTLEMENT_OBSERVER_ID,
  PROGRAMMABLE_RUNTIME_FEE_SETTLEMENT_PROOF_ASSURANCE,
  PROGRAMMABLE_RUNTIME_FEE_SETTLEMENT_PROOF_KIND,
  PROGRAMMABLE_RUNTIME_FEE_SETTLEMENT_PROOF_REASON_CODE,
  PROGRAMMABLE_RUNTIME_FEE_SETTLEMENT_PROOF_SCHEMA_ID,
  PROGRAMMABLE_RUNTIME_FEE_SETTLEMENT_PROOF_STATUS,
  PROGRAMMABLE_RUNTIME_FEE_SETTLEMENT_PROOF_VERSION,
  PROGRAMMABLE_RUNTIME_FEE_SETTLEMENT_VERIFICATION_PROFILE,
  ProgrammableRuntimeFeeSettlementProofError,
  canonicalProgrammableRuntimeFeeSettlementProofJsonV1,
  digestProgrammableRuntimeFeeSettlementProofBytesV1,
  parseProgrammableRuntimeFeeSettlementProofBytesV1,
  validateProgrammableRuntimeFeeSettlementProofV1
} from "./programmable-runtime-fee-settlement-proof-validation.mjs";

const REPOSITORY_REMOTE = "https://github.com/0xprogrammable/launch-policy.git";
const CURRENT_REPOSITORY_REMOTE = "https://github.com/programmablehq/Launch-Policy.git";
const PROOF_ROOT = "platform-evidence/runtime-fee-settlement";
const MAXIMUM_PROMOTION_BYTES = 1024 * 1024;
const protectedPendingRecords = new WeakSet();
const protectedPendingPolicyEvidence = new WeakSet();

export function readProtectedProgrammableRuntimeFeeSettlementObservationFromGitV1(options) {
  requireRuntimeFeeSettlementObjectV1(
    options,
    "options",
    "RUNTIME_FEE_PROOF_READER_ARGUMENTS_INVALID"
  );
  requireExactRuntimeFeeSettlementKeysV1(
    options,
    ["expectedBaseCommit", "proofPath", "repositoryRoot"],
    "options",
    "RUNTIME_FEE_PROOF_READER_ARGUMENTS_INVALID"
  );
  const { expectedBaseCommit, proofPath, repositoryRoot } = options;
  if (
    typeof repositoryRoot !== "string"
    || !path.isAbsolute(repositoryRoot)
    || !RUNTIME_FEE_SETTLEMENT_SHA1.test(expectedBaseCommit ?? "")
    || !isSafeRuntimeFeeSettlementPathV1(proofPath)
    || !proofPath.startsWith(PROOF_ROOT + "/")
  ) {
    failRuntimeFeeSettlementV1(
      "RUNTIME_FEE_PROOF_READER_ARGUMENTS_INVALID",
      "Trusted runtime fee proof reader arguments are invalid."
    );
  }
  assertRegularRepositoryRoot(repositoryRoot);

  const observedRemote = runGitText(repositoryRoot, ["remote", "get-url", "origin"], 4096);
  if (normalizeRemote(observedRemote) !== REPOSITORY_REMOTE) {
    failRuntimeFeeSettlementV1(
      "RUNTIME_FEE_PROOF_GIT_IDENTITY_INVALID",
      "Trusted proof repository origin does not resolve to repository id 1320171831."
    );
  }
  const baseCommit = runGitText(
    repositoryRoot,
    ["rev-parse", "--verify", expectedBaseCommit + "^{commit}"],
    128
  );
  if (baseCommit !== expectedBaseCommit) {
    failRuntimeFeeSettlementV1(
      "RUNTIME_FEE_PROOF_GIT_IDENTITY_INVALID",
      "Trusted proof base commit does not resolve exactly."
    );
  }
  const baseTree = runGitText(repositoryRoot, ["rev-parse", baseCommit + "^{tree}"], 128);
  const proofBlob = readGitBlob(
    repositoryRoot,
    baseCommit,
    proofPath,
    MAXIMUM_RUNTIME_FEE_SETTLEMENT_PROOF_BYTES
  );
  const parsed = parseProgrammableRuntimeFeeSettlementProofBytesV1(proofBlob.bytes);
  const expectedProofPath = PROOF_ROOT
    + "/"
    + parsed.proof.subject.projectId
    + "/"
    + parsed.proof.proofId
    + ".json";
  if (proofPath !== expectedProofPath) {
    failRuntimeFeeSettlementV1(
      "RUNTIME_FEE_PROOF_PATH_INVALID",
      "Runtime fee proof path must match its exact project and proof identity."
    );
  }

  const bundle = parsed.proof.evidence.bundle;
  const bundleBlob = readGitBlob(
    repositoryRoot,
    baseCommit,
    bundle.path,
    MAXIMUM_RUNTIME_FEE_SETTLEMENT_BUNDLE_BYTES
  );
  if (
    bundleBlob.gitBlobOid !== bundle.gitBlobOid
    || bundleBlob.bytes.length !== bundle.byteLength
    || runtimeFeeSettlementSha256V1(bundleBlob.bytes) !== bundle.sha256
  ) {
    failRuntimeFeeSettlementV1(
      "RUNTIME_FEE_PROOF_BUNDLE_MISMATCH",
      "Protected evidence bundle bytes do not match the proof binding."
    );
  }

  const promotionBinding = parsed.proof.bindings.promotion;
  const promotionBlob = readGitBlob(
    repositoryRoot,
    baseCommit,
    promotionBinding.path,
    MAXIMUM_PROMOTION_BYTES
  );
  if (runtimeFeeSettlementSha256V1(promotionBlob.bytes) !== promotionBinding.sha256) {
    failRuntimeFeeSettlementV1(
      "RUNTIME_FEE_PROOF_PROMOTION_MISMATCH",
      "Protected promotion bytes do not match the proof binding."
    );
  }
  validatePromotionBinding(parsed.proof, parsePromotionBytes(promotionBlob.bytes));

  const record = Object.freeze({
    ...parsed,
    baseCommit,
    baseTree,
    bundleBytes: bundleBlob.bytes,
    path: proofPath,
    promotionBytes: promotionBlob.bytes,
    proofGitBlobOid: proofBlob.gitBlobOid
  });
  protectedPendingRecords.add(record);
  return record;
}

export function projectProgrammableRuntimeFeeSettlementPendingPolicyEvidenceV1(record) {
  assertProtectedPendingRecord(record);
  const projection = {
    observationPath: record.path,
    observationSha256: record.sha256,
    protectedBaseCommit: record.baseCommit,
    protectedBaseTree: record.baseTree,
    protectedGitBlobOid: record.proofGitBlobOid,
    reasonCode: PROGRAMMABLE_RUNTIME_FEE_SETTLEMENT_PROOF_REASON_CODE,
    status: PROGRAMMABLE_RUNTIME_FEE_SETTLEMENT_PROOF_STATUS
  };
  deepFreezeRuntimeFeeSettlementV1(projection);
  protectedPendingPolicyEvidence.add(projection);
  return projection;
}

export function isProtectedProgrammableRuntimeFeeSettlementPendingPolicyEvidenceV1(value) {
  return isRuntimeFeeSettlementObjectV1(value)
    && protectedPendingPolicyEvidence.has(value)
    && Object.isFrozen(value);
}

function assertProtectedPendingRecord(record) {
  if (!isRuntimeFeeSettlementObjectV1(record) || !protectedPendingRecords.has(record)) {
    failRuntimeFeeSettlementV1(
      "RUNTIME_FEE_PROOF_TRUST_REQUIRED",
      "Pending policy evidence requires the exact structural record returned by the protected Git observation reader."
    );
  }
  const reparsed = parseProgrammableRuntimeFeeSettlementProofBytesV1(record.bytes);
  if (
    reparsed.sha256 !== record.sha256
    || runtimeFeeSettlementSha256V1(record.bundleBytes) !== record.proof.evidence.bundle.sha256
    || runtimeFeeSettlementSha256V1(record.promotionBytes) !== record.proof.bindings.promotion.sha256
  ) {
    failRuntimeFeeSettlementV1(
      "RUNTIME_FEE_PROOF_TRUST_REQUIRED",
      "Protected observation bytes or bound evidence changed after structural validation."
    );
  }
  validatePromotionBinding(record.proof, parsePromotionBytes(record.promotionBytes));
}

function parsePromotionBytes(bytes) {
  return parseCanonicalRuntimeFeeSettlementJsonBytesV1(
    bytes,
    "RUNTIME_FEE_PROOF_PROMOTION_INVALID",
    "RUNTIME_FEE_PROOF_PROMOTION_INVALID"
  );
}

function assertRegularRepositoryRoot(repositoryRoot) {
  let rootStatus;
  try {
    rootStatus = fs.lstatSync(repositoryRoot);
  } catch (error) {
    failRuntimeFeeSettlementV1(
      "RUNTIME_FEE_PROOF_GIT_IDENTITY_INVALID",
      "Trusted repository root is unavailable.",
      error
    );
  }
  if (!rootStatus.isDirectory() || rootStatus.isSymbolicLink()) {
    failRuntimeFeeSettlementV1(
      "RUNTIME_FEE_PROOF_GIT_IDENTITY_INVALID",
      "Trusted repository root must be a regular directory."
    );
  }
}

function readGitBlob(repositoryRoot, baseCommit, relativePath, maximumBytes) {
  if (!isSafeRuntimeFeeSettlementPathV1(relativePath)) {
    failRuntimeFeeSettlementV1(
      "RUNTIME_FEE_PROOF_GIT_OBJECT_INVALID",
      "Protected evidence path is invalid."
    );
  }
  const entry = runGitText(repositoryRoot, ["ls-tree", baseCommit, "--", relativePath], 2048);
  const match = /^(100644) blob ([0-9a-f]{40})\t(.+)$/u.exec(entry);
  if (!match || match[3] !== relativePath || !entry.endsWith("\t" + relativePath)) {
    failRuntimeFeeSettlementV1(
      "RUNTIME_FEE_PROOF_GIT_OBJECT_INVALID",
      "Protected evidence path must resolve to one non-executable regular Git blob."
    );
  }
  const gitObject = match[2];
  const declaredSize = Number(runGitText(repositoryRoot, ["cat-file", "-s", gitObject], 128));
  if (!Number.isSafeInteger(declaredSize) || declaredSize < 2 || declaredSize > maximumBytes) {
    failRuntimeFeeSettlementV1(
      "RUNTIME_FEE_PROOF_SIZE_INVALID",
      "Protected evidence Git blob exceeds its closed byte boundary."
    );
  }
  const bytes = runGit(repositoryRoot, ["cat-file", "blob", gitObject], maximumBytes + 1);
  if (bytes.length !== declaredSize) {
    failRuntimeFeeSettlementV1(
      "RUNTIME_FEE_PROOF_GIT_OBJECT_INVALID",
      "Protected evidence Git blob size does not match its declared size."
    );
  }
  return Object.freeze({ bytes, gitBlobOid: gitObject });
}

function normalizeRemote(remote) {
  const trimmed = remote.trim().replace(/\/$/u, "");
  const canonicalCandidate = trimmed.toLowerCase();
  if (canonicalCandidate === "git@github.com:programmablehq/launch-policy.git") return REPOSITORY_REMOTE;
  if (canonicalCandidate === CURRENT_REPOSITORY_REMOTE.toLowerCase()) return REPOSITORY_REMOTE;
  if (canonicalCandidate === "https://github.com/programmablehq/launch-policy") return REPOSITORY_REMOTE;
  if (trimmed === "git@github.com:0xprogrammable/launch-policy.git") return REPOSITORY_REMOTE;
  if (trimmed === "https://github.com/0xprogrammable/launch-policy") return REPOSITORY_REMOTE;
  if (trimmed === "git@github.com:0xprogrammable/submit-launch.git") return REPOSITORY_REMOTE;
  if (trimmed === "https://github.com/0xprogrammable/submit-launch.git") return REPOSITORY_REMOTE;
  if (trimmed === "https://github.com/0xprogrammable/submit-launch") return REPOSITORY_REMOTE;
  return trimmed;
}

function runGitText(repositoryRoot, args, maximumBytes) {
  return runGit(repositoryRoot, args, maximumBytes).toString("utf8").trim();
}

function runGit(repositoryRoot, args, maximumBytes) {
  try {
    return childProcess.execFileSync("git", args, {
      cwd: repositoryRoot,
      encoding: "buffer",
      maxBuffer: maximumBytes,
      stdio: ["ignore", "pipe", "pipe"]
    });
  } catch (error) {
    failRuntimeFeeSettlementV1(
      "RUNTIME_FEE_PROOF_GIT_IDENTITY_INVALID",
      "Protected Git evidence identity could not be resolved.",
      error
    );
  }
}
