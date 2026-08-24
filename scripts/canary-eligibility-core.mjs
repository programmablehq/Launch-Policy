import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { TextDecoder } from "node:util";

import {
  buildLaunchPolicyBinding,
  canonicalJson,
  compareLaunchPolicyBindings
} from "./launch-policy-core.mjs";
import {
  parseWorkflowCanaryApplicationBytes,
  parseWorkflowCanaryResultBytes
} from "./workflow-canary-core.mjs";
import { parseBoundedLosslessJson } from "../vendor/programmable-v4-hook-builder/scripts/github-public-source-lossless-json.mjs";

export const CANARY_ELIGIBILITY_COMMAND_VERSION = "programmable.protected-canary-eligibility-command.v1";
export const SIGNED_CANARY_ELIGIBILITY_COMMAND_VERSION = "programmable.signed-protected-canary-eligibility-command.v1";
export const CANARY_ELIGIBILITY_ENVELOPE_VERSION = "programmable.canary-eligibility-envelope.v1";
export const MAXIMUM_CANARY_ELIGIBILITY_LIFETIME_MS = 15 * 60 * 1000;
export const CANARY_ELIGIBILITY_AUDIENCES = Object.freeze([
  "programmable.market:hidden-canary:preview",
  "programmable.market:hidden-canary:staging",
  "programmable.market:hidden-canary:production"
]);

const PROFILE_ID = "workflow-canary";
const RESULT_VERSION = "programmable.workflow-canary-result.v1";
const OUTCOME = "CANARY_WORKFLOW_PASSED";
const BASE_REPOSITORY = "0xprogrammable/launch-policy";
const BASE_REPOSITORY_ID = "1320171831";
const SIGNING_DOMAIN = Buffer.from("programmable.submit-launch.protected-canary-eligibility-command.v1\0", "utf8");
const ELIGIBILITY_ID_DOMAIN = Buffer.from("programmable.submit-launch.canary-eligibility-id.v1\0", "utf8");
const MAXIMUM_SIGNED_COMMAND_BYTES = 1024 * 1024;
const MAXIMUM_RESULT_BYTES = 512 * 1024;
const MAXIMUM_APPLICATION_BYTES = 64 * 1024;
const MAXIMUM_KEY_BYTES = 16 * 1024;
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
const SHA256 = /^sha256:[0-9a-f]{64}$/u;
const OBJECT_ID = /^[0-9a-f]{40}$/u;
const OPAQUE_ID = /^[1-9][0-9]{0,63}$/u;
const APPLICATION_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const GITHUB_LOGIN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/u;
const REPOSITORY = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;
const CANONICAL_TIMESTAMP = /^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.[0-9]{3}Z$/u;
const AUDIENCES = new Set(CANARY_ELIGIBILITY_AUDIENCES);
const ELIGIBILITY = Object.freeze({
  surface: "hidden-canary",
  publicDiscovery: false,
  productionRouting: false,
  realFunds: false,
  launchAuthorized: false
});

export class CanaryEligibilityError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.name = "CanaryEligibilityError";
    this.code = code;
  }
}

export function canaryEligibilitySigningBytes(command) {
  validateCommand(command);
  return Buffer.concat([SIGNING_DOMAIN, Buffer.from(canonicalJson(command), "utf8")]);
}

export function canaryEligibilityAuthorityKeyId(publicKey) {
  const key = normalizeTrustedPublicKey(publicKey);
  const spki = key.export({ type: "spki", format: "der" });
  return `ed25519:sha256:${crypto.createHash("sha256").update(spki).digest("hex")}`;
}

export function compileCanaryEligibilityEnvelope({
  signedCommand,
  decisionBytes,
  applicationBytes,
  trustedAuthorityPublicKey,
  trustedPolicyRecord,
  now
}) {
  const trusted = validateSignedCommandAuthorization({
    signedCommand,
    trustedAuthorityPublicKey,
    now
  });
  const currentPolicyBinding = deriveCurrentPolicyBinding(trustedPolicyRecord);
  const parsed = parseBoundInputs({
    applicationBytes,
    decisionBytes,
    trustedPolicyRecord,
    expectedApplicationId: signedCommand.command.application.applicationId
  });
  validateApplicationResultClosure(parsed.application, parsed.applicationBytes, parsed.result, currentPolicyBinding);
  validateCommandResultClosure(signedCommand.command, parsed.result, parsed.resultBytes, currentPolicyBinding);

  const signedCommandDigest = digest(Buffer.from(canonicalJson(signedCommand), "utf8"));
  const eligibilityId = calculateEligibilityId(signedCommand.command);
  const envelope = {
    schemaVersion: CANARY_ELIGIBILITY_ENVELOPE_VERSION,
    state: "eligible",
    audience: signedCommand.command.audience,
    canaryCommand: structuredClone(signedCommand.command),
    authorization: {
      ...structuredClone(signedCommand.authorization),
      signedCommandDigest
    },
    applicationDocument: structuredClone(parsed.application),
    workflowCanaryResult: structuredClone(parsed.result),
    eligibility: structuredClone(ELIGIBILITY),
    eligibilityId
  };
  validateEnvelopeShape(envelope);
  if (trusted.keyId !== envelope.authorization.keyId) {
    fail("CANARY_AUTHORITY_KEY_MISMATCH", "The signed command authority does not match the pinned Canary key.");
  }
  return deepFreeze(envelope);
}

export function verifyWebsiteCanaryEligibility({
  envelope,
  trustedAuthorityPublicKey,
  trustedPolicyRecord,
  expectedAudience,
  expectedPolicyBinding,
  now
}) {
  if (!isPlainObject(envelope) || envelope.schemaVersion !== CANARY_ELIGIBILITY_ENVELOPE_VERSION) {
    fail("CANARY_ENVELOPE_UNSUPPORTED", "Only the signed Canary eligibility envelope v1 is accepted.");
  }
  if (
    !Object.hasOwn(envelope, "authorization")
    || !Object.hasOwn(envelope, "canaryCommand")
    || !Object.hasOwn(envelope, "applicationDocument")
    || !Object.hasOwn(envelope, "workflowCanaryResult")
  ) {
    fail("CANARY_ENVELOPE_UNSUPPORTED", "Unsigned, legacy, build, result-only, and partial objects are not Canary eligibility envelopes.");
  }
  validateEnvelopeShape(envelope);
  validateAudience(expectedAudience, "CANARY_EXPECTED_AUDIENCE_INVALID");
  if (envelope.audience !== expectedAudience || envelope.canaryCommand.audience !== expectedAudience) {
    fail("CANARY_AUDIENCE_MISMATCH", "Canary eligibility is not signed for this exact Website environment.");
  }
  const currentPolicyBinding = deriveCurrentPolicyBinding(trustedPolicyRecord);
  if (!compareLaunchPolicyBindings(expectedPolicyBinding, currentPolicyBinding)) {
    fail("CANARY_EXPECTED_POLICY_BINDING_MISMATCH", "Website policy expectation does not match the current exact trusted policy.");
  }
  const signedCommand = {
    authorization: {
      algorithm: envelope.authorization.algorithm,
      keyId: envelope.authorization.keyId,
      signature: envelope.authorization.signature
    },
    command: structuredClone(envelope.canaryCommand),
    schemaVersion: SIGNED_CANARY_ELIGIBILITY_COMMAND_VERSION
  };
  validateSignedCommandAuthorization({ signedCommand, trustedAuthorityPublicKey, now });
  const expectedSignedDigest = digest(Buffer.from(canonicalJson(signedCommand), "utf8"));
  if (envelope.authorization.signedCommandDigest !== expectedSignedDigest) {
    fail("CANARY_SIGNED_COMMAND_DIGEST_MISMATCH", "The envelope does not bind the exact signed Canary command.");
  }

  const applicationBytes = Buffer.from(`${canonicalJson(envelope.applicationDocument)}\n`, "utf8");
  const resultBytes = Buffer.from(`${canonicalJson(envelope.workflowCanaryResult)}\n`, "utf8");
  const parsed = parseBoundInputs({
    applicationBytes,
    decisionBytes: resultBytes,
    trustedPolicyRecord,
    expectedApplicationId: envelope.canaryCommand.application.applicationId
  });
  validateApplicationResultClosure(parsed.application, parsed.applicationBytes, parsed.result, currentPolicyBinding);
  validateCommandResultClosure(envelope.canaryCommand, parsed.result, parsed.resultBytes, currentPolicyBinding);
  if (
    canonicalJson(envelope.applicationDocument) !== canonicalJson(parsed.application)
    || canonicalJson(envelope.workflowCanaryResult) !== canonicalJson(parsed.result)
    || canonicalJson(envelope.eligibility) !== canonicalJson(ELIGIBILITY)
    || canonicalJson(envelope.canaryCommand.eligibility) !== canonicalJson(ELIGIBILITY)
  ) {
    fail("CANARY_ENVELOPE_BINDING_MISMATCH", "Embedded Canary artifacts or authority declarations do not match the signed command.");
  }
  const expectedEligibilityId = calculateEligibilityId(envelope.canaryCommand);
  if (envelope.eligibilityId !== expectedEligibilityId) {
    fail("CANARY_ELIGIBILITY_ID_MISMATCH", "The Canary eligibility id does not bind the immutable result identity.");
  }
  return deepFreeze(structuredClone(envelope));
}

export function readCanonicalCanaryEligibilityCommandFile(filePath) {
  const bytes = readStableRegularFile(filePath, MAXIMUM_SIGNED_COMMAND_BYTES, "CANARY_SIGNED_COMMAND_FILE_INVALID");
  const value = parseCanonicalJsonBytes(bytes, "CANARY_SIGNED_COMMAND_JSON_INVALID", "CANARY_SIGNED_COMMAND_JSON_NONCANONICAL");
  validateSignedCommand(value);
  return deepFreeze(value);
}

export function readCanaryEligibilityApplicationFile(filePath) {
  return readStableRegularFile(filePath, MAXIMUM_APPLICATION_BYTES, "CANARY_APPLICATION_FILE_INVALID");
}

export function readWorkflowCanaryResultFile(filePath) {
  return readStableRegularFile(filePath, MAXIMUM_RESULT_BYTES, "CANARY_RESULT_FILE_INVALID");
}

export function readCanaryEligibilityAuthorityPublicKeyFile(filePath) {
  return readStableRegularFile(filePath, MAXIMUM_KEY_BYTES, "CANARY_AUTHORITY_KEY_FILE_INVALID");
}

function parseBoundInputs({ applicationBytes, decisionBytes, trustedPolicyRecord, expectedApplicationId }) {
  let parsedResult;
  try {
    parsedResult = parseWorkflowCanaryResultBytes(decisionBytes, trustedPolicyRecord);
  } catch (error) {
    translatePolicyTrust(error);
    translateBoundArtifactError(error, "CANARY_RESULT_INVALID", "The exact workflow-canary result is invalid.");
  }
  let application;
  try {
    application = parseWorkflowCanaryApplicationBytes(applicationBytes, { expectedApplicationId });
  } catch (error) {
    translateBoundArtifactError(error, "CANARY_APPLICATION_INVALID", "The exact workflow-canary application is invalid.");
  }
  return {
    application,
    applicationBytes: Buffer.from(applicationBytes),
    result: parsedResult.result,
    resultBytes: parsedResult.bytes
  };
}

function deriveCurrentPolicyBinding(trustedPolicyRecord) {
  try {
    return buildLaunchPolicyBinding(trustedPolicyRecord, PROFILE_ID);
  } catch (error) {
    translatePolicyTrust(error);
    fail("CANARY_POLICY_INVALID", "The current trusted policy cannot produce the enabled workflow-canary binding.", error);
  }
}

function translatePolicyTrust(error) {
  if (error?.code === "LAUNCH_POLICY_TRUST_INVALID") {
    fail("CANARY_POLICY_TRUST_INVALID", "Canary eligibility requires the exact WeakSet-bound trusted policy record.", error);
  }
}

function translateBoundArtifactError(error, fallbackCode, message) {
  if (error instanceof CanaryEligibilityError) throw error;
  fail(typeof error?.code === "string" ? error.code : fallbackCode, message, error);
}

function validateApplicationResultClosure(application, applicationBytes, result, currentPolicyBinding) {
  const observedBlob = {
    path: `canary-submissions/${application.applicationId}/application.json`,
    byteLength: applicationBytes.length,
    gitBlobOid: gitBlobOid(applicationBytes),
    sha256: digest(applicationBytes)
  };
  if (
    application.applicationId !== result.application.applicationId
    || application.applicationRevision !== result.application.applicationRevision
    || canonicalJson(application.builder) !== canonicalJson(result.application.builder)
    || canonicalJson(observedBlob) !== canonicalJson(result.application.blob)
  ) {
    fail("CANARY_APPLICATION_BINDING_MISMATCH", "Exact Canary application bytes or identity do not match the trusted workflow result.");
  }
  if (canonicalJson(application.source) !== canonicalJson(result.source)) {
    fail("CANARY_SOURCE_BINDING_MISMATCH", "Canary application source does not match the trusted workflow result.");
  }
  if (
    !compareLaunchPolicyBindings(application.expectedPolicyBinding, currentPolicyBinding)
    || !compareLaunchPolicyBindings(result.policyBinding, currentPolicyBinding)
  ) {
    fail("CANARY_POLICY_BINDING_MISMATCH", "Canary application and result must bind the exact current trusted policy.");
  }
  if (
    result.pullRequest.authorGitHubUserId !== application.builder.githubUserId
    || result.pullRequest.authorGitHubLogin.toLowerCase() !== application.builder.githubLogin.toLowerCase()
    || result.pullRequest.base.repository !== BASE_REPOSITORY
    || result.pullRequest.base.numericRepositoryId !== BASE_REPOSITORY_ID
    || result.pullRequest.base.commit !== currentPolicyBinding.baseCommit
    || result.pullRequest.base.tree !== currentPolicyBinding.baseTree
  ) {
    fail("CANARY_PULL_REQUEST_BINDING_MISMATCH", "Canary PR author or protected-base identity is not closed over the application and policy.");
  }
}

function validateCommandResultClosure(command, result, resultBytes, currentPolicyBinding) {
  if (canonicalJson(command.application) !== canonicalJson(result.application)) {
    fail("CANARY_APPLICATION_BINDING_MISMATCH", "Signed Canary application identity does not match the trusted result.");
  }
  if (canonicalJson(command.pullRequest) !== canonicalJson(result.pullRequest)) {
    fail("CANARY_PULL_REQUEST_BINDING_MISMATCH", "Signed Canary pull-request identity does not match the trusted result.");
  }
  if (canonicalJson(command.source) !== canonicalJson(result.source)) {
    fail("CANARY_SOURCE_BINDING_MISMATCH", "Signed Canary source identity does not match the trusted result.");
  }
  if (
    !compareLaunchPolicyBindings(command.policyBinding, currentPolicyBinding)
    || !compareLaunchPolicyBindings(result.policyBinding, currentPolicyBinding)
  ) {
    fail("CANARY_POLICY_BINDING_MISMATCH", "Signed Canary policy identity is not the exact current trusted binding.");
  }
  const expectedResultBinding = {
    schemaVersion: RESULT_VERSION,
    profileId: PROFILE_ID,
    status: "passed",
    result: OUTCOME,
    outcome: OUTCOME,
    digest: result.digest,
    reviewDecisionDigest: result.reviewDecisionDigest,
    byteLength: resultBytes.length,
    sha256: digest(resultBytes)
  };
  if (canonicalJson(command.workflowCanaryResult) !== canonicalJson(expectedResultBinding)) {
    fail("CANARY_RESULT_BINDING_MISMATCH", "Signed Canary result identity does not bind the exact canonical workflow result bytes.");
  }
  requireObject(command.eligibility, "CANARY_COMMAND_INVALID");
  exactKeys(command.eligibility, ["launchAuthorized", "productionRouting", "publicDiscovery", "realFunds", "surface"], "CANARY_COMMAND_INVALID");
  if (canonicalJson(command.eligibility) !== canonicalJson(ELIGIBILITY)) {
    fail("CANARY_ELIGIBILITY_INVALID", "Canary eligibility must remain hidden and grant no production, funds, or launch authority.");
  }
}

function validateSignedCommandAuthorization({ signedCommand, trustedAuthorityPublicKey, now }) {
  validateSignedCommand(signedCommand);
  const trustedKey = normalizeTrustedPublicKey(trustedAuthorityPublicKey);
  const keyId = canaryEligibilityAuthorityKeyId(trustedKey);
  if (signedCommand.authorization.keyId !== keyId) {
    fail("CANARY_AUTHORITY_KEY_MISMATCH", "The Canary command was not addressed to the pinned trusted key.");
  }
  const signature = decodeSignature(signedCommand.authorization.signature);
  if (!crypto.verify(null, canaryEligibilitySigningBytes(signedCommand.command), trustedKey, signature)) {
    fail("CANARY_SIGNATURE_INVALID", "The Canary eligibility signature is invalid for its separate signing domain.");
  }
  validateTimeWindow(signedCommand.command, now);
  return { keyId, trustedKey };
}

function validateSignedCommand(value) {
  requireObject(value, "CANARY_SIGNED_COMMAND_INVALID");
  exactKeys(value, ["authorization", "command", "schemaVersion"], "CANARY_SIGNED_COMMAND_INVALID");
  if (value.schemaVersion !== SIGNED_CANARY_ELIGIBILITY_COMMAND_VERSION) {
    fail("CANARY_SIGNED_COMMAND_UNSUPPORTED", "Signed Canary command schema is unsupported.");
  }
  requireObject(value.authorization, "CANARY_SIGNED_COMMAND_INVALID");
  exactKeys(value.authorization, ["algorithm", "keyId", "signature"], "CANARY_SIGNED_COMMAND_INVALID");
  if (
    value.authorization.algorithm !== "ed25519"
    || !/^ed25519:sha256:[0-9a-f]{64}$/u.test(value.authorization.keyId ?? "")
    || !/^[A-Za-z0-9_-]{86}$/u.test(value.authorization.signature ?? "")
  ) {
    fail("CANARY_SIGNED_COMMAND_INVALID", "Canary command authorization is malformed.");
  }
  validateCommand(value.command);
}

function validateCommand(command) {
  requireObject(command, "CANARY_COMMAND_INVALID");
  exactKeys(command, [
    "action", "application", "audience", "eligibility", "issuedAt", "issuedBy", "policyBinding",
    "pullRequest", "schemaVersion", "source", "supersedes", "validUntil", "workflowCanaryResult"
  ], "CANARY_COMMAND_INVALID");
  if (command.schemaVersion !== CANARY_ELIGIBILITY_COMMAND_VERSION || command.action !== "issue-hidden-canary-eligibility") {
    fail("CANARY_COMMAND_UNSUPPORTED", "Canary eligibility command identity or action is unsupported.");
  }
  validateAudience(command.audience, "CANARY_AUDIENCE_INVALID");
  canonicalTimestamp(command.issuedAt, "CANARY_COMMAND_TIME_INVALID");
  canonicalTimestamp(command.validUntil, "CANARY_COMMAND_TIME_INVALID");
  validateIssuer(command.issuedBy);
  validateResultApplication(command.application);
  validatePullRequest(command.pullRequest);
  validateGitIdentity(command.source, "CANARY_SOURCE_BINDING_INVALID");
  validatePolicyBinding(command.policyBinding);
  validateResultBinding(command.workflowCanaryResult);
  requireObject(command.eligibility, "CANARY_COMMAND_INVALID");
  exactKeys(command.eligibility, ["launchAuthorized", "productionRouting", "publicDiscovery", "realFunds", "surface"], "CANARY_COMMAND_INVALID");
  if (canonicalJson(command.eligibility) !== canonicalJson(ELIGIBILITY)) {
    fail("CANARY_ELIGIBILITY_INVALID", "Canary eligibility constants cannot grant production authority.");
  }
  if (command.supersedes !== null) {
    fail("CANARY_SUPERSESSION_UNSUPPORTED", "Canary eligibility v1 does not claim stateless supersession authority.");
  }
}

function validateIssuer(issuer) {
  requireObject(issuer, "CANARY_ISSUER_INVALID");
  exactKeys(issuer, ["githubLogin", "githubUserId", "mode"], "CANARY_ISSUER_INVALID");
  if (
    !GITHUB_LOGIN.test(issuer.githubLogin ?? "")
    || !OPAQUE_ID.test(issuer.githubUserId ?? "")
    || !["automation-review", "human-review"].includes(issuer.mode)
  ) {
    fail("CANARY_ISSUER_INVALID", "Canary issuer audit metadata is malformed.");
  }
}

function validateResultApplication(application) {
  requireObject(application, "CANARY_APPLICATION_BINDING_INVALID");
  exactKeys(application, ["applicationId", "applicationRevision", "blob", "builder"], "CANARY_APPLICATION_BINDING_INVALID");
  if (
    !APPLICATION_ID.test(application.applicationId ?? "")
    || application.applicationId.length > 128
    || !Number.isSafeInteger(application.applicationRevision)
    || application.applicationRevision < 1
    || application.applicationRevision > 1_000_000_000
  ) fail("CANARY_APPLICATION_BINDING_INVALID", "Canary application identity is malformed.");
  requireObject(application.builder, "CANARY_APPLICATION_BINDING_INVALID");
  exactKeys(application.builder, ["githubLogin", "githubUserId"], "CANARY_APPLICATION_BINDING_INVALID");
  if (!GITHUB_LOGIN.test(application.builder.githubLogin ?? "") || !OPAQUE_ID.test(application.builder.githubUserId ?? "")) {
    fail("CANARY_APPLICATION_BINDING_INVALID", "Canary builder identity is malformed.");
  }
  requireObject(application.blob, "CANARY_APPLICATION_BINDING_INVALID");
  exactKeys(application.blob, ["byteLength", "gitBlobOid", "path", "sha256"], "CANARY_APPLICATION_BINDING_INVALID");
  if (
    application.blob.path !== `canary-submissions/${application.applicationId}/application.json`
    || !Number.isSafeInteger(application.blob.byteLength)
    || application.blob.byteLength < 2
    || application.blob.byteLength > MAXIMUM_APPLICATION_BYTES
    || !OBJECT_ID.test(application.blob.gitBlobOid ?? "")
    || !SHA256.test(application.blob.sha256 ?? "")
  ) fail("CANARY_APPLICATION_BINDING_INVALID", "Canary application blob identity is malformed.");
}

function validatePullRequest(pullRequest) {
  requireObject(pullRequest, "CANARY_PULL_REQUEST_BINDING_INVALID");
  exactKeys(pullRequest, ["authorGitHubLogin", "authorGitHubUserId", "base", "head", "mergeCommit", "number"], "CANARY_PULL_REQUEST_BINDING_INVALID");
  if (
    !/^[1-9][0-9]{0,19}$/u.test(pullRequest.number ?? "")
    || !GITHUB_LOGIN.test(pullRequest.authorGitHubLogin ?? "")
    || !OPAQUE_ID.test(pullRequest.authorGitHubUserId ?? "")
    || !OBJECT_ID.test(pullRequest.mergeCommit ?? "")
  ) fail("CANARY_PULL_REQUEST_BINDING_INVALID", "Canary pull-request identity is malformed.");
  validateGitIdentity(pullRequest.base, "CANARY_PULL_REQUEST_BINDING_INVALID");
  validateGitIdentity(pullRequest.head, "CANARY_PULL_REQUEST_BINDING_INVALID");
  if (pullRequest.base.repository !== BASE_REPOSITORY || pullRequest.base.numericRepositoryId !== BASE_REPOSITORY_ID) {
    fail("CANARY_PULL_REQUEST_BINDING_INVALID", "Canary pull request must target the fixed Submit Launch repository.");
  }
}

function validateGitIdentity(value, code) {
  requireObject(value, code);
  exactKeys(value, ["commit", "numericRepositoryId", "repository", "tree"], code);
  if (
    !REPOSITORY.test(value.repository ?? "")
    || value.repository.length > 202
    || !OPAQUE_ID.test(value.numericRepositoryId ?? "")
    || !OBJECT_ID.test(value.commit ?? "")
    || !OBJECT_ID.test(value.tree ?? "")
  ) fail(code, "Exact Git identity is malformed.");
}

function validatePolicyBinding(value) {
  requireObject(value, "CANARY_POLICY_BINDING_INVALID");
  exactKeys(value, [
    "baseCommit", "baseTree", "gitBlobOid", "numericRepositoryId", "path", "policyId",
    "policyVersion", "profileId", "repository", "schemaVersion", "sha256"
  ], "CANARY_POLICY_BINDING_INVALID");
  if (
    value.schemaVersion !== "programmable.launch-policy-binding.v1"
    || value.repository !== BASE_REPOSITORY
    || value.numericRepositoryId !== BASE_REPOSITORY_ID
    || value.path !== "policy/launch-policy.v1.json"
    || value.profileId !== PROFILE_ID
    || !OBJECT_ID.test(value.baseCommit ?? "")
    || !OBJECT_ID.test(value.baseTree ?? "")
    || !OBJECT_ID.test(value.gitBlobOid ?? "")
    || !/^[a-z0-9][a-z0-9.-]{2,79}$/u.test(value.policyId ?? "")
    || !/^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u.test(value.policyVersion ?? "")
    || !SHA256.test(value.sha256 ?? "")
  ) fail("CANARY_POLICY_BINDING_INVALID", "Workflow-canary policy binding is malformed.");
}

function validateResultBinding(value) {
  requireObject(value, "CANARY_RESULT_BINDING_INVALID");
  exactKeys(value, ["byteLength", "digest", "outcome", "profileId", "result", "reviewDecisionDigest", "schemaVersion", "sha256", "status"], "CANARY_RESULT_BINDING_INVALID");
  if (
    value.schemaVersion !== RESULT_VERSION
    || value.profileId !== PROFILE_ID
    || value.status !== "passed"
    || value.result !== OUTCOME
    || value.outcome !== OUTCOME
    || !Number.isSafeInteger(value.byteLength)
    || value.byteLength < 2
    || value.byteLength > MAXIMUM_RESULT_BYTES
    || !SHA256.test(value.digest ?? "")
    || !SHA256.test(value.reviewDecisionDigest ?? "")
    || !SHA256.test(value.sha256 ?? "")
  ) fail("CANARY_RESULT_BINDING_INVALID", "Workflow-canary result binding is malformed or non-passing.");
}

function validateEnvelopeShape(envelope) {
  requireObject(envelope, "CANARY_ENVELOPE_INVALID");
  exactKeys(envelope, [
    "applicationDocument", "audience", "authorization", "canaryCommand", "eligibility", "eligibilityId",
    "schemaVersion", "state", "workflowCanaryResult"
  ], "CANARY_ENVELOPE_INVALID");
  if (
    envelope.schemaVersion !== CANARY_ELIGIBILITY_ENVELOPE_VERSION
    || envelope.state !== "eligible"
    || !SHA256.test(envelope.eligibilityId ?? "")
  ) fail("CANARY_ENVELOPE_INVALID", "Canary eligibility envelope identity is malformed.");
  validateAudience(envelope.audience, "CANARY_ENVELOPE_INVALID");
  try {
    validateCommand(envelope.canaryCommand);
  } catch (error) {
    fail("CANARY_ENVELOPE_INVALID", "The embedded signed Canary command is malformed.", error);
  }
  requireObject(envelope.authorization, "CANARY_ENVELOPE_INVALID");
  exactKeys(envelope.authorization, ["algorithm", "keyId", "signature", "signedCommandDigest"], "CANARY_ENVELOPE_INVALID");
  if (
    envelope.authorization.algorithm !== "ed25519"
    || !/^ed25519:sha256:[0-9a-f]{64}$/u.test(envelope.authorization.keyId ?? "")
    || !/^[A-Za-z0-9_-]{86}$/u.test(envelope.authorization.signature ?? "")
    || !SHA256.test(envelope.authorization.signedCommandDigest ?? "")
    || envelope.audience !== envelope.canaryCommand.audience
    || canonicalJson(envelope.eligibility) !== canonicalJson(ELIGIBILITY)
  ) fail("CANARY_ENVELOPE_INVALID", "Canary envelope authorization or non-production constants are malformed.");
  requireObject(envelope.applicationDocument, "CANARY_ENVELOPE_INVALID");
  requireObject(envelope.workflowCanaryResult, "CANARY_ENVELOPE_INVALID");
}

function validateTimeWindow(command, now) {
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
    fail("CANARY_SYSTEM_TIME_INVALID", "Canary compiler and Website clocks must be valid Dates.");
  }
  const issuedAt = Date.parse(command.issuedAt);
  const validUntil = Date.parse(command.validUntil);
  if (validUntil <= issuedAt || validUntil - issuedAt > MAXIMUM_CANARY_ELIGIBILITY_LIFETIME_MS) {
    fail("CANARY_COMMAND_LIFETIME_INVALID", "Canary eligibility lifetime must be positive and no longer than fifteen minutes.");
  }
  if (now.getTime() < issuedAt || now.getTime() > validUntil) {
    fail("CANARY_COMMAND_NOT_CURRENT", "Canary eligibility command is outside its inclusive validity window.");
  }
}

function calculateEligibilityId(command) {
  const immutable = {
    application: command.application,
    audience: command.audience,
    eligibility: command.eligibility,
    policyBinding: command.policyBinding,
    pullRequest: command.pullRequest,
    source: command.source,
    workflowCanaryResult: command.workflowCanaryResult
  };
  return digest(Buffer.concat([ELIGIBILITY_ID_DOMAIN, Buffer.from(canonicalJson(immutable), "utf8")]));
}

function validateAudience(value, code) {
  if (!AUDIENCES.has(value)) {
    fail(code, "Canary audience must name one closed hidden-canary Website environment.");
  }
}

function parseCanonicalJsonBytes(bytes, invalidCode, noncanonicalCode) {
  let buffer;
  let source;
  let value;
  try {
    buffer = Buffer.from(bytes);
    source = utf8.decode(buffer);
    parseBoundedLosslessJson(source);
    value = JSON.parse(source);
  } catch (error) {
    fail(invalidCode, "Input must be bounded duplicate-free UTF-8 JSON.", error);
  }
  if (!buffer.equals(Buffer.from(`${canonicalJson(value)}\n`, "utf8"))) {
    fail(noncanonicalCode, "Input must be canonical JSON followed by exactly one LF.");
  }
  return value;
}

function readStableRegularFile(filePath, maximumBytes, code) {
  if (typeof filePath !== "string" || filePath.length < 1) fail(code, "An explicit input file path is required.");
  const target = path.resolve(filePath);
  let initial;
  try {
    initial = fs.lstatSync(target, { bigint: true });
  } catch (error) {
    fail(code, "A required Canary input file is unavailable.", error);
  }
  if (!isSafeRegularFileSnapshot(initial, maximumBytes)) {
    fail(code, "Canary input must be a bounded non-executable single-link regular file.");
  }
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_CLOEXEC ?? 0);
  let descriptor;
  try {
    descriptor = fs.openSync(target, flags);
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!sameFile(initial, before) || !isSafeRegularFileSnapshot(before, maximumBytes)) {
      fail(code, "Canary input path changed before its bounded read.");
    }
    const bytes = readBoundedDescriptor(descriptor, maximumBytes, code);
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (
      !sameFile(before, after)
      || !isSafeRegularFileSnapshot(after, maximumBytes)
      || BigInt(bytes.length) !== after.size
    ) {
      fail(code, "Canary input changed during its bounded read.");
    }
    return Buffer.from(bytes);
  } catch (error) {
    if (error instanceof CanaryEligibilityError) throw error;
    fail(code, "Canary input could not be read safely.", error);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function isSafeRegularFileSnapshot(snapshot, maximumBytes) {
  return snapshot.isFile()
    && snapshot.nlink === 1n
    && (snapshot.mode & 0o111n) === 0n
    && snapshot.size >= 2n
    && snapshot.size <= BigInt(maximumBytes);
}

function readBoundedDescriptor(descriptor, maximumBytes, code) {
  const buffer = Buffer.allocUnsafe(maximumBytes + 1);
  let offset = 0;
  while (offset < buffer.length) {
    const bytesRead = fs.readSync(descriptor, buffer, offset, buffer.length - offset, null);
    if (bytesRead === 0) break;
    offset += bytesRead;
  }
  if (offset > maximumBytes) {
    fail(code, "Canary input exceeded its byte limit during the bounded read.");
  }
  return buffer.subarray(0, offset);
}

function sameFile(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.nlink === right.nlink
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function normalizeTrustedPublicKey(publicKey) {
  let key;
  try {
    key = publicKey instanceof crypto.KeyObject ? publicKey : crypto.createPublicKey(publicKey);
  } catch (error) {
    fail("CANARY_AUTHORITY_KEY_INVALID", "Pinned Canary authority public key is invalid.", error);
  }
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") {
    fail("CANARY_AUTHORITY_KEY_INVALID", "Pinned Canary authority key must be an Ed25519 public key.");
  }
  return key;
}

function decodeSignature(value) {
  const bytes = Buffer.from(value ?? "", "base64url");
  if (bytes.length !== 64 || bytes.toString("base64url") !== value) {
    fail("CANARY_SIGNATURE_ENCODING_INVALID", "Canary signature must be canonical unpadded base64url Ed25519 bytes.");
  }
  return bytes;
}

function canonicalTimestamp(value, code) {
  if (typeof value !== "string" || !CANONICAL_TIMESTAMP.test(value)) {
    fail(code, "Canary timestamp is malformed.");
  }
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) {
    fail(code, "Canary timestamps must be canonical UTC ISO-8601 with milliseconds.");
  }
}

function gitBlobOid(bytes) {
  return crypto.createHash("sha1")
    .update(Buffer.from(`blob ${bytes.length}\0`, "utf8"))
    .update(bytes)
    .digest("hex");
}

function digest(bytes) {
  return `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
}

function requireObject(value, code) {
  if (!isPlainObject(value)) fail(code, "Canary eligibility object must be an ordinary JSON object.");
}

function exactKeys(value, expected, code) {
  if (!isPlainObject(value) || Object.keys(value).length !== expected.length || expected.some((key) => !Object.hasOwn(value, key))) {
    fail(code, "Canary eligibility object contains missing or unsupported fields.");
  }
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function fail(code, message, cause) {
  throw new CanaryEligibilityError(code, message, cause ? { cause } : undefined);
}
