import childProcess from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  buildLaunchPolicyBinding,
  canonicalJson as canonicalPolicyJson,
  readTrustedLaunchPolicyFromGit
} from "../scripts/launch-policy-core.mjs";
import { evaluateTrustedLaunchPolicyReview } from "./launch-policy-review-core.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SHA256 = /^sha256:[0-9a-f]{64}$/u;
const OBJECT_ID = /^[0-9a-f]{40}$/u;
const REPOSITORY = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;
const OBLIGATION_ID = /^[a-z0-9][a-z0-9._-]{2,79}$/u;
const AXES = new Set(["artifact_identity", "functionality", "disclosure", "integrity", "launch_compatibility", "advisory"]);
const OWNERS = new Set(["candidate", "platform"]);
const STATES = new Set(["closed", "unknown", "contradicted", "not_applicable"]);
const LEGACY_WITNESS_RULES = new Set([
  "BROKEN_ACCOUNTING_OR_CLAIM",
  "CONCEALED_EXIT_DENIAL",
  "PARTY_CONTROLLED_OBJECTIVE_OUTCOME",
  "REVIEWED_ARTIFACT_SUBSTITUTION",
  "UNAUTHORIZED_VALUE_DIVERSION",
  "UNBOUNDED_RETROACTIVE_AUTHORITY"
]);

// Compatibility only: legacy Open Review inputs are bounded and projected into
// the current checker-only production profile. They can no longer select or
// inject policy, satisfy current rules, or produce launch authority.
export function evaluateOpenReview(input) {
  validateOpenReviewInput(input);
  const expectedBaseCommit = trustedLocalHead();
  const policyRecord = readTrustedLaunchPolicyFromGit({
    repositoryRoot,
    expectedBaseCommit
  });
  return evaluateTrustedLaunchPolicyReview({
    input: toCentralReviewInput(
      input,
      buildLaunchPolicyBinding(policyRecord, "production-launch")
    ),
    repositoryRoot,
    expectedBaseCommit
  });
}

export function validateOpenReviewInput(input) {
  if (!plainObject(input)) fail("INPUT_INVALID", "review input must be an object");
  exactKeys(input, ["schemaVersion", "reviewedRevision", "currentRevision", "obligations", "witnesses"]);
  if (input.schemaVersion !== "programmable.open-review-input.v1") fail("SCHEMA_VERSION_INVALID", "unsupported legacy review input version");
  validateRevision(input.reviewedRevision, "reviewedRevision");
  validateRevision(input.currentRevision, "currentRevision");
  if (!Array.isArray(input.obligations) || input.obligations.length < 1 || input.obligations.length > 120) fail("OBLIGATIONS_INVALID", "legacy obligations must be a bounded non-empty array");
  if (!Array.isArray(input.witnesses) || input.witnesses.length > 8 || input.obligations.length + input.witnesses.length > 128) fail("WITNESSES_INVALID", "legacy witnesses must be a bounded array");

  const ids = new Set();
  for (const item of input.obligations) {
    if (!plainObject(item)) fail("OBLIGATION_INVALID", "every obligation must be an object");
    exactKeys(item, ["id", "axis", "critical", "owner", "state", "statement", "evidence"]);
    if (!OBLIGATION_ID.test(item.id) || ids.has(item.id)) fail("OBLIGATION_ID_INVALID", "obligation ids must be unique and canonical");
    ids.add(item.id);
    if (!AXES.has(item.axis) || !OWNERS.has(item.owner) || !STATES.has(item.state)) fail("OBLIGATION_ENUM_INVALID", `obligation ${item.id} contains an unsupported value`);
    if (typeof item.critical !== "boolean") fail("OBLIGATION_CRITICAL_INVALID", `obligation ${item.id} critical must be boolean`);
    if (!safeText(item.statement, 1000)) fail("OBLIGATION_STATEMENT_INVALID", `obligation ${item.id} statement is invalid`);
    if (!Array.isArray(item.evidence) || new Set(item.evidence).size !== item.evidence.length || item.evidence.some((digest) => !SHA256.test(digest))) fail("OBLIGATION_EVIDENCE_INVALID", `obligation ${item.id} evidence is invalid`);
    if (isClosed(item) && item.evidence.length === 0) fail("CLOSED_WITHOUT_EVIDENCE", `obligation ${item.id} cannot close without evidence`);
    if (item.axis === "advisory" && item.critical) fail("ADVISORY_CRITICAL_INVALID", `advisory ${item.id} cannot be decision-critical`);
  }

  for (const witness of input.witnesses) validateWitness(witness);
  return true;
}

export const canonicalJson = canonicalPolicyJson;

function toCentralReviewInput(input, expectedPolicyBinding) {
  return {
    schemaVersion: "programmable.launch-policy-review-input.v1",
    profileId: "production-launch",
    expectedPolicyBinding,
    expectedSubject: toSubject(input.reviewedRevision),
    currentSubject: toSubject(input.currentRevision),
    evaluations: [],
    observations: [
      ...input.obligations.map((obligation) => ({
        analyzerId: "legacy-open-review-v1",
        ruleId: "LEGACY_V2.ADMISSION",
        summary: `${obligation.id}: ${obligation.statement}`.slice(0, 1000)
      })),
      ...input.witnesses.map((witness) => ({
        analyzerId: "legacy-open-review-v1",
        ruleId: "LEGACY_V2.ADMISSION",
        summary: `Legacy witness ${witness.ruleId}: ${witness.violatedProperty}`.slice(0, 1000)
      }))
    ]
  };
}

function toSubject(revision) {
  return {
    numericRepositoryId: String(revision.numericRepositoryId),
    repository: revision.repository,
    commit: revision.commit,
    tree: revision.tree,
    configurationHash: revision.configurationHash,
    usesUniswapV4: true,
    routerProvenanceRequired: true
  };
}

function trustedLocalHead() {
  try {
    return childProcess.execFileSync("git", ["rev-parse", "--verify", "HEAD^{commit}"], {
      cwd: repositoryRoot,
      encoding: "utf8",
      maxBuffer: 128,
      stdio: ["ignore", "pipe", "pipe"]
    }).trim();
  } catch (error) {
    fail("REVIEW_BASE_IDENTITY_INVALID", "local checker could not resolve its exact Submit Launch commit", error);
  }
}

function validateRevision(value, label) {
  if (!plainObject(value)) fail("REVISION_INVALID", `${label} must be an object`);
  exactKeys(value, ["numericRepositoryId", "repository", "commit", "tree", "configurationHash"]);
  if (!Number.isSafeInteger(value.numericRepositoryId) || value.numericRepositoryId < 1) fail("REVISION_REPOSITORY_ID_INVALID", `${label} repository id is invalid`);
  if (!REPOSITORY.test(value.repository)) fail("REVISION_REPOSITORY_INVALID", `${label} repository is invalid`);
  if (!OBJECT_ID.test(value.commit) || !OBJECT_ID.test(value.tree) || !SHA256.test(value.configurationHash)) fail("REVISION_IDENTITY_INVALID", `${label} identity is invalid`);
}

function validateWitness(witness) {
  if (!plainObject(witness)) fail("WITNESS_INVALID", "every witness must be an object");
  exactKeys(witness, ["ruleId", "universal", "revisionBound", "reachable", "complete", "independentlyReplayed", "sequenceHash", "affectedActors", "affectedValue", "violatedProperty", "reproduction"]);
  if (!LEGACY_WITNESS_RULES.has(witness.ruleId)) fail("WITNESS_RULE_INVALID", "legacy witness rule is not recognized");
  for (const key of ["universal", "revisionBound", "reachable", "complete", "independentlyReplayed"]) {
    if (typeof witness[key] !== "boolean") fail("WITNESS_FLAG_INVALID", `witness ${key} must be boolean`);
  }
  if (!SHA256.test(witness.sequenceHash)) fail("WITNESS_SEQUENCE_INVALID", "witness sequence hash is invalid");
  for (const [key, maximum] of [["affectedActors", 500], ["affectedValue", 500], ["violatedProperty", 1000], ["reproduction", 2000]]) {
    if (!safeText(witness[key], maximum)) fail("WITNESS_TEXT_INVALID", `witness ${key} is invalid`);
  }
}

function isClosed(item) {
  return item.state === "closed" || item.state === "not_applicable";
}

function safeText(value, maximumLength) {
  return typeof value === "string"
    && value.length > 0
    && value.length <= maximumLength
    && !/[\u0000-\u001f\u007f\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/u.test(value);
}

function exactKeys(value, expected) {
  if (canonicalJson(Object.keys(value).sort()) !== canonicalJson([...expected].sort())) fail("FIELDS_INVALID", "object contains missing or unexpected fields");
}

function plainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function fail(code, message, cause) {
  const error = new Error(message, cause ? { cause } : undefined);
  error.code = code;
  throw error;
}
