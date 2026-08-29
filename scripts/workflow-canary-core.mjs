import childProcess from "node:child_process";
import crypto from "node:crypto";
import path from "node:path";
import { TextDecoder } from "node:util";

import {
  GITHUB_PUBLIC_SOURCE_CONTRACT_V1,
  GitHubPublicSourceError,
  parseBoundedLosslessJson,
  resolveGitHubPublicSourceV1
} from "../vendor/programmable-applicant-validator/scripts/public-applicant-validator.mjs";
import {
  canonicalLaunchPolicyDecision,
  evaluateTrustedLaunchPolicyReview
} from "../review/launch-policy-review-core.mjs";
import {
  buildLaunchPolicyBinding,
  canonicalJson,
  compareLaunchPolicyBindings,
  evaluateLaunchPolicyRules,
  readTrustedLaunchPolicyFromGit,
  rulesForProfile
} from "./launch-policy-core.mjs";

const APPLICATION_SCHEMA_VERSION = "programmable.workflow-canary-application.v1";
const RESULT_SCHEMA_VERSION = "programmable.workflow-canary-result.v1";
const PROFILE_ID = "workflow-canary";
const OUTCOME = "CANARY_WORKFLOW_PASSED";
const MAXIMUM_APPLICATION_BYTES = 64 * 1024;
const MAXIMUM_RESULT_BYTES = 512 * 1024;
const BASE_REPOSITORY = "programmablehq/Launch-Policy";
const BASE_REPOSITORY_ID = "1320171831";
const OBJECT_ID = /^[0-9a-f]{40}$/u;
const SHA256 = /^sha256:[0-9a-f]{64}$/u;
const POSITIVE_DECIMAL = /^[1-9][0-9]{0,63}$/u;
const PULL_REQUEST_NUMBER = /^[1-9][0-9]{0,19}$/u;
const APPLICATION_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const REPOSITORY = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;
const GITHUB_LOGIN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/u;
const RULE_ID = /^[A-Z][A-Z0-9_]*(?:\.[A-Z][A-Z0-9_]*)+$/u;
const CANARY_PATH = /^canary-submissions\/([a-z0-9]+(?:-[a-z0-9]+)*)\/application\.json$/u;
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
const RESULT_AUTHORITY = Object.freeze({
  checkerOnly: true,
  hiddenCanaryOnly: true,
  independentAudit: false,
  launchAuthorized: false,
  productionDiscoveryAllowed: false,
  productionRoutingAllowed: false,
  publicRoutingAllowed: false,
  realUserFundsAllowed: false
});

export class WorkflowCanaryError extends Error {
  constructor(code, message, { kind = "candidate", cause } = {}) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "WorkflowCanaryError";
    this.code = code;
    this.kind = kind;
  }
}

export function parseWorkflowCanaryApplicationBytes(bytes, options) {
  if (!isPlainObject(options) || !sameKeys(options, ["expectedApplicationId"])) {
    systemBlocked("CANARY_ARGUMENTS_INVALID", "Canary application parsing requires only the expected application id.");
  }
  const { expectedApplicationId } = options;
  if (!APPLICATION_ID.test(expectedApplicationId ?? "") || expectedApplicationId.length > 128) {
    systemBlocked("CANARY_ARGUMENTS_INVALID", "The expected canary application id is malformed.");
  }
  const buffer = boundedBytes(bytes, MAXIMUM_APPLICATION_BYTES, "CANARY_APPLICATION_SIZE_INVALID");
  const application = parseLosslessJson(buffer, "CANARY_JSON_INVALID");
  validateWorkflowCanaryApplication(application, expectedApplicationId);
  if (!buffer.equals(Buffer.from(`${canonicalJson(application)}\n`, "utf8"))) {
    reject("CANARY_JSON_NONCANONICAL", "The canary application must be canonical JSON followed by exactly one LF.");
  }
  return deepFreeze(application);
}

export async function verifyWorkflowCanary(options, dependencies = {}) {
  const optionKeys = [
    "baseRoot",
    "candidateRoot",
    "expectedBaseCommit",
    "expectedBaseRepository",
    "expectedBaseRepositoryId",
    "expectedBuilderLogin",
    "expectedBuilderUserId",
    "expectedCandidateCommit",
    "expectedHeadRepository",
    "expectedHeadRepositoryId",
    "expectedMergeCommit",
    "pullRequestNumber"
  ];
  if (!isPlainObject(options) || !sameKeys(options, optionKeys)) {
    systemBlocked("CANARY_ARGUMENTS_INVALID", "Protected canary verification requires the closed trusted argument set.");
  }
  if (!isPlainObject(dependencies) || !Object.keys(dependencies).every((key) => key === "resolveSource")) {
    systemBlocked("CANARY_ARGUMENTS_INVALID", "Canary verification dependencies are closed to the public-source resolver.");
  }
  if (dependencies.resolveSource !== undefined && typeof dependencies.resolveSource !== "function") {
    systemBlocked("CANARY_ARGUMENTS_INVALID", "The trusted canary public-source resolver is unavailable.");
  }
  validateTrustedEventIdentity(options);

  let policyRecord;
  try {
    policyRecord = readTrustedLaunchPolicyFromGit({
      repositoryRoot: path.resolve(options.baseRoot),
      expectedBaseCommit: options.expectedBaseCommit
    });
  } catch (error) {
    systemBlocked("TRUSTED_LAUNCH_POLICY_INVALID", "The exact protected-base launch policy is unavailable or invalid.", error);
  }
  const currentPolicyBinding = buildLaunchPolicyBinding(policyRecord, PROFILE_ID);
  const gitState = inspectCanaryPullRequest(options);
  const application = parseWorkflowCanaryApplicationBytes(gitState.applicationBytes, {
    expectedApplicationId: gitState.applicationId
  });

  if (!compareLaunchPolicyBindings(application.expectedPolicyBinding, currentPolicyBinding)) {
    reject("POLICY_DRIFT", "The canary application expected a different protected-base launch policy.");
  }
  if (application.builder.githubUserId !== options.expectedBuilderUserId) {
    reject("CANARY_BUILDER_ID_MISMATCH", "The canary builder id must match the authenticated pull-request author id.");
  }
  if (application.builder.githubLogin.toLowerCase() !== options.expectedBuilderLogin.toLowerCase()) {
    reject("CANARY_BUILDER_LOGIN_MISMATCH", "The canary builder login must match the authenticated pull-request author login.");
  }

  const sourceRequest = {
    schemaVersion: GITHUB_PUBLIC_SOURCE_CONTRACT_V1.schemaVersion,
    primary: {
      repositoryUri: `https://github.com/${application.source.repository}`,
      numericRepositoryId: application.source.numericRepositoryId,
      revisionObjectId: application.source.commit,
      treeObjectId: application.source.tree,
      sourcePaths: [],
      contractPaths: [],
      githubActionsRunIds: []
    },
    companions: []
  };
  const resolveSource = dependencies.resolveSource ?? ((request) => resolveGitHubPublicSourceV1(request));
  let sourceObservation;
  try {
    sourceObservation = await resolveSource(sourceRequest);
  } catch (error) {
    translateSourceError(error);
  }
  validateExactPublicSourceObservation(sourceRequest, sourceObservation);

  const applicationSha256 = digestBytes(gitState.applicationBytes);
  const resultApplication = {
    applicationId: application.applicationId,
    applicationRevision: application.applicationRevision,
    builder: structuredClone(application.builder),
    blob: {
      path: gitState.applicationPath,
      byteLength: gitState.applicationBytes.length,
      gitBlobOid: gitState.applicationBlobOid,
      sha256: applicationSha256
    }
  };
  const resultPullRequest = {
    number: options.pullRequestNumber,
    authorGitHubLogin: options.expectedBuilderLogin,
    authorGitHubUserId: options.expectedBuilderUserId,
    base: {
      repository: options.expectedBaseRepository,
      numericRepositoryId: options.expectedBaseRepositoryId,
      commit: options.expectedBaseCommit,
      tree: gitState.baseTree
    },
    head: {
      repository: options.expectedHeadRepository,
      numericRepositoryId: options.expectedHeadRepositoryId,
      commit: options.expectedCandidateCommit,
      tree: gitState.candidateTree
    },
    mergeCommit: options.expectedMergeCommit
  };
  const resultSource = structuredClone(application.source);
  const subjectCommitment = workflowCanarySubjectCommitment({
    application: resultApplication,
    pullRequest: resultPullRequest,
    source: resultSource
  });
  const evidence = buildCanaryEvidence(application, gitState, currentPolicyBinding);
  const ruleEvaluation = evaluateLaunchPolicyRules({
    policyRecord,
    profileId: PROFILE_ID,
    subject: { usesUniswapV4: true },
    evidence
  });
  if (!ruleEvaluation.passed || ruleEvaluation.outcome !== OUTCOME) {
    reject("CANARY_POLICY_RULES_FAILED", "The workflow canary did not satisfy every active central policy rule.");
  }

  const subject = {
    numericRepositoryId: application.source.numericRepositoryId,
    repository: application.source.repository,
    commit: application.source.commit,
    tree: application.source.tree,
    configurationHash: subjectCommitment,
    usesUniswapV4: true
  };
  const rules = rulesForProfile(policyRecord.policy, PROFILE_ID);
  const evaluations = rules.map((rule) => ({
    ruleId: rule.id,
    state: "passed",
    evidenceRefs: [digestCanonical({
      evidence: Object.fromEntries(rule.evidence.map((evidenceId) => [evidenceId, evidence[evidenceId]])),
      ruleId: rule.id,
      subjectCommitment
    })],
    analyzer: {
      kind: rule.enforcement.mode,
      id: rule.enforcement.handlerId
    }
  }));
  const reviewDecision = evaluateTrustedLaunchPolicyReview({
    repositoryRoot: path.resolve(options.baseRoot),
    expectedBaseCommit: options.expectedBaseCommit,
    input: {
      schemaVersion: "programmable.launch-policy-review-input.v1",
      profileId: PROFILE_ID,
      expectedPolicyBinding: structuredClone(currentPolicyBinding),
      expectedSubject: subject,
      currentSubject: structuredClone(subject),
      evaluations,
      observations: []
    }
  });
  if (reviewDecision.status !== "passed" || reviewDecision.outcome !== OUTCOME) {
    systemBlocked("CANARY_REVIEW_DECISION_INVALID", "Trusted deterministic canary review did not produce the closed pass result.");
  }
  canonicalLaunchPolicyDecision(reviewDecision, policyRecord);

  const resultWithoutDigest = {
    schemaVersion: RESULT_SCHEMA_VERSION,
    status: "passed",
    profileId: PROFILE_ID,
    result: OUTCOME,
    outcome: OUTCOME,
    application: resultApplication,
    pullRequest: resultPullRequest,
    source: resultSource,
    policyBinding: structuredClone(currentPolicyBinding),
    evaluatedRuleIds: rules.map(({ id }) => id),
    reviewDecision: structuredClone(reviewDecision),
    reviewDecisionDigest: reviewDecision.digest,
    authority: structuredClone(RESULT_AUTHORITY)
  };
  const result = {
    ...resultWithoutDigest,
    digest: digestCanonical(resultWithoutDigest)
  };
  validateWorkflowCanaryResult(result, policyRecord, { verifyDigest: true });
  return deepFreeze(result);
}

export function canonicalWorkflowCanaryResult(result, trustedPolicyRecord) {
  validateWorkflowCanaryResult(result, trustedPolicyRecord, { verifyDigest: true });
  return `${canonicalJson(result)}\n`;
}

export function parseWorkflowCanaryResultBytes(bytes, trustedPolicyRecord) {
  const buffer = boundedBytes(bytes, MAXIMUM_RESULT_BYTES, "CANARY_RESULT_SIZE_INVALID", { kind: "system" });
  const result = parseLosslessJson(buffer, "CANARY_RESULT_JSON_INVALID", { kind: "system" });
  validateWorkflowCanaryResult(result, trustedPolicyRecord, { verifyDigest: true });
  if (!buffer.equals(Buffer.from(`${canonicalJson(result)}\n`, "utf8"))) {
    systemBlocked("CANARY_RESULT_JSON_NONCANONICAL", "Workflow canary result bytes are not exact canonical JSON plus one LF.");
  }
  return Object.freeze({
    bytes: Buffer.from(buffer),
    result: deepFreeze(result),
    sha256: digestBytes(buffer)
  });
}

function validateWorkflowCanaryApplication(application, expectedApplicationId) {
  requireObject(application, "CANARY_FIELDS_INVALID", "Canary application must be a JSON object.");
  exactKeys(application, [
    "applicationId",
    "applicationRevision",
    "builder",
    "declarations",
    "expectedPolicyBinding",
    "schemaVersion",
    "source",
    "summary",
    "title"
  ], "CANARY_FIELDS_INVALID", "Canary application");
  if (
    application.schemaVersion !== APPLICATION_SCHEMA_VERSION
    || application.applicationId !== expectedApplicationId
    || !APPLICATION_ID.test(application.applicationId)
    || application.applicationId.length > 128
    || !Number.isInteger(application.applicationRevision)
    || application.applicationRevision < 1
    || application.applicationRevision > 1_000_000_000
  ) {
    reject("CANARY_IDENTITY_INVALID", "Canary application identity or revision is invalid.");
  }
  validateBuilder(application.builder, "CANARY_BUILDER_INVALID");
  validateSource(application.source, "CANARY_SOURCE_INVALID");
  validatePolicyBindingShape(application.expectedPolicyBinding, "CANARY_POLICY_BINDING_INVALID");
  safeText(application.title, 120, "CANARY_FIELDS_INVALID", "Canary title");
  safeText(application.summary, 1000, "CANARY_FIELDS_INVALID", "Canary summary");
  requireObject(application.declarations, "CANARY_DECLARATIONS_INVALID", "Canary declarations must be a closed object.");
  exactKeys(application.declarations, [
    "hiddenFromPublicRoutingAndDiscovery",
    "independentAudit",
    "productionRouting",
    "realUserFunds"
  ], "CANARY_DECLARATIONS_INVALID", "Canary declarations");
  if (
    application.declarations.hiddenFromPublicRoutingAndDiscovery !== true
    || application.declarations.independentAudit !== false
    || application.declarations.productionRouting !== false
    || application.declarations.realUserFunds !== false
  ) {
    reject("CANARY_DECLARATIONS_INVALID", "Canary declarations must remain hidden, unaudited, non-production, unrouted, and free of real-user funds.");
  }
}

function validateWorkflowCanaryResult(result, trustedPolicyRecord, { verifyDigest }) {
  let currentBinding;
  try {
    currentBinding = buildLaunchPolicyBinding(trustedPolicyRecord, PROFILE_ID);
  } catch (error) {
    systemBlocked("CANARY_RESULT_POLICY_INVALID", "Result validation requires the exact trusted workflow-canary policy record.", error);
  }
  requireObject(result, "CANARY_RESULT_FIELDS_INVALID", "Workflow canary result must be an object.", { kind: "system" });
  exactKeys(result, [
    "application",
    "authority",
    "digest",
    "evaluatedRuleIds",
    "outcome",
    "policyBinding",
    "profileId",
    "pullRequest",
    "result",
    "reviewDecision",
    "reviewDecisionDigest",
    "schemaVersion",
    "source",
    "status"
  ], "CANARY_RESULT_FIELDS_INVALID", "Workflow canary result", { kind: "system" });
  if (
    result.schemaVersion !== RESULT_SCHEMA_VERSION
    || result.status !== "passed"
    || result.profileId !== PROFILE_ID
    || result.result !== OUTCOME
    || result.outcome !== OUTCOME
  ) {
    systemBlocked("CANARY_RESULT_IDENTITY_INVALID", "Workflow canary result identity, status, or outcome is invalid.");
  }
  if (!compareLaunchPolicyBindings(result.policyBinding, currentBinding)) {
    systemBlocked("CANARY_RESULT_POLICY_INVALID", "Workflow canary result does not bind the current exact trusted policy.");
  }
  if (canonicalJson(result.authority) !== canonicalJson(RESULT_AUTHORITY)) {
    systemBlocked("CANARY_RESULT_AUTHORITY_INVALID", "Workflow canary result authority must remain hidden and entirely non-production.");
  }
  validateResultApplication(result.application);
  validateResultPullRequest(result.pullRequest, result.application, currentBinding);
  validateSource(result.source, "CANARY_RESULT_SOURCE_INVALID", { kind: "system" });

  const expectedRules = rulesForProfile(trustedPolicyRecord.policy, PROFILE_ID).map(({ id }) => id);
  if (!Array.isArray(result.evaluatedRuleIds) || canonicalJson(result.evaluatedRuleIds) !== canonicalJson(expectedRules)) {
    systemBlocked("CANARY_RESULT_RULES_INVALID", "Workflow canary result does not cover exactly every active canary Rule ID.");
  }
  if (result.evaluatedRuleIds.some((id) => !RULE_ID.test(id))) {
    systemBlocked("CANARY_RESULT_RULES_INVALID", "Workflow canary result contains a malformed Rule ID.");
  }
  let canonicalDecision;
  try {
    canonicalDecision = canonicalLaunchPolicyDecision(result.reviewDecision, trustedPolicyRecord);
  } catch (error) {
    systemBlocked("CANARY_RESULT_REVIEW_INVALID", "Embedded review decision is not semantically valid for the exact trusted policy.", error);
  }
  if (
    canonicalDecision !== canonicalJson(result.reviewDecision)
    || result.reviewDecisionDigest !== result.reviewDecision.digest
    || !SHA256.test(result.reviewDecisionDigest ?? "")
    || result.reviewDecision.profileId !== PROFILE_ID
    || result.reviewDecision.status !== "passed"
    || result.reviewDecision.outcome !== OUTCOME
    || !compareLaunchPolicyBindings(result.reviewDecision.expectedPolicyBinding, result.policyBinding)
    || !compareLaunchPolicyBindings(result.reviewDecision.currentPolicyBinding, result.policyBinding)
  ) {
    systemBlocked("CANARY_RESULT_REVIEW_INVALID", "Embedded review decision does not match the workflow-canary result.");
  }
  const subject = result.reviewDecision.currentSubject;
  const expectedSubjectCommitment = workflowCanarySubjectCommitment({
    application: result.application,
    pullRequest: result.pullRequest,
    source: result.source
  });
  if (
    canonicalJson(result.reviewDecision.expectedSubject) !== canonicalJson(subject)
    || subject.repository !== result.source.repository
    || subject.numericRepositoryId !== result.source.numericRepositoryId
    || subject.commit !== result.source.commit
    || subject.tree !== result.source.tree
    || subject.configurationHash !== expectedSubjectCommitment
    || subject.usesUniswapV4 !== true
  ) {
    systemBlocked("CANARY_RESULT_SUBJECT_INVALID", "Embedded review subject does not close over exact application, pull-request, and source identity.");
  }
  if (verifyDigest && (!SHA256.test(result.digest ?? "") || result.digest !== digestCanonical(withoutResultDigest(result)))) {
    systemBlocked("CANARY_RESULT_DIGEST_INVALID", "Workflow canary result digest does not bind its exact canonical fields.");
  }
}

function validateTrustedEventIdentity(options) {
  for (const [label, value] of [
    ["base commit", options.expectedBaseCommit],
    ["head commit", options.expectedCandidateCommit],
    ["merge commit", options.expectedMergeCommit]
  ]) {
    if (!OBJECT_ID.test(value ?? "")) systemBlocked("CANARY_EVENT_IDENTITY_INVALID", `Expected ${label} is malformed.`);
  }
  if (
    options.expectedBaseRepository !== BASE_REPOSITORY
    || options.expectedBaseRepositoryId !== BASE_REPOSITORY_ID
    || !REPOSITORY.test(options.expectedHeadRepository ?? "")
    || options.expectedHeadRepository.length > 202
    || !POSITIVE_DECIMAL.test(options.expectedHeadRepositoryId ?? "")
    || !PULL_REQUEST_NUMBER.test(options.pullRequestNumber ?? "")
    || !GITHUB_LOGIN.test(options.expectedBuilderLogin ?? "")
    || !POSITIVE_DECIMAL.test(options.expectedBuilderUserId ?? "")
  ) {
    systemBlocked("CANARY_EVENT_IDENTITY_INVALID", "Authenticated GitHub pull-request identity is malformed or outside the fixed base repository.");
  }
  if (
    typeof options.baseRoot !== "string"
    || typeof options.candidateRoot !== "string"
    || !path.isAbsolute(options.baseRoot)
    || !path.isAbsolute(options.candidateRoot)
  ) {
    systemBlocked("CANARY_EVENT_IDENTITY_INVALID", "Trusted base and candidate roots are required.");
  }
}

function inspectCanaryPullRequest(options) {
  const baseRoot = path.resolve(options.baseRoot);
  const candidateRoot = path.resolve(options.candidateRoot);
  const observedBaseCommit = runGitText(baseRoot, ["rev-parse", "HEAD^{commit}"], 128);
  if (observedBaseCommit !== options.expectedBaseCommit) {
    systemBlocked("CANARY_BASE_COMMIT_MISMATCH", "Trusted base checkout does not match the authenticated base commit.");
  }
  const baseTree = runGitText(baseRoot, ["rev-parse", `${observedBaseCommit}^{tree}`], 128);
  const observedMergeCommit = runGitText(candidateRoot, ["rev-parse", "HEAD^{commit}"], 128);
  if (observedMergeCommit !== options.expectedMergeCommit) {
    systemBlocked("CANARY_MERGE_COMMIT_MISMATCH", "Candidate object store does not match the authenticated merge commit.");
  }
  const commitObject = runGitText(candidateRoot, ["cat-file", "-p", `${observedMergeCommit}^{commit}`], 1024 * 1024);
  const header = commitObject.split("\n\n", 1)[0].split("\n");
  const parents = header.filter((line) => line.startsWith("parent ")).map((line) => line.slice(7));
  if (parents.length !== 2 || parents[0] !== options.expectedBaseCommit || parents[1] !== options.expectedCandidateCommit) {
    systemBlocked("CANARY_MERGE_PARENT_MISMATCH", "Candidate merge parents do not match authenticated base and head commits.");
  }
  const candidateTree = runGitText(candidateRoot, ["rev-parse", `${options.expectedCandidateCommit}^{tree}`], 128);
  if (!OBJECT_ID.test(baseTree) || !OBJECT_ID.test(candidateTree)) {
    systemBlocked("CANARY_GIT_IDENTITY_INVALID", "Canary base or head tree identity is malformed.");
  }

  const changed = runGit(candidateRoot, [
    "diff", "--name-status", "--no-renames", "-z",
    options.expectedBaseCommit, options.expectedCandidateCommit
  ], 4096);
  const fields = splitNul(changed);
  if (fields.length !== 2 || !new Set(["A", "M"]).has(fields[0])) {
    reject("CANARY_PATH_INVALID", "A workflow-canary pull request must add or modify exactly one application JSON blob.");
  }
  const applicationPath = fields[1];
  const match = CANARY_PATH.exec(applicationPath);
  if (!match) {
    reject("CANARY_PATH_INVALID", "Canary input must be exactly canary-submissions/<application-id>/application.json.");
  }
  const applicationId = match[1];
  const directoryEntries = parseTreePaths(runGit(candidateRoot, [
    "ls-tree", "-rz", "--full-tree", options.expectedCandidateCommit,
    "--", `canary-submissions/${applicationId}`
  ], 4096));
  if (directoryEntries.length !== 1 || directoryEntries[0].path !== applicationPath || directoryEntries[0].mode !== "100644" || directoryEntries[0].type !== "blob") {
    reject("CANARY_PATH_INVALID", "The canary application directory must contain exactly one non-executable application.json blob.");
  }
  const [{ oid: applicationBlobOid }] = directoryEntries;
  const declaredSize = Number(runGitText(candidateRoot, ["cat-file", "-s", applicationBlobOid], 128));
  if (!Number.isSafeInteger(declaredSize) || declaredSize < 2 || declaredSize > MAXIMUM_APPLICATION_BYTES) {
    reject("CANARY_APPLICATION_SIZE_INVALID", "Canary application JSON exceeds its closed byte bound.");
  }
  const applicationBytes = runGit(candidateRoot, ["cat-file", "blob", applicationBlobOid], MAXIMUM_APPLICATION_BYTES + 1);
  if (applicationBytes.length !== declaredSize) {
    systemBlocked("CANARY_GIT_BLOB_INVALID", "Hydrated canary application bytes do not match the exact Git blob size.");
  }
  return {
    applicationBlobOid,
    applicationBytes,
    applicationId,
    applicationPath,
    baseTree,
    candidateTree
  };
}

function buildCanaryEvidence(application, gitState, currentPolicyBinding) {
  const applicationSha256 = digestBytes(gitState.applicationBytes);
  return {
    "canary-application-authentication": true,
    "canary-public-source": true,
    "canary-hidden-namespace": gitState.applicationPath === `canary-submissions/${application.applicationId}/application.json`,
    "canary-no-production-discovery": application.declarations.hiddenFromPublicRoutingAndDiscovery === true,
    "canary-no-public-routing": application.declarations.hiddenFromPublicRoutingAndDiscovery === true && application.declarations.productionRouting === false,
    "canary-no-real-user-funds": application.declarations.realUserFunds === false,
    "canary-canonical-application-record": {
      status: "passed",
      schemaVersion: APPLICATION_SCHEMA_VERSION,
      path: gitState.applicationPath,
      byteLength: gitState.applicationBytes.length,
      gitBlobOid: gitState.applicationBlobOid,
      sha256: applicationSha256
    },
    "canary-current-policy-binding": {
      status: "passed",
      applicationSha256,
      policyBinding: structuredClone(currentPolicyBinding)
    },
    "canary-reproducible-application-parsing": {
      status: "passed",
      schemaVersion: APPLICATION_SCHEMA_VERSION,
      applicationSha256,
      canonicalJson: true,
      duplicateKeysRejected: true,
      encoding: "utf-8",
      trailingBytes: "one-lf"
    }
  };
}

function validateExactPublicSourceObservation(request, observation) {
  const expected = request.primary;
  if (
    !isPlainObject(observation)
    || observation.schemaVersion !== GITHUB_PUBLIC_SOURCE_CONTRACT_V1.schemaVersion
    || observation.kind !== GITHUB_PUBLIC_SOURCE_CONTRACT_V1.kind
    || observation.canonicalProviderOrigin !== GITHUB_PUBLIC_SOURCE_CONTRACT_V1.canonicalProviderOrigin
    || observation.githubApiVersion !== GITHUB_PUBLIC_SOURCE_CONTRACT_V1.githubApiVersion
    || !Array.isArray(observation.companions)
    || observation.companions.length !== 0
    || !isPlainObject(observation.primary)
    || !isPlainObject(observation.primary.authority)
    || !isPlainObject(observation.primary.display)
    || observation.primary.role !== "primary"
    || observation.primary.visibility !== "public"
    || !Array.isArray(observation.primary.sourcePaths)
    || observation.primary.sourcePaths.length !== 0
    || !Array.isArray(observation.primary.contractPaths)
    || observation.primary.contractPaths.length !== 0
    || !Array.isArray(observation.primary.githubActionsEvidence)
    || observation.primary.githubActionsEvidence.length !== 0
  ) {
    systemBlocked("CANARY_SOURCE_OBSERVATION_INVALID", "Trusted resolver returned a malformed exact public-source observation.");
  }
  if (observation.primary.authority.numericRepositoryId !== expected.numericRepositoryId) {
    reject("CANARY_SOURCE_ID_MISMATCH", "Public source repository numeric id did not match the canary application.");
  }
  if (observation.primary.display.repositoryUri !== expected.repositoryUri) {
    reject("CANARY_SOURCE_REPOSITORY_MISMATCH", "Public source repository locator did not match the canary application.");
  }
  if (observation.primary.authority.revisionObjectId !== expected.revisionObjectId) {
    reject("CANARY_SOURCE_COMMIT_MISMATCH", "Public source commit did not match the canary application.");
  }
  if (observation.primary.authority.treeObjectId !== expected.treeObjectId) {
    reject("CANARY_SOURCE_TREE_MISMATCH", "Public source tree did not match the canary application.");
  }
}

function translateSourceError(error) {
  if (error instanceof WorkflowCanaryError) throw error;
  if (!(error instanceof GitHubPublicSourceError)) {
    systemBlocked("CANARY_SOURCE_RESOLUTION_FAILED", "Trusted public-source resolver failed unexpectedly.", error);
  }
  const candidateCodes = new Set([
    "GITHUB_COMMIT_MISMATCH",
    "GITHUB_COMMIT_NOT_REACHABLE",
    "GITHUB_PUBLIC_REPOSITORY_UNAVAILABLE",
    "GITHUB_REDIRECT_REJECTED",
    "GITHUB_REPOSITORY_ID_MISMATCH",
    "GITHUB_REPOSITORY_LOCATOR_MISMATCH",
    "GITHUB_TREE_MISMATCH",
    "GITHUB_TREE_NOT_REACHABLE",
    "INVALID_REQUEST"
  ]);
  if (candidateCodes.has(error.code)) {
    reject(error.code, "Declared canary source did not resolve to its exact public Git identity.");
  }
  systemBlocked(error.code, "Trusted public-source resolution could not complete.", error);
}

function validateResultApplication(application) {
  requireObject(application, "CANARY_RESULT_APPLICATION_INVALID", "Result application is malformed.", { kind: "system" });
  exactKeys(application, ["applicationId", "applicationRevision", "blob", "builder"], "CANARY_RESULT_APPLICATION_INVALID", "Result application", { kind: "system" });
  if (!APPLICATION_ID.test(application.applicationId ?? "") || application.applicationId.length > 128 || !Number.isInteger(application.applicationRevision) || application.applicationRevision < 1 || application.applicationRevision > 1_000_000_000) {
    systemBlocked("CANARY_RESULT_APPLICATION_INVALID", "Result application identity is malformed.");
  }
  validateBuilder(application.builder, "CANARY_RESULT_APPLICATION_INVALID", { kind: "system" });
  requireObject(application.blob, "CANARY_RESULT_APPLICATION_INVALID", "Result application blob is malformed.", { kind: "system" });
  exactKeys(application.blob, ["byteLength", "gitBlobOid", "path", "sha256"], "CANARY_RESULT_APPLICATION_INVALID", "Result application blob", { kind: "system" });
  if (
    application.blob.path !== `canary-submissions/${application.applicationId}/application.json`
    || !Number.isInteger(application.blob.byteLength)
    || application.blob.byteLength < 2
    || application.blob.byteLength > MAXIMUM_APPLICATION_BYTES
    || !OBJECT_ID.test(application.blob.gitBlobOid ?? "")
    || !SHA256.test(application.blob.sha256 ?? "")
  ) {
    systemBlocked("CANARY_RESULT_APPLICATION_INVALID", "Result application blob identity is malformed.");
  }
}

function validateResultPullRequest(pullRequest, application, binding) {
  requireObject(pullRequest, "CANARY_RESULT_PR_INVALID", "Result pull request is malformed.", { kind: "system" });
  exactKeys(pullRequest, ["authorGitHubLogin", "authorGitHubUserId", "base", "head", "mergeCommit", "number"], "CANARY_RESULT_PR_INVALID", "Result pull request", { kind: "system" });
  if (
    !PULL_REQUEST_NUMBER.test(pullRequest.number ?? "")
    || !GITHUB_LOGIN.test(pullRequest.authorGitHubLogin ?? "")
    || !POSITIVE_DECIMAL.test(pullRequest.authorGitHubUserId ?? "")
    || !OBJECT_ID.test(pullRequest.mergeCommit ?? "")
    || pullRequest.authorGitHubUserId !== application.builder.githubUserId
    || pullRequest.authorGitHubLogin.toLowerCase() !== application.builder.githubLogin.toLowerCase()
  ) {
    systemBlocked("CANARY_RESULT_PR_INVALID", "Result pull-request author or merge identity is malformed.");
  }
  validateGitIdentity(pullRequest.base, "CANARY_RESULT_PR_INVALID");
  validateGitIdentity(pullRequest.head, "CANARY_RESULT_PR_INVALID");
  if (
    pullRequest.base.repository !== BASE_REPOSITORY
    || pullRequest.base.numericRepositoryId !== BASE_REPOSITORY_ID
    || pullRequest.base.commit !== binding.baseCommit
    || pullRequest.base.tree !== binding.baseTree
  ) {
    systemBlocked("CANARY_RESULT_PR_INVALID", "Result base identity does not match the protected policy base.");
  }
}

function validateBuilder(builder, code, options = {}) {
  requireObject(builder, code, "Canary builder must be a closed object.", options);
  exactKeys(builder, ["githubLogin", "githubUserId"], code, "Canary builder", options);
  if (!GITHUB_LOGIN.test(builder.githubLogin ?? "") || !POSITIVE_DECIMAL.test(builder.githubUserId ?? "")) {
    failByKind(code, "Canary builder GitHub identity is malformed.", options);
  }
}

function validateSource(source, code, options = {}) {
  validateGitIdentity(source, code, options);
}

function validateGitIdentity(identity, code, options = { kind: "system" }) {
  requireObject(identity, code, "Exact Git identity must be a closed object.", options);
  exactKeys(identity, ["commit", "numericRepositoryId", "repository", "tree"], code, "Exact Git identity", options);
  if (
    !REPOSITORY.test(identity.repository ?? "")
    || identity.repository.length > 202
    || !POSITIVE_DECIMAL.test(identity.numericRepositoryId ?? "")
    || !OBJECT_ID.test(identity.commit ?? "")
    || !OBJECT_ID.test(identity.tree ?? "")
  ) {
    failByKind(code, "Exact Git repository, numeric id, commit, or tree is malformed.", options);
  }
}

function validatePolicyBindingShape(binding, code) {
  requireObject(binding, code, "Expected policy binding must be a closed object.");
  exactKeys(binding, ["baseCommit", "baseTree", "gitBlobOid", "numericRepositoryId", "path", "policyId", "policyVersion", "profileId", "repository", "schemaVersion", "sha256"], code, "Expected policy binding");
  if (
    binding.schemaVersion !== "programmable.launch-policy-binding.v1"
    || binding.repository !== BASE_REPOSITORY
    || binding.numericRepositoryId !== BASE_REPOSITORY_ID
    || binding.path !== "policy/launch-policy.v1.json"
    || binding.profileId !== PROFILE_ID
    || !OBJECT_ID.test(binding.baseCommit ?? "")
    || !OBJECT_ID.test(binding.baseTree ?? "")
    || !OBJECT_ID.test(binding.gitBlobOid ?? "")
    || !/^[a-z0-9][a-z0-9.-]{2,79}$/u.test(binding.policyId ?? "")
    || !/^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u.test(binding.policyVersion ?? "")
    || !SHA256.test(binding.sha256 ?? "")
  ) {
    reject(code, "Expected workflow-canary policy binding is malformed.");
  }
}

function withoutResultDigest(result) {
  const keys = [
    "application", "authority", "evaluatedRuleIds", "outcome", "policyBinding", "profileId",
    "pullRequest", "result", "reviewDecision", "reviewDecisionDigest", "schemaVersion", "source", "status"
  ];
  return Object.fromEntries(keys.map((key) => [key, result[key]]));
}

function parseLosslessJson(buffer, code, options = {}) {
  let source;
  let value;
  try {
    source = utf8.decode(buffer);
    parseBoundedLosslessJson(source);
    value = JSON.parse(source);
  } catch (error) {
    failByKind(code, "Canary bytes must be duplicate-free, bounded, lossless UTF-8 JSON.", options, error);
  }
  return value;
}

function boundedBytes(bytes, maximum, code, options = {}) {
  let buffer;
  try {
    buffer = Buffer.from(bytes ?? []);
  } catch (error) {
    failByKind(code, "Canary bytes are unavailable.", options, error);
  }
  if (buffer.length < 2 || buffer.length > maximum) {
    failByKind(code, "Canary bytes exceed the closed byte boundary.", options);
  }
  return buffer;
}

function runGitText(repositoryRoot, args, maximumBytes) {
  return utf8.decode(runGit(repositoryRoot, args, maximumBytes)).trimEnd();
}

function runGit(repositoryRoot, args, maximumBytes) {
  const result = childProcess.spawnSync("git", [
    "-c", "credential.helper=",
    "-c", "credential.interactive=never",
    "-c", "core.hooksPath=/dev/null",
    "-c", "protocol.allow=never",
    "-C", repositoryRoot,
    ...args
  ], {
    encoding: null,
    shell: false,
    timeout: 30_000,
    killSignal: "SIGKILL",
    maxBuffer: maximumBytes,
    env: {
      ...process.env,
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_LFS_SKIP_SMUDGE: "1",
      GIT_NO_LAZY_FETCH: "1",
      GIT_OPTIONAL_LOCKS: "0",
      GIT_TERMINAL_PROMPT: "0"
    }
  });
  const stdout = Buffer.isBuffer(result.stdout) ? result.stdout : Buffer.alloc(0);
  if (result.status !== 0 || result.signal !== null || result.error || stdout.length > maximumBytes) {
    systemBlocked("CANARY_GIT_READ_FAILED", "Trusted bounded Git object inspection failed.", result.error);
  }
  return Buffer.from(stdout);
}

function parseTreePaths(bytes) {
  return splitNul(bytes).map((record) => {
    const match = /^(\d{6}) (blob|tree|commit) ([0-9a-f]{40})\t(.+)$/u.exec(record);
    if (!match) systemBlocked("CANARY_GIT_TREE_INVALID", "Trusted canary Git tree output is malformed.");
    return { mode: match[1], type: match[2], oid: match[3], path: match[4] };
  });
}

function splitNul(bytes) {
  const values = utf8.decode(bytes).split("\0");
  if (values.at(-1) !== "") systemBlocked("CANARY_GIT_TREE_INVALID", "Trusted NUL-delimited Git output is malformed.");
  values.pop();
  return values;
}

function safeText(value, maximum, code, label) {
  if (
    typeof value !== "string"
    || [...value].length < 1
    || [...value].length > maximum
    || value.trim() !== value
    || /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/u.test(value)
  ) {
    reject(code, `${label} is malformed or unsafe.`);
  }
}

function workflowCanarySubjectCommitment({ application, pullRequest, source }) {
  return digestCanonical({
    schemaVersion: "programmable.workflow-canary-subject-commitment.v1",
    application,
    pullRequest,
    source
  });
}

function digestCanonical(value) {
  return digestBytes(Buffer.from(canonicalJson(value), "utf8"));
}

function digestBytes(bytes) {
  return `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
}

function requireObject(value, code, message, options = {}) {
  if (!isPlainObject(value)) failByKind(code, message, options);
}

function exactKeys(value, keys, code, label, options = {}) {
  if (!isPlainObject(value) || !sameKeys(value, keys)) {
    failByKind(code, `${label} contains missing or unsupported fields.`, options);
  }
}

function sameKeys(value, keys) {
  return isPlainObject(value)
    && Object.keys(value).length === keys.length
    && keys.every((key) => Object.hasOwn(value, key));
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function reject(code, message, cause) {
  throw new WorkflowCanaryError(code, message, { kind: "candidate", cause });
}

function systemBlocked(code, message, cause) {
  throw new WorkflowCanaryError(code, message, { kind: "system", cause });
}

function failByKind(code, message, options = {}, cause) {
  if (options.kind === "system") systemBlocked(code, message, cause);
  reject(code, message, cause);
}

function deepFreeze(value) {
  if (Array.isArray(value)) {
    for (const entry of value) deepFreeze(entry);
    return Object.freeze(value);
  }
  if (isPlainObject(value)) {
    for (const entry of Object.values(value)) deepFreeze(entry);
    return Object.freeze(value);
  }
  return value;
}
