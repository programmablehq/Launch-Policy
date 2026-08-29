import crypto from "node:crypto";

import {
  buildLaunchPolicyBinding,
  canonicalJson,
  compareLaunchPolicyBindings,
  evaluateLaunchPolicyRules,
  readTrustedLaunchPolicyFromGit,
  rulesForProfile,
  selectLaunchPolicyProfile
} from "../scripts/launch-policy-core.mjs";
import {
  deriveTrustedPublicApplicationV3LaunchReadinessV1,
  isTrustedPublicApplicationV3LaunchReadinessV1
} from "../scripts/verify-public-application-v3-core.mjs";
import {
  deriveProgrammableLaunchRouterApplicabilityRecordV1,
  isTrustedProgrammableLaunchRouterApplicabilityRecordV1,
  parseProgrammableLaunchRouterReadinessBytesV1,
  projectProgrammableLaunchRouterPolicyEvidenceV1
} from "../scripts/programmable-launch-router-readiness-core.mjs";

const INPUT_SCHEMA_VERSION = "programmable.launch-policy-review-input.v1";
const DECISION_SCHEMA_VERSION = "programmable.launch-policy-review-decision.v1";
const BINDING_SCHEMA_VERSION = "programmable.launch-policy-binding.v1";
const PROFILES = new Set(["build", "launch-readiness", "production-launch", "workflow-canary"]);
const STATES = new Set(["analysis_pending", "passed", "violated"]);
const ANALYZER_KINDS = new Set(["deterministic", "human", "llm", "scanner"]);
const STATUS_VALUES = new Set(["analysis_pending", "changes_requested", "passed", "policy_drift", "profile_disabled", "subject_drift"]);
const OBJECT_ID = /^[0-9a-f]{40}$/u;
const SHA256 = /^sha256:[0-9a-f]{64}$/u;
const REPOSITORY = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;
const POSITIVE_DECIMAL = /^[1-9][0-9]{0,19}$/u;
const RULE_ID = /^[A-Z][A-Z0-9_]*(?:\.[A-Z][A-Z0-9_]*)+$/u;
const ANALYZER_ID = /^[a-z0-9][a-z0-9._-]{1,79}$/u;
const trustedLaunchReadinessReviewInputs = new WeakSet();
const trustedLaunchReadinessDecisions = new WeakSet();
const AUTHORITY = Object.freeze({
  checkerOnly: true,
  independentAudit: false,
  launchAuthorized: false,
  publicRoutingAuthorized: false,
  realFundsAuthorized: false
});
const DECISION_KEYS = [
  "advisories",
  "authority",
  "currentPolicyBinding",
  "currentSubject",
  "evaluations",
  "expectedPolicyBinding",
  "expectedSubject",
  "findings",
  "notApplicableRuleIds",
  "outcome",
  "pendingRuleIds",
  "profileId",
  "schemaVersion",
  "status",
  "trustedPolicy"
];

export class LaunchPolicyReviewError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.name = "LaunchPolicyReviewError";
    this.code = code;
  }
}

export function validateLaunchPolicyReviewInput(input) {
  requirePlainObject(input, "review input", "REVIEW_INPUT_INVALID");
  exactKeys(input, [
    "currentSubject",
    "evaluations",
    "expectedPolicyBinding",
    "expectedSubject",
    "observations",
    "profileId",
    "schemaVersion"
  ], "REVIEW_INPUT_FIELDS_INVALID", "Review input");
  if (input.schemaVersion !== INPUT_SCHEMA_VERSION || !PROFILES.has(input.profileId)) {
    fail("REVIEW_INPUT_IDENTITY_INVALID", "Review input schema or profile is unsupported.");
  }
  if (input.profileId === "production-launch") {
    if (input.expectedPolicyBinding !== null) {
      validatePolicyBinding(input.expectedPolicyBinding);
      if (input.expectedPolicyBinding.profileId !== input.profileId) {
        fail("REVIEW_POLICY_BINDING_INVALID", "Recorded policy binding profile does not match the review profile.");
      }
    }
  } else {
    validatePolicyBinding(input.expectedPolicyBinding);
    if (input.expectedPolicyBinding.profileId !== input.profileId) {
      fail("REVIEW_POLICY_BINDING_INVALID", "Recorded policy binding profile does not match the review profile.");
    }
  }
  const requireRouterProvenanceRequired = new Set(["launch-readiness", "production-launch"]).has(input.profileId);
  const requireApplicationIdentity = input.profileId === "launch-readiness";
  validateSubject(input.expectedSubject, "expectedSubject", { requireApplicationIdentity, requireRouterProvenanceRequired });
  validateSubject(input.currentSubject, "currentSubject", { requireApplicationIdentity, requireRouterProvenanceRequired });
  validateEvaluations(input.evaluations);
  validateObservations(input.observations);
  return true;
}

export function evaluateTrustedLaunchPolicyReview(options) {
  requirePlainObject(options, "review options", "REVIEW_ARGUMENTS_INVALID");
  exactKeys(options, ["expectedBaseCommit", "input", "repositoryRoot"], "REVIEW_ARGUMENTS_INVALID", "Review options");
  validateLaunchPolicyReviewInput(options.input);
  if (options.input.profileId === "launch-readiness" && !trustedLaunchReadinessReviewInputs.has(options.input)) {
    fail(
      "REVIEW_LAUNCH_READINESS_TRUST_REQUIRED",
      "Launch-readiness decisions must be compiled from exact trusted Application and Router-readiness records; caller-supplied applicability or evaluation states are not accepted."
    );
  }

  const input = structuredClone(options.input);
  const policyRecord = readTrustedLaunchPolicyFromGit({
    repositoryRoot: options.repositoryRoot,
    expectedBaseCommit: options.expectedBaseCommit
  });
  const profile = selectLaunchPolicyProfile(policyRecord.policy, input.profileId);
  const trustedPolicy = projectTrustedPolicy(policyRecord, input.profileId);
  const advisories = observationsToAdvisories(input.observations);

  if (!profile.enabled) {
    for (const evaluation of input.evaluations) advisories.push(unboundEvaluationAdvisory(evaluation));
    return createDecision({
      policyRecord,
      input,
      trustedPolicy,
      currentPolicyBinding: null,
      status: "profile_disabled",
      outcome: null,
      evaluations: [],
      pendingRuleIds: [],
      notApplicableRuleIds: [],
      findings: [],
      advisories
    });
  }

  if (input.expectedPolicyBinding === null) {
    fail("REVIEW_POLICY_BINDING_INVALID", "An enabled production review requires the exact policy binding.");
  }

  const currentPolicyBinding = buildLaunchPolicyBinding(policyRecord, input.profileId);
  if (!compareLaunchPolicyBindings(input.expectedPolicyBinding, currentPolicyBinding)) {
    return createDecision({
      policyRecord,
      input,
      trustedPolicy,
      currentPolicyBinding,
      status: "policy_drift",
      outcome: null,
      evaluations: [],
      pendingRuleIds: [],
      notApplicableRuleIds: [],
      findings: [],
      advisories
    });
  }

  if (canonicalJson(input.expectedSubject) !== canonicalJson(input.currentSubject)) {
    return createDecision({
      policyRecord,
      input,
      trustedPolicy,
      currentPolicyBinding,
      status: "subject_drift",
      outcome: null,
      evaluations: [],
      pendingRuleIds: [],
      notApplicableRuleIds: [],
      findings: [],
      advisories
    });
  }

  const activeRules = rulesForProfile(policyRecord.policy, input.profileId);
  const activeById = new Map(activeRules.map((rule) => [rule.id, rule]));
  const acceptedById = new Map();
  for (const evaluation of input.evaluations) {
    const rule = activeById.get(evaluation.ruleId);
    if (!rule) {
      advisories.push(unboundEvaluationAdvisory(evaluation));
      continue;
    }
    if (!ruleApplies(rule, input.currentSubject)) {
      fail("REVIEW_EVALUATION_NOT_APPLICABLE", `Rule ${rule.id} applicability is derived from the subject and cannot be evaluated by the caller.`);
    }
    if (evaluation.analyzer.kind !== rule.enforcement.mode || evaluation.analyzer.id !== rule.enforcement.handlerId) {
      fail("REVIEW_ANALYZER_MISMATCH", `Rule ${rule.id} must be evaluated only by its policy-bound analyzer.`);
    }
    acceptedById.set(rule.id, evaluation);
  }

  const accepted = [];
  const findings = [];
  const pendingRuleIds = [];
  const notApplicableRuleIds = [];
  for (const rule of activeRules) {
    if (!ruleApplies(rule, input.currentSubject)) {
      notApplicableRuleIds.push(rule.id);
      continue;
    }
    const evaluation = acceptedById.get(rule.id);
    if (!evaluation) {
      pendingRuleIds.push(rule.id);
      continue;
    }
    accepted.push(evaluation);
    if (evaluation.state === "analysis_pending") pendingRuleIds.push(rule.id);
    if (evaluation.state === "violated") findings.push(projectFinding(rule, evaluation));
  }

  const status = findings.length > 0
    ? "changes_requested"
    : pendingRuleIds.length > 0
      ? "analysis_pending"
      : "passed";
  return createDecision({
    policyRecord,
    input,
    trustedPolicy,
    currentPolicyBinding,
    status,
    outcome: status === "passed" ? profile.outcome : null,
    evaluations: accepted,
    pendingRuleIds,
    notApplicableRuleIds,
    findings,
    advisories
  });
}

export function evaluateTrustedLaunchReadinessPolicyReview(options) {
  requirePlainObject(options, "launch-readiness compiler options", "REVIEW_ARGUMENTS_INVALID");
  exactKeys(
    options,
    ["applicationResult", "expectedBaseCommit", "readinessBytes", "repositoryRoot"],
    "REVIEW_ARGUMENTS_INVALID",
    "Launch-readiness compiler options"
  );

  let applicationReadiness;
  try {
    applicationReadiness = deriveTrustedPublicApplicationV3LaunchReadinessV1(options.applicationResult);
  } catch (error) {
    fail("REVIEW_LAUNCH_READINESS_APPLICATION_INVALID", "Launch readiness requires an opaque result minted by the protected Application V3 package or exact-source verifier.", error);
  }
  if (!isTrustedPublicApplicationV3LaunchReadinessV1(applicationReadiness)) {
    fail("REVIEW_LAUNCH_READINESS_TRUST_REQUIRED", "Application launch applicability was not minted by the protected Application V3 verifier.");
  }

  let parsedReadiness = null;
  let routerApplicability = null;
  let evidence = {};
  if (options.readinessBytes !== null) {
    try {
      parsedReadiness = parseProgrammableLaunchRouterReadinessBytesV1(options.readinessBytes);
      routerApplicability = deriveProgrammableLaunchRouterApplicabilityRecordV1(parsedReadiness);
      if (!isTrustedProgrammableLaunchRouterApplicabilityRecordV1(routerApplicability)) {
        throw new TypeError("untrusted Router applicability record");
      }
    } catch (error) {
      fail("REVIEW_LAUNCH_READINESS_EVIDENCE_INVALID", "Exact Router-readiness bytes did not satisfy the trusted closed checker.", error);
    }
  } else if (applicationReadiness.decision === "not-applicable" && applicationReadiness.readinessBinding !== null) {
    fail("REVIEW_LAUNCH_READINESS_APPLICATION_MISMATCH", "A protected not-applicable Application cannot bind Router-readiness bytes.");
  }

  if (parsedReadiness !== null) {
    verifyApplicationRouterReadinessBinding({ applicationReadiness, parsedReadiness, routerApplicability, readinessBytes: options.readinessBytes });
    if (applicationReadiness.decision === "required") {
      if (routerApplicability.decision !== "required") {
        fail("REVIEW_LAUNCH_READINESS_APPLICATION_MISMATCH", "A fully verified required Application must bind prelaunch-bound Router readiness.");
      }
      evidence = projectProgrammableLaunchRouterPolicyEvidenceV1(parsedReadiness);
    }
  }

  const policyRecord = readTrustedLaunchPolicyFromGit({
    repositoryRoot: options.repositoryRoot,
    expectedBaseCommit: options.expectedBaseCommit
  });
  const profile = selectLaunchPolicyProfile(policyRecord.policy, "launch-readiness");
  if (!profile.enabled) {
    fail("REVIEW_LAUNCH_READINESS_PROFILE_DISABLED", "The protected launch-readiness compiler requires the enabled checker-only profile.");
  }

  const subject = {
    applicationId: applicationReadiness.applicationId,
    applicationRevision: Number(applicationReadiness.applicationRevision),
    applicationSha256: applicationReadiness.applicationSha256,
    packageSha256: applicationReadiness.packageSha256,
    numericRepositoryId: applicationReadiness.subject.numericRepositoryId,
    repository: applicationReadiness.subject.repository,
    commit: applicationReadiness.subject.commit,
    tree: applicationReadiness.subject.tree,
    configurationHash: applicationReadiness.subject.configurationHash,
    routerProvenanceRequired: applicationReadiness.decision !== "not-applicable",
    // Historical review decisions carried this architecture hint. It never
    // controls Router applicability; the protected applicability record does.
    usesUniswapV4: true
  };
  const policyEvaluation = evaluateLaunchPolicyRules({
    policyRecord,
    profileId: "launch-readiness",
    subject,
    evidence
  });
  const activeRules = new Map(rulesForProfile(policyRecord.policy, "launch-readiness").map((rule) => [rule.id, rule]));
  const stateByHandlerStatus = new Map([
    ["analysis-pending", "analysis_pending"],
    ["failed", "violated"],
    ["passed", "passed"]
  ]);
  const evaluations = policyEvaluation.results
    .filter(({ status }) => status !== "not-applicable")
    .map((result) => {
      const rule = activeRules.get(result.ruleId);
      const state = stateByHandlerStatus.get(result.status);
      if (!rule || !state) {
        fail("REVIEW_LAUNCH_READINESS_COMPILER_INVALID", "A policy handler returned an unbound launch-readiness result.");
      }
      return {
        ruleId: rule.id,
        state,
        evidenceRefs: [applicationReadiness.readinessBinding?.sha256 ?? routerApplicability?.readinessDocumentSha256]
          .filter((value) => typeof value === "string"),
        analyzer: { kind: rule.enforcement.mode, id: rule.enforcement.handlerId }
      };
    });
  const input = {
    schemaVersion: INPUT_SCHEMA_VERSION,
    profileId: "launch-readiness",
    expectedPolicyBinding: buildLaunchPolicyBinding(policyRecord, "launch-readiness"),
    expectedSubject: subject,
    currentSubject: structuredClone(subject),
    evaluations,
    observations: []
  };
  trustedLaunchReadinessReviewInputs.add(input);
  const decision = evaluateTrustedLaunchPolicyReview({
    input,
    repositoryRoot: options.repositoryRoot,
    expectedBaseCommit: options.expectedBaseCommit
  });
  trustedLaunchReadinessDecisions.add(decision);
  return decision;
}

export function canonicalLaunchPolicyDecision(decision, trustedPolicyRecord) {
  requireTrustedLaunchReadinessDecision(decision);
  validateLaunchPolicyDecision(decision, trustedPolicyRecord, { verifyDigest: true });
  return canonicalJson(decision);
}

export function digestLaunchPolicyDecision(decision, trustedPolicyRecord) {
  requireTrustedLaunchReadinessDecision(decision);
  validateLaunchPolicyDecision(decision, trustedPolicyRecord, { verifyDigest: false });
  return hashLaunchPolicyDecision(decision);
}

function requireTrustedLaunchReadinessDecision(decision) {
  if (decision?.profileId === "launch-readiness" && !trustedLaunchReadinessDecisions.has(decision)) {
    fail(
      "REVIEW_LAUNCH_READINESS_DECISION_TRUST_REQUIRED",
      "Canonical launch-readiness validation requires the exact decision minted by the protected Application and Router-readiness compiler; a caller-supplied digest cannot prove provenance."
    );
  }
}

function createDecision({
  policyRecord,
  input,
  trustedPolicy,
  currentPolicyBinding,
  status,
  outcome,
  evaluations,
  pendingRuleIds,
  notApplicableRuleIds,
  findings,
  advisories
}) {
  const decisionWithoutDigestValue = {
    schemaVersion: DECISION_SCHEMA_VERSION,
    profileId: input.profileId,
    trustedPolicy,
    expectedPolicyBinding: input.expectedPolicyBinding,
    currentPolicyBinding,
    expectedSubject: input.expectedSubject,
    currentSubject: input.currentSubject,
    status,
    outcome,
    authority: AUTHORITY,
    evaluations: sortByCanonical(evaluations),
    pendingRuleIds: [...pendingRuleIds].sort(compareUtf8),
    notApplicableRuleIds: [...notApplicableRuleIds].sort(compareUtf8),
    findings: sortByCanonical(findings),
    advisories: sortByCanonical(advisories)
  };
  const decision = {
    ...decisionWithoutDigestValue,
    digest: hashLaunchPolicyDecision(decisionWithoutDigestValue)
  };
  validateLaunchPolicyDecision(decision, policyRecord, { verifyDigest: true });
  return deepFreeze(decision);
}

function validateLaunchPolicyDecision(decision, trustedPolicyRecord, { verifyDigest }) {
  requirePlainObject(decision, "review decision", "REVIEW_DECISION_INVALID");
  exactKeys(decision, [...DECISION_KEYS, "digest"], "REVIEW_DECISION_FIELDS_INVALID", "Review decision");
  if (decision.schemaVersion !== DECISION_SCHEMA_VERSION || !PROFILES.has(decision.profileId) || !STATUS_VALUES.has(decision.status)) {
    fail("REVIEW_DECISION_IDENTITY_INVALID", "Review decision identity or status is invalid.");
  }
  if (canonicalJson(decision.authority) !== canonicalJson(AUTHORITY)) {
    fail("REVIEW_DECISION_AUTHORITY_INVALID", "Review decisions are checker-only and confer no audit, routing, launch, or funds authority.");
  }
  validateTrustedPolicyProjection(decision.trustedPolicy, decision.profileId);
  const requireRouterProvenanceRequired = new Set(["launch-readiness", "production-launch"]).has(decision.profileId);
  const requireApplicationIdentity = decision.profileId === "launch-readiness";
  validateSubject(decision.expectedSubject, "expectedSubject", { requireApplicationIdentity, requireRouterProvenanceRequired });
  validateSubject(decision.currentSubject, "currentSubject", { requireApplicationIdentity, requireRouterProvenanceRequired });
  validateEvaluations(decision.evaluations);
  if (canonicalJson(decision.evaluations) !== canonicalJson(sortByCanonical(decision.evaluations))) {
    fail("REVIEW_DECISION_EVALUATIONS_INVALID", "Decision evaluations must use deterministic canonical order.");
  }
  validateRuleIdSet(decision.pendingRuleIds, "pendingRuleIds");
  validateRuleIdSet(decision.notApplicableRuleIds, "notApplicableRuleIds");
  validateFindings(decision.findings, decision.evaluations);
  validateAdvisories(decision.advisories);
  validateDecisionAgainstTrustedPolicy(decision, trustedPolicyRecord);
  if (verifyDigest && (!SHA256.test(decision.digest ?? "") || decision.digest !== hashLaunchPolicyDecision(decision))) {
    fail("REVIEW_DECISION_DIGEST_INVALID", "Review decision digest does not bind the exact canonical decision.");
  }
  return true;
}

function hashLaunchPolicyDecision(decision) {
  const value = decisionWithoutDigest(decision);
  return `sha256:${crypto.createHash("sha256").update(canonicalJson(value), "utf8").digest("hex")}`;
}

function decisionWithoutDigest(decision) {
  requirePlainObject(decision, "review decision", "REVIEW_DECISION_INVALID");
  const permitted = new Set([...DECISION_KEYS, "digest"]);
  if (!DECISION_KEYS.every((key) => Object.hasOwn(decision, key)) || Object.keys(decision).some((key) => !permitted.has(key))) {
    fail("REVIEW_DECISION_FIELDS_INVALID", "Review decision contains missing or unsupported fields.");
  }
  return Object.fromEntries(DECISION_KEYS.map((key) => [key, decision[key]]));
}

function projectTrustedPolicy(record, profileId) {
  return {
    repository: record.repository,
    numericRepositoryId: record.numericRepositoryId,
    baseCommit: record.baseCommit,
    baseTree: record.baseTree,
    path: record.path,
    gitBlobOid: record.gitBlobOid,
    policyId: record.policy.policyId,
    policyVersion: record.policy.policyVersion,
    profileId,
    sha256: record.sha256
  };
}

function validateTrustedPolicyProjection(value, profileId) {
  requirePlainObject(value, "trustedPolicy", "REVIEW_DECISION_POLICY_INVALID");
  exactKeys(value, ["baseCommit", "baseTree", "gitBlobOid", "numericRepositoryId", "path", "policyId", "policyVersion", "profileId", "repository", "sha256"], "REVIEW_DECISION_POLICY_INVALID", "Trusted policy projection");
  if (
    value.repository !== "programmablehq/Launch-Policy"
    || value.numericRepositoryId !== "1320171831"
    || value.path !== "policy/launch-policy.v1.json"
    || value.profileId !== profileId
    || !OBJECT_ID.test(value.baseCommit ?? "")
    || !OBJECT_ID.test(value.baseTree ?? "")
    || !OBJECT_ID.test(value.gitBlobOid ?? "")
    || !/^[a-z0-9][a-z0-9.-]{2,79}$/u.test(value.policyId ?? "")
    || !/^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u.test(value.policyVersion ?? "")
    || !SHA256.test(value.sha256 ?? "")
  ) {
    fail("REVIEW_DECISION_POLICY_INVALID", "Trusted policy projection is invalid.");
  }
}

function validateDecisionAgainstTrustedPolicy(decision, policyRecord) {
  if (!isPlainObject(policyRecord)) {
    fail("REVIEW_TRUSTED_POLICY_REQUIRED", "Canonical review validation requires the exact trusted Git policy record.");
  }
  try {
    // The build binding is an authority-neutral trust probe. Task 1 permits it
    // only for the exact WeakSet-bound record returned by the trusted Git reader
    // and revalidates the record's canonical bytes on every call.
    buildLaunchPolicyBinding(policyRecord, "build");
  } catch (error) {
    fail("REVIEW_TRUSTED_POLICY_REQUIRED", "Canonical review validation requires the exact trusted Git policy record.", error);
  }

  const profile = selectLaunchPolicyProfile(policyRecord.policy, decision.profileId);
  const exactProjection = projectTrustedPolicy(policyRecord, decision.profileId);
  if (canonicalJson(decision.trustedPolicy) !== canonicalJson(exactProjection)) {
    fail("REVIEW_DECISION_POLICY_PROJECTION_INVALID", "Decision policy identity does not match the exact trusted policy record.");
  }

  if (!profile.enabled) {
    if (
      decision.profileId !== "production-launch"
      || decision.expectedPolicyBinding !== null
      || decision.currentPolicyBinding !== null
      || decision.status !== "profile_disabled"
      || decision.outcome !== null
      || !semanticArraysEmpty(decision)
    ) {
      fail("REVIEW_DECISION_STATUS_INVALID", "A disabled profile can emit only the empty profile_disabled decision.");
    }
    return;
  }

  validatePolicyBinding(decision.expectedPolicyBinding);
  validatePolicyBinding(decision.currentPolicyBinding);
  if (
    decision.expectedPolicyBinding.profileId !== decision.profileId
    || decision.currentPolicyBinding.profileId !== decision.profileId
  ) {
    fail("REVIEW_DECISION_PROFILE_INVALID", "Expected and current policy bindings must match the decision profile for every status.");
  }
  const exactCurrentBinding = buildLaunchPolicyBinding(policyRecord, decision.profileId);
  if (!compareLaunchPolicyBindings(decision.currentPolicyBinding, exactCurrentBinding)) {
    fail("REVIEW_DECISION_POLICY_PROJECTION_INVALID", "Current decision binding does not match the exact trusted policy record.");
  }
  const bindingMatches = compareLaunchPolicyBindings(decision.expectedPolicyBinding, exactCurrentBinding);
  const subjectMatches = canonicalJson(decision.expectedSubject) === canonicalJson(decision.currentSubject);

  if (decision.status === "policy_drift") {
    if (bindingMatches || decision.outcome !== null || !semanticArraysEmpty(decision)) {
      fail("REVIEW_DECISION_STATUS_INVALID", "Policy drift requires one well-formed unequal recorded binding and no semantic result.");
    }
    return;
  }
  if (!bindingMatches) {
    fail("REVIEW_DECISION_STATUS_INVALID", "A non-drift decision requires exact expected and current policy binding equality.");
  }

  if (decision.status === "subject_drift") {
    if (subjectMatches || decision.outcome !== null || !semanticArraysEmpty(decision)) {
      fail("REVIEW_DECISION_STATUS_INVALID", "Subject drift requires unequal closed subjects and no semantic result.");
    }
    return;
  }
  if (!subjectMatches) {
    fail("REVIEW_DECISION_STATUS_INVALID", "A semantic decision requires exact expected and current subject equality.");
  }
  if (!new Set(["analysis_pending", "changes_requested", "passed"]).has(decision.status)) {
    fail("REVIEW_DECISION_STATUS_INVALID", "Enabled policy profiles support only drift or derived semantic statuses.");
  }

  validateSemanticRuleClosure(decision, policyRecord, profile);
}

function validateSemanticRuleClosure(decision, policyRecord, profile) {
  const activeRules = rulesForProfile(policyRecord.policy, decision.profileId);
  const applicableRules = activeRules.filter((rule) => ruleApplies(rule, decision.currentSubject));
  const nonApplicableRuleIds = activeRules
    .filter((rule) => !ruleApplies(rule, decision.currentSubject))
    .map(({ id }) => id)
    .sort(compareUtf8);
  if (canonicalJson(decision.notApplicableRuleIds) !== canonicalJson(nonApplicableRuleIds)) {
    fail("REVIEW_DECISION_POLICY_PROJECTION_INVALID", "Not-applicable Rule IDs must be derived exactly from trusted policy applicability.");
  }

  const applicableById = new Map(applicableRules.map((rule) => [rule.id, rule]));
  const evaluationById = new Map();
  for (const evaluation of decision.evaluations) {
    const rule = applicableById.get(evaluation.ruleId);
    if (
      !rule
      || rule.enforcement.mode !== "deterministic"
      || evaluation.analyzer.kind !== rule.enforcement.mode
      || evaluation.analyzer.id !== rule.enforcement.handlerId
    ) {
      fail("REVIEW_DECISION_POLICY_PROJECTION_INVALID", "Every authoritative evaluation must match one applicable deterministic trusted-policy rule and handler.");
    }
    evaluationById.set(evaluation.ruleId, evaluation);
  }

  const exactPendingRuleIds = [];
  const exactFindings = [];
  for (const rule of applicableRules) {
    const evaluation = evaluationById.get(rule.id);
    if (!evaluation || evaluation.state === "analysis_pending") exactPendingRuleIds.push(rule.id);
    if (evaluation?.state === "violated") exactFindings.push(projectFinding(rule, evaluation));
  }
  exactPendingRuleIds.sort(compareUtf8);
  const exactSortedFindings = sortByCanonical(exactFindings);
  if (canonicalJson(decision.pendingRuleIds) !== canonicalJson(exactPendingRuleIds)) {
    fail("REVIEW_DECISION_STATUS_INVALID", "Pending Rule IDs must equal missing and analysis-pending applicable policy rules.");
  }
  const exactStatus = exactFindings.length > 0
    ? "changes_requested"
    : exactPendingRuleIds.length > 0
      ? "analysis_pending"
      : "passed";
  const exactOutcome = exactStatus === "passed" ? profile.outcome : null;
  if (decision.status !== exactStatus) {
    fail("REVIEW_DECISION_STATUS_INVALID", "Status and outcome must be derived exactly from trusted-policy evaluation closure.");
  }
  if (decision.outcome !== exactOutcome) {
    fail("REVIEW_DECISION_OUTCOME_INVALID", "Outcome must be derived exactly from the trusted enabled profile and semantic status.");
  }
  if (canonicalJson(decision.findings) !== canonicalJson(exactSortedFindings)) {
    fail("REVIEW_DECISION_POLICY_PROJECTION_INVALID", "Every finding field must be reconstructed exactly from trusted policy and its violation evaluation.");
  }
}

function semanticArraysEmpty(decision) {
  return [decision.evaluations, decision.pendingRuleIds, decision.notApplicableRuleIds, decision.findings]
    .every((items) => items.length === 0);
}

function projectFinding(rule, evaluation) {
  return {
    ruleId: rule.id,
    requirement: rule.requirement,
    severity: rule.severity,
    enforcement: rule.enforcement,
    evidenceRefs: evaluation.evidenceRefs
  };
}

function observationsToAdvisories(observations) {
  return observations.map((observation) => ({
    code: "UNBOUND_OBSERVATION",
    ruleId: observation.ruleId,
    summary: observation.summary,
    evidenceRefs: [],
    analyzer: { kind: "llm", id: observation.analyzerId }
  }));
}

function unboundEvaluationAdvisory(evaluation) {
  return {
    code: "UNBOUND_EVALUATION",
    ruleId: evaluation.ruleId,
    summary: "The evaluation does not address an active rule in the selected trusted policy profile.",
    evidenceRefs: evaluation.evidenceRefs,
    analyzer: evaluation.analyzer
  };
}

function verifyApplicationRouterReadinessBinding({ applicationReadiness, parsedReadiness, readinessBytes, routerApplicability }) {
  const binding = applicationReadiness.readinessBinding;
  const routerSubject = routerApplicability.subject;
  const readinessSubject = parsedReadiness.document.subject;
  if (
    binding === null
    || binding.path !== ".programmable/launch-router-readiness.v1.json"
    || binding.byteLength !== readinessBytes.length
    || binding.sha256 !== routerApplicability.readinessDocumentSha256
    || binding.gitBlobOid !== gitBlobOid(readinessBytes)
    || applicationReadiness.applicationId !== readinessSubject.applicationId
    || Number(applicationReadiness.applicationRevision) !== readinessSubject.applicationRevision
    || applicationReadiness.subject.repository !== routerSubject.repository
    || applicationReadiness.subject.numericRepositoryId !== routerSubject.numericRepositoryId
    || applicationReadiness.subject.commit !== routerSubject.commit
    || applicationReadiness.subject.tree !== routerSubject.tree
    || (applicationReadiness.decision === "required" && applicationReadiness.subject.configurationHash !== routerSubject.configurationHash)
  ) {
    fail("REVIEW_LAUNCH_READINESS_APPLICATION_MISMATCH", "Router-readiness bytes do not match the exact opaque Application V3.2 source and artifact binding.");
  }
}

function gitBlobOid(bytes) {
  const normalized = Buffer.from(bytes);
  return crypto.createHash("sha1")
    .update(Buffer.from(`blob ${normalized.length}\0`, "utf8"))
    .update(normalized)
    .digest("hex");
}

function validatePolicyBinding(binding) {
  requirePlainObject(binding, "expectedPolicyBinding", "REVIEW_POLICY_BINDING_INVALID");
  exactKeys(binding, ["baseCommit", "baseTree", "gitBlobOid", "numericRepositoryId", "path", "policyId", "policyVersion", "profileId", "repository", "schemaVersion", "sha256"], "REVIEW_POLICY_BINDING_INVALID", "Expected policy binding");
  if (
    binding.schemaVersion !== BINDING_SCHEMA_VERSION
    || binding.repository !== "programmablehq/Launch-Policy"
    || binding.numericRepositoryId !== "1320171831"
    || binding.path !== "policy/launch-policy.v1.json"
    || !OBJECT_ID.test(binding.baseCommit ?? "")
    || !OBJECT_ID.test(binding.baseTree ?? "")
    || !OBJECT_ID.test(binding.gitBlobOid ?? "")
    || !/^[a-z0-9][a-z0-9.-]{2,79}$/u.test(binding.policyId ?? "")
    || !/^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u.test(binding.policyVersion ?? "")
    || !new Set(["build", "launch-readiness", "production-launch", "workflow-canary"]).has(binding.profileId)
    || !SHA256.test(binding.sha256 ?? "")
  ) {
    fail("REVIEW_POLICY_BINDING_INVALID", "Expected policy binding must be the exact closed eleven-field binding contract.");
  }
}

function validateSubject(subject, label, { requireApplicationIdentity = false, requireRouterProvenanceRequired = false } = {}) {
  requirePlainObject(subject, label, "REVIEW_SUBJECT_INVALID");
  const baseKeys = ["commit", "configurationHash", "numericRepositoryId", "repository", "tree", "usesUniswapV4"];
  const optionalKeys = ["applicationId", "applicationRevision", "applicationSha256", "packageSha256", "routerProvenanceRequired"];
  const observedKeys = Object.keys(subject);
  if (
    !baseKeys.every((key) => observedKeys.includes(key))
    || observedKeys.some((key) => ![...baseKeys, ...optionalKeys].includes(key))
    || (requireRouterProvenanceRequired && !Object.hasOwn(subject, "routerProvenanceRequired"))
    || (requireApplicationIdentity && !["applicationId", "applicationRevision", "applicationSha256", "packageSha256"].every((key) => Object.hasOwn(subject, key)))
    || (["applicationId", "applicationRevision", "applicationSha256", "packageSha256"].some((key) => Object.hasOwn(subject, key))
      && !["applicationId", "applicationRevision", "applicationSha256", "packageSha256"].every((key) => Object.hasOwn(subject, key)))
  ) {
    fail("REVIEW_SUBJECT_INVALID", `${label} contains missing or unsupported fields.`);
  }
  if (
    !POSITIVE_DECIMAL.test(subject.numericRepositoryId ?? "")
    || !REPOSITORY.test(subject.repository ?? "")
    || !OBJECT_ID.test(subject.commit ?? "")
    || !OBJECT_ID.test(subject.tree ?? "")
    || !SHA256.test(subject.configurationHash ?? "")
    || typeof subject.usesUniswapV4 !== "boolean"
    || (Object.hasOwn(subject, "applicationId") && (typeof subject.applicationId !== "string" || subject.applicationId.length > 80 || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(subject.applicationId)))
    || (Object.hasOwn(subject, "applicationRevision") && (!Number.isSafeInteger(subject.applicationRevision) || subject.applicationRevision < 1 || subject.applicationRevision > 1_000_000))
    || (Object.hasOwn(subject, "applicationSha256") && !SHA256.test(subject.applicationSha256 ?? ""))
    || (Object.hasOwn(subject, "packageSha256") && !SHA256.test(subject.packageSha256 ?? ""))
    || (Object.hasOwn(subject, "routerProvenanceRequired") && typeof subject.routerProvenanceRequired !== "boolean")
  ) {
    fail("REVIEW_SUBJECT_INVALID", `${label} must bind one exact closed project revision and build context.`);
  }
}

function validateEvaluations(evaluations) {
  if (!Array.isArray(evaluations) || evaluations.length > 256) fail("REVIEW_EVALUATIONS_INVALID", "Evaluations must be a bounded array.");
  const ids = new Set();
  for (const evaluation of evaluations) {
    requirePlainObject(evaluation, "evaluation", "REVIEW_EVALUATION_INVALID");
    exactKeys(evaluation, ["analyzer", "evidenceRefs", "ruleId", "state"], "REVIEW_EVALUATION_INVALID", "Evaluation");
    if (!RULE_ID.test(evaluation.ruleId ?? "") || !STATES.has(evaluation.state)) fail("REVIEW_EVALUATION_INVALID", "Evaluation rule id or state is invalid.");
    if (ids.has(evaluation.ruleId)) fail("REVIEW_EVALUATION_DUPLICATE", `Rule ${evaluation.ruleId} has competing evaluations.`);
    ids.add(evaluation.ruleId);
    validateEvidenceRefs(evaluation.evidenceRefs);
    if (evaluation.state !== "analysis_pending" && evaluation.evidenceRefs.length === 0) {
      fail("REVIEW_EVIDENCE_REFS_INVALID", `Evaluation ${evaluation.ruleId} must bind evidence when it passes or violates a rule.`);
    }
    validateAnalyzer(evaluation.analyzer);
  }
}

function validateRuleIdSet(values, label) {
  if (
    !Array.isArray(values)
    || values.length > 256
    || values.some((value) => !RULE_ID.test(value))
    || new Set(values).size !== values.length
    || canonicalJson(values) !== canonicalJson([...values].sort(compareUtf8))
  ) {
    fail("REVIEW_DECISION_RULE_SET_INVALID", `${label} must be a unique UTF-8-sorted Rule ID set.`);
  }
}

function validateFindings(findings, evaluations) {
  if (!Array.isArray(findings) || findings.length > 256 || canonicalJson(findings) !== canonicalJson(sortByCanonical(findings))) {
    fail("REVIEW_DECISION_FINDINGS_INVALID", "Findings must be a bounded deterministic array.");
  }
  const violatedById = new Map(evaluations.filter(({ state }) => state === "violated").map((evaluation) => [evaluation.ruleId, evaluation]));
  const ids = new Set();
  for (const finding of findings) {
    requirePlainObject(finding, "finding", "REVIEW_DECISION_FINDINGS_INVALID");
    exactKeys(finding, ["enforcement", "evidenceRefs", "requirement", "ruleId", "severity"], "REVIEW_DECISION_FINDINGS_INVALID", "Finding");
    requirePlainObject(finding.enforcement, "finding.enforcement", "REVIEW_DECISION_FINDINGS_INVALID");
    exactKeys(finding.enforcement, ["handlerId", "mode", "owner"], "REVIEW_DECISION_FINDINGS_INVALID", "Finding enforcement");
    const evaluation = violatedById.get(finding.ruleId);
    if (
      ids.has(finding.ruleId)
      || !evaluation
      || !safeText(finding.requirement, 500)
      || !new Set(["blocker", "required"]).has(finding.severity)
      || finding.enforcement.mode !== "deterministic"
      || !new Set(["applicant", "maintainer", "platform"]).has(finding.enforcement.owner)
      || !ANALYZER_ID.test(finding.enforcement.handlerId ?? "")
    ) {
      fail("REVIEW_DECISION_FINDINGS_INVALID", "Finding metadata or violation linkage is invalid.");
    }
    validateEvidenceRefs(finding.evidenceRefs);
    if (canonicalJson(finding.evidenceRefs) !== canonicalJson(evaluation.evidenceRefs)) {
      fail("REVIEW_DECISION_FINDINGS_INVALID", "Finding evidence must match its policy-bound violation evaluation.");
    }
    ids.add(finding.ruleId);
  }
}

function validateAdvisories(advisories) {
  if (!Array.isArray(advisories) || advisories.length > 384 || canonicalJson(advisories) !== canonicalJson(sortByCanonical(advisories))) {
    fail("REVIEW_DECISION_ADVISORIES_INVALID", "Advisories must be a bounded deterministic array.");
  }
  for (const advisory of advisories) {
    requirePlainObject(advisory, "advisory", "REVIEW_DECISION_ADVISORIES_INVALID");
    exactKeys(advisory, ["analyzer", "code", "evidenceRefs", "ruleId", "summary"], "REVIEW_DECISION_ADVISORIES_INVALID", "Advisory");
    if (!new Set(["UNBOUND_EVALUATION", "UNBOUND_OBSERVATION"]).has(advisory.code) || !RULE_ID.test(advisory.ruleId ?? "") || !safeText(advisory.summary, 1000)) {
      fail("REVIEW_DECISION_ADVISORIES_INVALID", "Advisory fields are invalid.");
    }
    validateEvidenceRefs(advisory.evidenceRefs);
    validateAnalyzer(advisory.analyzer);
  }
}

function validateObservations(observations) {
  if (!Array.isArray(observations) || observations.length > 128) fail("REVIEW_OBSERVATIONS_INVALID", "Observations must be a bounded array.");
  const seen = new Set();
  for (const observation of observations) {
    requirePlainObject(observation, "observation", "REVIEW_OBSERVATION_INVALID");
    exactKeys(observation, ["analyzerId", "ruleId", "summary"], "REVIEW_OBSERVATION_INVALID", "Observation");
    if (!ANALYZER_ID.test(observation.analyzerId ?? "") || !RULE_ID.test(observation.ruleId ?? "") || !safeText(observation.summary, 1000)) {
      fail("REVIEW_OBSERVATION_INVALID", "Observation fields are invalid.");
    }
    const key = canonicalJson(observation);
    if (seen.has(key)) fail("REVIEW_OBSERVATION_DUPLICATE", "Duplicate observations are not accepted.");
    seen.add(key);
  }
}

function validateEvidenceRefs(evidenceRefs) {
  if (!Array.isArray(evidenceRefs) || evidenceRefs.length > 64 || evidenceRefs.some((entry) => !SHA256.test(entry))) {
    fail("REVIEW_EVIDENCE_REFS_INVALID", "Evidence references must be a bounded array of SHA-256 digests.");
  }
  if (new Set(evidenceRefs).size !== evidenceRefs.length || canonicalJson(evidenceRefs) !== canonicalJson([...evidenceRefs].sort(compareUtf8))) {
    fail("REVIEW_EVIDENCE_REFS_INVALID", "Evidence references must be unique and sorted in UTF-8 order.");
  }
}

function validateAnalyzer(analyzer) {
  requirePlainObject(analyzer, "analyzer", "REVIEW_ANALYZER_INVALID");
  exactKeys(analyzer, ["id", "kind"], "REVIEW_ANALYZER_INVALID", "Analyzer");
  if (!ANALYZER_KINDS.has(analyzer.kind) || !ANALYZER_ID.test(analyzer.id ?? "")) {
    fail("REVIEW_ANALYZER_INVALID", "Analyzer identity is invalid.");
  }
}

function ruleApplies(rule, subject) {
  if (rule.applicability.mode === "always") return true;
  if (rule.applicability.mode === "historical") return false;
  return rule.applicability.field.split(".").reduce((value, key) => value?.[key], subject) === rule.applicability.equals;
}

function sortByCanonical(values) {
  return [...values].sort((left, right) => compareUtf8(canonicalJson(left), canonicalJson(right)));
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function safeText(value, maximumLength) {
  return typeof value === "string"
    && value.length > 0
    && value.length <= maximumLength
    && !/[\u0000-\u001f\u007f\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/u.test(value);
}

function exactKeys(value, expected, code, label) {
  if (!sameKeys(value, expected)) fail(code, `${label} contains missing or unsupported fields.`);
}

function sameKeys(value, expected) {
  return isPlainObject(value) && canonicalJson(Object.keys(value).sort(compareUtf8)) === canonicalJson([...expected].sort(compareUtf8));
}

function requirePlainObject(value, label, code) {
  if (!isPlainObject(value)) fail(code, `${label} must be an ordinary object.`);
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
  throw new LaunchPolicyReviewError(code, message, cause ? { cause } : undefined);
}
