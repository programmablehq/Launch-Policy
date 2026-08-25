import childProcess from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { TextDecoder } from "node:util";

import { parseBoundedLosslessJson } from "../vendor/programmable-applicant-validator/scripts/public-applicant-validator.mjs";
import { ruleHandlersForPolicyVersion } from "./launch-policy-handlers.mjs";

const MAXIMUM_POLICY_BYTES = 512 * 1024;
const POLICY_PATH = "policy/launch-policy.v1.json";
const REPOSITORY = "0xprogrammable/launch-policy";
const LEGACY_REPOSITORY = "0xprogrammable/submit-launch";
const NUMERIC_REPOSITORY_ID = "1320171831";
const REPOSITORY_REMOTE = "https://github.com/0xprogrammable/launch-policy.git";
const POLICY_SCHEMA_VERSION = "programmable.launch-policy.v1";
const BINDING_SCHEMA_VERSION = "programmable.launch-policy-binding.v1";
const OBJECT_ID = /^[0-9a-f]{40}$/u;
const SHA256 = /^sha256:[0-9a-f]{64}$/u;
const SEMVER = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const POLICY_ID = /^[a-z0-9][a-z0-9.-]{2,79}$/u;
const PROFILE_ID = /^[a-z0-9][a-z0-9-]{1,63}$/u;
const RULE_ID = /^[A-Z][A-Z0-9_]*(?:\.[A-Z][A-Z0-9_]*)+$/u;
const EVIDENCE_ID = /^[a-z0-9][a-z0-9-]{1,79}$/u;
const HANDLER_ID = /^[a-z0-9][a-z0-9-]{1,79}$/u;
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
const trustedPolicyRecords = new WeakSet();

export class LaunchPolicyError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.name = "LaunchPolicyError";
    this.code = code;
  }
}

export function parseLaunchPolicyBytes(bytes) {
  const buffer = Buffer.isBuffer(bytes) ? Buffer.from(bytes) : Buffer.from(bytes ?? []);
  if (buffer.length < 2 || buffer.length > MAXIMUM_POLICY_BYTES) {
    fail("LAUNCH_POLICY_SIZE_INVALID", "Launch policy bytes exceed the closed 512 KiB boundary.");
  }
  let source;
  try {
    source = decoder.decode(buffer);
    parseBoundedLosslessJson(source);
  } catch (error) {
    fail("LAUNCH_POLICY_JSON_INVALID", "Launch policy bytes must be duplicate-free, lossless UTF-8 JSON.", error);
  }
  let policy;
  try {
    policy = JSON.parse(source);
  } catch (error) {
    fail("LAUNCH_POLICY_JSON_INVALID", "Launch policy bytes must be valid JSON.", error);
  }
  validateLaunchPolicy(policy);
  const canonicalBytes = Buffer.from(`${canonicalJson(policy)}\n`, "utf8");
  if (!buffer.equals(canonicalBytes)) {
    fail("LAUNCH_POLICY_JSON_NONCANONICAL", "Launch policy must be compact, UTF-8-sorted canonical JSON followed by one LF.");
  }
  deepFreeze(policy);
  return Object.freeze({ bytes: buffer, policy, sha256: digestLaunchPolicyBytes(buffer) });
}

export function validateLaunchPolicy(policy) {
  requirePlainObject(policy, "policy");
  exactKeys(policy, ["effective", "migration", "policyId", "policyVersion", "profiles", "repository", "rules", "schemaVersion"], "policy");
  if (policy.schemaVersion !== POLICY_SCHEMA_VERSION || !POLICY_ID.test(policy.policyId ?? "") || !SEMVER.test(policy.policyVersion ?? "")) {
    fail("LAUNCH_POLICY_IDENTITY_INVALID", "Policy schema, id, and version must use the supported canonical forms.");
  }

  requirePlainObject(policy.repository, "policy.repository");
  exactKeys(policy.repository, ["branch", "name", "numericRepositoryId", "path"], "policy.repository");
  if (
    ![REPOSITORY, LEGACY_REPOSITORY].includes(policy.repository.name)
    || policy.repository.numericRepositoryId !== NUMERIC_REPOSITORY_ID
    || policy.repository.branch !== "main"
    || policy.repository.path !== POLICY_PATH
  ) {
    fail("LAUNCH_POLICY_REPOSITORY_INVALID", "Policy repository identity must match the protected Launch Policy source or its legacy repository name.");
  }

  requirePlainObject(policy.effective, "policy.effective");
  exactKeys(policy.effective, ["startsAt", "state"], "policy.effective");
  if (policy.effective.state !== "current" || !validTimestamp(policy.effective.startsAt)) {
    fail("LAUNCH_POLICY_EFFECTIVE_STATE_INVALID", "Policy effective state is invalid.");
  }

  requirePlainObject(policy.migration, "policy.migration");
  exactKeys(policy.migration, ["emergencyAction", "openApplications", "previouslyAcceptedRevisions"], "policy.migration");
  if (
    policy.migration.openApplications !== "re-evaluate-current-policy"
    || policy.migration.previouslyAcceptedRevisions !== "preserve-unless-explicit-emergency"
    || policy.migration.emergencyAction !== null
  ) {
    fail("LAUNCH_POLICY_MIGRATION_INVALID", "Policy migration behavior is not the closed initial contract.");
  }

  validateProfiles(policy.profiles, policy.policyVersion);
  validateRules(policy.rules, policy.profiles);
  if (JSON.stringify(policy).includes("LAUNCH_APPROVED")) {
    fail("LAUNCH_POLICY_AUTHORITY_INVALID", "The initial policy cannot contain production launch approval authority.");
  }
  assertDeterministicValidatorCoverage(policy);
  return true;
}

export function digestLaunchPolicyBytes(bytes) {
  const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes ?? []);
  return `sha256:${crypto.createHash("sha256").update(buffer).digest("hex")}`;
}

export function readTrustedLaunchPolicyFromGit(options) {
  requirePlainObject(options, "options", "LAUNCH_POLICY_READER_ARGUMENTS_INVALID");
  if (!sameKeys(options, ["expectedBaseCommit", "repositoryRoot"])) {
    fail("LAUNCH_POLICY_READER_ARGUMENTS_INVALID", "Trusted policy reader accepts only repositoryRoot and expectedBaseCommit.");
  }
  const { repositoryRoot, expectedBaseCommit } = options;
  if (typeof repositoryRoot !== "string" || !path.isAbsolute(repositoryRoot) || !OBJECT_ID.test(expectedBaseCommit ?? "")) {
    fail("LAUNCH_POLICY_READER_ARGUMENTS_INVALID", "Trusted policy reader arguments are invalid.");
  }
  let repositoryStatus;
  try {
    repositoryStatus = fs.lstatSync(repositoryRoot);
  } catch (error) {
    fail("LAUNCH_POLICY_GIT_IDENTITY_INVALID", "Trusted policy repository root is unavailable.", error);
  }
  if (!repositoryStatus.isDirectory() || repositoryStatus.isSymbolicLink()) {
    fail("LAUNCH_POLICY_GIT_IDENTITY_INVALID", "Trusted policy repository root must be a regular directory.");
  }

  const observedRemote = runGitText(repositoryRoot, ["remote", "get-url", "origin"], 4096);
  if (normalizeRemote(observedRemote) !== REPOSITORY_REMOTE) {
    fail("LAUNCH_POLICY_GIT_IDENTITY_INVALID", "Trusted policy repository origin is not 0xprogrammable/launch-policy.");
  }
  const baseCommit = runGitText(repositoryRoot, ["rev-parse", "--verify", `${expectedBaseCommit}^{commit}`], 128);
  if (baseCommit !== expectedBaseCommit) {
    fail("LAUNCH_POLICY_GIT_IDENTITY_INVALID", "Trusted policy base commit does not resolve exactly.");
  }
  const baseTree = runGitText(repositoryRoot, ["rev-parse", `${baseCommit}^{tree}`], 128);
  const entry = runGitText(repositoryRoot, ["ls-tree", baseCommit, "--", POLICY_PATH], 1024);
  const match = /^(100644) blob ([0-9a-f]{40})\tpolicy\/launch-policy\.v1\.json$/u.exec(entry);
  if (!match) {
    fail("LAUNCH_POLICY_GIT_OBJECT_INVALID", "Trusted policy path must resolve to one non-executable regular Git blob.");
  }
  const gitBlobOid = match[2];
  const declaredSize = Number(runGitText(repositoryRoot, ["cat-file", "-s", gitBlobOid], 128));
  if (!Number.isSafeInteger(declaredSize) || declaredSize < 2 || declaredSize > MAXIMUM_POLICY_BYTES) {
    fail("LAUNCH_POLICY_SIZE_INVALID", "Trusted policy Git blob exceeds the closed byte boundary.");
  }
  const bytes = runGit(repositoryRoot, ["cat-file", "blob", gitBlobOid], MAXIMUM_POLICY_BYTES + 1);
  if (bytes.length !== declaredSize) {
    fail("LAUNCH_POLICY_GIT_OBJECT_INVALID", "Trusted policy Git blob size does not match its declared size.");
  }
  const parsed = parseLaunchPolicyBytes(bytes);
  const policyRecord = Object.freeze({
    ...parsed,
    repository: REPOSITORY,
    numericRepositoryId: NUMERIC_REPOSITORY_ID,
    baseCommit,
    baseTree,
    path: POLICY_PATH,
    gitBlobOid
  });
  trustedPolicyRecords.add(policyRecord);
  return policyRecord;
}

export function buildLaunchPolicyBinding(policyRecord, profileId) {
  assertTrustedPolicyRecord(policyRecord);
  const required = ["baseCommit", "baseTree", "gitBlobOid", "numericRepositoryId", "path", "policy", "repository", "sha256"];
  if (!required.every((key) => Object.hasOwn(policyRecord, key))) {
    fail("LAUNCH_POLICY_BINDING_SOURCE_INVALID", "A binding requires an exact trusted Git policy record.");
  }
  const profile = selectLaunchPolicyProfile(policyRecord.policy, profileId);
  if (!profile.enabled) fail("LAUNCH_POLICY_PROFILE_DISABLED", `Launch policy profile ${profileId} is disabled.`);
  if (
    policyRecord.repository !== REPOSITORY
    || policyRecord.numericRepositoryId !== NUMERIC_REPOSITORY_ID
    || policyRecord.path !== POLICY_PATH
    || !OBJECT_ID.test(policyRecord.baseCommit)
    || !OBJECT_ID.test(policyRecord.baseTree)
    || !OBJECT_ID.test(policyRecord.gitBlobOid)
    || !SHA256.test(policyRecord.sha256)
  ) {
    fail("LAUNCH_POLICY_BINDING_SOURCE_INVALID", "Trusted Git policy identity is invalid.");
  }
  return Object.freeze({
    schemaVersion: BINDING_SCHEMA_VERSION,
    repository: REPOSITORY,
    numericRepositoryId: NUMERIC_REPOSITORY_ID,
    baseCommit: policyRecord.baseCommit,
    baseTree: policyRecord.baseTree,
    path: POLICY_PATH,
    gitBlobOid: policyRecord.gitBlobOid,
    policyId: policyRecord.policy.policyId,
    policyVersion: policyRecord.policy.policyVersion,
    profileId,
    sha256: policyRecord.sha256
  });
}

export function compareLaunchPolicyBindings(expected, observed) {
  const keys = ["baseCommit", "baseTree", "gitBlobOid", "numericRepositoryId", "path", "policyId", "policyVersion", "profileId", "repository", "schemaVersion", "sha256"];
  return isPlainObject(expected)
    && isPlainObject(observed)
    && sameKeys(expected, keys)
    && sameKeys(observed, keys)
    && keys.every((key) => expected[key] === observed[key]);
}

export function selectLaunchPolicyProfile(policy, profileId) {
  if (!isPlainObject(policy) || typeof profileId !== "string") {
    fail("LAUNCH_POLICY_PROFILE_INVALID", "Policy and profile id are required.");
  }
  const profile = policy.profiles?.find(({ id }) => id === profileId);
  if (!profile) fail("LAUNCH_POLICY_PROFILE_INVALID", `Unknown launch policy profile ${profileId}.`);
  return profile;
}

export function rulesForProfile(policy, profileId) {
  selectLaunchPolicyProfile(policy, profileId);
  return Object.freeze(policy.rules.filter(({ profiles, status }) => status === "active" && profiles.includes(profileId)));
}

export function evaluateLaunchPolicyRules({ policyRecord, profileId, subject, evidence }) {
  assertTrustedPolicyRecord(policyRecord);
  const profile = selectLaunchPolicyProfile(policyRecord.policy, profileId);
  if (!profile.enabled) fail("LAUNCH_POLICY_PROFILE_DISABLED", `Launch policy profile ${profileId} is disabled.`);
  if (!isPlainObject(subject) || !isPlainObject(evidence)) {
    fail("LAUNCH_POLICY_EVALUATION_INPUT_INVALID", "Rule subject and evidence must be closed objects.");
  }
  const requiresRouterProvenance = rulesForProfile(policyRecord.policy, profileId)
    .some(({ applicability }) => applicability.mode === "when" && applicability.field === "routerProvenanceRequired");
  if (requiresRouterProvenance && typeof subject.routerProvenanceRequired !== "boolean") {
    fail("LAUNCH_POLICY_EVALUATION_INPUT_INVALID", `Policy profile ${profileId} requires the protected derived routerProvenanceRequired subject flag.`);
  }

  const results = [];
  for (const rule of rulesForProfile(policyRecord.policy, profileId)) {
    if (!ruleApplies(rule.applicability, subject)) {
      results.push(Object.freeze({ ruleId: rule.id, status: "not-applicable", missingEvidence: Object.freeze([]) }));
      continue;
    }
    const handler = ruleHandlersForPolicyVersion(policyRecord.policy.policyVersion)[rule.enforcement.handlerId];
    const result = handler({ evidence, rule, subject });
    if (!new Set(["analysis-pending", "failed", "passed"]).has(result.status)) {
      fail("LAUNCH_POLICY_HANDLER_RESULT_INVALID", `Policy handler ${rule.enforcement.handlerId} returned an invalid status.`);
    }
    results.push(Object.freeze({
      ruleId: rule.id,
      status: result.status,
      missingEvidence: result.missingEvidence,
      message: result.message
    }));
  }
  const findings = results
    .filter(({ status }) => status === "failed")
    .map(({ message, missingEvidence, ruleId }) => Object.freeze({ message, missingEvidence, ruleId }));
  const pendingRuleIds = results
    .filter(({ status }) => status === "analysis-pending")
    .map(({ ruleId }) => ruleId);
  const passed = findings.length === 0 && pendingRuleIds.length === 0;
  return Object.freeze({
    profileId,
    passed,
    outcome: passed ? profile.outcome : null,
    authority: profile.authority,
    results: Object.freeze(results),
    findings: Object.freeze(findings),
    pendingRuleIds: Object.freeze(pendingRuleIds)
  });
}

export function renderLaunchPolicyMarkdown(policyRecord) {
  if (!isPlainObject(policyRecord) || !isPlainObject(policyRecord.policy) || !SHA256.test(policyRecord.sha256 ?? "")) {
    fail("LAUNCH_POLICY_RECORD_INVALID", "A parsed launch policy record is required for rendering.");
  }
  validateLaunchPolicy(policyRecord.policy);
  const lines = [
    "# Programmable Launch Policy",
    "",
    `Generated from the canonical policy at \`${POLICY_PATH}\`. Digest: \`${policyRecord.sha256}\`.`,
    "",
    "This document is a generated projection. The canonical JSON is authoritative.",
    ""
  ];
  for (const profile of policyRecord.policy.profiles) {
    lines.push(`## ${title(profile.id)}${profile.enabled ? "" : " (disabled)"}`, "");
    lines.push(`Outcome: ${profile.outcome === null ? "none" : `\`${profile.outcome}\``}.`, "");
    for (const rule of rulesForProfile(policyRecord.policy, profile.id)) {
      lines.push(`- \`${rule.id}\`: ${rule.requirement}`);
    }
    lines.push("");
  }
  return `${lines.join("\n").trimEnd()}\n`;
}

function validateProfiles(profiles, policyVersion) {
  const legacy = new Set(["1.0.0", "1.1.0", "1.2.0", "1.3.0"]).has(policyVersion);
  const expectedProfileIds = legacy
    ? ["build", "production-launch", "workflow-canary"]
    : new Set(["2.0.0", "2.1.0"]).has(policyVersion)
      ? ["build", "launch-readiness", "production-launch", "workflow-canary"]
      : null;
  if (expectedProfileIds === null) {
    fail("LAUNCH_POLICY_IDENTITY_INVALID", `Policy version ${policyVersion} is unsupported.`);
  }
  if (!Array.isArray(profiles) || profiles.length !== expectedProfileIds.length) {
    fail("LAUNCH_POLICY_PROFILE_INVALID", `Policy ${policyVersion} must declare exactly ${expectedProfileIds.length} profiles.`);
  }
  assertSortedUnique(profiles.map(({ id } = {}) => id), "profile ids");
  if (canonicalJson(profiles.map(({ id }) => id)) !== canonicalJson(expectedProfileIds)) {
    fail("LAUNCH_POLICY_PROFILE_INVALID", `Policy profiles do not match the closed ${legacy ? "v1" : "v2"} set.`);
  }
  for (const profile of profiles) {
    requirePlainObject(profile, `profile ${profile?.id ?? "unknown"}`);
    exactKeys(profile, ["authority", "enabled", "id", "outcome"], `profile ${profile.id}`);
    if (!PROFILE_ID.test(profile.id) || typeof profile.enabled !== "boolean") fail("LAUNCH_POLICY_PROFILE_INVALID", `Profile ${profile.id} is invalid.`);
    requirePlainObject(profile.authority, `profile ${profile.id}.authority`);
    exactKeys(profile.authority, ["checkerOnly", "independentAudit", "launchAuthorized", "productionDiscoveryAllowed", "publicRoutingAllowed", "realUserFundsAllowed"], `profile ${profile.id}.authority`);
    if (Object.values(profile.authority).some((value) => typeof value !== "boolean")) fail("LAUNCH_POLICY_AUTHORITY_INVALID", `Profile ${profile.id} authority flags must be boolean.`);
    if (profile.authority.launchAuthorized || profile.authority.independentAudit) fail("LAUNCH_POLICY_AUTHORITY_INVALID", `Profile ${profile.id} cannot confer launch or audit authority.`);
  }
  const build = profiles[0];
  const readiness = legacy ? null : profiles[1];
  const production = profiles[legacy ? 1 : 2];
  const canary = profiles[legacy ? 2 : 3];
  if (!build.enabled || build.outcome !== "BUILT_NOT_REVIEWED") fail("LAUNCH_POLICY_PROFILE_INVALID", "Build profile outcome is invalid.");
  if (!closedAuthority(build.authority, true)) fail("LAUNCH_POLICY_AUTHORITY_INVALID", "Build authority must remain checker-only and non-production.");
  if (!legacy) {
    if (!readiness.enabled || readiness.outcome !== "LAUNCH_READINESS_CHECKED_NOT_AUTHORIZED") fail("LAUNCH_POLICY_PROFILE_INVALID", "Launch-readiness profile outcome is invalid.");
    if (!closedAuthority(readiness.authority, true)) fail("LAUNCH_POLICY_AUTHORITY_INVALID", "Launch-readiness authority must remain checker-only and non-production.");
  }
  if (production.enabled || production.outcome !== null) fail("LAUNCH_POLICY_PROFILE_INVALID", "Production launch profile must remain disabled without an outcome.");
  if (!closedAuthority(production.authority, false)) fail("LAUNCH_POLICY_AUTHORITY_INVALID", "Production launch authority must remain fully disabled.");
  if (!canary.enabled || canary.outcome !== "CANARY_WORKFLOW_PASSED") fail("LAUNCH_POLICY_PROFILE_INVALID", "Workflow canary outcome is invalid.");
  if (!closedAuthority(canary.authority, true)) fail("LAUNCH_POLICY_AUTHORITY_INVALID", "Workflow canary authority must remain checker-only and non-production.");
}

function validateRules(rules, profiles) {
  if (!Array.isArray(rules) || rules.length < 1 || rules.length > 256) fail("LAUNCH_POLICY_RULE_INVALID", "Policy rules must be a bounded non-empty array.");
  const ids = rules.map(({ id } = {}) => id);
  if (new Set(ids).size !== ids.length || ids.some((id) => !RULE_ID.test(id ?? ""))) fail("LAUNCH_POLICY_RULE_ID_INVALID", "Policy Rule IDs must be unique and canonical.");
  assertSortedUnique(ids, "rule ids");
  const profileIds = new Set(profiles.map(({ id }) => id));
  for (const rule of rules) validateRule(rule, profileIds);
}

function validateRule(rule, profileIds) {
  requirePlainObject(rule, `rule ${rule?.id ?? "unknown"}`);
  const allowed = ["applicability", "enforcement", "evidence", "id", "introducedIn", "parameters", "profiles", "requirement", "retiredIn", "severity", "status"];
  const required = allowed.filter((key) => key !== "parameters");
  if (!required.every((key) => Object.hasOwn(rule, key)) || Object.keys(rule).some((key) => !allowed.includes(key))) {
    fail("LAUNCH_POLICY_FIELDS_INVALID", `rule ${rule.id} has unsupported fields.`);
  }
  if (!SEMVER.test(rule.introducedIn ?? "") || (rule.retiredIn !== null && !SEMVER.test(rule.retiredIn ?? ""))) fail("LAUNCH_POLICY_RULE_INVALID", `rule ${rule.id} version history is invalid.`);
  if (!new Set(["blocker", "required"]).has(rule.severity) || !new Set(["active", "inactive"]).has(rule.status)) fail("LAUNCH_POLICY_RULE_INVALID", `rule ${rule.id} status or severity is invalid.`);
  requireSafeText(rule.requirement, `rule ${rule.id}.requirement`, 500);
  if (!Array.isArray(rule.profiles) || rule.profiles.length < 1 || rule.profiles.some((id) => !profileIds.has(id))) fail("LAUNCH_POLICY_RULE_INVALID", `rule ${rule.id} profiles are invalid.`);
  assertSortedUnique(rule.profiles, `rule ${rule.id} profiles`);
  if (!Array.isArray(rule.evidence) || rule.evidence.length < 1 || rule.evidence.some((id) => !EVIDENCE_ID.test(id))) fail("LAUNCH_POLICY_RULE_INVALID", `rule ${rule.id} evidence ids are invalid.`);
  assertSortedUnique(rule.evidence, `rule ${rule.id} evidence ids`);
  validateApplicability(rule);
  validateEnforcement(rule);
  if (rule.status === "active" && rule.applicability.mode === "historical") fail("LAUNCH_POLICY_RULE_INVALID", `active rule ${rule.id} cannot use historical applicability.`);
  if (rule.status === "active" && rule.retiredIn !== null) fail("LAUNCH_POLICY_RULE_INVALID", `active rule ${rule.id} cannot be retired.`);
  if (rule.status === "inactive") {
    const deterministicTombstone = rule.applicability.mode !== "historical"
      && rule.enforcement.mode === "deterministic";
    const legacyHistory = rule.applicability.mode === "historical"
      && new Set(["human", "legacy-adapter"]).has(rule.enforcement.mode)
      && canonicalJson(rule.profiles) === canonicalJson(["production-launch"]);
    if (rule.retiredIn === null || (!deterministicTombstone && !legacyHistory)) {
      fail("LAUNCH_POLICY_RULE_INVALID", `inactive rule ${rule.id} must preserve either a retired deterministic tombstone or production-only legacy history.`);
    }
  }
  if (Object.hasOwn(rule, "parameters")) validateJsonValue(rule.parameters, 0);
}

function validateApplicability(rule) {
  requirePlainObject(rule.applicability, `rule ${rule.id}.applicability`);
  const { applicability } = rule;
  if (applicability.mode === "always" || applicability.mode === "historical") {
    exactKeys(applicability, ["mode"], `rule ${rule.id}.applicability`);
    return;
  }
  if (applicability.mode === "when") {
    exactKeys(applicability, ["equals", "field", "mode"], `rule ${rule.id}.applicability`);
    if (!/^[a-z][A-Za-z0-9]*(?:\.[a-z][A-Za-z0-9]*)*$/u.test(applicability.field ?? "") || typeof applicability.equals !== "boolean") {
      fail("LAUNCH_POLICY_RULE_INVALID", `rule ${rule.id} conditional applicability is invalid.`);
    }
    return;
  }
  fail("LAUNCH_POLICY_RULE_INVALID", `rule ${rule.id} applicability mode is invalid.`);
}

function validateEnforcement(rule) {
  requirePlainObject(rule.enforcement, `rule ${rule.id}.enforcement`);
  exactKeys(rule.enforcement, ["handlerId", "mode", "owner"], `rule ${rule.id}.enforcement`);
  if (!new Set(["applicant", "maintainer", "platform"]).has(rule.enforcement.owner)) fail("LAUNCH_POLICY_RULE_INVALID", `rule ${rule.id} enforcement owner is invalid.`);
  if (rule.status === "active" || rule.enforcement.mode === "deterministic") {
    if (rule.enforcement.mode !== "deterministic" || !HANDLER_ID.test(rule.enforcement.handlerId ?? "")) fail("LAUNCH_POLICY_RULE_INVALID", `active rule ${rule.id} must bind a deterministic handler.`);
  } else if (!new Set(["human", "legacy-adapter"]).has(rule.enforcement.mode) || rule.enforcement.handlerId !== null) {
    fail("LAUNCH_POLICY_RULE_INVALID", `inactive rule ${rule.id} enforcement history is invalid.`);
  }
}

function assertDeterministicValidatorCoverage(policy) {
  const declared = policy.rules
    .filter(({ enforcement, status }) => status === "active" && enforcement.mode === "deterministic")
    .map(({ enforcement }) => enforcement.handlerId)
    .sort(compareUtf8);
  const implemented = Object.keys(ruleHandlersForPolicyVersion(policy.policyVersion)).sort(compareUtf8);
  if (new Set(declared).size !== declared.length || canonicalJson(declared) !== canonicalJson(implemented)) {
    fail("LAUNCH_POLICY_HANDLER_COVERAGE_INVALID", "Active deterministic handler ids and implemented handlers must form an exact bijection.");
  }
}

function ruleApplies(applicability, subject) {
  if (applicability.mode === "always") return true;
  if (applicability.mode === "historical") return false;
  return applicability.field.split(".").reduce((value, key) => value?.[key], subject) === applicability.equals;
}

function assertTrustedPolicyRecord(policyRecord) {
  if (!isPlainObject(policyRecord) || !trustedPolicyRecords.has(policyRecord)) {
    fail("LAUNCH_POLICY_TRUST_INVALID", "Policy authority requires the exact record returned by the trusted Git reader.");
  }
  let reparsed;
  try {
    reparsed = parseLaunchPolicyBytes(policyRecord.bytes);
  } catch (error) {
    fail("LAUNCH_POLICY_TRUST_INVALID", "Trusted policy bytes no longer satisfy the canonical policy contract.", error);
  }
  if (
    reparsed.sha256 !== policyRecord.sha256
    || canonicalJson(reparsed.policy) !== canonicalJson(policyRecord.policy)
  ) {
    fail("LAUNCH_POLICY_TRUST_INVALID", "Trusted policy bytes, digest, and policy value must remain exactly bound.");
  }
}

function closedAuthority(authority, checkerOnly) {
  return authority.checkerOnly === checkerOnly
    && authority.independentAudit === false
    && authority.launchAuthorized === false
    && authority.productionDiscoveryAllowed === false
    && authority.publicRoutingAllowed === false
    && authority.realUserFundsAllowed === false;
}

export function canonicalJson(value) {
  return JSON.stringify(sortJson(value));
}

function sortJson(value) {
  if (Array.isArray(value)) return value.map(sortJson);
  if (!isPlainObject(value)) return value;
  return Object.fromEntries(Object.keys(value).sort(compareUtf8).map((key) => [key, sortJson(value[key])]));
}

function exactKeys(value, expected, label) {
  if (!sameKeys(value, expected)) fail("LAUNCH_POLICY_FIELDS_INVALID", `${label} must contain exactly the supported fields.`);
}

function sameKeys(value, expected) {
  return isPlainObject(value) && canonicalJson(Object.keys(value).sort(compareUtf8)) === canonicalJson([...expected].sort(compareUtf8));
}

function assertSortedUnique(values, label) {
  if (values.some((value) => typeof value !== "string") || new Set(values).size !== values.length) {
    fail(label === "rule ids" ? "LAUNCH_POLICY_RULE_ID_INVALID" : "LAUNCH_POLICY_ORDER_INVALID", `${label} must be unique strings in UTF-8 order.`);
  }
  const sorted = [...values].sort(compareUtf8);
  if (canonicalJson(values) !== canonicalJson(sorted)) fail("LAUNCH_POLICY_ORDER_INVALID", `${label} must use UTF-8 byte order.`);
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function validateJsonValue(value, depth) {
  if (depth > 16) fail("LAUNCH_POLICY_RULE_INVALID", "Rule parameters exceed the depth boundary.");
  if (value === null || typeof value === "boolean") return;
  if (typeof value === "string") return requireSafeText(value, "rule parameter", 1000);
  if (typeof value === "number" && Number.isSafeInteger(value)) return;
  if (Array.isArray(value)) return value.forEach((entry) => validateJsonValue(entry, depth + 1));
  if (isPlainObject(value)) {
    for (const [key, entry] of Object.entries(value)) {
      requireSafeText(key, "rule parameter key", 100);
      validateJsonValue(entry, depth + 1);
    }
    return;
  }
  fail("LAUNCH_POLICY_RULE_INVALID", "Rule parameters must be bounded ordinary JSON.");
}

function requireSafeText(value, label, maximumLength) {
  if (typeof value !== "string" || value.length < 1 || value.length > maximumLength || /[\u0000-\u001f\u007f\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/u.test(value)) {
    fail("LAUNCH_POLICY_TEXT_INVALID", `${label} contains unsupported text.`);
  }
}

function validTimestamp(value) {
  return typeof value === "string" && /^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/u.test(value) && !Number.isNaN(Date.parse(value));
}

function normalizeRemote(remote) {
  const trimmed = remote.trim().replace(/\/$/u, "");
  const canonicalCandidate = trimmed.toLowerCase();
  if (canonicalCandidate === "git@github.com:0xprogrammable/launch-policy.git") return REPOSITORY_REMOTE;
  if (canonicalCandidate === REPOSITORY_REMOTE) return REPOSITORY_REMOTE;
  if (canonicalCandidate === "https://github.com/0xprogrammable/launch-policy") return REPOSITORY_REMOTE;
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
    fail("LAUNCH_POLICY_GIT_IDENTITY_INVALID", "Trusted policy Git identity could not be resolved.", error);
  }
}

function requirePlainObject(value, label, code = "LAUNCH_POLICY_FIELDS_INVALID") {
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

function title(profileId) {
  return profileId.split("-").map((word) => `${word[0].toUpperCase()}${word.slice(1)}`).join(" ");
}

function fail(code, message, cause) {
  throw new LaunchPolicyError(code, message, cause ? { cause } : undefined);
}
