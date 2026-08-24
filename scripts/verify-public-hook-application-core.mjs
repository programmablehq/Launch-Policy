import childProcess from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { TextDecoder } from "node:util";
import {
  createGitHubPublicFetchTransportV1,
  GITHUB_PUBLIC_SOURCE_CONTRACT_V1,
  GitHubPublicSourceError,
  isCanonicalGitHubRepositoryPathV1,
  parseBoundedLosslessJson,
  resolveGitHubPublicSourceV1,
  validateGitHubPublicSourceRequestV1
} from "../vendor/programmable-applicant-validator/scripts/public-applicant-validator.mjs";
import {
  createAnonymousGitHubExactObjectResolverV1,
  GITHUB_PUBLIC_GIT_OBJECT_RESOLVER_V1
} from "../vendor/programmable-applicant-validator/scripts/public-applicant-validator.mjs";
import { findUnsupportedPublicClaims } from "../vendor/programmable-applicant-validator/scripts/public-applicant-validator.mjs";
import {
  normalizeCompanionManifest,
  validateCompanionClosureReceipts,
  verifyCompanionManifestV2Closure
} from "../vendor/programmable-applicant-validator/scripts/public-applicant-validator.mjs";
import { normalizeBuilderTemplate } from "../vendor/programmable-applicant-validator/scripts/public-applicant-validator.mjs";
import { hasForbiddenInvisibleOrBidi } from "../vendor/programmable-applicant-validator/scripts/public-applicant-validator.mjs";
import {
  buildLaunchPolicyBinding,
  compareLaunchPolicyBindings,
  parseLaunchPolicyBytes,
  readTrustedLaunchPolicyFromGit
} from "./launch-policy-core.mjs";
import { parseWorkflowCanaryApplicationBytes } from "./workflow-canary-core.mjs";
import {
  PublicApplicationV3IntakeError,
  deriveApplicationV3FeeApplicabilityFromSubmissionV2,
  derivePublicPrApplicationV3PreviousBinding,
  deriveTrustedPublicApplicationV3LaunchReadinessV1,
  validatePublicApplicationV3PackageFiles,
  validatePublicApplicationV3SubmissionV2Bytes
} from "./verify-public-application-v3-core.mjs";

export const VALIDATOR_VERSION = "2.0.0";
export const PUBLIC_APPLICATION_SCHEMA_ID = "https://programmable.money/schemas/public-pr-application-v2.json";
export const PUBLIC_BETA_DISCLAIMER =
  "Builder-declared compatibility evidence; not an audit, approval, deployment, Uniswap endorsement, or launch.";
export const PUBLIC_INTAKE_STATES = Object.freeze(["prelaunch", "open", "paused-new", "paused-all", "closed"]);
export const MAXIMUM_MAINTAINED_LEGACY_PACKAGES = 32;
export const MAINTAINED_LEGACY_PACKAGE_TIMEOUT_MS = 120_000;

const APPLICATION_FILE = "application.json";
const INTAKE_STATUS_PATH = "docs/builder/intake-status.json";
const MAXIMUM_INTAKE_STATUS_BYTES = 32 * 1024;
const MAXIMUM_CONTINUING_PULL_REQUESTS = 32;
const MAXIMUM_CONTINUATION_COMPANIONS = 8;
const APPLICATION_FILES = Object.freeze([
  APPLICATION_FILE,
  "PROPOSAL.md",
  "TEST_PLAN.md",
  "THREAT_MODEL.md",
  "compatibility-report.json",
  "evidence-index.json"
]);
export const PUBLIC_APPLICATION_FILES = APPLICATION_FILES;
export const GITHUB_ANONYMOUS_RESOLUTION_BUDGET_V1 = Object.freeze({
  maximumProviderRequests: 60,
  maximumSourceRequests: GITHUB_PUBLIC_SOURCE_CONTRACT_V1.limits.anonymousRestRequests,
  maximumTransportRetries: 12,
  minimumIntervalMs: 125,
  maximumRetryDelayMs: 1_000,
  timeoutMs: GITHUB_PUBLIC_SOURCE_CONTRACT_V1.limits.maximumTimeoutMs
});
const maximumAnonymousSchedulingDelayMs =
  ((GITHUB_ANONYMOUS_RESOLUTION_BUDGET_V1.maximumProviderRequests - 1)
    * GITHUB_ANONYMOUS_RESOLUTION_BUDGET_V1.minimumIntervalMs)
  + (GITHUB_ANONYMOUS_RESOLUTION_BUDGET_V1.maximumTransportRetries
    * GITHUB_ANONYMOUS_RESOLUTION_BUDGET_V1.maximumRetryDelayMs);
if (
  GITHUB_ANONYMOUS_RESOLUTION_BUDGET_V1.maximumSourceRequests
    + GITHUB_ANONYMOUS_RESOLUTION_BUDGET_V1.maximumTransportRetries
    > GITHUB_ANONYMOUS_RESOLUTION_BUDGET_V1.maximumProviderRequests
  || maximumAnonymousSchedulingDelayMs >= GITHUB_ANONYMOUS_RESOLUTION_BUDGET_V1.timeoutMs
) {
  throw new Error("trusted anonymous GitHub request, pacing, retry, and timeout budgets are inconsistent");
}
const GITHUB_PUBLIC_TRANSPORT_DEFAULTS = Object.freeze({
  maximumRetryBodyBytes: 16 * 1024,
  maximumRetryDelayMs: GITHUB_ANONYMOUS_RESOLUTION_BUDGET_V1.maximumRetryDelayMs,
  minimumIntervalMs: GITHUB_ANONYMOUS_RESOLUTION_BUDGET_V1.minimumIntervalMs,
  transientRetryDelayMs: 250
});
const REVIEW_FILES = Object.freeze([
  "PROPOSAL.md",
  "TEST_PLAN.md",
  "THREAT_MODEL.md",
  "compatibility-report.json",
  "evidence-index.json"
]);
const EXECUTABLE_BUILDER_VENDOR_PREFIX = "vendor/programmable-v4-hook-builder/";
const COMPACT_APPLICANT_VALIDATOR_PREFIX = "vendor/programmable-applicant-validator/";
const REGISTRY_MAINTENANCE_PREFIXES = Object.freeze([
  "acceptance/",
  "assets/",
  "docs/",
  "intake/schemas/",
  "registry/",
  "review/",
  "scripts/test/fixtures/",
  "scripts/test/schema-validator/",
  "test/",
  COMPACT_APPLICANT_VALIDATOR_PREFIX,
  EXECUTABLE_BUILDER_VENDOR_PREFIX
]);
const REGISTRY_MAINTENANCE_FILES = new Set([
  ".programmable/applicant-compatibility.v1.json",
  ".programmable/applicant-compatibility.v2.json",
  ".programmable/active-contract.json",
  ".programmable/active-contract.v2.json",
  ".programmable/universal-admission-contract.v1.json",
  ".github/CODEOWNERS",
  ".github/ISSUE_TEMPLATE/config.yml",
  ".github/ISSUE_TEMPLATE/documentation.yml",
  ".github/ISSUE_TEMPLATE/review-or-registry-bug.yml",
  ".github/PULL_REQUEST_TEMPLATE.md",
  ".github/workflows/codeql.yml",
  ".github/workflows/verify-hook-builder.yml",
  ".github/workflows/verify-post-merge.yml",
  ".github/workflows/verify.yml",
  ".gitignore",
  "AGENTS.md",
  "CODE_OF_CONDUCT.md",
  "CONTRIBUTING.md",
  "LICENSE",
  "README.md",
  "SECURITY.md",
  "SUPPORT.md",
  "package-lock.json",
  "package.json",
  "policy/launch-policy-authority-ownership.v1.json",
  "policy/launch-policy.v1.json",
  "policy/schemas/launch-policy-authority-ownership.v1.schema.json",
  "policy/schemas/launch-policy-binding.v1.schema.json",
  "policy/schemas/launch-policy.v1.schema.json",
  "policy/schemas/programmable-runtime-fee-settlement-proof-v1.schema.json",
  "canary/schemas/workflow-canary-application-v1.schema.json",
  "canary/schemas/workflow-canary-result-v1.schema.json",
  "scripts/acceptance-entitlement-core.mjs",
  "scripts/active-contract-manifest-core.mjs",
  "scripts/applicant-compatibility-core.mjs",
  "scripts/applicant-v3_2-scaffold-core.mjs",
  "scripts/applicant-v3_2-scaffold.mjs",
  "scripts/benchmark-universal-admission-sqlite.mjs",
  "scripts/canary-eligibility-core.mjs",
  "scripts/compile-canary-eligibility.mjs",
  "scripts/compile-launch-entitlement.mjs",
  "scripts/generate-launch-policy-artifacts.mjs",
  "scripts/generate-registry.mjs",
  "scripts/launch-policy-authority-ownership.mjs",
  "scripts/launch-policy-core.mjs",
  "scripts/launch-policy-handlers.mjs",
  "scripts/launch-policy.mjs",
  "scripts/programmable-launch-router-readiness-core.mjs",
  "scripts/programmable-launch-router-readiness.mjs",
  "scripts/programmable-runtime-fee-settlement-proof-core.mjs",
  "scripts/programmable-runtime-fee-settlement-proof-validation.mjs",
  "scripts/registry-core.mjs",
  "scripts/release-version-core.mjs",
  "scripts/universal-admission-command-core.mjs",
  "scripts/universal-admission-contract-core.mjs",
  "scripts/universal-admission-contract.mjs",
  "scripts/universal-admission-core.mjs",
  "scripts/universal-admission-protocol-core.mjs",
  "scripts/universal-admission-service-core.mjs",
  "scripts/universal-admission-sqlite-store.mjs",
  "scripts/universal-admission-sqlite.mjs",
  "scripts/universal-admission.mjs",
  "scripts/test/application-v3-package-fixture.mjs",
  "scripts/test/verify-open-world-v2-trade-manifest-v2.test.mjs",
  "scripts/test/verify-public-application-v3.test.mjs",
  "scripts/verify-open-world-v2-contracts.mjs",
  "scripts/verify-open-world-v2-package.mjs",
  "scripts/verify-open-world-v2-trade-manifest-v2.mjs",
  "scripts/verify-open-world-v2-validation-fee.mjs",
  "scripts/verify-open-world-v2-validation-intake.mjs",
  "scripts/verify-open-world-v2-validation-intent.mjs",
  "scripts/verify-public-application-v3-core.mjs",
  "scripts/verify-public-application-v3-generation.mjs",
  "scripts/verify-public-application-v3-shared.mjs",
  "scripts/verify-repository.mjs",
  "scripts/verify-public-hook-application-core.mjs",
  "scripts/verify-public-hook-application.mjs",
  "scripts/verify-workflow-canary.mjs",
  "scripts/workflow-canary-core.mjs",
  "canary-submissions/README.md",
  "submissions/README.md",
  "vendor/receipt.json"
]);
const RESERVED_MAINTENANCE_PREFIXES = Object.freeze([
  ".github/",
  ".programmable/",
  "canary-submissions/",
  "canary/",
  "intake/",
  "policy/",
  "scripts/",
  "submissions/",
  "vendor/"
]);
const SHARED_REGISTRY_DOCUMENTATION_FILES = new Set([]);
const APPLICATION_PATH_PATTERN = /^submissions\/([a-z0-9]+(?:-[a-z0-9]+)*)\/([^/]+)$/;
const APPLICATION_V3_PATH_PATTERN = /^submissions\/([a-z0-9]+(?:-[a-z0-9]+)*)\/v3\/revisions\/([1-9][0-9]*)\/(.+)$/u;
const APPLICATION_V3_ROOT_FILE = "application.v3.json";
const MAXIMUM_APPLICATION_V3_PACKAGE_FILES = 100;
const MAXIMUM_APPLICATION_V3_FILE_BYTES = 4 * 1024 * 1024;
const MAXIMUM_APPLICATION_V3_MANIFEST_BYTES = 256 * 1024;
const MAXIMUM_APPLICATION_V3_PACKAGE_BYTES = 12 * 1024 * 1024;
const MAXIMUM_APPLICATION_V3_OPEN_DRAFT_COMMITS = 32;
const APPLICATION_V3_OPEN_DRAFT_FETCH_DEPTH = MAXIMUM_APPLICATION_V3_OPEN_DRAFT_COMMITS + 2;
const CANARY_APPLICATION_PREFIX = "canary-submissions/";
const CANARY_APPLICATION_PATH_PATTERN = /^canary-submissions\/([a-z0-9]+(?:-[a-z0-9]+)*)\/application\.json$/;
const SHA1_PATTERN = /^[a-f0-9]{40}$/;
const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
const OPAQUE_ID_PATTERN = /^[1-9][0-9]{0,63}$/;
const SAFE_CODE_PATTERN = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const APPLICATION_ID_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const EVIDENCE_ID_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const FINDING_CODE_PATTERN = /^[A-Z][A-Z0-9_]{2,79}$/;
const GITHUB_LOGIN_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
const FORBIDDEN_JSON_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });
const hasUnsafeSerializedText = (value) => hasForbiddenInvisibleOrBidi(
  String(value).replaceAll("\n", "").replaceAll("\t", "")
);
const TRUSTED_GIT_TIMEOUT_MS = 30_000;
const CANDIDATE_PREFLIGHT_API_RESPONSE_BYTES = 4 * 1024 * 1024;
const CANDIDATE_PREFLIGHT_FILES_PER_PAGE = 100;
const HYDRATION_API_RESPONSE_BYTES = 1 * 1024 * 1024;
const HYDRATION_ADDITIONAL_REPOSITORY_BYTES = 24 * 1024 * 1024;
const HYDRATION_FILE_SIZE_BYTES = 16 * 1024 * 1024;
const LEGACY_HYDRATION_ADDITIONAL_REPOSITORY_BYTES = 4 * 1024 * 1024;
const LEGACY_HYDRATION_FILE_SIZE_BYTES = 2 * 1024 * 1024;
const HYDRATION_OUTPUT_BYTES = 64 * 1024;
const HYDRATION_POLL_MS = 25;
const HYDRATION_KILL_GRACE_MS = 250;
const HYDRATION_MAXIMUM_ENTRIES = 65_536;
const CANDIDATE_GIT_ADDRESS_SPACE_BYTES = 512 * 1024 * 1024;
const CANDIDATE_GIT_CPU_SECONDS = 20;
const CANDIDATE_FETCH_FILE_SIZE_BYTES = 32 * 1024 * 1024;
const CANDIDATE_FETCH_REPOSITORY_BYTES = 64 * 1024 * 1024;
const GITHUB_REPOSITORY_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;
const PULL_REQUEST_NUMBER_PATTERN = /^[1-9][0-9]{0,19}$/u;
const LEGACY_V2_TRANSPORT_RULE_ID = "FROZEN_LEGACY_V2.FEE_PROJECTION";
const LEGACY_V2_POLICY_PROFILE = "legacy-v2-transport";
const LEGACY_V2_POLICY_ADAPTER_SCHEMA = "programmable.legacy-v2-policy-adapter.v1";
const TRUSTED_POLICY_SNAPSHOT_BINDING_SCHEMA = "programmable.trusted-policy-snapshot-binding.v1";
// These values are frozen into the historical six-file V2 transport. They are
// compatibility grammar, not current launch-policy requirements or authority.
const LEGACY_V2_TRANSPORT_EVIDENCE_ID = "zz-programmable-fee-submission";
const LEGACY_V2_EVIDENCE_ID = "legacy-v2-fee-projection";
const LEGACY_V2_FEE = Object.freeze({
  owner: "0x4957f49620AFf3Adbbe8195a4f633E49cc93376c",
  platformHundredthsOfBip: 1000,
  policyId: "programmable-volume-fee-v1",
  policyVersion: "1.1.0",
  swapModes: Object.freeze([
    "zeroForOne-exactInput",
    "zeroForOne-exactOutput",
    "oneForZero-exactInput",
    "oneForZero-exactOutput"
  ])
});
const legacyPolicyAdapters = new WeakSet();
const trustedLegacyPolicyAdapters = new WeakSet();

const DEFAULT_LIMITS = Object.freeze({
  maximumChangedFiles: 700,
  maximumGitEntries: 200_000,
  maximumGitTreeBytes: 64 * 1024 * 1024,
  maximumFindings: 128,
  maximumEvidence: 128,
  maximumEvidenceBlobBytes: 8 * 1024 * 1024,
  maximumEvidenceResolutionBytes: 32 * 1024 * 1024,
  maximumEvidenceRequests: GITHUB_PUBLIC_SOURCE_CONTRACT_V1.limits.anonymousRestRequests,
  maximumEvidenceTreeEntries: 200_000,
  maximumJsonDepth: 16,
  maximumJsonNodes: 20_000,
  maximumPackageBytes: 512 * 1024,
  maximumFileBytes: Object.freeze({
    "application.json": 64 * 1024,
    "compatibility-report.json": 160 * 1024,
    "evidence-index.json": 160 * 1024,
    "PROPOSAL.md": 64 * 1024,
    "THREAT_MODEL.md": 64 * 1024,
    "TEST_PLAN.md": 64 * 1024
  }),
});

export class PublicIntakeError extends Error {
  constructor(code, message, { kind = "candidate" } = {}) {
    super(message);
    this.name = "PublicIntakeError";
    this.code = code;
    this.kind = kind;
  }
}

function reject(code, message) {
  throw new PublicIntakeError(code, message, { kind: "candidate" });
}

function systemBlocked(code, message) {
  throw new PublicIntakeError(code, message, { kind: "system" });
}

/**
 * Construct the explicit non-authoritative adapter used by local historical
 * V2 package inspection. Protected pull-request intake never calls this
 * function and never accepts caller-supplied policy bytes.
 */
export function createHistoricalLegacyV2PolicyAdapterForLocalInspection(options) {
  if (
    !isPlainObject(options)
    || !arraysEqual(Object.keys(options).sort(compareUtf8), ["policyBytes"])
    || !(options.policyBytes instanceof Uint8Array)
  ) {
    systemBlocked(
      "LEGACY_V2_POLICY_ADAPTER_INPUT_INVALID",
      "Historical local inspection requires only explicit canonical policy bytes."
    );
  }
  let policyRecord;
  try {
    policyRecord = parseLaunchPolicyBytes(Buffer.from(options.policyBytes));
  } catch {
    systemBlocked(
      "LEGACY_V2_POLICY_ADAPTER_INPUT_INVALID",
      "Historical local inspection received invalid canonical policy bytes."
    );
  }
  return createLegacyV2PolicyAdapter({
    authority: "non-authoritative-local-inspection",
    policyBinding: null,
    policyRecord
  });
}

function readTrustedLegacyV2PolicyAdapter({ baseRoot, expectedBaseCommit }) {
  let policyRecord;
  try {
    policyRecord = readTrustedLaunchPolicyFromGit({
      repositoryRoot: path.resolve(baseRoot ?? ""),
      expectedBaseCommit
    });
  } catch {
    systemBlocked(
      "TRUSTED_LAUNCH_POLICY_INVALID",
      "The exact protected-base launch policy is missing, malformed, or unavailable."
    );
  }
  // Legacy V2 is historical transport, not an enabled review profile. This
  // closed snapshot identity therefore intentionally has no profileId and is
  // distinct from programmable.launch-policy-binding.v1. Callers cannot
  // provide or override any of these fields.
  const policyBinding = Object.freeze({
    schemaVersion: TRUSTED_POLICY_SNAPSHOT_BINDING_SCHEMA,
    repository: policyRecord.repository,
    numericRepositoryId: policyRecord.numericRepositoryId,
    baseCommit: policyRecord.baseCommit,
    baseTree: policyRecord.baseTree,
    path: policyRecord.path,
    gitBlobOid: policyRecord.gitBlobOid,
    policyId: policyRecord.policy.policyId,
    policyVersion: policyRecord.policy.policyVersion,
    sha256: policyRecord.sha256
  });
  const adapter = createLegacyV2PolicyAdapter({
    authority: "trusted-protected-base",
    policyBinding,
    policyRecord
  });
  trustedLegacyPolicyAdapters.add(adapter);
  return adapter;
}

function createLegacyV2PolicyAdapter({ authority, policyBinding, policyRecord }) {
  if (
    !policyRecord?.policy
    || !new Set(["non-authoritative-local-inspection", "trusted-protected-base"]).has(authority)
    || (authority === "trusted-protected-base") !== (policyBinding !== null)
  ) {
    systemBlocked(
      "LEGACY_V2_POLICY_ADAPTER_INVALID",
      "The frozen historical V2 transport adapter cannot be constructed."
    );
  }
  const adapter = Object.freeze({
    schemaVersion: LEGACY_V2_POLICY_ADAPTER_SCHEMA,
    authority,
    ruleId: LEGACY_V2_TRANSPORT_RULE_ID,
    evidenceId: LEGACY_V2_EVIDENCE_ID,
    transportEvidenceId: LEGACY_V2_TRANSPORT_EVIDENCE_ID,
    fee: LEGACY_V2_FEE,
    policyBinding
  });
  legacyPolicyAdapters.add(adapter);
  return adapter;
}

function requireLegacyV2PolicyAdapter(legacyPolicyAdapter, { trusted = false } = {}) {
  if (
    !isPlainObject(legacyPolicyAdapter)
    || !legacyPolicyAdapters.has(legacyPolicyAdapter)
    || (trusted && !trustedLegacyPolicyAdapters.has(legacyPolicyAdapter))
  ) {
    systemBlocked(
      "LEGACY_V2_POLICY_ADAPTER_REQUIRED",
      trusted
        ? "Protected V2 intake requires the adapter derived internally from exact trusted policy bytes."
        : "V2 package validation requires an explicit central-policy legacy adapter."
    );
  }
  return legacyPolicyAdapter;
}

export function canonicalJson(value) {
  return JSON.stringify(sortJson(value));
}

function sortJson(value) {
  if (Array.isArray(value)) return value.map(sortJson);
  if (!isPlainObject(value)) return value;
  return Object.fromEntries(Object.keys(value).sort(compareUtf8).map((key) => [key, sortJson(value[key])]));
}

export function classifyPublicIntakePullRequest({
  baseRoot,
  candidateRoot,
  expectedBaseCommit,
  expectedCandidateCommit,
  expectedMergeCommit,
  limits: limitOverrides = {}
}) {
  const limits = mergeLimits(limitOverrides);
  const comparison = compareGitRevisions({
    baseRoot,
    candidateRoot,
    expectedBaseCommit,
    expectedCandidateCommit,
    expectedMergeCommit,
    limits
  });
  const { changes } = comparison;

  if (changes.length === 0) return { mode: "no-op", ...comparison };

  const submissionChanges = changes.filter((change) => change.path.startsWith("submissions/"));
  const applicationDirectoryChanges = submissionChanges.filter((change) => change.path !== "submissions/README.md");
  const applicationV3Changes = applicationDirectoryChanges.filter((change) => APPLICATION_V3_PATH_PATTERN.test(change.path));
  if (applicationV3Changes.length > 0) {
    rejectUnsafeChangedEntries(changes);
    const classifiedV3 = classifyBoundedApplicationPathChanges(changes.map((change) => ({
      path: change.path,
      previousPath: null,
      status: change.status === "deleted" ? "removed" : change.status
    })));
    if (classifiedV3.contract !== "public-pr-application-v3") {
      reject("APPLICATION_PATH_INVALID", "An Application V3 pull request must add exactly one immutable revision directory.");
    }
    const applicationV3DraftPredecessor = deriveAuthenticatedOpenDraftApplicationV3Predecessor({
      base: comparison.base,
      candidate: comparison.candidate,
      applicationId: classifiedV3.applicationId,
      applicationRevision: classifiedV3.applicationRevision,
      limits
    });
    return {
      mode: "application-v3",
      applicationV3: classifiedV3,
      applicationV3DraftPredecessor,
      ...comparison
    };
  }
  const canaryApplicationChanges = changes.filter((change) => (
    change.path.startsWith(CANARY_APPLICATION_PREFIX)
    && change.path !== "canary-submissions/README.md"
  ));
  if (canaryApplicationChanges.length > 0) {
    rejectUnsafeChangedEntries(changes);
    if (
      changes.length !== 1
      || canaryApplicationChanges.length !== 1
      || canaryApplicationChanges[0].status === "deleted"
      || !CANARY_APPLICATION_PATH_PATTERN.test(canaryApplicationChanges[0].path)
    ) {
      reject(
        "APPLICATION_PATH_INVALID",
        "A workflow-canary pull request must add or modify exactly one canary-submissions/<application-id>/application.json blob and no other path."
      );
    }
    return { mode: "workflow-canary", ...comparison };
  }
  if (applicationDirectoryChanges.length > 0) {
    rejectUnsafeChangedEntries(changes);
    if (changes.every((change) => isAllowlistedApplicationPath(change.path))) {
      return { mode: "application", ...comparison };
    }
    if (changes.some((change) => isPolicyMaintenancePath(change.path))) {
      reject(
        "APPLICATION_PATH_INVALID",
        "Applicant V2 data cannot be mixed with trusted policy or active-contract maintenance."
      );
    }
    reject(
      "CHANGED_PATH_NOT_ALLOWED",
      "A pull request that touches submissions/ must contain only one closed six-file public application package."
    );
  }

  const maintenanceChanges = changes.filter((change) => (
    isRegistryMaintenancePath(change.path)
    && !SHARED_REGISTRY_DOCUMENTATION_FILES.has(change.path)
  ));
  if (maintenanceChanges.length === 0) {
    if (changes.some((change) => RESERVED_MAINTENANCE_PREFIXES.some((prefix) => change.path.startsWith(prefix)))) {
      reject(
        "CHANGED_PATH_NOT_ALLOWED",
        "A pull request cannot add or change an unrecognized first-party maintenance path."
      );
    }
    return { mode: "no-op", ...comparison };
  }

  rejectUnsafeChangedEntries(changes);
  if (changes.every((change) => isRegistryMaintenancePath(change.path))) {
    return { mode: "registry-maintenance", ...comparison };
  }

  reject(
    "CHANGED_PATH_NOT_ALLOWED",
    "A registry-maintenance pull request may change only first-party registry infrastructure and documentation."
  );
}

function isPolicyMaintenancePath(entryPath) {
  return entryPath === ".programmable/active-contract.json" || entryPath.startsWith("policy/");
}

/**
 * Read the intake switch from the trusted base revision before any candidate
 * Git objects are fetched. Closed states inspect only bounded GitHub PR
 * metadata so maintenance and legacy PRs can continue without letting an
 * application consume Git pack/decompression capacity.
 */
export async function preflightPublicApplicationCandidateFetch({
  baseRoot,
  expectedBaseCommit,
  expectedCandidateCommit,
  repository,
  pullRequestNumber,
  readToken,
  limits: limitOverrides = {}
}, dependencies = {}) {
  validateHydrationAuthority({ repository, readToken });
  validateCandidateHeadIdentity({ pullRequestNumber, expectedBaseCommit, expectedCandidateCommit });
  const limits = mergeLimits(limitOverrides);
  const base = inspectGitRevision(baseRoot, expectedBaseCommit, limits);
  const intakeStatus = readTrustedIntakeStatus(base);
  const { changedFiles, pullRequestDraft } = await resolveCentralPullRequestChangedFiles({
    repository,
    pullRequestNumber,
    expectedBaseCommit,
    expectedCandidateCommit,
    readToken,
    maximumChangedFiles: limits.maximumChangedFiles,
    fetchImplementation: dependencies.fetchImplementation ?? globalThis.fetch,
    timeoutMs: dependencies.timeoutMs ?? TRUSTED_GIT_TIMEOUT_MS
  });
  const changedPaths = [];
  for (const file of changedFiles) {
    changedPaths.push(file.path);
    if (file.previousPath !== null) changedPaths.push(file.previousPath);
  }
  const uniquePaths = [...new Set(changedPaths)].sort(compareUtf8);
  const applicationPaths = uniquePaths.filter(
    (entryPath) => entryPath.startsWith("submissions/") && entryPath !== "submissions/README.md"
  );
  if (applicationPaths.length === 0) {
    return {
      schemaVersion: 1,
      result: "candidate-fetch-allowed",
      intakeState: intakeStatus.state,
      modeHint: "non-application"
    };
  }

  if (["prelaunch", "paused-all", "closed"].includes(intakeStatus.state)) {
    enforceTrustedIntakeStatus({ intakeStatus, isUpdate: false, pullRequestNumber, applicationId: null });
  }

  if (applicationPaths.some((entryPath) => APPLICATION_V3_PATH_PATTERN.test(entryPath))) {
    if (pullRequestDraft !== true) {
      reject("APPLICATION_V3_DRAFT_REQUIRED", "Application V3 intake is available only through an exact open Draft pull request.");
    }
    const classifiedV3 = classifyBoundedApplicationPathChanges(changedFiles);
    if (classifiedV3.contract !== "public-pr-application-v3") {
      reject(
        "CHANGED_PATH_NOT_ALLOWED",
        "A paused-new Application V3 pull request must add one exact immutable revision package."
      );
    }
    const isUpdate = inspectTrustedBaseApplicationV3History(base, classifiedV3.applicationId).length > 0
      || hasTrustedLegacyV2Application(base, classifiedV3.applicationId);
    const continuation = enforceTrustedIntakeStatus({
      intakeStatus,
      isUpdate,
      pullRequestNumber,
      applicationId: classifiedV3.applicationId
    });
    return {
      schemaVersion: 1,
      result: "candidate-fetch-allowed",
      intakeState: intakeStatus.state,
      modeHint: isUpdate ? "application-v3-update" : "application-v3-continuation",
      pullRequestNumber,
      continuationAuthorized: continuation !== null
    };
  }

  const applicationIds = new Set();
  for (const entryPath of applicationPaths) {
    const match = APPLICATION_PATH_PATTERN.exec(entryPath);
    if (!match || !APPLICATION_FILES.includes(match[2])) {
      reject(
        "CHANGED_PATH_NOT_ALLOWED",
        "A paused-new pull request may fetch candidate data only for one existing closed application package."
      );
    }
    applicationIds.add(match[1]);
  }
  if (
    applicationIds.size !== 1
    || uniquePaths.some((entryPath) => !isAllowlistedApplicationPath(entryPath))
    || changedFiles.some((file) => file.status === "removed" && applicationPaths.includes(file.path))
  ) {
    reject(
      "CHANGED_PATH_NOT_ALLOWED",
      "A paused-new pull request may fetch candidate data only for one existing closed application package."
    );
  }
  const [applicationId] = applicationIds;
  const isUpdate = classifyTrustedBaseApplication(base, applicationId);
  const continuation = enforceTrustedIntakeStatus({
    intakeStatus,
    isUpdate,
    pullRequestNumber,
    applicationId
  });
  if (!isUpdate) assertNewApplicationChangedFileSet({ changedFiles, applicationId });
  return {
    schemaVersion: 1,
    result: "candidate-fetch-allowed",
    intakeState: intakeStatus.state,
    modeHint: isUpdate ? "application-update" : "application-continuation",
    pullRequestNumber,
    continuationAuthorized: continuation !== null
  };
}

/**
 * Prove from trusted GitHub metadata that a pull request contains only bounded
 * public-application data. This deliberately does not inspect or execute any
 * candidate bytes; the public-intake workflow remains the sole content gate.
 */
export async function verifyBoundedApplicationPullRequestPaths({
  repository,
  pullRequestNumber,
  expectedBaseCommit,
  expectedCandidateCommit,
  readToken
}, dependencies = {}) {
  validateHydrationAuthority({ repository, readToken });
  validateCandidateHeadIdentity({ pullRequestNumber, expectedBaseCommit, expectedCandidateCommit });
  const { changedFiles: changes, pullRequestDraft } = await resolveCentralPullRequestChangedFiles({
    repository,
    pullRequestNumber,
    expectedBaseCommit,
    expectedCandidateCommit,
    readToken,
    maximumChangedFiles: MAXIMUM_APPLICATION_V3_PACKAGE_FILES,
    fetchImplementation: dependencies.fetchImplementation ?? globalThis.fetch,
    timeoutMs: dependencies.timeoutMs ?? TRUSTED_GIT_TIMEOUT_MS
  });
  const classified = classifyBoundedApplicationPathChanges(changes);
  if (classified.contract === "public-pr-application-v3" && pullRequestDraft !== true) {
    reject("APPLICATION_V3_DRAFT_REQUIRED", "Application V3 intake is available only through an exact open Draft pull request.");
  }
  return {
    schemaVersion: 1,
    result: "bounded-public-application-paths",
    pullRequestNumber,
    applicationId: classified.applicationId,
    fileCount: classified.paths.length,
    paths: classified.paths,
    ...(classified.contract === "public-pr-application-v3" ? {
      applicationRevision: classified.applicationRevision,
      contract: classified.contract
    } : {})
  };
}

export function classifyBoundedApplicationPathChanges(changes) {
  if (!Array.isArray(changes) || changes.length < 1 || changes.length > MAXIMUM_APPLICATION_V3_PACKAGE_FILES) {
    reject(
      "CHANGED_PATH_NOT_ALLOWED",
      "A bounded public-application pull request must stay within the trusted file-count limit."
    );
  }
  const v3Matches = changes.map((change) => (
    isPlainObject(change) && typeof change.path === "string"
      ? APPLICATION_V3_PATH_PATTERN.exec(change.path)
      : null
  ));
  if (v3Matches.some(Boolean)) {
    const applicationIds = new Set();
    const revisions = new Set();
    const relativePaths = new Set();
    const paths = new Set();
    for (const [index, change] of changes.entries()) {
      const match = v3Matches[index];
      const relativePath = match?.[3] ?? null;
      if (
        !match
        || change.previousPath !== null
        || change.status !== "added"
        || !isSafeApplicationV3PackagePath(relativePath)
        || paths.has(change.path)
      ) {
        reject(
          "CHANGED_PATH_NOT_ALLOWED",
          "An Application V3 pull request may only add regular files in one immutable revision directory."
        );
      }
      applicationIds.add(match[1]);
      revisions.add(match[2]);
      relativePaths.add(relativePath);
      paths.add(change.path);
    }
    if (
      applicationIds.size !== 1
      || revisions.size !== 1
      || !relativePaths.has(APPLICATION_V3_ROOT_FILE)
    ) {
      reject(
        "CHANGED_PATH_NOT_ALLOWED",
        "An Application V3 pull request must add exactly one revision directory containing application.v3.json."
      );
    }
    return {
      applicationId: [...applicationIds][0],
      applicationRevision: [...revisions][0],
      contract: "public-pr-application-v3",
      paths: [...paths].sort(compareUtf8)
    };
  }
  if (changes.length > APPLICATION_FILES.length) {
    reject(
      "TOO_MANY_CHANGED_FILES",
      "A bounded V2 public-application pull request must change at most six allowlisted files."
    );
  }
  const applicationIds = new Set();
  const paths = new Set();
  for (const change of changes) {
    if (
      !isPlainObject(change)
      || typeof change.path !== "string"
      || change.previousPath !== null
      || (change.status !== "added" && change.status !== "modified")
      || !isAllowlistedApplicationPath(change.path)
      || paths.has(change.path)
    ) {
      reject(
        "CHANGED_PATH_NOT_ALLOWED",
        "A bounded public-application pull request may only add or modify allowlisted files in one application directory."
      );
    }
    const match = APPLICATION_PATH_PATTERN.exec(change.path);
    applicationIds.add(match[1]);
    paths.add(change.path);
  }
  if (applicationIds.size !== 1) {
    reject(
      "CHANGED_PATH_NOT_ALLOWED",
      "A bounded public-application pull request may change only one application directory."
    );
  }
  return {
    applicationId: [...applicationIds][0],
    paths: [...paths].sort(compareUtf8)
  };
}

function isSafeApplicationV3PackagePath(value) {
  return typeof value === "string"
    && value.length > 0
    && value.length <= 1024
    && !value.startsWith("/")
    && !value.includes("\\")
    && !hasUnsafeSerializedText(value)
    && value.split("/").every((segment) => (
      segment.length > 0
      && segment !== "."
      && segment !== ".."
      && segment.toLowerCase() !== ".git"
    ));
}

/**
 * Fetch the base repository's exact PR merge ref into a newly-created bare,
 * blobless object store under hard per-file and aggregate storage bounds.
 */
export async function fetchPublicApplicationCandidate({
  baseRoot,
  candidateRoot,
  repository,
  pullRequestNumber,
  expectedBaseCommit,
  expectedCandidateCommit,
  readToken
}, dependencies = {}) {
  validateHydrationAuthority({ repository, readToken });
  validateCandidateHeadIdentity({ pullRequestNumber, expectedBaseCommit, expectedCandidateCommit });
  await preflightPublicApplicationCandidateFetch({
    baseRoot,
    expectedBaseCommit,
    expectedCandidateCommit,
    repository,
    pullRequestNumber,
    readToken
  }, {
    fetchImplementation: dependencies.fetchImplementation,
    timeoutMs: dependencies.metadataTimeoutMs
  });
  const gitDirectory = validateNewCandidateDirectory(candidateRoot);
  const remoteUrl = dependencies.remoteUrlForTests ?? `https://github.com/${repository}.git`;
  if (typeof remoteUrl !== "string" || remoteUrl.length < 1 || /[\u0000\r\n]/u.test(remoteUrl)) {
    systemBlocked("CANDIDATE_FETCH_REMOTE_INVALID", "The central candidate remote is malformed.");
  }
  const gitExecutable = dependencies.gitExecutable ?? "git";
  let complete = false;
  try {
    const init = childProcess.spawnSync(
      gitExecutable,
      [
        "-c", "init.templateDir=",
        "-c", "core.hooksPath=/dev/null",
        "init", "--quiet", "--bare", "--object-format=sha1", gitDirectory
      ],
      {
        encoding: "utf8",
        shell: false,
        timeout: TRUSTED_GIT_TIMEOUT_MS,
        killSignal: "SIGKILL",
        env: trustedGitEnvironment()
      }
    );
    if (init.status !== 0) {
      systemBlocked("CANDIDATE_FETCH_INIT_FAILED", "The bounded candidate object store could not be initialized.");
    }
    writeCandidateGitConfig(gitDirectory, remoteUrl, readToken);

    const runFetch = dependencies.runFetch ?? runBoundedHydrationGitProcess;
    const result = await runFetch({
      gitExecutable,
      gitDirectory,
      args: [
        "fetch",
        "--force",
        "--no-tags",
        "--no-write-fetch-head",
        "--no-recurse-submodules",
        `--depth=${APPLICATION_V3_OPEN_DRAFT_FETCH_DEPTH}`,
        "--filter=blob:none",
        "origin",
        `+refs/pull/${pullRequestNumber}/merge:refs/heads/candidate-merge`
      ],
      timeoutMs: dependencies.fetchTimeoutMs ?? TRUSTED_GIT_TIMEOUT_MS,
      maximumOutputBytes: HYDRATION_OUTPUT_BYTES,
      maximumFileSizeBytes: dependencies.maximumFileSizeBytes ?? CANDIDATE_FETCH_FILE_SIZE_BYTES,
      maximumRepositoryBytes: dependencies.maximumRepositoryBytes ?? CANDIDATE_FETCH_REPOSITORY_BYTES,
      maximumAddressSpaceBytes: dependencies.maximumAddressSpaceBytes ?? CANDIDATE_GIT_ADDRESS_SPACE_BYTES,
      maximumCpuSeconds: dependencies.maximumCpuSeconds ?? CANDIDATE_GIT_CPU_SECONDS,
      allowFileProtocol: dependencies.allowFileProtocolForTests === true
    });
    if (
      !isBoundedGitProcessResult(result)
      || result.timedOut
      || result.outputExceeded
      || result.repositoryBytesExceeded
      || result.fileSizeExceeded
      || result.addressSpaceExceeded
      || result.cpuExceeded
      || result.status !== 0
    ) {
      systemBlocked("CANDIDATE_FETCH_BOUNDED_FAILURE", "The exact blobless PR merge exceeded trusted fetch bounds or was unavailable.");
    }
    runGit(gitDirectory, ["symbolic-ref", "HEAD", "refs/heads/candidate-merge"], 1024);
    const { mergeCommit: observedMergeCommit } = inspectExactPullRequestMergeIdentity(gitDirectory, {
      expectedBaseCommit,
      expectedCandidateCommit
    });
    complete = true;
    return {
      schemaVersion: 1,
      result: "exact-blobless-candidate-fetched",
      mergeCommit: observedMergeCommit
    };
  } finally {
    if (!complete && fs.lstatSync(gitDirectory, { throwIfNoEntry: false }) !== undefined) {
      removeCandidateDirectory(gitDirectory);
    }
  }
}

/**
 * Hydrate only the already-classified V2 package, immutable Application V3
 * revision, or one-file workflow canary.
 * GitHub's exact tree metadata is checked before any candidate blob is
 * requested, and the bounded Git process cannot lazily fetch anything else.
 */
export async function hydratePublicApplicationCandidate({
  baseRoot,
  candidateRoot,
  expectedBaseCommit,
  expectedCandidateCommit,
  expectedMergeCommit,
  pullRequestNumber,
  repository,
  readToken,
  limits: limitOverrides = {}
}, dependencies = {}) {
  const limits = mergeLimits(limitOverrides);
  validateHydrationAuthority({ repository, readToken });
  validateCandidateFetchIdentity({
    pullRequestNumber,
    expectedBaseCommit,
    expectedCandidateCommit,
    expectedMergeCommit
  });
  const classified = classifyPublicIntakePullRequest({
    baseRoot,
    candidateRoot,
    expectedBaseCommit,
    expectedCandidateCommit,
    expectedMergeCommit,
    limits
  });
  const isLegacyV2 = classified.mode === "application";
  const isApplicationV3 = classified.mode === "application-v3";
  const legacyPolicyAdapter = isLegacyV2
    ? readTrustedLegacyV2PolicyAdapter({ baseRoot, expectedBaseCommit })
    : null;
  if (isLegacyV2) requireLegacyV2PolicyAdapter(legacyPolicyAdapter, { trusted: true });
  const workflowCanaryPolicy = !isLegacyV2 && !isApplicationV3
    ? readTrustedWorkflowCanaryPolicy({ baseRoot, expectedBaseCommit })
    : null;
  const plan = isLegacyV2
    ? planApplicationHydration(classified, limits)
    : isApplicationV3
      ? planApplicationV3Hydration(classified)
      : planWorkflowCanaryHydration(classified, limits);
  const draftPredecessorPlan = isApplicationV3 && classified.applicationV3DraftPredecessor !== null
    ? planApplicationV3DraftPredecessorHydration(classified, plan)
    : null;
  const hydrationPlans = draftPredecessorPlan === null ? [plan] : [plan, draftPredecessorPlan];
  const intakeStatus = isLegacyV2 || isApplicationV3 ? readTrustedIntakeStatus(classified.base) : null;
  const isUpdate = isLegacyV2
    ? classifyTrustedBaseApplication(classified.base, plan.applicationId)
    : isApplicationV3
      ? inspectTrustedBaseApplicationV3History(classified.base, plan.applicationId).length > 0
        || hasTrustedLegacyV2Application(classified.base, plan.applicationId)
        || draftPredecessorPlan !== null
      : false;
  const continuation = isLegacyV2 || isApplicationV3
    ? enforceTrustedIntakeStatus({
      intakeStatus,
      isUpdate,
      pullRequestNumber,
      applicationId: plan.applicationId
    })
    : null;
  const gitDirectory = path.resolve(candidateRoot ?? "");
  requireHydrationRemote(
    gitDirectory,
    dependencies.remoteUrlForTests ?? `https://github.com/${repository}.git`
  );
  const boundedMetadataRecords = [];
  for (const hydrationPlan of hydrationPlans) {
    const packageTreeObjectId = readPackageTreeObjectId(
      gitDirectory,
      hydrationPlan.packageDirectory,
      hydrationPlan.commit ?? "HEAD"
    );
    const metadata = await resolveCandidateTreeMetadata({
      repository,
      readToken,
      packageTreeObjectId,
      fetchImplementation: dependencies.fetchImplementation ?? globalThis.fetch,
      timeoutMs: dependencies.metadataTimeoutMs ?? TRUSTED_GIT_TIMEOUT_MS,
      recursive: hydrationPlan.recursive === true
    });
    boundedMetadataRecords.push(enforceHydrationMetadata(hydrationPlan, metadata, limits));
  }
  const aggregateHydrationBytes = boundedMetadataRecords.reduce((total, metadata) => total + metadata.totalBytes, 0);
  if (isApplicationV3 && aggregateHydrationBytes > MAXIMUM_APPLICATION_V3_PACKAGE_BYTES * 2) {
    reject("APPLICATION_PACKAGE_TOO_LARGE", "Current and predecessor Draft packages exceed the trusted aggregate byte limit.");
  }

  const baselineBytes = measureHydrationDirectory(gitDirectory);
  const maximumAdditionalRepositoryBytes = dependencies.maximumAdditionalRepositoryBytes
    ?? (isApplicationV3
      ? HYDRATION_ADDITIONAL_REPOSITORY_BYTES
      : LEGACY_HYDRATION_ADDITIONAL_REPOSITORY_BYTES);
  const maximumFileSizeBytes = dependencies.maximumFileSizeBytes
    ?? (isApplicationV3 ? HYDRATION_FILE_SIZE_BYTES : LEGACY_HYDRATION_FILE_SIZE_BYTES);
  validateHydrationProcessLimits(maximumAdditionalRepositoryBytes, maximumFileSizeBytes);
  if (baselineBytes > Number.MAX_SAFE_INTEGER - maximumAdditionalRepositoryBytes) {
    systemBlocked("HYDRATION_STORAGE_INVALID", "Candidate object-store size could not be bounded safely.");
  }

  const sparsePath = path.join(gitDirectory, "info", "sparse-checkout");
  const sparsePaths = [...new Set(hydrationPlans.flatMap((hydrationPlan) => hydrationPlan.entries.map((entry) => entry.path)))];
  const sparseBytes = Buffer.from(`${sparsePaths.map((entryPath) => `/${entryPath}`).join("\n")}\n`, "utf8");
  let operationFailed = false;
  try {
    fs.mkdirSync(path.dirname(sparsePath), { recursive: true, mode: 0o700 });
    fs.writeFileSync(sparsePath, sparseBytes, { mode: 0o600, flag: "w" });
    runHydrationConfig(gitDirectory, ["core.sparseCheckout", "true"]);
    runHydrationConfig(gitDirectory, ["core.sparseCheckoutCone", "false"]);
    const result = await runBoundedHydrationGitProcess({
      gitExecutable: dependencies.gitExecutable ?? "git",
      gitDirectory,
      args: ["backfill", "--sparse"],
      timeoutMs: dependencies.backfillTimeoutMs ?? TRUSTED_GIT_TIMEOUT_MS,
      maximumOutputBytes: HYDRATION_OUTPUT_BYTES,
      maximumFileSizeBytes,
      maximumRepositoryBytes: baselineBytes + maximumAdditionalRepositoryBytes,
      maximumAddressSpaceBytes: CANDIDATE_GIT_ADDRESS_SPACE_BYTES,
      maximumCpuSeconds: CANDIDATE_GIT_CPU_SECONDS,
      allowFileProtocol: dependencies.allowFileProtocolForTests === true
    });
    if (result.timedOut) {
      systemBlocked("HYDRATION_TIMEOUT", "Bounded candidate blob hydration exceeded its trusted timeout.");
    }
    if (
      result.outputExceeded
      || result.repositoryBytesExceeded
      || result.fileSizeExceeded
      || result.addressSpaceExceeded
      || result.cpuExceeded
      || result.status !== 0
    ) {
      systemBlocked("HYDRATION_BOUNDED_FETCH_FAILED", "Git could not hydrate the bounded application blobs within trusted resource limits.");
    }
    const exactObjectIds = [...new Set(hydrationPlans.flatMap((hydrationPlan) => (
      hydrationPlan.entries.map((entry) => entry.oid)
    )))].sort(compareUtf8);
    const materialization = await runBoundedHydrationGitProcess({
      gitExecutable: dependencies.gitExecutable ?? "git",
      gitDirectory,
      args: ["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
      input: Buffer.from(`${exactObjectIds.join("\n")}\n`, "utf8"),
      timeoutMs: dependencies.backfillTimeoutMs ?? TRUSTED_GIT_TIMEOUT_MS,
      maximumOutputBytes: HYDRATION_OUTPUT_BYTES,
      maximumFileSizeBytes,
      maximumRepositoryBytes: baselineBytes + maximumAdditionalRepositoryBytes,
      maximumAddressSpaceBytes: CANDIDATE_GIT_ADDRESS_SPACE_BYTES,
      maximumCpuSeconds: CANDIDATE_GIT_CPU_SECONDS,
      allowFileProtocol: dependencies.allowFileProtocolForTests === true
    });
    if (materialization.timedOut) {
      systemBlocked("HYDRATION_TIMEOUT", "Exact candidate blob materialization exceeded its trusted timeout.");
    }
    if (
      materialization.outputExceeded
      || materialization.repositoryBytesExceeded
      || materialization.fileSizeExceeded
      || materialization.addressSpaceExceeded
      || materialization.cpuExceeded
      || materialization.status !== 0
    ) {
      systemBlocked("HYDRATION_BOUNDED_FETCH_FAILED", "Git could not materialize the exact bounded candidate blob identities.");
    }
    const materializedRecords = materialization.stdout.toString("utf8").trim().split("\n");
    if (
      materializedRecords.length !== exactObjectIds.length
      || materializedRecords.some((record, index) => {
        const match = /^([0-9a-f]{40}) blob (0|[1-9][0-9]*)$/u.exec(record);
        return match === null || match[1] !== exactObjectIds[index];
      })
    ) {
      systemBlocked("HYDRATION_OBJECT_INVALID", "Exact candidate blob materialization returned an unexpected object identity, type, or size.");
    }
    hydrationPlans.forEach((hydrationPlan, index) => {
      verifyHydratedObjects(gitDirectory, hydrationPlan, boundedMetadataRecords[index], limits);
    });
  } catch (error) {
    operationFailed = true;
    throw error;
  } finally {
    try {
      fs.rmSync(sparsePath, { force: true });
      runHydrationConfig(gitDirectory, ["--unset", "core.sparseCheckout"], { allowMissing: true });
      runHydrationConfig(gitDirectory, ["--unset", "core.sparseCheckoutCone"], { allowMissing: true });
    } catch (cleanupError) {
      if (!operationFailed) {
        systemBlocked("HYDRATION_CLEANUP_FAILED", "Trusted sparse hydration state could not be removed.");
      }
    }
  }

  const rootFileName = isApplicationV3 ? APPLICATION_V3_ROOT_FILE : APPLICATION_FILE;
  const applicationEntry = plan.entries.find((entry) => path.posix.basename(entry.path) === rootFileName);
  if (!applicationEntry) {
    systemBlocked("APPLICATION_ROOT_MISSING", "The bounded application root blob was unavailable after hydration.");
  }
  const applicationBytes = readGitBlob(
    path.resolve(candidateRoot ?? ""),
    applicationEntry,
    maximumHydrationEntryBytes(plan, applicationEntry, limits)
  );
  if (isLegacyV2) {
    const application = parseCanonicalJson(applicationBytes, APPLICATION_FILE, limits);
    validateApplicationManifest(application, plan.applicationId, limits, legacyPolicyAdapter);
    enforceTrustedContinuationIdentity({ continuation, application });
  } else if (!isApplicationV3) {
    let application;
    try {
      application = parseWorkflowCanaryApplicationBytes(applicationBytes, {
        expectedApplicationId: plan.applicationId
      });
    } catch (error) {
      if (error?.kind === "candidate") reject(error.code, error.message);
      systemBlocked(error?.code ?? "CANARY_APPLICATION_INVALID", "The bounded canary application could not be validated.");
    }
    if (!compareLaunchPolicyBindings(application.expectedPolicyBinding, workflowCanaryPolicy.binding)) {
      reject("POLICY_DRIFT", "The canary application expected a different protected-base launch policy.");
    }
  }

  return isLegacyV2
    ? {
      schemaVersion: 1,
      result: "bounded-application-blobs-hydrated",
      intakeState: intakeStatus.state,
      applicationId: plan.applicationId,
      pullRequestNumber,
      continuationAuthorized: continuation !== null,
      fileCount: plan.entries.length,
      totalBytes: aggregateHydrationBytes
    }
    : isApplicationV3
      ? {
        schemaVersion: 1,
        result: "bounded-application-v3-blobs-hydrated",
        intakeState: intakeStatus.state,
        applicationId: plan.applicationId,
        applicationRevision: plan.applicationRevision,
        pullRequestNumber,
        continuationAuthorized: continuation !== null,
        fileCount: plan.entries.length,
        totalBytes: aggregateHydrationBytes
      }
      : {
      schemaVersion: 1,
      result: "bounded-workflow-canary-blob-hydrated",
      applicationId: plan.applicationId,
      pullRequestNumber,
      policyBinding: workflowCanaryPolicy.binding,
      fileCount: 1,
      totalBytes: aggregateHydrationBytes
      };
}

function readTrustedWorkflowCanaryPolicy({ baseRoot, expectedBaseCommit }) {
  try {
    const record = readTrustedLaunchPolicyFromGit({
      repositoryRoot: path.resolve(baseRoot ?? ""),
      expectedBaseCommit
    });
    return Object.freeze({
      binding: buildLaunchPolicyBinding(record, "workflow-canary"),
      record
    });
  } catch {
    systemBlocked(
      "TRUSTED_LAUNCH_POLICY_INVALID",
      "The exact protected-base workflow-canary launch policy is missing, malformed, disabled, or unavailable."
    );
  }
}

function validateHydrationAuthority({ repository, readToken }) {
  if (typeof repository !== "string" || !GITHUB_REPOSITORY_PATTERN.test(repository) || repository.length > 202) {
    systemBlocked("HYDRATION_REPOSITORY_INVALID", "The central GitHub repository identity is malformed.");
  }
  if (
    typeof readToken !== "string"
    || readToken.length < 1
    || readToken.length > 4096
    || /[\u0000-\u001f\u007f-\u009f]/u.test(readToken)
  ) {
    systemBlocked("HYDRATION_CREDENTIAL_INVALID", "The central read credential is missing or malformed.");
  }
}

function validateCandidateFetchIdentity({
  pullRequestNumber,
  expectedBaseCommit,
  expectedCandidateCommit,
  expectedMergeCommit
}) {
  validateCandidateHeadIdentity({ pullRequestNumber, expectedBaseCommit, expectedCandidateCommit });
  if (!SHA1_PATTERN.test(expectedMergeCommit ?? "")) {
    systemBlocked("CANDIDATE_FETCH_ID_INVALID", "The expected pull-request merge commit is missing or malformed.");
  }
}

function validateCandidateHeadIdentity({ pullRequestNumber, expectedBaseCommit, expectedCandidateCommit }) {
  if (typeof pullRequestNumber !== "string" || !PULL_REQUEST_NUMBER_PATTERN.test(pullRequestNumber)) {
    systemBlocked("CANDIDATE_FETCH_ID_INVALID", "The pull-request number is missing or malformed.");
  }
  for (const [label, objectId] of [
    ["base", expectedBaseCommit],
    ["head", expectedCandidateCommit]
  ]) {
    if (!SHA1_PATTERN.test(objectId ?? "")) {
      systemBlocked("CANDIDATE_FETCH_ID_INVALID", `The expected pull-request ${label} commit is missing or malformed.`);
    }
  }
}

async function resolveCentralPullRequestChangedFiles({
  repository,
  pullRequestNumber,
  expectedBaseCommit,
  expectedCandidateCommit,
  readToken,
  maximumChangedFiles,
  fetchImplementation,
  timeoutMs
}) {
  if (typeof fetchImplementation !== "function") {
    systemBlocked("CANDIDATE_PREFLIGHT_UNAVAILABLE", "The trusted GitHub pull-request metadata transport is unavailable.");
  }
  if (
    !Number.isInteger(timeoutMs)
    || timeoutMs < 1
    || timeoutMs > TRUSTED_GIT_TIMEOUT_MS
    || !Number.isInteger(maximumChangedFiles)
    || maximumChangedFiles < 1
    || maximumChangedFiles > 1_000
  ) {
    systemBlocked("CANDIDATE_PREFLIGHT_INVALID", "The trusted pull-request metadata limits are invalid.");
  }
  const apiOrigin = GITHUB_PUBLIC_SOURCE_CONTRACT_V1.apiOrigin;
  const deadline = performance.now() + timeoutMs;
  const pullRequestUrl = `${apiOrigin}/repos/${repository}/pulls/${pullRequestNumber}`;
  const pullRequest = await requestCentralCandidateJson({
    url: pullRequestUrl,
    readToken,
    fetchImplementation,
    deadline
  });
  if (
    !isPlainObject(pullRequest)
    || String(pullRequest.number) !== pullRequestNumber
    || pullRequest.state !== "open"
    || pullRequest.base?.sha !== expectedBaseCommit
    || pullRequest.head?.sha !== expectedCandidateCommit
    || typeof pullRequest.base?.repo?.full_name !== "string"
    || pullRequest.base.repo.full_name.toLowerCase() !== repository.toLowerCase()
    || !Number.isInteger(pullRequest.changed_files)
    || pullRequest.changed_files < 0
  ) {
    systemBlocked("CANDIDATE_PREFLIGHT_ID_MISMATCH", "GitHub pull-request metadata did not match the immutable workflow event.");
  }
  if (pullRequest.changed_files > maximumChangedFiles) {
    reject("TOO_MANY_CHANGED_FILES", "The pull request exceeds the trusted changed-file limit before candidate fetch.");
  }

  const records = [];
  const pages = Math.ceil(pullRequest.changed_files / CANDIDATE_PREFLIGHT_FILES_PER_PAGE);
  for (let page = 1; page <= pages; page += 1) {
    const url = `${pullRequestUrl}/files?per_page=${CANDIDATE_PREFLIGHT_FILES_PER_PAGE}&page=${page}`;
    const document = await requestCentralCandidateJson({
      url,
      readToken,
      fetchImplementation,
      deadline
    });
    const expectedRecords = Math.min(
      CANDIDATE_PREFLIGHT_FILES_PER_PAGE,
      pullRequest.changed_files - records.length
    );
    if (!Array.isArray(document) || document.length !== expectedRecords) {
      systemBlocked("CANDIDATE_PREFLIGHT_INVALID", "GitHub returned an incomplete bounded pull-request file list.");
    }
    records.push(...document);
  }
  if (records.length !== pullRequest.changed_files) {
    systemBlocked("CANDIDATE_PREFLIGHT_INVALID", "GitHub pull-request file metadata did not match its declared count.");
  }

  const supportedStatuses = new Set(["added", "removed", "modified", "renamed", "copied", "changed", "unchanged"]);
  const observedPaths = new Set();
  const changedFiles = records.map((record) => {
    if (
      !isPlainObject(record)
      || typeof record.filename !== "string"
      || !supportedStatuses.has(record.status)
      || (record.status === "renamed") !== (typeof record.previous_filename === "string")
    ) {
      systemBlocked("CANDIDATE_PREFLIGHT_INVALID", "GitHub returned malformed pull-request file metadata.");
    }
    validateGitPath(record.filename);
    if (observedPaths.has(record.filename)) {
      systemBlocked("CANDIDATE_PREFLIGHT_INVALID", "GitHub returned a duplicate pull-request path.");
    }
    observedPaths.add(record.filename);
    let previousPath = null;
    if (record.status === "renamed") {
      validateGitPath(record.previous_filename);
      previousPath = record.previous_filename;
    }
    return { path: record.filename, previousPath, status: record.status };
  });
  return { changedFiles, pullRequestDraft: pullRequest.draft };
}

async function requestCentralCandidateJson({ url, readToken, fetchImplementation, deadline }) {
  const remaining = Math.floor(deadline - performance.now());
  if (remaining < 1) {
    systemBlocked("CANDIDATE_PREFLIGHT_TIMEOUT", "Trusted pull-request metadata resolution exceeded its total deadline.");
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), remaining);
  timeout.unref?.();
  let response;
  try {
    response = await fetchImplementation(url, {
      method: "GET",
      redirect: "error",
      signal: controller.signal,
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${readToken}`,
        "User-Agent": "programmable-public-intake-prefetch-v1",
        "X-GitHub-Api-Version": GITHUB_PUBLIC_SOURCE_CONTRACT_V1.githubApiVersion
      }
    });
  } catch {
    systemBlocked("CANDIDATE_PREFLIGHT_UNAVAILABLE", "GitHub pull-request metadata was unavailable before candidate fetch.");
  } finally {
    clearTimeout(timeout);
  }
  if (
    !response
    || response.status !== 200
    || response.redirected === true
    || (typeof response.url === "string" && response.url !== "" && response.url !== url)
  ) {
    systemBlocked("CANDIDATE_PREFLIGHT_UNAVAILABLE", "GitHub did not return exact same-origin pull-request metadata.");
  }
  const declaredLength = response.headers?.get?.("content-length");
  if (declaredLength !== null && declaredLength !== undefined) {
    if (
      !/^(?:0|[1-9][0-9]*)$/u.test(declaredLength)
      || Number(declaredLength) > CANDIDATE_PREFLIGHT_API_RESPONSE_BYTES
    ) {
      systemBlocked("CANDIDATE_PREFLIGHT_TOO_LARGE", "GitHub pull-request metadata exceeded its trusted response bound.");
    }
  }
  const bytes = await readBoundedHydrationResponse(response, CANDIDATE_PREFLIGHT_API_RESPONSE_BYTES);
  try {
    return JSON.parse(UTF8_DECODER.decode(bytes));
  } catch {
    systemBlocked("CANDIDATE_PREFLIGHT_INVALID", "GitHub pull-request metadata was not valid bounded UTF-8 JSON.");
  }
}

function validateNewCandidateDirectory(candidateRoot) {
  if (typeof candidateRoot !== "string" || candidateRoot.length < 1 || /[\u0000\r\n]/u.test(candidateRoot)) {
    systemBlocked("CANDIDATE_FETCH_PATH_INVALID", "The candidate object-store path is malformed.");
  }
  const resolved = path.resolve(candidateRoot);
  const parent = path.dirname(resolved);
  if (
    path.basename(resolved) !== "candidate.git"
    || !fs.statSync(parent, { throwIfNoEntry: false })?.isDirectory()
    || fs.lstatSync(resolved, { throwIfNoEntry: false }) !== undefined
  ) {
    systemBlocked("CANDIDATE_FETCH_PATH_INVALID", "The candidate object store must be a new candidate.git directory.");
  }
  return resolved;
}

function writeCandidateGitConfig(gitDirectory, remoteUrl, readToken) {
  const basicAuth = Buffer.from(`x-access-token:${readToken}`, "utf8").toString("base64");
  const config = [
    "[core]",
    "\trepositoryformatversion = 0",
    "\tfilemode = true",
    "\tbare = true",
    "\thooksPath = /dev/null",
    "\tattributesFile = /dev/null",
    "[protocol]",
    "\tallow = never",
    "\tversion = 2",
    "[protocol \"https\"]",
    "\tallow = always",
    "[http]",
    "\tfollowRedirects = false",
    "[http \"https://github.com/\"]",
    `\textraheader = AUTHORIZATION: basic ${basicAuth}`,
    "[fetch]",
    "\trecurseSubmodules = false",
    "\tfsckObjects = true",
    "[transfer]",
    "\tfsckObjects = true",
    "[maintenance]",
    "\tauto = false",
    "[gc]",
    "\tauto = 0",
    "[remote \"origin\"]",
    `\turl = ${remoteUrl}`,
    "\tpromisor = true",
    "\tpartialclonefilter = blob:none",
    ""
  ].join("\n");
  fs.writeFileSync(path.join(gitDirectory, "config"), config, { encoding: "utf8", mode: 0o600, flag: "w" });
}

function isBoundedGitProcessResult(value) {
  return isPlainObject(value)
    && Number.isInteger(value.status)
    && typeof value.timedOut === "boolean"
    && typeof value.outputExceeded === "boolean"
    && typeof value.repositoryBytesExceeded === "boolean"
    && typeof value.fileSizeExceeded === "boolean"
    && typeof value.addressSpaceExceeded === "boolean"
    && typeof value.cpuExceeded === "boolean";
}

function removeCandidateDirectory(gitDirectory) {
  const resolved = path.resolve(gitDirectory);
  if (path.basename(resolved) !== "candidate.git" || path.dirname(resolved) === resolved) {
    systemBlocked("CANDIDATE_FETCH_CLEANUP_FAILED", "The failed candidate object-store cleanup target changed identity.");
  }
  try {
    fs.rmSync(resolved, { recursive: true, force: true, maxRetries: 3, retryDelay: 20 });
  } catch {
    systemBlocked("CANDIDATE_FETCH_CLEANUP_FAILED", "The failed candidate object store and its credential could not be removed.");
  }
}

function planApplicationHydration(classified, limits) {
  if (classified.mode !== "application") {
    reject("APPLICATION_CHANGE_REQUIRED", "Only a closed public application package may hydrate candidate blobs.");
  }
  const applicationIds = new Set();
  for (const change of classified.changes) {
    if (change.status === "deleted") {
      reject("APPLICATION_FILE_DELETED", "Public application files cannot be deleted through the intake workflow.");
    }
    const match = APPLICATION_PATH_PATTERN.exec(change.path);
    if (!match) reject("APPLICATION_PATH_INVALID", "An application path is outside the closed package layout.");
    applicationIds.add(match[1]);
  }
  if (applicationIds.size !== 1) {
    reject("APPLICATION_COUNT_INVALID", "A public application pull request must add or update exactly one application id.");
  }
  const [applicationId] = applicationIds;
  const packageDirectory = `submissions/${applicationId}`;
  const packagePrefix = `${packageDirectory}/`;
  const entries = [...classified.candidate.entries.values()]
    .filter((entry) => entry.path.startsWith(packagePrefix))
    .sort((left, right) => compareUtf8(left.path, right.path));
  const expectedPaths = APPLICATION_FILES.map((fileName) => `${packagePrefix}${fileName}`).sort(compareUtf8);
  if (!arraysEqual(entries.map((entry) => entry.path), expectedPaths)) {
    reject(
      "APPLICATION_PACKAGE_NOT_CLOSED",
      "The application directory must contain exactly the six allowlisted manifest and review-package files."
    );
  }
  for (const entry of entries) {
    assertRegularBlob(entry);
    const maximumBytes = limits.maximumFileBytes[path.posix.basename(entry.path)];
    if (!Number.isInteger(maximumBytes)) {
      systemBlocked("FILE_LIMIT_MISSING", "The trusted validator has no size policy for an allowlisted package file.");
    }
  }
  return { applicationId, packageDirectory, entries, recursive: false };
}

function planApplicationV3Hydration(classified) {
  if (classified.mode !== "application-v3" || !isPlainObject(classified.applicationV3)) {
    reject("APPLICATION_CHANGE_REQUIRED", "Only one immutable Application V3 revision may hydrate candidate blobs.");
  }
  const { applicationId, applicationRevision, paths } = classified.applicationV3;
  if (
    !APPLICATION_ID_PATTERN.test(applicationId)
    || !/^[1-9][0-9]*$/u.test(applicationRevision)
    || !Array.isArray(paths)
    || paths.length < 1
    || paths.length > MAXIMUM_APPLICATION_V3_PACKAGE_FILES
  ) {
    systemBlocked("APPLICATION_V3_CLASSIFICATION_INVALID", "The trusted Application V3 classification was malformed.");
  }
  const packageDirectory = `submissions/${applicationId}/v3/revisions/${applicationRevision}`;
  const packagePrefix = `${packageDirectory}/`;
  const entries = [...classified.candidate.entries.values()]
    .filter((entry) => entry.path.startsWith(packagePrefix))
    .sort((left, right) => compareUtf8(left.path, right.path));
  if (!arraysEqual(entries.map((entry) => entry.path), paths)) {
    reject(
      "APPLICATION_PACKAGE_NOT_CLOSED",
      "The immutable Application V3 revision directory must contain exactly the changed bounded package files."
    );
  }
  if (classified.changes.length !== entries.length || classified.changes.some((change) => change.status !== "added")) {
    reject("APPLICATION_REVISION_NOT_IMMUTABLE", "An Application V3 revision must be new and add-only against the protected base.");
  }
  const rootPath = `${packagePrefix}${APPLICATION_V3_ROOT_FILE}`;
  if (!entries.some((entry) => entry.path === rootPath)) {
    reject("APPLICATION_ROOT_MISSING", "An Application V3 revision must contain application.v3.json at its root.");
  }
  for (const entry of entries) assertRegularBlob(entry);
  return {
    applicationId,
    applicationRevision,
    packageDirectory,
    entries,
    recursive: true,
    maximumPackageBytes: MAXIMUM_APPLICATION_V3_PACKAGE_BYTES
  };
}

function planApplicationV3DraftPredecessorHydration(classified, currentPlan) {
  const predecessor = classified.applicationV3DraftPredecessor;
  if (
    !isPlainObject(predecessor)
    || !SHA1_PATTERN.test(predecessor.commit)
    || incrementCanonicalDecimal(predecessor.revision) !== currentPlan.applicationRevision
    || !Array.isArray(predecessor.entries)
    || predecessor.entries.length < 1
    || predecessor.entries.length > MAXIMUM_APPLICATION_V3_PACKAGE_FILES
  ) {
    systemBlocked("APPLICATION_V3_DRAFT_HISTORY_INVALID", "The internally derived Draft predecessor plan was malformed.");
  }
  const packageDirectory = `submissions/${currentPlan.applicationId}/v3/revisions/${predecessor.revision}`;
  const packagePrefix = `${packageDirectory}/`;
  const entries = [...predecessor.entries].sort((left, right) => compareUtf8(left.path, right.path));
  if (
    entries.some((entry) => !entry.path.startsWith(packagePrefix))
    || !entries.some((entry) => entry.path === `${packagePrefix}${APPLICATION_V3_ROOT_FILE}`)
  ) {
    systemBlocked("APPLICATION_V3_DRAFT_HISTORY_INVALID", "The internally derived Draft predecessor entries escaped their exact revision directory.");
  }
  entries.forEach(assertRegularBlob);
  return {
    applicationId: currentPlan.applicationId,
    applicationRevision: predecessor.revision,
    packageDirectory,
    entries,
    recursive: true,
    maximumPackageBytes: MAXIMUM_APPLICATION_V3_PACKAGE_BYTES,
    commit: predecessor.commit
  };
}

function planWorkflowCanaryHydration(classified, limits) {
  if (classified.mode !== "workflow-canary" || classified.changes.length !== 1) {
    reject("APPLICATION_CHANGE_REQUIRED", "Only one closed workflow-canary application may hydrate candidate bytes.");
  }
  const [change] = classified.changes;
  if (change.status === "deleted") {
    reject("APPLICATION_FILE_DELETED", "Workflow-canary application data cannot be deleted through protected intake.");
  }
  const match = CANARY_APPLICATION_PATH_PATTERN.exec(change.path);
  if (!match) reject("APPLICATION_PATH_INVALID", "The workflow-canary path is outside its closed one-file layout.");
  const applicationId = match[1];
  const packageDirectory = `canary-submissions/${applicationId}`;
  const entries = [...classified.candidate.entries.values()]
    .filter((entry) => entry.path.startsWith(`${packageDirectory}/`))
    .sort((left, right) => compareUtf8(left.path, right.path));
  if (entries.length !== 1 || entries[0].path !== `${packageDirectory}/${APPLICATION_FILE}`) {
    reject("APPLICATION_PACKAGE_NOT_CLOSED", "The workflow-canary directory must contain exactly one application.json blob.");
  }
  assertRegularBlob(entries[0]);
  if (!Number.isInteger(limits.maximumFileBytes[APPLICATION_FILE])) {
    systemBlocked("FILE_LIMIT_MISSING", "The trusted validator has no size policy for workflow-canary application.json.");
  }
  return { applicationId, packageDirectory, entries, recursive: false };
}

function readPackageTreeObjectId(gitDirectory, packageDirectory, commit = "HEAD") {
  if (commit !== "HEAD" && !SHA1_PATTERN.test(commit)) {
    systemBlocked("HYDRATION_TREE_INVALID", "The historical application tree commit was malformed.");
  }
  const objectId = runGitText(
    gitDirectory,
    ["rev-parse", "--verify", `${commit}:${packageDirectory}`],
    128
  ).trim();
  if (!SHA1_PATTERN.test(objectId)) {
    systemBlocked("HYDRATION_TREE_INVALID", "The closed application directory did not resolve to an exact Git tree.");
  }
  const objectType = runGitText(gitDirectory, ["cat-file", "-t", objectId], 32).trim();
  if (objectType !== "tree") {
    systemBlocked("HYDRATION_TREE_INVALID", "The closed application directory was not a Git tree.");
  }
  return objectId;
}

function requireHydrationRemote(gitDirectory, expectedRemoteUrl) {
  if (typeof expectedRemoteUrl !== "string" || expectedRemoteUrl.length < 1 || /[\u0000\r\n]/u.test(expectedRemoteUrl)) {
    systemBlocked("HYDRATION_REMOTE_INVALID", "The trusted candidate remote identity is malformed.");
  }
  const remoteNames = runGitText(gitDirectory, ["remote"], 1024).trim().split("\n").filter(Boolean);
  const observedRemoteUrl = runGitText(
    gitDirectory,
    ["config", "--local", "--get", "remote.origin.url"],
    4096
  ).trim();
  if (remoteNames.length !== 1 || remoteNames[0] !== "origin" || observedRemoteUrl !== expectedRemoteUrl) {
    systemBlocked("HYDRATION_REMOTE_INVALID", "The candidate object store is not bound to the central GitHub repository.");
  }
}

async function resolveCandidateTreeMetadata({
  repository,
  readToken,
  packageTreeObjectId,
  fetchImplementation,
  timeoutMs,
  recursive = false
}) {
  if (typeof fetchImplementation !== "function") {
    systemBlocked("HYDRATION_METADATA_UNAVAILABLE", "The trusted GitHub metadata transport is unavailable.");
  }
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > TRUSTED_GIT_TIMEOUT_MS) {
    systemBlocked("HYDRATION_TIMEOUT_INVALID", "The trusted metadata timeout is outside its closed bound.");
  }
  if (typeof recursive !== "boolean") {
    systemBlocked("HYDRATION_METADATA_INVALID", "The trusted tree metadata recursion mode was malformed.");
  }
  const requestUrl = `https://api.github.com/repos/${repository}/git/trees/${packageTreeObjectId}${recursive ? "?recursive=1" : ""}`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  timeout.unref?.();
  let response;
  try {
    response = await fetchImplementation(requestUrl, {
      method: "GET",
      redirect: "error",
      signal: controller.signal,
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${readToken}`,
        "User-Agent": "programmable-public-intake-hydrator-v1",
        "X-GitHub-Api-Version": "2026-03-10"
      }
    });
  } catch {
    systemBlocked("HYDRATION_METADATA_UNAVAILABLE", "GitHub tree-size metadata was unavailable before candidate hydration.");
  } finally {
    clearTimeout(timeout);
  }
  if (
    !response
    || response.status !== 200
    || response.redirected === true
    || (typeof response.url === "string" && response.url !== "" && response.url !== requestUrl)
  ) {
    systemBlocked("HYDRATION_METADATA_UNAVAILABLE", "GitHub did not return exact same-origin tree-size metadata.");
  }
  const declaredLength = response.headers?.get?.("content-length");
  if (declaredLength !== null && declaredLength !== undefined) {
    if (!/^(?:0|[1-9][0-9]*)$/u.test(declaredLength) || Number(declaredLength) > HYDRATION_API_RESPONSE_BYTES) {
      systemBlocked("HYDRATION_METADATA_TOO_LARGE", "GitHub tree-size metadata exceeded its trusted response bound.");
    }
  }
  const bytes = await readBoundedHydrationResponse(response, HYDRATION_API_RESPONSE_BYTES);
  let parsed;
  try {
    parsed = JSON.parse(UTF8_DECODER.decode(bytes));
  } catch {
    systemBlocked("HYDRATION_METADATA_INVALID", "GitHub tree-size metadata was not valid bounded UTF-8 JSON.");
  }
  return { requestUrl, packageTreeObjectId, parsed };
}

async function readBoundedHydrationResponse(response, maximumBytes) {
  if (response.body?.getReader) {
    const reader = response.body.getReader();
    const chunks = [];
    let total = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const bytes = Buffer.from(value);
        total += bytes.length;
        if (total > maximumBytes) {
          await reader.cancel().catch(() => {});
          systemBlocked("HYDRATION_METADATA_TOO_LARGE", "GitHub tree-size metadata exceeded its trusted response bound.");
        }
        chunks.push(bytes);
      }
    } finally {
      reader.releaseLock?.();
    }
    return Buffer.concat(chunks, total);
  }
  if (typeof response.arrayBuffer !== "function") {
    systemBlocked("HYDRATION_METADATA_INVALID", "GitHub tree-size metadata had no readable response body.");
  }
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > maximumBytes) {
    systemBlocked("HYDRATION_METADATA_TOO_LARGE", "GitHub tree-size metadata exceeded its trusted response bound.");
  }
  return bytes;
}

function enforceHydrationMetadata(plan, metadata, limits) {
  const document = metadata.parsed;
  if (
    !isPlainObject(document)
    || document.sha !== metadata.packageTreeObjectId
    || document.truncated !== false
    || !Array.isArray(document.tree)
  ) {
    systemBlocked("HYDRATION_METADATA_INVALID", "GitHub tree-size metadata did not match the exact closed package tree.");
  }
  const expected = new Map(plan.entries.map((entry) => [
    plan.recursive === true
      ? entry.path.slice(`${plan.packageDirectory}/`.length)
      : path.posix.basename(entry.path),
    entry
  ]));
  const blobRecords = [];
  const observed = new Set();
  let totalBytes = 0;
  for (const record of document.tree) {
    if (!isPlainObject(record) || typeof record.path !== "string" || observed.has(record.path)) {
      systemBlocked("HYDRATION_METADATA_INVALID", "GitHub tree-size metadata contained an invalid or duplicate entry.");
    }
    observed.add(record.path);
    if (record.type === "tree") {
      if (
        plan.recursive !== true
        || record.mode !== "040000"
        || !SHA1_PATTERN.test(record.sha)
        || !isSafeApplicationV3PackagePath(record.path)
        || ![...expected.keys()].some((expectedPath) => expectedPath.startsWith(`${record.path}/`))
      ) {
        systemBlocked("HYDRATION_METADATA_INVALID", "GitHub recursive metadata contained an unexpected tree entry.");
      }
      continue;
    }
    blobRecords.push(record);
    const entry = expected.get(record.path);
    if (
      !entry
      || record.mode !== entry.mode
      || record.type !== entry.type
      || record.sha !== entry.oid
      || !Number.isSafeInteger(record.size)
      || record.size < 0
    ) {
      systemBlocked("HYDRATION_METADATA_MISMATCH", "GitHub tree-size metadata did not match the fetched exact Git tree.");
    }
    const maximumBytes = maximumHydrationEntryBytes(plan, entry, limits);
    if (record.size > maximumBytes) {
      reject("APPLICATION_FILE_TOO_LARGE", "An application package file exceeds its trusted byte limit before hydration.");
    }
    totalBytes += record.size;
    if (totalBytes > maximumHydrationPackageBytes(plan, limits)) {
      reject("APPLICATION_PACKAGE_TOO_LARGE", "The application review package exceeds its trusted byte limit before hydration.");
    }
  }
  if (blobRecords.length !== plan.entries.length || blobRecords.length !== expected.size) {
    systemBlocked("HYDRATION_METADATA_INVALID", "GitHub tree-size metadata did not match the exact bounded blob set.");
  }
  return {
    entries: new Map(blobRecords.map((record) => [record.sha, { path: record.path, size: record.size }])),
    totalBytes
  };
}

function maximumHydrationEntryBytes(plan, entry, limits) {
  if (plan.recursive === true) {
    return path.posix.basename(entry.path) === APPLICATION_V3_ROOT_FILE
      ? MAXIMUM_APPLICATION_V3_MANIFEST_BYTES
      : MAXIMUM_APPLICATION_V3_FILE_BYTES;
  }
  const maximumBytes = limits.maximumFileBytes[path.posix.basename(entry.path)];
  if (!Number.isInteger(maximumBytes)) {
    systemBlocked("FILE_LIMIT_MISSING", "The trusted validator has no size policy for a bounded package file.");
  }
  return maximumBytes;
}

function maximumHydrationPackageBytes(plan, limits) {
  return plan.recursive === true ? plan.maximumPackageBytes : limits.maximumPackageBytes;
}

function validateHydrationProcessLimits(maximumAdditionalRepositoryBytes, maximumFileSizeBytes) {
  for (const [label, value, maximum] of [
    ["additional repository", maximumAdditionalRepositoryBytes, HYDRATION_ADDITIONAL_REPOSITORY_BYTES],
    ["file size", maximumFileSizeBytes, HYDRATION_FILE_SIZE_BYTES]
  ]) {
    if (!Number.isInteger(value) || value < 512 || value > maximum) {
      systemBlocked("HYDRATION_LIMIT_INVALID", `The trusted ${label} hydration limit is invalid.`);
    }
  }
}

function runHydrationConfig(gitDirectory, configArgs, { allowMissing = false } = {}) {
  const result = childProcess.spawnSync(
    "git",
    [
      "-c", "credential.helper=",
      "-c", "core.hooksPath=/dev/null",
      "-C", gitDirectory,
      "config", "--local",
      ...configArgs
    ],
    {
      encoding: "utf8",
      shell: false,
      timeout: TRUSTED_GIT_TIMEOUT_MS,
      killSignal: "SIGKILL",
      env: trustedGitEnvironment()
    }
  );
  if (result.status === 0 || (allowMissing && result.status === 5)) return;
  systemBlocked("HYDRATION_CONFIG_FAILED", "Trusted sparse hydration configuration failed.");
}

function verifyHydratedObjects(gitDirectory, plan, metadata, limits) {
  let totalBytes = 0;
  for (const entry of plan.entries) {
    const type = runGitText(gitDirectory, ["cat-file", "-t", entry.oid], 32).trim();
    const sizeText = runGitText(gitDirectory, ["cat-file", "-s", entry.oid], 128).trim();
    if (type !== "blob" || !/^(?:0|[1-9][0-9]*)$/u.test(sizeText)) {
      systemBlocked("HYDRATION_OBJECT_INVALID", "A bounded application blob was unavailable after sparse hydration.");
    }
    const size = Number(sizeText);
    const expected = metadata.entries.get(entry.oid);
    if (!Number.isSafeInteger(size) || expected?.size !== size || size > maximumHydrationEntryBytes(plan, entry, limits)) {
      systemBlocked("HYDRATION_OBJECT_MISMATCH", "A hydrated blob did not match preflighted GitHub size metadata.");
    }
    totalBytes += size;
  }
  if (totalBytes !== metadata.totalBytes || totalBytes > maximumHydrationPackageBytes(plan, limits)) {
    systemBlocked("HYDRATION_OBJECT_MISMATCH", "Hydrated application bytes did not match the bounded package metadata.");
  }
}

export async function runBoundedHydrationGitProcess({
  gitExecutable = "git",
  gitDirectory,
  args,
  timeoutMs,
  maximumOutputBytes,
  maximumFileSizeBytes,
  maximumRepositoryBytes,
  maximumAddressSpaceBytes = CANDIDATE_GIT_ADDRESS_SPACE_BYTES,
  maximumCpuSeconds = CANDIDATE_GIT_CPU_SECONDS,
  allowFileProtocol = false,
  input = null
}) {
  if (process.platform !== "darwin" && process.platform !== "linux") {
    systemBlocked("HYDRATION_PLATFORM_UNSUPPORTED", "Bounded Git hydration supports macOS and Linux only.");
  }
  const safeArgs = [
    "-c", "credential.helper=",
    "-c", "credential.interactive=never",
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.attributesFile=/dev/null",
    "-c", "core.fsmonitor=false",
    "-c", "core.untrackedCache=false",
    "-c", "protocol.allow=never",
    "-c", "protocol.version=2",
    "-c", "protocol.https.allow=always",
    "-c", `protocol.file.allow=${allowFileProtocol ? "always" : "never"}`,
    "-c", "protocol.ext.allow=never",
    "-c", "protocol.ssh.allow=never",
    "-c", "http.followRedirects=false",
    "-c", "submodule.recurse=false",
    "-c", "fetch.recurseSubmodules=false",
    "-c", "fetch.fsckObjects=true",
    "-c", "transfer.fsckObjects=true",
    "-c", "core.deltaBaseCacheLimit=16m",
    "-c", "core.packedGitWindowSize=16m",
    "-c", "core.packedGitLimit=64m",
    "-c", "pack.deltaCacheLimit=16m",
    "-c", "pack.windowMemory=32m",
    "-c", "pack.threads=1",
    "-c", "index.threads=1",
    "-c", "maintenance.auto=false",
    "-c", "gc.auto=0",
    "-C", gitDirectory,
    ...args
  ];
  // Bash defines ulimit -f in 1024-byte increments on the supported runners.
  const fileLimitBlocks = Math.floor(maximumFileSizeBytes / 1024);
  const addressSpaceLimitKilobytes = process.platform === "linux"
    ? Math.floor(maximumAddressSpaceBytes / 1024)
    : 0;
  if (
    typeof gitExecutable !== "string"
    || gitExecutable.length < 1
    || /[\u0000\r\n]/u.test(gitExecutable)
    || !Array.isArray(args)
    || (input !== null && (!Buffer.isBuffer(input) || input.length < 1 || input.length > HYDRATION_OUTPUT_BYTES))
    || !Number.isInteger(timeoutMs)
    || timeoutMs < 1
    || timeoutMs > TRUSTED_GIT_TIMEOUT_MS
    || !Number.isInteger(maximumOutputBytes)
    || maximumOutputBytes < 1
    || !Number.isInteger(maximumRepositoryBytes)
    || maximumRepositoryBytes < 1
    || !Number.isInteger(maximumAddressSpaceBytes)
    || maximumAddressSpaceBytes < 64 * 1024 * 1024
    || maximumAddressSpaceBytes > CANDIDATE_GIT_ADDRESS_SPACE_BYTES
    || !Number.isInteger(maximumCpuSeconds)
    || maximumCpuSeconds < 1
    || maximumCpuSeconds > CANDIDATE_GIT_CPU_SECONDS
    || fileLimitBlocks < 1
  ) {
    systemBlocked("HYDRATION_PROCESS_INVALID", "Bounded Git hydration received invalid trusted process options.");
  }
  return new Promise((resolve, rejectPromise) => {
    // GitHub's production runner is Linux: RLIMIT_AS bounds decompression and
    // delta resolution even when a tiny pack expands far beyond its disk size.
    // Darwin does not implement a settable RLIMIT_AS, so local macOS tests keep
    // the file/CPU/repository/output/wall-clock limits while Linux adds RLIMIT_AS.
    const launcher = [
      'ulimit -f "$1" || exit 125',
      'ulimit -t "$2" || exit 125',
      'if [[ "$3" != "0" ]]; then ulimit -v "$3" || exit 125; fi',
      'shift 3',
      'exec "$@"'
    ].join("; ");
    let child;
    try {
      child = childProcess.spawn(
        "/bin/bash",
        [
          "--noprofile", "--norc", "-c", launcher, "bounded-git",
          String(fileLimitBlocks),
          String(maximumCpuSeconds),
          String(addressSpaceLimitKilobytes),
          gitExecutable,
          ...safeArgs
        ],
        {
          detached: true,
          env: hydrationGitEnvironment(),
          shell: false,
          stdio: [input === null ? "ignore" : "pipe", "pipe", "pipe"]
        }
      );
    } catch (error) {
      rejectPromise(error);
      return;
    }

    if (input !== null) {
      child.stdin.on("error", () => {});
      child.stdin.end(input);
    }

    const stdout = [];
    const stderr = [];
    let outputBytes = 0;
    let outputExceeded = false;
    let repositoryBytesExceeded = false;
    let timedOut = false;
    let terminated = false;
    let settled = false;
    let forceKillTimer = null;

    const killGroup = (signal) => {
      if (!Number.isInteger(child.pid)) return;
      try {
        process.kill(-child.pid, signal);
      } catch (error) {
        if (error?.code !== "ESRCH") child.kill(signal);
      }
    };
    const terminate = () => {
      if (terminated) return;
      terminated = true;
      killGroup("SIGTERM");
      forceKillTimer = setTimeout(() => killGroup("SIGKILL"), HYDRATION_KILL_GRACE_MS);
      forceKillTimer.unref?.();
    };
    const timeout = setTimeout(() => {
      timedOut = true;
      terminate();
    }, timeoutMs);
    timeout.unref?.();
    const sizePoll = setInterval(() => {
      if (settled || repositoryBytesExceeded) return;
      try {
        if (measureHydrationDirectory(gitDirectory) > maximumRepositoryBytes) {
          repositoryBytesExceeded = true;
          terminate();
        }
      } catch {
        repositoryBytesExceeded = true;
        terminate();
      }
    }, HYDRATION_POLL_MS);
    sizePoll.unref?.();

    const collect = (target) => (chunk) => {
      if (outputExceeded) return;
      const bytes = Buffer.from(chunk);
      outputBytes += bytes.length;
      if (outputBytes > maximumOutputBytes) {
        outputExceeded = true;
        terminate();
        return;
      }
      target.push(bytes);
    };
    child.stdout.on("data", collect(stdout));
    child.stderr.on("data", collect(stderr));
    child.on("error", (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      clearInterval(sizePoll);
      killGroup("SIGKILL");
      if (forceKillTimer !== null) clearTimeout(forceKillTimer);
      rejectPromise(error);
    });
    child.on("close", (status, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      clearInterval(sizePoll);
      // A successful leader must not be allowed to leave a detached helper
      // alive after the bounded operation has finished.
      killGroup("SIGKILL");
      if (forceKillTimer !== null) clearTimeout(forceKillTimer);
      try {
        if (measureHydrationDirectory(gitDirectory) > maximumRepositoryBytes) repositoryBytesExceeded = true;
      } catch {
        repositoryBytesExceeded = true;
      }
      const stderrBytes = Buffer.concat(stderr);
      const stderrText = stderrBytes.toString("utf8");
      resolve({
        status: Number.isInteger(status) ? status : 1,
        signal,
        stdout: Buffer.concat(stdout),
        stderr: stderrBytes,
        timedOut,
        outputExceeded,
        repositoryBytesExceeded,
        fileSizeExceeded: signal === "SIGXFSZ"
          || status === 153
          || /File size limit exceeded/iu.test(stderrText),
        addressSpaceExceeded: /(?:out of memory|cannot allocate memory|memory exhausted|failed to allocate memory)/iu.test(stderrText),
        cpuExceeded: signal === "SIGXCPU" || status === 152
      });
    });
  });
}

function hydrationGitEnvironment() {
  const environment = Object.create(null);
  for (const name of ["PATH", "TMPDIR", "TMP", "TEMP"]) {
    if (typeof process.env[name] === "string") environment[name] = process.env[name];
  }
  environment.LANG = "C";
  environment.LC_ALL = "C";
  environment.LC_CTYPE = "C";
  environment.GIT_CONFIG_NOSYSTEM = "1";
  environment.GIT_CONFIG_GLOBAL = "/dev/null";
  environment.GIT_TERMINAL_PROMPT = "0";
  environment.GIT_OPTIONAL_LOCKS = "0";
  environment.GIT_LFS_SKIP_SMUDGE = "1";
  environment.GIT_NO_REPLACE_OBJECTS = "1";
  environment.GIT_LITERAL_PATHSPECS = "1";
  environment.GIT_PROTOCOL_FROM_USER = "0";
  environment.GIT_PAGER = "cat";
  environment.GCM_INTERACTIVE = "Never";
  return environment;
}

export function measureHydrationDirectory(directory) {
  const root = path.resolve(directory ?? "");
  if (!fs.statSync(root, { throwIfNoEntry: false })?.isDirectory()) {
    systemBlocked("HYDRATION_STORAGE_INVALID", "The candidate object store is missing.");
  }
  const pending = [root];
  let entries = 0;
  let totalBytes = 0;
  while (pending.length > 0) {
    const current = pending.pop();
    let entriesInDirectory;
    try {
      entriesInDirectory = fs.readdirSync(current, { withFileTypes: true });
    } catch (error) {
      // Git creates, renames, and removes temporary pack directories while a
      // bounded fetch is active. A child that disappears between traversal
      // steps is harmless; the stable final measurement still runs after Git
      // exits. The object-store root itself must always remain present.
      if (current !== root && error?.code === "ENOENT") continue;
      throw error;
    }
    for (const entry of entriesInDirectory) {
      entries += 1;
      if (entries > HYDRATION_MAXIMUM_ENTRIES) {
        systemBlocked("HYDRATION_STORAGE_INVALID", "The candidate object store exceeds its trusted entry bound.");
      }
      const entryPath = path.join(current, entry.name);
      const status = fs.lstatSync(entryPath, { throwIfNoEntry: false });
      if (status === undefined) continue;
      if (status.isDirectory()) {
        pending.push(entryPath);
      } else {
        if (status.isFile() || status.isSymbolicLink()) totalBytes += status.size;
      }
      if (!Number.isSafeInteger(totalBytes)) {
        systemBlocked("HYDRATION_STORAGE_INVALID", "The candidate object-store size could not be represented safely.");
      }
    }
  }
  return totalBytes;
}

async function verifyPublicApplicationV3({
  classified,
  expectedBuilderLogin,
  expectedBuilderUserId,
  pullRequestNumber,
  resolveSource,
  resolveExactObjects
}) {
  const plan = planApplicationV3Hydration(classified);
  const baseHistory = inspectTrustedBaseApplicationV3History(classified.base, plan.applicationId);
  const hasLegacyV2 = hasTrustedLegacyV2Application(classified.base, plan.applicationId);
  const draftPredecessor = classified.applicationV3DraftPredecessor;
  const isUpdate = baseHistory.length > 0 || hasLegacyV2 || draftPredecessor !== null;
  const intakeStatus = readTrustedIntakeStatus(classified.base);
  const continuation = enforceTrustedIntakeStatus({
    intakeStatus,
    isUpdate,
    pullRequestNumber,
    applicationId: plan.applicationId
  });
  const packageFiles = readApplicationV3PackageFiles(classified.candidate.root, plan);
  let validated;
  try {
    validated = validatePublicApplicationV3PackageFiles({
      applicationId: plan.applicationId,
      applicationRevision: plan.applicationRevision,
      packageFiles,
      expectedBuilderLogin: normalizeExpectedBuilderLogin(expectedBuilderLogin),
      expectedBuilderUserId: normalizeExpectedBuilderUserId(expectedBuilderUserId)
    });
  } catch (error) {
    if (error instanceof PublicApplicationV3IntakeError) reject(error.code, error.message);
    throw error;
  }
  const { application } = validated;
  const legacyPredecessor = hasLegacyV2
    ? readTrustedLegacyV2Predecessor({
      application,
      base: classified.base,
      limits: mergeLimits({})
    })
    : null;
  enforceTrustedContinuationIdentity({ continuation, application });
  validateApplicationV3Lineage({
    application,
    base: classified.base,
    baseHistory,
    legacyPredecessor,
    draftPredecessor,
    draftPredecessorRoot: classified.candidate.root,
    expectedBuilderLogin: application.builder.githubLogin,
    expectedBuilderUserId: application.builder.githubUserId
  });

  const repositories = [application.source.primary, ...application.source.companions];
  const sourceResolver = resolveSource ?? resolvePublicGitHubSource;
  if (typeof sourceResolver !== "function") {
    systemBlocked("RESOLVER_UNAVAILABLE", "The trusted Application V3 source resolver is unavailable.");
  }
  for (const repository of repositories) {
    const request = projectApplicationV3RepositoryRequest(repository);
    let observation;
    try {
      observation = await sourceResolver(request);
    } catch (error) {
      translateSourceResolutionError(error);
    }
    validateSourceObservation(request, observation);
  }

  const exactResolver = resolveExactObjects ?? createAnonymousGitHubExactObjectResolverV1();
  if (typeof exactResolver !== "function") {
    systemBlocked("EVIDENCE_RESOLVER_UNAVAILABLE", "The trusted Application V3 exact-object resolver is unavailable.");
  }
  if (legacyPredecessor !== null) {
    await verifyTrustedLegacyV2PredecessorSource({
      application,
      predecessor: legacyPredecessor,
      sourceResolver,
      exactResolver,
      limits: mergeLimits({})
    });
  }
  const sourceArtifacts = await resolveApplicationV3SourceArtifacts({ application, repositories, exactResolver });
  const policy = application.policyBindings;
  const submissionBytes = sourceArtifacts.get(`${policy.submissionRepositoryRef}\0${policy.submissionPath}`);
  let submissionValidation;
  try {
    submissionValidation = validatePublicApplicationV3SubmissionV2Bytes({
      application,
      submissionBytes,
      sourceArtifacts,
      packageFiles
    });
  } catch (error) {
    if (error instanceof PublicApplicationV3IntakeError) reject(error.code, error.message);
    throw error;
  }

  const launchReadiness = application.contract.version === "3.2.0"
    ? deriveTrustedPublicApplicationV3LaunchReadinessV1(submissionValidation)
    : null;

  return {
    schemaVersion: 1,
    validatorVersion: application.contract.version,
    result: "valid-public-application-v3-package",
    mode: "application-v3",
    intakeState: intakeStatus.state,
    applicationId: plan.applicationId,
    applicationRevision: plan.applicationRevision,
    pullRequestNumber,
    continuationAuthorized: continuation !== null,
    sourceRepositoryCount: repositories.length,
    fileCount: plan.entries.length,
    totalBytes: validated.totalBytes,
    reviewState: "unreviewed",
    approvalGranted: false,
    acceptanceGranted: false,
    productionDiscoveryAllowed: false,
    publicRoutingAllowed: false,
    realUserFundsAllowed: false,
    ...(launchReadiness === null ? {} : { launchReadiness })
  };
}

function readApplicationV3PackageFiles(gitRoot, plan) {
  const prefix = `${plan.packageDirectory}/`;
  const files = new Map();
  let totalBytes = 0;
  for (const entry of plan.entries) {
    const relativePath = entry.path.slice(prefix.length);
    const bytes = readGitBlob(gitRoot, entry, maximumHydrationEntryBytes(plan, entry, mergeLimits({})));
    totalBytes += bytes.length;
    if (totalBytes > MAXIMUM_APPLICATION_V3_PACKAGE_BYTES) {
      reject("APPLICATION_PACKAGE_TOO_LARGE", "The Application V3 package exceeds its trusted byte limit.");
    }
    files.set(relativePath, bytes);
  }
  return files;
}

function inspectTrustedBaseApplicationV3History(base, applicationId) {
  const prefix = `submissions/${applicationId}/v3/revisions/`;
  const revisions = new Map();
  for (const entry of base.entries.values()) {
    if (!entry.path.startsWith(prefix)) continue;
    const match = APPLICATION_V3_PATH_PATTERN.exec(entry.path);
    if (!match || match[1] !== applicationId || !isSafeApplicationV3PackagePath(match[3])) {
      systemBlocked("INTAKE_BASE_APPLICATION_V3_INVALID", "The trusted base contains an invalid Application V3 revision path.");
    }
    assertTrustedRegularBlob(entry, "INTAKE_BASE_APPLICATION_V3_INVALID");
    const records = revisions.get(match[2]) ?? [];
    records.push(entry);
    revisions.set(match[2], records);
  }
  const history = [...revisions].map(([revision, entries]) => {
    const sortedEntries = entries.sort((left, right) => compareUtf8(left.path, right.path));
    const rootPath = `submissions/${applicationId}/v3/revisions/${revision}/${APPLICATION_V3_ROOT_FILE}`;
    if (!sortedEntries.some(({ path: entryPath }) => entryPath === rootPath)) {
      systemBlocked("INTAKE_BASE_APPLICATION_V3_INVALID", "A trusted base Application V3 revision is missing its root manifest.");
    }
    return { revision, entries: sortedEntries };
  });
  history.sort((left, right) => compareCanonicalDecimal(left.revision, right.revision));
  return history;
}

function hasTrustedLegacyV2Application(base, applicationId) {
  const prefix = `submissions/${applicationId}/`;
  const expected = APPLICATION_FILES.map((fileName) => `${prefix}${fileName}`).sort(compareUtf8);
  const directEntries = [...base.entries.values()]
    .filter((entry) => entry.path.startsWith(prefix) && APPLICATION_PATH_PATTERN.test(entry.path))
    .sort((left, right) => compareUtf8(left.path, right.path));
  if (directEntries.length === 0) return false;
  if (!arraysEqual(directEntries.map(({ path: entryPath }) => entryPath), expected)) {
    systemBlocked("INTAKE_BASE_APPLICATION_INVALID", "The trusted base contains an incomplete legacy V2 application package.");
  }
  directEntries.forEach((entry) => assertTrustedRegularBlob(entry, "INTAKE_BASE_APPLICATION_INVALID"));
  return true;
}

function assertTrustedRegularBlob(entry, code) {
  if (entry.mode !== "100644" || entry.type !== "blob" || !SHA1_PATTERN.test(entry.oid)) {
    systemBlocked(code, "The trusted base application package contains a non-regular entry.");
  }
}

function validateApplicationV3Lineage({
  application,
  base,
  baseHistory,
  legacyPredecessor,
  draftPredecessor,
  draftPredecessorRoot,
  expectedBuilderLogin,
  expectedBuilderUserId
}) {
  if (baseHistory.length === 0 && draftPredecessor === null) {
    if (legacyPredecessor !== null) {
      if (
        application.lineage.kind !== "schema-migration"
        || application.applicationRevision !== incrementCanonicalDecimal(String(legacyPredecessor.application.applicationRevision))
        || application.lineage.previous?.applicationContract !== "public-pr-application-v2"
      ) {
        reject(
          "APPLICATION_V2_BASE_LINEAGE_MISMATCH",
          "A first V3 revision over a legacy V2 application must increment its revision and declare exact schema-migration lineage."
        );
      }
      return;
    }
    if (application.applicationRevision !== "1" || application.lineage.kind !== "new" || application.lineage.previous !== null) {
      reject("APPLICATION_V3_LINEAGE_MISMATCH", "A new Application V3 history must start at revision 1 with null previous lineage.");
    }
    return;
  }
  const previous = baseHistory.at(-1) ?? draftPredecessor;
  if (application.applicationRevision !== incrementCanonicalDecimal(previous.revision)) {
    reject("APPLICATION_V3_LINEAGE_MISMATCH", "Application V3 revision must increment its exact authenticated predecessor once.");
  }
  const packageDirectory = `submissions/${application.applicationId}/v3/revisions/${previous.revision}`;
  const plan = {
    applicationId: application.applicationId,
    applicationRevision: previous.revision,
    packageDirectory,
    entries: previous.entries,
    recursive: true,
    maximumPackageBytes: MAXIMUM_APPLICATION_V3_PACKAGE_BYTES
  };
  const predecessorRoot = baseHistory.length > 0 ? base.root : draftPredecessorRoot;
  const packageFiles = readApplicationV3PackageFiles(predecessorRoot, plan);
  let validated;
  try {
    validated = validatePublicApplicationV3PackageFiles({
      applicationId: application.applicationId,
      applicationRevision: previous.revision,
      packageFiles,
      expectedBuilderLogin,
      expectedBuilderUserId
    });
  } catch (error) {
    if (error instanceof PublicApplicationV3IntakeError) {
      const code = baseHistory.length > 0
        ? "INTAKE_BASE_APPLICATION_V3_INVALID"
        : "APPLICATION_V3_DRAFT_HISTORY_INVALID";
      systemBlocked(code, "The exact trusted Application V3 predecessor package is invalid.");
    }
    throw error;
  }
  const targetDirectory = packageDirectory;
  const applicationBytes = packageFiles.get(APPLICATION_V3_ROOT_FILE);
  const files = [{
    path: `${targetDirectory}/${APPLICATION_V3_ROOT_FILE}`,
    mediaType: "application/json",
    byteLength: applicationBytes.length,
    sha256: sha256BytesV3(applicationBytes)
  }, ...validated.applicationRecords.map((record) => ({
    ...record,
    path: `${targetDirectory}/${record.path}`
  }))].sort((left, right) => compareUtf8(left.path, right.path));
  const expectedPrevious = derivePublicPrApplicationV3PreviousBinding({
    application: validated.application,
    applicationSha256: sha256BytesV3(applicationBytes),
    packageSha256: sha256CanonicalV3({
      contract: "public-pr-application-v3-package",
      applicationId: application.applicationId,
      applicationRevision: previous.revision,
      targetDirectory,
      files
    }),
    targetContractVersion: application.contract.version
  });
  const previousContractVersion = validated.application.contract.version;
  const currentContractVersion = application.contract.version;
  if (previousContractVersion === "3.2.0" && currentContractVersion === "3.1.0") {
    reject("APPLICATION_V3_CONTRACT_DOWNGRADE_FORBIDDEN", "An Application V3.2 history cannot downgrade to the V3.1 compatibility contract.");
  }
  if (previousContractVersion === "3.1.0" && currentContractVersion === "3.2.0" && application.lineage.kind !== "schema-migration") {
    reject("APPLICATION_V3_2_MIGRATION_KIND_REQUIRED", "An Application V3.1 to V3.2 transition must use exact schema-migration lineage.");
  }
  if (canonicalJson(application.lineage.previous) !== canonicalJson(expectedPrevious)) {
    reject("APPLICATION_V3_LINEAGE_MISMATCH", "Application V3 lineage does not bind the exact authenticated predecessor package.");
  }
}

function readTrustedLegacyV2Predecessor({ application, base, limits }) {
  const applicationDirectory = `submissions/${application.applicationId}`;
  const packageFiles = new Map();
  try {
    for (const fileName of APPLICATION_FILES) {
      const entry = base.entries.get(`${applicationDirectory}/${fileName}`);
      assertTrustedRegularBlob(entry, "INTAKE_BASE_APPLICATION_INVALID");
      packageFiles.set(fileName, readGitBlob(base.root, entry, limits.maximumFileBytes[fileName]));
    }
  } catch (error) {
    if (error instanceof PublicIntakeError) {
      systemBlocked("INTAKE_BASE_APPLICATION_INVALID", "The protected base legacy V2 predecessor package cannot be read exactly.");
    }
    throw error;
  }
  const legacyPolicyAdapter = readTrustedLegacyV2PolicyAdapter({
    baseRoot: base.root,
    expectedBaseCommit: base.commit
  });
  let validated;
  try {
    validated = validatePublicApplicationPackageFiles({
      applicationId: application.applicationId,
      packageFiles,
      legacyPolicyAdapter,
      limits
    });
  } catch (error) {
    if (error instanceof PublicIntakeError) {
      systemBlocked("INTAKE_BASE_APPLICATION_INVALID", "The protected base legacy V2 predecessor package fails its frozen contract.");
    }
    throw error;
  }
  if (validated.application.builder.githubUserId !== application.builder.githubUserId) {
    reject("APPLICATION_V2_BASE_LINEAGE_MISMATCH", "A V3 schema migration cannot replace the immutable legacy V2 builder identity.");
  }
  const records = APPLICATION_FILES.map((fileName) => {
    const bytes = packageFiles.get(fileName);
    return {
      path: fileName,
      byteLength: bytes.length,
      sha256: sha256BytesV3(bytes)
    };
  });
  return Object.freeze({
    application: validated.application,
    applicationBytes: packageFiles.get(APPLICATION_FILE),
    packageSha256: sha256CanonicalV3({
      applicationDirectory,
      applicationRevision: validated.application.applicationRevision,
      files: records
    })
  });
}

async function verifyTrustedLegacyV2PredecessorSource({
  application,
  predecessor,
  sourceResolver,
  exactResolver,
  limits
}) {
  const previousApplication = predecessor.application;
  const source = previousApplication.source.primary;
  const fee = previousApplication.programmableFee;
  const request = projectApplicationV3RepositoryRequest({
    ...source,
    githubActionsRunIds: [],
    sourceClosureMode: "manifest"
  });
  let observation;
  try {
    observation = await sourceResolver(request);
  } catch (error) {
    translateSourceResolutionError(error);
  }
  validateSourceObservation(request, observation);

  let result;
  try {
    result = await exactResolver({
      repositoryUri: source.repositoryUri,
      revisionObjectId: source.revisionObjectId,
      treeObjectId: source.treeObjectId,
      paths: [fee.submissionBinding.path],
      timeoutMs: GITHUB_PUBLIC_GIT_OBJECT_RESOLVER_V1.maximumTimeoutMs,
      maximumFileBytes: GITHUB_PUBLIC_GIT_OBJECT_RESOLVER_V1.maximumFileBytes,
      maximumTotalBytes: GITHUB_PUBLIC_GIT_OBJECT_RESOLVER_V1.maximumTotalBytes
    });
  } catch (error) {
    translateEvidenceResolutionError(error);
  }
  const records = result instanceof Map ? result : result?.records;
  const record = records instanceof Map ? records.get(fee.submissionBinding.path) : null;
  if (!(records instanceof Map) || records.size !== 1 || !isEvidenceExactObjectRecord(record) || record.mode !== "100644") {
    systemBlocked("INTAKE_BASE_APPLICATION_V2_SOURCE_INVALID", "The protected legacy V2 predecessor submission is not one exact regular Git blob.");
  }
  const submissionBytes = Buffer.from(record.bytes);
  if (
    submissionBytes.length < 1
    || submissionBytes.length > limits.maximumEvidenceBlobBytes
    || sha256BytesV3(submissionBytes) !== fee.submissionBinding.sha256
  ) {
    systemBlocked("INTAKE_BASE_APPLICATION_V2_SOURCE_INVALID", "The protected legacy V2 predecessor submission differs from its exact source binding.");
  }
  let submission;
  try {
    submission = parseCanonicalJson(submissionBytes, "legacy-v2:submission.json", limits);
  } catch (error) {
    if (error instanceof PublicIntakeError) {
      systemBlocked("INTAKE_BASE_APPLICATION_V2_SOURCE_INVALID", "The protected legacy V2 predecessor submission is not bounded canonical JSON.");
    }
    throw error;
  }
  if (
    (submission?.$schema !== undefined && submission.$schema !== "urn:programmable:v4-hook-submission:1.6.0")
    || submission?.standardVersion !== "1.6.0"
    || submission?.schemaVersion !== 1
    || submission?.model?.id !== application.applicationId
  ) {
    systemBlocked("INTAKE_BASE_APPLICATION_V2_SOURCE_INVALID", "The protected legacy V2 predecessor source artifact is not its fixed Submission 1.6.0 contract.");
  }
  const expectedPrevious = {
    applicationContract: "public-pr-application-v2",
    applicationSchemaVersion: 2,
    applicationRevision: String(previousApplication.applicationRevision),
    applicationSha256: sha256BytesV3(predecessor.applicationBytes),
    packageSha256: predecessor.packageSha256,
    sourceNumericRepositoryId: source.numericRepositoryId,
    sourceCommit: source.revisionObjectId,
    sourceTree: source.treeObjectId,
    submissionSchemaId: typeof submission.$schema === "string" ? submission.$schema : null,
    submissionStandard: submission.standardVersion,
    submissionPath: fee.submissionBinding.path,
    submissionSha256: fee.submissionBinding.sha256,
    feePolicyId: fee.policyId,
    feePolicyVersion: fee.policyVersion,
    feeApplicability: deriveApplicationV3FeeApplicabilityFromSubmissionV2(submission),
    feePolicyInstanceSha256: null
  };
  if (canonicalJson(application.lineage.previous) !== canonicalJson(expectedPrevious)) {
    reject(
      "APPLICATION_V2_BASE_LINEAGE_MISMATCH",
      "Application V3 schema-migration lineage differs from the exact protected V2 package, source, Submission 1.6.0, or fee projection."
    );
  }
}

function projectApplicationV3RepositoryRequest(repository) {
  const inline = repository.sourceClosureMode === "inline";
  const contractPaths = inline ? repository.contractPaths : [];
  const contractPathSet = new Set(contractPaths);
  return {
    schemaVersion: GITHUB_PUBLIC_SOURCE_CONTRACT_V1.schemaVersion,
    primary: {
      repositoryUri: repository.repositoryUri,
      numericRepositoryId: repository.numericRepositoryId,
      revisionObjectId: repository.revisionObjectId,
      treeObjectId: repository.treeObjectId,
      // Application V3 records the complete source closure and an explicit
      // contract subset. GitHubPublicSourceContractV1 expects its two path
      // classes to be disjoint, so project the subset only once without
      // changing the exact union of paths that is remotely verified.
      sourcePaths: inline
        ? repository.sourcePaths.filter((sourcePath) => !contractPathSet.has(sourcePath))
        : [],
      contractPaths,
      githubActionsRunIds: repository.githubActionsRunIds
    },
    companions: []
  };
}

async function resolveApplicationV3SourceArtifacts({ application, repositories, exactResolver }) {
  const repositoriesById = new Map(repositories.map((repository) => [repository.id, repository]));
  const expectedByRepository = new Map(repositories.map((repository) => [repository.id, new Map()]));
  for (const record of application.reviewPackage.records.filter(({ source }) => source === "source-repository")) {
    addExpectedApplicationV3Artifact(expectedByRepository, record.repositoryRef, {
      path: record.path,
      sha256: record.sha256,
      byteLength: record.byteLength,
      objectId: null
    });
  }
  const policy = application.policyBindings;
  addExpectedApplicationV3Artifact(expectedByRepository, policy.submissionRepositoryRef, {
    path: policy.submissionPath,
    sha256: policy.submissionSha256,
    byteLength: null,
    objectId: null
  });
  for (const repository of repositories) {
    if (repository.sourceClosureMode === "manifest") {
      addExpectedApplicationV3Artifact(expectedByRepository, repository.id, {
        path: repository.sourceManifest.path,
        sha256: repository.sourceManifest.sha256,
        byteLength: repository.sourceManifest.byteLength,
        objectId: repository.sourceManifest.blobObjectId
      });
    }
  }

  const resolved = new Map();
  for (const [repositoryRef, expected] of expectedByRepository) {
    const repository = repositoriesById.get(repositoryRef);
    if (!repository) {
      reject("APPLICATION_ARTIFACT_REPOSITORY_REF_MISSING", "An Application V3 artifact references no declared source repository.");
    }
    let result;
    try {
      result = await exactResolver({
        repositoryUri: repository.repositoryUri,
        revisionObjectId: repository.revisionObjectId,
        treeObjectId: repository.treeObjectId,
        paths: [...expected.keys()].sort(compareUtf8),
        timeoutMs: GITHUB_PUBLIC_GIT_OBJECT_RESOLVER_V1.maximumTimeoutMs,
        maximumFileBytes: GITHUB_PUBLIC_GIT_OBJECT_RESOLVER_V1.maximumFileBytes,
        maximumTotalBytes: GITHUB_PUBLIC_GIT_OBJECT_RESOLVER_V1.maximumTotalBytes
      });
    } catch (error) {
      translateEvidenceResolutionError(error);
    }
    const records = result instanceof Map ? result : result?.records;
    if (!(records instanceof Map) || records.size !== expected.size) {
      systemBlocked("APPLICATION_V3_SOURCE_OBSERVATION_INVALID", "The trusted exact-object resolver returned the wrong Application V3 artifact set.");
    }
    for (const [artifactPath, binding] of expected) {
      const record = records.get(artifactPath);
      if (!isEvidenceExactObjectRecord(record) || record.mode !== "100644") {
        reject("APPLICATION_V3_SOURCE_ARTIFACT_INVALID", "A bound Application V3 source artifact is not one regular non-executable Git blob.");
      }
      const bytes = Buffer.from(record.bytes);
      if (
        sha256BytesV3(bytes) !== binding.sha256
        || (binding.byteLength !== null && bytes.length !== binding.byteLength)
        || (binding.objectId !== null && record.objectId !== binding.objectId)
      ) {
        reject("APPLICATION_V3_SOURCE_ARTIFACT_MISMATCH", "A bound Application V3 source artifact differs from its exact commit, digest, size, or blob identity.");
      }
      resolved.set(`${repositoryRef}\0${artifactPath}`, bytes);
    }
  }
  return resolved;
}

function addExpectedApplicationV3Artifact(expectedByRepository, repositoryRef, binding) {
  const records = expectedByRepository.get(repositoryRef);
  if (!records || typeof binding.path !== "string") {
    reject("APPLICATION_ARTIFACT_REPOSITORY_REF_MISSING", "An Application V3 artifact binding is incomplete.");
  }
  const previous = records.get(binding.path);
  if (
    previous
    && (
      previous.sha256 !== binding.sha256
      || (previous.byteLength !== null && binding.byteLength !== null && previous.byteLength !== binding.byteLength)
      || (previous.objectId !== null && binding.objectId !== null && previous.objectId !== binding.objectId)
    )
  ) {
    reject("APPLICATION_V3_SOURCE_ARTIFACT_CONFLICT", "An Application V3 source path has conflicting byte bindings.");
  }
  records.set(binding.path, {
    path: binding.path,
    sha256: binding.sha256,
    byteLength: previous?.byteLength ?? binding.byteLength,
    objectId: previous?.objectId ?? binding.objectId
  });
}

function sha256BytesV3(bytes) {
  return `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
}

function sha256CanonicalV3(value) {
  return sha256BytesV3(Buffer.from(canonicalJson(value), "utf8"));
}

function compareCanonicalDecimal(left, right) {
  return left.length - right.length || compareUtf8(left, right);
}

function incrementCanonicalDecimal(value) {
  const digits = [...value];
  let carry = 1;
  for (let index = digits.length - 1; index >= 0 && carry === 1; index -= 1) {
    if (digits[index] === "9") digits[index] = "0";
    else {
      digits[index] = String(Number(digits[index]) + 1);
      carry = 0;
    }
  }
  if (carry === 1) digits.unshift("1");
  return digits.join("");
}

function decrementCanonicalDecimal(value) {
  if (!/^[1-9][0-9]*$/u.test(value) || value === "1") return null;
  const digits = [...value];
  let borrow = 1;
  for (let index = digits.length - 1; index >= 0 && borrow === 1; index -= 1) {
    if (digits[index] === "0") digits[index] = "9";
    else {
      digits[index] = String(Number(digits[index]) - 1);
      borrow = 0;
    }
  }
  if (digits[0] === "0") digits.shift();
  return digits.join("");
}

export async function verifyPublicHookApplication({
  baseRoot,
  candidateRoot,
  expectedBaseCommit,
  pullRequestNumber,
  expectedBuilderLogin,
  expectedBuilderUserId,
  expectedCandidateCommit,
  expectedMergeCommit,
  resolveSource,
  resolveEvidence,
  resolveCompanionClosure,
  resolveExactObjects,
  limits: limitOverrides = {}
}) {
  const limits = mergeLimits(limitOverrides);
  validateCandidateFetchIdentity({
    pullRequestNumber,
    expectedBaseCommit,
    expectedCandidateCommit,
    expectedMergeCommit
  });
  const classified = classifyPublicIntakePullRequest({
    baseRoot,
    candidateRoot,
    expectedBaseCommit,
    expectedCandidateCommit,
    expectedMergeCommit,
    limits
  });
  if (classified.mode === "application-v3") {
    return verifyPublicApplicationV3({
      classified,
      expectedBuilderLogin,
      expectedBuilderUserId,
      pullRequestNumber,
      resolveSource,
      resolveExactObjects
    });
  }
  const legacyPolicyAdapter = readTrustedLegacyV2PolicyAdapter({ baseRoot, expectedBaseCommit });
  requireLegacyV2PolicyAdapter(legacyPolicyAdapter, { trusted: true });
  if (classified.mode !== "application") {
    reject("APPLICATION_CHANGE_REQUIRED", "This validator accepts exactly one closed public application package.");
  }

  const changedApplicationIds = new Set();
  for (const change of classified.changes) {
    if (change.status === "deleted") {
      reject("APPLICATION_FILE_DELETED", "Public application files cannot be deleted through the intake workflow.");
    }
    const match = APPLICATION_PATH_PATTERN.exec(change.path);
    if (!match) reject("APPLICATION_PATH_INVALID", "An application path is outside the closed package layout.");
    changedApplicationIds.add(match[1]);
  }
  if (changedApplicationIds.size !== 1) {
    reject("APPLICATION_COUNT_INVALID", "A public application pull request must add or update exactly one application id.");
  }
  const [applicationId] = changedApplicationIds;
  const packagePrefix = `submissions/${applicationId}/`;
  const isUpdate = classifyTrustedBaseApplication(classified.base, applicationId);
  const intakeStatus = readTrustedIntakeStatus(classified.base);
  const continuation = enforceTrustedIntakeStatus({
    intakeStatus,
    isUpdate,
    pullRequestNumber,
    applicationId
  });

  if (resolveSource !== undefined && typeof resolveSource !== "function") {
    systemBlocked("RESOLVER_UNAVAILABLE", "The trusted public-source resolver is unavailable.");
  }
  if (resolveEvidence !== undefined && typeof resolveEvidence !== "function") {
    systemBlocked("EVIDENCE_RESOLVER_UNAVAILABLE", "The trusted public-evidence resolver is unavailable.");
  }
  if (resolveCompanionClosure !== undefined && typeof resolveCompanionClosure !== "function") {
    systemBlocked("COMPANION_CLOSURE_RESOLVER_UNAVAILABLE", "The trusted companion-closure resolver is unavailable.");
  }
  const normalizedBuilderLogin = normalizeExpectedBuilderLogin(expectedBuilderLogin);
  const normalizedBuilderUserId = normalizeExpectedBuilderUserId(expectedBuilderUserId);
  const candidatePackageEntries = [...classified.candidate.entries.values()]
    .filter((entry) => entry.path.startsWith(packagePrefix))
    .sort((left, right) => compareUtf8(left.path, right.path));
  const expectedPaths = APPLICATION_FILES.map((fileName) => `${packagePrefix}${fileName}`).sort(compareUtf8);
  const observedPaths = candidatePackageEntries.map((entry) => entry.path);
  if (!arraysEqual(observedPaths, expectedPaths)) {
    reject(
      "APPLICATION_PACKAGE_NOT_CLOSED",
      "The application directory must contain exactly the six allowlisted manifest and review-package files."
    );
  }
  for (const entry of candidatePackageEntries) assertRegularBlob(entry);

  const packageFiles = new Map();
  let packageBytes = 0;
  for (const entry of candidatePackageEntries) {
    const fileName = path.posix.basename(entry.path);
    const maximumBytes = limits.maximumFileBytes[fileName];
    if (!Number.isInteger(maximumBytes)) {
      systemBlocked("FILE_LIMIT_MISSING", "The trusted validator has no size policy for an allowlisted package file.");
    }
    const bytes = readGitBlob(classified.candidate.root, entry, maximumBytes);
    packageFiles.set(fileName, bytes);
    packageBytes += bytes.length;
  }
  if (packageBytes > limits.maximumPackageBytes) {
    reject("APPLICATION_PACKAGE_TOO_LARGE", "The application review package exceeds the trusted byte limit.");
  }

  const { application, compatibility, evidenceIndex } = validatePublicApplicationPackageFiles({
    applicationId,
    packageFiles,
    legacyPolicyAdapter,
    limits
  });
  enforceTrustedContinuationIdentity({ continuation, application });
  // This authenticated event value proves who opened the central pull request.
  // It does not prove that the author owns any declared public source repository.
  if (application.builder.githubUserId !== normalizedBuilderUserId) {
    reject(
      "BUILDER_ID_PR_AUTHOR_MISMATCH",
      "application.builder.githubUserId must equal the authenticated author id of this pull request."
    );
  }
  if (application.builder.githubLogin.toLowerCase() !== normalizedBuilderLogin) {
    reject(
      "BUILDER_LOGIN_PR_AUTHOR_MISMATCH",
      "application.builder.githubLogin must identify the authenticated author of this pull request."
    );
  }
  validateRevisionChange({
    application,
    applicationId,
    packagePrefix,
    classified,
    legacyPolicyAdapter,
    limits
  });

  const blobEvidence = evidenceIndex.evidence.filter((record) =>
    validateGitHubEvidenceUrl(record.url, "evidence.url", application.source.primary) === "blob"
  );
  if (resolveSource === undefined && resolveEvidence === undefined) {
    const session = createTrustedPublicApplicationResolutionSessionV1({
      source: application.source,
      evidence: blobEvidence
    });
    resolveSource = session.resolveSource;
    resolveEvidence = session.resolveEvidence;
    resolveCompanionClosure = session.resolveCompanionClosure;
  } else {
    resolveSource ??= resolvePublicGitHubSource;
    resolveEvidence ??= resolvePublicApplicationEvidence;
    resolveCompanionClosure ??= application.companionClosure.length === 0
      ? async () => []
      : resolvePublicCompanionClosure;
  }

  let sourceObservation;
  try {
    sourceObservation = await resolveSource(application.source);
  } catch (error) {
    translateSourceResolutionError(error);
  }
  validateSourceObservation(application.source, sourceObservation);

  let recomputedCompanionClosure;
  try {
    recomputedCompanionClosure = await resolveCompanionClosure({
      source: application.source,
      sourceObservation,
      companionClosure: application.companionClosure
    });
  } catch (error) {
    if (error instanceof PublicIntakeError) throw error;
    if (error instanceof GitHubPublicSourceError) translateSourceResolutionError(error);
    systemBlocked(
      "COMPANION_CLOSURE_RESOLUTION_FAILED",
      "The trusted companion-closure resolver failed unexpectedly."
    );
  }
  if (canonicalJson(recomputedCompanionClosure) !== canonicalJson(application.companionClosure)) {
    reject(
      "COMPANION_CLOSURE_RECEIPT_RECOMPUTE_MISMATCH",
      "Companion closure receipts must equal the trusted result recomputed from exact Git objects and Actions evidence."
    );
  }

  let blobObservations = [];
  if (blobEvidence.length > 0) {
    try {
      blobObservations = await resolveEvidence({
        primary: application.source.primary,
        evidence: blobEvidence,
        limits
      });
    } catch (error) {
      translateEvidenceResolutionError(error);
    }
  }
  const evidenceBindings = validateEvidenceObservations({
    application,
    compatibility,
    evidenceIndex,
    sourceObservation,
    blobObservations
  });
  validateProgrammableFeeSubmissionObservation({
    application,
    evidenceIndex,
    blobObservations,
    legacyPolicyAdapter,
    limits
  });

  return {
    schemaVersion: 1,
    validatorVersion: VALIDATOR_VERSION,
    result: "valid-public-application-package",
    mode: "application",
    intakeState: intakeStatus.state,
    applicationId,
    applicationRevision: application.applicationRevision,
    pullRequestNumber,
    continuationAuthorized: continuation !== null,
    builderIdentity: {
      authentication: "github-pull-request-author",
      immutableGitHubUserId: normalizedBuilderUserId,
      authenticatedLogin: expectedBuilderLogin,
      manifestLogin: application.builder.githubLogin,
      normalizedLogin: normalizedBuilderLogin,
      provesSourceRepositoryOwnership: false
    },
    baseCommit: classified.base.commit,
    candidateCommit: classified.candidate.commit,
    mergeCommit: classified.candidate.mergeCommit,
    sourceBinding: sourceAuthorityProjection(application.source),
    evidenceBindings,
    policyBinding: legacyPolicyAdapter.policyBinding,
    policyProfile: LEGACY_V2_POLICY_PROFILE,
    evaluatedRuleIds: [legacyPolicyAdapter.ruleId],
    evaluatedEvidenceIds: [legacyPolicyAdapter.evidenceId],
    authority: {
      checkerOnly: true,
      independentAudit: false,
      launchAuthorized: false,
      productionDiscoveryAllowed: false,
      publicRoutingAllowed: false,
      realUserFundsAllowed: false,
      workflowCanaryPassed: false
    }
  };
}

function readTrustedIntakeStatus(base) {
  const entry = base.entries.get(INTAKE_STATUS_PATH);
  if (!entry) {
    systemBlocked(
      "INTAKE_STATUS_MISSING",
      `The trusted base revision does not contain ${INTAKE_STATUS_PATH}.`
    );
  }
  if (entry.mode !== "100644" || entry.type !== "blob" || !SHA1_PATTERN.test(entry.oid)) {
    systemBlocked(
      "INTAKE_STATUS_INVALID",
      `The trusted base revision's ${INTAKE_STATUS_PATH} must be a non-executable regular Git blob.`
    );
  }

  const declaredSizeText = runGitText(base.root, ["cat-file", "-s", entry.oid], 128).trim();
  if (!/^(?:0|[1-9][0-9]*)$/u.test(declaredSizeText)) {
    systemBlocked("INTAKE_STATUS_INVALID", "Git returned an invalid trusted intake-status size.");
  }
  const declaredSize = Number(declaredSizeText);
  if (!Number.isSafeInteger(declaredSize) || declaredSize > MAXIMUM_INTAKE_STATUS_BYTES) {
    systemBlocked("INTAKE_STATUS_INVALID", "The trusted intake-status file exceeds its closed byte limit.");
  }
  const bytes = runGit(base.root, ["cat-file", "blob", entry.oid], MAXIMUM_INTAKE_STATUS_BYTES + 1);
  if (bytes.length !== declaredSize) {
    systemBlocked("INTAKE_STATUS_INVALID", "Trusted intake-status bytes do not match their declared Git blob size.");
  }

  let source;
  try {
    source = UTF8_DECODER.decode(bytes);
  } catch {
    systemBlocked("INTAKE_STATUS_INVALID", "The trusted intake-status file is not valid UTF-8.");
  }
  if (hasUnsafeSerializedText(source) || source.includes("\r")) {
    systemBlocked("INTAKE_STATUS_INVALID", "The trusted intake-status file contains unsupported text controls.");
  }

  let status;
  try {
    status = JSON.parse(source);
  } catch {
    systemBlocked("INTAKE_STATUS_INVALID", "The trusted intake-status file is not valid JSON.");
  }
  if (
    !isPlainObject(status)
    || !arraysEqual(
      Object.keys(status).sort(compareUtf8),
      ["continuingPullRequests", "schemaVersion", "state"]
    )
    || status.schemaVersion !== 2
    || !PUBLIC_INTAKE_STATES.includes(status.state)
    || !Array.isArray(status.continuingPullRequests)
    || status.continuingPullRequests.length > MAXIMUM_CONTINUING_PULL_REQUESTS
    || source !== `${canonicalJson(status)}\n`
  ) {
    systemBlocked(
      "INTAKE_STATUS_INVALID",
      "The trusted intake-status file must be closed canonical JSON with schemaVersion 2, a supported state, and a bounded continuation list."
    );
  }
  const continuingPullRequests = validateTrustedContinuations(status.continuingPullRequests);
  if (status.state !== "paused-new" && continuingPullRequests.length !== 0) {
    systemBlocked(
      "INTAKE_STATUS_INVALID",
      "Trusted pull-request continuations may be nonempty only while new application ids are paused."
    );
  }
  return Object.freeze({
    schemaVersion: status.schemaVersion,
    state: status.state,
    continuingPullRequests
  });
}

function validateTrustedContinuations(records) {
  const result = [];
  const pullRequestNumbers = new Set();
  const applicationIds = new Set();
  let previous = null;
  for (const record of records) {
    if (
      !isPlainObject(record)
      || !arraysEqual(Object.keys(record).sort(compareUtf8), [
        "applicationId",
        "builderGitHubUserId",
        "companionNumericRepositoryIds",
        "primaryNumericRepositoryId",
        "pullRequestNumber"
      ])
      || typeof record.applicationId !== "string"
      || !APPLICATION_ID_PATTERN.test(record.applicationId)
      || record.applicationId.length > 80
      || typeof record.builderGitHubUserId !== "string"
      || !OPAQUE_ID_PATTERN.test(record.builderGitHubUserId)
      || typeof record.primaryNumericRepositoryId !== "string"
      || !OPAQUE_ID_PATTERN.test(record.primaryNumericRepositoryId)
      || typeof record.pullRequestNumber !== "string"
      || !PULL_REQUEST_NUMBER_PATTERN.test(record.pullRequestNumber)
      || !Array.isArray(record.companionNumericRepositoryIds)
      || record.companionNumericRepositoryIds.length > MAXIMUM_CONTINUATION_COMPANIONS
    ) {
      systemBlocked("INTAKE_STATUS_INVALID", "A trusted pull-request continuation record is malformed.");
    }
    const companions = record.companionNumericRepositoryIds;
    for (let index = 0; index < companions.length; index += 1) {
      if (
        typeof companions[index] !== "string"
        || !OPAQUE_ID_PATTERN.test(companions[index])
        || (index > 0 && compareUtf8(companions[index - 1], companions[index]) >= 0)
        || companions[index] === record.primaryNumericRepositoryId
      ) {
        systemBlocked(
          "INTAKE_STATUS_INVALID",
          "Trusted continuation companion repository ids must be unique canonical decimal strings in source-contract order."
        );
      }
    }
    if (
      pullRequestNumbers.has(record.pullRequestNumber)
      || applicationIds.has(record.applicationId)
      || (previous !== null && compareContinuations(previous, record) >= 0)
    ) {
      systemBlocked(
        "INTAKE_STATUS_INVALID",
        "Trusted pull-request continuations must be uniquely bound and sorted by pull-request number and application id."
      );
    }
    pullRequestNumbers.add(record.pullRequestNumber);
    applicationIds.add(record.applicationId);
    previous = record;
    result.push(Object.freeze({
      applicationId: record.applicationId,
      builderGitHubUserId: record.builderGitHubUserId,
      companionNumericRepositoryIds: Object.freeze([...companions]),
      primaryNumericRepositoryId: record.primaryNumericRepositoryId,
      pullRequestNumber: record.pullRequestNumber
    }));
  }
  return Object.freeze(result);
}

function enforceTrustedIntakeStatus({ intakeStatus, isUpdate, pullRequestNumber, applicationId }) {
  if (intakeStatus?.state === "open") return null;
  if (intakeStatus?.state === "paused-new" && isUpdate) return null;
  if (intakeStatus?.state === "paused-new" && !isUpdate) {
    const continuation = intakeStatus.continuingPullRequests.find((record) => (
      record.pullRequestNumber === pullRequestNumber && record.applicationId === applicationId
    ));
    if (continuation) return continuation;
  }
  if (intakeStatus?.state === "prelaunch") {
    systemBlocked("INTAKE_PRELAUNCH", "Public Builder Beta applications are not open yet.");
  }
  if (intakeStatus?.state === "paused-new") {
    systemBlocked(
      "INTAKE_PAUSED_NEW",
      "Public Builder Beta intake is paused for new application ids except exact trusted pull-request continuations."
    );
  }
  if (intakeStatus?.state === "paused-all") {
    systemBlocked("INTAKE_PAUSED_ALL", "Public Builder Beta intake is temporarily paused for all application changes.");
  }
  if (intakeStatus?.state === "closed") {
    systemBlocked(
      "INTAKE_CLOSED",
      "GitHub launch intake is retired. Use the Programmable Custom Launch API."
    );
  }
  systemBlocked("INTAKE_STATUS_INVALID", "The trusted intake state could not be enforced.");
}

function enforceTrustedContinuationIdentity({ continuation, application }) {
  if (continuation === null) return;
  const companionIds = application.source.companions.map(({ numericRepositoryId }) => numericRepositoryId);
  if (
    application.applicationId !== continuation.applicationId
    || application.builder.githubUserId !== continuation.builderGitHubUserId
    || application.source.primary.numericRepositoryId !== continuation.primaryNumericRepositoryId
    || !arraysEqual(companionIds, continuation.companionNumericRepositoryIds)
  ) {
    reject(
      "INTAKE_CONTINUATION_IDENTITY_MISMATCH",
      "The paused-new continuation changed its trusted builder or repository lineage."
    );
  }
}

function compareContinuations(left, right) {
  const pullRequestOrder = compareDecimalStrings(left.pullRequestNumber, right.pullRequestNumber);
  return pullRequestOrder === 0 ? compareUtf8(left.applicationId, right.applicationId) : pullRequestOrder;
}

function compareDecimalStrings(left, right) {
  if (left.length !== right.length) return left.length - right.length;
  return left < right ? -1 : left > right ? 1 : 0;
}

function normalizeExpectedBuilderLogin(value) {
  if (typeof value !== "string" || value.length > 39 || !GITHUB_LOGIN_PATTERN.test(value)) {
    systemBlocked(
      "EXPECTED_BUILDER_LOGIN_INVALID",
      "The trusted GitHub pull-request author login is missing or malformed."
    );
  }
  return value.toLowerCase();
}

function normalizeExpectedBuilderUserId(value) {
  if (typeof value !== "string" || !OPAQUE_ID_PATTERN.test(value)) {
    systemBlocked(
      "EXPECTED_BUILDER_ID_INVALID",
      "The trusted GitHub pull-request author id is missing or malformed."
    );
  }
  return value;
}

export function validatePublicApplicationPackageFiles({
  applicationId,
  packageFiles,
  legacyPolicyAdapter,
  limits: limitOverrides = {}
}) {
  requireLegacyV2PolicyAdapter(legacyPolicyAdapter);
  const limits = mergeLimits(limitOverrides);
  if (
    !(packageFiles instanceof Map)
    || !arraysEqual([...packageFiles.keys()].sort(compareUtf8), [...APPLICATION_FILES].sort(compareUtf8))
  ) {
    reject("APPLICATION_PACKAGE_NOT_CLOSED", "The pure package validator requires exactly the six frozen application files.");
  }
  let packageBytes = 0;
  for (const [fileName, bytes] of packageFiles) {
    if (!Buffer.isBuffer(bytes)) systemBlocked("PACKAGE_BYTES_INVALID", "The pure package validator requires Buffer values.");
    if (bytes.length > limits.maximumFileBytes[fileName]) reject("APPLICATION_FILE_TOO_LARGE", "An application package file exceeds its trusted byte limit.");
    packageBytes += bytes.length;
  }
  if (packageBytes > limits.maximumPackageBytes) {
    reject("APPLICATION_PACKAGE_TOO_LARGE", "The application review package exceeds the trusted byte limit.");
  }
  const application = parseCanonicalJson(packageFiles.get(APPLICATION_FILE), APPLICATION_FILE, limits);
  validateApplicationManifest(application, applicationId, limits, legacyPolicyAdapter);
  const compatibility = parseCanonicalJson(
    packageFiles.get("compatibility-report.json"),
    "compatibility-report.json",
    limits
  );
  const evidenceIndex = parseCanonicalJson(packageFiles.get("evidence-index.json"), "evidence-index.json", limits);
  const evidenceIds = validateEvidenceIndex(evidenceIndex, application, limits);
  validateProgrammableFeeSubmissionEvidence(evidenceIndex, application, legacyPolicyAdapter);
  validateCompatibilityReport(compatibility, application, evidenceIndex, evidenceIds, limits);
  validateProgrammableFeeCompatibility(application, compatibility);
  validateReviewPackageHashes(application, packageFiles);
  const markdownSources = new Map([
    ["PROPOSAL.md", validateMarkdown(packageFiles.get("PROPOSAL.md"), "PROPOSAL.md", "# Proposal")],
    ["THREAT_MODEL.md", validateMarkdown(packageFiles.get("THREAT_MODEL.md"), "THREAT_MODEL.md", "# Threat model")],
    ["TEST_PLAN.md", validateMarkdown(packageFiles.get("TEST_PLAN.md"), "TEST_PLAN.md", "# Test plan")]
  ]);
  validatePublicClaims({ application, compatibility, evidenceIndex, markdownSources });
  return { application, compatibility, evidenceIndex };
}

export function inspectMaintainedSubmissions({
  repositoryRoot,
  maximumLegacyPackages = MAXIMUM_MAINTAINED_LEGACY_PACKAGES
}) {
  if (typeof repositoryRoot !== "string" || repositoryRoot.length === 0) {
    systemBlocked(
      "MAINTAINED_REPOSITORY_ROOT_INVALID",
      "Maintained submission verification requires an explicit repository root."
    );
  }
  if (!Number.isInteger(maximumLegacyPackages) || maximumLegacyPackages < 0) {
    systemBlocked(
      "MAINTAINED_LEGACY_LIMIT_INVALID",
      "The maintained legacy-package limit must be a non-negative integer."
    );
  }

  const resolvedRepositoryRoot = path.resolve(repositoryRoot);
  const submissionRoot = path.join(resolvedRepositoryRoot, "submissions");
  const rootStatus = lstatIfPresent(submissionRoot);
  if (!rootStatus || rootStatus.isSymbolicLink() || !rootStatus.isDirectory()) {
    systemBlocked(
      "MAINTAINED_SUBMISSIONS_ROOT_INVALID",
      "The trusted revision must contain a regular submissions directory."
    );
  }

  const applications = [];
  const applicationV3Revisions = [];
  const legacyPackages = [];
  const entries = fs.readdirSync(submissionRoot, { withFileTypes: true })
    .sort((left, right) => compareUtf8(left.name, right.name));

  for (const entry of entries) {
    const entryPath = path.join(submissionRoot, entry.name);
    if (entry.name === "README.md") {
      const readmeStatus = lstatIfPresent(entryPath);
      if (!readmeStatus || readmeStatus.isSymbolicLink() || !readmeStatus.isFile()) {
        systemBlocked(
          "MAINTAINED_SUBMISSION_ENTRY_INVALID",
          "submissions/README.md must be a regular file."
        );
      }
      continue;
    }
    if (entry.isSymbolicLink() || !entry.isDirectory()) {
      systemBlocked(
        "MAINTAINED_SUBMISSION_ENTRY_INVALID",
        `Unexpected maintained intake entry submissions/${entry.name}; only package directories and README.md are allowed.`
      );
    }

    const applicationManifest = path.join(entryPath, APPLICATION_FILE);
    const manifestStatus = lstatIfPresent(applicationManifest);
    const v3Root = path.join(entryPath, "v3");
    const v3Status = lstatIfPresent(v3Root);
    if (!manifestStatus && !v3Status) {
      legacyPackages.push({ name: entry.name, path: entryPath });
      continue;
    }
    if (manifestStatus && (manifestStatus.isSymbolicLink() || !manifestStatus.isFile())) {
      systemBlocked(
        "MAINTAINED_APPLICATION_FILE_INVALID",
        `Maintained application ${entry.name} has a non-regular application.json.`
      );
    }
    if (manifestStatus) {
      assertClosedMaintainedApplication(entryPath, entry.name, { allowV3: Boolean(v3Status) });
      applications.push({ name: entry.name, path: entryPath });
    }
    if (v3Status) {
      applicationV3Revisions.push(...inspectMaintainedApplicationV3Revisions({
        applicationId: entry.name,
        applicationRoot: entryPath,
        allowLegacyV2: Boolean(manifestStatus)
      }));
    }
  }

  if (legacyPackages.length > maximumLegacyPackages) {
    systemBlocked(
      "MAINTAINED_LEGACY_PACKAGE_LIMIT_EXCEEDED",
      `Maintained intake contains ${legacyPackages.length} legacy packages; the trusted validation limit is ${maximumLegacyPackages}.`
    );
  }

  return {
    repositoryRoot: resolvedRepositoryRoot,
    submissionRoot,
    applications,
    applicationV3Revisions,
    legacyPackages
  };
}

export async function verifyMaintainedSubmissions({
  repositoryRoot,
  maximumLegacyPackages = MAXIMUM_MAINTAINED_LEGACY_PACKAGES,
  validateLegacyPackage
}) {
  if (typeof validateLegacyPackage !== "function") {
    systemBlocked(
      "MAINTAINED_LEGACY_VALIDATOR_UNAVAILABLE",
      "Maintained submission verification requires the trusted legacy-package validator."
    );
  }
  const inventory = inspectMaintainedSubmissions({ repositoryRoot, maximumLegacyPackages });
  for (const legacyPackage of inventory.legacyPackages) {
    await validateLegacyPackage({
      repositoryRoot: inventory.repositoryRoot,
      packageName: legacyPackage.name,
      packageRoot: legacyPackage.path
    });
  }
  const histories = new Map();
  for (const revision of inventory.applicationV3Revisions) {
    const history = histories.get(revision.applicationId) ?? [];
    history.push(revision);
    histories.set(revision.applicationId, history);
  }
  for (const revisions of histories.values()) {
    validateMaintainedApplicationV3History(revisions);
  }
  return {
    schemaVersion: 1,
    result: "valid-maintained-submissions",
    applicationCount: inventory.applications.length,
    applicationV3RevisionCount: inventory.applicationV3Revisions.length,
    legacyPackageCount: inventory.legacyPackages.length,
    validatedLegacyPackages: inventory.legacyPackages.map((entry) => entry.name)
  };
}

function assertClosedMaintainedApplication(packageRoot, applicationId, { allowV3 = false } = {}) {
  const entries = fs.readdirSync(packageRoot, { withFileTypes: true })
    .sort((left, right) => compareUtf8(left.name, right.name));
  const observedNames = entries.map((entry) => entry.name);
  const expectedNames = [...APPLICATION_FILES, ...(allowV3 ? ["v3"] : [])].sort(compareUtf8);
  if (!arraysEqual(observedNames, expectedNames)) {
    systemBlocked(
      "MAINTAINED_APPLICATION_PACKAGE_NOT_CLOSED",
      `Maintained application ${applicationId} must contain exactly the six public application files.`
    );
  }
  for (const entry of entries.filter(({ name }) => name !== "v3")) {
    const fileStatus = lstatIfPresent(path.join(packageRoot, entry.name));
    if (!fileStatus || fileStatus.isSymbolicLink() || !fileStatus.isFile()) {
      systemBlocked(
        "MAINTAINED_APPLICATION_FILE_INVALID",
        `Maintained application ${applicationId} contains a non-regular package file.`
      );
    }
  }
}

function inspectMaintainedApplicationV3Revisions({ applicationId, applicationRoot, allowLegacyV2 }) {
  const observedApplicationEntries = fs.readdirSync(applicationRoot, { withFileTypes: true })
    .map(({ name }) => name)
    .sort(compareUtf8);
  const expectedApplicationEntries = [...(allowLegacyV2 ? APPLICATION_FILES : []), "v3"].sort(compareUtf8);
  if (!arraysEqual(observedApplicationEntries, expectedApplicationEntries)) {
    systemBlocked(
      "MAINTAINED_APPLICATION_V3_HIERARCHY_INVALID",
      `Maintained Application V3 ${applicationId} contains an unexpected sibling outside its immutable history.`
    );
  }
  const v3Root = path.join(applicationRoot, "v3");
  const v3Status = lstatIfPresent(v3Root);
  const revisionsRoot = path.join(v3Root, "revisions");
  const revisionsStatus = lstatIfPresent(revisionsRoot);
  if (
    !v3Status || v3Status.isSymbolicLink() || !v3Status.isDirectory()
    || !revisionsStatus || revisionsStatus.isSymbolicLink() || !revisionsStatus.isDirectory()
    || !arraysEqual(fs.readdirSync(v3Root).sort(compareUtf8), ["revisions"])
  ) {
    systemBlocked("MAINTAINED_APPLICATION_V3_HIERARCHY_INVALID", "Maintained Application V3 history must use only v3/revisions.");
  }
  const revisions = fs.readdirSync(revisionsRoot, { withFileTypes: true })
    .sort((left, right) => compareCanonicalDecimal(left.name, right.name));
  if (revisions.length < 1 || revisions.length > 10_000) {
    systemBlocked("MAINTAINED_APPLICATION_V3_REVISION_LIMIT", "Maintained Application V3 history has an invalid revision count.");
  }
  return revisions.map((entry) => {
    const revisionRoot = path.join(revisionsRoot, entry.name);
    if (!positiveDecimalString(entry.name) || entry.isSymbolicLink() || !entry.isDirectory()) {
      systemBlocked("MAINTAINED_APPLICATION_V3_HIERARCHY_INVALID", "Maintained Application V3 revision names must be canonical positive decimals.");
    }
    return {
      applicationId,
      applicationRevision: entry.name,
      revisionRoot,
      legacyPackageRoot: allowLegacyV2 ? applicationRoot : null
    };
  });
}

function validateMaintainedApplicationV3History(revisions) {
  if (!Array.isArray(revisions) || revisions.length < 1) {
    systemBlocked("MAINTAINED_APPLICATION_V3_HISTORY_INVALID", "Maintained Application V3 history is unavailable.");
  }
  revisions.sort((left, right) => compareCanonicalDecimal(left.applicationRevision, right.applicationRevision));
  const legacyPackageRoot = revisions[0].legacyPackageRoot;
  let expectedRevision = legacyPackageRoot === null
    ? "1"
    : incrementCanonicalDecimal(String(readMaintainedLegacyV2Application(legacyPackageRoot).applicationRevision));
  let previous = null;
  for (const revision of revisions) {
    if (revision.applicationRevision !== expectedRevision) {
      systemBlocked(
        "MAINTAINED_APPLICATION_V3_HISTORY_GAP",
        "Maintained Application V3 history must contain every canonical revision exactly once."
      );
    }
    const current = validateMaintainedApplicationV3Revision(revision);
    if (previous === null && legacyPackageRoot === null) {
      if (
        current.application.lineage.kind !== "new"
        || current.application.lineage.previous !== null
        || current.application.applicationRevision !== "1"
      ) {
        systemBlocked("MAINTAINED_APPLICATION_V3_LINEAGE_INVALID", "A maintained V3-only history must start at revision 1 with null new lineage.");
      }
    } else if (previous === null) {
      const legacyPrevious = deriveMaintainedLegacyV2PreviousBinding({
        applicationId: current.application.applicationId,
        packageRoot: legacyPackageRoot,
        claimedSubmissionSchemaId: current.application.lineage.previous?.submissionSchemaId
      });
      if (
        current.application.lineage.kind !== "schema-migration"
        || canonicalJson(current.application.lineage.previous) !== canonicalJson(legacyPrevious.binding)
        || String(current.application.builder.githubUserId) !== String(legacyPrevious.builderGithubUserId)
      ) {
        systemBlocked("MAINTAINED_APPLICATION_V3_LINEAGE_INVALID", "Maintained Application V3 migration lineage differs from the exact legacy V2 package.");
      }
    } else {
      const expectedPrevious = derivePublicPrApplicationV3PreviousBinding({
        application: previous.application,
        applicationSha256: previous.applicationSha256,
        packageSha256: previous.packageSha256,
        targetContractVersion: current.application.contract.version
      });
      if (
        canonicalJson(current.application.lineage.previous) !== canonicalJson(expectedPrevious)
        || String(current.application.builder.githubUserId) !== String(previous.application.builder.githubUserId)
      ) {
        systemBlocked("MAINTAINED_APPLICATION_V3_LINEAGE_INVALID", "Maintained Application V3 lineage differs from the exact immediately preceding V3 package.");
      }
      if (previous.application.contract.version === "3.2.0" && current.application.contract.version === "3.1.0") {
        systemBlocked("MAINTAINED_APPLICATION_V3_CONTRACT_DOWNGRADE", "Maintained Application V3 history cannot downgrade from V3.2 to V3.1.");
      }
    }
    previous = current;
    expectedRevision = incrementCanonicalDecimal(expectedRevision);
  }
}

function validateMaintainedApplicationV3Revision({ applicationId, applicationRevision, revisionRoot }) {
  const packageFiles = new Map();
  const pending = [{ absolute: revisionRoot, relative: "" }];
  while (pending.length > 0) {
    const current = pending.pop();
    const entries = fs.readdirSync(current.absolute, { withFileTypes: true }).sort((left, right) => compareUtf8(left.name, right.name));
    for (const entry of entries) {
      const absolute = path.join(current.absolute, entry.name);
      const relative = current.relative === "" ? entry.name : `${current.relative}/${entry.name}`;
      const status = lstatIfPresent(absolute);
      if (!status || status.isSymbolicLink()) {
        systemBlocked("MAINTAINED_APPLICATION_V3_FILE_INVALID", "Maintained Application V3 packages cannot contain symlinks.");
      }
      if (status.isDirectory()) {
        pending.push({ absolute, relative });
      } else if (status.isFile() && isSafeApplicationV3PackagePath(relative)) {
        const maximumBytes = relative === APPLICATION_V3_ROOT_FILE
          ? MAXIMUM_APPLICATION_V3_MANIFEST_BYTES
          : MAXIMUM_APPLICATION_V3_FILE_BYTES;
        if (status.size < 1 || status.size > maximumBytes) {
          systemBlocked("MAINTAINED_APPLICATION_V3_FILE_INVALID", "A maintained Application V3 file exceeds its trusted byte limit.");
        }
        packageFiles.set(relative, fs.readFileSync(absolute));
      } else {
        systemBlocked("MAINTAINED_APPLICATION_V3_FILE_INVALID", "Maintained Application V3 packages contain only safe regular files and directories.");
      }
      if (packageFiles.size > MAXIMUM_APPLICATION_V3_PACKAGE_FILES) {
        systemBlocked("MAINTAINED_APPLICATION_V3_FILE_LIMIT", "A maintained Application V3 revision exceeds the trusted file-count limit.");
      }
    }
  }
  const rootBytes = packageFiles.get(APPLICATION_V3_ROOT_FILE);
  let builder;
  try {
    builder = JSON.parse(UTF8_DECODER.decode(rootBytes)).builder;
  } catch {
    systemBlocked("MAINTAINED_APPLICATION_V3_ROOT_INVALID", "A maintained Application V3 root is not valid UTF-8 JSON.");
  }
  try {
    const validated = validatePublicApplicationV3PackageFiles({
      applicationId,
      applicationRevision,
      packageFiles,
      expectedBuilderLogin: builder?.githubLogin,
      expectedBuilderUserId: builder?.githubUserId
    });
    const applicationBytes = packageFiles.get(APPLICATION_V3_ROOT_FILE);
    const targetDirectory = `submissions/${applicationId}/v3/revisions/${applicationRevision}`;
    const files = [{
      path: `${targetDirectory}/${APPLICATION_V3_ROOT_FILE}`,
      mediaType: "application/json",
      byteLength: applicationBytes.length,
      sha256: sha256BytesV3(applicationBytes)
    }, ...validated.applicationRecords.map((record) => ({
      ...record,
      path: `${targetDirectory}/${record.path}`
    }))].sort((left, right) => compareUtf8(left.path, right.path));
    return Object.freeze({
      application: validated.application,
      applicationSha256: sha256BytesV3(applicationBytes),
      packageSha256: sha256CanonicalV3({
        contract: "public-pr-application-v3-package",
        applicationId,
        applicationRevision,
        targetDirectory,
        files
      })
    });
  } catch (error) {
    if (error instanceof PublicApplicationV3IntakeError) {
      systemBlocked("MAINTAINED_APPLICATION_V3_INVALID", "A maintained Application V3 revision fails its accepted root or package contract.");
    }
    throw error;
  }
}

function readMaintainedLegacyV2Application(packageRoot) {
  const bytes = fs.readFileSync(path.join(packageRoot, APPLICATION_FILE));
  try {
    return parseCanonicalJson(bytes, "maintained legacy V2 application", mergeLimits({}));
  } catch (error) {
    if (error instanceof PublicIntakeError) {
      systemBlocked("MAINTAINED_APPLICATION_V2_INVALID", "The maintained legacy V2 predecessor manifest is not bounded canonical JSON.");
    }
    throw error;
  }
}

function deriveMaintainedLegacyV2PreviousBinding({
  applicationId,
  packageRoot,
  claimedSubmissionSchemaId
}) {
  const application = readMaintainedLegacyV2Application(packageRoot);
  const applicationDirectory = `submissions/${applicationId}`;
  const packageFiles = new Map(APPLICATION_FILES.map((fileName) => [
    fileName,
    fs.readFileSync(path.join(packageRoot, fileName))
  ]));
  const source = application?.source?.primary;
  const fee = application?.programmableFee;
  if (
    application?.schemaVersion !== 2
    || application?.applicationId !== applicationId
    || !Number.isSafeInteger(application?.applicationRevision)
    || application.applicationRevision < 1
    || !isPlainObject(source)
    || !isPlainObject(fee)
    || !isPlainObject(fee.submissionBinding)
    || !new Set([null, "urn:programmable:v4-hook-submission:1.6.0"]).has(claimedSubmissionSchemaId)
  ) {
    systemBlocked("MAINTAINED_APPLICATION_V2_INVALID", "The maintained legacy V2 predecessor cannot derive the required V3 lineage binding.");
  }
  const records = APPLICATION_FILES.map((fileName) => {
    const bytes = packageFiles.get(fileName);
    return { path: fileName, byteLength: bytes.length, sha256: sha256BytesV3(bytes) };
  });
  const binding = Object.freeze({
    applicationContract: "public-pr-application-v2",
    applicationSchemaVersion: 2,
    applicationRevision: String(application.applicationRevision),
    applicationSha256: sha256BytesV3(packageFiles.get(APPLICATION_FILE)),
    packageSha256: sha256CanonicalV3({
      applicationDirectory,
      applicationRevision: application.applicationRevision,
      files: records
    }),
    sourceNumericRepositoryId: source.numericRepositoryId,
    sourceCommit: source.revisionObjectId,
    sourceTree: source.treeObjectId,
    submissionSchemaId: claimedSubmissionSchemaId,
    submissionStandard: "1.6.0",
    submissionPath: fee.submissionBinding.path,
    submissionSha256: fee.submissionBinding.sha256,
    feePolicyId: fee.policyId,
    feePolicyVersion: fee.policyVersion,
    feeApplicability: "applicable",
    feePolicyInstanceSha256: null
  });
  return Object.freeze({ binding, builderGithubUserId: application.builder?.githubUserId });
}

function positiveDecimalString(value) {
  return /^[1-9][0-9]*$/u.test(value);
}

function lstatIfPresent(target) {
  try {
    return fs.lstatSync(target);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

function mergeLimits(overrides) {
  if (!isPlainObject(overrides)) systemBlocked("LIMITS_INVALID", "Trusted validator limits must be an object.");
  return {
    ...DEFAULT_LIMITS,
    ...overrides,
    maximumFileBytes: {
      ...DEFAULT_LIMITS.maximumFileBytes,
      ...(isPlainObject(overrides.maximumFileBytes) ? overrides.maximumFileBytes : {})
    }
  };
}

function compareGitRevisions({
  baseRoot,
  candidateRoot,
  expectedBaseCommit,
  expectedCandidateCommit,
  expectedMergeCommit,
  limits
}) {
  const base = inspectGitRevision(baseRoot, expectedBaseCommit, limits);
  const candidate = inspectPullRequestMergeRevision(candidateRoot, {
    expectedBaseCommit,
    expectedCandidateCommit,
    expectedMergeCommit,
    limits
  });
  const allPaths = [...new Set([...base.entries.keys(), ...candidate.entries.keys()])].sort(compareUtf8);
  const changes = [];
  for (const entryPath of allPaths) {
    const before = base.entries.get(entryPath) ?? null;
    const after = candidate.entries.get(entryPath) ?? null;
    if (before && after && before.mode === after.mode && before.type === after.type && before.oid === after.oid) continue;
    changes.push({
      path: entryPath,
      status: before === null ? "added" : after === null ? "deleted" : "modified",
      before,
      after
    });
  }
  if (changes.length > limits.maximumChangedFiles) {
    reject("TOO_MANY_CHANGED_FILES", "The pull request exceeds the trusted changed-file limit.");
  }
  return { base, candidate, changes };
}

function inspectPullRequestMergeRevision(rootInput, {
  expectedBaseCommit,
  expectedCandidateCommit,
  expectedMergeCommit,
  limits
}) {
  const { root, mergeCommit } = inspectExactPullRequestMergeIdentity(rootInput, {
    expectedBaseCommit,
    expectedCandidateCommit,
    expectedMergeCommit
  });
  const output = runGit(root, ["ls-tree", "-rz", "--full-tree", "HEAD"], limits.maximumGitTreeBytes);
  const entries = parseGitTree(output, limits);
  return {
    root,
    commit: expectedCandidateCommit,
    mergeCommit,
    entries
  };
}

/**
 * Bind the fetched GitHub-owned refs/pull/N/merge object directly to the exact
 * workflow base and head. GitHub API version 2026-03-10 intentionally omits
 * merge_commit_sha, so the immutable Git object and its ordered parents are
 * the source of truth instead of mutable or removed REST response metadata.
 */
function inspectExactPullRequestMergeIdentity(rootInput, {
  expectedBaseCommit,
  expectedCandidateCommit,
  expectedMergeCommit = null
}) {
  for (const [label, commit] of [
    ["base", expectedBaseCommit],
    ["candidate", expectedCandidateCommit]
  ]) {
    if (!SHA1_PATTERN.test(commit ?? "")) {
      systemBlocked("EXPECTED_COMMIT_INVALID", `The workflow did not provide an exact lowercase ${label} commit id.`);
    }
  }
  if (expectedMergeCommit !== null && !SHA1_PATTERN.test(expectedMergeCommit ?? "")) {
    systemBlocked("EXPECTED_COMMIT_INVALID", "The workflow did not provide an exact lowercase merge commit id.");
  }

  const root = resolveGitRoot(rootInput);
  const mergeCommit = runGitText(root, ["rev-parse", "HEAD^{commit}"], 1024).trim();
  if (!SHA1_PATTERN.test(mergeCommit)) {
    systemBlocked("PR_MERGE_COMMIT_MALFORMED", "GitHub's PR merge ref did not resolve to one exact SHA-1 commit id.");
  }
  if (expectedMergeCommit !== null && mergeCommit !== expectedMergeCommit) {
    systemBlocked("CHECKOUT_COMMIT_MISMATCH", "The candidate-data checkout does not match GitHub's immutable PR merge commit.");
  }

  const commitObject = runGitText(root, ["cat-file", "-p", `${mergeCommit}^{commit}`], 1024 * 1024);
  const headerEnd = commitObject.indexOf("\n\n");
  if (headerEnd === -1) {
    systemBlocked("PR_MERGE_COMMIT_MALFORMED", "GitHub's PR merge commit has no canonical commit header boundary.");
  }
  const headerLines = commitObject.slice(0, headerEnd).split("\n");
  const treeLines = headerLines.filter((line) => line.startsWith("tree "));
  const parentLines = headerLines.filter((line) => line.startsWith("parent "));
  if (
    treeLines.length !== 1
    || !/^tree [a-f0-9]{40}$/u.test(treeLines[0])
    || parentLines.length !== 2
    || parentLines.some((line) => !/^parent [a-f0-9]{40}$/u.test(line))
  ) {
    systemBlocked("PR_MERGE_PARENT_CONTRACT_INVALID", "GitHub's PR merge commit does not have one tree and exactly two canonical parents.");
  }
  const parents = parentLines.map((line) => line.slice("parent ".length));
  if (parents[0] !== expectedBaseCommit || parents[1] !== expectedCandidateCommit) {
    systemBlocked("PR_MERGE_PARENT_MISMATCH", "GitHub's PR merge parents do not match the event's exact base and head commits.");
  }
  return { root, mergeCommit };
}

/**
 * Recover one unpublished V3 predecessor only from the exact PR head that was
 * authenticated as parent 2 of GitHub's merge ref. The protected base remains
 * authoritative whenever it already contains application history.
 */
function deriveAuthenticatedOpenDraftApplicationV3Predecessor({
  base,
  candidate,
  applicationId,
  applicationRevision,
  limits
}) {
  if (
    inspectTrustedBaseApplicationV3History(base, applicationId).length > 0
    || hasTrustedLegacyV2Application(base, applicationId)
    || applicationRevision === "1"
  ) return null;

  const previousRevision = decrementCanonicalDecimal(applicationRevision);
  if (previousRevision === null) {
    reject("APPLICATION_V3_LINEAGE_MISMATCH", "An unpublished Draft revision must have one exact preceding revision.");
  }
  const root = candidate.root;
  const mergeBases = runGitText(
    root,
    ["merge-base", "--all", base.commit, candidate.commit],
    4096
  ).trim().split("\n").filter(Boolean);
  if (mergeBases.length !== 1 || mergeBases[0] !== base.commit) {
    reject("APPLICATION_V3_DRAFT_HISTORY_INVALID", "The authenticated Draft head does not have the exact protected base as its unique merge base.");
  }
  const commits = runGitText(
    root,
    ["rev-list", "--first-parent", "--reverse", `${base.commit}..${candidate.commit}`],
    (MAXIMUM_APPLICATION_V3_OPEN_DRAFT_COMMITS + 1) * 41
  ).trim().split("\n").filter(Boolean);
  if (
    commits.length < 1
    || commits.length > MAXIMUM_APPLICATION_V3_OPEN_DRAFT_COMMITS
    || commits.at(-1) !== candidate.commit
    || commits.some((commit) => !SHA1_PATTERN.test(commit))
  ) {
    reject("APPLICATION_V3_DRAFT_HISTORY_INVALID", "The authenticated Draft first-parent history is missing or exceeds its trusted commit bound.");
  }

  const prefix = `submissions/${applicationId}/`;
  let phase = "empty";
  let previousState = inspectApplicationV3DraftHistoryState({
    root,
    commit: base.commit,
    applicationId,
    allowedRevisions: new Set([previousRevision, applicationRevision]),
    limits
  });
  if (previousState.key !== "") {
    systemBlocked("INTAKE_BASE_APPLICATION_V3_INVALID", "The protected base application state disagrees with its trusted history classification.");
  }
  let predecessor = null;
  let predecessorFingerprint = null;
  let currentFingerprint = null;

  for (const commit of commits) {
    const state = inspectApplicationV3DraftHistoryState({
      root,
      commit,
      applicationId,
      allowedRevisions: new Set([previousRevision, applicationRevision]),
      limits
    });
    const targetChanged = state.key !== previousState.key
      || [...state.revisions].some(([revision, record]) => previousState.revisions.get(revision)?.fingerprint !== record.fingerprint);
    const parents = readCommitParents(root, commit);
    if (targetChanged) {
      if (parents.length !== 1) {
        reject("APPLICATION_V3_DRAFT_HISTORY_INVALID", "A merge commit cannot introduce, remove, or substitute unpublished application bytes.");
      }
      const paths = runGitText(
        root,
        ["diff-tree", "--no-commit-id", "--name-only", "-r", "--no-renames", parents[0], commit],
        limits.maximumGitTreeBytes
      ).split("\n").filter(Boolean);
      if (paths.length < 1 || paths.some((entryPath) => !entryPath.startsWith(prefix))) {
        reject("APPLICATION_V3_DRAFT_HISTORY_INVALID", "A commit that changes unpublished application history must be confined to that exact application.");
      }
    } else if (parents.length > 1) {
      if (
        parents.length !== 2
        || !gitIsAncestor(root, parents[1], base.commit)
      ) {
        reject("APPLICATION_V3_DRAFT_HISTORY_INVALID", "A Draft base-sync merge is not anchored in the exact protected-base ancestry.");
      }
    }

    const prior = state.revisions.get(previousRevision) ?? null;
    const current = state.revisions.get(applicationRevision) ?? null;
    if (prior !== null) {
      if (predecessorFingerprint !== null && predecessorFingerprint !== prior.fingerprint) {
        reject("APPLICATION_V3_DRAFT_HISTORY_INVALID", "The unpublished predecessor revision was substituted in Draft history.");
      }
      predecessorFingerprint = prior.fingerprint;
      predecessor = { commit, revision: previousRevision, entries: prior.entries };
    }
    if (current !== null) {
      if (currentFingerprint !== null && currentFingerprint !== current.fingerprint) {
        reject("APPLICATION_V3_DRAFT_HISTORY_INVALID", "The current unpublished revision drifted in Draft history.");
      }
      currentFingerprint = current.fingerprint;
    }

    const nextPhase = state.key === previousRevision
      ? "previous"
      : state.key === `${previousRevision},${applicationRevision}`
        ? "transition"
        : state.key === applicationRevision
          ? "current"
          : state.key === ""
            ? "empty"
            : "invalid";
    const allowedTransition = (
      (phase === "empty" && (nextPhase === "empty" || nextPhase === "previous"))
      || (phase === "previous" && (nextPhase === "previous" || nextPhase === "transition"))
      || (phase === "transition" && (nextPhase === "transition" || nextPhase === "current"))
      || (phase === "current" && nextPhase === "current")
    );
    if (!allowedTransition) {
      reject("APPLICATION_V3_DRAFT_HISTORY_INVALID", "Unpublished revision history is not the monotonic previous-to-current Draft transition.");
    }
    phase = nextPhase;
    previousState = state;
  }
  if (phase !== "current" || predecessor === null || currentFingerprint === null) {
    reject("APPLICATION_V3_DRAFT_HISTORY_INVALID", "The exact Draft history does not close from one predecessor to one current revision.");
  }
  return predecessor;
}

function inspectApplicationV3DraftHistoryState({ root, commit, applicationId, allowedRevisions, limits }) {
  const prefix = `submissions/${applicationId}/`;
  const output = runGit(root, ["ls-tree", "-rz", "--full-tree", "-r", commit, "--", prefix], limits.maximumGitTreeBytes);
  const allEntries = parseGitTree(output, limits);
  const revisions = new Map();
  for (const entry of allEntries.values()) {
    const match = APPLICATION_V3_PATH_PATTERN.exec(entry.path);
    if (
      !match
      || match[1] !== applicationId
      || !allowedRevisions.has(match[2])
      || !isSafeApplicationV3PackagePath(match[3])
    ) {
      reject("APPLICATION_V3_DRAFT_HISTORY_INVALID", "Draft history contains an unrelated, legacy, or non-adjacent application entry.");
    }
    assertRegularBlob(entry);
    const record = revisions.get(match[2]) ?? [];
    record.push(entry);
    revisions.set(match[2], record);
  }
  const normalized = new Map();
  for (const [revision, entries] of [...revisions].sort(([left], [right]) => compareCanonicalDecimal(left, right))) {
    entries.sort((left, right) => compareUtf8(left.path, right.path));
    const rootPath = `${prefix}v3/revisions/${revision}/${APPLICATION_V3_ROOT_FILE}`;
    if (!entries.some((entry) => entry.path === rootPath) || entries.length > MAXIMUM_APPLICATION_V3_PACKAGE_FILES) {
      reject("APPLICATION_V3_DRAFT_HISTORY_INVALID", "A Draft-history revision is not one bounded closed package.");
    }
    normalized.set(revision, {
      entries,
      fingerprint: entries.map(({ path: entryPath, mode, type, oid }) => `${entryPath}\0${mode}\0${type}\0${oid}`).join("\n")
    });
  }
  return { revisions: normalized, key: [...normalized.keys()].join(",") };
}

function readCommitParents(root, commit) {
  const record = runGitText(root, ["rev-list", "--parents", "-n", "1", commit], 4096).trim().split(" ");
  if (record[0] !== commit || record.slice(1).some((parent) => !SHA1_PATTERN.test(parent))) {
    systemBlocked("APPLICATION_V3_DRAFT_HISTORY_INVALID", "Git returned malformed Draft commit ancestry.");
  }
  return record.slice(1);
}

function gitIsAncestor(root, ancestor, descendant) {
  const result = childProcess.spawnSync(
    "git",
    ["-c", "core.hooksPath=/dev/null", "-c", "credential.helper=", "-C", root, "merge-base", "--is-ancestor", ancestor, descendant],
    { encoding: null, shell: false, timeout: TRUSTED_GIT_TIMEOUT_MS, killSignal: "SIGKILL", env: trustedGitEnvironment() }
  );
  if (result.error || !new Set([0, 1]).has(result.status)) {
    systemBlocked("GIT_COMMAND_FAILED", "A fixed trusted Git ancestry check failed.");
  }
  return result.status === 0;
}

function inspectGitRevision(rootInput, expectedCommit, limits) {
  const root = resolveGitRoot(rootInput);
  if (!SHA1_PATTERN.test(expectedCommit ?? "")) {
    systemBlocked("EXPECTED_COMMIT_INVALID", "The workflow did not provide an exact lowercase 40-hex commit id.");
  }
  const commit = runGitText(root, ["rev-parse", "HEAD^{commit}"], 1024).trim();
  if (commit !== expectedCommit) {
    systemBlocked("CHECKOUT_COMMIT_MISMATCH", "A checkout does not match the immutable commit supplied by GitHub.");
  }
  const output = runGit(root, ["ls-tree", "-rz", "--full-tree", "HEAD"], limits.maximumGitTreeBytes);
  const entries = parseGitTree(output, limits);
  return { root, commit, entries };
}

function resolveGitRoot(rootInput) {
  const root = path.resolve(rootInput ?? "");
  if (!rootInput || !fs.statSync(root, { throwIfNoEntry: false })?.isDirectory()) {
    systemBlocked("GIT_ROOT_INVALID", "A trusted checkout root is missing or is not a directory.");
  }
  return root;
}

function parseGitTree(output, limits) {
  const entries = new Map();
  let offset = 0;
  while (offset < output.length) {
    const terminator = output.indexOf(0, offset);
    if (terminator === -1) systemBlocked("GIT_TREE_MALFORMED", "The trusted Git tree output is not NUL terminated.");
    const recordBytes = output.subarray(offset, terminator);
    offset = terminator + 1;
    if (recordBytes.length === 0) continue;
    let record;
    try {
      record = UTF8_DECODER.decode(recordBytes);
    } catch {
      reject("GIT_PATH_NOT_UTF8", "A changed Git path is not valid UTF-8.");
    }
    const match = /^(\d{6}) (blob|commit|tree) ([a-f0-9]{40})\t(.+)$/.exec(record);
    if (!match) systemBlocked("GIT_TREE_MALFORMED", "The trusted Git tree output contains an invalid record.");
    const [, mode, type, oid, entryPath] = match;
    validateGitPath(entryPath);
    if (entries.has(entryPath)) systemBlocked("GIT_TREE_DUPLICATE_PATH", "The Git tree contains a duplicate path.");
    entries.set(entryPath, { mode, type, oid, path: entryPath });
    if (entries.size > limits.maximumGitEntries) {
      reject("GIT_TREE_TOO_LARGE", "The candidate tree exceeds the trusted entry limit.");
    }
  }
  return entries;
}

function validateGitPath(entryPath) {
  if (!isCanonicalGitHubRepositoryPathV1(entryPath)) {
    reject("GIT_PATH_UNSAFE", "A changed Git path is outside the safe canonical path subset.");
  }
}

function rejectUnsafeChangedEntries(changes) {
  for (const change of changes) {
    if (change.after && (change.after.mode === "120000" || change.after.type === "commit" || change.after.mode === "160000")) {
      reject("LINKED_CONTENT_FORBIDDEN", "Candidate symlinks and submodules are forbidden in trusted intake paths.");
    }
    const allowedExecutableVendorBlob = change.after?.type === "blob"
      && change.after.mode === "100755"
      && change.path.startsWith(EXECUTABLE_BUILDER_VENDOR_PREFIX);
    const allowedNonExecutableBlob = change.after?.type === "blob" && change.after.mode === "100644";
    if (change.after && !allowedNonExecutableBlob && !allowedExecutableVendorBlob) {
      reject(
        "FILE_MODE_FORBIDDEN",
        "Changed intake files must be regular Git blobs; executable mode is allowed only under the exact Builder vendor path."
      );
    }
  }
}

function isAllowlistedApplicationPath(entryPath) {
  const match = APPLICATION_PATH_PATTERN.exec(entryPath);
  return Boolean(match && APPLICATION_FILES.includes(match[2]));
}

function classifyTrustedBaseApplication(base, applicationId) {
  const packagePrefix = `submissions/${applicationId}/`;
  const entries = [...base.entries.values()]
    .filter((entry) => entry.path.startsWith(packagePrefix))
    .sort((left, right) => compareUtf8(left.path, right.path));
  if (entries.length === 0) return false;
  const expectedPaths = APPLICATION_FILES
    .map((fileName) => `${packagePrefix}${fileName}`)
    .sort(compareUtf8);
  if (!arraysEqual(entries.map(({ path: entryPath }) => entryPath), expectedPaths)) {
    systemBlocked(
      "INTAKE_BASE_APPLICATION_INVALID",
      "The trusted base contains an incomplete or non-closed public application package."
    );
  }
  for (const entry of entries) {
    if (entry.mode !== "100644" || entry.type !== "blob" || !SHA1_PATTERN.test(entry.oid)) {
      systemBlocked(
        "INTAKE_BASE_APPLICATION_INVALID",
        "The trusted base application package contains a non-regular entry."
      );
    }
  }
  return true;
}

function assertNewApplicationChangedFileSet({ changedFiles, applicationId }) {
  const expectedPaths = APPLICATION_FILES
    .map((fileName) => `submissions/${applicationId}/${fileName}`)
    .sort(compareUtf8);
  const observedPaths = changedFiles.map(({ path: entryPath }) => entryPath).sort(compareUtf8);
  if (
    !arraysEqual(observedPaths, expectedPaths)
    || changedFiles.some(({ status, previousPath }) => status !== "added" || previousPath !== null)
  ) {
    reject(
      "CHANGED_PATH_NOT_ALLOWED",
      "A paused-new continuation must add exactly the six frozen files for its trusted application id."
    );
  }
}

function isRegistryMaintenancePath(entryPath) {
  return REGISTRY_MAINTENANCE_FILES.has(entryPath)
    || REGISTRY_MAINTENANCE_PREFIXES.some((prefix) => entryPath.startsWith(prefix))
    || /^scripts\/test\/verify-public-hook-application(?:-[a-z0-9-]+)?\.test\.mjs$/u.test(entryPath);
}

function assertRegularBlob(entry) {
  if (!entry || entry.mode !== "100644" || entry.type !== "blob" || !SHA1_PATTERN.test(entry.oid)) {
    reject("APPLICATION_FILE_NOT_REGULAR", "Every application package entry must be a non-executable regular Git blob.");
  }
}

function readGitBlob(root, entry, maximumBytes) {
  assertRegularBlob(entry);
  const declaredSizeText = runGitText(root, ["cat-file", "-s", entry.oid], 128).trim();
  if (!/^(?:0|[1-9][0-9]*)$/.test(declaredSizeText)) {
    systemBlocked("GIT_BLOB_SIZE_INVALID", "Git returned an invalid blob size.");
  }
  const declaredSize = Number(declaredSizeText);
  if (!Number.isSafeInteger(declaredSize) || declaredSize > maximumBytes) {
    reject("APPLICATION_FILE_TOO_LARGE", "An application package file exceeds its trusted byte limit.");
  }
  const bytes = runGit(root, ["cat-file", "blob", entry.oid], maximumBytes + 1);
  if (bytes.length !== declaredSize) systemBlocked("GIT_BLOB_SIZE_MISMATCH", "Git blob bytes do not match their declared size.");
  return bytes;
}

function parseCanonicalJson(bytes, documentName, limits) {
  let source;
  try {
    source = UTF8_DECODER.decode(bytes);
  } catch {
    reject("JSON_UTF8_INVALID", `${documentName} is not valid UTF-8.`);
  }
  if (hasUnsafeSerializedText(source) || source.includes("\r")) {
    reject("JSON_TEXT_UNSAFE", `${documentName} contains unsupported control, bidi, or carriage-return characters.`);
  }
  let value;
  try {
    value = JSON.parse(source);
  } catch {
    reject("JSON_PARSE_FAILED", `${documentName} is not valid JSON.`);
  }
  validateJsonTree(value, limits);
  if (source !== `${canonicalJson(value)}\n`) {
    reject("JSON_NOT_CANONICAL", `${documentName} must be sorted, compact canonical JSON followed by one LF.`);
  }
  return value;
}

function validateJsonTree(root, limits) {
  let nodes = 0;
  const visit = (value, depth) => {
    nodes += 1;
    if (nodes > limits.maximumJsonNodes) reject("JSON_NODE_LIMIT", "A JSON document exceeds the trusted node limit.");
    if (depth > limits.maximumJsonDepth) reject("JSON_DEPTH_LIMIT", "A JSON document exceeds the trusted depth limit.");
    if (typeof value === "string") {
      if (hasForbiddenInvisibleOrBidi(value)) reject("JSON_STRING_UNSAFE", "A JSON string contains unsafe control, invisible, or bidi characters.");
      return;
    }
    if (Array.isArray(value)) {
      value.forEach((entry) => visit(entry, depth + 1));
      return;
    }
    if (value === null || typeof value === "boolean" || typeof value === "number") return;
    if (!isPlainObject(value)) reject("JSON_VALUE_UNSUPPORTED", "A JSON document contains an unsupported value type.");
    for (const [key, entry] of Object.entries(value)) {
      if (FORBIDDEN_JSON_KEYS.has(key)) reject("JSON_KEY_FORBIDDEN", "A JSON document contains a prototype-sensitive key.");
      visit(entry, depth + 1);
    }
  };
  visit(root, 0);
}

function validateApplicationManifest(application, expectedApplicationId, limits, legacyPolicyAdapter) {
  requireLegacyV2PolicyAdapter(legacyPolicyAdapter);
  if (application?.schemaVersion !== 2) {
    reject(
      "PUBLIC_APPLICATION_CONTRACT_UNSUPPORTED",
      "application.json must use the current public-pr-application-v2 contract with mandatory fee and builder-template projections."
    );
  }
  expectClosedObject(application, [
    "applicationId",
    "applicationRevision",
    "builder",
    "builderTemplate",
    "companionClosure",
    "declarations",
    "programmableFee",
    "reviewPackage",
    "schemaVersion",
    "source",
    "stage",
    "summary",
    "title"
  ], "application.json");
  expectInteger(application.schemaVersion, 2, 2, "application.schemaVersion");
  expectPattern(application.applicationId, APPLICATION_ID_PATTERN, 80, "application.applicationId");
  if (application.applicationId !== expectedApplicationId) {
    reject("APPLICATION_ID_PATH_MISMATCH", "The manifest application id must equal its submissions directory.");
  }
  expectInteger(application.applicationRevision, 1, 1_000_000, "application.applicationRevision");
  if (!new Set(["proposal", "prototype"]).has(application.stage)) {
    reject("APPLICATION_STAGE_INVALID", "An application stage must be proposal or prototype.");
  }
  expectText(application.title, 3, 120, "application.title");
  expectText(application.summary, 20, 1_000, "application.summary");

  expectClosedObject(application.builder, ["contact", "githubLogin", "githubUserId"], "application.builder");
  expectPattern(application.builder.githubUserId, OPAQUE_ID_PATTERN, 64, "application.builder.githubUserId");
  expectPattern(application.builder.githubLogin, GITHUB_LOGIN_PATTERN, 39, "application.builder.githubLogin");
  if (application.builder.contact !== null) validatePublicHttpsUrl(application.builder.contact, "application.builder.contact");

  let normalizedBuilderTemplate;
  try {
    normalizedBuilderTemplate = normalizeBuilderTemplate(application.builderTemplate);
  } catch {
    reject("BUILDER_TEMPLATE_PROJECTION_INVALID", "application.builderTemplate must contain canonical, policy-neutral template provenance.");
  }
  if (canonicalJson(normalizedBuilderTemplate) !== canonicalJson(application.builderTemplate)) {
    reject("BUILDER_TEMPLATE_PROJECTION_NONCANONICAL", "application.builderTemplate must use canonical ordering and fields.");
  }

  expectClosedObject(application.declarations, [
    "noApprovalClaim",
    "noSecretsDeclared",
    "noUniswapEndorsementClaim",
    "publicInformationAcknowledged"
  ], "application.declarations");
  for (const value of Object.values(application.declarations)) {
    if (value !== true) reject("APPLICATION_DECLARATION_REQUIRED", "Every public-beta declaration must be explicitly true.");
  }

  validateApplicationSource(application.source);
  validateProgrammableFeeProjection(application.programmableFee, application.source, legacyPolicyAdapter);
  if (application.programmableFee.submissionBinding.path !== `submissions/${application.applicationId}/submission.json`) {
    reject(
      "PROGRAMMABLE_FEE_SOURCE_BINDING_INVALID",
      "The fee projection must bind this application's canonical source submission.json path."
    );
  }
  let normalizedCompanionClosure;
  try {
    normalizedCompanionClosure = validateCompanionClosureReceipts(application.companionClosure, application.source);
  } catch {
    reject("COMPANION_CLOSURE_RECEIPT_INVALID", "Companion closure receipts must match every exact v2 source authority and Actions run.");
  }
  if (canonicalJson(normalizedCompanionClosure) !== canonicalJson(application.companionClosure)) {
    reject("COMPANION_CLOSURE_RECEIPT_NONCANONICAL", "Companion closure receipts must use canonical ordering and fields.");
  }

  if (!Array.isArray(application.reviewPackage) || application.reviewPackage.length !== REVIEW_FILES.length) {
    reject("REVIEW_PACKAGE_INDEX_INVALID", "The manifest must index every review file exactly once.");
  }
  application.reviewPackage.forEach((record, index) => {
    expectClosedObject(record, ["byteLength", "path", "sha256"], `reviewPackage[${index}]`);
    if (record.path !== REVIEW_FILES[index]) reject("REVIEW_PACKAGE_ORDER_INVALID", "Review package records must use the canonical path order.");
    expectPattern(record.sha256, SHA256_PATTERN, 71, "reviewPackage.sha256");
    expectInteger(record.byteLength, 1, limits.maximumFileBytes[record.path], "reviewPackage.byteLength");
  });
}

function validateProgrammableFeeProjection(fee, source, legacyPolicyAdapter) {
  const legacyFee = requireLegacyV2PolicyAdapter(legacyPolicyAdapter).fee;
  const invalidFee = (message) => reject("PROGRAMMABLE_FEE_PROJECTION_INVALID", message);
  const exact = (actual, expected, label) => {
    if (canonicalJson(actual) !== canonicalJson(expected)) {
      invalidFee(`${label} does not match the mandatory Programmable fee policy.`);
    }
  };

  try {
    expectClosedObject(fee, [
      "accounting",
      "basis",
      "collection",
      "evidence",
      "ownership",
      "policyId",
      "policyVersion",
      "poolScope",
      "rates",
      "submissionBinding"
    ], "application.programmableFee");
    expectClosedObject(fee.rates, [
      "effectiveBuyHundredthsOfBip",
      "effectiveSellHundredthsOfBip",
      "formula",
      "lpFeeExcluded",
      "minimumEffectiveHundredthsOfBip",
      "platformHundredthsOfBip",
      "projectBuyHundredthsOfBip",
      "projectSellHundredthsOfBip",
      "selectedBuyHundredthsOfBip",
      "selectedSellHundredthsOfBip",
      "unit"
    ], "application.programmableFee.rates");
    expectClosedObject(fee.basis, ["quoteAsset", "volume"], "application.programmableFee.basis");
    expectClosedObject(fee.ownership, [
      "administratorCanMutate",
      "builderCanMutate",
      "claimAuthority",
      "claimAvailability",
      "claimDestinationPolicy",
      "immutable",
      "owner",
      "projectCanMutate",
      "storedMutableRecipient"
    ], "application.programmableFee.ownership");
    expectClosedObject(fee.collection, [
      "enforcement",
      "hookFeeMechanismBinding",
      "integration",
      "selfCallPolicy",
      "status",
      "supportedSwapModes",
      "swapModePaths"
    ], "application.programmableFee.collection");
    expectClosedObject(fee.collection.swapModePaths, [
      "oneForZeroExactInput",
      "oneForZeroExactOutput",
      "zeroForOneExactInput",
      "zeroForOneExactOutput"
    ], "application.programmableFee.collection.swapModePaths");
    expectClosedObject(fee.accounting, [
      "accrualMode",
      "claimResetsRemainders",
      "claimEvent",
      "collectionEvent",
      "crossPoolNetting",
      "fragmentationResistant",
      "liabilityKeyDimensions",
      "minimumGrossQuoteUnits",
      "remainderScope",
      "roundingPolicy",
      "valueFlowId"
    ], "application.programmableFee.accounting");
    expectClosedObject(fee.evidence, ["sourcePaths", "testPaths"], "application.programmableFee.evidence");
    expectClosedObject(fee.submissionBinding, ["path", "sha256"], "application.programmableFee.submissionBinding");
  } catch (error) {
    if (error instanceof PublicIntakeError) invalidFee(error.message);
    throw error;
  }

  exact(fee.policyId, legacyFee.policyId, "Fee policy id");
  exact(fee.policyVersion, legacyFee.policyVersion, "Fee policy version");
  exact(fee.poolScope, "canonical-launch-pool-key", "PoolKey scope");
  exact(fee.rates.unit, "hundredths-of-bip", "Fee unit");
  exact(
    fee.rates.minimumEffectiveHundredthsOfBip,
    legacyFee.platformHundredthsOfBip,
    "Effective total fee floor"
  );
  exact(
    fee.rates.platformHundredthsOfBip,
    legacyFee.platformHundredthsOfBip,
    "Programmable fee rate"
  );
  exact(
    fee.rates.formula,
    `per-side:effective=max(selected,${legacyFee.platformHundredthsOfBip});platform=${legacyFee.platformHundredthsOfBip};project=effective-${legacyFee.platformHundredthsOfBip}`,
    "Fee allocation formula"
  );
  exact(fee.rates.lpFeeExcluded, true, "LP-fee exclusion");
  exact(fee.basis.volume, "gross-quote-side-swap-volume", "Fee volume basis");
  exact(fee.basis.quoteAsset, "canonical-pool-quote-asset", "Quote-asset basis");
  exact(fee.ownership, {
    owner: legacyFee.owner,
    immutable: true,
    claimAuthority: "owner-only",
    claimAvailability: "anytime",
    claimDestinationPolicy: "owner-or-owner-selected-per-claim",
    storedMutableRecipient: false,
    builderCanMutate: false,
    projectCanMutate: false,
    administratorCanMutate: false
  }, "Fee ownership and claim authority");
  exact(fee.collection.integration, "canonical-pool-hook", "Collection integration");
  exact(fee.collection.enforcement, "non-bypassable", "Collection enforcement");
  exact(fee.collection.hookFeeMechanismBinding, "hook.feeMechanism", "Hook fee binding");
  if (!new Set([
    "same-pool-swap-forbidden",
    "same-pool-swap-fee-enforced-internally"
  ]).has(fee.collection.selfCallPolicy)) {
    invalidFee("Same-pool self-swaps must be forbidden or fee-enforced internally.");
  }
  exact(fee.accounting.accrualMode, "claimable-liability", "Fee accrual mode");
  exact(fee.accounting.liabilityKeyDimensions, ["poolId", "currency", "owner"], "Liability-key dimensions");
  exact(fee.accounting.crossPoolNetting, false, "Cross-pool netting policy");
  exact(fee.accounting.roundingPolicy, "cumulative-independent-platform-project-remainders", "Cumulative rounding policy");
  exact(fee.accounting.remainderScope, "canonical-pool-lifetime", "Remainder scope");
  exact(fee.accounting.claimResetsRemainders, false, "Claim remainder policy");
  exact(fee.accounting.minimumGrossQuoteUnits, 1000, "Minimum gross quote amount");
  exact(fee.accounting.fragmentationResistant, true, "Fragmentation resistance");
  if (!isCanonicalGitHubRepositoryPathV1(fee.submissionBinding.path)) {
    invalidFee("The exact submission binding path is not a canonical repository path.");
  }
  if (!SHA256_PATTERN.test(fee.submissionBinding.sha256 ?? "")) {
    invalidFee("The exact submission binding must include a lowercase SHA-256 digest.");
  }
  if (!source.primary.sourcePaths?.includes(fee.submissionBinding.path)) {
    invalidFee("The exact submission binding must be declared in primary.sourcePaths.");
  }

  for (const side of ["Buy", "Sell"]) {
    const selected = fee.rates[`selected${side}HundredthsOfBip`];
    const effective = fee.rates[`effective${side}HundredthsOfBip`];
    const project = fee.rates[`project${side}HundredthsOfBip`];
    if (selected === null) {
      if (effective !== null || project !== null) {
        invalidFee(`An unresolved selected ${side.toLowerCase()} fee must keep its effective and project fee projections unresolved.`);
      }
      continue;
    }
    if (!Number.isInteger(selected) || selected < 0 || selected > 999_999) {
      invalidFee(`The selected ${side.toLowerCase()} fee must be an integer in hundredths of a basis point.`);
    }
    const expectedEffective = Math.max(selected, legacyFee.platformHundredthsOfBip);
    if (effective !== expectedEffective || project !== expectedEffective - legacyFee.platformHundredthsOfBip) {
      invalidFee(`Effective and project ${side.toLowerCase()} fees must be derived from the central legacy adapter rate without adding the platform fee twice.`);
    }
  }

  if (!new Set(["pending-hook-integration", "implemented"]).has(fee.collection.status)) {
    invalidFee("Collection status must identify a pending or implemented canonical PoolKey integration.");
  }
  const implemented = fee.collection.status === "implemented";
  const expectedModes = implemented ? legacyFee.swapModes : [];
  exact(fee.collection.supportedSwapModes, expectedModes, "Covered swap modes");
  const swapModePathValues = Object.values(fee.collection.swapModePaths);
  if (implemented) {
    if (swapModePathValues.some((value) => !new Set([
      "before-swap-return-delta",
      "after-swap-return-delta"
    ]).has(value))) {
      invalidFee("Every implemented swap mode must bind its exact PoolManager return-delta collection path.");
    }
  } else if (swapModePathValues.some((value) => value !== null)) {
    invalidFee("Swap-mode collection paths must remain null while hook integration is pending.");
  }

  const nullableBindings = [
    [fee.accounting.valueFlowId, "Value-flow binding"],
    [fee.accounting.collectionEvent, "Collection-event binding"],
    [fee.accounting.claimEvent, "Claim-event binding"]
  ];
  for (const [value, label] of nullableBindings) {
    if (implemented) {
      if (typeof value !== "string" || value.length < 1 || value.length > 500 || hasForbiddenInvisibleOrBidi(value)) {
        invalidFee(`${label} is required for an implemented fee path.`);
      }
    } else if (value !== null) {
      invalidFee(`${label} must remain null while hook integration is pending.`);
    }
  }

  const boundSourcePaths = new Set();
  for (const repository of [source.primary, ...source.companions]) {
    for (const entryPath of repository.sourcePaths ?? []) boundSourcePaths.add(entryPath);
    for (const entryPath of repository.contractPaths ?? []) boundSourcePaths.add(entryPath);
  }
  for (const [paths, label] of [
    [fee.evidence.sourcePaths, "Fee source paths"],
    [fee.evidence.testPaths, "Fee test paths"]
  ]) {
    if (!Array.isArray(paths) || paths.length > 64 || (implemented && paths.length === 0)) {
      invalidFee(`${label} must be bounded and non-empty for an implemented fee path.`);
    }
    let previous = null;
    for (const entryPath of paths) {
      if (!isCanonicalGitHubRepositoryPathV1(entryPath) || !boundSourcePaths.has(entryPath)) {
        invalidFee(`${label} must bind repository paths from an exact declared GitHub source revision.`);
      }
      if (previous !== null && compareUtf8(previous, entryPath) >= 0) {
        invalidFee(`${label} must be unique and sorted canonically.`);
      }
      previous = entryPath;
    }
    if (!implemented && paths.length !== 0) {
      invalidFee(`${label} must remain empty while hook integration is pending.`);
    }
  }
}

function validateProgrammableFeeCompatibility(application, compatibility) {
  if (
    application.programmableFee.collection.status !== "implemented"
    && compatibility.result === "prototype-ready"
  ) {
    reject(
      "PROGRAMMABLE_FEE_READINESS_INVALID",
      "A pending Programmable fee integration cannot be projected as prototype-ready."
    );
  }
}

function validateProgrammableFeeSubmissionEvidence(evidenceIndex, application, legacyPolicyAdapter) {
  const { transportEvidenceId } = requireLegacyV2PolicyAdapter(legacyPolicyAdapter);
  const records = evidenceIndex.evidence.filter(({ id }) => id === transportEvidenceId);
  if (records.length !== 1) {
    reject(
      "PROGRAMMABLE_FEE_SOURCE_BINDING_MISSING",
      "The evidence index must contain one exact submission.json binding for trusted fee-policy recomputation."
    );
  }
  const [record] = records;
  const expectedPath = application.programmableFee.submissionBinding.path;
  const observedPath = validateGitHubEvidenceUrl(record.url, "programmable fee submission evidence", application.source.primary) === "blob"
    ? evidenceBlobPath(record.url, application.source.primary)
    : null;
  if (
    observedPath !== expectedPath
    || record.sha256 !== application.programmableFee.submissionBinding.sha256
    || record.kind !== "static-analysis"
    || record.status !== "passed"
  ) {
    reject(
      "PROGRAMMABLE_FEE_SOURCE_BINDING_INVALID",
      "The mandatory fee projection must bind the exact primary-source submission.json bytes."
    );
  }
}

function validateProgrammableFeeSubmissionObservation({
  application,
  evidenceIndex,
  blobObservations,
  legacyPolicyAdapter,
  limits
}) {
  validateProgrammableFeeSubmissionEvidence(evidenceIndex, application, legacyPolicyAdapter);
  const observation = blobObservations.find(({ id }) => id === legacyPolicyAdapter.transportEvidenceId);
  if (!observation || !Buffer.isBuffer(observation.bytes)) {
    systemBlocked(
      "PROGRAMMABLE_FEE_SOURCE_OBSERVATION_MISSING",
      "Trusted intake did not receive the exact submission.json bytes needed to recompute the fee projection."
    );
  }
  let source;
  let submission;
  try {
    source = UTF8_DECODER.decode(observation.bytes);
    // The lossless parser rejects duplicate keys and oversized numeric tokens;
    // the ordinary parse then exposes schema-bounded fee integers for arithmetic.
    parseBoundedLosslessJson(source);
    submission = JSON.parse(source);
    validateJsonTree(submission, limits);
  } catch {
    reject(
      "PROGRAMMABLE_FEE_SOURCE_SUBMISSION_INVALID",
      "The exact source-bound submission.json is not bounded lossless JSON."
    );
  }
  if (
    !isPlainObject(submission)
    || submission.standardVersion !== "1.6.0"
    || submission.schemaVersion !== 1
    || submission.model?.id !== application.applicationId
    || !isPlainObject(submission.builderTemplate)
    || !isPlainObject(submission.programmableFee)
  ) {
    reject(
      "PROGRAMMABLE_FEE_SOURCE_SUBMISSION_UNSUPPORTED",
      "The exact source submission must use the current 1.6.0 contract and match the application id."
    );
  }
  let sourceBuilderTemplate;
  try {
    sourceBuilderTemplate = normalizeBuilderTemplate(submission.builderTemplate);
  } catch {
    reject(
      "BUILDER_TEMPLATE_SOURCE_PROJECTION_INVALID",
      "The exact source submission contains invalid builder-template provenance."
    );
  }
  if (
    canonicalJson(sourceBuilderTemplate) !== canonicalJson(submission.builderTemplate)
    || canonicalJson(sourceBuilderTemplate) !== canonicalJson(application.builderTemplate)
  ) {
    reject(
      "BUILDER_TEMPLATE_SOURCE_PROJECTION_MISMATCH",
      "application.builderTemplate must equal the template provenance recomputed from the exact source-bound submission.json."
    );
  }
  const sourceFeeKeys = Object.keys(submission.programmableFee).sort(compareUtf8);
  const expectedSourceFeeKeys = [
    "accounting",
    "basis",
    "collection",
    "evidence",
    "ownership",
    "policyId",
    "policyVersion",
    "poolScope",
    "rates"
  ].sort(compareUtf8);
  if (!arraysEqual(sourceFeeKeys, expectedSourceFeeKeys)) {
    reject(
      "PROGRAMMABLE_FEE_SOURCE_SUBMISSION_UNSUPPORTED",
      "The source programmableFee record is not closed under the current 1.6.0 contract."
    );
  }
  const recomputed = {
    ...submission.programmableFee,
    submissionBinding: application.programmableFee.submissionBinding
  };
  validateProgrammableFeeProjection(recomputed, application.source, legacyPolicyAdapter);
  if (canonicalJson(recomputed) !== canonicalJson(application.programmableFee)) {
    reject(
      "PROGRAMMABLE_FEE_SOURCE_PROJECTION_MISMATCH",
      "application.programmableFee must equal the fee policy recomputed from the exact source-bound submission.json."
    );
  }
}

function validateEvidenceIndex(index, application, limits) {
  expectClosedObject(index, ["applicationId", "attestation", "evidence", "schemaVersion", "source"], "evidence-index.json");
  expectInteger(index.schemaVersion, 1, 1, "evidenceIndex.schemaVersion");
  if (index.applicationId !== application.applicationId) reject("EVIDENCE_APPLICATION_MISMATCH", "The evidence index is bound to another application id.");
  if (index.attestation !== "builder-declared-untrusted") reject("EVIDENCE_ATTESTATION_INVALID", "Builder evidence must remain explicitly untrusted.");
  validateSourceProjection(index.source, application.source.primary, "evidenceIndex.source");
  if (!Array.isArray(index.evidence) || index.evidence.length < 1 || index.evidence.length > limits.maximumEvidence) {
    reject("EVIDENCE_COUNT_INVALID", "The evidence index must contain at least one record and stay within the trusted record limit.");
  }
  const ids = new Set();
  const urls = new Set();
  const allowedKinds = new Set(["build", "unit", "fuzz", "invariant", "static-analysis", "fork", "ui", "manual-review", "other"]);
  const allowedStatuses = new Set(["passed", "failed", "blocked", "not-run"]);
  let previousId = null;
  index.evidence.forEach((record, recordIndex) => {
    expectClosedObject(record, ["id", "kind", "scope", "sha256", "status", "url"], `evidence[${recordIndex}]`);
    expectPattern(record.id, EVIDENCE_ID_PATTERN, 80, "evidence.id");
    if (ids.has(record.id)) reject("EVIDENCE_ID_DUPLICATE", "Evidence ids must be unique.");
    if (urls.has(record.url)) reject("EVIDENCE_TARGET_DUPLICATE", "Each immutable evidence target may be declared only once.");
    if (previousId !== null && compareUtf8(previousId, record.id) >= 0) reject("EVIDENCE_ORDER_INVALID", "Evidence records must be sorted by id.");
    ids.add(record.id);
    urls.add(record.url);
    previousId = record.id;
    if (!allowedKinds.has(record.kind)) reject("EVIDENCE_KIND_INVALID", "An evidence record has an unsupported kind.");
    if (!allowedStatuses.has(record.status)) reject("EVIDENCE_STATUS_INVALID", "An evidence record has an unsupported status.");
    expectText(record.scope, 12, 500, "evidence.scope");
    const evidenceLocation = validateGitHubEvidenceUrl(record.url, "evidence.url", application.source.primary);
    if (evidenceLocation === "blob" && record.sha256 === null) {
      reject("EVIDENCE_BLOB_HASH_REQUIRED", "Evidence bound to a source blob must declare its SHA-256 digest.");
    }
    if (evidenceLocation === "actions" && record.sha256 !== null) {
      reject("EVIDENCE_ACTION_HASH_INVALID", "A GitHub Actions run page is not immutable content and must use a null SHA-256 field.");
    }
    if (record.sha256 !== null) expectPattern(record.sha256, SHA256_PATTERN, 71, "evidence.sha256");
  });
  return ids;
}

function validateCompatibilityReport(report, application, evidenceIndex, evidenceIds, limits) {
  expectClosedObject(report, ["applicationId", "disclaimer", "findings", "result", "schemaVersion", "source"], "compatibility-report.json");
  expectInteger(report.schemaVersion, 1, 1, "compatibility.schemaVersion");
  if (report.applicationId !== application.applicationId) reject("COMPATIBILITY_APPLICATION_MISMATCH", "The compatibility report is bound to another application id.");
  validateSourceProjection(report.source, application.source.primary, "compatibility.source");
  const allowedResults = new Set(["prototype-ready", "changes-required", "architecture-review-required", "tooling-blocked"]);
  if (!allowedResults.has(report.result)) reject("COMPATIBILITY_RESULT_INVALID", "The compatibility report cannot claim approval, safety, or launch status.");
  if (report.disclaimer !== PUBLIC_BETA_DISCLAIMER) reject("COMPATIBILITY_DISCLAIMER_INVALID", "The required public-beta disclaimer is missing or changed.");
  if (!Array.isArray(report.findings) || report.findings.length > limits.maximumFindings) {
    reject("FINDING_COUNT_INVALID", "The compatibility report exceeds the trusted finding limit.");
  }
  const findingKeys = new Set();
  let previousKey = null;
  report.findings.forEach((finding, index) => {
    expectClosedObject(finding, ["code", "evidenceIds", "path", "remediation", "severity", "summary"], `findings[${index}]`);
    expectPattern(finding.code, FINDING_CODE_PATTERN, 80, "finding.code");
    if (!new Set(["informational", "warning", "blocker", "hard"]).has(finding.severity)) {
      reject("FINDING_SEVERITY_INVALID", "A finding has an unsupported severity.");
    }
    validateFindingPath(finding.path);
    expectText(finding.summary, 12, 800, "finding.summary");
    expectText(finding.remediation, 12, 800, "finding.remediation");
    validateSortedUniqueStrings(finding.evidenceIds, 0, 32, "finding.evidenceIds", (value) => {
      expectPattern(value, EVIDENCE_ID_PATTERN, 80, "finding.evidenceId");
      if (!evidenceIds.has(value)) reject("FINDING_EVIDENCE_UNKNOWN", "A finding references an unknown evidence id.");
    });
    const key = `${finding.code}\u0000${finding.path}`;
    if (findingKeys.has(key)) reject("FINDING_DUPLICATE", "Finding code and path pairs must be unique.");
    if (previousKey !== null && compareUtf8(previousKey, key) >= 0) reject("FINDING_ORDER_INVALID", "Findings must be sorted by code and path.");
    findingKeys.add(key);
    previousKey = key;
  });

  if (application.stage === "proposal" && report.result === "prototype-ready") {
    reject("COMPATIBILITY_STAGE_MISMATCH", "A proposal-stage application cannot claim prototype-ready compatibility.");
  }
  const evidenceStatuses = new Set(evidenceIndex.evidence.map((record) => record.status));
  const findingSeverities = new Set(report.findings.map((finding) => finding.severity));
  const hasActionableFinding = ["warning", "blocker", "hard"].some((severity) => findingSeverities.has(severity));
  if (
    report.result === "prototype-ready"
    && (evidenceIndex.evidence.some((record) => record.status !== "passed") || hasActionableFinding)
  ) {
    reject(
      "COMPATIBILITY_EVIDENCE_MISMATCH",
      "Prototype-ready compatibility requires passed evidence and no warning, blocker, or hard finding."
    );
  }
  if (
    report.result === "prototype-ready"
    && !evidenceIndex.evidence.some((record) =>
      record.status === "passed"
      && validateGitHubEvidenceUrl(record.url, "evidence.url", application.source.primary) === "actions"
    )
  ) {
    reject(
      "COMPATIBILITY_EVIDENCE_MISMATCH",
      "Prototype-ready compatibility requires a declared successful GitHub Actions run for the exact source revision."
    );
  }
  if (report.result === "changes-required" && !evidenceStatuses.has("failed") && !hasActionableFinding) {
    reject(
      "COMPATIBILITY_EVIDENCE_MISMATCH",
      "Changes-required compatibility needs failed evidence or an actionable finding."
    );
  }
  if (
    report.result === "tooling-blocked"
    && !evidenceStatuses.has("blocked")
    && !evidenceStatuses.has("not-run")
  ) {
    reject(
      "COMPATIBILITY_EVIDENCE_MISMATCH",
      "Tooling-blocked compatibility needs blocked or not-run evidence."
    );
  }
  // The six-file public record does not yet let trusted-base code reconstruct
  // the exact review target and every bound source/evidence blob digest.
  if (report.result === "prototype-ready") {
    reject(
      "PROTOTYPE_READY_REQUIRES_TRUSTED_REVIEW_TARGET",
      "Public prototype-ready requires trusted-base reconstruction of the exact review target and source/evidence blob digests; submit this revision for architecture or changes review until that gate is available."
    );
  }
}

function validateSourceProjection(source, primary, label) {
  expectClosedObject(source, ["numericRepositoryId", "revisionObjectId", "treeObjectId"], label);
  if (
    source.numericRepositoryId !== primary.numericRepositoryId
    || source.revisionObjectId !== primary.revisionObjectId
    || source.treeObjectId !== primary.treeObjectId
  ) {
    reject("REVIEW_SOURCE_BINDING_MISMATCH", "Review JSON is not bound to the exact primary source revision.");
  }
}

function validateReviewPackageHashes(application, files) {
  for (const record of application.reviewPackage) {
    const bytes = files.get(record.path);
    if (!bytes) systemBlocked("REVIEW_FILE_MISSING", "An indexed review file is unavailable to the trusted validator.");
    const digest = `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
    if (record.byteLength !== bytes.length || record.sha256 !== digest) {
      reject("REVIEW_FILE_BINDING_MISMATCH", "A review file does not match its manifest byte length and SHA-256 digest.");
    }
  }
}

function validateMarkdown(bytes, documentName, requiredHeading) {
  let source;
  try {
    source = UTF8_DECODER.decode(bytes);
  } catch {
    reject("MARKDOWN_UTF8_INVALID", `${documentName} is not valid UTF-8.`);
  }
  if (!source.endsWith("\n") || source.includes("\r") || source.includes("\t") || hasUnsafeSerializedText(source)) {
    reject("MARKDOWN_TEXT_UNSAFE", `${documentName} must be LF-delimited UTF-8 without tabs, controls, or bidi overrides.`);
  }
  if (source.split("\n", 1)[0] !== requiredHeading) {
    reject("MARKDOWN_HEADING_INVALID", `${documentName} is missing its exact first-level heading.`);
  }
  const body = source.slice(requiredHeading.length + 1).trim();
  if (body.length < 40) {
    reject("MARKDOWN_CONTENT_INCOMPLETE", `${documentName} must contain a substantive review body after its heading.`);
  }
  if (/<[!/?A-Za-z]/u.test(source) || /&(?:#x?[0-9A-Fa-f]+|[A-Za-z][A-Za-z0-9]+);/u.test(source)) {
    reject("MARKDOWN_ACTIVE_CONTENT", `${documentName} contains raw markup, autolinks, or encoded active content.`);
  }
  if (
    /!\[[^\]]*\]\s*(?:\([^)]*\)|\[[^\]]*\])/su.test(source)
    || /(?:javascript|data|file|vbscript)\s*:/iu.test(source)
  ) {
    reject("MARKDOWN_EMBEDDED_CONTENT", `${documentName} contains an image or unsafe URI scheme.`);
  }
  return source;
}

function validatePublicClaims({ application, compatibility, evidenceIndex, markdownSources }) {
  const documents = [
    ["application.json", [application.title, application.summary]],
    [
      "compatibility-report.json",
      compatibility.findings.flatMap((finding) => [finding.summary, finding.remediation])
    ],
    ["evidence-index.json", evidenceIndex.evidence.map((record) => record.scope)],
    ...[...markdownSources].map(([documentName, source]) => [documentName, [source]])
  ];
  for (const [documentName, strings] of documents) {
    for (const value of strings) {
      if (findUnsupportedPublicClaims(value).length > 0) {
        reject(
          "UNSUPPORTED_PUBLIC_CLAIM",
          `${documentName} contains an unsupported approval, audit, safety, deployment, launch, or availability claim.`
        );
      }
    }
  }
}

function validateRevisionChange({
  application,
  applicationId,
  packagePrefix,
  classified,
  legacyPolicyAdapter,
  limits
}) {
  const manifestPath = `${packagePrefix}${APPLICATION_FILE}`;
  const baseEntry = classified.base.entries.get(manifestPath);
  if (!baseEntry) {
    if (application.applicationRevision !== 1) {
      reject("NEW_APPLICATION_REVISION_INVALID", "A new public application must begin at revision 1.");
    }
    return;
  }
  assertRegularBlob(baseEntry);
  const prior = parseCanonicalJson(
    readGitBlob(classified.base.root, baseEntry, limits.maximumFileBytes[APPLICATION_FILE]),
    `base:${manifestPath}`,
    limits
  );
  validateApplicationManifest(prior, applicationId, limits, legacyPolicyAdapter);
  if (application.applicationRevision !== prior.applicationRevision + 1) {
    reject("APPLICATION_REVISION_NOT_INCREMENTED", "An updated application must increment its revision by exactly one.");
  }
  if (application.builder.githubUserId !== prior.builder.githubUserId) {
    reject(
      "BUILDER_IDENTITY_CHANGED",
      "An application update cannot replace its immutable GitHub builder user id."
    );
  }
  const priorPrimary = prior.source.primary;
  const nextPrimary = application.source.primary;
  if (priorPrimary.numericRepositoryId !== nextPrimary.numericRepositoryId) {
    reject("PRIMARY_SOURCE_LINEAGE_CHANGED", "An application update cannot replace its primary public repository lineage.");
  }
  const primaryCommitChanged = priorPrimary.revisionObjectId !== nextPrimary.revisionObjectId;
  const primaryTreeChanged = priorPrimary.treeObjectId !== nextPrimary.treeObjectId;
  if (primaryCommitChanged !== primaryTreeChanged) {
    reject("PRIMARY_SOURCE_REVISION_PARTIAL", "A primary source update must bind both a new commit and its new root tree.");
  }
  if (sameSourceAuthority(prior.source, application.source)) {
    reject("PRIMARY_SOURCE_REVISION_UNCHANGED", "An application update must bind a new primary or companion source authority.");
  }
  for (const requiredChangedFile of ["compatibility-report.json", "evidence-index.json"]) {
    const changed = classified.changes.find((entry) => entry.path === `${packagePrefix}${requiredChangedFile}`);
    if (!changed || changed.status !== "modified") {
      reject("REVIEW_EVIDENCE_NOT_REGENERATED", "A source revision update must regenerate compatibility and evidence JSON.");
    }
  }
}

function sameSourceAuthority(left, right) {
  const leftProjection = sourceAuthorityProjection(left);
  const rightProjection = sourceAuthorityProjection(right);
  return JSON.stringify(leftProjection) === JSON.stringify(rightProjection);
}

/**
 * One application-scoped resolver session shares the anonymous REST transport
 * and retains the exact declared primary and companion blobs returned during
 * source validation. Evidence and companion-receipt recomputation reuse those
 * inert Git bytes without another REST tree walk or anonymous smart-Git fetch.
 */
export function createTrustedPublicApplicationResolutionSessionV1(
  { primary, source, evidence },
  {
    exactObjectResolver = createAnonymousGitHubExactObjectResolverV1(),
    transport = createTrustedGitHubActionsPublicTransportV1()
  } = {}
) {
  const sourceRequest = source ?? (isPlainObject(primary) ? {
    schemaVersion: GITHUB_PUBLIC_SOURCE_CONTRACT_V1.schemaVersion,
    primary,
    companions: []
  } : null);
  primary = sourceRequest?.primary;
  if (!isPlainObject(primary) || !Array.isArray(evidence)) {
    systemBlocked("EVIDENCE_RESOLUTION_INPUT_INVALID", "Trusted resolution session received malformed inputs.");
  }
  if (typeof exactObjectResolver !== "function" || typeof transport !== "function") {
    systemBlocked("RESOLVER_UNAVAILABLE", "The trusted application resolution session is unavailable.");
  }
  const authorities = [primary, ...(sourceRequest.companions ?? [])].map((entry) => ({
    repositoryUri: entry.repositoryUri,
    revisionObjectId: entry.revisionObjectId,
    treeObjectId: entry.treeObjectId
  }));
  const sharedExactObjectResolver = createRetainedExactObjectResolverV1(exactObjectResolver, {
    authorities
  });
  return Object.freeze({
    resolveSource(request) {
      return resolvePublicGitHubSource(request, { exactObjectResolver: sharedExactObjectResolver, transport });
    },
    resolveEvidence(request) {
      return resolvePublicApplicationEvidence(request, { exactObjectResolver: sharedExactObjectResolver });
    },
    resolveCompanionClosure(request) {
      return resolvePublicCompanionClosure(request, { exactObjectResolver: sharedExactObjectResolver });
    }
  });
}

function createRetainedExactObjectResolverV1(delegate, authority) {
  const retainedRecords = new Map();
  return async (request) => {
    const retainedAuthority = authority.authorities.some((entry) => sameExactObjectAuthority(request, entry));
    const authorityKey = exactObjectAuthorityKey(request);
    if (retainedAuthority) {
      const cached = new Map();
      let cachedBytes = 0;
      for (const filePath of request.paths) {
        const record = retainedRecords.get(`${authorityKey}\0${filePath}`);
        if (record === undefined) break;
        cachedBytes += record.bytes.length;
        if (record.bytes.length > request.maximumFileBytes || cachedBytes > request.maximumTotalBytes) break;
        cached.set(filePath, cloneExactObjectRecord(record));
      }
      if (cached.size === request.paths.length) return { records: cached };
    }

    const result = await delegate(request);
    const records = result instanceof Map ? result : result?.records;
    if (retainedAuthority && records instanceof Map) {
      for (const [filePath, record] of records) {
        if (isEvidenceExactObjectRecord(record)) {
          retainedRecords.set(`${authorityKey}\0${filePath}`, cloneExactObjectRecord(record));
        }
      }
    }
    return result;
  };
}

function exactObjectAuthorityKey(value) {
  return `${value?.repositoryUri ?? ""}\0${value?.revisionObjectId ?? ""}\0${value?.treeObjectId ?? ""}`;
}

function sameExactObjectAuthority(request, authority) {
  return request?.repositoryUri === authority.repositoryUri
    && request?.revisionObjectId === authority.revisionObjectId
    && request?.treeObjectId === authority.treeObjectId;
}

function cloneExactObjectRecord(record) {
  return {
    bytes: Buffer.from(record.bytes),
    mode: record.mode,
    objectId: record.objectId
  };
}

export async function resolvePublicGitHubSource(request, options = {}) {
  const usesDefaultTrustedTransport = options.transport === undefined;
  const resolverOptions = {
    timeoutMs: GITHUB_PUBLIC_SOURCE_CONTRACT_V1.limits.maximumTimeoutMs,
    ...options
  };
  if (resolverOptions.transport === undefined) {
    resolverOptions.transport = createTrustedGitHubActionsPublicTransportV1();
  }
  if (resolverOptions.exactObjectResolver === undefined && usesDefaultTrustedTransport) {
    resolverOptions.exactObjectResolver = createAnonymousGitHubExactObjectResolverV1();
  }
  return resolveGitHubPublicSourceV1(request, resolverOptions);
}

export async function resolvePublicCompanionClosure(
  { source, sourceObservation, companionClosure },
  { exactObjectResolver = createAnonymousGitHubExactObjectResolverV1() } = {}
) {
  if (typeof exactObjectResolver !== "function") {
    systemBlocked("COMPANION_CLOSURE_RESOLVER_UNAVAILABLE", "The exact companion-object resolver is unavailable.");
  }
  let normalizedReceipts;
  try {
    normalizedReceipts = validateCompanionClosureReceipts(companionClosure, source);
  } catch {
    reject("COMPANION_CLOSURE_RECEIPT_INVALID", "Companion closure receipts do not match the exact source contract.");
  }
  if (normalizedReceipts.length === 0) return [];
  validateSourceObservation(source, sourceObservation);

  const output = [];
  for (const [index, receipt] of normalizedReceipts.entries()) {
    const companion = source.companions.find((entry) => entry.repositoryUri === receipt.repositoryUri);
    const observation = sourceObservation.companions.find(
      (entry) => entry.display.repositoryUri === receipt.repositoryUri
    );
    if (!companion || !observation) {
      systemBlocked("COMPANION_CLOSURE_OBSERVATION_INVALID", "A v2 companion observation is unavailable.");
    }
    const manifestRecord = await resolveExactCompanionRecords(
      exactObjectResolver,
      source.primary,
      [receipt.manifestPath]
    );
    let manifest;
    try {
      const manifestSource = UTF8_DECODER.decode(manifestRecord.get(receipt.manifestPath).bytes);
      manifest = parseBoundedLosslessJson(manifestSource);
      if (manifestSource !== `${canonicalJson(manifest)}\n`) throw new Error("manifest JSON is not canonical");
    } catch {
      reject(
        "COMPANION_CLOSURE_MANIFEST_INVALID",
        `Companion closure receipt ${index + 1} does not point to canonical bounded manifest JSON in the exact primary source.`
      );
    }
    let normalizedManifest;
    try {
      normalizedManifest = normalizeCompanionManifest(manifest);
    } catch {
      reject("COMPANION_CLOSURE_MANIFEST_INVALID", "The exact primary-source companion manifest is invalid.");
    }
    if (
      normalizedManifest.manifestV2 === null
      || canonicalJson(normalizedManifest.source) !== canonicalJson(companion)
    ) {
      reject(
        "COMPANION_CLOSURE_MANIFEST_SOURCE_MISMATCH",
        "The exact primary-source manifest does not bind the declared v2 companion authority and paths."
      );
    }
    const closurePaths = [
      ...normalizedManifest.manifestV2.sourcePaths,
      ...normalizedManifest.manifestV2.testPaths,
      ...normalizedManifest.manifestV2.runtimePaths,
      ...normalizedManifest.manifestV2.build.configurationPaths,
      normalizedManifest.manifestV2.build.packageManifestPath,
      normalizedManifest.manifestV2.build.packageLockPath,
      ...observation.githubActionsEvidence.map(({ workflowPath }) => workflowPath)
    ].sort(compareUtf8);
    const uniqueClosurePaths = [...new Set(closurePaths)];
    let recomputed;
    try {
      const records = await resolveExactCompanionRecords(
        exactObjectResolver,
        companion,
        uniqueClosurePaths
      );
      recomputed = verifyCompanionManifestV2Closure(
        normalizedManifest.manifestV2,
        records,
        observation.githubActionsEvidence,
        { manifestPath: receipt.manifestPath }
      );
    } catch (error) {
      if (error instanceof GitHubPublicSourceError || error instanceof PublicIntakeError) throw error;
      reject(
        "COMPANION_CLOSURE_RECOMPUTE_FAILED",
        "The exact companion objects, npm closure, runtime closure, workflow, and Actions evidence did not reproduce a v2 receipt."
      );
    }
    if (canonicalJson(recomputed) !== canonicalJson(receipt)) {
      reject(
        "COMPANION_CLOSURE_RECEIPT_RECOMPUTE_MISMATCH",
        "A declared companion receipt differs from the exact independently recomputed result."
      );
    }
    output.push(recomputed);
  }
  return output;
}

async function resolveExactCompanionRecords(exactObjectResolver, authority, paths) {
  let result;
  try {
    result = await exactObjectResolver({
      repositoryUri: authority.repositoryUri,
      revisionObjectId: authority.revisionObjectId,
      treeObjectId: authority.treeObjectId,
      paths,
      timeoutMs: GITHUB_PUBLIC_SOURCE_CONTRACT_V1.limits.maximumTimeoutMs,
      maximumFileBytes: GITHUB_PUBLIC_GIT_OBJECT_RESOLVER_V1.maximumFileBytes,
      maximumTotalBytes: GITHUB_PUBLIC_GIT_OBJECT_RESOLVER_V1.maximumTotalBytes
    });
  } catch (error) {
    if (error instanceof GitHubPublicSourceError) throw error;
    systemBlocked("COMPANION_CLOSURE_OBJECT_RESOLUTION_FAILED", "Exact companion Git objects were unavailable.");
  }
  const records = result instanceof Map ? result : result?.records;
  if (!(records instanceof Map) || records.size !== paths.length || paths.some((filePath) => !records.has(filePath))) {
    systemBlocked("COMPANION_CLOSURE_OBJECT_RESOLUTION_INVALID", "The exact-object resolver returned an invalid companion path set.");
  }
  return records;
}

export async function resolvePublicApplicationEvidence({ primary, evidence, limits: limitOverrides = {} }, options = {}) {
  if (!isPlainObject(primary) || !Array.isArray(evidence)) {
    systemBlocked("EVIDENCE_RESOLUTION_INPUT_INVALID", "Trusted evidence resolution received malformed inputs.");
  }
  const limits = mergeLimits(limitOverrides);
  const timeoutMs = options.timeoutMs ?? GITHUB_PUBLIC_SOURCE_CONTRACT_V1.limits.maximumTimeoutMs;
  if (
    !Number.isSafeInteger(timeoutMs)
    || timeoutMs < GITHUB_PUBLIC_SOURCE_CONTRACT_V1.limits.minimumTimeoutMs
    || timeoutMs > GITHUB_PUBLIC_SOURCE_CONTRACT_V1.limits.maximumTimeoutMs
  ) {
    systemBlocked("EVIDENCE_RESOLUTION_OPTIONS_INVALID", "Trusted evidence resolution received an invalid timeout.");
  }
  const usesDefaultTransport = options.transport === undefined;
  const exactObjectResolver = options.exactObjectResolver === undefined
    ? (usesDefaultTransport ? createAnonymousGitHubExactObjectResolverV1() : null)
    : options.exactObjectResolver;
  if (exactObjectResolver !== null && typeof exactObjectResolver !== "function") {
    systemBlocked("EVIDENCE_RESOLVER_UNAVAILABLE", "The trusted exact evidence resolver is unavailable.");
  }
  if (exactObjectResolver !== null) {
    return resolveEvidenceWithExactObjectResolver({
      primary,
      evidence,
      limits,
      timeoutMs,
      exactObjectResolver
    });
  }

  const transport = options.transport ?? createTrustedGitHubActionsPublicTransportV1();
  if (typeof transport !== "function") {
    systemBlocked("EVIDENCE_RESOLVER_UNAVAILABLE", "The trusted public-evidence transport is unavailable.");
  }
  const repository = new URL(primary.repositoryUri);
  const [owner, repositoryName] = repository.pathname.slice(1).split("/");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(new Error("evidence resolution timed out")), timeoutMs);
  const state = {
    controller,
    limits,
    owner,
    repositoryName,
    requests: 0,
    responseBytes: 0,
    transport,
    recursiveTree: null,
    blobCache: new Map()
  };
  try {
    const observations = [];
    for (const record of evidence) {
      const sourcePath = evidenceBlobPath(record.url, primary);
      const resolved = await resolveEvidenceBlob(sourcePath, primary.treeObjectId, state);
      observations.push({
        id: record.id,
        path: sourcePath,
        blobObjectId: resolved.blobObjectId,
        bytes: resolved.bytes
      });
    }
    return observations;
  } catch (error) {
    if (controller.signal.aborted) {
      systemBlocked("GITHUB_TIMEOUT", "Trusted evidence resolution exceeded its deadline.");
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

async function resolveEvidenceWithExactObjectResolver({
  primary,
  evidence,
  limits,
  timeoutMs,
  exactObjectResolver
}) {
  const paths = evidence.map((record) => evidenceBlobPath(record.url, primary));
  let result;
  try {
    result = await exactObjectResolver(Object.freeze({
      repositoryUri: primary.repositoryUri,
      revisionObjectId: primary.revisionObjectId,
      treeObjectId: primary.treeObjectId,
      paths: Object.freeze([...paths].sort(compareUtf8)),
      timeoutMs,
      maximumFileBytes: Math.min(
        limits.maximumEvidenceBlobBytes,
        GITHUB_PUBLIC_GIT_OBJECT_RESOLVER_V1.maximumFileBytes
      ),
      maximumTotalBytes: Math.min(
        limits.maximumEvidenceResolutionBytes,
        GITHUB_PUBLIC_GIT_OBJECT_RESOLVER_V1.maximumTotalBytes
      )
    }));
  } catch (error) {
    if (error instanceof GitHubPublicSourceError && error.code === "GITHUB_DECLARED_PATH_NOT_FOUND") {
      reject("EVIDENCE_BLOB_UNAVAILABLE", "The declared evidence path is not a regular blob in the exact source tree.");
    }
    if (error instanceof GitHubPublicSourceError && error.code === "GITHUB_RESPONSE_TOO_LARGE") {
      reject("EVIDENCE_RESPONSE_LIMIT", "Declared evidence exceeds the trusted inert-content limit.");
    }
    throw error;
  }

  const records = result instanceof Map ? result : result?.records;
  if (!(records instanceof Map) || records.size !== paths.length) {
    systemBlocked("EVIDENCE_OBSERVATION_INVALID", "The trusted exact evidence resolver returned an invalid path set.");
  }
  const expectedPaths = new Set(paths);
  for (const filePath of records.keys()) {
    if (!expectedPaths.has(filePath)) {
      systemBlocked("EVIDENCE_OBSERVATION_INVALID", "The trusted exact evidence resolver returned an undeclared path.");
    }
  }

  return evidence.map((record, index) => {
    const filePath = paths[index];
    const exactRecord = records.get(filePath);
    if (!isEvidenceExactObjectRecord(exactRecord)) {
      reject("EVIDENCE_BLOB_UNAVAILABLE", "The declared evidence path is not a regular blob in the exact source tree.");
    }
    const bytes = Buffer.from(exactRecord.bytes);
    if (bytes.length > limits.maximumEvidenceBlobBytes) {
      reject("EVIDENCE_BLOB_UNAVAILABLE", "The declared evidence blob exceeds the trusted byte limit.");
    }
    const observedObjectId = crypto.createHash("sha1")
      .update(Buffer.from(`blob ${bytes.length}\0`, "utf8"))
      .update(bytes)
      .digest("hex");
    if (observedObjectId !== exactRecord.objectId) {
      systemBlocked("EVIDENCE_BLOB_INVALID", "Exact evidence bytes did not match their Git blob object id.");
    }
    return {
      id: record.id,
      path: filePath,
      blobObjectId: exactRecord.objectId,
      bytes
    };
  });
}

function isEvidenceExactObjectRecord(value) {
  if (!isPlainObject(value)) return false;
  const keys = Object.keys(value).sort(compareUtf8);
  return arraysEqual(keys, ["bytes", "mode", "objectId"])
    && (value.mode === "100644" || value.mode === "100755")
    && SHA1_PATTERN.test(value.objectId ?? "")
    && value.bytes instanceof Uint8Array;
}

async function resolveEvidenceBlob(sourcePath, rootTreeObjectId, state) {
  const entries = await loadEvidenceRecursiveTree(rootTreeObjectId, state);
  const entry = entries.get(sourcePath);
  if (entry?.type !== "blob") {
    reject("EVIDENCE_BLOB_UNAVAILABLE", "The declared evidence path is not a blob in the exact source tree.");
  }
  const blobObjectId = entry.sha;
  const bytes = await loadEvidenceBlob(blobObjectId, state);
  return { blobObjectId, bytes };
}

async function loadEvidenceRecursiveTree(treeObjectId, state) {
  if (state.recursiveTree !== null) return state.recursiveTree;
  const tree = await requestEvidenceGitHubJson(
    `/repos/${state.owner}/${state.repositoryName}/git/trees/${treeObjectId}?recursive=1`,
    8 * 1024 * 1024,
    state
  );
  if (tree.sha !== treeObjectId || tree.truncated !== false || !Array.isArray(tree.tree)) {
    systemBlocked("EVIDENCE_TREE_INVALID", "GitHub could not provide a complete exact tree for REST evidence fallback.");
  }
  if (tree.tree.length > state.limits.maximumEvidenceTreeEntries) {
    reject("EVIDENCE_TREE_TOO_LARGE", "An evidence tree exceeds the trusted entry limit.");
  }
  const entries = new Map();
  for (const entry of tree.tree) {
    if (
      !isPlainObject(entry)
      || typeof entry.path !== "string"
      || entry.path.length === 0
      || !isCanonicalGitHubRepositoryPathV1(entry.path)
      || !new Set(["blob", "tree", "commit"]).has(entry.type)
      || !SHA1_PATTERN.test(entry.sha ?? "")
    ) {
      systemBlocked("EVIDENCE_TREE_INVALID", "GitHub returned a malformed direct tree entry.");
    }
    if (entries.has(entry.path)) {
      systemBlocked("EVIDENCE_TREE_INVALID", "GitHub returned duplicate direct tree entries.");
    }
    entries.set(entry.path, { type: entry.type, sha: entry.sha });
  }
  state.recursiveTree = entries;
  return entries;
}

async function loadEvidenceBlob(blobObjectId, state) {
  if (state.blobCache.has(blobObjectId)) return state.blobCache.get(blobObjectId);
  const blob = await requestEvidenceGitHubJson(
    `/repos/${state.owner}/${state.repositoryName}/git/blobs/${blobObjectId}`,
    Math.min(state.limits.maximumEvidenceResolutionBytes, 12 * 1024 * 1024),
    state
  );
  if (
    blob.sha !== blobObjectId
    || blob.encoding !== "base64"
    || typeof blob.content !== "string"
    || !Number.isSafeInteger(blob.size)
    || blob.size < 0
    || blob.size > state.limits.maximumEvidenceBlobBytes
  ) {
    reject("EVIDENCE_BLOB_UNAVAILABLE", "GitHub did not return a bounded base64 blob for the declared evidence path.");
  }
  const encoded = blob.content.replace(/\n/gu, "");
  if (
    /[^A-Za-z0-9+/=\n]/u.test(blob.content)
    || encoded.length % 4 !== 0
    || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(encoded)
  ) {
    systemBlocked("EVIDENCE_BLOB_INVALID", "GitHub returned malformed base64 evidence content.");
  }
  const bytes = Buffer.from(encoded, "base64");
  if (bytes.length !== blob.size || bytes.toString("base64") !== encoded) {
    systemBlocked("EVIDENCE_BLOB_INVALID", "GitHub evidence bytes did not match their declared base64 size.");
  }
  const gitObjectId = crypto.createHash("sha1")
    .update(Buffer.from(`blob ${bytes.length}\0`, "utf8"))
    .update(bytes)
    .digest("hex");
  if (gitObjectId !== blobObjectId) {
    systemBlocked("EVIDENCE_BLOB_INVALID", "GitHub evidence bytes did not match their exact Git blob object id.");
  }
  state.blobCache.set(blobObjectId, bytes);
  return bytes;
}

async function requestEvidenceGitHubJson(apiPath, maximumResponseBytes, state) {
  state.requests += 1;
  if (state.requests > state.limits.maximumEvidenceRequests) {
    systemBlocked(
      "EVIDENCE_REQUEST_LIMIT",
      "The bounded REST evidence fallback exhausted its tooling request budget."
    );
  }
  const url = `https://api.github.com${apiPath}`;
  let response;
  try {
    response = await state.transport({
      url,
      method: "GET",
      headers: {
        Accept: "application/vnd.github+json",
        "User-Agent": GITHUB_PUBLIC_SOURCE_CONTRACT_V1.userAgent,
        "X-GitHub-Api-Version": GITHUB_PUBLIC_SOURCE_CONTRACT_V1.githubApiVersion
      },
      redirect: "error",
      signal: state.controller.signal,
      maxResponseBytes: maximumResponseBytes
    });
  } catch (error) {
    if (error instanceof GitHubPublicSourceError || error instanceof PublicIntakeError) throw error;
    systemBlocked("GITHUB_NETWORK_ERROR", "GitHub evidence resolution failed at the transport boundary.");
  }
  if (!isPlainObject(response) || response.redirected === true || response.responseUrl !== url) {
    systemBlocked("GITHUB_PROTOCOL_ERROR", "GitHub evidence resolution received an invalid or redirected response.");
  }
  if (response.status !== 200) {
    if (response.status === 404 || response.status === 422) {
      reject("EVIDENCE_BLOB_UNAVAILABLE", "The declared evidence blob is unavailable from the exact source tree.");
    }
    if (response.status === 403 || response.status === 429) {
      systemBlocked("GITHUB_RATE_LIMITED", "GitHub rate-limited trusted evidence resolution.");
    }
    if (Number.isInteger(response.status) && response.status >= 500) {
      systemBlocked("GITHUB_UNAVAILABLE", "GitHub was unavailable during trusted evidence resolution.");
    }
    systemBlocked("GITHUB_UPSTREAM_REJECTED", "GitHub rejected trusted evidence resolution.");
  }
  let bytes;
  if (typeof response.body === "string") bytes = Buffer.from(response.body, "utf8");
  else if (response.body instanceof Uint8Array) bytes = Buffer.from(response.body);
  else if (response.body instanceof ArrayBuffer) bytes = Buffer.from(response.body);
  else systemBlocked("GITHUB_PROTOCOL_ERROR", "GitHub evidence response bytes were malformed.");
  if (bytes.length > maximumResponseBytes) {
    systemBlocked("GITHUB_RESPONSE_TOO_LARGE", "A GitHub evidence response exceeded its trusted byte limit.");
  }
  state.responseBytes += bytes.length;
  if (state.responseBytes > state.limits.maximumEvidenceResolutionBytes) {
    reject("EVIDENCE_RESPONSE_LIMIT", "Evidence resolution exceeded the trusted aggregate response limit.");
  }
  let source;
  try {
    source = UTF8_DECODER.decode(bytes);
  } catch {
    systemBlocked("GITHUB_PROTOCOL_ERROR", "GitHub evidence JSON was not valid UTF-8.");
  }
  let value;
  try {
    value = JSON.parse(source);
  } catch {
    systemBlocked("GITHUB_PROTOCOL_ERROR", "GitHub evidence response was not valid JSON.");
  }
  if (!isPlainObject(value)) {
    systemBlocked("GITHUB_PROTOCOL_ERROR", "GitHub evidence response was not a JSON object.");
  }
  return value;
}

/**
 * Anonymous, bounded transport for the trusted pull_request_target validator.
 *
 * GitHub documents GITHUB_TOKEN as an installation token whose authority is
 * limited to the workflow repository. It therefore is not a reliable
 * credential for arbitrary external public builder repositories and must not
 * be added here. The underlying public transport pins api.github.com, GET,
 * redirect rejection, fixed public headers, abort signals, and response byte
 * limits. This wrapper only adds serial pacing and one tightly bounded retry.
 */
export function createTrustedGitHubActionsPublicTransportV1({
  fetchImplementation = globalThis.fetch,
  maximumRetryBodyBytes = GITHUB_PUBLIC_TRANSPORT_DEFAULTS.maximumRetryBodyBytes,
  maximumRetryDelayMs = GITHUB_PUBLIC_TRANSPORT_DEFAULTS.maximumRetryDelayMs,
  minimumIntervalMs = GITHUB_PUBLIC_TRANSPORT_DEFAULTS.minimumIntervalMs,
  now = () => Date.now(),
  sleep = abortableDelay,
  transientRetryDelayMs = GITHUB_PUBLIC_TRANSPORT_DEFAULTS.transientRetryDelayMs
} = {}) {
  for (const [label, value, maximum] of [
    ["maximumRetryBodyBytes", maximumRetryBodyBytes, 64 * 1024],
    ["maximumRetryDelayMs", maximumRetryDelayMs, 5_000],
    ["minimumIntervalMs", minimumIntervalMs, 1_000],
    ["transientRetryDelayMs", transientRetryDelayMs, 5_000]
  ]) {
    if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
      throw new GitHubPublicSourceError("INVALID_OPTIONS", `${label} is outside the trusted transport bounds`);
    }
  }
  if (typeof now !== "function" || typeof sleep !== "function") {
    throw new GitHubPublicSourceError("INVALID_OPTIONS", "trusted transport clocks must be functions");
  }
  const maximumConfiguredDelayMs =
    ((GITHUB_ANONYMOUS_RESOLUTION_BUDGET_V1.maximumProviderRequests - 1) * minimumIntervalMs)
    + (GITHUB_ANONYMOUS_RESOLUTION_BUDGET_V1.maximumTransportRetries * maximumRetryDelayMs);
  if (maximumConfiguredDelayMs >= GITHUB_ANONYMOUS_RESOLUTION_BUDGET_V1.timeoutMs) {
    throw new GitHubPublicSourceError(
      "INVALID_OPTIONS",
      "trusted transport pacing and retry delays do not fit the resolver deadline"
    );
  }

  const publicTransport = createGitHubPublicFetchTransportV1(fetchImplementation);
  let earliestNextRequestMs = 0;
  let physicalRequestsRemaining = GITHUB_ANONYMOUS_RESOLUTION_BUDGET_V1.maximumProviderRequests;
  let retriesRemaining = GITHUB_ANONYMOUS_RESOLUTION_BUDGET_V1.maximumTransportRetries;
  let schedulingTail = Promise.resolve();

  return async function trustedGitHubActionsPublicTransport(request) {
    let response = await performPublicRequest(request);
    const retryDelayMs = selectTrustedRetryDelay(response, {
      maximumRetryBodyBytes,
      maximumRetryDelayMs,
      transientRetryDelayMs
    });
    if (retryDelayMs === null || retriesRemaining <= 0) return response;

    retriesRemaining -= 1;
    await sleep(retryDelayMs, request.signal);
    response = await performPublicRequest(request);
    return response;
  };

  async function performPublicRequest(request) {
    let releaseSlot;
    const predecessor = schedulingTail;
    schedulingTail = new Promise((resolve) => { releaseSlot = resolve; });
    await predecessor;
    let responsePromise;
    try {
      if (request?.signal?.aborted) throw request.signal.reason ?? new Error("request aborted");
      const currentMs = now();
      const waitMs = Math.max(0, earliestNextRequestMs - currentMs);
      if (waitMs > 0) await sleep(waitMs, request?.signal);
      earliestNextRequestMs = Math.max(currentMs + waitMs, now()) + minimumIntervalMs;
      if (physicalRequestsRemaining <= 0) {
        throw new GitHubPublicSourceError(
          "GITHUB_RATE_LIMITED",
          "The trusted anonymous GitHub REST request budget was exhausted",
          { retryable: true }
        );
      }
      physicalRequestsRemaining -= 1;
      // Invoke fetch while this start slot is still held; release immediately
      // afterwards so response bodies may be in flight concurrently.
      responsePromise = publicTransport(request);
    } finally {
      releaseSlot();
    }
    return responsePromise;
  }
}

function selectTrustedRetryDelay(response, {
  maximumRetryBodyBytes,
  maximumRetryDelayMs,
  transientRetryDelayMs
}) {
  const bodyBytes = responseBodyByteLength(response?.body);
  if (bodyBytes === null || bodyBytes > maximumRetryBodyBytes) return null;

  if (new Set([502, 503, 504]).has(response.status)) {
    return transientRetryDelayMs <= maximumRetryDelayMs ? transientRetryDelayMs : null;
  }
  if (response.status !== 403 && response.status !== 429) return null;

  const remaining = transportHeader(response.headers, "x-ratelimit-remaining");
  if (remaining === "0") return null;
  const retryAfter = transportHeader(response.headers, "retry-after");
  if (typeof retryAfter !== "string" || !/^(?:0|[1-9][0-9]{0,2})$/u.test(retryAfter)) return null;
  const retryDelayMs = Number(retryAfter) * 1_000;
  return retryDelayMs <= maximumRetryDelayMs ? retryDelayMs : null;
}

function responseBodyByteLength(body) {
  if (typeof body === "string") return Buffer.byteLength(body, "utf8");
  if (body instanceof Uint8Array) return body.byteLength;
  if (body instanceof ArrayBuffer) return body.byteLength;
  return null;
}

function transportHeader(headers, name) {
  if (headers === null || headers === undefined) return null;
  if (typeof headers.get === "function") return headers.get(name);
  if (!isPlainObject(headers)) return null;
  const match = Object.entries(headers).find(([key]) => key.toLowerCase() === name);
  return match?.[1] ?? null;
}

function abortableDelay(milliseconds, signal) {
  if (signal?.aborted) return Promise.reject(signal.reason ?? new Error("request aborted"));
  return new Promise((resolve, rejectDelay) => {
    const timeout = setTimeout(finish, milliseconds);
    signal?.addEventListener("abort", abort, { once: true });
    function finish() {
      signal?.removeEventListener("abort", abort);
      resolve();
    }
    function abort() {
      clearTimeout(timeout);
      rejectDelay(signal.reason ?? new Error("request aborted"));
    }
  });
}

function validateApplicationSource(source) {
  let normalized;
  try {
    normalized = validateGitHubPublicSourceRequestV1(source);
  } catch (error) {
    if (error instanceof GitHubPublicSourceError) {
      reject("SOURCE_CONTRACT_INVALID", "application.source does not satisfy GitHubPublicSourceContractV1.");
    }
    throw error;
  }

  const requestedRepositories = [source.primary, ...source.companions];
  const normalizedRepositories = [normalized.primary, ...normalized.companions];
  for (let index = 0; index < requestedRepositories.length; index += 1) {
    const requested = requestedRepositories[index];
    const canonical = normalizedRepositories[index];
    if (
      requested.numericRepositoryId !== canonical.numericRepositoryId
      || requested.repositoryUri !== canonical.repositoryUri
      || !arraysEqual(requested.sourcePaths ?? [], canonical.sourcePaths)
      || !arraysEqual(requested.contractPaths ?? [], canonical.contractPaths)
      || !arraysEqual(requested.githubActionsRunIds ?? [], canonical.githubActionsRunIds)
    ) {
      reject("SOURCE_CONTRACT_ORDER_INVALID", "application.source arrays and companions must use the contract's unsigned UTF-8 order.");
    }
  }
}

function translateSourceResolutionError(error) {
  if (error instanceof PublicIntakeError) throw error;
  if (!(error instanceof GitHubPublicSourceError)) {
    systemBlocked("SOURCE_RESOLUTION_FAILED", "The trusted GitHubPublicSourceContractV1 resolver failed unexpectedly.");
  }
  if (
    error.code === "GITHUB_UPSTREAM_REJECTED"
    && error.message.startsWith("Exact Git object tooling is unavailable:")
  ) {
    systemBlocked("TOOLING_BLOCKED", "The trusted runner cannot safely resolve exact public Git objects.");
  }
  const candidateCodes = new Set([
    "GITHUB_ACTIONS_RUN_MISMATCH",
    "GITHUB_ACTIONS_RUN_NOT_REACHABLE",
    "GITHUB_ACTIONS_WORKFLOW_NOT_IN_TREE",
    "GITHUB_COMMIT_MISMATCH",
    "GITHUB_COMMIT_NOT_REACHABLE",
    "GITHUB_DECLARED_PATH_NOT_FOUND",
    "GITHUB_PUBLIC_REPOSITORY_UNAVAILABLE",
    "GITHUB_REDIRECT_REJECTED",
    "GITHUB_REPOSITORY_ID_MISMATCH",
    "GITHUB_REPOSITORY_LOCATOR_MISMATCH",
    "GITHUB_TREE_MISMATCH",
    "GITHUB_TREE_NOT_REACHABLE",
    "INVALID_REQUEST"
  ]);
  if (candidateCodes.has(error.code)) {
    reject(error.code, "The declared public GitHub source did not resolve to its exact frozen authority.");
  }
  systemBlocked(error.code, "The trusted GitHubPublicSourceContractV1 resolver could not complete.");
}

function translateEvidenceResolutionError(error) {
  if (error instanceof PublicIntakeError) throw error;
  if (error instanceof GitHubPublicSourceError) translateSourceResolutionError(error);
  systemBlocked("EVIDENCE_RESOLUTION_FAILED", "The trusted public-evidence resolver failed unexpectedly.");
}

function validateSourceObservation(request, observation) {
  if (
    !isPlainObject(observation)
    || observation.schemaVersion !== GITHUB_PUBLIC_SOURCE_CONTRACT_V1.schemaVersion
    || observation.kind !== GITHUB_PUBLIC_SOURCE_CONTRACT_V1.kind
    || observation.canonicalProviderOrigin !== GITHUB_PUBLIC_SOURCE_CONTRACT_V1.canonicalProviderOrigin
    || observation.githubApiVersion !== GITHUB_PUBLIC_SOURCE_CONTRACT_V1.githubApiVersion
    || !Array.isArray(observation.companions)
  ) {
    systemBlocked("SOURCE_OBSERVATION_INVALID", "The trusted resolver returned an invalid GitHubPublicSourceContractV1 observation.");
  }
  const expected = [request.primary, ...request.companions];
  const observed = [observation.primary, ...observation.companions];
  if (expected.length !== observed.length) {
    systemBlocked("SOURCE_OBSERVATION_INVALID", "The trusted resolver returned the wrong number of source observations.");
  }
  expected.forEach((binding, index) => validateRepositoryObservation(binding, observed[index], index === 0 ? "primary" : "companion"));
}

function validateRepositoryObservation(binding, observation, expectedRole) {
  if (!isPlainObject(observation) || !isPlainObject(observation.authority) || !isPlainObject(observation.display)) {
    systemBlocked("SOURCE_OBSERVATION_INVALID", "The trusted resolver returned a malformed repository observation.");
  }
  if (observation.role !== expectedRole) systemBlocked("SOURCE_OBSERVATION_INVALID", "The trusted resolver returned an invalid repository role.");
  if (observation.visibility !== "public") reject("GITHUB_PUBLIC_REPOSITORY_UNAVAILABLE", "Every builder-beta source repository must resolve as public.");
  if (observation.display.repositoryUri !== binding.repositoryUri) reject("GITHUB_REPOSITORY_LOCATOR_MISMATCH", "GitHub resolved a different canonical repository URI.");
  if (observation.authority.numericRepositoryId !== binding.numericRepositoryId) reject("GITHUB_REPOSITORY_ID_MISMATCH", "GitHub resolved a different numeric repository id.");
  if (observation.authority.revisionObjectId !== binding.revisionObjectId) reject("GITHUB_COMMIT_MISMATCH", "GitHub did not resolve the declared source revision.");
  if (observation.authority.treeObjectId !== binding.treeObjectId) reject("GITHUB_TREE_MISMATCH", "GitHub resolved a different root tree for the declared revision.");
  if (
    !arraysEqual(observation.sourcePaths ?? [], binding.sourcePaths ?? [])
    || !arraysEqual(observation.contractPaths ?? [], binding.contractPaths ?? [])
    || !Array.isArray(observation.githubActionsEvidence)
    || observation.githubActionsEvidence.length !== (binding.githubActionsRunIds ?? []).length
  ) {
    systemBlocked("SOURCE_OBSERVATION_INVALID", "The trusted resolver returned incomplete path or Actions observations.");
  }
  observation.githubActionsEvidence.forEach((entry, index) => {
    validateActionsObservation(entry, binding, binding.githubActionsRunIds[index]);
  });
}

function validateActionsObservation(observation, binding, expectedRunId) {
  if (
    !isPlainObject(observation)
    || !OPAQUE_ID_PATTERN.test(observation.runId ?? "")
    || !OPAQUE_ID_PATTERN.test(observation.runAttempt ?? "")
    || !OPAQUE_ID_PATTERN.test(observation.workflowId ?? "")
    || typeof observation.workflowPath !== "string"
    || !SAFE_CODE_PATTERN.test(observation.event ?? "")
    || !SAFE_CODE_PATTERN.test(observation.status ?? "")
    || (observation.conclusion !== null && !SAFE_CODE_PATTERN.test(observation.conclusion ?? ""))
  ) {
    systemBlocked("SOURCE_OBSERVATION_INVALID", "The trusted resolver returned a malformed GitHub Actions observation.");
  }
  try {
    validateSourcePath(observation.workflowPath);
  } catch (error) {
    if (error instanceof PublicIntakeError) {
      systemBlocked("SOURCE_OBSERVATION_INVALID", "The trusted resolver returned an unsafe GitHub Actions workflow path.");
    }
    throw error;
  }
  if (
    !observation.workflowPath.startsWith(".github/workflows/")
    || !/\.ya?ml$/u.test(observation.workflowPath)
  ) {
    systemBlocked("SOURCE_OBSERVATION_INVALID", "The trusted resolver returned an invalid GitHub Actions workflow path.");
  }
  const expectedUrl = `${binding.repositoryUri}/actions/runs/${expectedRunId}`;
  if (
    observation.runId !== expectedRunId
    || observation.headRevision !== binding.revisionObjectId
    || observation.headTree !== binding.treeObjectId
    || observation.htmlUrl !== expectedUrl
  ) {
    reject("GITHUB_ACTIONS_RUN_MISMATCH", "GitHub Actions evidence did not match its exact run, attempt, commit, tree, or repository.");
  }
}

function validateEvidenceObservations({
  application,
  compatibility,
  evidenceIndex,
  sourceObservation,
  blobObservations
}) {
  if (!Array.isArray(blobObservations)) {
    systemBlocked("EVIDENCE_OBSERVATION_INVALID", "The trusted evidence resolver returned a malformed observation list.");
  }
  const primary = application.source.primary;
  const expectedBlobs = evidenceIndex.evidence.filter((record) =>
    validateGitHubEvidenceUrl(record.url, "evidence.url", primary) === "blob"
  );
  if (blobObservations.length !== expectedBlobs.length) {
    systemBlocked("EVIDENCE_OBSERVATION_INVALID", "The trusted evidence resolver returned the wrong number of blob observations.");
  }
  const blobBindings = new Map();
  expectedBlobs.forEach((record, index) => {
    const observation = blobObservations[index];
    const expectedPath = evidenceBlobPath(record.url, primary);
    if (
      !isPlainObject(observation)
      || observation.id !== record.id
      || observation.path !== expectedPath
      || !SHA1_PATTERN.test(observation.blobObjectId ?? "")
      || !Buffer.isBuffer(observation.bytes)
    ) {
      systemBlocked("EVIDENCE_OBSERVATION_INVALID", "The trusted evidence resolver returned a malformed blob observation.");
    }
    const gitObjectId = crypto.createHash("sha1")
      .update(Buffer.from(`blob ${observation.bytes.length}\0`, "utf8"))
      .update(observation.bytes)
      .digest("hex");
    if (gitObjectId !== observation.blobObjectId) {
      systemBlocked("EVIDENCE_OBSERVATION_INVALID", "Resolved evidence bytes do not match their immutable Git blob object id.");
    }
    const digest = `sha256:${crypto.createHash("sha256").update(observation.bytes).digest("hex")}`;
    if (digest !== record.sha256) {
      reject("EVIDENCE_BLOB_DIGEST_MISMATCH", "Resolved GitHub evidence bytes do not match the declared SHA-256 digest.");
    }
    blobBindings.set(record.id, {
      id: record.id,
      kind: record.kind,
      declaredStatus: record.status,
      statusAuthority: "builder-declared-untrusted",
      identityAuthority: "github-observed",
      location: "blob",
      path: expectedPath,
      blobObjectId: observation.blobObjectId,
      sha256: digest
    });
  });

  const actionObservations = new Map(
    sourceObservation.primary.githubActionsEvidence.map((observation) => [observation.runId, observation])
  );
  const actionBindings = new Map();
  for (const record of evidenceIndex.evidence) {
    if (validateGitHubEvidenceUrl(record.url, "evidence.url", primary) !== "actions") continue;
    const runId = record.url.slice(record.url.lastIndexOf("/") + 1);
    const observation = actionObservations.get(runId);
    if (!observation) {
      systemBlocked("EVIDENCE_OBSERVATION_INVALID", "The trusted source resolver omitted a declared GitHub Actions run.");
    }
    validateActionEvidenceStatus(record.status, observation.status, observation.conclusion);
    actionBindings.set(record.id, {
      id: record.id,
      kind: record.kind,
      declaredStatus: record.status,
      statusAuthority: "github-observed",
      identityAuthority: "github-observed",
      location: "github-actions",
      runId: observation.runId,
      runAttempt: observation.runAttempt,
      workflowId: observation.workflowId,
      workflowPath: observation.workflowPath,
      headRevision: observation.headRevision,
      headTree: observation.headTree,
      event: observation.event,
      status: observation.status,
      conclusion: observation.conclusion,
      htmlUrl: observation.htmlUrl
    });
  }
  if (compatibility.result === "prototype-ready" && actionBindings.size === 0) {
    reject(
      "COMPATIBILITY_EVIDENCE_MISMATCH",
      "Prototype-ready compatibility requires an exact successful GitHub Actions observation."
    );
  }
  return evidenceIndex.evidence.map((record) => blobBindings.get(record.id) ?? actionBindings.get(record.id));
}

function validateActionEvidenceStatus(declaredStatus, status, conclusion) {
  const nonCompletedStatuses = new Set(["queued", "in_progress", "pending", "requested", "waiting"]);
  const failedConclusions = new Set(["failure", "startup_failure", "timed_out"]);
  const blockedConclusions = new Set(["action_required", "cancelled", "stale"]);
  let matches = false;
  if (declaredStatus === "passed") matches = status === "completed" && conclusion === "success";
  else if (declaredStatus === "failed") matches = status === "completed" && failedConclusions.has(conclusion);
  else if (declaredStatus === "blocked") {
    matches = (nonCompletedStatuses.has(status) && conclusion === null)
      || (status === "completed" && blockedConclusions.has(conclusion));
  } else if (declaredStatus === "not-run") {
    matches = status === "completed" && conclusion === "skipped";
  }
  if (!matches) {
    reject(
      "EVIDENCE_ACTION_STATUS_MISMATCH",
      "A builder-declared GitHub Actions evidence status does not match the exact run attempt outcome."
    );
  }
}

function sourceAuthorityProjection(source) {
  const project = (repository) => ({
    repositoryUri: repository.repositoryUri,
    numericRepositoryId: repository.numericRepositoryId,
    revisionObjectId: repository.revisionObjectId,
    treeObjectId: repository.treeObjectId
  });
  return {
    schemaVersion: GITHUB_PUBLIC_SOURCE_CONTRACT_V1.schemaVersion,
    primary: project(source.primary),
    companions: source.companions.map(project)
  };
}

function validateSourcePath(value) {
  if (!isCanonicalGitHubRepositoryPathV1(value)) {
    reject("SOURCE_PATH_INVALID", "A declared source path is outside the safe canonical path subset.");
  }
}

function validateFindingPath(value) {
  if (value === "$" || (typeof value === "string" && value.startsWith("$.") && value.length <= 240 && !hasForbiddenInvisibleOrBidi(value))) return;
  if (typeof value === "string") {
    try {
      validateSourcePath(value);
      return;
    } catch (error) {
      if (!(error instanceof PublicIntakeError)) throw error;
    }
  }
  reject("FINDING_PATH_INVALID", "A finding path is neither a canonical JSON path nor a safe source path.");
}

function validateSortedUniqueStrings(value, minimum, maximum, label, validateEntry) {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) {
    reject("ARRAY_LENGTH_INVALID", `${label} has an invalid item count.`);
  }
  let previous = null;
  for (const entry of value) {
    validateEntry(entry);
    if (previous !== null && compareUtf8(previous, entry) >= 0) reject("ARRAY_ORDER_INVALID", `${label} must be sorted and unique.`);
    previous = entry;
  }
}

function expectClosedObject(value, expectedKeys, label) {
  if (!isPlainObject(value)) reject("OBJECT_REQUIRED", `${label} must be an object.`);
  const observed = Object.keys(value).sort(compareUtf8);
  const expected = [...expectedKeys].sort(compareUtf8);
  if (!arraysEqual(observed, expected)) reject("OBJECT_NOT_CLOSED", `${label} has missing or unsupported properties.`);
}

function expectInteger(value, minimum, maximum, label) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) reject("INTEGER_INVALID", `${label} is outside its integer bounds.`);
}

function expectPattern(value, pattern, maximumLength, label) {
  if (typeof value !== "string" || value.length > maximumLength || !pattern.test(value)) reject("STRING_PATTERN_INVALID", `${label} has an invalid canonical format.`);
}

function expectText(value, minimumLength, maximumLength, label) {
  if (
    typeof value !== "string"
    || value.length < minimumLength
    || value.length > maximumLength
    || value.trim() !== value
    || hasForbiddenInvisibleOrBidi(value)
  ) {
    reject("TEXT_INVALID", `${label} is empty, oversized, padded, or contains unsafe characters.`);
  }
}

function validatePublicHttpsUrl(value, label) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    reject("URL_INVALID", `${label} is not a valid public HTTPS URL.`);
  }
  if (value.length > 500 || parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.hash) {
    reject("URL_INVALID", `${label} must be a credential-free public HTTPS URL without a fragment.`);
  }
}

function validateGitHubEvidenceUrl(value, label, primary) {
  validatePublicHttpsUrl(value, label);
  const blobUrls = new Set((primary.sourcePaths ?? []).map((sourcePath) =>
    `${primary.repositoryUri}/blob/${primary.revisionObjectId}/${encodeGitHubPath(sourcePath)}`
  ));
  if (blobUrls.has(value)) return "blob";
  const actionUrls = new Set((primary.githubActionsRunIds ?? []).map((runId) =>
    `${primary.repositoryUri}/actions/runs/${runId}`
  ));
  if (actionUrls.has(value)) return "actions";
  reject(
    "EVIDENCE_URL_SOURCE_MISMATCH",
    "Evidence must be an exact primary-repository blob at the declared commit or a declared GitHub Actions run."
  );
}

function evidenceBlobPath(value, primary) {
  for (const sourcePath of primary.sourcePaths ?? []) {
    if (value === `${primary.repositoryUri}/blob/${primary.revisionObjectId}/${encodeGitHubPath(sourcePath)}`) {
      return sourcePath;
    }
  }
  systemBlocked("EVIDENCE_RESOLUTION_INPUT_INVALID", "Trusted blob evidence was not bound to a declared source path.");
}

function encodeGitHubPath(value) {
  return value.split("/").map((segment) => encodeURIComponent(segment)).join("/");
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function arraysEqual(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function runGitText(root, args, maximumBytes) {
  return UTF8_DECODER.decode(runGit(root, args, maximumBytes));
}

function runGit(root, args, maximumBytes) {
  const result = childProcess.spawnSync(
    "git",
    [
      "-c", "core.hooksPath=/dev/null",
      "-c", "credential.helper=",
      "-C", root,
      ...args
    ],
    {
      encoding: null,
      shell: false,
      maxBuffer: maximumBytes,
      timeout: TRUSTED_GIT_TIMEOUT_MS,
      killSignal: "SIGKILL",
      env: trustedGitEnvironment()
    }
  );
  if (result.error || result.status !== 0 || !Buffer.isBuffer(result.stdout)) {
    systemBlocked("GIT_COMMAND_FAILED", "A fixed trusted Git inspection command failed.");
  }
  return result.stdout;
}

function trustedGitEnvironment() {
  const environment = Object.fromEntries(
    Object.entries(process.env).filter(([key]) => !/^(?:GIT_|SSH_)/u.test(key))
  );
  return {
    ...environment,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_NO_LAZY_FETCH: "1",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_TERMINAL_PROMPT: "0"
  };
}
