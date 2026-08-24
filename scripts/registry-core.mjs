import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { TextDecoder } from "node:util";

import {
  parseProgrammableLaunchRouterReadinessBytesV1,
  projectProgrammableLaunchRouterPolicyEvidenceV1
} from "./programmable-launch-router-readiness-core.mjs";
import { derivePublicApplicationV3PackageBindingV1 } from "./verify-public-application-v3-core.mjs";
import { safeRepositoryPath } from "./verify-public-application-v3-shared.mjs";

export const REGISTRY_SCHEMA_VERSION = "1.0.0";
export const PROGRAMMABLE_FEE_OWNER = "0x4957f49620AFf3Adbbe8195a4f633E49cc93376c";
export const PROJECT_STATUSES = Object.freeze([
  "accepted",
  "available",
  "candidate",
  "deployed",
  "design",
  "retired",
  "suspended"
]);

const MAX_CONFIG_BYTES = 64 * 1024;
const MAX_PROJECT_BYTES = 128 * 1024;
const MAX_ACCEPTANCE_BYTES = 64 * 1024;
const MAX_PROMOTION_BYTES = 768 * 1024;
const MAX_RECORDS = 10_000;
const MAX_JSON_DEPTH = 128;
const MAX_JSON_NODES = 2_000_000;
const CONTROL_OR_BIDI = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u00ad\u061c\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/u;
const SLUG = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const SHA1 = /^[0-9a-f]{40}$/u;
const SHA256 = /^sha256:[0-9a-f]{64}$/u;
const BYTES32 = /^0x[0-9A-Fa-f]{64}$/u;
const ADDRESS = /^0x[0-9A-Fa-f]{40}$/u;
const DECIMAL = /^(?:0|[1-9][0-9]{0,77})$/u;
const OPAQUE_ID = /^[1-9][0-9]{0,63}$/u;
const GITHUB_URI = /^https:\/\/github\.com\/[A-Za-z0-9-]+\/[A-Za-z0-9._-]+$/u;
const ZERO_ADDRESS = `0x${"0".repeat(40)}`;
const ZERO_BYTES32 = `0x${"0".repeat(64)}`;
const LAUNCH_POLICY_REPOSITORY_ID = "1320171831";
const PROGRAMMABLE_TREASURY = "0x4957f49620AFf3Adbbe8195a4f633E49cc93376c";
const DEVELOPER_WELL_KNOWN_URL = "https://developers.programmable.family/.well-known/programmable.json";
const DEVELOPER_MANIFEST_URL = "https://developers.programmable.family/api/v2/manifest";
const LAUNCH_STAMP_ABI_URL = "https://developers.programmable.family/abis/ethereum/programmable-launch-stamp-router-v1.json";
const decoder = new TextDecoder("utf-8", { fatal: true });

export class RegistryError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "RegistryError";
    this.code = code;
  }
}

export function loadRegistry({ repositoryRoot }) {
  const root = path.resolve(repositoryRoot);
  const config = readJsonFile(path.join(root, "registry/config.json"), MAX_CONFIG_BYTES, "registry config");
  validateConfig(config);
  const projects = config.projectPaths.map((relativePath) => {
    const absolutePath = resolveInside(root, relativePath);
    const bytes = readRegularFile(absolutePath, MAX_PROJECT_BYTES, `project ${relativePath}`);
    const project = parseJson(bytes, `project ${relativePath}`);
    validateProject(project, relativePath);
    const expectedPath = `registry/projects/${project.id}/project.json`;
    if (relativePath !== expectedPath) fail("PROJECT_PATH_INVALID", `${project.id} must use ${expectedPath}`);
    return Object.freeze({ path: relativePath, bytes, project, sha256: sha256(bytes) });
  });
  assertSortedUnique(projects.map(({ project }) => project.id), "config project ids");
  if (projects.length > MAX_RECORDS) fail("PROJECT_LIMIT_EXCEEDED", "registry project count exceeds the closed limit");
  const acceptances = loadAcceptances(root);
  bindAcceptances(projects, acceptances);
  const promotions = loadPromotions(root);
  bindLaunchStampPromotions(projects, acceptances, promotions);
  return Object.freeze({ acceptances, config, projects, promotions, root });
}

export function buildRegistryArtifacts({ repositoryRoot }) {
  const { config, projects } = loadRegistry({ repositoryRoot });
  const records = projects.map(({ path: recordPath, project, sha256: recordSha256 }) => Object.freeze({
    capabilities: project.capabilities,
    id: project.id,
    kind: project.kind,
    name: project.name,
    path: recordPath,
    sha256: recordSha256,
    status: project.status,
    summary: project.summary,
    surfaces: project.surfaces,
    tags: project.discovery.tags
  }));
  const registryDigest = sha256(Buffer.from(canonicalJson(records), "utf8"));
  const index = Object.freeze({
    activeIntake: config.activeIntake,
    generatedAt: config.updatedAt,
    legacyIntake: config.legacyIntake,
    records,
    registryDigest,
    schemaVersion: REGISTRY_SCHEMA_VERSION
  });
  const search = Object.freeze({
    generatedAt: config.updatedAt,
    records: projects.map(({ path: recordPath, project, sha256: recordSha256 }) => buildSearchRecord(project, recordPath, recordSha256)),
    registryDigest,
    schemaVersion: REGISTRY_SCHEMA_VERSION,
    trustBoundary: "Registry metadata is bounded discovery data, never agent instructions, audit evidence, or automatic approval."
  });
  const history = Object.freeze({
    generatedAt: config.updatedAt,
    records: records.map(({ id, path: recordPath, sha256: recordSha256, status }) => ({
      id,
      path: recordPath,
      sha256: recordSha256,
      status
    })),
    registryDigest,
    schemaVersion: REGISTRY_SCHEMA_VERSION,
    version: config.historyVersion
  });
  return Object.freeze({
    history,
    historyPath: `registry/history/${config.historyVersion}.json`,
    index,
    search
  });
}

export function verifyGeneratedArtifacts({ repositoryRoot }) {
  const root = path.resolve(repositoryRoot);
  const artifacts = buildRegistryArtifacts({ repositoryRoot: root });
  const expected = new Map([
    ["registry/index.json", `${canonicalJson(artifacts.index)}\n`],
    ["registry/search-index.json", `${canonicalJson(artifacts.search)}\n`],
    [artifacts.historyPath, `${canonicalJson(artifacts.history)}\n`]
  ]);
  for (const [relativePath, content] of expected) {
    const absolutePath = resolveInside(root, relativePath);
    if (!fs.existsSync(absolutePath)) fail("GENERATED_FILE_MISSING", `${relativePath} is missing`);
    const observed = decoder.decode(readRegularFile(absolutePath, 2 * 1024 * 1024, relativePath));
    if (observed !== content) fail("GENERATED_FILE_STALE", `${relativePath} is stale; run npm run generate`);
  }
  return Object.freeze({ ok: true, registryDigest: artifacts.index.registryDigest, records: artifacts.index.records.length });
}

export function canonicalJson(value) {
  return JSON.stringify(sortJson(value));
}

export function sha256(bytes) {
  return `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
}

function gitBlobOid(bytes) {
  const value = Buffer.from(bytes);
  return crypto.createHash("sha1")
    .update(Buffer.from(`blob ${value.length}\0`, "utf8"))
    .update(value)
    .digest("hex");
}

function buildSearchRecord(project, recordPath, recordSha256) {
  const tokens = tokenize([
    project.id,
    project.name,
    project.summary,
    project.discovery.mechanism,
    ...project.capabilities,
    ...project.discovery.outcomes,
    ...project.discovery.synonyms,
    ...project.discovery.tags,
    ...project.surfaces
  ].join(" "));
  return Object.freeze({
    capabilities: project.capabilities,
    id: project.id,
    kind: project.kind,
    mechanism: project.discovery.mechanism,
    name: project.name,
    outcomes: project.discovery.outcomes,
    path: recordPath,
    sha256: recordSha256,
    status: project.status,
    summary: project.summary,
    surfaces: project.surfaces,
    tags: project.discovery.tags,
    tokens
  });
}

function validateConfig(value) {
  exactKeys(value, ["activeIntake", "historyVersion", "legacyIntake", "projectPaths", "schemaVersion", "updatedAt"], "registry config");
  if (value.schemaVersion !== REGISTRY_SCHEMA_VERSION) fail("CONFIG_INVALID", "registry config schemaVersion is unsupported");
  if (!/^1\.[0-9]+\.[0-9]+$/u.test(value.historyVersion ?? "")) fail("CONFIG_INVALID", "historyVersion must be a v1 semantic version");
  requireTimestamp(value.updatedAt, "registry config updatedAt");
  exactKeys(value.activeIntake, ["baseBranch", "directory", "repository", "state"], "activeIntake");
  if (value.activeIntake.baseBranch !== "main" || value.activeIntake.directory !== "submissions" || value.activeIntake.repository !== "0xprogrammable/launch-policy") {
    fail("CONFIG_INVALID", "active intake identity is not canonical");
  }
  if (!new Set(["prelaunch", "open", "paused-new", "paused-all", "closed"]).has(value.activeIntake.state)) fail("CONFIG_INVALID", "active intake state is invalid");
  if (!Array.isArray(value.projectPaths) || value.projectPaths.length < 1 || value.projectPaths.length > MAX_RECORDS) fail("CONFIG_INVALID", "projectPaths is invalid");
  assertSortedUnique(value.projectPaths, "projectPaths");
  if (!Array.isArray(value.legacyIntake) || value.legacyIntake.length > 8) fail("CONFIG_INVALID", "legacyIntake is invalid");
  for (const record of value.legacyIntake) {
    exactKeys(record, ["baseBranch", "continuingPullRequests", "repository"], "legacy intake record");
    requireText(record.baseBranch, "legacy base branch", 255);
    if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(record.repository ?? "")) fail("CONFIG_INVALID", "legacy repository is invalid");
    if (!Array.isArray(record.continuingPullRequests) || record.continuingPullRequests.length > 64) fail("CONFIG_INVALID", "legacy pull requests are invalid");
    assertSortedUnique(record.continuingPullRequests, "legacy pull requests", { numeric: true });
  }
}

function validateProject(project, relativePath) {
  const projectKeys = ["capabilities", "chains", "discovery", "economics", "hook", "id", "kind", "name", "provenance", "relations", "review", "schemaVersion", "source", "status", "statusUpdatedAt", "summary", "surfaces", "warnings"];
  const hasPromotionPath = Object.hasOwn(project, "promotionPath");
  const hasPromotionSha256 = Object.hasOwn(project, "promotionSha256");
  if (hasPromotionPath !== hasPromotionSha256) fail("PROJECT_PROMOTION_BINDING_INVALID", `${relativePath} must bind both promotion path and digest`);
  if (hasPromotionPath) projectKeys.push("promotionPath", "promotionSha256");
  exactKeys(project, projectKeys, relativePath);
  if (project.schemaVersion !== REGISTRY_SCHEMA_VERSION || !SLUG.test(project.id ?? "")) fail("PROJECT_INVALID", `${relativePath} has an invalid identity`);
  if (!PROJECT_STATUSES.includes(project.status)) fail("PROJECT_INVALID", `${project.id} has an invalid status`);
  if (!new Set(["launch-model", "hook-project", "application-game", "application-service", "composite"]).has(project.kind)) fail("PROJECT_INVALID", `${project.id} has an invalid kind`);
  requireText(project.name, `${project.id}.name`, 160);
  requireText(project.summary, `${project.id}.summary`, 1000);
  requireTimestamp(project.statusUpdatedAt, `${project.id}.statusUpdatedAt`);
  for (const [label, values, limit] of [
    ["capabilities", project.capabilities, 64],
    ["surfaces", project.surfaces, 32]
  ]) validateSlugSet(values, `${project.id}.${label}`, limit);
  validateTextSet(project.warnings, `${project.id}.warnings`, 32, false);

  exactKeys(project.discovery, ["mechanism", "outcomes", "synonyms", "tags"], `${project.id}.discovery`);
  requireText(project.discovery.mechanism, `${project.id}.discovery.mechanism`, 1000);
  validateTextSet(project.discovery.outcomes, `${project.id}.discovery.outcomes`, 32, false);
  validateTextSet(project.discovery.synonyms, `${project.id}.discovery.synonyms`, 32, true);
  validateSlugSet(project.discovery.tags, `${project.id}.discovery.tags`, 32);

  exactKeys(project.economics, ["programmableFee", "summary"], `${project.id}.economics`);
  requireText(project.economics.summary, `${project.id}.economics.summary`, 1000);
  exactKeys(project.economics.programmableFee, ["claimOwner", "inclusiveBps", "policyId", "required"], `${project.id}.programmableFee`);
  if (project.economics.programmableFee.claimOwner !== PROGRAMMABLE_FEE_OWNER || project.economics.programmableFee.inclusiveBps !== 10 || project.economics.programmableFee.required !== true || project.economics.programmableFee.policyId !== "programmable-volume-fee-v1") {
    fail("PROJECT_FEE_POLICY_INVALID", `${project.id} does not preserve the mandatory Programmable fee identity`);
  }

  exactKeys(project.hook, ["beforeSwapReturnDelta", "canonicalPoolRequired", "contractNames", "permissions", "upgradeability", "used"], `${project.id}.hook`);
  if (![true, false, null].includes(project.hook.used) || ![true, false, null].includes(project.hook.beforeSwapReturnDelta) || typeof project.hook.canonicalPoolRequired !== "boolean") fail("PROJECT_INVALID", `${project.id} has invalid hook state`);
  validateTextSet(project.hook.contractNames, `${project.id}.hook.contractNames`, 32, true);
  validateSlugSet(project.hook.permissions, `${project.id}.hook.permissions`, 14);
  if (!new Set(["none", "immutable-factory", "upgradeable", "unknown"]).has(project.hook.upgradeability)) fail("PROJECT_INVALID", `${project.id} has invalid upgradeability`);

  if (!Array.isArray(project.chains) || project.chains.length < 1 || project.chains.length > 16) fail("PROJECT_INVALID", `${project.id}.chains is invalid`);
  const chainIds = [];
  for (const chain of project.chains) {
    exactKeys(chain, ["chainId", "deploymentEvidence", "network", "state"], `${project.id}.chain`);
    if (!Number.isSafeInteger(chain.chainId) || chain.chainId < 1) fail("PROJECT_INVALID", `${project.id} has an invalid chain id`);
    chainIds.push(chain.chainId);
    requireText(chain.network, `${project.id}.chain.network`, 160);
    if (chain.deploymentEvidence !== null) requireHttpsUri(chain.deploymentEvidence, `${project.id}.chain.deploymentEvidence`);
    if (!new Set(["proposed", "declared-addresses", "deployed", "source-verified", "lifecycle-verified", "available"]).has(chain.state)) fail("PROJECT_INVALID", `${project.id} has an invalid chain state`);
  }
  assertSortedUnique(chainIds, `${project.id}.chainIds`, { numeric: true });

  exactKeys(project.source, ["manifestPath", "numericRepositoryId", "repositoryUri", "revisionObjectId", "treeObjectId"], `${project.id}.source`);
  if (!GITHUB_URI.test(project.source.repositoryUri ?? "") || !OPAQUE_ID.test(project.source.numericRepositoryId ?? "") || !SHA1.test(project.source.revisionObjectId ?? "") || !SHA1.test(project.source.treeObjectId ?? "") || !/^[A-Za-z0-9._/-]{1,512}$/u.test(project.source.manifestPath ?? "") || project.source.manifestPath.includes("..")) fail("PROJECT_INVALID", `${project.id} has an invalid exact source identity`);

  exactKeys(project.provenance, ["importedFrom", "observedAt", "recordClass"], `${project.id}.provenance`);
  requireHttpsUri(project.provenance.importedFrom, `${project.id}.provenance.importedFrom`);
  requireTimestamp(project.provenance.observedAt, `${project.id}.provenance.observedAt`);
  if (!new Set(["legacy-platform-record", "maintainer-acceptance"]).has(project.provenance.recordClass)) fail("PROJECT_INVALID", `${project.id} has invalid provenance`);

  if (hasPromotionPath) {
    if (project.promotionPath !== `registry/promotions/${project.id}/${path.posix.basename(project.promotionPath ?? "")}` || !/^registry\/promotions\/[a-z0-9]+(?:-[a-z0-9]+)*\/0x[0-9a-f]{64}\.json$/u.test(project.promotionPath ?? "") || !SHA256.test(project.promotionSha256 ?? "")) {
      fail("PROJECT_PROMOTION_BINDING_INVALID", `${project.id} has an invalid launch-stamp promotion binding`);
    }
  }

  exactKeys(project.review, ["acceptancePath", "applicationPullRequest", "independentAudit", "limitations", "state"], `${project.id}.review`);
  if (project.review.acceptancePath !== null && !/^registry\/acceptances\/[a-z0-9][a-z0-9-]*\/[a-z0-9][a-z0-9.-]*\.json$/u.test(project.review.acceptancePath)) fail("PROJECT_INVALID", `${project.id} has an invalid acceptance path`);
  if (project.review.applicationPullRequest !== null) requireHttpsUri(project.review.applicationPullRequest, `${project.id}.review.applicationPullRequest`);
  if (typeof project.review.independentAudit !== "boolean" || !new Set(["legacy-record", "pending", "changes-requested", "accepted", "suspended", "retired"]).has(project.review.state)) fail("PROJECT_INVALID", `${project.id} has invalid review state`);
  validateTextSet(project.review.limitations, `${project.id}.review.limitations`, 32, false);

  exactKeys(project.relations, ["similarTo", "supersededBy", "supersedes"], `${project.id}.relations`);
  validateSlugSet(project.relations.similarTo, `${project.id}.relations.similarTo`, 32);
  validateSlugSet(project.relations.supersedes, `${project.id}.relations.supersedes`, 32);
  if (project.relations.supersededBy !== null && !SLUG.test(project.relations.supersededBy)) fail("PROJECT_INVALID", `${project.id} has invalid supersession`);
  for (const related of [...project.relations.similarTo, ...project.relations.supersedes, project.relations.supersededBy].filter(Boolean)) {
    if (related === project.id) fail("PROJECT_INVALID", `${project.id} cannot relate to itself`);
  }
}

function loadAcceptances(root) {
  const acceptanceRoot = path.join(root, "registry/acceptances");
  let rootStatus;
  try {
    rootStatus = fs.lstatSync(acceptanceRoot);
  } catch {
    fail("ACCEPTANCE_DIRECTORY_INVALID", "registry/acceptances is missing");
  }
  if (!rootStatus.isDirectory() || rootStatus.isSymbolicLink()) fail("ACCEPTANCE_DIRECTORY_INVALID", "registry/acceptances must be a regular directory");
  const records = [];
  for (const entry of fs.readdirSync(acceptanceRoot, { withFileTypes: true }).sort((left, right) => compareUtf8(left.name, right.name))) {
    if (entry.name === "README.md" && entry.isFile() && !entry.isSymbolicLink()) continue;
    if (!entry.isDirectory() || entry.isSymbolicLink() || !SLUG.test(entry.name)) fail("ACCEPTANCE_PATH_INVALID", "acceptance directories must use canonical project ids");
    const directory = path.join(acceptanceRoot, entry.name);
    for (const file of fs.readdirSync(directory, { withFileTypes: true }).sort((left, right) => compareUtf8(left.name, right.name))) {
      if (!file.isFile() || file.isSymbolicLink() || !/^[a-z0-9][a-z0-9.-]*\.json$/u.test(file.name)) fail("ACCEPTANCE_PATH_INVALID", "acceptance records must be canonical regular JSON files");
      const relativePath = `registry/acceptances/${entry.name}/${file.name}`;
      const bytes = readRegularFile(path.join(directory, file.name), MAX_ACCEPTANCE_BYTES, relativePath);
      const acceptance = parseJson(bytes, relativePath);
      validateAcceptance(acceptance, relativePath, entry.name);
      records.push(Object.freeze({ acceptance, bytes, path: relativePath, sha256: sha256(bytes) }));
      if (records.length > MAX_RECORDS) fail("ACCEPTANCE_LIMIT_EXCEEDED", "acceptance record count exceeds the closed limit");
    }
  }
  assertSortedUnique(records.map(({ path: recordPath }) => recordPath), "acceptance paths");
  return Object.freeze(records);
}

function validateAcceptance(acceptance, relativePath, projectId) {
  exactKeys(acceptance, ["acceptedAt", "acceptedBy", "application", "conditions", "decision", "projectRecordPath", "schemaVersion", "source"], relativePath);
  if (acceptance.schemaVersion !== REGISTRY_SCHEMA_VERSION || acceptance.decision !== "accepted-for-registry-promotion") fail("ACCEPTANCE_INVALID", `${relativePath} has an unsupported decision contract`);
  requireTimestamp(acceptance.acceptedAt, `${relativePath}.acceptedAt`);
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/u.test(acceptance.acceptedBy ?? "")) fail("ACCEPTANCE_INVALID", `${relativePath} has an invalid maintainer identity`);
  if (acceptance.projectRecordPath !== `registry/projects/${projectId}/project.json`) fail("ACCEPTANCE_INVALID", `${relativePath} points to the wrong project record`);
  validateTextSet(acceptance.conditions, `${relativePath}.conditions`, 32, false);

  exactKeys(acceptance.application, ["applicationId", "applicationRevision", "packageDigest", "pullRequest"], `${relativePath}.application`);
  if (acceptance.application.applicationId !== projectId || !Number.isSafeInteger(acceptance.application.applicationRevision) || acceptance.application.applicationRevision < 1 || !/^sha256:[0-9a-f]{64}$/u.test(acceptance.application.packageDigest ?? "") || !/^https:\/\/github\.com\/0xprogrammable\/(?:launch-policy|submit-launch)\/pull\/[1-9][0-9]{0,19}$/u.test(acceptance.application.pullRequest ?? "")) {
    fail("ACCEPTANCE_INVALID", `${relativePath} has an invalid application binding`);
  }
  exactKeys(acceptance.source, ["numericRepositoryId", "repositoryUri", "revisionObjectId", "treeObjectId"], `${relativePath}.source`);
  if (!GITHUB_URI.test(acceptance.source.repositoryUri ?? "") || !OPAQUE_ID.test(acceptance.source.numericRepositoryId ?? "") || !SHA1.test(acceptance.source.revisionObjectId ?? "") || !SHA1.test(acceptance.source.treeObjectId ?? "")) fail("ACCEPTANCE_INVALID", `${relativePath} has an invalid source binding`);
}

function bindAcceptances(projects, acceptances) {
  const byPath = new Map(acceptances.map((record) => [record.path, record]));
  const projectIds = new Set(projects.map(({ project }) => project.id));
  for (const { acceptance, path: acceptancePath } of acceptances) {
    if (!projectIds.has(acceptance.application.applicationId)) fail("ACCEPTANCE_ORPHANED", `${acceptancePath} has no project record`);
  }
  for (const { project } of projects) {
    const acceptancePath = project.review.acceptancePath;
    if (acceptancePath === null) {
      if (project.review.state === "accepted") fail("ACCEPTANCE_BINDING_MISSING", `${project.id} is accepted without an acceptance record`);
      continue;
    }
    const record = byPath.get(acceptancePath);
    if (!record) fail("ACCEPTANCE_BINDING_MISSING", `${project.id} points to a missing acceptance record`);
    const source = record.acceptance.source;
    if (
      source.repositoryUri !== project.source.repositoryUri
      || source.numericRepositoryId !== project.source.numericRepositoryId
      || source.revisionObjectId !== project.source.revisionObjectId
      || source.treeObjectId !== project.source.treeObjectId
    ) fail("ACCEPTANCE_SOURCE_MISMATCH", `${project.id} does not match its accepted exact source`);
    if (!new Set(["accepted", "suspended", "retired"]).has(project.review.state) || !new Set(["accepted", "deployed", "available", "suspended", "retired"]).has(project.status)) fail("ACCEPTANCE_STATE_INVALID", `${project.id} has an acceptance record in an incompatible state`);
  }
}

function loadPromotions(root) {
  const promotionRoot = path.join(root, "registry/promotions");
  let rootStatus;
  try {
    rootStatus = fs.lstatSync(promotionRoot);
  } catch {
    fail("PROMOTION_DIRECTORY_INVALID", "registry/promotions is missing");
  }
  if (!rootStatus.isDirectory() || rootStatus.isSymbolicLink()) fail("PROMOTION_DIRECTORY_INVALID", "registry/promotions must be a regular directory");
  const records = [];
  for (const entry of fs.readdirSync(promotionRoot, { withFileTypes: true }).sort((left, right) => compareUtf8(left.name, right.name))) {
    if (entry.name === "README.md" && entry.isFile() && !entry.isSymbolicLink()) continue;
    if (!entry.isDirectory() || entry.isSymbolicLink() || !SLUG.test(entry.name)) fail("PROMOTION_PATH_INVALID", "promotion directories must use canonical project ids");
    const directory = path.join(promotionRoot, entry.name);
    for (const file of fs.readdirSync(directory, { withFileTypes: true }).sort((left, right) => compareUtf8(left.name, right.name))) {
      if (!file.isFile() || file.isSymbolicLink() || !/^0x[0-9a-f]{64}\.json$/u.test(file.name)) fail("PROMOTION_PATH_INVALID", "promotion record names must be the canonical lowercase launch id plus .json");
      const relativePath = `registry/promotions/${entry.name}/${file.name}`;
      const bytes = readRegularFile(path.join(directory, file.name), MAX_PROMOTION_BYTES, relativePath);
      const promotion = parseJson(bytes, relativePath);
      validateLaunchStampPromotion(promotion, relativePath, entry.name);
      records.push(Object.freeze({ bytes, path: relativePath, promotion, sha256: sha256(bytes) }));
      if (records.length > MAX_RECORDS) fail("PROMOTION_LIMIT_EXCEEDED", "promotion record count exceeds the closed limit");
    }
  }
  assertSortedUnique(records.map(({ path: recordPath }) => recordPath), "promotion paths");
  return Object.freeze(records);
}

function validateLaunchStampPromotion(promotion, relativePath, directoryProjectId) {
  exactKeys(promotion, ["acceptance", "application", "authority", "componentProofs", "economics", "evidence", "launch", "lookups", "manifest", "observation", "policy", "projectId", "routePlan", "schemaVersion", "source", "verifiedAt"], relativePath);
  if (promotion.schemaVersion !== "1.0.0" || promotion.projectId !== directoryProjectId || !SLUG.test(promotion.projectId ?? "")) fail("PROMOTION_INVALID", `${relativePath} has an invalid identity`);
  requireTimestamp(promotion.verifiedAt, `${relativePath}.verifiedAt`);

  const application = promotion.application;
  exactKeys(application, ["applicationId", "applicationRevision", "applicationSha256", "packageDigest", "packagePreimage", "pullRequest"], `${relativePath}.application`);
  if (application.applicationId !== promotion.projectId || !Number.isSafeInteger(application.applicationRevision) || application.applicationRevision < 1 || application.applicationRevision > 1_000_000 || !SHA256.test(application.applicationSha256 ?? "") || !SHA256.test(application.packageDigest ?? "") || !/^https:\/\/github\.com\/0xprogrammable\/(?:launch-policy|submit-launch)\/pull\/[1-9][0-9]{0,19}$/u.test(application.pullRequest ?? "")) {
    fail("PROMOTION_APPLICATION_INVALID", `${relativePath} has an invalid exact application binding`);
  }

  const source = promotion.source;
  exactKeys(source, ["commit", "configurationHash", "numericRepositoryId", "repository", "tree"], `${relativePath}.source`);
  if (!SHA1.test(source.commit ?? "") || !SHA1.test(source.tree ?? "") || !OPAQUE_ID.test(source.numericRepositoryId ?? "") || !GITHUB_URI.test(source.repository ?? "") || !SHA256.test(source.configurationHash ?? "")) fail("PROMOTION_SOURCE_INVALID", `${relativePath} has an invalid exact source binding`);

  const acceptance = promotion.acceptance;
  exactKeys(acceptance, ["path", "sha256"], `${relativePath}.acceptance`);
  if (!acceptance.path?.startsWith(`registry/acceptances/${promotion.projectId}/`) || !/^registry\/acceptances\/[a-z0-9]+(?:-[a-z0-9]+)*\/[a-z0-9][a-z0-9.-]*\.json$/u.test(acceptance.path ?? "") || !SHA256.test(acceptance.sha256 ?? "")) fail("PROMOTION_ACCEPTANCE_INVALID", `${relativePath} has an invalid exact acceptance binding`);

  const policy = promotion.policy;
  exactKeys(policy, ["baseCommit", "baseTree", "gitBlobOid", "launchReadinessDecision", "launchReadinessDecisionSha256", "numericRepositoryId", "path", "policyId", "policyVersion", "profileId", "repository", "sha256"], `${relativePath}.policy`);
  if (policy.repository !== "0xprogrammable/launch-policy" || policy.numericRepositoryId !== LAUNCH_POLICY_REPOSITORY_ID || policy.path !== "policy/launch-policy.v1.json" || policy.policyId !== "programmable-central-launch-policy" || policy.policyVersion !== "2.1.0" || policy.profileId !== "launch-readiness" || !SHA1.test(policy.baseCommit ?? "") || !SHA1.test(policy.baseTree ?? "") || !SHA1.test(policy.gitBlobOid ?? "") || !SHA256.test(policy.sha256 ?? "") || !SHA256.test(policy.launchReadinessDecisionSha256 ?? "")) {
    fail("PROMOTION_POLICY_INVALID", `${relativePath} does not bind the exact launch-readiness policy projection`);
  }

  const routePlan = promotion.routePlan;
  exactKeys(routePlan, ["chainId", "configurationHash", "directFactoryCall", "executionPath", "gitBlobOid", "launchKind", "path", "sha256"], `${relativePath}.routePlan`);
  if (routePlan.chainId !== 1 || routePlan.directFactoryCall !== false || routePlan.executionPath !== "canonical-launch-stamp-router-v1") fail("PROMOTION_DIRECT_FACTORY", `${relativePath} is not bound to canonical Router execution`);
  if (!isCanonicalJsonPath(routePlan.path) || !SHA1.test(routePlan.gitBlobOid ?? "") || !SHA256.test(routePlan.sha256 ?? "") || !SHA256.test(routePlan.configurationHash ?? "") || ![1, 2].includes(routePlan.launchKind) || routePlan.configurationHash !== source.configurationHash) {
    fail("PROMOTION_ROUTE_PLAN_INVALID", `${relativePath} has an invalid exact route-plan binding`);
  }

  const evidence = promotion.evidence;
  exactKeys(evidence, ["promotion", "promotionId", "promotionSha256", "readinessBytes", "readinessId", "readinessSha256"], `${relativePath}.evidence`);
  if (evidence.promotionId !== "programmable-router-promotion" || evidence.readinessId !== "programmable-router-readiness" || !SHA256.test(evidence.promotionSha256 ?? "") || !SHA256.test(evidence.readinessSha256 ?? "")) fail("PROMOTION_EVIDENCE_INVALID", `${relativePath} has invalid policy evidence bindings`);

  const economics = promotion.economics;
  exactKeys(economics, ["basis", "bps", "hundredthsOfBip", "treasury"], `${relativePath}.economics`);
  if (economics.basis !== "gross-canonical-pool-volume" || economics.bps !== 10 || economics.hundredthsOfBip !== 1000 || economics.treasury !== PROGRAMMABLE_TREASURY) fail("PROMOTION_FEE_INVALID", `${relativePath} does not preserve the exact 10 bps treasury identity`);

  validatePromotionManifest(promotion.manifest, relativePath);
  validatePromotionObservation(promotion.observation, promotion.manifest, relativePath);
  validatePromotionLaunch(promotion, relativePath);
  if (path.posix.basename(relativePath) !== `${promotion.launch.launchId.toLowerCase()}.json`) fail("PROMOTION_PATH_LAUNCH_ID_MISMATCH", `${relativePath} filename does not match the exact launch id`);
  validatePromotionAuthority(promotion.authority, relativePath);
  validatePromotionReadiness(promotion, relativePath);
  validatePromotionApplicationPackagePreimage(promotion, relativePath);
  validatePromotionDecision(promotion, relativePath);
  validatePromotionEvidenceProjection(promotion, relativePath);
}

function validatePromotionApplicationPackagePreimage(promotion, relativePath) {
  const { application, evidence, launch, routePlan, source } = promotion;
  const preimage = application.packagePreimage;
  exactKeys(preimage, ["applicationBytes"], `${relativePath}.application.packagePreimage`);
  const binding = preimage.applicationBytes;
  exactKeys(binding, ["base64", "byteLength"], `${relativePath}.application.packagePreimage.applicationBytes`);
  if (
    typeof binding.base64 !== "string"
    || !Number.isSafeInteger(binding.byteLength)
    || binding.byteLength < 2
    || binding.byteLength > 262_144
  ) {
    fail("PROMOTION_APPLICATION_PREIMAGE_INVALID", `${relativePath} has an invalid bounded Application V3 root binding`);
  }

  const applicationBytes = Buffer.from(binding.base64, "base64");
  if (applicationBytes.length !== binding.byteLength || applicationBytes.toString("base64") !== binding.base64) {
    fail("PROMOTION_APPLICATION_PREIMAGE_INVALID", `${relativePath} Application V3 root Base64 or byte length is not canonical`);
  }
  if (sha256(applicationBytes) !== application.applicationSha256) {
    fail("PROMOTION_APPLICATION_PREIMAGE_DIGEST_MISMATCH", `${relativePath} applicationSha256 does not bind the exact embedded Application V3 root bytes`);
  }

  let document;
  let sourceText;
  try {
    sourceText = decoder.decode(applicationBytes);
    document = parseStrictJson(sourceText, `${relativePath}.application.packagePreimage.applicationBytes`, {
      maximumDepth: 256,
      maximumNodes: 250_000
    });
  } catch {
    fail("PROMOTION_APPLICATION_PREIMAGE_INVALID", `${relativePath} embedded Application V3 root is not bounded strict UTF-8 JSON`);
  }
  if (sourceText !== `${canonicalJson(document)}\n`) {
    fail("PROMOTION_APPLICATION_PREIMAGE_INVALID", `${relativePath} embedded Application V3 root is not canonical JSON followed by one LF`);
  }

  const records = document.reviewPackage?.records;
  const primary = document.source?.primary;
  const reports = document.source?.verificationReports;
  const rootRoutePlan = document.launchRequest?.routePlan;
  if (!Array.isArray(records) || !Array.isArray(reports) || !isPlainObject(primary) || !isPlainObject(rootRoutePlan)) {
    fail("PROMOTION_APPLICATION_ROOT_MISMATCH", `${relativePath} embedded Application V3 root lacks its closed source, route-plan, or review-package projection`);
  }

  const applicationRecords = records
    .filter((record) => record?.source === "application-package")
    .map((record) => {
      if (
        !isPlainObject(record)
        || !SLUG.test(record.kind ?? "")
        || !safeRepositoryPath(record.path)
        || record.path === "application.v3.json"
        || typeof record.mediaType !== "string"
        || record.mediaType.length < 1
        || record.mediaType.length > 200
        || record.mediaType.trim() !== record.mediaType
        || CONTROL_OR_BIDI.test(record.mediaType)
        || !Number.isSafeInteger(record.byteLength)
        || record.byteLength < 1
        || record.byteLength > 4 * 1024 * 1024
        || !SHA256.test(record.sha256 ?? "")
        || record.repositoryRef !== null
      ) {
        fail("PROMOTION_APPLICATION_PREIMAGE_INVALID", `${relativePath} embedded Application V3 package record is invalid`);
      }
      return {
        path: record.path,
        mediaType: record.mediaType,
        byteLength: record.byteLength,
        sha256: record.sha256
      };
    });
  if (
    applicationRecords.length < 1
    || applicationRecords.length > 99
    || new Set(applicationRecords.map(({ path: recordPath }) => recordPath)).size !== applicationRecords.length
  ) {
    fail("PROMOTION_APPLICATION_PREIMAGE_INVALID", `${relativePath} embedded Application V3 package record set is not closed and unique`);
  }

  let packageBinding;
  try {
    packageBinding = derivePublicApplicationV3PackageBindingV1({
      application: document,
      applicationBytes,
      applicationRecords
    });
  } catch {
    fail("PROMOTION_APPLICATION_PREIMAGE_INVALID", `${relativePath} embedded Application V3 package preimage cannot be derived`);
  }
  if (packageBinding.applicationSha256 !== application.applicationSha256 || packageBinding.packageSha256 !== application.packageDigest) {
    fail("PROMOTION_APPLICATION_PACKAGE_MISMATCH", `${relativePath} embedded Application V3 root is not a member of the accepted exact package digest`);
  }

  const sourceRepository = source.repository.slice("https://github.com/".length);
  const coverage = reports.filter((report) => report?.repositoryRef === primary.id);
  const readinessRecords = records.filter((record) => (
    record?.kind === "programmable-launch-router-readiness"
    && record?.source === "source-repository"
    && record?.repositoryRef === primary.id
    && record?.path === rootRoutePlan.path
    && record?.sha256 === rootRoutePlan.sha256
    && record?.byteLength === rootRoutePlan.byteLength
  ));
  const expectedCategory = launch.launchKind === 1 ? "custom" : "classic";
  if (
    document.schemaVersion !== 3
    || document.contract?.id !== "public-pr-application-v3"
    || document.contract?.version !== "3.2.0"
    || document.contract?.submissionStandard !== "2.1.0"
    || document.contract?.validatorProfile !== "intent-open-world-v2"
    || document.applicationId !== application.applicationId
    || document.applicationRevision !== String(application.applicationRevision)
    || primary.repositoryUri !== source.repository
    || primary.numericRepositoryId !== source.numericRepositoryId
    || primary.revisionObjectId !== source.commit
    || primary.treeObjectId !== source.tree
    || coverage.length !== 1
    || coverage[0].revisionObjectId !== source.commit
    || coverage[0].treeObjectId !== source.tree
    || coverage[0].closureSha256 !== source.configurationHash
    || coverage[0].result !== "VERIFIED"
    || document.launchRequest?.requestedRoute !== "programmable-ethereum-mainnet"
    || document.launchRequest?.category !== expectedCategory
    || document.launchRequest?.launchKind !== launch.launchKind
    || rootRoutePlan.schemaId !== "urn:programmable:launch-router-readiness:1.0.0"
    || rootRoutePlan.path !== routePlan.path
    || rootRoutePlan.gitBlobOid !== routePlan.gitBlobOid
    || rootRoutePlan.sha256 !== evidence.readinessSha256
    || rootRoutePlan.byteLength !== evidence.readinessBytes.byteLength
    || rootRoutePlan.repositoryRef?.repository !== sourceRepository
    || rootRoutePlan.repositoryRef?.numericRepositoryId !== source.numericRepositoryId
    || rootRoutePlan.repositoryRef?.commit !== source.commit
    || rootRoutePlan.repositoryRef?.tree !== source.tree
    || readinessRecords.length !== 1
  ) {
    fail("PROMOTION_APPLICATION_ROOT_MISMATCH", `${relativePath} accepted Application V3 root does not bind the exact application, source revision, readiness route, and launch kind`);
  }
}

function validatePromotionManifest(manifest, relativePath) {
  exactKeys(manifest, ["abiSha256", "abiUrl", "bindings", "chainId", "deploymentEvidenceSha256", "endBlock", "finalityConfirmations", "jsonPointer", "manifestSha256", "manifestUrl", "routerAddress", "runtimeCodeHash", "startBlock", "status", "wellKnownUrl"], `${relativePath}.manifest`);
  if (manifest.wellKnownUrl !== DEVELOPER_WELL_KNOWN_URL || manifest.manifestUrl !== DEVELOPER_MANIFEST_URL || manifest.jsonPointer !== "/launchStampRouter" || manifest.abiUrl !== LAUNCH_STAMP_ABI_URL || manifest.chainId !== 1 || !new Set(["live", "retired"]).has(manifest.status)) fail("PROMOTION_MANIFEST_INVALID", `${relativePath} does not bind the official Developer manifest route`);
  if (!SHA256.test(manifest.manifestSha256 ?? "") || !SHA256.test(manifest.abiSha256 ?? "") || !SHA256.test(manifest.deploymentEvidenceSha256 ?? "") || !isNonzeroAddress(manifest.routerAddress) || !isNonzeroBytes32(manifest.runtimeCodeHash) || !isDecimal(manifest.startBlock) || (manifest.endBlock !== null && !isDecimal(manifest.endBlock)) || !Number.isSafeInteger(manifest.finalityConfirmations) || manifest.finalityConfirmations < 1 || manifest.finalityConfirmations > 4096) fail("PROMOTION_MANIFEST_INVALID", `${relativePath} has invalid manifest identity or finality fields`);
  if ((manifest.status === "live" && manifest.endBlock !== null) || (manifest.status === "retired" && manifest.endBlock === null)) fail("PROMOTION_MANIFEST_INVALID", `${relativePath} has an inconsistent manifest activation range`);
  if (manifest.endBlock !== null && BigInt(manifest.endBlock) < BigInt(manifest.startBlock)) fail("PROMOTION_MANIFEST_INVALID", `${relativePath} has an inverted manifest activation range`);

  const bindings = manifest.bindings;
  exactKeys(bindings, ["graphFactory", "graphFactoryRuntimeCodeHash", "permitAuthority", "permitAuthorityRuntimeCodeHash", "poolManager", "poolManagerRuntimeCodeHash"], `${relativePath}.manifest.bindings`);
  for (const address of [bindings.graphFactory, bindings.permitAuthority, bindings.poolManager]) {
    if (!isNonzeroAddress(address)) fail("PROMOTION_MANIFEST_INVALID", `${relativePath} has an invalid manifest address binding`);
  }
  for (const runtimeHash of [bindings.graphFactoryRuntimeCodeHash, bindings.permitAuthorityRuntimeCodeHash, bindings.poolManagerRuntimeCodeHash]) {
    if (!isNonzeroBytes32(runtimeHash)) fail("PROMOTION_MANIFEST_INVALID", `${relativePath} has an invalid manifest runtime binding`);
  }
}

function validatePromotionObservation(observation, manifest, relativePath) {
  exactKeys(observation, ["blockHash", "blockNumber", "eventEmitter", "finality", "finalizedAtBlockHash", "finalizedAtBlockNumber", "logIndex", "observedAt", "outcome", "routerAddress", "routerRuntimeCodeHash", "rpcEvidenceSha256", "transactionHash", "transactionIndex", "transactionTo", "verificationMode"], `${relativePath}.observation`);
  if (observation.outcome !== "stamped" || observation.finality !== "finalized" || observation.verificationMode !== "canonical-router-point-lookup-v1") fail("PROMOTION_NOT_FINALIZED", `${relativePath} is not a finalized stamped observation`);
  requireTimestamp(observation.observedAt, `${relativePath}.observation.observedAt`);
  if (!isDecimal(observation.blockNumber) || !isDecimal(observation.finalizedAtBlockNumber) || !isDecimal(observation.transactionIndex) || !isDecimal(observation.logIndex) || !isNonzeroBytes32(observation.blockHash) || !isNonzeroBytes32(observation.finalizedAtBlockHash) || !isNonzeroBytes32(observation.transactionHash) || !SHA256.test(observation.rpcEvidenceSha256 ?? "")) fail("PROMOTION_OBSERVATION_INVALID", `${relativePath} has invalid finalized transaction evidence`);
  if (!sameAddress(observation.routerAddress, manifest.routerAddress) || !sameAddress(observation.transactionTo, manifest.routerAddress) || !sameAddress(observation.eventEmitter, manifest.routerAddress) || !sameBytes32(observation.routerRuntimeCodeHash, manifest.runtimeCodeHash)) fail("PROMOTION_ROUTER_MISMATCH", `${relativePath} was not observed from the manifest-resolved Router runtime`);

  const blockNumber = BigInt(observation.blockNumber);
  const finalizedAt = BigInt(observation.finalizedAtBlockNumber);
  if (blockNumber < BigInt(manifest.startBlock) || (manifest.endBlock !== null && blockNumber > BigInt(manifest.endBlock)) || finalizedAt < blockNumber || finalizedAt - blockNumber < BigInt(manifest.finalityConfirmations)) {
    fail("PROMOTION_NOT_FINALIZED", `${relativePath} is outside the manifest range or finality depth`);
  }
}

function validatePromotionLaunch(promotion, relativePath) {
  const launch = promotion.launch;
  exactKeys(launch, ["componentSetHash", "expectedResultHash", "hook", "launchId", "launchKind", "permitDigest", "poolId", "poolKeyHash", "poolManager", "routeLauncher", "routeLauncherRuntimeCodeHash", "routePayloadHash", "stampHash", "token"], `${relativePath}.launch`);
  if (![1, 2].includes(launch.launchKind) || launch.launchKind !== promotion.routePlan.launchKind) fail("PROMOTION_LAUNCH_KIND_MISMATCH", `${relativePath} has an inconsistent Router launch kind`);
  for (const address of [launch.hook, launch.poolManager, launch.routeLauncher, launch.token]) {
    if (!isNonzeroAddress(address)) fail("PROMOTION_LAUNCH_INVALID", `${relativePath} has an invalid launch address`);
  }
  for (const commitment of [launch.componentSetHash, launch.expectedResultHash, launch.launchId, launch.permitDigest, launch.poolId, launch.poolKeyHash, launch.routeLauncherRuntimeCodeHash, launch.routePayloadHash, launch.stampHash]) {
    if (!isNonzeroBytes32(commitment)) fail("PROMOTION_LAUNCH_INVALID", `${relativePath} has an invalid Router commitment`);
  }
  if (!sameAddress(launch.poolManager, promotion.manifest.bindings.poolManager)) fail("PROMOTION_LAUNCH_MISMATCH", `${relativePath} does not use the manifest-bound PoolManager`);
  if (launch.launchKind === 1 && (!sameAddress(launch.routeLauncher, promotion.manifest.bindings.graphFactory) || !sameBytes32(launch.routeLauncherRuntimeCodeHash, promotion.manifest.bindings.graphFactoryRuntimeCodeHash))) {
    fail("PROMOTION_DIRECT_FACTORY", `${relativePath} CustomGraph route does not match the manifest-bound Graph Factory under Router execution`);
  }

  const lookups = promotion.lookups;
  exactKeys(lookups, ["pool", "token"], `${relativePath}.lookups`);
  exactKeys(lookups.token, ["address", "launchId"], `${relativePath}.lookups.token`);
  exactKeys(lookups.pool, ["launchId", "poolId", "poolManager"], `${relativePath}.lookups.pool`);
  if (!sameAddress(lookups.token.address, launch.token) || !sameBytes32(lookups.token.launchId, launch.launchId) || !sameAddress(lookups.pool.poolManager, launch.poolManager) || !sameBytes32(lookups.pool.poolId, launch.poolId) || !sameBytes32(lookups.pool.launchId, launch.launchId)) {
    fail("PROMOTION_LOOKUP_MISMATCH", `${relativePath} token and pool lookups do not resolve the exact launch id`);
  }

  if (!Array.isArray(promotion.componentProofs) || promotion.componentProofs.length < 1 || promotion.componentProofs.length > 2) fail("PROMOTION_PROOF_MISMATCH", `${relativePath} has an invalid component-proof set`);
  const roles = new Set();
  const components = new Set();
  for (const proof of promotion.componentProofs) {
    exactKeys(proof, ["component", "componentRole", "launchId", "stampHash"], `${relativePath}.componentProof`);
    const normalizedComponent = normalizeAddress(proof.component);
    if (!new Set(["hook", "token"]).has(proof.componentRole) || !isNonzeroAddress(proof.component) || roles.has(proof.componentRole) || components.has(normalizedComponent) || !sameBytes32(proof.launchId, launch.launchId) || !sameBytes32(proof.stampHash, launch.stampHash)) fail("PROMOTION_PROOF_MISMATCH", `${relativePath} component proof does not match the launch record`);
    roles.add(proof.componentRole);
    components.add(normalizedComponent);
    const expected = proof.componentRole === "token" ? launch.token : launch.hook;
    if (!sameAddress(proof.component, expected)) fail("PROMOTION_PROOF_MISMATCH", `${relativePath} component proof is bound to the wrong component`);
  }
  if (!roles.has("token") || (launch.launchKind === 1 && !roles.has("hook")) || (launch.launchKind === 2 && roles.has("hook"))) fail("PROMOTION_PROOF_MISMATCH", `${relativePath} does not contain the launch-kind-specific component proofs`);
}

function validatePromotionReadiness(promotion, relativePath) {
  const { evidence, launch, manifest, routePlan, source } = promotion;
  const binding = evidence.readinessBytes;
  exactKeys(binding, ["base64", "byteLength"], `${relativePath}.evidence.readinessBytes`);
  if (
    typeof binding.base64 !== "string"
    || !Number.isSafeInteger(binding.byteLength)
    || binding.byteLength < 1
    || binding.byteLength > 196_608
  ) {
    fail("PROMOTION_READINESS_BYTES_INVALID", `${relativePath} has an invalid bounded readiness byte binding`);
  }
  const readinessBytes = Buffer.from(binding.base64, "base64");
  if (readinessBytes.length !== binding.byteLength || readinessBytes.toString("base64") !== binding.base64) {
    fail("PROMOTION_READINESS_BYTES_INVALID", `${relativePath} readiness Base64 or byte length is not canonical`);
  }
  if (sha256(readinessBytes) !== evidence.readinessSha256) {
    fail("PROMOTION_READINESS_DIGEST_MISMATCH", `${relativePath} readiness digest does not bind its exact embedded bytes`);
  }
  if (gitBlobOid(readinessBytes) !== routePlan.gitBlobOid || routePlan.sha256 !== evidence.readinessSha256) {
    fail("PROMOTION_READINESS_ROUTE_MISMATCH", `${relativePath} route plan does not bind the exact readiness bytes and Git blob`);
  }

  let parsed;
  let policyEvidence;
  try {
    parsed = parseProgrammableLaunchRouterReadinessBytesV1(readinessBytes);
    policyEvidence = projectProgrammableLaunchRouterPolicyEvidenceV1(parsed);
  } catch {
    fail("PROMOTION_READINESS_INVALID", `${relativePath} embedded readiness bytes do not satisfy the trusted closed Router checker`);
  }
  const document = parsed.document;
  const readiness = policyEvidence["programmable-router-readiness"];
  const launchRequirement = policyEvidence["programmable-launch-requirement"];
  const repository = source.repository.slice("https://github.com/".length);
  const subject = document.subject;
  const router = document.resolvedRouter;
  const route = document.route;
  const stampRequest = route?.commitments?.stampRequestV1;
  const routePayload = route?.commitments?.routePayload;
  const expectedResult = route?.commitments?.expectedResult;

  if (
    parsed.documentSha256 !== evidence.readinessSha256
    || document.state !== "prelaunch-bound"
    || promotion.routePlan.path !== ".programmable/launch-router-readiness.v1.json"
    || subject?.applicationId !== promotion.application.applicationId
    || subject?.applicationRevision !== promotion.application.applicationRevision
    || subject?.sourceRepository !== repository
    || subject?.sourceRepositoryNumericId !== source.numericRepositoryId
    || subject?.sourceCommit !== source.commit
    || subject?.sourceTree !== source.tree
    || subject?.sourceConfigurationHash !== source.configurationHash
    || route?.executionPath !== routePlan.executionPath
    || route?.directFactoryCall !== false
    || route?.directFactoryFallbackAllowed !== false
    || route?.launchKind !== routePlan.launchKind
    || route?.transactionTarget !== router?.address
    || route?.sourceIdentity?.repository !== repository
    || route?.sourceIdentity?.numericRepositoryId !== source.numericRepositoryId
    || route?.sourceIdentity?.commit !== source.commit
    || route?.sourceIdentity?.tree !== source.tree
    || route?.sourceIdentity?.configurationHash !== source.configurationHash
    || readiness?.status !== "passed"
    || readiness?.chainId !== 1
    || readiness?.directFactoryCall !== false
    || readiness?.discoveryDocumentUrl !== DEVELOPER_WELL_KNOWN_URL
    || readiness?.manifestUrl !== DEVELOPER_MANIFEST_URL
    || readiness?.routerManifestPointer !== "/launchStampRouter"
    || readiness?.launchEntryPoint !== "launchAndStampV1"
    || readiness?.launchKind !== launch.launchKind
    || readiness?.routeEvidenceSha256 !== evidence.readinessSha256
    || readiness?.manifestSha256 !== manifest.manifestSha256
    || readiness?.abiSha256 !== manifest.abiSha256
    || readiness?.abiUrl !== manifest.abiUrl
    || !sameAddress(readiness?.routerAddress, manifest.routerAddress)
    || !sameBytes32(readiness?.routerRuntimeCodeHash, manifest.runtimeCodeHash)
    || readiness?.routerStatus !== manifest.status
    || readiness?.sourceCommit !== source.commit
    || readiness?.sourceTree !== source.tree
    || readiness?.sourceConfigurationHash !== source.configurationHash
    || launchRequirement?.status !== "passed"
    || launchRequirement?.chainId !== 1
    || launchRequirement?.network !== "ethereum-mainnet"
    || launchRequirement?.basis !== promotion.economics.basis
    || launchRequirement?.hundredthsOfBip !== promotion.economics.hundredthsOfBip
    || !sameAddress(launchRequirement?.treasury, promotion.economics.treasury)
  ) {
    fail("PROMOTION_READINESS_MISMATCH", `${relativePath} readiness decision evidence is not bound to the exact application, source, route, policy evidence, and fee identity`);
  }

  if (
    !sameAddress(router?.address, manifest.routerAddress)
    || !sameBytes32(router?.runtimeCodeHash, manifest.runtimeCodeHash)
    || router?.abiSha256 !== manifest.abiSha256
    || router?.abiUrl !== manifest.abiUrl
    || router?.startBlock !== manifest.startBlock
    || router?.endBlock !== manifest.endBlock
    || router?.finalityConfirmations !== manifest.finalityConfirmations
    || router?.status !== manifest.status
    || router?.deploymentEvidence?.evidenceSha256 !== manifest.deploymentEvidenceSha256
    || !sameAddress(router?.bindings?.graphFactory, manifest.bindings.graphFactory)
    || !sameBytes32(router?.bindings?.graphFactoryRuntimeCodeHash, manifest.bindings.graphFactoryRuntimeCodeHash)
    || !sameAddress(router?.bindings?.permitAuthority, manifest.bindings.permitAuthority)
    || !sameBytes32(router?.bindings?.permitAuthorityRuntimeCodeHash, manifest.bindings.permitAuthorityRuntimeCodeHash)
    || !sameAddress(router?.bindings?.poolManager, manifest.bindings.poolManager)
    || !sameBytes32(router?.bindings?.poolManagerRuntimeCodeHash, manifest.bindings.poolManagerRuntimeCodeHash)
  ) {
    fail("PROMOTION_READINESS_MANIFEST_MISMATCH", `${relativePath} readiness bytes do not resolve to the promoted manifest Router and runtime bindings`);
  }

  if (
    !sameBytes32(stampRequest?.launchId, launch.launchId)
    || !sameAddress(stampRequest?.token, launch.token)
    || !sameAddress(stampRequest?.poolKey?.hooks, launch.hook)
    || !sameBytes32(stampRequest?.componentSetHash, launch.componentSetHash)
    || !sameBytes32(stampRequest?.poolKeyHash, launch.poolKeyHash)
    || !sameBytes32(routePayload?.keccak256, launch.routePayloadHash)
    || !sameBytes32(expectedResult?.hash, launch.expectedResultHash)
  ) {
    fail("PROMOTION_READINESS_LAUNCH_MISMATCH", `${relativePath} finalized launch is not the exact route and stamp request committed by readiness`);
  }
}

function validatePromotionDecision(promotion, relativePath) {
  const { policy } = promotion;
  const decision = policy.launchReadinessDecision;
  const decisionKeys = [
    "advisories",
    "authority",
    "currentPolicyBinding",
    "currentSubject",
    "digest",
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
  exactKeys(decision, decisionKeys, `${relativePath}.policy.launchReadinessDecision`);
  const withoutDigest = Object.fromEntries(decisionKeys.filter((key) => key !== "digest").map((key) => [key, decision[key]]));
  const expectedDigest = sha256(Buffer.from(canonicalJson(withoutDigest), "utf8"));
  if (!SHA256.test(decision.digest ?? "") || decision.digest !== expectedDigest || policy.launchReadinessDecisionSha256 !== decision.digest) {
    fail("PROMOTION_DECISION_DIGEST_MISMATCH", `${relativePath} launch-readiness digest does not bind the exact embedded canonical decision`);
  }

  const authority = {
    checkerOnly: true,
    independentAudit: false,
    launchAuthorized: false,
    publicRoutingAuthorized: false,
    realFundsAuthorized: false
  };
  const trustedPolicy = {
    baseCommit: policy.baseCommit,
    baseTree: policy.baseTree,
    gitBlobOid: policy.gitBlobOid,
    numericRepositoryId: policy.numericRepositoryId,
    path: policy.path,
    policyId: policy.policyId,
    policyVersion: policy.policyVersion,
    profileId: policy.profileId,
    repository: policy.repository,
    sha256: policy.sha256
  };
  const policyBinding = {
    ...trustedPolicy,
    schemaVersion: "programmable.launch-policy-binding.v1"
  };
  const sourceRepository = promotion.source.repository.slice("https://github.com/".length);
  const subject = {
    applicationId: promotion.application.applicationId,
    applicationRevision: promotion.application.applicationRevision,
    applicationSha256: promotion.application.applicationSha256,
    commit: promotion.source.commit,
    configurationHash: promotion.source.configurationHash,
    numericRepositoryId: promotion.source.numericRepositoryId,
    packageSha256: promotion.application.packageDigest,
    repository: sourceRepository,
    routerProvenanceRequired: true,
    tree: promotion.source.tree,
    usesUniswapV4: true
  };
  const evaluations = [
    {
      analyzer: { id: "ethereum-treasury-10-bps-v1", kind: "deterministic" },
      evidenceRefs: [promotion.evidence.readinessSha256],
      ruleId: "LAUNCH.ETHEREUM_AND_TREASURY_10_BPS",
      state: "passed"
    },
    {
      analyzer: { id: "programmable-router-readiness-v1", kind: "deterministic" },
      evidenceRefs: [promotion.evidence.readinessSha256],
      ruleId: "LAUNCH.ETHEREUM_ROUTER_PROVENANCE_READINESS",
      state: "passed"
    }
  ].sort((left, right) => compareUtf8(canonicalJson(left), canonicalJson(right)));

  if (
    decision.schemaVersion !== "programmable.launch-policy-review-decision.v1"
    || decision.profileId !== "launch-readiness"
    || decision.status !== "passed"
    || decision.outcome !== "LAUNCH_READINESS_CHECKED_NOT_AUTHORIZED"
    || canonicalJson(decision.authority) !== canonicalJson(authority)
    || canonicalJson(decision.trustedPolicy) !== canonicalJson(trustedPolicy)
    || canonicalJson(decision.expectedPolicyBinding) !== canonicalJson(policyBinding)
    || canonicalJson(decision.currentPolicyBinding) !== canonicalJson(policyBinding)
    || canonicalJson(decision.expectedSubject) !== canonicalJson(subject)
    || canonicalJson(decision.currentSubject) !== canonicalJson(subject)
    || canonicalJson(decision.evaluations) !== canonicalJson(evaluations)
    || ![decision.advisories, decision.findings, decision.notApplicableRuleIds, decision.pendingRuleIds].every((items) => Array.isArray(items) && items.length === 0)
  ) {
    fail("PROMOTION_DECISION_INVALID", `${relativePath} does not embed the exact passed checker-only launch-readiness decision for this application, source, policy, and readiness evidence`);
  }
}

function validatePromotionEvidenceProjection(promotion, relativePath) {
  const evidence = promotion.evidence.promotion;
  const keys = [
    "abiSha256",
    "blockHash",
    "blockNumber",
    "canonicalBlockFinalized",
    "chainId",
    "componentSetHash",
    "confirmations",
    "discoveryDocumentUrl",
    "expectedResultHash",
    "finalityConfirmations",
    "hook",
    "launchId",
    "launchKind",
    "lookupMatched",
    "manifestSha256",
    "manifestUrl",
    "permitDigest",
    "poolId",
    "poolManager",
    "promotionEvidenceSha256",
    "promotionTargets",
    "routeBindingMatched",
    "routeLauncher",
    "routeLauncherRuntimeCodeHash",
    "routePayloadHash",
    "routerAddress",
    "routerManifestPointer",
    "routerRuntimeCodeHash",
    "sourceCommit",
    "sourceConfigurationHash",
    "sourceDeploymentBindingSha256",
    "sourceTree",
    "stampHash",
    "stampProofMatched",
    "status",
    "token",
    "transactionHash"
  ];
  exactKeys(evidence, keys, `${relativePath}.evidence.promotion`);
  const expectedDigest = sha256(Buffer.from(canonicalJson(evidence), "utf8"));
  if (promotion.evidence.promotionSha256 !== expectedDigest) {
    fail("PROMOTION_EVIDENCE_DIGEST_MISMATCH", `${relativePath} promotion evidence digest does not bind its exact canonical projection`);
  }

  const blockNumber = BigInt(promotion.observation.blockNumber);
  const finalizedAt = BigInt(promotion.observation.finalizedAtBlockNumber);
  const confirmations = finalizedAt - blockNumber;
  if (blockNumber > BigInt(Number.MAX_SAFE_INTEGER) || confirmations > 1_000_000n) {
    fail("PROMOTION_EVIDENCE_INVALID", `${relativePath} promotion evidence exceeds the bounded policy projection`);
  }
  const expected = {
    abiSha256: promotion.manifest.abiSha256,
    blockHash: promotion.observation.blockHash,
    blockNumber: Number(blockNumber),
    canonicalBlockFinalized: true,
    chainId: 1,
    componentSetHash: promotion.launch.componentSetHash,
    confirmations: Number(confirmations),
    discoveryDocumentUrl: promotion.manifest.wellKnownUrl,
    expectedResultHash: promotion.launch.expectedResultHash,
    finalityConfirmations: promotion.manifest.finalityConfirmations,
    hook: promotion.launch.hook,
    launchId: promotion.launch.launchId,
    launchKind: promotion.launch.launchKind,
    lookupMatched: true,
    manifestSha256: promotion.manifest.manifestSha256,
    manifestUrl: promotion.manifest.manifestUrl,
    permitDigest: promotion.launch.permitDigest,
    poolId: promotion.launch.poolId,
    poolManager: promotion.launch.poolManager,
    promotionEvidenceSha256: promotion.observation.rpcEvidenceSha256,
    promotionTargets: ["api-v2", "indexer", "public-discovery", "registry"],
    routeBindingMatched: true,
    routeLauncher: promotion.launch.routeLauncher,
    routeLauncherRuntimeCodeHash: promotion.launch.routeLauncherRuntimeCodeHash,
    routePayloadHash: promotion.launch.routePayloadHash,
    routerAddress: promotion.manifest.routerAddress,
    routerManifestPointer: promotion.manifest.jsonPointer,
    routerRuntimeCodeHash: promotion.manifest.runtimeCodeHash,
    sourceCommit: promotion.source.commit,
    sourceConfigurationHash: promotion.source.configurationHash,
    sourceDeploymentBindingSha256: promotion.manifest.deploymentEvidenceSha256,
    sourceTree: promotion.source.tree,
    stampHash: promotion.launch.stampHash,
    stampProofMatched: true,
    status: "passed",
    token: promotion.launch.token,
    transactionHash: promotion.observation.transactionHash
  };
  if (canonicalJson(evidence) !== canonicalJson(expected)) {
    fail("PROMOTION_EVIDENCE_PROJECTION_MISMATCH", `${relativePath} promotion evidence is not derived from the exact finalized Router, source, launch, lookup, pool, and stamp record`);
  }
}

function validatePromotionAuthority(authority, relativePath) {
  const keys = ["auditClaim", "currentLiquidityClaim", "currentTradabilityClaim", "fundsAuthority", "launchAuthority", "registryWriteAuthority", "safetyClaim", "sellabilityClaim", "terminalSupportClaim"];
  exactKeys(authority, keys, `${relativePath}.authority`);
  if (keys.some((key) => authority[key] !== false)) fail("PROMOTION_AUTHORITY_INVALID", `${relativePath} must remain non-authoritative and non-safety evidence`);
}

function bindLaunchStampPromotions(projects, acceptances, promotions) {
  const byPath = new Map(promotions.map((record) => [record.path, record]));
  const acceptanceByPath = new Map(acceptances.map((record) => [record.path, record]));
  const projectIds = new Set(projects.map(({ project }) => project.id));
  for (const { path: promotionPath, promotion } of promotions) {
    if (!projectIds.has(promotion.projectId)) fail("PROMOTION_ORPHANED", `${promotionPath} has no project record`);
  }

  for (const { project } of projects) {
    const ethereumChain = project.chains.find(({ chainId }) => chainId === 1);
    const futureEthereumMarket = project.provenance.recordClass === "maintainer-acceptance" && ethereumChain !== undefined && project.surfaces.includes("uniswap-v4-pool");
    const promotedAvailable = project.status === "available";
    const preservedLifecycle = new Set(["suspended", "retired"]).has(project.status);
    const promotionRequired = futureEthereumMarket && (promotedAvailable || preservedLifecycle);
    const hasBinding = Object.hasOwn(project, "promotionPath") && Object.hasOwn(project, "promotionSha256");

    if (promotedAvailable && futureEthereumMarket && !new Set(["lifecycle-verified", "available"]).has(ethereumChain.state)) fail("PROJECT_PROMOTION_STATE_INVALID", `${project.id} cannot be available before Ethereum lifecycle verification`);
    if (promotionRequired && !hasBinding) fail("PROMOTION_REQUIRED", `${project.id} requires finalized canonical Router evidence before availability promotion`);
    if (!hasBinding) continue;
    if (!futureEthereumMarket) fail("PROMOTION_NOT_APPLICABLE", `${project.id} is not a future maintainer-accepted Ethereum market record`);

    const record = byPath.get(project.promotionPath);
    if (!record) fail("PROMOTION_BINDING_MISSING", `${project.id} points to a missing launch-stamp promotion record`);
    if (record.sha256 !== project.promotionSha256) fail("PROMOTION_DIGEST_MISMATCH", `${project.id} promotion bytes do not match the project digest`);
    const promotion = record.promotion;
    if (promotion.projectId !== project.id) fail("PROMOTION_PROJECT_MISMATCH", `${project.id} promotion record selects another project`);

    const acceptanceRecord = acceptanceByPath.get(promotion.acceptance.path);
    if (!acceptanceRecord || project.review.acceptancePath !== promotion.acceptance.path || acceptanceRecord.sha256 !== promotion.acceptance.sha256) fail("PROMOTION_ACCEPTANCE_MISMATCH", `${project.id} promotion does not bind the selected exact acceptance`);
    const acceptedApplication = acceptanceRecord.acceptance.application;
    if (promotion.application.applicationId !== acceptedApplication.applicationId || promotion.application.applicationRevision !== acceptedApplication.applicationRevision || promotion.application.packageDigest !== acceptedApplication.packageDigest || promotion.application.pullRequest !== acceptedApplication.pullRequest || promotion.application.pullRequest !== project.review.applicationPullRequest) {
      fail("PROMOTION_APPLICATION_MISMATCH", `${project.id} promotion does not bind the accepted exact application`);
    }
    const acceptedSource = acceptanceRecord.acceptance.source;
    if (promotion.source.numericRepositoryId !== acceptedSource.numericRepositoryId || promotion.source.repository !== acceptedSource.repositoryUri || promotion.source.commit !== acceptedSource.revisionObjectId || promotion.source.tree !== acceptedSource.treeObjectId || promotion.source.numericRepositoryId !== project.source.numericRepositoryId || promotion.source.repository !== project.source.repositoryUri || promotion.source.commit !== project.source.revisionObjectId || promotion.source.tree !== project.source.treeObjectId) {
      fail("PROMOTION_SOURCE_MISMATCH", `${project.id} promotion does not bind the accepted exact source`);
    }
    if (promotion.economics.treasury !== project.economics.programmableFee.claimOwner || promotion.economics.bps !== project.economics.programmableFee.inclusiveBps) fail("PROMOTION_FEE_MISMATCH", `${project.id} promotion does not match the Registry fee identity`);
  }
}

function readJsonFile(filePath, maximumBytes, label) {
  return parseJson(readRegularFile(filePath, maximumBytes, label), label);
}

function parseJson(bytes, label) {
  try {
    return parseStrictJson(decoder.decode(bytes), label);
  } catch {
    fail("JSON_INVALID", `${label} is not closed lossless JSON`);
  }
}

function parseStrictJson(source, label, {
  maximumDepth = MAX_JSON_DEPTH,
  maximumNodes = MAX_JSON_NODES
} = {}) {
  let cursor = 0;
  let nodes = 0;

  const invalid = (message) => {
    throw new SyntaxError(`${label}: ${message}`);
  };
  const skipWhitespace = () => {
    while (cursor < source.length && /[\u0009\u000a\u000d\u0020]/u.test(source[cursor])) cursor += 1;
  };
  const parseString = () => {
    if (source[cursor] !== "\"") invalid("expected string");
    const start = cursor;
    cursor += 1;
    let escaped = false;
    while (cursor < source.length) {
      const character = source[cursor];
      if (!escaped && character === "\"") {
        cursor += 1;
        const value = JSON.parse(source.slice(start, cursor));
        if (hasLoneSurrogate(value)) invalid("lone surrogate in string");
        return value;
      }
      if (!escaped && character === "\\") escaped = true;
      else escaped = false;
      cursor += 1;
    }
    invalid("unterminated string");
  };
  const parseValue = (depth) => {
    nodes += 1;
    if (nodes > maximumNodes || depth > maximumDepth) invalid("structure exceeds bounds");
    skipWhitespace();
    const character = source[cursor];
    if (character === "{") {
      cursor += 1;
      skipWhitespace();
      const output = {};
      const keys = new Set();
      if (source[cursor] === "}") {
        cursor += 1;
        return output;
      }
      while (cursor < source.length) {
        skipWhitespace();
        const key = parseString();
        if (keys.has(key)) invalid(`duplicate object key ${JSON.stringify(key)}`);
        keys.add(key);
        skipWhitespace();
        if (source[cursor] !== ":") invalid("expected colon");
        cursor += 1;
        output[key] = parseValue(depth + 1);
        skipWhitespace();
        if (source[cursor] === "}") {
          cursor += 1;
          return output;
        }
        if (source[cursor] !== ",") invalid("expected comma");
        cursor += 1;
      }
      invalid("unterminated object");
    }
    if (character === "[") {
      cursor += 1;
      skipWhitespace();
      const output = [];
      if (source[cursor] === "]") {
        cursor += 1;
        return output;
      }
      while (cursor < source.length) {
        output.push(parseValue(depth + 1));
        skipWhitespace();
        if (source[cursor] === "]") {
          cursor += 1;
          return output;
        }
        if (source[cursor] !== ",") invalid("expected comma");
        cursor += 1;
      }
      invalid("unterminated array");
    }
    if (character === "\"") return parseString();
    for (const [token, value] of [["true", true], ["false", false], ["null", null]]) {
      if (source.startsWith(token, cursor)) {
        cursor += token.length;
        return value;
      }
    }
    const number = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u.exec(source.slice(cursor));
    if (number) {
      cursor += number[0].length;
      const value = Number(number[0]);
      if (!Number.isSafeInteger(value)) invalid("only safe integers are supported");
      return value;
    }
    invalid("unexpected token");
  };

  const parsed = parseValue(0);
  skipWhitespace();
  if (cursor !== source.length) invalid("trailing data");
  return parsed;
}

function hasLoneSurrogate(value) {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function readRegularFile(filePath, maximumBytes, label) {
  let stat;
  try {
    stat = fs.lstatSync(filePath);
  } catch {
    fail("FILE_MISSING", `${label} is missing`);
  }
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o111) !== 0 || stat.size < 2 || stat.size > maximumBytes) fail("FILE_INVALID", `${label} must be a bounded non-executable regular file`);
  return fs.readFileSync(filePath);
}

function resolveInside(root, relativePath) {
  if (typeof relativePath !== "string" || relativePath.startsWith("/") || relativePath.includes("\\") || relativePath.split("/").some((part) => part === "" || part === "." || part === "..")) fail("PATH_INVALID", "registry path is not canonical");
  const resolved = path.resolve(root, relativePath);
  if (!resolved.startsWith(`${root}${path.sep}`)) fail("PATH_INVALID", "registry path escapes the repository");
  return resolved;
}

function exactKeys(value, keys, label) {
  if (!isPlainObject(value) || !arraysEqual(Object.keys(value).sort(compareUtf8), [...keys].sort(compareUtf8))) fail("SHAPE_INVALID", `${label} has an unexpected shape`);
}

function validateSlugSet(values, label, maximum) {
  if (!Array.isArray(values) || values.length > maximum || values.some((value) => typeof value !== "string" || !SLUG.test(value))) fail("SET_INVALID", `${label} is invalid`);
  assertSortedUnique(values, label);
}

function validateTextSet(values, label, maximum, sorted) {
  if (!Array.isArray(values) || values.length > maximum) fail("SET_INVALID", `${label} is invalid`);
  values.forEach((value, index) => requireText(value, `${label}[${index}]`, 1000));
  if (new Set(values).size !== values.length) fail("SET_INVALID", `${label} contains duplicates`);
  if (sorted) assertSortedUnique(values, label);
}

function assertSortedUnique(values, label, { numeric = false } = {}) {
  if (!Array.isArray(values) || new Set(values).size !== values.length) fail("SET_INVALID", `${label} contains duplicates`);
  const expected = [...values].sort(numeric ? ((a, b) => a - b) : compareUtf8);
  if (!arraysEqual(values, expected)) fail("SET_INVALID", `${label} must be sorted`);
}

function requireText(value, label, maximum) {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum || value.trim() !== value || CONTROL_OR_BIDI.test(value)) fail("TEXT_INVALID", `${label} is invalid`);
}

function requireTimestamp(value, label) {
  requireText(value, label, 64);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u.test(value) || Number.isNaN(Date.parse(value))) fail("TIMESTAMP_INVALID", `${label} must be canonical UTC`);
}

function requireHttpsUri(value, label) {
  requireText(value, label, 2048);
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    fail("URI_INVALID", `${label} is invalid`);
  }
  if (parsed.protocol !== "https:" || parsed.username !== "" || parsed.password !== "" || parsed.hash !== "") fail("URI_INVALID", `${label} must be a clean HTTPS URI`);
}

function isCanonicalJsonPath(value) {
  return typeof value === "string"
    && value.length >= 1
    && value.length <= 1024
    && value.endsWith(".json")
    && !value.startsWith("/")
    && !value.includes("\\")
    && !value.split("/").some((part) => part === "" || part === "." || part === "..")
    && /^[A-Za-z0-9._/-]+$/u.test(value);
}

function isDecimal(value) {
  return typeof value === "string" && DECIMAL.test(value);
}

function isNonzeroAddress(value) {
  return typeof value === "string" && ADDRESS.test(value) && value.toLowerCase() !== ZERO_ADDRESS;
}

function isNonzeroBytes32(value) {
  return typeof value === "string" && BYTES32.test(value) && value.toLowerCase() !== ZERO_BYTES32;
}

function normalizeAddress(value) {
  return typeof value === "string" ? value.toLowerCase() : "";
}

function sameAddress(left, right) {
  return isNonzeroAddress(left) && isNonzeroAddress(right) && normalizeAddress(left) === normalizeAddress(right);
}

function sameBytes32(left, right) {
  return isNonzeroBytes32(left) && isNonzeroBytes32(right) && left.toLowerCase() === right.toLowerCase();
}

function tokenize(value) {
  return [...new Set(value.normalize("NFKD").toLowerCase().replace(/\p{Mark}+/gu, "").split(/[^a-z0-9]+/u).filter((token) => token.length >= 2 && token.length <= 64))].sort(compareUtf8).slice(0, 512);
}

function sortJson(value) {
  if (Array.isArray(value)) return value.map(sortJson);
  if (!isPlainObject(value)) return value;
  return Object.fromEntries(Object.keys(value).sort(compareUtf8).map((key) => [key, sortJson(value[key])]));
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function arraysEqual(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(String(left), "utf8"), Buffer.from(String(right), "utf8"));
}

function fail(code, message) {
  throw new RegistryError(code, message);
}
