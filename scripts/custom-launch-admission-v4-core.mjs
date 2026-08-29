import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { TextDecoder } from "node:util";

import { parseBoundedLosslessJson } from "../vendor/programmable-v4-hook-builder/scripts/github-public-source-lossless-json.mjs";
import { canonicalJson, parseLaunchPolicyBytes } from "./launch-policy-core.mjs";

export const CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_V4_PATH = "policy/custom-launch-admission-v4.json";
export const CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_V4_SCHEMA_PATH = "policy/schemas/custom-launch-admission-v4.schema.json";
export const CUSTOM_LAUNCH_ADMISSION_BINDING_V4_PATH = ".programmable/custom-launch-admission.v4.json";

const POLICY_PATH = "policy/launch-policy.v1.json";
const MAXIMUM_JSON_BYTES = 2 * 1024 * 1024;
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
const FOUNDATION_SOURCE_COMMITMENT = "0xe87f5edc2dc839bd87a26a80cb53f14b021e603a1753d27aae3a02862058d730";
const FINALITY_POLICY_DIGEST = "sha256:537d531423d1285a3808556a57303ec68f1e6bdeea3c9aaf6320f9e5a0e47153";
const POOL_MANAGER = "0x8366a39cc670b4001a1121b8f6a443a643e40951";
const DEPLOYMENT_ROOT_IDS = Object.freeze([
  "graphFactory",
  "permit2",
  "permitAuthoritySafe",
  "poolManager",
  "positionManager",
  "programmableLaunchStampRouter",
  "stateView",
  "universalRouter",
  "v4Quoter"
]);
const ROBINHOOD_RULE_IDS = Object.freeze([
  "LAUNCH.ROBINHOOD_FINALIZED_ROUTER_EVIDENCE_BEFORE_PROMOTION",
  "LAUNCH.ROBINHOOD_FUNDING_AND_SETTLEMENT_READINESS",
  "LAUNCH.ROBINHOOD_HONEST_FEE_CAPABILITY",
  "LAUNCH.ROBINHOOD_INDEXING_AND_READINESS",
  "LAUNCH.ROBINHOOD_NETWORK_AND_POOL_MANAGER_PROVENANCE",
  "LAUNCH.ROBINHOOD_PROGRAMMABLE_TRUST_ROOTS",
  "LAUNCH.ROBINHOOD_SERVER_VALIDATION_AND_SIMULATION",
  "LAUNCH.ROBINHOOD_SOURCE_VERIFICATION_BINDING",
  "LAUNCH.ROBINHOOD_WALLET_HANDOFF_CHAIN_BINDING"
]);

export class CustomLaunchAdmissionV4Error extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.name = "CustomLaunchAdmissionV4Error";
    this.code = code;
  }
}

export function readCustomLaunchAdmissionDescriptorV4({ repositoryRoot }) {
  const root = requireRepositoryRoot(repositoryRoot);
  const source = readCanonicalJsonSource(root, CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_V4_PATH);
  const descriptor = JSON.parse(source);
  validateCustomLaunchAdmissionDescriptorV4(descriptor);
  return Object.freeze({
    descriptor: deepFreeze(descriptor),
    sha256: sha256(Buffer.from(source, "utf8")),
    source
  });
}

export function validateCustomLaunchAdmissionDescriptorV4(descriptor) {
  assertObject(descriptor, "descriptor");
  assertExactKeys(descriptor, [
    "authority",
    "chain",
    "claims",
    "descriptorVersion",
    "funding",
    "metadata",
    "policySelection",
    "profile",
    "repository",
    "schemaVersion",
    "staticAdmission",
    "transport"
  ], "descriptor");
  assertEqual(descriptor.schemaVersion, "programmable.custom-launch-admission-descriptor.v4", "schemaVersion");
  assertEqual(descriptor.descriptorVersion, "1.0.0", "descriptorVersion");

  assertObject(descriptor.chain, "chain");
  assertExactKeys(descriptor.chain, [
    "caip2",
    "chainId",
    "deploymentEvidence",
    "explorerUrl",
    "name",
    "promotionStatus",
    "publicRpcProductionAuthority"
  ], "chain");
  assertEqual(descriptor.chain.caip2, "eip155:4663", "chain.caip2");
  assertEqual(descriptor.chain.chainId, "4663", "chain.chainId");
  assertEqual(descriptor.chain.explorerUrl, "https://robinhoodchain.blockscout.com", "chain.explorerUrl");
  assertEqual(descriptor.chain.name, "Robinhood Chain Mainnet", "chain.name");
  assertEqual(descriptor.chain.publicRpcProductionAuthority, false, "chain.publicRpcProductionAuthority");
  if (!new Set(["planned", "canary"]).has(descriptor.chain.promotionStatus)) {
    fail("CUSTOM_LAUNCH_ADMISSION_V4_INVALID", "Robinhood promotionStatus must remain planned or canary until production gates pass.");
  }
  validateDeploymentEvidence(descriptor.chain.deploymentEvidence, descriptor.chain.promotionStatus);

  assertExactObject(descriptor.policySelection, {
    authenticatedChainBoundRequestRequired: true,
    clientSelectable: false,
    productionProfileId: "robinhood-production-launch",
    readinessProfileId: "robinhood-launch-readiness",
    selectedBy: "api-server-chain-binding"
  }, "policySelection");
  assertExactObject(descriptor.authority, {
    admissionEvidenceAuthority: "private-custom-launch-api",
    agentAdmissionAuthority: false,
    backendAuthoritative: true,
    businessPolicyPath: POLICY_PATH,
    clientAdmissionAuthority: false,
    llmAuthorizationAllowed: false,
    platformAdmissionReceiptRequired: true
  }, "authority");
  assertExactObject(descriptor.repository, {
    branch: "main",
    foundationSourceCommitment: FOUNDATION_SOURCE_COMMITMENT,
    name: "programmablehq/Launch-Policy",
    numericRepositoryId: "1320171831",
    productBranch: "production",
    productRepository: "programmablehq/PROGRAMMABLE"
  }, "repository");
  assertExactObject(descriptor.profile, {
    allFourteenHookPermissionsStructurallySupported: true,
    maximumTargets: 16,
    minimumTargets: 3,
    multiContractGraphSupported: true,
    profileId: "programmable.custom-launch.robinhood-mainnet.v1",
    profileRevision: 1,
    profileVersion: "4.0.0",
    projectOwnedHookSupported: true,
    projectOwnedTokenSupported: true
  }, "profile");
  assertExactObject(descriptor.funding, {
    advertisedModes: ["none", "wallet-transaction-value"],
    erc20ModesRequireSeparateProof: true,
    unsupportedModesAbsent: true
  }, "funding");
  assertExactObject(descriptor.metadata, {
    digestBoundBeforeAuthorization: true,
    requiredFields: ["name", "symbol", "description", "image", "websiteUrl", "xUrl"]
  }, "metadata");
  assertExactObject(descriptor.claims, {
    auditClaim: false,
    buybacksLive: false,
    externalIndexingGuaranteed: false,
    feeBehaviorClaim: false,
    genericClaimingLive: false,
    safetyClaim: false,
    universalCompatibilityClaim: false,
    universalFeeBehaviorClaim: false
  }, "claims");
  assertExactObject(descriptor.transport, {
    capabilitiesPath: "/v4/chains/4663/capabilities",
    createPath: "/v4/chains/4663/custom-launches",
    finalizedPath: "/v4/chains/4663/finalized-custom-launches",
    openApiUrl: "https://programmable.market/openapi/custom-launch-v4.json",
    packConfigSchemaUrl: "https://programmable.market/schemas/custom-launch/v4/pack-config.json",
    preflightPath: "/v4/chains/4663/custom-launches/preflight",
    statusPathTemplate: "/v4/chains/4663/custom-launches/{launchId}"
  }, "transport");

  assertObject(descriptor.staticAdmission, "staticAdmission");
  assertExactKeys(descriptor.staticAdmission, [
    "hardBlockFindingCodes",
    "manualProjectAllowlist",
    "noveltyIsNotARejectionReason",
    "unknownFindingDisposition"
  ], "staticAdmission");
  if (
    descriptor.staticAdmission.manualProjectAllowlist !== false
    || descriptor.staticAdmission.noveltyIsNotARejectionReason !== true
    || descriptor.staticAdmission.unknownFindingDisposition !== "needs-evidence"
  ) fail("CUSTOM_LAUNCH_ADMISSION_V4_INVALID", "V4 static admission authority is invalid.");
  const codes = descriptor.staticAdmission.hardBlockFindingCodes;
  if (!Array.isArray(codes) || codes.length < 1 || codes.length > 64 || new Set(codes).size !== codes.length) {
    fail("CUSTOM_LAUNCH_ADMISSION_V4_INVALID", "V4 hard-block finding codes must be bounded and unique.");
  }
  for (const code of codes) {
    if (!/^[A-Z][A-Z0-9_]{2,127}$/u.test(code)) fail("CUSTOM_LAUNCH_ADMISSION_V4_INVALID", `Invalid V4 hard-block code ${code}.`);
  }
  return true;
}

function validateDeploymentEvidence(evidence, promotionStatus) {
  const nullRoots = Object.fromEntries(DEPLOYMENT_ROOT_IDS.map((id) => [id, null]));
  if (promotionStatus === "planned") {
    assertExactObject(evidence, {
      chainDeploymentDescriptorDigest: null,
      chainDeploymentId: null,
      finalityPolicyDigest: null,
      finalizedBlock: null,
      finalizedEvidenceRef: null,
      foundationSourceCommitment: null,
      roots: nullRoots
    }, "chain.deploymentEvidence");
    return;
  }

  assertObject(evidence, "chain.deploymentEvidence");
  assertExactKeys(evidence, [
    "chainDeploymentDescriptorDigest",
    "chainDeploymentId",
    "finalityPolicyDigest",
    "finalizedBlock",
    "finalizedEvidenceRef",
    "foundationSourceCommitment",
    "roots"
  ], "chain.deploymentEvidence");
  assertEqual(evidence.chainDeploymentId, "robinhood-mainnet-custom-launch-v1", "chain.deploymentEvidence.chainDeploymentId");
  assertEqual(evidence.foundationSourceCommitment, FOUNDATION_SOURCE_COMMITMENT, "chain.deploymentEvidence.foundationSourceCommitment");
  assertEqual(evidence.finalityPolicyDigest, FINALITY_POLICY_DIGEST, "chain.deploymentEvidence.finalityPolicyDigest");
  if (!/^sha256:[0-9a-f]{64}$/u.test(evidence.chainDeploymentDescriptorDigest ?? "")) {
    fail("CUSTOM_LAUNCH_ADMISSION_V4_INVALID", "Canary promotion requires the exact chain deployment descriptor digest.");
  }
  requirePositiveDecimal(evidence.finalizedBlock, "chain.deploymentEvidence.finalizedBlock");
  validateFinalizedEvidenceRef(evidence.finalizedEvidenceRef);
  assertObject(evidence.roots, "chain.deploymentEvidence.roots");
  assertExactKeys(evidence.roots, DEPLOYMENT_ROOT_IDS, "chain.deploymentEvidence.roots");
  const addresses = new Set();
  for (const rootId of DEPLOYMENT_ROOT_IDS) {
    const root = evidence.roots[rootId];
    assertObject(root, `chain.deploymentEvidence.roots.${rootId}`);
    assertExactKeys(root, ["address", "runtimeCodeHash", "startBlock"], `chain.deploymentEvidence.roots.${rootId}`);
    if (!/^0x[0-9a-f]{40}$/iu.test(root.address ?? "") || /^0x0{40}$/iu.test(root.address)) {
      fail("CUSTOM_LAUNCH_ADMISSION_V4_INVALID", `Canary ${rootId} address is invalid.`);
    }
    if (!/^0x[0-9a-f]{64}$/u.test(root.runtimeCodeHash ?? "") || /^0x0{64}$/u.test(root.runtimeCodeHash)) {
      fail("CUSTOM_LAUNCH_ADMISSION_V4_INVALID", `Canary ${rootId} runtime hash is invalid.`);
    }
    requirePositiveDecimal(root.startBlock, `chain.deploymentEvidence.roots.${rootId}.startBlock`);
    if (BigInt(root.startBlock) > BigInt(evidence.finalizedBlock)) {
      fail("CUSTOM_LAUNCH_ADMISSION_V4_INVALID", `Canary ${rootId} start block is later than the finalized evidence block.`);
    }
    const address = root.address.toLowerCase();
    if (addresses.has(address)) fail("CUSTOM_LAUNCH_ADMISSION_V4_INVALID", "Canary deployment roots must use distinct addresses.");
    addresses.add(address);
  }
  if (evidence.roots.poolManager.address.toLowerCase() !== POOL_MANAGER) {
    fail("CUSTOM_LAUNCH_ADMISSION_V4_INVALID", "Canary PoolManager does not match the pinned Robinhood Uniswap deployment.");
  }
}

function validateFinalizedEvidenceRef(reference) {
  assertObject(reference, "chain.deploymentEvidence.finalizedEvidenceRef");
  assertExactKeys(reference, ["commit", "path", "repository", "sha256"], "chain.deploymentEvidence.finalizedEvidenceRef");
  if (
    reference.repository !== "https://github.com/programmablehq/PROGRAMMABLE"
    || !/^[0-9a-f]{40}$/u.test(reference.commit ?? "")
    || !/^contracts\/deployments\/(?:evidence\/)?[A-Za-z0-9._/-]+\.json$/u.test(reference.path ?? "")
    || !/^sha256:[0-9a-f]{64}$/u.test(reference.sha256 ?? "")
  ) fail("CUSTOM_LAUNCH_ADMISSION_V4_INVALID", "Canary finalized deployment evidence reference is invalid or unpinned.");
}

function requirePositiveDecimal(value, label) {
  if (!/^[1-9][0-9]*$/u.test(value ?? "")) fail("CUSTOM_LAUNCH_ADMISSION_V4_INVALID", `${label} must be a positive decimal string.`);
}

export function buildCustomLaunchAdmissionBindingV4({ repositoryRoot }) {
  const root = requireRepositoryRoot(repositoryRoot);
  const descriptorRecord = readCustomLaunchAdmissionDescriptorV4({ repositoryRoot: root });
  const policySource = readRegularFile(root, POLICY_PATH);
  const policyRecord = parseLaunchPolicyBytes(Buffer.from(policySource, "utf8"));
  validatePolicySelection(policyRecord.policy);
  const { descriptor } = descriptorRecord;
  return deepFreeze({
    businessPolicy: {
      path: POLICY_PATH,
      policyVersion: policyRecord.policy.policyVersion,
      productionProfileId: descriptor.policySelection.productionProfileId,
      readinessProfileId: descriptor.policySelection.readinessProfileId,
      sha256: policyRecord.sha256
    },
    chain: descriptor.chain,
    claims: descriptor.claims,
    descriptor: {
      descriptorVersion: descriptor.descriptorVersion,
      path: CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_V4_PATH,
      schemaPath: CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_V4_SCHEMA_PATH,
      sha256: descriptorRecord.sha256
    },
    profile: descriptor.profile,
    repository: descriptor.repository,
    schemaVersion: "programmable.custom-launch-admission-binding.v4",
    transport: descriptor.transport
  });
}

export function verifyCustomLaunchAdmissionBindingV4({ repositoryRoot }) {
  const root = requireRepositoryRoot(repositoryRoot);
  const expected = buildCustomLaunchAdmissionBindingV4({ repositoryRoot: root });
  const source = readCanonicalJsonSource(root, CUSTOM_LAUNCH_ADMISSION_BINDING_V4_PATH);
  const observed = JSON.parse(source);
  if (canonicalJson(observed) !== canonicalJson(expected)) {
    fail("CUSTOM_LAUNCH_ADMISSION_V4_BINDING_STALE", "Generated V4 admission binding is stale. Run npm run policy:generate.");
  }
  return Object.freeze({
    descriptorSha256: expected.descriptor.sha256,
    ok: true,
    path: CUSTOM_LAUNCH_ADMISSION_BINDING_V4_PATH,
    policySha256: expected.businessPolicy.sha256
  });
}

function validatePolicySelection(policy) {
  if (policy.policyVersion !== "2.4.0" || policy.repository.name !== "programmablehq/Launch-Policy") {
    fail("CUSTOM_LAUNCH_ADMISSION_V4_POLICY_INVALID", "V4 admission must bind current programmablehq Launch Policy 2.4.0.");
  }
  const readiness = policy.profiles.find(({ id }) => id === "robinhood-launch-readiness");
  const production = policy.profiles.find(({ id }) => id === "robinhood-production-launch");
  for (const profile of [readiness, production]) {
    if (
      profile?.selection?.chainId !== 4663
      || profile.selection.clientSelectable !== false
      || profile.selection.selectedBy !== "api-server-chain-binding"
      || profile.selection.authenticatedRequestRequired !== true
    ) fail("CUSTOM_LAUNCH_ADMISSION_V4_POLICY_INVALID", "Robinhood policy profiles must remain server-selected from an authenticated chain-bound request.");
  }
  const robinhoodRules = policy.rules.filter(({ id }) => id.startsWith("LAUNCH.ROBINHOOD_"));
  if (canonicalJson(robinhoodRules.map(({ id }) => id)) !== canonicalJson(ROBINHOOD_RULE_IDS)) {
    fail("CUSTOM_LAUNCH_ADMISSION_V4_POLICY_INVALID", "Robinhood policy rule coverage is incomplete or unordered.");
  }
  const allowedProfiles = new Set(["robinhood-launch-readiness", "robinhood-production-launch"]);
  if (robinhoodRules.some(({ profiles }) => profiles.some((profile) => !allowedProfiles.has(profile)))) {
    fail("CUSTOM_LAUNCH_ADMISSION_V4_POLICY_INVALID", "Robinhood rules may apply only to server-selected Robinhood profiles.");
  }
  if (policy.rules.some(({ id, profiles }) => id.startsWith("LAUNCH.ETHEREUM_") && profiles.some((profile) => allowedProfiles.has(profile)))) {
    fail("CUSTOM_LAUNCH_ADMISSION_V4_POLICY_INVALID", "Ethereum policy rules must not apply to Robinhood profiles.");
  }
}

function readCanonicalJsonSource(repositoryRoot, relativePath) {
  const source = readRegularFile(repositoryRoot, relativePath);
  let value;
  try {
    parseBoundedLosslessJson(source);
    value = JSON.parse(source);
  } catch (error) {
    fail("CUSTOM_LAUNCH_ADMISSION_V4_JSON_INVALID", `${relativePath} must be duplicate-free UTF-8 JSON.`, error);
  }
  if (source !== `${canonicalJson(value)}\n`) {
    fail("CUSTOM_LAUNCH_ADMISSION_V4_JSON_NONCANONICAL", `${relativePath} must be canonical JSON with one trailing LF.`);
  }
  return source;
}

function readRegularFile(repositoryRoot, relativePath) {
  const absolutePath = path.join(repositoryRoot, relativePath);
  let status;
  try {
    status = fs.lstatSync(absolutePath);
  } catch (error) {
    fail("CUSTOM_LAUNCH_ADMISSION_V4_IO", `${relativePath} is unavailable.`, error);
  }
  if (!status.isFile() || status.isSymbolicLink() || status.size < 2 || status.size > MAXIMUM_JSON_BYTES) {
    fail("CUSTOM_LAUNCH_ADMISSION_V4_IO", `${relativePath} must be a bounded regular file.`);
  }
  const bytes = fs.readFileSync(absolutePath);
  if (bytes.length !== status.size) fail("CUSTOM_LAUNCH_ADMISSION_V4_IO", `${relativePath} changed while it was read.`);
  try {
    return UTF8_DECODER.decode(bytes);
  } catch (error) {
    fail("CUSTOM_LAUNCH_ADMISSION_V4_IO", `${relativePath} must be UTF-8.`, error);
  }
}

function requireRepositoryRoot(repositoryRoot) {
  if (typeof repositoryRoot !== "string" || !path.isAbsolute(repositoryRoot)) {
    fail("CUSTOM_LAUNCH_ADMISSION_V4_ARGUMENTS_INVALID", "repositoryRoot must be an absolute path.");
  }
  const status = fs.lstatSync(repositoryRoot);
  if (!status.isDirectory() || status.isSymbolicLink()) fail("CUSTOM_LAUNCH_ADMISSION_V4_ARGUMENTS_INVALID", "repositoryRoot must be a regular directory.");
  return repositoryRoot;
}

function assertExactObject(value, expected, label) {
  assertObject(value, label);
  if (canonicalJson(value) !== canonicalJson(expected)) fail("CUSTOM_LAUNCH_ADMISSION_V4_INVALID", `${label} is invalid.`);
}

function assertObject(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail("CUSTOM_LAUNCH_ADMISSION_V4_INVALID", `${label} must be an object.`);
}

function assertExactKeys(value, keys, label) {
  assertObject(value, label);
  if (canonicalJson(Object.keys(value).sort()) !== canonicalJson([...keys].sort())) fail("CUSTOM_LAUNCH_ADMISSION_V4_INVALID", `${label} has unsupported fields.`);
}

function assertEqual(actual, expected, label) {
  if (actual !== expected) fail("CUSTOM_LAUNCH_ADMISSION_V4_INVALID", `${label} is invalid.`);
}

function sha256(bytes) {
  return `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function fail(code, message, cause) {
  throw new CustomLaunchAdmissionV4Error(code, message, cause ? { cause } : undefined);
}
