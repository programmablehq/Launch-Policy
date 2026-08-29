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
export const ROBINHOOD_PROMOTION_ANCHOR_V4 = deepFreeze({
  chainDeploymentDescriptorDigest: null,
  chainDeploymentId: "robinhood-mainnet-custom-launch-v1",
  finalityPolicyDigest: "sha256:537d531423d1285a3808556a57303ec68f1e6bdeea3c9aaf6320f9e5a0e47153",
  finalizedBlock: null,
  finalizedEvidenceRef: null,
  foundationSourceCommitment: FOUNDATION_SOURCE_COMMITMENT,
  roots: {
    graphFactory: {
      address: "0x0B6b3F40f84Df25D3bd69238f937096177DD09Bd",
      runtimeCodeHash: "0xd23692fae59331592048e71a96d4963e170ee56e449683dc9f7fa3f9470018b8",
      startBlock: null
    },
    permit2: {
      address: "0x000000000022D473030F116dDEE9F6B43aC78BA3",
      runtimeCodeHash: "0x5208783f52488f7d3493e5e38311ab707c1d75457fe472a19b0b4d57d66a7fca",
      startBlock: null
    },
    permitAuthoritySafe: {
      address: "0xeD617CE7f82e2AB589aDeFFD319D1D872Bc8De06",
      runtimeCodeHash: "0xd7d408ebcd99b2b70be43e20253d6d92a8ea8fab29bd3be7f55b10032331fb4c",
      startBlock: null
    },
    poolManager: {
      address: "0x8366a39CC670B4001A1121B8F6A443A643e40951",
      runtimeCodeHash: "0xbd3881180b547f5fe817545743cfb4343e96b1bc6640dcd70c106b0066e95626",
      startBlock: "9070"
    },
    positionManager: {
      address: "0x58daec3116aae6D93017bAAea7749052E8a04fA7",
      runtimeCodeHash: "0xc873e135dc9aaec88489cfbad146b4cb49d6a32e0d80326377784b7ba17670b2",
      startBlock: "9073"
    },
    programmableLaunchStampRouter: {
      address: "0x34965F2A2ee9254522232C32F02056E92BE0C98a",
      runtimeCodeHash: "0x1dbbdaaad901ea3c6134dca0d4872a4789b3c071bf8ccfb44edd65d26d817388",
      startBlock: null
    },
    stateView: {
      address: "0xF3334192D15450CdD385c8B70e03f9A6bD9E673b",
      runtimeCodeHash: "0x7d9c591e0956fd89d98feb4ffcfe8bf1f7a62bd485edd979fa21d104b49878a6",
      startBlock: "9075"
    },
    universalRouter: {
      address: "0x06AfBA43Fd06227fA663b0DAecF536f6EaA6bf99",
      runtimeCodeHash: "0xbe8e8191bb42d843c2e948a5a55772eaab864ce01e54dcd47c9d089170b302d5",
      startBlock: "3347899"
    },
    v4Quoter: {
      address: "0x8Dc178eFB8111BB0973Dd9d722ebeFF267c98F94",
      runtimeCodeHash: "0xd707b1da8cb165e5ea35a3b4450d971eb562ec171e23492aa117036b78a868f6",
      startBlock: "9074"
    }
  }
});
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
  if (canonicalJson(evidence) !== canonicalJson(ROBINHOOD_PROMOTION_ANCHOR_V4)) {
    fail(
      "CUSTOM_LAUNCH_ADMISSION_V4_PROMOTION_ANCHOR_MISMATCH",
      "Robinhood deployment evidence must exactly match the reviewed code-owned promotion anchor."
    );
  }
  if (promotionStatus === "canary" && !promotionAnchorIsComplete(ROBINHOOD_PROMOTION_ANCHOR_V4)) {
    fail(
      "CUSTOM_LAUNCH_ADMISSION_V4_PROMOTION_ANCHOR_INCOMPLETE",
      "Robinhood canary promotion remains closed until a reviewed code update pins the descriptor digest, every start block, finalized block and exact evidence reference."
    );
  }
}

function promotionAnchorIsComplete(anchor) {
  return anchor.chainDeploymentDescriptorDigest !== null
    && anchor.finalizedBlock !== null
    && anchor.finalizedEvidenceRef !== null
    && Object.values(anchor.roots).every(({ startBlock }) => startBlock !== null);
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
