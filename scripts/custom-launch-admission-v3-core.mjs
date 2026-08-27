import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { TextDecoder } from "node:util";

import { parseBoundedLosslessJson } from "../vendor/programmable-v4-hook-builder/scripts/github-public-source-lossless-json.mjs";
import { canonicalJson, parseLaunchPolicyBytes } from "./launch-policy-core.mjs";

export const CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_V3_PATH = "policy/custom-launch-admission-v3.json";
export const CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_V3_SCHEMA_PATH = "policy/schemas/custom-launch-admission-v3.schema.json";
export const CUSTOM_LAUNCH_ADMISSION_BINDING_V3_PATH = ".programmable/custom-launch-admission.v3.json";

const POLICY_PATH = "policy/launch-policy.v1.json";
const MAXIMUM_JSON_BYTES = 2 * 1024 * 1024;
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
const CODE = /^[A-Z][A-Z0-9_]{2,127}$/u;
const ID = /^[a-z0-9][a-z0-9.-]{1,127}$/u;
const SHA256 = /^sha256:[0-9a-f]{64}$/u;

const PROJECTION_CONTRACT = Object.freeze([
  Object.freeze({
    id: "programmable-well-known",
    urlPointer: "/transport/discoveryUrl",
    checks: Object.freeze([
      pair("/profile/profileId", "/customLaunchApi/generalHookProfile/profileId"),
      pair("/profile/profileRevision", "/customLaunchApi/generalHookProfile/profileRevision"),
      pair("/profile/profileVersion", "/customLaunchApi/generalHookProfile/profileVersion"),
      pair("/staticAdmission/manualProjectAllowlist", "/customLaunchApi/generalHookProfile/admissionPolicy/manualProjectAllowlist"),
      pair("/staticAdmission/hardBlockFindingRules", "/customLaunchApi/generalHookProfile/admissionPolicy/hardBlockFindingRules"),
      pair("/staticAdmission/needsEvidenceFindingCodes", "/customLaunchApi/generalHookProfile/admissionPolicy/needsEvidenceFindingCodes"),
      pair("/staticAdmission/routerSimulationRequiredBeforeAuthorization", "/customLaunchApi/integrationPreview/routerSimulationRequiredBeforeAuthorization"),
      pair("/claims/safetyClaim", "/customLaunchApi/integrationPreview/safetyClaim"),
      pair("/claims/feeBehaviorClaim", "/customLaunchApi/integrationPreview/feeBehaviorClaim")
    ])
  }),
  Object.freeze({
    id: "custom-launch-capabilities-v3",
    urlPointer: "/transport/capabilitiesUrl",
    checks: Object.freeze([
      pair("/profile/profileId", "/profile/profileId"),
      pair("/profile/profileRevision", "/profile/profileRevision"),
      pair("/profile/profileVersion", "/profile/profileVersion"),
      pair("/hardSafetyInvariants", "/hardSafetyInvariants"),
      pair("/advancedFeaturesRequireEvidence", "/advancedFeaturesRequireEvidence"),
      pair("/feePolicyProjection/programmableHundredthsOfBip", "/feePolicy/programmableHundredthsOfBip"),
      pair("/feePolicyProjection/genericClaimingLive", "/feePolicy/genericClaimingLive"),
      pair("/feePolicyProjection/buybackManagementLive", "/feePolicy/buybackManagementLive"),
      pair("/claims/safetyClaim", "/safetyClaim"),
      pair("/claims/auditClaim", "/auditClaim"),
      pair("/claims/universalCompatibilityClaim", "/universalCompatibilityClaim")
    ])
  }),
  Object.freeze({
    id: "custom-launch-openapi-v3",
    urlPointer: "/transport/openApiUrl",
    checks: Object.freeze([
      pair("/profile/profileId", "/x-programmable-profile/profileId"),
      pair("/profile/profileRevision", "/x-programmable-profile/profileRevision"),
      pair("/profile/profileVersion", "/x-programmable-profile/profileVersion"),
      pair("/staticAdmission/manualProjectAllowlist", "/x-programmable-admission-policy/manualProjectAllowlist"),
      pair("/staticAdmission/hardBlockFindingRules", "/x-programmable-admission-policy/hardBlockFindingRules"),
      pair("/staticAdmission/needsEvidenceFindingCodes", "/x-programmable-admission-policy/needsEvidenceFindingCodes"),
      pair("/claims/safetyClaim", "/x-programmable-profile/safetyClaim"),
      pair("/claims/feeBehaviorClaim", "/x-programmable-profile/feeBehaviorClaim"),
      pair("/feePolicyProjection/programmableHundredthsOfBip", "/x-programmable-fee-accounting/programmableFeeHundredthsOfBip")
    ])
  })
]);

export class CustomLaunchAdmissionDescriptorError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.name = "CustomLaunchAdmissionDescriptorError";
    this.code = code;
  }
}

export function readCustomLaunchAdmissionDescriptorV3({ repositoryRoot }) {
  const root = requireRepositoryRoot(repositoryRoot);
  const source = readCanonicalJsonSource(root, CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_V3_PATH);
  const descriptor = JSON.parse(source);
  validateCustomLaunchAdmissionDescriptorV3(descriptor);
  return Object.freeze({
    descriptor: deepFreeze(descriptor),
    sha256: sha256(Buffer.from(source, "utf8")),
    source
  });
}

export function validateCustomLaunchAdmissionDescriptorV3(descriptor) {
  assertObject(descriptor, "descriptor");
  assertExactKeys(descriptor, [
    "advancedFeaturesRequireEvidence",
    "authority",
    "behaviorAssurance",
    "claims",
    "descriptorVersion",
    "feePolicyProjection",
    "hardSafetyInvariants",
    "profile",
    "schemaVersion",
    "staticAdmission",
    "transport"
  ], "descriptor");
  assertEqual(descriptor.schemaVersion, "programmable.custom-launch-admission-descriptor.v3", "descriptor.schemaVersion");
  assertEqual(descriptor.descriptorVersion, "1.0.0", "descriptor.descriptorVersion");

  assertObject(descriptor.profile, "descriptor.profile");
  assertExactKeys(descriptor.profile, ["chainId", "profileId", "profileRevision", "profileVersion"], "descriptor.profile");
  assertEqual(descriptor.profile.profileId, "programmable.direct-native-hook-graph.v1", "descriptor.profile.profileId");
  assertEqual(descriptor.profile.profileRevision, 3, "descriptor.profile.profileRevision");
  assertEqual(descriptor.profile.profileVersion, "3.2.0", "descriptor.profile.profileVersion");
  assertEqual(descriptor.profile.chainId, "1", "descriptor.profile.chainId");

  assertObject(descriptor.authority, "descriptor.authority");
  assertExactKeys(descriptor.authority, [
    "admissionDisclosurePath",
    "agentAdmissionAuthority",
    "businessPolicyPath",
    "businessPolicyScope",
    "cliAdmissionAuthority",
    "clientAdmissionAuthority",
    "executableEvidenceAuthority",
    "platformAdmissionReceiptRequired"
  ], "descriptor.authority");
  assertEqual(descriptor.authority.businessPolicyPath, POLICY_PATH, "descriptor.authority.businessPolicyPath");
  assertEqual(descriptor.authority.businessPolicyScope, "programmable-router-fee-and-promotion-obligations", "descriptor.authority.businessPolicyScope");
  assertEqual(descriptor.authority.admissionDisclosurePath, CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_V3_PATH, "descriptor.authority.admissionDisclosurePath");
  assertEqual(descriptor.authority.executableEvidenceAuthority, "private-custom-launch-api", "descriptor.authority.executableEvidenceAuthority");
  for (const key of ["clientAdmissionAuthority", "cliAdmissionAuthority", "agentAdmissionAuthority"]) {
    assertEqual(descriptor.authority[key], false, `descriptor.authority.${key}`);
  }
  assertEqual(descriptor.authority.platformAdmissionReceiptRequired, true, "descriptor.authority.platformAdmissionReceiptRequired");

  assertObject(descriptor.transport, "descriptor.transport");
  assertExactKeys(descriptor.transport, ["capabilitiesUrl", "createPath", "discoveryUrl", "openApiUrl", "preflightPath"], "descriptor.transport");
  assertEqual(descriptor.transport.discoveryUrl, "https://programmable.market/.well-known/programmable.json", "descriptor.transport.discoveryUrl");
  assertEqual(descriptor.transport.capabilitiesUrl, "https://api.programmable.market/v3/capabilities", "descriptor.transport.capabilitiesUrl");
  assertEqual(descriptor.transport.openApiUrl, "https://programmable.market/openapi/custom-launch-v3.json", "descriptor.transport.openApiUrl");
  assertEqual(descriptor.transport.createPath, "/v3/custom-launches", "descriptor.transport.createPath");
  assertEqual(descriptor.transport.preflightPath, "/v3/custom-launches/preflight", "descriptor.transport.preflightPath");

  assertObject(descriptor.staticAdmission, "descriptor.staticAdmission");
  assertExactKeys(descriptor.staticAdmission, [
    "hardBlockFindingRules",
    "manualProjectAllowlist",
    "needsEvidenceFindingCodes",
    "routerSimulationRequiredBeforeAuthorization",
    "unknownFindingDisposition"
  ], "descriptor.staticAdmission");
  assertEqual(descriptor.staticAdmission.manualProjectAllowlist, false, "descriptor.staticAdmission.manualProjectAllowlist");
  assertEqual(descriptor.staticAdmission.unknownFindingDisposition, "needs-evidence", "descriptor.staticAdmission.unknownFindingDisposition");
  assertEqual(descriptor.staticAdmission.routerSimulationRequiredBeforeAuthorization, true, "descriptor.staticAdmission.routerSimulationRequiredBeforeAuthorization");
  const hardCodes = new Set();
  assertArray(descriptor.staticAdmission.hardBlockFindingRules, "descriptor.staticAdmission.hardBlockFindingRules", 1, 64);
  for (const [index, rule] of descriptor.staticAdmission.hardBlockFindingRules.entries()) {
    assertObject(rule, `hardBlockFindingRules[${index}]`);
    assertExactKeys(rule, ["code", "targetRoles"], `hardBlockFindingRules[${index}]`);
    assertCode(rule.code, `hardBlockFindingRules[${index}].code`);
    if (hardCodes.has(rule.code)) fail("CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_INVALID", `Duplicate hard-block code ${rule.code}.`);
    hardCodes.add(rule.code);
    assertStringList(rule.targetRoles, `hardBlockFindingRules[${index}].targetRoles`, new Set(["any", "token", "hook", "initializer", "platform_fee_binding"]), 1, 5);
    if (rule.targetRoles.includes("any") && rule.targetRoles.length !== 1) fail("CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_INVALID", `${rule.code} combines any with a narrower target role.`);
  }
  assertCodeList(descriptor.staticAdmission.needsEvidenceFindingCodes, "descriptor.staticAdmission.needsEvidenceFindingCodes", 1, 128);
  for (const code of descriptor.staticAdmission.needsEvidenceFindingCodes) {
    if (hardCodes.has(code)) fail("CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_INVALID", `${code} is both hard-blocking and evidence-bound.`);
  }

  assertIdList(descriptor.hardSafetyInvariants, "descriptor.hardSafetyInvariants");
  assertIdList(descriptor.advancedFeaturesRequireEvidence, "descriptor.advancedFeaturesRequireEvidence");

  assertObject(descriptor.behaviorAssurance, "descriptor.behaviorAssurance");
  assertExactKeys(descriptor.behaviorAssurance, [
    "advancedRequiredVectorIds",
    "authorizationScope",
    "missingRunnerEvidenceAuthority",
    "missingRunnerResult",
    "mutableSurfaceResult",
    "riskClassifierVersion",
    "safetyResult",
    "standardRequiredVectorIds",
    "vectorSetVersion"
  ], "descriptor.behaviorAssurance");
  assertEqual(descriptor.behaviorAssurance.vectorSetVersion, "1.1.0", "descriptor.behaviorAssurance.vectorSetVersion");
  assertEqual(descriptor.behaviorAssurance.riskClassifierVersion, "1.1.0", "descriptor.behaviorAssurance.riskClassifierVersion");
  assertEqual(descriptor.behaviorAssurance.authorizationScope, "exact-launch-provenance-only", "descriptor.behaviorAssurance.authorizationScope");
  assertIdList(descriptor.behaviorAssurance.standardRequiredVectorIds, "descriptor.behaviorAssurance.standardRequiredVectorIds");
  assertIdList(descriptor.behaviorAssurance.advancedRequiredVectorIds, "descriptor.behaviorAssurance.advancedRequiredVectorIds");
  const standardVectorIds = new Set(descriptor.behaviorAssurance.standardRequiredVectorIds);
  for (const id of descriptor.behaviorAssurance.advancedRequiredVectorIds) {
    if (standardVectorIds.has(id)) fail("CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_INVALID", `${id} is both a standard and advanced behavior vector.`);
  }
  assertEqual(descriptor.behaviorAssurance.missingRunnerEvidenceAuthority, "none", "descriptor.behaviorAssurance.missingRunnerEvidenceAuthority");
  assertEqual(descriptor.behaviorAssurance.missingRunnerResult, "not_verified", "descriptor.behaviorAssurance.missingRunnerResult");
  assertEqual(descriptor.behaviorAssurance.mutableSurfaceResult, "conditional", "descriptor.behaviorAssurance.mutableSurfaceResult");
  assertEqual(descriptor.behaviorAssurance.safetyResult, "not_verified", "descriptor.behaviorAssurance.safetyResult");

  assertObject(descriptor.feePolicyProjection, "descriptor.feePolicyProjection");
  assertExactKeys(descriptor.feePolicyProjection, [
    "businessPolicyRuleId",
    "buybackManagementLive",
    "denominator",
    "feeBehaviorClaim",
    "genericClaimingLive",
    "programmableHundredthsOfBip",
    "runtimeBehaviorClaim"
  ], "descriptor.feePolicyProjection");
  assertEqual(descriptor.feePolicyProjection.businessPolicyRuleId, "LAUNCH.ETHEREUM_AND_TREASURY_10_BPS", "descriptor.feePolicyProjection.businessPolicyRuleId");
  assertEqual(descriptor.feePolicyProjection.programmableHundredthsOfBip, "1000", "descriptor.feePolicyProjection.programmableHundredthsOfBip");
  assertEqual(descriptor.feePolicyProjection.denominator, "1000000", "descriptor.feePolicyProjection.denominator");
  assertEqual(descriptor.feePolicyProjection.runtimeBehaviorClaim, "not-established-by-admission", "descriptor.feePolicyProjection.runtimeBehaviorClaim");
  for (const key of ["feeBehaviorClaim", "genericClaimingLive", "buybackManagementLive"]) {
    assertEqual(descriptor.feePolicyProjection[key], false, `descriptor.feePolicyProjection.${key}`);
  }

  assertObject(descriptor.claims, "descriptor.claims");
  assertExactKeys(descriptor.claims, ["auditClaim", "feeBehaviorClaim", "safetyClaim", "universalCompatibilityClaim"], "descriptor.claims");
  for (const [key, value] of Object.entries(descriptor.claims)) assertEqual(value, false, `descriptor.claims.${key}`);
  assertEqual(descriptor.claims.feeBehaviorClaim, descriptor.feePolicyProjection.feeBehaviorClaim, "descriptor feeBehaviorClaim projections");
  return true;
}

export function buildCustomLaunchAdmissionBindingV3({ repositoryRoot }) {
  const root = requireRepositoryRoot(repositoryRoot);
  const { descriptor, sha256: descriptorSha256 } = readCustomLaunchAdmissionDescriptorV3({ repositoryRoot: root });
  const policySource = readRegularFile(root, POLICY_PATH);
  const policy = parseLaunchPolicyBytes(Buffer.from(policySource, "utf8"));
  const feeRule = policy.policy.rules.find(({ id }) => id === descriptor.feePolicyProjection.businessPolicyRuleId);
  if (!feeRule || String(feeRule.parameters?.hundredthsOfBip) !== descriptor.feePolicyProjection.programmableHundredthsOfBip) {
    fail("CUSTOM_LAUNCH_ADMISSION_BUSINESS_POLICY_MISMATCH", "The V3 admission fee projection differs from the canonical business policy.");
  }
  return deepFreeze({
    schemaVersion: "programmable.custom-launch-admission-binding.v1",
    authority: {
      admissionDisclosure: "public-declarative-contract",
      businessPolicy: "public-canonical-policy",
      executableEvidence: descriptor.authority.executableEvidenceAuthority,
      clientAdmissionAuthority: false,
      cliAdmissionAuthority: false,
      agentAdmissionAuthority: false
    },
    businessPolicy: {
      path: POLICY_PATH,
      policyId: policy.policy.policyId,
      policyVersion: policy.policy.policyVersion,
      sha256: policy.sha256
    },
    descriptor: {
      path: CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_V3_PATH,
      schemaPath: CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_V3_SCHEMA_PATH,
      sha256: descriptorSha256
    },
    profile: structuredClone(descriptor.profile),
    projections: PROJECTION_CONTRACT.map(({ checks, id, urlPointer }) => ({
      checks: checks.map(({ descriptorPointer, projectionPointer }) => ({
        descriptorPointer,
        expectedSha256: digestValue(pointerValue(descriptor, descriptorPointer)),
        projectionPointer
      })),
      id,
      url: pointerValue(descriptor, urlPointer)
    }))
  });
}

export function verifyCustomLaunchAdmissionBindingV3({ repositoryRoot }) {
  const root = requireRepositoryRoot(repositoryRoot);
  const expected = `${canonicalJson(buildCustomLaunchAdmissionBindingV3({ repositoryRoot: root }))}\n`;
  const observed = readRegularFile(root, CUSTOM_LAUNCH_ADMISSION_BINDING_V3_PATH);
  if (observed !== expected) {
    fail("CUSTOM_LAUNCH_ADMISSION_BINDING_STALE", `Generated admission binding ${CUSTOM_LAUNCH_ADMISSION_BINDING_V3_PATH} is stale. Run npm run policy:generate.`);
  }
  const binding = JSON.parse(observed);
  if (!SHA256.test(binding.descriptor.sha256) || !SHA256.test(binding.businessPolicy.sha256)) {
    fail("CUSTOM_LAUNCH_ADMISSION_BINDING_INVALID", "Admission binding digests are invalid.");
  }
  return Object.freeze({
    bindingPath: CUSTOM_LAUNCH_ADMISSION_BINDING_V3_PATH,
    descriptorPath: CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_V3_PATH,
    descriptorSha256: binding.descriptor.sha256,
    ok: true
  });
}

export function verifyCustomLaunchAdmissionProjectionsV3({ repositoryRoot, wellKnown, capabilities, openApi }) {
  const { descriptor, sha256: descriptorSha256 } = readCustomLaunchAdmissionDescriptorV3({ repositoryRoot });
  const documents = new Map([
    ["programmable-well-known", wellKnown],
    ["custom-launch-capabilities-v3", capabilities],
    ["custom-launch-openapi-v3", openApi]
  ]);
  for (const projection of PROJECTION_CONTRACT) {
    const document = documents.get(projection.id);
    assertObject(document, projection.id);
    for (const { descriptorPointer, projectionPointer } of projection.checks) {
      const expected = pointerValue(descriptor, descriptorPointer);
      const observed = pointerValue(document, projectionPointer);
      if (canonicalJson(observed) !== canonicalJson(expected)) {
        fail("CUSTOM_LAUNCH_ADMISSION_PROJECTION_MISMATCH", `${projection.id}${projectionPointer} differs from ${CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_V3_PATH}${descriptorPointer}.`);
      }
    }
  }
  return Object.freeze({ descriptorSha256, ok: true, projections: Object.freeze([...documents.keys()]) });
}

function pair(descriptorPointer, projectionPointer) {
  return Object.freeze({ descriptorPointer, projectionPointer });
}

function pointerValue(value, pointer) {
  if (pointer === "") return value;
  if (typeof pointer !== "string" || !pointer.startsWith("/")) fail("CUSTOM_LAUNCH_ADMISSION_POINTER_INVALID", `Invalid JSON pointer ${pointer}.`);
  let current = value;
  for (const encoded of pointer.slice(1).split("/")) {
    const key = encoded.replaceAll("~1", "/").replaceAll("~0", "~");
    if (current === null || typeof current !== "object" || !Object.hasOwn(current, key)) {
      fail("CUSTOM_LAUNCH_ADMISSION_PROJECTION_MISSING", `Missing JSON pointer ${pointer}.`);
    }
    current = current[key];
  }
  return current;
}

function readCanonicalJsonSource(root, relativePath) {
  const source = readRegularFile(root, relativePath);
  let value;
  try {
    parseBoundedLosslessJson(source);
    value = JSON.parse(source);
  } catch (error) {
    fail("CUSTOM_LAUNCH_ADMISSION_JSON_INVALID", `${relativePath} is not duplicate-free UTF-8 JSON.`, error);
  }
  if (source !== `${canonicalJson(value)}\n`) fail("CUSTOM_LAUNCH_ADMISSION_JSON_NONCANONICAL", `${relativePath} must be canonical JSON with one trailing newline.`);
  return source;
}

function readRegularFile(root, relativePath) {
  const absolute = path.resolve(root, relativePath);
  if (!absolute.startsWith(`${root}${path.sep}`)) fail("CUSTOM_LAUNCH_ADMISSION_PATH_INVALID", `${relativePath} escapes the repository root.`);
  let status;
  try { status = fs.lstatSync(absolute); } catch (error) { fail("CUSTOM_LAUNCH_ADMISSION_IO", `${relativePath} is unavailable.`, error); }
  if (!status.isFile() || status.isSymbolicLink() || status.nlink !== 1 || status.size < 2 || status.size > MAXIMUM_JSON_BYTES) {
    fail("CUSTOM_LAUNCH_ADMISSION_IO", `${relativePath} must be one bounded regular file.`);
  }
  try { return UTF8_DECODER.decode(fs.readFileSync(absolute)); } catch (error) { fail("CUSTOM_LAUNCH_ADMISSION_IO", `${relativePath} is not valid UTF-8.`, error); }
}

function requireRepositoryRoot(repositoryRoot) {
  if (typeof repositoryRoot !== "string" || !path.isAbsolute(repositoryRoot)) fail("CUSTOM_LAUNCH_ADMISSION_ARGUMENTS_INVALID", "repositoryRoot must be absolute.");
  return path.resolve(repositoryRoot);
}

function assertObject(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    fail("CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_INVALID", `${label} must be a plain object.`);
  }
}

function assertExactKeys(value, keys, label) {
  const observed = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (canonicalJson(observed) !== canonicalJson(expected)) fail("CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_INVALID", `${label} has an open or incomplete field set.`);
}

function assertArray(value, label, minimum, maximum) {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) fail("CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_INVALID", `${label} has an invalid bounded array.`);
}

function assertCode(value, label) {
  if (typeof value !== "string" || !CODE.test(value)) fail("CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_INVALID", `${label} is invalid.`);
}

function assertCodeList(value, label, minimum, maximum) {
  assertArray(value, label, minimum, maximum);
  const seen = new Set();
  for (const code of value) {
    assertCode(code, label);
    if (seen.has(code)) fail("CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_INVALID", `${label} contains duplicate ${code}.`);
    seen.add(code);
  }
}

function assertIdList(value, label) {
  assertArray(value, label, 1, 128);
  const seen = new Set();
  for (const id of value) {
    if (typeof id !== "string" || !ID.test(id) || seen.has(id)) fail("CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_INVALID", `${label} contains an invalid or duplicate identifier.`);
    seen.add(id);
  }
}

function assertStringList(value, label, allowed, minimum, maximum) {
  assertArray(value, label, minimum, maximum);
  const seen = new Set();
  for (const item of value) {
    if (!allowed.has(item) || seen.has(item)) fail("CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_INVALID", `${label} contains an invalid or duplicate value.`);
    seen.add(item);
  }
}

function assertEqual(observed, expected, label) {
  if (observed !== expected) fail("CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_INVALID", `${label} is invalid.`);
}

function digestValue(value) {
  return sha256(Buffer.from(canonicalJson(value), "utf8"));
}

function sha256(bytes) {
  return `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
}

function deepFreeze(value) {
  if (value !== null && typeof value === "object") {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function fail(code, message, cause) {
  throw new CustomLaunchAdmissionDescriptorError(code, message, cause === undefined ? undefined : { cause });
}
