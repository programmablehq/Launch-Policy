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
const KECCAK256 = /^0x[0-9a-f]{64}$/u;

const PROJECTION_CONTRACT = Object.freeze([
  Object.freeze({
    id: "programmable-well-known",
    urlPointer: "/transport/discoveryUrl",
    checks: Object.freeze([
      pair("/profile/profileId", "/customLaunchApi/generalHookProfile/profileId"),
      pair("/profile/profileRevision", "/customLaunchApi/generalHookProfile/profileRevision"),
      pair("/profile/profileVersion", "/customLaunchApi/generalHookProfile/profileVersion"),
      pair("/compatibility/legacyExactProfileVersions", "/customLaunchApi/generalHookProfile/compatibleProfileVersions"),
      pair("/compatibility/legacySemantics", "/customLaunchApi/generalHookProfile/legacyProfileSemantics"),
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
      pair("/feePolicyProjection/denominator", "/feePolicy/denominator"),
      pair("/behaviorAssurance/walletHandoffRequiresVerifiedFeeEvidence", "/behaviorEvidence/walletHandoffRequiresVerifiedEvidence"),
      pair("/behaviorAssurance/missingRunnerResult", "/behaviorEvidence/notConfiguredDisposition"),
      pair("/behaviorAssurance/unavailableRunnerResult", "/behaviorEvidence/unavailableDisposition"),
      pair("/behaviorAssurance/failedRunnerResult", "/behaviorEvidence/executedFailureDisposition"),
      pair("/behaviorAssurance/configurationIsExecutionEvidence", "/behaviorEvidence/configurationIsExecutionEvidence"),
      pair("/behaviorAssurance/vectorSetVersion", "/behaviorEvidence/vectorSetVersion"),
      pair("/behaviorAssurance/maximumConfiguredRunnerAttempts", "/behaviorEvidence/maximumConfiguredRunnerAttempts"),
      pair("/claims/feeBehaviorClaim", "/behaviorEvidence/feeBehaviorClaim"),
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
      pair("/compatibility/legacyExactProfileVersions", "/x-programmable-admission-policy/legacyExactProfileVersions"),
      pair("/compatibility/legacySemantics", "/x-programmable-admission-policy/legacySemantics"),
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
    "candidateProfile",
    "claims",
    "compatibility",
    "descriptorVersion",
    "feeAuthorizationGate",
    "feePolicyProjection",
    "hardSafetyInvariants",
    "profile",
    "schemaVersion",
    "settlementDataflowClosure",
    "staticAdmission",
    "transport"
  ], "descriptor");
  assertEqual(descriptor.schemaVersion, "programmable.custom-launch-admission-descriptor.v3", "descriptor.schemaVersion");
  assertEqual(descriptor.descriptorVersion, "1.1.0", "descriptor.descriptorVersion");

  assertObject(descriptor.profile, "descriptor.profile");
  assertExactKeys(descriptor.profile, ["chainId", "profileId", "profileRevision", "profileVersion"], "descriptor.profile");
  assertEqual(descriptor.profile.profileId, "programmable.direct-native-hook-graph.v1", "descriptor.profile.profileId");
  assertEqual(descriptor.profile.profileRevision, 3, "descriptor.profile.profileRevision");
  assertEqual(descriptor.profile.profileVersion, "3.3.0", "descriptor.profile.profileVersion");
  assertEqual(descriptor.profile.chainId, "1", "descriptor.profile.chainId");

  assertObject(descriptor.candidateProfile, "descriptor.candidateProfile");
  assertExactKeys(descriptor.candidateProfile, [
    "activationState",
    "chainId",
    "freshWritesEnabled",
    "multiContractGraphSupported",
    "profileId",
    "profileRevision",
    "profileVersion",
    "projectOwnedHookSupported",
    "projectOwnedTokenSupported",
    "requiredSettlementDataflowReadback"
  ], "descriptor.candidateProfile");
  assertEqual(descriptor.candidateProfile.profileId, descriptor.profile.profileId, "descriptor.candidateProfile.profileId");
  assertEqual(descriptor.candidateProfile.profileRevision, descriptor.profile.profileRevision, "descriptor.candidateProfile.profileRevision");
  assertEqual(descriptor.candidateProfile.profileVersion, "3.4.0", "descriptor.candidateProfile.profileVersion");
  assertEqual(descriptor.candidateProfile.chainId, descriptor.profile.chainId, "descriptor.candidateProfile.chainId");
  assertEqual(descriptor.candidateProfile.activationState, "pending-runtime-readback", "descriptor.candidateProfile.activationState");
  assertEqual(descriptor.candidateProfile.freshWritesEnabled, false, "descriptor.candidateProfile.freshWritesEnabled");
  assertEqual(
    descriptor.candidateProfile.requiredSettlementDataflowReadback,
    "configured-autonomous-approval-exact-route-closure-receipt",
    "descriptor.candidateProfile.requiredSettlementDataflowReadback"
  );
  for (const key of ["projectOwnedTokenSupported", "projectOwnedHookSupported", "multiContractGraphSupported"]) {
    assertEqual(descriptor.candidateProfile[key], true, `descriptor.candidateProfile.${key}`);
  }

  assertObject(descriptor.settlementDataflowClosure, "descriptor.settlementDataflowClosure");
  assertExactKeys(descriptor.settlementDataflowClosure, [
    "candidateRouteCoverageComesFromRunner",
    "clientAssertionsAccepted",
    "completeValueFlowInventoryRequired",
    "configured",
    "evidenceAuthority",
    "exactLaunchGraphAndRouteBindingRequired",
    "receiptSchemaVersion",
    "runnerNoBypassScope",
    "sourceDecisionReceiptRequired",
    "walletHandoffRequiresClosure"
  ], "descriptor.settlementDataflowClosure");
  assertEqual(descriptor.settlementDataflowClosure.configured, false, "descriptor.settlementDataflowClosure.configured");
  assertEqual(descriptor.settlementDataflowClosure.evidenceAuthority, "programmable-autonomous-approval", "descriptor.settlementDataflowClosure.evidenceAuthority");
  assertEqual(descriptor.settlementDataflowClosure.receiptSchemaVersion, "programmable.autonomous-settlement-dataflow-receipt.v1", "descriptor.settlementDataflowClosure.receiptSchemaVersion");
  assertEqual(descriptor.settlementDataflowClosure.runnerNoBypassScope, "canonical-vault-entrypoints-only", "descriptor.settlementDataflowClosure.runnerNoBypassScope");
  for (const key of [
    "clientAssertionsAccepted",
    "candidateRouteCoverageComesFromRunner"
  ]) assertEqual(descriptor.settlementDataflowClosure[key], false, `descriptor.settlementDataflowClosure.${key}`);
  for (const key of [
    "completeValueFlowInventoryRequired",
    "exactLaunchGraphAndRouteBindingRequired",
    "sourceDecisionReceiptRequired",
    "walletHandoffRequiresClosure"
  ]) assertEqual(descriptor.settlementDataflowClosure[key], true, `descriptor.settlementDataflowClosure.${key}`);

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

  assertObject(descriptor.compatibility, "descriptor.compatibility");
  assertExactKeys(descriptor.compatibility, [
    "legacyExactProfileVersions",
    "legacyFeeBehaviorResult",
    "legacySemantics",
    "retroactiveAuthorizationGate"
  ], "descriptor.compatibility");
  if (canonicalJson(descriptor.compatibility.legacyExactProfileVersions) !== canonicalJson(["3.2.0", "3.1.0", "3.0.0", "2.0.0"])) {
    fail("CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_INVALID", "descriptor.compatibility.legacyExactProfileVersions is invalid.");
  }
  assertEqual(descriptor.compatibility.legacySemantics, "readable-and-byte-identical-retryable-only", "descriptor.compatibility.legacySemantics");
  assertEqual(descriptor.compatibility.legacyFeeBehaviorResult, "unverified", "descriptor.compatibility.legacyFeeBehaviorResult");
  assertEqual(descriptor.compatibility.retroactiveAuthorizationGate, false, "descriptor.compatibility.retroactiveAuthorizationGate");

  assertObject(descriptor.behaviorAssurance, "descriptor.behaviorAssurance");
  assertExactKeys(descriptor.behaviorAssurance, [
    "advancedRequiredVectorIds",
    "authorizationScope",
    "configurationIsExecutionEvidence",
    "failedRunnerResult",
    "maximumConfiguredRunnerAttempts",
    "missingRunnerEvidenceAuthority",
    "missingRunnerResult",
    "mutableSurfaceResult",
    "riskClassifierVersion",
    "retryingRunnerResult",
    "safetyResult",
    "standardRequiredVectorIds",
    "unavailableRunnerResult",
    "walletHandoffRequiresVerifiedFeeEvidence",
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
  assertEqual(descriptor.behaviorAssurance.configurationIsExecutionEvidence, false, "descriptor.behaviorAssurance.configurationIsExecutionEvidence");
  assertEqual(descriptor.behaviorAssurance.maximumConfiguredRunnerAttempts, 3, "descriptor.behaviorAssurance.maximumConfiguredRunnerAttempts");
  for (const key of ["missingRunnerResult", "retryingRunnerResult", "unavailableRunnerResult"]) {
    assertEqual(descriptor.behaviorAssurance[key], "claims_remain_unverified", `descriptor.behaviorAssurance.${key}`);
  }
  assertEqual(descriptor.behaviorAssurance.failedRunnerResult, "blocks_wallet_handoff", "descriptor.behaviorAssurance.failedRunnerResult");
  assertEqual(descriptor.behaviorAssurance.walletHandoffRequiresVerifiedFeeEvidence, false, "descriptor.behaviorAssurance.walletHandoffRequiresVerifiedFeeEvidence");
  assertEqual(descriptor.behaviorAssurance.mutableSurfaceResult, "conditional", "descriptor.behaviorAssurance.mutableSurfaceResult");
  assertEqual(descriptor.behaviorAssurance.safetyResult, "not_verified", "descriptor.behaviorAssurance.safetyResult");

  assertObject(descriptor.feeAuthorizationGate, "descriptor.feeAuthorizationGate");
  assertExactKeys(descriptor.feeAuthorizationGate, [
    "accountingMode",
    "activationPrerequisites",
    "activationState",
    "appliesTo",
    "behaviorEvidenceSchemaVersion",
    "callerAssertionsAccepted",
    "callerExemptionAllowed",
    "callerVerdictsAccepted",
    "configurationIsExecutionEvidence",
    "evidenceAuthority",
    "exactFeeVaultSourceRuntimeInterfaceRequired",
    "executedHardInvariantFailureDisposition",
    "executedFailureDisposition",
    "feeObservationAbiFrozenRequired",
    "feeVaultCompiler",
    "feeVaultCreationCodeKeccak256",
    "feeVaultReleaseBindingId",
    "feeVaultReleaseBindingSha256",
    "feeVaultRuntimeCodeKeccak256",
    "feeVaultSourcePath",
    "freshWritesEnabled",
    "immutableFeePathRequired",
    "missingEvidenceDisposition",
    "mode",
    "oneTimeRouteCodehashBindingRequired",
    "otherBehaviorAxesDisposition",
    "productionRuntimeReadbackRequired",
    "requiredAssertions",
    "requiredBindings",
    "requiredObservations",
    "requiredPlatformFeeConformanceStatus",
    "requiredSettlementDataflowClosureAssertions",
    "requiredSettlementDataflowClosureReceiptBindings",
    "retryingEvidenceDisposition",
    "scenarioInputsAreExecutionEvidence",
    "serverOwnedActionAbiFrozenRequired",
    "serverSignatureRequired",
    "signedRunnerIdentityConfiguredRequired",
    "unavailableEvidenceDisposition",
    "walletHandoffRequiresVerifiedEvidence"
  ], "descriptor.feeAuthorizationGate");
  assertEqual(descriptor.feeAuthorizationGate.mode, "verified-executed-platform-fee-evidence-required-before-authorization", "descriptor.feeAuthorizationGate.mode");
  assertEqual(descriptor.feeAuthorizationGate.appliesTo, "new-v3.4.0-official-router-market-bearing-writes", "descriptor.feeAuthorizationGate.appliesTo");
  assertEqual(descriptor.feeAuthorizationGate.accountingMode, "additive-platform-share", "descriptor.feeAuthorizationGate.accountingMode");
  assertEqual(descriptor.feeAuthorizationGate.activationState, "pending-runtime-readback", "descriptor.feeAuthorizationGate.activationState");
  assertEqual(descriptor.feeAuthorizationGate.freshWritesEnabled, false, "descriptor.feeAuthorizationGate.freshWritesEnabled");
  if (canonicalJson(descriptor.feeAuthorizationGate.activationPrerequisites) !== canonicalJson([
    "server-owned-action-abi-frozen",
    "fee-observation-abi-frozen",
    "signed-runner-identity-configured",
    "fee-vault-exact-source-runtime-interface-bound",
    "production-runtime-deployment-readback-matched",
    "exact-settlement-dataflow-closure"
  ])) fail("CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_INVALID", "descriptor.feeAuthorizationGate.activationPrerequisites is invalid.");
  assertEqual(descriptor.feeAuthorizationGate.callerExemptionAllowed, false, "descriptor.feeAuthorizationGate.callerExemptionAllowed");
  assertEqual(descriptor.feeAuthorizationGate.callerAssertionsAccepted, false, "descriptor.feeAuthorizationGate.callerAssertionsAccepted");
  assertEqual(descriptor.feeAuthorizationGate.callerVerdictsAccepted, false, "descriptor.feeAuthorizationGate.callerVerdictsAccepted");
  assertEqual(descriptor.feeAuthorizationGate.configurationIsExecutionEvidence, false, "descriptor.feeAuthorizationGate.configurationIsExecutionEvidence");
  assertEqual(descriptor.feeAuthorizationGate.scenarioInputsAreExecutionEvidence, false, "descriptor.feeAuthorizationGate.scenarioInputsAreExecutionEvidence");
  assertEqual(descriptor.feeAuthorizationGate.evidenceAuthority, "platform-runtime-executor", "descriptor.feeAuthorizationGate.evidenceAuthority");
  assertEqual(descriptor.feeAuthorizationGate.behaviorEvidenceSchemaVersion, "programmable.custom-launch-behavior-summary.v1", "descriptor.feeAuthorizationGate.behaviorEvidenceSchemaVersion");
  assertEqual(descriptor.feeAuthorizationGate.requiredPlatformFeeConformanceStatus, "verified", "descriptor.feeAuthorizationGate.requiredPlatformFeeConformanceStatus");
  assertEqual(descriptor.feeAuthorizationGate.serverSignatureRequired, true, "descriptor.feeAuthorizationGate.serverSignatureRequired");
  assertEqual(descriptor.feeAuthorizationGate.immutableFeePathRequired, true, "descriptor.feeAuthorizationGate.immutableFeePathRequired");
  assertEqual(descriptor.feeAuthorizationGate.walletHandoffRequiresVerifiedEvidence, true, "descriptor.feeAuthorizationGate.walletHandoffRequiresVerifiedEvidence");
  assertEqual(descriptor.feeAuthorizationGate.otherBehaviorAxesDisposition, "unclaimed-unless-separately-executed", "descriptor.feeAuthorizationGate.otherBehaviorAxesDisposition");
  assertEqual(descriptor.feeAuthorizationGate.feeVaultReleaseBindingId, "programmable:settlement-fee-vault:v1", "descriptor.feeAuthorizationGate.feeVaultReleaseBindingId");
  assertEqual(descriptor.feeAuthorizationGate.feeVaultReleaseBindingSha256, "sha256:39ccdfdf8cd61620bf5c62bf07fb8428adbd66d2608b1cf3ad583343116d7ed9", "descriptor.feeAuthorizationGate.feeVaultReleaseBindingSha256");
  assertEqual(descriptor.feeAuthorizationGate.feeVaultCreationCodeKeccak256, "0xdbc32e835739b50f33a101a8927008fc46af4c11604f7a5da006e5c56288b21e", "descriptor.feeAuthorizationGate.feeVaultCreationCodeKeccak256");
  assertEqual(descriptor.feeAuthorizationGate.feeVaultRuntimeCodeKeccak256, "0x92620fe3f83839334c9a264bea5bfcc819868ca5607cbd2260e5a9664dbd7554", "descriptor.feeAuthorizationGate.feeVaultRuntimeCodeKeccak256");
  assertEqual(SHA256.test(descriptor.feeAuthorizationGate.feeVaultReleaseBindingSha256), true, "descriptor.feeAuthorizationGate.feeVaultReleaseBindingSha256");
  assertEqual(KECCAK256.test(descriptor.feeAuthorizationGate.feeVaultCreationCodeKeccak256), true, "descriptor.feeAuthorizationGate.feeVaultCreationCodeKeccak256");
  assertEqual(KECCAK256.test(descriptor.feeAuthorizationGate.feeVaultRuntimeCodeKeccak256), true, "descriptor.feeAuthorizationGate.feeVaultRuntimeCodeKeccak256");
  assertEqual(descriptor.feeAuthorizationGate.feeVaultSourcePath, "src/ProgrammableSettlementFeeVaultV1.sol", "descriptor.feeAuthorizationGate.feeVaultSourcePath");
  assertObject(descriptor.feeAuthorizationGate.feeVaultCompiler, "descriptor.feeAuthorizationGate.feeVaultCompiler");
  assertExactKeys(descriptor.feeAuthorizationGate.feeVaultCompiler, ["appendCBOR", "evmVersion", "metadataBytecodeHash", "optimizerEnabled", "optimizerRuns", "solcVersion", "viaIR"], "descriptor.feeAuthorizationGate.feeVaultCompiler");
  if (canonicalJson(descriptor.feeAuthorizationGate.feeVaultCompiler) !== canonicalJson({
    appendCBOR: false,
    evmVersion: "paris",
    metadataBytecodeHash: "none",
    optimizerEnabled: true,
    optimizerRuns: 1000,
    solcVersion: "0.8.26",
    viaIR: false
  })) fail("CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_INVALID", "descriptor.feeAuthorizationGate.feeVaultCompiler is invalid.");
  for (const key of [
    "exactFeeVaultSourceRuntimeInterfaceRequired",
    "feeObservationAbiFrozenRequired",
    "immutableFeePathRequired",
    "oneTimeRouteCodehashBindingRequired",
    "productionRuntimeReadbackRequired",
    "serverOwnedActionAbiFrozenRequired",
    "serverSignatureRequired",
    "signedRunnerIdentityConfiguredRequired",
    "walletHandoffRequiresVerifiedEvidence"
  ]) assertEqual(descriptor.feeAuthorizationGate[key], true, `descriptor.feeAuthorizationGate.${key}`);
  for (const key of ["missingEvidenceDisposition", "retryingEvidenceDisposition", "unavailableEvidenceDisposition", "executedFailureDisposition"]) {
    assertEqual(descriptor.feeAuthorizationGate[key], "blocks_wallet_handoff", `descriptor.feeAuthorizationGate.${key}`);
  }
  assertEqual(descriptor.feeAuthorizationGate.executedHardInvariantFailureDisposition, "blocks_wallet_handoff", "descriptor.feeAuthorizationGate.executedHardInvariantFailureDisposition");
  if (canonicalJson(descriptor.feeAuthorizationGate.requiredBindings) !== canonicalJson([
    "launch-intent-hash", "profile-hash", "artifact-hash", "graph-commitment",
    "exact-target-runtimes", "pool-key", "pinned-fork-block", "fee-vault-release-binding",
    "fee-vault-source-hash", "fee-vault-runtime-codehash", "fee-vault-interface-hash",
    "one-time-route-codehash-binding", "server-owned-action-abi-hash", "fee-observation-abi-hash",
    "signed-runner-identity"
  ])) fail("CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_INVALID", "descriptor.feeAuthorizationGate.requiredBindings is invalid.");
  if (canonicalJson(descriptor.feeAuthorizationGate.requiredObservations) !== canonicalJson([
    "SettlementFeeAccounted", "fee-vault-balance", "fee-vault-accrual", "fee-vault-claim"
  ])) fail("CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_INVALID", "descriptor.feeAuthorizationGate.requiredObservations is invalid.");
  if (canonicalJson(descriptor.feeAuthorizationGate.requiredAssertions) !== canonicalJson([
    "fee.programmable-ten-bps", "fee.no-bypass", "fee.no-overcharge", "fee.claim-isolation"
  ])) fail("CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_INVALID", "descriptor.feeAuthorizationGate.requiredAssertions is invalid.");
  if (canonicalJson(descriptor.feeAuthorizationGate.requiredSettlementDataflowClosureReceiptBindings) !== canonicalJson([
    "profileHash", "launchIntentHash", "artifactHash", "graphBundleHash", "verificationBundleHash",
    "graphCommitment", "expectedPoolId", "vaultTargetId", "vaultRuntimeCodeHash", "authorizedRouteTargetId",
    "authorizedRouteRuntimeCodeHash", "platformFeeObservationSha256"
  ])) fail("CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_INVALID", "descriptor.feeAuthorizationGate.requiredSettlementDataflowClosureReceiptBindings is invalid.");
  if (canonicalJson(descriptor.feeAuthorizationGate.requiredSettlementDataflowClosureAssertions) !== canonicalJson([
    "autonomous-source-receipt-hashes-bound", "applicable-and-satisfied", "complete-value-flow-inventory",
    "nonempty-sorted-flow-and-path-closure", "exact-1000-per-1000000-treasury-observation",
    "closure-recomputed", "signed-trusted-authority"
  ])) fail("CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_INVALID", "descriptor.feeAuthorizationGate.requiredSettlementDataflowClosureAssertions is invalid.");

  assertObject(descriptor.feePolicyProjection, "descriptor.feePolicyProjection");
  assertExactKeys(descriptor.feePolicyProjection, [
    "authorizationGateRuleId",
    "businessPolicyRuleId",
    "buybackManagementLive",
    "denominator",
    "feeBehaviorClaim",
    "genericClaimingLive",
    "programmableHundredthsOfBip",
    "runtimeBehaviorClaim",
    "treasury"
  ], "descriptor.feePolicyProjection");
  assertEqual(descriptor.feePolicyProjection.businessPolicyRuleId, "LAUNCH.ETHEREUM_AND_TREASURY_10_BPS", "descriptor.feePolicyProjection.businessPolicyRuleId");
  assertEqual(descriptor.feePolicyProjection.authorizationGateRuleId, "LAUNCH.ETHEREUM_VERIFIED_EXECUTED_PLATFORM_FEE_BEFORE_AUTHORIZATION", "descriptor.feePolicyProjection.authorizationGateRuleId");
  assertEqual(descriptor.feePolicyProjection.programmableHundredthsOfBip, "1000", "descriptor.feePolicyProjection.programmableHundredthsOfBip");
  assertEqual(descriptor.feePolicyProjection.denominator, "1000000", "descriptor.feePolicyProjection.denominator");
  assertEqual(descriptor.feePolicyProjection.treasury, "0x4957f49620AFf3Adbbe8195a4f633E49cc93376c", "descriptor.feePolicyProjection.treasury");
  assertEqual(descriptor.feePolicyProjection.runtimeBehaviorClaim, "not-established-by-current-admission", "descriptor.feePolicyProjection.runtimeBehaviorClaim");
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
  if (!feeRule || feeRule.status !== "active" || String(feeRule.parameters?.hundredthsOfBip) !== descriptor.feePolicyProjection.programmableHundredthsOfBip) {
    fail("CUSTOM_LAUNCH_ADMISSION_BUSINESS_POLICY_MISMATCH", "The V3 admission fee projection differs from the canonical business policy.");
  }
  const authorizationGateRule = policy.policy.rules.find(({ id }) => id === descriptor.feePolicyProjection.authorizationGateRuleId);
  if (
    !authorizationGateRule
    || authorizationGateRule.status !== "inactive"
    || authorizationGateRule.retiredIn !== policy.policy.policyVersion
    || authorizationGateRule.enforcement?.owner !== "platform"
    || canonicalJson(authorizationGateRule.parameters?.activationPrerequisites) !== canonicalJson(descriptor.feeAuthorizationGate.activationPrerequisites)
    || authorizationGateRule.parameters?.activationState !== descriptor.candidateProfile.activationState
    || authorizationGateRule.parameters?.freshWritesEnabled !== descriptor.candidateProfile.freshWritesEnabled
    || authorizationGateRule.parameters?.profileVersion !== descriptor.candidateProfile.profileVersion
    || authorizationGateRule.parameters?.requiredSettlementDataflowReadback !== descriptor.candidateProfile.requiredSettlementDataflowReadback
    || authorizationGateRule.parameters?.accountingMode !== descriptor.feeAuthorizationGate.accountingMode
    || authorizationGateRule.parameters?.authorizationGateMode !== descriptor.feeAuthorizationGate.mode
    || authorizationGateRule.parameters?.behaviorEvidenceSchemaVersion !== descriptor.feeAuthorizationGate.behaviorEvidenceSchemaVersion
    || authorizationGateRule.parameters?.platformFeeConformanceStatus !== descriptor.feeAuthorizationGate.requiredPlatformFeeConformanceStatus
    || authorizationGateRule.parameters?.immutableFeePathRequired !== descriptor.feeAuthorizationGate.immutableFeePathRequired
    || authorizationGateRule.parameters?.feeVaultReleaseBindingId !== descriptor.feeAuthorizationGate.feeVaultReleaseBindingId
    || authorizationGateRule.parameters?.feeVaultReleaseBindingSha256 !== descriptor.feeAuthorizationGate.feeVaultReleaseBindingSha256
    || authorizationGateRule.parameters?.feeVaultCreationCodeKeccak256 !== descriptor.feeAuthorizationGate.feeVaultCreationCodeKeccak256
    || authorizationGateRule.parameters?.feeVaultRuntimeCodeKeccak256 !== descriptor.feeAuthorizationGate.feeVaultRuntimeCodeKeccak256
    || authorizationGateRule.parameters?.feeVaultSourcePath !== descriptor.feeAuthorizationGate.feeVaultSourcePath
    || authorizationGateRule.parameters?.feeVaultCompilerVersion !== descriptor.feeAuthorizationGate.feeVaultCompiler.solcVersion
    || authorizationGateRule.parameters?.feeVaultEvmVersion !== descriptor.feeAuthorizationGate.feeVaultCompiler.evmVersion
    || authorizationGateRule.parameters?.feeVaultOptimizerEnabled !== descriptor.feeAuthorizationGate.feeVaultCompiler.optimizerEnabled
    || authorizationGateRule.parameters?.feeVaultOptimizerRuns !== descriptor.feeAuthorizationGate.feeVaultCompiler.optimizerRuns
    || authorizationGateRule.parameters?.feeVaultViaIR !== descriptor.feeAuthorizationGate.feeVaultCompiler.viaIR
    || authorizationGateRule.parameters?.feeVaultMetadataBytecodeHash !== descriptor.feeAuthorizationGate.feeVaultCompiler.metadataBytecodeHash
    || authorizationGateRule.parameters?.feeVaultAppendCBOR !== descriptor.feeAuthorizationGate.feeVaultCompiler.appendCBOR
    || canonicalJson(authorizationGateRule.parameters?.requiredFeeVectorIds) !== canonicalJson(descriptor.feeAuthorizationGate.requiredAssertions)
    || canonicalJson(authorizationGateRule.parameters?.requiredFeeObservationIds) !== canonicalJson(descriptor.feeAuthorizationGate.requiredObservations)
    || canonicalJson(authorizationGateRule.parameters?.settlementDataflowClosure) !== canonicalJson(descriptor.settlementDataflowClosure)
    || canonicalJson(authorizationGateRule.parameters?.requiredSettlementDataflowClosureReceiptBindings) !== canonicalJson(descriptor.feeAuthorizationGate.requiredSettlementDataflowClosureReceiptBindings)
    || canonicalJson(authorizationGateRule.parameters?.requiredSettlementDataflowClosureAssertions) !== canonicalJson(descriptor.feeAuthorizationGate.requiredSettlementDataflowClosureAssertions)
    || authorizationGateRule.parameters?.otherBehaviorAxesDisposition !== descriptor.feeAuthorizationGate.otherBehaviorAxesDisposition
    || authorizationGateRule.parameters?.oneTimeRouteCodehashBindingRequired !== descriptor.feeAuthorizationGate.oneTimeRouteCodehashBindingRequired
    || authorizationGateRule.parameters?.productionRuntimeReadbackRequired !== descriptor.feeAuthorizationGate.productionRuntimeReadbackRequired
    || authorizationGateRule.parameters?.callerAssertionsAccepted !== descriptor.feeAuthorizationGate.callerAssertionsAccepted
    || authorizationGateRule.parameters?.callerVerdictsAccepted !== descriptor.feeAuthorizationGate.callerVerdictsAccepted
    || authorizationGateRule.parameters?.configurationIsExecutionEvidence !== descriptor.feeAuthorizationGate.configurationIsExecutionEvidence
    || authorizationGateRule.parameters?.scenarioInputsAreExecutionEvidence !== descriptor.feeAuthorizationGate.scenarioInputsAreExecutionEvidence
    || authorizationGateRule.parameters?.executedHardInvariantFailureBlocksWalletHandoff !== true
    || String(authorizationGateRule.parameters?.hundredthsOfBip) !== descriptor.feePolicyProjection.programmableHundredthsOfBip
    || String(authorizationGateRule.parameters?.rateDenominator) !== descriptor.feePolicyProjection.denominator
    || authorizationGateRule.parameters?.treasury !== descriptor.feePolicyProjection.treasury
  ) {
    fail("CUSTOM_LAUNCH_ADMISSION_BUSINESS_POLICY_MISMATCH", "The V3 admission fee authorization gate differs from the canonical business policy.");
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
    candidateProfile: structuredClone(descriptor.candidateProfile),
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
