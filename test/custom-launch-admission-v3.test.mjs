import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import Ajv2020 from "../scripts/test/schema-validator/node_modules/ajv/dist/2020.js";

import {
  buildCustomLaunchAdmissionBindingV3,
  validateCustomLaunchAdmissionDescriptorV3,
  verifyCustomLaunchAdmissionProjectionsV3
} from "../scripts/custom-launch-admission-v3-core.mjs";
import { canonicalJson } from "../scripts/launch-policy-core.mjs";

const root = path.resolve(import.meta.dirname, "..");
const descriptorPath = "policy/custom-launch-admission-v3.json";
const descriptorSource = fs.readFileSync(path.join(root, descriptorPath), "utf8");
const descriptor = JSON.parse(descriptorSource);

const HARD_BLOCK_CODES = Object.freeze([
  "RUNTIME_CALLCODE",
  "RUNTIME_SELFDESTRUCT",
  "SOURCE_SELFDESTRUCT_SURFACE",
  "V4_CALLBACK_AUTHENTICATION_MISSING",
  "V4_CALLBACK_AUTHENTICATION_INVALID",
  "V4_CALLBACK_POOL_MANAGER_MISMATCH",
  "V4_ENABLED_CALLBACK_IMPLEMENTATION_MISSING"
]);
const NEEDS_EVIDENCE_CODES = Object.freeze([
  "RUNTIME_CREATE",
  "RUNTIME_CREATE2",
  "SOURCE_TARGET_ANALYSIS_INCOMPLETE",
  "V4_CALLBACK_AUTHENTICATION_REVIEW_REQUIRED",
  "RUNTIME_DELEGATECALL",
  "SOURCE_PROXY_OR_UPGRADE_SURFACE",
  "SOURCE_MUTABLE_PAUSE_SURFACE",
  "SOURCE_MUTABLE_BLOCKLIST_SURFACE",
  "SOURCE_MUTABLE_TAX_OR_FEE_SURFACE",
  "SOURCE_MUTABLE_TRANSFER_RESTRICTION",
  "SOURCE_MUTABLE_ADMIN_SURFACE",
  "SOURCE_PUBLIC_MINT_SURFACE",
  "SOURCE_EXTERNAL_DEPENDENCY_SURFACE",
  "SOURCE_TRANSFER_FEE_SURFACE",
  "SOURCE_LIQUIDITY_LOCK_OR_CUSTODY_SURFACE"
]);
const STANDARD_VECTOR_IDS = Object.freeze([
  "swap.zero-for-one.exact-input.multi-size",
  "swap.zero-for-one.exact-output.multi-size",
  "swap.one-for-zero.exact-input.multi-size",
  "swap.one-for-zero.exact-output.multi-size",
  "swap.second-user",
  "swap.time-advance",
  "liquidity.lifecycle.add-remove-withdraw",
  "callback.permission-mask-and-declaration",
  "callback.enabled-entrypoints-and-selectors",
  "callback.canonical-pool-manager-only",
  "callback.unauthorized-rejected",
  "callback.wrong-pool-rejected-or-isolated",
  "fee.programmable-ten-bps",
  "fee.no-bypass",
  "fee.no-overcharge",
  "fee.claim-isolation"
]);
const ADVANCED_VECTOR_IDS = Object.freeze([
  "custom-accounting.delta-solvency",
  "custom-accounting.inventory-backing",
  "custom-accounting.refund",
  "custom-accounting.withdrawal"
]);

test("V3 admission descriptor is closed, canonical, and matches the public risk and behavior contracts", () => {
  const schema = JSON.parse(fs.readFileSync(path.join(root, "policy/schemas/custom-launch-admission-v3.schema.json"), "utf8"));
  const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
  assert.equal(validate(descriptor), true, JSON.stringify(validate.errors));
  assert.equal(validateCustomLaunchAdmissionDescriptorV3(structuredClone(descriptor)), true);
  assert.equal(descriptorSource, `${canonicalJson(descriptor)}\n`);
  assert.deepEqual(descriptor.staticAdmission.hardBlockFindingRules.map(({ code }) => code), HARD_BLOCK_CODES);
  assert.deepEqual(descriptor.staticAdmission.needsEvidenceFindingCodes, NEEDS_EVIDENCE_CODES);
  assert.equal(descriptor.behaviorAssurance.vectorSetVersion, "1.1.0");
  assert.equal(descriptor.behaviorAssurance.riskClassifierVersion, "1.1.0");
  assert.deepEqual(descriptor.behaviorAssurance.standardRequiredVectorIds, STANDARD_VECTOR_IDS);
  assert.deepEqual(descriptor.behaviorAssurance.advancedRequiredVectorIds, ADVANCED_VECTOR_IDS);
  assert.equal(descriptor.behaviorAssurance.authorizationScope, "exact-launch-provenance-only");
  assert.equal(descriptor.behaviorAssurance.missingRunnerEvidenceAuthority, "none");
  assert.equal(descriptor.behaviorAssurance.configurationIsExecutionEvidence, false);
  assert.equal(descriptor.behaviorAssurance.maximumConfiguredRunnerAttempts, 3);
  for (const key of ["missingRunnerResult", "retryingRunnerResult", "unavailableRunnerResult"]) {
    assert.equal(descriptor.behaviorAssurance[key], "claims_remain_unverified", key);
  }
  assert.equal(descriptor.behaviorAssurance.failedRunnerResult, "blocks_wallet_handoff");
  assert.equal(descriptor.behaviorAssurance.walletHandoffRequiresVerifiedFeeEvidence, false);
  assert.equal(descriptor.behaviorAssurance.mutableSurfaceResult, "conditional");
  assert.equal(descriptor.behaviorAssurance.safetyResult, "not_verified");
});

test("V3.4 fee authorization remains pending while current V3.3 keeps exact compatibility", () => {
  assert.equal(descriptor.profile.profileVersion, "3.3.0");
  assert.deepEqual(descriptor.candidateProfile, {
    activationState: "pending-runtime-readback",
    chainId: "1",
    freshWritesEnabled: false,
    multiContractGraphSupported: true,
    profileId: "programmable.direct-native-hook-graph.v1",
    profileRevision: 3,
    profileVersion: "3.4.0",
    projectOwnedHookSupported: true,
    projectOwnedTokenSupported: true,
    requiredSettlementDataflowReadback: "configured-autonomous-approval-exact-route-closure-receipt"
  });
  assert.deepEqual(descriptor.compatibility, {
    legacyExactProfileVersions: ["3.2.0", "3.1.0", "3.0.0", "2.0.0"],
    legacyFeeBehaviorResult: "unverified",
    legacySemantics: "readable-and-byte-identical-retryable-only",
    retroactiveAuthorizationGate: false
  });
  assert.equal(descriptor.feeAuthorizationGate.mode, "verified-executed-platform-fee-evidence-required-before-authorization");
  assert.equal(descriptor.feeAuthorizationGate.activationState, "pending-runtime-readback");
  assert.equal(descriptor.feeAuthorizationGate.freshWritesEnabled, false);
  assert.equal(descriptor.feeAuthorizationGate.appliesTo, "new-v3.4.0-official-router-market-bearing-writes");
  assert.equal(descriptor.feeAuthorizationGate.accountingMode, "additive-platform-share");
  assert.equal(descriptor.feeAuthorizationGate.callerExemptionAllowed, false);
  assert.equal(descriptor.feeAuthorizationGate.behaviorEvidenceSchemaVersion, "programmable.custom-launch-behavior-summary.v1");
  assert.equal(descriptor.feeAuthorizationGate.requiredPlatformFeeConformanceStatus, "verified");
  assert.equal(descriptor.feeAuthorizationGate.serverSignatureRequired, true);
  assert.equal(descriptor.feeAuthorizationGate.immutableFeePathRequired, true);
  assert.equal(descriptor.feeAuthorizationGate.walletHandoffRequiresVerifiedEvidence, true);
  assert.equal(descriptor.feeAuthorizationGate.callerAssertionsAccepted, false);
  assert.equal(descriptor.feeAuthorizationGate.callerVerdictsAccepted, false);
  assert.equal(descriptor.feeAuthorizationGate.otherBehaviorAxesDisposition, "unclaimed-unless-separately-executed");
  assert.equal(descriptor.feeAuthorizationGate.feeVaultReleaseBindingId, "programmable:settlement-fee-vault:v1");
  assert.equal(descriptor.feeAuthorizationGate.feeVaultReleaseBindingSha256, "sha256:39ccdfdf8cd61620bf5c62bf07fb8428adbd66d2608b1cf3ad583343116d7ed9");
  assert.equal(descriptor.feeAuthorizationGate.feeVaultRuntimeCodeKeccak256, "0x92620fe3f83839334c9a264bea5bfcc819868ca5607cbd2260e5a9664dbd7554");
  assert.deepEqual(descriptor.settlementDataflowClosure, {
    candidateRouteCoverageComesFromRunner: false,
    clientAssertionsAccepted: false,
    completeValueFlowInventoryRequired: true,
    configured: false,
    evidenceAuthority: "programmable-autonomous-approval",
    exactLaunchGraphAndRouteBindingRequired: true,
    receiptSchemaVersion: "programmable.autonomous-settlement-dataflow-receipt.v1",
    runnerNoBypassScope: "canonical-vault-entrypoints-only",
    sourceDecisionReceiptRequired: true,
    walletHandoffRequiresClosure: true
  });
  assert.equal(descriptor.feeAuthorizationGate.activationPrerequisites.includes("exact-settlement-dataflow-closure"), true);
  assert.deepEqual(descriptor.feeAuthorizationGate.requiredSettlementDataflowClosureReceiptBindings, [
    "profileHash",
    "launchIntentHash",
    "artifactHash",
    "graphBundleHash",
    "verificationBundleHash",
    "graphCommitment",
    "expectedPoolId",
    "vaultTargetId",
    "vaultRuntimeCodeHash",
    "authorizedRouteTargetId",
    "authorizedRouteRuntimeCodeHash",
    "platformFeeObservationSha256"
  ]);
  assert.deepEqual(descriptor.feeAuthorizationGate.requiredSettlementDataflowClosureReceiptClaims, {
    feePathImmutable: true,
    routeCodehashBindingComplete: true,
    upgradeAuthority: "none"
  });
  assert.deepEqual(descriptor.feeAuthorizationGate.requiredAssertions, [
    "fee.programmable-ten-bps",
    "fee.no-bypass",
    "fee.no-overcharge",
    "fee.claim-isolation"
  ]);
});

test("V3 admission authority never delegates admission or behavior claims to a client, CLI, or agent", () => {
  assert.deepEqual(descriptor.authority, {
    admissionDisclosurePath: descriptorPath,
    agentAdmissionAuthority: false,
    businessPolicyPath: "policy/launch-policy.v1.json",
    businessPolicyScope: "programmable-router-fee-and-promotion-obligations",
    cliAdmissionAuthority: false,
    clientAdmissionAuthority: false,
    executableEvidenceAuthority: "private-custom-launch-api",
    platformAdmissionReceiptRequired: true
  });
  assert.deepEqual(descriptor.claims, {
    auditClaim: false,
    feeBehaviorClaim: false,
    safetyClaim: false,
    universalCompatibilityClaim: false
  });
  assert.equal(descriptor.feePolicyProjection.runtimeBehaviorClaim, "not-established-by-current-admission");
  assert.equal(descriptor.feePolicyProjection.feeBehaviorClaim, false);
});

test("generated V3 binding pins the business policy, descriptor, and every public projection value", () => {
  const binding = buildCustomLaunchAdmissionBindingV3({ repositoryRoot: root });
  const expectedDescriptorDigest = `sha256:${crypto.createHash("sha256").update(descriptorSource).digest("hex")}`;
  assert.equal(binding.descriptor.sha256, expectedDescriptorDigest);
  assert.match(binding.businessPolicy.sha256, /^sha256:[0-9a-f]{64}$/u);
  assert.equal(binding.businessPolicy.policyVersion, "2.4.0");
  assert.deepEqual(binding.profile, descriptor.profile);
  assert.deepEqual(binding.candidateProfile, descriptor.candidateProfile);
  assert.equal(binding.projections.length, 3);
  for (const projection of binding.projections) {
    assert.match(projection.url, /^https:\/\//u);
    for (const check of projection.checks) assert.match(check.expectedSha256, /^sha256:[0-9a-f]{64}$/u);
  }
});

test("V3 projection reconciliation accepts exact values and rejects one drifted public value", () => {
  const wellKnown = {
    customLaunchApi: {
      generalHookProfile: {
        admissionPolicy: {
          hardBlockFindingRules: descriptor.staticAdmission.hardBlockFindingRules,
          manualProjectAllowlist: descriptor.staticAdmission.manualProjectAllowlist,
          needsEvidenceFindingCodes: descriptor.staticAdmission.needsEvidenceFindingCodes
        },
        profileId: descriptor.profile.profileId,
        profileRevision: descriptor.profile.profileRevision,
        profileVersion: descriptor.profile.profileVersion,
        compatibleProfileVersions: descriptor.compatibility.legacyExactProfileVersions,
        legacyProfileSemantics: descriptor.compatibility.legacySemantics
      },
      integrationPreview: {
        feeBehaviorClaim: descriptor.claims.feeBehaviorClaim,
        routerSimulationRequiredBeforeAuthorization: descriptor.staticAdmission.routerSimulationRequiredBeforeAuthorization,
        safetyClaim: descriptor.claims.safetyClaim
      }
    }
  };
  const capabilities = {
    advancedFeaturesRequireEvidence: descriptor.advancedFeaturesRequireEvidence,
    auditClaim: descriptor.claims.auditClaim,
    feePolicy: {
      buybackManagementLive: descriptor.feePolicyProjection.buybackManagementLive,
      denominator: descriptor.feePolicyProjection.denominator,
      genericClaimingLive: descriptor.feePolicyProjection.genericClaimingLive,
      immutableFeePathRequired: descriptor.feeAuthorizationGate.immutableFeePathRequired,
      programmableHundredthsOfBip: descriptor.feePolicyProjection.programmableHundredthsOfBip
    },
    behaviorEvidence: {
      configurationIsExecutionEvidence: descriptor.behaviorAssurance.configurationIsExecutionEvidence,
      executedFailureDisposition: descriptor.behaviorAssurance.failedRunnerResult,
      feeBehaviorClaim: descriptor.claims.feeBehaviorClaim,
      maximumConfiguredRunnerAttempts: descriptor.behaviorAssurance.maximumConfiguredRunnerAttempts,
      notConfiguredDisposition: descriptor.behaviorAssurance.missingRunnerResult,
      unavailableDisposition: descriptor.behaviorAssurance.unavailableRunnerResult,
      vectorSetVersion: descriptor.behaviorAssurance.vectorSetVersion,
      walletHandoffRequiresVerifiedEvidence: descriptor.behaviorAssurance.walletHandoffRequiresVerifiedFeeEvidence
    },
    hardSafetyInvariants: descriptor.hardSafetyInvariants,
    profile: descriptor.profile,
    safetyClaim: descriptor.claims.safetyClaim,
    universalCompatibilityClaim: descriptor.claims.universalCompatibilityClaim
  };
  const openApi = {
    "x-programmable-admission-policy": {
      hardBlockFindingRules: descriptor.staticAdmission.hardBlockFindingRules,
      legacyExactProfileVersions: descriptor.compatibility.legacyExactProfileVersions,
      legacySemantics: descriptor.compatibility.legacySemantics,
      manualProjectAllowlist: descriptor.staticAdmission.manualProjectAllowlist,
      needsEvidenceFindingCodes: descriptor.staticAdmission.needsEvidenceFindingCodes
    },
    "x-programmable-fee-accounting": {
      programmableFeeHundredthsOfBip: descriptor.feePolicyProjection.programmableHundredthsOfBip
    },
    "x-programmable-profile": {
      feeBehaviorClaim: descriptor.claims.feeBehaviorClaim,
      profileId: descriptor.profile.profileId,
      profileRevision: descriptor.profile.profileRevision,
      profileVersion: descriptor.profile.profileVersion,
      safetyClaim: descriptor.claims.safetyClaim
    }
  };
  assert.equal(verifyCustomLaunchAdmissionProjectionsV3({ repositoryRoot: root, wellKnown, capabilities, openApi }).ok, true);
  const drifted = structuredClone(openApi);
  drifted["x-programmable-profile"].profileRevision += 1;
  assert.throws(
    () => verifyCustomLaunchAdmissionProjectionsV3({ repositoryRoot: root, wellKnown, capabilities, openApi: drifted }),
    (error) => error?.code === "CUSTOM_LAUNCH_ADMISSION_PROJECTION_MISMATCH"
  );
});
