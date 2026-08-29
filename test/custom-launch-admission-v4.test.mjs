import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import Ajv2020 from "../scripts/test/schema-validator/node_modules/ajv/dist/2020.js";

import {
  buildCustomLaunchAdmissionBindingV4,
  validateCustomLaunchAdmissionDescriptorV4,
  verifyCustomLaunchAdmissionBindingV4
} from "../scripts/custom-launch-admission-v4-core.mjs";
import { canonicalJson, parseLaunchPolicyBytes } from "../scripts/launch-policy-core.mjs";

const root = path.resolve(import.meta.dirname, "..");
const descriptorPath = "policy/custom-launch-admission-v4.json";
const descriptorSource = fs.readFileSync(path.join(root, descriptorPath), "utf8");
const descriptor = JSON.parse(descriptorSource);
const schema = JSON.parse(fs.readFileSync(path.join(root, "policy/schemas/custom-launch-admission-v4.schema.json"), "utf8"));
const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);

function deploymentRoot(index, address = `0x${index.toString(16).padStart(40, "0")}`) {
  return {
    address,
    runtimeCodeHash: `0x${index.toString(16).padStart(64, "0")}`,
    startBlock: "1"
  };
}

function canaryDeploymentEvidence() {
  return {
    chainDeploymentDescriptorDigest: `sha256:${"1".repeat(64)}`,
    chainDeploymentId: "robinhood-mainnet-custom-launch-v1",
    finalityPolicyDigest: "sha256:537d531423d1285a3808556a57303ec68f1e6bdeea3c9aaf6320f9e5a0e47153",
    finalizedBlock: "10",
    finalizedEvidenceRef: {
      commit: "a".repeat(40),
      path: "contracts/deployments/evidence/robinhood-custom-launch-v1.json",
      repository: "https://github.com/programmablehq/PROGRAMMABLE",
      sha256: `sha256:${"2".repeat(64)}`
    },
    foundationSourceCommitment: "0xe87f5edc2dc839bd87a26a80cb53f14b021e603a1753d27aae3a02862058d730",
    roots: {
      graphFactory: deploymentRoot(1),
      permit2: deploymentRoot(2),
      permitAuthoritySafe: deploymentRoot(3),
      poolManager: deploymentRoot(4, "0x8366a39cc670b4001a1121b8f6a443a643e40951"),
      positionManager: deploymentRoot(5),
      programmableLaunchStampRouter: deploymentRoot(6),
      stateView: deploymentRoot(7),
      universalRouter: deploymentRoot(8),
      v4Quoter: deploymentRoot(9)
    }
  };
}

test("V4 Robinhood admission is closed, canonical and server-selected", () => {
  assert.equal(validate(descriptor), true, JSON.stringify(validate.errors));
  assert.equal(validateCustomLaunchAdmissionDescriptorV4(structuredClone(descriptor)), true);
  assert.equal(descriptorSource, `${canonicalJson(descriptor)}\n`);
  assert.deepEqual(descriptor.policySelection, {
    authenticatedChainBoundRequestRequired: true,
    clientSelectable: false,
    productionProfileId: "robinhood-production-launch",
    readinessProfileId: "robinhood-launch-readiness",
    selectedBy: "api-server-chain-binding"
  });
  assert.equal(descriptor.chain.promotionStatus, "planned");
  assert.deepEqual(descriptor.chain.deploymentEvidence, {
    chainDeploymentDescriptorDigest: null,
    chainDeploymentId: null,
    finalityPolicyDigest: null,
    finalizedBlock: null,
    finalizedEvidenceRef: null,
    foundationSourceCommitment: null,
    roots: {
      graphFactory: null,
      permit2: null,
      permitAuthoritySafe: null,
      poolManager: null,
      positionManager: null,
      programmableLaunchStampRouter: null,
      stateView: null,
      universalRouter: null,
      v4Quoter: null
    }
  });
  assert.equal(
    descriptor.repository.foundationSourceCommitment,
    "0xe87f5edc2dc839bd87a26a80cb53f14b021e603a1753d27aae3a02862058d730"
  );
  assert.equal(descriptor.staticAdmission.manualProjectAllowlist, false);
  assert.equal(
    descriptor.staticAdmission.hardBlockFindingCodes.includes("UNBOUND_EXTERNAL_CONTRACT_REFERENCE"),
    true
  );
  assert.deepEqual(descriptor.funding.advertisedModes, ["none", "wallet-transaction-value"]);
  assert.deepEqual(descriptor.claims, {
    auditClaim: false,
    buybacksLive: false,
    externalIndexingGuaranteed: false,
    feeBehaviorClaim: false,
    genericClaimingLive: false,
    safetyClaim: false,
    universalCompatibilityClaim: false,
    universalFeeBehaviorClaim: false
  });
});

test("V4 binding pins the exact policy, schema, chain and stable public pointers", () => {
  const binding = buildCustomLaunchAdmissionBindingV4({ repositoryRoot: root });
  const policy = parseLaunchPolicyBytes(fs.readFileSync(path.join(root, "policy/launch-policy.v1.json")));
  assert.equal(binding.businessPolicy.policyVersion, "2.4.0");
  assert.equal(binding.businessPolicy.sha256, policy.sha256);
  assert.equal(binding.businessPolicy.readinessProfileId, "robinhood-launch-readiness");
  assert.equal(binding.businessPolicy.productionProfileId, "robinhood-production-launch");
  const externalReferenceRule = policy.policy.rules.find(
    ({ id }) => id === "LAUNCH.ROBINHOOD_SOURCE_VERIFICATION_BINDING"
  );
  assert.deepEqual(externalReferenceRule.profiles, [
    "robinhood-launch-readiness",
    "robinhood-production-launch"
  ]);
  assert.equal(externalReferenceRule.parameters.externalContractReferenceCaip2, "eip155:4663");
  assert.equal(externalReferenceRule.parameters.externalContractReferenceCheckpointRequired, true);
  assert.equal(externalReferenceRule.parameters.externalContractReferenceExactAddressRequired, true);
  assert.equal(externalReferenceRule.parameters.externalContractReferenceRoleRequired, true);
  assert.equal(externalReferenceRule.parameters.externalContractReferenceRuntimeHashRequired, true);
  assert.equal(externalReferenceRule.parameters.externalContractReferenceServerVerificationRequired, true);
  assert.equal(externalReferenceRule.parameters.externalContractReferenceSourceVerificationEvidenceRequired, true);
  assert.equal(externalReferenceRule.parameters.requiredExactMatchProvider, "sourcify-v2");
  assert.equal(externalReferenceRule.parameters.sourcifyV2ExactMatchRequired, true);
  assert.equal(externalReferenceRule.parameters.blockscoutAvailability, "optional-unproven-degraded");
  assert.equal(externalReferenceRule.parameters.blockscoutExactSourceClaimAllowed, false);
  assert.equal(externalReferenceRule.parameters.blockscoutFinalityBlocker, false);
  assert.equal(externalReferenceRule.parameters.unboundExternalContractReferencesTrusted, false);
  const trustRootRule = policy.policy.rules.find(
    ({ id }) => id === "LAUNCH.ROBINHOOD_PROGRAMMABLE_TRUST_ROOTS"
  );
  assert.equal(
    trustRootRule.parameters.foundationSourceCommitment,
    descriptor.repository.foundationSourceCommitment
  );
  assert.equal(binding.chain.caip2, "eip155:4663");
  assert.equal(binding.transport.openApiUrl, "https://programmable.market/openapi/custom-launch-v4.json");
  assert.equal(binding.transport.packConfigSchemaUrl, "https://programmable.market/schemas/custom-launch/v4/pack-config.json");
  assert.deepEqual(verifyCustomLaunchAdmissionBindingV4({ repositoryRoot: root }), {
    descriptorSha256: binding.descriptor.sha256,
    ok: true,
    path: ".programmable/custom-launch-admission.v4.json",
    policySha256: binding.businessPolicy.sha256
  });
});

test("V4 rejects caller-selected profiles and mechanically couples promotion to finalized deployment evidence", () => {
  const selectable = structuredClone(descriptor);
  selectable.policySelection.clientSelectable = true;
  assert.throws(
    () => validateCustomLaunchAdmissionDescriptorV4(selectable),
    (error) => error?.code === "CUSTOM_LAUNCH_ADMISSION_V4_INVALID"
  );

  const live = structuredClone(descriptor);
  live.chain.promotionStatus = "live";
  assert.throws(
    () => validateCustomLaunchAdmissionDescriptorV4(live),
    (error) => error?.code === "CUSTOM_LAUNCH_ADMISSION_V4_INVALID"
  );

  const plannedWithEvidence = structuredClone(descriptor);
  plannedWithEvidence.chain.deploymentEvidence.chainDeploymentId = "robinhood-mainnet-custom-launch-v1";
  assert.equal(validate(plannedWithEvidence), false);
  assert.throws(
    () => validateCustomLaunchAdmissionDescriptorV4(plannedWithEvidence),
    (error) => error?.code === "CUSTOM_LAUNCH_ADMISSION_V4_INVALID"
  );

  const canaryWithoutEvidence = structuredClone(descriptor);
  canaryWithoutEvidence.chain.promotionStatus = "canary";
  assert.equal(validate(canaryWithoutEvidence), false);
  assert.throws(
    () => validateCustomLaunchAdmissionDescriptorV4(canaryWithoutEvidence),
    (error) => error?.code === "CUSTOM_LAUNCH_ADMISSION_V4_INVALID"
  );

  const canary = structuredClone(descriptor);
  canary.chain.promotionStatus = "canary";
  canary.chain.deploymentEvidence = canaryDeploymentEvidence();
  assert.equal(validate(canary), true, JSON.stringify(validate.errors));
  assert.equal(validateCustomLaunchAdmissionDescriptorV4(canary), true);

  const unfinalizedRoot = structuredClone(canary);
  unfinalizedRoot.chain.deploymentEvidence.roots.graphFactory.startBlock = "11";
  assert.throws(
    () => validateCustomLaunchAdmissionDescriptorV4(unfinalizedRoot),
    (error) => error?.code === "CUSTOM_LAUNCH_ADMISSION_V4_INVALID"
  );
});
