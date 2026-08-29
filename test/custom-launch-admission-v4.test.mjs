import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import Ajv2020 from "../scripts/test/schema-validator/node_modules/ajv/dist/2020.js";

import {
  ROBINHOOD_PROMOTION_ANCHOR_V4,
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
const FROZEN_V3_BYTES = Object.freeze({
  cli: "5d5e2604bcdaecaf2fc0c0605671a5fdb198ea4a3cac15b76e77e9ba1017ef34",
  descriptor: "b3a88009f081f653a8eadf87d4f199a2837704bae5edb752da70882ca994325c",
  schema: "d6ea4492f01c8ae94315f5cca49f0e0f5d36c7ff3238dd0d82bd758705f60627"
});

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function changedHex(value) {
  return `${value.slice(0, -1)}${value.endsWith("0") ? "1" : "0"}`;
}

function assertRejectedDescriptor(candidate, label) {
  assert.equal(validate(candidate), false, label);
  assert.throws(
    () => validateCustomLaunchAdmissionDescriptorV4(candidate),
    (error) => error?.code === "CUSTOM_LAUNCH_ADMISSION_V4_PROMOTION_ANCHOR_MISMATCH",
    label
  );
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
  assert.deepEqual(descriptor.chain.deploymentEvidence, ROBINHOOD_PROMOTION_ANCHOR_V4);
  assert.deepEqual(
    [
      ...Object.entries(descriptor.chain.deploymentEvidence)
        .filter(([, value]) => value === null)
        .map(([field]) => `chain.deploymentEvidence.${field}`),
      ...Object.entries(descriptor.chain.deploymentEvidence.roots)
        .filter(([, binding]) => binding.startBlock === null)
        .map(([rootId]) => `chain.deploymentEvidence.roots.${rootId}.startBlock`)
    ],
    [
      "chain.deploymentEvidence.chainDeploymentDescriptorDigest",
      "chain.deploymentEvidence.finalizedBlock",
      "chain.deploymentEvidence.finalizedEvidenceRef",
      "chain.deploymentEvidence.roots.graphFactory.startBlock",
      "chain.deploymentEvidence.roots.permit2.startBlock",
      "chain.deploymentEvidence.roots.permitAuthoritySafe.startBlock",
      "chain.deploymentEvidence.roots.programmableLaunchStampRouter.startBlock"
    ]
  );
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

test("V4 leaves the frozen V3 descriptor, schema, CLI and default npm entrypoint unchanged", () => {
  assert.equal(
    sha256(fs.readFileSync(path.join(root, "policy/custom-launch-admission-v3.json"))),
    FROZEN_V3_BYTES.descriptor
  );
  assert.equal(
    sha256(fs.readFileSync(path.join(root, "policy/schemas/custom-launch-admission-v3.schema.json"))),
    FROZEN_V3_BYTES.schema
  );
  assert.equal(
    sha256(fs.readFileSync(path.join(root, "scripts/custom-launch-admission-v3.mjs"))),
    FROZEN_V3_BYTES.cli
  );
  const packageManifest = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
  assert.equal(packageManifest.scripts["admission:v3"], "node scripts/custom-launch-admission-v3.mjs");
  assert.equal(packageManifest.scripts["admission:v4"], "node scripts/custom-launch-admission-v4.mjs --check");
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

test("V4 rejects caller-selected profiles and keeps promotion closed until the exact anchor is complete", () => {
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

  const canaryWithoutEvidence = structuredClone(descriptor);
  canaryWithoutEvidence.chain.promotionStatus = "canary";
  assert.equal(validate(canaryWithoutEvidence), false);
  assert.throws(
    () => validateCustomLaunchAdmissionDescriptorV4(canaryWithoutEvidence),
    (error) => error?.code === "CUSTOM_LAUNCH_ADMISSION_V4_PROMOTION_ANCHOR_INCOMPLETE"
  );

  const syntacticallyValidButUnreviewed = structuredClone(descriptor);
  syntacticallyValidButUnreviewed.chain.promotionStatus = "canary";
  syntacticallyValidButUnreviewed.chain.deploymentEvidence.chainDeploymentDescriptorDigest = `sha256:${"1".repeat(64)}`;
  syntacticallyValidButUnreviewed.chain.deploymentEvidence.finalizedBlock = "50000000";
  syntacticallyValidButUnreviewed.chain.deploymentEvidence.finalizedEvidenceRef = {
    commit: "a".repeat(40),
    path: "contracts/deployments/evidence/robinhood-custom-launch-v1.json",
    repository: "https://github.com/programmablehq/PROGRAMMABLE",
    sha256: `sha256:${"2".repeat(64)}`
  };
  for (const binding of Object.values(syntacticallyValidButUnreviewed.chain.deploymentEvidence.roots)) {
    if (binding.startBlock === null) binding.startBlock = "1";
  }
  assertRejectedDescriptor(syntacticallyValidButUnreviewed);
});

test("V4 rejects every promotion-anchor address, runtime hash, start block, digest and evidence mutation", () => {
  const mutations = [
    ["chain deployment descriptor digest", (candidate) => {
      candidate.chain.deploymentEvidence.chainDeploymentDescriptorDigest = `sha256:${"1".repeat(64)}`;
    }],
    ["chain deployment id", (candidate) => {
      candidate.chain.deploymentEvidence.chainDeploymentId = "robinhood-mainnet-custom-launch-v2";
    }],
    ["finality policy digest", (candidate) => {
      candidate.chain.deploymentEvidence.finalityPolicyDigest = `sha256:${"3".repeat(64)}`;
    }],
    ["finalized block", (candidate) => {
      candidate.chain.deploymentEvidence.finalizedBlock = "50000000";
    }],
    ["finalized evidence reference", (candidate) => {
      candidate.chain.deploymentEvidence.finalizedEvidenceRef = {
        commit: "a".repeat(40),
        path: "contracts/deployments/evidence/robinhood-custom-launch-v1.json",
        repository: "https://github.com/programmablehq/PROGRAMMABLE",
        sha256: `sha256:${"2".repeat(64)}`
      };
    }],
    ["foundation source commitment", (candidate) => {
      candidate.chain.deploymentEvidence.foundationSourceCommitment = changedHex(
        candidate.chain.deploymentEvidence.foundationSourceCommitment
      );
    }]
  ];
  for (const rootId of Object.keys(descriptor.chain.deploymentEvidence.roots)) {
    mutations.push(
      [`${rootId} address`, (candidate) => {
        const binding = candidate.chain.deploymentEvidence.roots[rootId];
        binding.address = changedHex(binding.address);
      }],
      [`${rootId} runtime hash`, (candidate) => {
        const binding = candidate.chain.deploymentEvidence.roots[rootId];
        binding.runtimeCodeHash = changedHex(binding.runtimeCodeHash);
      }],
      [`${rootId} start block`, (candidate) => {
        const binding = candidate.chain.deploymentEvidence.roots[rootId];
        binding.startBlock = binding.startBlock === null
          ? "1"
          : (BigInt(binding.startBlock) + 1n).toString();
      }]
    );
  }

  assert.equal(mutations.length, 33);
  for (const [label, mutate] of mutations) {
    const candidate = structuredClone(descriptor);
    mutate(candidate);
    assertRejectedDescriptor(candidate, label);
  }
});
