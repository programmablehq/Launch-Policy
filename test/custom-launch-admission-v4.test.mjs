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
const ajv = new Ajv2020({ allErrors: true, strict: true });
const validate = ajv.compile(schema);
const validateCompletePromotionAnchor = ajv.compile({ $ref: `${schema.$id}#/$defs/completePromotionAnchor` });
const validateCompletePromotionRoots = ajv.compile({ $ref: `${schema.$id}#/$defs/completePromotionRoots` });
const validateGenesisDeploymentRoot = ajv.compile({ $ref: `${schema.$id}#/$defs/genesisDeploymentRoot` });
const validatePlannedPromotionRoots = ajv.compile({ $ref: `${schema.$id}#/$defs/plannedPromotionRoots` });
const validateTransactionDeploymentRoot = ajv.compile({ $ref: `${schema.$id}#/$defs/transactionDeploymentRoot` });
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

function collectLeaves(value, pathSegments = []) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return [[pathSegments, value]];
  return Object.entries(value).flatMap(([key, child]) => collectLeaves(child, [...pathSegments, key]));
}

function collectNullPaths(value, pathSegments = []) {
  return collectLeaves(value, pathSegments)
    .filter(([, child]) => child === null)
    .map(([segments]) => segments.join("."));
}

function genericTransactionFilledAnchor() {
  const anchor = structuredClone(descriptor.chain.deploymentEvidence);
  anchor.chainDeploymentDescriptorDigest = `sha256:${"1".repeat(64)}`;
  anchor.finalizedBlock = "50000000";
  anchor.finalizedEvidenceRef = {
    commit: "a".repeat(40),
    path: "contracts/deployments/evidence/robinhood-custom-launch-v1.json",
    repository: "https://github.com/programmablehq/PROGRAMMABLE",
    sha256: `sha256:${"2".repeat(64)}`
  };
  const transactionProvenance = descriptor.chain.deploymentEvidence.roots.poolManager.provenance;
  for (const binding of Object.values(anchor.roots)) {
    if (binding.provenance === null) binding.provenance = structuredClone(transactionProvenance);
    if (binding.startBlock === null) binding.startBlock = "1";
  }
  return anchor;
}

function changedPromotionLeaf(pathSegments, value) {
  const label = pathSegments.join(".");
  if (value === null) {
    if (label === "chainDeploymentDescriptorDigest") return `sha256:${"1".repeat(64)}`;
    if (label === "finalizedBlock") return "50000000";
    if (label === "finalizedEvidenceRef") {
      return {
        commit: "a".repeat(40),
        path: "contracts/deployments/evidence/robinhood-custom-launch-v1.json",
        repository: "https://github.com/programmablehq/PROGRAMMABLE",
        sha256: `sha256:${"2".repeat(64)}`
      };
    }
    if (label.endsWith(".provenance")) {
      return structuredClone(descriptor.chain.deploymentEvidence.roots.permit2.provenance);
    }
    if (label.endsWith(".startBlock")) return "1";
    throw new Error(`Unsupported null promotion leaf ${label}`);
  }
  if (typeof value === "number") return value + 1;
  if (value === "genesis-allocation") return "deployment-transaction";
  if (value === "deployment-transaction") return "genesis-allocation";
  if (value.startsWith("https://")) return `${value}#mutated`;
  if (value.startsWith("0x") || value.startsWith("sha256:")) return changedHex(value);
  if (/^[0-9]+$/u.test(value)) return (BigInt(value) + 1n).toString();
  return `${value}-mutated`;
}

function setPath(value, pathSegments, replacement) {
  let cursor = value;
  for (const segment of pathSegments.slice(0, -1)) cursor = cursor[segment];
  cursor[pathSegments.at(-1)] = replacement;
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
    collectNullPaths(descriptor.chain.deploymentEvidence, ["chain", "deploymentEvidence"]),
    [
      "chain.deploymentEvidence.chainDeploymentDescriptorDigest",
      "chain.deploymentEvidence.finalizedBlock",
      "chain.deploymentEvidence.finalizedEvidenceRef",
      "chain.deploymentEvidence.roots.graphFactory.provenance",
      "chain.deploymentEvidence.roots.graphFactory.startBlock",
      "chain.deploymentEvidence.roots.permitAuthoritySafe.provenance",
      "chain.deploymentEvidence.roots.permitAuthoritySafe.startBlock",
      "chain.deploymentEvidence.roots.programmableLaunchStampRouter.provenance",
      "chain.deploymentEvidence.roots.programmableLaunchStampRouter.startBlock"
    ]
  );
  assert.deepEqual(descriptor.chain.deploymentEvidence.roots.permit2.provenance, {
    allocatedCodeBytes: 9152,
    kind: "genesis-allocation",
    sourceSha256: "sha256:353e6f6441b47695b41cee0c3645cde8dd7492d2f7f574bfb6aa4371e41bb6ba",
    sourceUrl: "https://cdn.robinhood.com/assets/generated_assets/hoodchain_docsite/chain-node-configs/robinhood-genesis.json"
  });
  assert.equal(descriptor.chain.deploymentEvidence.roots.permit2.startBlock, "0");
  assert.deepEqual(
    Object.entries(descriptor.chain.deploymentEvidence.roots)
      .filter(([, binding]) => binding.provenance?.kind === "deployment-transaction")
      .map(([rootId]) => rootId),
    ["poolManager", "positionManager", "stateView", "universalRouter", "v4Quoter"]
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

test("V4 provenance schema couples genesis, transaction and unbroadcast roots to exact start-block classes", () => {
  const plannedRoots = structuredClone(descriptor.chain.deploymentEvidence.roots);
  assert.equal(validatePlannedPromotionRoots(plannedRoots), true, JSON.stringify(validatePlannedPromotionRoots.errors));
  assert.equal(validateCompletePromotionRoots(plannedRoots), false);

  assert.equal(validateGenesisDeploymentRoot(plannedRoots.permit2), true);
  for (const rootId of ["poolManager", "positionManager", "stateView", "universalRouter", "v4Quoter"]) {
    assert.equal(validateTransactionDeploymentRoot(plannedRoots[rootId]), true, rootId);
  }

  const transactionAtBlockZero = structuredClone(plannedRoots.poolManager);
  transactionAtBlockZero.startBlock = "0";
  assert.equal(validateTransactionDeploymentRoot(transactionAtBlockZero), false);

  const transactionClaimingGenesis = structuredClone(plannedRoots.poolManager);
  transactionClaimingGenesis.provenance = structuredClone(plannedRoots.permit2.provenance);
  transactionClaimingGenesis.startBlock = "0";
  assert.equal(validateTransactionDeploymentRoot(transactionClaimingGenesis), false);

  const genesisClaimingTransaction = structuredClone(plannedRoots.permit2);
  genesisClaimingTransaction.provenance = structuredClone(plannedRoots.poolManager.provenance);
  genesisClaimingTransaction.startBlock = "9070";
  assert.equal(validateGenesisDeploymentRoot(genesisClaimingTransaction), false);

  const genesisAtPositiveBlock = structuredClone(plannedRoots.permit2);
  genesisAtPositiveBlock.startBlock = "1";
  assert.equal(validateGenesisDeploymentRoot(genesisAtPositiveBlock), false);

  const transactionWithoutHash = structuredClone(plannedRoots.stateView);
  delete transactionWithoutHash.provenance.transactionHash;
  assert.equal(validateTransactionDeploymentRoot(transactionWithoutHash), false);

  const genesisWithTransactionHash = structuredClone(plannedRoots.permit2);
  genesisWithTransactionHash.provenance.transactionHash = `0x${"1".repeat(64)}`;
  assert.equal(validateGenesisDeploymentRoot(genesisWithTransactionHash), false);

  const splitUnbroadcastProvenance = structuredClone(plannedRoots);
  splitUnbroadcastProvenance.graphFactory.provenance = structuredClone(plannedRoots.poolManager.provenance);
  assert.equal(validatePlannedPromotionRoots(splitUnbroadcastProvenance), false);

  const splitUnbroadcastBlock = structuredClone(plannedRoots);
  splitUnbroadcastBlock.graphFactory.startBlock = "1";
  assert.equal(validatePlannedPromotionRoots(splitUnbroadcastBlock), false);

  const genericFilledRoots = genericTransactionFilledAnchor().roots;
  assert.equal(validateCompletePromotionRoots(genericFilledRoots), false);
  for (const rootId of ["graphFactory", "permitAuthoritySafe", "programmableLaunchStampRouter"]) {
    const candidate = structuredClone(genericFilledRoots);
    candidate[rootId] = structuredClone(plannedRoots.poolManager);
    assert.equal(validateCompletePromotionRoots(candidate), false, `${rootId} cannot use generic Uniswap provenance`);
  }
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

  const genericFilledButUnreviewed = structuredClone(descriptor);
  genericFilledButUnreviewed.chain.promotionStatus = "canary";
  genericFilledButUnreviewed.chain.deploymentEvidence = genericTransactionFilledAnchor();
  assert.equal(validateCompletePromotionAnchor(genericFilledButUnreviewed.chain.deploymentEvidence), false);
  assertRejectedDescriptor(genericFilledButUnreviewed);
});

test("V4 rejects every promotion-anchor identity, provenance, hash, transaction and start-block leaf mutation", () => {
  const mutations = collectLeaves(descriptor.chain.deploymentEvidence);
  assert.equal(mutations.length, 60);
  for (const [pathSegments, observed] of mutations) {
    const candidate = structuredClone(descriptor);
    setPath(
      candidate.chain.deploymentEvidence,
      pathSegments,
      changedPromotionLeaf(pathSegments, observed)
    );
    assertRejectedDescriptor(candidate, pathSegments.join("."));
  }
});
