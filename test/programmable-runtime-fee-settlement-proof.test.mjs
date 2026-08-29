import assert from "node:assert/strict";
import childProcess from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import Ajv2020 from "../scripts/test/schema-validator/node_modules/ajv/dist/2020.js";

import {
  canonicalJson,
  evaluateLaunchPolicyRules,
  readTrustedLaunchPolicyFromGit
} from "../scripts/launch-policy-core.mjs";
import {
  canonicalProgrammableRuntimeFeeSettlementProofJsonV1,
  parseProgrammableRuntimeFeeSettlementProofBytesV1,
  projectProgrammableRuntimeFeeSettlementPendingPolicyEvidenceV1,
  readProtectedProgrammableRuntimeFeeSettlementObservationFromGitV1,
  validateProgrammableRuntimeFeeSettlementProofV1
} from "../scripts/programmable-runtime-fee-settlement-proof-core.mjs";
import { createFeeConformanceFixtureV1 } from "../scripts/test/fixtures/fee-conformance-v1-fixture.mjs";
import {
  canonicalFeeConformanceReceiptBytesV1,
  feeConformanceReceiptSha256V1
} from "../vendor/programmable-v4-hook-builder/scripts/fee-conformance-receipt-v1-core.mjs";

const root = path.resolve(import.meta.dirname, "..");
const treasury = "0x4957f49620AFf3Adbbe8195a4f633E49cc93376c";
const applicationId = "runtime-fee-proof-project";
const applicationRevision = 1;
const applicationSha256 = "sha256:" + "a".repeat(64);
const packageSha256 = "sha256:" + "b".repeat(64);
const configurationHash = "sha256:" + "c".repeat(64);
const sourceCommit = "33".repeat(20);
const sourceTree = "44".repeat(20);
const poolId = "0x" + "11".repeat(32);
const poolManager = "0x" + "12".repeat(20);
const routerAddress = "0x" + "13".repeat(20);
const routerRuntimeCodeHash = "0x" + "14".repeat(32);
const feeRuntimeAddress = "0x" + "15".repeat(20);
const feeRuntimeCodeHash = "0x" + "16".repeat(32);
const launchId = "0x" + "17".repeat(32);
const launchTransactionHash = "0x" + "18".repeat(32);
const activationBlockHash = "0x" + "19".repeat(32);
const observationEndBlockHash = "0x" + "1a".repeat(32);
const finalizedBlockHash = "0x" + "1b".repeat(32);
const zeroAddress = "0x" + "0".repeat(40);

function sha256(bytes) {
  return "sha256:" + crypto.createHash("sha256").update(bytes).digest("hex");
}

function gitBlobOid(bytes) {
  const value = Buffer.from(bytes);
  return crypto.createHash("sha1")
    .update(Buffer.from("blob " + value.length + "\0", "utf8"))
    .update(value)
    .digest("hex");
}

function canonicalBytes(value) {
  return Buffer.from(canonicalJson(value) + "\n", "utf8");
}

function runGit(repositoryRoot, args) {
  return childProcess.execFileSync("git", args, {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      GIT_AUTHOR_EMAIL: "runtime-fee-proof-test@example.invalid",
      GIT_AUTHOR_NAME: "Runtime Fee Proof Test",
      GIT_COMMITTER_EMAIL: "runtime-fee-proof-test@example.invalid",
      GIT_COMMITTER_NAME: "Runtime Fee Proof Test"
    }
  }).trim();
}

function standardLimits() {
  return {
    applicantAssertionAccepted: false,
    auditClaim: false,
    continuousMonitoringClaim: false,
    coverage: "one-fee-scope-one-asset-one-inclusive-finalized-range",
    currentLiquidityClaim: false,
    currentTradabilityClaim: false,
    fundsAuthority: false,
    futureCollectionClaim: false,
    futureSettlementClaim: false,
    launchAuthority: false,
    providerAssertionAccepted: false,
    registryWriteAuthority: false,
    safetyClaim: false,
    sellabilityClaim: false,
    terminalSupportClaim: false
  };
}

function makePromotion() {
  return {
    acceptance: {},
    application: {
      applicationId,
      applicationRevision,
      applicationSha256,
      packageDigest: packageSha256
    },
    authority: {},
    componentProofs: [],
    economics: {
      basis: "gross-canonical-pool-volume",
      bps: 10,
      hundredthsOfBip: 1000,
      treasury
    },
    evidence: {
      promotionSha256: "sha256:" + "d".repeat(64)
    },
    launch: {
      launchId,
      launchKind: 1,
      poolId,
      poolManager
    },
    lookups: {},
    manifest: {
      routerAddress,
      runtimeCodeHash: routerRuntimeCodeHash
    },
    observation: {
      transactionHash: launchTransactionHash
    },
    policy: {
      launchReadinessDecisionSha256: "sha256:" + "e".repeat(64)
    },
    projectId: applicationId,
    routePlan: {},
    schemaVersion: "1.0.0",
    source: {
      commit: sourceCommit,
      configurationHash,
      numericRepositoryId: "9001",
      repository: "https://github.com/example/runtime-fee-proof-project",
      tree: sourceTree
    },
    verifiedAt: "2026-08-20T12:00:00Z"
  };
}

function makeProof({ bundleBytes, promotion, receipt, receiptBytes }) {
  const bundleSha256 = sha256(bundleBytes);
  return {
    $schema: "urn:programmable:runtime-fee-settlement-observation-assertion-v1:1.0.0",
    assurance: "protected-accounting-assertion-not-finality-or-settlement-proof",
    bindings: {
      application: {
        applicationId,
        applicationRevision,
        applicationSha256,
        packageSha256
      },
      feeConformance: {
        assurance: receipt.assurance,
        collectionProfile: receipt.scope.collectionProfile,
        contractId: receipt.contract.id,
        feeScopeId: receipt.scope.feeScopeId,
        implementation: structuredClone(receipt.implementation),
        marketRef: receipt.scope.marketRef,
        path: "evidence/fee-conformance-main-market.receipt.v1.json",
        poolId: receipt.scope.poolId,
        quoteCurrency: receipt.scope.quoteCurrency,
        receiptBytes: {
          base64: receiptBytes.toString("base64"),
          byteLength: receiptBytes.length
        },
        receiptSha256: feeConformanceReceiptSha256V1(receipt),
        vectorSetSha256: receipt.vectorSet.sha256
      },
      promotion: {
        launchReadinessDecisionSha256: promotion.policy.launchReadinessDecisionSha256,
        path: "registry/promotions/" + applicationId + "/" + launchId + ".json",
        routerPromotionEvidenceSha256: promotion.evidence.promotionSha256,
        sha256: sha256(canonicalBytes(promotion))
      },
      source: structuredClone(promotion.source)
    },
    evidence: {
      applicantControlled: false,
      bundle: {
        byteLength: bundleBytes.length,
        gitBlobOid: gitBlobOid(bundleBytes),
        mediaType: "application/json",
        path: "platform-evidence/runtime-fee-settlement/bundles/" + bundleSha256.slice("sha256:".length) + ".json",
        sha256: bundleSha256
      },
      claimedCompleteHeaderChain: true,
      claimedCompleteReceiptSet: true,
      claimedConsensusFinality: true,
      finalityCheckpointSha256: "sha256:" + "1".repeat(64),
      headerChainSha256: "sha256:" + "2".repeat(64),
      observerConfigurationSha256: "sha256:" + "3".repeat(64),
      observerId: "programmable-protected-runtime-fee-observer-v1",
      claimedReceiptRootsRecomputed: true,
      receiptSetSha256: "sha256:" + "4".repeat(64),
      claimedRuntimeClosureCheckedEveryFeeRelevantBlock: true,
      runtimeStateProofSha256: "sha256:" + "5".repeat(64),
      verificationProfile: "ethereum-finalized-fee-settlement-v1"
    },
    kind: "programmable-runtime-fee-settlement-observation-assertion",
    limits: standardLimits(),
    proofId: "initial-finalized-fee-settlement",
    range: {
      claimedCanonicalFinalized: true,
      finalityMode: "ethereum-consensus-finalized",
      finalizedAtBlock: "110",
      finalizedAtBlockHash: finalizedBlockHash,
      fromBlock: "100",
      fromBlockHash: activationBlockHash,
      fromDeployment: true,
      previousProofSha256: null,
      toBlock: "101",
      toBlockHash: observationEndBlockHash
    },
    reasonCode: "runtime-fee-verifier-trust-root-unavailable",
    runtime: {
      activationBlockHash,
      activationBlockNumber: "100",
      activationTransactionHash: "0x" + "6".repeat(64),
      activationTransactionIndex: "1",
      chainId: 1,
      feeDeploymentBindingSha256: "sha256:" + "6".repeat(64),
      feeRuntimeAddress,
      feeRuntimeCodeHash,
      genesisHash: "0x" + "7".repeat(64),
      launchId,
      launchKind: 1,
      launchTransactionHash,
      poolId,
      poolManager,
      reviewedImplementationArtifactSha256: receipt.implementation.artifactSha256,
      routerAddress,
      routerRuntimeCodeHash,
      runtimeClosureSha256: "sha256:" + "7".repeat(64),
      runtimeVerifierSha256: "sha256:" + "8".repeat(64),
      treasury
    },
    schemaVersion: "1.0.0",
    settlement: {
      asset: {
        address: zeroAddress,
        kind: "native"
      },
      basis: "gross-canonical-pool-volume",
      closingLiabilityAtomic: "0",
      closingRemainderNumerator: "567000",
      executionCount: "1",
      executions: [{
        blockHash: activationBlockHash,
        blockNumber: "100",
        evidenceSha256: "sha256:" + "9".repeat(64),
        expectedFeeAtomic: "1234",
        grossCanonicalVolumeAtomic: "1234567",
        logIndex: "2",
        poolId,
        remainderAfterNumerator: "567000",
        remainderBeforeNumerator: "0",
        runtimeAddress: feeRuntimeAddress,
        transactionHash: "0x" + "8".repeat(64),
        transactionIndex: "2"
      }],
      expectedFeeAtomic: "1234",
      feeScopeId: receipt.scope.feeScopeId,
      grossCanonicalVolumeAtomic: "1234567",
      hundredthsOfBip: 1000,
      openingLiabilityAtomic: "0",
      openingRemainderNumerator: "0",
      rateDenominator: 1000000,
      settledTreasuryAtomic: "1234",
      settlementCount: "1",
      settlements: [{
        amountAtomic: "1234",
        assetAddress: zeroAddress,
        balanceDeltaEvidenceSha256: "sha256:" + "a".repeat(64),
        blockHash: observationEndBlockHash,
        blockNumber: "101",
        evidenceSha256: "sha256:" + "b".repeat(64),
        logOrTraceIndex: "3",
        runtimeAddress: feeRuntimeAddress,
        transactionHash: "0x" + "9".repeat(64),
        transactionIndex: "3",
        treasury
      }]
    },
    status: "analysis-pending",
    subject: {
      applicationId,
      applicationRevision,
      projectId: applicationId
    }
  };
}

function makeFixtureValues() {
  const fee = createFeeConformanceFixtureV1({
    applicationId,
    poolId
  });
  const receipt = structuredClone(fee.receipt);
  const receiptBytes = canonicalFeeConformanceReceiptBytesV1(receipt);
  const promotion = makePromotion();
  const bundleBytes = canonicalBytes({
    contract: "ethereum-finalized-fee-settlement-evidence-bundle-v1",
    records: ["headers", "receipts", "runtime-state", "treasury-balance-deltas"],
    schemaVersion: "1.0.0"
  });
  const proof = makeProof({ bundleBytes, promotion, receipt, receiptBytes });
  return { bundleBytes, promotion, proof, receipt, receiptBytes };
}

function writeFixtureRepository(t, {
  mutateBundle,
  mutatePolicy,
  mutatePromotion,
  mutateProof
} = {}) {
  const repositoryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "runtime-fee-proof-git-"));
  t.after(() => fs.rmSync(repositoryRoot, { recursive: true, force: true }));
  const values = makeFixtureValues();
  if (mutatePromotion) mutatePromotion(values.promotion);
  if (mutateBundle) values.bundleBytes = mutateBundle(Buffer.from(values.bundleBytes)) ?? values.bundleBytes;
  values.proof = makeProof(values);
  if (mutateProof) mutateProof(values.proof);

  const policy = JSON.parse(fs.readFileSync(path.join(root, "policy/launch-policy.v1.json"), "utf8"));
  // Exercise the retired settlement handler against its last active policy
  // contract without reactivating it in the current v2.3 production profile.
  policy.policyVersion = "2.1.0";
  policy.effective.startsAt = "2026-08-20T00:00:00Z";
  policy.profiles = policy.profiles.filter(({ id }) => !id.startsWith("robinhood-"));
  policy.rules = policy.rules.filter(({ id }) => !id.startsWith("LAUNCH.ROBINHOOD_"));
  const productionProfile = policy.profiles.find(({ id }) => id === "production-launch");
  productionProfile.enabled = false;
  productionProfile.outcome = null;
  productionProfile.authority.checkerOnly = false;
  policy.rules = policy.rules.filter(({ id }) => !new Set([
    "LAUNCH.ETHEREUM_EXACT_FEE_TEMPLATE_BEFORE_AUTHORIZATION",
    "LAUNCH.ETHEREUM_VERIFIED_EXECUTED_PLATFORM_FEE_BEFORE_AUTHORIZATION"
  ]).has(id));
  const settlementRule = policy.rules.find(({ id }) => id === "LAUNCH.ETHEREUM_FINALIZED_RUNTIME_FEE_SETTLEMENT_BEFORE_PROMOTION");
  settlementRule.status = "active";
  settlementRule.retiredIn = null;
  settlementRule.profiles = [
    "launch-readiness",
    "production-launch"
  ];
  if (mutatePolicy) mutatePolicy(policy);

  const proofPath = "platform-evidence/runtime-fee-settlement/" + applicationId + "/" + values.proof.proofId + ".json";
  const files = new Map([
    ["policy/launch-policy.v1.json", Buffer.from(canonicalJson(policy) + "\n", "utf8")],
    [proofPath, Buffer.from(canonicalProgrammableRuntimeFeeSettlementProofJsonV1(values.proof) + "\n", "utf8")],
    [values.proof.evidence.bundle.path, values.bundleBytes],
    [values.proof.bindings.promotion.path, canonicalBytes(values.promotion)]
  ]);
  for (const [relativePath, bytes] of files) {
    const absolutePath = path.join(repositoryRoot, relativePath);
    fs.mkdirSync(path.dirname(absolutePath), { recursive: true });
    fs.writeFileSync(absolutePath, bytes);
  }
  runGit(repositoryRoot, ["init", "--initial-branch=main"]);
  runGit(repositoryRoot, ["remote", "add", "origin", "https://github.com/0xprogrammable/launch-policy.git"]);
  runGit(repositoryRoot, ["add", "."]);
  runGit(repositoryRoot, ["commit", "-m", "protected proof fixture"]);
  const expectedBaseCommit = runGit(repositoryRoot, ["rev-parse", "HEAD^{commit}"]);
  return {
    ...values,
    expectedBaseCommit,
    policy,
    proofPath,
    repositoryRoot
  };
}

function readTrusted(fixture) {
  return readProtectedProgrammableRuntimeFeeSettlementObservationFromGitV1({
    expectedBaseCommit: fixture.expectedBaseCommit,
    proofPath: fixture.proofPath,
    repositoryRoot: fixture.repositoryRoot
  });
}

function policySubject() {
  return {
    applicationId,
    applicationRevision,
    applicationSha256,
    commit: sourceCommit,
    configurationHash,
    numericRepositoryId: "9001",
    packageSha256,
    repository: "example/runtime-fee-proof-project",
    routerProvenanceRequired: true,
    tree: sourceTree,
    usesUniswapV4: true
  };
}

function prelaunchEvidence() {
  return {
    "programmable-launch-requirement": {
      basis: "gross-canonical-pool-volume",
      chainId: 1,
      hundredthsOfBip: 1000,
      network: "ethereum-mainnet",
      status: "passed",
      treasury
    },
    "programmable-router-readiness": {
      abiSha256: "sha256:" + "1".repeat(64),
      abiUrl: "https://developers.programmable.family/api/v2/launch-stamp-router-abi",
      chainId: 1,
      directFactoryCall: false,
      discoveryDocumentUrl: "https://developers.programmable.family/.well-known/programmable.json",
      launchEntryPoint: "launchAndStampV1",
      launchKind: 1,
      manifestSha256: "sha256:" + "2".repeat(64),
      manifestUrl: "https://developers.programmable.family/api/v2/manifest",
      routeEvidenceSha256: "sha256:" + "3".repeat(64),
      routerAddress,
      routerManifestPointer: "/launchStampRouter",
      routerRuntimeCodeHash,
      routerStatus: "live",
      sourceCommit,
      sourceConfigurationHash: configurationHash,
      sourceTree,
      status: "passed"
    }
  };
}

function hasCode(code) {
  return (error) => error?.code === code;
}

test("closed schema and semantic core accept only a structurally bound pending observation assertion", () => {
  const { proof } = makeFixtureValues();
  const schema = JSON.parse(fs.readFileSync(
    path.join(root, "policy/schemas/programmable-runtime-fee-settlement-proof-v1.schema.json"),
    "utf8"
  ));
  const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
  assert.equal(validate(proof), true, JSON.stringify(validate.errors));
  assert.equal(validateProgrammableRuntimeFeeSettlementProofV1(proof), true);

  const bytes = Buffer.from(canonicalProgrammableRuntimeFeeSettlementProofJsonV1(proof) + "\n", "utf8");
  const parsed = parseProgrammableRuntimeFeeSettlementProofBytesV1(bytes);
  assert.equal(parsed.proof.status, "analysis-pending");
  assert.equal(parsed.proof.reasonCode, "runtime-fee-verifier-trust-root-unavailable");
  assert.equal(parsed.proof.limits.futureSettlementClaim, false);
  assert.equal(parsed.proof.limits.continuousMonitoringClaim, false);
  assert.equal(parsed.sha256, sha256(bytes));

  const extra = structuredClone(proof);
  extra.providerSaysPassed = true;
  assert.equal(validate(extra), false);
  assert.throws(
    () => parseProgrammableRuntimeFeeSettlementProofBytesV1(Buffer.from(canonicalJson(extra) + "\n")),
    hasCode("RUNTIME_FEE_PROOF_FIELDS_INVALID")
  );
  assert.throws(
    () => parseProgrammableRuntimeFeeSettlementProofBytesV1(Buffer.from(JSON.stringify(proof, null, 2) + "\n")),
    hasCode("RUNTIME_FEE_PROOF_JSON_NONCANONICAL")
  );
});

test("protected Git reader binds the pending assertion without minting settlement proof", (t) => {
  const fixture = writeFixtureRepository(t);
  const record = readTrusted(fixture);
  const evidence = projectProgrammableRuntimeFeeSettlementPendingPolicyEvidenceV1(record);
  assert.equal(evidence.status, "analysis-pending");
  assert.equal(evidence.reasonCode, "runtime-fee-verifier-trust-root-unavailable");
  assert.equal(evidence.protectedBaseCommit, fixture.expectedBaseCommit);
  assert.equal(evidence.observationPath, fixture.proofPath);
  assert.equal(evidence.observationSha256, record.sha256);
  assert.equal(Object.hasOwn(evidence, "passed"), false);

  record.bundleBytes[0] ^= 0xff;
  assert.throws(
    () => projectProgrammableRuntimeFeeSettlementPendingPolicyEvidenceV1(record),
    hasCode("RUNTIME_FEE_PROOF_TRUST_REQUIRED")
  );
});

test("protected Git reader accepts the organization-owned policy repository", (t) => {
  const fixture = writeFixtureRepository(t);
  runGit(fixture.repositoryRoot, [
    "remote",
    "set-url",
    "origin",
    "https://github.com/programmablehq/Launch-Policy.git"
  ]);

  const record = readTrusted(fixture);
  assert.equal(record.baseCommit, fixture.expectedBaseCommit);
  assert.equal(record.path, fixture.proofPath);
});

test("policy handler never passes repository-only accounting assertions and keeps missing evidence pending", (t) => {
  const fixture = writeFixtureRepository(t);
  const policyRecord = readTrustedLaunchPolicyFromGit({
    expectedBaseCommit: fixture.expectedBaseCommit,
    repositoryRoot: fixture.repositoryRoot
  });
  const trustedEvidence = projectProgrammableRuntimeFeeSettlementPendingPolicyEvidenceV1(readTrusted(fixture));
  const evidence = {
    ...prelaunchEvidence(),
    "programmable-runtime-fee-settlement": trustedEvidence
  };
  const structurallyBound = evaluateLaunchPolicyRules({
    evidence,
    policyRecord,
    profileId: "launch-readiness",
    subject: policySubject()
  });
  assert.equal(structurallyBound.passed, false);
  assert.equal(structurallyBound.outcome, null);
  assert.equal(structurallyBound.authority.launchAuthorized, false);
  assert.deepEqual(structurallyBound.findings, []);
  assert.deepEqual(structurallyBound.pendingRuleIds, [
    "LAUNCH.ETHEREUM_FINALIZED_RUNTIME_FEE_SETTLEMENT_BEFORE_PROMOTION"
  ]);
  assert.deepEqual(structurallyBound.results.map(({ status }) => status), [
    "passed",
    "analysis-pending",
    "passed"
  ]);

  const forged = {
    ...evidence,
    "programmable-runtime-fee-settlement": {
      ...structuredClone(trustedEvidence),
      reasonCode: "self-declared-provider-passed",
      status: "passed"
    }
  };
  const rejected = evaluateLaunchPolicyRules({
    evidence: forged,
    policyRecord,
    profileId: "launch-readiness",
    subject: policySubject()
  });
  assert.deepEqual(
    rejected.findings.map(({ ruleId }) => ruleId),
    ["LAUNCH.ETHEREUM_FINALIZED_RUNTIME_FEE_SETTLEMENT_BEFORE_PROMOTION"]
  );

  const pendingEvidence = prelaunchEvidence();
  const pending = evaluateLaunchPolicyRules({
    evidence: pendingEvidence,
    policyRecord,
    profileId: "launch-readiness",
    subject: policySubject()
  });
  assert.deepEqual(pending.findings, []);
  assert.deepEqual(
    pending.pendingRuleIds,
    ["LAUNCH.ETHEREUM_FINALIZED_RUNTIME_FEE_SETTLEMENT_BEFORE_PROMOTION"]
  );

  const noMarket = evaluateLaunchPolicyRules({
    evidence: {},
    policyRecord,
    profileId: "launch-readiness",
    subject: { ...policySubject(), routerProvenanceRequired: false }
  });
  assert.equal(noMarket.passed, true);
  assert.deepEqual(noMarket.results.map(({ status }) => status), [
    "not-applicable",
    "not-applicable",
    "not-applicable"
  ]);
});

test("applicant-declared or self-described provider objects cannot mint policy evidence", () => {
  const { proof } = makeFixtureValues();
  const parsed = parseProgrammableRuntimeFeeSettlementProofBytesV1(
    Buffer.from(canonicalProgrammableRuntimeFeeSettlementProofJsonV1(proof) + "\n")
  );
  assert.equal(parsed.proof.evidence.observerId, "programmable-protected-runtime-fee-observer-v1");
  assert.throws(
    () => projectProgrammableRuntimeFeeSettlementPendingPolicyEvidenceV1(parsed),
    hasCode("RUNTIME_FEE_PROOF_TRUST_REQUIRED")
  );

  const claimedProvider = structuredClone(proof);
  claimedProvider.evidence.applicantControlled = true;
  assert.throws(
    () => validateProgrammableRuntimeFeeSettlementProofV1(claimedProvider),
    hasCode("RUNTIME_FEE_PROOF_PROVENANCE_INVALID")
  );
});

test("integer carry, asset identity, and claimed treasury settlement stay structurally fail closed", () => {
  const cases = [
    ["rounding reset", (proof) => { proof.settlement.executions[0].remainderBeforeNumerator = "1"; }, "RUNTIME_FEE_PROOF_ROUNDING_INVALID"],
    ["rounded summary", (proof) => { proof.settlement.expectedFeeAtomic = "1235"; }, "RUNTIME_FEE_PROOF_ACCOUNTING_INVALID"],
    ["partial settlement", (proof) => { proof.settlement.settledTreasuryAtomic = "1233"; }, "RUNTIME_FEE_PROOF_ACCOUNTING_INVALID"],
    ["settlement event shortfall", (proof) => { proof.settlement.settlements[0].amountAtomic = "1233"; }, "RUNTIME_FEE_PROOF_ACCOUNTING_INVALID"],
    ["wrong asset", (proof) => {
      const weth = "0x" + "99".repeat(20);
      proof.settlement.asset = { address: weth, kind: "erc20" };
      proof.settlement.settlements[0].assetAddress = weth;
    }, "RUNTIME_FEE_PROOF_ASSET_MISMATCH"],
    ["native WETH alias", (proof) => {
      proof.settlement.asset = { address: "0x" + "99".repeat(20), kind: "native" };
    }, "RUNTIME_FEE_PROOF_ASSET_MISMATCH"],
    ["ERC-20 zero-address alias", (proof) => {
      proof.settlement.asset = { address: zeroAddress, kind: "erc20" };
    }, "RUNTIME_FEE_PROOF_ASSET_MISMATCH"],
    ["unrelated treasury donation", (proof) => {
      proof.settlement.settlements[0].runtimeAddress = "0x" + "98".repeat(20);
    }, "RUNTIME_FEE_PROOF_SETTLEMENT_INVALID"]
  ];
  for (const [label, mutate, code] of cases) {
    const { proof } = makeFixtureValues();
    mutate(proof);
    assert.throws(
      () => validateProgrammableRuntimeFeeSettlementProofV1(proof),
      hasCode(code),
      label
    );
  }
});

test("nonfinal, incomplete, and missing claimed ranges never become valid pending assertions", () => {
  const cases = [
    ["nonfinal range", (proof) => { proof.range.claimedCanonicalFinalized = false; }, "RUNTIME_FEE_PROOF_RANGE_INVALID"],
    ["provider finality only", (proof) => { proof.evidence.claimedConsensusFinality = false; }, "RUNTIME_FEE_PROOF_PROVENANCE_INVALID"],
    ["missing receipts", (proof) => { proof.evidence.claimedCompleteReceiptSet = false; }, "RUNTIME_FEE_PROOF_PROVENANCE_INVALID"],
    ["missing header chain", (proof) => { proof.evidence.claimedCompleteHeaderChain = false; }, "RUNTIME_FEE_PROOF_PROVENANCE_INVALID"],
    ["upgrade-and-rollback unchecked", (proof) => { proof.evidence.claimedRuntimeClosureCheckedEveryFeeRelevantBlock = false; }, "RUNTIME_FEE_PROOF_PROVENANCE_INVALID"],
    ["missing range", (proof) => { delete proof.range; }, "RUNTIME_FEE_PROOF_FIELDS_INVALID"]
  ];
  for (const [label, mutate, code] of cases) {
    const { proof } = makeFixtureValues();
    mutate(proof);
    assert.throws(
      () => validateProgrammableRuntimeFeeSettlementProofV1(proof),
      hasCode(code),
      label
    );
  }
});

test("rehashed tuple and runtime substitutions cannot escape promotion binding or invent a pass", (t) => {
  const tupleSubstitution = writeFixtureRepository(t, {
    mutateProof(proof) {
      const otherPool = "0x" + "aa".repeat(32);
      proof.runtime.poolId = otherPool;
      proof.bindings.feeConformance.poolId = otherPool;
      proof.settlement.executions[0].poolId = otherPool;
    }
  });
  assert.throws(
    () => readTrusted(tupleSubstitution),
    (error) => new Set([
      "RUNTIME_FEE_PROOF_CONFORMANCE_BINDING_INVALID",
      "RUNTIME_FEE_PROOF_PROMOTION_MISMATCH"
    ]).has(error?.code)
  );

  const fixture = writeFixtureRepository(t);
  const trusted = projectProgrammableRuntimeFeeSettlementPendingPolicyEvidenceV1(readTrusted(fixture));
  const rehashedRuntimeClone = {
    ...structuredClone(trusted),
    observationSha256: "sha256:" + "ad".repeat(32),
    reasonCode: "self-declared-finalized",
    status: "passed"
  };
  const policyRecord = readTrustedLaunchPolicyFromGit({
    expectedBaseCommit: fixture.expectedBaseCommit,
    repositoryRoot: fixture.repositoryRoot
  });
  const decision = evaluateLaunchPolicyRules({
    evidence: {
      ...prelaunchEvidence(),
      "programmable-runtime-fee-settlement": rehashedRuntimeClone
    },
    policyRecord,
    profileId: "launch-readiness",
    subject: policySubject()
  });
  assert.deepEqual(
    decision.findings.map(({ ruleId }) => ruleId),
    ["LAUNCH.ETHEREUM_FINALIZED_RUNTIME_FEE_SETTLEMENT_BEFORE_PROMOTION"]
  );
});

test("protected reader rejects path, promotion, and bundle substitutions", (t) => {
  const promotionMismatch = writeFixtureRepository(t, {
    mutatePromotion(promotion) {
      promotion.launch.poolId = "0x" + "ee".repeat(32);
    }
  });
  assert.throws(
    () => readTrusted(promotionMismatch),
    hasCode("RUNTIME_FEE_PROOF_PROMOTION_MISMATCH")
  );

  const fixture = writeFixtureRepository(t);
  assert.throws(
    () => readProtectedProgrammableRuntimeFeeSettlementObservationFromGitV1({
      expectedBaseCommit: fixture.expectedBaseCommit,
      proofPath: "platform-evidence/runtime-fee-settlement/attacker/" + fixture.proof.proofId + ".json",
      repositoryRoot: fixture.repositoryRoot
    }),
    hasCode("RUNTIME_FEE_PROOF_GIT_OBJECT_INVALID")
  );

  const bundleMismatch = writeFixtureRepository(t);
  const bundlePath = path.join(bundleMismatch.repositoryRoot, bundleMismatch.proof.evidence.bundle.path);
  fs.writeFileSync(bundlePath, Buffer.from("{\"tampered\":true}\n"));
  runGit(bundleMismatch.repositoryRoot, ["add", "."]);
  runGit(bundleMismatch.repositoryRoot, ["commit", "-m", "tamper bundle only"]);
  const tamperedCommit = runGit(bundleMismatch.repositoryRoot, ["rev-parse", "HEAD^{commit}"]);
  assert.throws(
    () => readProtectedProgrammableRuntimeFeeSettlementObservationFromGitV1({
      expectedBaseCommit: tamperedCommit,
      proofPath: bundleMismatch.proofPath,
      repositoryRoot: bundleMismatch.repositoryRoot
    }),
    hasCode("RUNTIME_FEE_PROOF_BUNDLE_MISMATCH")
  );
});
