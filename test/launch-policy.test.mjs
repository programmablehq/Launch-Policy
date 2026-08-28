import assert from "node:assert/strict";
import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import Ajv2020 from "../scripts/test/schema-validator/node_modules/ajv/dist/2020.js";

import {
  buildLaunchPolicyBinding,
  canonicalJson,
  compareLaunchPolicyBindings,
  digestLaunchPolicyBytes,
  evaluateLaunchPolicyRules,
  parseLaunchPolicyBytes,
  readTrustedLaunchPolicyFromGit,
  renderLaunchPolicyMarkdown,
  rulesForProfile,
  selectLaunchPolicyProfile,
  validateLaunchPolicy
} from "../scripts/launch-policy-core.mjs";

const root = path.resolve(import.meta.dirname, "..");
const policyPath = path.join(root, "policy/launch-policy.v1.json");

function hasCode(code) {
  return (error) => error?.code === code;
}

function canonicalPolicyRecord() {
  return parseLaunchPolicyBytes(fs.readFileSync(policyPath));
}

function launchReadinessSubject(routerProvenanceRequired = true) {
  return {
    commit: "a".repeat(40),
    configurationHash: `sha256:${"c".repeat(64)}`,
    routerProvenanceRequired,
    tree: "b".repeat(40)
  };
}

function launchReadinessEvidence() {
  return {
    "programmable-launch-requirement": {
      basis: "gross-canonical-pool-volume",
      chainId: 1,
      hundredthsOfBip: 1000,
      network: "ethereum-mainnet",
      status: "passed",
      treasury: "0x4957f49620AFf3Adbbe8195a4f633E49cc93376c"
    },
    "programmable-router-readiness": {
      abiSha256: `sha256:${"d".repeat(64)}`,
      abiUrl: "https://developers.programmable.family/api/v2/launch-stamp-router-abi",
      chainId: 1,
      directFactoryCall: false,
      discoveryDocumentUrl: "https://developers.programmable.family/.well-known/programmable.json",
      launchEntryPoint: "launchAndStampV1",
      launchKind: 1,
      manifestSha256: `sha256:${"e".repeat(64)}`,
      manifestUrl: "https://developers.programmable.family/api/v2/manifest",
      routeEvidenceSha256: `sha256:${"f".repeat(64)}`,
      routerAddress: `0x${"1".repeat(40)}`,
      routerManifestPointer: "/launchStampRouter",
      routerRuntimeCodeHash: `0x${"2".repeat(64)}`,
      routerStatus: "live",
      sourceCommit: "a".repeat(40),
      sourceConfigurationHash: `sha256:${"c".repeat(64)}`,
      sourceTree: "b".repeat(40),
      status: "passed"
    }
  };
}

function routerPromotionEvidence() {
  return {
    "programmable-router-promotion": {
      abiSha256: `sha256:${"1".repeat(64)}`,
      blockHash: `0x${"1".repeat(64)}`,
      blockNumber: 100,
      canonicalBlockFinalized: true,
      chainId: 1,
      componentSetHash: `0x${"2".repeat(64)}`,
      confirmations: 64,
      discoveryDocumentUrl: "https://developers.programmable.family/.well-known/programmable.json",
      expectedResultHash: `0x${"3".repeat(64)}`,
      finalityConfirmations: 64,
      hook: `0x${"1".repeat(40)}`,
      launchId: `0x${"4".repeat(64)}`,
      launchKind: 1,
      lookupMatched: true,
      manifestSha256: `sha256:${"2".repeat(64)}`,
      manifestUrl: "https://developers.programmable.family/api/v2/manifest",
      permitDigest: `0x${"5".repeat(64)}`,
      poolId: `0x${"6".repeat(64)}`,
      poolManager: `0x${"2".repeat(40)}`,
      promotionEvidenceSha256: `sha256:${"3".repeat(64)}`,
      promotionTargets: ["api-v2", "indexer", "public-discovery", "registry"],
      routeBindingMatched: true,
      routeLauncher: `0x${"3".repeat(40)}`,
      routeLauncherRuntimeCodeHash: `0x${"7".repeat(64)}`,
      routePayloadHash: `0x${"8".repeat(64)}`,
      routerAddress: `0x${"4".repeat(40)}`,
      routerManifestPointer: "/launchStampRouter",
      routerRuntimeCodeHash: `0x${"9".repeat(64)}`,
      sourceCommit: "a".repeat(40),
      sourceConfigurationHash: `sha256:${"c".repeat(64)}`,
      sourceDeploymentBindingSha256: `sha256:${"4".repeat(64)}`,
      sourceTree: "b".repeat(40),
      stampHash: `0x${"a".repeat(64)}`,
      stampProofMatched: true,
      status: "passed",
      token: `0x${"5".repeat(40)}`,
      transactionHash: `0x${"b".repeat(64)}`
    }
  };
}

function runGit(repositoryRoot, args) {
  return childProcess.execFileSync("git", args, {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      GIT_AUTHOR_EMAIL: "policy-test@example.invalid",
      GIT_AUTHOR_NAME: "Policy Test",
      GIT_COMMITTER_EMAIL: "policy-test@example.invalid",
      GIT_COMMITTER_NAME: "Policy Test"
    }
  }).trim();
}

function trustedPolicyFixture(t, policy = canonicalPolicyRecord().policy) {
  const repositoryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "launch-policy-git-"));
  t.after(() => fs.rmSync(repositoryRoot, { recursive: true, force: true }));
  fs.mkdirSync(path.join(repositoryRoot, "policy"), { recursive: true });
  fs.writeFileSync(
    path.join(repositoryRoot, "policy/launch-policy.v1.json"),
    `${canonicalJson(policy)}\n`,
    "utf8"
  );
  runGit(repositoryRoot, ["init", "--initial-branch=main"]);
  runGit(repositoryRoot, ["remote", "add", "origin", "https://github.com/0xprogrammable/launch-policy.git"]);
  runGit(repositoryRoot, ["add", "policy/launch-policy.v1.json"]);
  runGit(repositoryRoot, ["commit", "-m", "fixture policy"]);
  const baseCommit = runGit(repositoryRoot, ["rev-parse", "HEAD^{commit}"]);
  return {
    baseCommit,
    baseTree: runGit(repositoryRoot, ["rev-parse", "HEAD^{tree}"]),
    blob: runGit(repositoryRoot, ["rev-parse", "HEAD:policy/launch-policy.v1.json"]),
    record: readTrustedLaunchPolicyFromGit({ repositoryRoot, expectedBaseCommit: baseCommit }),
    repositoryRoot
  };
}

test("canonical policy exposes enabled production requirements without authority", () => {
  const record = canonicalPolicyRecord();
  assert.equal(record.policy.policyVersion, "2.3.0");
  assert.deepEqual(record.policy.profiles.map(({ id }) => id), ["build", "launch-readiness", "production-launch", "workflow-canary"]);
  assert.equal(selectLaunchPolicyProfile(record.policy, "build").enabled, true);
  assert.equal(selectLaunchPolicyProfile(record.policy, "launch-readiness").enabled, true);
  assert.equal(selectLaunchPolicyProfile(record.policy, "production-launch").enabled, true);
  assert.equal(selectLaunchPolicyProfile(record.policy, "workflow-canary").enabled, true);
  assert.equal(selectLaunchPolicyProfile(record.policy, "build").outcome, "BUILT_NOT_REVIEWED");
  assert.equal(selectLaunchPolicyProfile(record.policy, "launch-readiness").outcome, "LAUNCH_READINESS_CHECKED_NOT_AUTHORIZED");
  assert.equal(selectLaunchPolicyProfile(record.policy, "production-launch").outcome, "PRODUCTION_REQUIREMENTS_CHECKED_NOT_AUTHORIZED");
  assert.equal(selectLaunchPolicyProfile(record.policy, "workflow-canary").outcome, "CANARY_WORKFLOW_PASSED");
  for (const profile of record.policy.profiles) {
    assert.equal(profile.authority.launchAuthorized, false);
    assert.equal(profile.authority.productionDiscoveryAllowed, false);
    assert.equal(profile.authority.publicRoutingAllowed, false);
    assert.equal(profile.authority.realUserFundsAllowed, false);
  }
  assert.doesNotMatch(JSON.stringify(record.policy), /LAUNCH_APPROVED/u);
});

test("market-bearing readiness is closed while no-market stays admissible and unsupported integration stays pending", (t) => {
  const { policy } = canonicalPolicyRecord();
  assert.equal(policy.policyVersion, "2.3.0");
  assert.deepEqual(policy.rules.map(({ id }) => id), [
    "LAUNCH.ETHEREUM_AND_TREASURY_10_BPS",
    "LAUNCH.ETHEREUM_EXACT_FEE_TEMPLATE_BEFORE_AUTHORIZATION",
    "LAUNCH.ETHEREUM_FINALIZED_ROUTER_STAMP_BEFORE_PROMOTION",
    "LAUNCH.ETHEREUM_FINALIZED_RUNTIME_FEE_SETTLEMENT_BEFORE_PROMOTION",
    "LAUNCH.ETHEREUM_ROUTER_PROVENANCE_READINESS",
    "LAUNCH.ETHEREUM_VERIFIED_EXECUTED_PLATFORM_FEE_BEFORE_AUTHORIZATION"
  ]);
  assert.deepEqual(rulesForProfile(policy, "build"), []);
  assert.deepEqual(rulesForProfile(policy, "launch-readiness").map(({ id }) => id), [
    "LAUNCH.ETHEREUM_AND_TREASURY_10_BPS",
    "LAUNCH.ETHEREUM_ROUTER_PROVENANCE_READINESS"
  ]);
  assert.deepEqual(rulesForProfile(policy, "production-launch").map(({ id }) => id), [
    "LAUNCH.ETHEREUM_AND_TREASURY_10_BPS",
    "LAUNCH.ETHEREUM_EXACT_FEE_TEMPLATE_BEFORE_AUTHORIZATION",
    "LAUNCH.ETHEREUM_FINALIZED_ROUTER_STAMP_BEFORE_PROMOTION",
    "LAUNCH.ETHEREUM_ROUTER_PROVENANCE_READINESS"
  ]);
  assert.deepEqual(rulesForProfile(policy, "workflow-canary"), []);
  assert.deepEqual(
    policy.rules.filter(({ status }) => status !== "active").map(({ id }) => id),
    [
      "LAUNCH.ETHEREUM_FINALIZED_RUNTIME_FEE_SETTLEMENT_BEFORE_PROMOTION",
      "LAUNCH.ETHEREUM_VERIFIED_EXECUTED_PLATFORM_FEE_BEFORE_AUTHORIZATION"
    ],
  );

  const { record } = trustedPolicyFixture(t);
  const validEvidence = launchReadinessEvidence();
  const subject = launchReadinessSubject();
  const passed = evaluateLaunchPolicyRules({ policyRecord: record, profileId: "launch-readiness", subject, evidence: validEvidence });
  assert.equal(passed.passed, true);
  assert.equal(passed.outcome, "LAUNCH_READINESS_CHECKED_NOT_AUTHORIZED");
  assert.deepEqual(passed.pendingRuleIds, []);
  assert.equal(passed.authority.launchAuthorized, false);

  for (const [label, mutate] of [
    ["wrong chain", (evidence) => { evidence["programmable-launch-requirement"].chainId = 8453; }],
    ["wrong treasury", (evidence) => { evidence["programmable-launch-requirement"].treasury = `0x${"0".repeat(40)}`; }],
    ["wrong rate", (evidence) => { evidence["programmable-launch-requirement"].hundredthsOfBip = 999; }]
  ]) {
    const evidence = structuredClone(validEvidence);
    mutate(evidence);
    const failed = evaluateLaunchPolicyRules({ policyRecord: record, profileId: "launch-readiness", subject, evidence });
    assert.equal(failed.passed, false, label);
    assert.deepEqual(failed.findings.map(({ ruleId }) => ruleId), ["LAUNCH.ETHEREUM_AND_TREASURY_10_BPS"], label);
  }

  const directFactory = structuredClone(validEvidence);
  directFactory["programmable-router-readiness"].directFactoryCall = true;
  const directFactoryDecision = evaluateLaunchPolicyRules({ policyRecord: record, profileId: "launch-readiness", subject, evidence: directFactory });
  assert.deepEqual(directFactoryDecision.findings.map(({ ruleId }) => ruleId), ["LAUNCH.ETHEREUM_ROUTER_PROVENANCE_READINESS"]);

  const unsupported = structuredClone(validEvidence);
  delete unsupported["programmable-router-readiness"];
  const unsupportedDecision = evaluateLaunchPolicyRules({ policyRecord: record, profileId: "launch-readiness", subject, evidence: unsupported });
  assert.equal(unsupportedDecision.passed, false);
  assert.deepEqual(unsupportedDecision.findings, []);
  assert.deepEqual(unsupportedDecision.pendingRuleIds, ["LAUNCH.ETHEREUM_ROUTER_PROVENANCE_READINESS"]);

  const noMarketDecision = evaluateLaunchPolicyRules({
    policyRecord: record,
    profileId: "launch-readiness",
    subject: launchReadinessSubject(false),
    evidence: {}
  });
  assert.equal(noMarketDecision.passed, true);
  assert.equal(noMarketDecision.outcome, "LAUNCH_READINESS_CHECKED_NOT_AUTHORIZED");
  assert.deepEqual(noMarketDecision.results.map(({ status }) => status), ["not-applicable", "not-applicable"]);

  assert.throws(
    () => evaluateLaunchPolicyRules({ policyRecord: record, profileId: "launch-readiness", subject: {}, evidence: {} }),
    hasCode("LAUNCH_POLICY_EVALUATION_INPUT_INVALID")
  );
});

test("V3.4 exact executed fee gate is a frozen inactive candidate, never a caller-evaluable current rule", () => {
  const { policy } = canonicalPolicyRecord();
  const candidate = policy.rules.find(({ id }) => id === "LAUNCH.ETHEREUM_VERIFIED_EXECUTED_PLATFORM_FEE_BEFORE_AUTHORIZATION");
  assert.equal(candidate.status, "inactive");
  assert.equal(candidate.retiredIn, "2.3.0");
  assert.equal(candidate.parameters.activationState, "pending-runtime-readback");
  assert.equal(candidate.parameters.freshWritesEnabled, false);
  assert.equal(candidate.parameters.callerAssertionsAccepted, false);
  assert.equal(candidate.parameters.callerVerdictsAccepted, false);
  assert.equal(candidate.parameters.configurationIsExecutionEvidence, false);
  assert.equal(candidate.parameters.scenarioInputsAreExecutionEvidence, false);
  assert.equal(candidate.parameters.activationPrerequisites.includes("exact-settlement-dataflow-closure"), true);
  assert.equal(candidate.parameters.requiredSettlementDataflowReadback, "configured-autonomous-approval-exact-route-closure-receipt");
  assert.deepEqual(candidate.parameters.settlementDataflowClosure, {
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
  assert.equal(candidate.parameters.platformFeeConformanceStatus, "verified");
  assert.equal(candidate.parameters.otherBehaviorAxesDisposition, "unclaimed-unless-separately-executed");
  assert.equal(candidate.parameters.feeVaultReleaseBindingSha256, "sha256:39ccdfdf8cd61620bf5c62bf07fb8428adbd66d2608b1cf3ad583343116d7ed9");
  assert.equal(candidate.parameters.feeVaultRuntimeCodeKeccak256, "0x92620fe3f83839334c9a264bea5bfcc819868ca5607cbd2260e5a9664dbd7554");
  assert.deepEqual(candidate.parameters.requiredFeeVectorIds, [
    "fee.programmable-ten-bps",
    "fee.no-bypass",
    "fee.no-overcharge",
    "fee.claim-isolation"
  ]);
  assert.equal(rulesForProfile(policy, "production-launch").some(({ id }) => id === candidate.id), false);
});

test("finalized Router promotion handler validates the full closed projection instead of a status claim", (t) => {
  const policy = structuredClone(canonicalPolicyRecord().policy);
  policy.rules.find(({ id }) => id === "LAUNCH.ETHEREUM_FINALIZED_ROUTER_STAMP_BEFORE_PROMOTION").profiles = [
    "launch-readiness",
    "production-launch"
  ];
  const { record } = trustedPolicyFixture(t, policy);
  const subject = launchReadinessSubject();
  const evidence = { ...launchReadinessEvidence(), ...routerPromotionEvidence() };
  const passed = evaluateLaunchPolicyRules({ policyRecord: record, profileId: "launch-readiness", subject, evidence });
  assert.equal(passed.passed, true);
  assert.deepEqual(passed.results.map(({ status }) => status), ["passed", "passed", "passed"]);

  for (const [label, mutate] of [
    ["not finalized", (value) => { value.canonicalBlockFinalized = false; }],
    ["wrong manifest source", (value) => { value.manifestUrl = "https://example.invalid/manifest"; }],
    ["zero Router", (value) => { value.routerAddress = `0x${"0".repeat(40)}`; }],
    ["open payload", (value) => { value.untrusted = true; }]
  ]) {
    const invalid = structuredClone(evidence);
    mutate(invalid["programmable-router-promotion"]);
    const decision = evaluateLaunchPolicyRules({ policyRecord: record, profileId: "launch-readiness", subject, evidence: invalid });
    assert.equal(decision.passed, false, label);
    assert.deepEqual(
      decision.findings.map(({ ruleId }) => ruleId),
      ["LAUNCH.ETHEREUM_FINALIZED_ROUTER_STAMP_BEFORE_PROMOTION"],
      label
    );
  }

  const pendingEvidence = structuredClone(evidence);
  delete pendingEvidence["programmable-router-promotion"];
  const pending = evaluateLaunchPolicyRules({ policyRecord: record, profileId: "launch-readiness", subject, evidence: pendingEvidence });
  assert.deepEqual(pending.findings, []);
  assert.deepEqual(pending.pendingRuleIds, ["LAUNCH.ETHEREUM_FINALIZED_ROUTER_STAMP_BEFORE_PROMOTION"]);
});

test("policy rejects duplicate keys noncanonical bytes duplicate rule ids and unbound handlers", () => {
  assert.throws(
    () => parseLaunchPolicyBytes(Buffer.from('{"policyId":"a","policyId":"b"}\n')),
    hasCode("LAUNCH_POLICY_JSON_INVALID")
  );
  assert.throws(
    () => parseLaunchPolicyBytes(Buffer.from(`${JSON.stringify(canonicalPolicyRecord().policy, null, 2)}\n`)),
    hasCode("LAUNCH_POLICY_JSON_NONCANONICAL")
  );
  assert.throws(
    () => parseLaunchPolicyBytes(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), fs.readFileSync(policyPath)])),
    hasCode("LAUNCH_POLICY_JSON_NONCANONICAL")
  );
  assert.throws(
    () => parseLaunchPolicyBytes(Buffer.from([0xff, 0x0a])),
    hasCode("LAUNCH_POLICY_JSON_INVALID")
  );
  assert.throws(
    () => parseLaunchPolicyBytes(Buffer.alloc((512 * 1024) + 1, 0x20)),
    hasCode("LAUNCH_POLICY_SIZE_INVALID")
  );

  const duplicateRule = structuredClone(canonicalPolicyRecord().policy);
  duplicateRule.rules.push(structuredClone(duplicateRule.rules[0]));
  assert.throws(() => validateLaunchPolicy(duplicateRule), hasCode("LAUNCH_POLICY_RULE_ID_INVALID"));

  const unboundHandler = structuredClone(canonicalPolicyRecord().policy);
  unboundHandler.rules[0].enforcement.handlerId = "undeclared-handler-v1";
  assert.throws(() => validateLaunchPolicy(unboundHandler), hasCode("LAUNCH_POLICY_HANDLER_COVERAGE_INVALID"));

  const orphanedHandler = structuredClone(canonicalPolicyRecord().policy);
  orphanedHandler.rules = [];
  assert.throws(() => validateLaunchPolicy(orphanedHandler), hasCode("LAUNCH_POLICY_RULE_INVALID"));
});

test("policy semantic validation rejects field and UTF-8 ordering drift", () => {
  const extraField = structuredClone(canonicalPolicyRecord().policy);
  extraField.hiddenAuthority = true;
  assert.throws(() => validateLaunchPolicy(extraField), hasCode("LAUNCH_POLICY_FIELDS_INVALID"));

  const profileOrder = structuredClone(canonicalPolicyRecord().policy);
  profileOrder.profiles.reverse();
  assert.throws(() => validateLaunchPolicy(profileOrder), hasCode("LAUNCH_POLICY_ORDER_INVALID"));

  const evidenceOrder = structuredClone(canonicalPolicyRecord().policy);
  evidenceOrder.rules[0].evidence = ["z-evidence", "a-evidence"];
  assert.throws(() => validateLaunchPolicy(evidenceOrder), hasCode("LAUNCH_POLICY_ORDER_INVALID"));
});

test("active rules cannot become non-enforcing historical records", () => {
  const policy = structuredClone(canonicalPolicyRecord().policy);
  for (const rule of policy.rules.filter(({ status }) => status === "active")) {
    rule.applicability = { mode: "historical" };
  }
  assert.throws(() => validateLaunchPolicy(policy), hasCode("LAUNCH_POLICY_RULE_INVALID"));
});

test("checker-only profiles cannot carry routing discovery or real-user funds", () => {
  for (const profileId of ["build", "launch-readiness", "production-launch", "workflow-canary"]) {
    for (const [field, invalidValue] of [
      ["checkerOnly", false],
      ["independentAudit", true],
      ["launchAuthorized", true],
      ["productionDiscoveryAllowed", true],
      ["publicRoutingAllowed", true],
      ["realUserFundsAllowed", true]
    ]) {
      const policy = structuredClone(canonicalPolicyRecord().policy);
      policy.profiles.find(({ id }) => id === profileId).authority[field] = invalidValue;
      assert.throws(
        () => validateLaunchPolicy(policy),
        hasCode("LAUNCH_POLICY_AUTHORITY_INVALID"),
        `${profileId}.${field}`
      );
    }
  }
});

test("workflow canary carries no admission requirement while production remains non-authorizing", (t) => {
  const { record } = trustedPolicyFixture(t);
  const passed = evaluateLaunchPolicyRules({
    policyRecord: record,
    profileId: "workflow-canary",
    subject: {},
    evidence: {}
  });
  assert.equal(passed.passed, true);
  assert.equal(passed.outcome, "CANARY_WORKFLOW_PASSED");
  assert.equal(passed.authority.launchAuthorized, false);
  assert.equal(passed.authority.publicRoutingAllowed, false);
  assert.equal(passed.authority.realUserFundsAllowed, false);

  const production = evaluateLaunchPolicyRules({
    policyRecord: record,
    profileId: "production-launch",
    subject: { routerProvenanceRequired: true },
    evidence: {},
  });
  assert.equal(production.passed, false);
  assert.equal(production.authority.launchAuthorized, false);
  assert.equal(production.authority.realUserFundsAllowed, false);
});

test("fabricated records cannot mint bindings or evaluate policy", () => {
  const parsed = canonicalPolicyRecord();
  const fabricated = {
    ...parsed,
    repository: "0xprogrammable/launch-policy",
    numericRepositoryId: "1320171831",
    baseCommit: "0".repeat(40),
    baseTree: "0".repeat(40),
    path: "policy/launch-policy.v1.json",
    gitBlobOid: "0".repeat(40),
    sha256: `sha256:${"0".repeat(64)}`
  };
  assert.throws(
    () => buildLaunchPolicyBinding(fabricated, "workflow-canary"),
    hasCode("LAUNCH_POLICY_TRUST_INVALID")
  );
  assert.throws(
    () => evaluateLaunchPolicyRules({ policyRecord: fabricated, profileId: "workflow-canary", subject: {}, evidence: {} }),
    hasCode("LAUNCH_POLICY_TRUST_INVALID")
  );
});

test("trusted record bytes are revalidated and redigested at every authority boundary", (t) => {
  const { record } = trustedPolicyFixture(t);
  record.bytes[0] ^= 0xff;
  assert.throws(
    () => buildLaunchPolicyBinding(record, "workflow-canary"),
    hasCode("LAUNCH_POLICY_TRUST_INVALID")
  );
  assert.throws(
    () => evaluateLaunchPolicyRules({ policyRecord: record, profileId: "workflow-canary", subject: {}, evidence: {} }),
    hasCode("LAUNCH_POLICY_TRUST_INVALID")
  );
});

test("trusted Git reader binds fixed protected-base identity and rejects substitutions", (t) => {
  const { baseCommit, baseTree, blob, record, repositoryRoot } = trustedPolicyFixture(t);
  assert.equal(record.baseCommit, baseCommit);
  assert.equal(record.baseTree, baseTree);
  assert.equal(record.gitBlobOid, blob);
  assert.equal(record.path, "policy/launch-policy.v1.json");
  assert.equal(record.repository, "0xprogrammable/launch-policy");
  assert.equal(record.numericRepositoryId, "1320171831");

  const binding = buildLaunchPolicyBinding(record, "workflow-canary");
  assert.deepEqual(Object.keys(binding), [
    "schemaVersion",
    "repository",
    "numericRepositoryId",
    "baseCommit",
    "baseTree",
    "path",
    "gitBlobOid",
    "policyId",
    "policyVersion",
    "profileId",
    "sha256"
  ]);
  assert.equal(compareLaunchPolicyBindings(binding, structuredClone(binding)), true);
  assert.equal(compareLaunchPolicyBindings(binding, { ...binding, profileId: "build" }), false);
  assert.equal(digestLaunchPolicyBytes(record.bytes), record.sha256);

  assert.throws(
    () => readTrustedLaunchPolicyFromGit({ repositoryRoot, expectedBaseCommit: "0".repeat(40) }),
    hasCode("LAUNCH_POLICY_GIT_IDENTITY_INVALID")
  );
  assert.throws(
    () => readTrustedLaunchPolicyFromGit({ repositoryRoot, expectedBaseCommit: baseCommit, path: "attacker.json" }),
    hasCode("LAUNCH_POLICY_READER_ARGUMENTS_INVALID")
  );
});

test("trusted Git reader accepts canonical GitHub URL casing without changing authority identity", (t) => {
  const { baseCommit, repositoryRoot } = trustedPolicyFixture(t);
  runGit(repositoryRoot, ["remote", "set-url", "origin", "https://github.com/0xProgrammable/Launch-Policy.git"]);

  const record = readTrustedLaunchPolicyFromGit({ repositoryRoot, expectedBaseCommit: baseCommit });
  assert.equal(record.repository, "0xprogrammable/launch-policy");
  assert.equal(record.numericRepositoryId, "1320171831");
});

test("trusted Git reader rejects a different GitHub owner or repository", (t) => {
  for (const remote of [
    "https://github.com/not-programmable/Launch-Policy.git",
    "https://github.com/0xprogrammable/Launch-Policies.git"
  ]) {
    const { baseCommit, repositoryRoot } = trustedPolicyFixture(t);
    runGit(repositoryRoot, ["remote", "set-url", "origin", remote]);
    assert.throws(
      () => readTrustedLaunchPolicyFromGit({ repositoryRoot, expectedBaseCommit: baseCommit }),
      hasCode("LAUNCH_POLICY_GIT_IDENTITY_INVALID")
    );
  }
});

test("JSON Schema rejects profile duplication production disablement approval and authority escalation", () => {
  const schema = JSON.parse(fs.readFileSync(path.join(root, "policy/schemas/launch-policy.v1.schema.json"), "utf8"));
  const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
  const canonical = canonicalPolicyRecord().policy;
  assert.equal(validate(canonical), true, JSON.stringify(validate.errors));

  const mutations = [
    (policy) => { policy.policyVersion = "9.9.9"; },
    (policy) => { policy.profiles[0] = structuredClone(policy.profiles[3]); },
    (policy) => { policy.profiles[0].authority.checkerOnly = false; },
    (policy) => { policy.profiles[0].authority.publicRoutingAllowed = true; },
    (policy) => { policy.profiles[1].enabled = false; },
    (policy) => { policy.profiles[1].outcome = "LAUNCH_APPROVED"; },
    (policy) => { policy.profiles[2].enabled = false; },
    (policy) => { policy.profiles[2].authority.realUserFundsAllowed = true; },
    (policy) => { policy.profiles[3].authority.realUserFundsAllowed = true; },
    (policy) => { policy.rules.find(({ status }) => status === "active").applicability = { mode: "historical" }; }
  ];
  for (const mutate of mutations) {
    const policy = structuredClone(canonical);
    mutate(policy);
    assert.equal(validate(policy), false, JSON.stringify(policy.profiles));
  }
});

test("Markdown projection identifies itself as generated and binds exact policy bytes", () => {
  const record = canonicalPolicyRecord();
  const markdown = renderLaunchPolicyMarkdown(record);
  assert.match(markdown, /^# Programmable Launch Policy\n/u);
  assert.match(markdown, /Generated from the canonical policy/u);
  assert.match(markdown, new RegExp(record.sha256, "u"));
  assert.match(markdown, /## Production Launch/u);
  assert.match(markdown, /PRODUCTION_REQUIREMENTS_CHECKED_NOT_AUTHORIZED/u);
  assert.doesNotMatch(markdown, /LAUNCH_APPROVED/u);
});
