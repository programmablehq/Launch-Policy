import assert from "node:assert/strict";
import childProcess from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import Ajv2020 from "../scripts/test/schema-validator/node_modules/ajv/dist/2020.js";

import { keccak256Hex } from "../vendor/programmable-applicant-validator/scripts/evm-encoding-core.mjs";
import {
  canonicalProgrammableLaunchRouterReadinessJson,
  computeProgrammableLaunchRouterPoolIdV1,
  computeProgrammableLaunchRouterRouteCommitmentV1,
  computeProgrammableStampRequestV1Commitment,
  deriveProgrammableLaunchRouterApplicabilityRecordV1,
  deriveProgrammableLaunchRouterSourceConfigurationHashV1,
  isTrustedProgrammableLaunchRouterApplicabilityRecordV1,
  parseProgrammableLaunchRouterReadinessBytesV1,
  PROGRAMMABLE_LAUNCH_ROUTER_READINESS_PATH,
  PROGRAMMABLE_LAUNCH_ROUTER_READINESS_SCHEMA_ID,
  PROGRAMMABLE_LAUNCH_ROUTER_READINESS_SCHEMA_PATH,
  PROGRAMMABLE_LAUNCH_ROUTER_V1_DEVELOPER_REFERENCE,
  PROGRAMMABLE_LAUNCH_ROUTER_V1_MANIFEST_PROJECTION,
  PROGRAMMABLE_LAUNCH_ROUTER_V1_RESOLVED_ROUTER,
  PROGRAMMABLE_TREASURY_TEN_BPS_CONFIGURATION_SHA256,
  ProgrammableLaunchRouterReadinessError,
  projectProgrammableLaunchRouterPolicyEvidenceV1,
  verifyProgrammableLaunchRouterReadinessBytesV1
} from "../scripts/programmable-launch-router-readiness-core.mjs";

const repositoryRoot = path.resolve(import.meta.dirname, "..");
const cliPath = path.join(repositoryRoot, "scripts/programmable-launch-router-readiness.mjs");

test("the current Router V1 prelaunch fixture satisfies the closed schema and offline checker", () => {
  const fixture = currentRouterV1Fixture();
  const validate = compileSchema();
  assert.equal(validate(fixture), true, JSON.stringify(validate.errors));

  const result = verifyProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(fixture));
  assert.equal(result.ok, true);
  assert.equal(result.state, "prelaunch-bound");
  assert.equal(result.applicabilityRecord.decision, "required");
  assert.equal(isTrustedProgrammableLaunchRouterApplicabilityRecordV1(result.applicabilityRecord), true);
  assert.match(result.documentSha256, /^sha256:[0-9a-f]{64}$/u);
  assert.deepEqual(Object.keys(result.policyEvidence), [
    "programmable-launch-requirement",
    "programmable-router-readiness"
  ]);
  assert.deepEqual(result.policyEvidence["programmable-launch-requirement"], {
    basis: "gross-canonical-pool-volume",
    chainId: 1,
    hundredthsOfBip: 1000,
    network: "ethereum-mainnet",
    status: "passed",
    treasury: "0x4957f49620AFf3Adbbe8195a4f633E49cc93376c"
  });
  const readiness = result.policyEvidence["programmable-router-readiness"];
  assert.deepEqual(Object.keys(readiness).sort(), [
    "abiSha256",
    "abiUrl",
    "chainId",
    "directFactoryCall",
    "discoveryDocumentUrl",
    "launchEntryPoint",
    "launchKind",
    "manifestSha256",
    "manifestUrl",
    "routeEvidenceSha256",
    "routerAddress",
    "routerManifestPointer",
    "routerRuntimeCodeHash",
    "routerStatus",
    "sourceCommit",
    "sourceConfigurationHash",
    "sourceTree",
    "status"
  ].sort());
  assert.equal(readiness.status, "passed");
  assert.equal(readiness.launchKind, 1);
  assert.equal(readiness.directFactoryCall, false);
  assert.equal(readiness.routeEvidenceSha256, result.documentSha256);
  assert.equal(readiness.routerAddress, PROGRAMMABLE_LAUNCH_ROUTER_V1_RESOLVED_ROUTER.address);
  assert.equal(Object.isFrozen(result.policyEvidence), true);
  assert.equal(Object.isFrozen(readiness), true);
});

test("applicability is a WeakSet-bound typed record minted only from exact document bytes", () => {
  const fixtures = [
    [currentRouterV1Fixture(), "required", "programmable-ethereum-mainnet"],
    [pendingFixture(), "analysis-pending", "analysis-pending"],
    [notApplicableFixture("no-market"), "not-applicable", "no-market"]
  ];
  for (const [fixture, decision, routeMode] of fixtures) {
    const parsed = parseProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(fixture));
    const record = deriveProgrammableLaunchRouterApplicabilityRecordV1(parsed);
    assert.deepEqual(Object.keys(record).sort(), [
      "decision",
      "declaration",
      "kind",
      "readinessDocumentSha256",
      "routeMode",
      "schemaVersion",
      "subject"
    ].sort());
    assert.equal(record.decision, decision);
    assert.equal(record.routeMode, routeMode);
    assert.equal(record.subject.commit, fixture.subject.sourceCommit);
    assert.equal(record.subject.configurationHash, fixture.subject.sourceConfigurationHash);
    assert.equal(isTrustedProgrammableLaunchRouterApplicabilityRecordV1(record), true);
    assert.equal(isTrustedProgrammableLaunchRouterApplicabilityRecordV1(structuredClone(record)), false);
    assert.equal(Object.isFrozen(record), true);
    assert.equal(Object.isFrozen(record.subject), true);
  }

  const document = currentRouterV1Fixture();
  const forgedParsed = {
    document,
    documentSha256: digest(canonicalBytes(document))
  };
  assert.throws(
    () => deriveProgrammableLaunchRouterApplicabilityRecordV1(forgedParsed),
    hasCode("PROGRAMMABLE_ROUTER_RECORD_TRUST_INVALID")
  );
  assert.throws(
    () => projectProgrammableLaunchRouterPolicyEvidenceV1(forgedParsed),
    hasCode("PROGRAMMABLE_ROUTER_RECORD_TRUST_INVALID")
  );
});

test("manifest live-response observations are time-bound while the immutable Developer artifact remains exact", () => {
  const first = currentRouterV1Fixture();
  const second = currentRouterV1Fixture();
  second.manifestSnapshot.observedAt = "2026-08-20T12:34:56.000Z";

  const firstResult = verifyProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(first));
  const secondResult = verifyProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(second));
  assert.notEqual(firstResult.documentSha256, secondResult.documentSha256);
  assert.equal(
    firstResult.policyEvidence["programmable-router-readiness"].manifestSha256,
    PROGRAMMABLE_LAUNCH_ROUTER_V1_DEVELOPER_REFERENCE.deploymentManifest.sha256
  );
  assert.equal(
    secondResult.policyEvidence["programmable-router-readiness"].manifestSha256,
    PROGRAMMABLE_LAUNCH_ROUTER_V1_DEVELOPER_REFERENCE.deploymentManifest.sha256
  );
  assert.equal(first.manifestSnapshot.liveResponseSha256, second.manifestSnapshot.liveResponseSha256);
});

test("manifest snapshot embeds one canonical pointer projection and rejects jointly rehashed substitutions", () => {
  const cases = [
    ["status", (projection) => { projection.launchStampRouter.status = "retired"; }],
    ["end block", (projection) => { projection.launchStampRouter.endBlock = "25720000"; }],
    ["runtime", (projection) => { projection.launchStampRouter.runtimeCodeHash = bytes32("8"); }],
    ["unknown selected key", (projection) => { projection.launchStampRouter.unreviewedRouter = true; }]
  ];
  for (const [label, mutate] of cases) {
    const fixture = currentRouterV1Fixture();
    const projection = structuredClone(PROGRAMMABLE_LAUNCH_ROUTER_V1_MANIFEST_PROJECTION);
    mutate(projection);
    bindManifestProjection(fixture.manifestSnapshot, projection);
    assert.throws(
      () => verifyProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(fixture)),
      hasCode("PROGRAMMABLE_ROUTER_MANIFEST_SNAPSHOT_INVALID"),
      label
    );
  }

  const wrongPointer = currentRouterV1Fixture();
  wrongPointer.manifestSnapshot.manifestPointer = "/copiedLaunchStampRouter";
  assert.throws(
    () => verifyProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(wrongPointer)),
    hasCode("PROGRAMMABLE_ROUTER_MANIFEST_SNAPSHOT_INVALID")
  );

  const digestOnly = currentRouterV1Fixture();
  digestOnly.manifestSnapshot.liveResponseSha256 = sha256Value("f");
  assert.throws(
    () => verifyProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(digestOnly)),
    hasCode("PROGRAMMABLE_ROUTER_MANIFEST_SNAPSHOT_INVALID")
  );
});

test("analysis-pending is closed, carries exact subject identity, and cannot pass either policy rule", () => {
  const pending = pendingFixture();
  const validate = compileSchema();
  assert.equal(validate(pending), true, JSON.stringify(validate.errors));
  const result = verifyProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(pending));
  const readiness = result.policyEvidence["programmable-router-readiness"];
  assert.equal(readiness.status, "analysis-pending");
  assert.equal(readiness.sourceCommit, pending.subject.sourceCommit);
  assert.equal(readiness.sourceTree, pending.subject.sourceTree);
  assert.equal(readiness.sourceConfigurationHash, pending.subject.sourceConfigurationHash);
  assert.equal(readiness.chainId, 1);
  assert.equal(readiness.directFactoryCall, false);
  assert.equal(readiness.discoveryDocumentUrl, "https://developers.programmable.family/.well-known/programmable.json");
  assert.equal(readiness.launchEntryPoint, "launchAndStampV1");
  assert.equal(readiness.manifestUrl, "https://developers.programmable.family/api/v2/manifest");
  assert.equal(readiness.routerManifestPointer, "/launchStampRouter");
  for (const key of [
    "abiSha256",
    "abiUrl",
    "launchKind",
    "manifestSha256",
    "routeEvidenceSha256",
    "routerAddress",
    "routerRuntimeCodeHash",
    "routerStatus"
  ]) assert.equal(readiness[key], null, key);
  assert.equal(result.policyEvidence["programmable-launch-requirement"].status, "analysis-pending");

  pending.route = currentRouterV1Fixture().route;
  assert.throws(
    () => verifyProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(pending)),
    hasCode("PROGRAMMABLE_ROUTER_ANALYSIS_PENDING_INVALID")
  );
});

test("not-applicable requires a protected content-addressed no-market or external-route declaration", () => {
  for (const routeMode of ["no-market", "external-route"]) {
    const fixture = notApplicableFixture(routeMode);
    const validate = compileSchema();
    assert.equal(validate(fixture), true, `${routeMode}: ${JSON.stringify(validate.errors)}`);
    const result = verifyProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(fixture));
    assert.equal(result.state, "not-applicable");
    assert.deepEqual(result.policyEvidence, {});
  }

  const untrusted = notApplicableFixture("no-market");
  untrusted.applicability.trustedDeclaration.numericRepositoryId = "1";
  assert.throws(
    () => verifyProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(untrusted)),
    hasCode("PROGRAMMABLE_ROUTER_NOT_APPLICABLE_INVALID")
  );

  const mismatched = notApplicableFixture("external-route");
  mismatched.applicability.trustedDeclaration.declarationKind = "trusted-no-market-declaration";
  assert.throws(
    () => verifyProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(mismatched)),
    hasCode("PROGRAMMABLE_ROUTER_NOT_APPLICABLE_INVALID")
  );

  const smuggled = notApplicableFixture("no-market");
  smuggled.developerReference = structuredClone(PROGRAMMABLE_LAUNCH_ROUTER_V1_DEVELOPER_REFERENCE);
  assert.throws(
    () => verifyProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(smuggled)),
    hasCode("PROGRAMMABLE_ROUTER_NOT_APPLICABLE_INVALID")
  );

  for (const [label, mutate] of [
    ["oversized declaration", (value) => { value.applicability.trustedDeclaration.byteLength = 1_048_577; }],
    ["Unicode declaration path", (value) => { value.applicability.trustedDeclaration.path = "review/é.json"; }],
    ["empty declaration path segment", (value) => { value.applicability.trustedDeclaration.path = "review//route.json"; }]
  ]) {
    const drift = notApplicableFixture("no-market");
    mutate(drift);
    const validate = compileSchema();
    assert.equal(validate(drift), false, `${label} must fail the public schema`);
    assert.throws(
      () => verifyProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(drift)),
      hasCode("PROGRAMMABLE_ROUTER_NOT_APPLICABLE_INVALID"),
      `${label} must fail the core`
    );
  }
});

test("Developer repository, commit, tree, path, blob, and digest mismatches fail closed", () => {
  const cases = [
    ["repository", (value) => { value.developerReference.repository = "attacker/developers"; }],
    ["numeric id", (value) => { value.developerReference.numericRepositoryId = "1"; }],
    ["commit", (value) => { value.developerReference.commit = objectId("1"); }],
    ["tree", (value) => { value.developerReference.tree = objectId("2"); }],
    ["artifact path", (value) => { value.developerReference.routerAbi.path = "abis/ethereum/copied.json"; }],
    ["artifact blob", (value) => { value.developerReference.deploymentManifest.gitBlobOid = objectId("3"); }],
    ["artifact digest", (value) => { value.developerReference.terminalGuide.sha256 = sha256Value("4"); }],
    ["extra artifact", (value) => { value.developerReference.copiedRouter = {}; }]
  ];
  for (const [label, mutate] of cases) {
    const fixture = currentRouterV1Fixture();
    mutate(fixture);
    assert.throws(
      () => verifyProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(fixture)),
      hasCode("PROGRAMMABLE_ROUTER_DEVELOPER_REFERENCE_MISMATCH"),
      label
    );
  }
});

test("the live Router tuple cannot be substituted, retired, or partially rebound", () => {
  const cases = [
    ["address", (value) => { value.resolvedRouter.address = address("1"); }],
    ["runtime", (value) => { value.resolvedRouter.runtimeCodeHash = bytes32("2"); }],
    ["ABI", (value) => { value.resolvedRouter.abiSha256 = sha256Value("3"); }],
    ["status", (value) => { value.resolvedRouter.status = "retired"; }],
    ["start block", (value) => { value.resolvedRouter.startBlock = "25717613"; }],
    ["finality", (value) => { value.resolvedRouter.finalityConfirmations = 1; }],
    ["permit authority", (value) => { value.resolvedRouter.bindings.permitAuthority = address("4"); }],
    ["Graph Factory runtime", (value) => { value.resolvedRouter.bindings.graphFactoryRuntimeCodeHash = bytes32("5"); }],
    ["PoolManager", (value) => { value.resolvedRouter.bindings.poolManager = address("6"); }],
    ["selector", (value) => { value.resolvedRouter.atomicSelector = "0x00000000"; }]
  ];
  for (const [label, mutate] of cases) {
    const fixture = currentRouterV1Fixture();
    mutate(fixture);
    assert.throws(
      () => verifyProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(fixture)),
      hasCode("PROGRAMMABLE_ROUTER_RESOLVED_TUPLE_MISMATCH"),
      label
    );
  }
});

test("category, LaunchKindV1, entry point, and direct-factory exclusions are inseparable", () => {
  const mismatchedKind = currentRouterV1Fixture();
  mismatchedKind.route.launchKind = 2;
  mismatchedKind.route.commitments.launchPermitV1.kind = 2;
  assert.throws(
    () => verifyProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(mismatchedKind)),
    hasCode("PROGRAMMABLE_ROUTER_ROUTE_KIND_MISMATCH")
  );

  for (const [label, mutate, code] of [
    ["direct call", (value) => { value.route.directFactoryCall = true; }, "PROGRAMMABLE_ROUTER_DIRECT_FACTORY_FORBIDDEN"],
    ["fallback", (value) => { value.route.directFactoryFallbackAllowed = true; }, "PROGRAMMABLE_ROUTER_DIRECT_FACTORY_FORBIDDEN"],
    ["factory target", (value) => { value.route.transactionTarget = value.resolvedRouter.bindings.graphFactory; }, "PROGRAMMABLE_ROUTER_ROUTE_TARGET_MISMATCH"],
    ["selector", (value) => { value.route.transactionSelector = "0x00000000"; }, "PROGRAMMABLE_ROUTER_ROUTE_TARGET_MISMATCH"]
  ]) {
    const fixture = currentRouterV1Fixture();
    mutate(fixture);
    assert.throws(() => verifyProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(fixture)), hasCode(code), label);
  }

  const classic = currentRouterV1Fixture();
  switchToClassic(classic);
  const result = verifyProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(classic));
  assert.equal(result.policyEvidence["programmable-router-readiness"].launchKind, 2);
});

test("the route source identity must match the exact reviewed subject", () => {
  for (const [label, mutate] of [
    ["repository", (value) => { value.route.sourceIdentity.repository = "attacker/source"; }],
    ["repository id", (value) => { value.route.sourceIdentity.numericRepositoryId = "99"; }],
    ["commit", (value) => { value.route.sourceIdentity.commit = objectId("8"); }],
    ["tree", (value) => { value.route.sourceIdentity.tree = objectId("9"); }],
    ["configuration", (value) => { value.route.sourceIdentity.configurationHash = sha256Value("a"); }],
    ["self binding", (value) => { value.route.sourceIdentity.artifact.path = PROGRAMMABLE_LAUNCH_ROUTER_READINESS_PATH; }]
  ]) {
    const fixture = currentRouterV1Fixture();
    mutate(fixture);
    assert.throws(
      () => verifyProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(fixture)),
      hasCode("PROGRAMMABLE_ROUTER_SOURCE_IDENTITY_MISMATCH"),
      label
    );
  }
});

test("late wallet semantics prohibit premature signing state", () => {
  for (const [label, mutate] of [
    ["wallet set", (value) => { value.route.launchWallet.address = address("1"); }],
    ["mode changed", (value) => { value.route.launchWallet.bindingState = "already-bound"; }],
    ["permit wallet set", (value) => { value.route.commitments.launchPermitV1.launchWallet = address("2"); }],
    ["permit digest set", (value) => { value.route.commitments.launchPermitV1.permitDigest = bytes32("3"); }],
    ["signature set", (value) => { value.route.commitments.launchPermitV1.signature = "0x01"; }],
    ["validity set", (value) => { value.route.commitments.launchPermitV1.validAfter = "1"; }]
  ]) {
    const fixture = currentRouterV1Fixture();
    mutate(fixture);
    assert.throws(
      () => verifyProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(fixture)),
      (error) => error instanceof ProgrammableLaunchRouterReadinessError
        && new Set(["PROGRAMMABLE_ROUTER_WALLET_BINDING_INVALID", "PROGRAMMABLE_ROUTER_PERMIT_INVALID"]).has(error.code),
      label
    );
  }
});

test("routePayload, expectedResult, StampRequestV1, and LaunchPermitV1 commitments are byte-exact", () => {
  const cases = [
    ["payload bytes", (value) => { value.route.commitments.routePayload.contentBase64 = Buffer.from("tampered-route").toString("base64"); }],
    ["payload length", (value) => { value.route.commitments.routePayload.byteLength += 1; }],
    ["payload sha", (value) => { value.route.commitments.routePayload.sha256 = sha256Value("0"); }],
    ["payload keccak", (value) => { value.route.commitments.routePayload.keccak256 = bytes32("1"); }],
    ["payload encoding", (value) => { value.route.commitments.routePayload.encoding = "abi.encode(ClassicRouteV1)"; }],
    ["expected result", (value) => { value.route.commitments.expectedResult.hash = bytes32("8"); }],
    ["expected result payload binding", (value) => { value.route.commitments.expectedResult.routePayloadSha256 = sha256Value("8"); }],
    ["stamp component", (value) => { value.route.commitments.stampRequestV1.components[0].runtimeCodeHash = bytes32("8"); }],
    ["stamp pool key", (value) => { value.route.commitments.stampRequestV1.poolKey.fee = 500; }],
    ["stamp component hash", (value) => { value.route.commitments.stampRequestV1.componentSetHash = bytes32("8"); }],
    ["stamp request hash", (value) => { value.route.commitments.stampRequestV1.stampRequestHash = bytes32("8"); }],
    ["permit route hash", (value) => { value.route.commitments.launchPermitV1.routePayloadHash = bytes32("2"); }],
    ["permit result hash", (value) => { value.route.commitments.launchPermitV1.expectedResultHash = bytes32("3"); }],
    ["permit stamp hash", (value) => { value.route.commitments.launchPermitV1.stampRequestHash = bytes32("4"); }],
    ["permit router", (value) => { value.route.commitments.launchPermitV1.router = address("5"); }]
  ];
  for (const [label, mutate] of cases) {
    const fixture = currentRouterV1Fixture();
    mutate(fixture);
    assert.throws(
      () => verifyProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(fixture)),
      (error) => error instanceof ProgrammableLaunchRouterReadinessError
        && error.code.startsWith("PROGRAMMABLE_ROUTER_"),
      label
    );
  }
});

test("routePayload must be canonical ABI and its Router-derived result must match StampRequestV1", () => {
  const malformed = currentRouterV1Fixture();
  bindRawRouteBytes(malformed, Buffer.from("not-an-abi-route", "utf8"));
  assert.throws(
    () => verifyProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(malformed)),
    hasCode("PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID")
  );

  const noncanonical = currentRouterV1Fixture();
  const extraWord = Buffer.concat([
    Buffer.from(noncanonical.route.commitments.routePayload.contentBase64, "base64"),
    Buffer.alloc(32)
  ]);
  bindRawRouteBytes(noncanonical, extraWord);
  assert.throws(
    () => verifyProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(noncanonical)),
    hasCode("PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID")
  );

  const excessiveTargets = currentRouterV1Fixture();
  const excessiveTargetsBytes = Buffer.from(excessiveTargets.route.commitments.routePayload.contentBase64, "base64");
  const excessiveTargetsBase = customTargetsArrayBase(excessiveTargetsBytes);
  writeAbiUintWord(excessiveTargetsBytes, excessiveTargetsBase, 4096);
  bindRawRouteBytes(excessiveTargets, excessiveTargetsBytes);
  assert.throws(
    () => verifyProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(excessiveTargets)),
    hasCode("PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID"),
    "Custom targets must be bounded before their dynamic elements are decoded"
  );

  const aliasedTargets = currentRouterV1Fixture();
  const aliasedTargetsBytes = Buffer.from(aliasedTargets.route.commitments.routePayload.contentBase64, "base64");
  const aliasedElementsBase = customTargetsArrayBase(aliasedTargetsBytes) + 32;
  aliasedTargetsBytes.copy(aliasedTargetsBytes, aliasedElementsBase + 32, aliasedElementsBase, aliasedElementsBase + 32);
  bindRawRouteBytes(aliasedTargets, aliasedTargetsBytes);
  assert.throws(
    () => verifyProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(aliasedTargets)),
    hasCode("PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID"),
    "Custom target tails must not alias"
  );

  for (const [label, mutate] of [
    ["route nonce", (route) => { route.routeNonce = bytes32("8"); }],
    ["output component", (route) => { route.expectedOutputs[1].account = address("3"); }],
    ["empty init code", (route) => { route.targets[0].initCode = "0x"; }],
    ["nonzero initializer without calldata", (route) => { route.targets[0].initializerValue = "1"; }]
  ]) {
    const fixture = currentRouterV1Fixture();
    const route = customGraphRouteFixture();
    mutate(route);
    const commitmentValue = computeProgrammableLaunchRouterRouteCommitmentV1({ category: "custom", routePayload: route });
    bindRouteCommitment(fixture, commitmentValue);
    assert.throws(
      () => verifyProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(fixture)),
      hasCode("PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID"),
      label
    );
  }

  for (const [label, account, runtimeCodeHash] of [
    [
      "Graph Factory component",
      PROGRAMMABLE_LAUNCH_ROUTER_V1_RESOLVED_ROUTER.bindings.graphFactory,
      PROGRAMMABLE_LAUNCH_ROUTER_V1_RESOLVED_ROUTER.bindings.graphFactoryRuntimeCodeHash
    ],
    [
      "PoolManager component",
      PROGRAMMABLE_LAUNCH_ROUTER_V1_RESOLVED_ROUTER.bindings.poolManager,
      PROGRAMMABLE_LAUNCH_ROUTER_V1_RESOLVED_ROUTER.bindings.poolManagerRuntimeCodeHash
    ]
  ]) {
    const fixture = currentRouterV1Fixture();
    const route = customGraphRouteFixture();
    route.targets.push({
      applicantSalt: bytes32("0"),
      deploymentValue: "0",
      initCode: "0x6002",
      initializerCalldata: "0x",
      initializerValue: "0",
      targetIdHash: bytes32("f")
    });
    route.expectedOutputs.push({
      account,
      runtimeCodeHash,
      targetIdHash: bytes32("f"),
      targetIndex: 2
    });
    const routeCommitment = computeProgrammableLaunchRouterRouteCommitmentV1({ category: "custom", routePayload: route });
    bindRouteCommitment(fixture, routeCommitment);

    const stampRequest = fixture.route.commitments.stampRequestV1;
    stampRequest.components.push({ account, kind: 0, resultIndex: 2, runtimeCodeHash, scope: 1 });
    stampRequest.components.sort((left, right) => BigInt(left.account) < BigInt(right.account) ? -1 : 1);
    const stampCommitment = computeProgrammableStampRequestV1Commitment({
      category: "custom",
      stampRequest: rawStampRequest(stampRequest)
    });
    stampRequest.componentSetHash = stampCommitment.componentSetHash;
    stampRequest.poolKeyHash = stampCommitment.poolKeyHash;
    stampRequest.stampRequestHash = stampCommitment.stampRequestHash;
    fixture.route.commitments.launchPermitV1.stampRequestHash = stampCommitment.stampRequestHash;

    assert.throws(
      () => verifyProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(fixture)),
      hasCode("PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID"),
      label
    );
  }

  const classic = currentRouterV1Fixture();
  switchToClassic(classic);
  const classicRoute = classicRouteFixture(classic.route.commitments.stampRequestV1);
  classicRoute.expectedResult.rewardVault = address("8");
  const classicCommitment = computeProgrammableLaunchRouterRouteCommitmentV1({
    category: "classic",
    routePayload: classicRoute
  });
  bindRouteCommitment(classic, classicCommitment);
  assert.throws(
    () => verifyProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(classic)),
    hasCode("PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID")
  );
});

test("StampRequestV1 typed hashing rejects component smuggling and category-shape mismatches", () => {
  for (const [label, mutate] of [
    ["unsorted", (value) => { value.route.commitments.stampRequestV1.components.reverse(); }],
    ["duplicate result index", (value) => { value.route.commitments.stampRequestV1.components[1].resultIndex = 0; }],
    ["wrong token kind", (value) => { value.route.commitments.stampRequestV1.components[0].kind = 0; }],
    ["wrong hook scope", (value) => { value.route.commitments.stampRequestV1.components[1].scope = 2; }],
    ["wrong type hash", (value) => { value.route.commitments.stampRequestV1.typeHash = bytes32("8"); }],
    ["pool omits token", (value) => { value.route.commitments.stampRequestV1.poolKey.currency0 = address("3"); }]
  ]) {
    const fixture = currentRouterV1Fixture();
    mutate(fixture);
    assert.throws(
      () => verifyProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(fixture)),
      hasCode("PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID"),
      label
    );
  }
});

test("sourceConfigurationHash is domain-separated over both exact applicant artifacts", () => {
  const fixture = currentRouterV1Fixture();
  const expected = deriveProgrammableLaunchRouterSourceConfigurationHashV1({
    feeImplementationArtifact: fixture.feeConfiguration.implementationArtifact,
    routeArtifact: fixture.route.sourceIdentity.artifact
  });
  assert.equal(fixture.subject.sourceConfigurationHash, expected);

  const oneSided = currentRouterV1Fixture();
  oneSided.route.sourceIdentity.artifact.sha256 = sha256Value("2");
  assert.throws(
    () => verifyProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(oneSided)),
    hasCode("PROGRAMMABLE_ROUTER_SOURCE_CONFIGURATION_MISMATCH")
  );

  const jointlyRehashed = currentRouterV1Fixture();
  jointlyRehashed.route.sourceIdentity.artifact.sha256 = sha256Value("2");
  const rederived = deriveProgrammableLaunchRouterSourceConfigurationHashV1({
    feeImplementationArtifact: jointlyRehashed.feeConfiguration.implementationArtifact,
    routeArtifact: jointlyRehashed.route.sourceIdentity.artifact
  });
  jointlyRehashed.subject.sourceConfigurationHash = rederived;
  jointlyRehashed.route.sourceIdentity.configurationHash = rederived;
  const verified = verifyProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(jointlyRehashed));
  assert.equal(verified.policyEvidence["programmable-router-readiness"].sourceConfigurationHash, rederived);
  assert.notEqual(rederived, expected);
});

test("10 bps economics and the bound implementation artifact fail closed independently", () => {
  const cases = [
    ["bps", (value) => { value.feeConfiguration.bps = 9; }],
    ["hundredths", (value) => { value.feeConfiguration.hundredthsOfBip = 999; }],
    ["rate ppm", (value) => { value.feeConfiguration.ratePpm = 999; }],
    ["treasury", (value) => { value.feeConfiguration.treasury = address("0"); }],
    ["basis", (value) => { value.feeConfiguration.basis = "net-volume"; }],
    ["chain", (value) => { value.feeConfiguration.chainId = 8453; }],
    ["network", (value) => { value.feeConfiguration.network = "base-mainnet"; }],
    ["configuration digest", (value) => { value.feeConfiguration.configurationSha256 = sha256Value("d"); }],
    ["invalid implementation blob", (value) => { value.feeConfiguration.implementationArtifact.gitBlobOid = "x".repeat(40); }],
    ["self binding", (value) => { value.feeConfiguration.implementationArtifact.path = PROGRAMMABLE_LAUNCH_ROUTER_READINESS_PATH; }]
  ];
  for (const [label, mutate] of cases) {
    const fixture = currentRouterV1Fixture();
    mutate(fixture);
    assert.throws(
      () => verifyProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(fixture)),
      hasCode("PROGRAMMABLE_ROUTER_FEE_CONFIGURATION_INVALID"),
      label
    );
  }
});

test("every authority claim remains inert and unknown authority aliases are rejected", () => {
  for (const key of Object.keys(currentRouterV1Fixture().authority)) {
    const fixture = currentRouterV1Fixture();
    fixture.authority[key] = true;
    assert.throws(
      () => verifyProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(fixture)),
      hasCode("PROGRAMMABLE_ROUTER_AUTHORITY_INVALID"),
      key
    );
  }
  const extra = currentRouterV1Fixture();
  extra.authority.safe = true;
  assert.throws(
    () => verifyProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(extra)),
    hasCode("PROGRAMMABLE_ROUTER_AUTHORITY_INVALID")
  );
});

test("the parser rejects duplicate, noncanonical, invalid UTF-8, and extra-key JSON", () => {
  const fixture = currentRouterV1Fixture();
  const canonical = canonicalBytes(fixture);
  assert.throws(
    () => parseProgrammableLaunchRouterReadinessBytesV1(Buffer.from(canonical.toString("utf8").replace('{"$schema":', '{"$schema":"duplicate","$schema":'))),
    hasCode("PROGRAMMABLE_ROUTER_JSON_INVALID")
  );
  assert.throws(
    () => parseProgrammableLaunchRouterReadinessBytesV1(Buffer.from(`${JSON.stringify(fixture, null, 2)}\n`)),
    hasCode("PROGRAMMABLE_ROUTER_JSON_NONCANONICAL")
  );
  assert.throws(
    () => parseProgrammableLaunchRouterReadinessBytesV1(Buffer.concat([canonical, Buffer.from("\n")])),
    hasCode("PROGRAMMABLE_ROUTER_JSON_NONCANONICAL")
  );
  assert.throws(
    () => parseProgrammableLaunchRouterReadinessBytesV1(Buffer.from([0xff, 0xfe, 0xfd])),
    hasCode("PROGRAMMABLE_ROUTER_JSON_INVALID")
  );
  assert.throws(
    () => parseProgrammableLaunchRouterReadinessBytesV1(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), canonical])),
    hasCode("PROGRAMMABLE_ROUTER_JSON_INVALID")
  );
  fixture.readyToLaunch = true;
  assert.throws(
    () => parseProgrammableLaunchRouterReadinessBytesV1(canonicalBytes(fixture)),
    hasCode("PROGRAMMABLE_ROUTER_DOCUMENT_INVALID")
  );
});

test("the byte API uses intrinsic typed-array extents without invoking hostile subclass hooks", () => {
  const source = canonicalBytes(currentRouterV1Fixture());
  let hostileHooks = 0;
  class HostileBytes extends Uint8Array {
    get buffer() {
      hostileHooks += 1;
      throw new Error("caller-owned buffer getter executed");
    }

    get byteLength() {
      hostileHooks += 1;
      throw new Error("caller-owned byteLength getter executed");
    }

    get byteOffset() {
      hostileHooks += 1;
      throw new Error("caller-owned byteOffset getter executed");
    }

    valueOf() {
      hostileHooks += 1;
      throw new Error("caller-owned valueOf executed");
    }

    [Symbol.iterator]() {
      hostileHooks += 1;
      throw new Error("caller-owned iterator executed");
    }
  }
  const hostile = new HostileBytes(source.length);
  Uint8Array.prototype.set.call(hostile, source);
  const parsed = parseProgrammableLaunchRouterReadinessBytesV1(hostile);
  assert.equal(parsed.document.state, "prelaunch-bound");
  assert.equal(hostileHooks, 0);

  let proxyTrap = 0;
  const proxy = new Proxy(hostile, {
    get() {
      proxyTrap += 1;
      throw new Error("proxy trap executed");
    }
  });
  assert.throws(
    () => parseProgrammableLaunchRouterReadinessBytesV1(proxy),
    hasCode("PROGRAMMABLE_ROUTER_BYTES_INVALID")
  );
  assert.equal(proxyTrap, 0);

  const oversized = new HostileBytes(2 * 1024 * 1024 + 1);
  assert.throws(
    () => parseProgrammableLaunchRouterReadinessBytesV1(oversized),
    hasCode("PROGRAMMABLE_ROUTER_BYTES_INVALID")
  );
  assert.equal(hostileHooks, 0);
});

test("the CLI reads one safe file, emits exact evidence, and never executes candidate bytes", (t) => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "programmable-router-readiness-"));
  t.after(() => fs.rmSync(temporary, { force: true, recursive: true }));
  const marker = path.join(temporary, "candidate-executed");
  const input = path.join(temporary, "candidate.mjs");
  fs.writeFileSync(input, canonicalBytes(currentRouterV1Fixture()), { mode: 0o600 });

  const result = runCli(input);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, "");
  const output = JSON.parse(result.stdout);
  assert.equal(output.ok, true);
  assert.equal(output.state, "prelaunch-bound");
  assert.equal(output.policyEvidence["programmable-router-readiness"].status, "passed");
  assert.equal(output.policyEvidence["programmable-launch-requirement"].hundredthsOfBip, 1000);
  assert.equal(fs.existsSync(marker), false);
  assert.equal(result.stdout, `${canonicalProgrammableLaunchRouterReadinessJson(output)}\n`);
});

test("the CLI rejects symlinks, hardlinks, executable files, and invalid argument sets", (t) => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "programmable-router-input-"));
  t.after(() => fs.rmSync(temporary, { force: true, recursive: true }));
  const input = path.join(temporary, "readiness.json");
  fs.writeFileSync(input, canonicalBytes(currentRouterV1Fixture()), { mode: 0o600 });

  const symlink = path.join(temporary, "symlink.json");
  fs.symlinkSync(input, symlink);
  const symlinkResult = runCli(symlink);
  assert.equal(symlinkResult.status, 2);
  assert.match(symlinkResult.stderr, /PROGRAMMABLE_ROUTER_INPUT_INVALID/u);

  const hardlink = path.join(temporary, "hardlink.json");
  fs.linkSync(input, hardlink);
  const hardlinkResult = runCli(input);
  assert.equal(hardlinkResult.status, 2);
  assert.match(hardlinkResult.stderr, /PROGRAMMABLE_ROUTER_INPUT_INVALID/u);
  fs.unlinkSync(hardlink);

  fs.chmodSync(input, 0o700);
  const executableResult = runCli(input);
  assert.equal(executableResult.status, 2);
  assert.match(executableResult.stderr, /PROGRAMMABLE_ROUTER_INPUT_INVALID/u);

  const usageResult = childProcess.spawnSync(process.execPath, [cliPath], { encoding: "utf8" });
  assert.equal(usageResult.status, 2);
  assert.match(usageResult.stderr, /PROGRAMMABLE_ROUTER_CLI_USAGE_INVALID/u);
});

test("published identifiers and fee commitment remain exact", () => {
  assert.equal(PROGRAMMABLE_LAUNCH_ROUTER_READINESS_SCHEMA_ID, "urn:programmable:launch-router-readiness:1.0.0");
  assert.equal(PROGRAMMABLE_LAUNCH_ROUTER_READINESS_SCHEMA_PATH, "intake/schemas/programmable-launch-router-readiness-v1.schema.json");
  assert.equal(PROGRAMMABLE_LAUNCH_ROUTER_READINESS_PATH, ".programmable/launch-router-readiness.v1.json");
  assert.equal(PROGRAMMABLE_TREASURY_TEN_BPS_CONFIGURATION_SHA256, "sha256:391f5e976a7b21b86fc712a0f8ec319bcd01f73f362167c2351c08692fc6485a");
});

function currentRouterV1Fixture() {
  const routeCommitment = computeProgrammableLaunchRouterRouteCommitmentV1({
    category: "custom",
    routePayload: customGraphRouteFixture()
  });
  const routePayload = routePayloadDocument(routeCommitment);
  const expectedResult = {
    derivationMode: "router-v1-route-kind-specific-typed-hash",
    hash: routeCommitment.expectedResultHash,
    routePayloadSha256: routePayload.sha256
  };
  const stampRequest = stampRequestFixture("custom");
  const feeImplementationArtifact = artifact("src/FeeConfiguration.sol", "d", "e", 4096);
  const routeArtifact = artifact("src/LaunchRoute.sol", "f", "1", 8192);
  const subject = {
    applicationId: "generic-custom-launch",
    applicationRevision: 1,
    sourceCommit: objectId("a"),
    sourceConfigurationHash: deriveProgrammableLaunchRouterSourceConfigurationHashV1({
      feeImplementationArtifact,
      routeArtifact
    }),
    sourceRepository: "example/generic-launch",
    sourceRepositoryNumericId: "123456789",
    sourceTree: objectId("c")
  };
  const liveResponse = canonicalBytes(PROGRAMMABLE_LAUNCH_ROUTER_V1_MANIFEST_PROJECTION);
  return {
    $schema: PROGRAMMABLE_LAUNCH_ROUTER_READINESS_SCHEMA_ID,
    applicability: {
      routeMode: "programmable-ethereum-mainnet",
      trustedDeclaration: null
    },
    authority: inertAuthority(),
    developerReference: structuredClone(PROGRAMMABLE_LAUNCH_ROUTER_V1_DEVELOPER_REFERENCE),
    feeConfiguration: {
      basis: "gross-canonical-pool-volume",
      bps: 10,
      chainId: 1,
      configurationSha256: PROGRAMMABLE_TREASURY_TEN_BPS_CONFIGURATION_SHA256,
      doubleChargeAllowed: false,
      enforcementMode: "route-bound",
      hundredthsOfBip: 1000,
      implementationArtifact: feeImplementationArtifact,
      network: "ethereum-mainnet",
      ratePpm: 1000,
      scope: "official-programmable-market-path",
      treasury: "0x4957f49620AFf3Adbbe8195a4f633E49cc93376c"
    },
    kind: "programmable-launch-router-readiness",
    manifestSnapshot: {
      discoveryDocumentUrl: "https://developers.programmable.family/.well-known/programmable.json",
      liveResponseBase64: liveResponse.toString("base64"),
      liveResponseBindingScope: "time-bound-pointer-projection-not-origin-or-freshness-proof",
      liveResponseByteLength: liveResponse.length,
      liveResponseContentKind: "canonical-json-pointer-projection-v1",
      liveResponseSha256: digest(liveResponse),
      manifestPointer: "/launchStampRouter",
      manifestSourceGitBlobOid: PROGRAMMABLE_LAUNCH_ROUTER_V1_DEVELOPER_REFERENCE.deploymentManifest.gitBlobOid,
      manifestSourceSha256: PROGRAMMABLE_LAUNCH_ROUTER_V1_DEVELOPER_REFERENCE.deploymentManifest.sha256,
      manifestUrl: "https://developers.programmable.family/api/v2/manifest",
      manifestVersion: "3",
      observedAt: "2026-08-20T10:00:00.000Z",
      schemaVersion: "2.0.0"
    },
    resolvedRouter: structuredClone(PROGRAMMABLE_LAUNCH_ROUTER_V1_RESOLVED_ROUTER),
    route: {
      category: "custom",
      commitments: {
        commitmentState: "payload-and-results-bound-wallet-and-validity-late",
        expectedResult,
        launchPermitV1: {
          bindingState: "wallet-and-validity-window-late-bound-before-signing",
          chainId: 1,
          deadline: null,
          domainName: "ProgrammableLaunchStampRouter",
          domainVersion: "1",
          expectedResultHash: expectedResult.hash,
          kind: 1,
          launchWallet: null,
          nonce: bytes32("9"),
          permitDigest: null,
          primaryType: "ProgrammableLaunchPermitV1",
          routePayloadHash: routePayload.keccak256,
          router: PROGRAMMABLE_LAUNCH_ROUTER_V1_RESOLVED_ROUTER.address,
          signature: null,
          stampRequestHash: stampRequest.stampRequestHash,
          typeHash: "0x5147473bd302ad67f9ef14ef9262d1b0f8d4f7155081bc8c508195b647413761",
          typeSignature: "ProgrammableLaunchPermitV1(uint256 chainId,address router,address launchWallet,uint8 kind,bytes32 routePayloadHash,bytes32 expectedResultHash,bytes32 stampRequestHash,bytes32 nonce,uint64 validAfter,uint64 deadline,uint256 value)",
          validAfter: null,
          value: "0"
        },
        routePayload,
        stampRequestV1: stampRequest
      },
      directFactoryCall: false,
      directFactoryFallbackAllowed: false,
      executionPath: "canonical-launch-stamp-router-v1",
      launchKind: 1,
      launchWallet: {
        address: null,
        bindingState: "late-bound-before-permit-signing",
        immutableAfterPermitSigning: true,
        mustEqualTransactionSender: true
      },
      routeKind: "custom-graph",
      sourceIdentity: {
        artifact: routeArtifact,
        commit: subject.sourceCommit,
        configurationHash: subject.sourceConfigurationHash,
        numericRepositoryId: subject.sourceRepositoryNumericId,
        repository: subject.sourceRepository,
        tree: subject.sourceTree
      },
      transactionSelector: PROGRAMMABLE_LAUNCH_ROUTER_V1_RESOLVED_ROUTER.atomicSelector,
      transactionTarget: PROGRAMMABLE_LAUNCH_ROUTER_V1_RESOLVED_ROUTER.address
    },
    schemaVersion: "1.0.0",
    state: "prelaunch-bound",
    subject
  };
}

function switchToClassic(fixture) {
  const stampRequest = stampRequestFixture("classic");
  const routeCommitment = computeProgrammableLaunchRouterRouteCommitmentV1({
    category: "classic",
    routePayload: classicRouteFixture(stampRequest)
  });
  fixture.route.category = "classic";
  fixture.route.routeKind = "classic";
  fixture.route.launchKind = 2;
  fixture.route.commitments.routePayload = routePayloadDocument(routeCommitment);
  fixture.route.commitments.expectedResult.hash = routeCommitment.expectedResultHash;
  fixture.route.commitments.expectedResult.routePayloadSha256 = routeCommitment.sha256;
  fixture.route.commitments.stampRequestV1 = stampRequest;
  fixture.route.commitments.launchPermitV1.kind = 2;
  fixture.route.commitments.launchPermitV1.expectedResultHash = routeCommitment.expectedResultHash;
  fixture.route.commitments.launchPermitV1.routePayloadHash = routeCommitment.keccak256;
  fixture.route.commitments.launchPermitV1.stampRequestHash = fixture.route.commitments.stampRequestV1.stampRequestHash;
}

function customGraphRouteFixture() {
  return {
    expectedGraphDeploymentHash: bytes32("e"),
    expectedOutputs: [
      {
        account: address("1"),
        runtimeCodeHash: bytes32("a"),
        targetIdHash: bytes32("c"),
        targetIndex: 0
      },
      {
        account: address("2"),
        runtimeCodeHash: bytes32("b"),
        targetIdHash: bytes32("d"),
        targetIndex: 1
      }
    ],
    graphCommitment: bytes32("3"),
    routeNamespace: bytes32("1"),
    routeNonce: bytes32("9"),
    targets: [
      {
        applicantSalt: bytes32("0"),
        deploymentValue: "0",
        initCode: "0x6000",
        initializerCalldata: "0x",
        initializerValue: "0",
        targetIdHash: bytes32("c")
      },
      {
        applicantSalt: bytes32("0"),
        deploymentValue: "0",
        initCode: "0x6001",
        initializerCalldata: "0x",
        initializerValue: "0",
        targetIdHash: bytes32("d")
      }
    ],
    topologyHash: bytes32("2")
  };
}

function classicRouteFixture(stampRequest) {
  return {
    expectedResult: {
      initialBuyCustody: address("0"),
      initialBuyNativeAmount: "0",
      initialBuyTokenAmount: "1",
      launchHash: bytes32("7"),
      lockedTokenDust: "0",
      poolId: computeProgrammableLaunchRouterPoolIdV1(stampRequest.poolKey),
      positionRecipient: address("3"),
      positionTokenId: "1",
      rewardVault: address("2"),
      token: stampRequest.token,
      tokenLiquidityAmount: "1"
    },
    launcher: address("4"),
    launcherRuntimeCodeHash: bytes32("8"),
    parameters: {
      buySwapFeeBps: 100,
      creatorSalt: bytes32("0"),
      initialBuyCustody: {
        cliffDays: 0,
        durationDays: 0,
        mode: 0
      },
      metadata: {
        description: "Generic launch",
        extraData: "0x",
        image: "",
        website: ""
      },
      name: "Generic Launch",
      rewardBeneficiaries: [address("7")],
      rewardSharesBps: [10000],
      sellSwapFeeBps: 100,
      symbol: "GEN"
    }
  };
}

function routePayloadDocument(commitmentValue) {
  return {
    byteLength: commitmentValue.byteLength,
    contentBase64: commitmentValue.contentBase64,
    encoding: commitmentValue.encoding,
    keccak256: commitmentValue.keccak256,
    sha256: commitmentValue.sha256
  };
}

function bindRouteCommitment(fixture, commitmentValue) {
  fixture.route.commitments.routePayload = routePayloadDocument(commitmentValue);
  fixture.route.commitments.expectedResult.hash = commitmentValue.expectedResultHash;
  fixture.route.commitments.expectedResult.routePayloadSha256 = commitmentValue.sha256;
  fixture.route.commitments.launchPermitV1.expectedResultHash = commitmentValue.expectedResultHash;
  fixture.route.commitments.launchPermitV1.routePayloadHash = commitmentValue.keccak256;
}

function bindRawRouteBytes(fixture, bytes) {
  fixture.route.commitments.routePayload.byteLength = bytes.length;
  fixture.route.commitments.routePayload.contentBase64 = bytes.toString("base64");
  fixture.route.commitments.routePayload.keccak256 = keccak256Hex(bytes);
  fixture.route.commitments.routePayload.sha256 = digest(bytes);
  fixture.route.commitments.expectedResult.routePayloadSha256 = digest(bytes);
  fixture.route.commitments.launchPermitV1.routePayloadHash = keccak256Hex(bytes);
}

function customTargetsArrayBase(bytes) {
  const tupleBase = readAbiUintWord(bytes, 0);
  const targetsRelativeOffset = readAbiUintWord(bytes, tupleBase + 4 * 32);
  const targetsBase = tupleBase + targetsRelativeOffset;
  assert.ok(targetsBase >= 0 && targetsBase + 32 <= bytes.length);
  return targetsBase;
}

function readAbiUintWord(bytes, offset) {
  assert.ok(offset >= 0 && offset + 32 <= bytes.length);
  const value = BigInt(`0x${bytes.subarray(offset, offset + 32).toString("hex")}`);
  assert.ok(value <= BigInt(Number.MAX_SAFE_INTEGER));
  return Number(value);
}

function writeAbiUintWord(bytes, offset, value) {
  assert.ok(Number.isSafeInteger(value) && value >= 0);
  Buffer.from(value.toString(16).padStart(64, "0"), "hex").copy(bytes, offset);
}

function rawStampRequest(stampRequest) {
  return {
    components: stampRequest.components,
    hookRuntimeCodeHash: stampRequest.hookRuntimeCodeHash,
    launchId: stampRequest.launchId,
    poolKey: stampRequest.poolKey,
    token: stampRequest.token,
    tokenRuntimeCodeHash: stampRequest.tokenRuntimeCodeHash
  };
}

function stampRequestFixture(category) {
  const token = address("1");
  const tokenRuntimeCodeHash = bytes32("a");
  const hookRuntimeCodeHash = bytes32("b");
  const hook = category === "custom" ? address("2") : address("5");
  const request = {
    components: category === "custom"
      ? [
          {
            account: token,
            kind: 1,
            resultIndex: 0,
            runtimeCodeHash: tokenRuntimeCodeHash,
            scope: 1
          },
          {
            account: hook,
            kind: 2,
            resultIndex: 1,
            runtimeCodeHash: hookRuntimeCodeHash,
            scope: 1
          }
        ]
      : [
          {
            account: token,
            kind: 1,
            resultIndex: 0,
            runtimeCodeHash: tokenRuntimeCodeHash,
            scope: 1
          },
          {
            account: address("2"),
            kind: 0,
            resultIndex: 1,
            runtimeCodeHash: bytes32("c"),
            scope: 1
          },
          {
            account: address("3"),
            kind: 0,
            resultIndex: 2,
            runtimeCodeHash: bytes32("d"),
            scope: 1
          },
          {
            account: hook,
            kind: 2,
            resultIndex: 255,
            runtimeCodeHash: hookRuntimeCodeHash,
            scope: 2
          }
        ],
    hookRuntimeCodeHash,
    launchId: bytes32("6"),
    poolKey: {
      currency0: token,
      currency1: address("6"),
      fee: 3000,
      hooks: hook,
      tickSpacing: 60
    },
    token,
    tokenRuntimeCodeHash
  };
  const computed = computeProgrammableStampRequestV1Commitment({ category, stampRequest: request });
  return {
    ...request,
    componentSetHash: computed.componentSetHash,
    hashAlgorithm: "router-v1-typed-hash",
    poolKeyHash: computed.poolKeyHash,
    stampRequestHash: computed.stampRequestHash,
    typeHash: "0xa61627b33bfee8131fa1b566b7787c8d93afc86629f51a5c9719bf8f6b3e5573",
    typeSignature: "ProgrammableStampRequestV1(bytes32 launchId,address token,bytes32 tokenRuntimeCodeHash,bytes32 poolKeyHash,bytes32 hookRuntimeCodeHash,bytes32 componentSetHash)"
  };
}

function pendingFixture() {
  const fixture = currentRouterV1Fixture();
  fixture.state = "analysis-pending";
  fixture.applicability = {
    reasonCode: "route-analysis-incomplete",
    routeMode: "analysis-pending",
    trustedDeclaration: null
  };
  fixture.developerReference = null;
  fixture.feeConfiguration = null;
  fixture.manifestSnapshot = null;
  fixture.resolvedRouter = null;
  fixture.route = null;
  return fixture;
}

function notApplicableFixture(routeMode) {
  const fixture = pendingFixture();
  fixture.state = "not-applicable";
  fixture.applicability = {
    routeMode,
    trustedDeclaration: {
      byteLength: 1024,
      commit: objectId("2"),
      declaredRouteMode: routeMode,
      declarationKind: routeMode === "no-market"
        ? "trusted-no-market-declaration"
        : "trusted-external-route-declaration",
      gitBlobOid: objectId("3"),
      numericRepositoryId: "1320171831",
      path: `review/applicability/${routeMode}.json`,
      repository: "0xprogrammable/launch-policy",
      sha256: sha256Value("4"),
      tree: objectId("5"),
      trustBasis: "protected-launch-policy-base-content-addressed"
    }
  };
  return fixture;
}

function commitment(bytes) {
  return {
    byteLength: bytes.length,
    contentBase64: bytes.toString("base64"),
    keccak256: keccak256Hex(bytes),
    sha256: digest(bytes)
  };
}

function bindManifestProjection(snapshot, projection) {
  const bytes = canonicalBytes(projection);
  snapshot.liveResponseBase64 = bytes.toString("base64");
  snapshot.liveResponseByteLength = bytes.length;
  snapshot.liveResponseSha256 = digest(bytes);
}

function artifact(relativePath, blobCharacter, shaCharacter, byteLength) {
  return {
    byteLength,
    gitBlobOid: objectId(blobCharacter),
    path: relativePath,
    sha256: sha256Value(shaCharacter)
  };
}

function inertAuthority() {
  return {
    approvalGranted: false,
    candidateCodeExecuted: false,
    credentialsUsed: false,
    externalWritesPerformed: false,
    launchAuthorized: false,
    networkAccessed: false,
    publicDiscoveryAuthorized: false,
    realUserFundsAuthorized: false,
    rpcAccessed: false
  };
}

function compileSchema() {
  const schema = JSON.parse(fs.readFileSync(path.join(repositoryRoot, PROGRAMMABLE_LAUNCH_ROUTER_READINESS_SCHEMA_PATH), "utf8"));
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  return ajv.compile(schema);
}

function canonicalBytes(value) {
  return Buffer.from(`${canonicalProgrammableLaunchRouterReadinessJson(value)}\n`, "utf8");
}

function digest(bytes) {
  return `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
}

function objectId(character) {
  return character.repeat(40);
}

function sha256Value(character) {
  return `sha256:${character.repeat(64)}`;
}

function bytes32(character) {
  return `0x${character.repeat(64)}`;
}

function address(character) {
  return `0x${character.repeat(40)}`;
}

function hasCode(code) {
  return (error) => error instanceof ProgrammableLaunchRouterReadinessError && error.code === code;
}

function runCli(inputPath) {
  return childProcess.spawnSync(process.execPath, [cliPath, inputPath], {
    cwd: repositoryRoot,
    encoding: "utf8"
  });
}
