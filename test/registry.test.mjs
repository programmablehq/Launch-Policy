import assert from "node:assert/strict";
import childProcess from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import Ajv2020 from "../scripts/test/schema-validator/node_modules/ajv/dist/2020.js";
import addFormats from "../scripts/test/schema-validator/node_modules/ajv-formats/dist/index.js";

import {
  canonicalProgrammableLaunchRouterReadinessJson,
  computeProgrammableLaunchRouterPoolIdV1,
  computeProgrammableLaunchRouterRouteCommitmentV1,
  computeProgrammableStampRequestV1Commitment,
  deriveProgrammableLaunchRouterSourceConfigurationHashV1,
  PROGRAMMABLE_LAUNCH_ROUTER_READINESS_PATH,
  PROGRAMMABLE_LAUNCH_ROUTER_READINESS_SCHEMA_ID,
  PROGRAMMABLE_LAUNCH_ROUTER_V1_DEVELOPER_REFERENCE,
  PROGRAMMABLE_LAUNCH_ROUTER_V1_MANIFEST_PROJECTION,
  PROGRAMMABLE_LAUNCH_ROUTER_V1_RESOLVED_ROUTER,
  PROGRAMMABLE_TREASURY_TEN_BPS_CONFIGURATION_SHA256,
  verifyProgrammableLaunchRouterReadinessBytesV1
} from "../scripts/programmable-launch-router-readiness-core.mjs";

import {
  buildRegistryArtifacts,
  canonicalJson,
  loadRegistry,
  PROGRAMMABLE_FEE_OWNER,
  RegistryError,
  verifyGeneratedArtifacts
} from "../scripts/registry-core.mjs";
import { derivePublicApplicationV3PackageBindingV1 } from "../scripts/verify-public-application-v3-core.mjs";

const root = path.resolve(".");

test("the seeded registry distinguishes current availability from candidates and designs", () => {
  const { projects } = loadRegistry({ repositoryRoot: root });
  const states = Object.fromEntries(projects.map(({ project }) => [project.id, project.status]));
  assert.deepEqual(states, { classic: "available", "stock-paired": "candidate" });
  for (const { project } of projects) {
    assert.equal(project.economics.programmableFee.claimOwner, PROGRAMMABLE_FEE_OWNER);
    assert.equal(project.economics.programmableFee.inclusiveBps, 10);
    assert.equal(project.economics.programmableFee.required, true);
    assert.equal(project.review.independentAudit, false);
  }
});

test("generated discovery files are deterministic and hash-bind every full record", () => {
  const first = buildRegistryArtifacts({ repositoryRoot: root });
  const second = buildRegistryArtifacts({ repositoryRoot: root });
  assert.equal(canonicalJson(first), canonicalJson(second));
  assert.equal(first.index.registryDigest, first.search.registryDigest);
  assert.equal(first.index.registryDigest, first.history.registryDigest);
  assert.equal(first.index.records.length, 2);
  for (const record of first.index.records) {
    const bytes = fs.readFileSync(path.join(root, record.path));
    const indexed = first.search.records.find(({ id }) => id === record.id);
    assert.equal(indexed.sha256, record.sha256);
    assert.ok(bytes.length > 0);
  }
  assert.deepEqual(verifyGeneratedArtifacts({ repositoryRoot: root }), {
    ok: true,
    records: 2,
    registryDigest: first.index.registryDigest
  });
});

test("pending legacy pull requests remain explicitly separate from accepted records", () => {
  const { config } = loadRegistry({ repositoryRoot: root });
  assert.deepEqual(config.legacyIntake, [
    {
      baseBranch: "main",
      continuingPullRequests: [62],
      repository: "0xprogrammable/programmable"
    },
    {
      baseBranch: "main",
      continuingPullRequests: [10, 11, 12, 14, 15, 18, 19, 20],
      repository: "0xprogrammable/hookbuilder"
    }
  ]);
  assert.equal(config.activeIntake.state, "closed");
  assert.equal(config.activeIntake.repository, "0xprogrammable/launch-policy");
});

test("Deep is outside the active registry without rewriting released history", () => {
  const current = buildRegistryArtifacts({ repositoryRoot: root });
  assert.equal(current.index.records.some(({ id }) => id === "deep"), false);
  assert.equal(current.search.records.some(({ id }) => id === "deep"), false);
  const released = JSON.parse(fs.readFileSync(path.join(root, "registry/history/1.2.0.json"), "utf8"));
  assert.equal(released.records.some(({ id }) => id === "deep"), true);
});

test("duplicate JSON keys and source path escapes fail closed", (t) => {
  const duplicate = copyFixture(t);
  const configPath = path.join(duplicate, "registry/config.json");
  const source = fs.readFileSync(configPath, "utf8");
  fs.writeFileSync(configPath, source.replace('"schemaVersion": "1.0.0"', '"schemaVersion": "1.0.0",\n  "schemaVersion": "1.0.0"'));
  assert.throws(() => loadRegistry({ repositoryRoot: duplicate }), hasCode("JSON_INVALID"));

  const traversal = copyFixture(t);
  const traversalPath = path.join(traversal, "registry/config.json");
  const value = JSON.parse(fs.readFileSync(traversalPath, "utf8"));
  value.projectPaths[0] = "../outside.json";
  value.projectPaths.sort();
  fs.writeFileSync(traversalPath, `${JSON.stringify(value, null, 2)}\n`);
  assert.throws(() => loadRegistry({ repositoryRoot: traversal }), hasCode("PATH_INVALID"));
});

test("history generation refuses to rewrite an existing version", (t) => {
  const fixture = copyFixture(t);
  const config = JSON.parse(fs.readFileSync(path.join(fixture, "registry/config.json"), "utf8"));
  const historyPath = path.join(fixture, `registry/history/${config.historyVersion}.json`);
  fs.writeFileSync(historyPath, "{}\n");
  const result = childProcess.spawnSync(
    process.execPath,
    [path.join(fixture, "scripts/generate-registry.mjs"), "--write"],
    { cwd: fixture, encoding: "utf8" }
  );
  assert.equal(result.status, 1);
  assert.match(result.stdout, /HISTORY_IMMUTABLE/u);
  assert.equal(fs.readFileSync(historyPath, "utf8"), "{}\n");
});

test("maintainer acceptance must bind the exact application and source record", (t) => {
  const fixture = copyFixture(t);
  const projectPath = path.join(fixture, "registry/projects/classic/project.json");
  const project = JSON.parse(fs.readFileSync(projectPath, "utf8"));
  project.review = {
    acceptancePath: "registry/acceptances/classic/1.json",
    applicationPullRequest: "https://github.com/0xprogrammable/launch-policy/pull/7",
    independentAudit: false,
    limitations: ["Maintainer acceptance is not an audit or deployment approval."],
    state: "accepted"
  };
  fs.writeFileSync(projectPath, `${JSON.stringify(project, null, 2)}\n`);
  const acceptanceDirectory = path.join(fixture, "registry/acceptances/classic");
  fs.mkdirSync(acceptanceDirectory, { recursive: true });
  fs.writeFileSync(path.join(acceptanceDirectory, "1.json"), `${JSON.stringify({
    acceptedAt: "2026-08-02T12:00:00Z",
    acceptedBy: "0xprogrammable",
    application: {
      applicationId: "classic",
      applicationRevision: 1,
      packageDigest: `sha256:${"a".repeat(64)}`,
      pullRequest: "https://github.com/0xprogrammable/launch-policy/pull/7"
    },
    conditions: ["Maintainer acceptance is not an audit or deployment authorization."],
    decision: "accepted-for-registry-promotion",
    projectRecordPath: "registry/projects/classic/project.json",
    schemaVersion: "1.0.0",
    source: {
      numericRepositoryId: project.source.numericRepositoryId,
      repositoryUri: project.source.repositoryUri,
      revisionObjectId: project.source.revisionObjectId,
      treeObjectId: project.source.treeObjectId
    }
  }, null, 2)}\n`);
  assert.doesNotThrow(() => loadRegistry({ repositoryRoot: fixture }));

  const acceptancePath = path.join(acceptanceDirectory, "1.json");
  const acceptance = JSON.parse(fs.readFileSync(acceptancePath, "utf8"));
  acceptance.source.treeObjectId = "f".repeat(40);
  fs.writeFileSync(acceptancePath, `${JSON.stringify(acceptance, null, 2)}\n`);
  assert.throws(() => loadRegistry({ repositoryRoot: fixture }), hasCode("ACCEPTANCE_SOURCE_MISMATCH"));
});

test("launch-stamp promotion schemas close the project binding and receipt", (t) => {
  const fixture = makePromotionFixture(t);
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv, { mode: "full" });
  const validateProject = ajv.compile(readJson(root, "registry/schema/project.schema.json"));
  const validatePromotion = ajv.compile(readJson(root, "registry/schema/launch-stamp-promotion-v1.schema.json"));
  assert.equal(validateProject(fixture.project), true, JSON.stringify(validateProject.errors));
  assert.equal(validatePromotion(fixture.promotion), true, JSON.stringify(validatePromotion.errors));

  const unclosed = structuredClone(fixture.project);
  delete unclosed.promotionSha256;
  assert.equal(validateProject(unclosed), false);

  const nonLaunchIdPath = structuredClone(fixture.project);
  nonLaunchIdPath.promotionPath = "registry/promotions/classic/1.json";
  assert.equal(validateProject(nonLaunchIdPath), false);
});

test("a finalized manifest-resolved CustomGraph stamp permits later availability promotion", (t) => {
  const fixture = makePromotionFixture(t);
  const loaded = loadRegistry({ repositoryRoot: fixture.root });
  assert.equal(loaded.promotions.length, 1);
  assert.equal(loaded.promotions[0].promotion.observation.outcome, "stamped");
  assert.equal(loaded.promotions[0].promotion.launch.launchKind, 1);
  assert.equal(loaded.promotions[0].sha256, fixture.project.promotionSha256);
});

test("a finalized Classic stamp uses token and pool identity without classifying from the shared hook", (t) => {
  const fixture = makePromotionFixture(t);
  rewritePromotion(fixture, (receipt) => {
    receipt.routePlan.launchKind = 2;
    receipt.launch.launchKind = 2;
    receipt.launch.routeLauncher = "0x1111111111111111111111111111111111111111";
    receipt.launch.routeLauncherRuntimeCodeHash = `0x${"d".repeat(64)}`;
    receipt.componentProofs = receipt.componentProofs.filter(({ componentRole }) => componentRole === "token");
    bindValidPromotionEvidence(receipt);
  });
  rebindPromotionAcceptance(fixture);
  const loaded = loadRegistry({ repositoryRoot: fixture.root });
  assert.equal(loaded.promotions[0].promotion.launch.launchKind, 2);
  assert.deepEqual(loaded.promotions[0].promotion.componentProofs.map(({ componentRole }) => componentRole), ["token"]);
});

test("a future Ethereum market cannot become available without finalized Router promotion evidence", (t) => {
  const fixture = makePromotionFixture(t);
  delete fixture.project.promotionPath;
  delete fixture.project.promotionSha256;
  writeJson(fixture.projectPath, fixture.project);
  assert.throws(() => loadRegistry({ repositoryRoot: fixture.root }), hasCode("PROMOTION_REQUIRED"));
});

test("a promotion receipt filename must equal its exact lowercase launch id", (t) => {
  const fixture = makePromotionFixture(t);
  const wrongPath = path.join(path.dirname(fixture.promotionPath), `0x${"f".repeat(64)}.json`);
  fs.renameSync(fixture.promotionPath, wrongPath);
  fixture.project.promotionPath = path.relative(fixture.root, wrongPath).split(path.sep).join("/");
  writeJson(fixture.projectPath, fixture.project);
  assert.throws(() => loadRegistry({ repositoryRoot: fixture.root }), hasCode("PROMOTION_PATH_LAUNCH_ID_MISMATCH"));
});

test("Router identity, launch kind, lookup, proof, finality, and direct-factory mismatches fail closed", async (t) => {
  const cases = [
    ["PROMOTION_ROUTER_MISMATCH", (receipt) => { receipt.observation.routerRuntimeCodeHash = `0x${"f".repeat(64)}`; }],
    ["PROMOTION_LAUNCH_KIND_MISMATCH", (receipt) => { receipt.routePlan.launchKind = 2; }],
    ["PROMOTION_LOOKUP_MISMATCH", (receipt) => { receipt.lookups.token.launchId = `0x${"f".repeat(64)}`; }],
    ["PROMOTION_PROOF_MISMATCH", (receipt) => { receipt.componentProofs.find(({ componentRole }) => componentRole === "token").stampHash = `0x${"f".repeat(64)}`; }],
    ["PROMOTION_NOT_FINALIZED", (receipt) => { receipt.observation.finality = "confirmed"; }],
    ["PROMOTION_DIRECT_FACTORY", (receipt) => { receipt.routePlan.directFactoryCall = true; }]
  ];
  for (const [code, mutate] of cases) {
    await t.test(code, (subtest) => {
      const fixture = makePromotionFixture(subtest);
      rewritePromotion(fixture, mutate);
      assert.throws(() => loadRegistry({ repositoryRoot: fixture.root }), hasCode(code));
    });
  }
});

test("the selected promotion must bind its exact bytes, acceptance, application, and source", async (t) => {
  await t.test("project digest", (subtest) => {
    const fixture = makePromotionFixture(subtest);
    fixture.project.promotionSha256 = `sha256:${"f".repeat(64)}`;
    writeJson(fixture.projectPath, fixture.project);
    assert.throws(() => loadRegistry({ repositoryRoot: fixture.root }), hasCode("PROMOTION_DIGEST_MISMATCH"));
  });

  await t.test("acceptance digest", (subtest) => {
    const fixture = makePromotionFixture(subtest);
    rewritePromotion(fixture, (receipt) => { receipt.acceptance.sha256 = `sha256:${"f".repeat(64)}`; });
    assert.throws(() => loadRegistry({ repositoryRoot: fixture.root }), hasCode("PROMOTION_ACCEPTANCE_MISMATCH"));
  });

  await t.test("source commit", (subtest) => {
    const fixture = makePromotionFixture(subtest);
    rewritePromotion(fixture, (receipt) => {
      receipt.source.commit = "f".repeat(40);
      bindValidPromotionEvidence(receipt);
    });
    rebindPromotionAcceptance(fixture);
    assert.throws(() => loadRegistry({ repositoryRoot: fixture.root }), hasCode("PROMOTION_SOURCE_MISMATCH"));
  });

  await t.test("application revision", (subtest) => {
    const fixture = makePromotionFixture(subtest);
    rewritePromotion(fixture, (receipt) => {
      receipt.application.applicationRevision = 2;
      bindValidPromotionEvidence(receipt);
    });
    assert.throws(() => loadRegistry({ repositoryRoot: fixture.root }), hasCode("PROMOTION_APPLICATION_MISMATCH"));
  });
});

test("well-formed random decision and evidence hashes cannot replace their embedded canonical contents", async (t) => {
  const cases = [
    ["PROMOTION_READINESS_DIGEST_MISMATCH", (receipt) => { receipt.evidence.readinessSha256 = `sha256:${"f".repeat(64)}`; }],
    ["PROMOTION_DECISION_DIGEST_MISMATCH", (receipt) => { receipt.policy.launchReadinessDecisionSha256 = `sha256:${"f".repeat(64)}`; }],
    ["PROMOTION_EVIDENCE_DIGEST_MISMATCH", (receipt) => { receipt.evidence.promotionSha256 = `sha256:${"f".repeat(64)}`; }]
  ];
  for (const [code, mutate] of cases) {
    await t.test(code, (subtest) => {
      const fixture = makePromotionFixture(subtest);
      rewritePromotion(fixture, mutate);
      assert.throws(() => loadRegistry({ repositoryRoot: fixture.root }), hasCode(code));
    });
  }
});

test("fully rehashed decision, readiness, and promotion substitutions still fail their exact cross-bindings", async (t) => {
  await t.test("decision status", (subtest) => {
    const fixture = makePromotionFixture(subtest);
    rewritePromotion(fixture, (receipt) => {
      receipt.policy.launchReadinessDecision.status = "analysis_pending";
      receipt.policy.launchReadinessDecision.outcome = null;
      rehashLaunchReadinessDecision(receipt);
    });
    assert.throws(() => loadRegistry({ repositoryRoot: fixture.root }), hasCode("PROMOTION_DECISION_INVALID"));
  });

  await t.test("decision application identity", (subtest) => {
    const fixture = makePromotionFixture(subtest);
    rewritePromotion(fixture, (receipt) => {
      const replacement = `sha256:${"f".repeat(64)}`;
      receipt.policy.launchReadinessDecision.expectedSubject.applicationSha256 = replacement;
      receipt.policy.launchReadinessDecision.currentSubject.applicationSha256 = replacement;
      rehashLaunchReadinessDecision(receipt);
    });
    assert.throws(() => loadRegistry({ repositoryRoot: fixture.root }), hasCode("PROMOTION_DECISION_INVALID"));
  });

  await t.test("accepted package root", (subtest) => {
    const fixture = makePromotionFixture(subtest);
    rewritePromotion(fixture, (receipt) => {
      const document = JSON.parse(Buffer.from(receipt.application.packagePreimage.applicationBytes.base64, "base64").toString("utf8"));
      document.title = "Bilaterally substituted and fully rehashed application root";
      const applicationBytes = Buffer.from(`${canonicalJson(document)}\n`, "utf8");
      const replacement = sha256(applicationBytes);
      receipt.application.packagePreimage.applicationBytes = {
        base64: applicationBytes.toString("base64"),
        byteLength: applicationBytes.length
      };
      receipt.application.applicationSha256 = replacement;
      receipt.policy.launchReadinessDecision.expectedSubject.applicationSha256 = replacement;
      receipt.policy.launchReadinessDecision.currentSubject.applicationSha256 = replacement;
      rehashLaunchReadinessDecision(receipt);
    });
    assert.throws(() => loadRegistry({ repositoryRoot: fixture.root }), hasCode("PROMOTION_APPLICATION_PACKAGE_MISMATCH"));
  });

  await t.test("readiness application revision", (subtest) => {
    const fixture = makePromotionFixture(subtest);
    rewritePromotion(fixture, (receipt) => {
      rehashReadinessDocument(receipt, (document) => { document.subject.applicationRevision = 2; });
    });
    assert.throws(() => loadRegistry({ repositoryRoot: fixture.root }), hasCode("PROMOTION_READINESS_MISMATCH"));
  });

  await t.test("promotion stamp", (subtest) => {
    const fixture = makePromotionFixture(subtest);
    rewritePromotion(fixture, (receipt) => {
      receipt.evidence.promotion.stampHash = `0x${"f".repeat(64)}`;
      receipt.evidence.promotionSha256 = canonicalDigest(receipt.evidence.promotion);
    });
    assert.throws(() => loadRegistry({ repositoryRoot: fixture.root }), hasCode("PROMOTION_EVIDENCE_PROJECTION_MISMATCH"));
  });
});

test("legacy, no-market, non-Ethereum, accepted, and deployed records remain outside the later gate", async (t) => {
  assert.doesNotThrow(() => loadRegistry({ repositoryRoot: root }));
  const cases = [
    ["no-market available", { removeMarket: true, status: "available" }],
    ["non-Ethereum available", { chainId: 10, status: "available" }],
    ["accepted", { status: "accepted" }],
    ["deployed", { chainState: "deployed", status: "deployed" }]
  ];
  for (const [name, options] of cases) {
    await t.test(name, (subtest) => {
      const fixture = makeAcceptedFixture(subtest, options);
      assert.doesNotThrow(() => loadRegistry({ repositoryRoot: fixture.root }));
    });
  }
});

test("finalized promotion evidence remains required through suspended and retired lifecycle states", async (t) => {
  for (const status of ["suspended", "retired"]) {
    await t.test(status, (subtest) => {
      const fixture = makePromotionFixture(subtest, { status });
      assert.doesNotThrow(() => loadRegistry({ repositoryRoot: fixture.root }));
      delete fixture.project.promotionPath;
      delete fixture.project.promotionSha256;
      writeJson(fixture.projectPath, fixture.project);
      assert.throws(() => loadRegistry({ repositoryRoot: fixture.root }), hasCode("PROMOTION_REQUIRED"));
    });
  }
});

test("promotion bindings change the full record digest and stale discovery artifacts fail closed", (t) => {
  const fixture = makePromotionFixture(t);
  assert.throws(() => verifyGeneratedArtifacts({ repositoryRoot: fixture.root }), hasCode("GENERATED_FILE_STALE"));
});

function copyFixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "programmable-registry-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  for (const relative of ["intake", "registry", "scripts", "vendor"]) {
    fs.cpSync(path.join(root, relative), path.join(directory, relative), { recursive: true });
  }
  return directory;
}

function makeAcceptedFixture(t, { chainId = 1, chainState = "available", removeMarket = false, status = "available" } = {}) {
  const fixtureRoot = copyFixture(t);
  const projectPath = path.join(fixtureRoot, "registry/projects/classic/project.json");
  const project = readJson(fixtureRoot, "registry/projects/classic/project.json");
  project.provenance.recordClass = "maintainer-acceptance";
  project.review = {
    acceptancePath: "registry/acceptances/classic/1.json",
    applicationPullRequest: "https://github.com/0xprogrammable/launch-policy/pull/7",
    independentAudit: false,
    limitations: ["Maintainer acceptance and launch provenance are not safety or audit claims."],
    state: new Set(["suspended", "retired"]).has(status) ? status : "accepted"
  };
  project.status = status;
  project.statusUpdatedAt = "2026-08-20T12:00:00Z";
  project.chains = [{
    chainId,
    deploymentEvidence: "https://developers.programmable.family/api/v2/manifest",
    network: chainId === 1 ? "Ethereum Mainnet" : "OP Mainnet",
    state: chainState
  }];
  if (removeMarket) project.surfaces = project.surfaces.filter((surface) => surface !== "uniswap-v4-pool");

  const acceptance = {
    acceptedAt: "2026-08-20T10:00:00Z",
    acceptedBy: "0xprogrammable",
    application: {
      applicationId: "classic",
      applicationRevision: 1,
      packageDigest: `sha256:${"a".repeat(64)}`,
      pullRequest: "https://github.com/0xprogrammable/launch-policy/pull/7"
    },
    conditions: ["Finalized launch provenance remains a separate later promotion fact."],
    decision: "accepted-for-registry-promotion",
    projectRecordPath: "registry/projects/classic/project.json",
    schemaVersion: "1.0.0",
    source: {
      numericRepositoryId: project.source.numericRepositoryId,
      repositoryUri: project.source.repositoryUri,
      revisionObjectId: project.source.revisionObjectId,
      treeObjectId: project.source.treeObjectId
    }
  };
  const acceptancePath = path.join(fixtureRoot, project.review.acceptancePath);
  writeJson(acceptancePath, acceptance);
  writeJson(projectPath, project);
  return { acceptance, acceptancePath, project, projectPath, root: fixtureRoot };
}

function makePromotionFixture(t, { status = "available" } = {}) {
  const fixture = makeAcceptedFixture(t, { status });
  let acceptanceBytes = fs.readFileSync(fixture.acceptancePath);
  const promotion = makePromotionRecord(fixture.project, fixture.acceptance, sha256(acceptanceBytes));
  fixture.acceptance.application.packageDigest = promotion.application.packageDigest;
  writeJson(fixture.acceptancePath, fixture.acceptance);
  acceptanceBytes = fs.readFileSync(fixture.acceptancePath);
  promotion.acceptance.sha256 = sha256(acceptanceBytes);
  const promotionPath = path.join(fixture.root, `registry/promotions/classic/${promotion.launch.launchId}.json`);
  writeJson(promotionPath, promotion);
  fixture.project.promotionPath = path.relative(fixture.root, promotionPath).split(path.sep).join("/");
  fixture.project.promotionSha256 = sha256(fs.readFileSync(promotionPath));
  writeJson(fixture.projectPath, fixture.project);
  return { ...fixture, promotion, promotionPath };
}

function makePromotionRecord(project, acceptance, acceptanceSha256) {
  const router = "0x8622DD5bAb44185f2A458ac90384Ac99248f8d56";
  const graphFactory = "0xB012e4A8F2c5FC4E8E4faCA9D5Ad6FfF13FBA887";
  const poolManager = "0x000000000004444c5dc75cB358380D2e3dE08A90";
  const token = "0x9DEeB39D2590b0cAD5fc473F755C5F97Dcc8f7cE";
  const hook = "0xEBa46f25DfF528141dE5317109Acb5A989296044";
  const launchId = "0x5a52180427785716bff0a36218dde89f0459db265d0c2bdfcfde81a8fe733c92";
  const stampHash = "0x06cb71b38d9b8b1dd1ffcdb00f31c774be36f5473979c3831d5fd0c96cdaa579";
  const poolId = "0x5c5a3ebee6840640642ba2bea526621a4962d2c89c388c36a2edb4725802a229";
  const promotion = {
    acceptance: { path: project.review.acceptancePath, sha256: acceptanceSha256 },
    application: {
      ...acceptance.application,
      applicationSha256: `sha256:${"0".repeat(64)}`,
      packagePreimage: {
        applicationBytes: { base64: "e30K", byteLength: 3 }
      }
    },
    authority: {
      auditClaim: false,
      currentLiquidityClaim: false,
      currentTradabilityClaim: false,
      fundsAuthority: false,
      launchAuthority: false,
      registryWriteAuthority: false,
      safetyClaim: false,
      sellabilityClaim: false,
      terminalSupportClaim: false
    },
    componentProofs: [
      { component: hook, componentRole: "hook", launchId, stampHash },
      { component: token, componentRole: "token", launchId, stampHash }
    ],
    economics: {
      basis: "gross-canonical-pool-volume",
      bps: 10,
      hundredthsOfBip: 1000,
      treasury: PROGRAMMABLE_FEE_OWNER
    },
    evidence: {
      promotion: {},
      promotionId: "programmable-router-promotion",
      promotionSha256: `sha256:${"2".repeat(64)}`,
      readinessBytes: { base64: "e30K", byteLength: 3 },
      readinessId: "programmable-router-readiness",
      readinessSha256: `sha256:${"3".repeat(64)}`
    },
    launch: {
      componentSetHash: `0x${"4".repeat(64)}`,
      expectedResultHash: `0x${"5".repeat(64)}`,
      hook,
      launchId,
      launchKind: 1,
      permitDigest: `0x${"6".repeat(64)}`,
      poolId,
      poolKeyHash: `0x${"7".repeat(64)}`,
      poolManager,
      routeLauncher: graphFactory,
      routeLauncherRuntimeCodeHash: "0xd23692fae59331592048e71a96d4963e170ee56e449683dc9f7fa3f9470018b8",
      routePayloadHash: `0x${"8".repeat(64)}`,
      stampHash,
      token
    },
    lookups: {
      pool: { launchId, poolId, poolManager },
      token: { address: token, launchId }
    },
    manifest: {
      abiSha256: "sha256:bb4e728e9f9c850eb01f928e8a798ac206a82e241a8d93b3b3c686635c88ed86",
      abiUrl: "https://developers.programmable.family/abis/ethereum/programmable-launch-stamp-router-v1.json",
      bindings: {
        graphFactory,
        graphFactoryRuntimeCodeHash: "0xd23692fae59331592048e71a96d4963e170ee56e449683dc9f7fa3f9470018b8",
        permitAuthority: "0x755509eA6e3F5Ec1aA2E797bb68f1B87DD8b886b",
        permitAuthorityRuntimeCodeHash: "0xd7d408ebcd99b2b70be43e20253d6d92a8ea8fab29bd3be7f55b10032331fb4c",
        poolManager,
        poolManagerRuntimeCodeHash: "0x785f1014552b7ce7d5fb7d0c970ca60edee94fd00425d7ca21609acac7ce1293"
      },
      chainId: 1,
      deploymentEvidenceSha256: "sha256:f9786ebfb74c96a3c225567ad324f0fbecfd8520b8d8addec85ba58cd67e19ff",
      endBlock: null,
      finalityConfirmations: 64,
      jsonPointer: "/launchStampRouter",
      manifestSha256: PROGRAMMABLE_LAUNCH_ROUTER_V1_DEVELOPER_REFERENCE.deploymentManifest.sha256,
      manifestUrl: "https://developers.programmable.family/api/v2/manifest",
      routerAddress: router,
      runtimeCodeHash: "0x40e27ecf201761d5eb66bc4f2d5c6124831ef078d7baf458ca5f41b1a8108546",
      startBlock: "25717612",
      status: "live",
      wellKnownUrl: "https://developers.programmable.family/.well-known/programmable.json"
    },
    observation: {
      blockHash: "0x97827b6586f0dca00e44801acc529c3961b4c693988dfc9f4b2bb4c3d94632ba",
      blockNumber: "25717953",
      eventEmitter: router,
      finality: "finalized",
      finalizedAtBlockHash: `0x${"a".repeat(64)}`,
      finalizedAtBlockNumber: "25718017",
      logIndex: "42",
      observedAt: "2026-08-20T12:00:00Z",
      outcome: "stamped",
      routerAddress: router,
      routerRuntimeCodeHash: "0x40e27ecf201761d5eb66bc4f2d5c6124831ef078d7baf458ca5f41b1a8108546",
      rpcEvidenceSha256: `sha256:${"b".repeat(64)}`,
      transactionHash: "0xc07b4e70233534a1d4f435ffc9a636ed5f542f4aedcde35052c58224f378b612",
      transactionIndex: "17",
      transactionTo: router,
      verificationMode: "canonical-router-point-lookup-v1"
    },
    policy: {
      baseCommit: "1".repeat(40),
      baseTree: "2".repeat(40),
      gitBlobOid: "3".repeat(40),
      launchReadinessDecision: {},
      launchReadinessDecisionSha256: `sha256:${"c".repeat(64)}`,
      numericRepositoryId: "1320171831",
      path: "policy/launch-policy.v1.json",
      policyId: "programmable-central-launch-policy",
      policyVersion: "2.1.0",
      profileId: "launch-readiness",
      repository: "0xprogrammable/launch-policy",
      sha256: `sha256:${"d".repeat(64)}`
    },
    projectId: project.id,
    routePlan: {
      chainId: 1,
      configurationHash: `sha256:${"1".repeat(64)}`,
      directFactoryCall: false,
      executionPath: "canonical-launch-stamp-router-v1",
      gitBlobOid: "4".repeat(40),
      launchKind: 1,
      path: PROGRAMMABLE_LAUNCH_ROUTER_READINESS_PATH,
      sha256: `sha256:${"e".repeat(64)}`
    },
    schemaVersion: "1.0.0",
    source: {
      commit: project.source.revisionObjectId,
      configurationHash: `sha256:${"1".repeat(64)}`,
      numericRepositoryId: project.source.numericRepositoryId,
      repository: project.source.repositoryUri,
      tree: project.source.treeObjectId
    },
    verifiedAt: "2026-08-20T12:00:00Z"
  };
  bindValidPromotionEvidence(promotion);
  return promotion;
}

function bindValidPromotionEvidence(promotion) {
  const readiness = buildPromotionReadiness(promotion);
  verifyProgrammableLaunchRouterReadinessBytesV1(readiness.bytes);
  promotion.source.configurationHash = readiness.configurationHash;
  promotion.routePlan.configurationHash = readiness.configurationHash;
  promotion.routePlan.launchKind = promotion.launch.launchKind;
  promotion.routePlan.path = PROGRAMMABLE_LAUNCH_ROUTER_READINESS_PATH;
  promotion.routePlan.sha256 = sha256(readiness.bytes);
  promotion.routePlan.gitBlobOid = gitBlobOid(readiness.bytes);
  promotion.launch.componentSetHash = readiness.componentSetHash;
  promotion.launch.expectedResultHash = readiness.expectedResultHash;
  promotion.launch.poolKeyHash = readiness.poolKeyHash;
  promotion.launch.routePayloadHash = readiness.routePayloadHash;
  promotion.evidence.readinessBytes = {
    base64: readiness.bytes.toString("base64"),
    byteLength: readiness.bytes.length
  };
  promotion.evidence.readinessSha256 = promotion.routePlan.sha256;
  bindValidApplicationPackagePreimage(promotion);
  promotion.policy.launchReadinessDecision = makeLaunchReadinessDecision(promotion);
  promotion.policy.launchReadinessDecisionSha256 = promotion.policy.launchReadinessDecision.digest;
  promotion.evidence.promotion = makePromotionEvidenceProjection(promotion);
  promotion.evidence.promotionSha256 = canonicalDigest(promotion.evidence.promotion);
}

function bindValidApplicationPackagePreimage(promotion) {
  const sourceRepository = promotion.source.repository.slice("https://github.com/".length);
  const proposalBytes = Buffer.from("# Proposal\n\nCanonical package evidence.\n", "utf8");
  const applicationDocument = {
    applicationId: promotion.application.applicationId,
    applicationRevision: String(promotion.application.applicationRevision),
    contract: {
      id: "public-pr-application-v3",
      submissionStandard: "2.1.0",
      validatorProfile: "intent-open-world-v2",
      version: "3.2.0"
    },
    launchRequest: {
      category: promotion.launch.launchKind === 1 ? "custom" : "classic",
      launchKind: promotion.launch.launchKind,
      requestedRoute: "programmable-ethereum-mainnet",
      routePlan: {
        byteLength: promotion.evidence.readinessBytes.byteLength,
        gitBlobOid: promotion.routePlan.gitBlobOid,
        path: promotion.routePlan.path,
        repositoryRef: {
          commit: promotion.source.commit,
          numericRepositoryId: promotion.source.numericRepositoryId,
          repository: sourceRepository,
          tree: promotion.source.tree
        },
        schemaId: "urn:programmable:launch-router-readiness:1.0.0",
        sha256: promotion.evidence.readinessSha256
      },
      routerReadinessSchema: null
    },
    reviewPackage: {
      records: [
        {
          byteLength: proposalBytes.length,
          kind: "proposal",
          mediaType: "text/markdown",
          path: "PROPOSAL.md",
          repositoryRef: null,
          sha256: sha256(proposalBytes),
          source: "application-package"
        },
        {
          byteLength: promotion.evidence.readinessBytes.byteLength,
          kind: "programmable-launch-router-readiness",
          mediaType: "application/json",
          path: promotion.routePlan.path,
          repositoryRef: "primary",
          sha256: promotion.evidence.readinessSha256,
          source: "source-repository"
        }
      ]
    },
    schemaVersion: 3,
    source: {
      primary: {
        id: "primary",
        numericRepositoryId: promotion.source.numericRepositoryId,
        repositoryUri: promotion.source.repository,
        revisionObjectId: promotion.source.commit,
        treeObjectId: promotion.source.tree
      },
      verificationReports: [{
        closureSha256: promotion.source.configurationHash,
        repositoryRef: "primary",
        result: "VERIFIED",
        revisionObjectId: promotion.source.commit,
        treeObjectId: promotion.source.tree
      }]
    },
    title: "Canonical test application"
  };
  const applicationBytes = Buffer.from(`${canonicalJson(applicationDocument)}\n`, "utf8");
  const applicationRecords = applicationDocument.reviewPackage.records
    .filter(({ source }) => source === "application-package")
    .map(({ path: recordPath, mediaType, byteLength, sha256: recordSha256 }) => ({
      path: recordPath,
      mediaType,
      byteLength,
      sha256: recordSha256
    }));
  const packageBinding = derivePublicApplicationV3PackageBindingV1({
    application: applicationDocument,
    applicationBytes,
    applicationRecords
  });
  promotion.application.applicationSha256 = packageBinding.applicationSha256;
  promotion.application.packageDigest = packageBinding.packageSha256;
  promotion.application.packagePreimage = {
    applicationBytes: {
      base64: applicationBytes.toString("base64"),
      byteLength: applicationBytes.length
    }
  };
}

function buildPromotionReadiness(promotion) {
  const feeImplementationArtifact = testArtifact("src/FeeConfiguration.sol", "d", "e", 4096);
  const routeArtifact = testArtifact("src/LaunchRoute.sol", "f", "1", 8192);
  const configurationHash = deriveProgrammableLaunchRouterSourceConfigurationHashV1({
    feeImplementationArtifact,
    routeArtifact
  });
  const category = promotion.launch.launchKind === 1 ? "custom" : "classic";
  const stampRequest = makeReadinessStampRequest({
    category,
    hook: promotion.launch.hook,
    launchId: promotion.launch.launchId,
    token: promotion.launch.token
  });
  const routeCommitment = computeProgrammableLaunchRouterRouteCommitmentV1({
    category,
    routePayload: makeReadinessRoutePayload({ category, promotion, stampRequest })
  });
  const routePayload = {
    byteLength: routeCommitment.byteLength,
    contentBase64: routeCommitment.contentBase64,
    encoding: routeCommitment.encoding,
    keccak256: routeCommitment.keccak256,
    sha256: routeCommitment.sha256
  };
  const expectedResult = {
    derivationMode: "router-v1-route-kind-specific-typed-hash",
    hash: routeCommitment.expectedResultHash,
    routePayloadSha256: routePayload.sha256
  };
  const liveResponse = Buffer.from(`${canonicalProgrammableLaunchRouterReadinessJson(PROGRAMMABLE_LAUNCH_ROUTER_V1_MANIFEST_PROJECTION)}\n`, "utf8");
  const sourceRepository = promotion.source.repository.slice("https://github.com/".length);
  const subject = {
    applicationId: promotion.application.applicationId,
    applicationRevision: promotion.application.applicationRevision,
    sourceCommit: promotion.source.commit,
    sourceConfigurationHash: configurationHash,
    sourceRepository,
    sourceRepositoryNumericId: promotion.source.numericRepositoryId,
    sourceTree: promotion.source.tree
  };
  const document = {
    $schema: PROGRAMMABLE_LAUNCH_ROUTER_READINESS_SCHEMA_ID,
    applicability: {
      routeMode: "programmable-ethereum-mainnet",
      trustedDeclaration: null
    },
    authority: readinessAuthority(),
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
      treasury: PROGRAMMABLE_FEE_OWNER
    },
    kind: "programmable-launch-router-readiness",
    manifestSnapshot: {
      discoveryDocumentUrl: "https://developers.programmable.family/.well-known/programmable.json",
      liveResponseBase64: liveResponse.toString("base64"),
      liveResponseBindingScope: "time-bound-pointer-projection-not-origin-or-freshness-proof",
      liveResponseByteLength: liveResponse.length,
      liveResponseContentKind: "canonical-json-pointer-projection-v1",
      liveResponseSha256: sha256(liveResponse),
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
      category,
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
          kind: promotion.launch.launchKind,
          launchWallet: null,
          nonce: `0x${"9".repeat(64)}`,
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
      launchKind: promotion.launch.launchKind,
      launchWallet: {
        address: null,
        bindingState: "late-bound-before-permit-signing",
        immutableAfterPermitSigning: true,
        mustEqualTransactionSender: true
      },
      routeKind: category === "custom" ? "custom-graph" : "classic",
      sourceIdentity: {
        artifact: routeArtifact,
        commit: promotion.source.commit,
        configurationHash,
        numericRepositoryId: promotion.source.numericRepositoryId,
        repository: sourceRepository,
        tree: promotion.source.tree
      },
      transactionSelector: PROGRAMMABLE_LAUNCH_ROUTER_V1_RESOLVED_ROUTER.atomicSelector,
      transactionTarget: PROGRAMMABLE_LAUNCH_ROUTER_V1_RESOLVED_ROUTER.address
    },
    schemaVersion: "1.0.0",
    state: "prelaunch-bound",
    subject
  };
  const bytes = Buffer.from(`${canonicalProgrammableLaunchRouterReadinessJson(document)}\n`, "utf8");
  return {
    bytes,
    componentSetHash: stampRequest.componentSetHash,
    configurationHash,
    expectedResultHash: expectedResult.hash,
    poolKeyHash: stampRequest.poolKeyHash,
    routePayloadHash: routePayload.keccak256
  };
}

function makeReadinessStampRequest({ category, hook, launchId, token }) {
  const tokenRuntimeCodeHash = `0x${"a".repeat(64)}`;
  const hookRuntimeCodeHash = `0x${"b".repeat(64)}`;
  const components = (category === "custom"
    ? [
        { account: token, kind: 1, resultIndex: 0, runtimeCodeHash: tokenRuntimeCodeHash, scope: 1 },
        { account: hook, kind: 2, resultIndex: 1, runtimeCodeHash: hookRuntimeCodeHash, scope: 1 }
      ]
    : [
        { account: token, kind: 1, resultIndex: 0, runtimeCodeHash: tokenRuntimeCodeHash, scope: 1 },
        { account: "0x0000000000000000000000000000000000000002", kind: 0, resultIndex: 1, runtimeCodeHash: `0x${"c".repeat(64)}`, scope: 1 },
        { account: "0x0000000000000000000000000000000000000003", kind: 0, resultIndex: 2, runtimeCodeHash: `0x${"d".repeat(64)}`, scope: 1 },
        { account: hook, kind: 2, resultIndex: 255, runtimeCodeHash: hookRuntimeCodeHash, scope: 2 }
      ])
    .sort((left, right) => Buffer.compare(Buffer.from(left.account.toLowerCase()), Buffer.from(right.account.toLowerCase())));
  const request = {
    components,
    hookRuntimeCodeHash,
    launchId,
    poolKey: {
      currency0: "0x0000000000000000000000000000000000000006",
      currency1: token,
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

function makeReadinessRoutePayload({ category, promotion, stampRequest }) {
  if (category === "custom") {
    return {
      expectedGraphDeploymentHash: `0x${"e".repeat(64)}`,
      expectedOutputs: [
        {
          account: promotion.launch.token,
          runtimeCodeHash: stampRequest.tokenRuntimeCodeHash,
          targetIdHash: `0x${"c".repeat(64)}`,
          targetIndex: 0
        },
        {
          account: promotion.launch.hook,
          runtimeCodeHash: stampRequest.hookRuntimeCodeHash,
          targetIdHash: `0x${"d".repeat(64)}`,
          targetIndex: 1
        }
      ],
      graphCommitment: `0x${"3".repeat(64)}`,
      routeNamespace: `0x${"1".repeat(64)}`,
      routeNonce: `0x${"9".repeat(64)}`,
      targets: [
        {
          applicantSalt: `0x${"0".repeat(64)}`,
          deploymentValue: "0",
          initCode: "0x6000",
          initializerCalldata: "0x",
          initializerValue: "0",
          targetIdHash: `0x${"c".repeat(64)}`
        },
        {
          applicantSalt: `0x${"0".repeat(64)}`,
          deploymentValue: "0",
          initCode: "0x6001",
          initializerCalldata: "0x",
          initializerValue: "0",
          targetIdHash: `0x${"d".repeat(64)}`
        }
      ],
      topologyHash: `0x${"2".repeat(64)}`
    };
  }
  return {
    expectedResult: {
      initialBuyCustody: "0x0000000000000000000000000000000000000000",
      initialBuyNativeAmount: "0",
      initialBuyTokenAmount: "1",
      launchHash: `0x${"7".repeat(64)}`,
      lockedTokenDust: "0",
      poolId: computeProgrammableLaunchRouterPoolIdV1(stampRequest.poolKey),
      positionRecipient: "0x0000000000000000000000000000000000000003",
      positionTokenId: "1",
      rewardVault: "0x0000000000000000000000000000000000000002",
      token: promotion.launch.token,
      tokenLiquidityAmount: "1"
    },
    launcher: promotion.launch.routeLauncher,
    launcherRuntimeCodeHash: promotion.launch.routeLauncherRuntimeCodeHash,
    parameters: {
      buySwapFeeBps: 100,
      creatorSalt: `0x${"0".repeat(64)}`,
      initialBuyCustody: { cliffDays: 0, durationDays: 0, mode: 0 },
      metadata: {
        description: "Generic launch",
        extraData: "0x",
        image: "",
        website: ""
      },
      name: "Generic Launch",
      rewardBeneficiaries: ["0x0000000000000000000000000000000000000007"],
      rewardSharesBps: [10000],
      sellSwapFeeBps: 100,
      symbol: "GEN"
    }
  };
}

function makeLaunchReadinessDecision(promotion) {
  const trustedPolicy = {
    baseCommit: promotion.policy.baseCommit,
    baseTree: promotion.policy.baseTree,
    gitBlobOid: promotion.policy.gitBlobOid,
    numericRepositoryId: promotion.policy.numericRepositoryId,
    path: promotion.policy.path,
    policyId: promotion.policy.policyId,
    policyVersion: promotion.policy.policyVersion,
    profileId: promotion.policy.profileId,
    repository: promotion.policy.repository,
    sha256: promotion.policy.sha256
  };
  const policyBinding = {
    ...trustedPolicy,
    schemaVersion: "programmable.launch-policy-binding.v1"
  };
  const subject = {
    applicationId: promotion.application.applicationId,
    applicationRevision: promotion.application.applicationRevision,
    applicationSha256: promotion.application.applicationSha256,
    commit: promotion.source.commit,
    configurationHash: promotion.source.configurationHash,
    numericRepositoryId: promotion.source.numericRepositoryId,
    packageSha256: promotion.application.packageDigest,
    repository: promotion.source.repository.slice("https://github.com/".length),
    routerProvenanceRequired: true,
    tree: promotion.source.tree,
    usesUniswapV4: true
  };
  const evaluations = [
    {
      analyzer: { id: "ethereum-treasury-10-bps-v1", kind: "deterministic" },
      evidenceRefs: [promotion.evidence.readinessSha256],
      ruleId: "LAUNCH.ETHEREUM_AND_TREASURY_10_BPS",
      state: "passed"
    },
    {
      analyzer: { id: "programmable-router-readiness-v1", kind: "deterministic" },
      evidenceRefs: [promotion.evidence.readinessSha256],
      ruleId: "LAUNCH.ETHEREUM_ROUTER_PROVENANCE_READINESS",
      state: "passed"
    }
  ].sort((left, right) => Buffer.compare(Buffer.from(canonicalJson(left)), Buffer.from(canonicalJson(right))));
  const withoutDigest = {
    advisories: [],
    authority: {
      checkerOnly: true,
      independentAudit: false,
      launchAuthorized: false,
      publicRoutingAuthorized: false,
      realFundsAuthorized: false
    },
    currentPolicyBinding: structuredClone(policyBinding),
    currentSubject: structuredClone(subject),
    evaluations,
    expectedPolicyBinding: structuredClone(policyBinding),
    expectedSubject: structuredClone(subject),
    findings: [],
    notApplicableRuleIds: [],
    outcome: "LAUNCH_READINESS_CHECKED_NOT_AUTHORIZED",
    pendingRuleIds: [],
    profileId: "launch-readiness",
    schemaVersion: "programmable.launch-policy-review-decision.v1",
    status: "passed",
    trustedPolicy
  };
  return { ...withoutDigest, digest: canonicalDigest(withoutDigest) };
}

function makePromotionEvidenceProjection(promotion) {
  return {
    abiSha256: promotion.manifest.abiSha256,
    blockHash: promotion.observation.blockHash,
    blockNumber: Number(promotion.observation.blockNumber),
    canonicalBlockFinalized: true,
    chainId: 1,
    componentSetHash: promotion.launch.componentSetHash,
    confirmations: Number(BigInt(promotion.observation.finalizedAtBlockNumber) - BigInt(promotion.observation.blockNumber)),
    discoveryDocumentUrl: promotion.manifest.wellKnownUrl,
    expectedResultHash: promotion.launch.expectedResultHash,
    finalityConfirmations: promotion.manifest.finalityConfirmations,
    hook: promotion.launch.hook,
    launchId: promotion.launch.launchId,
    launchKind: promotion.launch.launchKind,
    lookupMatched: true,
    manifestSha256: promotion.manifest.manifestSha256,
    manifestUrl: promotion.manifest.manifestUrl,
    permitDigest: promotion.launch.permitDigest,
    poolId: promotion.launch.poolId,
    poolManager: promotion.launch.poolManager,
    promotionEvidenceSha256: promotion.observation.rpcEvidenceSha256,
    promotionTargets: ["api-v2", "indexer", "public-discovery", "registry"],
    routeBindingMatched: true,
    routeLauncher: promotion.launch.routeLauncher,
    routeLauncherRuntimeCodeHash: promotion.launch.routeLauncherRuntimeCodeHash,
    routePayloadHash: promotion.launch.routePayloadHash,
    routerAddress: promotion.manifest.routerAddress,
    routerManifestPointer: promotion.manifest.jsonPointer,
    routerRuntimeCodeHash: promotion.manifest.runtimeCodeHash,
    sourceCommit: promotion.source.commit,
    sourceConfigurationHash: promotion.source.configurationHash,
    sourceDeploymentBindingSha256: promotion.manifest.deploymentEvidenceSha256,
    sourceTree: promotion.source.tree,
    stampHash: promotion.launch.stampHash,
    stampProofMatched: true,
    status: "passed",
    token: promotion.launch.token,
    transactionHash: promotion.observation.transactionHash
  };
}

function readinessAuthority() {
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

function testArtifact(artifactPath, blobCharacter, shaCharacter, byteLength) {
  return {
    byteLength,
    gitBlobOid: blobCharacter.repeat(40),
    path: artifactPath,
    sha256: `sha256:${shaCharacter.repeat(64)}`
  };
}

function rewritePromotion(fixture, mutate) {
  mutate(fixture.promotion);
  writeJson(fixture.promotionPath, fixture.promotion);
  fixture.project.promotionSha256 = sha256(fs.readFileSync(fixture.promotionPath));
  writeJson(fixture.projectPath, fixture.project);
}

function rebindPromotionAcceptance(fixture) {
  fixture.acceptance.application.packageDigest = fixture.promotion.application.packageDigest;
  writeJson(fixture.acceptancePath, fixture.acceptance);
  fixture.promotion.acceptance.sha256 = sha256(fs.readFileSync(fixture.acceptancePath));
  writeJson(fixture.promotionPath, fixture.promotion);
  fixture.project.promotionSha256 = sha256(fs.readFileSync(fixture.promotionPath));
  writeJson(fixture.projectPath, fixture.project);
}

function rehashLaunchReadinessDecision(receipt) {
  const decision = receipt.policy.launchReadinessDecision;
  const withoutDigest = Object.fromEntries(Object.entries(decision).filter(([key]) => key !== "digest"));
  decision.digest = canonicalDigest(withoutDigest);
  receipt.policy.launchReadinessDecisionSha256 = decision.digest;
}

function rehashReadinessDocument(receipt, mutate) {
  const document = JSON.parse(Buffer.from(receipt.evidence.readinessBytes.base64, "base64").toString("utf8"));
  mutate(document);
  const bytes = Buffer.from(`${canonicalProgrammableLaunchRouterReadinessJson(document)}\n`, "utf8");
  receipt.evidence.readinessBytes = { base64: bytes.toString("base64"), byteLength: bytes.length };
  receipt.evidence.readinessSha256 = sha256(bytes);
  receipt.routePlan.sha256 = receipt.evidence.readinessSha256;
  receipt.routePlan.gitBlobOid = gitBlobOid(bytes);
  for (const evaluation of receipt.policy.launchReadinessDecision.evaluations) {
    evaluation.evidenceRefs = [receipt.evidence.readinessSha256];
  }
  rehashLaunchReadinessDecision(receipt);
}

function readJson(repositoryRoot, relativePath) {
  return JSON.parse(fs.readFileSync(path.join(repositoryRoot, relativePath), "utf8"));
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function sha256(bytes) {
  return `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
}

function canonicalDigest(value) {
  return sha256(Buffer.from(canonicalJson(value), "utf8"));
}

function gitBlobOid(bytes) {
  const value = Buffer.from(bytes);
  return crypto.createHash("sha1")
    .update(Buffer.from(`blob ${value.length}\0`, "utf8"))
    .update(value)
    .digest("hex");
}

function hasCode(code) {
  return (error) => error instanceof RegistryError && error.code === code;
}
