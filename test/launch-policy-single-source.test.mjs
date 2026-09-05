import assert from "node:assert/strict";
import childProcess from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import Ajv2020 from "../scripts/test/schema-validator/node_modules/ajv/dist/2020.js";

import { verifyWebsiteCanaryEligibility } from "../scripts/canary-eligibility-core.mjs";
import {
  AUTHORITY_OWNERSHIP_MANIFEST_PATH,
  canonicalAuthorityJson,
  LaunchPolicyAuthorityOwnershipError,
  readLaunchPolicyAuthorityOwnership,
  verifyLaunchPolicyAuthorityOwnership
} from "../scripts/launch-policy-authority-ownership.mjs";
import {
  buildLaunchPolicyBinding,
  evaluateLaunchPolicyRules,
  readTrustedLaunchPolicyFromGit,
  rulesForProfile
} from "../scripts/launch-policy-core.mjs";
import { evaluateOpenReview } from "../review/open-review-engine.mjs";
import { evaluateTrustedLaunchPolicyReview } from "../review/launch-policy-review-core.mjs";

const root = path.resolve(import.meta.dirname, "..");
const canonicalPolicyPath = "policy/launch-policy.v1.json";

test("the closed ownership manifest separates business-policy authority from the V3 and V4 admission disclosures", () => {
  const report = verifyLaunchPolicyAuthorityOwnership({ repositoryRoot: root });
  const manifest = readLaunchPolicyAuthorityOwnership({ repositoryRoot: root });
  const validateManifest = new Ajv2020({ allErrors: true, strict: true }).compile(
    readJson("policy/schemas/launch-policy-authority-ownership.v1.schema.json")
  );

  assert.equal(validateManifest(manifest), true, JSON.stringify(validateManifest.errors));
  assert.deepEqual(report, {
    canonicalPolicyPath,
    entrypoints: manifest.entrypoints.length,
    files: Object.keys(manifest.fileSha256).length + 1,
    frozenVendorTree: "3b974b0bcb006e08d8f2504c783ac81f2ee3bd74",
    ok: true,
    rules: manifest.semanticRuleMap.length
  });
  assert.deepEqual(manifest.fileClasses["canonical-admission-policy"], [canonicalPolicyPath, "policy/robinhood-custom-launch-economics-v1.json"]);
  assert.deepEqual(manifest.fileClasses["current-admission-disclosure"], [
    "policy/custom-launch-admission-v3.json",
    "policy/custom-launch-admission-v4.1.json",
    "policy/custom-launch-admission-v4.json"
  ]);
  assert.deepEqual(manifest.fileClasses["authority-ownership-manifest"], [AUTHORITY_OWNERSHIP_MANIFEST_PATH]);
  assert.equal(manifest.canonicalPolicy.path, canonicalPolicyPath);
  assert.equal(manifest.canonicalPolicy.schemaPath, "policy/schemas/launch-policy.v1.schema.json");
  assert.deepEqual(manifest.boundedApplicantData, [
    {
      contract: "workflow-canary-application-v1",
      files: ["application.json"],
      rootPath: "canary-submissions"
    },
    {
      contract: "public-pr-application-v2-six-file-v1",
      files: ["PROPOSAL.md", "TEST_PLAN.md", "THREAT_MODEL.md", "application.json", "compatibility-report.json", "evidence-index.json"],
      rootPath: "submissions"
    },
    {
      contract: "public-pr-application-v3.1-immutable-revision-v1",
      layout: "application-v3-revision-tree",
      maximumFileBytes: 4_194_304,
      maximumFiles: 100,
      maximumPackageBytes: 12_582_912,
      rootFile: "application.v3.json",
      rootMaximumBytes: 262_144,
      rootPath: "submissions"
    },
    {
      contract: "public-pr-application-v3.2-immutable-revision-v1",
      layout: "application-v3-revision-tree",
      maximumFileBytes: 4_194_304,
      maximumFiles: 100,
      maximumPackageBytes: 12_582_912,
      rootFile: "application.v3.json",
      rootMaximumBytes: 262_144,
      rootPath: "submissions"
    }
  ]);
  const readinessEntrypoint = manifest.entrypoints.find(({ path: entrypointPath }) => (
    entrypointPath === "scripts/programmable-launch-router-readiness.mjs"
  ));
  assert.deepEqual(readinessEntrypoint, {
    frozenVendorImports: [
      "vendor/programmable-applicant-validator/scripts/evm-encoding-core.mjs",
      "vendor/programmable-v4-hook-builder/scripts/github-public-source-lossless-json.mjs"
    ],
    id: "programmable-router-readiness-cli",
    moduleClosure: [
      "scripts/programmable-launch-router-readiness-core.mjs",
      "scripts/programmable-launch-router-readiness.mjs"
    ],
    path: "scripts/programmable-launch-router-readiness.mjs",
    role: "launch-readiness"
  });
  for (const compatibilityPath of [
    ".programmable/applicant-compatibility.v1.json",
    ".programmable/applicant-compatibility.v2.json"
  ]) {
    assert.equal(
      manifest.publicProjections.find(({ path: projectionPath }) => projectionPath === compatibilityPath)?.kind,
      "public-contract",
      compatibilityPath
    );
  }
  const withoutV3_2 = structuredClone(manifest);
  withoutV3_2.boundedApplicantData.pop();
  assert.equal(validateManifest(withoutV3_2), false);
  const duplicateV3_1 = structuredClone(manifest);
  duplicateV3_1.boundedApplicantData.at(-1).contract = "public-pr-application-v3.1-immutable-revision-v1";
  assert.equal(validateManifest(duplicateV3_1), false);
  const widenedReadinessRole = structuredClone(manifest);
  widenedReadinessRole.entrypoints.find(({ path: entrypointPath }) => (
    entrypointPath === "scripts/programmable-launch-router-readiness.mjs"
  )).role = "launch-readiness-unbounded";
  assert.equal(validateManifest(widenedReadinessRole), false);
  assert.deepEqual(findForbiddenPolicyValueKeys(manifest), []);

  const policy = readJson(canonicalPolicyPath);
  assert.equal(policy.repository.name, "programmablehq/Launch-Policy");
  assert.equal(policy.repository.numericRepositoryId, "1320171831");
  assert.equal(policy.repository.branch, "main");
  assert.equal(policy.repository.path, canonicalPolicyPath);
  assert.equal(policy.effective.state, "current");
  assert.equal(fs.existsSync(path.join(root, "review/policy.v1.json")), false);
});

test("V3.2, both compatibility contracts, and the Router-readiness CLI cannot self-weaken their authority declarations", () => {
  withRepositoryCopy((repositoryRoot) => {
    const original = JSON.parse(readAt(repositoryRoot, AUTHORITY_OWNERSHIP_MANIFEST_PATH));

    const withoutV3_2 = structuredClone(original);
    withoutV3_2.boundedApplicantData = withoutV3_2.boundedApplicantData.filter(({ contract }) => (
      contract !== "public-pr-application-v3.2-immutable-revision-v1"
    ));
    writeAuthorityManifest(repositoryRoot, withoutV3_2);
    assert.throws(
      () => verifyLaunchPolicyAuthorityOwnership({ repositoryRoot }),
      (error) => error instanceof LaunchPolicyAuthorityOwnershipError
        && error.code === "AUTHORITY_OWNERSHIP_BOUNDED_DATA_INVALID"
    );

    const widenedReadinessRole = structuredClone(original);
    widenedReadinessRole.entrypoints.find(({ path: entrypointPath }) => (
      entrypointPath === "scripts/programmable-launch-router-readiness.mjs"
    )).role = "public-intake";
    writeAuthorityManifest(repositoryRoot, widenedReadinessRole);
    assert.throws(
      () => verifyLaunchPolicyAuthorityOwnership({ repositoryRoot }),
      (error) => error instanceof LaunchPolicyAuthorityOwnershipError
        && error.code === "AUTHORITY_OWNERSHIP_ENTRYPOINTS_INVALID"
    );

    const downgradedCompatibilityV2 = structuredClone(original);
    downgradedCompatibilityV2.publicProjections.find(({ path: projectionPath }) => (
      projectionPath === ".programmable/applicant-compatibility.v2.json"
    )).kind = "public-documentation";
    writeAuthorityManifest(repositoryRoot, downgradedCompatibilityV2);
    assert.throws(
      () => verifyLaunchPolicyAuthorityOwnership({ repositoryRoot }),
      (error) => error instanceof LaunchPolicyAuthorityOwnershipError
        && error.code === "AUTHORITY_OWNERSHIP_PROJECTIONS_INVALID"
    );

    const missingReadinessImport = structuredClone(original);
    missingReadinessImport.entrypoints.find(({ path: entrypointPath }) => (
      entrypointPath === "scripts/programmable-launch-router-readiness.mjs"
    )).frozenVendorImports = [
      "vendor/programmable-v4-hook-builder/scripts/github-public-source-lossless-json.mjs"
    ];
    writeAuthorityManifest(repositoryRoot, missingReadinessImport);
    assert.throws(
      () => verifyLaunchPolicyAuthorityOwnership({ repositoryRoot }),
      (error) => error instanceof LaunchPolicyAuthorityOwnershipError
        && error.code === "AUTHORITY_OWNERSHIP_IMPORT_CLOSURE_MISMATCH"
    );

    const orphanedPromotionConsumer = structuredClone(original);
    const promotionMapping = orphanedPromotionConsumer.semanticRuleMap.find(({ ruleId }) => (
      ruleId === "LAUNCH.ETHEREUM_FINALIZED_ROUTER_STAMP_BEFORE_PROMOTION"
    ));
    promotionMapping.consumers = promotionMapping.consumers.filter((consumer) => consumer !== "scripts/registry-core.mjs");
    writeAuthorityManifest(repositoryRoot, orphanedPromotionConsumer);
    assert.throws(
      () => verifyLaunchPolicyAuthorityOwnership({ repositoryRoot }),
      (error) => error instanceof LaunchPolicyAuthorityOwnershipError
        && error.code === "AUTHORITY_OWNERSHIP_MODULE_RULE_MISMATCH"
    );
  });
});

test("the ownership gate rejects an added YAML policy and an indirect imported admission gate", () => {
  withRepositoryCopy((repositoryRoot) => {
    const expectedOwnedFiles = verifyLaunchPolicyAuthorityOwnership({ repositoryRoot }).files;
    const boundedCanaryPath = "canary-submissions/ownership-probe/application.json";
    fs.mkdirSync(path.dirname(path.join(repositoryRoot, boundedCanaryPath)), { recursive: true });
    fs.writeFileSync(path.join(repositoryRoot, boundedCanaryPath), "{}\n", "utf8");
    gitAt(repositoryRoot, ["add", "--", boundedCanaryPath]);
    assert.equal(verifyLaunchPolicyAuthorityOwnership({ repositoryRoot }).files, expectedOwnedFiles + 1);
    gitAt(repositoryRoot, ["rm", "-f", "--", boundedCanaryPath]);

    const yamlPath = path.join(repositoryRoot, "config/private-admission-policy.yaml");
    fs.mkdirSync(path.dirname(yamlPath), { recursive: true });
    fs.writeFileSync(yamlPath, "checks:\n  - id: PRIVATE.BLOCK\n    effect: reject\n", "utf8");
    gitAt(repositoryRoot, ["add", "--", "config/private-admission-policy.yaml"]);
    assert.throws(
      () => verifyLaunchPolicyAuthorityOwnership({ repositoryRoot }),
      (error) => error instanceof LaunchPolicyAuthorityOwnershipError
        && error.code === "AUTHORITY_OWNERSHIP_FILE_SET_MISMATCH"
    );
    gitAt(repositoryRoot, ["rm", "-f", "--", "config/private-admission-policy.yaml"]);

    const privateModulePath = "scripts/private-admission-gate.mjs";
    const workflowPath = "scripts/workflow-canary-core.mjs";
    fs.writeFileSync(
      path.join(repositoryRoot, privateModulePath),
      "export function privateAdmissionGate() { throw new Error(\"PRIVATE_ADMISSION_FAILED\"); }\n",
      "utf8"
    );
    fs.writeFileSync(
      path.join(repositoryRoot, workflowPath),
      `import { privateAdmissionGate } from "./private-admission-gate.mjs";\n${readAt(repositoryRoot, workflowPath)}\nprivateAdmissionGate();\n`,
      "utf8"
    );
    gitAt(repositoryRoot, ["add", "--", privateModulePath, workflowPath]);
    assert.throws(
      () => verifyLaunchPolicyAuthorityOwnership({ repositoryRoot }),
      (error) => error instanceof LaunchPolicyAuthorityOwnershipError
        && error.code === "AUTHORITY_OWNERSHIP_FILE_SET_MISMATCH"
    );

    const manifest = JSON.parse(readAt(repositoryRoot, AUTHORITY_OWNERSHIP_MANIFEST_PATH));
    manifest.fileClasses["current-admission-implementation"].push(privateModulePath);
    manifest.fileClasses["current-admission-implementation"].sort(compareUtf8);
    manifest.fileSha256[privateModulePath] = digestFile(repositoryRoot, privateModulePath);
    manifest.fileSha256[workflowPath] = digestFile(repositoryRoot, workflowPath);
    fs.writeFileSync(
      path.join(repositoryRoot, AUTHORITY_OWNERSHIP_MANIFEST_PATH),
      `${canonicalAuthorityJson(manifest)}\n`,
      "utf8"
    );

    assert.throws(
      () => verifyLaunchPolicyAuthorityOwnership({ repositoryRoot }),
      (error) => error instanceof LaunchPolicyAuthorityOwnershipError
        && error.code === "AUTHORITY_OWNERSHIP_IMPORT_CLOSURE_MISMATCH"
    );

    for (const entrypoint of manifest.entrypoints.filter(({ moduleClosure }) => moduleClosure.includes(workflowPath))) {
      entrypoint.moduleClosure.push(privateModulePath);
      entrypoint.moduleClosure.sort(compareUtf8);
    }
    manifest.moduleOwnership.push({ path: privateModulePath, role: "runtime-control", semanticRuleIds: [] });
    manifest.moduleOwnership.sort((left, right) => compareUtf8(left.path, right.path));
    fs.writeFileSync(
      path.join(repositoryRoot, AUTHORITY_OWNERSHIP_MANIFEST_PATH),
      `${canonicalAuthorityJson(manifest)}\n`,
      "utf8"
    );
    assert.throws(
      () => verifyLaunchPolicyAuthorityOwnership({ repositoryRoot }),
      (error) => error instanceof LaunchPolicyAuthorityOwnershipError
        && error.code === "AUTHORITY_OWNERSHIP_CONTROL_MODULE_INVALID"
    );

    manifest.fileClasses["current-admission-implementation"] = manifest.fileClasses["current-admission-implementation"]
      .filter((modulePath) => modulePath !== privateModulePath);
    manifest.fileClasses["current-admission-support"].push(privateModulePath);
    manifest.fileClasses["current-admission-support"].sort(compareUtf8);
    manifest.moduleOwnership.find(({ path: modulePath }) => modulePath === privateModulePath).role = "pure-support";
    fs.writeFileSync(
      path.join(repositoryRoot, AUTHORITY_OWNERSHIP_MANIFEST_PATH),
      `${canonicalAuthorityJson(manifest)}\n`,
      "utf8"
    );
    assert.throws(
      () => verifyLaunchPolicyAuthorityOwnership({ repositoryRoot }),
      (error) => error instanceof LaunchPolicyAuthorityOwnershipError
        && error.code === "AUTHORITY_OWNERSHIP_SUPPORT_SEMANTICS_FORBIDDEN"
    );
  });
});

test("an executable module cannot self-classify as admission support or runtime control", () => {
  withRepositoryCopy((repositoryRoot) => {
    const privateModulePath = "scripts/private-admission-support.mjs";
    const importerPath = "scripts/compile-canary-eligibility.mjs";
    fs.writeFileSync(
      path.join(repositoryRoot, privateModulePath),
      "export function privateAdmissionSupport() { throw new Error(\"PRIVATE_ADMISSION_FAILED\"); }\n",
      "utf8"
    );
    const importerSource = readAt(repositoryRoot, importerPath);
    const privateImport = "import { privateAdmissionSupport } from \"./private-admission-support.mjs\";\n";
    fs.writeFileSync(
      path.join(repositoryRoot, importerPath),
      importerSource.startsWith("#!")
        ? `${importerSource.slice(0, importerSource.indexOf("\n") + 1)}${privateImport}${importerSource.slice(importerSource.indexOf("\n") + 1)}\nprivateAdmissionSupport();\n`
        : `${privateImport}${importerSource}\nprivateAdmissionSupport();\n`,
      "utf8"
    );
    gitAt(repositoryRoot, ["add", "--", privateModulePath, importerPath]);

    const manifest = JSON.parse(readAt(repositoryRoot, AUTHORITY_OWNERSHIP_MANIFEST_PATH));
    manifest.fileClasses["current-admission-support"].push(privateModulePath);
    manifest.fileClasses["current-admission-support"].sort(compareUtf8);
    manifest.fileSha256[privateModulePath] = digestFile(repositoryRoot, privateModulePath);
    manifest.fileSha256[importerPath] = digestFile(repositoryRoot, importerPath);
    for (const entrypoint of manifest.entrypoints.filter(({ moduleClosure }) => moduleClosure.includes(importerPath))) {
      entrypoint.moduleClosure.push(privateModulePath);
      entrypoint.moduleClosure.sort(compareUtf8);
    }
    manifest.moduleOwnership.push({ path: privateModulePath, role: "pure-support", semanticRuleIds: [] });
    manifest.moduleOwnership.sort((left, right) => compareUtf8(left.path, right.path));
    fs.writeFileSync(
      path.join(repositoryRoot, AUTHORITY_OWNERSHIP_MANIFEST_PATH),
      `${canonicalAuthorityJson(manifest)}\n`,
      "utf8"
    );

    assert.throws(
      () => verifyLaunchPolicyAuthorityOwnership({ repositoryRoot }),
      (error) => error instanceof LaunchPolicyAuthorityOwnershipError
        && error.code === "AUTHORITY_OWNERSHIP_SUPPORT_SEMANTICS_FORBIDDEN"
    );

    manifest.moduleOwnership.find(({ path: modulePath }) => modulePath === privateModulePath).role = "runtime-control";
    fs.writeFileSync(
      path.join(repositoryRoot, AUTHORITY_OWNERSHIP_MANIFEST_PATH),
      `${canonicalAuthorityJson(manifest)}\n`,
      "utf8"
    );
    assert.throws(
      () => verifyLaunchPolicyAuthorityOwnership({ repositoryRoot }),
      (error) => error instanceof LaunchPolicyAuthorityOwnershipError
        && error.code === "AUTHORITY_OWNERSHIP_CONTROL_MODULE_INVALID"
    );
  });
});

test("every semantic finding and handler maps bijectively to a central Rule ID", () => {
  const manifest = readLaunchPolicyAuthorityOwnership({ repositoryRoot: root });
  const policyRecord = trustedPolicyRecord();
  const policyIds = new Set(policyRecord.policy.rules.map(({ id }) => id));
  const activeMap = manifest.semanticRuleMap.filter(({ status }) => status === "active");
  const activeIds = new Set(activeMap.map(({ ruleId }) => ruleId));
  const activeRules = policyRecord.policy.rules.filter(({ status }) => status === "active");

  assert.equal(activeIds.size, activeMap.length);
  assert.deepEqual([...activeIds].sort(compareUtf8), activeRules.map(({ id }) => id).sort(compareUtf8));

  for (const rule of activeRules) {
    const mapping = activeMap.find(({ ruleId }) => ruleId === rule.id);
    assert.equal(mapping.handlerId, rule.enforcement.handlerId, rule.id);
    assert.deepEqual(mapping.profiles, [...rule.profiles].sort(compareUtf8), rule.id);
  }

  const expectedConsumers = {
    "LAUNCH.ETHEREUM_AND_TREASURY_10_BPS": [
      "review/launch-policy-review-core.mjs",
      "scripts/custom-launch-admission-v3-core.mjs",
      "scripts/launch-policy-core.mjs",
      "scripts/launch-policy-handlers.mjs",
      "scripts/programmable-launch-router-readiness-core.mjs",
      "scripts/registry-core.mjs",
      "scripts/verify-public-application-v3-core.mjs"
    ],
    "LAUNCH.ETHEREUM_EXACT_FEE_TEMPLATE_BEFORE_AUTHORIZATION": [
      "review/launch-policy-review-core.mjs",
      "scripts/launch-policy-core.mjs",
      "scripts/launch-policy-handlers.mjs"
    ],
    "LAUNCH.ETHEREUM_FINALIZED_ROUTER_STAMP_BEFORE_PROMOTION": [
      "review/launch-policy-review-core.mjs",
      "scripts/launch-policy-core.mjs",
      "scripts/launch-policy-handlers.mjs",
      "scripts/registry-core.mjs"
    ],
    "LAUNCH.ETHEREUM_FINALIZED_RUNTIME_FEE_SETTLEMENT_BEFORE_PROMOTION": [
      "review/launch-policy-review-core.mjs",
      "scripts/launch-policy-core.mjs",
      "scripts/launch-policy-handlers.mjs",
      "scripts/programmable-runtime-fee-settlement-proof-core.mjs",
      "scripts/programmable-runtime-fee-settlement-proof-validation.mjs"
    ],
    "LAUNCH.ETHEREUM_ROUTER_PROVENANCE_READINESS": [
      "review/launch-policy-review-core.mjs",
      "scripts/launch-policy-core.mjs",
      "scripts/launch-policy-handlers.mjs",
      "scripts/programmable-launch-router-readiness-core.mjs",
      "scripts/registry-core.mjs",
      "scripts/verify-public-application-v3-core.mjs"
    ],
    "LAUNCH.ETHEREUM_VERIFIED_EXECUTED_PLATFORM_FEE_BEFORE_AUTHORIZATION": [
      "review/launch-policy-review-core.mjs",
      "scripts/custom-launch-admission-v3-core.mjs",
      "scripts/launch-policy-core.mjs",
      "scripts/launch-policy-handlers.mjs"
    ]
  };
  for (const ruleId of [...policyIds].filter((id) => id.startsWith("LAUNCH.ROBINHOOD_"))) {
    expectedConsumers[ruleId] = [
      "scripts/custom-launch-admission-v4-core.mjs",
      "scripts/launch-policy-core.mjs",
      "scripts/launch-policy-handlers.mjs"
    ];
  }
  assert.deepEqual(
    Object.fromEntries(manifest.semanticRuleMap.map(({ consumers, ruleId }) => [ruleId, consumers])),
    expectedConsumers
  );

  for (const profileId of ["build", "workflow-canary"]) {
    const rules = rulesForProfile(policyRecord.policy, profileId);
    const baselineInput = currentReviewInput(policyRecord, profileId, rules);
    const baseline = evaluateTrustedLaunchPolicyReview({
      input: baselineInput,
      repositoryRoot: root,
      expectedBaseCommit: policyRecord.baseCommit
    });
    assert.equal(baseline.status, "passed");
    assert.deepEqual(baseline.findings, []);

    assert.deepEqual(rules, []);
  }

  // Production requirements are evaluable but remain strictly checker-only.
  const productionDecision = evaluateLaunchPolicyRules({
    policyRecord,
    profileId: "production-launch",
    subject: { routerProvenanceRequired: true, usesUniswapV4: true },
    evidence: passedEvidenceForRules(activeRules)
  });
  assert.equal(productionDecision.passed, false);
  assert.equal(productionDecision.outcome, null);
  assert.equal(productionDecision.results.length, 4);
  assert.equal(productionDecision.authority.launchAuthorized, false);

  const legacyDecision = evaluateOpenReview(readJson("review/examples/disclosed-high-fee.json"));
  assert.equal(legacyDecision.status, "analysis_pending");
  assert.deepEqual(
    [...new Set(legacyDecision.advisories.map(({ ruleId }) => ruleId))],
    ["LEGACY_V2.ADMISSION"]
  );
  for (const advisory of legacyDecision.advisories) assert.equal(policyIds.has(advisory.ruleId), false);
});

test("the receipt-bound vendored Hookbuilder is frozen legacy data, never current policy authority", () => {
  const receipt = readJson("vendor/receipt.json");
  assert.deepEqual(receipt, {
    commit: "7869f44aa8dcc7cefeb379b76118407d53384558",
    release: "v0.10.3",
    repository: "0xprogrammable/hookbuilder",
    schemaVersion: "1.0.0",
    skillTree: "3b974b0bcb006e08d8f2504c783ac81f2ee3bd74",
    source: "https://github.com/0xprogrammable/hookbuilder/tree/7869f44aa8dcc7cefeb379b76118407d53384558/skills/programmable-v4-hook-builder"
  });

  assert.equal(git([
    "status",
    "--porcelain",
    "--untracked-files=all",
    "--",
    "vendor/receipt.json",
    "vendor/programmable-v4-hook-builder"
  ]), "");
  const tree = git(["write-tree"]);
  const entry = git(["ls-tree", tree, "vendor/programmable-v4-hook-builder"]);
  assert.match(entry, new RegExp(`^040000 tree ${receipt.skillTree}\\tvendor/programmable-v4-hook-builder$`, "u"));
  assert.match(read("AGENTS.md"), /frozen, receipt-bound validation dependency for historical legacy V2/u);
  assert.match(read("AGENTS.md"), /cannot author current central-policy requirements/u);
});

test("frozen legacy V2 compatibility cannot become a current policy or Website eligibility", () => {
  const policyRecord = trustedPolicyRecord();
  const intakeStatus = readJson("docs/builder/intake-status.json");
  const registryConfig = readJson("registry/config.json");
  assert.equal(intakeStatus.state, "closed");
  assert.deepEqual(registryConfig.activeIntake, {
    baseBranch: "main",
    directory: "submissions",
    repository: "0xprogrammable/launch-policy",
    state: "closed"
  });
  for (const relativePath of ["README.md", "CONTRIBUTING.md", "docs/builder/PUBLIC_GITHUB_PR_BETA.md"]) {
    assert.match(read(relativePath), /closed|retired|historical/iu, relativePath);
  }
  assert.equal(policyRecord.policy.rules.some(({ id }) => id.startsWith("LEGACY_V2.")), false);
  assert.equal(policyRecord.policy.rules.some(({ id }) => id.startsWith("FROZEN_LEGACY_V2.")), false);
  assert.equal(
    rulesForProfile(policyRecord.policy, "workflow-canary").some(({ id }) => id.startsWith("LEGACY_V2.")),
    false
  );

  assert.throws(
    () => verifyWebsiteCanaryEligibility({ envelope: { schemaVersion: "programmable.launch-entitlement-envelope.v1" } }),
    (error) => error?.code === "CANARY_ENVELOPE_UNSUPPORTED"
  );
});

test("public docs separate the current API flow from historical GitHub eligibility", () => {
  const readme = read("README.md");
  const architecture = read("docs/ARCHITECTURE.md");
  const lifecycle = read("docs/REVIEW_LIFECYCLE.md");
  const beta = read("docs/builder/PUBLIC_GITHUB_PR_BETA.md");
  const agents = read("AGENTS.md");

  for (const [name, source] of [
    ["README", readme],
    ["architecture", architecture],
    ["lifecycle", lifecycle],
    ["public intake", beta],
    ["agent contract", agents]
  ]) {
    assert.match(source, /policy\/launch-policy\.v1\.json/u, `${name} must name the canonical business policy`);
  }
  assert.match(architecture, /current launch flow is: `\.well-known` → live capabilities → advertised checksum-bound CLI → `pack`/u);
  assert.match(lifecycle, /received -> validating[\s\S]*prepared -> simulating -> authorized -> submitted -> finalized/u);
  assert.match(lifecycle, /awaiting_funding_authorization -> funding_authorization_verified/u);
  assert.match(lifecycle, /Preserved compatibility and promotion evidence states/u);
  assert.match(architecture, /checked-in namespaces are now immutable and\s+accept no new revisions/u);
  assert.match(agents, /final complete contract of the retired GitHub application flow/u);
  assert.doesNotMatch(agents + architecture + lifecycle, /complete current launch contract|current full application package|new or existing compatibility draft|New V3\.2 revisions|may enter only as an unreviewed draft|must use Application V3\.2/u);
  assert.match(beta, /GitHub launch intake is closed/u);
  assert.match(beta, /No contract in that list opens GitHub intake/u);
  assert.match(agents, /owns the preserved shared Router, fee, and promotion business obligations/u);
  assert.match(agents, /robinhood-custom-launch-economics-v1\.json` is the sole authored successor fee source for fresh Robinhood\s+chain 4663 profile 4\.1 launches/u);
  assert.match(agents, /Existing profiles, launches, and other chains keep their exact policy bytes/u);
  assert.match(agents, /separate public declarative contract for the current V3 profile/u);
  assert.match(agents, /private Custom Launch API exact-source\/runtime scanner, platform-owned behavior executor, and Router simulation\s+are the sole executable admission-evidence authorities/u);
  assert.match(readme, /request-bound policy obligation for the 10 bps Programmable share/u);
  assert.match(readme, /public V3 profile keeps `feeBehaviorClaim: false`/u);
  assert.match(readme, /launch-readiness.*checker-only/su);
  assert.match(readme, /GitHub launch intake is closed/u);
  assert.match(readme, /Custom Launch API/u);
  assert.match(readme, /historical GitHub records/iu);
  assert.match(readme, /legacy validators remain available for reproducing historical records/u);
  assert.match(readme, /Pull requests that modify the historical application namespaces fail closed/u);
});

function currentReviewInput(policyRecord, profileId, rules) {
  const subject = {
    numericRepositoryId: "9001",
    repository: "example/policy-consumer",
    commit: "a".repeat(40),
    tree: "b".repeat(40),
    configurationHash: `sha256:${"c".repeat(64)}`,
    usesUniswapV4: true
  };
  return {
    schemaVersion: "programmable.launch-policy-review-input.v1",
    profileId,
    expectedPolicyBinding: buildLaunchPolicyBinding(policyRecord, profileId),
    expectedSubject: subject,
    currentSubject: structuredClone(subject),
    evaluations: rules.map((rule) => ({
      ruleId: rule.id,
      state: "passed",
      evidenceRefs: [`sha256:${Buffer.from(rule.id, "utf8").toString("hex").padEnd(64, "0").slice(0, 64)}`],
      analyzer: { kind: rule.enforcement.mode, id: rule.enforcement.handlerId }
    })),
    observations: []
  };
}

function passedEvidenceForRules(rules) {
  return Object.fromEntries(
    rules.flatMap(({ evidence }) => evidence).map((evidenceId) => [evidenceId, { status: "passed" }])
  );
}

function findForbiddenPolicyValueKeys(value, location = "$") {
  const forbidden = new Set([
    "applicability",
    "authority",
    "evidence",
    "parameters",
    "requirement",
    "severity"
  ]);
  if (Array.isArray(value)) return value.flatMap((entry, index) => findForbiddenPolicyValueKeys(entry, `${location}[${index}]`));
  if (!isPlainObject(value)) return [];
  return Object.entries(value).flatMap(([key, child]) => [
    ...(forbidden.has(key) ? [`${location}.${key}`] : []),
    ...findForbiddenPolicyValueKeys(child, `${location}.${key}`)
  ]);
}

function withRepositoryCopy(callback) {
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "submit-launch-authority-"));
  const repositoryRoot = path.join(temporaryRoot, "repository");
  try {
    childProcess.execFileSync("git", ["clone", "--quiet", "--depth", "1", "--no-hardlinks", "--no-local", "--", root, repositoryRoot], {
      encoding: "utf8",
      maxBuffer: 32 * 1024 * 1024
    });
    for (const relativePath of git(["ls-files", "-z", "--cached", "--others", "--exclude-standard"], { trim: false }).split("\0").filter(Boolean)) {
      if (relativePath.startsWith("vendor/programmable-v4-hook-builder/")) continue;
      const source = path.join(root, relativePath);
      const target = path.join(repositoryRoot, relativePath);
      const status = fs.lstatSync(source);
      if (!status.isFile() || status.isSymbolicLink()) continue;
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.copyFileSync(source, target);
    }
    gitAt(repositoryRoot, ["add", "--all"]);
    verifyLaunchPolicyAuthorityOwnership({ repositoryRoot });
    callback(repositoryRoot);
  } finally {
    fs.rmSync(temporaryRoot, { force: true, recursive: true });
  }
}

function digestFile(repositoryRoot, relativePath) {
  return `sha256:${crypto.createHash("sha256").update(fs.readFileSync(path.join(repositoryRoot, relativePath))).digest("hex")}`;
}

function writeAuthorityManifest(repositoryRoot, manifest) {
  fs.writeFileSync(
    path.join(repositoryRoot, AUTHORITY_OWNERSHIP_MANIFEST_PATH),
    `${canonicalAuthorityJson(manifest)}\n`,
    "utf8"
  );
}

function trustedPolicyRecord() {
  return readTrustedLaunchPolicyFromGit({
    repositoryRoot: root,
    expectedBaseCommit: git(["rev-parse", "--verify", "HEAD^{commit}"])
  });
}

function read(relativePath) {
  return readAt(root, relativePath);
}

function readAt(repositoryRoot, relativePath) {
  return fs.readFileSync(path.join(repositoryRoot, relativePath), "utf8");
}

function readJson(relativePath) {
  return JSON.parse(read(relativePath));
}

function git(args, options) {
  return gitAt(root, args, options);
}

function gitAt(repositoryRoot, args, { trim = true } = {}) {
  const output = childProcess.execFileSync("git", args, {
    cwd: repositoryRoot,
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024
  });
  return trim ? output.trim() : output;
}

function compareUtf8(left, right) {
  return Buffer.from(left, "utf8").compare(Buffer.from(right, "utf8"));
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
