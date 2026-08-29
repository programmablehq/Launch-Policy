import assert from "node:assert/strict";
import childProcess from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import Ajv2020 from "../scripts/test/schema-validator/node_modules/ajv/dist/2020.js";

import {
  canonicalWorkflowCanaryResult,
  parseWorkflowCanaryApplicationBytes,
  parseWorkflowCanaryResultBytes,
  verifyWorkflowCanary
} from "../scripts/workflow-canary-core.mjs";
import {
  buildLaunchPolicyBinding,
  canonicalJson,
  readTrustedLaunchPolicyFromGit,
  rulesForProfile
} from "../scripts/launch-policy-core.mjs";
import { classifyPublicIntakePullRequest } from "../scripts/verify-public-hook-application-core.mjs";

const root = path.resolve(import.meta.dirname, "..");
const BASE_REPOSITORY = "programmablehq/Launch-Policy";
const BASE_REPOSITORY_ID = "1320171831";
const HEAD_REPOSITORY = "alice/submit-launch-fork";
const HEAD_REPOSITORY_ID = "88001";
const BUILDER_LOGIN = "Alice";
const BUILDER_USER_ID = "9007199254740993";
const PULL_REQUEST_NUMBER = "7";
const SOURCE = Object.freeze({
  repository: "alice/example-hook",
  numericRepositoryId: "123456789",
  commit: "a".repeat(40),
  tree: "b".repeat(40)
});

test("one inert exact-source canary application passes without fee or audit artifacts", async (t) => {
  const fixture = createCanaryFixture(t);
  const result = await verifyFixture(fixture);

  assert.equal(result.schemaVersion, "programmable.workflow-canary-result.v1");
  assert.equal(result.status, "passed");
  assert.equal(result.profileId, "workflow-canary");
  assert.equal(result.result, "CANARY_WORKFLOW_PASSED");
  assert.equal(result.outcome, "CANARY_WORKFLOW_PASSED");
  assert.deepEqual(result.authority, {
    checkerOnly: true,
    hiddenCanaryOnly: true,
    independentAudit: false,
    launchAuthorized: false,
    productionDiscoveryAllowed: false,
    productionRoutingAllowed: false,
    publicRoutingAllowed: false,
    realUserFundsAllowed: false
  });
  assert.deepEqual(result.application.builder, {
    githubLogin: BUILDER_LOGIN,
    githubUserId: BUILDER_USER_ID
  });
  assert.equal(result.application.blob.path, "canary-submissions/example-hook/application.json");
  assert.equal(result.application.blob.byteLength, fixture.applicationBytes.length);
  assert.equal(result.application.blob.sha256, sha256(fixture.applicationBytes));
  assert.match(result.application.blob.gitBlobOid, /^[0-9a-f]{40}$/u);
  assert.deepEqual(result.source, SOURCE);
  assert.deepEqual(result.pullRequest, {
    number: PULL_REQUEST_NUMBER,
    authorGitHubLogin: BUILDER_LOGIN,
    authorGitHubUserId: BUILDER_USER_ID,
    base: {
      repository: BASE_REPOSITORY,
      numericRepositoryId: BASE_REPOSITORY_ID,
      commit: fixture.baseCommit,
      tree: fixture.baseTree
    },
    head: {
      repository: HEAD_REPOSITORY,
      numericRepositoryId: HEAD_REPOSITORY_ID,
      commit: fixture.candidateCommit,
      tree: fixture.candidateTree
    },
    mergeCommit: fixture.mergeCommit
  });
  assert.deepEqual(result.policyBinding, fixture.policyBinding);
  assert.deepEqual(
    result.evaluatedRuleIds,
    rulesForProfile(fixture.policyRecord.policy, "workflow-canary").map(({ id }) => id)
  );
  assert.equal(result.reviewDecision.schemaVersion, "programmable.launch-policy-review-decision.v1");
  assert.equal(result.reviewDecision.status, "passed");
  assert.equal(result.reviewDecision.outcome, "CANARY_WORKFLOW_PASSED");
  assert.equal(result.reviewDecision.digest, result.reviewDecisionDigest);
  assert.match(result.digest, /^sha256:[0-9a-f]{64}$/u);
  assert.deepEqual(
    findForbiddenArtifactKeys(
      result,
      new Set(["programmableFee", "auditReport", "securityApproval", "registryRecord", "productionLaunch"])
    ),
    []
  );

  const bytes = Buffer.from(canonicalWorkflowCanaryResult(result, fixture.policyRecord), "utf8");
  const parsed = parseWorkflowCanaryResultBytes(bytes, fixture.policyRecord);
  assert.deepEqual(parsed.result, result);
  assert.deepEqual(parsed.bytes, bytes);
  assert.equal(parsed.sha256, sha256(bytes));
});

test("application and result schemas are strict and checked in", () => {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  const reviewDecisionSchema = readJson("review/schemas/launch-policy-review-decision.v1.schema.json");
  ajv.addSchema(reviewDecisionSchema);
  const applicationSchema = readJson("canary/schemas/workflow-canary-application-v1.schema.json");
  const resultSchema = readJson("canary/schemas/workflow-canary-result-v1.schema.json");
  assert.doesNotThrow(() => ajv.compile(applicationSchema));
  assert.doesNotThrow(() => ajv.compile(resultSchema));
});

test("application schema and runtime share Unicode code-point and safe-text semantics", (t) => {
  const fixture = createCanaryFixture(t);
  const validate = new Ajv2020({ allErrors: true, strict: true }).compile(
    readJson("canary/schemas/workflow-canary-application-v1.schema.json")
  );
  const canonical = JSON.parse(fixture.applicationBytes.toString("utf8"));
  const cases = [
    { field: "title", value: "Example Hook", expected: true },
    { field: "title", value: " Leading", expected: false },
    { field: "title", value: "Trailing ", expected: false },
    { field: "title", value: "\u00a0Leading", expected: false },
    { field: "title", value: "Control\u0001Character", expected: false },
    { field: "title", value: "Bidi\u202eOverride", expected: false },
    { field: "title", value: "😀".repeat(120), expected: true },
    { field: "title", value: "😀".repeat(121), expected: false },
    { field: "summary", value: "😀".repeat(1000), expected: true },
    { field: "summary", value: "😀".repeat(1001), expected: false }
  ];

  for (const { field, value, expected } of cases) {
    const application = { ...structuredClone(canonical), [field]: value };
    const schemaAccepted = validate(application);
    let runtimeAccepted = true;
    try {
      parseWorkflowCanaryApplicationBytes(jsonBytes(application), { expectedApplicationId: "example-hook" });
    } catch {
      runtimeAccepted = false;
    }
    assert.equal(schemaAccepted, expected, `${field} schema: ${JSON.stringify(value.slice(0, 24))}`);
    assert.equal(runtimeAccepted, expected, `${field} runtime: ${JSON.stringify(value.slice(0, 24))}`);
  }
});

test("result parser distinguishes raw bytes from self digest and revalidates embedded review semantics", async (t) => {
  const fixture = createCanaryFixture(t);
  const result = await verifyFixture(fixture);
  const canonicalBytes = Buffer.from(canonicalWorkflowCanaryResult(result, fixture.policyRecord), "utf8");
  const parsed = parseWorkflowCanaryResultBytes(canonicalBytes, fixture.policyRecord);
  assert.notEqual(parsed.sha256, result.digest);

  const tampered = structuredClone(result);
  tampered.reviewDecision.currentSubject.configurationHash = `sha256:${"0".repeat(64)}`;
  assert.throws(
    () => parseWorkflowCanaryResultBytes(jsonBytes(tampered), fixture.policyRecord),
    hasCode("CANARY_RESULT_REVIEW_INVALID")
  );

  assert.throws(
    () => parseWorkflowCanaryResultBytes(Buffer.concat([canonicalBytes, Buffer.from(" ")]), fixture.policyRecord),
    hasCode("CANARY_RESULT_JSON_NONCANONICAL")
  );
});

test("result parser binds authenticated head and merge identities into the embedded review subject", async (t) => {
  const fixture = createCanaryFixture(t);
  const result = await verifyFixture(fixture);

  for (const [label, mutate] of [
    ["head commit", (value) => { value.pullRequest.head.commit = "c".repeat(40); }],
    ["head tree", (value) => { value.pullRequest.head.tree = "d".repeat(40); }],
    ["merge commit", (value) => { value.pullRequest.mergeCommit = "e".repeat(40); }]
  ]) {
    const tampered = structuredClone(result);
    mutate(tampered);
    tampered.digest = unsafeResultDigest(tampered);
    assert.throws(
      () => parseWorkflowCanaryResultBytes(jsonBytes(tampered), fixture.policyRecord),
      hasCode("CANARY_RESULT_SUBJECT_INVALID"),
      label
    );
  }
});

test("V2, fee, audit artifact, approval, Registry, and production fields are forbidden", (t) => {
  const fixture = createCanaryFixture(t);
  for (const field of [
    "programmableFee",
    "auditReport",
    "securityApproval",
    "registryRecord",
    "productionLaunch"
  ]) {
    const value = JSON.parse(fixture.applicationBytes.toString("utf8"));
    value[field] = field === "programmableFee" ? { rate: 1 } : true;
    assert.throws(
      () => parseWorkflowCanaryApplicationBytes(jsonBytes(value), { expectedApplicationId: "example-hook" }),
      hasCode("CANARY_FIELDS_INVALID"),
      field
    );
  }
});

test("all four non-production declarations are exact constants", (t) => {
  const fixture = createCanaryFixture(t);
  const fields = Object.keys(JSON.parse(fixture.applicationBytes.toString("utf8")).declarations);
  for (const field of fields) {
    const value = JSON.parse(fixture.applicationBytes.toString("utf8"));
    value.declarations[field] = !value.declarations[field];
    assert.throws(
      () => parseWorkflowCanaryApplicationBytes(jsonBytes(value), { expectedApplicationId: "example-hook" }),
      hasCode("CANARY_DECLARATIONS_INVALID"),
      field
    );
  }
});

test("policy drift stops before public source resolution", async (t) => {
  let resolved = false;
  const fixture = createCanaryFixture(t, {
    mutateApplication(application) {
      application.expectedPolicyBinding.sha256 = `sha256:${"0".repeat(64)}`;
    }
  });
  await assert.rejects(
    verifyFixture(fixture, {
      async resolveSource() {
        resolved = true;
        return exactSourceObservation();
      }
    }),
    hasCode("POLICY_DRIFT")
  );
  assert.equal(resolved, false);
});

test("authenticated PR identity and exact public source are mandatory", async (t) => {
  await t.test("builder id", async (t2) => {
    const fixture = createCanaryFixture(t2, {
      mutateApplication(application) {
        application.builder.githubUserId = "999";
      }
    });
    await assert.rejects(verifyFixture(fixture), hasCode("CANARY_BUILDER_ID_MISMATCH"));
  });

  await t.test("source repository id", async (t2) => {
    const fixture = createCanaryFixture(t2);
    await assert.rejects(
      verifyFixture(fixture, {
        async resolveSource() {
          const observation = exactSourceObservation();
          observation.primary.authority.numericRepositoryId = "999";
          return observation;
        }
      }),
      hasCode("CANARY_SOURCE_ID_MISMATCH")
    );
  });
});

test("classifier chooses exactly one V2, canary, or maintenance namespace", (t) => {
  const fixture = createCanaryFixture(t);
  const classified = classifyPublicIntakePullRequest(classificationInput(fixture));
  assert.equal(classified.mode, "workflow-canary");
  assert.equal(classified.changes.length, 1);

  git(fixture.candidate, ["checkout", "--quiet", "--detach", fixture.candidateCommit]);
  writeFile(fixture.candidate, "policy/launch-policy.v1.json", `${fs.readFileSync(path.join(root, "policy/launch-policy.v1.json"), "utf8")} `);
  const mixedHead = commitAll(fixture.candidate, "mix canary and policy");
  const mixedMerge = createMergeCommit(fixture.candidate, fixture.baseCommit, mixedHead);
  assert.throws(
    () => classifyPublicIntakePullRequest({
      ...classificationInput(fixture),
      expectedCandidateCommit: mixedHead,
      expectedMergeCommit: mixedMerge
    }),
    hasCode("APPLICATION_PATH_INVALID")
  );
});

test("canary namespace permits exactly one canonical application blob", (t) => {
  const fixture = createCanaryFixture(t);
  writeFile(fixture.candidate, "canary-submissions/example-hook/README.md", "not allowed\n");
  const head = commitAll(fixture.candidate, "extra canary file");
  const merge = createMergeCommit(fixture.candidate, fixture.baseCommit, head);
  assert.throws(
    () => classifyPublicIntakePullRequest({
      ...classificationInput(fixture),
      expectedCandidateCommit: head,
      expectedMergeCommit: merge
    }),
    hasCode("APPLICATION_PATH_INVALID")
  );
});

function verifyFixture(fixture, dependencies = {}) {
  return verifyWorkflowCanary({
    baseRoot: fixture.base,
    candidateRoot: fixture.candidate,
    expectedBaseCommit: fixture.baseCommit,
    expectedCandidateCommit: fixture.candidateCommit,
    expectedMergeCommit: fixture.mergeCommit,
    pullRequestNumber: PULL_REQUEST_NUMBER,
    expectedBuilderLogin: BUILDER_LOGIN,
    expectedBuilderUserId: BUILDER_USER_ID,
    expectedBaseRepository: BASE_REPOSITORY,
    expectedBaseRepositoryId: BASE_REPOSITORY_ID,
    expectedHeadRepository: HEAD_REPOSITORY,
    expectedHeadRepositoryId: HEAD_REPOSITORY_ID
  }, {
    resolveSource: async () => exactSourceObservation(),
    ...dependencies
  });
}

function createCanaryFixture(t, { mutateApplication } = {}) {
  const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), "workflow-canary-"));
  t.after(() => fs.rmSync(fixtureRoot, { recursive: true, force: true }));
  const base = path.join(fixtureRoot, "base");
  const candidate = path.join(fixtureRoot, "candidate");
  fs.mkdirSync(base);
  git(base, ["init", "--initial-branch=main"]);
  git(base, ["remote", "add", "origin", "https://github.com/0xprogrammable/launch-policy.git"]);
  writeFile(base, "policy/launch-policy.v1.json", fs.readFileSync(path.join(root, "policy/launch-policy.v1.json")));
  writeFile(base, "README.md", "trusted base\n");
  const baseCommit = commitAll(base, "trusted base");
  const baseTree = git(base, ["rev-parse", `${baseCommit}^{tree}`]);
  const policyRecord = readTrustedLaunchPolicyFromGit({ repositoryRoot: base, expectedBaseCommit: baseCommit });
  const policyBinding = structuredClone(buildLaunchPolicyBinding(policyRecord, "workflow-canary"));

  git(fixtureRoot, ["clone", "--quiet", base, candidate]);
  const application = {
    schemaVersion: "programmable.workflow-canary-application.v1",
    applicationId: "example-hook",
    applicationRevision: 1,
    builder: {
      githubLogin: BUILDER_LOGIN,
      githubUserId: BUILDER_USER_ID
    },
    source: structuredClone(SOURCE),
    expectedPolicyBinding: policyBinding,
    title: "Example Hook",
    summary: "A hidden workflow-only canary.",
    declarations: {
      hiddenFromPublicRoutingAndDiscovery: true,
      independentAudit: false,
      productionRouting: false,
      realUserFunds: false
    }
  };
  mutateApplication?.(application);
  const applicationBytes = jsonBytes(application);
  writeFile(candidate, "canary-submissions/example-hook/application.json", applicationBytes);
  const candidateCommit = commitAll(candidate, "canary application");
  const candidateTree = git(candidate, ["rev-parse", `${candidateCommit}^{tree}`]);
  const mergeCommit = createMergeCommit(candidate, baseCommit, candidateCommit);
  return {
    applicationBytes,
    base,
    baseCommit,
    baseTree,
    candidate,
    candidateCommit,
    candidateTree,
    mergeCommit,
    policyBinding,
    policyRecord
  };
}

function createMergeCommit(repositoryRoot, baseCommit, candidateCommit) {
  git(repositoryRoot, ["checkout", "--quiet", "--detach", baseCommit]);
  git(repositoryRoot, ["merge", "--quiet", "--no-ff", "--no-commit", candidateCommit]);
  git(repositoryRoot, ["commit", "--quiet", "-m", "GitHub pull request merge"]);
  return git(repositoryRoot, ["rev-parse", "HEAD^{commit}"]);
}

function classificationInput(fixture) {
  return {
    baseRoot: fixture.base,
    candidateRoot: fixture.candidate,
    expectedBaseCommit: fixture.baseCommit,
    expectedCandidateCommit: fixture.candidateCommit,
    expectedMergeCommit: fixture.mergeCommit
  };
}

function exactSourceObservation() {
  return {
    schemaVersion: "1.0.0",
    kind: "github-public-source",
    canonicalProviderOrigin: "https://github.com",
    githubApiVersion: "2026-03-10",
    primary: {
      role: "primary",
      authority: {
        numericRepositoryId: SOURCE.numericRepositoryId,
        revisionObjectId: SOURCE.commit,
        treeObjectId: SOURCE.tree
      },
      display: {
        repositoryUri: `https://github.com/${SOURCE.repository}`,
        owner: "alice",
        repository: "example-hook",
        defaultBranch: "main"
      },
      visibility: "public",
      sourcePaths: [],
      contractPaths: [],
      githubActionsEvidence: []
    },
    companions: []
  };
}

function jsonBytes(value) {
  return Buffer.from(`${canonicalJson(value)}\n`, "utf8");
}

function sha256(bytes) {
  return `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
}

function unsafeResultDigest(result) {
  const withoutDigest = Object.fromEntries(Object.entries(result).filter(([key]) => key !== "digest"));
  return sha256(Buffer.from(canonicalJson(withoutDigest), "utf8"));
}

function findForbiddenArtifactKeys(value, forbiddenKeys, pathParts = []) {
  if (Array.isArray(value)) {
    return value.flatMap((entry, index) => findForbiddenArtifactKeys(entry, forbiddenKeys, [...pathParts, index]));
  }
  if (value === null || typeof value !== "object") return [];
  return Object.entries(value).flatMap(([key, entry]) => {
    const entryPath = [...pathParts, key];
    return [
      ...(forbiddenKeys.has(key) ? [entryPath.join(".")] : []),
      ...findForbiddenArtifactKeys(entry, forbiddenKeys, entryPath)
    ];
  });
}

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(root, relativePath), "utf8"));
}

function writeFile(repositoryRoot, relativePath, contents) {
  const target = path.join(repositoryRoot, relativePath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, contents);
}

function commitAll(repositoryRoot, message) {
  git(repositoryRoot, ["add", "-A"]);
  git(repositoryRoot, ["commit", "--quiet", "-m", message]);
  return git(repositoryRoot, ["rev-parse", "HEAD^{commit}"]);
}

function git(repositoryRoot, args) {
  return childProcess.execFileSync("git", args, {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      GIT_AUTHOR_EMAIL: "canary-test@example.invalid",
      GIT_AUTHOR_NAME: "Canary Test",
      GIT_COMMITTER_EMAIL: "canary-test@example.invalid",
      GIT_COMMITTER_NAME: "Canary Test"
    }
  }).trim();
}

function hasCode(code) {
  return (error) => error?.code === code;
}
