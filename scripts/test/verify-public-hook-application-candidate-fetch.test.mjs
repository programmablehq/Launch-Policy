import assert from "node:assert/strict";
import childProcess from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";

import {
  canonicalJson,
  classifyBoundedApplicationPathChanges,
  classifyPublicIntakePullRequest,
  createHistoricalLegacyV2PolicyAdapterForLocalInspection,
  fetchPublicApplicationCandidate,
  hydratePublicApplicationCandidate,
  measureHydrationDirectory,
  preflightPublicApplicationCandidateFetch,
  PUBLIC_BETA_DISCLAIMER,
  runBoundedHydrationGitProcess,
  validatePublicApplicationPackageFiles,
  verifyBoundedApplicationPullRequestPaths,
  verifyPublicHookApplication
} from "../verify-public-hook-application-core.mjs";
import {
  buildLaunchPolicyBinding,
  readTrustedLaunchPolicyFromGit
} from "../launch-policy-core.mjs";
import { validateGitHubPublicSourceRequestV1 } from "../../vendor/programmable-v4-hook-builder/scripts/github-public-source-request.mjs";
import { createApplicationV3TestPackage } from "./application-v3-package-fixture.mjs";
import {
  derivePublicPrApplicationV3PreviousBinding,
  isTrustedPublicApplicationV3LaunchReadinessV1
} from "../verify-public-application-v3-core.mjs";

const PULL_REQUEST_NUMBER = "7";
const BUILDER_USER_ID = "9007199254740993";
const TRUSTED_POLICY_BYTES = fs.readFileSync(path.resolve("policy/launch-policy.v1.json"));
const LOCAL_LEGACY_POLICY_ADAPTER = createHistoricalLegacyV2PolicyAdapterForLocalInspection({
  policyBytes: TRUSTED_POLICY_BYTES
});
const PRIMARY = Object.freeze({
  repositoryUri: "https://github.com/alice/example-hook",
  numericRepositoryId: "123456789",
  revisionObjectId: "a".repeat(40),
  treeObjectId: "b".repeat(40),
  sourcePaths: ["compatibility-report.json", "test/ExampleHook.t.sol"],
  contractPaths: ["src/ExampleHook.sol"],
  githubActionsRunIds: ["123"]
});

test("blobless maintenance classification never materializes an unexpected 100 MB candidate blob", async (t) => {
  const fixture = createRevisionPair(t);
  writeFile(
    fixture.candidate,
    "vendor/programmable-v4-hook-builder/SKILL.md",
    "---\nname: programmable-v4-hook-builder\ndescription: candidate data only\n---\n"
  );
  const oversizedPath = path.join(
    fixture.candidate,
    "vendor/programmable-v4-hook-builder/assets/unexpected-100mb.bin"
  );
  fs.mkdirSync(path.dirname(oversizedPath), { recursive: true });
  fs.closeSync(fs.openSync(oversizedPath, "w"));
  fs.truncateSync(oversizedPath, 100 * 1024 * 1024);

  const candidateCommit = commitAll(fixture.candidate, "candidate maintenance with unexpected large blob");
  const mergeCommit = createPullRequestMerge(fixture, candidateCommit);
  const oversizedObjectId = blobObjectIdAtPath(
    fixture.candidate,
    "vendor/programmable-v4-hook-builder/assets/unexpected-100mb.bin"
  );
  const candidateData = await fetchBloblessPullRequestMerge(fixture, mergeCommit);

  assert.equal(hasObjectWithoutLazyFetch(candidateData, oversizedObjectId), false);
  const classified = classifyPublicIntakePullRequest({
    baseRoot: fixture.base,
    candidateRoot: candidateData,
    expectedBaseCommit: fixture.baseCommit,
    expectedCandidateCommit: candidateCommit,
    expectedMergeCommit: mergeCommit
  });
  assert.equal(classified.mode, "registry-maintenance");
  assert.equal(hasObjectWithoutLazyFetch(candidateData, oversizedObjectId), false);
  assert.equal(fs.existsSync(path.join(candidateData, "vendor")), false);
});

test("bounded repository measurement tolerates Git removing a temporary child directory", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "public-hook-measure-race-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const stableBytes = Buffer.from("stable object bytes");
  fs.writeFileSync(path.join(root, "stable-object"), stableBytes);
  const transientDirectory = path.join(root, "temporary-pack");
  fs.mkdirSync(transientDirectory);
  fs.writeFileSync(path.join(transientDirectory, "in-flight.pack"), "temporary bytes");

  const originalLstatSync = fs.lstatSync;
  let removed = false;
  fs.lstatSync = function lstatAndRemoveTemporaryDirectory(target, options) {
    const status = originalLstatSync.call(fs, target, options);
    if (!removed && target === transientDirectory) {
      removed = true;
      fs.rmSync(transientDirectory, { recursive: true, force: true });
    }
    return status;
  };
  try {
    assert.equal(measureHydrationDirectory(root), stableBytes.length);
  } finally {
    fs.lstatSync = originalLstatSync;
  }
  assert.equal(removed, true);
});

test("trusted application validation hydrates only the six closed package blobs", async (t) => {
  const fixture = createRevisionPair(t);
  const packageFiles = makePackage();
  writePackage(fixture.candidate, packageFiles);
  const candidateCommit = commitAll(fixture.candidate, "valid closed application package");
  const mergeCommit = createPullRequestMerge(fixture, candidateCommit);
  const candidateData = await fetchBloblessPullRequestMerge(fixture, mergeCommit);
  const packageObjectIds = [...packageFiles.keys()].map((fileName) =>
    blobObjectIdAtPath(fixture.candidate, `submissions/example-hook/${fileName}`)
  );
  const unrelatedBaseObjectId = blobObjectIdAtPath(fixture.base, "README.md");

  assert.ok(packageObjectIds.every((objectId) => !hasObjectWithoutLazyFetch(candidateData, objectId)));
  assert.equal(hasObjectWithoutLazyFetch(candidateData, unrelatedBaseObjectId), false);

  const hydration = await hydratePublicApplicationCandidate({
    baseRoot: fixture.base,
    candidateRoot: candidateData,
    expectedBaseCommit: fixture.baseCommit,
    expectedCandidateCommit: candidateCommit,
    expectedMergeCommit: mergeCommit,
    pullRequestNumber: PULL_REQUEST_NUMBER,
    repository: "central/repository",
    readToken: "test-read-token"
  }, localHydrationDependencies(fixture));
  assert.deepEqual(
    { result: hydration.result, fileCount: hydration.fileCount },
    { result: "bounded-application-blobs-hydrated", fileCount: 6 }
  );

  const report = await verifyPublicHookApplication({
    baseRoot: fixture.base,
    candidateRoot: candidateData,
    expectedBaseCommit: fixture.baseCommit,
    pullRequestNumber: PULL_REQUEST_NUMBER,
    expectedBuilderLogin: "alice",
    expectedBuilderUserId: BUILDER_USER_ID,
    expectedCandidateCommit: candidateCommit,
    expectedMergeCommit: mergeCommit,
    resolveSource: exactSourceResolver,
    resolveEvidence: exactEvidenceResolver
  });

  assert.equal(report.result, "valid-public-application-package");
  assert.ok(packageObjectIds.every((objectId) => hasObjectWithoutLazyFetch(candidateData, objectId)));
  assert.equal(hasObjectWithoutLazyFetch(candidateData, unrelatedBaseObjectId), false);
  assert.equal(fs.existsSync(path.join(candidateData, "submissions")), false);
});

test("trusted intake hydrates only one immutable nested Application V3 revision", async (t) => {
  const fixture = createRevisionPair(t);
  const packageDirectory = "submissions/fade/v3/revisions/1";
  const packageFiles = new Map([
    ["application.v3.json", jsonBytes({
      applicationId: "fade",
      applicationRevision: 1,
      contractVersion: "3.1.0",
      schemaVersion: "programmable.public-pr-application.v3"
    })],
    ["PROPOSAL.md", Buffer.from("# FADE\n\nReview-only Application V3 package.\n")],
    ["security/source-verification.primary.v1.json", jsonBytes({ schemaVersion: 1 })]
  ]);
  for (const [relativePath, bytes] of packageFiles) {
    writeFile(fixture.candidate, `${packageDirectory}/${relativePath}`, bytes);
  }
  const candidateCommit = commitAll(fixture.candidate, "immutable Application V3 revision");
  const mergeCommit = createPullRequestMerge(fixture, candidateCommit);
  const objectIds = [...packageFiles.keys()].map((relativePath) => (
    blobObjectIdAtPath(fixture.candidate, `${packageDirectory}/${relativePath}`)
  ));
  const unrelatedBaseObjectId = blobObjectIdAtPath(fixture.base, "README.md");
  const candidateData = await fetchBloblessPullRequestMerge(fixture, mergeCommit);

  assert.ok(objectIds.every((objectId) => !hasObjectWithoutLazyFetch(candidateData, objectId)));
  const hydration = await hydratePublicApplicationCandidate({
    baseRoot: fixture.base,
    candidateRoot: candidateData,
    expectedBaseCommit: fixture.baseCommit,
    expectedCandidateCommit: candidateCommit,
    expectedMergeCommit: mergeCommit,
    pullRequestNumber: PULL_REQUEST_NUMBER,
    repository: "central/repository",
    readToken: "test-read-token"
  }, localHydrationDependencies(fixture, packageDirectory));

  assert.deepEqual(hydration, {
    schemaVersion: 1,
    result: "bounded-application-v3-blobs-hydrated",
    intakeState: "open",
    applicationId: "fade",
    applicationRevision: "1",
    pullRequestNumber: PULL_REQUEST_NUMBER,
    continuationAuthorized: false,
    fileCount: 3,
    totalBytes: [...packageFiles.values()].reduce((total, bytes) => total + bytes.length, 0)
  });
  assert.ok(objectIds.every((objectId) => hasObjectWithoutLazyFetch(candidateData, objectId)));
  assert.equal(hasObjectWithoutLazyFetch(candidateData, unrelatedBaseObjectId), false);
  assert.equal(fs.existsSync(path.join(candidateData, "submissions")), false);
});

test("open Draft update recovers one exact unpublished V3 predecessor from authenticated head history", async (t) => {
  const fixture = createRevisionPair(t);
  const revision1 = makeApplicationV3Package({ applicationId: "fade" });
  const revision1Directory = "submissions/fade/v3/revisions/1";
  writeApplicationV3Revision(fixture.candidate, revision1Directory, revision1.packageFiles);
  const revision1Commit = commitAll(fixture.candidate, "add unpublished revision 1");
  const syncTree = git(fixture.candidate, ["rev-parse", `${revision1Commit}^{tree}`]);
  const syncCommit = git(fixture.candidate, [
    "commit-tree", syncTree,
    "-p", revision1Commit,
    "-p", fixture.baseCommit,
    "-m", "sync protected base without changing applicant bytes"
  ]);
  git(fixture.candidate, ["reset", "--hard", syncCommit]);

  const previous = deriveApplicationV3PreviousBinding(revision1.application, revision1.packageFiles);
  const revision2 = makeApplicationV3Package({
    applicationId: "fade",
    applicationRevision: "2",
    lineage: { kind: "recheck", previous }
  });
  const revision2Directory = "submissions/fade/v3/revisions/2";
  writeApplicationV3Revision(fixture.candidate, revision2Directory, revision2.packageFiles);
  const transitionCommit = commitAll(fixture.candidate, "add unpublished revision 2");
  fs.rmSync(path.join(fixture.candidate, revision1Directory), { recursive: true });
  const candidateCommit = commitAll(fixture.candidate, "retain only current unpublished revision");
  const mergeCommit = createPullRequestMerge(fixture, candidateCommit);
  const candidateData = await fetchBloblessPullRequestMerge(fixture, mergeCommit);

  const hydration = await hydratePublicApplicationCandidate({
    baseRoot: fixture.base,
    candidateRoot: candidateData,
    expectedBaseCommit: fixture.baseCommit,
    expectedCandidateCommit: candidateCommit,
    expectedMergeCommit: mergeCommit,
    pullRequestNumber: PULL_REQUEST_NUMBER,
    repository: "central/repository",
    readToken: "test-read-token"
  }, {
    allowFileProtocolForTests: true,
    remoteUrlForTests: pathToFileURL(fixture.candidate).href,
    fetchImplementation: createMultipleTreeMetadataFetch(fixture.candidate, [
      { commit: transitionCommit, packageDirectory: revision1Directory },
      { commit: candidateCommit, packageDirectory: revision2Directory }
    ])
  });
  assert.equal(hydration.applicationRevision, "2");
  assert.equal(hydration.continuationAuthorized, false);

  const report = await verifyPublicHookApplication({
    baseRoot: fixture.base,
    candidateRoot: candidateData,
    expectedBaseCommit: fixture.baseCommit,
    pullRequestNumber: PULL_REQUEST_NUMBER,
    expectedBuilderLogin: revision2.application.builder.githubLogin,
    expectedBuilderUserId: revision2.application.builder.githubUserId,
    expectedCandidateCommit: candidateCommit,
    expectedMergeCommit: mergeCommit,
    resolveSource: exactApplicationV3SourceResolver,
    resolveExactObjects: exactApplicationV3ObjectResolver(revision2.sourceFiles)
  });
  assert.equal(report.result, "valid-public-application-v3-package");
  assert.equal(report.applicationRevision, "2");
  assert.equal(report.reviewState, "unreviewed");
  assert.equal(report.approvalGranted, false);
  assert.equal(report.acceptanceGranted, false);
  assert.equal(report.productionDiscoveryAllowed, false);
  assert.equal(report.publicRoutingAllowed, false);
  assert.equal(report.realUserFundsAllowed, false);
});

test("open Draft history rejects deleted, substituted, and unrelated predecessor transport", async (t) => {
  for (const scenario of ["deleted", "substituted", "unrelated"]) {
    await t.test(scenario, async (subtest) => {
      const fixture = createRevisionPair(subtest);
      const revision1 = makeApplicationV3Package({ applicationId: "fade" });
      const revision1Directory = "submissions/fade/v3/revisions/1";
      writeApplicationV3Revision(fixture.candidate, revision1Directory, revision1.packageFiles);
      commitAll(fixture.candidate, "add predecessor");
      if (scenario === "deleted") {
        fs.rmSync(path.join(fixture.candidate, revision1Directory), { recursive: true });
        commitAll(fixture.candidate, "delete predecessor early");
        writeApplicationV3Revision(fixture.candidate, revision1Directory, revision1.packageFiles);
        commitAll(fixture.candidate, "re-add predecessor");
      } else if (scenario === "substituted") {
        writeFile(fixture.candidate, `${revision1Directory}/PROPOSAL.md`, Buffer.from("# substituted\n"));
        commitAll(fixture.candidate, "substitute predecessor bytes");
      } else {
        writeFile(fixture.candidate, "submissions/fade/application.json", jsonBytes({ schemaVersion: 2 }));
        commitAll(fixture.candidate, "mix unrelated legacy history");
      }
      const previous = deriveApplicationV3PreviousBinding(revision1.application, revision1.packageFiles);
      const revision2 = makeApplicationV3Package({
        applicationId: "fade",
        applicationRevision: "2",
        lineage: { kind: "recheck", previous }
      });
      const revision2Directory = "submissions/fade/v3/revisions/2";
      writeApplicationV3Revision(fixture.candidate, revision2Directory, revision2.packageFiles);
      commitAll(fixture.candidate, "add current revision");
      fs.rmSync(path.join(fixture.candidate, revision1Directory), { recursive: true, force: true });
      fs.rmSync(path.join(fixture.candidate, "submissions/fade/application.json"), { force: true });
      const candidateCommit = commitAll(fixture.candidate, "close final visible revision");
      const mergeCommit = createPullRequestMerge(fixture, candidateCommit);
      const candidateData = await fetchBloblessPullRequestMerge(fixture, mergeCommit);
      assert.throws(
        () => classifyPublicIntakePullRequest({
          baseRoot: fixture.base,
          candidateRoot: candidateData,
          expectedBaseCommit: fixture.baseCommit,
          expectedCandidateCommit: candidateCommit,
          expectedMergeCommit: mergeCommit
        }),
        (error) => error?.code === "APPLICATION_V3_DRAFT_HISTORY_INVALID"
      );
    });
  }
});

test("Application V3 metadata fails closed for closed, non-Draft, base, and head drift", async (t) => {
  const fixture = createRevisionPair(t);
  const files = [{
    filename: "submissions/fade/v3/revisions/1/application.v3.json",
    status: "added"
  }];
  for (const scenario of ["closed", "non-draft", "base-drift", "head-drift"]) {
    const baseCommit = scenario === "base-drift" ? "a".repeat(40) : fixture.baseCommit;
    const candidateCommit = scenario === "head-drift" ? "b".repeat(40) : "c".repeat(40);
    await assert.rejects(
      verifyBoundedApplicationPullRequestPaths({
        repository: "central/repository",
        pullRequestNumber: PULL_REQUEST_NUMBER,
        expectedBaseCommit: fixture.baseCommit,
        expectedCandidateCommit: "c".repeat(40),
        readToken: "test-read-token"
      }, {
        fetchImplementation: createPullRequestMetadataFetch({
          baseCommit,
          candidateCommit,
          files,
          state: scenario === "closed" ? "closed" : "open",
          draft: scenario !== "non-draft"
        })
      }),
      (error) => scenario === "non-draft"
        ? error?.code === "APPLICATION_V3_DRAFT_REQUIRED" && error?.kind === "candidate"
        : error?.code === "CANDIDATE_PREFLIGHT_ID_MISMATCH" && error?.kind === "system"
    );
  }
});

test("protected dispatch validates no-fee proposal and prototype Application V3 packages without executing candidate code", async (t) => {
  for (const stage of ["proposal", "prototype"]) {
    await t.test(stage, async (subtest) => {
      const fixture = createRevisionPair(subtest);
      const { application, packageFiles, sourceFiles } = makeApplicationV3Package({ stage });
      const packageDirectory = `submissions/${application.applicationId}/v3/revisions/${application.applicationRevision}`;
      for (const [relativePath, bytes] of packageFiles) {
        writeFile(fixture.candidate, `${packageDirectory}/${relativePath}`, bytes);
      }
      const candidateCommit = commitAll(fixture.candidate, `complete no-fee ${stage} Application V3 package`);
      const mergeCommit = createPullRequestMerge(fixture, candidateCommit);
      const candidateData = await fetchBloblessPullRequestMerge(fixture, mergeCommit);
      await hydratePublicApplicationCandidate({
        baseRoot: fixture.base,
        candidateRoot: candidateData,
        expectedBaseCommit: fixture.baseCommit,
        expectedCandidateCommit: candidateCommit,
        expectedMergeCommit: mergeCommit,
        pullRequestNumber: PULL_REQUEST_NUMBER,
        repository: "central/repository",
        readToken: "test-read-token"
      }, localHydrationDependencies(fixture, packageDirectory));

      const report = await verifyPublicHookApplication({
        baseRoot: fixture.base,
        candidateRoot: candidateData,
        expectedBaseCommit: fixture.baseCommit,
        pullRequestNumber: PULL_REQUEST_NUMBER,
        expectedBuilderLogin: application.builder.githubLogin,
        expectedBuilderUserId: application.builder.githubUserId,
        expectedCandidateCommit: candidateCommit,
        expectedMergeCommit: mergeCommit,
        resolveSource: exactApplicationV3SourceResolver,
        resolveExactObjects: exactApplicationV3ObjectResolver(sourceFiles)
      });

      assert.equal(report.result, "valid-public-application-v3-package");
      assert.equal(report.mode, "application-v3");
      assert.equal(report.reviewState, "unreviewed");
      assert.equal(report.approvalGranted, false);
      assert.equal(report.productionDiscoveryAllowed, false);
      assert.equal(report.publicRoutingAllowed, false);
      assert.equal(report.realUserFundsAllowed, false);
    });
  }
});

test("protected dispatch validates exact V3.2 no-market bytes and returns trusted not-applicable readiness", async (t) => {
  const fixture = createRevisionPair(t);
  const candidatePackage = makeApplicationV3Package({
    applicationContractVersion: "3.2.0",
    requestedRoute: "none",
    marketMode: "no-market"
  });
  const prepared = await prepareApplicationV3Candidate(
    fixture,
    candidatePackage,
    "complete V3.2 no-market Application package"
  );

  const report = await verifyPublicHookApplication({
    ...applicationV3VerificationInput(fixture, candidatePackage, prepared),
    resolveSource: exactApplicationV3SourceResolver,
    resolveExactObjects: exactApplicationV3ObjectResolver(candidatePackage.sourceFiles)
  });

  assert.equal(report.result, "valid-public-application-v3-package");
  assert.equal(report.validatorVersion, "3.2.0");
  assert.equal(report.launchReadiness.decision, "not-applicable");
  assert.equal(report.launchReadiness.requestedRoute, "none");
  assert.equal(report.launchReadiness.readinessBinding, null);
  assert.match(report.launchReadiness.applicationSha256, /^sha256:[0-9a-f]{64}$/u);
  assert.match(report.launchReadiness.packageSha256, /^sha256:[0-9a-f]{64}$/u);
  assert.equal(isTrustedPublicApplicationV3LaunchReadinessV1(report.launchReadiness), true);
});

test("protected dispatch validates the full source-bound official V3.2 route and returns trusted required readiness", async (t) => {
  const fixture = createRevisionPair(t);
  const candidatePackage = makeApplicationV3Package({
    applicationContractVersion: "3.2.0",
    requestedRoute: "programmable-ethereum-mainnet",
    marketMode: "tradable"
  });
  const prepared = await prepareApplicationV3Candidate(
    fixture,
    candidatePackage,
    "complete source-bound official V3.2 route"
  );

  const report = await verifyPublicHookApplication({
    ...applicationV3VerificationInput(fixture, candidatePackage, prepared),
    resolveSource: exactApplicationV3SourceResolver,
    resolveExactObjects: exactApplicationV3ObjectResolver(candidatePackage.sourceFiles)
  });

  assert.equal(report.result, "valid-public-application-v3-package");
  assert.equal(report.validatorVersion, "3.2.0");
  assert.equal(report.launchReadiness.decision, "required");
  assert.equal(report.launchReadiness.requestedRoute, "programmable-ethereum-mainnet");
  assert.equal(report.launchReadiness.readinessBinding.path, ".programmable/launch-router-readiness.v1.json");
  assert.equal(report.launchReadiness.readinessBinding.sha256, candidatePackage.application.launchRequest.routePlan.sha256);
  assert.equal(report.launchReadiness.readinessBinding.gitBlobOid, candidatePackage.application.launchRequest.routePlan.gitBlobOid);
  assert.match(report.launchReadiness.applicationSha256, /^sha256:[0-9a-f]{64}$/u);
  assert.match(report.launchReadiness.packageSha256, /^sha256:[0-9a-f]{64}$/u);
  assert.equal(isTrustedPublicApplicationV3LaunchReadinessV1(report.launchReadiness), true);
});

test("protected V3 history accepts only V3.1 to V3.2 migration and rejects downgrade", async (t) => {
  await t.test("V3.1 to V3.2 schema migration", async (subtest) => {
    const fixture = createRevisionPair(subtest);
    const first = makeApplicationV3Package({ applicationId: "protected-version-migration" });
    installTrustedApplicationV3Revision(fixture, first, "trusted V3.1 predecessor");
    const second = makeApplicationV3Package({
      applicationId: "protected-version-migration",
      applicationContractVersion: "3.2.0",
      applicationRevision: "2",
      lineage: {
        kind: "schema-migration",
        previous: deriveApplicationV3PreviousBinding(first.application, first.packageFiles, "3.2.0")
      }
    });
    const prepared = await prepareApplicationV3Candidate(
      fixture,
      second,
      "migrate protected V3.1 predecessor to V3.2"
    );

    const report = await verifyPublicHookApplication({
      ...applicationV3VerificationInput(fixture, second, prepared),
      resolveSource: exactApplicationV3SourceResolver,
      resolveExactObjects: exactApplicationV3ObjectResolver(second.sourceFiles)
    });
    assert.equal(report.result, "valid-public-application-v3-package");
    assert.equal(report.applicationRevision, "2");
    assert.equal(report.validatorVersion, "3.2.0");
    assert.equal(report.launchReadiness.decision, "not-applicable");
  });

  await t.test("V3.1 to V3.2 requires schema-migration", async (subtest) => {
    const fixture = createRevisionPair(subtest);
    const first = makeApplicationV3Package({ applicationId: "protected-wrong-migration" });
    installTrustedApplicationV3Revision(fixture, first, "trusted V3.1 predecessor");
    const second = makeApplicationV3Package({
      applicationId: "protected-wrong-migration",
      applicationContractVersion: "3.2.0",
      applicationRevision: "2",
      lineage: {
        kind: "recheck",
        previous: deriveApplicationV3PreviousBinding(first.application, first.packageFiles, "3.2.0")
      }
    });
    const prepared = await prepareApplicationV3Candidate(
      fixture,
      second,
      "mislabel protected V3.1 to V3.2 transition",
      { hydrate: false }
    );
    let resolverCalls = 0;

    await assert.rejects(
      () => verifyPublicHookApplication({
        ...applicationV3VerificationInput(fixture, second, prepared),
        resolveSource: async () => { resolverCalls += 1; },
        resolveExactObjects: exactApplicationV3ObjectResolver(second.sourceFiles)
      }),
      (error) => error?.code === "APPLICATION_V3_2_MIGRATION_KIND_REQUIRED" && error?.kind === "candidate"
    );
    assert.equal(resolverCalls, 0);
  });

  await t.test("V3.2 to V3.1 downgrade", async (subtest) => {
    const fixture = createRevisionPair(subtest);
    const first = makeApplicationV3Package({
      applicationId: "protected-version-downgrade",
      applicationContractVersion: "3.2.0"
    });
    installTrustedApplicationV3Revision(fixture, first, "trusted V3.2 predecessor");
    const second = makeApplicationV3Package({
      applicationId: "protected-version-downgrade",
      applicationRevision: "2",
      lineage: {
        kind: "recheck",
        previous: deriveApplicationV3PreviousBinding(first.application, first.packageFiles, "3.1.0")
      }
    });
    const prepared = await prepareApplicationV3Candidate(
      fixture,
      second,
      "attempt protected V3.2 to V3.1 downgrade",
      { hydrate: false }
    );
    let resolverCalls = 0;

    await assert.rejects(
      () => verifyPublicHookApplication({
        ...applicationV3VerificationInput(fixture, second, prepared),
        resolveSource: async () => { resolverCalls += 1; },
        resolveExactObjects: exactApplicationV3ObjectResolver(second.sourceFiles)
      }),
      (error) => error?.code === "APPLICATION_V3_CONTRACT_DOWNGRADE_FORBIDDEN" && error?.kind === "candidate"
    );
    assert.equal(resolverCalls, 0);
  });
});

test("protected dispatch resolves inline Application V3 contract paths once when they are also in the source closure", async (t) => {
  const fixture = createRevisionPair(t);
  const { application, packageFiles, sourceFiles } = makeApplicationV3Package({ stage: "proposal" });
  const contractPath = application.source.primary.sourcePaths.find((sourcePath) => sourcePath.endsWith("submission.v2.json"));
  assert.equal(typeof contractPath, "string");
  application.source.primary.contractPaths = [contractPath];
  packageFiles.set("application.v3.json", jsonBytes(application));

  const packageDirectory = `submissions/${application.applicationId}/v3/revisions/${application.applicationRevision}`;
  for (const [relativePath, bytes] of packageFiles) {
    writeFile(fixture.candidate, `${packageDirectory}/${relativePath}`, bytes);
  }
  const candidateCommit = commitAll(fixture.candidate, "Application V3 source and contract path overlap");
  const mergeCommit = createPullRequestMerge(fixture, candidateCommit);
  const candidateData = await fetchBloblessPullRequestMerge(fixture, mergeCommit);
  await hydratePublicApplicationCandidate({
    baseRoot: fixture.base,
    candidateRoot: candidateData,
    expectedBaseCommit: fixture.baseCommit,
    expectedCandidateCommit: candidateCommit,
    expectedMergeCommit: mergeCommit,
    pullRequestNumber: PULL_REQUEST_NUMBER,
    repository: "central/repository",
    readToken: "test-read-token"
  }, localHydrationDependencies(fixture, packageDirectory));

  let observedRequest = null;
  const report = await verifyPublicHookApplication({
    baseRoot: fixture.base,
    candidateRoot: candidateData,
    expectedBaseCommit: fixture.baseCommit,
    pullRequestNumber: PULL_REQUEST_NUMBER,
    expectedBuilderLogin: application.builder.githubLogin,
    expectedBuilderUserId: application.builder.githubUserId,
    expectedCandidateCommit: candidateCommit,
    expectedMergeCommit: mergeCommit,
    resolveSource: async (request) => {
      observedRequest = validateGitHubPublicSourceRequestV1(request);
      return exactApplicationV3SourceResolver(observedRequest);
    },
    resolveExactObjects: exactApplicationV3ObjectResolver(sourceFiles)
  });

  assert.equal(report.result, "valid-public-application-v3-package");
  assert.deepEqual(observedRequest.primary.contractPaths, [contractPath]);
  assert.equal(observedRequest.primary.sourcePaths.includes(contractPath), false);
  assert.deepEqual(
    [...new Set([...observedRequest.primary.sourcePaths, ...observedRequest.primary.contractPaths])].sort(
      (left, right) => Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"))
    ),
    application.source.primary.sourcePaths
  );
});

test("protected dispatch rejects an inline Application V3 contract path outside the source closure before resolution", async (t) => {
  const fixture = createRevisionPair(t);
  const { application, packageFiles, sourceFiles } = makeApplicationV3Package({ stage: "proposal" });
  application.source.primary.contractPaths = ["src/OutsideClosure.sol"];
  packageFiles.set("application.v3.json", jsonBytes(application));

  const packageDirectory = `submissions/${application.applicationId}/v3/revisions/${application.applicationRevision}`;
  for (const [relativePath, bytes] of packageFiles) {
    writeFile(fixture.candidate, `${packageDirectory}/${relativePath}`, bytes);
  }
  const candidateCommit = commitAll(fixture.candidate, "Application V3 contract path outside source closure");
  const mergeCommit = createPullRequestMerge(fixture, candidateCommit);
  const candidateData = await fetchBloblessPullRequestMerge(fixture, mergeCommit);
  await hydratePublicApplicationCandidate({
    baseRoot: fixture.base,
    candidateRoot: candidateData,
    expectedBaseCommit: fixture.baseCommit,
    expectedCandidateCommit: candidateCommit,
    expectedMergeCommit: mergeCommit,
    pullRequestNumber: PULL_REQUEST_NUMBER,
    repository: "central/repository",
    readToken: "test-read-token"
  }, localHydrationDependencies(fixture, packageDirectory));

  let resolverCalls = 0;
  await assert.rejects(
    () => verifyPublicHookApplication({
      baseRoot: fixture.base,
      candidateRoot: candidateData,
      expectedBaseCommit: fixture.baseCommit,
      pullRequestNumber: PULL_REQUEST_NUMBER,
      expectedBuilderLogin: application.builder.githubLogin,
      expectedBuilderUserId: application.builder.githubUserId,
      expectedCandidateCommit: candidateCommit,
      expectedMergeCommit: mergeCommit,
      resolveSource: async () => { resolverCalls += 1; },
      resolveExactObjects: exactApplicationV3ObjectResolver(sourceFiles)
    }),
    (error) => error?.code === "APPLICATION_CONTRACT_PATH_OUTSIDE_CLOSURE" && error?.kind === "candidate"
  );
  assert.equal(resolverCalls, 0);
});

test("protected dispatch independently rederives an exact legacy V2 schema-migration predecessor", async (t) => {
  for (const mismatch of [false, true]) {
    await t.test(mismatch ? "mismatch" : "valid", async (subtest) => {
      const applicationId = "legacy-open-world-example";
      const fixture = createRevisionPair(subtest);
      const legacyFiles = makePackage({ applicationId });
      writePackage(fixture.base, legacyFiles, applicationId);
      fixture.baseCommit = commitAll(fixture.base, "trusted legacy V2 predecessor");
      git(fixture.candidate, ["fetch", "--quiet", fixture.base, fixture.baseCommit]);
      git(fixture.candidate, ["reset", "--hard", fixture.baseCommit]);

      const legacySubmissionBytes = sourceSubmissionBytes(makeProgrammableFee(), applicationId);
      const previous = deriveLegacyV2PreviousBinding({
        applicationId,
        packageFiles: legacyFiles,
        submissionBytes: legacySubmissionBytes
      });
      if (mismatch) previous.packageSha256 = `sha256:${"f".repeat(64)}`;
      const { application, packageFiles, sourceFiles } = makeApplicationV3Package({
        applicationRevision: "2",
        lineage: { kind: "schema-migration", previous }
      });
      sourceFiles.set(`submissions/${applicationId}/submission.json`, legacySubmissionBytes);
      const packageDirectory = `submissions/${applicationId}/v3/revisions/2`;
      for (const [relativePath, bytes] of packageFiles) {
        writeFile(fixture.candidate, `${packageDirectory}/${relativePath}`, bytes);
      }
      const candidateCommit = commitAll(fixture.candidate, "Application V3 migration from protected V2 predecessor");
      const mergeCommit = createPullRequestMerge(fixture, candidateCommit);
      const candidateData = await fetchBloblessPullRequestMerge(fixture, mergeCommit);
      await hydratePublicApplicationCandidate({
        baseRoot: fixture.base,
        candidateRoot: candidateData,
        expectedBaseCommit: fixture.baseCommit,
        expectedCandidateCommit: candidateCommit,
        expectedMergeCommit: mergeCommit,
        pullRequestNumber: PULL_REQUEST_NUMBER,
        repository: "central/repository",
        readToken: "test-read-token"
      }, localHydrationDependencies(fixture, packageDirectory));

      const verification = verifyPublicHookApplication({
        baseRoot: fixture.base,
        candidateRoot: candidateData,
        expectedBaseCommit: fixture.baseCommit,
        pullRequestNumber: PULL_REQUEST_NUMBER,
        expectedBuilderLogin: application.builder.githubLogin,
        expectedBuilderUserId: application.builder.githubUserId,
        expectedCandidateCommit: candidateCommit,
        expectedMergeCommit: mergeCommit,
        resolveSource: exactApplicationV3SourceResolver,
        resolveExactObjects: exactApplicationV3ObjectResolver(sourceFiles)
      });
      if (mismatch) {
        await assert.rejects(
          verification,
          (error) => error?.code === "APPLICATION_V2_BASE_LINEAGE_MISMATCH" && error?.kind === "candidate"
        );
      } else {
        const report = await verification;
        assert.equal(report.result, "valid-public-application-v3-package");
        assert.equal(report.applicationRevision, "2");
        assert.equal(report.approvalGranted, false);
      }
    });
  }
});

test("workflow canary hydration materializes exactly one policy-bound JSON blob", async (t) => {
  const fixture = createRevisionPair(t);
  const policyRecord = readTrustedLaunchPolicyFromGit({
    repositoryRoot: fixture.base,
    expectedBaseCommit: fixture.baseCommit
  });
  const applicationBytes = jsonBytes({
    schemaVersion: "programmable.workflow-canary-application.v1",
    applicationId: "example-hook",
    applicationRevision: 1,
    builder: { githubLogin: "alice", githubUserId: BUILDER_USER_ID },
    source: {
      repository: "alice/example-hook",
      numericRepositoryId: PRIMARY.numericRepositoryId,
      commit: PRIMARY.revisionObjectId,
      tree: PRIMARY.treeObjectId
    },
    expectedPolicyBinding: buildLaunchPolicyBinding(policyRecord, "workflow-canary"),
    title: "Example Hook",
    summary: "One hidden workflow canary.",
    declarations: {
      hiddenFromPublicRoutingAndDiscovery: true,
      independentAudit: false,
      productionRouting: false,
      realUserFunds: false
    }
  });
  const applicationPath = "canary-submissions/example-hook/application.json";
  writeFile(fixture.candidate, applicationPath, applicationBytes);
  const candidateCommit = commitAll(fixture.candidate, "one workflow canary blob");
  const mergeCommit = createPullRequestMerge(fixture, candidateCommit);
  const applicationObjectId = blobObjectIdAtPath(fixture.candidate, applicationPath);
  const unrelatedBaseObjectId = blobObjectIdAtPath(fixture.base, "README.md");
  const candidateData = await fetchBloblessPullRequestMerge(fixture, mergeCommit);

  assert.equal(hasObjectWithoutLazyFetch(candidateData, applicationObjectId), false);
  assert.equal(hasObjectWithoutLazyFetch(candidateData, unrelatedBaseObjectId), false);
  const hydration = await hydratePublicApplicationCandidate({
    baseRoot: fixture.base,
    candidateRoot: candidateData,
    expectedBaseCommit: fixture.baseCommit,
    expectedCandidateCommit: candidateCommit,
    expectedMergeCommit: mergeCommit,
    pullRequestNumber: PULL_REQUEST_NUMBER,
    repository: "central/repository",
    readToken: "test-read-token"
  }, localHydrationDependencies(fixture, "canary-submissions/example-hook"));

  assert.equal(hydration.result, "bounded-workflow-canary-blob-hydrated");
  assert.equal(hydration.applicationId, "example-hook");
  assert.equal(hydration.fileCount, 1);
  assert.deepEqual(hydration.policyBinding, buildLaunchPolicyBinding(policyRecord, "workflow-canary"));
  assert.equal(hasObjectWithoutLazyFetch(candidateData, applicationObjectId), true);
  assert.equal(hasObjectWithoutLazyFetch(candidateData, unrelatedBaseObjectId), false);
});

test("candidate package cannot remove the mandatory companion closure receipt index", () => {
  const packageFiles = makePackage();
  const application = JSON.parse(packageFiles.get("application.json").toString("utf8"));
  delete application.companionClosure;
  packageFiles.set("application.json", jsonBytes(application));
  assert.throws(
    () => validatePackageFiles({ applicationId: "example-hook", packageFiles }),
    (error) => error?.code === "OBJECT_NOT_CLOSED" && error?.kind === "candidate"
  );
});

test("an allowlisted 100 MB blob is rejected from metadata before hydration", async (t) => {
  const fixture = createRevisionPair(t);
  writePackage(fixture.candidate, makePackage());
  const oversizedPath = path.join(fixture.candidate, "submissions/example-hook/PROPOSAL.md");
  fs.closeSync(fs.openSync(oversizedPath, "w"));
  fs.truncateSync(oversizedPath, 100 * 1024 * 1024);
  const candidateCommit = commitAll(fixture.candidate, "oversized allowlisted application blob");
  const mergeCommit = createPullRequestMerge(fixture, candidateCommit);
  const oversizedObjectId = blobObjectIdAtPath(fixture.candidate, "submissions/example-hook/PROPOSAL.md");
  const candidateData = await fetchBloblessPullRequestMerge(fixture, mergeCommit);

  assert.equal(hasObjectWithoutLazyFetch(candidateData, oversizedObjectId), false);
  await assert.rejects(
    hydratePublicApplicationCandidate({
      baseRoot: fixture.base,
      candidateRoot: candidateData,
      expectedBaseCommit: fixture.baseCommit,
      expectedCandidateCommit: candidateCommit,
      expectedMergeCommit: mergeCommit,
      pullRequestNumber: PULL_REQUEST_NUMBER,
      repository: "central/repository",
      readToken: "test-read-token"
    }, localHydrationDependencies(fixture)),
    (error) => error?.code === "APPLICATION_FILE_TOO_LARGE" && error?.kind === "candidate"
  );
  assert.equal(hasObjectWithoutLazyFetch(candidateData, oversizedObjectId), false);
  assert.equal(fs.existsSync(path.join(candidateData, "submissions")), false);
});

test("bounded hydration enforces a hard child file-size limit", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "public-hook-hydration-fsize-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const outputPath = path.join(root, "oversized.pack");
  const executable = writeExecutable(root, "write-too-much.sh", [
    "#!/bin/bash",
    `dd if=/dev/zero of=${shellQuote(outputPath)} bs=1048576 count=4 status=none`,
    ""
  ].join("\n"));
  const result = await runBoundedHydrationGitProcess({
    gitExecutable: executable,
    gitDirectory: root,
    args: ["backfill", "--sparse"],
    timeoutMs: 5_000,
    maximumOutputBytes: 65_536,
    maximumFileSizeBytes: 64 * 1024,
    maximumRepositoryBytes: 2 * 1024 * 1024
  });
  assert.notEqual(result.status, 0);
  assert.equal(result.fileSizeExceeded, true);
  assert.ok(fs.statSync(outputPath).size <= 64 * 1024);
});

test("bounded hydration timeout kills the complete Git process group", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "public-hook-hydration-process-tree-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const childPidPath = path.join(root, "child.pid");
  const executable = writeExecutable(root, "spawn-child.sh", [
    "#!/bin/bash",
    "sleep 30 &",
    `printf '%s\\n' \"$!\" > ${shellQuote(childPidPath)}`,
    "wait",
    ""
  ].join("\n"));
  const operation = runBoundedHydrationGitProcess({
    gitExecutable: executable,
    gitDirectory: root,
    args: ["backfill", "--sparse"],
    timeoutMs: 5_000,
    maximumOutputBytes: 65_536,
    maximumFileSizeBytes: 64 * 1024,
    maximumRepositoryBytes: 2 * 1024 * 1024
  });
  const childReady = await waitForRegularFile(childPidPath, 4_000);
  const childPid = childReady ? Number(fs.readFileSync(childPidPath, "utf8").trim()) : NaN;
  assert.equal(childReady, true, "the descendant must be running before the timeout assertion");
  assert.ok(Number.isInteger(childPid) && childPid > 1);
  assert.doesNotThrow(() => process.kill(childPid, 0));
  const result = await operation;
  assert.equal(result.timedOut, true);
  await waitForProcessExit(childPid);
});

test("trusted closed intake blocks application data before candidate Git fetch", async (t) => {
  for (const [intakeState, expectedCode] of [
    ["prelaunch", "INTAKE_PRELAUNCH"],
    ["paused-new", "INTAKE_PAUSED_NEW"],
    ["paused-all", "INTAKE_PAUSED_ALL"],
    ["closed", "INTAKE_CLOSED"]
  ]) {
    await t.test(intakeState, async (t2) => {
      const fixture = createRevisionPair(t2, { intakeState });
      const candidateRoot = path.join(fixture.root, "candidate.git");
      const candidateCommit = "b".repeat(40);
      let runFetchCalled = false;
      await assert.rejects(
        fetchPublicApplicationCandidate({
          baseRoot: fixture.base,
          candidateRoot,
          repository: "central/repository",
          pullRequestNumber: PULL_REQUEST_NUMBER,
          expectedBaseCommit: fixture.baseCommit,
          expectedCandidateCommit: candidateCommit,
          readToken: "test-read-token"
        }, {
          fetchImplementation: createPullRequestMetadataFetch({
            baseCommit: fixture.baseCommit,
            candidateCommit,
            files: [{ filename: "submissions/example-hook/application.json", status: "added" }]
          }),
          async runFetch() {
            runFetchCalled = true;
            assert.fail("closed application intake must stop before candidate Git fetch");
          }
        }),
        (error) => error?.code === expectedCode && error?.kind === "system"
      );
      assert.equal(runFetchCalled, false);
      assert.equal(fs.existsSync(candidateRoot), false);
    });
  }
});

test("closed intake metadata preflight still permits maintenance and existing paused-new updates", async (t) => {
  const maintenance = createRevisionPair(t, { intakeState: "prelaunch" });
  const maintenanceHead = "b".repeat(40);
  const maintenanceMerge = "c".repeat(40);
  const maintenanceReport = await preflightPublicApplicationCandidateFetch({
    baseRoot: maintenance.base,
    expectedBaseCommit: maintenance.baseCommit,
    expectedCandidateCommit: maintenanceHead,
    expectedMergeCommit: maintenanceMerge,
    repository: "central/repository",
    pullRequestNumber: PULL_REQUEST_NUMBER,
    readToken: "test-read-token"
  }, {
    fetchImplementation: createPullRequestMetadataFetch({
      baseCommit: maintenance.baseCommit,
      candidateCommit: maintenanceHead,
      mergeCommit: maintenanceMerge,
      files: [{ filename: "vendor/programmable-v4-hook-builder/SKILL.md", status: "modified" }]
    })
  });
  assert.equal(maintenanceReport.modeHint, "non-application");

  const update = createRevisionPair(t, { intakeState: "paused-new", existingApplication: true });
  const updateHead = "d".repeat(40);
  const updateMerge = "e".repeat(40);
  const updateReport = await preflightPublicApplicationCandidateFetch({
    baseRoot: update.base,
    expectedBaseCommit: update.baseCommit,
    expectedCandidateCommit: updateHead,
    expectedMergeCommit: updateMerge,
    repository: "central/repository",
    pullRequestNumber: PULL_REQUEST_NUMBER,
    readToken: "test-read-token"
  }, {
    fetchImplementation: createPullRequestMetadataFetch({
      baseCommit: update.baseCommit,
      candidateCommit: updateHead,
      mergeCommit: updateMerge,
      files: [{ filename: "submissions/example-hook/application.json", status: "modified" }]
    })
  });
  assert.equal(updateReport.modeHint, "application-update");
});

test("trusted metadata proves a bounded application-only pull request without candidate execution", async () => {
  const baseCommit = "a".repeat(40);
  const candidateCommit = "b".repeat(40);
  const files = [...makePackage().keys()].map((fileName) => ({
    filename: `submissions/example-hook/${fileName}`,
    status: "added"
  }));
  const report = await verifyBoundedApplicationPullRequestPaths({
    repository: "central/repository",
    pullRequestNumber: PULL_REQUEST_NUMBER,
    expectedBaseCommit: baseCommit,
    expectedCandidateCommit: candidateCommit,
    readToken: "test-read-token"
  }, {
    fetchImplementation: createPullRequestMetadataFetch({ baseCommit, candidateCommit, files })
  });
  assert.deepEqual(report, {
    schemaVersion: 1,
    result: "bounded-public-application-paths",
    pullRequestNumber: PULL_REQUEST_NUMBER,
    applicationId: "example-hook",
    fileCount: 6,
    paths: files.map(({ filename }) => filename).sort()
  });
});

test("bounded application metadata rejects mixed, cross-application, renamed, removed, and oversized changes", async (t) => {
  const baseCommit = "a".repeat(40);
  const candidateCommit = "b".repeat(40);
  const cases = [
    ["empty", [], "CHANGED_PATH_NOT_ALLOWED"],
    ["mixed central path", [
      { filename: "submissions/example-hook/application.json", status: "modified" },
      { filename: "README.md", status: "modified" }
    ], "CHANGED_PATH_NOT_ALLOWED"],
    ["two application ids", [
      { filename: "submissions/example-hook/application.json", status: "modified" },
      { filename: "submissions/other-hook/application.json", status: "modified" }
    ], "CHANGED_PATH_NOT_ALLOWED"],
    ["unknown application file", [
      { filename: "submissions/example-hook/source.js", status: "added" }
    ], "CHANGED_PATH_NOT_ALLOWED"],
    ["renamed application file", [{
      filename: "submissions/example-hook/application.json",
      previous_filename: "submissions/other-hook/application.json",
      status: "renamed"
    }], "CHANGED_PATH_NOT_ALLOWED"],
    ["removed application file", [
      { filename: "submissions/example-hook/application.json", status: "removed" }
    ], "CHANGED_PATH_NOT_ALLOWED"],
    ["too many files", [
      ...[...makePackage().keys()].map((fileName) => ({
        filename: `submissions/example-hook/${fileName}`,
        status: "modified"
      })),
      { filename: "README.md", status: "modified" }
    ], "TOO_MANY_CHANGED_FILES"]
  ];
  for (const [name, files, expectedCode] of cases) {
    await t.test(name, async () => {
      await assert.rejects(
        verifyBoundedApplicationPullRequestPaths({
          repository: "central/repository",
          pullRequestNumber: PULL_REQUEST_NUMBER,
          expectedBaseCommit: baseCommit,
          expectedCandidateCommit: candidateCommit,
          readToken: "test-read-token"
        }, {
          fetchImplementation: createPullRequestMetadataFetch({ baseCommit, candidateCommit, files })
        }),
        (error) => error?.code === expectedCode
      );
    });
  }
  assert.throws(
    () => classifyBoundedApplicationPathChanges([
      { path: "submissions/example-hook/application.json", previousPath: null, status: "modified" },
      { path: "submissions/example-hook/application.json", previousPath: null, status: "modified" }
    ]),
    (error) => error?.code === "CHANGED_PATH_NOT_ALLOWED" && error?.kind === "candidate"
  );
});

test("bounded metadata accepts exactly one immutable Application V3 revision directory", async () => {
  const paths = [
    "application.v3.json",
    "PROPOSAL.md",
    "security/source-verification.primary.v1.json"
  ].map((relativePath) => ({
    path: `submissions/fade/v3/revisions/1/${relativePath}`,
    previousPath: null,
    status: "added"
  }));
  assert.deepEqual(classifyBoundedApplicationPathChanges(paths), {
    applicationId: "fade",
    applicationRevision: "1",
    contract: "public-pr-application-v3",
    paths: paths.map(({ path: entryPath }) => entryPath).sort()
  });

  for (const changes of [
    [...paths, { path: "README.md", previousPath: null, status: "modified" }],
    [...paths, { path: "submissions/other/v3/revisions/1/application.v3.json", previousPath: null, status: "added" }],
    [...paths, { path: "submissions/fade/v3/revisions/2/application.v3.json", previousPath: null, status: "added" }],
    paths.map((change, index) => index === 0 ? { ...change, status: "modified" } : change),
    [...paths, { path: "submissions/fade/v3/revisions/1/.git/config", previousPath: null, status: "added" }]
  ]) {
    assert.throws(
      () => classifyBoundedApplicationPathChanges(changes),
      (error) => error?.code === "CHANGED_PATH_NOT_ALLOWED" && error?.kind === "candidate"
    );
  }
});

test("candidate preflight rejects a programmatic numeric pull-request identity", async (t) => {
  const fixture = createRevisionPair(t, { intakeState: "open" });
  await assert.rejects(
    preflightPublicApplicationCandidateFetch({
      baseRoot: fixture.base,
      expectedBaseCommit: fixture.baseCommit,
      expectedCandidateCommit: "b".repeat(40),
      expectedMergeCommit: "c".repeat(40),
      repository: "central/repository",
      pullRequestNumber: 7,
      readToken: "test-read-token"
    }, {
      fetchImplementation: async () => assert.fail("invalid identity must stop before GitHub metadata")
    }),
    (error) => error?.code === "CANDIDATE_FETCH_ID_INVALID" && error?.kind === "system"
  );
});

test("paused-new preflight permits only the exact trusted PR and application pair", async (t) => {
  const fixture = createRevisionPair(t, {
    intakeState: "paused-new",
    continuingPullRequests: [continuationRecord()]
  });
  const candidateCommit = "b".repeat(40);
  const mergeCommit = "c".repeat(40);
  const files = [...makePackage().keys()].map((fileName) => ({
    filename: `submissions/example-hook/${fileName}`,
    status: "added"
  }));
  const report = await preflightPublicApplicationCandidateFetch({
    baseRoot: fixture.base,
    expectedBaseCommit: fixture.baseCommit,
    expectedCandidateCommit: candidateCommit,
    expectedMergeCommit: mergeCommit,
    repository: "central/repository",
    pullRequestNumber: PULL_REQUEST_NUMBER,
    readToken: "test-read-token"
  }, {
    fetchImplementation: createPullRequestMetadataFetch({
      baseCommit: fixture.baseCommit,
      candidateCommit,
      mergeCommit,
      files
    })
  });
  assert.equal(report.modeHint, "application-continuation");
  assert.equal(report.pullRequestNumber, PULL_REQUEST_NUMBER);
  assert.equal(report.continuationAuthorized, true);

  for (const [name, continuingPullRequests] of [
    ["wrong application", [continuationRecord({ applicationId: "other-hook" })]],
    ["wrong pull request", [continuationRecord({ pullRequestNumber: "8" })]],
    ["empty allowlist", []]
  ]) {
    await t.test(name, async (t2) => {
      const blocked = createRevisionPair(t2, { intakeState: "paused-new", continuingPullRequests });
      await assert.rejects(
        preflightPublicApplicationCandidateFetch({
          baseRoot: blocked.base,
          expectedBaseCommit: blocked.baseCommit,
          expectedCandidateCommit: candidateCommit,
          expectedMergeCommit: mergeCommit,
          repository: "central/repository",
          pullRequestNumber: PULL_REQUEST_NUMBER,
          readToken: "test-read-token"
        }, {
          fetchImplementation: createPullRequestMetadataFetch({
            baseCommit: blocked.baseCommit,
            candidateCommit,
            mergeCommit,
            files
          })
        }),
        (error) => error?.code === "INTAKE_PAUSED_NEW" && error?.kind === "system"
      );
    });
  }
});

test("the 32-record worst-case continuation status stays within its enforced byte bound", async (t) => {
  const companionNumericRepositoryIds = Array.from({ length: 8 }, (_, index) => String(index + 1).repeat(64));
  const continuingPullRequests = Array.from({ length: 32 }, (_, index) => ({
    applicationId: `hook-${String(index).padStart(2, "0")}-${"a".repeat(70)}`,
    builderGitHubUserId: "8".repeat(64),
    companionNumericRepositoryIds,
    primaryNumericRepositoryId: "9".repeat(64),
    pullRequestNumber: (90_000_000_000_000_000_00n + BigInt(index)).toString()
  }));
  const statusSource = `${canonicalJson({
    continuingPullRequests,
    schemaVersion: 2,
    state: "paused-new"
  })}\n`;
  assert.ok(Buffer.byteLength(statusSource, "utf8") <= 32 * 1024);

  const fixture = createRevisionPair(t, { intakeState: "paused-new", continuingPullRequests });
  const candidateCommit = "b".repeat(40);
  const mergeCommit = "c".repeat(40);
  const report = await preflightPublicApplicationCandidateFetch({
    baseRoot: fixture.base,
    expectedBaseCommit: fixture.baseCommit,
    expectedCandidateCommit: candidateCommit,
    expectedMergeCommit: mergeCommit,
    repository: "central/repository",
    pullRequestNumber: PULL_REQUEST_NUMBER,
    readToken: "test-read-token"
  }, {
    fetchImplementation: createPullRequestMetadataFetch({
      baseCommit: fixture.baseCommit,
      candidateCommit,
      mergeCommit,
      files: [{ filename: "vendor/programmable-v4-hook-builder/SKILL.md", status: "modified" }]
    })
  });
  assert.equal(report.modeHint, "non-application");
});

test("hydration and final verification rebind a continuation to trusted builder and repository lineage", async (t) => {
  const cases = [
    ["builder", (application) => { application.builder.githubUserId = "999"; }],
    ["primary", (application) => { application.source.primary.numericRepositoryId = "999"; }],
    ["companions", (application) => {
      application.source.companions = [{
        repositoryUri: "https://github.com/alice/companion",
        numericRepositoryId: "987654321",
        revisionObjectId: "c".repeat(40),
        treeObjectId: "d".repeat(40),
        sourcePaths: [],
        contractPaths: [],
        githubActionsRunIds: []
      }];
    }]
  ];
  for (const [name, mutate] of cases) {
    await t.test(name, async (t2) => {
      const fixture = createRevisionPair(t2, {
        intakeState: "paused-new",
        continuingPullRequests: [continuationRecord()]
      });
      const packageFiles = makePackage();
      const application = JSON.parse(packageFiles.get("application.json").toString("utf8"));
      mutate(application);
      packageFiles.set("application.json", jsonBytes(application));
      writePackage(fixture.candidate, packageFiles);
      const candidateCommit = commitAll(fixture.candidate, `continuation ${name} lineage swap`);
      const mergeCommit = createPullRequestMerge(fixture, candidateCommit);
      const candidateData = fetchBloblessPullRequestMergeWithoutIntake(fixture, mergeCommit);
      await assert.rejects(
        hydratePublicApplicationCandidate({
          baseRoot: fixture.base,
          candidateRoot: candidateData,
          expectedBaseCommit: fixture.baseCommit,
          expectedCandidateCommit: candidateCommit,
          expectedMergeCommit: mergeCommit,
          pullRequestNumber: PULL_REQUEST_NUMBER,
          repository: "central/repository",
          readToken: "test-read-token"
        }, localHydrationDependencies(fixture)),
        (error) => error?.code === "INTAKE_CONTINUATION_IDENTITY_MISMATCH" && error?.kind === "candidate"
      );
    });
  }
});

test("a fully bound paused-new continuation passes hydration and final verification", async (t) => {
  const fixture = createRevisionPair(t, {
    intakeState: "paused-new",
    continuingPullRequests: [continuationRecord()]
  });
  writePackage(fixture.candidate, makePackage());
  const candidateCommit = commitAll(fixture.candidate, "exact paused-new continuation");
  const mergeCommit = createPullRequestMerge(fixture, candidateCommit);
  const candidateData = fetchBloblessPullRequestMergeWithoutIntake(fixture, mergeCommit);
  const hydration = await hydratePublicApplicationCandidate({
    baseRoot: fixture.base,
    candidateRoot: candidateData,
    expectedBaseCommit: fixture.baseCommit,
    expectedCandidateCommit: candidateCommit,
    expectedMergeCommit: mergeCommit,
    pullRequestNumber: PULL_REQUEST_NUMBER,
    repository: "central/repository",
    readToken: "test-read-token"
  }, localHydrationDependencies(fixture));
  assert.equal(hydration.continuationAuthorized, true);

  const report = await verifyPublicHookApplication({
    baseRoot: fixture.base,
    candidateRoot: candidateData,
    expectedBaseCommit: fixture.baseCommit,
    expectedBuilderLogin: "alice",
    expectedBuilderUserId: BUILDER_USER_ID,
    expectedCandidateCommit: candidateCommit,
    expectedMergeCommit: mergeCommit,
    pullRequestNumber: PULL_REQUEST_NUMBER,
    resolveSource: exactSourceResolver,
    resolveEvidence: exactEvidenceResolver
  });
  assert.equal(report.continuationAuthorized, true);
  assert.equal(report.pullRequestNumber, PULL_REQUEST_NUMBER);
});

test("paused-new preflight rejects foreign, mixed, renamed, and deleted application paths before fetch", async (t) => {
  const fixture = createRevisionPair(t, { intakeState: "paused-new", existingApplication: true });
  const candidateCommit = "b".repeat(40);
  const mergeCommit = "c".repeat(40);
  const cases = [
    {
      name: "foreign application id",
      files: [{ filename: "submissions/foreign-hook/application.json", status: "modified" }],
      code: "INTAKE_PAUSED_NEW"
    },
    {
      name: "mixed central path",
      files: [
        { filename: "submissions/example-hook/application.json", status: "modified" },
        { filename: "README.md", status: "modified" }
      ],
      code: "CHANGED_PATH_NOT_ALLOWED"
    },
    {
      name: "renamed application path",
      files: [{
        filename: "submissions/example-hook/application.json",
        previous_filename: "submissions/foreign-hook/application.json",
        status: "renamed"
      }],
      code: "CHANGED_PATH_NOT_ALLOWED"
    },
    {
      name: "deleted application path",
      files: [{ filename: "submissions/example-hook/application.json", status: "removed" }],
      code: "CHANGED_PATH_NOT_ALLOWED"
    }
  ];
  for (const entry of cases) {
    await t.test(entry.name, async () => {
      await assert.rejects(
        preflightPublicApplicationCandidateFetch({
          baseRoot: fixture.base,
          expectedBaseCommit: fixture.baseCommit,
          expectedCandidateCommit: candidateCommit,
          repository: "central/repository",
          pullRequestNumber: PULL_REQUEST_NUMBER,
          readToken: "test-read-token"
        }, {
          fetchImplementation: createPullRequestMetadataFetch({
            baseCommit: fixture.baseCommit,
            candidateCommit,
            mergeCommit,
            files: entry.files
          })
        }),
        (error) => error?.code === entry.code
      );
    });
  }
});

test("candidate preflight binds exact GitHub base and head without removed merge metadata", async (t) => {
  const fixture = createRevisionPair(t, { intakeState: "prelaunch" });
  const candidateCommit = "b".repeat(40);
  for (const mismatch of ["base", "head"]) {
    await t.test(mismatch, async () => {
      const observedBase = mismatch === "base" ? "d".repeat(40) : fixture.baseCommit;
      const observedHead = mismatch === "head" ? "d".repeat(40) : candidateCommit;
      await assert.rejects(
        preflightPublicApplicationCandidateFetch({
          baseRoot: fixture.base,
          expectedBaseCommit: fixture.baseCommit,
          expectedCandidateCommit: candidateCommit,
          repository: "central/repository",
          pullRequestNumber: PULL_REQUEST_NUMBER,
          readToken: "test-read-token"
        }, {
          fetchImplementation: createPullRequestMetadataFetch({
            baseCommit: observedBase,
            candidateCommit: observedHead,
            files: [{ filename: "submissions/example-hook/application.json", status: "added" }]
          })
        }),
        (error) => error?.code === "CANDIDATE_PREFLIGHT_ID_MISMATCH" && error?.kind === "system"
      );
    });
  }
});

test("hydration enforces trusted intake state before GitHub tree metadata or backfill", async (t) => {
  const fixture = createRevisionPair(t, { intakeState: "prelaunch" });
  writePackage(fixture.candidate, makePackage());
  const candidateCommit = commitAll(fixture.candidate, "prelaunch application package");
  const mergeCommit = createPullRequestMerge(fixture, candidateCommit);
  const candidateData = fetchBloblessPullRequestMergeWithoutIntake(fixture, mergeCommit);
  let metadataCalled = false;

  await assert.rejects(
    hydratePublicApplicationCandidate({
      baseRoot: fixture.base,
      candidateRoot: candidateData,
      expectedBaseCommit: fixture.baseCommit,
      expectedCandidateCommit: candidateCommit,
      expectedMergeCommit: mergeCommit,
      pullRequestNumber: PULL_REQUEST_NUMBER,
      repository: "central/repository",
      readToken: "test-read-token"
    }, {
      fetchImplementation: async () => {
        metadataCalled = true;
        assert.fail("closed intake must stop before candidate tree metadata");
      }
    }),
    (error) => error?.code === "INTAKE_PRELAUNCH" && error?.kind === "system"
  );
  assert.equal(metadataCalled, false);
});

test("initial candidate fetch derives the merge id and immediately binds the event head", async (t) => {
  const fixture = createRevisionPair(t, { intakeState: "open" });
  writeFile(fixture.candidate, "vendor/programmable-v4-hook-builder/SKILL.md", "candidate data\n");
  const candidateCommit = commitAll(fixture.candidate, "candidate revision");
  const mergeCommit = createPullRequestMerge(fixture, candidateCommit);
  git(fixture.candidate, ["update-ref", `refs/pull/${PULL_REQUEST_NUMBER}/merge`, mergeCommit]);
  git(fixture.candidate, ["config", "uploadpack.allowFilter", "true"]);
  const candidateData = path.join(fixture.root, "candidate.git");

  await assert.rejects(
    fetchPublicApplicationCandidate({
      baseRoot: fixture.base,
      candidateRoot: candidateData,
      repository: "central/repository",
      pullRequestNumber: PULL_REQUEST_NUMBER,
      expectedBaseCommit: fixture.baseCommit,
      expectedCandidateCommit: "d".repeat(40),
      readToken: "test-read-token"
    }, {
      remoteUrlForTests: pathToFileURL(fixture.candidate).href,
      allowFileProtocolForTests: true,
      fetchImplementation: createPullRequestMetadataFetch({
        baseCommit: fixture.baseCommit,
        candidateCommit: "d".repeat(40),
        files: pullRequestChangedFiles(fixture.candidate, fixture.baseCommit, candidateCommit)
      })
    }),
    (error) => error?.code === "PR_MERGE_PARENT_MISMATCH" && error?.kind === "system"
  );
  assert.equal(fs.existsSync(candidateData), false);
});

test("initial candidate fetch rejects a giant pack and removes the token-bearing object store", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "public-hook-fetch-giant-pack-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const candidateData = path.join(root, "candidate.git");
  const base = path.join(root, "base");
  fs.mkdirSync(base);
  git(base, ["init", "-b", "main"]);
  configureIdentity(base, "Trusted Test", "trusted@example.invalid");
  writeFile(base, "docs/builder/intake-status.json", `${canonicalJson({ continuingPullRequests: [], schemaVersion: 2, state: "open" })}\n`);
  const baseCommit = commitAll(base, "trusted open intake");
  const executable = writeExecutable(root, "write-giant-pack.sh", [
    "#!/bin/bash",
    `dd if=/dev/zero of=${shellQuote(path.join(candidateData, "objects/pack/untrusted.pack"))} bs=1048576 count=4 status=none`,
    ""
  ].join("\n"));

  await assert.rejects(
    fetchPublicApplicationCandidate({
      baseRoot: base,
      candidateRoot: candidateData,
      repository: "central/repository",
      pullRequestNumber: PULL_REQUEST_NUMBER,
      expectedBaseCommit: baseCommit,
      expectedCandidateCommit: "b".repeat(40),
      readToken: "test-read-token"
    }, {
      remoteUrlForTests: "https://github.com/central/repository.git",
      fetchImplementation: createPullRequestMetadataFetch({
        baseCommit,
        candidateCommit: "b".repeat(40),
        files: []
      }),
      maximumFileSizeBytes: 64 * 1024,
      maximumRepositoryBytes: 2 * 1024 * 1024,
      runFetch(parameters) {
        return runBoundedHydrationGitProcess({ ...parameters, gitExecutable: executable });
      }
    }),
    (error) => error?.code === "CANDIDATE_FETCH_BOUNDED_FAILURE" && error?.kind === "system"
  );
  assert.equal(fs.existsSync(candidateData), false);
});

test("Linux candidate Git runner hard-stops compressed-pack-style address-space expansion", {
  skip: process.platform !== "linux" || !fs.existsSync("/usr/bin/perl")
}, async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "public-hook-fetch-address-space-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const executable = writeExecutable(root, "expand-in-memory.pl", [
    "#!/usr/bin/perl",
    "my $payload = 'x' x (256 * 1024 * 1024);",
    "print STDERR 'allocation unexpectedly succeeded: ' . length($payload) . \"\\n\";",
    ""
  ].join("\n"));

  const result = await runBoundedHydrationGitProcess({
    gitExecutable: executable,
    gitDirectory: root,
    args: ["index-pack", "--stdin"],
    timeoutMs: 5_000,
    maximumOutputBytes: 65_536,
    maximumFileSizeBytes: 2 * 1024 * 1024,
    maximumRepositoryBytes: 2 * 1024 * 1024,
    maximumAddressSpaceBytes: 96 * 1024 * 1024,
    maximumCpuSeconds: 4
  });
  assert.notEqual(result.status, 0);
  assert.equal(result.addressSpaceExceeded, true);
  assert.doesNotMatch(result.stderr.toString("utf8"), /allocation unexpectedly succeeded/u);
});

function makePackage({ applicationId = "example-hook" } = {}) {
  const submissionPath = `submissions/${applicationId}/submission.json`;
  const programmableFee = makeProgrammableFee();
  const submissionBytes = sourceSubmissionBytes(programmableFee, applicationId);
  const submissionSha256 = `sha256:${crypto.createHash("sha256").update(submissionBytes).digest("hex")}`;
  const primary = {
    ...PRIMARY,
    sourcePaths: [...new Set([
      ...PRIMARY.sourcePaths,
      submissionPath
    ])].sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right))),
    contractPaths: [...new Set([
      ...PRIMARY.contractPaths,
      "src/ProgrammableFeeHook.sol",
      "test/ProgrammableFeeHook.t.sol"
    ])].sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)))
  };
  const files = new Map([
    ["PROPOSAL.md", Buffer.from("# Proposal\nA bounded public application for an exact external GitHub source revision.\n")],
    ["TEST_PLAN.md", Buffer.from("# Test plan\nRun builder-owned unit, fuzz, invariant, static-analysis, and integration evidence.\n")],
    ["THREAT_MODEL.md", Buffer.from("# Threat model\nPoolManager authority, value conservation, custody, exits, and failure paths require review.\n")]
  ]);
  const sourceProjection = {
    numericRepositoryId: PRIMARY.numericRepositoryId,
    revisionObjectId: PRIMARY.revisionObjectId,
    treeObjectId: PRIMARY.treeObjectId
  };
  files.set("compatibility-report.json", jsonBytes({
    schemaVersion: 1,
    applicationId,
    source: sourceProjection,
    result: "architecture-review-required",
    findings: [],
    disclaimer: PUBLIC_BETA_DISCLAIMER
  }));
  files.set("evidence-index.json", jsonBytes({
    schemaVersion: 1,
    applicationId,
    source: sourceProjection,
    attestation: "builder-declared-untrusted",
    evidence: [
      {
        id: "unit-tests",
        kind: "unit",
        status: "passed",
        scope: "Builder-owned checks for the exact declared source revision.",
        url: `${PRIMARY.repositoryUri}/actions/runs/123`,
        sha256: null
      },
      {
        id: "zz-programmable-fee-submission",
        kind: "static-analysis",
        status: "passed",
        scope: "Exact source submission used to recompute the mandatory Programmable fee projection.",
        url: `${PRIMARY.repositoryUri}/blob/${PRIMARY.revisionObjectId}/${submissionPath}`,
        sha256: submissionSha256
      }
    ]
  }));
  files.set("application.json", jsonBytes({
    schemaVersion: 2,
    applicationId,
    applicationRevision: 1,
    stage: "proposal",
    title: "Example external hook application",
    summary: "A public GitHub source binding with a bounded central review package.",
    builder: {
      githubUserId: BUILDER_USER_ID,
      githubLogin: "alice",
      contact: "https://github.com/alice"
    },
    builderTemplate: manualBuilderTemplate(),
    source: {
      schemaVersion: "1.0.0",
      primary: { ...primary, sourcePaths: [...primary.sourcePaths], contractPaths: [...primary.contractPaths], githubActionsRunIds: [...primary.githubActionsRunIds] },
      companions: []
    },
    companionClosure: [],
    programmableFee: {
      ...programmableFee,
      submissionBinding: { path: submissionPath, sha256: submissionSha256 }
    },
    reviewPackage: reviewRecords(files),
    declarations: {
      publicInformationAcknowledged: true,
      noSecretsDeclared: true,
      noApprovalClaim: true,
      noUniswapEndorsementClaim: true
    }
  }));
  return files;
}

function makeProgrammableFee() {
  return {
    policyId: "programmable-volume-fee-v1",
    policyVersion: "1.1.0",
    poolScope: "canonical-launch-pool-key",
    rates: {
      unit: "hundredths-of-bip",
      selectedBuyHundredthsOfBip: 30000,
      selectedSellHundredthsOfBip: 20000,
      minimumEffectiveHundredthsOfBip: 1000,
      effectiveBuyHundredthsOfBip: 30000,
      effectiveSellHundredthsOfBip: 20000,
      platformHundredthsOfBip: 1000,
      projectBuyHundredthsOfBip: 29000,
      projectSellHundredthsOfBip: 19000,
      formula: "per-side:effective=max(selected,1000);platform=1000;project=effective-1000",
      lpFeeExcluded: true
    },
    basis: { volume: "gross-quote-side-swap-volume", quoteAsset: "canonical-pool-quote-asset" },
    ownership: {
      owner: "0x4957f49620AFf3Adbbe8195a4f633E49cc93376c",
      immutable: true,
      claimAuthority: "owner-only",
      claimAvailability: "anytime",
      claimDestinationPolicy: "owner-or-owner-selected-per-claim",
      storedMutableRecipient: false,
      builderCanMutate: false,
      projectCanMutate: false,
      administratorCanMutate: false
    },
    collection: {
      status: "implemented",
      integration: "canonical-pool-hook",
      enforcement: "non-bypassable",
      hookFeeMechanismBinding: "hook.feeMechanism",
      supportedSwapModes: [
        "zeroForOne-exactInput",
        "zeroForOne-exactOutput",
        "oneForZero-exactInput",
        "oneForZero-exactOutput"
      ],
      swapModePaths: {
        zeroForOneExactInput: "after-swap-return-delta",
        zeroForOneExactOutput: "after-swap-return-delta",
        oneForZeroExactInput: "after-swap-return-delta",
        oneForZeroExactOutput: "after-swap-return-delta"
      },
      selfCallPolicy: "same-pool-swap-forbidden"
    },
    accounting: {
      accrualMode: "claimable-liability",
      liabilityKeyDimensions: ["poolId", "currency", "owner"],
      crossPoolNetting: false,
      roundingPolicy: "cumulative-independent-platform-project-remainders",
      remainderScope: "canonical-pool-lifetime",
      claimResetsRemainders: false,
      minimumGrossQuoteUnits: 1000,
      fragmentationResistant: true,
      valueFlowId: "programmable-volume-fee",
      collectionEvent: "ProgrammableFeeAccrued(bytes32,address,uint256)",
      claimEvent: "ProgrammableFeeClaimed(address,address,uint256)"
    },
    evidence: {
      sourcePaths: ["src/ProgrammableFeeHook.sol"],
      testPaths: ["test/ProgrammableFeeHook.t.sol"]
    }
  };
}

function makeApplicationV3Package(options = {}) {
  const fixture = createApplicationV3TestPackage({
    ...options,
    builderGithubUserId: BUILDER_USER_ID,
    builderGithubLogin: "alice",
    sourceRepositoryUri: PRIMARY.repositoryUri,
    sourceNumericRepositoryId: PRIMARY.numericRepositoryId,
    sourceRevisionObjectId: PRIMARY.revisionObjectId,
    sourceTreeObjectId: PRIMARY.treeObjectId
  });
  return {
    application: fixture.application,
    packageFiles: fixture.applicationPackageFiles,
    sourceFiles: fixture.sourceFiles
  };
}

function writeApplicationV3Revision(repository, packageDirectory, packageFiles) {
  for (const [relativePath, bytes] of packageFiles) {
    writeFile(repository, `${packageDirectory}/${relativePath}`, bytes);
  }
}

function installTrustedApplicationV3Revision(fixture, candidatePackage, message) {
  const { application, packageFiles } = candidatePackage;
  const packageDirectory = `submissions/${application.applicationId}/v3/revisions/${application.applicationRevision}`;
  writeApplicationV3Revision(fixture.base, packageDirectory, packageFiles);
  fixture.baseCommit = commitAll(fixture.base, message);
  git(fixture.candidate, ["fetch", "--quiet", fixture.base, fixture.baseCommit]);
  git(fixture.candidate, ["reset", "--hard", fixture.baseCommit]);
}

async function prepareApplicationV3Candidate(
  fixture,
  candidatePackage,
  message,
  { hydrate = true } = {}
) {
  const { application, packageFiles } = candidatePackage;
  const packageDirectory = `submissions/${application.applicationId}/v3/revisions/${application.applicationRevision}`;
  writeApplicationV3Revision(fixture.candidate, packageDirectory, packageFiles);
  const candidateCommit = commitAll(fixture.candidate, message);
  const mergeCommit = createPullRequestMerge(fixture, candidateCommit);
  if (!hydrate) return { candidateCommit, candidateData: fixture.candidate, mergeCommit };
  const candidateData = await fetchBloblessPullRequestMerge(fixture, mergeCommit);
  await hydratePublicApplicationCandidate({
    baseRoot: fixture.base,
    candidateRoot: candidateData,
    expectedBaseCommit: fixture.baseCommit,
    expectedCandidateCommit: candidateCommit,
    expectedMergeCommit: mergeCommit,
    pullRequestNumber: PULL_REQUEST_NUMBER,
    repository: "central/repository",
    readToken: "test-read-token"
  }, localHydrationDependencies(fixture, packageDirectory));
  return { candidateCommit, candidateData, mergeCommit };
}

function applicationV3VerificationInput(fixture, candidatePackage, prepared) {
  const { application } = candidatePackage;
  return {
    baseRoot: fixture.base,
    candidateRoot: prepared.candidateData,
    expectedBaseCommit: fixture.baseCommit,
    pullRequestNumber: PULL_REQUEST_NUMBER,
    expectedBuilderLogin: application.builder.githubLogin,
    expectedBuilderUserId: application.builder.githubUserId,
    expectedCandidateCommit: prepared.candidateCommit,
    expectedMergeCommit: prepared.mergeCommit
  };
}

function deriveApplicationV3PreviousBinding(
  application,
  packageFiles,
  targetContractVersion = application.contract.version
) {
  const applicationBytes = packageFiles.get("application.v3.json");
  const targetDirectory = `submissions/${application.applicationId}/v3/revisions/${application.applicationRevision}`;
  const files = [{
    path: `${targetDirectory}/application.v3.json`,
    mediaType: "application/json",
    byteLength: applicationBytes.length,
    sha256: sha256Bytes(applicationBytes)
  }, ...application.reviewPackage.records
    .filter((record) => record.source === "application-package")
    .map((record) => ({
      path: `${targetDirectory}/${record.path}`,
      mediaType: record.mediaType,
      byteLength: record.byteLength,
      sha256: record.sha256
    }))]
    .sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));
  return derivePublicPrApplicationV3PreviousBinding({
    application,
    applicationSha256: sha256Bytes(applicationBytes),
    packageSha256: sha256Bytes(Buffer.from(canonicalJson({
      contract: "public-pr-application-v3-package",
      applicationId: application.applicationId,
      applicationRevision: application.applicationRevision,
      targetDirectory,
      files
    }), "utf8")),
    targetContractVersion
  });
}
async function exactApplicationV3SourceResolver(request) {
  const primary = request.primary;
  return {
    schemaVersion: "1.0.0",
    kind: "github-public-source",
    canonicalProviderOrigin: "https://github.com",
    githubApiVersion: "2026-03-10",
    primary: {
      role: "primary",
      authority: {
        numericRepositoryId: primary.numericRepositoryId,
        revisionObjectId: primary.revisionObjectId,
        treeObjectId: primary.treeObjectId
      },
      display: {
        repositoryUri: primary.repositoryUri,
        owner: "alice",
        repository: "example-hook",
        defaultBranch: "main"
      },
      visibility: "public",
      sourcePaths: [...primary.sourcePaths],
      contractPaths: [...primary.contractPaths],
      githubActionsEvidence: []
    },
    companions: []
  };
}

function exactApplicationV3ObjectResolver(sourceFiles) {
  return async (request) => ({
    records: new Map(request.paths.map((sourcePath) => {
      const bytes = sourceFiles.get(sourcePath);
      assert.ok(bytes, `unexpected exact Application V3 source path: ${sourcePath}`);
      return [sourcePath, {
        mode: "100644",
        objectId: crypto.createHash("sha1")
          .update(Buffer.from(`blob ${bytes.length}\0`, "utf8"))
          .update(bytes)
          .digest("hex"),
        bytes
      }];
    }))
  });
}

function sha256Bytes(bytes) {
  return `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
}

function sourceSubmissionBytes(programmableFee, applicationId = "example-hook") {
  return Buffer.from(`${canonicalJson({
    builderTemplate: manualBuilderTemplate(),
    model: { id: applicationId },
    programmableFee,
    schemaVersion: 1,
    standardVersion: "1.6.0"
  })}\n`, "utf8");
}

function manualBuilderTemplate() {
  return {
    schemaVersion: "1.0.0",
    source: "manual",
    templateSelection: null
  };
}

function reviewRecords(files) {
  return [...files.entries()]
    .sort(([left], [right]) => Buffer.compare(Buffer.from(left), Buffer.from(right)))
    .map(([fileName, bytes]) => ({
      path: fileName,
      sha256: `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`,
      byteLength: bytes.length
    }));
}

function deriveLegacyV2PreviousBinding({ applicationId, packageFiles, submissionBytes }) {
  const applicationBytes = packageFiles.get("application.json");
  const application = JSON.parse(applicationBytes.toString("utf8"));
  const submission = JSON.parse(submissionBytes.toString("utf8"));
  const applicationDirectory = `submissions/${applicationId}`;
  const orderedFiles = [
    "application.json",
    "PROPOSAL.md",
    "TEST_PLAN.md",
    "THREAT_MODEL.md",
    "compatibility-report.json",
    "evidence-index.json"
  ];
  return {
    applicationContract: "public-pr-application-v2",
    applicationSchemaVersion: 2,
    applicationRevision: String(application.applicationRevision),
    applicationSha256: sha256Bytes(applicationBytes),
    packageSha256: sha256Bytes(Buffer.from(canonicalJson({
      applicationDirectory,
      applicationRevision: application.applicationRevision,
      files: orderedFiles.map((filePath) => ({
        path: filePath,
        byteLength: packageFiles.get(filePath).length,
        sha256: sha256Bytes(packageFiles.get(filePath))
      }))
    }), "utf8")),
    sourceNumericRepositoryId: application.source.primary.numericRepositoryId,
    sourceCommit: application.source.primary.revisionObjectId,
    sourceTree: application.source.primary.treeObjectId,
    submissionSchemaId: typeof submission.$schema === "string" ? submission.$schema : null,
    submissionStandard: submission.standardVersion,
    submissionPath: application.programmableFee.submissionBinding.path,
    submissionSha256: application.programmableFee.submissionBinding.sha256,
    feePolicyId: application.programmableFee.policyId,
    feePolicyVersion: application.programmableFee.policyVersion,
    feeApplicability: "unresolved",
    feePolicyInstanceSha256: null
  };
}

function jsonBytes(value) {
  return Buffer.from(`${canonicalJson(value)}\n`);
}

function continuationRecord(overrides = {}) {
  return {
    applicationId: "example-hook",
    builderGitHubUserId: BUILDER_USER_ID,
    companionNumericRepositoryIds: [],
    primaryNumericRepositoryId: PRIMARY.numericRepositoryId,
    pullRequestNumber: PULL_REQUEST_NUMBER,
    ...overrides
  };
}

function validatePackageFiles(options) {
  return validatePublicApplicationPackageFiles({
    ...options,
    legacyPolicyAdapter: LOCAL_LEGACY_POLICY_ADAPTER
  });
}

function createRevisionPair(t, {
  intakeState = "open",
  existingApplication = false,
  continuingPullRequests = []
} = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "public-hook-blobless-candidate-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const base = path.join(root, "base");
  const candidate = path.join(root, "candidate-source");
  fs.mkdirSync(base);
  git(base, ["init", "-b", "main"]);
  configureIdentity(base, "Trusted Test", "trusted@example.invalid");
  git(base, ["remote", "add", "origin", "https://github.com/0xprogrammable/launch-policy.git"]);
  writeFile(base, "README.md", "trusted base\n");
  writeFile(base, "policy/launch-policy.v1.json", TRUSTED_POLICY_BYTES);
  writeFile(
    base,
    "docs/builder/intake-status.json",
    `${canonicalJson({ continuingPullRequests, schemaVersion: 2, state: intakeState })}\n`
  );
  if (existingApplication) writePackage(base, makePackage());
  const baseCommit = commitAll(base, "trusted base");
  const clone = childProcess.spawnSync("git", ["clone", "--quiet", "--no-hardlinks", base, candidate], {
    encoding: "utf8",
    shell: false,
    env: trustedGitEnvironment()
  });
  assert.equal(clone.status, 0, clone.stderr);
  configureIdentity(candidate, "Candidate Test", "candidate@example.invalid");
  return { root, base, candidate, baseCommit };
}

function createPullRequestMerge(fixture, candidateCommit) {
  git(fixture.candidate, ["fetch", "--quiet", "--no-tags", fixture.base, fixture.baseCommit]);
  const mergedTree = git(fixture.candidate, ["merge-tree", "--write-tree", fixture.baseCommit, candidateCommit]);
  const mergeCommit = git(fixture.candidate, [
    "commit-tree",
    mergedTree,
    "-p", fixture.baseCommit,
    "-p", candidateCommit,
    "-m", "Synthetic GitHub pull request merge"
  ]);
  git(fixture.candidate, ["reset", "--hard", mergeCommit]);
  return mergeCommit;
}

async function fetchBloblessPullRequestMerge(fixture, mergeCommit) {
  const candidateData = path.join(fixture.root, "candidate.git");
  const candidateCommit = git(fixture.candidate, ["rev-parse", `${mergeCommit}^2`]);
  const files = pullRequestChangedFiles(fixture.candidate, fixture.baseCommit, candidateCommit);
  git(fixture.candidate, ["update-ref", `refs/pull/${PULL_REQUEST_NUMBER}/merge`, mergeCommit]);
  git(fixture.candidate, ["config", "uploadpack.allowFilter", "true"]);
  const report = await fetchPublicApplicationCandidate({
    baseRoot: fixture.base,
    candidateRoot: candidateData,
    repository: "central/repository",
    pullRequestNumber: PULL_REQUEST_NUMBER,
    expectedBaseCommit: fixture.baseCommit,
    expectedCandidateCommit: candidateCommit,
    readToken: "test-read-token"
  }, {
    remoteUrlForTests: pathToFileURL(fixture.candidate).href,
    allowFileProtocolForTests: true,
    fetchImplementation: createPullRequestMetadataFetch({
      baseCommit: fixture.baseCommit,
      candidateCommit,
      files
    })
  });
  assert.equal(report.result, "exact-blobless-candidate-fetched");
  assert.equal(report.mergeCommit, mergeCommit);
  return candidateData;
}

function fetchBloblessPullRequestMergeWithoutIntake(fixture, mergeCommit) {
  const candidateData = path.join(fixture.root, "candidate.git");
  git(fixture.candidate, ["update-ref", `refs/pull/${PULL_REQUEST_NUMBER}/merge`, mergeCommit]);
  git(fixture.candidate, ["config", "uploadpack.allowFilter", "true"]);
  const init = childProcess.spawnSync("git", ["init", "--quiet", "--bare", candidateData], {
    encoding: "utf8",
    shell: false,
    env: trustedGitEnvironment()
  });
  assert.equal(init.status, 0, init.stderr);
  git(candidateData, ["remote", "add", "origin", pathToFileURL(fixture.candidate).href]);
  git(candidateData, ["config", "remote.origin.promisor", "true"]);
  git(candidateData, ["config", "remote.origin.partialclonefilter", "blob:none"]);
  const fetch = childProcess.spawnSync("git", [
    "-c", "protocol.file.allow=always",
    "-C", candidateData,
    "fetch", "--quiet", "--force", "--no-tags", "--depth=1", "--filter=blob:none",
    "origin", `+refs/pull/${PULL_REQUEST_NUMBER}/merge:refs/heads/candidate-merge`
  ], {
    encoding: "utf8",
    shell: false,
    env: trustedGitEnvironment()
  });
  assert.equal(fetch.status, 0, fetch.stderr);
  git(candidateData, ["symbolic-ref", "HEAD", "refs/heads/candidate-merge"]);
  return candidateData;
}

function createPullRequestMetadataFetch({ baseCommit, candidateCommit, files, draft = true, state = "open" }) {
  const pullRequestUrl = `https://api.github.com/repos/central/repository/pulls/${PULL_REQUEST_NUMBER}`;
  const documents = new Map([
    [pullRequestUrl, {
      number: Number(PULL_REQUEST_NUMBER),
      state,
      draft,
      base: { sha: baseCommit, repo: { full_name: "central/repository" } },
      head: { sha: candidateCommit },
      changed_files: files.length
    }],
    [`${pullRequestUrl}/files?per_page=100&page=1`, files]
  ]);
  return async (url, options) => {
    assert.equal(options.method, "GET");
    assert.equal(options.redirect, "error");
    assert.equal(options.headers.Authorization, "Bearer test-read-token");
    assert.equal(options.headers["X-GitHub-Api-Version"], "2026-03-10");
    assert.ok(documents.has(url), `unexpected preflight URL: ${url}`);
    const body = Buffer.from(JSON.stringify(documents.get(url)));
    return {
      status: 200,
      redirected: false,
      url,
      headers: { get(name) { return name.toLowerCase() === "content-length" ? String(body.length) : null; } },
      body: null,
      async arrayBuffer() { return body; }
    };
  };
}

function pullRequestChangedFiles(repository, baseCommit, candidateCommit) {
  const statusNames = new Map([["A", "added"], ["M", "modified"], ["D", "removed"]]);
  return git(repository, ["diff", "--name-status", "--no-renames", baseCommit, candidateCommit])
    .split("\n")
    .filter(Boolean)
    .map((line) => {
      const [status, filename] = line.split("\t");
      assert.ok(statusNames.has(status), `unexpected GitHub fixture status: ${line}`);
      return { filename, status: statusNames.get(status) };
    });
}

function writePackage(repository, files, applicationId = "example-hook") {
  for (const [fileName, bytes] of files) {
    writeFile(repository, `submissions/${applicationId}/${fileName}`, bytes);
  }
}

function writeFile(root, relativePath, contents) {
  const target = path.join(root, relativePath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, contents);
}

function configureIdentity(repository, name, email) {
  git(repository, ["config", "user.name", name]);
  git(repository, ["config", "user.email", email]);
}

function commitAll(repository, message) {
  git(repository, ["add", "-A"]);
  git(repository, ["commit", "-m", message]);
  return git(repository, ["rev-parse", "HEAD"]);
}

function blobObjectIdAtPath(repository, relativePath) {
  const output = git(repository, ["ls-tree", "HEAD", "--", relativePath]);
  const match = /^100644 blob ([a-f0-9]{40})\t/u.exec(output);
  assert.ok(match, `expected one regular blob at ${relativePath}`);
  return match[1];
}

function hasObjectWithoutLazyFetch(repository, objectId) {
  const result = childProcess.spawnSync("git", ["-C", repository, "cat-file", "-e", objectId], {
    encoding: "utf8",
    shell: false,
    env: { ...trustedGitEnvironment(), GIT_NO_LAZY_FETCH: "1" }
  });
  assert.ok([0, 1].includes(result.status), result.stderr);
  return result.status === 0;
}

function git(repository, args) {
  const result = childProcess.spawnSync("git", ["-C", repository, ...args], {
    encoding: "utf8",
    shell: false,
    env: trustedGitEnvironment()
  });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

function trustedGitEnvironment() {
  return {
    ...process.env,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_TERMINAL_PROMPT: "0"
  };
}

function localHydrationDependencies(fixture, packageDirectory = "submissions/example-hook") {
  return {
    allowFileProtocolForTests: true,
    remoteUrlForTests: pathToFileURL(fixture.candidate).href,
    fetchImplementation: createTreeMetadataFetch(fixture.candidate, packageDirectory)
  };
}

function createTreeMetadataFetch(repository, packageDirectory = "submissions/example-hook") {
  const recursive = packageDirectory.includes("/v3/revisions/");
  const packageTreeObjectId = git(repository, ["rev-parse", `HEAD:${packageDirectory}`]);
  const records = git(repository, ["ls-tree", ...(recursive ? ["-r"] : []), "-l", `HEAD:${packageDirectory}`])
    .split("\n")
    .filter(Boolean)
    .map((line) => {
      const match = /^([0-7]{6}) (blob|tree|commit) ([a-f0-9]{40})\s+([0-9-]+)\t(.+)$/u.exec(line);
      assert.ok(match, `unexpected ls-tree metadata: ${line}`);
      return {
        path: match[5],
        mode: match[1],
        type: match[2],
        sha: match[3],
        size: Number(match[4]),
        url: `https://api.github.com/repos/central/repository/git/blobs/${match[3]}`
      };
    });
  const body = Buffer.from(JSON.stringify({
    sha: packageTreeObjectId,
    url: `https://api.github.com/repos/central/repository/git/trees/${packageTreeObjectId}`,
    truncated: false,
    tree: records
  }));
  return async (url, options) => {
    assert.equal(
      url,
      `https://api.github.com/repos/central/repository/git/trees/${packageTreeObjectId}${recursive ? "?recursive=1" : ""}`
    );
    assert.equal(options.method, "GET");
    assert.equal(options.redirect, "error");
    assert.equal(options.headers.Authorization, "Bearer test-read-token");
    return {
      status: 200,
      redirected: false,
      url,
      headers: { get(name) { return name.toLowerCase() === "content-length" ? String(body.length) : null; } },
      body: null,
      async arrayBuffer() { return body; }
    };
  };
}

function createMultipleTreeMetadataFetch(repository, plans) {
  const documents = new Map();
  for (const { commit, packageDirectory } of plans) {
    const packageTreeObjectId = git(repository, ["rev-parse", `${commit}:${packageDirectory}`]);
    const records = git(repository, ["ls-tree", "-r", "-l", `${commit}:${packageDirectory}`])
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        const match = /^([0-7]{6}) (blob|tree|commit) ([a-f0-9]{40})\s+([0-9-]+)\t(.+)$/u.exec(line);
        assert.ok(match, `unexpected historical ls-tree metadata: ${line}`);
        return {
          path: match[5],
          mode: match[1],
          type: match[2],
          sha: match[3],
          size: Number(match[4]),
          url: `https://api.github.com/repos/central/repository/git/blobs/${match[3]}`
        };
      });
    const url = `https://api.github.com/repos/central/repository/git/trees/${packageTreeObjectId}?recursive=1`;
    documents.set(url, Buffer.from(JSON.stringify({
      sha: packageTreeObjectId,
      url: url.slice(0, -"?recursive=1".length),
      truncated: false,
      tree: records
    })));
  }
  return async (url, options) => {
    assert.equal(options.method, "GET");
    assert.equal(options.redirect, "error");
    assert.equal(options.headers.Authorization, "Bearer test-read-token");
    assert.ok(documents.has(url), `unexpected historical tree URL: ${url}`);
    const body = documents.get(url);
    return {
      status: 200,
      redirected: false,
      url,
      headers: { get(name) { return name.toLowerCase() === "content-length" ? String(body.length) : null; } },
      body: null,
      async arrayBuffer() { return body; }
    };
  };
}

function writeExecutable(root, name, source) {
  const target = path.join(root, name);
  fs.writeFileSync(target, source, { mode: 0o700 });
  fs.chmodSync(target, 0o700);
  return target;
}

function shellQuote(value) {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

async function waitForRegularFile(target, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      if (fs.lstatSync(target).isFile()) return true;
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  return false;
}

async function waitForProcessExit(pid) {
  const deadline = Date.now() + 2_000;
  while (Date.now() < deadline) {
    try {
      process.kill(pid, 0);
    } catch (error) {
      if (error?.code === "ESRCH") return;
      throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  assert.fail(`descendant process ${pid} survived the bounded process-group timeout`);
}

async function exactSourceResolver(source) {
  const primary = source.primary;
  return {
    schemaVersion: "1.0.0",
    kind: "github-public-source",
    canonicalProviderOrigin: "https://github.com",
    githubApiVersion: "2026-03-10",
    primary: {
      role: "primary",
      authority: {
        numericRepositoryId: primary.numericRepositoryId,
        revisionObjectId: primary.revisionObjectId,
        treeObjectId: primary.treeObjectId
      },
      display: {
        repositoryUri: primary.repositoryUri,
        owner: "alice",
        repository: "example-hook",
        defaultBranch: "main"
      },
      visibility: "public",
      sourcePaths: [...primary.sourcePaths],
      contractPaths: [...primary.contractPaths],
      githubActionsEvidence: [{
        runId: "123",
        runAttempt: "1",
        workflowId: "456",
        workflowPath: ".github/workflows/ci.yml",
        headRevision: primary.revisionObjectId,
        headTree: primary.treeObjectId,
        event: "push",
        status: "completed",
        conclusion: "success",
        htmlUrl: `${primary.repositoryUri}/actions/runs/123`
      }]
    },
    companions: []
  };
}

async function exactEvidenceResolver({ primary, evidence }) {
  return evidence.map((record) => {
    assert.equal(record.id, "zz-programmable-fee-submission");
    const bytes = sourceSubmissionBytes(makeProgrammableFee());
    return {
      id: record.id,
      path: "submissions/example-hook/submission.json",
      blobObjectId: crypto.createHash("sha1")
        .update(Buffer.from(`blob ${bytes.length}\0`, "utf8"))
        .update(bytes)
        .digest("hex"),
      bytes
    };
  });
}
