import crypto from "node:crypto";
import fs from "node:fs";

import { canonicalJson } from "../../vendor/programmable-v4-hook-builder/scripts/submission-core.mjs";
import {
  OPEN_WORLD_V2_ARTIFACTS,
  OPEN_WORLD_V2_OPTIONAL_SUPPORTING_ARTIFACTS,
  OPEN_WORLD_V2_SUPPORTING_ARTIFACTS,
  architectureSnapshotSha256,
  sha256Bytes
} from "../../vendor/programmable-v4-hook-builder/scripts/open-world-v2-core.mjs";
import {
  createApplicableOpenWorldV2PrototypeFixture,
  createNoMarketOpenWorldV2PrototypeFixture
} from "./fixtures/open-world-v2-prototype-fixture.mjs";
import {
  PUBLIC_PR_APPLICATION_V3_BASE_REQUIRED_REVIEW_KINDS
} from "../verify-public-application-v3-core.mjs";
import {
  tradeCapabilityManifestSha256V2,
  tradeTestResultSha256V2
} from "../verify-open-world-v2-trade-manifest-v2.mjs";
import {
  canonicalProgrammableLaunchRouterReadinessJson,
  computeProgrammableLaunchRouterRouteCommitmentV1,
  computeProgrammableStampRequestV1Commitment,
  deriveProgrammableLaunchRouterSourceConfigurationHashV1,
  parseProgrammableLaunchRouterReadinessBytesV1,
  PROGRAMMABLE_LAUNCH_ROUTER_READINESS_PATH,
  PROGRAMMABLE_LAUNCH_ROUTER_READINESS_SCHEMA_ID,
  PROGRAMMABLE_LAUNCH_ROUTER_READINESS_SCHEMA_PATH,
  PROGRAMMABLE_LAUNCH_ROUTER_V1_DEVELOPER_REFERENCE,
  PROGRAMMABLE_LAUNCH_ROUTER_V1_MANIFEST_PROJECTION,
  PROGRAMMABLE_LAUNCH_ROUTER_V1_RESOLVED_ROUTER,
  PROGRAMMABLE_TREASURY_TEN_BPS_CONFIGURATION_SHA256
} from "../programmable-launch-router-readiness-core.mjs";

const EXAMPLE_PATH = new URL("./fixtures/public-pr-application-v3.1.example.json", import.meta.url);
const SECURITY_SCHEMA_PATH = new URL(
  "../../vendor/programmable-v4-hook-builder/references/open-world-security-v1.schema.json",
  import.meta.url
);
const ROUTER_READINESS_SCHEMA_PATH = new URL(
  `../../${PROGRAMMABLE_LAUNCH_ROUTER_READINESS_SCHEMA_PATH}`,
  import.meta.url
);
const ROUTE_SOURCE_PATH = "src/LaunchRoute.sol";
const FEE_SOURCE_PATH = "src/FeeConfiguration.sol";

export function createApplicationV3TestPackage({
  applicationContractVersion = "3.1.0",
  feeMode = "not-selected",
  stage = "prototype",
  applicationId = "legacy-open-world-example",
  applicationRevision = "1",
  lineage = { kind: "new", previous: null },
  requestedRoute = "none",
  marketMode = requestedRoute === "programmable-ethereum-mainnet" ? "tradable" : "no-market",
  builderGithubUserId = "424242",
  builderGithubLogin = "alice",
  sourceRepositoryUri = "https://github.com/alice/example-hook",
  sourceNumericRepositoryId = "123456789",
  sourceRevisionObjectId = "a".repeat(40),
  sourceTreeObjectId = "b".repeat(40)
} = {}) {
  if (!new Set(["proposal", "prototype"]).has(stage)) throw new TypeError("test fixture stage must be proposal or prototype");
  if (stage === "proposal" && feeMode !== "not-selected") throw new TypeError("proposal test fixture supports only the policy-neutral not-selected path");
  if (!new Set(["3.1.0", "3.2.0"]).has(applicationContractVersion)) throw new TypeError("test fixture contract version is unsupported");
  if (applicationContractVersion === "3.1.0" && requestedRoute !== "none") throw new TypeError("Application V3.1 cannot claim launch readiness");
  if (applicationContractVersion === "3.2.0" && feeMode !== "not-selected") throw new TypeError("Application V3.2 uses policy-neutral Submission 2.1");
  if (!new Set(["none", "other", "programmable-ethereum-mainnet"]).has(requestedRoute)) throw new TypeError("test fixture requested route is unsupported");
  if (!new Set(["no-market", "tradable"]).has(marketMode)) throw new TypeError("test fixture market mode is unsupported");
  const rawSourcePackage = applicationContractVersion === "3.2.0" && marketMode === "tradable"
    ? createApplicableOpenWorldV2PrototypeFixture(applicationId)
    : feeMode === "selected"
    ? createApplicableOpenWorldV2PrototypeFixture(applicationId)
    : stage === "proposal"
      ? createFeeUnselectedV2ProposalFixture(applicationId)
      : createFeeUnselectedV2PrototypeFixture(applicationId);
  const sourcePackage = applicationContractVersion === "3.2.0"
    ? upgradeOpenWorldPackageToV2_1(rawSourcePackage)
    : rawSourcePackage;
  const application = JSON.parse(fs.readFileSync(EXAMPLE_PATH, "utf8"));
  const sourcePackageDirectory = `submissions/${applicationId}`;
  const submissionPath = `${sourcePackageDirectory}/submission.v2.json`;
  const applicationPackageFiles = new Map();
  const sourceFiles = new Map();
  const reviewRecords = [];
  const artifactKinds = classifySourcePackageArtifacts(sourcePackage);

  for (const [packagePath, bytes] of sourcePackage.files) {
    const kind = artifactKinds.get(packagePath) ?? "extension-schema";
    if (kind === "trade-capability-manifest" || kind === "trade-test-result") {
      applicationPackageFiles.set(packagePath, Buffer.from(bytes));
      reviewRecords.push(reviewRecord({ kind, path: packagePath, bytes, source: "application-package", repositoryRef: null }));
    } else {
      const repositoryPath = `${sourcePackageDirectory}/${packagePath}`;
      sourceFiles.set(repositoryPath, Buffer.from(bytes));
      reviewRecords.push(reviewRecord({ kind, path: repositoryPath, bytes, source: "source-repository", repositoryRef: "primary" }));
    }
  }

  Object.assign(application, {
    applicationId,
    applicationRevision,
    stage,
    lineage: structuredClone(lineage)
  });
  if (applicationContractVersion === "3.2.0") {
    application.contract = {
      id: "public-pr-application-v3",
      version: "3.2.0",
      submissionStandard: "2.1.0",
      validatorProfile: "intent-open-world-v2"
    };
    application.launchRequest = {
      requestedRoute,
      category: null,
      launchKind: null,
      routePlan: null,
      routerReadinessSchema: null
    };
  }
  let launchReadinessBytes = null;
  let launchReadinessDocument = null;
  let routeSourceBytes = null;
  let feeSourceBytes = null;
  const contractPaths = [];
  if (requestedRoute === "programmable-ethereum-mainnet") {
    const officialRoute = createOfficialProgrammableRouterRouteFixture({
      applicationId,
      applicationRevision,
      sourceRepositoryUri,
      sourceNumericRepositoryId,
      sourceRevisionObjectId,
      sourceTreeObjectId
    });
    ({
      launchReadinessBytes,
      launchReadinessDocument,
      routeSourceBytes,
      feeSourceBytes
    } = officialRoute);
    for (const [kind, repositoryPath, mediaType, bytes] of [
      ["programmable-launch-route-source", ROUTE_SOURCE_PATH, "text/plain", routeSourceBytes],
      ["programmable-launch-fee-source", FEE_SOURCE_PATH, "text/plain", feeSourceBytes],
      ["programmable-launch-router-readiness", PROGRAMMABLE_LAUNCH_ROUTER_READINESS_PATH, "application/json", launchReadinessBytes]
    ]) {
      sourceFiles.set(repositoryPath, bytes);
      reviewRecords.push(reviewRecord({ kind, path: repositoryPath, mediaType, bytes, source: "source-repository", repositoryRef: "primary" }));
    }
    contractPaths.push(ROUTE_SOURCE_PATH, FEE_SOURCE_PATH);
    application.launchRequest = {
      requestedRoute,
      category: "custom",
      launchKind: 1,
      routePlan: immutableGitArtifactBinding({
        bytes: launchReadinessBytes,
        commit: sourceRevisionObjectId,
        numericRepositoryId: sourceNumericRepositoryId,
        path: PROGRAMMABLE_LAUNCH_ROUTER_READINESS_PATH,
        repository: githubRepositoryFromUri(sourceRepositoryUri),
        tree: sourceTreeObjectId
      }),
      routerReadinessSchema: immutableGitArtifactBinding({
        bytes: fs.readFileSync(ROUTER_READINESS_SCHEMA_PATH),
        commit: "2".repeat(40),
        numericRepositoryId: "1320171831",
        path: PROGRAMMABLE_LAUNCH_ROUTER_READINESS_SCHEMA_PATH,
        repository: "0xprogrammable/launch-policy",
        tree: "3".repeat(40)
      })
    };
  }
  Object.assign(application.builder, {
    githubUserId: builderGithubUserId,
    githubLogin: builderGithubLogin,
    contact: `https://github.com/${builderGithubLogin}`
  });
  Object.assign(application.source.primary, {
    numericRepositoryId: sourceNumericRepositoryId,
    repositoryUri: sourceRepositoryUri,
    revisionObjectId: sourceRevisionObjectId,
    treeObjectId: sourceTreeObjectId,
    sourceClosureMode: "inline",
    sourcePaths: [...sourceFiles.keys()].sort(compareUtf8),
    sourceManifest: null,
    contractPaths: contractPaths.sort(compareUtf8),
    githubActionsRunIds: []
  });
  application.source.companions = [];
  application.intentCapture = {
    ...application.intentCapture,
    captureStatus: "captured-verbatim-public-safe",
    originalIdeaDisplayExcerpt: "Build the exact owner-confirmed complete project.",
    agentInterpretationStatus: "owner-confirmed",
    facts: application.intentCapture.facts.map((fact) => ({
      ...fact,
      provenance: "owner-stated",
      confirmationStatus: "confirmed"
    })),
    unresolvedMaterialDecisions: [],
    ideaSourcePath: `${sourcePackageDirectory}/${sourcePackage.submission.intentPackage.ideaSource.path}`,
    ideaSourceRepositoryRef: "primary",
    ideaSourceSha256: sourcePackage.submission.intentPackage.ideaSource.sha256
  };
  application.fidelity = {
    schemaVersion: "1.0.0",
    status: "complete",
    reasonCode: null,
    requirementBindings: []
  };

  const submissionBytes = sourcePackage.files.get("submission.v2.json");
  const policy = application.policyBindings;
  Object.assign(policy, {
    submissionPath,
    submissionRepositoryRef: "primary",
    submissionSha256: sha256Bytes(submissionBytes)
  });
  if (feeMode === "selected") {
    const fee = sourcePackage.submission.programmableFee;
    const schemaBinding = sourcePackage.submission.supportingPackage.feePolicySchema;
    const instanceBinding = sourcePackage.submission.supportingPackage.feePolicy;
    Object.assign(policy, {
      feePolicySchemaId: schemaBinding.schemaId,
      programmableFeePolicyId: fee.policyId,
      programmableFeePolicyVersion: fee.policyVersion,
      programmableFeePolicyHashPreimage: fee.policyHashPreimage,
      programmableFeePolicyHash: fee.policyHash,
      feeApplicability: sourcePackage.feeApplicability,
      feePolicySchemaPath: `${sourcePackageDirectory}/${schemaBinding.path}`,
      feePolicySchemaRepositoryRef: "primary",
      feePolicySchemaSha256: schemaBinding.sha256,
      feePolicyInstancePath: `${sourcePackageDirectory}/${instanceBinding.path}`,
      feePolicyInstanceRepositoryRef: "primary",
      feePolicyInstanceSha256: instanceBinding.sha256
    });
  } else {
    Object.assign(policy, {
      feePolicySchemaId: null,
      programmableFeePolicyId: null,
      programmableFeePolicyVersion: null,
      programmableFeePolicyHashPreimage: null,
      programmableFeePolicyHash: null,
      feeApplicability: "not-selected",
      feePolicySchemaPath: null,
      feePolicySchemaRepositoryRef: null,
      feePolicySchemaSha256: null,
      feePolicyInstancePath: null,
      feePolicyInstanceRepositoryRef: null,
      feePolicyInstanceSha256: null
    });
  }

  const sourcePathsSha256 = sha256Bytes(jsonBytes(application.source.primary.sourcePaths));
  const closureSha256 = sha256Bytes(Buffer.from(
    `test-inline-source-closure-v1\n${canonicalJson(application.source.primary.sourcePaths)}\n`,
    "utf8"
  ));
  const reportPath = "source-closure-verification.primary.json";
  const verificationReport = {
    status: "VERIFIED",
    sourceClosureVerified: true,
    readOnly: true,
    networkAccessed: false,
    candidateCodeExecuted: false,
    dependencyPointerCoverage: dependencyPointerCoverage(),
    sourceBinding: {
      repositoryRef: "primary",
      revisionObjectId: sourceRevisionObjectId,
      treeObjectId: sourceTreeObjectId,
      sourceClosureMode: "inline",
      sourcePaths: [...application.source.primary.sourcePaths],
      sourcePathsSha256,
      closureSha256
    }
  };
  const verificationReportBytes = jsonBytes(verificationReport);
  const verificationReportSha256 = sha256Bytes(verificationReportBytes);
  const persistedCoverage = {
    repositoryRef: "primary",
    revisionObjectId: sourceRevisionObjectId,
    treeObjectId: sourceTreeObjectId,
    sourceClosureMode: "inline",
    sourcePaths: [...application.source.primary.sourcePaths],
    sourcePathsSha256,
    manifestPath: null,
    manifestSha256: null,
    manifestByteLength: null,
    closureSha256,
    reportPath,
    reportSha256: verificationReportSha256,
    reportByteLength: verificationReportBytes.length,
    result: "VERIFIED"
  };
  application.source.verificationReports = [structuredClone(persistedCoverage)];
  const securityAssessment = {
    schemaVersion: "open-world-security-v1",
    subject: {
      id: applicationId,
      revision: sourceRevisionObjectId,
      stage
    },
    assessment: {
      state: "source-assessed",
      reasonCode: null,
      evidenceRefs: [reportPath],
      sourceCoverage: {
        primaryRepositoryRef: "primary",
        repositories: [structuredClone(persistedCoverage)]
      }
    },
    layers: {
      source: {
        evidenceRefs: [reportPath],
        customProfiles: []
      }
    },
    extensions: []
  };
  const securitySchema = JSON.parse(fs.readFileSync(SECURITY_SCHEMA_PATH, "utf8"));
  const securitySchemaBytes = jsonBytes(securitySchema);
  const securityAssessmentBytes = jsonBytes(securityAssessment);
  Object.assign(application.securityBindings, {
    securityAssessmentSchemaPath: "security-assessment-v1.schema.json",
    securityAssessmentSchemaRepositoryRef: null,
    securityAssessmentSchemaSha256: sha256Bytes(securitySchemaBytes),
    securityAssessmentSchemaByteLength: securitySchemaBytes.length,
    securityAssessmentPath: "security-assessment.v1.json",
    securityAssessmentRepositoryRef: null,
    securityAssessmentSha256: sha256Bytes(securityAssessmentBytes),
    securityAssessmentByteLength: securityAssessmentBytes.length
  });

  for (const [kind, filePath, mediaType, bytes] of [
    ["proposal", "PROPOSAL.md", "text/markdown", Buffer.from("# Proposal\n\nExact public review artifact.\n")],
    ["test-plan", "TEST_PLAN.md", "text/markdown", Buffer.from("# Test plan\n\nExact public review artifact.\n")],
    ["threat-model", "THREAT_MODEL.md", "text/markdown", Buffer.from("# Threat model\n\nExact public review artifact.\n")],
    ["compatibility-report", "compatibility-report.json", "application/json", jsonBytes(stage === "proposal"
      ? { result: "architecture-review-required", schemaVersion: 3 }
      : {})],
    ["evidence-index", "evidence-index.json", "application/json", jsonBytes({})],
    ["security-assessment-schema", "security-assessment-v1.schema.json", "application/schema+json", securitySchemaBytes],
    ["security-assessment", "security-assessment.v1.json", "application/json", securityAssessmentBytes],
    ["source-closure-verification", reportPath, "application/json", verificationReportBytes]
  ]) {
    applicationPackageFiles.set(filePath, bytes);
    reviewRecords.push(reviewRecord({ kind, path: filePath, mediaType, bytes, source: "application-package", repositoryRef: null }));
  }
  application.reviewPackage.requiredKinds = [
    ...PUBLIC_PR_APPLICATION_V3_BASE_REQUIRED_REVIEW_KINDS.slice(0, 9),
    ...(feeMode === "selected" ? ["fee-policy-schema"] : []),
    ...PUBLIC_PR_APPLICATION_V3_BASE_REQUIRED_REVIEW_KINDS.slice(9)
  ];
  application.reviewPackage.records = reviewRecords.sort((left, right) => (
    compareUtf8(`${left.source}:${left.repositoryRef ?? ""}:${left.path}:${left.kind}`, `${right.source}:${right.repositoryRef ?? ""}:${right.path}:${right.kind}`)
  ));
  applicationPackageFiles.set("application.v3.json", jsonBytes(application));
  return {
    application,
    applicationPackageFiles,
    sourceFiles,
    sourcePackage,
    securityAssessment,
    verificationReport,
    launchReadinessBytes,
    launchReadinessDocument,
    routeSourceBytes,
    feeSourceBytes
  };
}

function createOfficialProgrammableRouterRouteFixture({
  applicationId,
  applicationRevision,
  sourceRepositoryUri,
  sourceNumericRepositoryId,
  sourceRevisionObjectId,
  sourceTreeObjectId
}) {
  const numericRevision = Number(applicationRevision);
  if (!Number.isSafeInteger(numericRevision) || numericRevision < 1 || numericRevision > 1_000_000) {
    throw new TypeError("official route fixture requires a Router-readiness-compatible application revision");
  }
  const routeSourceBytes = Buffer.from(
    `// SPDX-License-Identifier: MIT\npragma solidity ^0.8.26;\ncontract LaunchRoute { address constant ROUTER = ${PROGRAMMABLE_LAUNCH_ROUTER_V1_RESOLVED_ROUTER.address}; bool constant DIRECT_FACTORY_FALLBACK_ALLOWED = false; }\n`,
    "utf8"
  );
  const feeSourceBytes = Buffer.from(
    "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.26;\ncontract FeeConfiguration { address constant TREASURY = 0x4957f49620AFf3Adbbe8195a4f633E49cc93376c; uint16 constant SWAP_FEE_BPS = 10; }\n",
    "utf8"
  );
  const routeArtifact = sourceArtifactBinding(ROUTE_SOURCE_PATH, routeSourceBytes);
  const feeImplementationArtifact = sourceArtifactBinding(FEE_SOURCE_PATH, feeSourceBytes);
  const sourceConfigurationHash = deriveProgrammableLaunchRouterSourceConfigurationHashV1({
    feeImplementationArtifact,
    routeArtifact
  });
  const routeCommitment = computeProgrammableLaunchRouterRouteCommitmentV1({
    category: "custom",
    routePayload: customGraphRouteFixture()
  });
  const routePayload = routePayloadDocument(routeCommitment);
  const stampRequest = customStampRequestFixture();
  const repository = githubRepositoryFromUri(sourceRepositoryUri);
  const liveResponse = canonicalReadinessBytes(PROGRAMMABLE_LAUNCH_ROUTER_V1_MANIFEST_PROJECTION);
  const launchReadinessDocument = {
    $schema: PROGRAMMABLE_LAUNCH_ROUTER_READINESS_SCHEMA_ID,
    applicability: {
      routeMode: "programmable-ethereum-mainnet",
      trustedDeclaration: null
    },
    authority: {
      approvalGranted: false,
      candidateCodeExecuted: false,
      credentialsUsed: false,
      externalWritesPerformed: false,
      launchAuthorized: false,
      networkAccessed: false,
      publicDiscoveryAuthorized: false,
      realUserFundsAuthorized: false,
      rpcAccessed: false
    },
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
      liveResponseSha256: sha256Bytes(liveResponse),
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
        expectedResult: {
          derivationMode: "router-v1-route-kind-specific-typed-hash",
          hash: routeCommitment.expectedResultHash,
          routePayloadSha256: routePayload.sha256
        },
        launchPermitV1: {
          bindingState: "wallet-and-validity-window-late-bound-before-signing",
          chainId: 1,
          deadline: null,
          domainName: "ProgrammableLaunchStampRouter",
          domainVersion: "1",
          expectedResultHash: routeCommitment.expectedResultHash,
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
        commit: sourceRevisionObjectId,
        configurationHash: sourceConfigurationHash,
        numericRepositoryId: sourceNumericRepositoryId,
        repository,
        tree: sourceTreeObjectId
      },
      transactionSelector: PROGRAMMABLE_LAUNCH_ROUTER_V1_RESOLVED_ROUTER.atomicSelector,
      transactionTarget: PROGRAMMABLE_LAUNCH_ROUTER_V1_RESOLVED_ROUTER.address
    },
    schemaVersion: "1.0.0",
    state: "prelaunch-bound",
    subject: {
      applicationId,
      applicationRevision: numericRevision,
      sourceCommit: sourceRevisionObjectId,
      sourceConfigurationHash,
      sourceRepository: repository,
      sourceRepositoryNumericId: sourceNumericRepositoryId,
      sourceTree: sourceTreeObjectId
    }
  };
  const launchReadinessBytes = canonicalReadinessBytes(launchReadinessDocument);
  parseProgrammableLaunchRouterReadinessBytesV1(launchReadinessBytes);
  return {
    launchReadinessBytes,
    launchReadinessDocument,
    routeSourceBytes,
    feeSourceBytes
  };
}

function customGraphRouteFixture() {
  return {
    expectedGraphDeploymentHash: bytes32("e"),
    expectedOutputs: [
      { account: address("1"), runtimeCodeHash: bytes32("a"), targetIdHash: bytes32("c"), targetIndex: 0 },
      { account: address("2"), runtimeCodeHash: bytes32("b"), targetIdHash: bytes32("d"), targetIndex: 1 }
    ],
    graphCommitment: bytes32("3"),
    routeNamespace: bytes32("1"),
    routeNonce: bytes32("9"),
    targets: [
      { applicantSalt: bytes32("0"), deploymentValue: "0", initCode: "0x6000", initializerCalldata: "0x", initializerValue: "0", targetIdHash: bytes32("c") },
      { applicantSalt: bytes32("0"), deploymentValue: "0", initCode: "0x6001", initializerCalldata: "0x", initializerValue: "0", targetIdHash: bytes32("d") }
    ],
    topologyHash: bytes32("2")
  };
}

function customStampRequestFixture() {
  const token = address("1");
  const hook = address("2");
  const tokenRuntimeCodeHash = bytes32("a");
  const hookRuntimeCodeHash = bytes32("b");
  const request = {
    components: [
      { account: token, kind: 1, resultIndex: 0, runtimeCodeHash: tokenRuntimeCodeHash, scope: 1 },
      { account: hook, kind: 2, resultIndex: 1, runtimeCodeHash: hookRuntimeCodeHash, scope: 1 }
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
  const commitment = computeProgrammableStampRequestV1Commitment({ category: "custom", stampRequest: request });
  return {
    ...request,
    componentSetHash: commitment.componentSetHash,
    hashAlgorithm: "router-v1-typed-hash",
    poolKeyHash: commitment.poolKeyHash,
    stampRequestHash: commitment.stampRequestHash,
    typeHash: "0xa61627b33bfee8131fa1b566b7787c8d93afc86629f51a5c9719bf8f6b3e5573",
    typeSignature: "ProgrammableStampRequestV1(bytes32 launchId,address token,bytes32 tokenRuntimeCodeHash,bytes32 poolKeyHash,bytes32 hookRuntimeCodeHash,bytes32 componentSetHash)"
  };
}

function routePayloadDocument(commitment) {
  return {
    byteLength: commitment.byteLength,
    contentBase64: commitment.contentBase64,
    encoding: commitment.encoding,
    keccak256: commitment.keccak256,
    sha256: commitment.sha256
  };
}

function sourceArtifactBinding(path, bytes) {
  return {
    byteLength: bytes.length,
    gitBlobOid: gitBlobOid(bytes),
    path,
    sha256: sha256Bytes(bytes)
  };
}

function immutableGitArtifactBinding({ bytes, commit, numericRepositoryId, path, repository, tree }) {
  return {
    schemaId: PROGRAMMABLE_LAUNCH_ROUTER_READINESS_SCHEMA_ID,
    repositoryRef: { repository, numericRepositoryId, commit, tree },
    path,
    gitBlobOid: gitBlobOid(bytes),
    sha256: sha256Bytes(bytes),
    byteLength: bytes.length
  };
}

function canonicalReadinessBytes(value) {
  return Buffer.from(`${canonicalProgrammableLaunchRouterReadinessJson(value)}\n`, "utf8");
}

function githubRepositoryFromUri(repositoryUri) {
  const parsed = new URL(repositoryUri);
  const repository = parsed.pathname.replace(/^\//u, "").replace(/\.git$/u, "");
  if (parsed.origin !== "https://github.com" || repository.split("/").length !== 2) {
    throw new TypeError("official route fixture requires one canonical GitHub repository URI");
  }
  return repository;
}

function gitBlobOid(bytes) {
  return crypto.createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex");
}

function bytes32(character) {
  return `0x${character.repeat(64)}`;
}

function address(character) {
  return `0x${character.repeat(40)}`;
}

function createFeeUnselectedV2PrototypeFixture(applicationId) {
  const original = createNoMarketOpenWorldV2PrototypeFixture(applicationId);
  const submission = structuredClone(original.submission);
  const files = new Map([...original.files].map(([filePath, bytes]) => [filePath, Buffer.from(bytes)]));
  delete submission.programmableFee;
  delete submission.supportingPackage.feePolicy;
  delete submission.supportingPackage.feePolicySchema;
  submission.authorities = submission.authorities.filter(({ id }) => id !== "programmable-fee-owner");
  submission.valueFlows = submission.valueFlows.filter(({ authorityRefs, to }) => (
    !authorityRefs.includes("programmable-fee-owner")
    && !(to.collection === "authorities" && to.id === "programmable-fee-owner")
  ));
  for (const market of submission.markets) market.canonicalScopes = [];
  files.delete("fee-policy-v2.schema.json");
  files.delete("fee-policy.v2.json");
  const intentFidelity = JSON.parse(files.get(OPEN_WORLD_V2_ARTIFACTS.intentFidelity.file));
  intentFidelity.inputDigests.architectureSnapshotSha256 = architectureSnapshotSha256(submission);
  const intentFidelityBytes = jsonBytes(intentFidelity);
  files.set(OPEN_WORLD_V2_ARTIFACTS.intentFidelity.file, intentFidelityBytes);
  submission.intentPackage.intentFidelity = artifactBinding(OPEN_WORLD_V2_ARTIFACTS.intentFidelity, intentFidelityBytes);
  files.set("submission.v2.json", jsonBytes(submission));
  return Object.freeze({ submission, files, feeApplicability: "not-selected" });
}

function createFeeUnselectedV2ProposalFixture(applicationId) {
  const original = createFeeUnselectedV2PrototypeFixture(applicationId);
  const submission = structuredClone(original.submission);
  const files = new Map([...original.files].map(([filePath, bytes]) => [filePath, Buffer.from(bytes)]));
  submission.stage = "proposal";
  submission.project.summary = {
    language: "en",
    text: "A custom tradable project whose exact route architecture remains unresolved for review."
  };
  submission.tradeCapability = {
    applicability: "unresolved",
    facetEntryRef: "routing-trade-capability",
    markets: []
  };
  const intentFidelity = JSON.parse(files.get(OPEN_WORLD_V2_ARTIFACTS.intentFidelity.file));
  intentFidelity.inputDigests.architectureSnapshotSha256 = architectureSnapshotSha256(submission);
  const intentFidelityBytes = jsonBytes(intentFidelity);
  files.set(OPEN_WORLD_V2_ARTIFACTS.intentFidelity.file, intentFidelityBytes);
  submission.intentPackage.intentFidelity = artifactBinding(OPEN_WORLD_V2_ARTIFACTS.intentFidelity, intentFidelityBytes);
  files.set("submission.v2.json", jsonBytes(submission));
  return Object.freeze({ submission, files, feeApplicability: "not-selected" });
}

function upgradeOpenWorldPackageToV2_1(original) {
  const submission = structuredClone(original.submission);
  const files = new Map([...original.files].map(([filePath, bytes]) => [filePath, Buffer.from(bytes)]));
  const obsoletePaths = new Set();
  for (const binding of [submission.supportingPackage?.feePolicy, submission.supportingPackage?.feePolicySchema]) {
    if (binding?.path) obsoletePaths.add(binding.path);
  }
  for (const scopeArtifact of submission.programmableFee?.conformance?.scopeArtifacts ?? []) {
    for (const binding of [scopeArtifact.receipt, scopeArtifact.vectorSet]) if (binding?.path) obsoletePaths.add(binding.path);
  }
  delete submission.programmableFee;
  delete submission.supportingPackage.feePolicy;
  delete submission.supportingPackage.feePolicySchema;
  submission.authorities = submission.authorities.filter(({ id }) => id !== "programmable-fee-owner");
  submission.valueFlows = submission.valueFlows.filter(({ authorityRefs, to }) => (
    !authorityRefs.includes("programmable-fee-owner")
    && !(to.collection === "authorities" && to.id === "programmable-fee-owner")
  ));
  for (const phase of submission.lifecyclePhases) {
    phase.valueFlowRefs = phase.valueFlowRefs.filter((ref) => ref !== "platform-fee-flow");
  }
  for (const market of submission.markets) market.canonicalScopes = [];
  submission.$schema = "urn:programmable:v4-hook-submission:2.1.0";
  submission.standardVersion = "2.1.0";
  for (const obsoletePath of obsoletePaths) files.delete(obsoletePath);

  for (const market of submission.tradeCapability?.markets ?? []) {
    const manifest = JSON.parse(files.get(market.manifest.path));
    const routeDefinedCurrency = manifest.feeBehavior.programmableFeeV2?.quoteCurrency ?? manifest.poolKey.currency0;
    delete manifest.feeBehavior.programmableFeeV2;
    manifest.$schema = "urn:programmable:trade-capability-manifest:2.0.0";
    manifest.schemaVersion = "2.0.0";
    manifest.contract = { id: "trade-capability-manifest-v2", version: "2.0.0" };
    manifest.testEvidence.contract = "source-test-contracts-v2";
    for (const component of manifest.feeBehavior.components) {
      if (component.currencyRole === "programmable-quote-currency") {
        component.currencyRole = "route-defined";
        component.routeDefinedCurrency = routeDefinedCurrency;
      }
    }
    for (const test of manifest.testEvidence.quoteTests) {
      test.resultContract = "trade-quote-test-result-v2";
      test.resultBindings = test.resultBindings.map((binding) => binding === "fee-conformance" ? "declared-fees" : binding);
    }
    for (const test of manifest.testEvidence.executionTests) {
      test.resultContract = "trade-execution-test-result-v2";
      test.resultBindings = test.resultBindings.map((binding) => binding === "fee-conformance" ? "declared-fees" : binding);
    }
    const manifestSha256 = tradeCapabilityManifestSha256V2(manifest);
    const feeBehaviorSha256 = tradeCapabilityManifestSha256V2(manifest.feeBehavior);
    for (const test of [...manifest.testEvidence.quoteTests, ...manifest.testEvidence.executionTests]) {
      const result = JSON.parse(files.get(test.resultArtifactPath));
      const quote = test.resultContract === "trade-quote-test-result-v2";
      result.$schema = quote
        ? "urn:programmable:trade-quote-test-result:2.0.0"
        : "urn:programmable:trade-execution-test-result:2.0.0";
      result.schemaVersion = "2.0.0";
      result.contract = test.resultContract;
      result.context.manifestSha256 = manifestSha256;
      result.context.fee = {
        feeBehaviorSha256,
        amounts: result.context.fee.amounts,
        quotedFeesSha256: result.context.fee.quotedFeesSha256
      };
      result.contentSha256 = tradeTestResultSha256V2(result);
      files.set(test.resultArtifactPath, jsonBytes(result));
    }
    const manifestBytes = jsonBytes(manifest);
    files.set(market.manifest.path, manifestBytes);
    market.manifest = {
      artifactType: "trade-capability-manifest",
      schemaId: "urn:programmable:trade-capability-manifest:2.0.0",
      path: market.manifest.path,
      sha256: sha256Bytes(manifestBytes),
      byteLength: manifestBytes.length
    };
  }

  const intentFidelityPath = submission.intentPackage.intentFidelity.path;
  const intentFidelity = JSON.parse(files.get(intentFidelityPath));
  intentFidelity.inputDigests.architectureSnapshotSha256 = architectureSnapshotSha256(submission);
  const intentFidelityBytes = jsonBytes(intentFidelity);
  files.set(intentFidelityPath, intentFidelityBytes);
  submission.intentPackage.intentFidelity = artifactBinding(OPEN_WORLD_V2_ARTIFACTS.intentFidelity, intentFidelityBytes);
  files.set("submission.v2.json", jsonBytes(submission));
  return Object.freeze({ submission, files, feeApplicability: "not-selected" });
}

function classifySourcePackageArtifacts(sourcePackage) {
  const kinds = new Map([["submission.v2.json", "submission"]]);
  for (const binding of Object.values(sourcePackage.submission.intentPackage ?? {})) {
    if (binding?.path) kinds.set(binding.path, binding.artifactType);
  }
  for (const binding of Object.values(sourcePackage.submission.supportingPackage ?? {})) {
    if (binding?.path) kinds.set(binding.path, binding.artifactType);
  }
  for (const artifact of sourcePackage.submission.programmableFee?.conformance?.scopeArtifacts ?? []) {
    for (const binding of [artifact.receipt, artifact.vectorSet]) if (binding?.path) kinds.set(binding.path, binding.artifactType);
  }
  for (const market of sourcePackage.submission.tradeCapability?.markets ?? []) {
    if (market.manifest?.path) {
      kinds.set(market.manifest.path, "trade-capability-manifest");
      const manifest = JSON.parse(sourcePackage.files.get(market.manifest.path));
      for (const test of [...(manifest.testEvidence?.quoteTests ?? []), ...(manifest.testEvidence?.executionTests ?? [])]) {
        kinds.set(test.resultArtifactPath, "trade-test-result");
      }
    }
  }
  return kinds;
}

function reviewRecord({ kind, path, mediaType = "application/json", bytes, source, repositoryRef }) {
  return {
    kind,
    path,
    mediaType,
    byteLength: bytes.length,
    sha256: sha256Bytes(bytes),
    source,
    repositoryRef
  };
}

function artifactBinding(spec, bytes) {
  return {
    artifactType: spec.artifactType,
    schemaId: spec.schemaId,
    path: spec.file,
    sha256: sha256Bytes(bytes),
    byteLength: bytes.length
  };
}

function dependencyPointerCoverage() {
  return {
    schemaVersion: "1.0.0",
    pointerCount: 0,
    pointerRecordsSha256: `sha256:${"0".repeat(64)}`,
    sourceCriticalDereferenceState: "NONE",
    counts: {
      symlink: 0,
      gitlink: 0,
      gitLfs: 0,
      internalVerified: 0,
      targetVerified: 0,
      unresolved: 0,
      sourceCritical: 0,
      runtimeAssetDelegated: 0,
      unclassified: 0
    }
  };
}

function jsonBytes(value) {
  return Buffer.from(`${canonicalJson(value)}\n`, "utf8");
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}
