import { isProtectedProgrammableRuntimeFeeSettlementPendingPolicyEvidenceV1 } from "./programmable-runtime-fee-settlement-proof-core.mjs";

function declaredEvidenceHandler({ evidence, rule }) {
  const missingEvidence = rule.evidence.filter((evidenceId) => !evidencePassed(evidence?.[evidenceId]));
  return Object.freeze({
    passed: missingEvidence.length === 0,
    status: missingEvidence.length === 0 ? "passed" : "failed",
    missingEvidence: Object.freeze(missingEvidence),
    message: missingEvidence.length === 0
      ? "All policy-declared evidence is present and passed."
      : `Missing passed evidence: ${missingEvidence.join(", ")}.`
  });
}

function evidencePassed(value) {
  return value === true || value?.status === "passed";
}

function exactEvidenceHandler({ evidence, rule }, parameterKeys) {
  const [evidenceId] = rule.evidence;
  const value = evidence?.[evidenceId];
  const expectedKeys = [...parameterKeys, "status"].sort();
  const observedKeys = value && typeof value === "object" && !Array.isArray(value)
    ? Object.keys(value).sort()
    : [];
  const exactParameters = observedKeys.length === expectedKeys.length
    && observedKeys.every((key, index) => key === expectedKeys[index])
    && parameterKeys.every((key) => value[key] === rule.parameters?.[key]);
  if ((value === undefined || (exactParameters && value.status === "analysis-pending"))) {
    return Object.freeze({
      passed: false,
      status: "analysis-pending",
      missingEvidence: Object.freeze([evidenceId]),
      message: `Policy evidence ${evidenceId} is analysis-pending.`
    });
  }
  const passed = exactParameters && value.status === "passed";
  return Object.freeze({
    passed,
    status: passed ? "passed" : "failed",
    missingEvidence: Object.freeze(passed ? [] : [evidenceId]),
    message: passed
      ? `Policy evidence ${evidenceId} exactly matches the current rule.`
      : `Policy evidence ${evidenceId} is missing or does not exactly match the current rule.`
  });
}

function ethereumTreasuryTenBpsHandler(context) {
  return exactEvidenceHandler(context, ["basis", "chainId", "hundredthsOfBip", "network", "treasury"]);
}

function programmableExactFeeTemplateHandler(context) {
  return exactEvidenceHandler(context, [
    "assetMode",
    "basis",
    "chainId",
    "claimPrerequisite",
    "enforcementProof",
    "hundredthsOfBip",
    "network",
    "rateDenominator",
    "treasury"
  ]);
}

function robinhoodNetworkAndPoolManagerProvenanceHandler(context) {
  return exactEvidenceHandler(context, [
    "caip2",
    "chainId",
    "network",
    "officialDeploymentRegistry",
    "poolManager",
    "registryCommit"
  ]);
}

function robinhoodProgrammableTrustRootsHandler(context) {
  return exactEvidenceHandler(context, [
    "chainDeploymentDescriptorRequired",
    "exactRuntimeHashesRequired",
    "foundationSourceCommitment",
    "graphFactoryRequired",
    "permitAuthorityRequired",
    "routerRequired",
    "sourceRepository",
    "sourceRepositoryBranch"
  ]);
}

function robinhoodWalletHandoffChainBindingHandler(context) {
  return exactEvidenceHandler(context, [
    "caip2",
    "chainId",
    "connectedAccountRecheckRequired",
    "connectedChainRecheckRequired",
    "crossChainReplayRejected",
    "destinationRuntimeHashRecheckRequired",
    "exactTransactionPreimageRequired",
    "walletSignatureSeparate"
  ]);
}

function robinhoodServerValidationAndSimulationHandler(context) {
  return exactEvidenceHandler(context, [
    "backendAuthority",
    "canonicalRequestBytesRebuilt",
    "chainSpecificForkSimulationRequired",
    "clientVerdictsAccepted",
    "deterministicValidationRequired",
    "llmAuthorizationAllowed",
    "pathBodyChainBindingRequired"
  ]);
}

function robinhoodFundingAndSettlementReadinessHandler(context) {
  return exactEvidenceHandler(context, [
    "advertisedFundingModes",
    "erc20ModesRequireSeparateProof",
    "settlementClosureRequired",
    "unsupportedModesAbsent"
  ]);
}

function robinhoodFinalizedRouterEvidenceHandler(context) {
  return exactEvidenceHandler(context, [
    "caip2",
    "chainId",
    "finalityCheckpoint",
    "finalizedRouterEvidenceRequired",
    "promotionTargets"
  ]);
}

function robinhoodSourceVerificationBindingHandler(context) {
  return exactEvidenceHandler(context, [
    "blockscoutAvailability",
    "blockscoutExactSourceClaimAllowed",
    "blockscoutFinalityBlocker",
    "exactMatchClaimRequiresProviderReceipt",
    "externalContractReferenceCaip2",
    "externalContractReferenceCheckpointRequired",
    "externalContractReferenceExactAddressRequired",
    "externalContractReferenceRoleRequired",
    "externalContractReferenceRuntimeHashRequired",
    "externalContractReferenceServerVerificationRequired",
    "externalContractReferenceSourceVerificationEvidenceRequired",
    "finalityIndependent",
    "jobStates",
    "requiredExactMatchProvider",
    "sourceBuildBindingRequired",
    "sourcifyV2ExactMatchRequired",
    "unboundExternalContractReferencesTrusted"
  ]);
}

function robinhoodIndexingAndReadinessHandler(context) {
  return exactEvidenceHandler(context, [
    "chainScopedIdentityRequired",
    "crossChainFailureIsolation",
    "lastKnownGoodSnapshotRequired",
    "qualityStates",
    "routerLedgerProjectionRequired"
  ]);
}

function robinhoodHonestFeeCapabilityHandler(context) {
  return exactEvidenceHandler(context, [
    "buybacksLive",
    "feeBehaviorClaim",
    "genericClaimingLive",
    "launchValidityIndependentOfFeeCertification",
    "universalFeeBehaviorClaim"
  ]);
}

function programmableVerifiedExecutedPlatformFeeHandler({ evidence, rule }) {
  const [evidenceId] = rule.evidence;
  const value = evidence?.[evidenceId];
  const parameterKeys = [
    "accountingMode",
    "activationPrerequisites",
    "activationState",
    "assetMode",
    "authorizationGateMode",
    "basis",
    "behaviorEvidenceSchemaVersion",
    "callerAssertionsAccepted",
    "callerExemptionAllowed",
    "callerVerdictsAccepted",
    "chainId",
    "claimIsolationRequired",
    "configurationIsExecutionEvidence",
    "evidenceAuthority",
    "executedHardInvariantFailureBlocksWalletHandoff",
    "feeVaultAppendCBOR",
    "feeVaultCompilerVersion",
    "feeVaultCreationCodeKeccak256",
    "feeVaultEvmVersion",
    "feeVaultMetadataBytecodeHash",
    "feeVaultOptimizerEnabled",
    "feeVaultOptimizerRuns",
    "feeVaultReleaseBindingId",
    "feeVaultReleaseBindingSha256",
    "feeVaultRuntimeCodeKeccak256",
    "feeVaultSourcePath",
    "feeVaultViaIR",
    "freshWritesEnabled",
    "hundredthsOfBip",
    "immutableFeePathRequired",
    "network",
    "noBypassRequired",
    "noOverchargeRequired",
    "oneTimeRouteCodehashBindingRequired",
    "otherBehaviorAxesDisposition",
    "platformFeeConformanceStatus",
    "productionRuntimeReadbackRequired",
    "profileVersion",
    "rateDenominator",
    "requestScope",
    "requiredFeeObservationIds",
    "requiredFeeVectorIds",
    "requiredSettlementDataflowClosureAssertions",
    "requiredSettlementDataflowClosureReceiptBindings",
    "requiredSettlementDataflowClosureReceiptClaims",
    "requiredSettlementDataflowReadback",
    "scenarioInputsAreExecutionEvidence",
    "settlementDataflowClosure",
    "serverSignatureRequired",
    "successfulSwapsOnly",
    "treasury"
  ];
  if (value === undefined) {
    return Object.freeze({
      passed: false,
      status: "analysis-pending",
      missingEvidence: Object.freeze([evidenceId]),
      message: "The private Custom Launch API has not supplied authoritative executed platform-fee evidence."
    });
  }
  const expectedKeys = [...parameterKeys, "status"].sort();
  const observedKeys = value && typeof value === "object" && !Array.isArray(value)
    ? Object.keys(value).sort()
    : [];
  const exactConfiguration = observedKeys.length === expectedKeys.length
    && observedKeys.every((key, index) => key === expectedKeys[index])
    && parameterKeys.every((key) => canonicalValue(value[key]) === canonicalValue(rule.parameters?.[key]));
  if (!exactConfiguration) {
    return Object.freeze({
      passed: false,
      status: "failed",
      missingEvidence: Object.freeze([evidenceId]),
      message: "The claimed platform-fee configuration does not match the immutable V3.4 rule."
    });
  }
  return Object.freeze({
    passed: false,
    status: "analysis-pending",
    missingEvidence: Object.freeze([evidenceId]),
    message: "Matching configuration is not execution evidence; only the private API can verify both its server-signed fee receipt and separate trusted exact-route settlement-dataflow closure before wallet handoff."
  });
}

function canonicalValue(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalValue).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalValue(value[key])}`).join(",")}}`;
}

const SHA256 = /^sha256:[0-9a-f]{64}$/u;
const OBJECT_ID = /^[0-9a-f]{40}$/u;
const ADDRESS = /^0x[0-9A-Fa-f]{40}$/u;
const BYTES32 = /^0x[0-9a-f]{64}$/u;
const PROGRAMMABLE_MANIFEST_URL = "https://developers.programmable.family/api/v2/manifest";
const PENDING_REASON_CODES = new Set([
  "fee-settlement-observation-pending",
  "finality-pending",
  "manifest-unavailable",
  "platform-integration-pending",
  "route-classification-unresolved",
  "source-deployment-binding-pending"
]);

function programmableRuntimeFeeSettlementHandler(context) {
  const { evidence, rule } = context;
  const [evidenceId] = rule.evidence;
  const value = evidence?.[evidenceId];
  if (value === undefined) {
    return Object.freeze({
      passed: false,
      status: "analysis-pending",
      missingEvidence: Object.freeze([evidenceId]),
      message: "Runtime fee settlement remains analysis-pending: no independently verified Ethereum finality/receipt/state proof is available."
    });
  }

  const pendingKeys = [
    "observationPath",
    "observationSha256",
    "protectedBaseCommit",
    "protectedBaseTree",
    "protectedGitBlobOid",
    "reasonCode",
    "status"
  ];
  if (
    isProtectedProgrammableRuntimeFeeSettlementPendingPolicyEvidenceV1(value)
    && exactObjectKeys(value, pendingKeys)
    && value.status === "analysis-pending"
    && value.reasonCode === "runtime-fee-verifier-trust-root-unavailable"
  ) {
    return Object.freeze({
      passed: false,
      status: "analysis-pending",
      missingEvidence: Object.freeze([evidenceId]),
      message: "The protected accounting assertion is structurally bound but remains analysis-pending until a versioned Ethereum finality/receipt/state verifier reproduces it from an independent trust root."
    });
  }

  return Object.freeze({
    passed: false,
    status: "failed",
    missingEvidence: Object.freeze([evidenceId]),
    message: "Applicant-declared, provider-declared, repository-only, cloned, or status-only runtime fee claims cannot prove finalized treasury settlement."
  });
}

function programmableRouterReadinessHandler(context) {
  const { evidence, rule, subject } = context;
  const [evidenceId] = rule.evidence;
  const value = evidence?.[evidenceId];
  if (value === undefined) {
    return Object.freeze({
      passed: false,
      status: "analysis-pending",
      missingEvidence: Object.freeze([evidenceId]),
      message: "Canonical Router readiness evidence is analysis-pending."
    });
  }
  const keys = [
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
  ];
  const commonValid = exactObjectKeys(value, keys)
    && new Set(["analysis-pending", "passed"]).has(value.status)
    && value.chainId === rule.parameters?.chainId
    && value.discoveryDocumentUrl === rule.parameters?.discoveryDocumentUrl
    && value.manifestUrl === PROGRAMMABLE_MANIFEST_URL
    && value.routerManifestPointer === rule.parameters?.routerManifestPointer
    && value.launchEntryPoint === rule.parameters?.launchEntryPoint
    && value.directFactoryCall === false
    && value.sourceCommit === subject?.commit
    && value.sourceTree === subject?.tree
    && value.sourceConfigurationHash === subject?.configurationHash
    && OBJECT_ID.test(value.sourceCommit ?? "")
    && OBJECT_ID.test(value.sourceTree ?? "")
    && SHA256.test(value.sourceConfigurationHash ?? "");
  if (
    commonValid
    && value.status === "analysis-pending"
    && [
      value.abiSha256,
      value.abiUrl,
      value.launchKind,
      value.manifestSha256,
      value.routeEvidenceSha256,
      value.routerAddress,
      value.routerRuntimeCodeHash,
      value.routerStatus
    ].every((entry) => entry === null)
  ) {
    return Object.freeze({
      passed: false,
      status: "analysis-pending",
      missingEvidence: Object.freeze([evidenceId]),
      message: "Canonical Router readiness remains analysis-pending without rejecting the launch design."
    });
  }
  const passed = commonValid
    && value.status === "passed"
    && value.routerStatus === "live"
    && new Set([1, 2]).has(value.launchKind)
    && validHttpsUrl(value.abiUrl)
    && SHA256.test(value.manifestSha256 ?? "")
    && SHA256.test(value.abiSha256 ?? "")
    && SHA256.test(value.routeEvidenceSha256 ?? "")
    && validAddress(value.routerAddress)
    && validBytes32(value.routerRuntimeCodeHash);
  return evidenceResult({
    evidenceId,
    passed,
    passedMessage: "The exact reviewed revision is ready for the manifest-resolved canonical Router path.",
    failedMessage: "Canonical Router readiness evidence is malformed, inconsistent, direct-factory based, or not bound to the reviewed revision."
  });
}

function programmableRouterPromotionHandler(context) {
  const { evidence, rule, subject } = context;
  const [evidenceId] = rule.evidence;
  const value = evidence?.[evidenceId];
  const pending = pendingEvidence(value, evidenceId, "Finalized canonical Router promotion evidence is analysis-pending.");
  if (pending) return pending;

  const keys = [
    "abiSha256",
    "blockHash",
    "blockNumber",
    "canonicalBlockFinalized",
    "chainId",
    "componentSetHash",
    "confirmations",
    "discoveryDocumentUrl",
    "expectedResultHash",
    "finalityConfirmations",
    "hook",
    "launchId",
    "launchKind",
    "lookupMatched",
    "manifestSha256",
    "manifestUrl",
    "permitDigest",
    "poolId",
    "poolManager",
    "promotionEvidenceSha256",
    "promotionTargets",
    "routeBindingMatched",
    "routeLauncher",
    "routeLauncherRuntimeCodeHash",
    "routePayloadHash",
    "routerAddress",
    "routerManifestPointer",
    "routerRuntimeCodeHash",
    "sourceCommit",
    "sourceConfigurationHash",
    "sourceDeploymentBindingSha256",
    "sourceTree",
    "stampHash",
    "stampProofMatched",
    "status",
    "token",
    "transactionHash"
  ];
  const passed = exactObjectKeys(value, keys)
    && value.status === "passed"
    && value.chainId === rule.parameters?.chainId
    && value.discoveryDocumentUrl === rule.parameters?.discoveryDocumentUrl
    && value.routerManifestPointer === rule.parameters?.routerManifestPointer
    && equalJson(value.promotionTargets, rule.parameters?.promotionTargets)
    && new Set([1, 2]).has(value.launchKind)
    && value.canonicalBlockFinalized === true
    && value.lookupMatched === true
    && value.routeBindingMatched === true
    && value.stampProofMatched === true
    && Number.isSafeInteger(value.blockNumber)
    && value.blockNumber > 0
    && Number.isSafeInteger(value.finalityConfirmations)
    && value.finalityConfirmations > 0
    && Number.isSafeInteger(value.confirmations)
    && value.confirmations >= value.finalityConfirmations
    && value.manifestUrl === PROGRAMMABLE_MANIFEST_URL
    && SHA256.test(value.manifestSha256 ?? "")
    && SHA256.test(value.abiSha256 ?? "")
    && SHA256.test(value.promotionEvidenceSha256 ?? "")
    && SHA256.test(value.sourceDeploymentBindingSha256 ?? "")
    && validAddress(value.routerAddress)
    && validAddress(value.token)
    && validAddress(value.hook)
    && validAddress(value.poolManager)
    && validAddress(value.routeLauncher)
    && [
      value.blockHash,
      value.componentSetHash,
      value.expectedResultHash,
      value.launchId,
      value.permitDigest,
      value.poolId,
      value.routeLauncherRuntimeCodeHash,
      value.routePayloadHash,
      value.routerRuntimeCodeHash,
      value.stampHash,
      value.transactionHash
    ].every((entry) => validBytes32(entry))
    && value.sourceCommit === subject?.commit
    && value.sourceTree === subject?.tree
    && value.sourceConfigurationHash === subject?.configurationHash
    && OBJECT_ID.test(value.sourceCommit ?? "")
    && OBJECT_ID.test(value.sourceTree ?? "")
    && SHA256.test(value.sourceConfigurationHash ?? "");
  return evidenceResult({
    evidenceId,
    passed,
    passedMessage: "Finalized canonical Router evidence is bound to the reviewed revision and may satisfy the promotion prerequisite.",
    failedMessage: "Router promotion evidence is malformed, non-final, inconsistent, or not bound to the reviewed revision."
  });
}

function pendingEvidence(value, evidenceId, message) {
  if (value === undefined) {
    return Object.freeze({
      passed: false,
      status: "analysis-pending",
      missingEvidence: Object.freeze([evidenceId]),
      message
    });
  }
  if (
    exactObjectKeys(value, ["reasonCode", "status"])
    && value.status === "analysis-pending"
    && PENDING_REASON_CODES.has(value.reasonCode)
  ) {
    return Object.freeze({
      passed: false,
      status: "analysis-pending",
      missingEvidence: Object.freeze([evidenceId]),
      message: `${message} Reason: ${value.reasonCode}.`
    });
  }
  return null;
}

function evidenceResult({ evidenceId, failedMessage, passed, passedMessage }) {
  return Object.freeze({
    passed,
    status: passed ? "passed" : "failed",
    missingEvidence: Object.freeze(passed ? [] : [evidenceId]),
    message: passed ? passedMessage : failedMessage
  });
}

function exactObjectKeys(value, expected) {
  return isPlainObject(value)
    && equalJson(Object.keys(value).sort(), [...expected].sort());
}

function equalJson(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function validHttpsUrl(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 2048) return false;
  try {
    const url = new URL(value);
    return url.protocol === "https:"
      && url.username === ""
      && url.password === ""
      && url.hash === "";
  } catch {
    return false;
  }
}

function validAddress(value) {
  return ADDRESS.test(value ?? "") && !/^0x0{40}$/iu.test(value);
}

function validBytes32(value) {
  return BYTES32.test(value ?? "") && !/^0x0{64}$/iu.test(value);
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

const COMMON_RULE_HANDLERS = Object.freeze({
  "authenticated-application-v1": declaredEvidenceHandler,
  "declared-evidence-v1": declaredEvidenceHandler,
  "disclosure-v1": declaredEvidenceHandler,
  "exact-public-source-v1": declaredEvidenceHandler,
  "exact-source-v1": declaredEvidenceHandler,
  "hidden-namespace-v1": declaredEvidenceHandler,
  "no-public-routing-v1": declaredEvidenceHandler,
  "no-real-user-funds-v1": declaredEvidenceHandler,
  "v4-identity-permissions-v1": declaredEvidenceHandler
});

const RULE_HANDLERS_BY_POLICY_VERSION = Object.freeze({
  "1.0.0": Object.freeze({
    ...COMMON_RULE_HANDLERS,
    "reproducible-inert-artifact-v1": declaredEvidenceHandler
  }),
  "1.1.0": Object.freeze({
    ...COMMON_RULE_HANDLERS,
    "reproducible-inert-application-record-v1": declaredEvidenceHandler
  }),
  "1.2.0": Object.freeze({
    "ethereum-treasury-10-bps-v1": ethereumTreasuryTenBpsHandler
  }),
  "1.3.0": Object.freeze({
    "ethereum-treasury-10-bps-v1": ethereumTreasuryTenBpsHandler
  }),
  "2.0.0": Object.freeze({
    "ethereum-treasury-10-bps-v1": ethereumTreasuryTenBpsHandler,
    "programmable-router-promotion-v1": programmableRouterPromotionHandler,
    "programmable-router-readiness-v1": programmableRouterReadinessHandler
  }),
  "2.1.0": Object.freeze({
    "ethereum-treasury-10-bps-v1": ethereumTreasuryTenBpsHandler,
    "programmable-router-promotion-v1": programmableRouterPromotionHandler,
    "programmable-router-readiness-v1": programmableRouterReadinessHandler,
    "programmable-runtime-fee-settlement-v1": programmableRuntimeFeeSettlementHandler
  }),
  "2.2.0": Object.freeze({
    "ethereum-treasury-10-bps-v1": ethereumTreasuryTenBpsHandler,
    "programmable-exact-fee-template-v1": programmableExactFeeTemplateHandler,
    "programmable-router-promotion-v1": programmableRouterPromotionHandler,
    "programmable-router-readiness-v1": programmableRouterReadinessHandler
  }),
  "2.3.0": Object.freeze({
    "ethereum-treasury-10-bps-v1": ethereumTreasuryTenBpsHandler,
    "programmable-exact-fee-template-v1": programmableExactFeeTemplateHandler,
    "programmable-router-promotion-v1": programmableRouterPromotionHandler,
    "programmable-router-readiness-v1": programmableRouterReadinessHandler
  }),
  "2.4.0": Object.freeze({
    "ethereum-treasury-10-bps-v1": ethereumTreasuryTenBpsHandler,
    "programmable-exact-fee-template-v1": programmableExactFeeTemplateHandler,
    "programmable-router-promotion-v1": programmableRouterPromotionHandler,
    "programmable-router-readiness-v1": programmableRouterReadinessHandler,
    "robinhood-finalized-router-evidence-v1": robinhoodFinalizedRouterEvidenceHandler,
    "robinhood-funding-settlement-readiness-v1": robinhoodFundingAndSettlementReadinessHandler,
    "robinhood-honest-fee-capability-v1": robinhoodHonestFeeCapabilityHandler,
    "robinhood-indexing-readiness-v1": robinhoodIndexingAndReadinessHandler,
    "robinhood-network-pool-manager-provenance-v1": robinhoodNetworkAndPoolManagerProvenanceHandler,
    "robinhood-programmable-trust-roots-v1": robinhoodProgrammableTrustRootsHandler,
    "robinhood-server-validation-simulation-v1": robinhoodServerValidationAndSimulationHandler,
    "robinhood-source-verification-binding-v1": robinhoodSourceVerificationBindingHandler,
    "robinhood-wallet-handoff-chain-binding-v1": robinhoodWalletHandoffChainBindingHandler
  })
});

export function ruleHandlersForPolicyVersion(policyVersion) {
  return RULE_HANDLERS_BY_POLICY_VERSION[policyVersion] ?? Object.freeze({});
}
