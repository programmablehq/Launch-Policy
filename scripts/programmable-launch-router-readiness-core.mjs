import crypto from "node:crypto";
import { TextDecoder, types } from "node:util";

import { keccak256Hex } from "../vendor/programmable-applicant-validator/scripts/evm-encoding-core.mjs";
import { parseBoundedLosslessJson } from "../vendor/programmable-v4-hook-builder/scripts/github-public-source-lossless-json.mjs";

export const PROGRAMMABLE_LAUNCH_ROUTER_READINESS_PATH = ".programmable/launch-router-readiness.v1.json";
export const PROGRAMMABLE_LAUNCH_ROUTER_READINESS_SCHEMA_PATH = "intake/schemas/programmable-launch-router-readiness-v1.schema.json";
export const PROGRAMMABLE_LAUNCH_ROUTER_READINESS_SCHEMA_ID = "urn:programmable:launch-router-readiness:1.0.0";
export const MAXIMUM_PROGRAMMABLE_LAUNCH_ROUTER_READINESS_BYTES = 2 * 1024 * 1024;
export const MAXIMUM_PROGRAMMABLE_LAUNCH_ROUTE_PAYLOAD_BYTES = 532_256;

const DOCUMENT_KIND = "programmable-launch-router-readiness";
const DOCUMENT_VERSION = "1.0.0";
const DEVELOPER_REPOSITORY = "0xprogrammable/developers";
const DEVELOPER_REPOSITORY_ID = "1322379959";
const LAUNCH_POLICY_REPOSITORY = "0xprogrammable/launch-policy";
const LAUNCH_POLICY_REPOSITORY_ID = "1320171831";
const DISCOVERY_DOCUMENT_URL = "https://developers.programmable.family/.well-known/programmable.json";
const MANIFEST_URL = "https://developers.programmable.family/api/v2/manifest";
const ROUTER_MANIFEST_POINTER = "/launchStampRouter";
const ROUTER_ADDRESS = "0x8622DD5bAb44185f2A458ac90384Ac99248f8d56";
const ROUTER_ABI_URL = "https://developers.programmable.family/abis/ethereum/programmable-launch-stamp-router-v1.json";
const ROUTER_ABI_SHA256 = "sha256:bb4e728e9f9c850eb01f928e8a798ac206a82e241a8d93b3b3c686635c88ed86";
const ROUTER_RUNTIME_CODE_HASH = "0x40e27ecf201761d5eb66bc4f2d5c6124831ef078d7baf458ca5f41b1a8108546";
const ROUTER_SELECTOR = "0xe5f6b8cd";
const LAUNCH_ENTRY_POINT = "launchAndStampV1";
const TREASURY = "0x4957f49620AFf3Adbbe8195a4f633E49cc93376c";
const COMPONENT_TYPE_SIGNATURE = "ProgrammableLaunchComponentV1(uint8 resultIndex,address account,bytes32 runtimeCodeHash,uint8 kind,uint8 scope)";
const COMPONENT_TYPE_HASH = "0xb6c08d4570c37a0e9c54db009c42903c8e4502c124ab43e45ef164cc308175e7";
const POOL_KEY_TYPE_SIGNATURE = "ProgrammablePoolKeyV1(address currency0,address currency1,uint24 fee,int24 tickSpacing,address hooks)";
const POOL_KEY_TYPE_HASH = "0xdea3cb132986289de4f65fdbd36603c5a538081f172ef9de81dc8f893a4d883f";
const STAMP_REQUEST_TYPE_SIGNATURE = "ProgrammableStampRequestV1(bytes32 launchId,address token,bytes32 tokenRuntimeCodeHash,bytes32 poolKeyHash,bytes32 hookRuntimeCodeHash,bytes32 componentSetHash)";
const STAMP_REQUEST_TYPE_HASH = "0xa61627b33bfee8131fa1b566b7787c8d93afc86629f51a5c9719bf8f6b3e5573";
const EXPECTED_GRAPH_OUTPUT_TYPE_HASH = "0xbb3b89c4feaa987f443390264fe393e227b8d205d1eb77ceb2b0a5e5dfdeeb7f";
const EXPECTED_GRAPH_RESULT_TYPE_HASH = "0xb87089bcff971cb32d09e3f27f2472a9aa38fec88c320e25f683bbb10715efc9";
const CLASSIC_RESULT_ADDRESSES_TYPE_HASH = "0x10a8f2de88ffdca8d77bafcce2d5ac21adc53c2979d4eab09d21f45152a8c834";
const CLASSIC_RESULT_AMOUNTS_TYPE_HASH = "0x900dcb6e18d3d7bfc1519cf44a0028db6a44fbd949146d8ee3d797290f89d874";
const CLASSIC_RESULT_TYPE_HASH = "0xfb75788b01a892d5c09837cd0f132c6aa87dcc55f9b9b23309d1c214888c33fb";
const SOURCE_CONFIGURATION_DOMAIN = "programmable-launch-router-source-configuration-v1";
const SHA256 = /^sha256:[0-9a-f]{64}$/u;
const OBJECT_ID = /^[0-9a-f]{40}$/u;
const BYTES32 = /^0x[0-9a-f]{64}$/u;
const NONZERO_BYTES32 = /^0x(?!0{64}$)[0-9a-f]{64}$/u;
const NUMERIC_ID = /^[1-9][0-9]{0,63}$/u;
const REPOSITORY = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;
const REPOSITORY_PATH = /^[A-Za-z0-9._/-]+$/u;
const SLUG = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/u;
const CANONICAL_TIMESTAMP = /^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.[0-9]{3}Z$/u;
const ABI_ADDRESS = Object.freeze({ kind: "address" });
const ABI_BYTES32 = Object.freeze({ kind: "bytes32" });
const ABI_BYTES = Object.freeze({ kind: "bytes" });
const ABI_STRING = Object.freeze({ kind: "string" });
const ABI_UINT8_NUMBER = Object.freeze({ bits: 8, json: "number", kind: "uint" });
const ABI_UINT16_NUMBER = Object.freeze({ bits: 16, json: "number", kind: "uint" });
const ABI_UINT256_DECIMAL = Object.freeze({ bits: 256, json: "decimal", kind: "uint" });
const GRAPH_TARGET_ABI_TYPE = abiTuple([
  ["targetIdHash", ABI_BYTES32],
  ["applicantSalt", ABI_BYTES32],
  ["deploymentValue", ABI_UINT256_DECIMAL],
  ["initializerValue", ABI_UINT256_DECIMAL],
  ["initCode", ABI_BYTES],
  ["initializerCalldata", ABI_BYTES]
]);
const EXPECTED_GRAPH_OUTPUT_ABI_TYPE = abiTuple([
  ["targetIndex", ABI_UINT8_NUMBER],
  ["targetIdHash", ABI_BYTES32],
  ["account", ABI_ADDRESS],
  ["runtimeCodeHash", ABI_BYTES32]
]);
const CUSTOM_GRAPH_ROUTE_ABI_TYPE = abiTuple([
  ["routeNamespace", ABI_BYTES32],
  ["routeNonce", ABI_BYTES32],
  ["topologyHash", ABI_BYTES32],
  ["graphCommitment", ABI_BYTES32],
  ["targets", abiArray(GRAPH_TARGET_ABI_TYPE, 16)],
  ["expectedOutputs", abiArray(EXPECTED_GRAPH_OUTPUT_ABI_TYPE, 16)],
  ["expectedGraphDeploymentHash", ABI_BYTES32]
]);
const UERC20_METADATA_ABI_TYPE = abiTuple([
  ["description", ABI_STRING],
  ["website", ABI_STRING],
  ["image", ABI_STRING],
  ["extraData", ABI_BYTES]
]);
const CLASSIC_CUSTODY_ABI_TYPE = abiTuple([
  ["mode", ABI_UINT8_NUMBER],
  ["durationDays", ABI_UINT16_NUMBER],
  ["cliffDays", ABI_UINT16_NUMBER]
]);
const CLASSIC_LAUNCH_PARAMETERS_ABI_TYPE = abiTuple([
  ["name", ABI_STRING],
  ["symbol", ABI_STRING],
  ["buySwapFeeBps", ABI_UINT16_NUMBER],
  ["sellSwapFeeBps", ABI_UINT16_NUMBER],
  ["creatorSalt", ABI_BYTES32],
  ["metadata", UERC20_METADATA_ABI_TYPE],
  ["rewardBeneficiaries", abiArray(ABI_ADDRESS)],
  ["rewardSharesBps", abiArray(ABI_UINT16_NUMBER)],
  ["initialBuyCustody", CLASSIC_CUSTODY_ABI_TYPE]
]);
const CLASSIC_LAUNCH_RESULT_ABI_TYPE = abiTuple([
  ["token", ABI_ADDRESS],
  ["rewardVault", ABI_ADDRESS],
  ["positionRecipient", ABI_ADDRESS],
  ["positionTokenId", ABI_UINT256_DECIMAL],
  ["tokenLiquidityAmount", ABI_UINT256_DECIMAL],
  ["lockedTokenDust", ABI_UINT256_DECIMAL],
  ["initialBuyNativeAmount", ABI_UINT256_DECIMAL],
  ["initialBuyTokenAmount", ABI_UINT256_DECIMAL],
  ["initialBuyCustody", ABI_ADDRESS],
  ["poolId", ABI_BYTES32],
  ["launchHash", ABI_BYTES32]
]);
const CLASSIC_ROUTE_ABI_TYPE = abiTuple([
  ["launcher", ABI_ADDRESS],
  ["launcherRuntimeCodeHash", ABI_BYTES32],
  ["parameters", CLASSIC_LAUNCH_PARAMETERS_ABI_TYPE],
  ["expectedResult", CLASSIC_LAUNCH_RESULT_ABI_TYPE]
]);
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
const ROOT_UINT8_ARRAY = Uint8Array;
const ROOT_TYPED_ARRAY_PROTOTYPE = Object.getPrototypeOf(ROOT_UINT8_ARRAY.prototype);
const ROOT_TYPED_ARRAY_BUFFER = Function.prototype.call.bind(
  Object.getOwnPropertyDescriptor(ROOT_TYPED_ARRAY_PROTOTYPE, "buffer").get
);
const ROOT_TYPED_ARRAY_BYTE_OFFSET = Function.prototype.call.bind(
  Object.getOwnPropertyDescriptor(ROOT_TYPED_ARRAY_PROTOTYPE, "byteOffset").get
);
const ROOT_TYPED_ARRAY_BYTE_LENGTH = Function.prototype.call.bind(
  Object.getOwnPropertyDescriptor(ROOT_TYPED_ARRAY_PROTOTYPE, "byteLength").get
);
const TRUSTED_PARSED_READINESS_RECORDS = new WeakSet();
const TRUSTED_APPLICABILITY_RECORDS = new WeakSet();

export const PROGRAMMABLE_LAUNCH_ROUTER_V1_DEVELOPER_REFERENCE = deepFreeze({
  commit: "79f14e9c57cb6668bb33f66ef636c1c8c5ff2c56",
  deploymentManifest: {
    byteLength: 21102,
    gitBlobOid: "1a2411f2080ad330a02971b1b4104b7d2f5c3499",
    path: "deployments/ethereum-v2.json",
    sha256: "sha256:15af12e7efee7f48a40132bc2d234f6494b90746cf84a1a258e29d4f995311eb"
  },
  launchStampReference: {
    byteLength: 22849,
    gitBlobOid: "fb2ad8f43d0407a99ea8b16c5adc11145c6b02c6",
    path: "docs/reference/launch-stamp.md",
    sha256: "sha256:8f33b7446b5f0ca4a169a920fcb7d8d4c1443e77ebd5dd5d491d289a86e78e0b"
  },
  manifestSchema: {
    byteLength: 48089,
    gitBlobOid: "dc728f220aa5e77972f87bc2f371f4c4392bc1e7",
    path: "schemas/v2/manifest.schema.json",
    sha256: "sha256:6f3b87eabf4c44c07dc8cfcb9ecb2e4e4a662f2375e7e149ee170860f0a0c4c9"
  },
  numericRepositoryId: DEVELOPER_REPOSITORY_ID,
  repository: DEVELOPER_REPOSITORY,
  routerAbi: {
    byteLength: 26541,
    gitBlobOid: "b6e14bd7db9c701bd3b10e65561a985d7fcdb991",
    path: "abis/ethereum/programmable-launch-stamp-router-v1.json",
    sha256: ROUTER_ABI_SHA256
  },
  terminalGuide: {
    byteLength: 14321,
    gitBlobOid: "b3181c29960d11a0d799f7348408dc39fbc5f956",
    path: "docs/guides/terminals-and-scanners.md",
    sha256: "sha256:433de062adea4771dd0678ebb4a53be753e64d22fca99957bdd5d9dd26edd85a"
  },
  tree: "021691684291fd7958d60e039504ce51455c638b"
});

export const PROGRAMMABLE_LAUNCH_ROUTER_V1_RESOLVED_ROUTER = deepFreeze({
  abiSha256: ROUTER_ABI_SHA256,
  abiUrl: ROUTER_ABI_URL,
  address: ROUTER_ADDRESS,
  atomicSelector: ROUTER_SELECTOR,
  atomicSignature: "launchAndStampV1((uint256,address,address,uint8,bytes32,bytes32,bytes32,bytes32,uint64,uint64,uint256),(bytes32,address,bytes32,(address,address,uint24,int24,address),bytes32,(uint8,address,bytes32,uint8,uint8)[]),bytes,bytes)",
  authorityMode: "eip-1271-contract-only",
  bindings: {
    graphFactory: "0xB012e4A8F2c5FC4E8E4faCA9D5Ad6FfF13FBA887",
    graphFactoryRuntimeCodeHash: "0xd23692fae59331592048e71a96d4963e170ee56e449683dc9f7fa3f9470018b8",
    permitAuthority: "0x755509eA6e3F5Ec1aA2E797bb68f1B87DD8b886b",
    permitAuthorityRuntimeCodeHash: "0xd7d408ebcd99b2b70be43e20253d6d92a8ea8fab29bd3be7f55b10032331fb4c",
    poolManager: "0x000000000004444c5dc75cB358380D2e3dE08A90",
    poolManagerRuntimeCodeHash: "0x785f1014552b7ce7d5fb7d0c970ca60edee94fd00425d7ca21609acac7ce1293"
  },
  canonicalReadBlock: "finalized-or-explicit-canonical-block",
  chainId: 1,
  contractName: "ProgrammableLaunchStampRouterV1",
  deploymentEvidence: {
    deploymentBlockHash: "0x8e4512193217c2171624657717d32dbfe9896455e553cadc192fbfe32d3278bc",
    deploymentBlockNumber: "25717612",
    deploymentTransactionHash: "0x3bc086661555c10040feb3fceb23d33003e22ca033e65cfae72592119ee8d486",
    evidenceSha256: "sha256:f9786ebfb74c96a3c225567ad324f0fbecfd8520b8d8addec85ba58cd67e19ff",
    finalizedBlockHash: "0x4177a280cd7e43da181bf1d73900eb2431c26d5fe933a5ed0e583370064cbd6e",
    finalizedBlockNumber: "25717634",
    getterBundleSha256: "sha256:6e6e8a93193bbe2f79f98594a1af32c27bae0746f8297dd13592d9608e2feb20",
    runtimeCodeSha256: "sha256:0b0e89074bff270bd5bf80ca9642f748dca1857d1ab643cbce65f4f663937ec7",
    verificationStatus: "finalized-verified"
  },
  endBlock: null,
  finalityConfirmations: 64,
  generation: "1",
  runtimeCodeHash: ROUTER_RUNTIME_CODE_HASH,
  scope: "future-launches-only",
  startBlock: "25717612",
  status: "live",
  version: "1"
});

export const PROGRAMMABLE_LAUNCH_ROUTER_V1_MANIFEST_PROJECTION = deepFreeze(
  expectedManifestRouterProjection(PROGRAMMABLE_LAUNCH_ROUTER_V1_RESOLVED_ROUTER)
);

const INERT_AUTHORITY = deepFreeze({
  approvalGranted: false,
  candidateCodeExecuted: false,
  credentialsUsed: false,
  externalWritesPerformed: false,
  launchAuthorized: false,
  networkAccessed: false,
  publicDiscoveryAuthorized: false,
  realUserFundsAuthorized: false,
  rpcAccessed: false
});

const FEE_COMMITMENT = deepFreeze({
  basis: "gross-canonical-pool-volume",
  bps: 10,
  chainId: 1,
  doubleChargeAllowed: false,
  enforcementMode: "route-bound",
  hundredthsOfBip: 1000,
  network: "ethereum-mainnet",
  ratePpm: 1000,
  scope: "official-programmable-market-path",
  treasury: TREASURY
});

export const PROGRAMMABLE_TREASURY_TEN_BPS_CONFIGURATION_SHA256 = digestBytes(
  Buffer.from(`${canonicalProgrammableLaunchRouterReadinessJson(FEE_COMMITMENT)}\n`, "utf8")
);

export class ProgrammableLaunchRouterReadinessError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.name = "ProgrammableLaunchRouterReadinessError";
    this.code = code;
  }
}

export function canonicalProgrammableLaunchRouterReadinessJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      fail("PROGRAMMABLE_ROUTER_CANONICAL_JSON_INVALID", "Canonical readiness JSON supports only safe integers.");
    }
    return String(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalProgrammableLaunchRouterReadinessJson(item)).join(",")}]`;
  }
  if (isPlainObject(value)) {
    const members = Object.keys(value)
      .sort(compareUtf8)
      .map((key) => `${JSON.stringify(key)}:${canonicalProgrammableLaunchRouterReadinessJson(value[key])}`);
    return `{${members.join(",")}}`;
  }
  fail("PROGRAMMABLE_ROUTER_CANONICAL_JSON_INVALID", "Canonical readiness JSON contains an unsupported value.");
}

export function computeProgrammableStampRequestV1Commitment(options) {
  assertExactKeys(options, ["category", "stampRequest"], "PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID", "StampRequestV1 computation options");
  if (!new Set(["custom", "classic"]).has(options.category)) {
    fail("PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID", "StampRequestV1 category must be custom or classic.");
  }
  const computed = computeStampRequestCommitment(options.stampRequest, options.category);
  return deepFreeze({
    componentSetHash: computed.componentSetHash,
    poolKeyHash: computed.poolKeyHash,
    stampRequestHash: computed.stampRequestHash
  });
}

export function computeProgrammableLaunchRouterRouteCommitmentV1(options) {
  assertExactKeys(options, ["category", "routePayload"], "PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID", "route payload computation options");
  if (!new Set(["custom", "classic"]).has(options.category)) {
    fail("PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID", "Route payload category must be custom or classic.");
  }
  const type = options.category === "custom" ? CUSTOM_GRAPH_ROUTE_ABI_TYPE : CLASSIC_ROUTE_ABI_TYPE;
  let bytes;
  try {
    bytes = encodeAbiArguments([type], [options.routePayload], "routePayload");
  } catch (cause) {
    if (cause instanceof ProgrammableLaunchRouterReadinessError) throw cause;
    fail("PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID", "Route payload could not be canonically ABI-encoded.", cause);
  }
  if (bytes.length < 1 || bytes.length > MAXIMUM_PROGRAMMABLE_LAUNCH_ROUTE_PAYLOAD_BYTES) {
    fail("PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID", "Route payload is outside the closed byte boundary.");
  }
  const decoded = decodeAndRequireCanonicalRoutePayload(bytes, options.category);
  const expectedResultHash = computeRouteExpectedResultHash(decoded, options.category);
  return deepFreeze({
    byteLength: bytes.length,
    contentBase64: bytes.toString("base64"),
    encoding: options.category === "custom" ? "abi.encode(CustomGraphRouteV1)" : "abi.encode(ClassicRouteV1)",
    expectedResultHash,
    keccak256: keccak256Hex(bytes),
    sha256: digestBytes(bytes)
  });
}

export function computeProgrammableLaunchRouterPoolIdV1(poolKey) {
  assertExactKeys(
    poolKey,
    ["currency0", "currency1", "fee", "hooks", "tickSpacing"],
    "PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID",
    "StampRequestV1.poolKey"
  );
  computePoolKeyHash(poolKey, poolKey.currency0);
  return keccak256Hex(abiEncodeWords([
    addressAbiWord(poolKey.currency0),
    addressAbiWord(poolKey.currency1),
    uintAbiWord(BigInt(poolKey.fee)),
    signedAbiWord(BigInt(poolKey.tickSpacing), 24),
    addressAbiWord(poolKey.hooks)
  ]));
}

export function deriveProgrammableLaunchRouterSourceConfigurationHashV1(options) {
  assertExactKeys(
    options,
    ["feeImplementationArtifact", "routeArtifact"],
    "PROGRAMMABLE_ROUTER_SOURCE_CONFIGURATION_INVALID",
    "source configuration derivation options"
  );
  validateArtifactBinding(
    options.feeImplementationArtifact,
    "source configuration feeImplementationArtifact",
    "PROGRAMMABLE_ROUTER_SOURCE_CONFIGURATION_INVALID"
  );
  validateArtifactBinding(
    options.routeArtifact,
    "source configuration routeArtifact",
    "PROGRAMMABLE_ROUTER_SOURCE_CONFIGURATION_INVALID"
  );
  for (const [label, artifact] of [
    ["feeImplementationArtifact", options.feeImplementationArtifact],
    ["routeArtifact", options.routeArtifact]
  ]) {
    if (artifact.path === PROGRAMMABLE_LAUNCH_ROUTER_READINESS_PATH) {
      fail(
        "PROGRAMMABLE_ROUTER_SOURCE_CONFIGURATION_INVALID",
        `source configuration ${label} must bind applicant source bytes, not the readiness document itself.`
      );
    }
  }
  const commitment = {
    domain: SOURCE_CONFIGURATION_DOMAIN,
    feeImplementationArtifact: structuredClone(options.feeImplementationArtifact),
    routeArtifact: structuredClone(options.routeArtifact),
    schemaVersion: "1.0.0"
  };
  return digestBytes(Buffer.from(`${canonicalProgrammableLaunchRouterReadinessJson(commitment)}\n`, "utf8"));
}

export function parseProgrammableLaunchRouterReadinessBytesV1(bytes) {
  const buffer = snapshotReadinessBytes(bytes);
  if (buffer.length >= 3 && buffer[0] === 0xef && buffer[1] === 0xbb && buffer[2] === 0xbf) {
    fail("PROGRAMMABLE_ROUTER_JSON_INVALID", "Router-readiness UTF-8 must not contain a byte-order mark.");
  }
  let source;
  let document;
  try {
    source = UTF8_DECODER.decode(buffer);
    parseBoundedLosslessJson(source);
    document = JSON.parse(source);
  } catch (error) {
    fail("PROGRAMMABLE_ROUTER_JSON_INVALID", "Router-readiness input must be duplicate-free UTF-8 JSON.", error);
  }
  if (source !== `${canonicalProgrammableLaunchRouterReadinessJson(document)}\n`) {
    fail("PROGRAMMABLE_ROUTER_JSON_NONCANONICAL", "Router-readiness input must be canonical JSON followed by exactly one LF.");
  }
  validateDocument(document);
  const record = deepFreeze({
    document,
    documentSha256: digestBytes(buffer)
  });
  TRUSTED_PARSED_READINESS_RECORDS.add(record);
  return record;
}

export function projectProgrammableLaunchRouterPolicyEvidenceV1(parsedRecord) {
  requireTrustedParsedRecord(parsedRecord);
  assertExactKeys(parsedRecord, ["document", "documentSha256"], "PROGRAMMABLE_ROUTER_RECORD_INVALID", "parsed readiness record");
  validateDocument(parsedRecord.document);
  assertSha256(parsedRecord.documentSha256, "parsed readiness record documentSha256");
  const expectedDocumentSha256 = digestBytes(Buffer.from(`${canonicalProgrammableLaunchRouterReadinessJson(parsedRecord.document)}\n`, "utf8"));
  assertEqual(parsedRecord.documentSha256, expectedDocumentSha256, "PROGRAMMABLE_ROUTER_RECORD_DIGEST_MISMATCH", "parsed readiness record digest");
  return deepFreeze(buildPolicyEvidence(parsedRecord.document, parsedRecord.documentSha256));
}

export function deriveProgrammableLaunchRouterApplicabilityRecordV1(parsedRecord) {
  requireTrustedParsedRecord(parsedRecord);
  const document = parsedRecord.document;
  const decision = document.state === "prelaunch-bound"
    ? "required"
    : document.state === "not-applicable" ? "not-applicable" : "analysis-pending";
  const record = deepFreeze({
    decision,
    declaration: document.state === "not-applicable"
      ? structuredClone(document.applicability.trustedDeclaration)
      : null,
    kind: "programmable-launch-router-applicability",
    readinessDocumentSha256: parsedRecord.documentSha256,
    routeMode: document.applicability.routeMode,
    schemaVersion: "1.0.0",
    subject: {
      commit: document.subject.sourceCommit,
      configurationHash: document.subject.sourceConfigurationHash,
      numericRepositoryId: document.subject.sourceRepositoryNumericId,
      repository: document.subject.sourceRepository,
      tree: document.subject.sourceTree
    }
  });
  TRUSTED_APPLICABILITY_RECORDS.add(record);
  return record;
}

export function isTrustedProgrammableLaunchRouterApplicabilityRecordV1(value) {
  return value !== null
    && typeof value === "object"
    && !types.isProxy(value)
    && TRUSTED_APPLICABILITY_RECORDS.has(value);
}

export function verifyProgrammableLaunchRouterReadinessBytesV1(bytes) {
  const parsed = parseProgrammableLaunchRouterReadinessBytesV1(bytes);
  return deepFreeze({
    applicabilityRecord: deriveProgrammableLaunchRouterApplicabilityRecordV1(parsed),
    documentSha256: parsed.documentSha256,
    ok: true,
    policyEvidence: projectProgrammableLaunchRouterPolicyEvidenceV1(parsed),
    state: parsed.document.state
  });
}

function requireTrustedParsedRecord(value) {
  if (
    value === null
    || typeof value !== "object"
    || types.isProxy(value)
    || !TRUSTED_PARSED_READINESS_RECORDS.has(value)
  ) {
    fail("PROGRAMMABLE_ROUTER_RECORD_TRUST_INVALID", "Only a record minted from exact canonical readiness bytes is trusted.");
  }
}

function snapshotReadinessBytes(value) {
  // Native brand/proxy checks plus prebound root %TypedArray% accessors avoid
  // consulting caller-owned getters, iterators, constructors, or valueOf.
  // Establish the byte extent before the only copy and verify it afterward.
  if (
    value === null
    || typeof value !== "object"
    || types.isProxy(value)
    || !types.isUint8Array(value)
  ) {
    fail("PROGRAMMABLE_ROUTER_BYTES_INVALID", "Router-readiness input must be one non-proxy bounded byte sequence.");
  }
  const before = intrinsicReadinessByteRegion(value);
  if (before.byteLength < 3 || before.byteLength > MAXIMUM_PROGRAMMABLE_LAUNCH_ROUTER_READINESS_BYTES) {
    fail("PROGRAMMABLE_ROUTER_BYTES_INVALID", "Router-readiness input exceeds its closed byte boundary.");
  }
  let snapshot;
  try {
    const safeView = new ROOT_UINT8_ARRAY(before.buffer, before.byteOffset, before.byteLength);
    snapshot = Buffer.from(safeView);
  } catch (cause) {
    fail("PROGRAMMABLE_ROUTER_BYTES_INVALID", "Router-readiness bytes could not be snapshotted exactly once.", cause);
  }
  const after = intrinsicReadinessByteRegion(value);
  if (
    after.buffer !== before.buffer
    || after.byteOffset !== before.byteOffset
    || after.byteLength !== before.byteLength
    || snapshot.byteLength !== before.byteLength
    || snapshot.byteLength < 3
    || snapshot.byteLength > MAXIMUM_PROGRAMMABLE_LAUNCH_ROUTER_READINESS_BYTES
  ) {
    fail("PROGRAMMABLE_ROUTER_BYTES_INVALID", "Router-readiness backing region changed while it was being snapshotted.");
  }
  return snapshot;
}

function intrinsicReadinessByteRegion(value) {
  try {
    const buffer = ROOT_TYPED_ARRAY_BUFFER(value);
    const byteOffset = ROOT_TYPED_ARRAY_BYTE_OFFSET(value);
    const byteLength = ROOT_TYPED_ARRAY_BYTE_LENGTH(value);
    if (
      !Number.isSafeInteger(byteOffset)
      || byteOffset < 0
      || !Number.isSafeInteger(byteLength)
      || byteLength < 0
    ) {
      fail("PROGRAMMABLE_ROUTER_BYTES_INVALID", "Router-readiness input has an invalid intrinsic byte region.");
    }
    return { buffer, byteLength, byteOffset };
  } catch (cause) {
    if (cause instanceof ProgrammableLaunchRouterReadinessError) throw cause;
    fail("PROGRAMMABLE_ROUTER_BYTES_INVALID", "Router-readiness intrinsic byte region could not be inspected.", cause);
  }
}

function validateDocument(document) {
  assertExactKeys(document, [
    "$schema",
    "applicability",
    "authority",
    "developerReference",
    "feeConfiguration",
    "kind",
    "manifestSnapshot",
    "resolvedRouter",
    "route",
    "schemaVersion",
    "state",
    "subject"
  ], "PROGRAMMABLE_ROUTER_DOCUMENT_INVALID", "readiness document");
  assertEqual(document.$schema, PROGRAMMABLE_LAUNCH_ROUTER_READINESS_SCHEMA_ID, "PROGRAMMABLE_ROUTER_DOCUMENT_INVALID", "$schema");
  assertEqual(document.kind, DOCUMENT_KIND, "PROGRAMMABLE_ROUTER_DOCUMENT_INVALID", "kind");
  assertEqual(document.schemaVersion, DOCUMENT_VERSION, "PROGRAMMABLE_ROUTER_DOCUMENT_INVALID", "schemaVersion");
  validateSubject(document.subject);
  assertCanonicalEqual(document.authority, INERT_AUTHORITY, "PROGRAMMABLE_ROUTER_AUTHORITY_INVALID", "authority");

  if (document.state === "not-applicable") {
    validateNotApplicable(document);
    return;
  }
  if (document.state === "analysis-pending") {
    validateAnalysisPending(document);
    return;
  }
  if (document.state !== "prelaunch-bound") {
    fail("PROGRAMMABLE_ROUTER_STATE_INVALID", "state must be not-applicable, analysis-pending, or prelaunch-bound.");
  }
  validatePrelaunchBound(document);
}

function validateSubject(subject) {
  assertExactKeys(subject, [
    "applicationId",
    "applicationRevision",
    "sourceCommit",
    "sourceConfigurationHash",
    "sourceRepository",
    "sourceRepositoryNumericId",
    "sourceTree"
  ], "PROGRAMMABLE_ROUTER_SUBJECT_INVALID", "subject");
  if (typeof subject.applicationId !== "string" || subject.applicationId.length > 80 || !SLUG.test(subject.applicationId)) {
    fail("PROGRAMMABLE_ROUTER_SUBJECT_INVALID", "subject.applicationId must be one lowercase slug.");
  }
  if (!Number.isSafeInteger(subject.applicationRevision) || subject.applicationRevision < 1 || subject.applicationRevision > 1_000_000) {
    fail("PROGRAMMABLE_ROUTER_SUBJECT_INVALID", "subject.applicationRevision is invalid.");
  }
  assertObjectId(subject.sourceCommit, "subject.sourceCommit", "PROGRAMMABLE_ROUTER_SUBJECT_INVALID");
  assertSha256(subject.sourceConfigurationHash, "subject.sourceConfigurationHash", "PROGRAMMABLE_ROUTER_SUBJECT_INVALID");
  assertRepository(subject.sourceRepository, "subject.sourceRepository", "PROGRAMMABLE_ROUTER_SUBJECT_INVALID");
  assertNumericId(subject.sourceRepositoryNumericId, "subject.sourceRepositoryNumericId", "PROGRAMMABLE_ROUTER_SUBJECT_INVALID");
  assertObjectId(subject.sourceTree, "subject.sourceTree", "PROGRAMMABLE_ROUTER_SUBJECT_INVALID");
}

function validateNotApplicable(document) {
  assertNullPrelaunchBindings(document, "PROGRAMMABLE_ROUTER_NOT_APPLICABLE_INVALID");
  assertExactKeys(document.applicability, ["routeMode", "trustedDeclaration"], "PROGRAMMABLE_ROUTER_NOT_APPLICABLE_INVALID", "applicability");
  if (!new Set(["no-market", "external-route"]).has(document.applicability.routeMode)) {
    fail("PROGRAMMABLE_ROUTER_NOT_APPLICABLE_INVALID", "not-applicable requires no-market or external-route.");
  }
  const declaration = document.applicability.trustedDeclaration;
  assertExactKeys(declaration, [
    "byteLength",
    "commit",
    "declaredRouteMode",
    "declarationKind",
    "gitBlobOid",
    "numericRepositoryId",
    "path",
    "repository",
    "sha256",
    "tree",
    "trustBasis"
  ], "PROGRAMMABLE_ROUTER_NOT_APPLICABLE_INVALID", "trusted applicability declaration");
  assertEqual(declaration.repository, LAUNCH_POLICY_REPOSITORY, "PROGRAMMABLE_ROUTER_NOT_APPLICABLE_INVALID", "trusted declaration repository");
  assertEqual(declaration.numericRepositoryId, LAUNCH_POLICY_REPOSITORY_ID, "PROGRAMMABLE_ROUTER_NOT_APPLICABLE_INVALID", "trusted declaration repository id");
  assertEqual(declaration.trustBasis, "protected-launch-policy-base-content-addressed", "PROGRAMMABLE_ROUTER_NOT_APPLICABLE_INVALID", "trusted declaration basis");
  assertEqual(declaration.declaredRouteMode, document.applicability.routeMode, "PROGRAMMABLE_ROUTER_NOT_APPLICABLE_INVALID", "trusted declaration route mode");
  const expectedKind = declaration.declaredRouteMode === "no-market"
    ? "trusted-no-market-declaration"
    : "trusted-external-route-declaration";
  assertEqual(declaration.declarationKind, expectedKind, "PROGRAMMABLE_ROUTER_NOT_APPLICABLE_INVALID", "trusted declaration kind");
  assertObjectId(declaration.commit, "trusted declaration commit", "PROGRAMMABLE_ROUTER_NOT_APPLICABLE_INVALID");
  assertObjectId(declaration.tree, "trusted declaration tree", "PROGRAMMABLE_ROUTER_NOT_APPLICABLE_INVALID");
  validateArtifactBinding({
    byteLength: declaration.byteLength,
    gitBlobOid: declaration.gitBlobOid,
    path: declaration.path,
    sha256: declaration.sha256
  }, "trusted declaration", "PROGRAMMABLE_ROUTER_NOT_APPLICABLE_INVALID");
  if (declaration.byteLength > 1024 * 1024) {
    fail("PROGRAMMABLE_ROUTER_NOT_APPLICABLE_INVALID", "trusted declaration.byteLength exceeds its closed one-megabyte boundary.");
  }
  if (declaration.path === PROGRAMMABLE_LAUNCH_ROUTER_READINESS_PATH) {
    fail("PROGRAMMABLE_ROUTER_NOT_APPLICABLE_INVALID", "A trusted applicability declaration cannot be the applicant readiness document itself.");
  }
}

function validateAnalysisPending(document) {
  assertNullPrelaunchBindings(document, "PROGRAMMABLE_ROUTER_ANALYSIS_PENDING_INVALID");
  assertExactKeys(document.applicability, ["reasonCode", "routeMode", "trustedDeclaration"], "PROGRAMMABLE_ROUTER_ANALYSIS_PENDING_INVALID", "applicability");
  assertEqual(document.applicability.routeMode, "analysis-pending", "PROGRAMMABLE_ROUTER_ANALYSIS_PENDING_INVALID", "analysis route mode");
  assertEqual(document.applicability.trustedDeclaration, null, "PROGRAMMABLE_ROUTER_ANALYSIS_PENDING_INVALID", "analysis trusted declaration");
  const reasons = new Set([
    "market-analysis-incomplete",
    "route-analysis-incomplete",
    "source-binding-incomplete",
    "manifest-binding-incomplete",
    "commitment-binding-incomplete",
    "fee-binding-incomplete"
  ]);
  if (!reasons.has(document.applicability.reasonCode)) {
    fail("PROGRAMMABLE_ROUTER_ANALYSIS_PENDING_INVALID", "analysis-pending reasonCode is not recognized.");
  }
}

function validatePrelaunchBound(document) {
  assertExactKeys(document.applicability, ["routeMode", "trustedDeclaration"], "PROGRAMMABLE_ROUTER_PRELAUNCH_INVALID", "applicability");
  assertEqual(document.applicability.routeMode, "programmable-ethereum-mainnet", "PROGRAMMABLE_ROUTER_PRELAUNCH_INVALID", "prelaunch route mode");
  assertEqual(document.applicability.trustedDeclaration, null, "PROGRAMMABLE_ROUTER_PRELAUNCH_INVALID", "prelaunch trusted declaration");
  assertCanonicalEqual(document.developerReference, PROGRAMMABLE_LAUNCH_ROUTER_V1_DEVELOPER_REFERENCE, "PROGRAMMABLE_ROUTER_DEVELOPER_REFERENCE_MISMATCH", "Developer reference");
  assertCanonicalEqual(document.resolvedRouter, PROGRAMMABLE_LAUNCH_ROUTER_V1_RESOLVED_ROUTER, "PROGRAMMABLE_ROUTER_RESOLVED_TUPLE_MISMATCH", "resolved Router tuple");
  validateManifestSnapshot(document.manifestSnapshot, document.resolvedRouter);
  validateRoute(document.route, document.subject, document.resolvedRouter);
  validateFeeConfiguration(document.feeConfiguration, document.subject);
  const sourceConfigurationHash = deriveProgrammableLaunchRouterSourceConfigurationHashV1({
    feeImplementationArtifact: document.feeConfiguration.implementationArtifact,
    routeArtifact: document.route.sourceIdentity.artifact
  });
  assertEqual(
    document.subject.sourceConfigurationHash,
    sourceConfigurationHash,
    "PROGRAMMABLE_ROUTER_SOURCE_CONFIGURATION_MISMATCH",
    "subject.sourceConfigurationHash"
  );
}

function assertNullPrelaunchBindings(document, code) {
  for (const key of ["developerReference", "feeConfiguration", "manifestSnapshot", "resolvedRouter", "route"]) {
    if (document[key] !== null) fail(code, `${key} must be null outside prelaunch-bound.`);
  }
}

function validateManifestSnapshot(snapshot, resolvedRouter) {
  assertExactKeys(snapshot, [
    "discoveryDocumentUrl",
    "liveResponseBase64",
    "liveResponseBindingScope",
    "liveResponseByteLength",
    "liveResponseContentKind",
    "liveResponseSha256",
    "manifestPointer",
    "manifestSourceGitBlobOid",
    "manifestSourceSha256",
    "manifestUrl",
    "manifestVersion",
    "observedAt",
    "schemaVersion"
  ], "PROGRAMMABLE_ROUTER_MANIFEST_SNAPSHOT_INVALID", "manifest snapshot");
  const exact = {
    discoveryDocumentUrl: DISCOVERY_DOCUMENT_URL,
    liveResponseBindingScope: "time-bound-pointer-projection-not-origin-or-freshness-proof",
    liveResponseContentKind: "canonical-json-pointer-projection-v1",
    manifestPointer: ROUTER_MANIFEST_POINTER,
    manifestSourceGitBlobOid: PROGRAMMABLE_LAUNCH_ROUTER_V1_DEVELOPER_REFERENCE.deploymentManifest.gitBlobOid,
    manifestSourceSha256: PROGRAMMABLE_LAUNCH_ROUTER_V1_DEVELOPER_REFERENCE.deploymentManifest.sha256,
    manifestUrl: MANIFEST_URL,
    manifestVersion: "3",
    schemaVersion: "2.0.0"
  };
  for (const [key, expected] of Object.entries(exact)) {
    assertEqual(snapshot[key], expected, "PROGRAMMABLE_ROUTER_MANIFEST_SNAPSHOT_INVALID", `manifestSnapshot.${key}`);
  }
  const projection = validateCanonicalManifestProjectionBytes({
    base64: snapshot.liveResponseBase64,
    byteLength: snapshot.liveResponseByteLength,
    sha256: snapshot.liveResponseSha256
  });
  assertCanonicalEqual(
    projection,
    expectedManifestRouterProjection(resolvedRouter),
    "PROGRAMMABLE_ROUTER_MANIFEST_SNAPSHOT_INVALID",
    "manifestSnapshot live Router pointer projection"
  );
  assertCanonicalTimestamp(snapshot.observedAt, "manifestSnapshot.observedAt", "PROGRAMMABLE_ROUTER_MANIFEST_SNAPSHOT_INVALID");
}

function validateCanonicalManifestProjectionBytes(binding) {
  if (!Number.isSafeInteger(binding.byteLength) || binding.byteLength < 3 || binding.byteLength > 262_144) {
    fail("PROGRAMMABLE_ROUTER_MANIFEST_SNAPSHOT_INVALID", "manifestSnapshot.liveResponseByteLength is outside the closed projection boundary.");
  }
  if (typeof binding.base64 !== "string" || binding.base64.length < 4 || binding.base64.length > 349_528) {
    fail("PROGRAMMABLE_ROUTER_MANIFEST_SNAPSHOT_INVALID", "manifestSnapshot.liveResponseBase64 must contain bounded canonical Base64 bytes.");
  }
  let bytes;
  let source;
  let projection;
  try {
    bytes = Buffer.from(binding.base64, "base64");
    if (
      bytes.length !== binding.byteLength
      || bytes.toString("base64") !== binding.base64
      || (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf)
    ) throw new TypeError("noncanonical embedded bytes");
    assertSha256(binding.sha256, "manifestSnapshot.liveResponseSha256", "PROGRAMMABLE_ROUTER_MANIFEST_SNAPSHOT_INVALID");
    if (digestBytes(bytes) !== binding.sha256) throw new TypeError("embedded digest mismatch");
    source = UTF8_DECODER.decode(bytes);
    parseBoundedLosslessJson(source);
    projection = JSON.parse(source);
  } catch (cause) {
    if (cause instanceof ProgrammableLaunchRouterReadinessError) throw cause;
    fail(
      "PROGRAMMABLE_ROUTER_MANIFEST_SNAPSHOT_INVALID",
      "manifestSnapshot live response projection must be digest-bound duplicate-free UTF-8 JSON.",
      cause
    );
  }
  if (source !== `${canonicalProgrammableLaunchRouterReadinessJson(projection)}\n`) {
    fail(
      "PROGRAMMABLE_ROUTER_MANIFEST_SNAPSHOT_INVALID",
      "manifestSnapshot live response projection must use canonical JSON followed by exactly one LF."
    );
  }
  return projection;
}

function expectedManifestRouterProjection(router) {
  return {
    chainId: router.chainId,
    launchStampRouter: {
      abiSha256: router.abiSha256,
      abiUrl: router.abiUrl,
      address: router.address,
      atomicSelector: router.atomicSelector,
      atomicSignature: router.atomicSignature,
      authorityMode: router.authorityMode,
      bindings: structuredClone(router.bindings),
      canonicalReadBlock: router.canonicalReadBlock,
      contractName: router.contractName,
      deploymentEvidence: {
        address: router.address,
        deploymentBlockHash: router.deploymentEvidence.deploymentBlockHash,
        deploymentBlockNumber: router.deploymentEvidence.deploymentBlockNumber,
        deploymentTransactionHash: router.deploymentEvidence.deploymentTransactionHash,
        evidenceSha256: router.deploymentEvidence.evidenceSha256,
        finalityDepth: 22,
        finalizedBlockHash: router.deploymentEvidence.finalizedBlockHash,
        finalizedBlockNumber: router.deploymentEvidence.finalizedBlockNumber,
        getterBundleSha256: router.deploymentEvidence.getterBundleSha256,
        observedBindings: {
          chainId: router.chainId,
          graphFactory: router.bindings.graphFactory,
          graphFactoryRuntimeCodeHash: router.bindings.graphFactoryRuntimeCodeHash,
          permitAuthority: router.bindings.permitAuthority,
          permitAuthorityRuntimeCodeHash: router.bindings.permitAuthorityRuntimeCodeHash,
          poolManager: router.bindings.poolManager,
          poolManagerRuntimeCodeHash: router.bindings.poolManagerRuntimeCodeHash
        },
        runtimeCodeBytes: 23013,
        runtimeCodeKeccak256: router.runtimeCodeHash,
        runtimeCodeSha256: router.deploymentEvidence.runtimeCodeSha256,
        verificationStatus: router.deploymentEvidence.verificationStatus
      },
      endBlock: router.endBlock,
      finalityConfirmations: router.finalityConfirmations,
      generation: router.generation,
      runtimeCodeHash: router.runtimeCodeHash,
      scope: router.scope,
      startBlock: router.startBlock,
      status: router.status,
      version: router.version
    },
    manifestVersion: "3",
    schemaVersion: "2.0.0"
  };
}

function validateRoute(route, subject, resolvedRouter) {
  assertExactKeys(route, [
    "category",
    "commitments",
    "directFactoryCall",
    "directFactoryFallbackAllowed",
    "executionPath",
    "launchKind",
    "launchWallet",
    "routeKind",
    "sourceIdentity",
    "transactionSelector",
    "transactionTarget"
  ], "PROGRAMMABLE_ROUTER_ROUTE_INVALID", "route");
  const expectedKind = route.category === "custom" ? 1 : route.category === "classic" ? 2 : null;
  const expectedRouteKind = route.category === "custom" ? "custom-graph" : route.category === "classic" ? "classic" : null;
  if (expectedKind === null || route.launchKind !== expectedKind || route.routeKind !== expectedRouteKind) {
    fail("PROGRAMMABLE_ROUTER_ROUTE_KIND_MISMATCH", "route category, routeKind, and LaunchKindV1 integer do not match.");
  }
  assertEqual(route.executionPath, "canonical-launch-stamp-router-v1", "PROGRAMMABLE_ROUTER_ROUTE_INVALID", "route.executionPath");
  assertEqual(route.directFactoryCall, false, "PROGRAMMABLE_ROUTER_DIRECT_FACTORY_FORBIDDEN", "route.directFactoryCall");
  assertEqual(route.directFactoryFallbackAllowed, false, "PROGRAMMABLE_ROUTER_DIRECT_FACTORY_FORBIDDEN", "route.directFactoryFallbackAllowed");
  assertEqual(route.transactionTarget, resolvedRouter.address, "PROGRAMMABLE_ROUTER_ROUTE_TARGET_MISMATCH", "route.transactionTarget");
  assertEqual(route.transactionSelector, resolvedRouter.atomicSelector, "PROGRAMMABLE_ROUTER_ROUTE_TARGET_MISMATCH", "route.transactionSelector");
  validateSourceIdentity(route.sourceIdentity, subject, "route.sourceIdentity", "PROGRAMMABLE_ROUTER_SOURCE_IDENTITY_MISMATCH");

  assertExactKeys(route.launchWallet, [
    "address",
    "bindingState",
    "immutableAfterPermitSigning",
    "mustEqualTransactionSender"
  ], "PROGRAMMABLE_ROUTER_WALLET_BINDING_INVALID", "route.launchWallet");
  assertEqual(route.launchWallet.address, null, "PROGRAMMABLE_ROUTER_WALLET_BINDING_INVALID", "route.launchWallet.address");
  assertEqual(route.launchWallet.bindingState, "late-bound-before-permit-signing", "PROGRAMMABLE_ROUTER_WALLET_BINDING_INVALID", "route.launchWallet.bindingState");
  assertEqual(route.launchWallet.immutableAfterPermitSigning, true, "PROGRAMMABLE_ROUTER_WALLET_BINDING_INVALID", "route.launchWallet.immutableAfterPermitSigning");
  assertEqual(route.launchWallet.mustEqualTransactionSender, true, "PROGRAMMABLE_ROUTER_WALLET_BINDING_INVALID", "route.launchWallet.mustEqualTransactionSender");
  validateCommitments(route.commitments, route.launchKind, route.category, resolvedRouter);
}

function validateSourceIdentity(identity, subject, label, code) {
  assertExactKeys(identity, [
    "artifact",
    "commit",
    "configurationHash",
    "numericRepositoryId",
    "repository",
    "tree"
  ], code, label);
  const expected = {
    commit: subject.sourceCommit,
    configurationHash: subject.sourceConfigurationHash,
    numericRepositoryId: subject.sourceRepositoryNumericId,
    repository: subject.sourceRepository,
    tree: subject.sourceTree
  };
  for (const [key, value] of Object.entries(expected)) assertEqual(identity[key], value, code, `${label}.${key}`);
  validateArtifactBinding(identity.artifact, `${label}.artifact`, code);
  if (identity.artifact.path === PROGRAMMABLE_LAUNCH_ROUTER_READINESS_PATH) {
    fail(code, `${label}.artifact must bind reviewed source or configuration bytes, not the readiness document itself.`);
  }
}

function validateCommitments(commitments, launchKind, category, resolvedRouter) {
  assertExactKeys(commitments, [
    "commitmentState",
    "expectedResult",
    "launchPermitV1",
    "routePayload",
    "stampRequestV1"
  ], "PROGRAMMABLE_ROUTER_COMMITMENTS_INVALID", "route.commitments");
  assertEqual(commitments.commitmentState, "payload-and-results-bound-wallet-and-validity-late", "PROGRAMMABLE_ROUTER_COMMITMENTS_INVALID", "commitment state");
  const routePayload = validateRoutePayloadCommitment(commitments.routePayload, category);
  const expectedResult = validateExpectedResultCommitment(commitments.expectedResult, routePayload);
  const stampRequest = validateStampRequestCommitment(commitments.stampRequestV1, category);
  const permit = commitments.launchPermitV1;
  assertExactKeys(permit, [
    "bindingState",
    "chainId",
    "deadline",
    "domainName",
    "domainVersion",
    "expectedResultHash",
    "kind",
    "launchWallet",
    "nonce",
    "permitDigest",
    "primaryType",
    "routePayloadHash",
    "router",
    "signature",
    "stampRequestHash",
    "typeHash",
    "typeSignature",
    "validAfter",
    "value"
  ], "PROGRAMMABLE_ROUTER_PERMIT_INVALID", "LaunchPermitV1 template");
  const exact = {
    bindingState: "wallet-and-validity-window-late-bound-before-signing",
    chainId: 1,
    deadline: null,
    domainName: "ProgrammableLaunchStampRouter",
    domainVersion: "1",
    kind: launchKind,
    launchWallet: null,
    permitDigest: null,
    primaryType: "ProgrammableLaunchPermitV1",
    router: resolvedRouter.address,
    signature: null,
    typeHash: "0x5147473bd302ad67f9ef14ef9262d1b0f8d4f7155081bc8c508195b647413761",
    typeSignature: "ProgrammableLaunchPermitV1(uint256 chainId,address router,address launchWallet,uint8 kind,bytes32 routePayloadHash,bytes32 expectedResultHash,bytes32 stampRequestHash,bytes32 nonce,uint64 validAfter,uint64 deadline,uint256 value)",
    validAfter: null
  };
  for (const [key, value] of Object.entries(exact)) assertEqual(permit[key], value, "PROGRAMMABLE_ROUTER_PERMIT_INVALID", `LaunchPermitV1.${key}`);
  assertEqual(permit.routePayloadHash, routePayload.keccak256, "PROGRAMMABLE_ROUTER_PERMIT_COMMITMENT_MISMATCH", "LaunchPermitV1.routePayloadHash");
  assertEqual(permit.expectedResultHash, expectedResult.hash, "PROGRAMMABLE_ROUTER_PERMIT_COMMITMENT_MISMATCH", "LaunchPermitV1.expectedResultHash");
  assertEqual(permit.stampRequestHash, stampRequest.stampRequestHash, "PROGRAMMABLE_ROUTER_PERMIT_COMMITMENT_MISMATCH", "LaunchPermitV1.stampRequestHash");
  if (typeof permit.nonce !== "string" || !NONZERO_BYTES32.test(permit.nonce)) {
    fail("PROGRAMMABLE_ROUTER_PERMIT_INVALID", "LaunchPermitV1.nonce must be one nonzero lowercase bytes32 commitment.");
  }
  if (typeof permit.value !== "string" || permit.value.length > 78 || !DECIMAL.test(permit.value)) {
    fail("PROGRAMMABLE_ROUTER_PERMIT_INVALID", "LaunchPermitV1.value must be one canonical uint256 decimal string.");
  }
  try {
    if (BigInt(permit.value) > (1n << 256n) - 1n) throw new RangeError("uint256 overflow");
  } catch (error) {
    fail("PROGRAMMABLE_ROUTER_PERMIT_INVALID", "LaunchPermitV1.value exceeds uint256.", error);
  }
  validateRouteSemanticBindings(routePayload.decoded, stampRequest.request, permit, resolvedRouter, category);
}

function validateRoutePayloadCommitment(value, category) {
  assertExactKeys(value, ["byteLength", "contentBase64", "encoding", "keccak256", "sha256"], "PROGRAMMABLE_ROUTER_COMMITMENTS_INVALID", "routePayload");
  const expectedEncoding = category === "custom" ? "abi.encode(CustomGraphRouteV1)" : "abi.encode(ClassicRouteV1)";
  assertEqual(value.encoding, expectedEncoding, "PROGRAMMABLE_ROUTER_COMMITMENTS_INVALID", "routePayload.encoding");
  const binding = validateBoundBytes({
    base64: value.contentBase64,
    byteLength: value.byteLength,
    keccak256: value.keccak256,
    sha256: value.sha256
  }, "routePayload");
  const decoded = decodeAndRequireCanonicalRoutePayload(binding.bytes, category);
  return {
    ...binding,
    decoded,
    expectedResultHash: computeRouteExpectedResultHash(decoded, category)
  };
}

function validateExpectedResultCommitment(value, routePayload) {
  assertExactKeys(value, ["derivationMode", "hash", "routePayloadSha256"], "PROGRAMMABLE_ROUTER_COMMITMENTS_INVALID", "expectedResult");
  assertEqual(value.derivationMode, "router-v1-route-kind-specific-typed-hash", "PROGRAMMABLE_ROUTER_COMMITMENTS_INVALID", "expectedResult.derivationMode");
  if (typeof value.hash !== "string" || !NONZERO_BYTES32.test(value.hash)) {
    fail("PROGRAMMABLE_ROUTER_COMMITMENTS_INVALID", "expectedResult.hash must be one nonzero lowercase bytes32 value.");
  }
  assertEqual(value.routePayloadSha256, routePayload.sha256, "PROGRAMMABLE_ROUTER_COMMITMENTS_INVALID", "expectedResult.routePayloadSha256");
  assertEqual(value.hash, routePayload.expectedResultHash, "PROGRAMMABLE_ROUTER_COMMITMENTS_INVALID", "expectedResult.hash");
  return { hash: value.hash };
}

function validateStampRequestCommitment(value, category) {
  assertExactKeys(value, [
    "componentSetHash",
    "components",
    "hashAlgorithm",
    "hookRuntimeCodeHash",
    "launchId",
    "poolKey",
    "poolKeyHash",
    "stampRequestHash",
    "token",
    "tokenRuntimeCodeHash",
    "typeHash",
    "typeSignature"
  ], "PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID", "StampRequestV1 commitment");
  assertEqual(value.hashAlgorithm, "router-v1-typed-hash", "PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID", "StampRequestV1 hashAlgorithm");
  assertEqual(value.typeHash, STAMP_REQUEST_TYPE_HASH, "PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID", "StampRequestV1 typeHash");
  assertEqual(value.typeSignature, STAMP_REQUEST_TYPE_SIGNATURE, "PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID", "StampRequestV1 typeSignature");
  const request = {
    components: value.components,
    hookRuntimeCodeHash: value.hookRuntimeCodeHash,
    launchId: value.launchId,
    poolKey: value.poolKey,
    token: value.token,
    tokenRuntimeCodeHash: value.tokenRuntimeCodeHash
  };
  const computed = computeStampRequestCommitment(request, category);
  assertEqual(value.componentSetHash, computed.componentSetHash, "PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID", "StampRequestV1.componentSetHash");
  assertEqual(value.poolKeyHash, computed.poolKeyHash, "PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID", "StampRequestV1.poolKeyHash");
  assertEqual(value.stampRequestHash, computed.stampRequestHash, "PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID", "StampRequestV1.stampRequestHash");
  return { request, stampRequestHash: computed.stampRequestHash };
}

function computeStampRequestCommitment(request, category) {
  assertExactKeys(request, [
    "components",
    "hookRuntimeCodeHash",
    "launchId",
    "poolKey",
    "token",
    "tokenRuntimeCodeHash"
  ], "PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID", "StampRequestV1 fields");
  if (!new Set(["custom", "classic"]).has(category)) {
    fail("PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID", "StampRequestV1 category must be custom or classic.");
  }
  assertNonzeroBytes32(request.launchId, "StampRequestV1.launchId");
  assertAddress(request.token, "StampRequestV1.token");
  assertNonzeroBytes32(request.tokenRuntimeCodeHash, "StampRequestV1.tokenRuntimeCodeHash");
  assertNonzeroBytes32(request.hookRuntimeCodeHash, "StampRequestV1.hookRuntimeCodeHash");
  const poolKeyHash = computePoolKeyHash(request.poolKey, request.token);
  const componentSetHash = computeComponentSetHash(request.components, request, category);
  const stampRequestHash = keccak256Hex(abiEncodeWords([
    bytes32AbiWord(STAMP_REQUEST_TYPE_HASH),
    bytes32AbiWord(request.launchId),
    addressAbiWord(request.token),
    bytes32AbiWord(request.tokenRuntimeCodeHash),
    bytes32AbiWord(poolKeyHash),
    bytes32AbiWord(request.hookRuntimeCodeHash),
    bytes32AbiWord(componentSetHash)
  ]));
  return { componentSetHash, poolKeyHash, stampRequestHash };
}

function computePoolKeyHash(poolKey, token) {
  assertExactKeys(poolKey, ["currency0", "currency1", "fee", "hooks", "tickSpacing"], "PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID", "StampRequestV1.poolKey");
  assertAddress(poolKey.currency0, "StampRequestV1.poolKey.currency0", { allowZero: true });
  assertAddress(poolKey.currency1, "StampRequestV1.poolKey.currency1", { allowZero: true });
  assertAddress(poolKey.hooks, "StampRequestV1.poolKey.hooks");
  const currency0 = BigInt(poolKey.currency0);
  const currency1 = BigInt(poolKey.currency1);
  if (currency0 >= currency1 || (BigInt(token) !== currency0 && BigInt(token) !== currency1)) {
    fail("PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID", "StampRequestV1 PoolKey currencies must be sorted and contain the token.");
  }
  if (!Number.isSafeInteger(poolKey.fee) || poolKey.fee < 0 || poolKey.fee > 0xff_ffff) {
    fail("PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID", "StampRequestV1.poolKey.fee must be uint24.");
  }
  if (!Number.isSafeInteger(poolKey.tickSpacing) || poolKey.tickSpacing < -0x80_0000 || poolKey.tickSpacing > 0x7f_ffff) {
    fail("PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID", "StampRequestV1.poolKey.tickSpacing must be int24.");
  }
  return keccak256Hex(abiEncodeWords([
    bytes32AbiWord(POOL_KEY_TYPE_HASH),
    addressAbiWord(poolKey.currency0),
    addressAbiWord(poolKey.currency1),
    uintAbiWord(BigInt(poolKey.fee)),
    signedAbiWord(BigInt(poolKey.tickSpacing), 24),
    addressAbiWord(poolKey.hooks)
  ]));
}

function computeComponentSetHash(components, request, category) {
  if (!Array.isArray(components) || types.isProxy(components) || components.length < 2 || components.length > 16) {
    fail("PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID", "StampRequestV1.components must contain two through sixteen components.");
  }
  if (category === "classic" && !new Set([4, 5]).has(components.length)) {
    fail("PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID", "Classic StampRequestV1 must contain exactly four or five components.");
  }
  let previous = -1n;
  const componentHashes = [];
  const resultIndexes = new Set();
  let tokenComponents = 0;
  let hookComponents = 0;
  for (const [index, component] of components.entries()) {
    assertExactKeys(component, ["account", "kind", "resultIndex", "runtimeCodeHash", "scope"], "PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID", `StampRequestV1.components[${index}]`);
    assertAddress(component.account, `StampRequestV1.components[${index}].account`);
    assertNonzeroBytes32(component.runtimeCodeHash, `StampRequestV1.components[${index}].runtimeCodeHash`);
    if (!Number.isSafeInteger(component.resultIndex) || component.resultIndex < 0 || component.resultIndex > 255) {
      fail("PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID", `StampRequestV1.components[${index}].resultIndex must be uint8.`);
    }
    if (!new Set([0, 1, 2]).has(component.kind) || !new Set([1, 2]).has(component.scope)) {
      fail("PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID", `StampRequestV1.components[${index}] kind or scope is invalid.`);
    }
    const account = BigInt(component.account);
    if (account <= previous) {
      fail("PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID", "StampRequestV1 components must be strictly address-sorted and unique.");
    }
    previous = account;
    if (resultIndexes.has(component.resultIndex)) {
      fail("PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID", "StampRequestV1 component result indexes must be unique.");
    }
    resultIndexes.add(component.resultIndex);
    const isToken = account === BigInt(request.token);
    const isHook = account === BigInt(request.poolKey.hooks);
    if (isToken) {
      tokenComponents += 1;
      if (component.kind !== 1 || component.scope !== 1 || component.runtimeCodeHash !== request.tokenRuntimeCodeHash) {
        fail("PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID", "StampRequestV1 token component does not match its token commitment.");
      }
    } else if (isHook) {
      hookComponents += 1;
      const expectedScope = category === "custom" ? 1 : 2;
      if (component.kind !== 2 || component.scope !== expectedScope || component.runtimeCodeHash !== request.hookRuntimeCodeHash) {
        fail("PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID", "StampRequestV1 hook component does not match its hook commitment.");
      }
    } else if (component.kind !== 0 || component.scope !== 1) {
      fail("PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID", "Non-token and non-hook components must be exclusive Other components.");
    }
    componentHashes.push(keccak256Hex(abiEncodeWords([
      bytes32AbiWord(COMPONENT_TYPE_HASH),
      uintAbiWord(BigInt(component.resultIndex)),
      addressAbiWord(component.account),
      bytes32AbiWord(component.runtimeCodeHash),
      uintAbiWord(BigInt(component.kind)),
      uintAbiWord(BigInt(component.scope))
    ])));
  }
  if (tokenComponents !== 1 || hookComponents !== 1 || BigInt(request.token) === BigInt(request.poolKey.hooks)) {
    fail("PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID", "StampRequestV1 requires one distinct token and hook component.");
  }
  if (category === "custom") {
    if (components.some((component) => component.scope !== 1)) {
      fail("PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID", "Custom Graph StampRequestV1 components must all be exclusive.");
    }
    for (let index = 0; index < components.length; index += 1) {
      if (!resultIndexes.has(index)) {
        fail("PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID", "Custom Graph StampRequestV1 result indexes must cover every target exactly once.");
      }
    }
  } else {
    const expectedIndexes = components.length === 4 ? [0, 1, 2, 255] : [0, 1, 2, 3, 255];
    if (expectedIndexes.some((index) => !resultIndexes.has(index))) {
      fail("PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID", "Classic StampRequestV1 component indexes do not match Router V1.");
    }
    const tokenComponent = components.find((component) => BigInt(component.account) === BigInt(request.token));
    const hookComponent = components.find((component) => BigInt(component.account) === BigInt(request.poolKey.hooks));
    if (tokenComponent?.resultIndex !== 0 || hookComponent?.resultIndex !== 255) {
      fail("PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID", "Classic token and shared hook indexes must be 0 and 255.");
    }
  }
  return keccak256Hex(Buffer.concat(componentHashes.map((hash) => Buffer.from(hash.slice(2), "hex"))));
}

function abiEncodeWords(words) {
  if (!Array.isArray(words) || words.length < 1 || words.some((word) => !Buffer.isBuffer(word) || word.length !== 32)) {
    fail("PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID", "Router V1 ABI word encoding is invalid.");
  }
  return Buffer.concat(words);
}

function bytes32AbiWord(value) {
  assertNonzeroBytes32(value, "Router V1 bytes32 ABI word");
  return Buffer.from(value.slice(2), "hex");
}

function addressAbiWord(value) {
  assertAddress(value, "Router V1 address ABI word", { allowZero: true });
  return Buffer.from(value.slice(2).toLowerCase().padStart(64, "0"), "hex");
}

function uintAbiWord(value) {
  if (typeof value !== "bigint" || value < 0n || value > (1n << 256n) - 1n) {
    fail("PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID", "Router V1 uint ABI word is out of range.");
  }
  return Buffer.from(value.toString(16).padStart(64, "0"), "hex");
}

function signedAbiWord(value, bits) {
  const minimum = -(1n << BigInt(bits - 1));
  const maximum = (1n << BigInt(bits - 1)) - 1n;
  if (typeof value !== "bigint" || value < minimum || value > maximum) {
    fail("PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID", `Router V1 int${bits} ABI word is out of range.`);
  }
  const encoded = value < 0n ? (1n << 256n) + value : value;
  return Buffer.from(encoded.toString(16).padStart(64, "0"), "hex");
}

function abiTuple(entries) {
  return Object.freeze({
    fields: Object.freeze(entries.map(([name, type]) => Object.freeze({ name, type }))),
    kind: "tuple"
  });
}

function abiArray(element, maximumLength = 4096) {
  return Object.freeze({ element, kind: "array", maximumLength });
}

function abiTypeIsDynamic(type) {
  if (type.kind === "bytes" || type.kind === "string" || type.kind === "array") return true;
  if (type.kind === "tuple") return type.fields.some((field) => abiTypeIsDynamic(field.type));
  return false;
}

function abiStaticSize(type) {
  if (abiTypeIsDynamic(type)) return null;
  if (type.kind === "tuple") {
    return type.fields.reduce((total, field) => total + abiStaticSize(field.type), 0);
  }
  return 32;
}

function encodeAbiArguments(types, values, label) {
  if (!Array.isArray(types) || !Array.isArray(values) || types.length !== values.length) {
    fail("PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID", `${label} ABI argument list is invalid.`);
  }
  return encodeAbiSequence(types, values, label);
}

function encodeAbiSequence(types, values, label) {
  const headLength = types.reduce((total, type) => total + (abiTypeIsDynamic(type) ? 32 : abiStaticSize(type)), 0);
  const heads = [];
  const tails = [];
  let tailLength = 0;
  for (let index = 0; index < types.length; index += 1) {
    const type = types[index];
    const value = values[index];
    const itemLabel = `${label}[${index}]`;
    if (abiTypeIsDynamic(type)) {
      const tail = encodeAbiDynamic(type, value, itemLabel);
      heads.push(uintAbiWord(BigInt(headLength + tailLength)));
      tails.push(tail);
      tailLength += tail.length;
    } else {
      heads.push(encodeAbiStatic(type, value, itemLabel));
    }
  }
  return Buffer.concat([...heads, ...tails]);
}

function encodeAbiStatic(type, value, label) {
  if (type.kind === "address") {
    assertAddress(value, label, { allowZero: true });
    return addressAbiWord(value);
  }
  if (type.kind === "bytes32") {
    if (typeof value !== "string" || !BYTES32.test(value)) {
      fail("PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID", `${label} must be one lowercase bytes32 value.`);
    }
    return Buffer.from(value.slice(2), "hex");
  }
  if (type.kind === "uint") return uintAbiWord(readAbiUintJson(value, type, label));
  if (type.kind === "tuple") {
    assertExactKeys(value, type.fields.map((field) => field.name), "PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID", label);
    return encodeAbiSequence(
      type.fields.map((field) => field.type),
      type.fields.map((field) => value[field.name]),
      label
    );
  }
  fail("PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID", `${label} has an unsupported static ABI type.`);
}

function encodeAbiDynamic(type, value, label) {
  if (type.kind === "tuple") {
    assertExactKeys(value, type.fields.map((field) => field.name), "PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID", label);
    return encodeAbiSequence(
      type.fields.map((field) => field.type),
      type.fields.map((field) => value[field.name]),
      label
    );
  }
  if (type.kind === "array") {
    if (!Array.isArray(value) || types.isProxy(value) || value.length > type.maximumLength) {
      fail("PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID", `${label} must be one bounded non-proxy ABI array.`);
    }
    return Buffer.concat([
      uintAbiWord(BigInt(value.length)),
      encodeAbiSequence(
        Array.from({ length: value.length }, () => type.element),
        value,
        label
      )
    ]);
  }
  let bytes;
  if (type.kind === "bytes") {
    if (typeof value !== "string" || !/^0x(?:[0-9a-f]{2})*$/u.test(value)) {
      fail("PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID", `${label} must be canonical lowercase hex bytes.`);
    }
    bytes = Buffer.from(value.slice(2), "hex");
  } else if (type.kind === "string") {
    if (typeof value !== "string" || Buffer.from(value, "utf8").toString("utf8") !== value) {
      fail("PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID", `${label} must be one valid UTF-8 string.`);
    }
    bytes = Buffer.from(value, "utf8");
  } else {
    fail("PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID", `${label} has an unsupported dynamic ABI type.`);
  }
  if (bytes.length > 262_144) {
    fail("PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID", `${label} exceeds the closed dynamic byte boundary.`);
  }
  const padded = Buffer.alloc(Math.ceil(bytes.length / 32) * 32);
  bytes.copy(padded);
  return Buffer.concat([uintAbiWord(BigInt(bytes.length)), padded]);
}

function readAbiUintJson(value, type, label) {
  let parsed;
  if (type.json === "number") {
    if (!Number.isSafeInteger(value) || value < 0) {
      fail("PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID", `${label} must be one nonnegative safe integer.`);
    }
    parsed = BigInt(value);
  } else {
    if (typeof value !== "string" || !DECIMAL.test(value) || value.length > 78) {
      fail("PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID", `${label} must be one canonical uint decimal string.`);
    }
    parsed = BigInt(value);
  }
  if (parsed >= (1n << BigInt(type.bits))) {
    fail("PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID", `${label} exceeds uint${type.bits}.`);
  }
  return parsed;
}

function decodeAndRequireCanonicalRoutePayload(bytes, category) {
  const type = category === "custom" ? CUSTOM_GRAPH_ROUTE_ABI_TYPE : CLASSIC_ROUTE_ABI_TYPE;
  let decoded;
  try {
    const result = decodeAbiSequence([type], bytes, 0, "routePayload");
    [decoded] = result.values;
    if (result.end !== bytes.length) throw new TypeError("routePayload has noncanonical trailing ABI bytes");
    const canonical = encodeAbiArguments([type], [decoded], "routePayload");
    if (!canonical.equals(bytes)) throw new TypeError("noncanonical ABI encoding");
  } catch (cause) {
    if (cause instanceof ProgrammableLaunchRouterReadinessError) throw cause;
    fail(
      "PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID",
      `routePayload must be one canonical abi.encode(${category === "custom" ? "CustomGraphRouteV1" : "ClassicRouteV1"}) value.`,
      cause
    );
  }
  return decoded;
}

function decodeAbiSequence(types, bytes, base, label) {
  const headLength = types.reduce((total, type) => total + (abiTypeIsDynamic(type) ? 32 : abiStaticSize(type)), 0);
  requireAbiRegion(bytes, base, headLength, `${label} head`);
  const values = [];
  let cursor = base;
  let tailCursor = base + headLength;
  for (let index = 0; index < types.length; index += 1) {
    const type = types[index];
    const itemLabel = `${label}[${index}]`;
    if (abiTypeIsDynamic(type)) {
      const offset = readAbiOffset(bytes, cursor, itemLabel);
      const absoluteOffset = base + offset;
      if (offset < headLength || offset % 32 !== 0 || absoluteOffset !== tailCursor) {
        throw new TypeError(`${itemLabel} has a noncanonical or aliased ABI offset`);
      }
      const decoded = decodeAbiDynamic(type, bytes, absoluteOffset, itemLabel);
      values.push(decoded.value);
      tailCursor = decoded.end;
      cursor += 32;
    } else {
      values.push(decodeAbiStatic(type, bytes, cursor, itemLabel));
      cursor += abiStaticSize(type);
    }
  }
  return { end: tailCursor, values };
}

function decodeAbiStatic(type, bytes, offset, label) {
  if (type.kind === "address") {
    const word = readAbiWord(bytes, offset, label);
    if (!word.subarray(0, 12).equals(Buffer.alloc(12))) throw new TypeError(`${label} address is not left-padded`);
    return `0x${word.subarray(12).toString("hex")}`;
  }
  if (type.kind === "bytes32") return `0x${readAbiWord(bytes, offset, label).toString("hex")}`;
  if (type.kind === "uint") {
    const parsed = readAbiWordUint(bytes, offset, label);
    if (parsed >= (1n << BigInt(type.bits))) throw new TypeError(`${label} exceeds uint${type.bits}`);
    return type.json === "number" ? Number(parsed) : parsed.toString();
  }
  if (type.kind === "tuple") {
    const decoded = decodeAbiSequence(type.fields.map((field) => field.type), bytes, offset, label);
    return Object.fromEntries(type.fields.map((field, index) => [field.name, decoded.values[index]]));
  }
  throw new TypeError(`${label} has an unsupported static ABI type`);
}

function decodeAbiDynamic(type, bytes, offset, label) {
  if (type.kind === "tuple") {
    const decoded = decodeAbiSequence(type.fields.map((field) => field.type), bytes, offset, label);
    return {
      end: decoded.end,
      value: Object.fromEntries(type.fields.map((field, index) => [field.name, decoded.values[index]]))
    };
  }
  if (type.kind === "array") {
    const length = readAbiBoundedLength(bytes, offset, label, type.maximumLength);
    const decoded = decodeAbiSequence(
      Array.from({ length }, () => type.element),
      bytes,
      offset + 32,
      label
    );
    return { end: decoded.end, value: decoded.values };
  }
  const length = readAbiBoundedLength(bytes, offset, label, 262_144);
  const paddedLength = Math.ceil(length / 32) * 32;
  requireAbiRegion(bytes, offset + 32, paddedLength, label);
  const padded = bytes.subarray(offset + 32, offset + 32 + paddedLength);
  if (!padded.subarray(length).equals(Buffer.alloc(paddedLength - length))) {
    throw new TypeError(`${label} has nonzero ABI padding`);
  }
  const value = padded.subarray(0, length);
  if (type.kind === "bytes") return { end: offset + 32 + paddedLength, value: `0x${value.toString("hex")}` };
  if (type.kind === "string") {
    const decoded = UTF8_DECODER.decode(value);
    if (!Buffer.from(decoded, "utf8").equals(value)) throw new TypeError(`${label} is not canonical UTF-8`);
    return { end: offset + 32 + paddedLength, value: decoded };
  }
  throw new TypeError(`${label} has an unsupported dynamic ABI type`);
}

function readAbiBoundedLength(bytes, offset, label, maximum) {
  const parsed = readAbiWordUint(bytes, offset, `${label} length`);
  if (parsed > BigInt(maximum)) throw new TypeError(`${label} exceeds its ABI length boundary`);
  return Number(parsed);
}

function readAbiOffset(bytes, offset, label) {
  const parsed = readAbiWordUint(bytes, offset, `${label} offset`);
  if (parsed > BigInt(bytes.length)) throw new TypeError(`${label} ABI offset exceeds the payload`);
  return Number(parsed);
}

function readAbiWordUint(bytes, offset, label) {
  return BigInt(`0x${readAbiWord(bytes, offset, label).toString("hex")}`);
}

function readAbiWord(bytes, offset, label) {
  requireAbiRegion(bytes, offset, 32, label);
  return bytes.subarray(offset, offset + 32);
}

function requireAbiRegion(bytes, offset, length, label) {
  if (
    !Number.isSafeInteger(offset)
    || !Number.isSafeInteger(length)
    || offset < 0
    || length < 0
    || offset > bytes.length
    || length > bytes.length - offset
  ) throw new TypeError(`${label} exceeds the ABI payload boundary`);
}

function computeRouteExpectedResultHash(route, category) {
  if (category === "custom") {
    const outputHashes = route.expectedOutputs.map((output) => keccak256Hex(abiEncodeWords([
      bytes32AbiWord(EXPECTED_GRAPH_OUTPUT_TYPE_HASH),
      uintAbiWord(BigInt(output.targetIndex)),
      bytes32AbiWordAllowZero(output.targetIdHash, "ExpectedGraphOutputV1.targetIdHash"),
      addressAbiWord(output.account),
      bytes32AbiWordAllowZero(output.runtimeCodeHash, "ExpectedGraphOutputV1.runtimeCodeHash")
    ])));
    const expectedOutputsHash = keccak256Hex(Buffer.concat(outputHashes.map((hash) => Buffer.from(hash.slice(2), "hex"))));
    return keccak256Hex(abiEncodeWords([
      bytes32AbiWord(EXPECTED_GRAPH_RESULT_TYPE_HASH),
      bytes32AbiWord(expectedOutputsHash),
      bytes32AbiWordAllowZero(route.expectedGraphDeploymentHash, "CustomGraphRouteV1.expectedGraphDeploymentHash")
    ]));
  }
  const result = route.expectedResult;
  const addressesHash = keccak256Hex(abiEncodeWords([
    bytes32AbiWord(CLASSIC_RESULT_ADDRESSES_TYPE_HASH),
    addressAbiWord(result.token),
    addressAbiWord(result.rewardVault),
    addressAbiWord(result.positionRecipient),
    addressAbiWord(result.initialBuyCustody)
  ]));
  const amountsHash = keccak256Hex(abiEncodeWords([
    bytes32AbiWord(CLASSIC_RESULT_AMOUNTS_TYPE_HASH),
    uintAbiWord(BigInt(result.positionTokenId)),
    uintAbiWord(BigInt(result.tokenLiquidityAmount)),
    uintAbiWord(BigInt(result.lockedTokenDust)),
    uintAbiWord(BigInt(result.initialBuyNativeAmount)),
    uintAbiWord(BigInt(result.initialBuyTokenAmount))
  ]));
  return keccak256Hex(abiEncodeWords([
    bytes32AbiWord(CLASSIC_RESULT_TYPE_HASH),
    bytes32AbiWord(addressesHash),
    bytes32AbiWord(amountsHash),
    bytes32AbiWordAllowZero(result.poolId, "ClassicRouteV1.expectedResult.poolId"),
    bytes32AbiWordAllowZero(result.launchHash, "ClassicRouteV1.expectedResult.launchHash")
  ]));
}

function bytes32AbiWordAllowZero(value, label) {
  if (typeof value !== "string" || !BYTES32.test(value)) {
    fail("PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID", `${label} must be one lowercase bytes32 value.`);
  }
  return Buffer.from(value.slice(2), "hex");
}

function validateRouteSemanticBindings(route, stampRequest, permit, router, category) {
  if (category === "custom") {
    validateCustomRouteSemanticBindings(route, stampRequest, permit, router);
    return;
  }
  validateClassicRouteSemanticBindings(route, stampRequest, permit, router);
}

function validateCustomRouteSemanticBindings(route, stampRequest, permit, router) {
  const length = route.targets.length;
  if (length < 1 || length > 16 || route.expectedOutputs.length !== length || stampRequest.components.length !== length) {
    fail("PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID", "CustomGraphRouteV1 target, output, and component counts must match within Router V1 bounds.");
  }
  for (const [label, value] of [
    ["routeNamespace", route.routeNamespace],
    ["topologyHash", route.topologyHash],
    ["graphCommitment", route.graphCommitment],
    ["expectedGraphDeploymentHash", route.expectedGraphDeploymentHash]
  ]) assertRouteNonzeroBytes32(value, `CustomGraphRouteV1.${label}`);
  assertEqual(route.routeNonce, permit.nonce, "PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID", "CustomGraphRouteV1.routeNonce");
  const accounts = new Set();
  const targetIds = new Set();
  let targetValueSum = 0n;
  let totalInputBytes = 0;
  for (let index = 0; index < length; index += 1) {
    const target = route.targets[index];
    const initCodeBytes = (target.initCode.length - 2) / 2;
    const initializerBytes = (target.initializerCalldata.length - 2) / 2;
    totalInputBytes += initCodeBytes + initializerBytes;
    targetValueSum += BigInt(target.deploymentValue) + BigInt(target.initializerValue);
    if (
      !NONZERO_BYTES32.test(target.targetIdHash)
      || targetIds.has(target.targetIdHash)
      || initCodeBytes < 1
      || initCodeBytes > 49_152
      || initializerBytes > 131_072
      || totalInputBytes > 524_288
      || (BigInt(target.initializerValue) !== 0n && initializerBytes === 0)
    ) {
      fail("PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID", `CustomGraphRouteV1.targets[${index}] violates Graph Factory V1 input bindings.`);
    }
    targetIds.add(target.targetIdHash);
    const output = route.expectedOutputs[index];
    if (
      output.targetIndex !== index
      || output.targetIdHash !== route.targets[index].targetIdHash
      || isZeroAddress(output.account)
      || !NONZERO_BYTES32.test(output.runtimeCodeHash)
      || accounts.has(output.account)
    ) {
      fail("PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID", `CustomGraphRouteV1.expectedOutputs[${index}] violates Router V1 shape bindings.`);
    }
    accounts.add(output.account);
    const component = stampRequest.components.find((candidate) => candidate.resultIndex === index);
    if (
      component === undefined
      || !sameAddress(component.account, output.account)
      || component.runtimeCodeHash !== output.runtimeCodeHash
      || component.scope !== 1
      || [router.bindings.graphFactory, router.bindings.poolManager]
        .some((address) => sameAddress(address, component.account))
    ) {
      fail("PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID", `CustomGraphRouteV1 expected output ${index} does not match StampRequestV1.`);
    }
  }
  if (targetValueSum !== BigInt(permit.value)) {
    fail("PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID", "CustomGraphRouteV1 target values must sum to LaunchPermitV1.value.");
  }
}

function validateClassicRouteSemanticBindings(route, stampRequest, permit, router) {
  if (
    isZeroAddress(route.launcher)
    || !NONZERO_BYTES32.test(route.launcherRuntimeCodeHash)
    || [router.address, router.bindings.graphFactory, router.bindings.poolManager, router.bindings.permitAuthority]
      .some((address) => sameAddress(address, route.launcher))
  ) {
    fail("PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID", "ClassicRouteV1 launcher identity violates Router V1 bindings.");
  }
  const result = route.expectedResult;
  const expectedPoolId = computeProgrammableLaunchRouterPoolIdV1(stampRequest.poolKey);
  if (
    !sameAddress(result.token, stampRequest.token)
    || isZeroAddress(result.rewardVault)
    || isZeroAddress(result.positionRecipient)
    || result.poolId !== expectedPoolId
    || BigInt(result.initialBuyNativeAmount) !== BigInt(permit.value)
    || BigInt(result.initialBuyTokenAmount) === 0n
    || !NONZERO_BYTES32.test(result.launchHash)
  ) {
    fail("PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID", "ClassicRouteV1 expected result violates Router V1 bindings.");
  }
  const expectedLength = isZeroAddress(result.initialBuyCustody) ? 4 : 5;
  if (stampRequest.components.length !== expectedLength) {
    fail("PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID", "ClassicRouteV1 component count does not match initial-buy custody.");
  }
  const expectedAccounts = new Map([
    [0, result.token],
    [1, result.rewardVault],
    [2, result.positionRecipient],
    [255, stampRequest.poolKey.hooks]
  ]);
  if (!isZeroAddress(result.initialBuyCustody)) expectedAccounts.set(3, result.initialBuyCustody);
  for (const [resultIndex, account] of expectedAccounts) {
    const component = stampRequest.components.find((candidate) => candidate.resultIndex === resultIndex);
    if (component === undefined || !sameAddress(component.account, account)) {
      fail("PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID", `ClassicRouteV1 result component ${resultIndex} does not match StampRequestV1.`);
    }
  }
  validateClassicCustodyConfiguration(route.parameters.initialBuyCustody);
}

function validateClassicCustodyConfiguration(custody) {
  const { mode, durationDays, cliffDays } = custody;
  if (
    mode > 3
    || (mode === 0 && (durationDays !== 0 || cliffDays !== 0))
    || (mode !== 0 && (durationDays < 1 || durationDays > 3650))
    || (mode !== 3 && cliffDays !== 0)
    || (mode === 3 && (cliffDays < 1 || cliffDays >= durationDays))
  ) {
    fail("PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID", "ClassicRouteV1 initial-buy custody schedule is invalid.");
  }
}

function assertRouteNonzeroBytes32(value, label) {
  if (typeof value !== "string" || !NONZERO_BYTES32.test(value)) {
    fail("PROGRAMMABLE_ROUTER_ROUTE_PAYLOAD_INVALID", `${label} must be one nonzero lowercase bytes32 value.`);
  }
}

function sameAddress(left, right) {
  return typeof left === "string" && typeof right === "string" && left.toLowerCase() === right.toLowerCase();
}

function isZeroAddress(value) {
  return typeof value !== "string" || /^0x0{40}$/iu.test(value);
}

function assertAddress(value, label, { allowZero = false } = {}) {
  if (
    typeof value !== "string"
    || !/^0x[0-9A-Fa-f]{40}$/u.test(value)
    || (!allowZero && /^0x0{40}$/iu.test(value))
  ) {
    fail("PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID", `${label} must be ${allowZero ? "an" : "a nonzero"} Ethereum address.`);
  }
}

function assertNonzeroBytes32(value, label) {
  if (typeof value !== "string" || !NONZERO_BYTES32.test(value)) {
    fail("PROGRAMMABLE_ROUTER_STAMP_REQUEST_INVALID", `${label} must be one nonzero lowercase bytes32 value.`);
  }
}

function validateBoundBytes(binding, label, code = "PROGRAMMABLE_ROUTER_COMMITMENTS_INVALID") {
  if (!Number.isSafeInteger(binding.byteLength) || binding.byteLength < 1 || binding.byteLength > MAXIMUM_PROGRAMMABLE_LAUNCH_ROUTE_PAYLOAD_BYTES) {
    fail(code, `${label}.byteLength is outside the closed commitment boundary.`);
  }
  if (typeof binding.base64 !== "string" || binding.base64.length < 4 || binding.base64.length > 709_676) {
    fail(code, `${label} must contain bounded canonical Base64 bytes.`);
  }
  let bytes;
  try {
    bytes = Buffer.from(binding.base64, "base64");
  } catch (error) {
    fail(code, `${label} Base64 could not be decoded.`, error);
  }
  if (bytes.length < 1 || bytes.toString("base64") !== binding.base64 || bytes.length !== binding.byteLength) {
    fail(code, `${label} Base64 or byte length is not canonical.`);
  }
  assertSha256(binding.sha256, `${label}.sha256`, code);
  if (digestBytes(bytes) !== binding.sha256) fail(code, `${label} SHA-256 does not match its exact bytes.`);
  if (typeof binding.keccak256 !== "string" || !NONZERO_BYTES32.test(binding.keccak256)) {
    fail(code, `${label}.keccak256 must be one nonzero lowercase bytes32 value.`);
  }
  if (keccak256Hex(bytes) !== binding.keccak256) fail(code, `${label} Keccak-256 does not match its exact bytes.`);
  return { bytes, keccak256: binding.keccak256, sha256: binding.sha256 };
}

function validateFeeConfiguration(fee, subject) {
  assertExactKeys(fee, [
    "basis",
    "bps",
    "chainId",
    "configurationSha256",
    "doubleChargeAllowed",
    "enforcementMode",
    "hundredthsOfBip",
    "implementationArtifact",
    "network",
    "ratePpm",
    "scope",
    "treasury"
  ], "PROGRAMMABLE_ROUTER_FEE_CONFIGURATION_INVALID", "feeConfiguration");
  for (const [key, value] of Object.entries(FEE_COMMITMENT)) {
    assertEqual(fee[key], value, "PROGRAMMABLE_ROUTER_FEE_CONFIGURATION_INVALID", `feeConfiguration.${key}`);
  }
  assertEqual(fee.configurationSha256, PROGRAMMABLE_TREASURY_TEN_BPS_CONFIGURATION_SHA256, "PROGRAMMABLE_ROUTER_FEE_CONFIGURATION_INVALID", "feeConfiguration.configurationSha256");
  validateArtifactBinding(fee.implementationArtifact, "feeConfiguration.implementationArtifact", "PROGRAMMABLE_ROUTER_FEE_CONFIGURATION_INVALID");
  if (fee.implementationArtifact.path === PROGRAMMABLE_LAUNCH_ROUTER_READINESS_PATH) {
    fail("PROGRAMMABLE_ROUTER_FEE_CONFIGURATION_INVALID", "Fee evidence must bind implementation or configuration bytes, not the readiness document itself.");
  }
  if (!subject.sourceConfigurationHash.startsWith("sha256:")) {
    fail("PROGRAMMABLE_ROUTER_FEE_CONFIGURATION_INVALID", "Fee evidence requires the exact reviewed source configuration hash.");
  }
}

function validateArtifactBinding(binding, label, code) {
  assertExactKeys(binding, ["byteLength", "gitBlobOid", "path", "sha256"], code, label);
  if (!Number.isSafeInteger(binding.byteLength) || binding.byteLength < 1 || binding.byteLength > 16 * 1024 * 1024) {
    fail(code, `${label}.byteLength is invalid.`);
  }
  assertObjectId(binding.gitBlobOid, `${label}.gitBlobOid`, code);
  assertRepositoryPath(binding.path, `${label}.path`, code);
  assertSha256(binding.sha256, `${label}.sha256`, code);
}

function buildPolicyEvidence(document, documentSha256) {
  if (document.state === "not-applicable") return {};
  const pending = document.state === "analysis-pending";
  const subject = document.subject;
  const router = document.resolvedRouter;
  const manifest = document.manifestSnapshot;
  const route = document.route;
  const readiness = {
    abiSha256: pending ? null : router.abiSha256,
    abiUrl: pending ? null : router.abiUrl,
    chainId: 1,
    directFactoryCall: false,
    discoveryDocumentUrl: DISCOVERY_DOCUMENT_URL,
    launchEntryPoint: LAUNCH_ENTRY_POINT,
    launchKind: pending ? null : route.launchKind,
    manifestSha256: pending ? null : manifest.manifestSourceSha256,
    manifestUrl: MANIFEST_URL,
    routeEvidenceSha256: pending ? null : documentSha256,
    routerAddress: pending ? null : router.address,
    routerManifestPointer: ROUTER_MANIFEST_POINTER,
    routerRuntimeCodeHash: pending ? null : router.runtimeCodeHash,
    routerStatus: pending ? null : router.status,
    sourceCommit: subject.sourceCommit,
    sourceConfigurationHash: subject.sourceConfigurationHash,
    sourceTree: subject.sourceTree,
    status: pending ? "analysis-pending" : "passed"
  };
  assertExactKeys(readiness, [
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
  ], "PROGRAMMABLE_ROUTER_POLICY_PROJECTION_INVALID", "programmable-router-readiness projection");
  const fee = pending ? FEE_COMMITMENT : document.feeConfiguration;
  const launchRequirement = {
    basis: fee.basis,
    chainId: fee.chainId,
    hundredthsOfBip: fee.hundredthsOfBip,
    network: fee.network,
    status: pending ? "analysis-pending" : "passed",
    treasury: fee.treasury
  };
  return {
    "programmable-launch-requirement": launchRequirement,
    "programmable-router-readiness": readiness
  };
}

function assertRepositoryPath(value, label, code) {
  const parts = typeof value === "string" ? value.split("/") : [];
  if (
    typeof value !== "string"
    || value.length < 1
    || value.length > 1024
    || Buffer.byteLength(value, "utf8") > 1024
    || !REPOSITORY_PATH.test(value)
    || value.startsWith("/")
    || value.includes("\\")
    || value.includes("\0")
    || value.includes("\n")
    || value.includes("\r")
    || parts.some((part) => part === "" || part === "." || part === ".." || part.toLowerCase() === ".git")
  ) fail(code, `${label} must be one canonical repository-relative path.`);
}

function assertCanonicalTimestamp(value, label, code) {
  if (typeof value !== "string" || !CANONICAL_TIMESTAMP.test(value)) fail(code, `${label} must be canonical UTC ISO-8601 with milliseconds.`);
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) fail(code, `${label} is not a real canonical timestamp.`);
}

function assertSha256(value, label, code = "PROGRAMMABLE_ROUTER_DOCUMENT_INVALID") {
  if (typeof value !== "string" || !SHA256.test(value)) fail(code, `${label} must be one lowercase SHA-256 binding.`);
}

function assertObjectId(value, label, code) {
  if (typeof value !== "string" || !OBJECT_ID.test(value)) fail(code, `${label} must be one lowercase Git object id.`);
}

function assertRepository(value, label, code) {
  if (typeof value !== "string" || !REPOSITORY.test(value)) fail(code, `${label} must be one owner/repository identity.`);
}

function assertNumericId(value, label, code) {
  if (typeof value !== "string" || !NUMERIC_ID.test(value)) fail(code, `${label} must be one nonzero decimal repository id.`);
}

function assertCanonicalEqual(observed, expected, code, label) {
  if (canonicalProgrammableLaunchRouterReadinessJson(observed) !== canonicalProgrammableLaunchRouterReadinessJson(expected)) {
    fail(code, `${label} does not match the exact closed V1 value.`);
  }
}

function assertEqual(observed, expected, code, label) {
  if (observed !== expected) fail(code, `${label} must equal ${JSON.stringify(expected)}.`);
}

function assertExactKeys(value, expectedKeys, code, label) {
  if (!isPlainObject(value)) fail(code, `${label} must be a plain object.`);
  const observed = Object.keys(value).sort(compareUtf8);
  const expected = [...expectedKeys].sort(compareUtf8);
  if (observed.length !== expected.length || observed.some((key, index) => key !== expected[index])) {
    fail(code, `${label} must have the exact closed key set.`);
  }
}

function digestBytes(bytes) {
  return `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function isPlainObject(value) {
  return value !== null
    && typeof value === "object"
    && !types.isProxy(value)
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function fail(code, message, cause) {
  throw new ProgrammableLaunchRouterReadinessError(code, message, cause === undefined ? undefined : { cause });
}
