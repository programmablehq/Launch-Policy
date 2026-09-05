import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { TextDecoder } from "node:util";

import { parseBoundedLosslessJson } from "../vendor/programmable-v4-hook-builder/scripts/github-public-source-lossless-json.mjs";
import { canonicalJson } from "./launch-policy-core.mjs";
import { validateCustomLaunchAdmissionDescriptorV4 } from "./custom-launch-admission-v4-core.mjs";

export const ROBINHOOD_ECONOMICS_POLICY_V1_PATH = "policy/robinhood-custom-launch-economics-v1.json";
export const CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_V41_PATH = "policy/custom-launch-admission-v4.1.json";
export const CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_V41_SCHEMA_PATH = "policy/schemas/custom-launch-admission-v4.1.schema.json";
export const CUSTOM_LAUNCH_ADMISSION_BINDING_V41_PATH = ".programmable/custom-launch-admission.v4.1.json";
const LEGACY_POLICY_PATH = "policy/launch-policy.v1.json";
const MAXIMUM_JSON_BYTES = 2 * 1024 * 1024;
const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });

export function readCustomLaunchAdmissionV41Sources({ repositoryRoot }) {
  const policy = readCanonical(repositoryRoot, ROBINHOOD_ECONOMICS_POLICY_V1_PATH);
  const descriptor = readCanonical(repositoryRoot, CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_V41_PATH);
  validateRobinhoodEconomicsPolicyV1(policy.value);
  validateCustomLaunchAdmissionDescriptorV41(descriptor.value);
  equal(canonicalJson(descriptor.value.funding.plan), canonicalJson(policy.value.fundingPlan), "funding plan duties");
  const inherited = readCanonical(repositoryRoot, LEGACY_POLICY_PATH);
  equal(policy.value.inheritedPolicy.sha256, inherited.sha256, "inherited policy digest");
  equal(policy.value.inheritedPolicy.policyVersion, inherited.value.policyVersion, "inherited policy version");
  equal(descriptor.value.profile.profileVersion, policy.value.scope.profileVersion, "profile version");
  equal(descriptor.value.profile.profileRevision, policy.value.scope.profileRevision, "profile revision");
  equal(descriptor.value.economics.policyVersion, policy.value.policyVersion, "economics policy version");
  return deepFreeze({ policy, descriptor });
}

export function validateRobinhoodEconomicsPolicyV1(policy) {
  exactKeys(policy, ["accounting", "activation", "authority", "claims", "conformance", "custody", "flexibility", "fundingPlan", "inheritedPolicy", "platformFee", "policyId", "policyVersion", "repository", "schemaVersion", "scope"], "economics policy");
  equal(policy.schemaVersion, "programmable.robinhood-custom-launch-economics.v1", "economics schema");
  equal(policy.policyVersion, "1.0.0", "economics version");
  equal(policy.repository.path, ROBINHOOD_ECONOMICS_POLICY_V1_PATH, "economics path");
  equal(policy.scope.chainId, "4663", "economics chain");
  equal(policy.scope.caip2, "eip155:4663", "economics CAIP-2");
  equal(policy.scope.profileVersion, "4.1.0", "economics profile");
  equal(policy.scope.profileRevision, 2, "economics revision");
  equal(policy.scope.productionProfileId, "robinhood-production-launch", "production profile");
  equal(policy.authority.clientSelectable, false, "server selection");
  equal(policy.authority.clientVerdictsAccepted, false, "evidence authority");
  equal(policy.platformFee.feeBps, 20, "platform bps");
  equal(policy.platformFee.denominator, 10000, "bps denominator");
  equal(policy.platformFee.currency, "native-ETH", "fee currency");
  equal(policy.platformFee.recipient, "0xD88539d3c4C460136a733A3Fd60cf6BF269079da", "platform recipient");
  equal(policy.platformFee.rounding, "ceil-per-trade-wei", "rounding");
  equal(policy.platformFee.waiverAllowed, false, "no fee waiver");
  equal(policy.platformFee.recipientMutable, false, "fixed recipient");
  equal(policy.platformFee.feeMutable, false, "fixed fee");
  equal(policy.platformFee.creatorFeeIndependent, true, "creator independence");
  equal(policy.conformance.requiredForEveryFreshLaunch, true, "fresh launch fee proof");
  equal(policy.conformance.requestAssertionsAreEvidence, false, "no self-certification");
  equal(policy.flexibility.unsupportedDisposition, "needs-evidence", "unsupported proof disposition");
  equal(policy.flexibility.noveltyIsNotARejectionReason, true, "architecture neutrality");
  equal(policy.inheritedPolicy.path, LEGACY_POLICY_PATH, "inherited source");
  equal(canonicalJson(policy.inheritedPolicy.supersededRules), canonicalJson(["LAUNCH.ROBINHOOD_HONEST_FEE_CAPABILITY"]), "scoped supersession");
  equal(policy.activation.publishingDocumentActivatesProfile, false, "publication boundary");
  equal(policy.fundingPlan.schemaVersion, "programmable.robinhood-funding-plan.v1", "funding plan schema");
  equal(policy.fundingPlan.required, true, "required funding plan");
  equal(policy.fundingPlan.buildOnlyCannotCreate, true, "build-only launch boundary");
  for (const [claim, value] of Object.entries(policy.claims)) equal(value, false, `claim ${claim}`);
  return true;
}

export function validateCustomLaunchAdmissionDescriptorV41(descriptor) {
  exactKeys(descriptor.economics, ["policyPath", "policyVersion", "exactFeePathRequiredForFreshLaunch", "clientFeeAssertionsAccepted", "unknownSettlementDisposition", "lpPrincipalSafetyIsSeparate"], "economics binding");
  equal(descriptor.schemaVersion, "programmable.custom-launch-admission-descriptor.v4.1", "descriptor schema");
  equal(descriptor.authority.businessPolicyPath, ROBINHOOD_ECONOMICS_POLICY_V1_PATH, "business policy");
  equal(descriptor.economics.policyPath, ROBINHOOD_ECONOMICS_POLICY_V1_PATH, "economics source");
  equal(descriptor.economics.exactFeePathRequiredForFreshLaunch, true, "fee proof duty");
  equal(descriptor.economics.clientFeeAssertionsAccepted, false, "fee evidence authority");
  equal(descriptor.economics.unknownSettlementDisposition, "needs-evidence", "settlement evidence");
  equal(descriptor.economics.lpPrincipalSafetyIsSeparate, true, "principal boundary");
  equal(descriptor.funding.plan.schemaVersion, "programmable.robinhood-funding-plan.v1", "funding plan schema");
  equal(descriptor.funding.plan.required, true, "funding plan required");
  equal(descriptor.funding.plan.boundToLaunchIntent, true, "funding plan binding");
  equal(descriptor.transport.packConfigSchemaUrl, "https://programmable.market/schemas/custom-launch/v4.1/pack-config.json", "pack schema URL");
  equal(descriptor.transport.openApiUrl, "https://programmable.market/openapi/custom-launch-v4.1.json", "OpenAPI URL");
  equal(descriptor.profile.profileVersion, "4.1.0", "descriptor profile");
  equal(descriptor.profile.profileRevision, 2, "descriptor revision");
  equal(descriptor.profile.allFourteenHookPermissionsStructurallySupported, false, "bounded kernel capability");
  equal(canonicalJson(descriptor.activation), canonicalJson({state:"candidate",publishingDescriptorActivatesProfile:false,runtimeSourceAndProviderTupleRequired:true,historicalProfileReadsPreserved:true}), "activation boundary");
  // Reuse the exact frozen chain, transport and authority shape; never mutate V4.0 bytes.
  const legacy = structuredClone(descriptor);
  delete legacy.economics;
  delete legacy.activation;
  delete legacy.funding.plan;
  legacy.schemaVersion = "programmable.custom-launch-admission-descriptor.v4";
  legacy.authority.businessPolicyPath = LEGACY_POLICY_PATH;
  legacy.profile.profileVersion = "4.0.0";
  legacy.profile.profileRevision = 1;
  legacy.profile.allFourteenHookPermissionsStructurallySupported = true;
  legacy.transport.packConfigSchemaUrl = "https://programmable.market/schemas/custom-launch/v4/pack-config.json";
  legacy.transport.openApiUrl = "https://programmable.market/openapi/custom-launch-v4.json";
  validateCustomLaunchAdmissionDescriptorV4(legacy);
  return true;
}

export function buildCustomLaunchAdmissionSchemaV41({ repositoryRoot }) {
  const { policy, descriptor } = readCustomLaunchAdmissionV41Sources({ repositoryRoot });
  // Generated exact schema, not an independently authored fee-policy source.
  return deepFreeze({
    $schema: "https://json-schema.org/draft/2020-12/schema",
    $id: "https://programmable.market/schemas/custom-launch-admission-v4.1.json",
    title: "Programmable Robinhood admission 4.1 candidate",
    $defs: { economicsPolicy: { const: policy.value } },
    const: descriptor.value
  });
}

export function buildCustomLaunchAdmissionBindingV41({ repositoryRoot }) {
  const { policy, descriptor: record } = readCustomLaunchAdmissionV41Sources({ repositoryRoot });
  const descriptor = record.value;
  return deepFreeze({
    schemaVersion: "programmable.custom-launch-admission-binding.v4.1",
    businessPolicy: {
      path: ROBINHOOD_ECONOMICS_POLICY_V1_PATH, policyVersion: policy.value.policyVersion,
      productionProfileId: descriptor.policySelection.productionProfileId,
      readinessProfileId: descriptor.policySelection.readinessProfileId, sha256: policy.sha256
    },
    descriptor: {descriptorVersion: descriptor.descriptorVersion, path: CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_V41_PATH, schemaPath: CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_V41_SCHEMA_PATH, sha256: record.sha256},
    chain: descriptor.chain, claims: descriptor.claims, profile: descriptor.profile,
    repository: descriptor.repository, transport: descriptor.transport, economics: descriptor.economics,
    activation: descriptor.activation
  });
}

export function verifyCustomLaunchAdmissionBindingV41({ repositoryRoot }) {
  const binding = readCanonical(repositoryRoot, CUSTOM_LAUNCH_ADMISSION_BINDING_V41_PATH);
  const schema = readCanonical(repositoryRoot, CUSTOM_LAUNCH_ADMISSION_DESCRIPTOR_V41_SCHEMA_PATH);
  const expected = buildCustomLaunchAdmissionBindingV41({ repositoryRoot });
  equal(canonicalJson(binding.value), canonicalJson(expected), "generated binding; run npm run policy:generate");
  equal(canonicalJson(schema.value), canonicalJson(buildCustomLaunchAdmissionSchemaV41({repositoryRoot})), "generated schema; run npm run policy:generate");
  return Object.freeze({ok:true, path:CUSTOM_LAUNCH_ADMISSION_BINDING_V41_PATH, descriptorSha256:expected.descriptor.sha256, policySha256:expected.businessPolicy.sha256, schemaSha256:schema.sha256, bindingSha256:binding.sha256});
}

function readCanonical(root, relativePath) {
  if (typeof root !== "string" || !path.isAbsolute(root)) fail("Repository root must be absolute.");
  const filename = path.join(root, relativePath);
  const stat = fs.lstatSync(filename);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 2 || stat.size > MAXIMUM_JSON_BYTES) fail(`${relativePath} must be a bounded regular file.`);
  const bytes = fs.readFileSync(filename);
  if (bytes.length !== stat.size) fail(`${relativePath} changed while read.`);
  const source = UTF8.decode(bytes);
  parseBoundedLosslessJson(source);
  const value = JSON.parse(source);
  equal(source, `${canonicalJson(value)}\n`, `${relativePath} canonical JSON`);
  return {value, source, sha256:`sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`};
}
function equal(actual, expected, label) { if (actual !== expected) fail(`${label} is invalid.`); }
function exactKeys(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${label} must be an object.`);
  equal(canonicalJson(Object.keys(value).sort()), canonicalJson([...keys].sort()), `${label} keys`);
}
function fail(message) { const error = new Error(message); error.code = "CUSTOM_LAUNCH_ADMISSION_V41_INVALID"; throw error; }
function deepFreeze(value) { if(value && typeof value === "object" && !Object.isFrozen(value)) {Object.freeze(value);for(const child of Object.values(value))deepFreeze(child);}return value; }
