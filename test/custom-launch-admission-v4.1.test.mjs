import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import Ajv2020 from "../scripts/test/schema-validator/node_modules/ajv/dist/2020.js";
import { canonicalJson } from "../scripts/launch-policy-core.mjs";
import {
  readCustomLaunchAdmissionV41Sources, validateRobinhoodEconomicsPolicyV1,
  validateCustomLaunchAdmissionDescriptorV41, verifyCustomLaunchAdmissionBindingV41
} from "../scripts/custom-launch-admission-v4.1-core.mjs";
const repositoryRoot = path.resolve(import.meta.dirname, "..");
const read = p => fs.readFileSync(path.join(repositoryRoot,p));
const policyPath = "policy/robinhood-custom-launch-economics-v1.json";
const descriptorPath = "policy/custom-launch-admission-v4.1.json";
const schemaPath = "policy/schemas/custom-launch-admission-v4.1.schema.json";
const schema = JSON.parse(read(schemaPath));
const ajv = new Ajv2020({strict:true,allErrors:true});
const validateDescriptorSchema = ajv.compile(schema);
const validatePolicySchema = ajv.compile({$ref:`${schema.$id}#/$defs/economicsPolicy`});
const {policy,descriptor} = readCustomLaunchAdmissionV41Sources({repositoryRoot});

test("4.1 policy, exact generated schema and binding agree without changing legacy policy", () => {
  assert.equal(verifyCustomLaunchAdmissionBindingV41({repositoryRoot}).ok,true);
  assert.equal(validateDescriptorSchema(descriptor.value),true);
  assert.equal(validatePolicySchema(policy.value),true);
  assert.equal(policy.value.inheritedPolicy.remainingRulesRequired,true);
  assert.deepEqual(policy.value.inheritedPolicy.supersededRules,["LAUNCH.ROBINHOOD_HONEST_FEE_CAPABILITY"]);
  for(const [p,hash]of Object.entries({
    "policy/launch-policy.v1.json":"31e6b286ca839b31cb1edfe30c05d9f334892f3d84377961dc10b93959c7e216",
    "policy/custom-launch-admission-v4.json":"99b4ccabdaaf143bad28a8f6af441a1b93e1f113d0179236328b7fa594d1f948",
    "policy/custom-launch-admission-v3.json":"b3a88009f081f653a8eadf87d4f199a2837704bae5edb752da70882ca994325c"
  }))assert.equal(crypto.createHash("sha256").update(read(p)).digest("hex"),hash,p);
});

test("a weakened fee, recipient, evidence authority or chain cannot fit profile 4.1", () => {
  for(const [field,key,value]of [
    ["scope","chainId","1"],["platformFee","feeBps",10],
    ["platformFee","recipient","0x0000000000000000000000000000000000000001"],
    ["platformFee","waiverAllowed",true],["platformFee","recipientMutable",true],
    ["platformFee","creatorFeeIndependent",false],["authority","clientVerdictsAccepted",true],
    ["conformance","requiredForEveryFreshLaunch",false],
    ["fundingPlan","buildOnlyCannotCreate",false]
  ]){const x=structuredClone(policy.value);x[field][key]=value;assert.equal(validatePolicySchema(x),false);assert.throws(()=>validateRobinhoodEconomicsPolicyV1(x));}
  for(const mutate of [x=>x.profile.profileRevision=1,x=>x.authority.businessPolicyPath="policy/launch-policy.v1.json",x=>x.economics.exactFeePathRequiredForFreshLaunch=false,x=>x.profile.allFourteenHookPermissionsStructurallySupported=true,x=>x.activation.state="active"]){const x=structuredClone(descriptor.value);mutate(x);assert.equal(validateDescriptorSchema(x),false);assert.throws(()=>validateCustomLaunchAdmissionDescriptorV41(x));}
});

test("every authored policy or descriptor leaf is bound by the generated exact schema", () => {
  const leaves=(value,segments=[])=>value!==null&&typeof value==="object"?Object.entries(value).flatMap(([k,v])=>leaves(v,[...segments,k])):[[segments,value]];
  for(const [record,validate]of [[policy,validatePolicySchema],[descriptor,validateDescriptorSchema]]){
    for(const [segments,value]of leaves(record.value)){const x=structuredClone(record.value);let parent=x;for(const k of segments.slice(0,-1))parent=parent[k];parent[segments.at(-1)]=typeof value==="boolean"?!value:typeof value==="number"?value+1:value===null?"unexpected":`${value}-changed`;assert.equal(validate(x),false,segments.join("."));}
  }
});

test("funding purpose is bound without implying reserve or fee proof", () => {
  assert.deepEqual(descriptor.value.funding.plan,policy.value.fundingPlan);
  const plan=policy.value.fundingPlan;
  assert.equal(plan.boundToLaunchIntent,true);assert.equal(plan.allocationsEqualExactTransactionValue,true);
  assert.equal(plan.initialBuyCountedOnce,true);assert.equal(plan.gasBudgetSeparate,true);
  assert.equal(plan.budgetAcknowledgementProvesAvailableFunds,false);assert.equal(plan.declaredPurposeProvesReservesOrSolvency,false);
  assert.equal(policy.value.flexibility.unsupportedDisposition,"needs-evidence");
  assert.equal(policy.value.flexibility.noveltyIsNotARejectionReason,true);
  assert.equal(policy.value.conformance.lpPrincipalSafetyIsSeparate,true);
});

test("fee scope is four quadrants, alternate routers and separate backed claims", () => {
  assert.deepEqual(policy.value.accounting.quadrants.map(x=>x.id),["buy-native-exact-input","buy-token-exact-output","sell-token-exact-input","sell-native-exact-output"]);
  assert.equal(policy.value.conformance.alternateRouterNoBypassRequired,true);
  assert.equal(policy.value.platformFee.otherPoolsAndTokenTransfersCovered,false);
  assert.equal(policy.value.custody.automaticEoaTransferDuringSwap,false);
  assert.equal(policy.value.custody.claimTransactionRequired,true);
  assert.equal(policy.value.custody.claimPlatform.destination,"fixed-platform-recipient");
  assert.equal(policy.value.custody.claimBucketsIsolated,true);
  assert.equal(policy.value.platformFee.feeBps/policy.value.platformFee.denominator*2_000_000,4000);
});

test("first buy requires atomic funded execution and a fresh server-owned USD reference", () => {
  const firstBuy=policy.value.firstBuy;
  assert.equal(firstBuy.requiredForEveryFreshLaunch,true);
  assert.equal(firstBuy.minimumUsd,"1.00");
  assert.equal(firstBuy.nativeAllocationCount,1);
  assert.equal(firstBuy.recipient,"bound-launch-controller");
  assert.equal(firstBuy.executionTimeUsdValueGuaranteed,false);
  assert.equal(firstBuy.externalChartOrIndexingGuaranteed,false);
  for(const mutate of [
    x=>x.firstBuy.requiredForEveryFreshLaunch=false,
    x=>x.firstBuy.minimumUsd="0.01",
    x=>x.firstBuy.atomicWithLaunch=false,
    x=>x.firstBuy.actualTokenOutputMustBePositive=false,
    x=>x.firstBuy.boundMinimumTokenOutputRequired=false,
    x=>x.firstBuy.clientPriceAssertionsAccepted=true,
    x=>x.firstBuy.freshQuoteRequiredBeforePermitSigning=false,
    x=>x.firstBuy.priceReference.sourceChainId="4663",
    x=>x.firstBuy.priceReference.decimals=18,
    x=>x.firstBuy.priceReference.independentProvidersRequired=1,
    x=>x.firstBuy.priceReference.sameRoundAndAnswerRequired=false,
    x=>x.firstBuy.priceReference.maximumSourceBlockAgeSeconds=121,
    x=>x.firstBuy.priceReference.maximumRoundAgeSeconds=7201,
    x=>x.firstBuy.priceReference.maximumQuoteAgeSeconds=61,
    x=>x.firstBuy.priceReference.providerFailureOrDisagreementBlocksAuthorization=false,
  ]){const x=structuredClone(policy.value);mutate(x);assert.equal(validatePolicySchema(x),false);assert.throws(()=>validateRobinhoodEconomicsPolicyV1(x));}
});

test("duplicate JSON and inherited source drift fail closed before producing a binding", t => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(),"rh41-policy-"));
  t.after(()=>fs.rmSync(temporary,{recursive:true,force:true}));
  for(const p of [policyPath,descriptorPath,"policy/launch-policy.v1.json"]){const target=path.join(temporary,p);fs.mkdirSync(path.dirname(target),{recursive:true});fs.writeFileSync(target,read(p));}
  const target=path.join(temporary,policyPath);
  fs.writeFileSync(target,policy.source.replace('"policyVersion":"1.1.0"','"policyVersion":"1.1.0","policyVersion":"1.1.0"'));
  assert.throws(()=>readCustomLaunchAdmissionV41Sources({repositoryRoot:temporary}));
  fs.writeFileSync(target,policy.source);
  const inherited=JSON.parse(read("policy/launch-policy.v1.json"));inherited.policyVersion="2.4.1";
  fs.writeFileSync(path.join(temporary,"policy/launch-policy.v1.json"),canonicalJson(inherited)+'\n');
  assert.throws(()=>readCustomLaunchAdmissionV41Sources({repositoryRoot:temporary}));
});
