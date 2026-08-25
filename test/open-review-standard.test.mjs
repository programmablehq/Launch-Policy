import assert from "node:assert/strict";
import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import Ajv2020 from "../scripts/test/schema-validator/node_modules/ajv/dist/2020.js";

import { canonicalJson, evaluateOpenReview, validateOpenReviewInput } from "../review/open-review-engine.mjs";

const root = path.resolve(import.meta.dirname, "..");

test("legacy Open Review is a non-authorizing production compatibility preview", () => {
  const decision = evaluateOpenReview(fixture("disclosed-high-fee.json"));
  assert.equal(decision.profileId, "production-launch");
  assert.equal(decision.status, "analysis_pending");
  assert.equal(decision.outcome, null);
  assert.deepEqual(decision.currentPolicyBinding, decision.expectedPolicyBinding);
  assert.deepEqual(decision.pendingRuleIds, [
    "LAUNCH.ETHEREUM_AND_TREASURY_10_BPS",
    "LAUNCH.ETHEREUM_EXACT_FEE_TEMPLATE_BEFORE_AUTHORIZATION",
    "LAUNCH.ETHEREUM_FINALIZED_ROUTER_STAMP_BEFORE_PROMOTION",
    "LAUNCH.ETHEREUM_ROUTER_PROVENANCE_READINESS"
  ]);
  assert.deepEqual(decision.authority, {
    checkerOnly: true,
    independentAudit: false,
    launchAuthorized: false,
    publicRoutingAuthorized: false,
    realFundsAuthorized: false
  });
  assert.doesNotMatch(JSON.stringify(decision), /launch_ready|LAUNCH_APPROVED/u);
});

test("legacy novelty unknowns and witnesses remain bounded advisories only", () => {
  const novel = evaluateOpenReview(fixture("novel-platform-pending.json"));
  assert.equal(novel.status, "analysis_pending");
  assert.deepEqual(novel.findings, []);
  assert.equal(novel.advisories.length, 5);

  const witness = evaluateOpenReview(fixture("proven-unauthorized-diversion.json"));
  assert.equal(witness.status, "analysis_pending");
  assert.deepEqual(witness.findings, []);
  assert.equal(witness.advisories.some(({ summary }) => summary.includes("UNAUTHORIZED_VALUE_DIVERSION")), true);
});

test("the compatibility adapter cannot inject a policy or produce authority", () => {
  const input = fixture("disclosed-high-fee.json");
  const injected = { policyId: "attacker", outcome: "LAUNCH_APPROVED", profiles: [] };
  const decision = evaluateOpenReview(input, injected);
  assert.equal(evaluateOpenReview.length, 1);
  assert.equal(decision.trustedPolicy.policyId, "programmable-central-launch-policy");
  assert.equal(decision.outcome, null);
  assert.equal(decision.authority.launchAuthorized, false);
});

test("legacy compatibility rationales remain explicitly outside the canonical policy", () => {
  const policy = JSON.parse(fs.readFileSync(path.join(root, "policy/launch-policy.v1.json"), "utf8"));
  const ids = new Set(policy.rules.map(({ id }) => id));
  for (const name of legacyExamples()) {
    const decision = evaluateOpenReview(fixture(name));
    for (const advisory of decision.advisories) {
      assert.equal(advisory.ruleId, "LEGACY_V2.ADMISSION", `${name}: ${advisory.ruleId}`);
      assert.equal(ids.has(advisory.ruleId), false, `${name}: ${advisory.ruleId}`);
    }
    assert.deepEqual(decision.findings, [], name);
  }
});

test("legacy exact revisions remain visible without becoming launch authority", () => {
  const input = fixture("disclosed-high-fee.json");
  input.currentRevision.commit = "d".repeat(40);
  const decision = evaluateOpenReview(input);
  assert.equal(decision.status, "subject_drift");
  assert.equal(decision.expectedSubject.commit, "a".repeat(40));
  assert.equal(decision.currentSubject.commit, "d".repeat(40));
});

test("legacy closed obligations still require evidence", () => {
  const input = fixture("disclosed-high-fee.json");
  input.obligations[0].evidence = [];
  assert.throws(() => validateOpenReviewInput(input), hasCode("CLOSED_WITHOUT_EVIDENCE"));
});

test("candidate-controlled scores and extra fields cannot affect compatibility", () => {
  const input = fixture("disclosed-high-fee.json");
  input.riskScore = 100;
  assert.throws(() => validateOpenReviewInput(input), hasCode("FIELDS_INVALID"));
});

test("legacy input arrays are resource-bounded", () => {
  const input = fixture("disclosed-high-fee.json");
  input.obligations = Array.from({ length: 121 }, (_, index) => ({
    ...structuredClone(input.obligations[0]),
    id: `artifact.${String(index).padStart(3, "0")}`
  }));
  assert.throws(() => validateOpenReviewInput(input), hasCode("OBLIGATIONS_INVALID"));
});

test("compatibility decisions and digests are deterministic", () => {
  const input = fixture("disclosed-high-fee.json");
  const first = evaluateOpenReview(input);
  const second = evaluateOpenReview(input);
  assert.equal(canonicalJson(first), canonicalJson(second));
  assert.equal(first.digest, second.digest);
  assert.match(first.digest, /^sha256:[0-9a-f]{64}$/u);
});

test("legacy inputs and current decisions conform to their closed schemas", () => {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  const validateLegacyInput = ajv.compile(readJson("review/schemas/open-review-input.v1.schema.json"));
  const validateDecision = ajv.compile(readJson("review/schemas/launch-policy-review-decision.v1.schema.json"));

  for (const name of legacyExamples()) {
    const input = fixture(name);
    assert.equal(validateLegacyInput(input), true, `${name}: ${JSON.stringify(validateLegacyInput.errors)}`);
    const decision = evaluateOpenReview(input);
    assert.equal(validateDecision(decision), true, `${name}: ${JSON.stringify(validateDecision.errors)}`);
  }
});

test("the public CLI preserves its one-file checker-only transport", () => {
  const result = childProcess.spawnSync(process.execPath, ["review/cli.mjs", "review/examples/disclosed-high-fee.json"], {
    cwd: root,
    encoding: "utf8"
  });
  assert.equal(result.status, 0, result.stderr);
  const output = JSON.parse(result.stdout);
  assert.equal(result.stdout, `${canonicalJson(output)}\n`);
  assert.equal(output.ok, true);
  assert.equal(output.decision.status, "analysis_pending");
  assert.equal(output.decision.authority.launchAuthorized, false);
});

test("the public CLI rejects ambiguous duplicate-key JSON", (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "legacy-review-cli-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const inputPath = path.join(directory, "duplicate.json");
  fs.writeFileSync(inputPath, '{"schemaVersion":"programmable.open-review-input.v1","schemaVersion":"attacker"}\n');
  const result = childProcess.spawnSync(process.execPath, ["review/cli.mjs", inputPath], {
    cwd: root,
    encoding: "utf8"
  });
  assert.equal(result.status, 1);
  const output = JSON.parse(result.stdout);
  assert.equal(result.stdout, `${canonicalJson(output)}\n`);
  assert.equal(output.ok, false);
  assert.equal(output.error.code, "INPUT_JSON_INVALID");
});

function fixture(name) {
  return readJson(`review/examples/${name}`);
}

function legacyExamples() {
  return ["disclosed-high-fee.json", "novel-platform-pending.json", "proven-unauthorized-diversion.json"];
}

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(root, relativePath), "utf8"));
}

function hasCode(code) {
  return (error) => error?.code === code;
}
