import assert from "node:assert/strict";
import childProcess from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  ACTIVE_CONTRACT_ROLE_PATHS_V1,
  ACTIVE_CONTRACT_ROLE_PATHS_V2,
  buildLaunchPolicyArtifacts,
  readRepositoryLaunchPolicy,
  verifyLaunchPolicyArtifacts
} from "../scripts/generate-launch-policy-artifacts.mjs";
import {
  canonicalJson,
  renderLaunchPolicyMarkdown
} from "../scripts/launch-policy-core.mjs";

const root = path.resolve(import.meta.dirname, "..");
const cli = path.join(root, "scripts/launch-policy.mjs");
const read = (relativePath) => fs.readFileSync(path.join(root, relativePath), "utf8");

function run(arguments_) {
  return childProcess.spawnSync(process.execPath, [cli, ...arguments_], {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env },
    shell: false
  });
}

function parseCanonicalOutput(result) {
  const value = JSON.parse(result.stdout);
  assert.equal(result.stdout, `${canonicalJson(value)}\n`);
  return value;
}

function digest(relativePath) {
  return `sha256:${crypto.createHash("sha256").update(fs.readFileSync(path.join(root, relativePath))).digest("hex")}`;
}

function isolatedCliFixture(t, policyBytes) {
  const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), "launch-policy-cli-"));
  t.after(() => fs.rmSync(fixtureRoot, { recursive: true, force: true }));
  for (const relativePath of [
    "scripts/launch-policy.mjs",
    "scripts/launch-policy-core.mjs",
    "scripts/launch-policy-handlers.mjs",
    "scripts/programmable-runtime-fee-settlement-proof-core.mjs",
    "scripts/programmable-runtime-fee-settlement-proof-validation.mjs",
    "vendor/programmable-v4-hook-builder/scripts/github-public-source-lossless-json.mjs"
  ]) {
    const target = path.join(fixtureRoot, relativePath);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.copyFileSync(path.join(root, relativePath), target);
  }
  fs.cpSync(
    path.join(root, "vendor/programmable-applicant-validator"),
    path.join(fixtureRoot, "vendor/programmable-applicant-validator"),
    { recursive: true }
  );
  fs.cpSync(
    path.join(root, "vendor/programmable-v4-hook-builder"),
    path.join(fixtureRoot, "vendor/programmable-v4-hook-builder"),
    { recursive: true }
  );
  if (policyBytes !== null) {
    const target = path.join(fixtureRoot, "policy/launch-policy.v1.json");
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, policyBytes);
  }
  return path.join(fixtureRoot, "scripts/launch-policy.mjs");
}

test("generated Markdown and active contract are byte-exact projections", () => {
  const record = readRepositoryLaunchPolicy({ repositoryRoot: root });
  assert.equal(read("docs/LAUNCH_POLICY.md"), renderLaunchPolicyMarkdown(record));
  assert.match(read("docs/LAUNCH_POLICY.md"), new RegExp(record.sha256, "u"));

  const artifacts = buildLaunchPolicyArtifacts({ repositoryRoot: root });
  assert.equal(artifacts.get("docs/LAUNCH_POLICY.md"), read("docs/LAUNCH_POLICY.md"));
  assert.equal(artifacts.get(".programmable/active-contract.json"), read(".programmable/active-contract.json"));
  assert.deepEqual(verifyLaunchPolicyArtifacts({ repositoryRoot: root }), {
    activeContractPath: ".programmable/active-contract.json",
    policyPath: "policy/launch-policy.v1.json",
    policySha256: record.sha256,
    renderedPolicyPath: "docs/LAUNCH_POLICY.md"
  });
});

test("generated-artifact verifier fails closed on stale bytes", (t) => {
  const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), "launch-policy-artifacts-"));
  t.after(() => fs.rmSync(fixtureRoot, { recursive: true, force: true }));
  const generated = buildLaunchPolicyArtifacts({ repositoryRoot: root });
  const generatedPaths = new Set(generated.keys());
  const sourcePaths = new Set([
    ...Object.values(ACTIVE_CONTRACT_ROLE_PATHS_V1).flat(),
    ...Object.values(ACTIVE_CONTRACT_ROLE_PATHS_V2).flat(),
    "vendor/programmable-applicant-validator/scripts/evm-encoding-core.mjs",
    "vendor/programmable-v4-hook-builder/scripts/github-public-source-lossless-json.mjs"
  ]);
  for (const relativePath of [...sourcePaths].filter((value) => !generatedPaths.has(value))) {
    const target = path.join(fixtureRoot, relativePath);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.copyFileSync(path.join(root, relativePath), target);
  }
  for (const [relativePath, source] of generated) {
    const target = path.join(fixtureRoot, relativePath);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, source, "utf8");
  }
  fs.appendFileSync(path.join(fixtureRoot, "docs/LAUNCH_POLICY.md"), "stale\n");
  assert.throws(
    () => verifyLaunchPolicyArtifacts({ repositoryRoot: fixtureRoot }),
    (error) => error?.code === "LAUNCH_POLICY_ARTIFACT_STALE"
  );
});

test("active contract V1 compatibility envelope binds the complete V2 role contract", () => {
  const generated = buildLaunchPolicyArtifacts({ repositoryRoot: root });
  const v2Source = generated.get(".programmable/active-contract.v2.json");
  for (const [relativePath, schemaVersion, expectedPaths] of [
    [".programmable/active-contract.json", "1.0.0", ACTIVE_CONTRACT_ROLE_PATHS_V1],
    [".programmable/active-contract.v2.json", "2.0.0", ACTIVE_CONTRACT_ROLE_PATHS_V2]
  ]) {
    const source = generated.get(relativePath);
    const manifest = JSON.parse(source);
    assert.equal(source, `${canonicalJson(manifest)}\n`);
    assert.deepEqual(Object.keys(manifest), ["$schema", "artifacts", "contractId", "defaultBranch", "kind", "schemaVersion"]);
    assert.equal(manifest.$schema, `urn:programmable:active-contract-manifest:${schemaVersion}`);
    assert.equal(manifest.schemaVersion, schemaVersion);
    assert.equal(manifest.kind, "programmable-active-contract");
    assert.equal(manifest.contractId, "launch-policy");
    assert.equal(manifest.defaultBranch, "main");
    assert.deepEqual(Object.keys(manifest.artifacts), ["package", "policy", "validator", "workflow"]);
    assert.deepEqual(manifest.artifacts, Object.fromEntries(
      Object.entries(expectedPaths).map(([role, paths]) => [
        role,
        paths.map((artifactPath) => ({
          path: artifactPath,
          sha256: artifactPath === ".programmable/active-contract.v2.json"
            ? `sha256:${crypto.createHash("sha256").update(v2Source).digest("hex")}`
            : digest(artifactPath)
        }))
      ])
    ));
  }
});

test("third-party requirements CLI needs no Hookbuilder and projects declared rules", () => {
  const result = run(["requirements", "--profile", "workflow-canary"]);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, "");
  const output = parseCanonicalOutput(result);
  assert.deepEqual(Object.keys(output), ["policy", "profile", "rules", "schemaVersion"]);
  assert.equal(output.schemaVersion, "programmable.launch-policy-requirements.v1");
  assert.equal(output.profile.id, "workflow-canary");
  assert.equal(output.profile.outcome, "CANARY_WORKFLOW_PASSED");
  assert.equal(output.profile.authority.launchAuthorized, false);
  assert.equal(output.profile.authority.publicRoutingAllowed, false);
  assert.equal(output.profile.authority.realUserFundsAllowed, false);
  assert.deepEqual(output.rules, []);
  assert.equal(output.policy.path, "policy/launch-policy.v1.json");
  assert.match(output.policy.sha256, /^sha256:[0-9a-f]{64}$/u);
});

test("launch-readiness requirements are enabled checker-only and project only prelaunch rules", () => {
  const result = run(["requirements", "--profile", "launch-readiness"]);
  assert.equal(result.status, 0, result.stderr);
  const output = parseCanonicalOutput(result);
  assert.equal(output.profile.enabled, true);
  assert.equal(output.profile.outcome, "LAUNCH_READINESS_CHECKED_NOT_AUTHORIZED");
  assert.equal(output.profile.authority.checkerOnly, true);
  assert.equal(output.profile.authority.launchAuthorized, false);
  assert.equal(output.profile.authority.productionDiscoveryAllowed, false);
  assert.equal(output.profile.authority.publicRoutingAllowed, false);
  assert.equal(output.profile.authority.realUserFundsAllowed, false);
  assert.deepEqual(output.rules.map(({ id }) => id), [
    "LAUNCH.ETHEREUM_AND_TREASURY_10_BPS",
    "LAUNCH.ETHEREUM_ROUTER_PROVENANCE_READINESS"
  ]);
  assert.doesNotMatch(result.stdout, /LAUNCH_APPROVED/u);
});

test("requirements expose enabled production checks without inventing approval authority", () => {
  const result = run(["requirements", "--profile", "production-launch"]);
  assert.equal(result.status, 0, result.stderr);
  const output = parseCanonicalOutput(result);
  assert.equal(output.profile.enabled, true);
  assert.equal(output.profile.outcome, "PRODUCTION_REQUIREMENTS_CHECKED_NOT_AUTHORIZED");
  assert.equal(output.profile.authority.checkerOnly, true);
  assert.equal(output.profile.authority.launchAuthorized, false);
  assert.deepEqual(output.rules.map(({ id }) => id), [
    "LAUNCH.ETHEREUM_AND_TREASURY_10_BPS",
    "LAUNCH.ETHEREUM_EXACT_FEE_TEMPLATE_BEFORE_AUTHORIZATION",
    "LAUNCH.ETHEREUM_FINALIZED_ROUTER_STAMP_BEFORE_PROMOTION",
    "LAUNCH.ETHEREUM_ROUTER_PROVENANCE_READINESS"
  ]);
  assert.doesNotMatch(result.stdout, /LAUNCH_APPROVED/u);
});

test("binding CLI binds the fixed Git policy for readiness and non-authorizing production checks", () => {
  const result = run(["binding", "--profile", "launch-readiness"]);
  assert.equal(result.status, 0, result.stderr);
  const binding = parseCanonicalOutput(result);
  assert.equal(binding.repository, "0xprogrammable/launch-policy");
  assert.equal(binding.numericRepositoryId, "1320171831");
  assert.equal(binding.baseCommit, childProcess.execFileSync("git", ["rev-parse", "HEAD^{commit}"], { cwd: root, encoding: "utf8" }).trim());
  assert.equal(binding.path, "policy/launch-policy.v1.json");
  assert.equal(binding.profileId, "launch-readiness");

  const production = run(["binding", "--profile", "production-launch"]);
  assert.equal(production.status, 0, production.stderr);
  const productionBinding = parseCanonicalOutput(production);
  assert.equal(productionBinding.profileId, "production-launch");
});

test("validate-policy and render read only the fixed local policy", () => {
  const validation = run(["validate-policy"]);
  assert.equal(validation.status, 0, validation.stderr);
  const result = parseCanonicalOutput(validation);
  assert.equal(result.result, "valid");
  assert.equal(result.policy.path, "policy/launch-policy.v1.json");

  const rendered = run(["render"]);
  assert.equal(rendered.status, 0, rendered.stderr);
  assert.equal(rendered.stderr, "");
  const projection = parseCanonicalOutput(rendered);
  assert.equal(projection.schemaVersion, "programmable.launch-policy-render.v1");
  assert.equal(projection.markdown, read("docs/LAUNCH_POLICY.md"));
  assert.equal(projection.policy.path, "policy/launch-policy.v1.json");
});

test("CLI help is a canonical read-only success result", () => {
  const result = run(["--help"]);
  assert.equal(result.status, 0, result.stderr);
  const help = parseCanonicalOutput(result);
  assert.equal(help.fixedPolicyPath, "policy/launch-policy.v1.json");
  assert.deepEqual(help.commands, [
    "requirements --profile <id>",
    "binding --profile <id>",
    "validate-policy",
    "render"
  ]);
});

test("CLI rejects caller-selected authority inputs before any protected read", () => {
  const unknown = run(["requirements", "--profile", "unknown"]);
  assert.equal(unknown.status, 1);
  assert.equal(JSON.parse(unknown.stderr).error.code, "LAUNCH_POLICY_PROFILE_INVALID");

  for (const arguments_ of [
    ["requirements", "--profile", "workflow-canary", "--policy", "/tmp/attacker.json"],
    ["binding", "--profile", "workflow-canary", "--repository", "attacker/repo"],
    ["validate-policy", "--path", "/tmp/attacker.json"],
    ["render", "--outcome", "LAUNCH_APPROVED"]
  ]) {
    const result = run(arguments_);
    assert.equal(result.status, 2, arguments_.join(" "));
    assert.equal(result.stdout, "");
    const failure = JSON.parse(result.stderr);
    assert.equal(result.stderr, `${canonicalJson(failure)}\n`);
    assert.equal(failure.ok, false);
  }
});

test("CLI distinguishes invalid owned policy from operational policy I/O", (t) => {
  const invalidCli = isolatedCliFixture(t, Buffer.from("{}\n", "utf8"));
  const invalid = childProcess.spawnSync(process.execPath, [invalidCli, "validate-policy"], {
    encoding: "utf8",
    shell: false
  });
  assert.equal(invalid.status, 1, invalid.stderr);
  assert.equal(JSON.parse(invalid.stderr).error.code, "LAUNCH_POLICY_FIELDS_INVALID");

  const missingCli = isolatedCliFixture(t, null);
  const missing = childProcess.spawnSync(process.execPath, [missingCli, "validate-policy"], {
    encoding: "utf8",
    shell: false
  });
  assert.equal(missing.status, 2, missing.stderr);
  assert.equal(JSON.parse(missing.stderr).error.code, "LAUNCH_POLICY_IO_FAILED");

  const noGitCli = isolatedCliFixture(t, fs.readFileSync(path.join(root, "policy/launch-policy.v1.json")));
  const noGit = childProcess.spawnSync(process.execPath, [noGitCli, "binding", "--profile", "workflow-canary"], {
    encoding: "utf8",
    shell: false
  });
  assert.equal(noGit.status, 2, noGit.stderr);
  assert.equal(JSON.parse(noGit.stderr).error.code, "LAUNCH_POLICY_GIT_FAILED");
});
