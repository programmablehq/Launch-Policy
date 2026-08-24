import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const read = (relativePath) => fs.readFileSync(path.resolve(relativePath), "utf8");
const intake = read(".github/workflows/verify-hook-builder.yml");
const ordinary = read(".github/workflows/verify.yml");
const postMerge = read(".github/workflows/verify-post-merge.yml");
const codeql = read(".github/workflows/codeql.yml");
const packageManifest = JSON.parse(read("package.json"));
const packageLock = JSON.parse(read("package-lock.json"));
const readme = read("README.md");

test("the retired GitHub intake is a read-only path guard", () => {
  assert.match(intake, /^name: GitHub launch intake is closed$/mu);
  assert.match(intake, /pull_request_target:\n\s+branches:\n\s+- main/u);
  assert.match(intake, /paths:\n\s+- "submissions\/\*\*"\n\s+- "canary-submissions\/\*\*"/u);
  assert.match(intake, /\npermissions:\n  contents: read\n/u);
  assert.match(intake, /name: Use the Custom Launch API/u);
  assert.match(intake, /https:\/\/programmable\.market\/developers\/api-keys/u);
  assert.match(intake, /https:\/\/programmable\.market\/developers\/custom-launch-api-v1\.md/u);
  assert.match(intake, /exit 1/u);
  assert.doesNotMatch(intake, /actions\/checkout|npm\s+(?:ci|install|test)|secrets\.|github\.token|contents:\s*write|pull-requests:\s*write|id-token:/u);
});

test("ordinary maintenance CI is read-only and exposes the Node 24 required context", () => {
  assert.match(ordinary, /pull_request:\n\s+branches:\n\s+- main/u);
  assert.match(ordinary, /\n  workflow_dispatch:/u);
  assert.doesNotMatch(ordinary, /pull_request_target|paths-ignore/u);
  assert.match(ordinary, /\npermissions:\n  contents: read\n/u);
  assert.match(ordinary, /persist-credentials: false/u);
  assert.match(ordinary, /node:\n\s+- 24/u);
  assert.doesNotMatch(ordinary, /\n\s+- 22(?:\n|$)/u);
  assert.match(ordinary, /run: npm test/u);
  assert.match(ordinary, /name: Node \$\{\{ matrix\.node \}\}/u);
  assert.match(ordinary, /needs:\n\s+- repository/u);
  assert.doesNotMatch(ordinary, /secrets\.|github\.token|contents:\s*write/u);
});

test("CodeQL is an ordinary read-only pull-request check", () => {
  assert.match(codeql, /pull_request:\n\s+branches:\n\s+- main/u);
  assert.match(codeql, /push:\n\s+branches:\n\s+- main/u);
  assert.doesNotMatch(codeql, /pull_request_target|paths-ignore|bounded-application/u);
  assert.match(codeql, /permissions:\n\s+contents: read\n\s+security-events: write/u);
  assert.match(codeql, /languages: javascript-typescript/u);
  assert.match(codeql, /name: CodeQL/u);
  assert.doesNotMatch(codeql, /secrets\.|contents:\s*write|pull-requests:\s*write/u);
});

test("post-merge verifies the repository and preserved historical records", () => {
  assert.match(postMerge, /push:\n\s+branches:\n\s+- main/u);
  assert.match(postMerge, /\n  workflow_dispatch:/u);
  assert.doesNotMatch(postMerge, /pull_request/u);
  assert.match(postMerge, /working-directory: source\n\s+run: npm test/u);
  assert.match(postMerge, /--verify-maintained/u);
  assert.match(postMerge, /--repository-root "\$source_root"/u);
  assert.match(postMerge, /node:\n\s+- 24/u);
});

test("all third-party actions remain commit-pinned", () => {
  for (const [name, source] of [["ordinary", ordinary], ["post-merge", postMerge], ["CodeQL", codeql]]) {
    const uses = [...source.matchAll(/^\s*uses:\s*([^\s#]+)/gmu)].map((match) => match[1]);
    assert.ok(uses.length > 0, `${name} must use at least one action`);
    for (const action of uses) assert.match(action, /^[^@\s]+@[a-f0-9]{40}$/u);
  }
});

test("the active runtime and package identity are Launch Policy on Node 24", () => {
  assert.equal(packageManifest.name, "@programmable/launch-policy");
  assert.equal(packageLock.packages[""].name, "@programmable/launch-policy");
  assert.equal(packageManifest.engines.node, ">=24.12.0");
  assert.equal(packageLock.packages[""].engines.node, ">=24.12.0");
  assert.match(readme, /Node\.js 24\.12 or newer is required/u);
  for (const source of [ordinary, postMerge, codeql]) {
    assert.doesNotMatch(source, /node-version:\s*(?:20|22)(?:\s|$)|\n\s+- (?:20|22)(?:\n|$)/u);
  }
});
