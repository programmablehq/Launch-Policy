import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(".");
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");

test("the public landing page leads with the API-first launch boundary", () => {
  const readme = read("README.md");
  assert.match(readme, /<h1 align="center">Programmable Launch Policy<\/h1>/u);
  assert.match(readme, /\*\*GitHub launch intake is closed\.\*\*/u);
  assert.match(readme, /https:\/\/programmable\.market\/developers\/api-keys/u);
  assert.match(readme, /https:\/\/programmable\.market\/developers\/custom-launch-api-v1\.md/u);
  assert.match(readme, /https:\/\/programmable\.market\/openapi\.json/u);
  assert.match(readme, /POST https:\/\/api\.programmable\.market\/v1\/custom-launches/u);
  assert.match(readme, /does not accept or launch projects/u);
  assert.ok(readme.indexOf("GitHub launch intake is closed") < readme.indexOf("## Launch policy"));
});

test("the current owner is launch-policy while legacy provenance remains explicit", () => {
  const readme = read("README.md");
  assert.match(readme, /0xprogrammable\/launch-policy/u);
  assert.match(readme, /formerly named `0xprogrammable\/submit-launch`/u);
  assert.match(readme, /versioned legacy protocol\s+identifiers, frozen vendor bytes, historical snapshots, and old provenance links/u);
  assert.match(readme, /submissions\/.*preserves former V2, V3\.1, and V3\.2 application records/su);
  assert.match(readme, /canary-submissions\/.*preserves former Workflow Canary records/su);
  assert.doesNotMatch(readme, /Three intake transports are open|Open legacy V2/u);
});

test("public support routes are canonical and have issue forms", () => {
  const config = read(".github/ISSUE_TEMPLATE/config.yml");
  assert.match(config, /https:\/\/github\.com\/0xprogrammable\/launch-policy\/security\/advisories\/new/u);
  assert.match(config, /https:\/\/github\.com\/0xprogrammable\/hookbuilder\/issues\/new\/choose/u);
  assert.doesNotMatch(config, /programmable-registry|programmable-v4-builder|hookbuilder\/discussions/u);
  for (const form of ["review-or-registry-bug.yml", "documentation.yml"]) {
    assert.equal(fs.existsSync(path.join(root, ".github/ISSUE_TEMPLATE", form)), true);
  }
});

test("the security policy separates private reports, testing limits, and rewards", () => {
  const security = read("SECURITY.md");
  assert.match(security, /## Report privately/u);
  assert.match(security, /## Responsible testing/u);
  assert.match(security, /## Safe harbor/u);
  assert.match(security, /This is not a standing bug bounty program/u);
});

test("contribution surfaces accept maintenance and preserve historical records", () => {
  const contributing = read("CONTRIBUTING.md");
  const maturity = read("docs/CODE_MATURITY.md");
  const migration = read("docs/MIGRATION.md");
  const template = read(".github/PULL_REQUEST_TEMPLATE.md");
  assert.match(contributing, /GitHub launch intake is closed/u);
  assert.match(contributing, /Repository pull requests are for maintenance only/u);
  assert.match(contributing, /Changes under `submissions\/` or `canary-submissions\/` are rejected/u);
  assert.match(maturity, /checked-in intake state is\s+`closed`/u);
  assert.match(migration, /GitHub intake is retired/u);
  assert.match(migration, /old `0xprogrammable\/submit-launch` name.*historical provenance/su);
  assert.match(template, /Programmable Launch Policy accepts maintenance pull requests only/u);
  assert.match(template, /does not submit a launch, application, template, or Workflow Canary/u);
  assert.doesNotMatch(template, /Generated six-file application package|Hidden workflow-canary application/u);
});

test("public Markdown does not contain a broken relative link", () => {
  const queue = [root];
  const markdown = [];
  while (queue.length > 0) {
    const directory = queue.pop();
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name);
      const relative = path.relative(root, absolute);
      if (entry.isDirectory()) {
        if (![".git", "node_modules", "vendor"].includes(entry.name)) queue.push(absolute);
      } else if (entry.isFile() && relative.endsWith(".md")) {
        markdown.push(relative);
      }
    }
  }

  for (const relative of markdown.sort()) {
    const source = read(relative);
    for (const match of source.matchAll(/!?\[[^\]]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)/gu)) {
      const target = match[1];
      if (/^(?:https?:|mailto:|#)/u.test(target)) continue;
      const pathname = decodeURIComponent(target.split("#", 1)[0]);
      assert.equal(fs.existsSync(path.resolve(root, path.dirname(relative), pathname)), true, `${relative}: ${target}`);
    }
  }
});
