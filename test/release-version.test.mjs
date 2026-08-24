import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  RELEASE_VERSION,
  ReleaseVersionError,
  verifyReleaseVersion
} from "../scripts/release-version-core.mjs";

const root = path.resolve(".");

test("release version is identical across package, lockfile, config, and current history", () => {
  const result = verifyReleaseVersion({ repositoryRoot: root });
  assert.deepEqual(result, {
    historyFiles: 15,
    ok: true,
    version: "1.11.0"
  });
  assert.equal(RELEASE_VERSION, "1.11.0");
});

test("the complete repository verifier invokes the release integrity gate", () => {
  const source = fs.readFileSync(path.join(root, "scripts/verify-repository.mjs"), "utf8");
  assert.match(source, /import \{ ReleaseVersionError, verifyReleaseVersion \} from "\.\/release-version-core\.mjs";/u);
  assert.match(source, /verifyReleaseVersion\(\{ repositoryRoot: root \}\)/u);
  assert.match(source, /"release-version"/u);
});

test("every release version projection fails closed when changed independently", (t) => {
  const cases = [
    ["package.json", (value) => { value.version = "1.11.1"; }, "RELEASE_VERSION_MISMATCH"],
    ["package-lock.json", (value) => { value.version = "1.11.1"; }, "RELEASE_VERSION_MISMATCH"],
    ["package-lock.json", (value) => { value.packages[""].version = "1.11.1"; }, "RELEASE_VERSION_MISMATCH"],
    ["registry/config.json", (value) => { value.historyVersion = "1.11.1"; }, "RELEASE_VERSION_MISMATCH"],
    ["registry/config.json", (value) => { value.updatedAt = "2026-08-21T00:00:01Z"; }, "RELEASE_HISTORY_MISMATCH"],
    ["registry/history/1.11.0.json", (value) => { value.version = "1.11.1"; }, "RELEASE_HISTORY_MISMATCH"],
    ["registry/history/1.11.0.json", (value) => { value.generatedAt = "2026-08-21T00:00:01Z"; }, "RELEASE_HISTORY_MISMATCH"]
  ];

  for (const [relativePath, mutate, code] of cases) {
    const fixture = copyFixture(t);
    const target = path.join(fixture, relativePath);
    const value = JSON.parse(fs.readFileSync(target, "utf8"));
    mutate(value);
    fs.writeFileSync(target, `${JSON.stringify(value)}\n`);
    assert.throws(() => verifyReleaseVersion({ repositoryRoot: fixture }), hasCode(code), relativePath);
  }
});

test("released history snapshots are append-only and byte-immutable", (t) => {
  const mutated = copyFixture(t);
  fs.appendFileSync(path.join(mutated, "registry/history/1.4.0.json"), "\n");
  assert.throws(
    () => verifyReleaseVersion({ repositoryRoot: mutated }),
    hasCode("RELEASE_HISTORY_IMMUTABLE")
  );

  const missing = copyFixture(t);
  fs.unlinkSync(path.join(missing, "registry/history/1.0.0.json"));
  assert.throws(
    () => verifyReleaseVersion({ repositoryRoot: missing }),
    hasCode("RELEASE_HISTORY_SET_INVALID")
  );

  const extra = copyFixture(t);
  fs.writeFileSync(path.join(extra, "registry/history/1.9.1.json"), "{}\n");
  assert.throws(
    () => verifyReleaseVersion({ repositoryRoot: extra }),
    hasCode("RELEASE_HISTORY_SET_INVALID")
  );
});

function copyFixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "submit-launch-release-version-"));
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  fs.cpSync(path.join(root, "package.json"), path.join(directory, "package.json"));
  fs.cpSync(path.join(root, "package-lock.json"), path.join(directory, "package-lock.json"));
  fs.cpSync(path.join(root, "registry"), path.join(directory, "registry"), { recursive: true });
  return directory;
}

function hasCode(code) {
  return (error) => error instanceof ReleaseVersionError && error.code === code;
}
