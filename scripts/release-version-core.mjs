import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { TextDecoder } from "node:util";

import { parseBoundedLosslessJson } from "../vendor/programmable-v4-hook-builder/scripts/github-public-source-lossless-json.mjs";

export const RELEASE_VERSION = "1.11.0";

const RELEASED_HISTORY_SHA256 = Object.freeze({
  "1.0.0": "e95c13613e8c921b0fb6c084b0766429859d2492f0e36312cbc47d51228af989",
  "1.1.0": "1787cb2275bb0b11291ac065dd8eafeeb7f882089e258591fc6248bb8079a86d",
  "1.2.0": "196ec4f84c5bb972eee99b10cc9f095718fa6fef130c52e6a068218b06808ed7",
  "1.3.0": "90d6ec973e93e9b2db05e6d56512be5e81e9b2deae5b8287bf60cf648e71baba",
  "1.4.0": "336ab3ce3d1d91f20f2a554386a7e1470d259d4a81c472ec4c8f7b0536ed1373",
  "1.5.0": "a68c86535e4e91b7b3faed33caa1236d78725108c7e260119499f654e2224173",
  "1.6.0": "de6546c66dcd3c007cbd77144ad209a1736e530ad7f5d6ba408d37666ecf07c5",
  "1.6.1": "e7af0786aec04977d6923445e589dafc58b0b2504f039f1370d89118f9c4924a",
  "1.6.2": "b066e089fedc1fbe8b47c1ec55402c24adb336bd997c265a83821ccc69b497b0",
  "1.6.3": "f26206a1f730b75fd948c263814a65708f0cbcfef88219c23d10b4af56dab20b",
  "1.7.0": "f94c4d49770d9116fbe14fc41491bc457510ce34844f220f568e8f5cd5176bac",
  "1.8.0": "3e928370685a0ba1bea2822b4c39d63530d144e2ab0e00200e8085ab94087487",
  "1.9.0": "aaad452ff39c6ef8f70d5a65b6c2dc76930eaf578510808583d99510b09fac46",
  "1.10.0": "dfbb0a23e172f78b5038a3b98483f1d307d49d69e83ea65bccbe9173f208d602",
  "1.11.0": "4c126ee1a79a255b26e66814d0cc5c79e0832decd330a991cbea3ff11665f632"
});

const MAX_JSON_BYTES = 2 * 1024 * 1024;
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });

export class ReleaseVersionError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.name = "ReleaseVersionError";
    this.code = code;
  }
}

export function verifyReleaseVersion({ repositoryRoot }) {
  const root = path.resolve(repositoryRoot);
  const packageManifest = readJson(root, "package.json");
  const packageLock = readJson(root, "package-lock.json");
  const registryConfig = readJson(root, "registry/config.json");

  const projections = [
    ["package.json version", packageManifest.version],
    ["package-lock.json version", packageLock.version],
    ["package-lock.json root package version", packageLock.packages?.[""]?.version],
    ["registry config historyVersion", registryConfig.historyVersion]
  ];
  for (const [label, observed] of projections) {
    if (observed !== RELEASE_VERSION) {
      fail("RELEASE_VERSION_MISMATCH", `${label} must equal the canonical release version ${RELEASE_VERSION}`);
    }
  }

  const historyDirectory = resolveInside(root, "registry/history");
  const releasedVersions = Object.keys(RELEASED_HISTORY_SHA256);
  const newestReleasedVersion = [...releasedVersions].sort(compareSemver).at(-1);
  if (newestReleasedVersion !== RELEASE_VERSION) {
    fail("RELEASE_HISTORY_SET_INVALID", "the canonical release version must be the newest immutable history snapshot");
  }
  const expectedHistoryFiles = releasedVersions.map((version) => `${version}.json`).sort(compareUtf8);
  const observedHistoryFiles = readHistoryFileSet(historyDirectory);
  if (!sameStrings(observedHistoryFiles, expectedHistoryFiles)) {
    fail("RELEASE_HISTORY_SET_INVALID", "registry/history must contain the complete append-only released history set");
  }

  const currentHistory = readJson(root, `registry/history/${RELEASE_VERSION}.json`);
  if (currentHistory.version !== RELEASE_VERSION || currentHistory.generatedAt !== registryConfig.updatedAt) {
    fail("RELEASE_HISTORY_MISMATCH", "current history must bind the canonical release version and registry updatedAt");
  }

  for (const [version, expectedSha256] of Object.entries(RELEASED_HISTORY_SHA256)) {
    const relativePath = `registry/history/${version}.json`;
    const bytes = readRegularFile(resolveInside(root, relativePath), relativePath);
    const observedSha256 = crypto.createHash("sha256").update(bytes).digest("hex");
    if (observedSha256 !== expectedSha256) {
      fail("RELEASE_HISTORY_IMMUTABLE", `${relativePath} does not match its released immutable bytes`);
    }
  }

  return Object.freeze({
    historyFiles: expectedHistoryFiles.length,
    ok: true,
    version: RELEASE_VERSION
  });
}

function readHistoryFileSet(directory) {
  let entries;
  try {
    entries = fs.readdirSync(directory, { withFileTypes: true });
  } catch (error) {
    fail("RELEASE_HISTORY_SET_INVALID", "registry/history is missing or unreadable", error);
  }
  const files = [];
  for (const entry of entries) {
    if (!entry.isFile() || entry.isSymbolicLink() || !/^1\.[0-9]+\.[0-9]+\.json$/u.test(entry.name)) {
      fail("RELEASE_HISTORY_SET_INVALID", "registry/history may contain only released regular JSON snapshots");
    }
    files.push(entry.name);
  }
  return files.sort(compareUtf8);
}

function readJson(root, relativePath) {
  const bytes = readRegularFile(resolveInside(root, relativePath), relativePath);
  let source;
  try {
    source = UTF8_DECODER.decode(bytes);
    parseBoundedLosslessJson(source);
    return JSON.parse(source);
  } catch (error) {
    fail("RELEASE_FILE_INVALID", `${relativePath} must be duplicate-free UTF-8 JSON`, error);
  }
}

function readRegularFile(absolutePath, relativePath) {
  let status;
  try {
    status = fs.lstatSync(absolutePath);
  } catch (error) {
    fail("RELEASE_FILE_INVALID", `${relativePath} is missing`, error);
  }
  if (!status.isFile() || status.isSymbolicLink() || status.size > MAX_JSON_BYTES) {
    fail("RELEASE_FILE_INVALID", `${relativePath} must be a bounded regular file`);
  }
  return fs.readFileSync(absolutePath);
}

function resolveInside(root, relativePath) {
  const target = path.resolve(root, relativePath);
  if (target === root || !target.startsWith(`${root}${path.sep}`)) {
    fail("RELEASE_FILE_INVALID", `${relativePath} escapes the repository root`);
  }
  return target;
}

function sameStrings(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function compareUtf8(left, right) {
  return Buffer.from(left, "utf8").compare(Buffer.from(right, "utf8"));
}

function compareSemver(left, right) {
  const leftParts = left.split(".").map(Number);
  const rightParts = right.split(".").map(Number);
  for (let index = 0; index < 3; index += 1) {
    if (leftParts[index] !== rightParts[index]) return leftParts[index] - rightParts[index];
  }
  return 0;
}

function fail(code, message, cause) {
  throw new ReleaseVersionError(code, message, cause === undefined ? undefined : { cause });
}
