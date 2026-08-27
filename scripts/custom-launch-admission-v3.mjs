#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { canonicalJson } from "./launch-policy-core.mjs";
import {
  CustomLaunchAdmissionDescriptorError,
  verifyCustomLaunchAdmissionBindingV3,
  verifyCustomLaunchAdmissionProjectionsV3
} from "./custom-launch-admission-v3-core.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

try {
  const args = process.argv.slice(2);
  if (args.length === 0 || (args.length === 1 && args[0] === "--check")) {
    process.stdout.write(`${canonicalJson(verifyCustomLaunchAdmissionBindingV3({ repositoryRoot }))}\n`);
  } else if (args.length === 7 && args[0] === "--check-projections") {
    const paths = parseProjectionArguments(args.slice(1));
    const result = verifyCustomLaunchAdmissionProjectionsV3({
      repositoryRoot,
      wellKnown: readJson(paths.wellKnown),
      capabilities: readJson(paths.capabilities),
      openApi: readJson(paths.openApi)
    });
    process.stdout.write(`${canonicalJson(result)}\n`);
  } else {
    throw new CustomLaunchAdmissionDescriptorError(
      "CUSTOM_LAUNCH_ADMISSION_CLI_USAGE_INVALID",
      "Usage: node scripts/custom-launch-admission-v3.mjs --check | --check-projections --well-known FILE --capabilities FILE --openapi FILE"
    );
  }
} catch (error) {
  const code = error instanceof CustomLaunchAdmissionDescriptorError ? error.code : "CUSTOM_LAUNCH_ADMISSION_CHECK_FAILED";
  const message = String(error?.message ?? "Custom Launch admission check failed.").slice(0, 1000);
  process.stdout.write(`${canonicalJson({ error: { code, message }, ok: false })}\n`);
  process.exitCode = 1;
}

function parseProjectionArguments(args) {
  const result = Object.create(null);
  for (let index = 0; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    const key = flag === "--well-known" ? "wellKnown"
      : flag === "--capabilities" ? "capabilities"
      : flag === "--openapi" ? "openApi"
      : null;
    if (key === null || typeof value !== "string" || Object.hasOwn(result, key)) {
      throw new CustomLaunchAdmissionDescriptorError("CUSTOM_LAUNCH_ADMISSION_CLI_USAGE_INVALID", "Projection arguments are invalid.");
    }
    result[key] = value;
  }
  if (!Object.hasOwn(result, "wellKnown") || !Object.hasOwn(result, "capabilities") || !Object.hasOwn(result, "openApi")) {
    throw new CustomLaunchAdmissionDescriptorError("CUSTOM_LAUNCH_ADMISSION_CLI_USAGE_INVALID", "All three projection files are required.");
  }
  return result;
}

function readJson(candidatePath) {
  const absolute = path.resolve(candidatePath);
  const status = fs.lstatSync(absolute);
  if (!status.isFile() || status.isSymbolicLink() || status.nlink !== 1 || status.size < 2 || status.size > 8 * 1024 * 1024) {
    throw new CustomLaunchAdmissionDescriptorError("CUSTOM_LAUNCH_ADMISSION_PROJECTION_IO", `${candidatePath} must be one bounded regular JSON file.`);
  }
  return JSON.parse(fs.readFileSync(absolute, "utf8"));
}
