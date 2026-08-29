#!/usr/bin/env node

import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import {
  buildCustomLaunchAdmissionBindingV4,
  readCustomLaunchAdmissionDescriptorV4,
  verifyCustomLaunchAdmissionBindingV4
} from "./custom-launch-admission-v4-core.mjs";
import { canonicalJson } from "./launch-policy-core.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

try {
  const arguments_ = process.argv.slice(2);
  let result;
  if (arguments_.length === 1 && arguments_[0] === "--check") {
    const descriptor = readCustomLaunchAdmissionDescriptorV4({ repositoryRoot });
    result = {
      binding: verifyCustomLaunchAdmissionBindingV4({ repositoryRoot }),
      descriptorSha256: descriptor.sha256,
      ok: true
    };
  } else if (arguments_.length === 1 && arguments_[0] === "--print-binding") {
    result = buildCustomLaunchAdmissionBindingV4({ repositoryRoot });
  } else {
    const error = new Error("Usage: node scripts/custom-launch-admission-v4.mjs --check | --print-binding");
    error.code = "CUSTOM_LAUNCH_ADMISSION_V4_USAGE_INVALID";
    throw error;
  }
  process.stdout.write(`${canonicalJson(result)}\n`);
} catch (error) {
  const code = typeof error?.code === "string" ? error.code : "CUSTOM_LAUNCH_ADMISSION_V4_FAILED";
  const message = String(error?.message ?? "Custom Launch V4 admission check failed.").slice(0, 1000);
  process.stderr.write(`${canonicalJson({ error: { code, message }, ok: false })}\n`);
  process.exitCode = 1;
}
