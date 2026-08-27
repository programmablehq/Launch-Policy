import fs from "node:fs";

import { UniversalAdmissionSqliteStore } from "../../scripts/universal-admission-sqlite-store.mjs";

const encoded = process.argv[2];
if (typeof encoded !== "string" || encoded.length > 1024 * 1024) {
  process.stdout.write(`${JSON.stringify({ error: { code: "WORKER_REQUEST_INVALID" } })}\n`);
  process.exitCode = 2;
} else {
  let store;
  try {
    const request = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
    if (request.constructorReadyPath !== undefined) {
      if (typeof request.constructorReadyPath !== "string" || request.constructorReadyPath.length > 4096) {
        throw Object.assign(new Error("Invalid SQLite constructor-ready path."), { code: "WORKER_REQUEST_INVALID" });
      }
      fs.writeFileSync(request.constructorReadyPath, "ready\n", { encoding: "utf8", flag: "wx", mode: 0o600 });
    }
    store = new UniversalAdmissionSqliteStore({
      dbPath: request.dbPath,
      maxCasBytes: request.maxCasBytes ?? "4294967296",
      maxDatabaseBytes: request.maxDatabaseBytes ?? "17179869184",
      nowMs: request.nowMs,
      policy: request.policy,
      serviceAudience: request.serviceAudience
    });
    let result;
    if (request.operation === "submit") {
      result = await store.submit({
        authenticatedRequestByteLength: request.authenticatedRequestByteLength,
        bytes: Buffer.from(request.bytesBase64, "base64"),
        expectedCapacityPolicySha256: request.expectedCapacityPolicySha256,
        principalContext: request.principalContext,
        requestDigest: request.requestDigest,
        requestId: request.requestId
      });
    } else if (request.operation === "claim") {
      result = await store.claim({
        commandId: request.commandId,
        workerContext: request.workerContext
      });
    } else {
      throw Object.assign(new Error("Unsupported SQLite worker operation."), { code: "WORKER_OPERATION_INVALID" });
    }
    process.stdout.write(`${JSON.stringify(encode(result))}\n`);
  } catch (error) {
    process.stdout.write(`${JSON.stringify({
      error: {
        code: error?.code ?? "WORKER_FAILED",
        message: error?.message ?? "Worker failed.",
        retryable: error?.retryable ?? false
      }
    })}\n`);
    process.exitCode = 1;
  } finally {
    if (store) store.close();
  }
}

function encode(value) {
  if (value instanceof Uint8Array) return { $bytesBase64: Buffer.from(value).toString("base64") };
  if (Array.isArray(value)) return value.map(encode);
  if (value !== null && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, encode(child)]));
  return value;
}
