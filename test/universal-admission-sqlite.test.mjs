import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import test, { after } from "node:test";

import { sha256Bytes } from "../vendor/programmable-applicant-validator/scripts/open-world-v2-primitives.mjs";

import {
  DEFAULT_SQLITE_RUNTIME_POLICY,
  UNIVERSAL_ADMISSION_SQLITE_MAX_SNAPSHOT_REFERENCES,
  UniversalAdmissionSqliteStore
} from "../scripts/universal-admission-sqlite-store.mjs";
import {
  DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE,
  buildUniversalAdmissionEventReceipt,
  canonicalProtocolBytes,
  deriveUniversalAdmissionDurableCommandEffectKeys,
  deriveUniversalAdmissionProtocolBindings,
  deriveUniversalAdmissionRevisionBinding,
  digestProtocolValue,
  digestUniversalAdmissionRuntimePolicy
} from "../scripts/universal-admission-protocol-core.mjs";
import {
  admissionBytes,
  commandId,
  principalContext,
  registerUniversalAdmissionStoreConformance,
  requestBinding,
  workerContext,
  workerResult
} from "./helpers/universal-admission-store-conformance.mjs";

const root = path.resolve(".");
const cliPath = path.join(root, "scripts/universal-admission-sqlite.mjs");
const workerPath = path.join(root, "test/helpers/universal-admission-sqlite-worker.mjs");
const resources = [];

registerUniversalAdmissionStoreConformance({
  createStore: (options = {}) => trackedStore({ ...options, nowMs: options.nowMs ?? "1000000" }),
  label: "SQLite reference store"
});

after(() => {
  for (const resource of resources) {
    try { resource.store?.close(); } catch {}
  }
  for (const resource of resources) {
    try { fs.rmSync(resource.directory, { force: true, recursive: true }); } catch {}
  }
});

test("SQLite store persists WAL/FULL state and replays committed requests and commands after restart", async (t) => {
  const directory = privateTemporaryDirectory();
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  const dbPath = path.join(directory, "admission.sqlite");
  const bytes = admissionBytes({ applicationId: "restart-job" });
  const principal = principalContext();
  const request = requestBinding("restart-request");
  const worker = workerContext();

  let store = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  const queued = await store.submit({ bytes, principalContext: principal, ...request });
  const claim = await store.claim({ commandId: "1".repeat(32), workerContext: worker });
  const storage = store.inspectStorage();
  assert.equal(storage.journalMode, "wal");
  assert.equal(storage.synchronous, "2");
  assert.equal(storage.foreignKeys, true);
  assert.equal(storage.defensive, true);
  assert.equal(storage.referenceOnly, true);
  assert.equal(storage.singleHost, true);
  store.close();

  store = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  const replayedSubmit = await store.submit({ bytes, principalContext: principal, ...request });
  const replayedClaim = await store.claim({ commandId: "1".repeat(32), workerContext: worker });
  assert.deepEqual(replayedSubmit, queued);
  assert.equal(digestProtocolValue(withBase64(replayedClaim)), digestProtocolValue(withBase64(claim)));
  assert.deepEqual(replayedClaim.envelopeBytes, claim.envelopeBytes);
  assert.equal(store.readJob(queued.jobId).state, "leased");
  assert.equal(store.assertConsistent(), true);
  store.close();
});

test("SQLite BEGIN IMMEDIATE closes same-request and conflicting-revision races across processes", async (t) => {
  const directory = privateTemporaryDirectory();
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  const dbPath = path.join(directory, "admission.sqlite");
  const bootstrap = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  bootstrap.close();

  const bytes = admissionBytes({ applicationId: "process-replay" });
  const principal = principalContext("tenant-a", "alice");
  const request = requestBinding("process-replay");
  const replayResults = await Promise.all(Array.from({ length: 12 }, () => runWorker({
    bytesBase64: bytes.toString("base64"),
    dbPath,
    nowMs: "1000000",
    operation: "submit",
    policy: DEFAULT_SQLITE_RUNTIME_POLICY,
    principalContext: principal,
    serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE,
    ...request
  })));
  assert.deepEqual(replayResults.map(({ status }) => status), Array(12).fill("QUEUED"));
  assert.equal(new Set(replayResults.map(({ receiptSha256 }) => receiptSha256)).size, 1);

  const left = requestBinding("process-conflict-left");
  const right = requestBinding("process-conflict-right");
  const conflictResults = await Promise.all([
    runWorker({
      bytesBase64: admissionBytes({ applicationId: "process-conflict", projectLabel: "left" }).toString("base64"),
      dbPath,
      nowMs: "1000000",
      operation: "submit",
      policy: DEFAULT_SQLITE_RUNTIME_POLICY,
      principalContext: principal,
      serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE,
      ...left
    }, { allowError: true }),
    runWorker({
      bytesBase64: admissionBytes({ applicationId: "process-conflict", projectLabel: "right" }).toString("base64"),
      dbPath,
      nowMs: "1000000",
      operation: "submit",
      policy: DEFAULT_SQLITE_RUNTIME_POLICY,
      principalContext: principal,
      serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE,
      ...right
    }, { allowError: true })
  ]);
  assert.equal(conflictResults.filter(({ status }) => status === "QUEUED").length, 1);
  assert.equal(conflictResults.filter(({ error }) => error?.code === "UNIVERSAL_ADMISSION_PROTOCOL_REVISION_EQUIVOCATION").length, 1);

  const store = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  assert.equal(store.inspectCounters().global.outstanding, "2");
  assert.equal(store.assertConsistent(), true);
  store.close();
});

test("SQLite constructor retries WAL configuration while another process owns the writer lock", async (t) => {
  const directory = privateTemporaryDirectory();
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  const dbPath = path.join(directory, "admission.sqlite");
  const readyPath = path.join(directory, "constructor-ready");
  const bootstrap = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  bootstrap.close();

  const writer = new DatabaseSync(dbPath, { readBigInts: true, timeout: 0 });
  writer.exec("BEGIN IMMEDIATE");
  try {
    const bytes = admissionBytes({ applicationId: "constructor-lock-retry" });
    const resultPromise = runWorker({
      bytesBase64: bytes.toString("base64"),
      constructorReadyPath: readyPath,
      dbPath,
      nowMs: "1000000",
      operation: "submit",
      policy: DEFAULT_SQLITE_RUNTIME_POLICY,
      principalContext: principalContext(),
      serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE,
      ...requestBinding("constructor-lock-retry")
    });
    await waitForRegularFile(readyPath);
    await new Promise((resolve) => setTimeout(resolve, 350));
    writer.exec("ROLLBACK");
    const result = await resultPromise;
    assert.equal(result.status, "QUEUED");
  } finally {
    try { writer.exec("ROLLBACK"); } catch {}
    writer.close();
  }
});

test("SQLite persists deterministic equivocation rejection and request charge across restart", async (t) => {
  const directory = privateTemporaryDirectory();
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  const dbPath = path.join(directory, "admission.sqlite");
  const principal = principalContext();
  const request = requestBinding("restart-equivocation");
  const original = admissionBytes({ applicationId: "restart-equivocation", projectLabel: "Original" });
  const conflict = admissionBytes({ applicationId: "restart-equivocation", projectLabel: "Conflict" });
  let store = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  await store.submit({ bytes: original, principalContext: principal, ...requestBinding("restart-equivocation-original") });
  await assert.rejects(
    store.submit({ bytes: conflict, principalContext: principal, ...request }),
    hasCode("UNIVERSAL_ADMISSION_PROTOCOL_REVISION_EQUIVOCATION")
  );
  const afterFailure = store.inspectCounters();
  assert.equal(afterFailure.tenants["tenant-a"].authenticatedRequests, "2");
  store.close();

  store = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  await assert.rejects(
    store.submit({ bytes: conflict, principalContext: principal, ...request }),
    hasCode("UNIVERSAL_ADMISSION_PROTOCOL_REVISION_EQUIVOCATION")
  );
  assert.deepEqual(store.inspectCounters(), afterFailure);
  assert.equal(store.assertConsistent(), true);
  store.close();
});

test("SQLite commits authenticated charge and exact error replay when a successful submit response exceeds replay bytes", async (t) => {
  const directory = privateTemporaryDirectory();
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  const policy = {
    ...DEFAULT_SQLITE_RUNTIME_POLICY,
    maxTenantReplayBytes: "512",
    maxTenantReplayRecords: "1"
  };
  const request = requestBinding("response-capacity-rejection", policy);
  const store = new UniversalAdmissionSqliteStore({
    dbPath: path.join(directory, "admission.sqlite"),
    nowMs: "1000000",
    policy,
    serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE
  });
  t.after(() => store.close());
  const submission = {
    bytes: admissionBytes({ applicationId: "response-capacity-rejection" }),
    principalContext: principalContext(),
    ...request
  };
  await assert.rejects(store.submit(submission), hasCode("UNIVERSAL_ADMISSION_PROTOCOL_TENANT_REPLAY_BYTE_CAPACITY"));
  const beforeReplay = store.inspectCounters();
  assert.equal(beforeReplay.durable.commands, "1");
  assert.equal(beforeReplay.global.outstanding, "0");
  assert.equal(beforeReplay.tenants["tenant-a"].authenticatedRequests, "1");
  assert.equal(beforeReplay.tenants["tenant-a"].replayRecords, "1");
  await assert.rejects(store.submit(submission), hasCode("UNIVERSAL_ADMISSION_PROTOCOL_TENANT_REPLAY_BYTE_CAPACITY"));
  assert.deepEqual(store.inspectCounters(), beforeReplay);
  assert.equal(store.assertConsistent(), true);
});

test("SQLite stores the full 31-digit revision as text and rejects 32 digits before storage", async (t) => {
  const directory = privateTemporaryDirectory();
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  const dbPath = path.join(directory, "admission.sqlite");
  const store = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  const principal = principalContext();
  const revision = "9".repeat(31);
  const accepted = await store.submit({
    bytes: admissionBytes({ applicationId: "long-revision", revision }),
    principalContext: principal,
    ...requestBinding("long-revision")
  });
  assert.equal(store.readJob(accepted.jobId).revision, revision);
  const before = store.inspectCounters();
  await assert.rejects(
    store.submit({
      bytes: admissionBytes({ applicationId: "too-long-revision", revision: "9".repeat(32) }),
      principalContext: principal,
      ...requestBinding("too-long-revision")
    })
  );
  assert.deepEqual(store.inspectCounters(), before);
  assert.equal(store.assertConsistent(), true);
  store.close();
});

test("SQLite completion rejects a declared artifact length that differs from durable CAS bytes", async (t) => {
  const directory = privateTemporaryDirectory();
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  const store = new UniversalAdmissionSqliteStore({
    dbPath: path.join(directory, "admission.sqlite"),
    nowMs: "1000000",
    serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE
  });
  t.after(() => store.close());
  const worker = workerContext();
  const submission = await store.submit({
    bytes: admissionBytes({ applicationId: "artifact-size" }),
    principalContext: principalContext(),
    ...requestBinding("artifact-size")
  });
  const claim = await store.claim({ commandId: commandId("artifact-size-claim"), workerContext: worker });
  const report = await store.putObjectIfAbsent({ bytes: Buffer.from("report\n"), mediaType: "public-evidence" });
  const artifact = await store.putObjectIfAbsent({ bytes: Buffer.from("artifact\n"), mediaType: "public-evidence" });
  const result = workerResult({ artifact, claim, report, worker });
  result.artifacts[0].byteLength = String(BigInt(artifact.byteLength) + 1n);
  const before = store.inspectCounters();
  const completionCommandId = commandId("artifact-size-complete");
  await assert.rejects(
    store.complete({ commandId: completionCommandId, jobId: submission.jobId, resultBytes: canonicalProtocolBytes(result), workerContext: worker }),
    hasCode("UNIVERSAL_ADMISSION_PROTOCOL_ARTIFACT_SIZE_MISMATCH")
  );
  const afterFailure = store.inspectCounters();
  assert.equal(BigInt(afterFailure.durable.commands), BigInt(before.durable.commands) + 1n);
  await assert.rejects(
    store.complete({ commandId: completionCommandId, jobId: submission.jobId, resultBytes: canonicalProtocolBytes(result), workerContext: worker }),
    hasCode("UNIVERSAL_ADMISSION_PROTOCOL_ARTIFACT_SIZE_MISMATCH")
  );
  assert.deepEqual(store.inspectCounters(), afterFailure);
  assert.equal(store.readJob(submission.jobId).state, "leased");
  assert.equal(store.assertConsistent(), true);
});

test("SQLite durable completion command replays exactly after restart without a second transition", async (t) => {
  const directory = privateTemporaryDirectory();
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  const dbPath = path.join(directory, "admission.sqlite");
  const worker = workerContext();
  const completionCommandId = "2".repeat(32);
  let store = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  const submission = await store.submit({
    bytes: admissionBytes({ applicationId: "durable-completion" }),
    principalContext: principalContext(),
    ...requestBinding("durable-completion")
  });
  const claim = await store.claim({ commandId: commandId("durable-completion-claim"), workerContext: worker });
  const report = await store.putObjectIfAbsent({ bytes: Buffer.from("report\n"), mediaType: "public-evidence" });
  const artifact = await store.putObjectIfAbsent({ bytes: Buffer.from("artifact\n"), mediaType: "public-evidence" });
  const resultBytes = canonicalProtocolBytes(workerResult({ artifact, claim, report, worker }));
  const completed = await store.complete({ commandId: completionCommandId, jobId: submission.jobId, resultBytes, workerContext: worker });
  const completedJob = store.readJob(submission.jobId);
  store.close();

  store = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  const replayed = await store.complete({ commandId: completionCommandId, jobId: submission.jobId, resultBytes, workerContext: worker });
  assert.deepEqual(replayed, completed);
  assert.deepEqual(store.readJob(submission.jobId), completedJob);
  assert.equal(store.assertConsistent(), true);
  store.close();
});

test("SQLite audit and replay reject same-length durable claim response tampering", async (t) => {
  const directory = privateTemporaryDirectory();
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  const dbPath = path.join(directory, "admission.sqlite");
  const worker = workerContext();
  const claimCommandId = commandId("tampered-durable-claim");
  let store = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  await store.submit({ bytes: admissionBytes({ applicationId: "tampered-durable-claim" }), principalContext: principalContext(), ...requestBinding("tampered-durable-claim") });
  const claimed = await store.claim({ commandId: claimCommandId, workerContext: worker });
  assert.equal(claimed.status, "LEASED");
  store.close();
  mutateDatabase(dbPath, (database) => {
    const row = database.prepare("SELECT response_json FROM durable_commands WHERE command_id = ?").get(claimCommandId);
    const response = JSON.parse(Buffer.from(row.response_json).toString("utf8"));
    response.status = "QUEUED";
    const tampered = canonicalProtocolBytes(response);
    assert.equal(tampered.length, Buffer.from(row.response_json).length);
    database.prepare("UPDATE durable_commands SET response_json = ? WHERE command_id = ?").run(tampered, claimCommandId);
  });
  store = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  assert.throws(() => store.assertConsistent(), hasCode("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION"));
  await assert.rejects(
    store.claim({ commandId: claimCommandId, workerContext: worker }),
    hasCode("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION")
  );
  store.close();
});

test("SQLite durable renew replay cannot be rebound to another same-worker job after a full response/effect rehash", async (t) => {
  const directory = privateTemporaryDirectory();
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  const dbPath = path.join(directory, "admission.sqlite");
  const worker = workerContext("durable-swap-worker", "1");
  const firstRenewCommand = commandId("durable-swap-renew-a");
  const secondRenewCommand = commandId("durable-swap-renew-b");
  let store = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  for (const applicationId of ["durable-swap-a", "durable-swap-b"]) {
    await store.submit({ bytes: admissionBytes({ applicationId }), principalContext: principalContext(), ...requestBinding(applicationId) });
  }
  const firstClaim = await store.claim({ commandId: commandId("durable-swap-claim-a"), workerContext: worker });
  const secondClaim = await store.claim({ commandId: commandId("durable-swap-claim-b"), workerContext: worker });
  await store.renew({
    commandId: firstRenewCommand,
    fenceToken: firstClaim.lease.fenceToken,
    jobId: firstClaim.jobId,
    leaseId: firstClaim.lease.leaseId,
    workerContext: worker
  });
  await store.renew({
    commandId: secondRenewCommand,
    fenceToken: secondClaim.lease.fenceToken,
    jobId: secondClaim.jobId,
    leaseId: secondClaim.lease.leaseId,
    workerContext: worker
  });
  store.close();

  mutateDatabase(dbPath, (database) => {
    const target = database.prepare("SELECT * FROM durable_commands WHERE command_id = ?").get(firstRenewCommand);
    const source = database.prepare("SELECT * FROM durable_commands WHERE command_id = ?").get(secondRenewCommand);
    const requestPreimage = JSON.parse(Buffer.from(target.request_json).toString("utf8"));
    const response = JSON.parse(Buffer.from(source.response_json).toString("utf8"));
    const responseBytes = canonicalProtocolBytes(response);
    const effectKeys = deriveUniversalAdmissionDurableCommandEffectKeys({
      commandKind: "renew",
      requestValue: requestPreimage.request,
      response
    });
    const effectBytes = canonicalProtocolBytes(effectKeys);
    const rebound = {
      ...target,
      effect_keys_sha256: sha256Bytes(effectBytes),
      response_sha256: sha256Bytes(responseBytes)
    };
    const recordBindingSha256 = digestProtocolValue({
      actorKey: rebound.actor_key,
      authenticatedRequestBytes: rebound.authenticated_request_bytes === null ? null : String(rebound.authenticated_request_bytes),
      capacityPolicySha256: digestUniversalAdmissionRuntimePolicy(DEFAULT_SQLITE_RUNTIME_POLICY),
      commandId: rebound.command_id,
      commandKind: rebound.command_kind,
      createdAtMs: String(rebound.created_at_ms),
      effectKeysSha256: rebound.effect_keys_sha256,
      expiresAtMs: String(rebound.expires_at_ms),
      kind: "programmable-universal-admission-sqlite-durable-record-binding",
      outcomeKind: rebound.outcome_kind,
      principalKey: rebound.principal_key,
      requestSha256: rebound.request_sha256,
      responseSha256: rebound.response_sha256,
      serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE,
      tenantId: rebound.tenant_id
    });
    database.prepare(`
      UPDATE durable_commands SET
        response_json = ?, response_sha256 = ?, response_bytes = ?,
        effect_keys_json = ?, effect_keys_sha256 = ?, effect_keys_bytes = ?,
        record_binding_sha256 = ?
      WHERE command_id = ?
    `).run(
      responseBytes, rebound.response_sha256, BigInt(responseBytes.length),
      effectBytes, rebound.effect_keys_sha256, BigInt(effectBytes.length),
      recordBindingSha256, firstRenewCommand
    );
  });

  store = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  assert.throws(() => store.assertConsistent(), hasCode("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION"));
  await assert.rejects(
    store.renew({
      commandId: firstRenewCommand,
      fenceToken: firstClaim.lease.fenceToken,
      jobId: firstClaim.jobId,
      leaseId: firstClaim.lease.leaseId,
      workerContext: worker
    }),
    hasCode("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION")
  );
  store.close();
});

test("SQLite audit rejects durable command expiry extension", async (t) => {
  const directory = privateTemporaryDirectory();
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  const dbPath = path.join(directory, "admission.sqlite");
  const command = commandId("tampered-durable-expiry");
  let store = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  await store.claim({ commandId: command, workerContext: workerContext() });
  store.close();
  mutateDatabase(dbPath, (database) => {
    database.prepare("UPDATE durable_commands SET expires_at_ms = expires_at_ms + 1 WHERE command_id = ?").run(command);
  });
  store = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  assert.throws(() => store.assertConsistent(), hasCode("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION"));
  store.close();
});

test("SQLite durable error replay rejects a fully rehashed code outside the exact command vocabulary", async (t) => {
  const directory = privateTemporaryDirectory();
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  const dbPath = path.join(directory, "admission.sqlite");
  const renewCommand = commandId("durable-error-vocabulary");
  const request = {
    commandId: renewCommand,
    fenceToken: "1",
    jobId: digestProtocolValue({ missing: "durable-error-vocabulary" }),
    leaseId: digestProtocolValue({ lease: "durable-error-vocabulary" }),
    workerContext: workerContext("durable-error-worker", "1")
  };
  let store = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  await assert.rejects(store.renew(request), hasCode("UNIVERSAL_ADMISSION_PROTOCOL_JOB_NOT_FOUND"));
  store.close();

  mutateDatabase(dbPath, (database) => {
    const row = database.prepare("SELECT * FROM durable_commands WHERE command_id = ?").get(renewCommand);
    const forgedFailure = {
      code: "UNIVERSAL_ADMISSION_PROTOCOL_SNAPSHOT_INVALID",
      path: null,
      retryAfterMs: null,
      retryable: false
    };
    const responseBytes = canonicalProtocolBytes(forgedFailure);
    const responseSha256 = sha256Bytes(responseBytes);
    const recordBindingSha256 = digestProtocolValue({
      actorKey: row.actor_key,
      authenticatedRequestBytes: null,
      capacityPolicySha256: digestUniversalAdmissionRuntimePolicy(DEFAULT_SQLITE_RUNTIME_POLICY),
      commandId: row.command_id,
      commandKind: row.command_kind,
      createdAtMs: String(row.created_at_ms),
      effectKeysSha256: row.effect_keys_sha256,
      expiresAtMs: String(row.expires_at_ms),
      kind: "programmable-universal-admission-sqlite-durable-record-binding",
      outcomeKind: row.outcome_kind,
      principalKey: row.principal_key,
      requestSha256: row.request_sha256,
      responseSha256,
      serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE,
      tenantId: null
    });
    const delta = BigInt(responseBytes.length) - row.response_bytes;
    database.prepare(`
      UPDATE durable_commands SET
        response_json = ?, response_sha256 = ?, response_bytes = ?, record_binding_sha256 = ?
      WHERE command_id = ?
    `).run(responseBytes, responseSha256, BigInt(responseBytes.length), recordBindingSha256, renewCommand);
    database.prepare("UPDATE admission_meta SET durable_command_bytes = durable_command_bytes + ? WHERE singleton = 1").run(delta);
  });

  store = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  assert.throws(() => store.assertConsistent(), hasCode("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION"));
  await assert.rejects(store.renew(request), hasCode("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION"));
  store.close();
});

test("SQLite typed durable audit rejects rehashed false submit and GC statuses", async (t) => {
  const directory = privateTemporaryDirectory();
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  const dbPath = path.join(directory, "admission.sqlite");
  const submitRequest = requestBinding("typed-submit-status");
  const gcCommandId = commandId("typed-gc-status");
  let store = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  await store.submit({ bytes: admissionBytes({ applicationId: "typed-submit-status" }), principalContext: principalContext(), ...submitRequest });
  await store.putObjectIfAbsent({ bytes: Buffer.from("typed-gc-orphan\n"), mediaType: "public-evidence" });
  store.advanceTime(DEFAULT_SQLITE_RUNTIME_POLICY.orphanRetentionMs);
  const snapshot = await store.snapshot({ commandId: commandId("typed-gc-snapshot") });
  await store.gc({ commandId: gcCommandId, snapshotSha256: snapshot.snapshotSha256 });
  store.close();
  mutateDatabase(dbPath, (database) => {
    for (const [command, mutate] of [
      [submitRequest.requestId, (response) => { response.status = "DUPLICATE"; }],
      [gcCommandId, (response) => { response.remainingCount = "999"; }]
    ]) {
      const row = database.prepare("SELECT response_json FROM durable_commands WHERE command_id = ?").get(command);
      const response = JSON.parse(Buffer.from(row.response_json).toString("utf8"));
      mutate(response);
      const bytes = canonicalProtocolBytes(response);
      database.prepare(`
        UPDATE durable_commands SET response_json = ?, response_sha256 = ?, response_bytes = ?
        WHERE command_id = ?
      `).run(bytes, sha256Bytes(bytes), BigInt(bytes.length), command);
    }
  });
  store = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  assert.throws(() => store.assertConsistent(), hasCode("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION"));
  store.close();
});

test("SQLite historical jobs tolerate a new generation of an expired shared admission digest", async (t) => {
  const directory = privateTemporaryDirectory();
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  const store = new UniversalAdmissionSqliteStore({
    dbPath: path.join(directory, "admission.sqlite"),
    nowMs: "1000000",
    serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE
  });
  t.after(() => store.close());
  const bytes = admissionBytes({ applicationId: "shared-generation" });
  const first = await store.submit({ bytes, principalContext: principalContext("tenant-a", "alice"), ...requestBinding("shared-generation-a") });
  const worker = workerContext();
  const claim = await store.claim({ commandId: commandId("shared-generation-claim"), workerContext: worker });
  const report = await store.putObjectIfAbsent({ bytes: Buffer.from("shared generation report\n"), mediaType: "public-evidence" });
  const artifact = await store.putObjectIfAbsent({ bytes: Buffer.from("shared generation artifact\n"), mediaType: "public-evidence" });
  await store.complete({
    commandId: commandId("shared-generation-complete"),
    jobId: first.jobId,
    resultBytes: canonicalProtocolBytes(workerResult({ artifact, claim, report, worker })),
    workerContext: worker
  });
  store.advanceTime(DEFAULT_SQLITE_RUNTIME_POLICY.terminalPayloadRetentionMs);
  const snapshot = await store.snapshot({ commandId: commandId("shared-generation-snapshot") });
  await store.gc({ commandId: commandId("shared-generation-gc"), snapshotSha256: snapshot.snapshotSha256 });
  assert.equal(store.readObject(first.admissionDigest), null);
  const second = await store.submit({ bytes, principalContext: principalContext("tenant-b", "bob"), ...requestBinding("shared-generation-b") });
  assert.equal(second.admissionDigest, first.admissionDigest);
  assert.equal(store.assertConsistent(), true);
});

test("SQLite reserves LEASE_EXPIRED for the system reaper and durably replays the rejection", async (t) => {
  const directory = privateTemporaryDirectory();
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  const store = new UniversalAdmissionSqliteStore({
    dbPath: path.join(directory, "admission.sqlite"),
    nowMs: "1000000",
    serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE
  });
  t.after(() => store.close());
  const worker = workerContext();
  const submission = await store.submit({
    bytes: admissionBytes({ applicationId: "reserved-lease-expired" }),
    principalContext: principalContext(),
    ...requestBinding("reserved-lease-expired")
  });
  const claim = await store.claim({ commandId: commandId("reserved-lease-expired-claim"), workerContext: worker });
  const failureCommandId = commandId("reserved-lease-expired-fail");
  const request = {
    commandId: failureCommandId,
    failure: {
      code: "LEASE_EXPIRED",
      detailsSha256: digestProtocolValue({ jobId: claim.jobId, leaseId: claim.lease.leaseId }),
      retryable: true
    },
    fenceToken: claim.lease.fenceToken,
    jobId: claim.jobId,
    leaseId: claim.lease.leaseId,
    workerContext: worker
  };
  await assert.rejects(store.fail(request), hasCode("UNIVERSAL_ADMISSION_PROTOCOL_FAILURE_CODE_RESERVED"));
  const afterFailure = store.inspectCounters();
  await assert.rejects(store.fail(request), hasCode("UNIVERSAL_ADMISSION_PROTOCOL_FAILURE_CODE_RESERVED"));
  assert.deepEqual(store.inspectCounters(), afterFailure);
  assert.equal(store.readJob(submission.jobId).state, "leased");
  assert.equal(store.assertConsistent(), true);
});

test("SQLite persisted GC progress reaches every candidate and exact replay cannot advance twice", async (t) => {
  const directory = privateTemporaryDirectory();
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  const store = new UniversalAdmissionSqliteStore({
    dbPath: path.join(directory, "admission.sqlite"),
    nowMs: "1000000",
    serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE
  });
  t.after(() => store.close());
  const objects = await Promise.all(["orphan-a\n", "orphan-b\n", "orphan-c\n"].map((value) => (
    store.putObjectIfAbsent({ bytes: Buffer.from(value), mediaType: "public-evidence" })
  )));
  store.advanceTime(DEFAULT_SQLITE_RUNTIME_POLICY.orphanRetentionMs);
  const snapshot = await store.snapshot({ commandId: commandId("cursor-snapshot") });
  const firstCommandId = commandId("progress-gc-0");
  const firstBatch = await store.gc({ commandId: firstCommandId, limit: 1, snapshotSha256: snapshot.snapshotSha256 });
  assert.deepEqual(await store.gc({ commandId: firstCommandId, limit: 1, snapshotSha256: snapshot.snapshotSha256 }), firstBatch);
  let deletedCount = Number(firstBatch.deletedCount);
  let done = firstBatch.done;
  let batchIndex = 1;
  do {
    const batch = await store.gc({ commandId: commandId(`progress-gc-${batchIndex}`), limit: 1, snapshotSha256: snapshot.snapshotSha256 });
    deletedCount += Number(batch.deletedCount);
    done = batch.done;
    batchIndex += 1;
  } while (!done);
  assert.equal(deletedCount, objects.length);
  for (const object of objects) assert.equal(store.readObject(object.digest), null);
  assert.equal(store.assertConsistent(), true);
});

test("SQLite GC rejects canonical candidate tampering against the committed snapshot root", async (t) => {
  const directory = privateTemporaryDirectory();
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  const dbPath = path.join(directory, "admission.sqlite");
  let store = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  await store.putObjectIfAbsent({ bytes: Buffer.from("tamper-candidate\n"), mediaType: "public-evidence" });
  store.advanceTime(DEFAULT_SQLITE_RUNTIME_POLICY.orphanRetentionMs);
  const snapshot = await store.snapshot({ commandId: commandId("candidate-tamper-snapshot") });
  store.close();

  mutateDatabase(dbPath, (database) => {
    const row = database.prepare("SELECT candidates_json FROM snapshots WHERE snapshot_sha256 = ?").get(snapshot.snapshotSha256);
    const candidates = JSON.parse(Buffer.from(row.candidates_json).toString("utf8"));
    candidates[0].reason = "terminal-payload";
    database.prepare("UPDATE snapshots SET candidates_json = ? WHERE snapshot_sha256 = ?")
      .run(canonicalProtocolBytes(candidates), snapshot.snapshotSha256);
  });
  store = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  await assert.rejects(
    store.gc({ commandId: commandId("candidate-tamper-gc"), snapshotSha256: snapshot.snapshotSha256 }),
    hasCode("UNIVERSAL_ADMISSION_PROTOCOL_SNAPSHOT_INVALID")
  );
  assert.throws(() => store.assertConsistent(), hasCode("UNIVERSAL_ADMISSION_PROTOCOL_SNAPSHOT_INVALID"));
  store.close();
});

test("SQLite invariant audit rejects same-length CAS corruption", async (t) => {
  const directory = privateTemporaryDirectory();
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  const dbPath = path.join(directory, "admission.sqlite");
  let store = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  const submission = await store.submit({
    bytes: admissionBytes({ applicationId: "cas-corruption" }),
    principalContext: principalContext(),
    ...requestBinding("cas-corruption")
  });
  store.close();
  mutateDatabase(dbPath, (database) => {
    const row = database.prepare("SELECT bytes FROM cas_objects WHERE digest = ?").get(submission.admissionDigest);
    const bytes = Buffer.from(row.bytes);
    bytes[bytes.length - 2] ^= 1;
    database.prepare("UPDATE cas_objects SET bytes = ? WHERE digest = ?").run(bytes, submission.admissionDigest);
  });
  store = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  assert.throws(() => store.assertConsistent(), hasCode("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION"));
  store.close();
});

test("SQLite invariant audit rejects a missing retention-live admission reference", async (t) => {
  const directory = privateTemporaryDirectory();
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  const dbPath = path.join(directory, "admission.sqlite");
  let store = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  const submission = await store.submit({
    bytes: admissionBytes({ applicationId: "missing-admission-ref" }),
    principalContext: principalContext(),
    ...requestBinding("missing-admission-ref")
  });
  store.close();
  mutateDatabase(dbPath, (database) => {
    database.prepare("DELETE FROM object_refs WHERE reference = ?").run(`${submission.jobId}:admission`);
  });
  store = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  assert.throws(() => store.assertConsistent(), hasCode("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION"));
  store.close();
});

test("SQLite invariant audit rejects cross-job first-receipt substitution", async (t) => {
  const directory = privateTemporaryDirectory();
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  const dbPath = path.join(directory, "admission.sqlite");
  let store = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  const left = await store.submit({ bytes: admissionBytes({ applicationId: "receipt-swap-left" }), principalContext: principalContext(), ...requestBinding("receipt-swap-left") });
  const right = await store.submit({ bytes: admissionBytes({ applicationId: "receipt-swap-right" }), principalContext: principalContext(), ...requestBinding("receipt-swap-right") });
  store.close();
  mutateDatabase(dbPath, (database) => {
    database.prepare(`
      UPDATE jobs SET first_receipt_sha256 = CASE job_id WHEN ? THEN ? WHEN ? THEN ? ELSE first_receipt_sha256 END
      WHERE job_id IN (?, ?)
    `).run(left.jobId, right.receiptSha256, right.jobId, left.receiptSha256, left.jobId, right.jobId);
    database.prepare(`
      UPDATE revisions SET first_receipt_sha256 = CASE job_id WHEN ? THEN ? WHEN ? THEN ? ELSE first_receipt_sha256 END
      WHERE job_id IN (?, ?)
    `).run(left.jobId, right.receiptSha256, right.jobId, left.receiptSha256, left.jobId, right.jobId);
  });
  store = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  assert.throws(() => store.assertConsistent(), hasCode("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION"));
  store.close();
});

test("SQLite invariant audit rejects indexed lease expiry drift", async (t) => {
  const directory = privateTemporaryDirectory();
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  const dbPath = path.join(directory, "admission.sqlite");
  let store = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  const submission = await store.submit({ bytes: admissionBytes({ applicationId: "lease-index-drift" }), principalContext: principalContext(), ...requestBinding("lease-index-drift") });
  await store.claim({ commandId: commandId("lease-index-drift-claim"), workerContext: workerContext() });
  store.close();
  mutateDatabase(dbPath, (database) => {
    database.prepare("UPDATE jobs SET lease_expires_at_ms = lease_expires_at_ms + 1 WHERE job_id = ?").run(submission.jobId);
  });
  store = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  assert.throws(() => store.assertConsistent(), hasCode("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION"));
  store.close();
});

test("SQLite invariant audit reconstructs exact tenant fairness ordinals", async (t) => {
  const directory = privateTemporaryDirectory();
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  const dbPath = path.join(directory, "admission.sqlite");
  let store = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  await store.submit({ bytes: admissionBytes({ applicationId: "fair-ledger-a" }), principalContext: principalContext("tenant-a", "alice"), ...requestBinding("fair-ledger-a") });
  await store.submit({ bytes: admissionBytes({ applicationId: "fair-ledger-b" }), principalContext: principalContext("tenant-b", "bob"), ...requestBinding("fair-ledger-b") });
  const first = await store.claim({ commandId: commandId("fair-ledger-claim-a"), workerContext: workerContext() });
  const second = await store.claim({ commandId: commandId("fair-ledger-claim-b"), workerContext: workerContext() });
  assert.deepEqual([first.lease.claimOrdinal, second.lease.claimOrdinal], ["1", "2"]);
  store.close();
  mutateDatabase(dbPath, (database) => {
    database.prepare(`
      UPDATE tenants SET last_claim_ordinal = CASE tenant_id
        WHEN 'tenant-a' THEN 2
        WHEN 'tenant-b' THEN 1
        ELSE last_claim_ordinal
      END
      WHERE tenant_id IN ('tenant-a','tenant-b')
    `).run();
  });
  store = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  assert.throws(() => store.assertConsistent(), hasCode("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION"));
  store.close();
});

test("SQLite invariant audit binds each tenant enqueue ordinal to its exact job receipt", async (t) => {
  const directory = privateTemporaryDirectory();
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  const dbPath = path.join(directory, "admission.sqlite");
  let store = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  const left = await store.submit({ bytes: admissionBytes({ applicationId: "enqueue-ledger-left" }), principalContext: principalContext(), ...requestBinding("enqueue-ledger-left") });
  const right = await store.submit({ bytes: admissionBytes({ applicationId: "enqueue-ledger-right" }), principalContext: principalContext(), ...requestBinding("enqueue-ledger-right") });
  store.close();
  mutateDatabase(dbPath, (database) => {
    database.prepare(`
      UPDATE enqueue_ordinals SET job_id = CASE job_id
        WHEN ? THEN ?
        WHEN ? THEN ?
        ELSE job_id
      END
      WHERE job_id IN (?, ?)
    `).run(left.jobId, right.jobId, right.jobId, left.jobId, left.jobId, right.jobId);
  });
  store = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  assert.throws(() => store.assertConsistent(), hasCode("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION"));
  store.close();
});

test("SQLite snapshot preflight rejects reference fanout before JS materialization", async (t) => {
  const directory = privateTemporaryDirectory();
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  const dbPath = path.join(directory, "admission.sqlite");
  let store = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  const submission = await store.submit({ bytes: admissionBytes({ applicationId: "reference-fanout" }), principalContext: principalContext(), ...requestBinding("reference-fanout") });
  store.close();
  mutateDatabase(dbPath, (database) => {
    database.prepare(`
      WITH digits(d) AS (VALUES (0),(1),(2),(3),(4),(5),(6),(7),(8),(9)),
      sequence(n) AS (
        SELECT a.d + 10*b.d + 100*c.d + 1000*d.d + 10000*e.d + 100000*f.d
        FROM digits a, digits b, digits c, digits d, digits e, digits f
        LIMIT ?
      )
      INSERT INTO object_refs (digest, reference, job_id, purpose)
      SELECT ?, ? || ':fanout:' || printf('%06d', n), ?, 'fanout'
      FROM sequence
    `).run(
      BigInt(UNIVERSAL_ADMISSION_SQLITE_MAX_SNAPSHOT_REFERENCES + 1),
      submission.admissionDigest,
      submission.jobId,
      submission.jobId
    );
  });
  store = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  await assert.rejects(
    store.snapshot({ commandId: commandId("reference-fanout-snapshot") }),
    hasCode("UNIVERSAL_ADMISSION_PROTOCOL_LIMIT_INVALID")
  );
  store.close();
});

test("SQLite public CAS rejects reserved admission bytes without charging admission", async (t) => {
  const directory = privateTemporaryDirectory();
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  const store = new UniversalAdmissionSqliteStore({
    dbPath: path.join(directory, "admission.sqlite"),
    nowMs: "1000000",
    serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE
  });
  t.after(() => store.close());
  const bytes = admissionBytes({ applicationId: "media-type-conflict" });
  const before = store.inspectCounters();
  await assert.rejects(
    store.putObjectIfAbsent({ bytes, mediaType: "public-evidence" }),
    hasCode("UNIVERSAL_ADMISSION_PROTOCOL_CAS_MEDIA_TYPE_CONFLICT")
  );
  assert.deepEqual(store.inspectCounters(), before);
  assert.equal(store.assertConsistent(), true);
});

test("SQLite submission atomically returns and references an initial receipt already present in CAS", async (t) => {
  const directory = privateTemporaryDirectory();
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  const dbPath = path.join(directory, "admission.sqlite");
  const store = new UniversalAdmissionSqliteStore({ dbPath, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE });
  t.after(() => store.close());
  const bytes = admissionBytes({ applicationId: "preseeded-receipt" });
  const principal = principalContext();
  const request = requestBinding("preseeded-receipt");
  const bindings = deriveUniversalAdmissionProtocolBindings({ bytes, principalContext: principal });
  const { revisionBindingSha256 } = deriveUniversalAdmissionRevisionBinding({
    bindings,
    createdAtMs: "1000000",
    creatorPrincipalBindingSha256: bindings.principal.principalBindingSha256
  });
  const eventReceipt = buildUniversalAdmissionEventReceipt({
    capacityPolicySha256: digestUniversalAdmissionRuntimePolicy(DEFAULT_SQLITE_RUNTIME_POLICY),
    eventIndex: "1",
    eventType: "queued",
    failure: null,
    job: {
      admissionDigest: bindings.admissionDigest,
      applicationId: bindings.applicationId,
      attempt: "0",
      availableAtMs: "1000000",
      cycle: "0",
      enqueueOrdinal: "1",
      fenceToken: "0",
      jobId: bindings.jobId,
      revision: bindings.revision,
      revisionBindingSha256,
      revisionKey: bindings.revisionKey,
      tenantId: bindings.tenantId
    },
    lease: null,
    occurredAtMs: "1000000",
    previousReceiptSha256: null,
    principalBindingSha256: bindings.principal.principalBindingSha256,
    idempotencyKey: bindings.idempotencyKey,
    request,
    result: null,
    serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE,
    transition: { from: null, to: "queued" },
    workerBindingSha256: null
  });
  const preseeded = await store.testOnlyPutReservedObjectIfAbsent({
    bytes: canonicalProtocolBytes(eventReceipt),
    mediaType: "universal-admission-event-receipt"
  });
  const queued = await store.submit({ bytes, principalContext: principal, ...request });
  assert.equal(queued.receiptSha256, preseeded.digest);
  assert.deepEqual(queued.eventReceipt, eventReceipt);
  store.close();

  const database = new DatabaseSync(dbPath, { readBigInts: true, readOnly: true });
  try {
    const row = database.prepare(`
      SELECT count(*) AS count FROM object_refs
      WHERE digest = ? AND job_id = ? AND purpose = 'receipt:1'
    `).get(preseeded.digest, queued.jobId);
    assert.equal(row.count, 1n);
  } finally {
    database.close();
  }
});

test("SQLite CLI reports its local reference boundary and FULL/WAL storage state", async (t) => {
  const directory = privateTemporaryDirectory();
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  const requestPath = path.join(directory, "request.json");
  fs.writeFileSync(requestPath, canonicalProtocolBytes({
    store: { serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE }
  }), { mode: 0o600 });
  const response = await runCli([
    path.join(directory, "admission.sqlite"),
    "inspect",
    requestPath
  ]);
  assert.equal(response.ok, true);
  assert.equal(response.referenceOnly, true);
  assert.equal(response.singleHost, true);
  assert.equal(response.result.storage.journalMode, "wal");
  assert.equal(response.result.storage.synchronous, "2");
});

test("SQLite path rejects symbolic links and multiply linked database files", (t) => {
  const directory = privateTemporaryDirectory();
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  const target = path.join(directory, "target.sqlite");
  fs.writeFileSync(target, "", { mode: 0o600 });
  const symlink = path.join(directory, "symlink.sqlite");
  fs.symlinkSync(target, symlink);
  assert.throws(
    () => new UniversalAdmissionSqliteStore({ dbPath: symlink, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE }),
    hasCode("UNIVERSAL_ADMISSION_SQLITE_PATH_INVALID")
  );
  const hardlink = path.join(directory, "hardlink.sqlite");
  fs.linkSync(target, hardlink);
  assert.throws(
    () => new UniversalAdmissionSqliteStore({ dbPath: target, nowMs: "1000000", serviceAudience: DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE }),
    hasCode("UNIVERSAL_ADMISSION_SQLITE_PATH_INVALID")
  );
});

function trackedStore(options) {
  const directory = privateTemporaryDirectory();
  const store = new UniversalAdmissionSqliteStore({
    dbPath: path.join(directory, "admission.sqlite"),
    ...options,
    serviceAudience: options.serviceAudience ?? DEFAULT_UNIVERSAL_ADMISSION_SERVICE_AUDIENCE
  });
  resources.push({ directory, store });
  return store;
}

function privateTemporaryDirectory() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "programmable-admission-sqlite-"));
  fs.chmodSync(directory, 0o700);
  return directory;
}

async function waitForRegularFile(filePath) {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    try {
      if (fs.lstatSync(filePath).isFile()) return;
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error("Timed out waiting for the SQLite constructor race barrier.");
}

function mutateDatabase(dbPath, operation) {
  const database = new DatabaseSync(dbPath, { readBigInts: true });
  try {
    database.exec("PRAGMA foreign_keys=ON");
    database.exec("BEGIN IMMEDIATE");
    operation(database);
    database.exec("COMMIT");
  } catch (error) {
    try { database.exec("ROLLBACK"); } catch {}
    throw error;
  } finally {
    database.close();
  }
}

function runWorker(request, { allowError = false } = {}) {
  const encoded = Buffer.from(JSON.stringify(request), "utf8").toString("base64url");
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [workerPath, encoded], {
      cwd: root,
      stdio: ["ignore", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", (code) => {
      let parsed;
      try { parsed = JSON.parse(stdout); } catch (error) {
        reject(new Error(`SQLite helper emitted invalid JSON (${code}): ${stdout}\n${stderr}`, { cause: error }));
        return;
      }
      if (parsed.error && !allowError) {
        reject(Object.assign(new Error(parsed.error.message), parsed.error));
        return;
      }
      resolve(parsed);
    });
  });
}

function runCli(argumentsList) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cliPath, ...argumentsList], {
      cwd: root,
      stdio: ["ignore", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", (code) => {
      let parsed;
      try { parsed = JSON.parse(stdout); } catch (error) {
        reject(new Error(`SQLite CLI emitted invalid JSON (${code}): ${stdout}\n${stderr}`, { cause: error }));
        return;
      }
      if (code !== 0 || parsed.ok !== true) {
        reject(new Error(`SQLite CLI failed (${code}): ${stdout}\n${stderr}`));
        return;
      }
      resolve(parsed);
    });
  });
}

function withBase64(value) {
  return { ...value, envelopeBytes: Buffer.from(value.envelopeBytes).toString("base64") };
}

function hasCode(code) {
  return (error) => error?.code === code;
}
