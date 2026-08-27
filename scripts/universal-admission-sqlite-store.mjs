import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { types } from "node:util";

import {
  DEFAULT_UNIVERSAL_ADMISSION_RUNTIME_POLICY,
  MAX_UNIVERSAL_ADMISSION_CAS_OBJECT_BYTES,
  MAX_UNIVERSAL_ADMISSION_DURABLE_COMMAND_REQUEST_BYTES,
  MIN_UNIVERSAL_ADMISSION_DURABLE_RESPONSE_RESERVATION_BYTES,
  UNIVERSAL_ADMISSION_PROTOCOL_VERSION,
  UniversalAdmissionProtocolError,
  buildUniversalAdmissionEventReceipt,
  buildUniversalAdmissionSnapshot,
  canonicalProtocolBytes,
  deriveLeaseId,
  derivePrincipalBinding,
  deriveUniversalAdmissionDurableCommandEffectKeys,
  deriveUniversalAdmissionDurableCommandRequestBinding,
  deriveUniversalAdmissionProtocolBindings,
  deriveUniversalAdmissionRequestKey,
  deriveUniversalAdmissionRevisionBinding,
  deriveWorkerBinding,
  deterministicRetryDelayMs,
  digestProtocolValue,
  digestUniversalAdmissionRuntimePolicy,
  isUniversalAdmissionDurableCommandFailureCode,
  parseUniversalAdmissionWorkerResultBytes,
  snapshotLeafDigest,
  snapshotShardDigest,
  validateUniversalAdmissionCommandId,
  validateUniversalAdmissionDurableCommandFailure,
  validateUniversalAdmissionEventReceipt,
  validateUniversalAdmissionFailure,
  validateUniversalAdmissionReceiptChain,
  validateUniversalAdmissionRequestBinding,
  validateUniversalAdmissionRuntimePolicy,
  validateUniversalAdmissionServiceAudience,
  validateUniversalAdmissionSnapshot
} from "./universal-admission-protocol-core.mjs";
import { validateUniversalAdmissionBytes } from "./universal-admission-core.mjs";
import { sha256Bytes } from "../vendor/programmable-applicant-validator/scripts/open-world-v2-primitives.mjs";

export const UNIVERSAL_ADMISSION_SQLITE_SCHEMA_VERSION = 2;
export const UNIVERSAL_ADMISSION_SQLITE_MINIMUM_NODE = Object.freeze({ major: 24, minor: 12 });
export const UNIVERSAL_ADMISSION_SQLITE_MAX_OBJECT_BYTES = MAX_UNIVERSAL_ADMISSION_CAS_OBJECT_BYTES;
export const UNIVERSAL_ADMISSION_SQLITE_MAX_REAPER_BATCH = 1000;
export const UNIVERSAL_ADMISSION_SQLITE_MAX_GC_BATCH = 1000;
export const UNIVERSAL_ADMISSION_SQLITE_MAX_SNAPSHOT_RECORDS = 100_000;
export const UNIVERSAL_ADMISSION_SQLITE_MAX_SNAPSHOT_REFERENCES = 100_000;
export const UNIVERSAL_ADMISSION_SQLITE_MAX_SNAPSHOT_CANDIDATES = 100_000;
export const UNIVERSAL_ADMISSION_SQLITE_MAX_SNAPSHOT_RECORD_BYTES = 64 * 1024 * 1024;
export const UNIVERSAL_ADMISSION_SQLITE_MAX_SNAPSHOT_CANDIDATE_BYTES = 32 * 1024 * 1024;
export const UNIVERSAL_ADMISSION_SQLITE_MAX_SNAPSHOTS = 64;
export const UNIVERSAL_ADMISSION_SQLITE_MAX_AUDIT_ROWS = 500_000;
export const UNIVERSAL_ADMISSION_SQLITE_MAX_AUDIT_BYTES = 128 * 1024 * 1024;
export const UNIVERSAL_ADMISSION_SQLITE_MAX_DURABLE_REQUEST_BYTES = MAX_UNIVERSAL_ADMISSION_DURABLE_COMMAND_REQUEST_BYTES;
export const UNIVERSAL_ADMISSION_SQLITE_MAX_DURABLE_EFFECT_BYTES = 256 * 1024;

export const DEFAULT_SQLITE_RUNTIME_POLICY = DEFAULT_UNIVERSAL_ADMISSION_RUNTIME_POLICY;

const SAFE_MEDIA_TYPES = new Set([
  "public-evidence",
  "universal-admission-envelope",
  "universal-admission-event-receipt",
  "universal-admission-snapshot",
  "universal-admission-worker-result"
]);
const RESERVED_MEDIA_TYPE_BY_KIND = Object.freeze({
  "programmable-universal-admission": "universal-admission-envelope",
  "programmable-universal-admission-event-receipt": "universal-admission-event-receipt",
  "programmable-universal-admission-snapshot": "universal-admission-snapshot",
  "programmable-universal-admission-worker-result": "universal-admission-worker-result"
});
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const COMMAND_ID = /^[0-9a-f]{32}$/u;
const DURABLE_COMMAND_KINDS = new Set(["claim", "complete", "fail", "gc", "reap-expired", "redrive", "renew", "snapshot", "submit"]);
const ACTIVE_STATES = new Set(["queued", "retry-wait", "leased"]);
const TERMINAL_STATES = new Set(["dead-lettered", "processing-completed"]);
const GC_CANDIDATE_REASONS = new Set(["orphan", "terminal-payload"]);
const BUSY_ERRCODE = 5;
const FULL_ERRCODE = 13;
const MAX_BUSY_RETRIES = 8;
const SQLITE_APPLICATION_ID = 1_347_764_529;
const MAX_PROTOCOL_TIMESTAMP = 999_999_999_999_999_999n;
const SLEEP_ARRAY = new Int32Array(new SharedArrayBuffer(4));
const TYPED_ARRAY_PROTOTYPE = Object.getPrototypeOf(Uint8Array.prototype);
const TYPED_ARRAY_BUFFER = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, "buffer").get;
const TYPED_ARRAY_BYTE_LENGTH = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, "byteLength").get;
const TYPED_ARRAY_BYTE_OFFSET = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, "byteOffset").get;

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS admission_meta (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  schema_version INTEGER NOT NULL CHECK (schema_version = 2),
  policy_sha256 TEXT NOT NULL CHECK (length(policy_sha256) = 71),
  policy_json BLOB NOT NULL,
  service_audience TEXT NOT NULL,
  now_ms INTEGER NOT NULL CHECK (now_ms >= 0),
  claim_ordinal INTEGER NOT NULL DEFAULT 0 CHECK (claim_ordinal >= 0),
  global_outstanding INTEGER NOT NULL DEFAULT 0 CHECK (global_outstanding >= 0),
  global_leased INTEGER NOT NULL DEFAULT 0 CHECK (global_leased >= 0),
  durable_command_count INTEGER NOT NULL DEFAULT 0 CHECK (durable_command_count >= 0),
  durable_command_bytes INTEGER NOT NULL DEFAULT 0 CHECK (durable_command_bytes >= 0),
  cas_bytes INTEGER NOT NULL DEFAULT 0 CHECK (cas_bytes >= 0),
  max_cas_bytes INTEGER NOT NULL CHECK (max_cas_bytes > 0),
  max_database_bytes INTEGER NOT NULL CHECK (max_database_bytes > 0),
  snapshot_head TEXT CHECK (snapshot_head IS NULL OR length(snapshot_head) = 71)
) STRICT;

CREATE TABLE IF NOT EXISTS object_generations (
  digest TEXT PRIMARY KEY CHECK (length(digest) = 71),
  generation INTEGER NOT NULL CHECK (generation > 0)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS cas_objects (
  digest TEXT PRIMARY KEY CHECK (length(digest) = 71),
  bytes BLOB NOT NULL,
  byte_length INTEGER NOT NULL CHECK (byte_length BETWEEN 1 AND 262144 AND byte_length = length(bytes)),
  generation INTEGER NOT NULL CHECK (generation > 0),
  media_type TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  FOREIGN KEY (digest) REFERENCES object_generations(digest) ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS tenants (
  tenant_id TEXT PRIMARY KEY,
  last_claim_ordinal INTEGER NOT NULL DEFAULT 0 CHECK (last_claim_ordinal >= 0),
  next_enqueue_ordinal INTEGER NOT NULL DEFAULT 0 CHECK (next_enqueue_ordinal >= 0),
  outstanding INTEGER NOT NULL DEFAULT 0 CHECK (outstanding >= 0),
  leased INTEGER NOT NULL DEFAULT 0 CHECK (leased >= 0 AND leased <= outstanding),
  window_start_ms INTEGER NOT NULL CHECK (window_start_ms >= 0),
  window_jobs INTEGER NOT NULL DEFAULT 0 CHECK (window_jobs >= 0),
  window_bytes INTEGER NOT NULL DEFAULT 0 CHECK (window_bytes >= 0),
  authenticated_request_count INTEGER NOT NULL DEFAULT 0 CHECK (authenticated_request_count >= 0),
  authenticated_request_bytes INTEGER NOT NULL DEFAULT 0 CHECK (authenticated_request_bytes >= 0),
  replay_record_count INTEGER NOT NULL DEFAULT 0 CHECK (replay_record_count >= 0),
  replay_bytes INTEGER NOT NULL DEFAULT 0 CHECK (replay_bytes >= 0)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS applications (
  tenant_id TEXT NOT NULL,
  application_id TEXT NOT NULL,
  outstanding INTEGER NOT NULL DEFAULT 0 CHECK (outstanding >= 0),
  PRIMARY KEY (tenant_id, application_id),
  FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS jobs (
  job_id TEXT PRIMARY KEY CHECK (length(job_id) = 71),
  tenant_id TEXT NOT NULL,
  application_id TEXT NOT NULL,
  revision TEXT NOT NULL,
  revision_key TEXT NOT NULL UNIQUE CHECK (length(revision_key) = 71),
  revision_binding_sha256 TEXT NOT NULL CHECK (length(revision_binding_sha256) = 71),
  admission_digest TEXT NOT NULL CHECK (length(admission_digest) = 71),
  idempotency_key TEXT NOT NULL CHECK (length(idempotency_key) = 71),
  object_generation INTEGER NOT NULL CHECK (object_generation > 0),
  state TEXT NOT NULL CHECK (state IN ('queued','leased','retry-wait','dead-lettered','processing-completed')),
  attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
  cycle INTEGER NOT NULL DEFAULT 0 CHECK (cycle >= 0),
  fence_token INTEGER NOT NULL DEFAULT 0 CHECK (fence_token >= 0),
  redrives INTEGER NOT NULL DEFAULT 0 CHECK (redrives >= 0),
  available_at_ms INTEGER NOT NULL CHECK (available_at_ms >= 0),
  enqueue_ordinal INTEGER NOT NULL CHECK (enqueue_ordinal > 0),
  event_index INTEGER NOT NULL DEFAULT 0 CHECK (event_index >= 0),
  first_receipt_sha256 TEXT CHECK (first_receipt_sha256 IS NULL OR length(first_receipt_sha256) = 71),
  head_receipt_sha256 TEXT CHECK (head_receipt_sha256 IS NULL OR length(head_receipt_sha256) = 71),
  lease_json BLOB,
  lease_expires_at_ms INTEGER CHECK (lease_expires_at_ms IS NULL OR lease_expires_at_ms >= 0),
  result_sha256 TEXT CHECK (result_sha256 IS NULL OR length(result_sha256) = 71),
  terminal_at_ms INTEGER CHECK (terminal_at_ms IS NULL OR terminal_at_ms >= 0),
  CHECK ((state = 'leased' AND lease_json IS NOT NULL AND lease_expires_at_ms IS NOT NULL) OR (state <> 'leased' AND lease_json IS NULL AND lease_expires_at_ms IS NULL)),
  CHECK ((state IN ('dead-lettered','processing-completed') AND terminal_at_ms IS NOT NULL) OR (state NOT IN ('dead-lettered','processing-completed') AND terminal_at_ms IS NULL)),
  FOREIGN KEY (tenant_id, application_id) REFERENCES applications(tenant_id, application_id) ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS jobs_claim_idx
  ON jobs(tenant_id, available_at_ms, enqueue_ordinal, job_id)
  WHERE state IN ('queued','retry-wait');
CREATE INDEX IF NOT EXISTS jobs_ready_idx
  ON jobs(available_at_ms, tenant_id, enqueue_ordinal, job_id)
  WHERE state IN ('queued','retry-wait');
CREATE INDEX IF NOT EXISTS jobs_expiry_idx
  ON jobs(lease_expires_at_ms, job_id)
  WHERE state = 'leased';
CREATE INDEX IF NOT EXISTS jobs_application_state_idx
  ON jobs(tenant_id, application_id, state);

CREATE TABLE IF NOT EXISTS enqueue_charges (
  job_id TEXT NOT NULL,
  cycle INTEGER NOT NULL CHECK (cycle >= 0),
  tenant_id TEXT NOT NULL,
  application_id TEXT NOT NULL,
  charged_at_ms INTEGER NOT NULL CHECK (charged_at_ms >= 0),
  byte_length INTEGER NOT NULL CHECK (byte_length > 0),
  PRIMARY KEY (job_id, cycle),
  FOREIGN KEY (job_id) REFERENCES jobs(job_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, application_id) REFERENCES applications(tenant_id, application_id) ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS enqueue_charges_window_idx
  ON enqueue_charges(tenant_id, charged_at_ms);

CREATE TABLE IF NOT EXISTS revisions (
  revision_key TEXT PRIMARY KEY CHECK (length(revision_key) = 71),
  tenant_id TEXT NOT NULL,
  application_id TEXT NOT NULL,
  revision TEXT NOT NULL,
  admission_digest TEXT NOT NULL CHECK (length(admission_digest) = 71),
  job_id TEXT NOT NULL UNIQUE,
  revision_binding_sha256 TEXT NOT NULL CHECK (length(revision_binding_sha256) = 71),
  creator_principal_binding_sha256 TEXT NOT NULL CHECK (length(creator_principal_binding_sha256) = 71),
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  first_receipt_sha256 TEXT NOT NULL CHECK (length(first_receipt_sha256) = 71),
  binding_json BLOB NOT NULL,
  FOREIGN KEY (job_id) REFERENCES jobs(job_id) ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS protocol_receipts (
  receipt_sha256 TEXT PRIMARY KEY CHECK (length(receipt_sha256) = 71),
  job_id TEXT NOT NULL,
  event_index INTEGER NOT NULL CHECK (event_index > 0),
  receipt_json BLOB NOT NULL,
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  UNIQUE (job_id, event_index),
  FOREIGN KEY (job_id) REFERENCES jobs(job_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  FOREIGN KEY (receipt_sha256) REFERENCES cas_objects(digest) ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS claim_ordinals (
  claim_ordinal INTEGER PRIMARY KEY CHECK (claim_ordinal > 0),
  tenant_id TEXT NOT NULL,
  job_id TEXT NOT NULL,
  receipt_sha256 TEXT NOT NULL UNIQUE CHECK (length(receipt_sha256) = 71),
  claimed_at_ms INTEGER NOT NULL CHECK (claimed_at_ms >= 0),
  FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  FOREIGN KEY (job_id) REFERENCES jobs(job_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  FOREIGN KEY (receipt_sha256) REFERENCES protocol_receipts(receipt_sha256) ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT;
CREATE INDEX IF NOT EXISTS claim_ordinals_tenant_idx ON claim_ordinals(tenant_id, claim_ordinal);

CREATE TABLE IF NOT EXISTS enqueue_ordinals (
  tenant_id TEXT NOT NULL,
  enqueue_ordinal INTEGER NOT NULL CHECK (enqueue_ordinal > 0),
  job_id TEXT NOT NULL,
  cycle INTEGER NOT NULL CHECK (cycle >= 0),
  receipt_sha256 TEXT NOT NULL UNIQUE CHECK (length(receipt_sha256) = 71),
  enqueued_at_ms INTEGER NOT NULL CHECK (enqueued_at_ms >= 0),
  PRIMARY KEY (tenant_id, enqueue_ordinal),
  FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  FOREIGN KEY (job_id) REFERENCES jobs(job_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  FOREIGN KEY (receipt_sha256) REFERENCES protocol_receipts(receipt_sha256) ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS object_refs (
  digest TEXT NOT NULL,
  reference TEXT NOT NULL,
  job_id TEXT,
  purpose TEXT NOT NULL,
  PRIMARY KEY (digest, reference),
  FOREIGN KEY (digest) REFERENCES cas_objects(digest) ON UPDATE RESTRICT ON DELETE CASCADE,
  FOREIGN KEY (job_id) REFERENCES jobs(job_id) ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS object_refs_job_idx ON object_refs(job_id, digest);

CREATE TABLE IF NOT EXISTS completion_bindings (
  job_id TEXT NOT NULL,
  purpose TEXT NOT NULL,
  digest TEXT NOT NULL CHECK (length(digest) = 71),
  descriptor_json BLOB NOT NULL,
  PRIMARY KEY (job_id, purpose),
  FOREIGN KEY (job_id) REFERENCES jobs(job_id) ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS durable_commands (
  actor_key TEXT NOT NULL,
  principal_key TEXT NOT NULL,
  tenant_id TEXT,
  command_id TEXT NOT NULL CHECK (length(command_id) = 32),
  command_kind TEXT NOT NULL,
  request_sha256 TEXT NOT NULL CHECK (length(request_sha256) = 71),
  request_json BLOB NOT NULL,
  request_bytes INTEGER NOT NULL CHECK (request_bytes > 0 AND request_bytes = length(request_json) AND request_bytes <= 65536),
  authenticated_request_bytes INTEGER CHECK (authenticated_request_bytes IS NULL OR authenticated_request_bytes > 0),
  outcome_kind TEXT NOT NULL CHECK (outcome_kind IN ('success','error')),
  response_json BLOB NOT NULL,
  response_sha256 TEXT NOT NULL CHECK (length(response_sha256) = 71),
  response_bytes INTEGER NOT NULL CHECK (response_bytes > 0 AND response_bytes = length(response_json)),
  effect_keys_json BLOB NOT NULL,
  effect_keys_sha256 TEXT NOT NULL CHECK (length(effect_keys_sha256) = 71),
  effect_keys_bytes INTEGER NOT NULL CHECK (effect_keys_bytes > 0 AND effect_keys_bytes = length(effect_keys_json) AND effect_keys_bytes <= 262144),
  record_binding_sha256 TEXT NOT NULL CHECK (length(record_binding_sha256) = 71),
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms > created_at_ms),
  PRIMARY KEY (actor_key, command_id),
  CHECK ((command_kind = 'submit' AND tenant_id IS NOT NULL AND authenticated_request_bytes IS NOT NULL)
    OR (command_kind <> 'submit' AND authenticated_request_bytes IS NULL))
) STRICT, WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS durable_commands_expiry_idx
  ON durable_commands(expires_at_ms, actor_key, command_id);
CREATE INDEX IF NOT EXISTS durable_commands_tenant_idx
  ON durable_commands(tenant_id, expires_at_ms)
  WHERE tenant_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS snapshots (
  snapshot_sha256 TEXT PRIMARY KEY CHECK (length(snapshot_sha256) = 71),
  previous_snapshot_sha256 TEXT CHECK (previous_snapshot_sha256 IS NULL OR length(previous_snapshot_sha256) = 71),
  manifest_json BLOB NOT NULL,
  records_json BLOB NOT NULL,
  candidates_json BLOB NOT NULL,
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  gc_complete INTEGER NOT NULL DEFAULT 0 CHECK (gc_complete IN (0,1)),
  gc_processed_count INTEGER NOT NULL DEFAULT 0 CHECK (gc_processed_count >= 0),
  FOREIGN KEY (snapshot_sha256) REFERENCES cas_objects(digest) ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;
`;

/**
 * Crash-durable, same-host reference implementation of the Universal
 * Admission protocol. SQLite WAL intentionally remains a single-writer,
 * single-host boundary; this class is not distributed queue evidence.
 */
export class UniversalAdmissionSqliteStore {
  constructor({
    dbPath,
    maxCasBytes = "4294967296",
    maxDatabaseBytes = "17179869184",
    nowMs = null,
    policy = DEFAULT_SQLITE_RUNTIME_POLICY,
    serviceAudience
  } = {}) {
    assertSupportedNode();
    this.policy = validateUniversalAdmissionRuntimePolicy(structuredClone(policy));
    this.capacityPolicySha256 = digestUniversalAdmissionRuntimePolicy(this.policy);
    this.serviceAudience = validateServiceAudience(serviceAudience);
    this.wallClock = nowMs === null || nowMs === undefined;
    this.initialized = false;
    this.maximumCasBytes = parseDecimal(maxCasBytes, "maxCasBytes", { positive: true });
    this.maximumDatabaseBytes = parseDecimal(maxDatabaseBytes, "maxDatabaseBytes", { positive: true });
    if (this.maximumDatabaseBytes < this.maximumCasBytes) protocolFail("UNIVERSAL_ADMISSION_SQLITE_POLICY_MISMATCH", "SQLite database byte limit must cover the configured CAS byte limit.");
    this.databasePath = prepareSecureDatabasePath(dbPath);
    this.db = new DatabaseSync(this.databasePath, {
      allowBareNamedParameters: false,
      allowExtension: false,
      allowUnknownNamedParameters: false,
      defensive: true,
      enableDoubleQuotedStringLiterals: false,
      enableForeignKeyConstraints: true,
      readBigInts: true,
      timeout: 250
    });
    try {
      this.db.enableDefensive(true);
      this.#configureDatabase();
      const initialNow = this.wallClock ? BigInt(Date.now()) : parseTimestamp(nowMs, "nowMs");
      assertOperationalClock(initialNow, this.policy);
      this.#initialize(initialNow);
      this.initialized = true;
      fs.chmodSync(this.databasePath, 0o600);
    } catch (error) {
      try { this.db.close(); } catch {}
      throw error;
    }
  }

  close() {
    if (this.db !== null) {
      this.db.close();
      this.db = null;
    }
  }

  setNowMs(value) {
    if (this.wallClock) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_CLOCK_INVALID", "Wall-clock SQLite stores do not accept manual clock mutation.");
    const next = parseTimestamp(value, "nowMs");
    return this.#transaction(() => {
      const current = this.#now();
      if (next < current) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_CLOCK_INVALID", "SQLite protocol clock cannot move backwards.");
      assertOperationalClock(next, this.policy);
      this.#run("UPDATE admission_meta SET now_ms = ? WHERE singleton = 1", next);
      return String(next);
    });
  }

  advanceTime(deltaMs) {
    if (this.wallClock) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_CLOCK_INVALID", "Wall-clock SQLite stores do not accept manual clock mutation.");
    const delta = parseTimestamp(deltaMs, "deltaMs");
    return this.#transaction(() => {
      const next = addTimestamp(this.#now(), delta, "advanced SQLite clock");
      assertOperationalClock(next, this.policy);
      this.#run("UPDATE admission_meta SET now_ms = ? WHERE singleton = 1", next);
      return String(next);
    });
  }

  async putObjectIfAbsent({ bytes, mediaType = "public-evidence" }) {
    if (mediaType !== "public-evidence") protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_RESERVED_MEDIA_FORBIDDEN", "Public SQLite CAS writes accept only public-evidence media.");
    const buffer = validateObjectBytes(bytes, mediaType);
    if (reservedMediaTypeForBytes(buffer) !== null) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_CAS_MEDIA_TYPE_CONFLICT", "Reserved protocol bytes cannot be stored as public evidence.");
    return this.#transaction(() => freeze(this.#putObject(buffer, mediaType)));
  }

  async testOnlyPutReservedObjectIfAbsent({ bytes, mediaType }) {
    if (mediaType === "public-evidence" || !SAFE_MEDIA_TYPES.has(mediaType)) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_RESERVED_MEDIA_FORBIDDEN", "The test-only SQLite writer requires a reserved protocol media type.");
    }
    const buffer = validateObjectBytes(bytes, mediaType);
    validateReservedProtocolObject(buffer, mediaType);
    return this.#transaction(() => freeze(this.#putObject(buffer, mediaType)));
  }

  async submit({ authenticatedRequestByteLength, bytes, expectedCapacityPolicySha256, principalContext, requestDigest, requestId }) {
    const envelopeBytes = snapshotBoundedBytes(bytes, "SQLite admission envelope");
    const bindings = deriveUniversalAdmissionProtocolBindings({ bytes: envelopeBytes, principalContext });
    const request = validateUniversalAdmissionRequestBinding({
      authenticatedRequestByteLength,
      expectedCapacityPolicySha256,
      requestDigest,
      requestId
    });
    const actorKey = deriveUniversalAdmissionRequestKey({ audience: bindings.audience, requestId: request.requestId, tenantId: bindings.tenantId });
    return this.#commandTransaction({
      actorKey,
      authenticatedRequestByteLength: BigInt(request.authenticatedRequestByteLength),
      commandId: request.requestId,
      commandKind: "submit",
      principalKey: bindings.principal.principalBindingSha256,
      principalMismatchCode: "UNIVERSAL_ADMISSION_PROTOCOL_REQUEST_PRINCIPAL_MISMATCH",
      replayConflictCode: "UNIVERSAL_ADMISSION_PROTOCOL_REQUEST_REPLAY_CONFLICT",
      requestValue: request,
      tenantId: bindings.tenantId,
      precondition: () => {
        if (bindings.audience !== this.serviceAudience) {
          protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_AUDIENCE_MISMATCH", "Authenticated principal audience does not match this SQLite queue.");
        }
        if (request.expectedCapacityPolicySha256 !== this.capacityPolicySha256) {
          protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_CAPACITY_POLICY_MISMATCH", "Signed request capacity policy digest does not match this SQLite queue.");
        }
      },
      beforeOperation: () => {
        const now = this.#now();
        this.#ensureTenant(bindings.tenantId, now);
        this.#resetWindow(bindings.tenantId, now);
        this.#assertTenantReplayReservation(bindings.tenantId);
        this.#reserveAuthenticatedRequest({
          byteLength: BigInt(request.authenticatedRequestByteLength),
          tenantId: bindings.tenantId
        });
      }
    }, () => this.#submit(envelopeBytes, bindings, request));
  }

  async claim({ commandId = null, workerContext }) {
    const checkedCommandId = normalizeCommandId(commandId);
    const worker = deriveWorkerBinding(workerContext);
    return this.#commandTransaction({
      actorKey: worker.workerBindingSha256,
      commandId: checkedCommandId,
      commandKind: "claim",
      precondition: () => this.#assertServiceAudience(worker.audience),
      requestValue: { worker }
    }, () => this.#claim(worker));
  }

  async renew({ commandId = null, fenceToken, jobId, leaseId, workerContext }) {
    const checkedCommandId = normalizeCommandId(commandId);
    const checkedFenceToken = normalizeFenceToken(fenceToken);
    const checkedJobId = normalizeDigest(jobId, "jobId");
    const checkedLeaseId = normalizeDigest(leaseId, "leaseId");
    const worker = deriveWorkerBinding(workerContext);
    return this.#commandTransaction({
      actorKey: worker.workerBindingSha256,
      commandId: checkedCommandId,
      commandKind: "renew",
      precondition: () => this.#assertServiceAudience(worker.audience),
      requestValue: { fenceToken: checkedFenceToken, jobId: checkedJobId, leaseId: checkedLeaseId, worker }
    }, () => this.#renew({ fenceToken: checkedFenceToken, jobId: checkedJobId, leaseId: checkedLeaseId, worker }));
  }

  async fail({ commandId = null, failure, fenceToken, jobId, leaseId, workerContext }) {
    const checkedCommandId = normalizeCommandId(commandId);
    const checkedFenceToken = normalizeFenceToken(fenceToken);
    const checkedJobId = normalizeDigest(jobId, "jobId");
    const checkedLeaseId = normalizeDigest(leaseId, "leaseId");
    const worker = deriveWorkerBinding(workerContext);
    const checkedFailure = validateUniversalAdmissionFailure(failure);
    return this.#commandTransaction({
      actorKey: worker.workerBindingSha256,
      commandId: checkedCommandId,
      commandKind: "fail",
      precondition: () => this.#assertServiceAudience(worker.audience),
      requestValue: { failure: checkedFailure, fenceToken: checkedFenceToken, jobId: checkedJobId, leaseId: checkedLeaseId, worker }
    }, () => {
      if (checkedFailure.code === "LEASE_EXPIRED") {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_FAILURE_CODE_RESERVED", "LEASE_EXPIRED is reserved for the authenticated system reaper.");
      }
      const job = this.#job(checkedJobId);
      this.#assertLease(job, {
        fenceToken: checkedFenceToken,
        leaseId: checkedLeaseId,
        workerBindingSha256: worker.workerBindingSha256
      });
      return this.#settleFailure(job, checkedFailure, { allowExpired: false });
    });
  }

  async reapExpired({ commandId = null, limit = 100 } = {}) {
    const checkedCommandId = normalizeCommandId(commandId);
    validateBatchLimit(limit, UNIVERSAL_ADMISSION_SQLITE_MAX_REAPER_BATCH, "Reaper");
    return this.#commandTransaction({
      actorKey: "system:lease-reaper",
      commandId: checkedCommandId,
      commandKind: "reap-expired",
      requestValue: { limit }
    }, () => {
      const now = this.#now();
      const rows = this.#all(`
        SELECT job_id FROM jobs
        WHERE state = 'leased'
          AND lease_expires_at_ms <= ?
        ORDER BY lease_expires_at_ms, job_id
        LIMIT ?
      `, now, BigInt(limit));
      const results = [];
      for (const row of rows) {
        const job = this.#job(row.job_id);
        const failure = validateUniversalAdmissionFailure({
          code: "LEASE_EXPIRED",
          detailsSha256: digestProtocolValue({ jobId: job.jobId, leaseId: job.lease.leaseId }),
          retryable: true
        });
        results.push(this.#settleFailure(job, failure, { allowExpired: true }));
      }
      return freeze({ processed: String(results.length), results });
    });
  }

  async redrive({ commandId = null, expectedReceiptSha256, jobId, principalContext }) {
    const checkedCommandId = normalizeCommandId(commandId);
    const checkedExpectedReceiptSha256 = normalizeDigest(expectedReceiptSha256, "expectedReceiptSha256");
    const checkedJobId = normalizeDigest(jobId, "jobId");
    const principal = derivePrincipalBinding(principalContext);
    return this.#commandTransaction({
      actorKey: principal.principalBindingSha256,
      commandId: checkedCommandId,
      commandKind: "redrive",
      precondition: () => this.#assertServiceAudience(principal.audience),
      requestValue: { expectedReceiptSha256: checkedExpectedReceiptSha256, jobId: checkedJobId, principal },
      tenantId: principal.tenantId,
      beforeOperation: () => {
        const now = this.#now();
        this.#ensureTenant(principal.tenantId, now);
        this.#resetWindow(principal.tenantId, now);
        this.#assertTenantReplayReservation(principal.tenantId);
      }
    }, () => this.#redrive({ expectedReceiptSha256: checkedExpectedReceiptSha256, jobId: checkedJobId, principal }));
  }

  async complete({ commandId = null, jobId, resultBytes, workerContext }) {
    const checkedCommandId = normalizeCommandId(commandId);
    const checkedJobId = normalizeDigest(jobId, "jobId");
    const worker = deriveWorkerBinding(workerContext);
    const boundedResultBytes = snapshotBoundedBytes(resultBytes, "SQLite worker result");
    const result = parseUniversalAdmissionWorkerResultBytes(boundedResultBytes);
    return this.#commandTransaction({
      actorKey: worker.workerBindingSha256,
      commandId: checkedCommandId,
      commandKind: "complete",
      precondition: () => this.#assertServiceAudience(worker.audience),
      requestValue: { jobId: checkedJobId, resultSha256: sha256Bytes(boundedResultBytes), worker }
    }, () => this.#complete({ jobId: checkedJobId, result, resultBytes: boundedResultBytes, worker }));
  }

  async snapshot({ commandId = null } = {}) {
    const checkedCommandId = normalizeCommandId(commandId);
    return this.#commandTransaction({
      actorKey: "system:snapshot",
      commandId: checkedCommandId,
      commandKind: "snapshot",
      requestValue: {}
    }, () => this.#snapshot());
  }

  async gc(input) {
    if (!input || typeof input !== "object" || Array.isArray(input)
      || !Object.hasOwn(input, "commandId")
      || !Object.hasOwn(input, "snapshotSha256")
      || Object.keys(input).some((key) => !new Set(["commandId", "limit", "snapshotSha256"]).has(key))) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_FIELD_SET_INVALID", "GC request fields do not match the closed provider-neutral contract.");
    }
    const { commandId = null, limit = UNIVERSAL_ADMISSION_SQLITE_MAX_GC_BATCH, snapshotSha256 } = input;
    const checkedCommandId = normalizeCommandId(commandId);
    const checkedSnapshotSha256 = normalizeDigest(snapshotSha256, "snapshotSha256");
    validateBatchLimit(limit, UNIVERSAL_ADMISSION_SQLITE_MAX_GC_BATCH, "GC");
    return this.#commandTransaction({
      actorKey: "system:gc",
      commandId: checkedCommandId,
      commandKind: "gc",
      requestValue: { limit, snapshotSha256: checkedSnapshotSha256 }
    }, () => this.#gc({ limit, snapshotSha256: checkedSnapshotSha256 }));
  }

  readJob(jobId) {
    assertDigest(jobId, "jobId");
    const row = this.#get("SELECT * FROM jobs WHERE job_id = ?", jobId);
    return row ? freeze(this.#publicJob(rowToJob(row))) : null;
  }

  readReceipt(receiptSha256) {
    assertDigest(receiptSha256, "receiptSha256");
    const row = this.#get("SELECT receipt_json FROM protocol_receipts WHERE receipt_sha256 = ?", receiptSha256);
    if (!row) return null;
    const receipt = validateUniversalAdmissionEventReceipt(parseCanonicalBlob(row.receipt_json));
    const bytes = canonicalProtocolBytes(receipt);
    const object = this.#verifiedObject(receiptSha256, "universal-admission-event-receipt");
    if (!Buffer.from(row.receipt_json).equals(bytes) || !object.bytes.equals(bytes)) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite receipt row and CAS bytes differ.");
    }
    return freeze(receipt);
  }

  listJobReceipts(jobId) {
    const job = this.#job(jobId);
    const receipts = this.#all(
      "SELECT receipt_sha256 FROM protocol_receipts WHERE job_id = ? ORDER BY event_index",
      job.jobId
    ).map(({ receipt_sha256: receiptSha256 }) => this.readReceipt(receiptSha256));
    return freeze(receipts);
  }

  readObject(digest) {
    assertDigest(digest, "digest");
    const object = this.#verifiedObject(digest);
    return object === null ? null : Buffer.from(object.bytes);
  }

  inspectCounters() {
    const meta = this.#meta();
    const applications = Object.fromEntries(this.#all(
      "SELECT tenant_id, application_id, outstanding FROM applications ORDER BY tenant_id, application_id"
    ).map((row) => [`${row.tenant_id}\u0000${row.application_id}`, String(row.outstanding)]));
    const tenants = Object.fromEntries(this.#all(
      `SELECT tenant_id, leased, outstanding, window_bytes, window_jobs,
        authenticated_request_count, authenticated_request_bytes,
        replay_record_count, replay_bytes
      FROM tenants ORDER BY tenant_id`
    ).map((row) => [row.tenant_id, {
      authenticatedRequestBytes: String(row.authenticated_request_bytes),
      authenticatedRequests: String(row.authenticated_request_count),
      leased: String(row.leased),
      outstanding: String(row.outstanding),
      replayBytes: String(row.replay_bytes),
      replayRecords: String(row.replay_record_count),
      windowBytes: String(row.window_bytes),
      windowJobs: String(row.window_jobs)
    }]));
    return freeze({
      applications,
      durable: { bytes: String(meta.durable_command_bytes), commands: String(meta.durable_command_count) },
      global: { leased: String(meta.global_leased), outstanding: String(meta.global_outstanding) },
      tenants
    });
  }

  inspectStorage() {
    const journal = this.#get("PRAGMA journal_mode");
    const synchronous = this.#get("PRAGMA synchronous");
    const foreignKeys = this.#get("PRAGMA foreign_keys");
    const meta = this.#meta();
    return freeze({
      casBytes: String(meta.cas_bytes),
      databasePath: this.databasePath,
      defensive: true,
      foreignKeys: String(foreignKeys.foreign_keys) === "1",
      journalMode: journal.journal_mode,
      maxCasBytes: String(meta.max_cas_bytes),
      maxDatabaseBytes: String(meta.max_database_bytes),
      nodeVersion: process.version,
      clockMode: this.wallClock ? "wall" : "manual-test",
      referenceOnly: true,
      serviceAudience: meta.service_audience,
      singleHost: true,
      synchronous: String(synchronous.synchronous)
    });
  }

  assertConsistent() {
    return this.#readTransaction(() => this.#assertConsistent());
  }

  #assertConsistent() {
    const auditPreflight = this.#get(`
      SELECT
        (SELECT count(*) FROM object_generations)
        + (SELECT count(*) FROM cas_objects)
        + (SELECT count(*) FROM tenants)
        + (SELECT count(*) FROM applications)
        + (SELECT count(*) FROM jobs)
        + (SELECT count(*) FROM enqueue_charges)
        + (SELECT count(*) FROM revisions)
        + (SELECT count(*) FROM protocol_receipts)
        + (SELECT count(*) FROM claim_ordinals)
        + (SELECT count(*) FROM enqueue_ordinals)
        + (SELECT count(*) FROM object_refs)
        + (SELECT count(*) FROM completion_bindings)
        + (SELECT count(*) FROM durable_commands)
        + (SELECT count(*) FROM snapshots) AS count,
        (SELECT coalesce(sum(length(policy_json)), 0) FROM admission_meta)
        + (SELECT coalesce(sum(byte_length), 0) FROM cas_objects)
        + (SELECT coalesce(sum(length(lease_json)), 0) FROM jobs)
        + (SELECT coalesce(sum(length(binding_json)), 0) FROM revisions)
        + (SELECT coalesce(sum(length(receipt_json)), 0) FROM protocol_receipts)
        + (SELECT coalesce(sum(length(descriptor_json)), 0) FROM completion_bindings)
        + (SELECT coalesce(sum(length(request_json) + length(response_json) + length(effect_keys_json)), 0) FROM durable_commands)
        + (SELECT coalesce(sum(length(manifest_json) + length(records_json) + length(candidates_json)), 0) FROM snapshots)
          AS bytes
    `);
    if (auditPreflight.count > BigInt(UNIVERSAL_ADMISSION_SQLITE_MAX_AUDIT_ROWS)
      || auditPreflight.bytes > BigInt(UNIVERSAL_ADMISSION_SQLITE_MAX_AUDIT_BYTES)) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_LIMIT_INVALID", "SQLite invariant audit row or byte bound is exceeded.");
    }
    const foreign = this.#all("PRAGMA foreign_key_check");
    if (foreign.length > 0) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite foreign-key check failed.");
    const quick = this.#get("PRAGMA quick_check");
    if (!quick || Object.values(quick)[0] !== "ok") protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite quick-check failed.");

    const meta = this.#meta();
    const active = this.#get("SELECT count(*) AS n FROM jobs WHERE state IN ('queued','retry-wait','leased')").n;
    const leased = this.#get("SELECT count(*) AS n FROM jobs WHERE state = 'leased'").n;
    const casBytes = this.#get("SELECT coalesce(sum(byte_length),0) AS n FROM cas_objects").n;
    const durable = this.#get("SELECT count(*) AS count, coalesce(sum(response_bytes),0) AS bytes FROM durable_commands");
    if (active !== meta.global_outstanding || leased !== meta.global_leased || casBytes !== meta.cas_bytes) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite global counters differ from materialized state.");
    }
    if (meta.global_outstanding > BigInt(this.policy.maxGlobalOutstanding)
      || meta.global_leased > BigInt(this.policy.maxGlobalLeased)) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite global queue counters exceed runtime policy.");
    }
    if (durable.count !== meta.durable_command_count || durable.bytes !== meta.durable_command_bytes
      || durable.count > BigInt(this.policy.maxDurableCommands)
      || durable.bytes > BigInt(this.policy.maxDurableCommandBytes)) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable command counters differ from materialized replay state.");
    }
    for (const command of this.#all("SELECT * FROM durable_commands ORDER BY actor_key, command_id")) this.#assertDurableRow(command);
    for (const object of this.#all("SELECT digest, bytes, byte_length, generation, media_type FROM cas_objects ORDER BY digest")) {
      const bytes = Buffer.from(object.bytes);
      const generation = this.#get("SELECT generation FROM object_generations WHERE digest = ?", object.digest);
      if (object.byte_length < 1n
        || object.byte_length > BigInt(UNIVERSAL_ADMISSION_SQLITE_MAX_OBJECT_BYTES)
        || BigInt(bytes.length) !== object.byte_length
        || sha256Bytes(bytes) !== object.digest
        || !SAFE_MEDIA_TYPES.has(object.media_type)
        || generation?.generation !== object.generation) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite CAS content, digest, media type, or generation is inconsistent.");
      }
      const reservedMediaType = reservedMediaTypeForBytes(bytes);
      if (object.media_type === "public-evidence") {
        if (reservedMediaType !== null) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite public evidence aliases reserved protocol bytes.");
      } else {
        if (reservedMediaType !== object.media_type) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite reserved CAS media does not match its canonical object kind.");
        validateReservedProtocolObject(bytes, object.media_type);
      }
    }

    this.#assertRevisionRows();
    if (this.#get("SELECT count(*) AS count FROM object_refs WHERE job_id IS NULL").count !== 0n) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite object references must belong to an exact admission job.");
    }

    for (const tenant of this.#all(`
      SELECT tenant_id, last_claim_ordinal, next_enqueue_ordinal, outstanding, leased,
        window_start_ms, window_jobs, window_bytes,
        authenticated_request_count, authenticated_request_bytes,
        replay_record_count, replay_bytes
      FROM tenants ORDER BY tenant_id
    `)) {
      const counts = this.#get(`
        SELECT
          sum(CASE WHEN state IN ('queued','retry-wait','leased') THEN 1 ELSE 0 END) AS outstanding,
          sum(CASE WHEN state = 'leased' THEN 1 ELSE 0 END) AS leased
        FROM jobs WHERE tenant_id = ?
      `, tenant.tenant_id);
      if ((counts.outstanding ?? 0n) !== tenant.outstanding || (counts.leased ?? 0n) !== tenant.leased) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite tenant counters differ from job state.");
      }
      const replay = this.#get(`
        SELECT count(*) AS count, coalesce(sum(response_bytes),0) AS bytes
        FROM durable_commands WHERE tenant_id = ?
      `, tenant.tenant_id);
      if (replay.count !== tenant.replay_record_count || replay.bytes !== tenant.replay_bytes
        || replay.count > BigInt(this.policy.maxTenantReplayRecords)
        || replay.bytes > BigInt(this.policy.maxTenantReplayBytes)) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite tenant replay counters differ from durable command state.");
      }
      if (tenant.outstanding > BigInt(this.policy.maxTenantOutstanding)
        || tenant.leased > BigInt(this.policy.maxTenantLeased)
        || tenant.window_jobs > BigInt(this.policy.maxTenantNewJobsPerWindow)
        || tenant.window_bytes > BigInt(this.policy.maxTenantNewBytesPerWindow)
        || tenant.authenticated_request_count > BigInt(this.policy.maxTenantAuthenticatedRequestsPerWindow)
        || tenant.authenticated_request_bytes > BigInt(this.policy.maxTenantAuthenticatedRequestBytesPerWindow)
        || tenant.last_claim_ordinal > meta.claim_ordinal) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite tenant quota or fairness counters exceed their closed bounds.");
      }
      if (tenant.window_start_ms === windowStart(meta.now_ms, BigInt(this.policy.fixedWindowMs))) {
        const enqueueWindow = this.#get(`
          SELECT count(*) AS count, coalesce(sum(byte_length),0) AS bytes
          FROM enqueue_charges
          WHERE tenant_id = ? AND charged_at_ms >= ? AND charged_at_ms < ?
        `, tenant.tenant_id, tenant.window_start_ms, tenant.window_start_ms + BigInt(this.policy.fixedWindowMs));
        const requestWindow = this.#get(`
          SELECT count(*) AS count, coalesce(sum(authenticated_request_bytes),0) AS bytes
          FROM durable_commands
          WHERE tenant_id = ? AND command_kind = 'submit'
            AND created_at_ms >= ? AND created_at_ms < ?
        `, tenant.tenant_id, tenant.window_start_ms, tenant.window_start_ms + BigInt(this.policy.fixedWindowMs));
        if (enqueueWindow.count !== tenant.window_jobs || enqueueWindow.bytes !== tenant.window_bytes
          || requestWindow.count !== tenant.authenticated_request_count
          || requestWindow.bytes !== tenant.authenticated_request_bytes) {
          protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite current-window quota counters differ from their durable charge ledgers.");
        }
      }
    }
    for (const application of this.#all("SELECT tenant_id, application_id, outstanding FROM applications")) {
      const count = this.#get(`
        SELECT count(*) AS n FROM jobs
        WHERE tenant_id = ? AND application_id = ? AND state IN ('queued','retry-wait','leased')
      `, application.tenant_id, application.application_id).n;
      if (count !== application.outstanding || count > BigInt(this.policy.maxApplicationOutstanding)) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite application counter differs from job state or runtime policy.");
    }

    let observedClaimEvents = 0n;
    const claimEventsByTenant = new Map();
    const enqueueEventsByTenant = new Map();
    const lastClaimOrdinals = new Set();
    for (const row of this.#all("SELECT * FROM jobs ORDER BY job_id")) {
      const job = rowToJob(row);
      const receipts = this.#all(
        "SELECT receipt_sha256, event_index, receipt_json FROM protocol_receipts WHERE job_id = ? ORDER BY event_index",
        job.jobId
      );
      let previous = null;
      const receiptValues = [];
      for (let index = 0; index < receipts.length; index += 1) {
        const receipt = parseCanonicalBlob(receipts[index].receipt_json);
        validateUniversalAdmissionEventReceipt(receipt);
        if (receipt.eventIndex !== String(index + 1) || receipt.previousReceiptSha256 !== previous) {
          protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite receipt chain is not contiguous.");
        }
        const bytes = canonicalProtocolBytes(receipt);
        if (sha256Bytes(bytes) !== receipts[index].receipt_sha256) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite receipt digest is invalid.");
        const object = this.#get("SELECT bytes FROM cas_objects WHERE digest = ?", receipts[index].receipt_sha256);
        if (!object || !Buffer.from(object.bytes).equals(bytes)) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite receipt CAS bytes differ.");
        previous = receipts[index].receipt_sha256;
        receiptValues.push(receipt);
        if (receipt.eventType === "lease-claimed") {
          observedClaimEvents += 1n;
          claimEventsByTenant.set(job.tenantId, (claimEventsByTenant.get(job.tenantId) ?? 0n) + 1n);
        }
        if (new Set(["queued", "retry-scheduled", "dead-letter-redriven"]).has(receipt.eventType)) {
          const ordinal = BigInt(receipt.job.enqueueOrdinal);
          const state = enqueueEventsByTenant.get(job.tenantId) ?? { maximum: 0n, ordinals: new Set() };
          if (ordinal < 1n || state.ordinals.has(String(ordinal))) {
            protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite tenant enqueue ordinals are duplicated or non-positive across immutable queue events.");
          }
          state.ordinals.add(String(ordinal));
          if (ordinal > state.maximum) state.maximum = ordinal;
          enqueueEventsByTenant.set(job.tenantId, state);
        }
      }
      if (BigInt(receipts.length) !== job.eventIndex || previous !== job.headReceiptSha256) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite job receipt head is inconsistent.");
      }
      if (receiptValues[0]?.idempotencyKey !== job.idempotencyKey) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite job idempotency key differs from its immutable receipt chain.");
      }
      validateUniversalAdmissionReceiptChain(receiptValues, {
        admissionDigest: job.admissionDigest,
        applicationId: job.applicationId,
        attempt: String(job.attempt),
        availableAtMs: String(job.availableAtMs),
        capacityPolicySha256: this.capacityPolicySha256,
        cycle: String(job.cycle),
        enqueueOrdinal: String(job.enqueueOrdinal),
        fenceToken: String(job.fenceToken),
        firstReceiptSha256: job.firstReceiptSha256,
        headReceiptSha256: job.headReceiptSha256,
        idempotencyKey: job.idempotencyKey,
        jobId: job.jobId,
        lease: job.lease,
        redrives: String(job.redrives),
        resultSha256: job.resultSha256,
        revision: job.revision,
        revisionBindingSha256: job.revisionBindingSha256,
        revisionKey: job.revisionKey,
        runtimePolicy: this.policy,
        serviceAudience: this.serviceAudience,
        state: job.state,
        tenantId: job.tenantId,
        terminalAtMs: job.terminalAtMs === null ? null : String(job.terminalAtMs)
      });
      this.#assertJobObjectBindings(row, job, receiptValues);
    }
    if (observedClaimEvents !== meta.claim_ordinal) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite global claim ordinal differs from immutable claim events.");
    }
    for (const tenant of this.#all("SELECT tenant_id, last_claim_ordinal, next_enqueue_ordinal FROM tenants ORDER BY tenant_id")) {
      const tenantClaims = claimEventsByTenant.get(tenant.tenant_id) ?? 0n;
      const ledger = this.#get("SELECT count(*) AS count, max(claim_ordinal) AS latest FROM claim_ordinals WHERE tenant_id = ?", tenant.tenant_id);
      const latestClaimOrdinal = ledger.latest ?? 0n;
      const enqueueState = enqueueEventsByTenant.get(tenant.tenant_id) ?? { maximum: 0n, ordinals: new Set() };
      const enqueueLedger = this.#get("SELECT count(*) AS count, max(enqueue_ordinal) AS latest FROM enqueue_ordinals WHERE tenant_id = ?", tenant.tenant_id);
      if (ledger.count !== tenantClaims
        || tenant.last_claim_ordinal !== latestClaimOrdinal
        || enqueueLedger.count !== BigInt(enqueueState.ordinals.size)
        || (enqueueLedger.latest ?? 0n) !== enqueueState.maximum
        || tenant.next_enqueue_ordinal !== BigInt(enqueueState.ordinals.size)
        || tenant.next_enqueue_ordinal !== enqueueState.maximum
        || (tenant.last_claim_ordinal > 0n && lastClaimOrdinals.has(String(tenant.last_claim_ordinal)))) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite tenant fairness ordinals differ from immutable queue events.");
      }
      if (tenant.last_claim_ordinal > 0n) lastClaimOrdinals.add(String(tenant.last_claim_ordinal));
    }
    const claimLedger = this.#all("SELECT * FROM claim_ordinals ORDER BY claim_ordinal");
    if (BigInt(claimLedger.length) !== meta.claim_ordinal) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable claim ledger length differs from the global fairness ordinal.");
    }
    for (let index = 0; index < claimLedger.length; index += 1) {
      const entry = claimLedger[index];
      const receiptRow = this.#get("SELECT job_id, receipt_json, created_at_ms FROM protocol_receipts WHERE receipt_sha256 = ?", entry.receipt_sha256);
      if (entry.claim_ordinal !== BigInt(index + 1) || !receiptRow) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable claim ledger is not contiguous or references a missing receipt.");
      }
      const receipt = validateUniversalAdmissionEventReceipt(parseCanonicalBlob(receiptRow.receipt_json));
      if (receipt.eventType !== "lease-claimed"
        || receiptRow.job_id !== entry.job_id
        || receipt.job.jobId !== entry.job_id
        || receipt.job.tenantId !== entry.tenant_id
        || receipt.lease.claimOrdinal !== String(entry.claim_ordinal)
        || receipt.occurredAtMs !== String(entry.claimed_at_ms)
        || receiptRow.created_at_ms !== entry.claimed_at_ms
        || sha256Bytes(canonicalProtocolBytes(receipt)) !== entry.receipt_sha256) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable claim ledger differs from its immutable claim receipt identity.");
      }
    }
    for (const entry of this.#all("SELECT * FROM enqueue_ordinals ORDER BY tenant_id, enqueue_ordinal")) {
      const receiptRow = this.#get("SELECT job_id, receipt_json, created_at_ms FROM protocol_receipts WHERE receipt_sha256 = ?", entry.receipt_sha256);
      if (!receiptRow) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable enqueue ledger references a missing receipt.");
      const receipt = validateUniversalAdmissionEventReceipt(parseCanonicalBlob(receiptRow.receipt_json));
      if (!new Set(["queued", "retry-scheduled", "dead-letter-redriven"]).has(receipt.eventType)
        || receiptRow.job_id !== entry.job_id
        || receipt.job.jobId !== entry.job_id
        || receipt.job.tenantId !== entry.tenant_id
        || receipt.job.enqueueOrdinal !== String(entry.enqueue_ordinal)
        || receipt.job.cycle !== String(entry.cycle)
        || receipt.occurredAtMs !== String(entry.enqueued_at_ms)
        || receiptRow.created_at_ms !== entry.enqueued_at_ms
        || sha256Bytes(canonicalProtocolBytes(receipt)) !== entry.receipt_sha256) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable enqueue ledger differs from its immutable queue receipt identity.");
      }
    }
    for (const snapshot of this.#all("SELECT snapshot_sha256 FROM snapshots ORDER BY created_at_ms, snapshot_sha256")) {
      this.#validatedSnapshot(snapshot.snapshot_sha256);
    }
    if (meta.snapshot_head !== null && !this.#get("SELECT 1 AS present FROM snapshots WHERE snapshot_sha256 = ?", meta.snapshot_head)) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite snapshot head is not retained locally.");
    }
    return true;
  }

  #assertDurableRow(command) {
    try {
      if (!DURABLE_COMMAND_KINDS.has(command.command_kind)
        || !COMMAND_ID.test(command.command_id)
        || !DIGEST.test(command.request_sha256)
        || !DIGEST.test(command.response_sha256)
        || !DIGEST.test(command.effect_keys_sha256)
        || !DIGEST.test(command.record_binding_sha256)
        || typeof command.actor_key !== "string"
        || typeof command.principal_key !== "string"
        || command.expires_at_ms !== addTimestamp(command.created_at_ms, BigInt(this.policy.commandReplayRetentionMs), "durable command audit expiry")) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable command identity, kind, or exact replay expiry is invalid.");
      }
      parseTimestamp(String(command.created_at_ms), "durable command createdAtMs");
      parseTimestamp(String(command.expires_at_ms), "durable command expiresAtMs");

      const storedPreimage = parseCanonicalBlob(command.request_json);
      const requestBytes = canonicalProtocolBytes(storedPreimage);
      if (!Buffer.from(command.request_json).equals(requestBytes)
        || BigInt(requestBytes.length) !== command.request_bytes
        || requestBytes.length > UNIVERSAL_ADMISSION_SQLITE_MAX_DURABLE_REQUEST_BYTES) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable command request preimage bytes are inconsistent or unbounded.");
      }
      const requestBinding = deriveUniversalAdmissionDurableCommandRequestBinding({
        actorKey: command.actor_key,
        commandId: command.command_id,
        commandKind: command.command_kind,
        requestValue: storedPreimage.request,
        serviceAudience: this.serviceAudience
      });
      if (!requestBytes.equals(canonicalProtocolBytes(requestBinding.requestPreimage))
        || requestBinding.requestSha256 !== command.request_sha256) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable command request preimage differs from its exact actor, id, kind, or digest.");
      }
      const request = requestBinding.requestValue;
      this.#assertDurableRequest(command, request);

      const storedOutcome = parseCanonicalBlob(command.response_json);
      const responseBytes = canonicalProtocolBytes(storedOutcome);
      if (!Buffer.from(command.response_json).equals(responseBytes)
        || BigInt(responseBytes.length) !== command.response_bytes
        || sha256Bytes(responseBytes) !== command.response_sha256) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable command response bytes or digest are inconsistent.");
      }
      const response = command.outcome_kind === "success" ? decodeResponse(storedOutcome) : null;
      if (!new Set(["error", "success"]).has(command.outcome_kind)) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable command outcome kind is invalid.");
      }
      const expectedEffectKeys = command.outcome_kind === "success"
        ? deriveUniversalAdmissionDurableCommandEffectKeys({ commandKind: command.command_kind, requestValue: request, response })
        : emptyDurableEffectKeys();
      const storedEffectKeys = parseCanonicalBlob(command.effect_keys_json);
      const effectBytes = canonicalProtocolBytes(storedEffectKeys);
      if (!Buffer.from(command.effect_keys_json).equals(effectBytes)
        || BigInt(effectBytes.length) !== command.effect_keys_bytes
        || effectBytes.length > UNIVERSAL_ADMISSION_SQLITE_MAX_DURABLE_EFFECT_BYTES
        || sha256Bytes(effectBytes) !== command.effect_keys_sha256
        || !effectBytes.equals(canonicalProtocolBytes(expectedEffectKeys))) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable command effect keys differ from its exact request and outcome.");
      }
      if (command.record_binding_sha256 !== this.#durableRecordBindingSha256(command)) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable command row binding differs from its immutable request, outcome, and retention fields.");
      }
      if (command.outcome_kind === "error") {
        validateUniversalAdmissionDurableCommandFailure({ commandKind: command.command_kind, failure: storedOutcome });
        decodeProtocolError(storedOutcome);
        return;
      }
      this.#assertDurableSuccess(command, response, request);
    } catch (cause) {
      if (cause instanceof UniversalAdmissionProtocolError
        && cause.code === "UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION") throw cause;
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable command replay row is not self-consistent.", { cause });
    }
  }

  #assertDurableRequest(command, request) {
    const systemActor = {
      gc: "system:gc",
      "reap-expired": "system:lease-reaper",
      snapshot: "system:snapshot"
    }[command.command_kind] ?? null;
    if (systemActor !== null) {
      if (command.actor_key !== systemActor || command.principal_key !== systemActor || command.tenant_id !== null) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite system durable command actor binding is invalid.");
      }
    } else if (command.command_kind === "submit") {
      const checked = validateUniversalAdmissionRequestBinding(request);
      if (command.tenant_id === null
        || command.actor_key !== deriveUniversalAdmissionRequestKey({ audience: this.serviceAudience, requestId: command.command_id, tenantId: command.tenant_id })
        || command.command_id !== checked.requestId
        || command.authenticated_request_bytes !== BigInt(checked.authenticatedRequestByteLength)
        || checked.expectedCapacityPolicySha256 !== this.capacityPolicySha256
        || !DIGEST.test(command.principal_key)) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite submit durable request actor, policy, or authenticated ingress binding is invalid.");
      }
      return;
    } else if (command.command_kind === "redrive") {
      if (command.tenant_id === null || command.actor_key !== command.principal_key || !DIGEST.test(command.actor_key)
        || !isExactObject(request, ["expectedReceiptSha256", "jobId", "principal"])
        || !isExactObject(request.principal, ["audience", "authorityId", "principalBindingSha256", "tenantId"])
        || request.principal.audience !== this.serviceAudience
        || request.principal.principalBindingSha256 !== command.actor_key
        || request.principal.tenantId !== command.tenant_id) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite redrive durable request principal binding is invalid.");
      }
      assertDigest(request.expectedReceiptSha256, "durable redrive expected receipt");
      assertDigest(request.jobId, "durable redrive job");
      return;
    } else if (command.tenant_id !== null || command.actor_key !== command.principal_key || !DIGEST.test(command.actor_key)) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite worker durable command actor binding is invalid.");
    }

    if (command.command_kind === "snapshot") {
      if (!isExactObject(request, [])) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite snapshot durable request is not empty.");
      return;
    }
    if (command.command_kind === "reap-expired") {
      if (!isExactObject(request, ["limit"])) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite reaper durable request has an invalid field set.");
      validateBatchLimit(request.limit, UNIVERSAL_ADMISSION_SQLITE_MAX_REAPER_BATCH, "Durable reaper");
      return;
    }
    if (command.command_kind === "gc") {
      if (!isExactObject(request, ["limit", "snapshotSha256"])) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite GC durable request has an invalid field set.");
      validateBatchLimit(request.limit, UNIVERSAL_ADMISSION_SQLITE_MAX_GC_BATCH, "Durable GC");
      assertDigest(request.snapshotSha256, "durable GC snapshot");
      return;
    }

    const requestFields = {
      claim: ["worker"],
      complete: ["jobId", "resultSha256", "worker"],
      fail: ["failure", "fenceToken", "jobId", "leaseId", "worker"],
      renew: ["fenceToken", "jobId", "leaseId", "worker"]
    }[command.command_kind];
    if (!requestFields || !isExactObject(request, requestFields)
      || !isExactObject(request.worker, ["audience", "authorityId", "implementationSha256", "workerBindingSha256", "workerId"])
      || request.worker.audience !== this.serviceAudience
      || request.worker.workerBindingSha256 !== command.actor_key) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite worker durable request has an invalid closed actor binding.");
    }
    const worker = deriveWorkerBinding({
      authenticated: true,
      audience: request.worker.audience,
      authorityId: request.worker.authorityId,
      implementationSha256: request.worker.implementationSha256,
      kind: "programmable-authenticated-worker-context",
      schemaVersion: UNIVERSAL_ADMISSION_PROTOCOL_VERSION,
      workerId: request.worker.workerId
    });
    if (worker.workerBindingSha256 !== command.actor_key) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable request worker binding cannot be re-derived.");
    }
    if (command.command_kind !== "claim") {
      assertDigest(request.jobId, "durable worker job");
    }
    if (new Set(["fail", "renew"]).has(command.command_kind)) {
      assertDigest(request.leaseId, "durable worker lease");
      parseDecimal(request.fenceToken, "durable worker fenceToken", { positive: true });
    }
    if (command.command_kind === "fail") validateUniversalAdmissionFailure(request.failure);
    if (command.command_kind === "complete") assertDigest(request.resultSha256, "durable worker result");
  }

  #durableRecordBindingSha256(command) {
    return digestProtocolValue({
      actorKey: command.actor_key,
      authenticatedRequestBytes: command.authenticated_request_bytes === null ? null : String(command.authenticated_request_bytes),
      capacityPolicySha256: this.capacityPolicySha256,
      commandId: command.command_id,
      commandKind: command.command_kind,
      createdAtMs: String(command.created_at_ms),
      effectKeysSha256: command.effect_keys_sha256,
      expiresAtMs: String(command.expires_at_ms),
      kind: "programmable-universal-admission-sqlite-durable-record-binding",
      outcomeKind: command.outcome_kind,
      principalKey: command.principal_key,
      requestSha256: command.request_sha256,
      responseSha256: command.response_sha256,
      serviceAudience: this.serviceAudience,
      tenantId: command.tenant_id
    });
  }

  #assertDurableSuccess(command, response, request) {
    if (command.command_kind === "submit") {
      if (!isExactObject(response, ["admissionDigest", "authority", "eventReceipt", "idempotencyKey", "jobId", "principalBindingSha256", "receiptSha256", "requestDigest", "requestId", "revisionBindingSha256", "revisionKey", "status", "tenantId"])
        || !new Set(["DUPLICATE", "QUEUED"]).has(response.status)
        || response.requestId !== command.command_id
        || response.requestDigest !== request.requestDigest
        || response.tenantId !== command.tenant_id
        || response.principalBindingSha256 !== command.principal_key
        || digestProtocolValue(response.authority) !== digestProtocolValue(authorityFalse())) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable submit response has an invalid closed identity.");
      }
      const receipt = this.#durableReceipt(response.receiptSha256, response.jobId, ["queued"]);
      if (sha256Bytes(canonicalProtocolBytes(response.eventReceipt)) !== response.receiptSha256
        || digestProtocolValue(response.eventReceipt) !== digestProtocolValue(receipt)
        || receipt.job.admissionDigest !== response.admissionDigest
        || receipt.job.tenantId !== response.tenantId
        || receipt.job.revisionBindingSha256 !== response.revisionBindingSha256
        || receipt.job.revisionKey !== response.revisionKey
        || receipt.idempotencyKey !== response.idempotencyKey) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable submit response differs from its immutable initial receipt.");
      }
      const isInitialRequest = receipt.request.requestId === response.requestId
        && receipt.request.requestDigest === response.requestDigest
        && receipt.request.authenticatedRequestByteLength === String(command.authenticated_request_bytes)
        && receipt.principalBindingSha256 === response.principalBindingSha256;
      if ((response.status === "QUEUED") !== isInitialRequest) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable submit status does not distinguish the exact initial request from a separately authenticated duplicate.");
      }
      return;
    }
    if (command.command_kind === "claim") {
      if (isExactObject(response, ["reason", "status"]) && response.status === "NO_WORK"
        && new Set(["GLOBAL_LEASE_CAPACITY", "NO_ELIGIBLE_JOB"]).has(response.reason)) return;
      if (!isExactObject(response, ["admissionDigest", "envelopeBytes", "jobId", "lease", "receiptSha256", "revisionBindingSha256", "revisionKey", "status"])
        || response.status !== "LEASED" || !(response.envelopeBytes instanceof Uint8Array)
        || sha256Bytes(response.envelopeBytes) !== response.admissionDigest) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable claim response has an invalid closed payload.");
      }
      const receipt = this.#durableReceipt(response.receiptSha256, response.jobId, ["lease-claimed"]);
      if (receipt.workerBindingSha256 !== command.actor_key
        || digestProtocolValue(receipt.lease) !== digestProtocolValue(response.lease)
        || receipt.job.admissionDigest !== response.admissionDigest
        || receipt.job.revisionBindingSha256 !== response.revisionBindingSha256
        || receipt.job.revisionKey !== response.revisionKey) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable claim response differs from its immutable lease receipt.");
      }
      return;
    }
    if (command.command_kind === "renew") {
      if (!isExactObject(response, ["lease", "receiptSha256", "status"]) || response.status !== "LEASED") {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable renewal response has an invalid closed shape.");
      }
      const receipt = this.#durableReceipt(response.receiptSha256, request.jobId, ["lease-renewed"]);
      if (receipt.workerBindingSha256 !== command.actor_key
        || receipt.lease.leaseId !== request.leaseId
        || receipt.lease.fenceToken !== request.fenceToken
        || digestProtocolValue(receipt.lease) !== digestProtocolValue(response.lease)) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable renewal response differs from its immutable receipt.");
      }
      return;
    }
    if (command.command_kind === "fail") {
      const receipt = this.#assertDurableFailureResponse(response, command.actor_key, request.jobId);
      if (response.jobId !== request.jobId
        || receipt.lease.leaseId !== request.leaseId
        || receipt.lease.fenceToken !== request.fenceToken
        || digestProtocolValue(receipt.failure) !== digestProtocolValue(request.failure)
        || receipt.failure.code === "LEASE_EXPIRED") {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite public failure command response uses the system-reserved lease expiry code.");
      }
      return;
    }
    if (command.command_kind === "reap-expired") {
      if (!isExactObject(response, ["processed", "results"]) || !Array.isArray(response.results)
        || parseDecimal(response.processed, "durable reaper processed") !== BigInt(response.results.length)
        || response.results.length > request.limit) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable reaper response has an invalid closed batch.");
      }
      const receiptDigests = new Set();
      const jobIds = new Set();
      for (const result of response.results) {
        const receipt = this.#assertDurableFailureResponse(result, null);
        if (receipt.failure.code !== "LEASE_EXPIRED"
          || receipt.failure.retryable !== true
          || receipt.failure.detailsSha256 !== digestProtocolValue({ jobId: receipt.job.jobId, leaseId: receipt.lease.leaseId })
          || receiptDigests.has(result.receiptSha256)
          || jobIds.has(result.jobId)) {
          protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable reaper response does not contain unique system lease-expiry settlements.");
        }
        receiptDigests.add(result.receiptSha256);
        jobIds.add(result.jobId);
      }
      return;
    }
    if (command.command_kind === "redrive") {
      if (!isExactObject(response, ["jobId", "receiptSha256", "status"])
        || response.status !== "QUEUED" || response.jobId !== request.jobId) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable redrive response has an invalid closed shape.");
      }
      const receipt = this.#durableReceipt(response.receiptSha256, request.jobId, ["dead-letter-redriven"]);
      if (receipt.principalBindingSha256 !== command.principal_key
        || receipt.previousReceiptSha256 !== request.expectedReceiptSha256
        || receipt.job.tenantId !== command.tenant_id) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable redrive response differs from its immutable applicant receipt.");
      }
      return;
    }
    if (command.command_kind === "complete") {
      if (!isExactObject(response, ["jobId", "receiptSha256", "resultSha256", "status"])
        || response.status !== "PROCESSING_COMPLETED"
        || response.jobId !== request.jobId
        || response.resultSha256 !== request.resultSha256) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable completion response has an invalid closed shape.");
      }
      const receipt = this.#durableReceipt(response.receiptSha256, request.jobId, ["processing-completed"]);
      if (receipt.workerBindingSha256 !== command.actor_key || receipt.result.resultSha256 !== response.resultSha256) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable completion response differs from its immutable terminal receipt.");
      }
      return;
    }
    if (command.command_kind === "snapshot") {
      if (!isExactObject(response, ["manifest", "snapshotSha256"])) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable snapshot response has an invalid closed shape.");
      }
      const manifest = validateUniversalAdmissionSnapshot(response.manifest);
      const row = this.#get("SELECT manifest_json FROM snapshots WHERE snapshot_sha256 = ?", response.snapshotSha256);
      if (!row || sha256Bytes(canonicalProtocolBytes(manifest)) !== response.snapshotSha256
        || !Buffer.from(row.manifest_json).equals(canonicalProtocolBytes(manifest))) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable snapshot response differs from its retained immutable manifest.");
      }
      return;
    }
    if (command.command_kind === "gc") {
      if (!isExactObject(response, ["deletedCount", "done", "remainingCount", "snapshotSha256"])
        || typeof response.done !== "boolean"
        || response.snapshotSha256 !== request.snapshotSha256
        || !this.#get("SELECT 1 AS present FROM snapshots WHERE snapshot_sha256 = ?", response.snapshotSha256)) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable GC response has an invalid closed snapshot binding.");
      }
      const deletedCount = parseDecimal(response.deletedCount, "durable GC deletedCount");
      const remainingCount = parseDecimal(response.remainingCount, "durable GC remainingCount");
      const snapshot = this.#get("SELECT manifest_json, gc_complete FROM snapshots WHERE snapshot_sha256 = ?", response.snapshotSha256);
      const candidateCount = BigInt(validateUniversalAdmissionSnapshot(parseCanonicalBlob(snapshot.manifest_json)).totals.gcCandidates);
      if ((response.done !== (remainingCount === 0n))
        || deletedCount > BigInt(request.limit)
        || deletedCount > candidateCount
        || remainingCount > candidateCount
        || (response.done && snapshot.gc_complete !== 1n)) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable GC response counts contradict its retained immutable snapshot bounds.");
      }
      return;
    }
    protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable success response command kind is unsupported.");
  }

  #assertDurableFailureResponse(response, workerBindingSha256, expectedJobId = null) {
    const retry = isExactObject(response, ["availableAtMs", "jobId", "receiptSha256", "status"]) && response.status === "RETRY_WAIT";
    const dead = isExactObject(response, ["jobId", "receiptSha256", "status"]) && response.status === "DEAD_LETTERED";
    if (!retry && !dead) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable failure response has an invalid closed shape.");
    const receipt = this.#durableReceipt(response.receiptSha256, expectedJobId ?? response.jobId, [retry ? "retry-scheduled" : "dead-lettered"]);
    if ((workerBindingSha256 !== null && receipt.workerBindingSha256 !== workerBindingSha256)
      || (retry && receipt.job.availableAtMs !== response.availableAtMs)) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable failure response differs from its immutable settlement receipt.");
    }
    return receipt;
  }

  #durableReceipt(receiptSha256, jobId, eventTypes) {
    assertDigest(receiptSha256, "durable response receipt digest");
    const row = this.#get("SELECT job_id, receipt_json FROM protocol_receipts WHERE receipt_sha256 = ?", receiptSha256);
    if (!row || (jobId !== null && row.job_id !== jobId)) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable response references a missing or different job receipt.");
    }
    const receipt = validateUniversalAdmissionEventReceipt(parseCanonicalBlob(row.receipt_json));
    const object = this.#verifiedObject(receiptSha256, "universal-admission-event-receipt");
    if (!object || !eventTypes.includes(receipt.eventType)
      || sha256Bytes(canonicalProtocolBytes(receipt)) !== receiptSha256
      || !object.bytes.equals(canonicalProtocolBytes(receipt))) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable response receipt type or immutable bytes are invalid.");
    }
    return receipt;
  }

  #assertRevisionRows() {
    const counts = this.#get(`
      SELECT
        (SELECT count(*) FROM revisions) AS revisions,
        (SELECT count(*) FROM jobs) AS jobs
    `);
    if (counts.revisions !== counts.jobs) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite revision authority is not in one-to-one correspondence with admission jobs.");
    }
    for (const row of this.#all("SELECT * FROM revisions ORDER BY revision_key")) {
      const job = this.#get("SELECT * FROM jobs WHERE job_id = ?", row.job_id);
      const firstRow = this.#get(`
        SELECT receipt_sha256, event_index, receipt_json, created_at_ms
        FROM protocol_receipts WHERE receipt_sha256 = ?
      `, row.first_receipt_sha256);
      if (!job || !firstRow || firstRow.event_index !== 1n || firstRow.created_at_ms !== row.created_at_ms) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite revision authority is missing its exact job or first receipt.");
      }
      const bindings = {
        admissionDigest: row.admission_digest,
        applicationId: row.application_id,
        audience: this.serviceAudience,
        jobId: row.job_id,
        revision: row.revision,
        revisionKey: row.revision_key,
        tenantId: row.tenant_id
      };
      const derived = deriveUniversalAdmissionRevisionBinding({
        bindings,
        createdAtMs: String(row.created_at_ms),
        creatorPrincipalBindingSha256: row.creator_principal_binding_sha256
      });
      const bindingBytes = canonicalProtocolBytes(derived.revisionBinding);
      const first = validateUniversalAdmissionEventReceipt(parseCanonicalBlob(firstRow.receipt_json));
      if (row.revision_key !== job.revision_key
        || row.tenant_id !== job.tenant_id
        || row.application_id !== job.application_id
        || row.revision !== job.revision
        || row.admission_digest !== job.admission_digest
        || row.revision_binding_sha256 !== job.revision_binding_sha256
        || row.revision_binding_sha256 !== derived.revisionBindingSha256
        || row.first_receipt_sha256 !== job.first_receipt_sha256
        || !Buffer.from(row.binding_json).equals(bindingBytes)
        || first.eventType !== "queued"
        || first.occurredAtMs !== String(row.created_at_ms)
        || first.principalBindingSha256 !== row.creator_principal_binding_sha256
        || first.job.revisionBindingSha256 !== row.revision_binding_sha256
        || first.job.revisionKey !== row.revision_key
        || first.job.jobId !== row.job_id
        || first.job.admissionDigest !== row.admission_digest
        || first.job.applicationId !== row.application_id
        || first.job.revision !== row.revision
        || first.job.tenantId !== row.tenant_id) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite revision row, canonical binding, job, and immutable queued receipt disagree.");
      }
    }
  }

  #assertJobObjectBindings(row, job, receipts) {
    if (job.lease === null) {
      if (row.lease_json !== null || row.lease_expires_at_ms !== null) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite non-leased job retains lease columns.");
      }
    } else if (row.lease_expires_at_ms !== BigInt(job.lease.expiresAtMs)
      || !Buffer.from(row.lease_json).equals(canonicalProtocolBytes(job.lease))) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite lease JSON and indexed expiry column disagree.");
    }

    const charges = this.#all("SELECT * FROM enqueue_charges WHERE job_id = ? ORDER BY cycle", job.jobId);
    if (BigInt(charges.length) !== job.redrives + 1n) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite enqueue charge ledger does not cover every admission cycle.");
    }
    const admissionObject = this.#get("SELECT byte_length, generation, media_type FROM cas_objects WHERE digest = ?", job.admissionDigest);
    for (let index = 0; index < charges.length; index += 1) {
      const charge = charges[index];
      const enqueueReceipt = receipts.find((receipt) => BigInt(receipt.job.cycle) === BigInt(index)
        && (index === 0 ? receipt.eventType === "queued" : receipt.eventType === "dead-letter-redriven"));
      if (charge.cycle !== BigInt(index)
        || charge.tenant_id !== job.tenantId
        || charge.application_id !== job.applicationId
        || !enqueueReceipt
        || charge.charged_at_ms !== BigInt(enqueueReceipt.occurredAtMs)
        || (admissionObject !== undefined && admissionObject !== null && charge.byte_length !== admissionObject.byte_length)) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite enqueue charge ledger differs from immutable queue events or admission bytes.");
      }
    }

    const now = this.#meta().now_ms;
    const payloadLive = ACTIVE_STATES.has(job.state)
      || (job.state === "dead-lettered" && now - job.terminalAtMs < BigInt(this.policy.deadLetterPayloadRetentionMs))
      || (job.state === "processing-completed" && now - job.terminalAtMs < BigInt(this.policy.terminalPayloadRetentionMs));
    const admissionRef = this.#get(`
      SELECT 1 AS present FROM object_refs
      WHERE digest = ? AND reference = ? AND job_id = ? AND purpose = 'admission'
    `, job.admissionDigest, `${job.jobId}:admission`, job.jobId);
    if (admissionObject && (admissionObject.media_type !== "universal-admission-envelope"
      || ((payloadLive || admissionRef) && admissionObject.generation !== job.objectGeneration))) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite job admission CAS generation or media binding is inconsistent.");
    }
    if (payloadLive && (!admissionObject || !admissionRef)) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite retention-live job admission payload is missing.");
    }

    const expectedRefs = new Map();
    const admissionReference = `${job.jobId}:admission`;
    if (admissionObject) expectedRefs.set(admissionReference, { digest: job.admissionDigest, purpose: "admission", required: payloadLive });
    for (let index = 0; index < receipts.length; index += 1) {
      const receiptSha256 = sha256Bytes(canonicalProtocolBytes(receipts[index]));
      const purpose = `receipt:${index + 1}`;
      expectedRefs.set(`${job.jobId}:${purpose}`, { digest: receiptSha256, purpose, required: true });
    }

    const completionRows = this.#all("SELECT purpose, digest, descriptor_json FROM completion_bindings WHERE job_id = ? ORDER BY purpose", job.jobId);
    if (job.state !== "processing-completed") {
      if (completionRows.length !== 0 || job.resultSha256 !== null) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite non-completed job retains completion authority.");
      }
    } else {
      const terminal = receipts.at(-1);
      if (terminal?.eventType !== "processing-completed" || completionRows.length < 2) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite completed job lacks terminal receipt or completion bindings.");
      }
      const descriptors = new Map();
      const artifacts = [];
      for (const binding of completionRows) {
        const descriptor = parseCanonicalBlob(binding.descriptor_json);
        if (descriptors.has(binding.purpose)) {
          protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite completion binding purpose is duplicated.");
        }
        descriptors.set(binding.purpose, { descriptor, digest: binding.digest });
        if (binding.purpose === "result") {
          if (!isExactObject(descriptor, ["kind", "sha256"]) || descriptor.kind !== "result" || descriptor.sha256 !== binding.digest) {
            protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite result completion descriptor is invalid.");
          }
        } else if (binding.purpose === "report") {
          if (!isExactObject(descriptor, ["kind", "sha256"]) || descriptor.kind !== "report" || descriptor.sha256 !== binding.digest) {
            protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite report completion descriptor is invalid.");
          }
        } else if (binding.purpose.startsWith("artifact:")) {
          if (!isExactObject(descriptor, ["artifact", "ordinal"])
            || !isExactObject(descriptor.artifact, ["byteLength", "id", "kind", "sha256"])
            || descriptor.artifact.id !== binding.purpose.slice("artifact:".length)
            || descriptor.artifact.sha256 !== binding.digest
            || typeof descriptor.artifact.kind !== "string"
            || typeof descriptor.ordinal !== "string") {
            protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite artifact completion descriptor is invalid.");
          }
          assertDigest(descriptor.artifact.sha256, "completion artifact digest");
          parseDecimal(descriptor.artifact.byteLength, "completion artifact byteLength", { positive: true });
          artifacts.push({ artifact: descriptor.artifact, ordinal: parseDecimal(descriptor.ordinal, "completion artifact ordinal") });
        } else {
          protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite completion binding purpose is outside the closed set.");
        }
        expectedRefs.set(`${job.jobId}:${binding.purpose}`, { digest: binding.digest, purpose: binding.purpose, required: payloadLive });
      }
      const resultBinding = descriptors.get("result");
      const reportBinding = descriptors.get("report");
      artifacts.sort((left, right) => left.ordinal < right.ordinal ? -1 : left.ordinal > right.ordinal ? 1 : 0);
      if (!resultBinding || !reportBinding
        || resultBinding.digest !== job.resultSha256
        || resultBinding.digest !== terminal.result.resultSha256
        || reportBinding.digest !== terminal.result.reportSha256
        || artifacts.some((entry, index) => entry.ordinal !== BigInt(index))
        || digestProtocolValue(artifacts.map(({ artifact }) => artifact)) !== terminal.result.artifactsSha256) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite completion descriptors differ from the terminal receipt.");
      }
      const resultObject = this.#verifiedObject(job.resultSha256, "universal-admission-worker-result");
      if (payloadLive && !resultObject) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite retention-live worker result is missing.");
      }
      if (resultObject) {
        const result = parseUniversalAdmissionWorkerResultBytes(resultObject.bytes);
        const expectedBinding = {
          admissionDigest: job.admissionDigest,
          attempt: String(job.attempt),
          cycle: String(job.cycle),
          fenceToken: String(job.fenceToken),
          jobId: job.jobId,
          leaseId: terminal.lease.leaseId,
          revisionBindingSha256: job.revisionBindingSha256,
          revisionKey: job.revisionKey
        };
        if (digestProtocolValue(result.binding) !== digestProtocolValue(expectedBinding)
          || result.worker.workerBindingSha256 !== terminal.workerBindingSha256
          || result.reportSha256 !== reportBinding.digest
          || result.reviewState !== terminal.result.reviewState
          || !canonicalProtocolBytes(result.artifacts).equals(canonicalProtocolBytes(artifacts.map(({ artifact }) => artifact)))) {
          protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite worker result differs from its job, completion descriptors, or terminal receipt.");
        }
      }
      for (const { artifact } of artifacts) {
        const object = this.#verifiedObject(artifact.sha256, "public-evidence");
        if (payloadLive && (!object || object.byteLength !== BigInt(artifact.byteLength))) {
          protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite retention-live completion artifact is missing or has the wrong byte length.");
        }
        if (object && object.byteLength !== BigInt(artifact.byteLength)) {
          protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite completion artifact byte length differs from its persisted descriptor.");
        }
      }
      if (payloadLive && !this.#verifiedObject(reportBinding.digest, "public-evidence")) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite retention-live completion report is missing.");
      }
    }

    const actualRefs = this.#all("SELECT digest, reference, purpose FROM object_refs WHERE job_id = ? ORDER BY reference", job.jobId);
    const actualByReference = new Map(actualRefs.map((ref) => [ref.reference, ref]));
    for (const [reference, expected] of expectedRefs) {
      const actual = actualByReference.get(reference);
      if (expected.required && (!actual || actual.digest !== expected.digest || actual.purpose !== expected.purpose)) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite mandatory job object reference is absent or malformed.");
      }
    }
    for (const actual of actualRefs) {
      const expected = expectedRefs.get(actual.reference);
      if (!expected || actual.reference !== `${job.jobId}:${actual.purpose}`
        || actual.digest !== expected.digest || actual.purpose !== expected.purpose) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite job contains a forged or unbound object reference.");
      }
    }
  }

  #configureDatabase() {
    this.#retryBusy(() => {
      this.db.exec("PRAGMA page_size=4096");
      this.db.exec("PRAGMA auto_vacuum=INCREMENTAL");
      const mode = this.db.prepare("PRAGMA journal_mode=WAL").get();
      if (String(mode.journal_mode).toLowerCase() !== "wal") protocolFail("UNIVERSAL_ADMISSION_SQLITE_WAL_UNAVAILABLE", "SQLite WAL mode is required for the reference backend.");
      this.db.exec(`PRAGMA application_id=${SQLITE_APPLICATION_ID}`);
      this.db.exec("PRAGMA synchronous=FULL");
      this.db.exec("PRAGMA foreign_keys=ON");
      this.db.exec("PRAGMA trusted_schema=OFF");
      this.db.exec("PRAGMA cell_size_check=ON");
      this.db.exec("PRAGMA wal_autocheckpoint=1000");
      this.db.exec("PRAGMA journal_size_limit=67108864");
      const maximumPages = this.maximumDatabaseBytes / 4096n;
      if (maximumPages < 256n) protocolFail("UNIVERSAL_ADMISSION_SQLITE_POLICY_MISMATCH", "SQLite database byte limit must reserve at least 1 MiB.");
      const pageLimit = this.#get(`PRAGMA max_page_count=${maximumPages}`).max_page_count;
      if (pageLimit !== maximumPages) protocolFail("UNIVERSAL_ADMISSION_SQLITE_POLICY_MISMATCH", "SQLite could not enforce the configured database page limit.");
      this.db.exec("PRAGMA temp_store=MEMORY");
      this.db.exec("PRAGMA mmap_size=0");
    });
  }

  #initialize(initialNow) {
    const policyBytes = canonicalProtocolBytes(this.policy);
    this.#transaction(() => {
      this.db.exec(SCHEMA_SQL);
      const existing = this.#get("SELECT * FROM admission_meta WHERE singleton = 1");
      if (!existing) {
        this.#run(`
          INSERT INTO admission_meta (
            singleton, schema_version, policy_sha256, policy_json, now_ms,
            max_cas_bytes, max_database_bytes, service_audience
          ) VALUES (1, ?, ?, ?, ?, ?, ?, ?)
        `, BigInt(UNIVERSAL_ADMISSION_SQLITE_SCHEMA_VERSION), this.capacityPolicySha256, policyBytes, initialNow, this.maximumCasBytes, this.maximumDatabaseBytes, this.serviceAudience);
      } else {
        if (existing.schema_version !== BigInt(UNIVERSAL_ADMISSION_SQLITE_SCHEMA_VERSION)) protocolFail("UNIVERSAL_ADMISSION_SQLITE_SCHEMA_MISMATCH", "SQLite schema version differs from this implementation.");
        if (existing.policy_sha256 !== this.capacityPolicySha256 || !Buffer.from(existing.policy_json).equals(policyBytes)) protocolFail("UNIVERSAL_ADMISSION_SQLITE_POLICY_MISMATCH", "SQLite runtime policy differs from the opened store.");
        if (existing.max_cas_bytes !== this.maximumCasBytes) protocolFail("UNIVERSAL_ADMISSION_SQLITE_POLICY_MISMATCH", "SQLite CAS byte limit differs from the opened store.");
        if (existing.max_database_bytes !== this.maximumDatabaseBytes) protocolFail("UNIVERSAL_ADMISSION_SQLITE_POLICY_MISMATCH", "SQLite database byte limit differs from the opened store.");
        if (existing.service_audience !== this.serviceAudience) protocolFail("UNIVERSAL_ADMISSION_SQLITE_AUDIENCE_MISMATCH", "SQLite service audience differs from the opened store.");
        parseTimestamp(String(existing.now_ms), "stored nowMs");
        assertOperationalClock(existing.now_ms, this.policy);
        if (initialNow > existing.now_ms) this.#run("UPDATE admission_meta SET now_ms = ? WHERE singleton = 1", initialNow);
      }
      this.db.exec(`PRAGMA user_version=${UNIVERSAL_ADMISSION_SQLITE_SCHEMA_VERSION}`);
    });
  }

  #submit(envelopeBytes, bindings, request) {
    const existing = this.#get("SELECT * FROM revisions WHERE revision_key = ?", bindings.revisionKey);
    if (existing) return this.#existingRevisionResponse(existing, bindings, request);

    const object = this.#putObject(validateObjectBytes(envelopeBytes, "universal-admission-envelope"), "universal-admission-envelope");
    const raced = this.#get("SELECT * FROM revisions WHERE revision_key = ?", bindings.revisionKey);
    if (raced) return this.#existingRevisionResponse(raced, bindings, request);

    const now = this.#now();
    this.#ensureTenant(bindings.tenantId, now);
    this.#ensureApplication(bindings.tenantId, bindings.applicationId);
    this.#resetWindow(bindings.tenantId, now);
    this.#assertSubmitCapacity({
      applicationId: bindings.applicationId,
      byteLength: BigInt(bindings.envelopeByteLength),
      tenantId: bindings.tenantId
    });
    this.#run("UPDATE tenants SET next_enqueue_ordinal = next_enqueue_ordinal + 1 WHERE tenant_id = ?", bindings.tenantId);
    const enqueueOrdinal = this.#get("SELECT next_enqueue_ordinal FROM tenants WHERE tenant_id = ?", bindings.tenantId).next_enqueue_ordinal;
    const { revisionBinding, revisionBindingSha256 } = deriveUniversalAdmissionRevisionBinding({
      bindings,
      createdAtMs: String(now),
      creatorPrincipalBindingSha256: bindings.principal.principalBindingSha256
    });
    const job = {
      admissionDigest: bindings.admissionDigest,
      applicationId: bindings.applicationId,
      attempt: 0n,
      availableAtMs: now,
      cycle: 0n,
      enqueueOrdinal,
      eventIndex: 0n,
      fenceToken: 0n,
      firstReceiptSha256: null,
      headReceiptSha256: null,
      idempotencyKey: bindings.idempotencyKey,
      jobId: bindings.jobId,
      lease: null,
      objectGeneration: BigInt(object.generation),
      redrives: 0n,
      resultSha256: null,
      revision: bindings.revision,
      revisionBindingSha256,
      revisionKey: bindings.revisionKey,
      state: "queued",
      tenantId: bindings.tenantId,
      terminalAtMs: null
    };
    this.#insertJob(job);
    this.#addObjectRef(job.admissionDigest, `${job.jobId}:admission`, job.jobId, "admission");
    this.#consumeSubmitCapacity({
      applicationId: job.applicationId,
      byteLength: BigInt(bindings.envelopeByteLength),
      tenantId: job.tenantId
    });
    this.#recordEnqueueCharge(job, BigInt(bindings.envelopeByteLength), now);
    const receipt = this.#appendReceipt(job, {
      eventType: "queued",
      failure: null,
      lease: null,
      principalBindingSha256: bindings.principal.principalBindingSha256,
      request,
      result: null,
      transition: { from: null, to: "queued" },
      workerBindingSha256: null
    });
    this.#recordEnqueueOrdinal(job, receipt.receiptSha256, now);
    job.firstReceiptSha256 = receipt.receiptSha256;
    this.#saveJob(job);
    this.#run(`
      INSERT INTO revisions (
        revision_key, tenant_id, application_id, revision, admission_digest, job_id,
        revision_binding_sha256, creator_principal_binding_sha256, created_at_ms,
        first_receipt_sha256, binding_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
    job.revisionKey, job.tenantId, job.applicationId, job.revision, job.admissionDigest, job.jobId,
    revisionBindingSha256, bindings.principal.principalBindingSha256, now,
    receipt.receiptSha256, canonicalProtocolBytes(revisionBinding));
    return this.#submissionResponse({ bindings, job, receiptSha256: receipt.receiptSha256, request, status: "QUEUED" });
  }

  #claim(worker) {
    const meta = this.#meta();
    if (meta.global_leased >= BigInt(this.policy.maxGlobalLeased)) return freeze({ status: "NO_WORK", reason: "GLOBAL_LEASE_CAPACITY" });
    const now = meta.now_ms;
    const tenant = this.#get(`
      SELECT t.tenant_id
      FROM jobs j INDEXED BY jobs_ready_idx
      JOIN tenants t ON t.tenant_id = j.tenant_id
      WHERE j.state IN ('queued','retry-wait')
        AND j.available_at_ms <= ?
        AND t.leased < ?
      GROUP BY t.tenant_id, t.last_claim_ordinal
      ORDER BY t.last_claim_ordinal, t.tenant_id
      LIMIT 1
    `, now, BigInt(this.policy.maxTenantLeased));
    if (!tenant) return freeze({ status: "NO_WORK", reason: "NO_ELIGIBLE_JOB" });
    const row = this.#get(`
      SELECT * FROM jobs
      WHERE tenant_id = ? AND state IN ('queued','retry-wait') AND available_at_ms <= ?
      ORDER BY available_at_ms, enqueue_ordinal, job_id
      LIMIT 1
    `, tenant.tenant_id, now);
    if (!row) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "Fair-claim tenant had no eligible job.");
    const job = rowToJob(row);
    const priorState = job.state;
    job.attempt += 1n;
    job.fenceToken += 1n;
    job.state = "leased";
    this.#run("UPDATE admission_meta SET claim_ordinal = claim_ordinal + 1, global_leased = global_leased + 1 WHERE singleton = 1");
    const ordinal = this.#meta().claim_ordinal;
    const claimedAtMs = String(now);
    const fenceToken = String(job.fenceToken);
    const leaseId = deriveLeaseId({
      claimedAtMs,
      claimOrdinal: String(ordinal),
      cycle: String(job.cycle),
      fenceToken,
      jobId: job.jobId,
      workerBindingSha256: worker.workerBindingSha256
    });
    job.lease = {
      claimedAtMs,
      claimOrdinal: String(ordinal),
      expiresAtMs: String(addTimestamp(now, BigInt(this.policy.leaseDurationMs), "lease expiry")),
      fenceToken,
      leaseId,
      renewals: "0",
      workerBindingSha256: worker.workerBindingSha256
    };
    this.#run("UPDATE tenants SET last_claim_ordinal = ?, leased = leased + 1 WHERE tenant_id = ?", ordinal, job.tenantId);
    this.#saveJob(job);
    const receipt = this.#appendReceipt(job, {
      eventType: "lease-claimed",
      failure: null,
      lease: job.lease,
      principalBindingSha256: null,
      result: null,
      transition: { from: priorState, to: "leased" },
      workerBindingSha256: worker.workerBindingSha256
    });
    this.#run(`
      INSERT INTO claim_ordinals (claim_ordinal, tenant_id, job_id, receipt_sha256, claimed_at_ms)
      VALUES (?, ?, ?, ?, ?)
    `, ordinal, job.tenantId, job.jobId, receipt.receiptSha256, now);
    this.#saveJob(job);
    const object = this.#verifiedObject(job.admissionDigest, "universal-admission-envelope");
    if (!object) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_CAS_CONFLICT", "Claimed admission envelope is absent from SQLite CAS.");
    return freeze({
      admissionDigest: job.admissionDigest,
      envelopeBytes: Buffer.from(object.bytes),
      jobId: job.jobId,
      lease: structuredClone(job.lease),
      receiptSha256: receipt.receiptSha256,
      revisionBindingSha256: job.revisionBindingSha256,
      revisionKey: job.revisionKey,
      status: "LEASED"
    });
  }

  #renew({ fenceToken, jobId, leaseId, worker }) {
    const job = this.#job(jobId);
    this.#assertLease(job, { fenceToken, leaseId, workerBindingSha256: worker.workerBindingSha256 });
    const renewals = BigInt(job.lease.renewals);
    if (renewals >= BigInt(this.policy.maxLeaseRenewals)) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_LEASE_RENEWAL_LIMIT", "Lease renewal limit is exhausted.");
    const maximumExpiry = addTimestamp(BigInt(job.lease.claimedAtMs), BigInt(this.policy.maxLeaseDurationMs), "maximum lease expiry");
    const requestedExpiry = addTimestamp(BigInt(job.lease.expiresAtMs), BigInt(this.policy.leaseDurationMs), "renewed lease expiry");
    const nextExpiry = requestedExpiry < maximumExpiry ? requestedExpiry : maximumExpiry;
    if (nextExpiry <= BigInt(job.lease.expiresAtMs)) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_LEASE_RENEWAL_LIMIT", "Lease reached its maximum cumulative duration.");
    job.lease = { ...job.lease, expiresAtMs: String(nextExpiry), renewals: String(renewals + 1n) };
    this.#saveJob(job);
    const receipt = this.#appendReceipt(job, {
      eventType: "lease-renewed",
      failure: null,
      lease: job.lease,
      principalBindingSha256: null,
      result: null,
      transition: { from: "leased", to: "leased" },
      workerBindingSha256: worker.workerBindingSha256
    });
    this.#saveJob(job);
    return freeze({ lease: structuredClone(job.lease), receiptSha256: receipt.receiptSha256, status: "LEASED" });
  }

  #redrive({ expectedReceiptSha256, jobId, principal }) {
    const job = this.#job(jobId);
    if (principal.tenantId !== job.tenantId) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_PRINCIPAL_TENANT_MISMATCH", "Principal tenant does not own this job.");
    if (job.state !== "dead-lettered") protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_JOB_STATE_CONFLICT", "Only a dead-lettered job can be redriven.");
    if (this.#now() - job.terminalAtMs >= BigInt(this.policy.deadLetterPayloadRetentionMs)) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_REDRIVE_WINDOW_EXPIRED", "Dead-letter redrive window has expired.");
    }
    if (job.headReceiptSha256 !== expectedReceiptSha256) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_DLQ_REDRIVE_CONFLICT", "DLQ head receipt changed before redrive.");
    if (job.redrives >= BigInt(this.policy.maxRedrives)) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_DLQ_REDRIVE_LIMIT", "DLQ redrive limit is exhausted.");
    const object = this.#verifiedObject(job.admissionDigest, "universal-admission-envelope");
    if (!object) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_CAS_CONFLICT", "Dead-lettered admission payload is absent from SQLite CAS.");
    const now = this.#now();
    this.#resetWindow(job.tenantId, now);
    this.#assertSubmitCapacity({ applicationId: job.applicationId, byteLength: object.byteLength, tenantId: job.tenantId });
    job.cycle += 1n;
    job.attempt = 0n;
    job.redrives += 1n;
    job.state = "queued";
    job.availableAtMs = now;
    job.terminalAtMs = null;
    this.#run("UPDATE tenants SET next_enqueue_ordinal = next_enqueue_ordinal + 1 WHERE tenant_id = ?", job.tenantId);
    job.enqueueOrdinal = this.#get("SELECT next_enqueue_ordinal FROM tenants WHERE tenant_id = ?", job.tenantId).next_enqueue_ordinal;
    this.#addObjectRef(job.admissionDigest, `${job.jobId}:admission`, job.jobId, "admission");
    this.#consumeSubmitCapacity({ applicationId: job.applicationId, byteLength: object.byteLength, tenantId: job.tenantId });
    this.#recordEnqueueCharge(job, object.byteLength, now);
    this.#saveJob(job);
    const receipt = this.#appendReceipt(job, {
      eventType: "dead-letter-redriven",
      failure: null,
      lease: null,
      principalBindingSha256: principal.principalBindingSha256,
      result: null,
      transition: { from: "dead-lettered", to: "queued" },
      workerBindingSha256: null
    });
    this.#recordEnqueueOrdinal(job, receipt.receiptSha256, now);
    this.#saveJob(job);
    return freeze({ jobId: job.jobId, receiptSha256: receipt.receiptSha256, status: "QUEUED" });
  }

  #complete({ jobId, result, resultBytes, worker }) {
    const job = this.#job(jobId);
    this.#assertLease(job, {
      fenceToken: result.binding.fenceToken,
      leaseId: result.binding.leaseId,
      workerBindingSha256: worker.workerBindingSha256
    });
    const expected = {
      admissionDigest: job.admissionDigest,
      attempt: String(job.attempt),
      cycle: String(job.cycle),
      fenceToken: String(job.fenceToken),
      jobId: job.jobId,
      leaseId: job.lease.leaseId,
      revisionBindingSha256: job.revisionBindingSha256,
      revisionKey: job.revisionKey
    };
    if (digestProtocolValue(result.binding) !== digestProtocolValue(expected)
      || result.worker.workerBindingSha256 !== worker.workerBindingSha256
      || result.worker.implementationSha256 !== worker.implementationSha256) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_RESULT_BINDING_MISMATCH", "Worker result does not bind the current exact job lease.");
    }
    if (!this.#publicEvidenceObject(result.reportSha256)) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ARTIFACT_MISSING", `Worker result report ${result.reportSha256} is absent from SQLite CAS.`);
    }
    for (const artifact of result.artifacts) {
      const object = this.#publicEvidenceObject(artifact.sha256);
      if (!object) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ARTIFACT_MISSING", `Worker result artifact ${artifact.sha256} is absent from SQLite CAS.`);
      if (object.byteLength !== BigInt(artifact.byteLength)) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ARTIFACT_SIZE_MISMATCH", `Worker result artifact ${artifact.sha256} has a different stored byte length.`);
      }
    }
    const resultObject = this.#putObject(validateObjectBytes(resultBytes, "universal-admission-worker-result"), "universal-admission-worker-result");
    const oldLease = structuredClone(job.lease);
    job.state = "processing-completed";
    job.terminalAtMs = this.#now();
    job.resultSha256 = resultObject.digest;
    job.lease = null;
    this.#releaseOutstanding(job);
    this.#recordCompletionBinding(job.jobId, "result", resultObject.digest, { kind: "result", sha256: resultObject.digest });
    this.#recordCompletionBinding(job.jobId, "report", result.reportSha256, { kind: "report", sha256: result.reportSha256 });
    for (const [ordinal, artifact] of result.artifacts.entries()) {
      this.#recordCompletionBinding(job.jobId, `artifact:${artifact.id}`, artifact.sha256, { artifact, ordinal: String(ordinal) });
    }
    this.#addObjectRef(resultObject.digest, `${job.jobId}:result`, job.jobId, "result");
    this.#addObjectRef(result.reportSha256, `${job.jobId}:report`, job.jobId, "report");
    for (const artifact of result.artifacts) this.#addObjectRef(artifact.sha256, `${job.jobId}:artifact:${artifact.id}`, job.jobId, `artifact:${artifact.id}`);
    const receipt = this.#appendReceipt(job, {
      eventType: "processing-completed",
      failure: null,
      lease: oldLease,
      principalBindingSha256: null,
      result: {
        artifactsSha256: digestProtocolValue(result.artifacts),
        reportSha256: result.reportSha256,
        resultSha256: resultObject.digest,
        reviewState: result.reviewState
      },
      transition: { from: "leased", to: "processing-completed" },
      workerBindingSha256: worker.workerBindingSha256
    });
    this.#saveJob(job);
    return freeze({ jobId: job.jobId, receiptSha256: receipt.receiptSha256, resultSha256: resultObject.digest, status: "PROCESSING_COMPLETED" });
  }

  #snapshot() {
    this.#pruneCompletedSnapshots();
    const records = this.#snapshotRecords();
    const recordsBytes = canonicalProtocolBytes(records);
    if (recordsBytes.length > UNIVERSAL_ADMISSION_SQLITE_MAX_SNAPSHOT_RECORD_BYTES) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_LIMIT_INVALID", "SQLite snapshot record byte bound is exceeded.");
    const shards = snapshotShards(records);
    const candidates = this.#gcCandidates();
    const candidatesBytes = canonicalProtocolBytes(candidates);
    if (candidatesBytes.length > UNIVERSAL_ADMISSION_SQLITE_MAX_SNAPSHOT_CANDIDATE_BYTES) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_LIMIT_INVALID", "SQLite snapshot candidate byte bound is exceeded.");
    const meta = this.#meta();
    const liveObjectReferences = records
      .filter(({ key }) => key.startsWith("object/"))
      .reduce((total, record) => total + record.value.references.length, 0);
    const manifest = buildUniversalAdmissionSnapshot({
      createdAtMs: String(meta.now_ms),
      cutSha256: digestProtocolValue(records),
      gcCandidatesSha256: digestProtocolValue(candidates.map(({ digest, generation, reason }) => ({ digest, generation: String(generation), reason }))),
      previousSnapshotSha256: meta.snapshot_head,
      serviceAudience: this.serviceAudience,
      shards,
      totals: {
        gcCandidates: String(candidates.length),
        liveObjectReferences: String(liveObjectReferences),
        records: String(records.length)
      }
    });
    const bytes = canonicalProtocolBytes(manifest);
    const object = this.#putObject(bytes, "universal-admission-snapshot");
    this.#run(`
      INSERT INTO snapshots (
        snapshot_sha256, previous_snapshot_sha256, manifest_json, records_json,
        candidates_json, created_at_ms, gc_complete, gc_processed_count
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 0)
    `, object.digest, meta.snapshot_head, bytes, recordsBytes, candidatesBytes, meta.now_ms, candidates.length === 0 ? 1n : 0n);
    this.#run("UPDATE admission_meta SET snapshot_head = ? WHERE singleton = 1", object.digest);
    return freeze({ manifest, snapshotSha256: object.digest });
  }

  #gc({ limit, snapshotSha256 }) {
    assertDigest(snapshotSha256, "snapshotSha256");
    const { candidates: allCandidates } = this.#validatedSnapshot(snapshotSha256);
    const progress = this.#get("SELECT gc_processed_count FROM snapshots WHERE snapshot_sha256 = ?", snapshotSha256);
    const effectiveStart = Number(progress.gc_processed_count);
    const candidates = allCandidates.slice(effectiveStart, effectiveStart + limit);
    const deleted = [];
    for (const candidate of candidates) {
      const object = this.#get("SELECT generation, byte_length FROM cas_objects WHERE digest = ?", candidate.digest);
      if (!object || object.generation !== BigInt(candidate.generation)) {
        continue;
      }
      if (!this.#currentlyGcEligible(candidate.digest, candidate.reason)) {
        continue;
      }
      if (candidate.reason === "terminal-payload") this.#run("DELETE FROM object_refs WHERE digest = ?", candidate.digest);
      this.#run("DELETE FROM cas_objects WHERE digest = ?", candidate.digest);
      this.#run("UPDATE admission_meta SET cas_bytes = cas_bytes - ? WHERE singleton = 1", object.byte_length);
      deleted.push(candidate.digest);
    }
    const consumed = effectiveStart + candidates.length;
    this.#run(`
      UPDATE snapshots SET gc_complete = ?, gc_processed_count = ?
      WHERE snapshot_sha256 = ?
    `, consumed === allCandidates.length ? 1n : 0n, BigInt(consumed), snapshotSha256);
    return freeze({
      deletedCount: String(deleted.length),
      done: consumed === allCandidates.length,
      remainingCount: String(Math.max(0, allCandidates.length - consumed)),
      snapshotSha256
    });
  }

  #settleFailure(job, failure, { allowExpired }) {
    this.#assertLease(job, {
      fenceToken: job.lease.fenceToken,
      leaseId: job.lease.leaseId,
      workerBindingSha256: job.lease.workerBindingSha256
    }, { allowExpired });
    const oldLease = structuredClone(job.lease);
    const workerBindingSha256 = oldLease.workerBindingSha256;
    const retry = failure.retryable && job.attempt < BigInt(this.policy.maxAttempts);
    if (retry) {
      const delay = BigInt(deterministicRetryDelayMs({
        attempt: String(job.attempt),
        cycle: String(job.cycle),
        jobId: job.jobId,
        policy: this.policy
      }));
      job.state = "retry-wait";
      job.availableAtMs = addTimestamp(this.#now(), delay, "retry availability");
      this.#run("UPDATE tenants SET next_enqueue_ordinal = next_enqueue_ordinal + 1, leased = leased - 1 WHERE tenant_id = ?", job.tenantId);
      job.enqueueOrdinal = this.#get("SELECT next_enqueue_ordinal FROM tenants WHERE tenant_id = ?", job.tenantId).next_enqueue_ordinal;
      this.#run("UPDATE admission_meta SET global_leased = global_leased - 1 WHERE singleton = 1");
      job.lease = null;
      this.#saveJob(job);
      const receipt = this.#appendReceipt(job, {
        eventType: "retry-scheduled",
        failure,
        lease: oldLease,
        principalBindingSha256: null,
        result: null,
        transition: { from: "leased", to: "retry-wait" },
        workerBindingSha256
      });
      this.#recordEnqueueOrdinal(job, receipt.receiptSha256, this.#now());
      this.#saveJob(job);
      return freeze({ availableAtMs: String(job.availableAtMs), jobId: job.jobId, receiptSha256: receipt.receiptSha256, status: "RETRY_WAIT" });
    }
    job.state = "dead-lettered";
    job.terminalAtMs = this.#now();
    job.lease = null;
    this.#releaseOutstanding(job);
    const receipt = this.#appendReceipt(job, {
      eventType: "dead-lettered",
      failure,
      lease: oldLease,
      principalBindingSha256: null,
      result: null,
      transition: { from: "leased", to: "dead-lettered" },
      workerBindingSha256
    });
    this.#saveJob(job);
    return freeze({ jobId: job.jobId, receiptSha256: receipt.receiptSha256, status: "DEAD_LETTERED" });
  }

  #appendReceipt(job, event) {
    job.eventIndex += 1n;
    const receipt = buildUniversalAdmissionEventReceipt({
      capacityPolicySha256: this.capacityPolicySha256,
      eventIndex: String(job.eventIndex),
      eventType: event.eventType,
      failure: event.failure,
      idempotencyKey: job.idempotencyKey,
      job: {
        admissionDigest: job.admissionDigest,
        applicationId: job.applicationId,
        attempt: String(job.attempt),
        availableAtMs: String(job.availableAtMs),
        cycle: String(job.cycle),
        enqueueOrdinal: String(job.enqueueOrdinal),
        fenceToken: String(job.fenceToken),
        jobId: job.jobId,
        revision: job.revision,
        revisionBindingSha256: job.revisionBindingSha256,
        revisionKey: job.revisionKey,
        tenantId: job.tenantId
      },
      lease: event.lease === null ? null : structuredClone(event.lease),
      occurredAtMs: String(this.#now()),
      previousReceiptSha256: job.headReceiptSha256,
      principalBindingSha256: event.principalBindingSha256,
      request: event.request ?? null,
      result: event.result,
      serviceAudience: this.serviceAudience,
      transition: event.transition,
      workerBindingSha256: event.workerBindingSha256
    });
    const bytes = canonicalProtocolBytes(receipt);
    const receiptSha256 = sha256Bytes(bytes);
    this.#putObject(bytes, "universal-admission-event-receipt");
    this.#addObjectRef(receiptSha256, `${job.jobId}:receipt:${job.eventIndex}`, job.jobId, `receipt:${job.eventIndex}`);
    this.#run(`
      INSERT INTO protocol_receipts (
        receipt_sha256, job_id, event_index, receipt_json, created_at_ms
      ) VALUES (?, ?, ?, ?, ?)
    `, receiptSha256, job.jobId, job.eventIndex, bytes, this.#now());
    job.headReceiptSha256 = receiptSha256;
    this.#saveJob(job);
    return { receipt, receiptSha256 };
  }

  #putObject(bytes, mediaType) {
    const requiredMediaType = reservedMediaTypeForBytes(bytes);
    if (requiredMediaType !== null && requiredMediaType !== mediaType) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_CAS_MEDIA_TYPE_CONFLICT", `Reserved ${requiredMediaType} bytes cannot be stored as ${mediaType}.`);
    }
    const digest = sha256Bytes(bytes);
    const existing = this.#get("SELECT bytes, byte_length, generation, media_type FROM cas_objects WHERE digest = ?", digest);
    if (existing) {
      if (!Buffer.from(existing.bytes).equals(bytes)) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_CAS_CONFLICT", "Existing SQLite CAS bytes differ at the same digest.");
      if (existing.media_type !== mediaType) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_CAS_MEDIA_TYPE_CONFLICT", "Existing SQLite CAS media type differs at the same digest.");
      return { created: false, digest, generation: String(existing.generation), byteLength: String(existing.byte_length) };
    }
    const meta = this.#meta();
    if (meta.cas_bytes + BigInt(bytes.length) > meta.max_cas_bytes) protocolFail("UNIVERSAL_ADMISSION_SQLITE_CAS_CAPACITY", "SQLite CAS byte capacity is exhausted.", { retryable: true });
    this.#run(`
      INSERT INTO object_generations (digest, generation) VALUES (?, 1)
      ON CONFLICT(digest) DO UPDATE SET generation = generation + 1
    `, digest);
    const generation = this.#get("SELECT generation FROM object_generations WHERE digest = ?", digest).generation;
    this.#run(`
      INSERT INTO cas_objects (digest, bytes, byte_length, generation, media_type, created_at_ms)
      VALUES (?, ?, ?, ?, ?, ?)
    `, digest, bytes, BigInt(bytes.length), generation, mediaType, this.#now());
    this.#run("UPDATE admission_meta SET cas_bytes = cas_bytes + ? WHERE singleton = 1", BigInt(bytes.length));
    return { created: true, digest, generation: String(generation), byteLength: String(bytes.length) };
  }

  #verifiedObject(digest, expectedMediaType = null) {
    const row = this.#get("SELECT bytes, byte_length, generation, media_type FROM cas_objects WHERE digest = ?", digest);
    if (!row) return null;
    const bytes = Buffer.from(row.bytes);
    const generation = this.#get("SELECT generation FROM object_generations WHERE digest = ?", digest);
    if (sha256Bytes(bytes) !== digest
      || BigInt(bytes.length) !== row.byte_length
      || !SAFE_MEDIA_TYPES.has(row.media_type)
      || (expectedMediaType !== null && row.media_type !== expectedMediaType)
      || generation?.generation !== row.generation) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite CAS object failed digest, length, media, or generation verification.");
    }
    return { byteLength: row.byte_length, bytes, generation: row.generation, mediaType: row.media_type };
  }

  #publicEvidenceObject(digest) {
    const row = this.#get("SELECT media_type FROM cas_objects WHERE digest = ?", digest);
    return !row || row.media_type !== "public-evidence"
      ? null
      : this.#verifiedObject(digest, "public-evidence");
  }

  #addObjectRef(digest, reference, jobId, purpose) {
    if (!this.#get("SELECT 1 AS present FROM cas_objects WHERE digest = ?", digest)) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_CAS_CONFLICT", "Referenced SQLite CAS object is missing.");
    this.#run(`
      INSERT INTO object_refs (digest, reference, job_id, purpose) VALUES (?, ?, ?, ?)
      ON CONFLICT(digest, reference) DO NOTHING
    `, digest, reference, jobId, purpose);
  }

  #recordEnqueueCharge(job, byteLength, chargedAtMs) {
    this.#run(`
      INSERT INTO enqueue_charges (
        job_id, cycle, tenant_id, application_id, charged_at_ms, byte_length
      ) VALUES (?, ?, ?, ?, ?, ?)
    `, job.jobId, job.cycle, job.tenantId, job.applicationId, chargedAtMs, byteLength);
  }

  #recordEnqueueOrdinal(job, receiptSha256, enqueuedAtMs) {
    this.#run(`
      INSERT INTO enqueue_ordinals (
        tenant_id, enqueue_ordinal, job_id, cycle, receipt_sha256, enqueued_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?)
    `, job.tenantId, job.enqueueOrdinal, job.jobId, job.cycle, receiptSha256, enqueuedAtMs);
  }

  #recordCompletionBinding(jobId, purpose, digest, descriptor) {
    this.#run(
      "INSERT INTO completion_bindings (job_id, purpose, digest, descriptor_json) VALUES (?, ?, ?, ?)",
      jobId,
      purpose,
      digest,
      canonicalProtocolBytes(descriptor)
    );
  }

  #assertLease(job, { fenceToken, leaseId, workerBindingSha256 }, { allowExpired = false } = {}) {
    if (job.state !== "leased" || job.lease === null) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_JOB_STATE_CONFLICT", "Job has no live lease.");
    if (fenceToken !== String(job.fenceToken) || fenceToken !== job.lease.fenceToken) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_STALE_FENCE", "Lease fence is stale.");
    if (leaseId !== job.lease.leaseId) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_LEASE_NOT_FOUND", "Lease id does not match the current lease.");
    if (workerBindingSha256 !== job.lease.workerBindingSha256) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_LEASE_OWNER_MISMATCH", "Lease belongs to another authenticated worker.");
    if (!allowExpired && this.#now() >= BigInt(job.lease.expiresAtMs)) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_LEASE_EXPIRED", "Lease expired before this mutation.");
  }

  #releaseOutstanding(job) {
    this.#run("UPDATE tenants SET leased = leased - 1, outstanding = outstanding - 1 WHERE tenant_id = ?", job.tenantId);
    this.#run("UPDATE applications SET outstanding = outstanding - 1 WHERE tenant_id = ? AND application_id = ?", job.tenantId, job.applicationId);
    this.#run("UPDATE admission_meta SET global_leased = global_leased - 1, global_outstanding = global_outstanding - 1 WHERE singleton = 1");
  }

  #ensureTenant(tenantId, now) {
    const start = windowStart(now, BigInt(this.policy.fixedWindowMs));
    this.#run(`
      INSERT INTO tenants (tenant_id, window_start_ms) VALUES (?, ?)
      ON CONFLICT(tenant_id) DO NOTHING
    `, tenantId, start);
  }

  #ensureApplication(tenantId, applicationId) {
    this.#run(`
      INSERT INTO applications (tenant_id, application_id, outstanding) VALUES (?, ?, 0)
      ON CONFLICT(tenant_id, application_id) DO NOTHING
    `, tenantId, applicationId);
  }

  #resetWindow(tenantId, now) {
    const start = windowStart(now, BigInt(this.policy.fixedWindowMs));
    this.#run(`
      UPDATE tenants SET
        window_start_ms = ?, window_jobs = 0, window_bytes = 0,
        authenticated_request_count = 0, authenticated_request_bytes = 0
      WHERE tenant_id = ? AND window_start_ms <> ?
    `, start, tenantId, start);
  }

  #assertSubmitCapacity({ applicationId, byteLength, tenantId }) {
    const tenant = this.#get("SELECT * FROM tenants WHERE tenant_id = ?", tenantId);
    const application = this.#get("SELECT * FROM applications WHERE tenant_id = ? AND application_id = ?", tenantId, applicationId);
    const now = this.#now();
    const retryAfterMs = String(tenant.window_start_ms + BigInt(this.policy.fixedWindowMs) - now);
    if (tenant.window_jobs + 1n > BigInt(this.policy.maxTenantNewJobsPerWindow)
      || tenant.window_bytes + byteLength > BigInt(this.policy.maxTenantNewBytesPerWindow)) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_TENANT_RATE_LIMITED", "Tenant fixed-window admission budget is exhausted.", { retryable: true, retryAfterMs });
    }
    if (application.outstanding + 1n > BigInt(this.policy.maxApplicationOutstanding)) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_APPLICATION_BACKPRESSURE", "Application outstanding capacity is exhausted.", { retryable: true });
    if (tenant.outstanding + 1n > BigInt(this.policy.maxTenantOutstanding)) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_TENANT_BACKPRESSURE", "Tenant outstanding capacity is exhausted.", { retryable: true });
    if (this.#meta().global_outstanding + 1n > BigInt(this.policy.maxGlobalOutstanding)) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_GLOBAL_BACKPRESSURE", "Global outstanding capacity is exhausted.", { retryable: true });
  }

  #reserveAuthenticatedRequest({ byteLength, tenantId }) {
    const tenant = this.#get("SELECT * FROM tenants WHERE tenant_id = ?", tenantId);
    const now = this.#now();
    const retryAfterMs = String(tenant.window_start_ms + BigInt(this.policy.fixedWindowMs) - now);
    if (tenant.authenticated_request_count + 1n > BigInt(this.policy.maxTenantAuthenticatedRequestsPerWindow)
      || tenant.authenticated_request_bytes + byteLength > BigInt(this.policy.maxTenantAuthenticatedRequestBytesPerWindow)) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_AUTHENTICATED_REQUEST_RATE_LIMITED", "Tenant authenticated-request budget is exhausted.", { retryable: true, retryAfterMs });
    }
    this.#run(`
      UPDATE tenants SET
        authenticated_request_count = authenticated_request_count + 1,
        authenticated_request_bytes = authenticated_request_bytes + ?
      WHERE tenant_id = ?
    `, byteLength, tenantId);
  }

  #consumeSubmitCapacity({ applicationId, byteLength, tenantId }) {
    this.#run(`
      UPDATE tenants
      SET outstanding = outstanding + 1, window_jobs = window_jobs + 1, window_bytes = window_bytes + ?
      WHERE tenant_id = ?
    `, byteLength, tenantId);
    this.#run("UPDATE applications SET outstanding = outstanding + 1 WHERE tenant_id = ? AND application_id = ?", tenantId, applicationId);
    this.#run("UPDATE admission_meta SET global_outstanding = global_outstanding + 1 WHERE singleton = 1");
  }

  #existingRevisionResponse(existing, bindings, request) {
    if (existing.admission_digest !== bindings.admissionDigest) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_REVISION_EQUIVOCATION", "Tenant/application/revision is already bound to a different admission digest.");
    const job = this.#job(existing.job_id);
    return this.#submissionResponse({ bindings, job, receiptSha256: existing.first_receipt_sha256, request, status: "DUPLICATE" });
  }

  #submissionResponse({ bindings, job, receiptSha256, request, status }) {
    const receipt = this.#get("SELECT receipt_json FROM protocol_receipts WHERE receipt_sha256 = ?", receiptSha256);
    if (!receipt) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite initial event receipt is missing from the committed submission state.");
    return freeze({
      admissionDigest: bindings.admissionDigest,
      authority: authorityFalse(),
      eventReceipt: parseCanonicalBlob(receipt.receipt_json),
      idempotencyKey: bindings.idempotencyKey,
      jobId: job.jobId,
      principalBindingSha256: bindings.principal.principalBindingSha256,
      receiptSha256,
      requestDigest: request.requestDigest,
      requestId: request.requestId,
      revisionBindingSha256: job.revisionBindingSha256,
      revisionKey: job.revisionKey,
      status,
      tenantId: job.tenantId
    });
  }

  #insertJob(job) {
    this.#run(`
      INSERT INTO jobs (
        job_id, tenant_id, application_id, revision, revision_key,
        revision_binding_sha256, admission_digest, idempotency_key, object_generation, state,
        attempt, cycle, fence_token, redrives, available_at_ms, enqueue_ordinal,
        event_index, first_receipt_sha256, head_receipt_sha256, lease_json,
        lease_expires_at_ms, result_sha256, terminal_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
    job.jobId, job.tenantId, job.applicationId, job.revision, job.revisionKey,
    job.revisionBindingSha256, job.admissionDigest, job.idempotencyKey, job.objectGeneration, job.state,
    job.attempt, job.cycle, job.fenceToken, job.redrives, job.availableAtMs, job.enqueueOrdinal,
    job.eventIndex, job.firstReceiptSha256, job.headReceiptSha256, leaseBytes(job.lease),
    job.lease === null ? null : BigInt(job.lease.expiresAtMs), job.resultSha256, job.terminalAtMs);
  }

  #saveJob(job) {
    this.#run(`
      UPDATE jobs SET
        state = ?, attempt = ?, cycle = ?, fence_token = ?, redrives = ?,
        available_at_ms = ?, enqueue_ordinal = ?, event_index = ?,
        first_receipt_sha256 = ?, head_receipt_sha256 = ?, lease_json = ?,
        lease_expires_at_ms = ?, result_sha256 = ?, terminal_at_ms = ?
      WHERE job_id = ?
    `,
    job.state, job.attempt, job.cycle, job.fenceToken, job.redrives,
    job.availableAtMs, job.enqueueOrdinal, job.eventIndex,
    job.firstReceiptSha256, job.headReceiptSha256, leaseBytes(job.lease),
    job.lease === null ? null : BigInt(job.lease.expiresAtMs), job.resultSha256, job.terminalAtMs, job.jobId);
  }

  #job(jobId) {
    assertDigest(jobId, "jobId");
    const row = this.#get("SELECT * FROM jobs WHERE job_id = ?", jobId);
    if (!row) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_JOB_NOT_FOUND", "Admission job does not exist.");
    return rowToJob(row);
  }

  #publicJob(job) {
    return {
      admissionDigest: job.admissionDigest,
      applicationId: job.applicationId,
      attempt: String(job.attempt),
      availableAtMs: String(job.availableAtMs),
      cycle: String(job.cycle),
      enqueueOrdinal: String(job.enqueueOrdinal),
      fenceToken: String(job.fenceToken),
      firstReceiptSha256: job.firstReceiptSha256,
      headReceiptSha256: job.headReceiptSha256,
      jobId: job.jobId,
      lease: job.lease === null ? null : structuredClone(job.lease),
      redrives: String(job.redrives),
      resultSha256: job.resultSha256,
      revision: job.revision,
      revisionBindingSha256: job.revisionBindingSha256,
      revisionKey: job.revisionKey,
      state: job.state,
      tenantId: job.tenantId,
      terminalAtMs: job.terminalAtMs === null ? null : String(job.terminalAtMs)
    };
  }

  #snapshotRecords() {
    const preflight = this.#get(`
      SELECT
        (SELECT count(*) FROM jobs)
        + (SELECT count(*) FROM cas_objects
           WHERE media_type NOT IN ('universal-admission-event-receipt','universal-admission-snapshot')) AS record_count,
        (SELECT count(*)
         FROM object_refs reference
         JOIN cas_objects object ON object.digest = reference.digest
         WHERE object.media_type NOT IN ('universal-admission-event-receipt','universal-admission-snapshot')) AS reference_count,
        (SELECT coalesce(sum(length(reference.reference)), 0)
         FROM object_refs reference
         JOIN cas_objects object ON object.digest = reference.digest
         WHERE object.media_type NOT IN ('universal-admission-event-receipt','universal-admission-snapshot')) AS reference_bytes,
        (SELECT coalesce(sum(length(media_type)), 0)
         FROM cas_objects
         WHERE media_type NOT IN ('universal-admission-event-receipt','universal-admission-snapshot')) AS media_bytes
    `);
    const conservativeBytes = preflight.record_count * 512n
      + preflight.reference_bytes * 6n
      + preflight.reference_count * 4n
      + preflight.media_bytes * 6n;
    if (preflight.record_count > BigInt(UNIVERSAL_ADMISSION_SQLITE_MAX_SNAPSHOT_RECORDS)
      || preflight.reference_count > BigInt(UNIVERSAL_ADMISSION_SQLITE_MAX_SNAPSHOT_REFERENCES)
      || conservativeBytes > BigInt(UNIVERSAL_ADMISSION_SQLITE_MAX_SNAPSHOT_RECORD_BYTES)) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_LIMIT_INVALID", "SQLite snapshot record, reference, or conservative byte bound is exceeded before materialization.");
    }
    const records = [];
    for (const row of this.#all("SELECT job_id, state, terminal_at_ms FROM jobs ORDER BY job_id")) {
      records.push({
        key: `job/${row.job_id}`,
        value: {
          jobId: row.job_id,
          state: row.state,
          terminalAtMs: row.terminal_at_ms === null ? null : String(row.terminal_at_ms)
        }
      });
    }
    for (const row of this.#all(`
      SELECT digest, created_at_ms, generation, media_type
      FROM cas_objects
      WHERE media_type NOT IN ('universal-admission-event-receipt','universal-admission-snapshot')
      ORDER BY digest
    `)) {
      const references = this.#all(
        "SELECT reference FROM object_refs WHERE digest = ? ORDER BY reference",
        row.digest
      ).map(({ reference }) => reference);
      records.push({
        key: `object/${row.digest}`,
        value: {
          createdAtMs: String(row.created_at_ms),
          digest: row.digest,
          generation: String(row.generation),
          mediaType: row.media_type,
          references
        }
      });
    }
    return records;
  }

  #validatedSnapshot(snapshotSha256) {
    const sizes = this.#get(`
      SELECT
        length(manifest_json) AS manifest_bytes,
        length(records_json) AS record_bytes,
        length(candidates_json) AS candidate_bytes
      FROM snapshots WHERE snapshot_sha256 = ?
    `, snapshotSha256);
    if (!sizes) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_SNAPSHOT_INVALID", "GC requires an existing committed SQLite snapshot.");
    if (sizes.manifest_bytes > BigInt(UNIVERSAL_ADMISSION_SQLITE_MAX_OBJECT_BYTES)
      || sizes.record_bytes > BigInt(UNIVERSAL_ADMISSION_SQLITE_MAX_SNAPSHOT_RECORD_BYTES)
      || sizes.candidate_bytes > BigInt(UNIVERSAL_ADMISSION_SQLITE_MAX_SNAPSHOT_CANDIDATE_BYTES)) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_SNAPSHOT_INVALID", "Stored SQLite snapshot exceeds its closed byte bounds.");
    }
    const row = this.#get("SELECT * FROM snapshots WHERE snapshot_sha256 = ?", snapshotSha256);
    const manifest = validateUniversalAdmissionSnapshot(parseCanonicalBlob(row.manifest_json));
    const manifestBytes = canonicalProtocolBytes(manifest);
    const object = this.#get("SELECT bytes, media_type FROM cas_objects WHERE digest = ?", snapshotSha256);
    if (sha256Bytes(manifestBytes) !== snapshotSha256
      || !object
      || object.media_type !== "universal-admission-snapshot"
      || !Buffer.from(row.manifest_json).equals(manifestBytes)
      || !Buffer.from(object.bytes).equals(manifestBytes)
      || manifest.serviceAudience !== this.serviceAudience
      || manifest.previousSnapshotSha256 !== row.previous_snapshot_sha256
      || manifest.createdAtMs !== String(row.created_at_ms)) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_SNAPSHOT_INVALID", "Stored SQLite snapshot manifest is not bound to its CAS object and row metadata.");
    }
    const records = parseCanonicalBlob(row.records_json);
    const candidates = parseCanonicalBlob(row.candidates_json);
    if (!Buffer.from(row.records_json).equals(canonicalProtocolBytes(records))
      || !Buffer.from(row.candidates_json).equals(canonicalProtocolBytes(candidates))) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_SNAPSHOT_INVALID", "Stored SQLite snapshot records and candidates must retain canonical bytes.");
    }
    if (!Array.isArray(records) || records.length > UNIVERSAL_ADMISSION_SQLITE_MAX_SNAPSHOT_RECORDS
      || !Array.isArray(candidates) || candidates.length > UNIVERSAL_ADMISSION_SQLITE_MAX_SNAPSHOT_CANDIDATES) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_SNAPSHOT_INVALID", "Stored SQLite snapshot arrays exceed their closed bounds.");
    }
    const seenRecordKeys = new Set();
    let previousRecordKey = null;
    for (const record of records) {
      if (!isExactObject(record, ["key", "value"])
        || seenRecordKeys.has(record.key)
        || (previousRecordKey !== null && compareUtf8(previousRecordKey, record.key) >= 0)) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_SNAPSHOT_INVALID", "Stored SQLite snapshot records must have unique sorted closed keys.");
      }
      validateGcControlSnapshotRecord(record);
      snapshotLeafDigest({ key: record.key, recordSha256: digestProtocolValue(record.value) });
      seenRecordKeys.add(record.key);
      previousRecordKey = record.key;
    }
    let previousDigest = null;
    for (const candidate of candidates) {
      if (!isExactObject(candidate, ["digest", "generation", "reason"])) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_SNAPSHOT_INVALID", "Stored SQLite GC candidate has an open field set.");
      assertDigest(candidate.digest, "snapshot candidate digest");
      parseDecimal(candidate.generation, "snapshot candidate generation", { positive: true });
      if (!GC_CANDIDATE_REASONS.has(candidate.reason)
        || (previousDigest !== null && compareUtf8(previousDigest, candidate.digest) >= 0)) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_SNAPSHOT_INVALID", "Stored SQLite GC candidates must be uniquely digest-sorted with a closed reason.");
      }
      previousDigest = candidate.digest;
    }
    const expectedShards = snapshotShards(records);
    const liveObjectReferences = records
      .filter(({ key }) => key.startsWith("object/"))
      .reduce((total, record) => total + record.value.references.length, 0);
    if (manifest.cutSha256 !== digestProtocolValue(records)
      || manifest.gcCandidatesSha256 !== digestProtocolValue(candidates)
      || manifest.totals.records !== String(records.length)
      || manifest.totals.gcCandidates !== String(candidates.length)
      || manifest.totals.liveObjectReferences !== String(liveObjectReferences)
      || !canonicalProtocolBytes(manifest.shards).equals(canonicalProtocolBytes(expectedShards))) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_SNAPSHOT_INVALID", "Stored SQLite snapshot records or candidates do not match the committed manifest root.");
    }
    if (row.gc_processed_count > BigInt(candidates.length)) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_SNAPSHOT_INVALID", "Stored SQLite GC progress exceeds the immutable candidate count.");
    }
    const processedCount = Number(row.gc_processed_count);
    if ((row.gc_complete === 1n) !== (processedCount === candidates.length)) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_SNAPSHOT_INVALID", "Stored SQLite GC completion flag differs from committed progress.");
    }
    return { candidates, manifest, records };
  }

  #pruneCompletedSnapshots() {
    let count = this.#get("SELECT count(*) AS count FROM snapshots").count;
    while (count >= BigInt(UNIVERSAL_ADMISSION_SQLITE_MAX_SNAPSHOTS)) {
      const cutoff = this.#now() - BigInt(this.policy.commandReplayRetentionMs);
      const row = this.#get(`
        SELECT snapshot_sha256 FROM snapshots
        WHERE gc_complete = 1
          AND created_at_ms <= ?
          AND snapshot_sha256 <> (SELECT snapshot_head FROM admission_meta WHERE singleton = 1)
        ORDER BY created_at_ms, snapshot_sha256
        LIMIT 1
      `, cutoff);
      if (!row) protocolFail("UNIVERSAL_ADMISSION_SQLITE_SNAPSHOT_CAPACITY", "SQLite snapshot retention capacity is exhausted; complete GC or wait for replay retention before retrying.", { retryable: true });
      const object = this.#get("SELECT byte_length FROM cas_objects WHERE digest = ?", row.snapshot_sha256);
      this.#run("DELETE FROM snapshots WHERE snapshot_sha256 = ?", row.snapshot_sha256);
      if (object) {
        this.#run("DELETE FROM cas_objects WHERE digest = ?", row.snapshot_sha256);
        this.#run("UPDATE admission_meta SET cas_bytes = cas_bytes - ? WHERE singleton = 1", object.byte_length);
      }
      count -= 1n;
    }
  }

  #gcCandidates() {
    const now = this.#now();
    const result = this.#all(`
      SELECT
        object.digest,
        object.generation,
        CASE
          WHEN NOT EXISTS (SELECT 1 FROM object_refs reference WHERE reference.digest = object.digest)
            THEN 'orphan'
          ELSE 'terminal-payload'
        END AS reason
      FROM cas_objects object
      WHERE object.media_type NOT IN ('universal-admission-event-receipt','universal-admission-snapshot')
        AND (
          (
            NOT EXISTS (SELECT 1 FROM object_refs reference WHERE reference.digest = object.digest)
            AND ? - object.created_at_ms >= ?
          )
          OR (
            EXISTS (SELECT 1 FROM object_refs reference WHERE reference.digest = object.digest)
            AND NOT EXISTS (
              SELECT 1
              FROM object_refs reference
              LEFT JOIN jobs job ON job.job_id = reference.job_id
              WHERE reference.digest = object.digest
                AND (
                  reference.job_id IS NULL
                  OR job.job_id IS NULL
                  OR job.terminal_at_ms IS NULL
                  OR job.state NOT IN ('processing-completed','dead-lettered')
                  OR (job.state = 'processing-completed' AND ? - job.terminal_at_ms < ?)
                  OR (job.state = 'dead-lettered' AND ? - job.terminal_at_ms < ?)
                )
            )
          )
        )
      ORDER BY digest
      LIMIT ?
    `,
    now, BigInt(this.policy.orphanRetentionMs),
    now, BigInt(this.policy.terminalPayloadRetentionMs),
    now, BigInt(this.policy.deadLetterPayloadRetentionMs),
    BigInt(UNIVERSAL_ADMISSION_SQLITE_MAX_SNAPSHOT_CANDIDATES + 1));
    if (result.length > UNIVERSAL_ADMISSION_SQLITE_MAX_SNAPSHOT_CANDIDATES) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_LIMIT_INVALID", "SQLite snapshot candidate bound is exceeded before full materialization.");
    }
    return result.map(({ digest, generation, reason }) => ({ digest, generation: String(generation), reason }));
  }

  #currentlyGcEligible(digest, reason) {
    const object = this.#get("SELECT created_at_ms FROM cas_objects WHERE digest = ?", digest);
    if (!object) return false;
    const now = this.#now();
    if (reason === "orphan") {
      return now - object.created_at_ms >= BigInt(this.policy.orphanRetentionMs)
        && !this.#get("SELECT 1 AS present FROM object_refs WHERE digest = ? LIMIT 1", digest);
    }
    if (reason !== "terminal-payload") return false;
    const eligibility = this.#get(`
      SELECT
        EXISTS(SELECT 1 FROM object_refs WHERE digest = ?) AS has_refs,
        NOT EXISTS (
          SELECT 1
          FROM object_refs reference
          LEFT JOIN jobs job ON job.job_id = reference.job_id
          WHERE reference.digest = ?
            AND (
              reference.job_id IS NULL
              OR job.job_id IS NULL
              OR job.terminal_at_ms IS NULL
              OR job.state NOT IN ('processing-completed','dead-lettered')
              OR (job.state = 'processing-completed' AND ? - job.terminal_at_ms < ?)
              OR (job.state = 'dead-lettered' AND ? - job.terminal_at_ms < ?)
            )
        ) AS all_expired
    `,
    digest,
    digest,
    now, BigInt(this.policy.terminalPayloadRetentionMs),
    now, BigInt(this.policy.deadLetterPayloadRetentionMs));
    return eligibility.has_refs === 1n && eligibility.all_expired === 1n;
  }

  #expireDurableCommands() {
    const now = this.#now();
    const totals = this.#get(`
      SELECT count(*) AS count, coalesce(sum(response_bytes), 0) AS bytes
      FROM durable_commands WHERE expires_at_ms <= ?
    `, now);
    if (totals.count === 0n) return;
    const tenants = this.#all(`
      SELECT tenant_id, count(*) AS count, sum(response_bytes) AS bytes
      FROM durable_commands
      WHERE expires_at_ms <= ? AND tenant_id IS NOT NULL
      GROUP BY tenant_id
      ORDER BY tenant_id
    `, now);
    this.#run("DELETE FROM durable_commands WHERE expires_at_ms <= ?", now);
    this.#run(`
      UPDATE admission_meta SET
        durable_command_count = durable_command_count - ?,
        durable_command_bytes = durable_command_bytes - ?
      WHERE singleton = 1
    `, totals.count, totals.bytes);
    for (const tenant of tenants) {
      this.#run(`
        UPDATE tenants SET
          replay_record_count = replay_record_count - ?,
          replay_bytes = replay_bytes - ?
        WHERE tenant_id = ?
      `, tenant.count, tenant.bytes, tenant.tenant_id);
    }
  }

  #assertDurableCommandCapacity({ byteLength, tenantId }) {
    const meta = this.#meta();
    if (meta.durable_command_count + 1n > BigInt(this.policy.maxDurableCommands)) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_DURABLE_COMMAND_CAPACITY", "SQLite durable command replay row capacity is exhausted.", { retryable: true, retryAfterMs: this.#durableRetryAfterMs() });
    }
    if (meta.durable_command_bytes + byteLength > BigInt(this.policy.maxDurableCommandBytes)) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_DURABLE_COMMAND_BYTE_CAPACITY", "SQLite durable command replay byte capacity is exhausted.", { retryable: true, retryAfterMs: this.#durableRetryAfterMs() });
    }
    if (tenantId !== null) {
      const tenant = this.#get("SELECT replay_record_count, replay_bytes FROM tenants WHERE tenant_id = ?", tenantId);
      if (!tenant || tenant.replay_record_count + 1n > BigInt(this.policy.maxTenantReplayRecords)) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_TENANT_REPLAY_CAPACITY", "SQLite tenant replay row capacity is exhausted.", { retryable: true, retryAfterMs: this.#tenantReplayRetryAfterMs(tenantId) });
      }
      if (tenant.replay_bytes + byteLength > BigInt(this.policy.maxTenantReplayBytes)) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_TENANT_REPLAY_BYTE_CAPACITY", "SQLite tenant replay byte capacity is exhausted.", { retryable: true, retryAfterMs: this.#tenantReplayRetryAfterMs(tenantId) });
      }
    }
  }

  #assertGlobalDurableCommandReservation() {
    const meta = this.#meta();
    const minimum = BigInt(MIN_UNIVERSAL_ADMISSION_DURABLE_RESPONSE_RESERVATION_BYTES);
    if (meta.durable_command_count + 1n > BigInt(this.policy.maxDurableCommands)) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_DURABLE_COMMAND_CAPACITY", "SQLite durable command replay row capacity is exhausted.", { retryable: true, retryAfterMs: this.#durableRetryAfterMs() });
    }
    if (meta.durable_command_bytes + minimum > BigInt(this.policy.maxDurableCommandBytes)) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_DURABLE_COMMAND_BYTE_CAPACITY", "SQLite durable command replay byte reservation is exhausted.", { retryable: true, retryAfterMs: this.#durableRetryAfterMs() });
    }
  }

  #assertTenantReplayReservation(tenantId) {
    const tenant = this.#get("SELECT replay_record_count, replay_bytes FROM tenants WHERE tenant_id = ?", tenantId);
    const minimum = BigInt(MIN_UNIVERSAL_ADMISSION_DURABLE_RESPONSE_RESERVATION_BYTES);
    if (!tenant || tenant.replay_record_count + 1n > BigInt(this.policy.maxTenantReplayRecords)) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_TENANT_REPLAY_CAPACITY", "SQLite tenant replay row capacity is exhausted.", { retryable: true, retryAfterMs: this.#tenantReplayRetryAfterMs(tenantId) });
    }
    if (tenant.replay_bytes + minimum > BigInt(this.policy.maxTenantReplayBytes)) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_TENANT_REPLAY_BYTE_CAPACITY", "SQLite tenant replay byte reservation is exhausted.", { retryable: true, retryAfterMs: this.#tenantReplayRetryAfterMs(tenantId) });
    }
  }

  #durableRetryAfterMs() {
    const row = this.#get("SELECT min(expires_at_ms) AS expires_at_ms FROM durable_commands");
    return row?.expires_at_ms === null || row?.expires_at_ms === undefined
      ? null
      : String(maximum(1n, row.expires_at_ms - this.#now()));
  }

  #tenantReplayRetryAfterMs(tenantId) {
    const row = this.#get("SELECT min(expires_at_ms) AS expires_at_ms FROM durable_commands WHERE tenant_id = ?", tenantId);
    return row?.expires_at_ms === null || row?.expires_at_ms === undefined
      ? null
      : String(maximum(1n, row.expires_at_ms - this.#now()));
  }

  #commandTransaction({
    actorKey,
    authenticatedRequestByteLength = null,
    commandId,
    commandKind,
    principalKey = actorKey,
    principalMismatchCode = "UNIVERSAL_ADMISSION_PROTOCOL_COMMAND_REPLAY_CONFLICT",
    replayConflictCode = "UNIVERSAL_ADMISSION_PROTOCOL_COMMAND_REPLAY_CONFLICT",
    requestValue,
    precondition = null,
    beforeOperation = null,
    tenantId = null
  }, operation) {
    const normalized = normalizeCommandId(commandId);
    const requestBinding = deriveUniversalAdmissionDurableCommandRequestBinding({
      actorKey,
      commandId: normalized,
      commandKind,
      requestValue,
      serviceAudience: this.serviceAudience
    });
    const requestBytes = canonicalProtocolBytes(requestBinding.requestPreimage);
    if (requestBytes.length > UNIVERSAL_ADMISSION_SQLITE_MAX_DURABLE_REQUEST_BYTES) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_COMMAND_REQUEST_INVALID", "SQLite durable command request preimage exceeds its fixed byte bound.");
    }
    const effectiveRequestSha256 = requestBinding.requestSha256;
    const outcome = this.#transaction(() => {
      this.#expireDurableCommands();
      const existing = this.#get("SELECT * FROM durable_commands WHERE actor_key = ? AND command_id = ?", actorKey, normalized);
      if (existing) {
        if (existing.command_kind !== commandKind
          || existing.tenant_id !== tenantId
          || existing.authenticated_request_bytes !== authenticatedRequestByteLength) {
          protocolFail(replayConflictCode, "Command id is already bound to another command kind, tenant, or ingress byte count.");
        }
        if (existing.request_sha256 !== effectiveRequestSha256) protocolFail(replayConflictCode, "Command id is already bound to different request bytes.");
        if (existing.principal_key !== principalKey) protocolFail(principalMismatchCode, "Command id is already bound to another authenticated principal.");
        if (!Buffer.from(existing.request_json).equals(requestBytes)) protocolFail(replayConflictCode, "Command id is already bound to a different canonical request preimage.");
        this.#assertDurableRow(existing);
        if (existing.outcome_kind === "error") {
          return { error: decodeProtocolError(parseCanonicalBlob(existing.response_json)), response: null };
        }
        return { error: null, response: freeze(decodeResponse(parseCanonicalBlob(existing.response_json))) };
      }
      this.#assertGlobalDurableCommandReservation();
      if (beforeOperation !== null) beforeOperation();
      let operationError = null;
      let response = null;
      let successfulResponseBytes = null;
      this.db.exec("SAVEPOINT universal_admission_command_operation");
      try {
        response = operation();
        const candidateResponseBytes = canonicalProtocolBytes(encodeResponse(response));
        this.#assertDurableCommandCapacity({ byteLength: BigInt(candidateResponseBytes.length), tenantId });
        successfulResponseBytes = candidateResponseBytes;
      } catch (error) {
        operationError = error;
      }
      if (operationError === null) {
        this.db.exec("RELEASE universal_admission_command_operation");
      } else {
        this.db.exec("ROLLBACK TO universal_admission_command_operation");
        this.db.exec("RELEASE universal_admission_command_operation");
        if (!isDurableProtocolRejection(operationError, commandKind)) throw operationError;
      }
      const outcomeKind = operationError === null ? "success" : "error";
      const storedOutcome = operationError === null ? encodeResponse(response) : encodeProtocolError(operationError);
      if (operationError !== null) {
        validateUniversalAdmissionDurableCommandFailure({ commandKind, failure: storedOutcome });
      }
      const responseBytes = successfulResponseBytes ?? canonicalProtocolBytes(storedOutcome);
      if (operationError !== null && responseBytes.length > MIN_UNIVERSAL_ADMISSION_DURABLE_RESPONSE_RESERVATION_BYTES) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable protocol rejection exceeds its reserved byte boundary.");
      }
      if (operationError !== null) this.#assertDurableCommandCapacity({ byteLength: BigInt(responseBytes.length), tenantId });
      const now = this.#now();
      const expiresAtMs = addTimestamp(now, BigInt(this.policy.commandReplayRetentionMs), "durable command expiry");
      const effectKeys = operationError === null
        ? deriveUniversalAdmissionDurableCommandEffectKeys({
          commandKind,
          requestValue: requestBinding.requestValue,
          response
        })
        : emptyDurableEffectKeys();
      const effectBytes = canonicalProtocolBytes(effectKeys);
      if (effectBytes.length > UNIVERSAL_ADMISSION_SQLITE_MAX_DURABLE_EFFECT_BYTES) {
        protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "SQLite durable command effect keys exceed their fixed byte bound.");
      }
      const durableRow = {
        actor_key: actorKey,
        authenticated_request_bytes: authenticatedRequestByteLength,
        command_id: normalized,
        command_kind: commandKind,
        created_at_ms: now,
        effect_keys_sha256: sha256Bytes(effectBytes),
        expires_at_ms: expiresAtMs,
        outcome_kind: outcomeKind,
        principal_key: principalKey,
        request_sha256: effectiveRequestSha256,
        response_sha256: sha256Bytes(responseBytes),
        tenant_id: tenantId
      };
      this.#run(`
        INSERT INTO durable_commands (
          actor_key, principal_key, tenant_id, command_id, command_kind,
          request_sha256, request_json, request_bytes, authenticated_request_bytes,
          outcome_kind, response_json, response_sha256, response_bytes,
          effect_keys_json, effect_keys_sha256, effect_keys_bytes, record_binding_sha256,
          created_at_ms, expires_at_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      actorKey, principalKey, tenantId, normalized, commandKind,
      effectiveRequestSha256, requestBytes, BigInt(requestBytes.length), authenticatedRequestByteLength,
      outcomeKind, responseBytes, durableRow.response_sha256, BigInt(responseBytes.length),
      effectBytes, durableRow.effect_keys_sha256, BigInt(effectBytes.length),
      this.#durableRecordBindingSha256(durableRow), now, expiresAtMs);
      this.#run(`
        UPDATE admission_meta SET
          durable_command_count = durable_command_count + 1,
          durable_command_bytes = durable_command_bytes + ?
        WHERE singleton = 1
      `, BigInt(responseBytes.length));
      if (tenantId !== null) {
        this.#run(`
          UPDATE tenants SET
            replay_record_count = replay_record_count + 1,
          replay_bytes = replay_bytes + ?
        WHERE tenant_id = ?
      `, BigInt(responseBytes.length), tenantId);
      }
      return operationError === null
        ? { error: null, response }
        : { error: operationError, response: null };
    }, { beforeMutation: precondition });
    if (outcome.error !== null) throw outcome.error;
    return outcome.response;
  }

  #transaction(operation, { beforeMutation = null } = {}) {
    this.#assertOpen();
    for (let attempt = 0; attempt <= MAX_BUSY_RETRIES; attempt += 1) {
      let begun = false;
      try {
        this.db.exec("BEGIN IMMEDIATE");
        begun = true;
        if (beforeMutation !== null) beforeMutation();
        if (this.wallClock && this.initialized) {
          const wallNow = BigInt(Date.now());
          this.#run("UPDATE admission_meta SET now_ms = ? WHERE singleton = 1 AND now_ms < ?", wallNow, wallNow);
        }
        const result = operation();
        this.db.exec("COMMIT");
        return result;
      } catch (error) {
        if (begun) {
          try { this.db.exec("ROLLBACK"); } catch {}
        }
        if (isBusy(error) && attempt < MAX_BUSY_RETRIES) {
          Atomics.wait(SLEEP_ARRAY, 0, 0, 4 + attempt * 7);
          continue;
        }
        if (isBusy(error)) throw new UniversalAdmissionProtocolError("UNIVERSAL_ADMISSION_SQLITE_BUSY", "SQLite writer is temporarily busy.", { retryable: true, retryAfterMs: "50" });
        if (isFull(error)) throw new UniversalAdmissionProtocolError("UNIVERSAL_ADMISSION_SQLITE_DATABASE_CAPACITY", "SQLite database hard byte capacity is exhausted.", { retryable: true });
        throw error;
      }
    }
    throw new UniversalAdmissionProtocolError("UNIVERSAL_ADMISSION_SQLITE_BUSY", "SQLite writer is temporarily busy.", { retryable: true, retryAfterMs: "50" });
  }

  #retryBusy(operation) {
    for (let attempt = 0; attempt <= MAX_BUSY_RETRIES; attempt += 1) {
      try {
        return operation();
      } catch (error) {
        if (isBusy(error) && attempt < MAX_BUSY_RETRIES) {
          Atomics.wait(SLEEP_ARRAY, 0, 0, 4 + attempt * 7);
          continue;
        }
        if (isBusy(error)) throw new UniversalAdmissionProtocolError("UNIVERSAL_ADMISSION_SQLITE_BUSY", "SQLite writer is temporarily busy.", { retryable: true, retryAfterMs: "50" });
        if (isFull(error)) throw new UniversalAdmissionProtocolError("UNIVERSAL_ADMISSION_SQLITE_DATABASE_CAPACITY", "SQLite database hard byte capacity is exhausted.", { retryable: true });
        throw error;
      }
    }
    throw new UniversalAdmissionProtocolError("UNIVERSAL_ADMISSION_SQLITE_BUSY", "SQLite writer is temporarily busy.", { retryable: true, retryAfterMs: "50" });
  }

  #readTransaction(operation) {
    this.#assertOpen();
    let begun = false;
    try {
      this.db.exec("BEGIN");
      begun = true;
      const result = operation();
      this.db.exec("COMMIT");
      return result;
    } catch (error) {
      if (begun) {
        try { this.db.exec("ROLLBACK"); } catch {}
      }
      throw error;
    }
  }

  #meta() {
    return this.#get("SELECT * FROM admission_meta WHERE singleton = 1");
  }

  #now() {
    return this.#meta().now_ms;
  }

  #assertServiceAudience(audience) {
    if (audience !== this.serviceAudience) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_AUDIENCE_MISMATCH", "Authenticated principal or worker audience does not match this SQLite queue.");
    }
  }

  #get(sql, ...parameters) {
    return this.db.prepare(sql).get(...parameters);
  }

  #all(sql, ...parameters) {
    return this.db.prepare(sql).all(...parameters);
  }

  #run(sql, ...parameters) {
    return this.db.prepare(sql).run(...parameters);
  }

  #assertOpen() {
    if (this.db === null) protocolFail("UNIVERSAL_ADMISSION_SQLITE_CLOSED", "SQLite admission store is closed.");
  }
}

function prepareSecureDatabasePath(value) {
  if (typeof value !== "string" || value.length < 1 || Buffer.byteLength(value, "utf8") > 3072 || value.includes("\u0000") || !path.isAbsolute(value)) {
    protocolFail("UNIVERSAL_ADMISSION_SQLITE_PATH_INVALID", "SQLite path must be a bounded absolute filesystem path.");
  }
  const resolved = path.resolve(value);
  if (resolved !== value) protocolFail("UNIVERSAL_ADMISSION_SQLITE_PATH_INVALID", "SQLite path must already be normalized.");
  const parent = path.dirname(resolved);
  let parentStat;
  try {
    parentStat = fs.lstatSync(parent, { bigint: true });
  } catch (error) {
    protocolFail("UNIVERSAL_ADMISSION_SQLITE_PATH_INVALID", "SQLite parent directory does not exist.", { cause: error });
  }
  if (parentStat.isSymbolicLink() || !parentStat.isDirectory() || (parentStat.mode & 0o077n) !== 0n) {
    protocolFail("UNIVERSAL_ADMISSION_SQLITE_PATH_INVALID", "SQLite parent must be a private non-symlink directory.");
  }
  if (typeof process.getuid === "function" && parentStat.uid !== BigInt(process.getuid())) {
    protocolFail("UNIVERSAL_ADMISSION_SQLITE_PATH_INVALID", "SQLite parent must be owned by the service uid.");
  }
  try {
    const stat = fs.lstatSync(resolved, { bigint: true });
    if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1n || (stat.mode & 0o077n) !== 0n) {
      protocolFail("UNIVERSAL_ADMISSION_SQLITE_PATH_INVALID", "Existing SQLite database must be one private regular file.");
    }
    if (typeof process.getuid === "function" && stat.uid !== BigInt(process.getuid())) protocolFail("UNIVERSAL_ADMISSION_SQLITE_PATH_INVALID", "SQLite database must be owned by the service uid.");
  } catch (error) {
    if (error instanceof UniversalAdmissionProtocolError) throw error;
    if (error?.code !== "ENOENT") protocolFail("UNIVERSAL_ADMISSION_SQLITE_PATH_INVALID", "SQLite database path could not be inspected.", { cause: error });
    const flags = fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_RDWR | noFollowFlag() | closeOnExecFlag();
    let descriptor;
    try {
      descriptor = fs.openSync(resolved, flags, 0o600);
      fs.fsyncSync(descriptor);
    } catch (cause) {
      protocolFail("UNIVERSAL_ADMISSION_SQLITE_PATH_INVALID", "SQLite database could not be created securely.", { cause });
    } finally {
      if (descriptor !== undefined) fs.closeSync(descriptor);
    }
    fsyncDirectory(parent);
  }
  return resolved;
}

function rowToJob(row) {
  return {
    admissionDigest: row.admission_digest,
    applicationId: row.application_id,
    attempt: row.attempt,
    availableAtMs: row.available_at_ms,
    cycle: row.cycle,
    enqueueOrdinal: row.enqueue_ordinal,
    eventIndex: row.event_index,
    fenceToken: row.fence_token,
    firstReceiptSha256: row.first_receipt_sha256,
    headReceiptSha256: row.head_receipt_sha256,
    jobId: row.job_id,
    idempotencyKey: row.idempotency_key,
    lease: row.lease_json === null ? null : parseCanonicalBlob(row.lease_json),
    objectGeneration: row.object_generation,
    redrives: row.redrives,
    resultSha256: row.result_sha256,
    revision: row.revision,
    revisionBindingSha256: row.revision_binding_sha256,
    revisionKey: row.revision_key,
    state: row.state,
    tenantId: row.tenant_id,
    terminalAtMs: row.terminal_at_ms
  };
}

function leaseBytes(value) {
  return value === null ? null : canonicalProtocolBytes(value);
}

function validateObjectBytes(bytes, mediaType) {
  if (!SAFE_MEDIA_TYPES.has(mediaType)) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_OBJECT_INVALID", "SQLite CAS media type is outside the protocol contract.");
  return snapshotBoundedBytes(bytes, "SQLite CAS object");
}

function snapshotBoundedBytes(value, label) {
  if (!(value instanceof Uint8Array) || types.isProxy(value)) {
    protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_OBJECT_INVALID", `${label} must be a non-proxy byte array within the closed 256 KiB boundary.`);
  }
  let arrayBuffer;
  let byteLength;
  let byteOffset;
  try {
    arrayBuffer = Reflect.apply(TYPED_ARRAY_BUFFER, value, []);
    byteLength = Reflect.apply(TYPED_ARRAY_BYTE_LENGTH, value, []);
    byteOffset = Reflect.apply(TYPED_ARRAY_BYTE_OFFSET, value, []);
  } catch (cause) {
    protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_OBJECT_INVALID", `${label} byte extent could not be read intrinsically.`, { cause });
  }
  if (byteLength < 1 || byteLength > UNIVERSAL_ADMISSION_SQLITE_MAX_OBJECT_BYTES) {
    protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_OBJECT_INVALID", `${label} must be within the closed 256 KiB boundary.`);
  }
  let snapshot;
  try {
    snapshot = Buffer.from(new Uint8Array(arrayBuffer, byteOffset, byteLength));
  } catch (cause) {
    protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_OBJECT_INVALID", `${label} could not be snapshotted.`, { cause });
  }
  if (snapshot.length !== byteLength || snapshot.length < 1 || snapshot.length > UNIVERSAL_ADMISSION_SQLITE_MAX_OBJECT_BYTES) {
    protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_OBJECT_INVALID", `${label} changed while being snapshotted.`);
  }
  return snapshot;
}

function parseCanonicalBlob(value) {
  const buffer = Buffer.from(value);
  let parsed;
  try { parsed = JSON.parse(buffer.toString("utf8")); } catch (error) {
    protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "Stored SQLite JSON is invalid.", { cause: error });
  }
  if (!canonicalProtocolBytes(parsed).equals(buffer)) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "Stored SQLite JSON is not canonical.");
  return parsed;
}

function reservedMediaTypeForBytes(bytes) {
  let value;
  try {
    value = JSON.parse(Buffer.from(bytes).toString("utf8"));
  } catch {
    return null;
  }
  return Object.hasOwn(RESERVED_MEDIA_TYPE_BY_KIND, value?.kind)
    ? RESERVED_MEDIA_TYPE_BY_KIND[value.kind]
    : null;
}

function validateReservedProtocolObject(bytes, mediaType) {
  if (reservedMediaTypeForBytes(bytes) !== mediaType) {
    protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_CAS_MEDIA_TYPE_CONFLICT", "Reserved SQLite CAS bytes do not match their declared protocol media type.");
  }
  if (mediaType === "universal-admission-envelope") {
    validateUniversalAdmissionBytes(bytes);
    return;
  }
  if (mediaType === "universal-admission-worker-result") {
    parseUniversalAdmissionWorkerResultBytes(bytes);
    return;
  }
  const value = parseCanonicalBlob(bytes);
  if (mediaType === "universal-admission-event-receipt") {
    validateUniversalAdmissionEventReceipt(value);
    return;
  }
  if (mediaType === "universal-admission-snapshot") {
    validateUniversalAdmissionSnapshot(value);
    return;
  }
  protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_RESERVED_MEDIA_FORBIDDEN", "Unknown reserved SQLite protocol media type.");
}

function encodeResponse(value) {
  if (value instanceof Uint8Array) return { $bytesBase64: Buffer.from(value).toString("base64") };
  if (Array.isArray(value)) return value.map(encodeResponse);
  if (value !== null && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, encodeResponse(child)]));
  return value;
}

function decodeResponse(value) {
  if (Array.isArray(value)) return value.map(decodeResponse);
  if (value !== null && typeof value === "object") {
    if (Object.keys(value).length === 1 && typeof value.$bytesBase64 === "string") return Buffer.from(value.$bytesBase64, "base64");
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, decodeResponse(child)]));
  }
  return value;
}

function emptyDurableEffectKeys() {
  return Object.freeze({
    jobIds: Object.freeze([]),
    receiptSha256s: Object.freeze([]),
    resultSha256s: Object.freeze([]),
    snapshotSha256s: Object.freeze([])
  });
}

function encodeProtocolError(error) {
  return {
    code: error.code,
    path: error.path ?? null,
    retryAfterMs: error.retryAfterMs ?? null,
    retryable: error.retryable ?? false
  };
}

function decodeProtocolError(value) {
  if (!isExactObject(value, ["code", "path", "retryAfterMs", "retryable"])
    || typeof value.code !== "string"
    || !(value.path === null || typeof value.path === "string")
    || !(value.retryAfterMs === null || typeof value.retryAfterMs === "string")
    || typeof value.retryable !== "boolean") {
    protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_ATOMICITY_VIOLATION", "Stored durable protocol rejection is invalid.");
  }
  return new UniversalAdmissionProtocolError(value.code, `Durable replay of ${value.code}.`, {
    path: value.path,
    retryAfterMs: value.retryAfterMs,
    retryable: value.retryable
  });
}

function isDurableProtocolRejection(error, commandKind) {
  return error instanceof UniversalAdmissionProtocolError
    && isUniversalAdmissionDurableCommandFailureCode({ commandKind, code: error.code });
}

function normalizeCommandId(value) {
  return validateUniversalAdmissionCommandId(value);
}

function normalizeDigest(value, label) {
  assertDigest(value, label);
  return value;
}

function normalizeFenceToken(value) {
  let stable;
  try {
    stable = String(value);
  } catch (cause) {
    protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_DECIMAL_INVALID", "fenceToken could not be normalized.", { cause });
  }
  parseDecimal(stable, "fenceToken", { positive: true });
  return stable;
}

function parseDecimal(value, label, { positive = false } = {}) {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]*)$/u.test(value)) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_DECIMAL_INVALID", `${label} must be a decimal string.`);
  const result = BigInt(value);
  if (positive && result === 0n) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_DECIMAL_INVALID", `${label} must be positive.`);
  if (result > 9_223_372_036_854_775_807n) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_DECIMAL_INVALID", `${label} exceeds signed 64-bit SQLite range.`);
  return result;
}

function parseTimestamp(value, label) {
  const result = parseDecimal(value, label);
  if (result > MAX_PROTOCOL_TIMESTAMP) {
    protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_CLOCK_INVALID", `${label} exceeds the closed protocol timestamp range.`);
  }
  return result;
}

function addTimestamp(value, delta, label) {
  const result = value + delta;
  if (result > MAX_PROTOCOL_TIMESTAMP) {
    protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_CLOCK_INVALID", `${label} exceeds the closed protocol timestamp range.`);
  }
  return result;
}

function assertOperationalClock(value, policy) {
  addTimestamp(value, BigInt(policy.commandReplayRetentionMs), "SQLite command replay horizon");
}

function validateServiceAudience(value) {
  return validateUniversalAdmissionServiceAudience(value);
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !DIGEST.test(value)) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_DIGEST_INVALID", `${label} must be a lowercase sha256 digest.`);
}

function validateBatchLimit(value, maximum, label) {
  if (!Number.isInteger(value) || value < 1 || value > maximum) protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_LIMIT_INVALID", `${label} limit must be 1..${maximum}.`);
}

function windowStart(now, size) {
  return (now / size) * size;
}

function maximum(left, right) {
  return left > right ? left : right;
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function snapshotShards(records) {
  const leavesByPrefix = new Map();
  for (const record of records) {
    const recordSha256 = digestProtocolValue(record.value);
    const keyDigest = digestProtocolValue({ key: record.key });
    const prefix = keyDigest.slice(7, 9);
    const leaf = snapshotLeafDigest({ key: record.key, recordSha256 });
    if (!leavesByPrefix.has(prefix)) leavesByPrefix.set(prefix, []);
    leavesByPrefix.get(prefix).push({ key: record.key, leaf });
  }
  return [...leavesByPrefix.entries()]
    .sort(([left], [right]) => compareUtf8(left, right))
    .map(([prefix, entries]) => {
      entries.sort((left, right) => compareUtf8(left.key, right.key));
      return {
        prefix,
        recordCount: String(entries.length),
        rootSha256: snapshotShardDigest({ leafDigests: entries.map(({ leaf }) => leaf), prefix })
      };
    });
}

function isExactObject(value, keys) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) return false;
  const actual = Object.keys(value).sort(compareUtf8);
  const expected = [...keys].sort(compareUtf8);
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function validateGcControlSnapshotRecord(record) {
  if (record.key.startsWith("job/")) {
    if (!isExactObject(record.value, ["jobId", "state", "terminalAtMs"])) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_SNAPSHOT_INVALID", "GC-control job record has an open field set.");
    }
    assertDigest(record.value.jobId, "snapshot job id");
    if (record.key !== `job/${record.value.jobId}`
      || (!ACTIVE_STATES.has(record.value.state) && !TERMINAL_STATES.has(record.value.state))
      || (TERMINAL_STATES.has(record.value.state) !== (record.value.terminalAtMs !== null))) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_SNAPSHOT_INVALID", "GC-control job record identity, state, or terminal time is invalid.");
    }
    if (record.value.terminalAtMs !== null) parseDecimal(record.value.terminalAtMs, "snapshot job terminalAtMs");
    return;
  }
  if (!record.key.startsWith("object/")
    || !isExactObject(record.value, ["createdAtMs", "digest", "generation", "mediaType", "references"])) {
    protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_SNAPSHOT_INVALID", "GC-control object record has an invalid key or open field set.");
  }
  assertDigest(record.value.digest, "snapshot object digest");
  if (record.key !== `object/${record.value.digest}`
    || !SAFE_MEDIA_TYPES.has(record.value.mediaType)
    || record.value.mediaType === "universal-admission-event-receipt"
    || record.value.mediaType === "universal-admission-snapshot") {
    protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_SNAPSHOT_INVALID", "GC-control object identity or media type is invalid.");
  }
  parseDecimal(record.value.createdAtMs, "snapshot object createdAtMs");
  parseDecimal(record.value.generation, "snapshot object generation", { positive: true });
  if (!Array.isArray(record.value.references)) {
    protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_SNAPSHOT_INVALID", "GC-control object references must be a closed array.");
  }
  let previous = null;
  for (const reference of record.value.references) {
    if (typeof reference !== "string"
      || Buffer.byteLength(reference, "utf8") < 1
      || Buffer.byteLength(reference, "utf8") > 512
      || /[\u0000\r\n]/u.test(reference)
      || (previous !== null && compareUtf8(previous, reference) >= 0)) {
      protocolFail("UNIVERSAL_ADMISSION_PROTOCOL_SNAPSHOT_INVALID", "GC-control object references must be bounded, unique, and sorted.");
    }
    previous = reference;
  }
}

function authorityFalse() {
  return {
    admissionDecisionGranted: false,
    approvalGranted: false,
    auditCompleted: false,
    deploymentPerformed: false,
    fundMovementAuthorized: false,
    fundMovementPerformed: false,
    independentAudit: false,
    launchAuthorized: false,
    repositoryOwnershipProven: false,
    reviewCompleted: false,
    safetyCertified: false,
    safetyGuaranteed: false
  };
}

function freeze(value) {
  return Object.freeze(structuredClone(value));
}

function isBusy(error) {
  return error?.code === "ERR_SQLITE_ERROR" && error?.errcode === BUSY_ERRCODE;
}

function isFull(error) {
  return error?.code === "ERR_SQLITE_ERROR" && error?.errcode === FULL_ERRCODE;
}

function assertSupportedNode() {
  const [major, minor] = process.versions.node.split(".").map(Number);
  if (major < UNIVERSAL_ADMISSION_SQLITE_MINIMUM_NODE.major
    || (major === UNIVERSAL_ADMISSION_SQLITE_MINIMUM_NODE.major && minor < UNIVERSAL_ADMISSION_SQLITE_MINIMUM_NODE.minor)) {
    protocolFail("UNIVERSAL_ADMISSION_SQLITE_NODE_UNSUPPORTED", "SQLite reference backend requires Node.js 24.12 or later.");
  }
}

function noFollowFlag() {
  return Number.isInteger(fs.constants.O_NOFOLLOW) ? fs.constants.O_NOFOLLOW : 0;
}

function closeOnExecFlag() {
  return Number.isInteger(fs.constants.O_CLOEXEC) ? fs.constants.O_CLOEXEC : 0;
}

function fsyncDirectory(directory) {
  let descriptor;
  try {
    descriptor = fs.openSync(directory, fs.constants.O_RDONLY | closeOnExecFlag());
    fs.fsyncSync(descriptor);
  } catch (error) {
    protocolFail("UNIVERSAL_ADMISSION_SQLITE_PATH_INVALID", "SQLite parent directory could not be durability-synced.", { cause: error });
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function protocolFail(code, message, options) {
  throw new UniversalAdmissionProtocolError(code, message, options);
}
