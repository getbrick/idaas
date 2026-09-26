import { createHash } from "node:crypto";
import {
  complianceIdempotencyKeyReused,
  complianceIdempotencyRequestInProgress,
  complianceInvalidIdempotencyKey,
  complianceStorageUnavailable,
  complianceValidationError,
} from "./errors.js";
import {
  cloneComplianceValue,
  normalizeComplianceTenantId,
  requireComplianceIdentifier,
} from "./validation.js";
import type { ComplianceDependencyReadiness } from "./types.js";

export const COMPLIANCE_IDEMPOTENCY_MIN_RETENTION_MS = 60_000;
export const COMPLIANCE_IDEMPOTENCY_MAX_RETENTION_MS = 604_800_000;
export const COMPLIANCE_IDEMPOTENCY_DEFAULT_RETENTION_MS = 86_400_000;
export const COMPLIANCE_IDEMPOTENCY_MIN_ENTRIES = 100;
export const COMPLIANCE_IDEMPOTENCY_MAX_ENTRIES = 100_000;
export const COMPLIANCE_IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/u;

export interface ComplianceIdempotencyScope {
  readonly tenantId: string;
  readonly actorId: string;
  readonly operation: string;
  readonly key: string;
}

export interface ComplianceIdempotencyEntry {
  readonly scope: ComplianceIdempotencyScope;
  readonly requestHash: string;
  readonly value: unknown;
  readonly createdAt: string;
}

export interface ComplianceIdempotencyRecord extends ComplianceIdempotencyEntry {
  readonly expiresAt: string;
}

export interface ComplianceIdempotencyPort {
  readonly productionReady?: boolean;
  readonly readiness?: ComplianceDependencyReadiness;
  get(scope: ComplianceIdempotencyScope): Promise<ComplianceIdempotencyRecord | undefined>;
  put(entry: ComplianceIdempotencyEntry): Promise<ComplianceIdempotencyRecord>;
  delete(scope: ComplianceIdempotencyScope): Promise<boolean>;
  prune(): Promise<number>;
}

export interface InMemoryComplianceIdempotencyStoreOptions {
  readonly clock?: () => Date;
  readonly retentionMs?: number;
  readonly maxEntries?: number;
  readonly production?: boolean;
}

export class InMemoryComplianceIdempotencyStore implements ComplianceIdempotencyPort {
  readonly productionReady = false;
  readonly readiness: ComplianceDependencyReadiness;
  readonly retentionMs: number;
  readonly maxEntries: number;
  private readonly records = new Map<string, ComplianceIdempotencyRecord>();
  private readonly clock: () => Date;

  constructor(options: InMemoryComplianceIdempotencyStoreOptions = {}) {
    this.clock = options.clock ?? (() => new Date());
    this.retentionMs = normalizeRetentionMs(options.retentionMs);
    this.maxEntries = normalizeMaxEntries(options.maxEntries);
    this.readiness = Object.freeze({
      storage: "memory" as const,
      distributed: false,
      ready: () => options.production !== true,
    });
  }

  async get(
    scope: ComplianceIdempotencyScope,
  ): Promise<ComplianceIdempotencyRecord | undefined> {
    const normalized = normalizeComplianceIdempotencyScope(scope);
    const storageKey = complianceIdempotencyScopeKey(normalized);
    const existing = this.records.get(storageKey);
    if (existing === undefined) return undefined;
    if (this.expired(existing)) {
      this.records.delete(storageKey);
      return undefined;
    }
    this.records.delete(storageKey);
    this.records.set(storageKey, existing);
    return cloneComplianceValue(existing);
  }

  async put(entry: ComplianceIdempotencyEntry): Promise<ComplianceIdempotencyRecord> {
    const normalized = normalizeComplianceIdempotencyEntry(entry, this.retentionMs);
    const storageKey = complianceIdempotencyScopeKey(normalized.scope);
    this.pruneExpired();
    this.records.delete(storageKey);
    this.records.set(storageKey, normalized);
    while (this.records.size > this.maxEntries) {
      const oldest = this.records.keys().next();
      if (oldest.done === true) break;
      this.records.delete(oldest.value);
    }
    return cloneComplianceValue(normalized);
  }

  async delete(scope: ComplianceIdempotencyScope): Promise<boolean> {
    return this.records.delete(
      complianceIdempotencyScopeKey(normalizeComplianceIdempotencyScope(scope)),
    );
  }

  async prune(): Promise<number> {
    return this.pruneExpired();
  }

  snapshot(tenantId: string): ComplianceIdempotencyRecord[] {
    const normalized = normalizeComplianceTenantId(tenantId);
    return [...this.records.values()]
      .filter((record) => record.scope.tenantId === normalized)
      .map((record) => cloneComplianceValue(record));
  }

  size(): number {
    return this.records.size;
  }

  private pruneExpired(): number {
    let removed = 0;
    for (const [storageKey, record] of [...this.records.entries()]) {
      if (!this.expired(record)) continue;
      this.records.delete(storageKey);
      removed += 1;
    }
    return removed;
  }

  private expired(record: ComplianceIdempotencyRecord): boolean {
    return Date.parse(record.expiresAt) <= this.now();
  }

  private now(): number {
    const value = this.clock();
    if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
      throw complianceValidationError("Compliance idempotency clock is invalid", "clock");
    }
    return value.getTime();
  }
}

export const InMemoryComplianceIdempotencyRepository = InMemoryComplianceIdempotencyStore;
export const InMemoryComplianceIdempotencyRepositoryStore =
  InMemoryComplianceIdempotencyStore;

export function createInMemoryComplianceIdempotencyStore(
  options: InMemoryComplianceIdempotencyStoreOptions = {},
): InMemoryComplianceIdempotencyStore {
  return new InMemoryComplianceIdempotencyStore(options);
}

export function isComplianceIdempotencyPort(
  value: unknown,
): value is ComplianceIdempotencyPort {
  return value !== null &&
    typeof value === "object" &&
    typeof (value as ComplianceIdempotencyPort).get === "function" &&
    typeof (value as ComplianceIdempotencyPort).put === "function" &&
    typeof (value as ComplianceIdempotencyPort).delete === "function";
}

export function isComplianceIdempotencyProductionReady(
  value: ComplianceIdempotencyPort,
): boolean {
  return value.productionReady === true;
}

export function normalizeComplianceIdempotencyKey(value: unknown): string {
  if (typeof value !== "string") throw complianceInvalidIdempotencyKey();
  const normalized = value.trim();
  if (!COMPLIANCE_IDEMPOTENCY_KEY_PATTERN.test(normalized)) {
    throw complianceInvalidIdempotencyKey();
  }
  return normalized;
}

export function normalizeComplianceIdempotencyScope(
  value: unknown,
): ComplianceIdempotencyScope {
  if (value === null || typeof value !== "object") {
    throw complianceValidationError("Compliance idempotency scope is invalid", "scope");
  }
  const scope = value as ComplianceIdempotencyScope;
  return Object.freeze({
    tenantId: normalizeComplianceTenantId(scope.tenantId),
    actorId: requireComplianceIdentifier(scope.actorId, "actorId", 128),
    operation: requireComplianceIdentifier(scope.operation, "operation", 128),
    key: normalizeComplianceIdempotencyKey(scope.key),
  });
}

export function complianceIdempotencyScopeKey(
  scope: ComplianceIdempotencyScope,
): string {
  return [
    scope.tenantId,
    scope.actorId,
    scope.operation,
    scope.key,
  ].join("\u0000");
}

export function normalizeComplianceIdempotencyEntry(
  entry: ComplianceIdempotencyEntry,
  retentionMs: number,
): ComplianceIdempotencyRecord {
  if (entry === null || typeof entry !== "object") {
    throw complianceValidationError("Compliance idempotency entry is invalid", "entry");
  }
  const createdAt = normalizeComplianceIdempotencyTimestamp(entry.createdAt, "createdAt");
  return Object.freeze({
    scope: normalizeComplianceIdempotencyScope(entry.scope),
    requestHash: normalizeComplianceIdempotencyHash(entry.requestHash),
    value: cloneComplianceValue(entry.value),
    createdAt,
    expiresAt: new Date(
      Date.parse(createdAt) + normalizeRetentionMs(retentionMs),
    ).toISOString(),
  });
}

export function normalizeComplianceIdempotencyTimestamp(
  value: unknown,
  field: string,
): string {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) {
    throw complianceValidationError("Compliance idempotency timestamp is invalid", field);
  }
  return new Date(Date.parse(value)).toISOString();
}

export function createComplianceIdempotencyRequestHash(
  operation: string,
  request: unknown,
): string {
  return createHash("sha256")
    .update(
      stableSerialize({
        operation: requireComplianceIdentifier(operation, "operation", 128),
        request,
      }),
      "utf8",
    )
    .digest("hex");
}

export function assertComplianceIdempotencyReplayable(
  existing: ComplianceIdempotencyRecord,
  requestHash: string,
): void {
  if (existing.requestHash !== requestHash) throw complianceIdempotencyKeyReused();
}

export function assertComplianceIdempotencyAvailable(
  inProgress: boolean,
): void {
  if (inProgress) throw complianceIdempotencyRequestInProgress();
}

export function complianceIdempotencyStorageUnavailable(): never {
  throw complianceStorageUnavailable();
}

function normalizeRetentionMs(value: unknown): number {
  if (value === undefined) return COMPLIANCE_IDEMPOTENCY_DEFAULT_RETENTION_MS;
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < COMPLIANCE_IDEMPOTENCY_MIN_RETENTION_MS ||
    value > COMPLIANCE_IDEMPOTENCY_MAX_RETENTION_MS
  ) {
    throw complianceValidationError(
      "Compliance idempotency retention is invalid",
      "retentionMs",
    );
  }
  return value;
}

function normalizeMaxEntries(value: unknown): number {
  if (value === undefined) return 10_000;
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < COMPLIANCE_IDEMPOTENCY_MIN_ENTRIES ||
    value > COMPLIANCE_IDEMPOTENCY_MAX_ENTRIES
  ) {
    throw complianceValidationError(
      "Compliance idempotency capacity is invalid",
      "maxEntries",
    );
  }
  return value;
}

function normalizeComplianceIdempotencyHash(value: unknown): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/u.test(value)) {
    throw complianceValidationError(
      "Compliance idempotency request hash is invalid",
      "requestHash",
    );
  }
  return value;
}

function stableSerialize(value: unknown): string {
  if (value === null) return "null";
  if (value === undefined) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw complianceValidationError("Compliance idempotency payload is invalid", "request");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableSerialize(item)).join(",")}]`;
  }
  if (typeof value !== "object") {
    throw complianceValidationError("Compliance idempotency payload is invalid", "request");
  }
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, item]) => item !== undefined)
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));
  return `{${entries
    .map(([key, item]) => `${JSON.stringify(key)}:${stableSerialize(item)}`)
    .join(",")}}`;
}
