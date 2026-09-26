import {
  cloneCommerceValue,
  normalizeCommerceTenantId,
  normalizeIdempotencyKey,
  requireCommerceIdentifier,
} from "./validation.js";
import { commerceValidationError } from "./errors.js";
import type { CommerceDependencyReadiness } from "./types.js";

export const COMMERCE_IDEMPOTENCY_SERVICE_ACTOR = "service";
export const COMMERCE_IDEMPOTENCY_MIN_RETENTION_MS = 60_000;
export const COMMERCE_IDEMPOTENCY_MAX_RETENTION_MS = 604_800_000;
export const COMMERCE_IDEMPOTENCY_MAX_ENTRIES = 100_000;
export const COMMERCE_IDEMPOTENCY_MIN_ENTRIES = 100;

export interface CommerceIdempotencyScope {
  readonly tenantId: string;
  readonly actorId: string;
  readonly operation: string;
  readonly key: string;
}

export interface CommerceIdempotencyEntry {
  readonly scope: CommerceIdempotencyScope;
  readonly requestHash: string;
  readonly value: unknown;
  readonly createdAt: string;
}

export interface CommerceIdempotencyRecord extends CommerceIdempotencyEntry {
  readonly expiresAt: string;
}

export interface CommerceIdempotencyPort {
  readonly productionReady?: boolean;
  readonly readiness?: CommerceDependencyReadiness;
  get(
    scope: CommerceIdempotencyScope,
  ): Promise<CommerceIdempotencyRecord | undefined>;
  put(entry: CommerceIdempotencyEntry): Promise<CommerceIdempotencyRecord>;
  delete(scope: CommerceIdempotencyScope): Promise<boolean>;
  prune(): Promise<number>;
}

export interface InMemoryCommerceIdempotencyStoreOptions {
  readonly clock?: () => Date;
  readonly retentionMs?: number;
  readonly maxEntries?: number;
  readonly production?: boolean;
}

export class InMemoryCommerceIdempotencyStore implements CommerceIdempotencyPort {
  readonly productionReady = false;
  readonly readiness: CommerceDependencyReadiness;
  readonly retentionMs: number;
  readonly maxEntries: number;
  private readonly records = new Map<string, CommerceIdempotencyRecord>();
  private readonly clock: () => Date;

  constructor(options: InMemoryCommerceIdempotencyStoreOptions = {}) {
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
    scope: CommerceIdempotencyScope,
  ): Promise<CommerceIdempotencyRecord | undefined> {
    const normalized = normalizeCommerceIdempotencyScope(scope);
    const storageKey = commerceIdempotencyScopeKey(normalized);
    const existing = this.records.get(storageKey);
    if (existing === undefined) return undefined;
    if (this.expired(existing)) {
      this.records.delete(storageKey);
      return undefined;
    }
    this.records.delete(storageKey);
    this.records.set(storageKey, existing);
    return cloneCommerceValue(existing);
  }

  async put(entry: CommerceIdempotencyEntry): Promise<CommerceIdempotencyRecord> {
    const normalized = normalizeCommerceIdempotencyEntry(entry, this.retentionMs);
    const storageKey = commerceIdempotencyScopeKey(normalized.scope);
    this.pruneExpired();
    this.records.delete(storageKey);
    this.records.set(storageKey, normalized);
    while (this.records.size > this.maxEntries) {
      const oldest = this.records.keys().next();
      if (oldest.done === true) break;
      this.records.delete(oldest.value);
    }
    return cloneCommerceValue(normalized);
  }

  async delete(scope: CommerceIdempotencyScope): Promise<boolean> {
    return this.records.delete(commerceIdempotencyScopeKey(normalizeCommerceIdempotencyScope(scope)));
  }

  async prune(): Promise<number> {
    return this.pruneExpired();
  }

  snapshot(tenantId: string): CommerceIdempotencyRecord[] {
    const normalizedTenantId = normalizeCommerceTenantId(tenantId);
    return [...this.records.values()]
      .filter((record) => record.scope.tenantId === normalizedTenantId)
      .map((record) => cloneCommerceValue(record));
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

  private expired(record: CommerceIdempotencyRecord): boolean {
    return Date.parse(record.expiresAt) <= this.now();
  }

  private now(): number {
    const value = this.clock();
    if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
      throw commerceValidationError("Commerce idempotency clock is invalid", "clock");
    }
    return value.getTime();
  }
}

export const InMemoryCommerceIdempotencyRepository = InMemoryCommerceIdempotencyStore;
export const InMemoryCommerceIdempotencyRepositoryStore = InMemoryCommerceIdempotencyStore;

export function createInMemoryCommerceIdempotencyStore(
  options: InMemoryCommerceIdempotencyStoreOptions = {},
): InMemoryCommerceIdempotencyStore {
  return new InMemoryCommerceIdempotencyStore(options);
}

export const createInMemoryCommerceIdempotencyRepository =
  createInMemoryCommerceIdempotencyStore;

export function isCommerceIdempotencyPort(
  value: unknown,
): value is CommerceIdempotencyPort {
  return value !== null &&
    typeof value === "object" &&
    typeof (value as CommerceIdempotencyPort).get === "function" &&
    typeof (value as CommerceIdempotencyPort).put === "function" &&
    typeof (value as CommerceIdempotencyPort).delete === "function";
}

export function isCommerceIdempotencyProductionReady(
  value: CommerceIdempotencyPort,
): boolean {
  return value.productionReady === true;
}

export function normalizeCommerceIdempotencyScope(
  value: unknown,
): CommerceIdempotencyScope {
  if (value === null || typeof value !== "object") {
    throw commerceValidationError("Commerce idempotency scope is invalid", "scope");
  }
  const scope = value as CommerceIdempotencyScope;
  return Object.freeze({
    tenantId: normalizeCommerceTenantId(scope.tenantId),
    actorId: requireCommerceIdentifier(
      scope.actorId ?? COMMERCE_IDEMPOTENCY_SERVICE_ACTOR,
      "actorId",
    ),
    operation: requireCommerceIdentifier(scope.operation, "operation"),
    key: normalizeIdempotencyKey(scope.key),
  });
}

export function commerceIdempotencyScopeKey(
  scope: CommerceIdempotencyScope,
): string {
  return [
    scope.tenantId,
    scope.actorId,
    scope.operation,
    scope.key,
  ].join("\u0000");
}

export function normalizeCommerceIdempotencyEntry(
  entry: CommerceIdempotencyEntry,
  retentionMs: number,
): CommerceIdempotencyRecord {
  if (entry === null || typeof entry !== "object") {
    throw commerceValidationError("Commerce idempotency entry is invalid", "entry");
  }
  const createdAt = normalizeCommerceIdempotencyTimestamp(entry.createdAt, "createdAt");
  return Object.freeze({
    scope: normalizeCommerceIdempotencyScope(entry.scope),
    requestHash: normalizeCommerceIdempotencyHash(entry.requestHash),
    value: cloneCommerceValue(entry.value),
    createdAt,
    expiresAt: new Date(
      Date.parse(createdAt) + normalizeRetentionMs(retentionMs),
    ).toISOString(),
  });
}

export function normalizeCommerceIdempotencyRecord(
  value: unknown,
): CommerceIdempotencyRecord {
  if (value === null || typeof value !== "object") {
    throw commerceValidationError("Commerce idempotency record is invalid", "record");
  }
  const record = value as CommerceIdempotencyRecord;
  const createdAt = normalizeCommerceIdempotencyTimestamp(record.createdAt, "createdAt");
  const expiresAt = normalizeCommerceIdempotencyTimestamp(record.expiresAt, "expiresAt");
  if (Date.parse(expiresAt) <= Date.parse(createdAt)) {
    throw commerceValidationError("Commerce idempotency expiry is invalid", "expiresAt");
  }
  return Object.freeze({
    scope: normalizeCommerceIdempotencyScope(record.scope),
    requestHash: normalizeCommerceIdempotencyHash(record.requestHash),
    value: cloneCommerceValue(record.value),
    createdAt,
    expiresAt,
  });
}

export function normalizeCommerceIdempotencyTimestamp(
  value: unknown,
  field: string,
): string {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) {
    throw commerceValidationError("Commerce idempotency timestamp is invalid", field);
  }
  return new Date(Date.parse(value)).toISOString();
}

export function normalizeRetentionMs(value: unknown): number {
  if (value === undefined) return 86_400_000;
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < COMMERCE_IDEMPOTENCY_MIN_RETENTION_MS ||
    value > COMMERCE_IDEMPOTENCY_MAX_RETENTION_MS
  ) {
    throw commerceValidationError("Commerce idempotency retention is invalid", "retentionMs");
  }
  return value;
}

function normalizeMaxEntries(value: unknown): number {
  if (value === undefined) return 10_000;
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < COMMERCE_IDEMPOTENCY_MIN_ENTRIES ||
    value > COMMERCE_IDEMPOTENCY_MAX_ENTRIES
  ) {
    throw commerceValidationError("Commerce idempotency capacity is invalid", "maxEntries");
  }
  return value;
}

function normalizeCommerceIdempotencyHash(value: unknown): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/u.test(value)) {
    throw commerceValidationError("Commerce idempotency request hash is invalid", "requestHash");
  }
  return value;
}
