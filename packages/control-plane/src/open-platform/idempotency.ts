import { createHash } from "node:crypto";
import { validationError } from "./errors.js";
import type {
  IdempotencyAcquireRequest,
  IdempotencyAcquireResult,
  IdempotencyCompleteRequest,
  IdempotencyRecord,
  IdempotencyReleaseRequest,
  IdempotencyScope,
  IdempotencyStore,
  OpenPlatformDependencyReadiness,
} from "./types.js";

export interface InMemoryIdempotencyStoreOptions {
  clock?: () => Date;
  leaseMs?: number;
  retentionMs?: number;
}

export class InMemoryIdempotencyStore implements IdempotencyStore {
  readonly readiness: OpenPlatformDependencyReadiness = Object.freeze({
    storage: "memory" as const,
    distributed: false,
    ready: () => true,
  });
  private readonly records = new Map<string, IdempotencyRecord>();
  private readonly clock: () => Date;

  constructor(options: InMemoryIdempotencyStoreOptions = {}) {
    this.clock = options.clock ?? (() => new Date());
    const leaseMs = options.leaseMs ?? 30_000;
    const retentionMs = options.retentionMs ?? 86_400_000;
    if (
      !Number.isSafeInteger(leaseMs) ||
      leaseMs < 1_000 ||
      leaseMs > 300_000
    ) {
      throw validationError("Idempotency lease duration is invalid");
    }
    if (
      !Number.isSafeInteger(retentionMs) ||
      retentionMs < leaseMs ||
      retentionMs > 604_800_000
    ) {
      throw validationError("Idempotency retention duration is invalid");
    }
  }

  async acquire(
    request: IdempotencyAcquireRequest,
  ): Promise<IdempotencyAcquireResult> {
    const normalized = normalizeAcquireRequest(request);
    const storageKey = scopeKey(normalized.scope);
    const existing = this.records.get(storageKey);
    const now = Date.parse(normalized.now);

    if (existing !== undefined) {
      if (existing.requestHash !== normalized.requestHash) {
        return { state: "conflict" };
      }
      const expired = Date.parse(existing.expiresAt) <= now;
      const leaseExpired = existing.state === "inProgress" &&
        Date.parse(existing.leaseExpiresAt) <= now;
      if (expired || leaseExpired) {
        this.records.delete(storageKey);
      } else if (existing.state === "completed") {
        return {
          state: "replay",
          response: structuredClone(existing.response),
        };
      } else {
        return { state: "inProgress" };
      }
    }

    this.records.set(storageKey, {
      scope: normalized.scope,
      requestHash: normalized.requestHash,
      state: "inProgress",
      leaseToken: normalized.leaseToken,
      leaseExpiresAt: normalized.leaseExpiresAt,
      expiresAt: normalized.expiresAt,
      createdAt: normalized.now,
    });
    return { state: "acquired" };
  }

  async complete(request: IdempotencyCompleteRequest): Promise<boolean> {
    const normalized = normalizeCompleteRequest(request);
    const storageKey = scopeKey(normalized.scope);
    const existing = this.records.get(storageKey);
    const now = Date.parse(normalized.now);
    if (
      existing === undefined ||
      existing.state !== "inProgress" ||
      existing.requestHash !== normalized.requestHash ||
      existing.leaseToken !== normalized.leaseToken ||
      Date.parse(existing.leaseExpiresAt) <= now
    ) {
      return false;
    }
    this.records.set(storageKey, {
      ...existing,
      state: "completed",
      completedAt: normalized.now,
      expiresAt: normalized.expiresAt,
      response: structuredClone(normalized.response),
      leaseToken: undefined,
      leaseExpiresAt: normalized.now,
    });
    return true;
  }

  async release(request: IdempotencyReleaseRequest): Promise<boolean> {
    const normalized = normalizeReleaseRequest(request);
    const storageKey = scopeKey(normalized.scope);
    const existing = this.records.get(storageKey);
    if (
      existing === undefined ||
      existing.state !== "inProgress" ||
      existing.requestHash !== normalized.requestHash ||
      existing.leaseToken !== normalized.leaseToken
    ) {
      return false;
    }
    return this.records.delete(storageKey);
  }

  snapshot(tenantId: string): IdempotencyRecord[] {
    return [...this.records.values()]
      .filter((record) => record.scope.tenantId === tenantId)
      .map((record) => structuredClone(record));
  }
}

export function hashOpenPlatformIdempotencyRequest(value: unknown): string {
  return createHash("sha256")
    .update(stableSerialize(value))
    .digest("hex");
}

function normalizeAcquireRequest(
  request: IdempotencyAcquireRequest,
): IdempotencyAcquireRequest {
  if (request === null || typeof request !== "object") {
    throw validationError("Idempotency request is invalid");
  }
  const scope = normalizeScope(request.scope);
  const requestHash = normalizeHash(request.requestHash);
  const leaseToken = normalizeToken(request.leaseToken);
  const now = normalizeTimestamp(request.now, "now");
  const leaseExpiresAt = normalizeTimestamp(
    request.leaseExpiresAt,
    "leaseExpiresAt",
  );
  const expiresAt = normalizeTimestamp(request.expiresAt, "expiresAt");
  if (
    Date.parse(leaseExpiresAt) <= Date.parse(now) ||
    Date.parse(expiresAt) <= Date.parse(leaseExpiresAt)
  ) {
    throw validationError("Idempotency lease is invalid");
  }
  return {
    scope,
    requestHash,
    leaseToken,
    now,
    leaseExpiresAt,
    expiresAt,
  };
}

function normalizeCompleteRequest(
  request: IdempotencyCompleteRequest,
): IdempotencyCompleteRequest {
  if (request === null || typeof request !== "object") {
    throw validationError("Idempotency completion is invalid");
  }
  const now = normalizeTimestamp(request.now, "now");
  const expiresAt = normalizeTimestamp(request.expiresAt, "expiresAt");
  if (Date.parse(expiresAt) <= Date.parse(now)) {
    throw validationError("Idempotency completion expiry is invalid");
  }
  return {
    scope: normalizeScope(request.scope),
    requestHash: normalizeHash(request.requestHash),
    leaseToken: normalizeToken(request.leaseToken),
    now,
    expiresAt,
    response: structuredClone(request.response),
  };
}

function normalizeReleaseRequest(
  request: IdempotencyReleaseRequest,
): IdempotencyReleaseRequest {
  if (request === null || typeof request !== "object") {
    throw validationError("Idempotency release is invalid");
  }
  return {
    scope: normalizeScope(request.scope),
    requestHash: normalizeHash(request.requestHash),
    leaseToken: normalizeToken(request.leaseToken),
    now: normalizeTimestamp(request.now, "now"),
  };
}

function normalizeScope(value: unknown): IdempotencyScope {
  if (value === null || typeof value !== "object") {
    throw validationError("Idempotency scope is invalid");
  }
  const scope = value as IdempotencyScope;
  return {
    tenantId: requirePart(scope.tenantId, "tenantId"),
    actorId: requirePart(scope.actorId, "actorId"),
    operation: requirePart(scope.operation, "operation"),
    key: requirePart(scope.key, "key"),
  };
}

function normalizeHash(value: unknown): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/u.test(value)) {
    throw validationError("Idempotency request hash is invalid");
  }
  return value;
}

function normalizeToken(value: unknown): string {
  if (
    typeof value !== "string" ||
    !/^[A-Za-z0-9_-]{32,128}$/u.test(value)
  ) {
    throw validationError("Idempotency lease token is invalid");
  }
  return value;
}

function normalizeTimestamp(value: unknown, field: string): string {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) {
    throw validationError("Idempotency timestamp is invalid", { field });
  }
  return new Date(Date.parse(value)).toISOString();
}

function requirePart(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw validationError("Idempotency scope is invalid", { field });
  }
  const normalized = value.trim();
  if (
    normalized.length < 1 ||
    normalized.length > 128 ||
    /[\s\u0000-\u001f\u007f]/u.test(normalized)
  ) {
    throw validationError("Idempotency scope is invalid", { field });
  }
  return normalized;
}

function scopeKey(scope: IdempotencyScope): string {
  return [
    scope.tenantId,
    scope.actorId,
    scope.operation,
    scope.key,
  ].join("\u0000");
}

function stableSerialize(value: unknown): string {
  const ancestors = new Set<object>();

  const serialize = (current: unknown): string => {
    if (current === null) return "null";
    if (typeof current === "string") return JSON.stringify(current);
    if (typeof current === "boolean") return current ? "true" : "false";
    if (typeof current === "number") {
      if (!Number.isFinite(current)) {
        throw validationError("Idempotent request is invalid");
      }
      return JSON.stringify(current);
    }
    if (current === undefined) return "null";
    if (typeof current !== "object") {
      throw validationError("Idempotent request is invalid");
    }
    if (ancestors.has(current)) {
      throw validationError("Idempotent request is invalid");
    }
    ancestors.add(current);
    try {
      if (Array.isArray(current)) {
        return `[${current.map((item) => serialize(item)).join(",")}]`;
      }
      if (current instanceof Date) {
        return JSON.stringify(current.toISOString());
      }
      const entries = Object.entries(current as Record<string, unknown>)
        .filter(([, item]) => item !== undefined)
        .sort(([left], [right]) => left.localeCompare(right));
      return `{${entries
        .map(([key, item]) => `${JSON.stringify(key)}:${serialize(item)}`)
        .join(",")}}`;
    } finally {
      ancestors.delete(current);
    }
  };

  return serialize(value);
}
