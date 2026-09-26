import { validationError } from "../errors.js";
import type {
  IdempotencyAcquireRequest,
  IdempotencyAcquireResult,
  IdempotencyCompleteRequest,
  IdempotencyRecord,
  IdempotencyReleaseRequest,
  IdempotencyScope,
  IdempotencyStore,
  OpenPlatformDependencyReadiness,
} from "../types.js";
import {
  OpenPlatformSqlRuntime,
  cloneRecord,
  createOpenPlatformSqlRuntime,
  readDate,
  readJson,
  readText,
  rowValue,
  type DatabaseAdapter,
  type OpenPlatformSqlRepositoryInput,
  type OpenPlatformSqlRepositorySecondOptions,
} from "./adapter.js";

export class SqlIdempotencyStore implements IdempotencyStore {
  readonly readiness: OpenPlatformDependencyReadiness;
  private readonly runtime: OpenPlatformSqlRuntime;

  constructor(input: OpenPlatformSqlRepositoryInput, options?: OpenPlatformSqlRepositorySecondOptions) {
    this.runtime = createOpenPlatformSqlRuntime(input, options);
    this.readiness = Object.freeze({
      storage: "persistent" as const,
      distributed: this.runtime.distributed,
      ready: async () => {
        if (!this.runtime.distributed) return false;
        return this.runtime.isReady(["idempotency"]);
      },
    });
  }

  async acquire(request: IdempotencyAcquireRequest): Promise<IdempotencyAcquireResult> {
    const normalized = normalizeAcquire(request);
    return this.runtime.withTransaction(async (executor) => {
      const insert = await this.runtime.executeMutation(
        `INSERT INTO ${this.runtime.table("idempotency")} (${this.insertColumns()}) VALUES (${this.insertPlaceholders()}) ON CONFLICT (${this.scopeConflictColumns()}) DO NOTHING RETURNING ${this.runtime.select("idempotency")}`,
        [
          normalized.scope.tenantId,
          normalized.scope.actorId,
          normalized.scope.operation,
          normalized.scope.key,
          normalized.requestHash,
          "inProgress",
          normalized.leaseToken,
          normalized.leaseExpiresAt,
          normalized.expiresAt,
          normalized.now,
          normalized.now,
        ],
        executor,
      );
      if (insert.affected === 1) return { state: "acquired" } as const;
      for (let attempt = 0; attempt < 3; attempt += 1) {
        const existing = await this.readExisting(normalized.scope, executor);
        if (existing === undefined) {
          const retry = await this.runtime.executeMutation(
            `INSERT INTO ${this.runtime.table("idempotency")} (${this.insertColumns()}) VALUES (${this.insertPlaceholders()}) ON CONFLICT (${this.scopeConflictColumns()}) DO NOTHING RETURNING ${this.runtime.select("idempotency")}`,
            [
              normalized.scope.tenantId,
              normalized.scope.actorId,
              normalized.scope.operation,
              normalized.scope.key,
              normalized.requestHash,
              "inProgress",
              normalized.leaseToken,
              normalized.leaseExpiresAt,
              normalized.expiresAt,
              normalized.now,
              normalized.now,
            ],
            executor,
          );
          if (retry.affected === 1) return { state: "acquired" } as const;
          continue;
        }
        if (existing.requestHash !== normalized.requestHash) return { state: "conflict" } as const;
        const now = Date.parse(normalized.now);
        const expired = Date.parse(existing.expiresAt) <= now;
        const leaseExpired = existing.state === "inProgress" && Date.parse(existing.leaseExpiresAt) <= now;
        if (expired || leaseExpired) {
          const takeover = await this.runtime.executeMutation(
            `UPDATE ${this.runtime.table("idempotency")} SET ${this.runtime.column("idempotency", "requestHash")} = $5, ${this.runtime.column("idempotency", "state")} = 'inProgress', ${this.runtime.column("idempotency", "leaseToken")} = $6, ${this.runtime.column("idempotency", "leaseExpiresAt")} = $7, ${this.runtime.column("idempotency", "expiresAt")} = $8, ${this.runtime.column("idempotency", "createdAt")} = $9, ${this.runtime.column("idempotency", "updatedAt")} = $9, ${this.runtime.column("idempotency", "completedAt")} = NULL, ${this.runtime.column("idempotency", "response")} = NULL WHERE ${this.runtime.column("idempotency", "tenantId")} = $1 AND ${this.runtime.column("idempotency", "actorId")} = $2 AND ${this.runtime.column("idempotency", "operation")} = $3 AND ${this.runtime.column("idempotency", "key")} = $4 AND ${this.runtime.column("idempotency", "requestHash")} = $5 AND (${this.runtime.column("idempotency", "expiresAt")} <= $9 OR (${this.runtime.column("idempotency", "state")} = 'inProgress' AND ${this.runtime.column("idempotency", "leaseExpiresAt")} <= $9)) RETURNING ${this.runtime.select("idempotency")}`,
            [
              normalized.scope.tenantId,
              normalized.scope.actorId,
              normalized.scope.operation,
              normalized.scope.key,
              normalized.requestHash,
              normalized.leaseToken,
              normalized.leaseExpiresAt,
              normalized.expiresAt,
              normalized.now,
            ],
            executor,
          );
          if (takeover.affected === 1) return { state: "acquired" } as const;
          continue;
        }
        if (existing.state === "completed") {
          return { state: "replay", response: cloneRecord(existing.response) } as const;
        }
        return { state: "inProgress" } as const;
      }
      return { state: "inProgress" } as const;
    });
  }

  async complete(request: IdempotencyCompleteRequest): Promise<boolean> {
    const normalized = normalizeComplete(request);
    return this.runtime.withTransaction(async (executor) => {
      const result = await this.runtime.executeMutation(
        `UPDATE ${this.runtime.table("idempotency")} SET ${this.runtime.column("idempotency", "state")} = 'completed', ${this.runtime.column("idempotency", "response")} = $5::jsonb, ${this.runtime.column("idempotency", "completedAt")} = $6, ${this.runtime.column("idempotency", "updatedAt")} = $6, ${this.runtime.column("idempotency", "expiresAt")} = $7, ${this.runtime.column("idempotency", "leaseToken")} = NULL, ${this.runtime.column("idempotency", "leaseExpiresAt")} = $6 WHERE ${this.runtime.column("idempotency", "tenantId")} = $1 AND ${this.runtime.column("idempotency", "actorId")} = $2 AND ${this.runtime.column("idempotency", "operation")} = $3 AND ${this.runtime.column("idempotency", "key")} = $4 AND ${this.runtime.column("idempotency", "requestHash")} = $8 AND ${this.runtime.column("idempotency", "state")} = 'inProgress' AND ${this.runtime.column("idempotency", "leaseToken")} = $9 AND ${this.runtime.column("idempotency", "leaseExpiresAt")} > $6`,
        [
          normalized.scope.tenantId,
          normalized.scope.actorId,
          normalized.scope.operation,
          normalized.scope.key,
          safeResponse(normalized.response),
          normalized.now,
          normalized.expiresAt,
          normalized.requestHash,
          normalized.leaseToken,
        ],
        executor,
      );
      return result.affected === 1;
    });
  }

  async release(request: IdempotencyReleaseRequest): Promise<boolean> {
    const normalized = normalizeRelease(request);
    return this.runtime.withTransaction(async (executor) => {
      const result = await this.runtime.executeMutation(
        `DELETE FROM ${this.runtime.table("idempotency")} WHERE ${this.runtime.column("idempotency", "tenantId")} = $1 AND ${this.runtime.column("idempotency", "actorId")} = $2 AND ${this.runtime.column("idempotency", "operation")} = $3 AND ${this.runtime.column("idempotency", "key")} = $4 AND ${this.runtime.column("idempotency", "requestHash")} = $5 AND ${this.runtime.column("idempotency", "state")} = 'inProgress' AND ${this.runtime.column("idempotency", "leaseToken")} = $6`,
        [
          normalized.scope.tenantId,
          normalized.scope.actorId,
          normalized.scope.operation,
          normalized.scope.key,
          normalized.requestHash,
          normalized.leaseToken,
        ],
        executor,
      );
      return result.affected === 1;
    });
  }

  async isReady(): Promise<boolean> {
    return this.runtime.isReady(["idempotency"]);
  }

  private async readExisting(
    scope: IdempotencyScope,
    executor: DatabaseAdapter,
  ): Promise<IdempotencyRecord | undefined> {
    const rows = await this.runtime.queryRows(
      `SELECT ${this.runtime.select("idempotency")} FROM ${this.runtime.table("idempotency")} WHERE ${this.runtime.column("idempotency", "tenantId")} = $1 AND ${this.runtime.column("idempotency", "actorId")} = $2 AND ${this.runtime.column("idempotency", "operation")} = $3 AND ${this.runtime.column("idempotency", "key")} = $4 FOR UPDATE`,
      [scope.tenantId, scope.actorId, scope.operation, scope.key],
      executor,
    );
    return rows[0] === undefined ? undefined : this.mapRow(rows[0]);
  }

  private mapRow(row: Record<string, unknown>): IdempotencyRecord {
    const scope: IdempotencyScope = {
      tenantId: requiredText(rowValue(row, "tenantId"), "idempotency"),
      actorId: requiredText(rowValue(row, "actorId"), "idempotency"),
      operation: requiredText(rowValue(row, "operation"), "idempotency"),
      key: requiredText(rowValue(row, "key"), "idempotency"),
    };
    const state = requiredText(rowValue(row, "state"), "idempotency");
    if (state !== "inProgress" && state !== "completed") {
      throw new Error("Invalid idempotency SQL row");
    }
    const leaseToken = readText(rowValue(row, "leaseToken"));
    const completedAt = readDate(rowValue(row, "completedAt"));
    const response = readJson(rowValue(row, "response"));
    return {
      scope,
      requestHash: requiredText(rowValue(row, "requestHash"), "idempotency"),
      state,
      ...(leaseToken === undefined ? {} : { leaseToken }),
      leaseExpiresAt: requiredDate(rowValue(row, "leaseExpiresAt"), "idempotency"),
      expiresAt: requiredDate(rowValue(row, "expiresAt"), "idempotency"),
      createdAt: requiredDate(rowValue(row, "createdAt"), "idempotency"),
      ...(completedAt === undefined ? {} : { completedAt }),
      ...(response === undefined ? {} : { response }),
    };
  }

  private insertColumns(): string {
    return [
      "tenantId",
      "actorId",
      "operation",
      "key",
      "requestHash",
      "state",
      "leaseToken",
      "leaseExpiresAt",
      "expiresAt",
      "createdAt",
      "updatedAt",
    ].map((field) => this.runtime.column("idempotency", field)).join(", ");
  }

  private insertPlaceholders(): string {
    return Array.from({ length: 11 }, (_value, index) => `$${index + 1}`).join(", ");
  }

  private scopeConflictColumns(): string {
    return [
      "tenantId",
      "actorId",
      "operation",
      "key",
    ].map((field) => this.runtime.column("idempotency", field)).join(", ");
  }
}

function normalizeAcquire(request: IdempotencyAcquireRequest): IdempotencyAcquireRequest {
  assertRequest(request);
  const scope = normalizeScope(request.scope);
  const requestHash = normalizeHash(request.requestHash);
  const leaseToken = normalizeToken(request.leaseToken);
  const now = normalizeTimestamp(request.now, "now");
  const leaseExpiresAt = normalizeTimestamp(request.leaseExpiresAt, "leaseExpiresAt");
  const expiresAt = normalizeTimestamp(request.expiresAt, "expiresAt");
  if (Date.parse(leaseExpiresAt) <= Date.parse(now) || Date.parse(expiresAt) <= Date.parse(leaseExpiresAt)) {
    throw validationError("Idempotency lease is invalid");
  }
  return { scope, requestHash, leaseToken, now, leaseExpiresAt, expiresAt };
}

function normalizeComplete(request: IdempotencyCompleteRequest): IdempotencyCompleteRequest {
  assertRequest(request);
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
    response: cloneRecord(request.response),
  };
}

function normalizeRelease(request: IdempotencyReleaseRequest): IdempotencyReleaseRequest {
  assertRequest(request);
  return {
    scope: normalizeScope(request.scope),
    requestHash: normalizeHash(request.requestHash),
    leaseToken: normalizeToken(request.leaseToken),
    now: normalizeTimestamp(request.now, "now"),
  };
}

function assertRequest(value: unknown): void {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw validationError("Idempotency request is invalid");
  }
}

function normalizeScope(value: unknown): IdempotencyScope {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw validationError("Idempotency scope is invalid");
  }
  const scope = value as IdempotencyScope;
  return {
    tenantId: requirePart(scope.tenantId),
    actorId: requirePart(scope.actorId),
    operation: requirePart(scope.operation),
    key: requirePart(scope.key),
  };
}

function normalizeHash(value: unknown): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/u.test(value)) {
    throw validationError("Idempotency request hash is invalid");
  }
  return value;
}

function normalizeToken(value: unknown): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{32,128}$/u.test(value)) {
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

function requirePart(value: unknown): string {
  if (typeof value !== "string") throw validationError("Idempotency scope is invalid");
  const normalized = value.trim();
  if (normalized.length < 1 || normalized.length > 128 || /[\s\u0000-\u001f\u007f]/u.test(normalized)) {
    throw validationError("Idempotency scope is invalid");
  }
  return normalized;
}

function safeResponse(value: unknown): string {
  if (value === undefined) return "null";
  if (containsSensitiveKey(value)) throw validationError("Sensitive idempotency response is not accepted");
  try {
    return JSON.stringify(value);
  } catch {
    throw validationError("Idempotency response is invalid");
  }
}

function containsSensitiveKey(value: unknown, depth = 0): boolean {
  if (depth > 8) return true;
  if (value === null || typeof value !== "object") return false;
  if (Array.isArray(value)) return value.some((item) => containsSensitiveKey(item, depth + 1));
  for (const [key, nested] of Object.entries(value)) {
    const normalized = key.replace(/[-_]/gu, "").toLowerCase();
    if (["secret", "token", "password", "privatekey", "authorization", "plaintext"].includes(normalized) && nested !== undefined && nested !== null) return true;
    if (containsSensitiveKey(nested, depth + 1)) return true;
  }
  return false;
}

function requiredText(value: unknown, kind: string): string {
  const text = readText(value);
  if (text === undefined) throw new Error(`Invalid ${kind} SQL row`);
  return text;
}

function requiredDate(value: unknown, kind: string): string {
  const date = readDate(value);
  if (date === undefined) throw new Error(`Invalid ${kind} SQL row`);
  return date;
}

export const PostgresIdempotencyStore = SqlIdempotencyStore;
export const PostgreSqlIdempotencyStore = SqlIdempotencyStore;
export const SqlOpenPlatformIdempotencyStore = SqlIdempotencyStore;
