import { createHash, randomBytes, randomUUID } from "node:crypto";
import type {
  OpaqueClientSession,
  OpaqueClientSessionClientKind,
  OpaqueClientSessionIssueResult,
  OpaqueClientSessionRecord,
  OpaqueClientSessionStatus,
} from "@getbrick/idaas-contracts";
import type {
  OpaqueClientSessionIssueInput,
  OpaqueClientSessionRepository,
} from "./application-types.js";
import { validateApplicationSqlIdentifier } from "./application-sql-repository.js";

export const DEFAULT_CLIENT_SESSION_TABLE = "gb_idaas_client_session";
export const DEFAULT_CLIENT_SESSION_TTL_SECONDS = 60 * 60 * 24 * 30;
export const MIN_CLIENT_SESSION_TTL_SECONDS = 60;
export const MAX_CLIENT_SESSION_TTL_SECONDS = 60 * 60 * 24 * 365;
export const CLIENT_SESSION_HASH_BYTES = 32;

export interface InMemoryOpaqueClientSessionRepositoryOptions {
  tenantId?: string;
  records?: readonly OpaqueClientSessionRecord[];
  now?: () => Date;
  randomReference?: () => string;
}

export interface OpaqueClientSessionSqlExecutor {
  query(text: string, values?: unknown[]): unknown | Promise<unknown>;
}

export interface SqlOpaqueClientSessionRepositoryOptions {
  executor: OpaqueClientSessionSqlExecutor;
  tenantId?: string;
  tableName?: string;
  now?: () => Date;
}

export class InMemoryOpaqueClientSessionRepository implements OpaqueClientSessionRepository {
  readonly tenantId: string;
  private readonly records = new Map<string, OpaqueClientSessionRecord>();
  private readonly now: () => Date;
  private readonly randomReference: () => string;

  constructor(options: InMemoryOpaqueClientSessionRepositoryOptions = {}) {
    this.tenantId = normalizeTenantId(options.tenantId);
    this.now = normalizeClock(options.now);
    this.randomReference = options.randomReference ?? (() => randomBytes(CLIENT_SESSION_HASH_BYTES).toString("base64url"));
    for (const record of options.records ?? []) this.seed(record);
  }

  issue(input: OpaqueClientSessionIssueInput): OpaqueClientSessionIssueResult {
    const clientKind = normalizeClientKind(input.clientKind);
    const applicationId = normalizeIdentifier(input.applicationId, "applicationId");
    const clientId = normalizeIdentifier(input.clientId, "clientId");
    const userId = normalizeIdentifier(input.userId, "userId");
    const sessionReference = normalizeReference(selectSessionReference(input.sessionReference, input.sessionToken) ?? this.randomReference());
    const sessionHash = hashClientSessionReference(sessionReference);
    const key = this.key(sessionHash);
    if (this.records.has(key)) throw new Error("Opaque client session already exists");
    const createdAt = this.currentDate();
    const expiresAt = new Date(createdAt.getTime() + ttlMilliseconds(input.expiresInSeconds));
    const record: OpaqueClientSessionRecord = {
      id: randomUUID(),
      tenantId: this.tenantId,
      applicationId,
      clientId,
      clientKind,
      sessionHash,
      userId,
      status: "active",
      ...(input.deviceId === undefined ? {} : { deviceId: normalizeIdentifier(input.deviceId, "deviceId") }),
      ...(input.binding === undefined ? {} : { bindingHash: hashClientSessionReference(normalizeReference(input.binding)) }),
      createdAt: createdAt.toISOString(),
      updatedAt: createdAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
    };
    this.records.set(key, record);
    return {
      session: toPublicSession(sessionReference, record),
      record: cloneRecord(record),
    };
  }

  create(input: OpaqueClientSessionIssueInput): OpaqueClientSessionIssueResult {
    return this.issue(input);
  }

  find(sessionReference: string): OpaqueClientSessionRecord | undefined {
    const key = this.key(hashClientSessionReference(normalizeReference(sessionReference)));
    const record = this.records.get(key);
    if (record === undefined || record.status !== "active") return undefined;
    if (record.expiresAt <= this.currentDate().toISOString() && record.status === "active") {
      const expired = { ...record, status: "expired" as const, updatedAt: this.currentDate().toISOString() };
      this.records.set(key, expired);
      return undefined;
    }
    return cloneRecord(record);
  }

  get(sessionReference: string): OpaqueClientSessionRecord | undefined {
    return this.find(sessionReference);
  }

  touch(sessionReference: string, at = this.currentDate()): OpaqueClientSessionRecord | undefined {
    const key = this.key(hashClientSessionReference(normalizeReference(sessionReference)));
    const current = this.records.get(key);
    if (current === undefined || current.status !== "active" || current.expiresAt <= at.toISOString()) return undefined;
    const updated = { ...current, lastUsedAt: at.toISOString(), updatedAt: at.toISOString() };
    this.records.set(key, updated);
    return cloneRecord(updated);
  }

  consume(sessionReference: string, at = this.currentDate()): OpaqueClientSessionRecord | undefined {
    return this.touch(sessionReference, at);
  }

  revoke(sessionReference: string, at = this.currentDate()): boolean {
    const key = this.key(hashClientSessionReference(normalizeReference(sessionReference)));
    const current = this.records.get(key);
    if (current === undefined || current.status === "revoked") return false;
    this.records.set(key, {
      ...current,
      status: "revoked",
      revokedAt: at.toISOString(),
      updatedAt: at.toISOString(),
    });
    return true;
  }

  cleanupExpired(at = this.currentDate()): number {
    const timestamp = at.toISOString();
    let removed = 0;
    for (const [key, record] of this.records) {
      if (record.expiresAt <= timestamp || record.status === "expired" || record.status === "revoked") {
        this.records.delete(key);
        removed += 1;
      }
    }
    return removed;
  }

  purgeExpired(at = this.currentDate()): number {
    return this.cleanupExpired(at);
  }

  ready(): boolean {
    return true;
  }

  isReady(): boolean {
    return true;
  }

  snapshot(): OpaqueClientSessionRecord[] {
    return [...this.records.values()].map(cloneRecord);
  }

  private seed(record: OpaqueClientSessionRecord): void {
    if (record.tenantId !== this.tenantId) return;
    const normalized = cloneRecord({
      ...record,
      sessionHash: normalizeHash(record.sessionHash),
      status: normalizeStatus(record.status),
    });
    this.records.set(this.key(normalized.sessionHash), normalized);
  }

  private key(sessionHash: string): string {
    return `${this.tenantId}:${sessionHash}`;
  }

  private currentDate(): Date {
    const value = this.now();
    if (Number.isNaN(value.getTime())) throw new Error("Opaque client session clock is invalid");
    return value;
  }
}

export class SqlOpaqueClientSessionRepository implements OpaqueClientSessionRepository {
  readonly tenantId: string;
  private readonly executor: OpaqueClientSessionSqlExecutor;
  private readonly table: string;
  private readonly now: () => Date;

  constructor(options: SqlOpaqueClientSessionRepositoryOptions) {
    if (!options || typeof options.executor?.query !== "function") throw new TypeError("Opaque client session SQL executor is required");
    this.executor = options.executor;
    this.tenantId = normalizeTenantId(options.tenantId);
    this.table = qualifyTable(options.tableName ?? DEFAULT_CLIENT_SESSION_TABLE);
    this.now = normalizeClock(options.now);
  }

  async issue(input: OpaqueClientSessionIssueInput): Promise<OpaqueClientSessionIssueResult> {
    const clientKind = normalizeClientKind(input.clientKind);
    const applicationId = normalizeIdentifier(input.applicationId, "applicationId");
    const clientId = normalizeIdentifier(input.clientId, "clientId");
    const userId = normalizeIdentifier(input.userId, "userId");
    const sessionReference = normalizeReference(selectSessionReference(input.sessionReference, input.sessionToken) ?? randomBytes(CLIENT_SESSION_HASH_BYTES).toString("base64url"));
    const sessionHash = hashClientSessionReference(sessionReference);
    const now = this.currentDate();
    const expiresAt = new Date(now.getTime() + ttlMilliseconds(input.expiresInSeconds));
    const result = await this.executor.query(
      `INSERT INTO ${this.table} (${[
        "id",
        "tenant_id",
        "application_id",
        "client_id",
        "client_kind",
        "session_hash",
        "user_id",
        "status",
        "device_id",
        "binding_hash",
        "created_at",
        "updated_at",
        "expires_at",
      ].map(quoteColumn).join(", ")}) VALUES ($1, $2, $3, $4, $5, $6, $7, 'active', $8, $9, $10, $10, $11) RETURNING ${[
        "id",
        "tenant_id",
        "application_id",
        "client_id",
        "client_kind",
        "session_hash",
        "user_id",
        "status",
        "device_id",
        "binding_hash",
        "created_at",
        "updated_at",
        "last_used_at",
        "expires_at",
        "revoked_at",
      ].map(quoteColumn).join(", ")}`,
      [
        randomUUID(),
        this.tenantId,
        applicationId,
        clientId,
        clientKind,
        sessionHash,
        userId,
        input.deviceId === undefined ? null : normalizeIdentifier(input.deviceId, "deviceId"),
        input.binding === undefined ? null : hashClientSessionReference(normalizeReference(input.binding)),
        now.toISOString(),
        expiresAt.toISOString(),
      ],
    );
    const record = rowFromResult(result, this.tenantId, "Opaque client session insert failed");
    return { session: toPublicSession(sessionReference, record), record };
  }

  async find(sessionReference: string): Promise<OpaqueClientSessionRecord | undefined> {
    const now = this.currentDate().toISOString();
    const result = await this.executor.query(
      `SELECT ${sessionColumns()} FROM ${this.table} WHERE ${quoteColumn("tenant_id")} = $1 AND ${quoteColumn("session_hash")} = $2 AND ${quoteColumn("status")} = 'active' AND ${quoteColumn("expires_at")} > $3 LIMIT 1`,
      [this.tenantId, hashClientSessionReference(normalizeReference(sessionReference)), now],
    );
    const row = firstRow(result);
    if (row === undefined) return undefined;
    const record = mapRecord(row, this.tenantId);
    if (record.status !== "active" || record.expiresAt <= now) return undefined;
    return record;
  }

  async touch(sessionReference: string, at = this.currentDate()): Promise<OpaqueClientSessionRecord | undefined> {
    const result = await this.executor.query(
      `UPDATE ${this.table} SET ${quoteColumn("last_used_at")} = $3, ${quoteColumn("updated_at")} = $3 WHERE ${quoteColumn("tenant_id")} = $1 AND ${quoteColumn("session_hash")} = $2 AND ${quoteColumn("status")} = 'active' AND ${quoteColumn("expires_at")} > $3 RETURNING ${sessionColumns()}`,
      [this.tenantId, hashClientSessionReference(normalizeReference(sessionReference)), at.toISOString()],
    );
    const row = firstRow(result);
    return row === undefined ? undefined : mapRecord(row, this.tenantId);
  }

  async cleanupExpired(at = this.currentDate()): Promise<number> {
    const result = await this.executor.query(
      `DELETE FROM ${this.table} WHERE ${quoteColumn("tenant_id")} = $1 AND (${quoteColumn("expires_at")} <= $2 OR ${quoteColumn("status")} IN ('expired', 'revoked'))`,
      [this.tenantId, at.toISOString()],
    );
    return affectedRows(result);
  }

  async purgeExpired(at = this.currentDate()): Promise<number> {
    return this.cleanupExpired(at);
  }

  async revoke(sessionReference: string, at = this.currentDate()): Promise<boolean> {
    const result = await this.executor.query(
      `UPDATE ${this.table} SET ${quoteColumn("status")} = 'revoked', ${quoteColumn("revoked_at")} = $3, ${quoteColumn("updated_at")} = $3 WHERE ${quoteColumn("tenant_id")} = $1 AND ${quoteColumn("session_hash")} = $2 AND ${quoteColumn("status")} <> 'revoked'`,
      [this.tenantId, hashClientSessionReference(normalizeReference(sessionReference)), at.toISOString()],
    );
    return affectedRows(result) > 0;
  }

  async ready(): Promise<boolean> {
    try {
      await this.executor.query(`SELECT 1 FROM ${this.table} LIMIT 0`, []);
      return true;
    } catch {
      return false;
    }
  }

  async isReady(): Promise<boolean> {
    return this.ready();
  }

  private currentDate(): Date {
    const value = this.now();
    if (Number.isNaN(value.getTime())) throw new Error("Opaque client session clock is invalid");
    return value;
  }
}

export const InMemoryClientSessionRepository = InMemoryOpaqueClientSessionRepository;
export const InMemoryOpaqueSessionRepository = InMemoryOpaqueClientSessionRepository;
export const SqlClientSessionRepository = SqlOpaqueClientSessionRepository;
export const SqlOpaqueSessionRepository = SqlOpaqueClientSessionRepository;
export const createInMemoryClientSessionRepository = (options: InMemoryOpaqueClientSessionRepositoryOptions = {}): InMemoryOpaqueClientSessionRepository => new InMemoryOpaqueClientSessionRepository(options);
export const createClientSessionRepository = createInMemoryClientSessionRepository;
export const createInMemoryOpaqueClientSessionRepository = createInMemoryClientSessionRepository;
export const createOpaqueClientSessionRepository = createInMemoryClientSessionRepository;
export const createSqlClientSessionRepository = (options: SqlOpaqueClientSessionRepositoryOptions): SqlOpaqueClientSessionRepository => new SqlOpaqueClientSessionRepository(options);

export function hashClientSessionReference(value: string): string {
  return createHash("sha256").update(normalizeReference(value), "utf8").digest("hex");
}

export const hashOpaqueClientSession = hashClientSessionReference;
export const hashClientSession = hashClientSessionReference;

export function generateOpaqueClientSessionReference(): string {
  return randomBytes(CLIENT_SESSION_HASH_BYTES).toString("base64url");
}

export function isOpaqueClientSessionReference(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{16,512}$/u.test(value);
}

function toPublicSession(sessionReference: string, record: OpaqueClientSessionRecord): OpaqueClientSession {
  return {
    sessionReference,
    expiresAt: record.expiresAt,
    clientKind: record.clientKind,
    tokenType: "Bearer",
  };
}

function normalizeClientKind(value: unknown): OpaqueClientSessionClientKind {
  if (value !== "mp_weixin" && value !== "native") throw new TypeError("Opaque client session kind is invalid");
  return value;
}

function normalizeIdentifier(value: unknown, field: string): string {
  if (typeof value !== "string") throw new TypeError(`Invalid ${field}`);
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 256 || /[\u0000-\u001f\u007f]/u.test(normalized)) throw new TypeError(`Invalid ${field}`);
  return normalized;
}

function normalizeReference(value: unknown): string {
  if (!isOpaqueClientSessionReference(value)) throw new TypeError("Opaque client session reference is invalid");
  return value;
}

function selectSessionReference(first: unknown, second: unknown): string | undefined {
  if (first !== undefined && second !== undefined && first !== second) throw new TypeError("Opaque client session reference aliases conflict");
  return first === undefined ? (second === undefined ? undefined : String(second)) : String(first);
}

function normalizeHash(value: unknown): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/u.test(value)) throw new TypeError("Opaque client session hash is invalid");
  return value;
}

function normalizeStatus(value: unknown): OpaqueClientSessionStatus {
  if (value !== "active" && value !== "expired" && value !== "revoked") throw new TypeError("Opaque client session status is invalid");
  return value;
}

function normalizeTenantId(value: unknown): string {
  if (value === undefined) return "default";
  return normalizeIdentifier(value, "tenantId");
}

function normalizeClock(value: (() => Date) | undefined): () => Date {
  const clock = value ?? (() => new Date());
  if (typeof clock !== "function") throw new TypeError("Opaque client session clock is invalid");
  return clock;
}

function ttlMilliseconds(value: number | undefined): number {
  const seconds = value ?? DEFAULT_CLIENT_SESSION_TTL_SECONDS;
  if (!Number.isSafeInteger(seconds) || seconds < MIN_CLIENT_SESSION_TTL_SECONDS || seconds > MAX_CLIENT_SESSION_TTL_SECONDS) {
    throw new TypeError("Opaque client session lifetime is invalid");
  }
  return seconds * 1000;
}

function cloneRecord(record: OpaqueClientSessionRecord): OpaqueClientSessionRecord {
  return {
    ...record,
    createdAt: new Date(record.createdAt).toISOString(),
    ...(record.updatedAt === undefined ? {} : { updatedAt: new Date(record.updatedAt).toISOString() }),
    ...(record.lastUsedAt === undefined ? {} : { lastUsedAt: new Date(record.lastUsedAt).toISOString() }),
    expiresAt: new Date(record.expiresAt).toISOString(),
    ...(record.revokedAt === undefined ? {} : { revokedAt: new Date(record.revokedAt).toISOString() }),
  };
}

function qualifyTable(value: string): string {
  return validateApplicationSqlIdentifier(value, "client session table").split(".").map((part) => `"${part}"`).join(".");
}

function quoteColumn(value: string): string {
  return `"${value}"`;
}

function sessionColumns(): string {
  return [
    "id",
    "tenant_id",
    "application_id",
    "client_id",
    "client_kind",
    "session_hash",
    "user_id",
    "status",
    "device_id",
    "binding_hash",
    "created_at",
    "updated_at",
    "last_used_at",
    "expires_at",
    "revoked_at",
  ].map(quoteColumn).join(", ");
}

function mapRecord(row: Record<string, unknown>, fallbackTenantId: string): OpaqueClientSessionRecord {
  const value = (key: string): unknown => {
    const camel = key.replace(/_([a-z])/gu, (_match, letter: string) => letter.toUpperCase());
    const snake = key.replace(/[A-Z]/gu, (letter) => `_${letter.toLowerCase()}`);
    return row[key] ?? row[camel] ?? row[snake];
  };
  const createdAt = requiredDate(value("createdAt"), "createdAt");
  const expiresAt = requiredDate(value("expiresAt"), "expiresAt");
  return {
    id: requiredString(value("id"), "id"),
    tenantId: requiredString(value("tenantId") ?? fallbackTenantId, "tenantId"),
    applicationId: requiredString(value("applicationId"), "applicationId"),
    clientId: requiredString(value("clientId"), "clientId"),
    clientKind: normalizeClientKind(value("clientKind")),
    sessionHash: normalizeHash(value("sessionHash")),
    userId: requiredString(value("userId"), "userId"),
    status: normalizeStatus(value("status")),
    ...(value("deviceId") === undefined || value("deviceId") === null ? {} : { deviceId: requiredString(value("deviceId"), "deviceId") }),
    ...(value("bindingHash") === undefined || value("bindingHash") === null ? {} : { bindingHash: normalizeHash(value("bindingHash")) }),
    createdAt,
    ...(value("updatedAt") === undefined || value("updatedAt") === null ? {} : { updatedAt: requiredDate(value("updatedAt"), "updatedAt") }),
    ...(value("lastUsedAt") === undefined || value("lastUsedAt") === null ? {} : { lastUsedAt: requiredDate(value("lastUsedAt"), "lastUsedAt") }),
    expiresAt,
    ...(value("revokedAt") === undefined || value("revokedAt") === null ? {} : { revokedAt: requiredDate(value("revokedAt"), "revokedAt") }),
  };
}

function requiredString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(`Opaque client session ${field} is invalid`);
  return value;
}

function requiredDate(value: unknown, field: string): string {
  const date = value instanceof Date ? value : new Date(typeof value === "string" || typeof value === "number" ? value : NaN);
  if (Number.isNaN(date.getTime())) throw new Error(`Opaque client session ${field} is invalid`);
  return date.toISOString();
}

function resultRows(value: unknown): unknown[] {
  if (Array.isArray(value)) return value;
  if (typeof value === "object" && value !== null && "rows" in value && Array.isArray((value as { rows?: unknown }).rows)) return (value as { rows: unknown[] }).rows;
  throw new Error("Opaque client session result is invalid");
}

function firstRow(value: unknown): Record<string, unknown> | undefined {
  const row = resultRows(value)[0];
  if (row === undefined) return undefined;
  if (typeof row !== "object" || row === null || Array.isArray(row)) throw new Error("Opaque client session row is invalid");
  return row as Record<string, unknown>;
}

function rowFromResult(value: unknown, fallbackTenantId: string, message: string): OpaqueClientSessionRecord {
  const row = firstRow(value);
  if (row === undefined) throw new Error(message);
  return mapRecord(row, fallbackTenantId);
}

function affectedRows(value: unknown): number {
  if (typeof value === "object" && value !== null && "rowCount" in value) {
    const count = (value as { rowCount?: unknown }).rowCount;
    if (typeof count === "number" && Number.isSafeInteger(count)) return count;
  }
  return resultRows(value).length;
}
