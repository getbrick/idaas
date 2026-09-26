import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import type {
  WebviewTicket,
  WebviewTicketConsumeRequest,
  WebviewTicketIssueResult,
  WebviewTicketRecord,
  WebviewTicketStatus,
} from "@getbrick/idaas-contracts";
import type {
  WebviewTicketIssueInput,
  WebviewTicketRepository,
} from "./application-types.js";
import { validateApplicationSqlIdentifier } from "./application-sql-repository.js";

export const DEFAULT_WEBVIEW_TICKET_TABLE = "gb_idaas_webview_ticket";
export const DEFAULT_WEBVIEW_TICKET_TTL_SECONDS = 5 * 60;
export const MIN_WEBVIEW_TICKET_TTL_SECONDS = 30;
export const MAX_WEBVIEW_TICKET_TTL_SECONDS = 15 * 60;
export const WEBVIEW_TICKET_HASH_BYTES = 32;

export interface InMemoryWebviewTicketRepositoryOptions {
  tenantId?: string;
  records?: readonly WebviewTicketRecord[];
  now?: () => Date;
  randomTicket?: () => string;
}

export interface WebviewTicketSqlExecutor {
  query(text: string, values?: unknown[]): unknown | Promise<unknown>;
}

export interface SqlWebviewTicketRepositoryOptions {
  executor: WebviewTicketSqlExecutor;
  tenantId?: string;
  tableName?: string;
  now?: () => Date;
}

export class InMemoryWebviewTicketRepository implements WebviewTicketRepository {
  readonly tenantId: string;
  private readonly records = new Map<string, WebviewTicketRecord>();
  private readonly now: () => Date;
  private readonly randomTicket: () => string;

  constructor(options: InMemoryWebviewTicketRepositoryOptions = {}) {
    this.tenantId = normalizeTenantId(options.tenantId);
    this.now = normalizeClock(options.now);
    this.randomTicket = options.randomTicket ?? (() => randomBytes(WEBVIEW_TICKET_HASH_BYTES).toString("base64url"));
    for (const record of options.records ?? []) this.seed(record);
  }

  issue(input: WebviewTicketIssueInput): WebviewTicketIssueResult {
    const applicationId = normalizeIdentifier(input.applicationId, "applicationId");
    const platformId = normalizeIdentifier(input.platformId, "platformId");
    const redirectUri = normalizeRedirectUri(input.redirectUri);
    const ticketReference = normalizeOptionalReference(selectTicketReference(input.ticketReference, input.ticket));
    const normalizedTicket = ticketReference ?? this.randomTicket();
    const ticketHash = hashWebviewTicket(normalizedTicket);
    const key = this.key(ticketHash);
    if (this.records.has(key)) throw new Error("Webview ticket already exists");
    const now = this.currentDate();
    const expiresAt = new Date(now.getTime() + ttlMilliseconds(input.expiresInSeconds));
    const record: WebviewTicketRecord = {
      id: randomUUID(),
      tenantId: this.tenantId,
      applicationId,
      platformId,
      ...(input.clientId === undefined ? {} : { clientId: normalizeIdentifier(input.clientId, "clientId") }),
      ticketHash,
      ...(input.sessionReference === undefined ? {} : { sessionHash: hashWebviewTicket(normalizeReference(input.sessionReference)) }),
      ...(input.binding === undefined ? {} : { bindingHash: hashWebviewTicket(normalizeReference(input.binding)) }),
      redirectUri,
      status: "issued",
      createdAt: now.toISOString(),
      updatedAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
    };
    this.records.set(key, record);
    return {
      ticket: toPublicTicket(normalizedTicket, record),
      record: cloneRecord(record),
    };
  }

  create(input: WebviewTicketIssueInput): WebviewTicketIssueResult {
    return this.issue(input);
  }

  consume(input: WebviewTicketConsumeRequest): WebviewTicketRecord | undefined {
    const ticketHash = hashWebviewTicket(normalizeReference(input.ticketReference));
    const key = this.key(ticketHash);
    const current = this.records.get(key);
    if (current === undefined || current.status !== "issued") return undefined;
    const now = this.currentDate();
    if (current.expiresAt <= now.toISOString()) {
      const expired = { ...current, status: "expired" as const, updatedAt: now.toISOString() };
      this.records.set(key, expired);
      return undefined;
    }
    if (input.clientId !== undefined && current.clientId !== input.clientId) return undefined;
    if (input.sessionReference !== undefined && !matchesHash(current.sessionHash, hashWebviewTicket(normalizeReference(input.sessionReference)))) return undefined;
    if (input.binding !== undefined && !matchesHash(current.bindingHash, hashWebviewTicket(normalizeReference(input.binding)))) return undefined;
    const consumed: WebviewTicketRecord = {
      ...current,
      status: "consumed",
      consumedAt: now.toISOString(),
      updatedAt: now.toISOString(),
    };
    this.records.set(key, consumed);
    return cloneRecord(consumed);
  }

  redeem(input: WebviewTicketConsumeRequest): WebviewTicketRecord | undefined {
    return this.consume(input);
  }

  revoke(ticketReference: string): boolean {
    const key = this.key(hashWebviewTicket(normalizeReference(ticketReference)));
    const current = this.records.get(key);
    if (current === undefined || current.status === "revoked") return false;
    const now = this.currentDate().toISOString();
    this.records.set(key, { ...current, status: "revoked", revokedAt: now, updatedAt: now });
    return true;
  }

  find(ticketReference: string): WebviewTicketRecord | undefined {
    const current = this.records.get(this.key(hashWebviewTicket(normalizeReference(ticketReference))));
    return current === undefined ? undefined : cloneRecord(current);
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

  snapshot(): WebviewTicketRecord[] {
    return [...this.records.values()].map(cloneRecord);
  }

  private seed(record: WebviewTicketRecord): void {
    if (record.tenantId !== this.tenantId) return;
    const normalized = cloneRecord({
      ...record,
      ticketHash: normalizeHash(record.ticketHash),
      status: normalizeStatus(record.status),
      redirectUri: normalizeRedirectUri(record.redirectUri),
    });
    this.records.set(this.key(normalized.ticketHash), normalized);
  }

  private key(ticketHash: string): string {
    return `${this.tenantId}:${ticketHash}`;
  }

  private currentDate(): Date {
    const value = this.now();
    if (Number.isNaN(value.getTime())) throw new Error("Webview ticket clock is invalid");
    return value;
  }
}

export class SqlWebviewTicketRepository implements WebviewTicketRepository {
  readonly tenantId: string;
  private readonly executor: WebviewTicketSqlExecutor;
  private readonly table: string;
  private readonly now: () => Date;

  constructor(options: SqlWebviewTicketRepositoryOptions) {
    if (!options || typeof options.executor?.query !== "function") throw new TypeError("Webview ticket SQL executor is required");
    this.executor = options.executor;
    this.tenantId = normalizeTenantId(options.tenantId);
    this.table = qualifyTable(options.tableName ?? DEFAULT_WEBVIEW_TICKET_TABLE);
    this.now = normalizeClock(options.now);
  }

  async issue(input: WebviewTicketIssueInput): Promise<WebviewTicketIssueResult> {
    const ticketReference = normalizeOptionalReference(input.ticketReference) ?? randomBytes(WEBVIEW_TICKET_HASH_BYTES).toString("base64url");
    const ticketHash = hashWebviewTicket(ticketReference);
    const now = this.currentDate();
    const expiresAt = new Date(now.getTime() + ttlMilliseconds(input.expiresInSeconds));
    const result = await this.executor.query(
      `INSERT INTO ${this.table} (${[
        "id",
        "tenant_id",
        "application_id",
        "platform_id",
        "client_id",
        "ticket_hash",
        "session_hash",
        "binding_hash",
        "redirect_uri",
        "status",
        "created_at",
        "updated_at",
        "expires_at",
      ].map(quoteColumn).join(", ")}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'issued', $10, $10, $11) RETURNING ${ticketColumns()}`,
      [
        randomUUID(),
        this.tenantId,
        normalizeIdentifier(input.applicationId, "applicationId"),
        normalizeIdentifier(input.platformId, "platformId"),
        input.clientId === undefined ? null : normalizeIdentifier(input.clientId, "clientId"),
        ticketHash,
        input.sessionReference === undefined ? null : hashWebviewTicket(normalizeReference(input.sessionReference)),
        input.binding === undefined ? null : hashWebviewTicket(normalizeReference(input.binding)),
        normalizeRedirectUri(input.redirectUri),
        now.toISOString(),
        expiresAt.toISOString(),
      ],
    );
    const record = rowFromResult(result, this.tenantId);
    return { ticket: toPublicTicket(ticketReference, record), record };
  }

  async consume(input: WebviewTicketConsumeRequest): Promise<WebviewTicketRecord | undefined> {
    const now = this.currentDate().toISOString();
    const result = await this.executor.query(
      `UPDATE ${this.table} SET ${quoteColumn("status")} = 'consumed', ${quoteColumn("consumed_at")} = $3, ${quoteColumn("updated_at")} = $3 WHERE ${quoteColumn("tenant_id")} = $1 AND ${quoteColumn("ticket_hash")} = $2 AND ${quoteColumn("status")} = 'issued' AND ${quoteColumn("expires_at")} > $3 AND (${quoteColumn("client_id")} IS NULL OR ${quoteColumn("client_id")} = $4) AND (${quoteColumn("session_hash")} IS NULL OR ${quoteColumn("session_hash")} = $5) AND (${quoteColumn("binding_hash")} IS NULL OR ${quoteColumn("binding_hash")} = $6) RETURNING ${ticketColumns()}`,
      [
        this.tenantId,
        hashWebviewTicket(normalizeReference(input.ticketReference)),
        now,
        input.clientId ?? null,
        input.sessionReference === undefined ? null : hashWebviewTicket(normalizeReference(input.sessionReference)),
        input.binding === undefined ? null : hashWebviewTicket(normalizeReference(input.binding)),
      ],
    );
    const row = firstRow(result);
    return row === undefined ? undefined : mapRecord(row, this.tenantId);
  }

  async cleanupExpired(at = this.currentDate()): Promise<number> {
    const result = await this.executor.query(
      `DELETE FROM ${this.table} WHERE ${quoteColumn("tenant_id")} = $1 AND (${quoteColumn("expires_at")} <= $2 OR ${quoteColumn("status")} IN ('expired', 'revoked', 'consumed'))`,
      [this.tenantId, at.toISOString()],
    );
    return affectedRows(result);
  }

  async purgeExpired(at = this.currentDate()): Promise<number> {
    return this.cleanupExpired(at);
  }

  async revoke(ticketReference: string): Promise<boolean> {
    const result = await this.executor.query(
      `UPDATE ${this.table} SET ${quoteColumn("status")} = 'revoked', ${quoteColumn("revoked_at")} = CURRENT_TIMESTAMP, ${quoteColumn("updated_at")} = CURRENT_TIMESTAMP WHERE ${quoteColumn("tenant_id")} = $1 AND ${quoteColumn("ticket_hash")} = $2 AND ${quoteColumn("status")} <> 'revoked'`,
      [this.tenantId, hashWebviewTicket(normalizeReference(ticketReference))],
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
    if (Number.isNaN(value.getTime())) throw new Error("Webview ticket clock is invalid");
    return value;
  }
}

export const InMemoryWebviewTicketStore = InMemoryWebviewTicketRepository;
export const InMemoryClientTicketRepository = InMemoryWebviewTicketRepository;
export const SqlWebviewTicketStore = SqlWebviewTicketRepository;
export const SqlClientTicketRepository = SqlWebviewTicketRepository;
export const createInMemoryWebviewTicketRepository = (options: InMemoryWebviewTicketRepositoryOptions = {}): InMemoryWebviewTicketRepository => new InMemoryWebviewTicketRepository(options);
export const createWebviewTicketRepository = createInMemoryWebviewTicketRepository;
export const createOpaqueWebviewTicketRepository = createInMemoryWebviewTicketRepository;
export const createSqlWebviewTicketRepository = (options: SqlWebviewTicketRepositoryOptions): SqlWebviewTicketRepository => new SqlWebviewTicketRepository(options);

export function hashWebviewTicket(value: string): string {
  return createHash("sha256").update(normalizeReference(value), "utf8").digest("hex");
}

export const hashWebviewTicketReference = hashWebviewTicket;
export const hashClientWebviewTicket = hashWebviewTicket;

export function generateWebviewTicket(): string {
  return randomBytes(WEBVIEW_TICKET_HASH_BYTES).toString("base64url");
}

export function isWebviewTicketReference(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{16,512}$/u.test(value);
}

function toPublicTicket(ticketReference: string, record: WebviewTicketRecord): WebviewTicket {
  return {
    ticketReference,
    ticket: ticketReference,
    clientKind: "webview",
    redirectUri: record.redirectUri,
    expiresAt: record.expiresAt,
  };
}

function normalizeReference(value: unknown): string {
  if (!isWebviewTicketReference(value)) throw new TypeError("Webview ticket reference is invalid");
  return value;
}

function normalizeOptionalReference(value: unknown): string | undefined {
  return value === undefined ? undefined : normalizeReference(value);
}

function selectTicketReference(first: unknown, second: unknown): string | undefined {
  if (first !== undefined && second !== undefined && first !== second) throw new TypeError("Webview ticket reference aliases conflict");
  return first === undefined ? (second === undefined ? undefined : String(second)) : String(first);
}

function normalizeHash(value: unknown): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/u.test(value)) throw new TypeError("Webview ticket hash is invalid");
  return value;
}

function normalizeIdentifier(value: unknown, field: string): string {
  if (typeof value !== "string") throw new TypeError(`Invalid ${field}`);
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 256 || /[\u0000-\u001f\u007f]/u.test(normalized)) throw new TypeError(`Invalid ${field}`);
  return normalized;
}

function normalizeRedirectUri(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 2048 || value !== value.trim() || /[\u0000-\u001f\u007f\s\\]/u.test(value)) {
    throw new TypeError("Webview ticket redirect URI is invalid");
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new TypeError("Webview ticket redirect URI is invalid");
  }
  if (
    (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
    (parsed.protocol !== "https:" && !isLoopbackHost(parsed.hostname)) ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.hash !== "" ||
    parsed.hostname.length === 0
  ) {
    throw new TypeError("Webview ticket redirect URI is invalid");
  }
  return value;
}

function isLoopbackHost(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}

function normalizeStatus(value: unknown): WebviewTicketStatus {
  if (value !== "issued" && value !== "consumed" && value !== "expired" && value !== "revoked") throw new TypeError("Webview ticket status is invalid");
  return value;
}

function normalizeTenantId(value: unknown): string {
  if (value === undefined) return "default";
  return normalizeIdentifier(value, "tenantId");
}

function normalizeClock(value: (() => Date) | undefined): () => Date {
  const clock = value ?? (() => new Date());
  if (typeof clock !== "function") throw new TypeError("Webview ticket clock is invalid");
  return clock;
}

function ttlMilliseconds(value: number | undefined): number {
  const seconds = value ?? DEFAULT_WEBVIEW_TICKET_TTL_SECONDS;
  if (!Number.isSafeInteger(seconds) || seconds < MIN_WEBVIEW_TICKET_TTL_SECONDS || seconds > MAX_WEBVIEW_TICKET_TTL_SECONDS) {
    throw new TypeError("Webview ticket lifetime is invalid");
  }
  return seconds * 1000;
}

function matchesHash(expected: string | undefined, actual: string): boolean {
  if (expected === undefined) return true;
  const left = Buffer.from(expected, "hex");
  const right = Buffer.from(actual, "hex");
  return left.length === right.length && timingSafeEqual(left, right);
}

function cloneRecord(record: WebviewTicketRecord): WebviewTicketRecord {
  return {
    ...record,
    createdAt: new Date(record.createdAt).toISOString(),
    ...(record.updatedAt === undefined ? {} : { updatedAt: new Date(record.updatedAt).toISOString() }),
    expiresAt: new Date(record.expiresAt).toISOString(),
    ...(record.consumedAt === undefined ? {} : { consumedAt: new Date(record.consumedAt).toISOString() }),
    ...(record.revokedAt === undefined ? {} : { revokedAt: new Date(record.revokedAt).toISOString() }),
  };
}

function qualifyTable(value: string): string {
  return validateApplicationSqlIdentifier(value, "webview ticket table").split(".").map((part) => `"${part}"`).join(".");
}

function quoteColumn(value: string): string {
  return `"${value}"`;
}

function ticketColumns(): string {
  return [
    "id",
    "tenant_id",
    "application_id",
    "platform_id",
    "client_id",
    "ticket_hash",
    "session_hash",
    "binding_hash",
    "redirect_uri",
    "status",
    "created_at",
    "updated_at",
    "consumed_at",
    "expires_at",
    "revoked_at",
  ].map(quoteColumn).join(", ");
}

function mapRecord(row: Record<string, unknown>, fallbackTenantId: string): WebviewTicketRecord {
  const value = (key: string): unknown => {
    const camel = key.replace(/_([a-z])/gu, (_match, letter: string) => letter.toUpperCase());
    const snake = key.replace(/[A-Z]/gu, (letter) => `_${letter.toLowerCase()}`);
    return row[key] ?? row[camel] ?? row[snake];
  };
  return {
    id: requiredString(value("id"), "id"),
    tenantId: requiredString(value("tenantId") ?? fallbackTenantId, "tenantId"),
    applicationId: requiredString(value("applicationId"), "applicationId"),
    platformId: requiredString(value("platformId"), "platformId"),
    ...(value("clientId") === undefined || value("clientId") === null ? {} : { clientId: requiredString(value("clientId"), "clientId") }),
    ticketHash: normalizeHash(value("ticketHash")),
    ...(value("sessionHash") === undefined || value("sessionHash") === null ? {} : { sessionHash: normalizeHash(value("sessionHash")) }),
    ...(value("bindingHash") === undefined || value("bindingHash") === null ? {} : { bindingHash: normalizeHash(value("bindingHash")) }),
    redirectUri: normalizeRedirectUri(value("redirectUri")),
    status: normalizeStatus(value("status")),
    createdAt: requiredDate(value("createdAt"), "createdAt"),
    ...(value("updatedAt") === undefined || value("updatedAt") === null ? {} : { updatedAt: requiredDate(value("updatedAt"), "updatedAt") }),
    ...(value("consumedAt") === undefined || value("consumedAt") === null ? {} : { consumedAt: requiredDate(value("consumedAt"), "consumedAt") }),
    expiresAt: requiredDate(value("expiresAt"), "expiresAt"),
    ...(value("revokedAt") === undefined || value("revokedAt") === null ? {} : { revokedAt: requiredDate(value("revokedAt"), "revokedAt") }),
  };
}

function requiredString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(`Webview ticket ${field} is invalid`);
  return value;
}

function requiredDate(value: unknown, field: string): string {
  const date = value instanceof Date ? value : new Date(typeof value === "string" || typeof value === "number" ? value : NaN);
  if (Number.isNaN(date.getTime())) throw new Error(`Webview ticket ${field} is invalid`);
  return date.toISOString();
}

function resultRows(value: unknown): unknown[] {
  if (Array.isArray(value)) return value;
  if (typeof value === "object" && value !== null && "rows" in value && Array.isArray((value as { rows?: unknown }).rows)) return (value as { rows: unknown[] }).rows;
  throw new Error("Webview ticket result is invalid");
}

function firstRow(value: unknown): Record<string, unknown> | undefined {
  const row = resultRows(value)[0];
  if (row === undefined) return undefined;
  if (typeof row !== "object" || row === null || Array.isArray(row)) throw new Error("Webview ticket row is invalid");
  return row as Record<string, unknown>;
}

function rowFromResult(value: unknown, fallbackTenantId: string): WebviewTicketRecord {
  const row = firstRow(value);
  if (row === undefined) throw new Error("Webview ticket insert failed");
  return mapRecord(row, fallbackTenantId);
}

function affectedRows(value: unknown): number {
  if (typeof value === "object" && value !== null && "rowCount" in value) {
    const count = (value as { rowCount?: unknown }).rowCount;
    if (typeof count === "number" && Number.isSafeInteger(count)) return count;
  }
  return resultRows(value).length;
}
