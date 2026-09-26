import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import {
  Body,
  Controller,
  Get,
  HttpCode,
  Inject,
  Injectable,
  Module,
  Optional,
  Post,
  Req,
  Res,
  UseFilters,
} from "@nestjs/common";
import type { DynamicModule, OnModuleInit, Provider } from "@nestjs/common";
import {
  GetbrickIdaasModule,
  Public,
  type GetbrickAuthLike,
  type GetbrickGuardMode,
} from "@getbrick/idaas-nestjs";
import {
  sanitizePlatformIdentity,
  type PlatformIdentity,
} from "@getbrick/idaas-core";
import type { IdaasProfile, RoleGraph } from "@getbrick/idaas-core";
import type {
  ClientAuthBffClientType,
  ClientAuthBffCodeChallengeMethod,
  ClientAuthBffExchangeRequest,
  ClientAuthBffLogoutResponse,
  ClientAuthBffMeResponse,
  ClientAuthBffRefreshResponse,
  ClientAuthBffSessionReferenceRequest,
  ClientAuthBffSessionResultDto,
  ClientAuthBffStartRequest,
  ClientAuthBffStartResponse,
  ClientAuthBffUserDto,
  ClientAuthBffWebMeResponse,
} from "@getbrick/idaas-contracts";
import { CONTROL_PLANE_ERROR_CODES, ControlPlaneError } from "./errors.js";
import { ControlPlaneExceptionFilter } from "./filter.js";
import {
  normalizeTenantConfig,
  normalizeTenantId,
  qualifyTenantTable,
  quoteTenantSqlIdentifier,
  validateTenantSqlIdentifier,
  type TenantConfig,
  type TenantConfigInput,
} from "./tenant.js";
import { CONTROL_PLANE_BASE_PATH } from "./types.js";

export const CLIENT_AUTH_BFF_BASE_PATH = `${CONTROL_PLANE_BASE_PATH}/client/auth`;
export const CLIENT_AUTH_BFF_STATE_VERSION = 1 as const;
export const CLIENT_AUTH_BFF_DEFAULT_STATE_TTL_MS = 10 * 60 * 1000;
export const CLIENT_AUTH_BFF_MAX_STATE_TTL_MS = 30 * 60 * 1000;
export const CLIENT_AUTH_BFF_STATE_HASH_BYTES = 32;
export const DEFAULT_CLIENT_AUTH_BFF_STATE_TABLE = "gb_idaas_client_auth_bff_state";
export const DEFAULT_SQL_CLIENT_AUTH_BFF_STATE_TABLE = DEFAULT_CLIENT_AUTH_BFF_STATE_TABLE;
export const DEFAULT_CLIENT_AUTH_STATE_TABLE = DEFAULT_CLIENT_AUTH_BFF_STATE_TABLE;
export const CLIENT_AUTH_BINDING_COOKIE_NAME = "gb_client_auth_binding";
export const CLIENT_AUTH_SESSION_HEADER = "x-client-session";
export const CLIENT_AUTH_BFF_SERVICE = "CLIENT_AUTH_BFF_SERVICE";
export const CLIENT_AUTH_BFF_ADAPTER = "CLIENT_AUTH_BFF_ADAPTER";
export const CLIENT_AUTH_BFF_STATE_STORE = "CLIENT_AUTH_BFF_STATE_STORE";
export const CLIENT_AUTH_BFF_SESSION_SERVICE = "CLIENT_AUTH_BFF_SESSION_SERVICE";
export const CLIENT_AUTH_BFF_READINESS = "CLIENT_AUTH_BFF_READINESS";

export type ClientAuthBbfClientKind = ClientAuthBffClientType;

export interface ClientAuthBffTrustedClientConfiguration {
  readonly clientId: string;
  readonly clientType: ClientAuthBffClientType;
  readonly redirectUris: readonly string[];
  readonly scopes?: readonly string[];
  readonly scope?: string;
  readonly [key: string]: unknown;
}

export type ClientAuthBbfClientConfiguration = ClientAuthBffTrustedClientConfiguration;
export type ClientAuthBffServerClientConfiguration = ClientAuthBffTrustedClientConfiguration;

export interface ClientAuthBffAuthorizationInput {
  client: ClientAuthBffTrustedClientConfiguration;
  configuration: ClientAuthBffTrustedClientConfiguration;
  clientConfiguration: ClientAuthBffTrustedClientConfiguration;
  clientConfig: ClientAuthBffTrustedClientConfiguration;
  serverClient: ClientAuthBffTrustedClientConfiguration;
  serverConfiguration: ClientAuthBffTrustedClientConfiguration;
  clientId: string;
  clientType: ClientAuthBffClientType;
  redirectUri: string;
  state: string;
  nonce: string;
  scope: string;
  codeChallenge: string;
  codeChallengeMethod: ClientAuthBffCodeChallengeMethod;
}

export interface ClientAuthBffCodeExchangeInput {
  client: ClientAuthBffTrustedClientConfiguration;
  configuration: ClientAuthBffTrustedClientConfiguration;
  clientConfiguration: ClientAuthBffTrustedClientConfiguration;
  clientConfig: ClientAuthBffTrustedClientConfiguration;
  serverClient: ClientAuthBffTrustedClientConfiguration;
  serverConfiguration: ClientAuthBffTrustedClientConfiguration;
  clientId: string;
  clientType: ClientAuthBffClientType;
  code: string;
  codeVerifier: string;
  redirectUri: string;
  state: string;
  nonce: string;
  scope: string;
  codeChallenge: string;
  codeChallengeMethod: ClientAuthBffCodeChallengeMethod;
}

export interface ClientAuthBbfHostSessionResult {
  sessionReference?: string;
  expiresAt?: string | number | Date;
  clientKind?: ClientAuthBffClientType;
  user?: unknown;
  response?: Response;
}

export interface ClientAuthBbfAdapterResult {
  identity: PlatformIdentity;
  session?: ClientAuthBbfHostSessionResult;
  user?: unknown;
  response?: Response;
}

export type ClientAuthBffAdapterExchangeResult = Response | ClientAuthBbfAdapterResult;

export interface ClientAuthBffHostAdapter {
  createAuthorizationUrl?(
    input: ClientAuthBffAuthorizationInput,
  ): string | URL | Promise<string | URL>;
  authorizationUrl?(
    input: ClientAuthBffAuthorizationInput,
  ): string | URL | Promise<string | URL>;
  getAuthorizationUrl?(
    input: ClientAuthBffAuthorizationInput,
  ): string | URL | Promise<string | URL>;
  start?(
    input: ClientAuthBffAuthorizationInput,
  ): string | URL | Promise<string | URL>;
  exchangeCode?(
    input: ClientAuthBffCodeExchangeInput,
  ): ClientAuthBffAdapterExchangeResult | Promise<ClientAuthBffAdapterExchangeResult>;
  exchange?(
    input: ClientAuthBffCodeExchangeInput,
  ): ClientAuthBffAdapterExchangeResult | Promise<ClientAuthBffAdapterExchangeResult>;
  exchangeAuthorizationCode?(
    input: ClientAuthBffCodeExchangeInput,
  ): ClientAuthBffAdapterExchangeResult | Promise<ClientAuthBffAdapterExchangeResult>;
}

export type ClientAuthBbfHostAdapter = ClientAuthBffHostAdapter;
export type ClientAuthBbfAdapter = ClientAuthBffHostAdapter;
export type ClientAuthBffTrustedHostAdapter = ClientAuthBffHostAdapter;
export type ClientAuthBffHostExchangeInput = ClientAuthBffCodeExchangeInput;

export interface ClientAuthBffStateRecord {
  readonly version: typeof CLIENT_AUTH_BFF_STATE_VERSION;
  readonly stateHash: string;
  readonly nonce: string;
  readonly codeChallenge: string;
  readonly redirectUri: string;
  readonly clientType: ClientAuthBffClientType;
  readonly clientId: string;
  readonly scope: string;
  readonly expiresAt: number;
  readonly bindingHash?: string;
}

export interface ClientAuthBffStateClaim {
  readonly redirectUri?: string;
  readonly clientType?: ClientAuthBffClientType;
  readonly clientId?: string;
  readonly bindingHash?: string;
}

export interface ClientAuthBffStateStore {
  readonly persistent?: boolean;
  save?(record: ClientAuthBffStateRecord): void | Promise<void>;
  put?(record: ClientAuthBffStateRecord): void | Promise<void>;
  set?(record: ClientAuthBffStateRecord): void | Promise<void>;
  consume(
    stateHash: string,
    expected?: ClientAuthBffStateClaim,
  ): ClientAuthBffStateRecord | undefined | Promise<ClientAuthBffStateRecord | undefined>;
  remove?(stateHash: string): void | Promise<void>;
  delete?(stateHash: string): void | Promise<void>;
  revoke?(stateHash: string): void | Promise<void>;
  ready?(): boolean | Promise<boolean>;
}

export interface InMemoryClientAuthBffStateStoreOptions {
  now?: () => number;
  maxEntries?: number;
}

export class InMemoryClientAuthBffStateStore implements ClientAuthBffStateStore {
  readonly persistent = false;
  private readonly records = new Map<string, ClientAuthBffStateRecord>();
  private readonly now: () => number;
  private readonly maxEntries: number;

  constructor(options: InMemoryClientAuthBffStateStoreOptions = {}) {
    this.now = options.now ?? Date.now;
    this.maxEntries = normalizePositiveInteger(options.maxEntries ?? 10_000, 10_000);
    if (typeof this.now !== "function") throw new Error("[getbrick-idaas] client auth state store clock is invalid");
  }

  get size(): number {
    this.removeExpired();
    return this.records.size;
  }

  save(record: ClientAuthBffStateRecord): void {
    assertStateRecord(record);
    this.removeExpired();
    if (this.records.has(record.stateHash)) throw invalidClientAuth("state_collision", "Client authentication state is invalid");
    if (this.records.size >= this.maxEntries) throw invalidClientAuth("state_store_full", "Client authentication is temporarily unavailable");
    this.records.set(record.stateHash, freezeRecord(record));
  }

  async consume(
    stateHash: string,
    expected?: ClientAuthBffStateClaim,
  ): Promise<ClientAuthBffStateRecord | undefined> {
    const normalizedHash = assertHash(stateHash, "state");
    const record = this.records.get(normalizedHash);
    if (record === undefined) return undefined;
    try {
      assertStateRecord(record);
      if (record.expiresAt <= this.clock()) {
        this.records.delete(normalizedHash);
        return undefined;
      }
      if (expected?.redirectUri !== undefined && record.redirectUri !== expected.redirectUri) return undefined;
      if (expected?.clientType !== undefined && record.clientType !== expected.clientType) return undefined;
      if (expected?.clientId !== undefined && record.clientId !== expected.clientId) return undefined;
      if (expected?.bindingHash !== undefined && (record.bindingHash === undefined || !hashesEqual(record.bindingHash, expected.bindingHash))) return undefined;
      this.records.delete(normalizedHash);
      return cloneRecord(record);
    } catch {
      return undefined;
    }
  }

  remove(stateHash: string): void {
    const normalizedHash = assertHash(stateHash, "state");
    this.records.delete(normalizedHash);
  }

  ready(): boolean {
    return true;
  }

  cleanupExpired(): number {
    return this.removeExpired();
  }

  private removeExpired(): number {
    const now = this.clock();
    let removed = 0;
    for (const [key, record] of this.records) {
      if (record.expiresAt <= now) {
        this.records.delete(key);
        removed += 1;
      }
    }
    return removed;
  }

  private clock(): number {
    const value = this.now();
    if (!Number.isSafeInteger(value) || value < 0) throw new Error("[getbrick-idaas] client auth state store clock is invalid");
    return value;
  }
}

export function createInMemoryClientAuthBffStateStore(
  options?: InMemoryClientAuthBffStateStoreOptions,
): InMemoryClientAuthBffStateStore {
  return new InMemoryClientAuthBffStateStore(options);
}

export const InMemoryClientAuthBbfStateStore = InMemoryClientAuthBffStateStore;
export const createClientAuthBbfStateStore = createInMemoryClientAuthBffStateStore;

export interface ClientAuthBffSqlExecutor {
  query(text: string, values?: unknown[]): unknown | Promise<unknown>;
  transaction?<T>(callback: (executor: ClientAuthBffSqlExecutor) => Promise<T>): Promise<T>;
}

export interface ClientAuthBffSqlColumns {
  tenantId: string;
  stateHash: string;
  nonce: string;
  codeChallenge: string;
  redirectUri: string;
  clientType: string;
  clientId: string;
  scope: string;
  bindingHash: string;
  expiresAt: string;
}

export interface ClientAuthBffSqlStateStoreOptions {
  executor?: ClientAuthBffSqlExecutor;
  query?: ClientAuthBffSqlExecutor["query"];
  tableName?: string;
  table?: string;
  schema?: string;
  tenantId?: string;
  tenantColumn?: string | null;
  tenant?: TenantConfigInput;
  tenantConfig?: TenantConfigInput;
  tenantMode?: string;
  mode?: string;
  columns?: Partial<ClientAuthBffSqlColumns>;
  columnNames?: Partial<ClientAuthBffSqlColumns>;
  now?: () => number;
}

export type SqlClientAuthBffStateStoreOptions = ClientAuthBffSqlStateStoreOptions;
export type PostgresClientAuthBffStateStoreOptions = ClientAuthBffSqlStateStoreOptions;
export type ClientAuthBffStateSqlExecutor = ClientAuthBffSqlExecutor;

export type ClientAuthBffSqlStoreInput =
  | ClientAuthBffSqlStateStoreOptions
  | ClientAuthBffSqlExecutor
  | ClientAuthBffSqlExecutor["query"];

type ClientAuthBffSqlClaim = ClientAuthBffStateClaim;

export class PostgresClientAuthBffStateStore implements ClientAuthBffStateStore {
  readonly persistent = true as const;
  readonly tenantId: string;
  readonly tenant: TenantConfig;
  private readonly executor: ClientAuthBffSqlExecutor;
  private readonly table: string;
  private readonly columns: ClientAuthBffSqlColumns;
  private readonly now: () => number;

  constructor(options: ClientAuthBffSqlStateStoreOptions);
  constructor(executor: ClientAuthBffSqlExecutor, options?: Omit<ClientAuthBffSqlStateStoreOptions, "executor" | "query">);
  constructor(query: ClientAuthBffSqlExecutor["query"], options?: Omit<ClientAuthBffSqlStateStoreOptions, "executor" | "query">);
  constructor(
    input: ClientAuthBffSqlStoreInput,
    secondOptions: Omit<ClientAuthBffSqlStateStoreOptions, "executor" | "query"> = {},
  ) {
    const options = normalizeClientAuthBffSqlOptions(input, secondOptions);
    this.tenant = normalizeTenantConfig({
      ...(options.tenant ?? {}),
      ...(options.tenantConfig ?? {}),
      ...(options.tenantMode === undefined ? {} : { mode: options.tenantMode }),
      ...(options.mode === undefined ? {} : { mode: options.mode }),
      ...(options.tenantId === undefined ? {} : { tenantId: options.tenantId }),
      ...(options.tenantColumn === undefined ? {} : { tenantColumn: options.tenantColumn }),
      ...(options.schema === undefined ? {} : { schema: options.schema }),
    });
    this.tenantId = this.tenant.tenantId;
    this.executor = normalizeClientAuthBffSqlExecutor(options);
    if (this.tenant.requireTransactions && typeof this.executor.transaction !== "function") {
      throw new TypeError("Shared client auth BFF state requires a transaction-capable SQL executor");
    }
    this.table = quoteTenantSqlIdentifier(
      qualifyTenantTable(options.tableName ?? options.table ?? DEFAULT_CLIENT_AUTH_BFF_STATE_TABLE, this.tenant.schema),
      "client auth BFF state table",
    );
    this.columns = normalizeClientAuthBffSqlColumns(options, this.tenant.tenantColumn);
    this.now = normalizeClientAuthBffSqlClock(options.now);
  }

  async save(record: ClientAuthBffStateRecord): Promise<void> {
    assertStateRecord(record);
    const values: unknown[] = [
      this.tenantId,
      record.stateHash,
      record.nonce,
      record.codeChallenge,
      record.redirectUri,
      record.clientType,
      record.clientId,
      record.scope,
      record.bindingHash ?? null,
      clientAuthBffSqlTimestamp(record.expiresAt),
    ];
    await this.executor.query(
      `INSERT INTO ${this.table} (${this.stateColumnList()}) VALUES (${values.map((_value, index) => `$${index + 1}`).join(", ")})`,
      values,
    );
  }

  async consume(
    stateHash: string,
    expected?: ClientAuthBffStateClaim,
  ): Promise<ClientAuthBffStateRecord | undefined> {
    const normalizedHash = assertHash(stateHash, "state");
    const claim = normalizeClientAuthBffSqlClaim(expected);
    const now = this.clock();
    const values: unknown[] = [this.tenantId, normalizedHash, clientAuthBffSqlTimestamp(now)];
    const clauses: string[] = [
      `${this.quote(this.columns.tenantId)} = $1`,
      `${this.quote(this.columns.stateHash)} = $2`,
      `${this.quote(this.columns.expiresAt)} > $3`,
    ];
    const addClaimClause = (column: string, value: unknown): void => {
      values.push(value);
      clauses.push(`${this.quote(column)} = $${values.length}`);
    };
    if (claim.redirectUri !== undefined) addClaimClause(this.columns.redirectUri, claim.redirectUri);
    if (claim.clientId !== undefined) addClaimClause(this.columns.clientId, claim.clientId);
    if (claim.clientType !== undefined) addClaimClause(this.columns.clientType, claim.clientType);
    if (claim.bindingHash !== undefined) addClaimClause(this.columns.bindingHash, claim.bindingHash);
    else if (claim.clientType !== undefined) clauses.push(`${this.quote(this.columns.bindingHash)} IS NULL`);
    const result = await this.executor.query(
      `DELETE FROM ${this.table} WHERE ${clauses.join(" AND ")} RETURNING ${this.stateColumnList()}`,
      values,
    );
    const rows = clientAuthBffSqlResultRows(result);
    if (rows.length === 0) return undefined;
    if (rows.length !== 1) throw new Error("Client auth BFF state SQL result is invalid");
    const record = clientAuthBffRecordFromRow(rows[0], this.tenantId);
    if (record.stateHash !== normalizedHash || record.expiresAt <= now || !clientAuthBffClaimMatches(record, claim)) {
      throw new Error("Client auth BFF state SQL row is invalid");
    }
    return cloneRecord(record);
  }

  async remove(stateHash: string): Promise<void> {
    const normalizedHash = assertHash(stateHash, "state");
    await this.executor.query(
      `DELETE FROM ${this.table} WHERE ${this.quote(this.columns.tenantId)} = $1 AND ${this.quote(this.columns.stateHash)} = $2`,
      [this.tenantId, normalizedHash],
    );
  }

  async delete(stateHash: string): Promise<void> {
    return this.remove(stateHash);
  }

  async revoke(stateHash: string): Promise<void> {
    return this.remove(stateHash);
  }

  async cleanupExpired(at = this.clock()): Promise<number> {
    const timestamp = clientAuthBffSqlTimestamp(normalizeClientAuthBffSqlNow(at));
    const result = await this.executor.query(
      `DELETE FROM ${this.table} WHERE ${this.quote(this.columns.tenantId)} = $1 AND ${this.quote(this.columns.expiresAt)} <= $2`,
      [this.tenantId, timestamp],
    );
    return clientAuthBffAffectedRows(result);
  }

  async ready(): Promise<boolean> {
    try {
      const result = await this.executor.query(`SELECT 1 FROM ${this.table} LIMIT 0`, []);
      return clientAuthBffSqlReadResultIsValid(result);
    } catch {
      return false;
    }
  }

  private clock(): number {
    return normalizeClientAuthBffSqlNow(this.now());
  }

  private stateColumnList(): string {
    return [
      this.columns.tenantId,
      this.columns.stateHash,
      this.columns.nonce,
      this.columns.codeChallenge,
      this.columns.redirectUri,
      this.columns.clientType,
      this.columns.clientId,
      this.columns.scope,
      this.columns.bindingHash,
      this.columns.expiresAt,
    ].map((column) => this.quote(column)).join(", ");
  }

  private quote(value: string): string {
    return quoteTenantSqlIdentifier(value, "client auth BFF state column");
  }
}

export { PostgresClientAuthBffStateStore as SqlClientAuthBffStateStore };

export function createSqlClientAuthBffStateStore(
  input: ClientAuthBffSqlStoreInput,
  options?: Omit<ClientAuthBffSqlStateStoreOptions, "executor" | "query">,
): PostgresClientAuthBffStateStore {
  return new PostgresClientAuthBffStateStore(input as ClientAuthBffSqlExecutor, options);
}

export const createPostgresClientAuthBffStateStore = createSqlClientAuthBffStateStore;

function normalizeClientAuthBffSqlOptions(
  input: ClientAuthBffSqlStoreInput,
  secondOptions: Omit<ClientAuthBffSqlStateStoreOptions, "executor" | "query">,
): ClientAuthBffSqlStateStoreOptions {
  if (typeof input === "function") return { ...secondOptions, query: input };
  if (isClientAuthBffSqlExecutor(input) && !hasClientAuthBffSqlOptions(input)) {
    return { ...secondOptions, executor: input };
  }
  return { ...input, ...secondOptions };
}

function isClientAuthBffSqlExecutor(value: unknown): value is ClientAuthBffSqlExecutor {
  return isObjectLike(value) && typeof value.query === "function";
}

function hasClientAuthBffSqlOptions(value: ClientAuthBffSqlExecutor): boolean {
  return [
    "executor",
    "tableName",
    "table",
    "schema",
    "tenantId",
    "tenantColumn",
    "tenant",
    "tenantConfig",
    "tenantMode",
    "mode",
    "columns",
    "columnNames",
    "now",
  ].some((key) => Object.prototype.hasOwnProperty.call(value, key));
}

function normalizeClientAuthBffSqlExecutor(options: ClientAuthBffSqlStateStoreOptions): ClientAuthBffSqlExecutor {
  if (isClientAuthBffSqlExecutor(options.executor)) return options.executor;
  if (typeof options.query === "function") return { query: options.query };
  throw new TypeError("Client auth BFF SQL executor is required");
}

function normalizeClientAuthBffSqlColumns(
  options: ClientAuthBffSqlStateStoreOptions,
  tenantColumn: string,
): ClientAuthBffSqlColumns {
  const defaults: ClientAuthBffSqlColumns = {
    tenantId: tenantColumn,
    stateHash: "state_hash",
    nonce: "nonce",
    codeChallenge: "code_challenge",
    redirectUri: "redirect_uri",
    clientType: "client_type",
    clientId: "client_id",
    scope: "scope",
    bindingHash: "binding_hash",
    expiresAt: "expires_at",
  };
  const source = { ...defaults, ...(options.columns ?? {}), ...(options.columnNames ?? {}) };
  const output = {} as ClientAuthBffSqlColumns;
  const allowed = new Set(["tenantId", "stateHash", "nonce", "codeChallenge", "redirectUri", "clientType", "clientId", "scope", "bindingHash", "expiresAt"]);
  for (const [key, value] of Object.entries(source)) {
    if (!allowed.has(key)) throw new TypeError(`Invalid client auth BFF SQL column for ${key}`);
    if (typeof value !== "string" || value.includes(".")) throw new TypeError(`Invalid client auth BFF SQL column for ${key}`);
    const normalized = validateTenantSqlIdentifier(value, `client auth BFF SQL column ${key}`);
    const compact = normalized.replace(/[-_]/gu, "").toLowerCase();
    if (["state", "codeverifier", "rawstate", "rawcodeverifier", "clientsecret"].includes(compact)) {
      throw new TypeError(`Invalid client auth BFF SQL column for ${key}`);
    }
    output[key as keyof ClientAuthBffSqlColumns] = normalized;
  }
  if (options.tenantColumn !== undefined) output.tenantId = validateTenantSqlIdentifier(options.tenantColumn, "client auth BFF tenant column");
  return output;
}

function normalizeClientAuthBffSqlClock(value: (() => number) | undefined): () => number {
  const clock = value ?? Date.now;
  if (typeof clock !== "function") throw new TypeError("Client auth BFF SQL clock is invalid");
  return clock;
}

function normalizeClientAuthBffSqlNow(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError("Client auth BFF SQL clock is invalid");
  return value;
}

function clientAuthBffSqlTimestamp(value: number): string {
  const normalized = normalizeClientAuthBffSqlNow(value);
  const date = new Date(normalized);
  if (!Number.isFinite(date.getTime())) throw new TypeError("Client auth BFF SQL timestamp is invalid");
  return date.toISOString();
}

function normalizeClientAuthBffSqlClaim(value: unknown): ClientAuthBffSqlClaim {
  if (value === undefined) return {};
  if (!isObjectLike(value)) throw new TypeError("Client auth BFF state claim is invalid");
  const clientType = value.clientType;
  if (clientType !== undefined && clientType !== "web" && clientType !== "native") {
    throw new TypeError("Client auth BFF state claim is invalid");
  }
  const redirectUri = value.redirectUri;
  if (redirectUri !== undefined) {
    if (typeof redirectUri !== "string") throw new TypeError("Client auth BFF state claim is invalid");
    assertSafeRedirectUri(redirectUri, true, clientType ?? "native");
  }
  const clientId = value.clientId;
  if (clientId !== undefined) parseClientId(clientId);
  const bindingHash = value.bindingHash;
  if (bindingHash !== undefined) assertHash(bindingHash, "binding");
  return {
    ...(redirectUri === undefined ? {} : { redirectUri: redirectUri as string }),
    ...(clientType === undefined ? {} : { clientType }),
    ...(clientId === undefined ? {} : { clientId: clientId as string }),
    ...(bindingHash === undefined ? {} : { bindingHash: bindingHash as string }),
  };
}

function clientAuthBffClaimMatches(record: ClientAuthBffStateRecord, claim: ClientAuthBffSqlClaim): boolean {
  if (claim.redirectUri !== undefined && record.redirectUri !== claim.redirectUri) return false;
  if (claim.clientId !== undefined && record.clientId !== claim.clientId) return false;
  if (claim.clientType !== undefined && record.clientType !== claim.clientType) return false;
  if (claim.clientType !== undefined && claim.bindingHash === undefined && record.bindingHash !== undefined) return false;
  if (claim.bindingHash !== undefined && (record.bindingHash === undefined || !hashesEqual(record.bindingHash, claim.bindingHash))) return false;
  return true;
}

function clientAuthBffSqlResultRows(value: unknown): unknown[] {
  if (Array.isArray(value)) return value;
  if (isObjectLike(value) && Array.isArray(value.rows)) {
    const count = clientAuthBffAffectedCount(value);
    if (count !== undefined && count !== value.rows.length) throw new Error("Client auth BFF state SQL result is invalid");
    return value.rows;
  }
  throw new Error("Client auth BFF state SQL result is invalid");
}

function clientAuthBffSqlReadResultIsValid(value: unknown): boolean {
  if (Array.isArray(value)) return value.length === 0;
  if (!isObjectLike(value) || !Array.isArray(value.rows)) return false;
  if (value.rows.length !== 0) return false;
  try {
    const count = clientAuthBffAffectedCount(value);
    return count === undefined || count >= 0;
  } catch {
    return false;
  }
}

function clientAuthBffAffectedRows(value: unknown): number {
  const count = clientAuthBffAffectedCount(value);
  if (count !== undefined) {
    if (isObjectLike(value) && Array.isArray(value.rows) && value.rows.length > 0) throw new Error("Client auth BFF state SQL result is invalid");
    return count;
  }
  return clientAuthBffSqlResultRows(value).length;
}

function clientAuthBffAffectedCount(value: unknown): number | undefined {
  if (!isObjectLike(value) || !Object.prototype.hasOwnProperty.call(value, "rowCount")) return undefined;
  const count = value.rowCount;
  if (typeof count === "number" && Number.isSafeInteger(count) && count >= 0) return count;
  if (typeof count === "bigint" && count >= 0n && Number.isSafeInteger(Number(count))) return Number(count);
  throw new Error("Client auth BFF state SQL result is invalid");
}

function clientAuthBffRecordFromRow(value: unknown, fallbackTenantId: string): ClientAuthBffStateRecord {
  if (!isRecord(value)) throw new Error("Client auth BFF state SQL row is invalid");
  const allowed = new Set(["tenantid", "statehash", "nonce", "codechallenge", "redirecturi", "clienttype", "clientid", "scope", "bindinghash", "expiresat", "version"]);
  for (const key of Object.keys(value)) {
    const normalized = key.replace(/[^A-Za-z0-9]/gu, "").toLowerCase();
    if (!allowed.has(normalized)) throw new Error("Client auth BFF state SQL row is invalid");
  }
  const read = (key: string): unknown => {
    const snake = key.replace(/[A-Z]/gu, (letter) => `_${letter.toLowerCase()}`);
    const camel = key.replace(/_([a-z])/gu, (_match, letter: string) => letter.toUpperCase());
    if (Object.prototype.hasOwnProperty.call(value, key)) return value[key];
    if (Object.prototype.hasOwnProperty.call(value, camel)) return value[camel];
    if (Object.prototype.hasOwnProperty.call(value, snake)) return value[snake];
    return undefined;
  };
  const requiredString = (key: string): string => {
    const item = read(key);
    if (typeof item !== "string" || item.length === 0) throw new Error(`Client auth BFF state SQL row ${key} is invalid`);
    return item;
  };
  const rawTenantId = requiredString("tenantId");
  const tenantId = normalizeTenantId(rawTenantId);
  if (rawTenantId !== tenantId || tenantId !== fallbackTenantId) throw new Error("Client auth BFF state SQL row tenant is invalid");
  const version = read("version");
  if (version !== undefined && version !== 1) throw new Error("Client auth BFF state SQL row version is invalid");
  const bindingValue = read("bindingHash");
  const record: ClientAuthBffStateRecord = {
    version: CLIENT_AUTH_BFF_STATE_VERSION,
    stateHash: requiredString("stateHash"),
    nonce: requiredString("nonce"),
    codeChallenge: requiredString("codeChallenge"),
    redirectUri: requiredString("redirectUri"),
    clientType: requiredString("clientType") as ClientAuthBffClientType,
    clientId: requiredString("clientId"),
    scope: requiredString("scope"),
    expiresAt: clientAuthBffSqlTimestampFromRow(read("expiresAt")),
    ...(bindingValue === undefined || bindingValue === null ? {} : { bindingHash: requiredString("bindingHash") }),
  };
  try {
    assertStateRecord(record);
  } catch {
    throw new Error("Client auth BFF state SQL row is invalid");
  }
  return record;
}

function clientAuthBffSqlTimestampFromRow(value: unknown): number {
  if (value instanceof Date) {
    const time = value.getTime();
    if (!Number.isSafeInteger(time) || time < 0) throw new Error("Client auth BFF state SQL row expiresAt is invalid");
    return time;
  }
  if (typeof value === "number") return normalizeClientAuthBffSqlNow(value);
  if (typeof value === "bigint" && value >= 0n && Number.isSafeInteger(Number(value))) return Number(value);
  if (typeof value === "string" && value.length > 0) {
    if (/^\d+$/u.test(value)) {
      const numeric = Number(value);
      if (Number.isSafeInteger(numeric)) return numeric;
    }
    const time = new Date(value).getTime();
    if (Number.isSafeInteger(time) && time >= 0) return time;
  }
  throw new Error("Client auth BFF state SQL row expiresAt is invalid");
}

export interface ClientAuthBffBindingContext {
  bindingHash?: string;
  request?: unknown;
}

export interface ClientAuthBffExchangeOutcome {
  clientType: ClientAuthBffClientType;
  publicResult?: ClientAuthBffSessionResultDto;
  response?: Response;
  responseHeaders?: ClientAuthBffSafeResponseHeaders;
}

export interface ClientAuthBffWebSessionOutcome {
  responseHeaders?: ClientAuthBffSafeResponseHeaders;
  user?: ClientAuthBffUserDto;
}

export interface ClientAuthBffSafeResponseHeaders {
  setCookie: string[];
  cacheControl?: string;
  pragma?: string;
}

export interface ClientAuthBffSessionService {
  refresh?(input: ClientAuthBffSessionReferenceRequest): unknown;
  refreshSession?(input: ClientAuthBffSessionReferenceRequest): unknown;
  logout?(input: ClientAuthBffSessionReferenceRequest): unknown;
  logoutSession?(input: ClientAuthBffSessionReferenceRequest): unknown;
  me?(input: ClientAuthBffSessionReferenceRequest): unknown;
  get?(input: ClientAuthBffSessionReferenceRequest): unknown;
  getSession?(input: ClientAuthBffSessionReferenceRequest): unknown;
  refreshWeb?(request: unknown): unknown;
  refreshCookie?(request: unknown): unknown;
  logoutWeb?(request: unknown): unknown;
  logoutCookie?(request: unknown): unknown;
  meWeb?(request: unknown): unknown;
  meCookie?(request: unknown): unknown;
  ready?(): boolean | Promise<boolean>;
}

export type ClientAuthBbfSessionService = ClientAuthBffSessionService;

export interface ClientAuthBffServiceOptions {
  adapter?: ClientAuthBffHostAdapter;
  hostAdapter?: ClientAuthBffHostAdapter;
  store?: ClientAuthBffStateStore;
  stateStore?: ClientAuthBffStateStore;
  transactionStore?: ClientAuthBffStateStore;
  clientConfiguration?: ClientAuthBffTrustedClientConfiguration;
  clientConfig?: ClientAuthBffTrustedClientConfiguration | ((input: {
    clientId: string;
    clientType: ClientAuthBffClientType;
  }) => ClientAuthBffTrustedClientConfiguration | undefined | Promise<ClientAuthBffTrustedClientConfiguration | undefined>);
  configurations?: readonly ClientAuthBffTrustedClientConfiguration[] | Readonly<Record<string, ClientAuthBffTrustedClientConfiguration>> | ReadonlyMap<string, ClientAuthBffTrustedClientConfiguration>;
  clients?: readonly ClientAuthBffTrustedClientConfiguration[] | Readonly<Record<string, ClientAuthBffTrustedClientConfiguration>> | ReadonlyMap<string, ClientAuthBffTrustedClientConfiguration>;
  resolveClientConfiguration?: (input: {
    clientId: string;
    clientType: ClientAuthBffClientType;
  }) => ClientAuthBffTrustedClientConfiguration | undefined | Promise<ClientAuthBffTrustedClientConfiguration | undefined>;
  resolveClient?: (input: {
    clientId: string;
    clientType: ClientAuthBffClientType;
  }) => ClientAuthBffTrustedClientConfiguration | undefined | Promise<ClientAuthBffTrustedClientConfiguration | undefined>;
  clientResolver?: (input: {
    clientId: string;
    clientType: ClientAuthBffClientType;
  }) => ClientAuthBffTrustedClientConfiguration | undefined | Promise<ClientAuthBffTrustedClientConfiguration | undefined>;
  clientConfigResolver?: (input: {
    clientId: string;
    clientType: ClientAuthBffClientType;
  }) => ClientAuthBffTrustedClientConfiguration | undefined | Promise<ClientAuthBffTrustedClientConfiguration | undefined>;
  sessionService?: ClientAuthBffSessionService;
  stateTtlMs?: number;
  stateTtlSeconds?: number;
  transactionTtlMs?: number;
  ttlMs?: number;
  now?: () => number;
  allowInsecureHttp?: boolean;
  allowLoopbackHttp?: boolean;
  trustedOrigins?: readonly string[];
  profile?: IdaasProfile;
}

export type ClientAuthBffServiceConstructionOptions = Omit<ClientAuthBffServiceOptions, "adapter">;

@Injectable()
export class ClientAuthBffService {
  private readonly adapter: ClientAuthBffHostAdapter;
  private readonly store: ClientAuthBffStateStore;
  private readonly sessionService?: ClientAuthBffSessionService;
  private readonly now: () => number;
  private readonly stateTtlMs: number;
  private readonly allowLoopbackHttp: boolean;
  private readonly trustedOrigins?: readonly string[];
  private readonly singleConfiguration?: ClientAuthBffTrustedClientConfiguration;
  private readonly configurations?: ClientAuthBffServiceOptions["configurations"];
  private readonly clients?: ClientAuthBffServiceOptions["clients"];
  private readonly resolveClientConfiguration?: ClientAuthBffServiceOptions["resolveClientConfiguration"];

  constructor(options: ClientAuthBffServiceOptions);
  constructor(adapter: ClientAuthBffHostAdapter, options?: ClientAuthBffServiceConstructionOptions);
  constructor(
    optionsOrAdapter: ClientAuthBffServiceOptions | ClientAuthBffHostAdapter,
    secondaryOptions: ClientAuthBffServiceConstructionOptions = {},
  ) {
    const options: ClientAuthBffServiceOptions = isValidAdapter(optionsOrAdapter)
      ? { ...secondaryOptions, adapter: optionsOrAdapter }
      : optionsOrAdapter as ClientAuthBffServiceOptions;
    if (options === null || typeof options !== "object") throw new Error("[getbrick-idaas] client auth BFF configuration is invalid");
    const adapter = options.adapter ?? options.hostAdapter;
    if (!isValidAdapter(adapter)) throw new Error("[getbrick-idaas] client auth BFF adapter is invalid");
    const profile = options.profile ?? (process.env.NODE_ENV === "production" ? "production" : "development");
    const configuredStore = options.store ?? options.stateStore ?? options.transactionStore;
    if (configuredStore !== undefined && !isValidStateStore(configuredStore)) {
      throw new Error("[getbrick-idaas] client auth BFF state store is invalid");
    }
    if (profile === "production" && configuredStore === undefined) {
      throw new Error("[getbrick-idaas] production client auth BFF requires a state store");
    }
    if (profile === "production" && (configuredStore instanceof InMemoryClientAuthBffStateStore || configuredStore?.persistent !== true)) {
      throw new Error("[getbrick-idaas] production client auth BFF requires a persistent state store");
    }
    if (profile === "production" && typeof configuredStore?.ready !== "function") {
      throw new Error("[getbrick-idaas] production client auth BFF requires a readiness-checkable state store");
    }
    this.adapter = adapter;
    this.store = configuredStore ?? new InMemoryClientAuthBffStateStore({ now: options.now });
    this.sessionService = options.sessionService;
    this.now = options.now ?? Date.now;
    this.stateTtlMs = normalizeStateTtl(options.stateTtlMs ?? options.transactionTtlMs ?? options.ttlMs, options.stateTtlSeconds);
    this.allowLoopbackHttp = profile === "production" ? false : options.allowLoopbackHttp ?? options.allowInsecureHttp ?? true;
    this.trustedOrigins = normalizeTrustedOrigins(options.trustedOrigins);
    this.singleConfiguration = options.clientConfiguration ?? (typeof options.clientConfig === "function" ? undefined : options.clientConfig);
    this.configurations = options.configurations;
    this.clients = options.clients;
    this.resolveClientConfiguration = options.resolveClientConfiguration ?? options.resolveClient ?? options.clientResolver ?? options.clientConfigResolver ?? (typeof options.clientConfig === "function" ? options.clientConfig : undefined);
    if (typeof this.now !== "function") throw new Error("[getbrick-idaas] client auth BFF clock is invalid");
  }

  async start(input: unknown, context: ClientAuthBffBindingContext = {}): Promise<ClientAuthBffStartResponse> {
    const request = parseStartRequest(input, this.allowLoopbackHttp);
    this.assertRequestOrigin(context.request, request.clientType, request.redirectUri);
    const configuration = await this.resolveClient(request.clientId, request.clientType);
    assertScopeAllowed(request.scope, configuration.scopes);
    assertRedirectAllowed(request.redirectUri, configuration.redirectUris, request.clientType, this.allowLoopbackHttp);
    const bindingHash = this.readBindingHash(context, request.clientType);
    const now = this.clock();
    const expiresAt = now + this.stateTtlMs;
    const stateHash = hashText(request.state);
    const record: ClientAuthBffStateRecord = {
      version: CLIENT_AUTH_BFF_STATE_VERSION,
      stateHash,
      nonce: request.nonce,
      codeChallenge: request.codeChallenge,
      redirectUri: request.redirectUri,
      clientType: request.clientType,
      clientId: request.clientId,
      scope: request.scope,
      expiresAt,
      ...(bindingHash === undefined ? {} : { bindingHash }),
    };
    try {
      await this.saveState(record);
    } catch (error) {
      if (error instanceof ControlPlaneError) throw error;
      throw unavailableClientAuth("state_store_unavailable");
    }
    try {
      const rawUrl = await this.createAuthorizationUrl({
        client: configuration,
        configuration,
        clientConfiguration: configuration,
        clientConfig: configuration,
        serverClient: configuration,
        serverConfiguration: configuration,
        clientId: request.clientId,
        clientType: request.clientType,
        redirectUri: request.redirectUri,
        state: request.state,
        nonce: request.nonce,
        scope: request.scope,
        codeChallenge: request.codeChallenge,
        codeChallengeMethod: request.codeChallengeMethod,
      });
      const authorizationUrl = assertAuthorizationUrl(rawUrl, request.state, request.redirectUri, request.scope, this.allowLoopbackHttp, request.clientId, request.nonce, request.codeChallenge, request.clientType);
      return {
        authorizationUrl,
        state: request.state,
        expiresAt: new Date(expiresAt).toISOString(),
        redirectUri: request.redirectUri,
      };
    } catch (error) {
      await this.discardState(stateHash);
      if (error instanceof ControlPlaneError) throw error;
      throw unavailableClientAuth("authorization_unavailable");
    }
  }

  async exchange(input: unknown, context: ClientAuthBffBindingContext = {}): Promise<ClientAuthBffExchangeOutcome> {
    const request = parseExchangeRequest(input, this.allowLoopbackHttp);
    this.assertRequestOrigin(context.request, request.clientType, request.redirectUri);
    const bindingHash = this.readBindingHash(context, request.clientType);
    const stateHash = hashText(request.state);
    let transaction: ClientAuthBffStateRecord | undefined;
    try {
      transaction = await this.store.consume(stateHash, {
        redirectUri: request.redirectUri,
        clientId: request.clientId,
        clientType: request.clientType,
        ...(bindingHash === undefined ? {} : { bindingHash }),
      });
    } catch (error) {
      if (error instanceof ControlPlaneError) throw error;
      throw unavailableClientAuth("state_store_unavailable");
    }
    if (transaction === undefined) throw invalidClientAuth("invalid_state", "Client authentication state is invalid");
    assertConsumedTransaction(transaction, stateHash, request.redirectUri, request.clientId, request.clientType, this.clock());
    if (transaction.clientType === "web") {
      if (bindingHash === undefined) throw invalidClientAuth("binding_required", "Client authentication binding is required");
      if (!hashesEqual(transaction.bindingHash, bindingHash)) throw invalidClientAuth("binding_mismatch", "Client authentication binding is invalid");
    } else if (transaction.bindingHash !== undefined) {
      throw invalidClientAuth("binding_not_allowed", "Client authentication binding is invalid");
    }
    const configuration = await this.resolveClient(transaction.clientId, transaction.clientType);
    assertRedirectAllowed(transaction.redirectUri, configuration.redirectUris, transaction.clientType, this.allowLoopbackHttp);
    verifyPkceS256(request.codeVerifier, transaction.codeChallenge);
    let rawResult: ClientAuthBffAdapterExchangeResult;
    try {
      rawResult = await this.exchangeCode({
        client: configuration,
        configuration,
        clientConfiguration: configuration,
        clientConfig: configuration,
        serverClient: configuration,
        serverConfiguration: configuration,
        clientId: transaction.clientId,
        clientType: transaction.clientType,
        code: request.code,
        codeVerifier: request.codeVerifier,
        redirectUri: transaction.redirectUri,
        state: request.state,
        nonce: transaction.nonce,
        scope: transaction.scope,
        codeChallenge: transaction.codeChallenge,
        codeChallengeMethod: "S256",
      });
    } catch (error) {
      if (error instanceof ControlPlaneError) throw error;
      throw unavailableClientAuth("exchange_unavailable");
    }
    try {
      return normalizeAdapterExchangeResult(rawResult, transaction.clientType, request.code, request.state);
    } catch (error) {
      if (error instanceof ControlPlaneError) throw error;
      throw unavailableClientAuth("exchange_unavailable");
    }
  }

  async refresh(input: ClientAuthBffSessionReferenceRequest): Promise<ClientAuthBffRefreshResponse> {
    const result = await this.sessionOperation("refresh", input);
    if (result === undefined) throw invalidClientAuth("invalid_session_result", "Client session result is invalid");
    return result;
  }

  async logout(input: ClientAuthBffSessionReferenceRequest): Promise<ClientAuthBffLogoutResponse | undefined> {
    return this.sessionOperation("logout", input);
  }

  async me(input: ClientAuthBffSessionReferenceRequest): Promise<ClientAuthBffMeResponse> {
    const result = await this.sessionOperation("me", input);
    if (result === undefined) throw invalidClientAuth("invalid_session_result", "Client session result is invalid");
    return result;
  }

  async getSession(input: ClientAuthBffSessionReferenceRequest): Promise<ClientAuthBffMeResponse> {
    return this.me(input);
  }

  async startOidc(input: unknown, context: ClientAuthBffBindingContext = {}): Promise<ClientAuthBffStartResponse> {
    return this.start(input, context);
  }

  async exchangeAuthorizationCode(input: unknown, context: ClientAuthBffBindingContext = {}): Promise<ClientAuthBffExchangeOutcome> {
    return this.exchange(input, context);
  }

  async exchangeCallback(input: unknown, context: ClientAuthBffBindingContext = {}): Promise<ClientAuthBffExchangeOutcome> {
    return this.exchange(input, context);
  }

  async refreshSession(input: ClientAuthBffSessionReferenceRequest): Promise<ClientAuthBffRefreshResponse> {
    return this.refresh(input);
  }

  async logoutSession(input: ClientAuthBffSessionReferenceRequest): Promise<ClientAuthBffLogoutResponse | undefined> {
    return this.logout(input);
  }

  async refreshWeb(request: unknown): Promise<ClientAuthBffWebSessionOutcome> {
    return this.webSessionOperation("refresh", request);
  }

  async logoutWeb(request: unknown): Promise<ClientAuthBffWebSessionOutcome> {
    return this.webSessionOperation("logout", request);
  }

  async meWeb(request: unknown): Promise<ClientAuthBffWebMeResponse> {
    const result = await this.webSessionOperation("me", request);
    if (result.user === undefined) throw invalidClientAuth("invalid_session_result", "Client session result is invalid");
    return { user: result.user };
  }

  async refreshCookie(request: unknown): Promise<ClientAuthBffWebSessionOutcome> {
    return this.refreshWeb(request);
  }

  async logoutCookie(request: unknown): Promise<ClientAuthBffWebSessionOutcome> {
    return this.logoutWeb(request);
  }

  async meCookie(request: unknown): Promise<ClientAuthBffWebMeResponse> {
    return this.meWeb(request);
  }

  private async createAuthorizationUrl(input: ClientAuthBffAuthorizationInput): Promise<string | URL> {
    const adapter = this.adapter as ClientAuthBffHostAdapter & {
      authorizationUrl?: ClientAuthBffHostAdapter["createAuthorizationUrl"];
      getAuthorizationUrl?: ClientAuthBffHostAdapter["createAuthorizationUrl"];
      start?: ClientAuthBffHostAdapter["createAuthorizationUrl"];
    };
    const method = adapter.createAuthorizationUrl ?? adapter.authorizationUrl ?? adapter.getAuthorizationUrl ?? adapter.start;
    if (typeof method !== "function") throw new Error("[getbrick-idaas] client auth adapter cannot create authorization URLs");
    return method.call(adapter, input);
  }

  private async exchangeCode(input: ClientAuthBffCodeExchangeInput): Promise<ClientAuthBffAdapterExchangeResult> {
    const adapter = this.adapter as ClientAuthBffHostAdapter & {
      exchange?: ClientAuthBffHostAdapter["exchangeCode"];
      exchangeAuthorizationCode?: ClientAuthBffHostAdapter["exchangeCode"];
    };
    const method = adapter.exchangeCode ?? adapter.exchange ?? adapter.exchangeAuthorizationCode;
    if (typeof method !== "function") throw new Error("[getbrick-idaas] client auth adapter cannot exchange codes");
    return method.call(adapter, input);
  }

  private async webSessionOperation(
    operation: "refresh" | "logout" | "me",
    request: unknown,
  ): Promise<ClientAuthBffWebSessionOutcome> {
    this.assertCookieRequestOrigin(request);
    const service = this.sessionService;
    if (service === undefined) throw unavailableClientAuth("session_service_unavailable");
    let method: ((value: unknown) => unknown) | undefined;
    if (operation === "refresh") method = service.refreshWeb?.bind(service) ?? service.refreshCookie?.bind(service);
    if (operation === "logout") method = service.logoutWeb?.bind(service) ?? service.logoutCookie?.bind(service);
    if (operation === "me") method = service.meWeb?.bind(service) ?? service.meCookie?.bind(service);
    if (method === undefined) throw unavailableClientAuth("session_service_unavailable");
    let value: unknown;
    try {
      value = await method(request);
    } catch (error) {
      if (error instanceof ControlPlaneError) throw error;
      throw unavailableClientAuth("session_service_unavailable");
    }
    if (operation === "me") {
      if (isResponse(value)) throw invalidClientAuth("invalid_session_result", "Client session result is invalid");
      try {
        return { user: normalizeWebUserResult(value) };
      } catch (error) {
        if (error instanceof ControlPlaneError) throw error;
        throw invalidClientAuth("invalid_session_result", "Client session result is invalid");
      }
    }
    const response = isResponse(value)
      ? value
      : isRecord(value) && isResponse(value.response)
        ? value.response
        : undefined;
    if (response === undefined) throw invalidClientAuth("invalid_session_response", "Client session response is invalid");
    const responseHeaders = safeResponseHeaders(response);
    if (responseHeaders.setCookie.length === 0) throw invalidClientAuth("invalid_session_response", "Client session response is invalid");
    return { responseHeaders };
  }

  private assertCookieRequestOrigin(requestValue: unknown): void {
    if (this.trustedOrigins === undefined || this.trustedOrigins.length === 0) throw unavailableClientAuth("trusted_origin_unavailable");
    if (!isObjectLike(requestValue) || !isObjectLike(requestValue.headers)) throw invalidClientAuth("invalid_origin", "Client authentication origin is invalid");
    const origin = headerValue(requestValue.headers as Record<string, unknown>, "origin");
    if (origin === undefined) throw invalidClientAuth("invalid_origin", "Client authentication origin is required");
    let actual: string;
    try {
      const parsed = new URL(origin);
      if ((parsed.pathname !== "" && parsed.pathname !== "/") || parsed.search !== "" || parsed.hash !== "" || parsed.username !== "" || parsed.password !== "" || parsed.origin !== origin) throw new Error("invalid");
      actual = parsed.origin;
    } catch {
      throw invalidClientAuth("invalid_origin", "Client authentication origin is invalid");
    }
    if (!this.trustedOrigins.includes(actual)) throw invalidClientAuth("invalid_origin", "Client authentication origin is invalid");
  }

  private   async sessionOperation(
    operation: "refresh" | "logout" | "me",
    input: ClientAuthBffSessionReferenceRequest,
  ): Promise<ClientAuthBffSessionResultDto | undefined> {
    const reference = parseSessionReference(input);
    const service = this.sessionService;
    if (service === undefined) throw unavailableClientAuth("session_service_unavailable");
    let method: ((value: ClientAuthBffSessionReferenceRequest) => unknown) | undefined;
    if (operation === "refresh") method = service.refresh?.bind(service) ?? service.refreshSession?.bind(service);
    if (operation === "logout") method = service.logout?.bind(service) ?? service.logoutSession?.bind(service);
    if (operation === "me") {
      method = service.me?.bind(service) ?? service.get?.bind(service) ?? service.getSession?.bind(service);
    }
    if (method === undefined) throw unavailableClientAuth("session_service_unavailable");
    let value: unknown;
    try {
      value = await method({ sessionReference: reference });
    } catch (error) {
      if (error instanceof ControlPlaneError) throw error;
      throw unavailableClientAuth("session_service_unavailable");
    }
    if (operation === "logout" && (value === undefined || value === null)) return undefined;
    try {
      return normalizePublicSessionResult(value);
    } catch (error) {
      if (error instanceof ControlPlaneError) throw error;
      throw invalidClientAuth("invalid_session_result", "Client session result is invalid");
    }
  }

  private async resolveClient(
    clientId: string,
    clientType: ClientAuthBffClientType,
  ): Promise<ClientAuthBffTrustedClientConfiguration> {
    if (this.resolveClientConfiguration !== undefined) {
      try {
        const resolved = await this.resolveClientConfiguration({ clientId, clientType });
        if (resolved !== undefined) return this.normalizeConfiguration(resolved, clientId, clientType);
      } catch (error) {
        if (error instanceof ControlPlaneError) throw error;
        throw unavailableClientAuth("client_configuration_unavailable");
      }
    }
    const sources = [this.singleConfiguration, this.configurations, this.clients];
    for (const source of sources) {
      if (source === undefined) continue;
      const value = findConfiguration(source, clientId, clientType);
      if (value !== undefined) return this.normalizeConfiguration(value, clientId, clientType);
    }
    const adapter = this.adapter as ClientAuthBffHostAdapter & {
      clientConfiguration?: unknown;
      clientConfig?: unknown;
      configuration?: unknown;
    };
    const adapterSource = adapter.clientConfiguration ?? adapter.clientConfig ?? adapter.configuration;
    if (adapterSource !== undefined) {
      const value = findConfiguration(adapterSource, clientId, clientType);
      if (value !== undefined) return this.normalizeConfiguration(value, clientId, clientType);
    }
    throw invalidClientAuth("unknown_client", "Client authentication request is invalid");
  }

  private normalizeConfiguration(
    value: ClientAuthBffTrustedClientConfiguration,
    clientId: string,
    clientType: ClientAuthBffClientType,
  ): ClientAuthBffTrustedClientConfiguration {
    if (!isRecord(value)) throw unavailableClientAuth("client_configuration_unavailable");
    const candidateId = value.clientId ?? clientId;
    const candidateType = value.clientType ?? clientType;
    if (candidateId !== clientId || candidateType !== clientType) throw invalidClientAuth("unknown_client", "Client authentication request is invalid");
    const redirectUris = readConfigurationRedirectUris(value.redirectUris ?? value.redirectUri);
    if (redirectUris.length === 0) throw unavailableClientAuth("client_configuration_unavailable");
    for (const redirectUri of redirectUris) assertSafeRedirectUri(redirectUri, this.allowLoopbackHttp, clientType);
    const scopes = readConfigurationScopes(value.scopes ?? value.scope);
    const copy: Record<string, unknown> = { ...value, clientId, clientType, redirectUris, ...(scopes === undefined ? {} : { scopes }) };
    return Object.freeze(copy) as ClientAuthBffTrustedClientConfiguration;
  }

  private readBindingHash(context: ClientAuthBffBindingContext, clientType: ClientAuthBffClientType): string | undefined {
    if (!isRecord(context)) throw invalidClientAuth("binding_required", "Client authentication binding is invalid");
    const value = context.bindingHash;
    if (clientType === "web") {
      if (typeof value !== "string") throw invalidClientAuth("binding_required", "Client authentication binding is required");
      return assertHash(value, "binding");
    }
    return undefined;
  }

  private assertRequestOrigin(requestValue: unknown, clientType: ClientAuthBffClientType, redirectUri: string): void {
    if (clientType !== "web" || requestValue === undefined) return;
    if (!isObjectLike(requestValue)) throw invalidClientAuth("invalid_origin", "Client authentication origin is invalid");
    const headers = requestValue.headers;
    if (!isObjectLike(headers)) throw invalidClientAuth("invalid_origin", "Client authentication origin is invalid");
    const origin = headerValue(headers as Record<string, unknown>, "origin");
    if (origin === undefined) throw invalidClientAuth("invalid_origin", "Client authentication origin is required");
    let actual: string;
    try {
      const parsed = new URL(origin);
      if ((parsed.pathname !== "" && parsed.pathname !== "/") || parsed.search !== "" || parsed.hash !== "" || parsed.username !== "" || parsed.password !== "" || parsed.origin !== origin) throw new Error("invalid");
      actual = parsed.origin;
    } catch {
      throw invalidClientAuth("invalid_origin", "Client authentication origin is invalid");
    }
    let expected: string;
    try {
      expected = new URL(redirectUri).origin;
    } catch {
      throw invalidClientAuth("invalid_origin", "Client authentication origin is invalid");
    }
    if (actual !== expected && (this.trustedOrigins === undefined || !this.trustedOrigins.includes(actual))) {
      throw invalidClientAuth("invalid_origin", "Client authentication origin is invalid");
    }
  }

  private async saveState(record: ClientAuthBffStateRecord): Promise<void> {
    const method = this.store.save ?? this.store.put ?? this.store.set;
    if (method === undefined) throw new Error("[getbrick-idaas] client auth state store cannot save state");
    await method.call(this.store, record);
  }

  private async discardState(stateHash: string): Promise<void> {
    try {
      const method = this.store.remove ?? this.store.delete ?? this.store.revoke;
      if (method !== undefined) {
        await method.call(this.store, stateHash);
      } else {
        await this.store.consume(stateHash);
      }
    } catch {
      return;
    }
  }

  private clock(): number {
    const value = this.now();
    if (!Number.isSafeInteger(value) || value < 0) throw unavailableClientAuth("clock_unavailable");
    return value;
  }
}

export const ClientAuthBbfService = ClientAuthBffService;
export const ClientAuthenticationBffService = ClientAuthBffService;
export const ClientAuthBFFService = ClientAuthBffService;
export type ClientAuthBbfServiceOptions = ClientAuthBffServiceOptions;

export class ClientAuthBbfAdapterResultValidator {
  static validate(value: unknown): ClientAuthBffExchangeOutcome {
    return normalizeAdapterExchangeResult(value, "native");
  }
}

@Controller(CLIENT_AUTH_BFF_BASE_PATH)
@Public()
@UseFilters(ControlPlaneExceptionFilter)
export class ClientAuthBffController {
  constructor(
    @Inject(ClientAuthBffService)
    private readonly service: ClientAuthBffService,
  ) {}

  @Post("oidc/start")
  @HttpCode(200)
  async start(
    @Body() body: unknown,
    @Req() request: ClientAuthBffHttpRequest,
    @Res() response: ClientAuthBffHttpResponse,
  ): Promise<ClientAuthBffStartResponse> {
    setNoStore(response);
    assertNoCredentialHeaders(request);
    assertNoRequestQuery(request);
    const parsed = parseStartRequest(body, true);
    const binding = parsed.clientType === "web" ? createBindingValue() : undefined;
    const result = await this.service.start(parsed, { request, ...(binding === undefined ? {} : { bindingHash: hashText(binding) }) });
    if (binding !== undefined) {
      const maxAge = Math.max(1, Math.min(CLIENT_AUTH_BFF_MAX_STATE_TTL_MS / 1000, Math.ceil((Date.parse(result.expiresAt) - Date.now()) / 1000)));
      setHeader(response, "Set-Cookie", serializeBindingCookie(binding, Number.isFinite(maxAge) ? maxAge : CLIENT_AUTH_BFF_MAX_STATE_TTL_MS / 1000));
    }
    writeJson(response, 200, result);
    return result;
  }

  @Post(["oidc/exchange", "oidc/callback"])
  @HttpCode(200)
  async exchange(
    @Body() body: unknown,
    @Req() request: ClientAuthBffHttpRequest,
    @Res() response: ClientAuthBffHttpResponse,
  ): Promise<void> {
    setNoStore(response);
    assertNoCredentialHeaders(request);
    assertNoRequestQuery(request);
    const binding = readBindingCookie(request);
    const result = await this.service.exchange(body, { request, ...(binding === undefined ? {} : { bindingHash: hashText(binding) }) });
    if (result.clientType === "web") {
      clearBindingCookie(response);
      if (result.responseHeaders !== undefined) {
        writeSafeResponseHeaders(response, result.responseHeaders);
        writeNoContent(response);
        return;
      }
    }
    if (result.publicResult === undefined) throw invalidClientAuth("invalid_session_result", "Client session result is invalid");
    writeJson(response, 200, result.publicResult);
  }

  @Post(["refresh", "session/refresh"])
  @HttpCode(200)
  async refresh(
    @Body() body: unknown,
    @Req() request: ClientAuthBffHttpRequest,
    @Res() response: ClientAuthBffHttpResponse,
  ): Promise<void> {
    setNoStore(response);
    assertNoCredentialHeaders(request);
    assertNoRequestQuery(request);
    const sessionReference = readOptionalSessionReference(body, request, true);
    if (sessionReference === undefined) {
      const result = await this.service.refreshWeb(request);
      if (result.responseHeaders === undefined) throw invalidClientAuth("invalid_session_response", "Client session response is invalid");
      writeSafeResponseHeaders(response, result.responseHeaders);
      writeNoContent(response);
      return;
    }
    writeJson(response, 200, await this.service.refresh({ sessionReference }));
  }

  @Post(["logout", "session/logout"])
  @HttpCode(200)
  async logout(
    @Body() body: unknown,
    @Req() request: ClientAuthBffHttpRequest,
    @Res() response: ClientAuthBffHttpResponse,
  ): Promise<void> {
    setNoStore(response);
    assertNoCredentialHeaders(request);
    assertNoRequestQuery(request);
    const sessionReference = readOptionalSessionReference(body, request, true);
    if (sessionReference === undefined) {
      const result = await this.service.logoutWeb(request);
      if (result.responseHeaders === undefined) throw invalidClientAuth("invalid_session_response", "Client session response is invalid");
      writeSafeResponseHeaders(response, result.responseHeaders);
      writeNoContent(response);
      return;
    }
    const result = await this.service.logout({ sessionReference });
    if (result === undefined) {
      writeNoContent(response);
      return;
    }
    writeJson(response, 200, result);
  }

  @Get("me")
  @HttpCode(200)
  async me(
    @Req() request: ClientAuthBffHttpRequest,
    @Res() response: ClientAuthBffHttpResponse,
  ): Promise<void> {
    setNoStore(response);
    assertNoCredentialHeaders(request);
    if (request.query !== undefined && !isEmptyRecord(request.query)) throw invalidClientAuth("invalid_request", "Client authentication request is invalid");
    if (request.body !== undefined && !isEmptyRecord(request.body)) throw invalidClientAuth("invalid_request", "Client authentication request is invalid");
    const sessionReference = readOptionalSessionReference(undefined, request, false);
    if (sessionReference === undefined) {
      writeJson(response, 200, await this.service.meWeb(request));
      return;
    }
    writeJson(response, 200, await this.service.me({ sessionReference }));
  }

  async startOidc(
    body: unknown,
    request: ClientAuthBffHttpRequest = {},
    response: ClientAuthBffHttpResponse = createResponse(),
  ): Promise<ClientAuthBffStartResponse> {
    return this.start(body, request, response);
  }

  async exchangeOidc(
    body: unknown,
    request: ClientAuthBffHttpRequest = {},
    response: ClientAuthBffHttpResponse = createResponse(),
  ): Promise<void> {
    return this.exchange(body, request, response);
  }

  async exchangeCallback(
    body: unknown,
    request: ClientAuthBffHttpRequest = {},
    response: ClientAuthBffHttpResponse = createResponse(),
  ): Promise<void> {
    return this.exchange(body, request, response);
  }
}

export const ClientAuthBbfController = ClientAuthBffController;
export const ClientAuthenticationBffController = ClientAuthBbfController;

export interface ClientAuthBffHttpRequest {
  headers?: Record<string, unknown>;
  query?: unknown;
  body?: unknown;
}

export interface ClientAuthBffHttpResponse {
  status?: (code: number) => unknown;
  statusCode?: number;
  setHeader?: (name: string, value: string | string[]) => unknown;
  getHeader?: (name: string) => unknown;
  json?: (value: unknown) => unknown;
  end?: (value?: unknown) => unknown;
}

export interface ClientAuthBffModuleOptions extends ClientAuthBffServiceOptions {
  auth?: GetbrickAuthLike;
  rbac?: RoleGraph;
  guard?: GetbrickGuardMode;
  globalGuard?: boolean;
  manualGuard?: boolean;
  basePath?: string;
  trustProxy?: boolean;
  readiness?: () => boolean | Promise<boolean>;
}

@Injectable()
class ClientAuthBffReadiness implements OnModuleInit {
  constructor(
    @Optional()
    @Inject(CLIENT_AUTH_BFF_READINESS)
    private readonly check?: () => boolean | Promise<boolean>,
  ) {}

  async onModuleInit(): Promise<void> {
    if (this.check === undefined) return;
    if (!(await this.check())) throw new Error("[getbrick-idaas] client auth BFF storage is not ready");
  }
}

@Module({})
export class ClientAuthBffModule {
  static forRoot(options: ClientAuthBffModuleOptions): DynamicModule {
    const profile = options.profile ?? (process.env.NODE_ENV === "production" ? "production" : "development");
    const configuredAdapter = options.adapter ?? options.hostAdapter;
    if (!isValidAdapter(configuredAdapter)) throw new Error("[getbrick-idaas] client auth BFF adapter is invalid");
    const suppliedStore = options.store ?? options.stateStore ?? options.transactionStore;
    if (profile === "production" && suppliedStore === undefined) {
      throw new Error("[getbrick-idaas] production client auth BFF requires a state store");
    }
    if (profile === "production" && (suppliedStore instanceof InMemoryClientAuthBffStateStore || suppliedStore?.persistent !== true)) {
      throw new Error("[getbrick-idaas] production client auth BFF requires a persistent state store");
    }
    if (profile === "production" && typeof suppliedStore?.ready !== "function") {
      throw new Error("[getbrick-idaas] production client auth BFF requires a readiness-checkable state store");
    }
    if (suppliedStore !== undefined && !isValidStateStore(suppliedStore)) {
      throw new Error("[getbrick-idaas] client auth BFF state store is invalid");
    }
    if (profile === "production" && !options.auth) {
      throw new Error("[getbrick-idaas] production client auth BFF requires authentication");
    }
    const serviceOptions: ClientAuthBffServiceOptions = {
      ...(configuredAdapter === undefined ? {} : { adapter: configuredAdapter }),
      ...(suppliedStore === undefined ? {} : { store: suppliedStore }),
      ...(options.transactionStore === undefined ? {} : { transactionStore: options.transactionStore }),
      ...(options.clientConfiguration === undefined ? {} : { clientConfiguration: options.clientConfiguration }),
      ...(options.clientConfig === undefined ? {} : { clientConfig: options.clientConfig }),
      ...(options.configurations === undefined ? {} : { configurations: options.configurations }),
      ...(options.clients === undefined ? {} : { clients: options.clients }),
      ...(options.resolveClientConfiguration === undefined ? {} : { resolveClientConfiguration: options.resolveClientConfiguration }),
      ...(options.resolveClient === undefined ? {} : { resolveClient: options.resolveClient }),
      ...(options.clientResolver === undefined ? {} : { clientResolver: options.clientResolver }),
      ...(options.clientConfigResolver === undefined ? {} : { clientConfigResolver: options.clientConfigResolver }),
      ...(options.sessionService === undefined ? {} : { sessionService: options.sessionService }),
      ...(options.stateTtlMs === undefined ? {} : { stateTtlMs: options.stateTtlMs }),
      ...(options.stateTtlSeconds === undefined ? {} : { stateTtlSeconds: options.stateTtlSeconds }),
      ...(options.transactionTtlMs === undefined ? {} : { transactionTtlMs: options.transactionTtlMs }),
      ...(options.ttlMs === undefined ? {} : { ttlMs: options.ttlMs }),
      ...(options.now === undefined ? {} : { now: options.now }),
       ...(options.allowInsecureHttp === undefined ? {} : { allowInsecureHttp: options.allowInsecureHttp }),
       ...(options.allowLoopbackHttp === undefined ? {} : { allowLoopbackHttp: options.allowLoopbackHttp }),
       ...(options.trustedOrigins === undefined ? {} : { trustedOrigins: options.trustedOrigins }),
       profile,
    };
    const readinessChecks = [readinessOf(suppliedStore), readinessOf(options.sessionService)].filter((check): check is () => boolean | Promise<boolean> => check !== undefined);
    const readiness = options.readiness ?? (readinessChecks.length === 0 ? undefined : async () => {
      for (const check of readinessChecks) {
        if (!(await check())) return false;
      }
      return true;
    });
    const providers: Provider[] = [
      { provide: CLIENT_AUTH_BFF_ADAPTER, useValue: configuredAdapter },
      { provide: ClientAuthBffService, useFactory: () => new ClientAuthBffService(serviceOptions) },
    ];
    if (suppliedStore !== undefined) providers.push({ provide: CLIENT_AUTH_BFF_STATE_STORE, useValue: suppliedStore });
    if (options.sessionService !== undefined) providers.push({ provide: CLIENT_AUTH_BFF_SESSION_SERVICE, useValue: options.sessionService });
    if (readiness !== undefined) {
      providers.push({ provide: CLIENT_AUTH_BFF_READINESS, useValue: readiness }, ClientAuthBffReadiness);
    }
    const exports = [
      CLIENT_AUTH_BFF_ADAPTER,
      ClientAuthBffService,
      ...(suppliedStore === undefined ? [] : [CLIENT_AUTH_BFF_STATE_STORE]),
      ...(options.sessionService === undefined ? [] : [CLIENT_AUTH_BFF_SESSION_SERVICE]),
    ];
    const imports = options.auth
      ? [GetbrickIdaasModule.forRoot({
          auth: options.auth,
          rbac: options.rbac,
          guard: options.guard,
          globalGuard: options.globalGuard,
          manualGuard: options.manualGuard,
          basePath: options.basePath,
          trustProxy: options.trustProxy,
        })]
      : [];
    return {
      module: ClientAuthBffModule,
      imports,
      controllers: [ClientAuthBffController],
      providers,
      exports,
    };
  }
}

export const ClientAuthenticationBffModule = ClientAuthBffModule;
export const ClientAuthenticationBFFModule = ClientAuthBffModule;
export const ClientAuthBFFModule = ClientAuthBffModule;

function parseStartRequest(value: unknown, allowLoopbackHttp: boolean): ClientAuthBffStartRequest {
  assertExactFields(value, ["redirectUri", "clientType", "clientId", "scope", "state", "nonce", "codeChallenge", "codeChallengeMethod"], "start");
  const record = value as Record<string, unknown>;
  const clientType = record.clientType;
  if (clientType !== "web" && clientType !== "native") throw invalidClientAuth("invalid_request", "Client authentication request is invalid");
  const codeChallengeMethod = record.codeChallengeMethod;
  if (codeChallengeMethod !== "S256") throw invalidClientAuth("invalid_request", "Client authentication request is invalid");
  return {
    redirectUri: parseRedirectUri(record.redirectUri, clientType, allowLoopbackHttp),
    clientType,
    clientId: parseClientId(record.clientId),
    scope: parseScope(record.scope),
    state: parseState(record.state),
    nonce: parseNonce(record.nonce),
    codeChallenge: parseCodeChallenge(record.codeChallenge),
    codeChallengeMethod,
  };
}

function parseExchangeRequest(value: unknown, allowLoopbackHttp: boolean): ClientAuthBffExchangeRequest {
  assertExactFields(value, ["code", "codeVerifier", "redirectUri", "state", "clientId", "clientType"], "exchange");
  const record = value as Record<string, unknown>;
  const clientType = record.clientType;
  if (clientType !== "web" && clientType !== "native") throw invalidClientAuth("invalid_request", "Client authentication request is invalid");
  return {
    code: parseAuthorizationCode(record.code),
    codeVerifier: parseCodeVerifier(record.codeVerifier),
    redirectUri: parseExchangeRedirectUri(record.redirectUri, allowLoopbackHttp, clientType),
    state: parseState(record.state),
    clientId: parseClientId(record.clientId),
    clientType,
  };
}

function parseSessionReference(value: unknown): string {
  if (typeof value === "string") return parseOpaqueReference(value, "sessionReference");
  assertExactFields(value, ["sessionReference"], "session");
  return parseOpaqueReference((value as Record<string, unknown>).sessionReference, "sessionReference");
}

function parseClientId(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 512 || value !== value.trim() || /[\u0000-\u001f\u007f\s]/u.test(value)) {
    throw invalidClientAuth("invalid_request", "Client authentication request is invalid");
  }
  return value;
}

function parseState(value: unknown): string {
  if (typeof value !== "string" || value.length < 32 || value.length > 512 || !/^[A-Za-z0-9_-]+$/u.test(value)) {
    throw invalidClientAuth("invalid_state", "Client authentication state is invalid");
  }
  return value;
}

function parseNonce(value: unknown): string {
  if (typeof value !== "string" || value.length < 32 || value.length > 512 || !/^[A-Za-z0-9_-]+$/u.test(value)) {
    throw invalidClientAuth("invalid_nonce", "Client authentication request is invalid");
  }
  return value;
}

function parseCodeChallenge(value: unknown): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(value)) {
    throw invalidClientAuth("invalid_challenge", "Client authentication request is invalid");
  }
  return value;
}

function parseCodeVerifier(value: unknown): string {
  if (typeof value !== "string" || value.length < 43 || value.length > 128 || !/^[A-Za-z0-9._~-]+$/u.test(value)) {
    throw invalidClientAuth("invalid_verifier", "Client authentication request is invalid");
  }
  return value;
}

function parseAuthorizationCode(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 4096 || value !== value.trim() || /[\u0000-\u001f\u007f\s]/u.test(value)) {
    throw invalidClientAuth("invalid_code", "Client authentication code is invalid");
  }
  return value;
}

function parseScope(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 2048 || value !== value.trim() || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw invalidClientAuth("invalid_scope", "Client authentication request is invalid");
  }
  const scopes = value.split(/\s+/u).filter((item) => item.length > 0);
  if (scopes.length === 0 || scopes.length > 100 || scopes.some((item) => !/^[!#-'*+\-.0-9A-Z^-~]+$/u.test(item))) {
    throw invalidClientAuth("invalid_scope", "Client authentication request is invalid");
  }
  if (new Set(scopes).size !== scopes.length || !scopes.includes("openid")) {
    throw invalidClientAuth("invalid_scope", "Client authentication request is invalid");
  }
  return scopes.join(" ");
}

function parseRedirectUri(value: unknown, clientType: ClientAuthBffClientType, allowLoopbackHttp: boolean): string {
  return assertSafeRedirectUri(value, allowLoopbackHttp, clientType);
}

function parseExchangeRedirectUri(value: unknown, allowLoopbackHttp: boolean, clientType: ClientAuthBffClientType): string {
  try {
    return assertSafeRedirectUri(value, allowLoopbackHttp, clientType);
  } catch {
    throw invalidClientAuth("invalid_redirect", "Client authentication redirect is invalid");
  }
}

function assertSafeRedirectUri(value: unknown, allowLoopbackHttp: boolean, clientType: ClientAuthBffClientType): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 2048 || value !== value.trim() || /[\u0000-\u001f\u007f\s\\]/u.test(value)) {
    throw invalidClientAuth("invalid_redirect", "Client authentication redirect is invalid");
  }
  if (hasUnsafePercentEncoding(value)) throw invalidClientAuth("invalid_redirect", "Client authentication redirect is invalid");
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw invalidClientAuth("invalid_redirect", "Client authentication redirect is invalid");
  }
  if (parsed.username !== "" || parsed.password !== "" || parsed.hash !== "") {
    throw invalidClientAuth("invalid_redirect", "Client authentication redirect is invalid");
  }
  if (parsed.protocol === "https:") {
    if (parsed.hostname.length === 0) throw invalidClientAuth("invalid_redirect", "Client authentication redirect is invalid");
    return value;
  }
  if (parsed.protocol === "http:") {
    if (allowLoopbackHttp && parsed.hostname.length > 0 && isLoopbackHost(parsed.hostname)) return value;
    throw invalidClientAuth("invalid_redirect", "Client authentication redirect is invalid");
  }
  if (clientType !== "native" || !isPrivateUseRedirectProtocol(parsed.protocol)) throw invalidClientAuth("invalid_redirect", "Client authentication redirect is invalid");
  if (parsed.pathname === "" && parsed.hostname === "") throw invalidClientAuth("invalid_redirect", "Client authentication redirect is invalid");
  return value;
}

function assertAuthorizationUrl(
  value: unknown,
  state: string,
  redirectUri: string,
  scope: string,
  allowLoopbackHttp: boolean,
  clientId: string,
  nonce: string,
  codeChallenge: string,
  clientType: ClientAuthBffClientType,
): string {
  let parsed: URL;
  try {
    parsed = new URL(value instanceof URL ? value.toString() : String(value));
  } catch {
    throw invalidClientAuth("authorization_url_invalid", "Client authorization URL is invalid");
  }
  if (
    (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
    (parsed.protocol === "http:" && (!allowLoopbackHttp || !isLoopbackHost(parsed.hostname))) ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.hash !== "" ||
    parsed.hostname.length === 0 ||
    parsed.toString().length > 4096 ||
    hasUnsafePercentEncoding(parsed.toString())
  ) {
    throw invalidClientAuth("authorization_url_invalid", "Client authorization URL is invalid");
  }
  assertRequiredAuthorizationValue(parsed, "client_id", clientId);
  assertRequiredAuthorizationValue(parsed, "redirect_uri", redirectUri);
  assertRequiredAuthorizationValue(parsed, "response_type", "code");
  assertRequiredAuthorizationValue(parsed, "scope", scope);
  assertRequiredAuthorizationValue(parsed, "state", state);
  assertRequiredAuthorizationValue(parsed, "nonce", nonce);
  assertRequiredAuthorizationValue(parsed, "code_challenge", codeChallenge);
  assertRequiredAuthorizationValue(parsed, "code_challenge_method", "S256");
  if (!isSafeRedirectUri(redirectUri, allowLoopbackHttp, clientType)) throw invalidClientAuth("authorization_redirect_invalid", "Client authorization URL is invalid");
  for (const [key, value] of parsed.searchParams) {
    const normalized = normalizeParameterKey(key);
    if (FORBIDDEN_AUTHORIZATION_PARAMETERS.has(normalized) || FORBIDDEN_AUTHORIZATION_PARAMETER_SUFFIXES.some((suffix) => normalized.endsWith(suffix))) {
      throw invalidClientAuth("authorization_url_invalid", "Client authorization URL is invalid");
    }
    if (/[\u0000-\u001f\u007f]/u.test(`${key}${value}`) || FORBIDDEN_CREDENTIAL_TEXT.test(`${key} ${value}`)) throw invalidClientAuth("authorization_url_invalid", "Client authorization URL is invalid");
  }
  return parsed.toString();
}

function assertRequiredAuthorizationValue(url: URL, name: string, expected: string): void {
  const keys = [...url.searchParams.keys()].filter((key) => normalizeParameterKey(key) === normalizeParameterKey(name));
  const values = url.searchParams.getAll(name);
  if (keys.length !== 1 || values.length !== 1 || values[0] !== expected) {
    throw invalidClientAuth("authorization_url_invalid", "Client authorization URL is invalid");
  }
}

function isSafeRedirectUri(value: string, allowLoopbackHttp: boolean, clientType: ClientAuthBffClientType): boolean {
  try {
    assertSafeRedirectUri(value, allowLoopbackHttp, clientType);
    return true;
  } catch {
    return false;
  }
}

function verifyPkceS256(codeVerifier: string, expectedChallenge: string): void {
  const actual = createHash("sha256").update(codeVerifier, "ascii").digest("base64url");
  const expected = Buffer.from(expectedChallenge, "ascii");
  const actualBuffer = Buffer.from(actual, "ascii");
  if (expected.length !== actualBuffer.length || !timingSafeEqual(expected, actualBuffer)) {
    throw invalidClientAuth("pkce_invalid", "Client authentication verification failed");
  }
}

function assertConsumedTransaction(
  record: ClientAuthBffStateRecord,
  stateHash: string,
  redirectUri: string,
  clientId: string,
  clientType: ClientAuthBffClientType,
  now: number,
): void {
  try {
    assertStateRecord(record);
  } catch {
    throw invalidClientAuth("invalid_state", "Client authentication state is invalid");
  }
  if (!hashesEqual(record.stateHash, stateHash) || record.redirectUri !== redirectUri || record.clientId !== clientId || record.clientType !== clientType || record.expiresAt <= now) {
    throw invalidClientAuth("invalid_state", "Client authentication state is invalid");
  }
}

function normalizeAdapterExchangeResult(
  value: unknown,
  clientType: ClientAuthBffClientType,
  authorizationCode?: string,
  authorizationState?: string,
): ClientAuthBffExchangeOutcome {
  assertNoCredentialFields(value);
  if (isResponse(value)) {
    if (clientType !== "web") throw invalidClientAuth("invalid_session_result", "Client session result is invalid");
    const responseHeaders = safeResponseHeaders(value);
    if (responseHeaders.setCookie.length === 0) throw invalidClientAuth("invalid_session_response", "Client session response is invalid");
    return { clientType, response: value, responseHeaders };
  }
  if (!isRecord(value)) throw invalidClientAuth("invalid_session_result", "Client session result is invalid");
  assertAllowedFields(value, ["identity", "platformIdentity", "session", "user", "response", "sessionReference", "expiresAt", "clientKind"], "adapter result");
  const identityInput = value.identity ?? value.platformIdentity;
  if (identityInput === undefined) throw invalidClientAuth("invalid_identity", "Client authentication identity is invalid");
  const identity = normalizeIdentity(identityInput);
  const responseValue = value.response ?? (isRecord(value.session) ? value.session.response : undefined);
  if (responseValue !== undefined && !isResponse(responseValue)) throw invalidClientAuth("invalid_session_result", "Client session result is invalid");
  if (responseValue !== undefined && clientType !== "web") throw invalidClientAuth("invalid_session_result", "Client session result is invalid");
  if (clientType === "native" && (Object.prototype.hasOwnProperty.call(value, "response") || isRecord(value.session) && Object.prototype.hasOwnProperty.call(value.session, "response"))) {
    throw invalidClientAuth("invalid_session_result", "Client session result is invalid");
  }
  const sessionValue = isRecord(value.session) ? value.session : value;
  if (isRecord(value.session)) assertAllowedFields(value.session, ["sessionReference", "expiresAt", "clientKind", "user", "response"], "adapter session");
  const sessionReference = readSessionResultField(sessionValue, value, "sessionReference");
  const expiresAtValue = readSessionResultField(sessionValue, value, "expiresAt");
  const clientKindValue = readSessionResultField(sessionValue, value, "clientKind");
  if (responseValue !== undefined) {
    if (sessionReference !== undefined || clientKindValue !== undefined && clientKindValue !== clientType) throw invalidClientAuth("invalid_session_result", "Client session result is invalid");
    const responseUser = readSessionResultField(sessionValue, value, "user");
    if (responseUser !== undefined) normalizeUser(responseUser);
    if (expiresAtValue !== undefined) parseDate(expiresAtValue);
    const responseHeaders = safeResponseHeaders(responseValue as Response);
    if (responseHeaders.setCookie.length === 0) throw invalidClientAuth("invalid_session_response", "Client session response is invalid");
    return { clientType, response: responseValue as Response, responseHeaders };
  }
  if (clientType === "web") throw invalidClientAuth("invalid_session_result", "Web client sessions must use a cookie response");
  if (clientKindValue !== clientType || sessionReference === undefined || expiresAtValue === undefined) {
    throw invalidClientAuth("invalid_session_result", "Client session result is invalid");
  }
  const expiresAt = parseDate(expiresAtValue);
  const reference = parseOpaqueReference(sessionReference, "sessionReference");
  if ((authorizationCode !== undefined && reference === authorizationCode) || (authorizationState !== undefined && reference === authorizationState)) throw invalidClientAuth("invalid_session_result", "Client session result is invalid");
  const userInput = readSessionResultField(sessionValue, value, "user");
  if (userInput === undefined) throw invalidClientAuth("invalid_user", "Client authentication user is invalid");
  const user = normalizeUser(userInput);
  return {
    clientType,
    publicResult: {
      sessionReference: reference,
      expiresAt,
      clientKind: clientType,
      user,
    },
    response: undefined,
    responseHeaders: undefined,
  };
}

function normalizeIdentity(value: unknown): PlatformIdentity {
  if (!isRecord(value)) throw invalidClientAuth("invalid_identity", "Client authentication identity is invalid");
  assertAllowedFields(value, ["provider", "platform", "appId", "subject", "openid", "unionid", "nickname", "avatarUrl", "email", "emailVerified", "scopes"], "identity");
  for (const field of ["provider", "platform", "appId", "subject", "scopes"]) {
    if (!Object.prototype.hasOwnProperty.call(value, field) || value[field] === undefined) throw invalidClientAuth("invalid_identity", "Client authentication identity is invalid");
  }
  if (!Array.isArray(value.scopes)) throw invalidClientAuth("invalid_identity", "Client authentication identity is invalid");
  try {
    return sanitizePlatformIdentity(value);
  } catch {
    throw invalidClientAuth("invalid_identity", "Client authentication identity is invalid");
  }
}

function normalizeUser(value: unknown): ClientAuthBffUserDto {
  if (!isRecord(value)) throw invalidClientAuth("invalid_user", "Client authentication user is invalid");
  const image = value.image;
  assertAllowedFields(value, ["id", "name", "email", "emailVerified", "avatarUrl", "image"], "user");
  if (value.id === undefined || value.name === undefined || value.email === undefined || value.emailVerified === undefined) throw invalidClientAuth("invalid_user", "Client authentication user is invalid");
  const id = parseSafeUserText(value.id, "user");
  const name = parseSafeUserText(value.name, "name");
  const email = parseSafeEmail(value.email);
  if (value.emailVerified !== true && value.emailVerified !== false) throw invalidClientAuth("invalid_user", "Client authentication user is invalid");
  if (value.email === null && value.emailVerified !== false) throw invalidClientAuth("invalid_user", "Client authentication user is invalid");
  if (value.email !== null && value.emailVerified === true && email === null) throw invalidClientAuth("invalid_user", "Client authentication user is invalid");
  const avatarValue = value.avatarUrl ?? image;
  if (value.avatarUrl !== undefined && image !== undefined && value.avatarUrl !== image) throw invalidClientAuth("invalid_user", "Client authentication user is invalid");
  const avatarUrl = avatarValue === undefined || avatarValue === null ? undefined : parseSafeAvatarUrl(avatarValue);
  return {
    id,
    name,
    email,
    emailVerified: value.emailVerified,
    ...(avatarUrl === undefined ? {} : { avatarUrl }),
  };
}

function normalizeWebUserResult(value: unknown): ClientAuthBffUserDto {
  assertNoCredentialFields(value);
  const root = isRecord(value) && isRecord(value.data) ? value.data : value;
  if (!isRecord(root)) throw invalidClientAuth("invalid_user", "Client authentication user is invalid");
  assertAllowedFields(root, ["user"], "web session result");
  return normalizeUser(root.user);
}

function normalizePublicSessionResult(value: unknown): ClientAuthBffSessionResultDto {
  assertNoCredentialFields(value);
  if (isResponse(value) || !isRecord(value)) throw invalidClientAuth("invalid_session_result", "Client session result is invalid");
  const session = isRecord(value.session) ? value.session : value;
  if (isRecord(value.session)) assertAllowedFields(value.session, ["sessionReference", "expiresAt", "clientKind", "user"], "session result");
  const sessionReference = readSessionResultField(session, value, "sessionReference");
  const expiresAtValue = readSessionResultField(session, value, "expiresAt");
  const clientKindValue = readSessionResultField(session, value, "clientKind");
  const userValue = readSessionResultField(session, value, "user");
  if (sessionReference === undefined || expiresAtValue === undefined || clientKindValue === undefined || userValue === undefined) throw invalidClientAuth("invalid_session_result", "Client session result is invalid");
  if (clientKindValue !== "web" && clientKindValue !== "native") throw invalidClientAuth("invalid_session_result", "Client session result is invalid");
  return {
    sessionReference: parseOpaqueReference(sessionReference, "sessionReference"),
    expiresAt: parseDate(expiresAtValue),
    clientKind: clientKindValue,
    user: normalizeUser(userValue),
  };
}

function readSessionResultField(session: Record<string, unknown>, root: Record<string, unknown>, field: string): unknown {
  const sessionValue = session[field];
  const rootValue = root[field];
  if (sessionValue !== undefined && rootValue !== undefined && sessionValue !== rootValue) throw invalidClientAuth("invalid_session_result", "Client session result is invalid");
  return sessionValue !== undefined ? sessionValue : rootValue;
}

function safeResponseHeaders(response: Response): ClientAuthBffSafeResponseHeaders {
  const output: ClientAuthBffSafeResponseHeaders = { setCookie: [] };
  const setCookie = responseHeaders(response, "set-cookie");
  for (const value of setCookie) {
    const cookieName = value.split(";", 1)[0]?.split("=", 1)[0]?.trim().toLowerCase();
    if (cookieName === CLIENT_AUTH_BINDING_COOKIE_NAME || !isSafeHeaderValue(value) || FORBIDDEN_CREDENTIAL_TEXT.test(value) || !isSafeSessionCookie(value)) throw invalidClientAuth("invalid_session_response", "Client session response is invalid");
    output.setCookie.push(value);
  }
  const cacheControl = response.headers.get("cache-control");
  if (cacheControl !== null && isSafeCacheHeader(cacheControl)) output.cacheControl = cacheControl;
  const pragma = response.headers.get("pragma");
  if (pragma !== null && isSafeCacheHeader(pragma)) output.pragma = pragma;
  return output;
}

function responseHeaders(response: Response, name: string): string[] {
  const headers = response.headers as Headers & { getSetCookie?: () => string[] };
  if (name === "set-cookie" && typeof headers.getSetCookie === "function") return headers.getSetCookie.call(headers);
  const value = response.headers.get(name);
  return value === null ? [] : [value];
}

function isSafeCacheHeader(value: string): boolean {
  return isSafeHeaderValue(value) && !FORBIDDEN_CREDENTIAL_TEXT.test(value) && /(?:no-store|no-cache|private)/iu.test(value);
}

function isSafeHeaderValue(value: string): boolean {
  return value.length > 0 && value.length <= 4096 && !/[\u0000-\u001f\u007f]/u.test(value);
}

function isSafeSessionCookie(value: string): boolean {
  const parts = value.split(";").map((part) => part.trim()).filter((part) => part.length > 0);
  if (parts.length < 2) return false;
  const attributes = new Map<string, string>();
  for (const part of parts.slice(1)) {
    const separator = part.indexOf("=");
    const key = (separator === -1 ? part : part.slice(0, separator)).trim().toLowerCase();
    const attributeValue = separator === -1 ? "" : part.slice(separator + 1).trim();
    if (key.length === 0 || attributes.has(key)) return false;
    attributes.set(key, attributeValue);
  }
  if (!attributes.has("httponly") || !attributes.has("secure") || !attributes.has("samesite") || !attributes.has("path") || attributes.has("domain")) return false;
  if (attributes.get("httponly") !== "" || attributes.get("secure") !== "") return false;
  const sameSite = attributes.get("samesite")?.toLowerCase();
  if (sameSite !== "lax" && sameSite !== "strict" && sameSite !== "none") return false;
  if (sameSite === "none" && !attributes.has("secure")) return false;
  return attributes.get("path") === "/";
}

function assertNoCredentialFields(value: unknown, depth = 0, seen = new Set<object>()): void {
  if (depth > 8 || value === null || value === undefined || isResponse(value)) return;
  if (typeof value !== "object") return;
  if (seen.has(value)) return;
  seen.add(value);
  if (Array.isArray(value)) {
    for (const item of value) assertNoCredentialFields(item, depth + 1, seen);
    return;
  }
  if (!isRecord(value)) return;
  for (const key of Object.getOwnPropertyNames(value)) {
    const normalized = normalizeParameterKey(key);
    if (FORBIDDEN_RESULT_KEYS.has(normalized) || FORBIDDEN_RESULT_SUFFIXES.some((suffix) => normalized.endsWith(suffix))) {
      throw invalidClientAuth("credential_exposed", "Client authentication result is invalid");
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor)) throw invalidClientAuth("invalid_result", "Client authentication result is invalid");
    assertNoCredentialFields(descriptor.value, depth + 1, seen);
  }
  for (const key of Object.getOwnPropertySymbols(value)) throw invalidClientAuth("invalid_result", "Client authentication result is invalid");
  seen.delete(value);
}

function assertStateRecord(record: ClientAuthBffStateRecord): void {
  if (!isRecord(record) || record.version !== CLIENT_AUTH_BFF_STATE_VERSION) throw invalidClientAuth("invalid_state", "Client authentication state is invalid");
  assertAllowedFields(record as unknown as Record<string, unknown>, ["version", "stateHash", "nonce", "codeChallenge", "redirectUri", "clientType", "clientId", "scope", "expiresAt", "bindingHash"], "state");
  assertHash(record.stateHash, "state");
  parseNonce(record.nonce);
  parseCodeChallenge(record.codeChallenge);
  assertSafeRedirectUri(record.redirectUri, true, record.clientType);
  if (record.clientType !== "web" && record.clientType !== "native") throw invalidClientAuth("invalid_state", "Client authentication state is invalid");
  parseClientId(record.clientId);
  parseScope(record.scope);
  if (!Number.isSafeInteger(record.expiresAt) || record.expiresAt < 0) throw invalidClientAuth("invalid_state", "Client authentication state is invalid");
  if (record.bindingHash !== undefined) assertHash(record.bindingHash, "binding");
}

function readConfigurationRedirectUris(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (!Array.isArray(value) || value.length === 0 || value.length > 100) throw unavailableClientAuth("client_configuration_unavailable");
  const output: string[] = [];
  for (const item of value) {
    if (typeof item !== "string" || output.includes(item)) throw unavailableClientAuth("client_configuration_unavailable");
    output.push(item);
  }
  return output;
}

function readConfigurationScopes(value: unknown): string[] | undefined {
  if (value === undefined) return undefined;
  const values = typeof value === "string" ? value.split(/\s+/u) : value;
  if (!Array.isArray(values) || values.length === 0 || values.length > 100) throw unavailableClientAuth("client_configuration_unavailable");
  const output: string[] = [];
  for (const item of values) {
    if (typeof item !== "string" || item.length === 0 || item.length > 128 || !/^[!#-'*+\-.0-9A-Z^-~]+$/u.test(item) || output.includes(item)) throw unavailableClientAuth("client_configuration_unavailable");
    output.push(item);
  }
  return output;
}

function findConfiguration(
  source: unknown,
  clientId: string,
  clientType: ClientAuthBffClientType,
): ClientAuthBffTrustedClientConfiguration | undefined {
  if (source instanceof Map) {
    const value = source.get(clientId);
    return isRecord(value) ? value as ClientAuthBffTrustedClientConfiguration : undefined;
  }
  if (Array.isArray(source)) {
    const value = source.find((item) => isRecord(item) && (item.clientId === clientId || item.clientId === undefined) && (item.clientType === clientType || item.clientType === undefined));
    return value as ClientAuthBffTrustedClientConfiguration | undefined;
  }
  if (isRecord(source)) {
    const direct = source[clientId];
    if (isRecord(direct)) return direct as ClientAuthBffTrustedClientConfiguration;
    if (source.clientId === clientId || source.clientId === undefined) return source as ClientAuthBffTrustedClientConfiguration;
  }
  return undefined;
}

function normalizeStateTtl(ttlMs: number | undefined, ttlSeconds: number | undefined): number {
  if (ttlMs !== undefined && ttlSeconds !== undefined && ttlMs !== ttlSeconds * 1000) throw new Error("[getbrick-idaas] client auth state lifetime is invalid");
  const value = ttlMs ?? (ttlSeconds === undefined ? CLIENT_AUTH_BFF_DEFAULT_STATE_TTL_MS : ttlSeconds * 1000);
  if (!Number.isSafeInteger(value) || value < 1_000 || value > CLIENT_AUTH_BFF_MAX_STATE_TTL_MS) throw new Error("[getbrick-idaas] client auth state lifetime is invalid");
  return value;
}

function normalizePositiveInteger(value: number, fallback: number): number {
  return Number.isSafeInteger(value) && value > 0 ? value : fallback;
}

function normalizeTrustedOrigins(value: readonly string[] | undefined): readonly string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length > 100) throw new Error("[getbrick-idaas] client auth trusted origins are invalid");
  const origins = new Set<string>();
  for (const item of value) {
    if (typeof item !== "string") throw new Error("[getbrick-idaas] client auth trusted origins are invalid");
    let parsed: URL;
    try {
      parsed = new URL(item);
    } catch {
      throw new Error("[getbrick-idaas] client auth trusted origins are invalid");
    }
    if (parsed.origin !== item || parsed.username !== "" || parsed.password !== "" || (parsed.pathname !== "" && parsed.pathname !== "/") || parsed.search !== "" || parsed.hash !== "" || (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && isLoopbackHost(parsed.hostname)))) {
      throw new Error("[getbrick-idaas] client auth trusted origins are invalid");
    }
    origins.add(parsed.origin);
  }
  return Object.freeze([...origins]);
}

function hashText(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function assertHash(value: unknown, field: string): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/u.test(value)) throw invalidClientAuth(`invalid_${field}`, "Client authentication state is invalid");
  return value;
}

function hashesEqual(left: string | undefined, right: string | undefined): boolean {
  if (left === undefined || right === undefined) return left === right;
  const leftBuffer = Buffer.from(left, "hex");
  const rightBuffer = Buffer.from(right, "hex");
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function cloneRecord(record: ClientAuthBffStateRecord): ClientAuthBffStateRecord {
  return {
    version: record.version,
    stateHash: record.stateHash,
    nonce: record.nonce,
    codeChallenge: record.codeChallenge,
    redirectUri: record.redirectUri,
    clientType: record.clientType,
    clientId: record.clientId,
    scope: record.scope,
    expiresAt: record.expiresAt,
    ...(record.bindingHash === undefined ? {} : { bindingHash: record.bindingHash }),
  };
}

function freezeRecord(record: ClientAuthBffStateRecord): ClientAuthBffStateRecord {
  return Object.freeze(cloneRecord(record));
}

function parseOpaqueReference(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length < 16 || value.length > 512 || value !== value.trim() || /[\u0000-\u001f\u007f\s]/u.test(value) || FORBIDDEN_REFERENCE_TEXT.test(value)) {
    throw invalidClientAuth(`invalid_${field.toLowerCase()}`, "Client authentication session is invalid");
  }
  return value;
}

function parseSafeUserText(value: unknown, field: string): string {
  if (typeof value !== "string") throw invalidClientAuth("invalid_user", "Client authentication user is invalid");
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 512 || /[\u0000-\u001f\u007f]/u.test(normalized) || FORBIDDEN_CREDENTIAL_TEXT.test(normalized)) throw invalidClientAuth("invalid_user", "Client authentication user is invalid");
  return normalized;
}

function parseSafeEmail(value: unknown): string | null {
  if (value === null) return null;
  if (typeof value !== "string") throw invalidClientAuth("invalid_user", "Client authentication user is invalid");
  const normalized = value.trim().toLowerCase();
  if (normalized.length === 0 || normalized.length > 320 || /[\u0000-\u001f\u007f\s]/u.test(normalized) || !normalized.includes("@") || normalized.endsWith("@placeholder.invalid")) throw invalidClientAuth("invalid_user", "Client authentication user is invalid");
  return normalized;
}

function parseSafeAvatarUrl(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 2048 || value !== value.trim() || /[\u0000-\u001f\u007f\s\\]/u.test(value)) throw invalidClientAuth("invalid_user", "Client authentication user is invalid");
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw invalidClientAuth("invalid_user", "Client authentication user is invalid");
  }
  if (parsed.protocol !== "https:" || parsed.username !== "" || parsed.password !== "" || parsed.hash !== "" || parsed.hostname.length === 0) throw invalidClientAuth("invalid_user", "Client authentication user is invalid");
  return value;
}

function parseDate(value: unknown): string {
  const date = value instanceof Date ? value : new Date(value as string | number);
  if (!Number.isFinite(date.getTime())) throw invalidClientAuth("invalid_session_result", "Client session result is invalid");
  return date.toISOString();
}

function assertScopeAllowed(scope: string, allowed: readonly string[] | undefined): void {
  if (allowed === undefined) return;
  const allowedSet = new Set(allowed);
  const requested = scope.split(/\s+/u).filter((item) => item.length > 0);
  if (requested.some((item) => !allowedSet.has(item))) throw invalidClientAuth("invalid_scope", "Client authentication request is invalid");
}

function assertRedirectAllowed(redirectUri: string, registered: readonly string[], clientType: ClientAuthBffClientType, allowLoopbackHttp: boolean): void {
  if (!registered.includes(redirectUri) || !isSafeRedirectUri(redirectUri, allowLoopbackHttp, clientType)) throw invalidClientAuth("invalid_redirect", "Client authentication redirect is invalid");
}

function assertAllowedFields(value: Record<string, unknown>, fields: readonly string[], label: string): void {
  const allowed = new Set(fields);
  for (const key of Object.getOwnPropertyNames(value)) {
    if (!allowed.has(key)) throw invalidClientAuth(`invalid_${label.replace(/\s+/gu, "_")}`, "Client authentication result is invalid");
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor)) throw invalidClientAuth(`invalid_${label.replace(/\s+/gu, "_")}`, "Client authentication result is invalid");
  }
  for (const key of Object.getOwnPropertySymbols(value)) throw invalidClientAuth(`invalid_${label.replace(/\s+/gu, "_")}`, "Client authentication result is invalid");
}

function assertExactFields(value: unknown, fields: readonly string[], label: string): void {
  if (!isRecord(value)) throw invalidClientAuth("invalid_request", "Client authentication request is invalid");
  const allowed = new Set(fields);
  const names = Object.getOwnPropertyNames(value);
  if (names.length !== fields.length || names.some((key) => !allowed.has(key))) throw invalidClientAuth("invalid_request", "Client authentication request is invalid");
  for (const key of names) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor)) throw invalidClientAuth("invalid_request", "Client authentication request is invalid");
  }
  if (Object.getOwnPropertySymbols(value).length !== 0) throw invalidClientAuth("invalid_request", "Client authentication request is invalid");
  void label;
}

function isValidAdapter(value: unknown): value is ClientAuthBffHostAdapter {
  if (!isObjectLike(value)) return false;
  const adapter = value as Record<string, unknown>;
  const creates = typeof adapter.createAuthorizationUrl === "function" || typeof adapter.authorizationUrl === "function" || typeof adapter.getAuthorizationUrl === "function" || typeof adapter.start === "function";
  const exchanges = typeof adapter.exchangeCode === "function" || typeof adapter.exchange === "function" || typeof adapter.exchangeAuthorizationCode === "function";
  return creates && exchanges;
}

function isValidStateStore(value: unknown): value is ClientAuthBffStateStore {
  if (!isObjectLike(value)) return false;
  const hasSave = typeof value.save === "function" || typeof value.put === "function" || typeof value.set === "function";
  const hasRemove = value.remove === undefined || typeof value.remove === "function";
  const hasDelete = value.delete === undefined || typeof value.delete === "function";
  const hasRevoke = value.revoke === undefined || typeof value.revoke === "function";
  return hasSave && typeof value.consume === "function" && hasRemove && hasDelete && hasRevoke && (value.ready === undefined || typeof value.ready === "function");
}

function readinessOf(value: unknown): (() => boolean | Promise<boolean>) | undefined {
  if (value === null || typeof value !== "object") return undefined;
  const record = value as { ready?: unknown; readiness?: unknown; isReady?: unknown };
  const method = typeof record.ready === "function" ? record.ready : typeof record.readiness === "function" ? record.readiness : typeof record.isReady === "function" ? record.isReady : undefined;
  if (method === undefined) return undefined;
  return async () => {
    const result = await method.call(value);
    if (typeof result === "boolean") return result;
    if (result !== null && typeof result === "object" && "ready" in result) return (result as { ready?: unknown }).ready === true;
    return false;
  };
}

function invalidClientAuth(reason: string, message: string): ControlPlaneError {
  const safeReason = /^[a-z0-9_]{1,64}$/u.test(reason) ? reason : "invalid_request";
  return new ControlPlaneError(CONTROL_PLANE_ERROR_CODES.INVALID_REQUEST, message, {
    statusCode: 400,
    details: { reason: safeReason },
  });
}

function unavailableClientAuth(reason: string): ControlPlaneError {
  const safeReason = /^[a-z0-9_]{1,64}$/u.test(reason) ? reason : "service_unavailable";
  return new ControlPlaneError(CONTROL_PLANE_ERROR_CODES.SERVICE_UNAVAILABLE, "Client authentication service is unavailable", {
    statusCode: 503,
    details: { reason: safeReason },
  });
}

function createBindingValue(): string {
  return randomBytes(32).toString("base64url");
}

function serializeBindingCookie(value: string, maxAge: number): string {
  return `${CLIENT_AUTH_BINDING_COOKIE_NAME}=${encodeURIComponent(value)}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

function serializeExpiredBindingCookie(): string {
  return `${CLIENT_AUTH_BINDING_COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

function readBindingCookie(request: ClientAuthBffHttpRequest): string | undefined {
  const header = headerValue(request.headers, "cookie");
  if (header === undefined) return undefined;
  let found: string | undefined;
  for (const part of header.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    const key = part.slice(0, separator).trim();
    if (key !== CLIENT_AUTH_BINDING_COOKIE_NAME) continue;
    if (found !== undefined) throw invalidClientAuth("invalid_binding", "Client authentication binding is invalid");
    const raw = part.slice(separator + 1).trim();
    let value: string;
    try {
      value = decodeURIComponent(raw);
    } catch {
      throw invalidClientAuth("invalid_binding", "Client authentication binding is invalid");
    }
    if (!/^[A-Za-z0-9_-]{32,512}$/u.test(value)) throw invalidClientAuth("invalid_binding", "Client authentication binding is invalid");
    found = value;
  }
  return found;
}

function readOptionalSessionReference(body: unknown, request: ClientAuthBffHttpRequest, allowBody: boolean): string | undefined {
  let bodyReference: string | undefined;
  if (allowBody && body !== undefined) {
    if (!isEmptyRecord(body)) bodyReference = parseSessionReference(body);
  } else if (body !== undefined && !isEmptyRecord(body)) {
    throw invalidClientAuth("invalid_request", "Client authentication request is invalid");
  }
  const sessionReferenceHeader = headerValue(request.headers, "x-session-reference");
  const clientSessionHeader = headerValue(request.headers, CLIENT_AUTH_SESSION_HEADER);
  if (sessionReferenceHeader !== undefined && clientSessionHeader !== undefined && sessionReferenceHeader !== clientSessionHeader) {
    throw invalidClientAuth("invalid_session_reference", "Client authentication session is invalid");
  }
  const headerReference = sessionReferenceHeader ?? clientSessionHeader;
  if (headerReference !== undefined && !/^[A-Za-z0-9._~-]{16,512}$/u.test(headerReference)) throw invalidClientAuth("invalid_session_reference", "Client authentication session is invalid");
  if (bodyReference !== undefined && headerReference !== undefined && bodyReference !== headerReference) throw invalidClientAuth("invalid_session_reference", "Client authentication session is invalid");
  return bodyReference ?? headerReference;
}

function readSessionReference(body: unknown, request: ClientAuthBffHttpRequest, allowBody: boolean): string {
  const value = readOptionalSessionReference(body, request, allowBody);
  if (value === undefined) throw invalidClientAuth("invalid_session_reference", "Client authentication session is invalid");
  return value;
}

function assertNoRequestQuery(request: ClientAuthBffHttpRequest): void {
  if (request.query !== undefined && !isEmptyRecord(request.query)) throw invalidClientAuth("invalid_request", "Client authentication request is invalid");
}

function assertNoCredentialHeaders(request: ClientAuthBffHttpRequest): void {
  const headers = request.headers ?? {};
  for (const key of Object.keys(headers)) {
    const normalized = normalizeParameterKey(key);
    if (FORBIDDEN_HEADER_KEYS.has(normalized) || FORBIDDEN_RESULT_SUFFIXES.some((suffix) => normalized.endsWith(suffix)) || normalized.endsWith("userid") || normalized.endsWith("tenantid") || normalized.endsWith("linkingpolicy") || normalized.endsWith("provider") || normalized.endsWith("providerid")) {
      throw invalidClientAuth("credential_exposed", "Client authentication request is invalid");
    }
  }
}

function headerValue(headers: Record<string, unknown> | undefined, name: string): string | undefined {
  if (headers === undefined) return undefined;
  const entries = Object.entries(headers).filter(([key]) => key.toLowerCase() === name);
  if (entries.length !== 1) {
    if (entries.length > 1) throw invalidClientAuth("invalid_header", "Client authentication request is invalid");
    return undefined;
  }
  const raw = entries[0][1];
  if (Array.isArray(raw) && raw.length !== 1) throw invalidClientAuth("invalid_header", "Client authentication request is invalid");
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (typeof value !== "string") throw invalidClientAuth("invalid_header", "Client authentication request is invalid");
  if (/[\u0000-\u001f\u007f]/u.test(value)) throw invalidClientAuth("invalid_header", "Client authentication request is invalid");
  return value.trim();
}

function isEmptyRecord(value: unknown): boolean {
  return isRecord(value) && Object.getOwnPropertyNames(value).length === 0 && Object.getOwnPropertySymbols(value).length === 0;
}

function isObjectLike(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (!isObjectLike(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isResponse(value: unknown): value is Response {
  return typeof Response !== "undefined" && value instanceof Response;
}

function hasUnsafePercentEncoding(value: string): boolean {
  let decoded = value;
  for (let depth = 0; depth <= 4; depth += 1) {
    if (!/%[0-9a-f]{2}/iu.test(decoded)) break;
    try {
      const next = decodeURIComponent(decoded);
      if (next === decoded) break;
      decoded = next;
    } catch {
      return true;
    }
  }
  return /[\u0000-\u001f\u007f\s\\]/u.test(decoded) || /%(?:[0-9a-f]{2})?/iu.test(value) && /%[^0-9a-f]/iu.test(value);
}

function isPrivateUseRedirectProtocol(protocol: string): boolean {
  const normalized = protocol.endsWith(":") ? protocol.slice(0, -1) : protocol;
  return /^[a-z][a-z0-9+.-]*$/u.test(normalized) && !["http", "https", "javascript", "data", "file", "about", "blob", "ws", "wss", "mailto", "tel", "urn"].includes(normalized);
}

function isLoopbackHost(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/gu, "");
  return normalized === "localhost" || normalized === "::1" || /^127(?:\.\d{1,3}){3}$/u.test(normalized);
}

function normalizeParameterKey(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/gu, "");
}

function createResponse(): ClientAuthBffHttpResponse {
  return {
    status: () => undefined,
    setHeader: () => undefined,
    json: () => undefined,
    end: () => undefined,
  };
}

function setNoStore(response: ClientAuthBffHttpResponse): void {
  setHeader(response, "Cache-Control", "no-store");
  setHeader(response, "Pragma", "no-cache");
  setHeader(response, "Referrer-Policy", "no-referrer");
}

function setHeader(response: ClientAuthBffHttpResponse, name: string, value: string | string[]): void {
  response.setHeader?.(name, value);
}

function writeJson(response: ClientAuthBffHttpResponse, status: number, body: unknown): void {
  setNoStore(response);
  if (typeof response.status === "function") response.status(status);
  else response.statusCode = status;
  if (typeof response.json === "function") {
    response.json(body);
    return;
  }
  setHeader(response, "Content-Type", "application/json");
  response.end?.(JSON.stringify(body));
}

function writeNoContent(response: ClientAuthBffHttpResponse): void {
  setNoStore(response);
  if (typeof response.status === "function") response.status(204);
  else response.statusCode = 204;
  response.end?.();
}

function clearBindingCookie(response: ClientAuthBffHttpResponse): void {
  appendSetCookie(response, serializeExpiredBindingCookie());
}

function writeSafeResponseHeaders(response: ClientAuthBffHttpResponse, headers: ClientAuthBffSafeResponseHeaders): void {
  for (const cookie of headers.setCookie) appendSetCookie(response, cookie);
}

function appendSetCookie(response: ClientAuthBffHttpResponse, cookie: string): void {
  const existing = response.getHeader?.("Set-Cookie");
  const values = Array.isArray(existing) ? existing.map(String) : existing === undefined ? [] : [String(existing)];
  if (!values.includes(cookie)) values.push(cookie);
  setHeader(response, "Set-Cookie", values);
}

const FORBIDDEN_AUTHORIZATION_PARAMETERS = new Set([
  "code",
  "accesstoken",
  "refreshtoken",
  "idtoken",
  "sessionkey",
  "sessionid",
  "sessiontoken",
  "hostsessiontoken",
  "authorizationcode",
  "clientsecret",
  "secret",
  "password",
  "providerresponse",
  "providercode",
  "codeverifier",
  "userid",
  "tenantid",
  "linkingpolicy",
  "authorization",
  "cookie",
  "session",
  "token",
  "tokens",
]);

const FORBIDDEN_AUTHORIZATION_PARAMETER_SUFFIXES = ["accesstoken", "refreshtoken", "idtoken", "sessiontoken", "authorizationcode", "clientsecret"];

const FORBIDDEN_RESULT_KEYS = new Set([
  "sessionid",
  "sessiontoken",
  "rawsession",
  "rawsessiontoken",
  "bettersession",
  "bettersessiontoken",
  "betterauthtoken",
  "betterauthsessiontoken",
  "setcookie",
  "cookie",
  "accesstoken",
  "refreshtoken",
  "idtoken",
  "providertoken",
  "oauthtoken",
  "authorizationcode",
  "authorization",
  "proxyauthorization",
  "codeverifier",
  "codechallenge",
  "nonce",
  "state",
  "providercode",
  "providerresponse",
  "clientsecret",
  "secret",
  "password",
  "credential",
  "credentials",
  "userid",
  "tenantid",
  "linkingpolicy",
  "identitylinkingpolicy",
]);

const FORBIDDEN_RESULT_SUFFIXES = ["accesstoken", "refreshtoken", "idtoken", "sessiontoken", "authorizationcode", "clientsecret", "privatekey"];

const FORBIDDEN_REFERENCE_TEXT = /(?:provider|access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?(?:id|key|token)|host[_-]?session[_-]?token|authorization[_-]?code|(?:^|[^a-z])code(?:$|[^a-z])|(?:^|[^a-z])state(?:$|[^a-z]))/iu;

const FORBIDDEN_CREDENTIAL_TEXT = /(?:access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?(?:id|key|token)|host[_-]?session[_-]?token|raw[_-]?(?:better[_-]?auth[_-]?)?(?:session[_-]?)?token|provider[_-]?token|authorization[_-]?code|client[_-]?secret|password|credential|authorization|(?:^|[^a-z])token(?:$|[^a-z]))/iu;

const FORBIDDEN_HEADER_KEYS = new Set([
  "authorization",
  "proxyauthorization",
  "xapikey",
  "xclientsecret",
  "xsessiontoken",
  "xhostsessiontoken",
  "xprovidertoken",
  "xaccesstoken",
  "xrefreshtoken",
  "xidtoken",
  "xsessionkey",
  "xsessionid",
  "userid",
  "tenantid",
  "provider",
  "providerid",
  "linkingpolicy",
  "identitylinkingpolicy",
]);

export function verifyClientAuthBffPkceS256(codeVerifier: string, codeChallenge: string): boolean {
  try {
    verifyPkceS256(parseCodeVerifier(codeVerifier), parseCodeChallenge(codeChallenge));
    return true;
  } catch {
    return false;
  }
}

export function createClientAuthBffBindingHash(value: string): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{32,512}$/u.test(value)) throw invalidClientAuth("invalid_binding", "Client authentication binding is invalid");
  return hashText(value);
}

export const CLIENT_AUTH_BFF_COOKIE_NAME = CLIENT_AUTH_BINDING_COOKIE_NAME;
export const CLIENT_AUTH_BFF_SESSION_HEADER = CLIENT_AUTH_SESSION_HEADER;
export const ClientAuthBbfBindingCookieName = CLIENT_AUTH_BINDING_COOKIE_NAME;
export const ClientAuthBbfServiceToken = CLIENT_AUTH_BFF_SERVICE;
export const ClientAuthBbfAdapterToken = CLIENT_AUTH_BFF_ADAPTER;
export const ClientAuthBbfStateStoreToken = CLIENT_AUTH_BFF_STATE_STORE;
export const ClientAuthBbfSessionServiceToken = CLIENT_AUTH_BFF_SESSION_SERVICE;
