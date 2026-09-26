import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { ApplicationPlatformError, toSafeApplicationPlatformError } from "./platforms.js";
import {
  assertPlatformIdentityLinkHostContext,
  normalizePlatformIdentityLinkingPolicy,
  type PlatformIdentityLinkHostContext,
  type PlatformIdentityLinkingPolicy,
} from "./identity-linker.js";

export const PLATFORM_LOGIN_STATE_VERSION = 1 as const;
export const DEFAULT_PLATFORM_LOGIN_STATE_TTL_MS = 10 * 60 * 1000;
export const MAX_PLATFORM_LOGIN_STATE_TTL_MS = 30 * 60 * 1000;
export const PLATFORM_LOGIN_STATE_HASH_BYTES = 32;
export const MAX_PLATFORM_LOGIN_RETURN_TO_LENGTH = 2048;
export const DEFAULT_POSTGRES_PLATFORM_LOGIN_STATE_TABLE = "gb_idaas_platform_login_state";
export const DEFAULT_PLATFORM_LOGIN_STATE_TENANT_ID = "default";

const PLATFORM_STATE_CLAIM_CLOCKS = new WeakMap<object, number>();

export type PlatformLoginClient = "web" | "native" | "mp_weixin" | "webview";
export type PlatformLoginClientInput = PlatformLoginClient | "mini_program";
export type PlatformLoginStateStatus = "issued" | "claimed" | "leased" | "consumed" | "expired" | "revoked";
export type PlatformLoginStateFlow = PlatformLoginClient;

export interface PlatformLoginBinding {
  browserId: string;
  sessionId?: string;
}

export type PlatformLoginBindingValue = Partial<PlatformLoginBinding> & {
  browserId?: string;
};

export interface PlatformLoginBindingInput {
  browserId?: string;
  browserBinding?: string;
  sessionId?: string;
  sessionBinding?: string;
  browser?: string | { browserId?: string; id?: string; sessionId?: string; browser?: string; session?: string };
  binding?: string | { browserId?: string; id?: string; sessionId?: string; browser?: string; session?: string };
  session?: string;
}

export interface PlatformLoginStateRecord {
  version: typeof PLATFORM_LOGIN_STATE_VERSION;
  tenantId: string;
  stateHash: string;
  applicationId: string;
  platformId: string;
  redirectUri: string;
  returnTo?: string;
  bindingHash?: string;
  browserBindingHash?: string;
  sessionBindingHash?: string;
  flow?: PlatformLoginStateFlow;
  status?: PlatformLoginStateStatus;
  leaseOwner?: string;
  leaseExpiresAt?: number;
  createdAt: number;
  updatedAt?: number;
  consumedAt?: number;
  expiresAt: number;
  scope?: string;
  linkingPolicy: PlatformIdentityLinkingPolicy;
  requestedUserId?: string;
  client?: PlatformLoginClient;
}

export interface PlatformLoginStateClaim {
  tenantId?: string;
  applicationId?: string;
  platformId?: string;
  browserBindingHash?: string;
  sessionBindingHash?: string;
  checkBrowserBinding?: boolean;
  checkSessionBinding?: boolean;
  bindingHash?: string;
  redirectUri?: string;
  client?: PlatformLoginClientInput;
  flow?: PlatformLoginClientInput;
  leaseOwner?: string;
}

export interface PlatformLoginStateStore {
  readonly tenantId?: string;
  readonly persistent?: boolean;
  save(record: PlatformLoginStateRecord): void | Promise<void>;
  consume(
    stateHash: string,
    expected?: PlatformLoginStateClaim,
  ): PlatformLoginStateRecord | undefined | Promise<PlatformLoginStateRecord | undefined>;
  claim?(
    stateHash: string,
    expected?: PlatformLoginStateClaim,
  ): PlatformLoginStateRecord | undefined | Promise<PlatformLoginStateRecord | undefined>;
  peek?(
    stateHash: string,
    expected?: PlatformLoginStateClaim,
  ): PlatformLoginStateRecord | undefined | Promise<PlatformLoginStateRecord | undefined>;
  remove?(stateHash: string, tenantId?: string, applicationId?: string): void | Promise<void>;
  status?(
    stateHash: string,
    tenantId?: string,
    applicationId?: string,
  ): PlatformLoginStateStatus | undefined | Promise<PlatformLoginStateStatus | undefined>;
  lease?(
    stateHash: string,
    owner: string,
    leaseMs?: number,
    expected?: PlatformLoginStateClaim,
  ): PlatformLoginStateRecord | undefined | Promise<PlatformLoginStateRecord | undefined>;
  releaseLease?(stateHash: string, owner: string, tenantId?: string, applicationId?: string): boolean | Promise<boolean>;
  cleanupExpired?(now?: number): number | Promise<number>;
  purge?(now?: number): number | Promise<number>;
  expire?(stateHash: string, tenantId?: string, applicationId?: string): boolean | Promise<boolean>;
}

export interface PlatformLoginStateManagerOptions {
  ttlMs?: number;
  ttlSeconds?: number;
  expiresInSeconds?: number;
  now?: () => number;
  randomState?: () => string;
  requireSessionBinding?: boolean;
  tenantId?: string;
}

export interface PlatformLoginStateIssueInput {
  tenantId?: string;
  applicationId: string;
  platformId: string;
  redirectUri: string;
  returnTo?: string;
  binding?: PlatformLoginBindingValue;
  linkingPolicy?: PlatformIdentityLinkingPolicy;
  requestedUserId?: string;
  hostContext?: PlatformIdentityLinkHostContext;
  scope?: string;
  client?: PlatformLoginClientInput;
}

export interface PlatformLoginStateIssueResult {
  state: string;
  record: PlatformLoginStateRecord;
}

export interface PlatformLoginStateConsumeInput {
  state: string;
  tenantId?: string;
  binding?: PlatformLoginBindingValue;
  expectedRedirectUri?: string;
  expectedApplicationId?: string;
  expectedPlatformId?: string;
  client?: PlatformLoginClientInput;
  allowMissingBrowser?: boolean;
  leaseOwner?: string;
}

export type PlatformLoginState = PlatformLoginStateRecord;

export interface InMemoryPlatformLoginStateStoreOptions {
  tenantId?: string;
  now?: () => number;
  maxEntries?: number;
}

export class InMemoryPlatformLoginStateStore implements PlatformLoginStateStore {
  private readonly records = new Map<string, PlatformLoginStateRecord>();
  readonly persistent = false;
  readonly tenantId: string;
  private readonly now: () => number;
  private readonly maxEntries: number;

  constructor(options: InMemoryPlatformLoginStateStoreOptions = {}) {
    this.tenantId = assertTenantId(options.tenantId ?? DEFAULT_PLATFORM_LOGIN_STATE_TENANT_ID);
    this.now = options.now ?? Date.now;
    this.maxEntries = options.maxEntries ?? 10_000;
    if (!Number.isSafeInteger(this.maxEntries) || this.maxEntries < 1 || this.maxEntries > 100_000) {
      throw new ApplicationPlatformError("invalid_platform_state_store", "Platform login state store is invalid");
    }
    if (typeof this.now !== "function") {
      throw new ApplicationPlatformError("invalid_platform_state_store", "Platform login state store is invalid");
    }
  }

  get size(): number {
    return this.records.size;
  }

  save(record: PlatformLoginStateRecord): void {
    assertStateRecord(record);
    const key = stateKey(record.tenantId, record.applicationId, record.stateHash);
    if (this.records.has(key)) {
      throw new ApplicationPlatformError("platform_state_collision", "Platform login state could not be created");
    }
    if (this.records.size >= this.maxEntries) {
      throw new ApplicationPlatformError("platform_state_store_full", "Platform login state store is full");
    }
    const client = normalizeClient(record.client ?? record.flow);
    this.records.set(key, cloneRecord({
      ...record,
      client,
      flow: client,
      status: record.status ?? "issued",
      updatedAt: record.updatedAt ?? record.createdAt,
    }));
  }

  peek(stateHash: string, expected?: PlatformLoginStateClaim): PlatformLoginStateRecord | undefined {
    const normalizedHash = assertHash(stateHash, "platform_state");
    const tenantId = assertTenantId(expected?.tenantId ?? this.tenantId);
    const found = this.findRecord(tenantId, normalizedHash, expected?.applicationId);
    if (found === undefined) return undefined;
    try {
      assertStateRecord(found.record);
    } catch {
      return undefined;
    }
    if (expected !== undefined && !matchesClaim(found.record, expected)) return undefined;
    return cloneRecord(found.record);
  }

  claim(
    stateHash: string,
    expected?: PlatformLoginStateClaim,
  ): PlatformLoginStateRecord | undefined {
    const normalizedHash = assertHash(stateHash, "platform_state");
    const tenantId = assertTenantId(expected?.tenantId ?? this.tenantId);
    const found = this.findRecord(tenantId, normalizedHash, expected?.applicationId);
    if (found === undefined) return undefined;
    try {
      assertStateRecord(found.record);
    } catch {
      return undefined;
    }
    const now = claimClock(expected, () => this.currentTime());
    if (expected !== undefined && !matchesClaim(found.record, expected, now)) return undefined;
    if (found.record.expiresAt <= now || !canConsumeStatus(found.record, expected?.leaseOwner, now)) return undefined;
    const consumed: PlatformLoginStateRecord = {
      ...found.record,
      status: "consumed",
      consumedAt: now,
      updatedAt: now,
      leaseOwner: undefined,
      leaseExpiresAt: undefined,
    };
    this.records.set(found.key, consumed);
    return cloneRecord(consumed);
  }

  consume(stateHash: string, expected?: PlatformLoginStateClaim): PlatformLoginStateRecord | undefined {
    return this.claim(stateHash, expected);
  }

  remove(stateHash: string, tenantId = this.tenantId, applicationId?: string): void {
    const normalizedHash = assertHash(stateHash, "platform_state");
    const found = this.findRecord(assertTenantId(tenantId), normalizedHash, applicationId);
    if (found === undefined) return;
    this.records.set(found.key, {
      ...found.record,
      status: "revoked",
      updatedAt: this.currentTime(),
      leaseOwner: undefined,
      leaseExpiresAt: undefined,
    });
  }

  delete(stateHash: string, tenantId = this.tenantId, applicationId?: string): void {
    const normalizedHash = assertHash(stateHash, "platform_state");
    const found = this.findRecord(assertTenantId(tenantId), normalizedHash, applicationId);
    if (found === undefined) return;
    this.records.delete(found.key);
  }

  status(stateHash: string, tenantId = this.tenantId, applicationId?: string): PlatformLoginStateStatus | undefined {
    return this.peek(stateHash, { tenantId, ...(applicationId === undefined ? {} : { applicationId }) })?.status;
  }

  getStatus(stateHash: string, tenantId = this.tenantId, applicationId?: string): PlatformLoginStateStatus | undefined {
    return this.status(stateHash, tenantId, applicationId);
  }

  lease(
    stateHash: string,
    owner: string,
    leaseMs = 30_000,
    expected?: PlatformLoginStateClaim,
  ): PlatformLoginStateRecord | undefined {
    const normalizedHash = assertHash(stateHash, "platform_state");
    const tenantId = assertTenantId(expected?.tenantId ?? this.tenantId);
    const found = this.findRecord(tenantId, normalizedHash, expected?.applicationId);
    const normalizedOwner = assertBindingValue(owner, "lease owner");
    if (found === undefined) return undefined;
    try {
      assertStateRecord(found.record);
    } catch {
      return undefined;
    }
    if (expected !== undefined && !matchesClaim(found.record, expected)) return undefined;
    const now = this.currentTime();
    if (found.record.expiresAt <= now) return undefined;
    const leaseExpiresAt = now + normalizedLeaseDuration(leaseMs);
    if (
      found.record.status !== "issued" &&
      !(found.record.status === "leased" && ((found.record.leaseExpiresAt ?? 0) <= now || found.record.leaseOwner === normalizedOwner))
    ) return undefined;
    const leased = { ...found.record, status: "leased" as const, leaseOwner: normalizedOwner, leaseExpiresAt, updatedAt: now };
    this.records.set(found.key, leased);
    return cloneRecord(leased);
  }

  releaseLease(stateHash: string, owner: string, tenantId = this.tenantId, applicationId?: string): boolean {
    const normalizedHash = assertHash(stateHash, "platform_state");
    const found = this.findRecord(assertTenantId(tenantId), normalizedHash, applicationId);
    const normalizedOwner = assertBindingValue(owner, "lease owner");
    const now = this.currentTime();
    if (found === undefined || found.record.status !== "leased" || found.record.leaseOwner !== normalizedOwner || found.record.expiresAt <= now) return false;
    this.records.set(found.key, { ...found.record, status: "issued", leaseOwner: undefined, leaseExpiresAt: undefined, updatedAt: now });
    return true;
  }

  purgeExpired(now = this.currentTime()): number {
    let removed = 0;
    for (const [key, record] of this.records) {
      if (record.expiresAt <= now) {
        this.records.delete(key);
        removed += 1;
      }
    }
    return removed;
  }

  cleanupExpired(now = this.currentTime()): number {
    return this.purgeExpired(now);
  }

  purge(now = this.currentTime()): number {
    return this.purgeExpired(now);
  }

  expire(stateHash: string, tenantId = this.tenantId, applicationId?: string): boolean {
    const normalizedHash = assertHash(stateHash, "platform_state");
    const found = this.findRecord(assertTenantId(tenantId), normalizedHash, applicationId);
    const now = this.currentTime();
    if (found === undefined || (found.record.expiresAt > now && found.record.status !== "issued" && found.record.status !== "leased")) return false;
    this.records.set(found.key, { ...found.record, status: "expired", updatedAt: now, leaseOwner: undefined, leaseExpiresAt: undefined });
    return true;
  }

  private findRecord(tenantId: string, stateHash: string, applicationId?: string): { key: string; record: PlatformLoginStateRecord } | undefined {
    if (applicationId !== undefined) {
      const normalizedApplicationId = assertIdentifier(applicationId, "application");
      const key = stateKey(tenantId, normalizedApplicationId, stateHash);
      const record = this.records.get(key);
      return record === undefined ? undefined : { key, record };
    }
    const matches = [...this.records.entries()].filter(([, record]) => (
      record.tenantId === tenantId && record.stateHash === stateHash
    ));
    return matches.length === 1 ? { key: matches[0][0], record: matches[0][1] } : undefined;
  }

  private currentTime(): number {
    return assertClockValue(this.now());
  }
}

export function createInMemoryPlatformLoginStateStore(
  options?: InMemoryPlatformLoginStateStoreOptions,
): InMemoryPlatformLoginStateStore {
  return new InMemoryPlatformLoginStateStore(options);
}

export interface PlatformLoginStateSqlExecutor {
  query(text: string, values?: unknown[]): unknown | Promise<unknown>;
}

export interface PostgresPlatformLoginStateStoreOptions {
  tableName?: string;
  tenantId?: string;
  initializeSchema?: boolean;
  now?: () => number;
  leaseDurationMs?: number;
  leaseOwner?: string;
}

export class PostgresPlatformLoginStateStore implements PlatformLoginStateStore {
  private readonly executor: PlatformLoginStateSqlExecutor;
  private readonly table: string;
  readonly persistent = true;
  readonly tenantId: string;
  private readonly now: () => number;
  private readonly initializeSchema: boolean;
  private readonly leaseDurationMs: number;
  private readonly leaseOwner: string | undefined;
  private schemaPromise?: Promise<void>;

  constructor(executor: PlatformLoginStateSqlExecutor, options: PostgresPlatformLoginStateStoreOptions = {}) {
    if (!executor || typeof executor.query !== "function") {
      throw new ApplicationPlatformError("invalid_platform_state_store", "Platform login state store is invalid");
    }
    this.executor = executor;
    this.table = quoteStateTable(options.tableName ?? DEFAULT_POSTGRES_PLATFORM_LOGIN_STATE_TABLE);
    this.tenantId = assertTenantId(options.tenantId ?? DEFAULT_PLATFORM_LOGIN_STATE_TENANT_ID);
    this.now = options.now ?? Date.now;
    this.initializeSchema = options.initializeSchema === true;
    this.leaseDurationMs = normalizedLeaseDuration(options.leaseDurationMs ?? 30_000);
    this.leaseOwner = options.leaseOwner === undefined ? undefined : assertBindingValue(options.leaseOwner, "lease owner");
    if (typeof this.now !== "function") {
      throw new ApplicationPlatformError("invalid_platform_state_store", "Platform login state store is invalid");
    }
  }

  async ready(): Promise<boolean> {
    try {
      await this.ensureSchema();
      const result = await this.executor.query(`SELECT return_to FROM ${this.table} LIMIT 0`, []);
      return Array.isArray(result) || (isRecord(result) && Array.isArray(result.rows));
    } catch {
      return false;
    }
  }

  async save(record: PlatformLoginStateRecord): Promise<void> {
    assertStateRecord(record);
    if (record.tenantId !== this.tenantId) {
      throw new ApplicationPlatformError("platform_state_tenant_mismatch", "Platform login state tenant does not match the store");
    }
    await this.ensureSchema();
    const flow = normalizeClient(record.flow ?? record.client);
    const status = record.status ?? "issued";
    const values = [
      record.tenantId,
      record.stateHash,
      record.bindingHash ?? record.browserBindingHash ?? record.sessionBindingHash ?? record.stateHash,
      record.browserBindingHash ?? null,
      record.sessionBindingHash ?? null,
      record.applicationId,
      record.platformId,
      flow,
      status,
      record.leaseOwner ?? null,
      record.leaseExpiresAt === undefined ? null : toSqlTimestamp(record.leaseExpiresAt),
      toSqlTimestamp(record.expiresAt),
      record.redirectUri,
      record.scope ?? null,
      JSON.stringify(record.linkingPolicy),
      record.requestedUserId ?? null,
      toSqlTimestamp(record.createdAt),
      toSqlTimestamp(record.updatedAt ?? record.createdAt),
      record.consumedAt === undefined ? null : toSqlTimestamp(record.consumedAt),
      record.returnTo ?? null,
    ];
    try {
      await this.executor.query(
        `INSERT INTO ${this.table} (tenant_id, state_hash, binding_hash, browser_binding_hash, session_binding_hash, application_id, platform_id, flow, status, lease_owner, lease_expires_at, expires_at, redirect_uri, scope, linking_policy, requested_user_id, created_at, updated_at, consumed_at, return_to) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15::jsonb, $16, $17, $18, $19, $20)`,
        values,
      );
    } catch (error) {
      if (isUniqueViolation(error)) {
        throw new ApplicationPlatformError("platform_state_collision", "Platform login state could not be created");
      }
      throw error;
    }
  }

  async peek(stateHash: string, expected?: PlatformLoginStateClaim): Promise<PlatformLoginStateRecord | undefined> {
    await this.ensureSchema();
    const normalizedHash = assertHash(stateHash, "platform_state");
    if (expected?.tenantId !== undefined && expected.tenantId !== this.tenantId) return undefined;
    const values: unknown[] = [this.tenantId, normalizedHash];
    const clauses = ["tenant_id = $1", "state_hash = $2"];
    appendClaimClauses(clauses, values, expected);
    const result = await this.executor.query(
      `SELECT ${stateSelect()} FROM ${this.table} WHERE ${clauses.join(" AND ")} LIMIT 2`,
      values,
    );
    const rows = rowsFromResult(result);
    return rows.length === 1 ? recordFromRow(rows[0], this.tenantId) : undefined;
  }

  async claim(
    stateHash: string,
    expected?: PlatformLoginStateClaim,
  ): Promise<PlatformLoginStateRecord | undefined> {
    await this.ensureSchema();
    const normalizedHash = assertHash(stateHash, "platform_state");
    if (expected?.tenantId !== undefined && expected.tenantId !== this.tenantId) return undefined;
    let claimExpected = expected;
    if (claimExpected?.applicationId === undefined) {
      const existing = await this.peek(normalizedHash, claimExpected);
      if (existing === undefined) return undefined;
      claimExpected = { ...claimExpected, applicationId: existing.applicationId };
      copyClaimClock(claimExpected, expected);
    }
    const now = claimClock(claimExpected, () => this.currentTime());
    const values: unknown[] = [this.tenantId, normalizedHash, toSqlTimestamp(now)];
    const clauses = [
      "tenant_id = $1",
      "state_hash = $2",
    ];
    if (claimExpected?.leaseOwner === undefined) {
      clauses.push("status = 'issued'");
    } else {
      values.push(assertBindingValue(claimExpected.leaseOwner, "lease owner"));
      clauses.push(`(status = 'issued' OR (status = 'claimed' AND lease_owner = $${values.length}) OR (status = 'leased' AND lease_owner = $${values.length} AND lease_expires_at > $3))`);
    }
    clauses.push("expires_at > $3");
    appendClaimClauses(clauses, values, claimExpected);
    const result = await this.executor.query(
      `UPDATE ${this.table} SET status = 'consumed', consumed_at = $3, updated_at = $3, lease_owner = NULL, lease_expires_at = NULL WHERE ${clauses.join(" AND ")} RETURNING ${stateSelect()}`,
      values,
    );
    return recordFromRow(rowsFromResult(result)[0], this.tenantId);
  }

  async consume(stateHash: string, expected?: PlatformLoginStateClaim): Promise<PlatformLoginStateRecord | undefined> {
    return this.claim(stateHash, expected);
  }

  async remove(stateHash: string, tenantId = this.tenantId, applicationId?: string): Promise<void> {
    await this.ensureSchema();
    const normalizedHash = assertHash(stateHash, "platform_state");
    const normalizedTenant = assertTenantId(tenantId);
    if (normalizedTenant !== this.tenantId) return;
    let scopedApplicationId = applicationId;
    if (scopedApplicationId === undefined) {
      const existing = await this.peek(normalizedHash, { tenantId: this.tenantId });
      if (existing === undefined) return;
      scopedApplicationId = existing.applicationId;
    }
    const values: unknown[] = [this.tenantId, normalizedHash, toSqlTimestamp(this.currentTime())];
    const clauses = ["tenant_id = $1", "state_hash = $2", "status IN ('issued', 'leased')"];
    values.push(assertIdentifier(scopedApplicationId, "application"));
    clauses.push(`application_id = $${values.length}`);
    await this.executor.query(
      `UPDATE ${this.table} SET status = 'revoked', updated_at = $3, lease_owner = NULL, lease_expires_at = NULL WHERE ${clauses.join(" AND ")}`,
      values,
    );
  }

  async revoke(stateHash: string, tenantId = this.tenantId, applicationId?: string): Promise<void> {
    return this.remove(stateHash, tenantId, applicationId);
  }

  async status(stateHash: string, tenantId = this.tenantId, applicationId?: string): Promise<PlatformLoginStateStatus | undefined> {
    const record = await this.peek(stateHash, {
      tenantId,
      ...(applicationId === undefined ? {} : { applicationId }),
    });
    return record?.status;
  }

  async getStatus(stateHash: string, tenantId = this.tenantId, applicationId?: string): Promise<PlatformLoginStateStatus | undefined> {
    return this.status(stateHash, tenantId, applicationId);
  }

  async lease(
    stateHash: string,
    owner = this.leaseOwner,
    leaseMs = this.leaseDurationMs,
    expected?: PlatformLoginStateClaim,
  ): Promise<PlatformLoginStateRecord | undefined> {
    if (owner === undefined) {
      throw new ApplicationPlatformError("invalid_platform_state_store", "Platform login state lease owner is required");
    }
    await this.ensureSchema();
    const normalizedHash = assertHash(stateHash, "platform_state");
    if (expected?.tenantId !== undefined && expected.tenantId !== this.tenantId) return undefined;
    let leaseExpected = expected;
    if (leaseExpected?.applicationId === undefined) {
      const existing = await this.peek(normalizedHash, leaseExpected);
      if (existing === undefined) return undefined;
      leaseExpected = { ...leaseExpected, applicationId: existing.applicationId };
      copyClaimClock(leaseExpected, expected);
    }
    const now = claimClock(leaseExpected, () => this.currentTime());
    const values: unknown[] = [
      this.tenantId,
      normalizedHash,
      assertBindingValue(owner, "lease owner"),
      toSqlTimestamp(now),
      toSqlTimestamp(now + normalizedLeaseDuration(leaseMs)),
    ];
    const clauses = [
      "tenant_id = $1",
      "state_hash = $2",
      "(status = 'issued' OR (status = 'leased' AND (lease_expires_at <= $4 OR lease_owner = $3)))",
      "expires_at > $4",
    ];
    appendClaimClauses(clauses, values, leaseExpected);
    const result = await this.executor.query(
      `UPDATE ${this.table} SET status = 'leased', lease_owner = $3, lease_expires_at = $5, updated_at = $4 WHERE ${clauses.join(" AND ")} RETURNING ${stateSelect()}`,
      values,
    );
    return recordFromRow(rowsFromResult(result)[0], this.tenantId);
  }

  async releaseLease(stateHash: string, owner: string, tenantId = this.tenantId, applicationId?: string): Promise<boolean> {
    await this.ensureSchema();
    const normalizedHash = assertHash(stateHash, "platform_state");
    const normalizedTenant = assertTenantId(tenantId);
    if (normalizedTenant !== this.tenantId) return false;
    let scopedApplicationId = applicationId;
    if (scopedApplicationId === undefined) {
      const existing = await this.peek(normalizedHash, { tenantId: this.tenantId });
      if (existing === undefined) return false;
      scopedApplicationId = existing.applicationId;
    }
    const values: unknown[] = [
      this.tenantId,
      normalizedHash,
      assertBindingValue(owner, "lease owner"),
      toSqlTimestamp(this.currentTime()),
    ];
    const clauses = [
      "tenant_id = $1",
      "state_hash = $2",
      "status = 'leased'",
      "lease_owner = $3",
      "lease_expires_at > $4",
    ];
    values.push(assertIdentifier(scopedApplicationId, "application"));
    clauses.push(`application_id = $${values.length}`);
    const result = await this.executor.query(
      `UPDATE ${this.table} SET status = 'issued', lease_owner = NULL, lease_expires_at = NULL, updated_at = $4 WHERE ${clauses.join(" AND ")}`,
      values,
    );
    return affectedRows(result) > 0;
  }

  async purgeExpired(now = this.currentTime()): Promise<number> {
    await this.ensureSchema();
    const result = await this.executor.query(
      `DELETE FROM ${this.table} WHERE tenant_id = $1 AND (expires_at <= $2 OR status IN ('expired', 'revoked')) RETURNING state_hash`,
      [this.tenantId, toSqlTimestamp(now)],
    );
    return affectedRows(result);
  }

  async cleanupExpired(now = this.currentTime()): Promise<number> {
    return this.purgeExpired(now);
  }

  async purge(now = this.currentTime()): Promise<number> {
    return this.purgeExpired(now);
  }

  async expire(stateHash: string, tenantId = this.tenantId, applicationId?: string): Promise<boolean> {
    await this.ensureSchema();
    const normalizedHash = assertHash(stateHash, "platform_state");
    const normalizedTenant = assertTenantId(tenantId);
    if (normalizedTenant !== this.tenantId) return false;
    let scopedApplicationId = applicationId;
    if (scopedApplicationId === undefined) {
      const existing = await this.peek(normalizedHash, { tenantId: this.tenantId });
      if (existing === undefined) return false;
      scopedApplicationId = existing.applicationId;
    }
    const values: unknown[] = [this.tenantId, normalizedHash, toSqlTimestamp(this.currentTime())];
    const clauses = [
      "tenant_id = $1",
      "state_hash = $2",
      "(expires_at <= $3 OR status IN ('issued', 'leased'))",
    ];
    values.push(assertIdentifier(scopedApplicationId, "application"));
    clauses.push(`application_id = $${values.length}`);
    const result = await this.executor.query(
      `UPDATE ${this.table} SET status = 'expired', updated_at = $3, lease_owner = NULL, lease_expires_at = NULL WHERE ${clauses.join(" AND ")}`,
      values,
    );
    return affectedRows(result) > 0;
  }

  private currentTime(): number {
    return assertClockValue(this.now());
  }

  private async ensureSchema(): Promise<void> {
    if (!this.initializeSchema) return;
    if (this.schemaPromise === undefined) {
      this.schemaPromise = (async () => {
        await this.executor.query(
          `CREATE TABLE IF NOT EXISTS ${this.table} (tenant_id TEXT NOT NULL, state_hash TEXT NOT NULL, binding_hash TEXT NOT NULL, browser_binding_hash TEXT, session_binding_hash TEXT, application_id TEXT NOT NULL, platform_id TEXT NOT NULL, flow TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'issued', lease_owner TEXT, lease_expires_at TIMESTAMPTZ, expires_at TIMESTAMPTZ NOT NULL, redirect_uri TEXT NOT NULL, scope TEXT, linking_policy JSONB NOT NULL, requested_user_id TEXT, created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL, consumed_at TIMESTAMPTZ, return_to TEXT, PRIMARY KEY (tenant_id, application_id, state_hash))`,
          [],
        );
        await this.executor.query(
          `ALTER TABLE ${this.table} ADD COLUMN IF NOT EXISTS "return_to" TEXT`,
          [],
        );
        await this.executor.query(
          `CREATE INDEX IF NOT EXISTS ${quoteStateIndex(`${unqualifiedStateTable(this.table)}_expires_at_idx`)} ON ${this.table} (tenant_id, status, expires_at)`,
          [],
        );
      })().catch((error: unknown) => {
        this.schemaPromise = undefined;
        throw error;
      });
    }
    await this.schemaPromise;
  }
}

export function createPostgresPlatformLoginStateStore(
  executor: PlatformLoginStateSqlExecutor,
  options?: PostgresPlatformLoginStateStoreOptions,
): PostgresPlatformLoginStateStore {
  return new PostgresPlatformLoginStateStore(executor, options);
}

export const SqlPlatformLoginStateStore = PostgresPlatformLoginStateStore;
export const createSqlPlatformLoginStateStore = createPostgresPlatformLoginStateStore;

export class PlatformLoginStateManager {
  private readonly store: PlatformLoginStateStore;
  private readonly ttlMs: number;
  private readonly now: () => number;
  private readonly randomState: () => string;
  private readonly requireSessionBinding: boolean;
  readonly tenantId: string;

  get persistent(): boolean {
    return this.store.persistent === true;
  }

  constructor(store: PlatformLoginStateStore, options: PlatformLoginStateManagerOptions = {}) {
    if (!store || typeof store.save !== "function" || typeof store.consume !== "function") {
      throw new ApplicationPlatformError("invalid_platform_state_store", "Platform login state store is invalid");
    }
    const ttlSeconds = options.ttlSeconds ?? options.expiresInSeconds;
    if (options.ttlMs !== undefined && ttlSeconds !== undefined && options.ttlMs !== ttlSeconds * 1000) {
      throw new ApplicationPlatformError("invalid_platform_state_ttl", "Platform login state lifetime is invalid");
    }
    const ttlMs = options.ttlMs ?? (ttlSeconds === undefined ? DEFAULT_PLATFORM_LOGIN_STATE_TTL_MS : ttlSeconds * 1000);
    if (!Number.isSafeInteger(ttlMs) || ttlMs < 1_000 || ttlMs > MAX_PLATFORM_LOGIN_STATE_TTL_MS) {
      throw new ApplicationPlatformError("invalid_platform_state_ttl", "Platform login state lifetime is invalid");
    }
    this.store = store;
    this.ttlMs = ttlMs;
    this.now = options.now ?? Date.now;
    this.randomState = options.randomState ?? (() => randomBytes(PLATFORM_LOGIN_STATE_HASH_BYTES).toString("base64url"));
    this.requireSessionBinding = options.requireSessionBinding === true;
    this.tenantId = assertTenantId(options.tenantId ?? this.store.tenantId ?? DEFAULT_PLATFORM_LOGIN_STATE_TENANT_ID);
    if (typeof this.now !== "function" || typeof this.randomState !== "function") {
      throw new ApplicationPlatformError("invalid_platform_state_store", "Platform login state store is invalid");
    }
  }

  async issue(input: PlatformLoginStateIssueInput): Promise<PlatformLoginStateIssueResult> {
    if (!isRecord(input)) {
      throw new ApplicationPlatformError("invalid_platform_request", "Platform login state request is invalid");
    }
    const tenantId = assertTenantId(input.tenantId ?? this.tenantId);
    const applicationId = assertIdentifier(input.applicationId, "application");
    const platformId = assertIdentifier(input.platformId, "platform");
    const redirectUri = assertRedirectValue(input.redirectUri);
    const client = normalizeClient(input.client);
    const returnTo = input.returnTo === undefined ? undefined : assertPlatformLoginReturnTo(input.returnTo);
    if (returnTo !== undefined && client !== "web") {
      throw new ApplicationPlatformError("invalid_return_to", "Platform login returnTo is only valid for web clients");
    }
    const binding = normalizePlatformLoginBinding(input.binding, {
      allowMissingBrowser: client !== "web",
    });
    if (client === "web" && binding.browserId === undefined) {
      throw new ApplicationPlatformError("invalid_platform_binding", "Platform login browser binding is required");
    }
    if (this.requireSessionBinding && binding.sessionId === undefined) {
      throw new ApplicationPlatformError("invalid_platform_binding", "Platform login session binding is required");
    }
    const linkingPolicy = normalizePlatformIdentityLinkingPolicy(input.linkingPolicy);
    const requestedUserId = input.requestedUserId === undefined
      ? undefined
      : assertIdentifier(input.requestedUserId, "user");
    if (requestedUserId !== undefined && linkingPolicy.mode !== "link_existing") {
      throw new ApplicationPlatformError("invalid_identity_linking_policy", "Only explicit account linking accepts a user target");
    }
    assertPlatformIdentityLinkHostContext(linkingPolicy, requestedUserId, input.hostContext);
    const scope = input.scope === undefined ? undefined : assertScope(input.scope);
    const state = assertGeneratedState(this.randomState());
    const stateHash = hashPlatformLoginState(state);
    const createdAt = this.currentTime();
    const browserBindingHash = binding.browserId === undefined ? undefined : hashPlatformLoginBinding(binding.browserId);
    const sessionBindingHash = binding.sessionId === undefined ? undefined : hashPlatformLoginBinding(binding.sessionId);
    const record: PlatformLoginStateRecord = {
      version: PLATFORM_LOGIN_STATE_VERSION,
      tenantId,
      stateHash,
      applicationId,
      platformId,
      redirectUri,
      ...(returnTo === undefined ? {} : { returnTo }),
      bindingHash: browserBindingHash ?? sessionBindingHash ?? stateHash,
      ...(browserBindingHash === undefined ? {} : { browserBindingHash }),
      ...(sessionBindingHash === undefined ? {} : { sessionBindingHash }),
      flow: client,
      status: "issued",
      createdAt,
      updatedAt: createdAt,
      expiresAt: createdAt + this.ttlMs,
      ...(scope === undefined ? {} : { scope }),
      linkingPolicy,
      ...(requestedUserId === undefined ? {} : { requestedUserId }),
      client,
    };
    try {
      await this.store.save(record);
    } catch (error) {
      throw toSafeApplicationPlatformError(
        error,
        "platform_state_store_unavailable",
        "Platform login state could not be stored",
      );
    }
    return { state, record: cloneRecord(record) };
  }

  async create(input: PlatformLoginStateIssueInput): Promise<PlatformLoginStateIssueResult> {
    return this.issue(input);
  }

  async createState(input: PlatformLoginStateIssueInput): Promise<PlatformLoginStateIssueResult> {
    return this.issue(input);
  }

  canPeek(): boolean {
    return typeof this.store.peek === "function";
  }

  async peek(input: PlatformLoginStateConsumeInput): Promise<PlatformLoginStateRecord> {
    if (!isRecord(input)) {
      throw new ApplicationPlatformError("invalid_platform_request", "Platform login state request is invalid");
    }
    const state = assertState(input.state);
    const tenantId = assertTenantId(input.tenantId ?? this.tenantId);
    const client = normalizeClient(input.client);
    const binding = normalizePlatformLoginBinding(input.binding, {
      allowMissingBrowser: input.allowMissingBrowser === true || client !== "web",
    });
    if (client === "web" && binding.browserId === undefined) {
      throw new ApplicationPlatformError("invalid_platform_binding", "Platform login browser binding is required");
    }
    const expectedRedirectUri = input.expectedRedirectUri === undefined
      ? undefined
      : assertRedirectValue(input.expectedRedirectUri);
    const expectedApplicationId = input.expectedApplicationId === undefined
      ? undefined
      : assertIdentifier(input.expectedApplicationId, "application");
    const expectedPlatformId = input.expectedPlatformId === undefined
      ? undefined
      : assertIdentifier(input.expectedPlatformId, "platform");
    const leaseOwner = input.leaseOwner === undefined
      ? undefined
      : assertBindingValue(input.leaseOwner, "lease owner");
    if (typeof this.store.peek !== "function") {
      throw new ApplicationPlatformError("platform_state_store_unavailable", "Platform login state could not be read");
    }
    let record: PlatformLoginStateRecord | undefined;
    try {
      record = await this.store.peek(hashPlatformLoginState(state), {
        tenantId,
        ...(expectedApplicationId === undefined ? {} : { applicationId: expectedApplicationId }),
        ...(expectedPlatformId === undefined ? {} : { platformId: expectedPlatformId }),
        client,
        flow: client,
        ...(expectedRedirectUri === undefined ? {} : { redirectUri: expectedRedirectUri }),
        ...(leaseOwner === undefined ? {} : { leaseOwner }),
      });
    } catch (error) {
      throw toSafeApplicationPlatformError(error, "platform_state_store_unavailable", "Platform login state could not be read");
    }
    if (record === undefined) {
      throw new ApplicationPlatformError("invalid_platform_state", "Platform login state is invalid or has already been used");
    }
    this.validateConsumedRecord(record, hashPlatformLoginState(state), binding, expectedRedirectUri, client, expectedApplicationId, expectedPlatformId, tenantId, "peek", leaseOwner);
    return cloneRecord(record);
  }

  async consume(input: PlatformLoginStateConsumeInput): Promise<PlatformLoginStateRecord> {
    if (!isRecord(input)) {
      throw new ApplicationPlatformError("invalid_platform_request", "Platform login state request is invalid");
    }
    const state = assertState(input.state);
    const tenantId = assertTenantId(input.tenantId ?? this.tenantId);
    const client = normalizeClient(input.client);
    const binding = normalizePlatformLoginBinding(input.binding, {
      allowMissingBrowser: input.allowMissingBrowser === true || client !== "web",
    });
    if (client === "web" && binding.browserId === undefined) {
      throw new ApplicationPlatformError("invalid_platform_binding", "Platform login browser binding is required");
    }
    const expectedRedirectUri = input.expectedRedirectUri === undefined
      ? undefined
      : assertRedirectValue(input.expectedRedirectUri);
    const expectedApplicationId = input.expectedApplicationId === undefined
      ? undefined
      : assertIdentifier(input.expectedApplicationId, "application");
    const expectedPlatformId = input.expectedPlatformId === undefined
      ? undefined
      : assertIdentifier(input.expectedPlatformId, "platform");
    const leaseOwner = input.leaseOwner === undefined
      ? undefined
      : assertBindingValue(input.leaseOwner, "lease owner");
    const stateHash = hashPlatformLoginState(state);
    const expected: PlatformLoginStateClaim = {
      tenantId,
      ...(expectedApplicationId === undefined ? {} : { applicationId: expectedApplicationId }),
      ...(expectedPlatformId === undefined ? {} : { platformId: expectedPlatformId }),
      checkBrowserBinding: true,
      checkSessionBinding: true,
      ...(binding.browserId === undefined ? {} : { browserBindingHash: hashPlatformLoginBinding(binding.browserId) }),
      ...(binding.sessionId === undefined ? {} : { sessionBindingHash: hashPlatformLoginBinding(binding.sessionId) }),
      ...(expectedRedirectUri === undefined ? {} : { redirectUri: expectedRedirectUri }),
      client,
      flow: client,
      ...(leaseOwner === undefined ? {} : { leaseOwner }),
    };
    setClaimClock(expected, this.currentTime());
    let record: PlatformLoginStateRecord | undefined;
    try {
      if (typeof this.store.peek === "function") {
        const existing = await this.store.peek(stateHash, {
          tenantId,
          ...(expectedApplicationId === undefined ? {} : { applicationId: expectedApplicationId }),
          ...(expectedPlatformId === undefined ? {} : { platformId: expectedPlatformId }),
          client,
          flow: client,
          ...(expectedRedirectUri === undefined ? {} : { redirectUri: expectedRedirectUri }),
          ...(leaseOwner === undefined ? {} : { leaseOwner }),
        });
        if (existing === undefined) {
          throw new ApplicationPlatformError("invalid_platform_state", "Platform login state is invalid or has already been used");
        }
        this.validateConsumedRecord(existing, stateHash, binding, expectedRedirectUri, client, expectedApplicationId, expectedPlatformId, tenantId, "peek", leaseOwner);
      }
      if (typeof this.store.claim === "function") {
        record = await this.store.claim(stateHash, expected);
        if (record === undefined) {
          const existing = typeof this.store.peek === "function"
            ? await this.store.peek(stateHash, {
                tenantId,
                ...(expectedApplicationId === undefined ? {} : { applicationId: expectedApplicationId }),
                ...(expectedPlatformId === undefined ? {} : { platformId: expectedPlatformId }),
                client,
                flow: client,
                ...(expectedRedirectUri === undefined ? {} : { redirectUri: expectedRedirectUri }),
              })
            : undefined;
          if (existing !== undefined) {
            this.validateConsumedRecord(existing, stateHash, binding, expectedRedirectUri, client, expectedApplicationId, expectedPlatformId, tenantId, "peek", leaseOwner);
            throw new ApplicationPlatformError("invalid_platform_state", "Platform login state is invalid or has already been used");
          }
          throw new ApplicationPlatformError("invalid_platform_state", "Platform login state is invalid or has already been used");
        }
      } else if (typeof this.store.peek === "function") {
        const existing = await this.store.peek(stateHash, {
          tenantId,
          ...(expectedApplicationId === undefined ? {} : { applicationId: expectedApplicationId }),
          ...(expectedPlatformId === undefined ? {} : { platformId: expectedPlatformId }),
          client,
          flow: client,
          ...(expectedRedirectUri === undefined ? {} : { redirectUri: expectedRedirectUri }),
          ...(leaseOwner === undefined ? {} : { leaseOwner }),
        });
        if (existing === undefined) {
          throw new ApplicationPlatformError("invalid_platform_state", "Platform login state is invalid or has already been used");
        }
        this.validateConsumedRecord(existing, stateHash, binding, expectedRedirectUri, client, expectedApplicationId, expectedPlatformId, tenantId, "peek", leaseOwner);
        record = await this.store.consume(stateHash, expected);
      } else {
        record = await this.store.consume(stateHash, expected);
      }
    } catch (error) {
      if (error instanceof ApplicationPlatformError) throw error;
      throw toSafeApplicationPlatformError(
        error,
        "platform_state_store_unavailable",
        "Platform login state could not be read",
      );
    }
    if (record === undefined) {
      throw new ApplicationPlatformError("invalid_platform_state", "Platform login state is invalid or has already been used");
    }
    this.validateConsumedRecord(record, stateHash, binding, expectedRedirectUri, client, expectedApplicationId, expectedPlatformId, tenantId, "consumed", leaseOwner);
    return cloneRecord(record);
  }

  async claim(input: PlatformLoginStateConsumeInput): Promise<PlatformLoginStateRecord> {
    return this.consume(input);
  }

  async consumeState(
    state: string,
    binding: PlatformLoginBinding | PlatformLoginBindingValue | undefined,
    expectedRedirectUri?: string,
    client?: PlatformLoginClientInput,
    tenantId?: string,
    applicationId?: string,
  ): Promise<PlatformLoginStateRecord> {
    return this.consume({
      state,
      binding,
      ...(expectedRedirectUri === undefined ? {} : { expectedRedirectUri }),
      ...(client === undefined ? {} : { client }),
      ...(tenantId === undefined ? {} : { tenantId }),
      ...(applicationId === undefined ? {} : { expectedApplicationId: applicationId }),
    });
  }

  async revoke(state: string, tenantId = this.tenantId, applicationId?: string): Promise<void> {
    const stateHash = hashPlatformLoginState(assertState(state));
    try {
      if (typeof this.store.remove === "function") {
        await this.store.remove(stateHash, tenantId, applicationId);
      } else {
        await this.store.consume(stateHash, {
          tenantId,
          ...(applicationId === undefined ? {} : { applicationId }),
        });
      }
    } catch {
      return;
    }
  }

  private validateConsumedRecord(
    record: PlatformLoginStateRecord,
    stateHash: string,
    binding: PlatformLoginBindingValue,
    expectedRedirectUri: string | undefined,
    client: PlatformLoginClient,
    expectedApplicationId: string | undefined,
     expectedPlatformId: string | undefined,
     expectedTenantId: string,
     phase: "peek" | "consumed",
     leaseOwner?: string,
  ): void {
    try {
      assertStateRecord(record);
    } catch {
      throw new ApplicationPlatformError("invalid_platform_state", "Platform login state is invalid or has already been used");
    }
    if (!safeHashEqual(record.stateHash, stateHash)) {
      throw new ApplicationPlatformError("invalid_platform_state", "Platform login state is invalid or has already been used");
    }
    if (record.tenantId !== expectedTenantId) {
      throw new ApplicationPlatformError("platform_state_tenant_mismatch", "Platform callback tenant does not match login state");
    }
    const status = normalizeStateStatus(record.status);
    const now = this.currentTime();
    if (
      (phase === "peek" && status !== "issued" && !canConsumeStatus(record, leaseOwner, now)) ||
      (phase === "consumed" && status !== "consumed")
    ) {
      throw new ApplicationPlatformError("invalid_platform_state", "Platform login state is invalid or has already been used");
    }
    if (record.flow !== undefined && normalizeClient(record.flow) !== client) {
      throw new ApplicationPlatformError("invalid_platform_state", "Platform login state is invalid or has already been used");
    }
    if (record.expiresAt <= now) {
      throw new ApplicationPlatformError("platform_state_expired", "Platform login state has expired");
    }
    if (normalizeClient(record.client) !== client) {
      throw new ApplicationPlatformError("invalid_platform_state", "Platform login state is invalid or has already been used");
    }
    if (expectedApplicationId !== undefined && record.applicationId !== expectedApplicationId) {
      throw new ApplicationPlatformError("platform_state_application_mismatch", "Platform callback application does not match login state");
    }
    if (expectedPlatformId !== undefined && record.platformId !== expectedPlatformId) {
      throw new ApplicationPlatformError("platform_state_platform_mismatch", "Platform callback platform does not match login state");
    }
    if (record.browserBindingHash === undefined) {
      if (binding.browserId !== undefined) {
        throw new ApplicationPlatformError("platform_state_binding_mismatch", "Platform login state is not bound to this browser");
      }
    } else if (binding.browserId === undefined || !safeHashEqual(record.browserBindingHash, hashPlatformLoginBinding(binding.browserId))) {
      throw new ApplicationPlatformError("platform_state_binding_mismatch", "Platform login state is not bound to this browser");
    }
    if (this.requireSessionBinding && record.sessionBindingHash === undefined) {
      throw new ApplicationPlatformError("platform_state_binding_mismatch", "Platform login state is not bound to this session");
    }
    if (
      record.sessionBindingHash !== undefined &&
      (binding.sessionId === undefined || !safeHashEqual(record.sessionBindingHash, hashPlatformLoginBinding(binding.sessionId)))
    ) {
      throw new ApplicationPlatformError("platform_state_binding_mismatch", "Platform login state is not bound to this session");
    }
    if (expectedRedirectUri !== undefined && record.redirectUri !== expectedRedirectUri) {
      throw new ApplicationPlatformError("invalid_redirect_uri", "Platform callback redirect URI is not registered");
    }
  }

  private currentTime(): number {
    const value = this.now();
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new ApplicationPlatformError("invalid_platform_state_clock", "Platform login state clock is invalid");
    }
    return value;
  }
}

function setClaimClock(expected: PlatformLoginStateClaim, now: number): void {
  PLATFORM_STATE_CLAIM_CLOCKS.set(expected, assertClockValue(now));
}

function copyClaimClock(target: PlatformLoginStateClaim, source: PlatformLoginStateClaim | undefined): void {
  if (source === undefined) return;
  const now = PLATFORM_STATE_CLAIM_CLOCKS.get(source);
  if (now !== undefined) setClaimClock(target, now);
}

function claimClock(expected: PlatformLoginStateClaim | undefined, fallback: () => number): number {
  const now = expected === undefined ? undefined : PLATFORM_STATE_CLAIM_CLOCKS.get(expected);
  return now === undefined ? assertClockValue(fallback()) : now;
}

function assertClockValue(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new ApplicationPlatformError("invalid_platform_state_clock", "Platform login state clock is invalid");
  }
  return value as number;
}

export function normalizePlatformLoginBinding(
  value: unknown,
  options: { allowMissingBrowser?: boolean } = {},
): PlatformLoginBindingValue {
  if (typeof value === "string") {
    return { browserId: assertBindingValue(value, "browser") };
  }
  if (value === undefined || value === null) {
    if (options.allowMissingBrowser === true) return {};
    throw new ApplicationPlatformError("invalid_platform_binding", "Platform login browser binding is invalid");
  }
  if (!isRecord(value)) {
    throw new ApplicationPlatformError("invalid_platform_binding", "Platform login browser binding is invalid");
  }
  const nested = value.browser ?? value.binding;
  const nestedRecord = isRecord(nested) ? nested : undefined;
  const nestedBrowser = typeof nestedRecord?.browser === "string" ? nestedRecord.browser : undefined;
  const nestedSession = typeof nestedRecord?.session === "string" ? nestedRecord.session : undefined;
  const browserValue = selectBindingValue([
    value.browserId,
    value.browserBinding,
    typeof nested === "string" ? nested : undefined,
    nestedRecord?.browserId,
    nestedRecord?.id,
    nestedBrowser,
  ], "browser");
  const browserId = browserValue === undefined
    ? undefined
    : assertBindingValue(browserValue, "browser");
  if (browserId === undefined && options.allowMissingBrowser !== true) {
    throw new ApplicationPlatformError("invalid_platform_binding", "Platform login browser binding is invalid");
  }
  const sessionId = selectBindingValue([
    value.sessionId,
    value.sessionBinding,
    typeof value.session === "string" ? value.session : undefined,
    nestedRecord?.sessionId,
    nestedSession,
  ], "session");
  return {
    ...(browserId === undefined ? {} : { browserId }),
    ...(sessionId === undefined ? {} : { sessionId }),
  };
}

export function hashPlatformLoginState(state: string): string {
  return createHash("sha256").update(assertState(state), "utf8").digest("hex");
}

export function hashPlatformLoginBinding(value: string): string {
  return createHash("sha256").update(assertBindingValue(value, "binding"), "utf8").digest("hex");
}

export const hashPlatformState = hashPlatformLoginState;
export const hashPlatformLogin = hashPlatformLoginState;

function assertStateRecord(record: PlatformLoginStateRecord): void {
  if (!isRecord(record) || record.version !== PLATFORM_LOGIN_STATE_VERSION) {
    throw new ApplicationPlatformError("invalid_platform_state", "Platform login state is invalid");
  }
  assertHash(record.stateHash, "platform_state");
  assertTenantId(record.tenantId);
  assertIdentifier(record.applicationId, "application");
  assertIdentifier(record.platformId, "platform");
  assertRedirectValue(record.redirectUri);
  if (record.bindingHash !== undefined) assertHash(record.bindingHash, "binding");
  if (record.browserBindingHash !== undefined) assertHash(record.browserBindingHash, "browser");
  if (record.sessionBindingHash !== undefined) assertHash(record.sessionBindingHash, "session");
  const client = record.client === undefined ? undefined : normalizeClient(record.client);
  const flow = record.flow === undefined ? undefined : normalizeClient(record.flow);
  if (client !== undefined && flow !== undefined && client !== flow) {
    throw new ApplicationPlatformError("invalid_platform_state", "Platform login state is invalid");
  }
  if (record.returnTo !== undefined) {
    try {
      assertPlatformLoginReturnTo(record.returnTo);
    } catch {
      throw new ApplicationPlatformError("invalid_platform_state", "Platform login state is invalid");
    }
    if ((client ?? flow ?? "web") !== "web") {
      throw new ApplicationPlatformError("invalid_platform_state", "Platform login state is invalid");
    }
  }
  const status = normalizeStateStatus(record.status);
  if (record.leaseOwner !== undefined) assertBindingValue(record.leaseOwner, "lease owner");
  if (record.leaseExpiresAt !== undefined && (!Number.isSafeInteger(record.leaseExpiresAt) || record.leaseExpiresAt < 0)) {
    throw new ApplicationPlatformError("invalid_platform_state", "Platform login state is invalid");
  }
  if (status === "leased" && (record.leaseOwner === undefined || record.leaseExpiresAt === undefined)) {
    throw new ApplicationPlatformError("invalid_platform_state", "Platform login state is invalid");
  }
  if (!Number.isSafeInteger(record.createdAt) || record.createdAt < 0) {
    throw new ApplicationPlatformError("invalid_platform_state", "Platform login state is invalid");
  }
  if (record.updatedAt !== undefined && (!Number.isSafeInteger(record.updatedAt) || record.updatedAt < record.createdAt)) {
    throw new ApplicationPlatformError("invalid_platform_state", "Platform login state is invalid");
  }
  if (record.consumedAt !== undefined && (!Number.isSafeInteger(record.consumedAt) || record.consumedAt < record.createdAt)) {
    throw new ApplicationPlatformError("invalid_platform_state", "Platform login state is invalid");
  }
  if (
    !Number.isSafeInteger(record.expiresAt) ||
    record.expiresAt <= record.createdAt ||
    record.expiresAt - record.createdAt > MAX_PLATFORM_LOGIN_STATE_TTL_MS
  ) {
    throw new ApplicationPlatformError("invalid_platform_state", "Platform login state is invalid");
  }
  if (record.scope !== undefined) assertScope(record.scope);
  if (record.requestedUserId !== undefined) assertIdentifier(record.requestedUserId, "user");
  try {
    const policy = normalizePlatformIdentityLinkingPolicy(record.linkingPolicy);
    if (policy.mode !== "link_existing" && record.requestedUserId !== undefined) {
      throw new Error("user target");
    }
  } catch {
    throw new ApplicationPlatformError("invalid_platform_state", "Platform login state is invalid");
  }
}

function assertGeneratedState(value: unknown): string {
  if (typeof value !== "string" || value.length < 32 || value.length > 512 || !/^[A-Za-z0-9_-]+$/u.test(value)) {
    throw new ApplicationPlatformError("invalid_platform_state", "Platform login state could not be generated");
  }
  return value;
}

function assertState(value: unknown): string {
  if (typeof value !== "string" || value.length < 32 || value.length > 512 || !/^[A-Za-z0-9_-]+$/u.test(value)) {
    throw new ApplicationPlatformError("invalid_platform_state", "Platform login state is invalid");
  }
  return value;
}

function assertHash(value: unknown, field: string): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/u.test(value)) {
    throw new ApplicationPlatformError("invalid_platform_state", `Platform login ${field} hash is invalid`);
  }
  return value;
}

function selectBindingValue(values: unknown[], field: string): string | undefined {
  const normalized = values
    .filter((value) => value !== undefined && value !== null)
    .map((value) => assertBindingValue(value, field));
  const unique = [...new Set(normalized)];
  if (unique.length > 1) {
    throw new ApplicationPlatformError("invalid_platform_binding", "Platform login browser binding is ambiguous");
  }
  return unique[0];
}

function assertBindingValue(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new ApplicationPlatformError("invalid_platform_binding", "Platform login browser binding is invalid");
  }
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 512 || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new ApplicationPlatformError("invalid_platform_binding", "Platform login browser binding is invalid");
  }
  return normalized;
}

function assertIdentifier(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new ApplicationPlatformError("invalid_platform_identifier", `Platform ${field} identifier is invalid`);
  }
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 256 || /[:\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new ApplicationPlatformError("invalid_platform_identifier", `Platform ${field} identifier is invalid`);
  }
  return normalized;
}

function assertRedirectValue(value: unknown): string {
  if (typeof value !== "string") {
    throw new ApplicationPlatformError("invalid_redirect_uri", "Platform callback redirect URI is invalid");
  }
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 2048 || /[\u0000-\u001f\u007f\s]/u.test(normalized)) {
    throw new ApplicationPlatformError("invalid_redirect_uri", "Platform callback redirect URI is invalid");
  }
  return normalized;
}

export function isValidPlatformLoginReturnTo(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_PLATFORM_LOGIN_RETURN_TO_LENGTH) return false;
  if (!value.startsWith("/") || value.includes("\\") || value.includes("#") || /[\u0000-\u0020\u007f-\u009f]/u.test(value)) return false;
  if (/%(?![0-9a-f]{2})/iu.test(value)) return false;
  const queryIndex = value.indexOf("?");
  const path = queryIndex === -1 ? value : value.slice(0, queryIndex);
  if (!isValidPlatformLoginReturnToPath(path)) return false;
  if (queryIndex === -1) return true;
  const query = value.slice(queryIndex + 1);
  try {
    const decoded = decodeURIComponent(query);
    return !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\\]/u.test(decoded);
  } catch {
    return false;
  }
}

function isValidPlatformLoginReturnToPath(value: string): boolean {
  if (!value.startsWith("/") || value.includes("//") || hasUnsafePlatformLoginReturnToText(value)) return false;
  let current = value;
  for (let depth = 0; hasPercentEscape(current); depth += 1) {
    if (depth >= 64) return false;
    if (hasUnsafePercentEscapeForReturnTo(current)) return false;
    const byteDecoded = decodePercentLayer(current);
    let decoded: string;
    try {
      decoded = decodeURIComponent(current);
    } catch {
      if (depth === 0) return false;
      decoded = byteDecoded;
    }
    if (decoded === current) break;
    if (hasUnsafePlatformLoginReturnToText(decoded)) return false;
    current = decoded;
  }
  return !hasUnsafePlatformLoginReturnToText(current);
}

export function validatePlatformLoginReturnTo(value: unknown): string {
  if (!isValidPlatformLoginReturnTo(value)) {
    throw new ApplicationPlatformError("invalid_return_to", "Platform login returnTo is invalid");
  }
  return value;
}

export const assertPlatformLoginReturnTo = validatePlatformLoginReturnTo;

function hasUnsafePlatformLoginReturnToText(value: string): boolean {
  return value.includes("//") || value.includes("\\") || value.includes("#") || /[\u0000-\u0020\u007f-\u009f\s]/u.test(value);
}

function hasPercentEscape(value: string): boolean {
  return /%[0-9a-f]{2}/iu.test(value);
}

function hasUnsafePercentEscapeForReturnTo(value: string): boolean {
  return /%(?:2f|5c|23|09|0a|0d|20|00|01|02|03|04|05|06|07|08|0b|0c|0e|0f|10|11|12|13|14|15|16|17|18|19|1a|1b|1c|1d|1e|1f|7f)/iu.test(value);
}

function decodePercentLayer(value: string): string {
  let output = "";
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] !== "%" || index + 2 >= value.length || !isHexDigit(value[index + 1] ?? "") || !isHexDigit(value[index + 2] ?? "")) {
      output += value[index];
      continue;
    }
    output += String.fromCharCode(Number.parseInt(value.slice(index + 1, index + 3), 16));
    index += 2;
  }
  return output;
}

function isHexDigit(value: string): boolean {
  return typeof value === "string" && value.length === 1 && /^[0-9a-f]$/iu.test(value);
}

function assertScope(value: unknown): string {
  if (typeof value !== "string") {
    throw new ApplicationPlatformError("invalid_scope", "Platform scope is invalid");
  }
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 512 || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new ApplicationPlatformError("invalid_scope", "Platform scope is invalid");
  }
  return normalized;
}

function safeHashEqual(left: string, right: string): boolean {
  if (!/^[a-f0-9]{64}$/u.test(left) || !/^[a-f0-9]{64}$/u.test(right)) return false;
  const leftBuffer = Buffer.from(left, "hex");
  const rightBuffer = Buffer.from(right, "hex");
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function cloneRecord(record: PlatformLoginStateRecord): PlatformLoginStateRecord {
  return {
    ...record,
    linkingPolicy: typeof record.linkingPolicy === "string"
      ? record.linkingPolicy
      : { ...record.linkingPolicy },
  };
}

export function normalizePlatformLoginClient(value: unknown): PlatformLoginClient {
  return normalizeClient(value);
}

function normalizeClient(value: unknown): PlatformLoginClient {
  if (value === undefined || value === null || value === "web") return "web";
  if (value === "native") return "native";
  if (value === "mp_weixin" || value === "mini_program") return "mp_weixin";
  if (value === "webview") return "webview";
  throw new ApplicationPlatformError("invalid_platform_client", "Platform login client is invalid");
}

function canConsumeStatus(record: PlatformLoginStateRecord, leaseOwner: string | undefined, now: number): boolean {
  const status = normalizeStateStatus(record.status);
  if (status === "issued") return true;
  if (leaseOwner === undefined || record.leaseOwner !== leaseOwner) return false;
  if (status === "claimed") return true;
  return status === "leased" && (record.leaseExpiresAt ?? 0) > now;
}

function matchesClaim(record: PlatformLoginStateRecord, expected: PlatformLoginStateClaim, now?: number): boolean {
  const client = normalizeClient(record.client);
  if (expected.tenantId !== undefined && record.tenantId !== expected.tenantId) return false;
  if (expected.client !== undefined && normalizeClient(expected.client) !== client) return false;
  if (expected.flow !== undefined && normalizeClient(expected.flow) !== client) return false;
  if (record.flow !== undefined && normalizeClient(record.flow) !== client) return false;
  if (expected.leaseOwner !== undefined) {
    const status = normalizeStateStatus(record.status);
    if (status === "leased" || status === "claimed") {
      if (record.leaseOwner !== expected.leaseOwner) return false;
      if (status === "leased" && now !== undefined && (record.leaseExpiresAt ?? 0) <= now) return false;
    }
  }
  if (expected.applicationId !== undefined && record.applicationId !== expected.applicationId) return false;
  if (expected.platformId !== undefined && record.platformId !== expected.platformId) return false;
  if (expected.checkBrowserBinding === true || expected.browserBindingHash !== undefined) {
    if (expected.browserBindingHash === undefined) {
      if (record.browserBindingHash !== undefined) return false;
    } else if (record.browserBindingHash === undefined || !safeHashEqual(record.browserBindingHash, expected.browserBindingHash)) {
      return false;
    }
  }
  if (expected.checkSessionBinding === true || expected.sessionBindingHash !== undefined) {
    if (expected.sessionBindingHash === undefined) {
      if (record.sessionBindingHash !== undefined) return false;
    } else if (record.sessionBindingHash === undefined || !safeHashEqual(record.sessionBindingHash, expected.sessionBindingHash)) {
      return false;
    }
  }
  if (expected.bindingHash !== undefined && (record.bindingHash === undefined || !safeHashEqual(record.bindingHash, expected.bindingHash))) return false;
  if (expected.redirectUri !== undefined && record.redirectUri !== expected.redirectUri) return false;
  return true;
}

function recordFromRow(value: unknown, fallbackTenantId = DEFAULT_PLATFORM_LOGIN_STATE_TENANT_ID): PlatformLoginStateRecord | undefined {
  if (!isRecord(value)) return undefined;
  const stateHash = stringValue(value.state_hash ?? value.stateHash);
  const tenantId = stringValue(value.tenant_id ?? value.tenantId) ?? fallbackTenantId;
  const applicationId = stringValue(value.application_id ?? value.applicationId);
  const platformId = stringValue(value.platform_id ?? value.platformId);
  const redirectUri = stringValue(value.redirect_uri ?? value.redirectUri);
  const createdAt = timestampValue(value.created_at ?? value.createdAt);
  const expiresAt = timestampValue(value.expires_at ?? value.expiresAt);
  const linkingPolicy = typeof value.linking_policy === "string"
    ? safeJsonParse(value.linking_policy)
    : value.linking_policy;
  if (
    stateHash === undefined ||
    applicationId === undefined ||
    platformId === undefined ||
    redirectUri === undefined ||
    createdAt === undefined ||
    expiresAt === undefined ||
    (!isRecord(linkingPolicy) && typeof linkingPolicy !== "string")
  ) return undefined;
  const browserBindingHash = stringValue(value.browser_binding_hash ?? value.browserBindingHash);
  const sessionBindingHash = stringValue(value.session_binding_hash ?? value.sessionBindingHash);
  const bindingHash = stringValue(value.binding_hash ?? value.bindingHash) ?? browserBindingHash ?? sessionBindingHash ?? stateHash;
  const scope = stringValue(value.scope);
  const requestedUserId = stringValue(value.requested_user_id ?? value.requestedUserId);
  const rawReturnTo = value.return_to ?? value.returnTo;
  const returnTo = rawReturnTo === undefined || rawReturnTo === null
    ? undefined
    : typeof rawReturnTo === "string"
      ? rawReturnTo
      : undefined;
  if (rawReturnTo !== undefined && rawReturnTo !== null && returnTo === undefined) return undefined;
  const flowValue = stringValue(value.flow);
  const clientValue = stringValue(value.client);
  let flow: PlatformLoginClient | undefined;
  try {
    flow = flowValue === undefined ? undefined : normalizeClient(flowValue);
    const client = clientValue === undefined ? undefined : normalizeClient(clientValue);
    if (flow !== undefined && client !== undefined && flow !== client) return undefined;
    flow ??= client;
  } catch {
    return undefined;
  }
  let status: PlatformLoginStateStatus;
  try {
    status = normalizeStateStatus(value.status);
  } catch {
    return undefined;
  }
  const effectiveClient = flow ?? "web";
  const updatedAt = timestampValue(value.updated_at ?? value.updatedAt) ?? createdAt;
  const consumedAt = timestampValue(value.consumed_at ?? value.consumedAt);
  const leaseExpiresAt = timestampValue(value.lease_expires_at ?? value.leaseExpiresAt);
  const record: PlatformLoginStateRecord = {
    version: PLATFORM_LOGIN_STATE_VERSION,
    tenantId,
    stateHash,
    applicationId,
    platformId,
    redirectUri,
    ...(returnTo === undefined ? {} : { returnTo }),
    bindingHash,
    ...(browserBindingHash === undefined ? {} : { browserBindingHash }),
    ...(sessionBindingHash === undefined ? {} : { sessionBindingHash }),
    flow: effectiveClient,
    status,
    ...(stringValue(value.lease_owner ?? value.leaseOwner) === undefined ? {} : { leaseOwner: stringValue(value.lease_owner ?? value.leaseOwner) }),
    ...(leaseExpiresAt === undefined ? {} : { leaseExpiresAt }),
    createdAt,
    updatedAt,
    ...(consumedAt === undefined ? {} : { consumedAt }),
    expiresAt,
    ...(scope === undefined ? {} : { scope }),
    linkingPolicy: linkingPolicy as PlatformIdentityLinkingPolicy,
    ...(requestedUserId === undefined ? {} : { requestedUserId }),
    client: effectiveClient,
  };
  try {
    assertStateRecord(record);
    return record;
  } catch {
    return undefined;
  }
}

function stateSelect(): string {
  return "tenant_id, state_hash, binding_hash, browser_binding_hash, session_binding_hash, application_id, platform_id, flow, status, lease_owner, lease_expires_at, expires_at, redirect_uri, scope, linking_policy, requested_user_id, created_at, updated_at, consumed_at, return_to";
}

function appendClaimClauses(
  clauses: string[],
  values: unknown[],
  expected: PlatformLoginStateClaim | undefined,
): void {
  if (expected === undefined) return;
  const add = (column: string, value: unknown): void => {
    values.push(value);
    clauses.push(`${column} = $${values.length}`);
  };
  if (expected.applicationId !== undefined) add("application_id", expected.applicationId);
  if (expected.platformId !== undefined) add("platform_id", expected.platformId);
  if (expected.checkBrowserBinding === true) {
    if (expected.browserBindingHash === undefined) clauses.push("browser_binding_hash IS NULL");
    else add("browser_binding_hash", expected.browserBindingHash);
  } else if (expected.browserBindingHash !== undefined) {
    add("browser_binding_hash", expected.browserBindingHash);
  }
  if (expected.checkSessionBinding === true) {
    if (expected.sessionBindingHash === undefined) clauses.push("session_binding_hash IS NULL");
    else add("session_binding_hash", expected.sessionBindingHash);
  } else if (expected.sessionBindingHash !== undefined) {
    add("session_binding_hash", expected.sessionBindingHash);
  }
  if (expected.bindingHash !== undefined) add("binding_hash", expected.bindingHash);
  if (expected.redirectUri !== undefined) add("redirect_uri", expected.redirectUri);
  const flow = expected.flow ?? expected.client;
  if (flow !== undefined) add("flow", flow);
}

function stateKey(tenantId: string, applicationId: string, stateHash: string): string {
  return `${assertTenantId(tenantId)}\u0000${assertIdentifier(applicationId, "application")}\u0000${assertHash(stateHash, "platform_state")}`;
}

function assertTenantId(value: unknown): string {
  if (typeof value !== "string") {
    throw new ApplicationPlatformError("invalid_platform_identifier", "Platform tenant identifier is invalid");
  }
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 256 || /[:\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new ApplicationPlatformError("invalid_platform_identifier", "Platform tenant identifier is invalid");
  }
  return normalized;
}

function normalizedLeaseDuration(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1_000 || value > MAX_PLATFORM_LOGIN_STATE_TTL_MS) {
    throw new ApplicationPlatformError("invalid_platform_state_lease", "Platform login state lease is invalid");
  }
  return value;
}

function toSqlTimestamp(value: number): string {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) {
    throw new ApplicationPlatformError("invalid_platform_state_clock", "Platform login state clock is invalid");
  }
  return date.toISOString();
}

function timestampValue(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return value;
  if (typeof value === "bigint" && value >= 0n && Number.isSafeInteger(Number(value))) return Number(value);
  if (value instanceof Date && Number.isFinite(value.getTime())) return value.getTime();
  if (typeof value === "string" && /^\d+$/u.test(value)) {
    const numeric = Number(value);
    return Number.isSafeInteger(numeric) ? numeric : undefined;
  }
  if (typeof value === "string" || typeof value === "number") {
    const timestamp = new Date(value).getTime();
    return Number.isSafeInteger(timestamp) && timestamp >= 0 ? timestamp : undefined;
  }
  return undefined;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function normalizeStateStatus(value: unknown): PlatformLoginStateStatus {
  if (value === undefined || value === null || value === "") return "issued";
  if (value === "issued" || value === "claimed" || value === "leased" || value === "consumed" || value === "expired" || value === "revoked") return value;
  throw new ApplicationPlatformError("invalid_platform_state", "Platform login state is invalid");
}

function affectedRows(value: unknown): number {
  if (isRecord(value) && typeof value.rowCount === "number") return value.rowCount;
  if (isRecord(value) && typeof value.rowCount === "bigint") return Number(value.rowCount);
  return rowsFromResult(value).length;
}

function unqualifiedStateTable(value: string): string {
  return value.split(".").at(-1) ?? value;
}

function rowsFromResult(value: unknown): unknown[] {
  if (Array.isArray(value)) return value;
  if (isRecord(value) && Array.isArray(value.rows)) return value.rows;
  return [];
}

function safeJsonParse(value: string): unknown {
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return undefined;
  }
}

function isUniqueViolation(error: unknown): boolean {
  return isRecord(error) && (error.code === "23505" || error.code === "SQLITE_CONSTRAINT");
}

function quoteStateTable(value: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 256 || !/^[a-zA-Z_][a-zA-Z0-9_.]*$/u.test(value)) {
    throw new ApplicationPlatformError("invalid_platform_state_store", "Platform login state store is invalid");
  }
  return value.split(".").map((part) => `"${part.replace(/"/gu, '""')}"`).join(".");
}

function quoteStateIndex(value: string): string {
  const parts = value.split(".");
  const name = parts.pop();
  if (name === undefined || !/^[a-zA-Z_][a-zA-Z0-9_]*$/u.test(name)) {
    throw new ApplicationPlatformError("invalid_platform_state_store", "Platform login state store is invalid");
  }
  return [...parts, name].map((part) => `"${part.replace(/"/gu, '""')}"`).join(".");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
