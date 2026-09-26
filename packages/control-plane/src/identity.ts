import { randomUUID } from "node:crypto";
import {
  DEFAULT_TENANT_COLUMN,
  createTenantSqlObjectName,
  getTenantTransactionExecutor,
  normalizeTenantConfig,
  normalizeTenantId,
  normalizeTenantMode,
  quoteTenantSqlIdentifier,
  qualifyTenantTable,
  runWithTenantTransaction,
  tenantQualifiedKey,
  validateTenantSqlIdentifier,
  type TenantConfig,
  type TenantConfigInput,
  type TenantMode,
  type TenantQualifiedKey,
  type TenantReadiness,
  type TenantSqlExecutor,
  type TenantSqlQuery,
} from "./tenant.js";

export const DEFAULT_IDENTITY_TABLE = "gb_idaas_identity";
export const DEFAULT_APPLICATION_IDENTITY_TABLE = "gb_idaas_application_external_identity";
export interface ExternalIdentityCanonicalKey {
  readonly tenantId: string;
  readonly applicationId: string;
  readonly provider: string;
  readonly platform: string;
  readonly providerAppId: string;
  readonly subject: string;
  readonly key: string;
}

export function externalIdentityCanonicalKey(input: {
  tenantId: string;
  applicationId: string;
  provider: string;
  platform?: string | null;
  providerAppId?: string | null;
  subject: string;
}): ExternalIdentityCanonicalKey {
  const tenantId = normalizeTenantId(input.tenantId);
  const applicationId = normalizeText(input.applicationId, "application id", 512);
  const provider = normalizeText(input.provider, "provider", 256);
  const platform = normalizeOptionalKeyPart(input.platform, "platform");
  const providerAppId = normalizeOptionalKeyPart(input.providerAppId, "provider app id");
  const subject = normalizeText(input.subject, "subject", 1024);
  return {
    tenantId,
    applicationId,
    provider,
    platform,
    providerAppId,
    subject,
    key: [tenantId, applicationId, provider, platform, providerAppId, subject].map((part) => encodeURIComponent(part)).join("|"),
  };
}

export const createExternalIdentityCanonicalKey = externalIdentityCanonicalKey;
export const canonicalExternalIdentityKey = externalIdentityCanonicalKey;
export const buildExternalIdentityCanonicalKey = externalIdentityCanonicalKey;

export const DEFAULT_APPLICATION_IDENTITY_COLUMNS = {
  id: "id",
  tenantId: "tenant_id",
  applicationId: "application_id",
  platformId: "platform_id",
  platform: "platform",
  provider: "provider",
  providerAppId: "provider_app_id",
  subject: "subject",
  externalAppId: "external_app_id",
  openid: "openid",
  unionid: "unionid",
  nickname: "nickname",
  displayName: "display_name",
  email: "email",
  avatarUrl: "avatar_url",
  scopes: "scopes",
  canonicalUserId: "canonical_user_id",
  linkStatus: "link_status",
  emailVerified: "email_verified",
  firstLinkedAt: "first_linked_at",
  linkedAt: "linked_at",
  lastAuthenticatedAt: "last_authenticated_at",
  version: "version",
  createdAt: "created_at",
  updatedAt: "updated_at",
} as const;

export interface ApplicationIdentitySqlColumns {
  id: string;
  tenantId: string;
  applicationId: string;
  platformId: string;
  platform: string;
  provider: string;
  providerAppId: string;
  subject: string;
  externalAppId: string;
  openid: string;
  unionid: string;
  nickname: string;
  displayName: string;
  email: string;
  avatarUrl: string;
  scopes: string;
  canonicalUserId: string;
  linkStatus: string;
  emailVerified: string;
  firstLinkedAt: string;
  linkedAt: string;
  lastAuthenticatedAt: string;
  version: string;
  createdAt: string;
  updatedAt: string;
}
export const DEFAULT_IDENTITY_COLUMNS = {
  id: "id",
  tenantId: "tenant_id",
  kind: "kind",
  provider: "provider",
  subject: "subject",
  externalId: "external_id",
  label: "label",
  metadata: "metadata",
  version: "version",
  createdAt: "created_at",
  updatedAt: "updated_at",
  disabledAt: "disabled_at",
} as const;

export type IdentityKind = "subject" | "email" | "phone" | "username" | "external" | string;

export interface IdentityRecord {
  id: string;
  tenantId: string;
  kind: IdentityKind;
  provider: string;
  subject: string;
  externalId?: string;
  label?: string | null;
  metadata?: Record<string, unknown>;
  version: number;
  createdAt?: Date | string | null;
  updatedAt?: Date | string | null;
  disabledAt?: Date | string | null;
  [key: string]: unknown;
}

export interface IdentityCreateInput {
  id?: string;
  kind: IdentityKind;
  provider: string;
  subject: string;
  externalId?: string;
  label?: string | null;
  metadata?: Record<string, unknown>;
}

export interface IdentityUpdateInput {
  kind?: IdentityKind;
  provider?: string;
  subject?: string;
  externalId?: string;
  label?: string | null;
  metadata?: Record<string, unknown>;
  version?: number;
}

export interface IdentityListQuery {
  cursor?: string;
  limit?: number;
  offset?: number;
  kind?: string;
  provider?: string;
  search?: string;
}

export interface IdentityPage {
  items: IdentityRecord[];
  nextCursor?: string;
  hasMore: boolean;
  total: number;
}

export interface IdentitySqlTableNames {
  identities: string;
  identity?: string;
}

export interface IdentitySqlColumns {
  id: string;
  tenantId: string;
  kind: string;
  provider: string;
  subject: string;
  externalId: string;
  label: string;
  metadata: string;
  version: string;
  createdAt: string;
  updatedAt: string;
  disabledAt: string;
}

export interface IdentityRepository {
  readonly tenant: TenantConfig;
  get(id: string): Promise<IdentityRecord | undefined>;
  find(subject: string, provider?: string): Promise<IdentityRecord | undefined>;
  list(query?: IdentityListQuery): Promise<IdentityPage>;
  create(input: IdentityCreateInput): Promise<IdentityRecord>;
  update(id: string, input: IdentityUpdateInput): Promise<IdentityRecord>;
  delete(id: string, version?: number): Promise<boolean>;
  isReady(): Promise<boolean>;
}

export interface IdentitySqlRepositoryOptions {
  executor?: TenantSqlExecutor;
  query?: TenantSqlQuery;
  sharedExecutor?: TenantSqlExecutor;
  dedicatedExecutor?: TenantSqlExecutor;
  fallbackExecutor?: TenantSqlExecutor;
  allowSharedFallback?: boolean;
  tenant?: TenantConfigInput;
  tenantConfig?: TenantConfigInput;
  mode?: string;
  tenantId?: string;
  tenantColumn?: string | null;
  table?: string;
  tables?: Partial<IdentitySqlTableNames>;
  tableNames?: Partial<IdentitySqlTableNames>;
  columns?: Partial<IdentitySqlColumns>;
  columnNames?: Partial<IdentitySqlColumns>;
}

export interface IdentityReadiness extends TenantReadiness {
  table: string;
}

export const IDENTITY_SQL_TABLE = DEFAULT_IDENTITY_TABLE;
export const IDENTITY_SQL_COLUMNS: IdentitySqlColumns = { ...DEFAULT_IDENTITY_COLUMNS };

export function createIdentityTableMigrationSql(
  table = DEFAULT_IDENTITY_TABLE,
  columns: Partial<IdentitySqlColumns> = {},
  tenantColumn = DEFAULT_TENANT_COLUMN,
): string {
  const normalized = normalizeColumns(columns, tenantColumn);
  const definitions = [
    `${quoteTenantSqlIdentifier(normalized.id)} TEXT NOT NULL`,
    `${quoteTenantSqlIdentifier(normalized.tenantId)} TEXT NOT NULL`,
    `${quoteTenantSqlIdentifier(normalized.kind)} TEXT NOT NULL`,
    `${quoteTenantSqlIdentifier(normalized.provider)} TEXT NOT NULL`,
    `${quoteTenantSqlIdentifier(normalized.subject)} TEXT NOT NULL`,
    `${quoteTenantSqlIdentifier(normalized.externalId)} TEXT`,
    `${quoteTenantSqlIdentifier(normalized.label)} TEXT`,
    `${quoteTenantSqlIdentifier(normalized.metadata)} JSONB NOT NULL DEFAULT '{}'::jsonb`,
    `${quoteTenantSqlIdentifier(normalized.version)} INTEGER NOT NULL DEFAULT 1`,
    `${quoteTenantSqlIdentifier(normalized.createdAt)} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `${quoteTenantSqlIdentifier(normalized.updatedAt)} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `${quoteTenantSqlIdentifier(normalized.disabledAt)} TIMESTAMPTZ`,
    `PRIMARY KEY (${quoteTenantSqlIdentifier(normalized.tenantId)}, ${quoteTenantSqlIdentifier(normalized.id)})`,
  ];
  const qualifiedTable = quoteTenantSqlIdentifier(table, "identity table");
  return [
    `CREATE TABLE IF NOT EXISTS ${qualifiedTable} (${definitions.join(", ")})`,
    ...ensureIdentityColumns(table, normalized),
    `CREATE UNIQUE INDEX IF NOT EXISTS ${quoteTenantSqlIdentifier(createTenantSqlObjectName(table, "subject_uq"))} ON ${qualifiedTable} (${quoteTenantSqlIdentifier(normalized.tenantId)}, ${quoteTenantSqlIdentifier(normalized.provider)}, ${quoteTenantSqlIdentifier(normalized.subject)})`,
    `CREATE INDEX IF NOT EXISTS ${quoteTenantSqlIdentifier(createTenantSqlObjectName(table, "query_idx"))} ON ${qualifiedTable} (${quoteTenantSqlIdentifier(normalized.tenantId)}, ${quoteTenantSqlIdentifier(normalized.kind)}, ${quoteTenantSqlIdentifier(normalized.provider)}, ${quoteTenantSqlIdentifier(normalized.id)})`,
  ].join(";\n");
}

export function createIdentityTableSql(
  table = DEFAULT_IDENTITY_TABLE,
  columns: Partial<IdentitySqlColumns> = {},
  tenantColumn = DEFAULT_TENANT_COLUMN,
): string {
  return createIdentityTableMigrationSql(table, columns, tenantColumn);
}

export function createApplicationExternalIdentityTableMigrationSql(
  table = DEFAULT_APPLICATION_IDENTITY_TABLE,
  columns: Partial<ApplicationIdentitySqlColumns> = {},
  tenantColumn = DEFAULT_TENANT_COLUMN,
): string {
  const normalized = normalizeApplicationColumns(columns, tenantColumn);
  const definitions = [
    `${quoteTenantSqlIdentifier(normalized.id)} TEXT NOT NULL`,
    `${quoteTenantSqlIdentifier(normalized.tenantId)} TEXT NOT NULL`,
    `${quoteTenantSqlIdentifier(normalized.applicationId)} TEXT NOT NULL`,
    `${quoteTenantSqlIdentifier(normalized.platformId)} TEXT`,
    `${quoteTenantSqlIdentifier(normalized.platform)} TEXT NOT NULL DEFAULT ''`,
    `${quoteTenantSqlIdentifier(normalized.provider)} TEXT NOT NULL`,
    `${quoteTenantSqlIdentifier(normalized.providerAppId)} TEXT NOT NULL DEFAULT ''`,
    `${quoteTenantSqlIdentifier(normalized.subject)} TEXT NOT NULL`,
    `${quoteTenantSqlIdentifier(normalized.externalAppId)} TEXT`,
    `${quoteTenantSqlIdentifier(normalized.openid)} TEXT`,
    `${quoteTenantSqlIdentifier(normalized.unionid)} TEXT`,
    `${quoteTenantSqlIdentifier(normalized.nickname)} TEXT`,
    `${quoteTenantSqlIdentifier(normalized.displayName)} TEXT`,
    `${quoteTenantSqlIdentifier(normalized.email)} TEXT`,
    `${quoteTenantSqlIdentifier(normalized.avatarUrl)} TEXT`,
    `${quoteTenantSqlIdentifier(normalized.scopes)} JSONB NOT NULL DEFAULT '[]'::jsonb`,
    `${quoteTenantSqlIdentifier(normalized.canonicalUserId)} TEXT`,
    `${quoteTenantSqlIdentifier(normalized.linkStatus)} TEXT NOT NULL DEFAULT 'pending'`,
    `${quoteTenantSqlIdentifier(normalized.emailVerified)} BOOLEAN NOT NULL DEFAULT FALSE`,
    `${quoteTenantSqlIdentifier(normalized.firstLinkedAt)} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `${quoteTenantSqlIdentifier(normalized.linkedAt)} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `${quoteTenantSqlIdentifier(normalized.lastAuthenticatedAt)} TIMESTAMPTZ`,
    `${quoteTenantSqlIdentifier(normalized.version)} INTEGER NOT NULL DEFAULT 1`,
    `${quoteTenantSqlIdentifier(normalized.createdAt)} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `${quoteTenantSqlIdentifier(normalized.updatedAt)} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `PRIMARY KEY (${quoteTenantSqlIdentifier(normalized.tenantId)}, ${quoteTenantSqlIdentifier(normalized.id)})`,
  ];
  const qualifiedTable = quoteTenantSqlIdentifier(table, "application identity table");
  return [
    `CREATE TABLE IF NOT EXISTS ${qualifiedTable} (${definitions.join(", ")})`,
    ...ensureApplicationIdentityColumns(table, normalized),
    `UPDATE ${qualifiedTable} SET ${quoteTenantSqlIdentifier(normalized.platform)} = COALESCE(${quoteTenantSqlIdentifier(normalized.platform)}, ${quoteTenantSqlIdentifier(normalized.platformId)}, ''), ${quoteTenantSqlIdentifier(normalized.providerAppId)} = COALESCE(${quoteTenantSqlIdentifier(normalized.providerAppId)}, ${quoteTenantSqlIdentifier(normalized.externalAppId)}, ''), ${quoteTenantSqlIdentifier(normalized.firstLinkedAt)} = COALESCE(${quoteTenantSqlIdentifier(normalized.firstLinkedAt)}, ${quoteTenantSqlIdentifier(normalized.linkedAt)}, ${quoteTenantSqlIdentifier(normalized.createdAt)}, CURRENT_TIMESTAMP) WHERE ${quoteTenantSqlIdentifier(normalized.platform)} IS NULL OR ${quoteTenantSqlIdentifier(normalized.providerAppId)} IS NULL OR ${quoteTenantSqlIdentifier(normalized.firstLinkedAt)} IS NULL`,
    `CREATE UNIQUE INDEX IF NOT EXISTS ${quoteTenantSqlIdentifier(createTenantSqlObjectName(table, "canonical_uq"))} ON ${qualifiedTable} (${quoteTenantSqlIdentifier(normalized.tenantId)}, ${quoteTenantSqlIdentifier(normalized.applicationId)}, ${quoteTenantSqlIdentifier(normalized.provider)}, ${quoteTenantSqlIdentifier(normalized.platform)}, ${quoteTenantSqlIdentifier(normalized.providerAppId)}, ${quoteTenantSqlIdentifier(normalized.subject)})`,
    `CREATE INDEX IF NOT EXISTS ${quoteTenantSqlIdentifier(createTenantSqlObjectName(table, "query_idx"))} ON ${qualifiedTable} (${quoteTenantSqlIdentifier(normalized.tenantId)}, ${quoteTenantSqlIdentifier(normalized.applicationId)}, ${quoteTenantSqlIdentifier(normalized.platformId)}, ${quoteTenantSqlIdentifier(normalized.id)})`,
  ].join(";\n");
}

export const createApplicationIdentityTableMigrationSql = createApplicationExternalIdentityTableMigrationSql;

export function ensureApplicationIdentityColumns(
  table: string,
  columns: Partial<ApplicationIdentitySqlColumns> = {},
  tenantColumn = DEFAULT_TENANT_COLUMN,
): string[] {
  const normalized = normalizeApplicationColumns(columns, tenantColumn);
  return [
    addColumn(table, normalized.id, "TEXT"),
    addColumn(table, normalized.tenantId, "TEXT"),
    addColumn(table, normalized.applicationId, "TEXT"),
    addColumn(table, normalized.platformId, "TEXT"),
    addColumn(table, normalized.platform, "TEXT DEFAULT ''"),
    addColumn(table, normalized.provider, "TEXT"),
    addColumn(table, normalized.providerAppId, "TEXT DEFAULT ''"),
    addColumn(table, normalized.subject, "TEXT"),
    addColumn(table, normalized.externalAppId, "TEXT"),
    addColumn(table, normalized.openid, "TEXT"),
    addColumn(table, normalized.unionid, "TEXT"),
    addColumn(table, normalized.nickname, "TEXT"),
    addColumn(table, normalized.displayName, "TEXT"),
    addColumn(table, normalized.email, "TEXT"),
     addColumn(table, normalized.avatarUrl, "TEXT"),
     addColumn(table, normalized.scopes, "JSONB DEFAULT '[]'::jsonb"),
     addColumn(table, normalized.canonicalUserId, "TEXT"),
     addColumn(table, normalized.linkStatus, "TEXT DEFAULT 'pending'"),
     addColumn(table, normalized.emailVerified, "BOOLEAN DEFAULT FALSE"),
     addColumn(table, normalized.firstLinkedAt, "TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP"),
    addColumn(table, normalized.linkedAt, "TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP"),
    addColumn(table, normalized.lastAuthenticatedAt, "TIMESTAMPTZ"),
    addColumn(table, normalized.version, "INTEGER DEFAULT 1"),
    addColumn(table, normalized.createdAt, "TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP"),
    addColumn(table, normalized.updatedAt, "TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP"),
  ].filter((statement): statement is string => statement !== undefined);
}

export function ensureIdentityColumns(
  table: string,
  columns: Partial<IdentitySqlColumns> = {},
  tenantColumn = DEFAULT_TENANT_COLUMN,
): string[] {
  const normalized = normalizeColumns(columns, tenantColumn);
  return [
    addColumn(table, normalized.id, "TEXT"),
    addColumn(table, normalized.tenantId, "TEXT"),
    addColumn(table, normalized.kind, "TEXT"),
    addColumn(table, normalized.provider, "TEXT"),
    addColumn(table, normalized.subject, "TEXT"),
    addColumn(table, normalized.externalId, "TEXT"),
    addColumn(table, normalized.label, "TEXT"),
    addColumn(table, normalized.metadata, "JSONB DEFAULT '{}'::jsonb"),
    addColumn(table, normalized.version, "INTEGER DEFAULT 1"),
    addColumn(table, normalized.createdAt, "TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP"),
    addColumn(table, normalized.updatedAt, "TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP"),
    addColumn(table, normalized.disabledAt, "TIMESTAMPTZ"),
  ].filter((statement): statement is string => statement !== undefined);
}

export class SqlIdentityRepository implements IdentityRepository {
  readonly tenant: TenantConfig;
  readonly table: string;
  private readonly executor: TenantSqlExecutor;
  private readonly columns: IdentitySqlColumns;
  private readonly scopedExecutors = new WeakSet<object>();

  constructor(options: IdentitySqlRepositoryOptions);
  constructor(executor: TenantSqlExecutor, options?: Omit<IdentitySqlRepositoryOptions, "executor" | "query">);
  constructor(query: TenantSqlQuery, options?: Omit<IdentitySqlRepositoryOptions, "executor" | "query">);
  constructor(input: IdentitySqlRepositoryOptions | TenantSqlExecutor | TenantSqlQuery, options?: Omit<IdentitySqlRepositoryOptions, "executor" | "query">);
  constructor(
    input: IdentitySqlRepositoryOptions | TenantSqlExecutor | TenantSqlQuery,
    second: Omit<IdentitySqlRepositoryOptions, "executor" | "query"> = {},
  ) {
    const options = normalizeOptions(input, second);
    assertNoIdentityDedicatedFallback(options);
    this.tenant = normalizeTenantConfig({
      ...(options.tenant ?? {}),
      ...(options.tenantConfig ?? {}),
      ...(options.mode === undefined ? {} : { mode: options.mode }),
      ...(options.tenantId === undefined ? {} : { tenantId: options.tenantId }),
      ...(options.tenantColumn === undefined ? {} : { tenantColumn: options.tenantColumn }),
    });
    this.executor = normalizeExecutor(options, this.tenant.mode);
    this.table = qualifyTenantTable(
      options.tables?.identities ?? options.tables?.identity ?? options.tableNames?.identities ?? options.tableNames?.identity ?? options.table ?? DEFAULT_IDENTITY_TABLE,
      this.tenant.schema,
    );
    this.columns = normalizeColumns({
      ...(options.columns ?? {}),
      ...(options.columnNames ?? {}),
    }, this.tenant.tenantColumn);
  }

  async get(id: string): Promise<IdentityRecord | undefined> {
    const resource = normalizeId(id);
    const values: unknown[] = [this.tenant.tenantId, resource];
    const rows = await this.queryRows(
      `SELECT ${this.select()} FROM ${this.qualifiedTable()} WHERE ${this.quote(this.columns.tenantId)} = $1 AND ${this.quote(this.columns.id)} = $2 AND ${this.quote(this.columns.disabledAt)} IS NULL LIMIT 1`,
      values,
    );
    return rows[0] === undefined ? undefined : this.map(rows[0]);
  }

  async find(subject: string, provider?: string): Promise<IdentityRecord | undefined> {
    const normalizedSubject = normalizeSubject(subject);
    const values: unknown[] = [this.tenant.tenantId];
    const clauses = [`${this.quote(this.columns.tenantId)} = $1`, `${this.quote(this.columns.disabledAt)} IS NULL`];
    if (provider !== undefined) {
      values.push(normalizeProvider(provider));
      clauses.push(`${this.quote(this.columns.provider)} = $${values.length}`);
    }
    values.push(normalizedSubject);
    clauses.push(`${this.quote(this.columns.subject)} = $${values.length}`);
    const rows = await this.queryRows(
      `SELECT ${this.select()} FROM ${this.qualifiedTable()} WHERE ${clauses.join(" AND ")} ORDER BY ${this.quote(this.columns.id)} ASC LIMIT 1`,
      values,
    );
    return rows[0] === undefined ? undefined : this.map(rows[0]);
  }

  async list(query: IdentityListQuery = {}): Promise<IdentityPage> {
    const limit = normalizeLimit(query.limit);
    const values: unknown[] = [this.tenant.tenantId];
    const clauses = [`${this.quote(this.columns.tenantId)} = $1`, `${this.quote(this.columns.disabledAt)} IS NULL`];
    if (query.kind !== undefined) {
      values.push(normalizeKind(query.kind));
      clauses.push(`${this.quote(this.columns.kind)} = $${values.length}`);
    }
    if (query.provider !== undefined) {
      values.push(normalizeProvider(query.provider));
      clauses.push(`${this.quote(this.columns.provider)} = $${values.length}`);
    }
    if (query.search !== undefined) {
      values.push(`%${query.search}%`);
      const parameter = `$${values.length}`;
      clauses.push(`(${[
        this.columns.id,
        this.columns.subject,
        this.columns.externalId,
        this.columns.label,
      ].map((column) => `LOWER(COALESCE(${this.quote(column)}, '')) LIKE LOWER(${parameter})`).join(" OR ")})`);
    }
    const decoded = query.cursor === undefined ? undefined : decodeIdentityCursor(query.cursor, this.tenant.tenantId);
    if (decoded !== undefined) {
      values.push(this.tenant.tenantId, decoded);
      clauses.push(`(${this.quote(this.columns.tenantId)}, ${this.quote(this.columns.id)}) > ($${values.length - 1}, $${values.length})`);
    }
    const where = ` WHERE ${clauses.join(" AND ")}`;
    const countRows = await this.queryRows(`SELECT COUNT(*)::int AS "total" FROM ${this.qualifiedTable()}${where}`, values);
    const total = readCount(countRows[0]?.total);
    const offset = query.cursor === undefined ? Math.max(0, query.offset ?? 0) : 0;
    const rows = await this.queryRows(
      `SELECT ${this.select()} FROM ${this.qualifiedTable()}${where} ORDER BY ${this.quote(this.columns.tenantId)}, ${this.quote(this.columns.id)} ASC LIMIT $${values.length + 1}${query.cursor === undefined ? ` OFFSET $${values.length + 2}` : ""}`,
      [...values, limit + 1, ...(query.cursor === undefined ? [offset] : [])],
    );
    const items = rows.slice(0, limit).map((row) => this.map(row));
    const hasMore = query.cursor === undefined ? offset + rows.length < total : rows.length > limit;
    const page: IdentityPage = { items, total, hasMore };
    if (hasMore && items.length > 0) page.nextCursor = encodeIdentityCursor(items[items.length - 1].id, this.tenant.tenantId);
    return page;
  }

  async create(input: IdentityCreateInput): Promise<IdentityRecord> {
    if (this.tenant.requireTransactions && typeof this.executor.transaction !== "function") {
      throw new Error("Tenant-scoped identity writes require a transaction");
    }
    const operation = async (): Promise<IdentityRecord> => {
      const now = new Date();
      const record: IdentityRecord = {
        id: normalizeId(input.id ?? randomUUID()),
        tenantId: this.tenant.tenantId,
        kind: normalizeKind(input.kind),
        provider: normalizeProvider(input.provider),
        subject: normalizeSubject(input.subject),
        externalId: input.externalId === undefined ? input.subject : normalizeText(input.externalId, "external id", 1024),
        label: input.label ?? null,
        metadata: input.metadata ?? {},
        version: 1,
        createdAt: now,
        updatedAt: now,
        disabledAt: null,
      };
      const fields = ["id", "tenantId", "kind", "provider", "subject", "externalId", "label", "metadata", "version", "createdAt", "updatedAt", "disabledAt"];
      const values = fields.map((field) => storageValue(field, record[field as keyof IdentityRecord]));
      const columns = fields.map((field) => this.quote(this.columns[field as keyof IdentitySqlColumns]));
      const rows = await this.queryRows(
        `INSERT INTO ${this.qualifiedTable()} (${columns.join(", ")}) VALUES (${values.map((_value, index) => `$${index + 1}`).join(", ")}) RETURNING ${this.select()}`,
        values,
      );
      if (rows[0] === undefined) return record;
      return this.map(rows[0]);
    };
    return this.runWrite(operation);
  }

  async update(id: string, input: IdentityUpdateInput): Promise<IdentityRecord> {
    if (this.tenant.requireTransactions && typeof this.executor.transaction !== "function") {
      throw new Error("Tenant-scoped identity writes require a transaction");
    }
    const operation = async (): Promise<IdentityRecord> => {
      const current = await this.get(id);
      if (current === undefined) throw new Error("Identity not found");
      const expectedVersion = input.version ?? current.version;
      const values: Record<string, unknown> = {
        kind: input.kind ?? current.kind,
        provider: input.provider ?? current.provider,
        subject: input.subject ?? current.subject,
        externalId: input.externalId === undefined ? input.subject ?? current.externalId : normalizeText(input.externalId, "external id", 1024),
        label: input.label ?? current.label,
        metadata: input.metadata ?? current.metadata,
        updatedAt: new Date(),
        version: current.version + 1,
      };
      const entries = Object.entries(values);
      const whereValues: unknown[] = [this.tenant.tenantId, normalizeId(id), expectedVersion];
      const sets = entries.map(([field, value], index) => `${this.quote(this.columns[field as keyof IdentitySqlColumns])} = $${index + 4}`);
      const where = `${this.quote(this.columns.tenantId)} = $1 AND ${this.quote(this.columns.id)} = $2 AND ${this.quote(this.columns.version)} = $3`;
      const rows = await this.queryRows(
        `UPDATE ${this.qualifiedTable()} SET ${sets.join(", ")} WHERE ${where} RETURNING ${this.select()}`,
        [...whereValues, ...entries.map(([field, value]) => storageValue(field, value))],
      );
      if (rows[0] === undefined) throw new Error("Identity version changed");
      return this.map(rows[0]);
    };
    return this.runWrite(operation);
  }

  async delete(id: string, version?: number): Promise<boolean> {
    if (this.tenant.requireTransactions && typeof this.executor.transaction !== "function") {
      throw new Error("Tenant-scoped identity writes require a transaction");
    }
    const operation = async (): Promise<boolean> => {
      const values: unknown[] = [this.tenant.tenantId, normalizeId(id)];
      let where = `${this.quote(this.columns.tenantId)} = $1 AND ${this.quote(this.columns.id)} = $2`;
      if (version !== undefined) {
        values.push(version);
        where += ` AND ${this.quote(this.columns.version)} = $3`;
      }
      const result = await this.queryAffected(`DELETE FROM ${this.qualifiedTable()} WHERE ${where}`, values);
      return result > 0;
    };
    return this.runWrite(operation);
  }

  async isReady(): Promise<boolean> {
    try {
      if (this.tenant.requireTransactions && typeof this.executor.transaction !== "function") return false;
      if (this.tenant.requireRls && typeof this.executor.transaction !== "function") return false;
      if (this.tenant.requireRls) {
        const role = await this.queryRows(`SELECT r.rolsuper AS "superuser", r.rolbypassrls AS "bypassRls" FROM pg_roles r WHERE r.rolname = current_user`, []);
        if (role[0] !== undefined && (readBoolean(role[0].superuser) || readBoolean(role[0].bypassRls))) return false;
      }
      await this.queryRows(`SELECT ${this.select()} FROM ${this.qualifiedTable()} LIMIT 0`, []);
      if (this.tenant.requireRls) {
        const rls = await this.queryRows(
          `SELECT c.relrowsecurity AS "rls", c.relforcerowsecurity AS "forceRls", EXISTS (SELECT 1 FROM pg_policies p WHERE p.schemaname = n.nspname AND p.tablename = c.relname AND p.qual IS NOT NULL AND p.with_check IS NOT NULL) AS "policy" FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = $1::regclass`,
          [this.table],
        );
        if (!readBoolean(rls[0]?.rls) || !readBoolean(rls[0]?.forceRls) || (rls[0]?.policy !== undefined && !readBoolean(rls[0]?.policy))) return false;
      }
      return true;
    } catch {
      return false;
    }
  }

  async readiness(): Promise<IdentityReadiness> {
    const ready = await this.isReady();
    return {
      ready,
      mode: this.tenant.mode,
      rls: !this.tenant.requireRls || ready,
      transactions: !this.tenant.requireTransactions || typeof this.executor.transaction === "function",
      requiredColumns: ready,
      missingColumns: ready ? [] : ["tenant isolation"],
      context: !this.tenant.requireRls || typeof this.executor.transaction === "function",
      table: this.table,
    };
  }

  tenantKey(id: string): TenantQualifiedKey {
    return tenantQualifiedKey(this.tenant.tenantId, id);
  }

  private select(): string {
    return Object.values(this.columns).map((column) => `${this.quote(column)} AS ${this.quote(column)}`).join(", ");
  }

  private qualifiedTable(): string {
    return this.quoteTenantTable();
  }

  private quoteTenantTable(): string {
    return quoteTenantSqlIdentifier(this.table, "identity table");
  }

  private quote(value: string): string {
    return quoteTenantSqlIdentifier(value, "column");
  }

  private async runWrite<T>(operation: () => Promise<T>): Promise<T> {
    if (typeof this.executor.transaction === "function") return this.withTransaction(operation);
    return operation();
  }

  async withTransaction<T>(operation: () => Promise<T>): Promise<T> {
    if (typeof this.executor.transaction !== "function") {
      throw new Error("Identity repository transaction is required");
    }
    const active = getTenantTransactionExecutor(this.executor);
    if (active !== undefined) return this.withTenantContext(operation);
    return this.executor.transaction(async (executor) => runWithTenantTransaction(this.executor, executor, () => this.withTenantContext(operation)));
  }

  async withTenantContext<T>(operation: (executor: TenantSqlExecutor) => Promise<T>): Promise<T> {
    const active = getTenantTransactionExecutor(this.executor);
    if (active !== undefined) {
      this.scopedExecutors.add(active);
      try {
        if (this.tenant.requireRls) await active.query("SELECT set_config('app.tenant_id', $1, true)", [this.tenant.tenantId]);
        return await operation(active);
      } finally {
        this.scopedExecutors.delete(active);
      }
    }
    if (!this.tenant.requireRls) return operation(this.executor);
    if (typeof this.executor.transaction !== "function") throw new Error("Tenant-scoped request context requires a transaction");
    return this.executor.transaction(async (executor) => {
      this.scopedExecutors.add(executor);
      try {
        await executor.query("SELECT set_config('app.tenant_id', $1, true)", [this.tenant.tenantId]);
        return await operation(executor);
      } finally {
        this.scopedExecutors.delete(executor);
      }
    });
  }

  private async queryRows(
    text: string,
    values: readonly unknown[],
    executor: TenantSqlExecutor = getTenantTransactionExecutor(this.executor) ?? this.executor,
  ): Promise<Record<string, unknown>[]> {
    if (this.tenant.requireRls && executor === this.executor && !this.scopedExecutors.has(executor)) {
      return this.withTenantContext((scoped) => this.queryRows(text, values, scoped));
    }
    const result = await executor.query(text, [...values]);
    const rows = resultRows(result);
    if (rows === undefined) throw new Error("Identity SQL result failed");
    return rows.filter(isRecord);
  }

  private async queryAffected(text: string, values: readonly unknown[]): Promise<number> {
    const executor = getTenantTransactionExecutor(this.executor) ?? this.executor;
    if (this.tenant.requireRls && executor === this.executor) {
      return this.withTenantContext(async (scoped) => readAffected(await scoped.query(text, [...values])));
    }
    return readAffected(await executor.query(text, [...values]));
  }

  private map(row: Record<string, unknown>): IdentityRecord {
    const id = readString(row[this.columns.id] ?? row.id ?? row[this.columns.id.toLowerCase()]);
    const kind = readString(row[this.columns.kind] ?? row.kind ?? row[this.columns.kind.toLowerCase()]);
    const provider = readString(row[this.columns.provider] ?? row.provider ?? row[this.columns.provider.toLowerCase()]);
    const subject = readString(row[this.columns.subject] ?? row.subject ?? row[this.columns.subject.toLowerCase()]);
    const tenantId = readString(row[this.columns.tenantId] ?? row.tenant_id ?? row[this.columns.tenantId.toLowerCase()]);
    if (id === undefined || kind === undefined || provider === undefined || subject === undefined || tenantId !== this.tenant.tenantId) throw new Error("Invalid identity row");
    return {
      id,
      tenantId,
      kind,
      provider,
      subject,
      externalId: readString(row[this.columns.externalId] ?? row.externalId ?? row[this.columns.externalId.toLowerCase()]) ?? subject,
      label: readString(row[this.columns.label] ?? row.label),
      metadata: readJson(row[this.columns.metadata] ?? row.metadata) ?? {},
      version: readNumber(row[this.columns.version] ?? row.version) ?? 1,
      createdAt: readDate(row[this.columns.createdAt] ?? row.createdAt),
      updatedAt: readDate(row[this.columns.updatedAt] ?? row.updatedAt),
      disabledAt: readDate(row[this.columns.disabledAt] ?? row.disabledAt),
    };
  }
}

export class InMemoryIdentityRepository implements IdentityRepository {
  readonly tenant: TenantConfig;
  private readonly records = new Map<string, IdentityRecord>();

  constructor(options: IdentitySqlRepositoryOptions & { identities?: readonly IdentityRecord[] } = {}) {
    this.tenant = normalizeTenantConfig({
      ...(options.tenant ?? {}),
      ...(options.tenantConfig ?? {}),
      ...(options.mode === undefined ? {} : { mode: options.mode }),
      ...(options.tenantId === undefined ? {} : { tenantId: options.tenantId }),
      ...(options.tenantColumn === undefined ? {} : { tenantColumn: options.tenantColumn }),
    });
    for (const identity of options.identities ?? []) {
      if (identity.tenantId !== undefined && identity.tenantId !== this.tenant.tenantId) continue;
      this.records.set(this.key(identity.id), { ...identity, tenantId: this.tenant.tenantId, metadata: { ...(identity.metadata ?? {}) } });
    }
  }

  async get(id: string): Promise<IdentityRecord | undefined> {
    const value = this.records.get(this.key(id));
    return value === undefined || value.disabledAt !== undefined && value.disabledAt !== null
      ? undefined
      : { ...value, metadata: { ...(value.metadata ?? {}) } };
  }

  async find(subject: string, provider?: string): Promise<IdentityRecord | undefined> {
    const normalizedSubject = normalizeSubject(subject);
    const normalizedProvider = provider === undefined ? undefined : normalizeProvider(provider);
    const value = [...this.records.values()].find((item) =>
      (item.disabledAt === undefined || item.disabledAt === null) &&
      item.subject === normalizedSubject &&
      (normalizedProvider === undefined || item.provider === normalizedProvider),
    );
    return value === undefined ? undefined : { ...value, metadata: { ...(value.metadata ?? {}) } };
  }

  async list(query: IdentityListQuery = {}): Promise<IdentityPage> {
    const limit = normalizeLimit(query.limit);
    const values = [...this.records.values()]
      .filter((item) => item.tenantId === this.tenant.tenantId)
      .filter((item) => item.disabledAt === undefined || item.disabledAt === null)
      .filter((item) => query.kind === undefined || item.kind === normalizeKind(query.kind))
      .filter((item) => query.provider === undefined || item.provider === normalizeProvider(query.provider))
      .filter((item) => query.search === undefined || [item.id, item.subject, item.label].some((field) => typeof field === "string" && field.toLowerCase().includes(query.search!.toLowerCase())))
      .sort((left, right) => left.id.localeCompare(right.id));
    const cursor = query.cursor === undefined ? undefined : decodeIdentityCursor(query.cursor, this.tenant.tenantId);
    const filtered = cursor === undefined ? values : values.filter((item) => item.id > cursor);
    const offset = query.cursor === undefined ? Math.max(0, query.offset ?? 0) : 0;
    const items = filtered.slice(offset, offset + limit).map((item) => ({ ...item, metadata: { ...(item.metadata ?? {}) } }));
    const hasMore = offset + items.length < filtered.length;
    return {
      items,
      total: filtered.length,
      hasMore,
      ...(hasMore && items.length > 0 ? { nextCursor: encodeIdentityCursor(items[items.length - 1].id, this.tenant.tenantId) } : {}),
    };
  }

  async create(input: IdentityCreateInput): Promise<IdentityRecord> {
    const now = new Date();
    const record: IdentityRecord = {
      id: normalizeId(input.id ?? randomUUID()),
      tenantId: this.tenant.tenantId,
      kind: normalizeKind(input.kind),
      provider: normalizeProvider(input.provider),
      subject: normalizeSubject(input.subject),
      externalId: input.externalId === undefined ? input.subject : normalizeText(input.externalId, "external id", 1024),
      label: input.label ?? null,
      metadata: { ...(input.metadata ?? {}) },
      version: 1,
      createdAt: now,
      updatedAt: now,
      disabledAt: null,
    };
    if ([...this.records.values()].some((item) => item.provider === record.provider && item.subject === record.subject && (item.disabledAt === undefined || item.disabledAt === null))) {
      throw new Error("Identity already exists");
    }
    this.records.set(this.key(record.id), record);
    return { ...record, metadata: { ...(record.metadata ?? {}) } };
  }

  async update(id: string, input: IdentityUpdateInput): Promise<IdentityRecord> {
    const current = this.records.get(this.key(id));
    if (current === undefined) throw new Error("Identity not found");
    if (input.version !== undefined && input.version !== current.version) throw new Error("Identity version changed");
    const updated: IdentityRecord = {
      ...current,
      kind: input.kind ?? current.kind,
      provider: input.provider ?? current.provider,
      subject: input.subject ?? current.subject,
      externalId: input.externalId === undefined ? input.subject ?? current.externalId : normalizeText(input.externalId, "external id", 1024),
      label: input.label ?? current.label,
      metadata: input.metadata ?? current.metadata,
      version: current.version + 1,
      updatedAt: new Date(),
    };
    if ([...this.records.values()].some((item) => item.id !== current.id && item.provider === updated.provider && item.subject === updated.subject && (item.disabledAt === undefined || item.disabledAt === null))) {
      throw new Error("Identity already exists");
    }
    this.records.set(this.key(id), updated);
    return { ...updated, metadata: { ...(updated.metadata ?? {}) } };
  }

  async delete(id: string, version?: number): Promise<boolean> {
    const current = this.records.get(this.key(id));
    if (current === undefined || (version !== undefined && current.version !== version)) return false;
    return this.records.delete(this.key(id));
  }

  async isReady(): Promise<boolean> {
    return true;
  }

  private key(id: string): string {
    return tenantQualifiedKey(this.tenant.tenantId, id).key;
  }
}

export function createIdentityRepository(
  input: IdentitySqlRepositoryOptions | TenantSqlExecutor | TenantSqlQuery,
  options: Omit<IdentitySqlRepositoryOptions, "executor" | "query"> = {},
): SqlIdentityRepository {
  return new SqlIdentityRepository(input as IdentitySqlRepositoryOptions, options);
}

function hasIdentityRepositoryOptions(value: object): boolean {
  return ["tenantId", "tenant", "tenantConfig", "mode", "tenantColumn", "table", "tables", "tableNames", "columns", "columnNames", "sharedExecutor", "dedicatedExecutor", "fallbackExecutor", "allowSharedFallback"].some((key) => Object.prototype.hasOwnProperty.call(value, key));
}

function assertNoIdentityDedicatedFallback(options: IdentitySqlRepositoryOptions): void {
  const mode = normalizeTenantMode(options.tenant?.mode ?? options.tenantConfig?.mode ?? options.mode);
  if (mode === "dedicated" && (options.allowSharedFallback === true || options.sharedExecutor !== undefined || options.fallbackExecutor !== undefined)) {
    throw new TypeError("Dedicated tenant mode cannot use a shared pool fallback");
  }
}

function normalizeOptions(
  input: IdentitySqlRepositoryOptions | TenantSqlExecutor | TenantSqlQuery,
  second: Omit<IdentitySqlRepositoryOptions, "executor" | "query">,
): IdentitySqlRepositoryOptions {
  if (typeof input === "function") return { ...second, query: input };
  if (isExecutor(input) && !hasIdentityRepositoryOptions(input)) return { ...second, executor: input };
  return { ...input, ...second };
}

function normalizeExecutor(options: IdentitySqlRepositoryOptions, mode: TenantMode): TenantSqlExecutor {
  if (options.executor && typeof options.executor.query === "function") return options.executor;
  if (typeof options.query === "function") return { query: options.query };
  if (mode === "shared" && options.sharedExecutor && typeof options.sharedExecutor.query === "function") return options.sharedExecutor;
  if (mode === "dedicated" && options.dedicatedExecutor && typeof options.dedicatedExecutor.query === "function") return options.dedicatedExecutor;
  throw new TypeError("An identity SQL query executor is required");
}

function normalizeApplicationColumns(columns: Partial<ApplicationIdentitySqlColumns>, tenantColumn: string): ApplicationIdentitySqlColumns {
  const source = { ...DEFAULT_APPLICATION_IDENTITY_COLUMNS, ...columns, tenantId: columns.tenantId ?? tenantColumn };
  return {
    id: validateTenantSqlIdentifier(source.id, "application identity id column"),
    tenantId: validateTenantSqlIdentifier(source.tenantId, "application identity tenant column"),
    applicationId: validateTenantSqlIdentifier(source.applicationId, "application identity application column"),
    platformId: validateTenantSqlIdentifier(source.platformId, "application identity platform column"),
    platform: validateTenantSqlIdentifier(source.platform, "application identity platform type column"),
    provider: validateTenantSqlIdentifier(source.provider, "application identity provider column"),
    providerAppId: validateTenantSqlIdentifier(source.providerAppId, "application identity provider app column"),
    subject: validateTenantSqlIdentifier(source.subject, "application identity subject column"),
    externalAppId: validateTenantSqlIdentifier(source.externalAppId, "application identity external app column"),
    openid: validateTenantSqlIdentifier(source.openid, "application identity openid column"),
    unionid: validateTenantSqlIdentifier(source.unionid, "application identity unionid column"),
    nickname: validateTenantSqlIdentifier(source.nickname, "application identity nickname column"),
    displayName: validateTenantSqlIdentifier(source.displayName, "application identity display name column"),
    email: validateTenantSqlIdentifier(source.email, "application identity email column"),
     avatarUrl: validateTenantSqlIdentifier(source.avatarUrl, "application identity avatar column"),
     scopes: validateTenantSqlIdentifier(source.scopes, "application identity scopes column"),
     canonicalUserId: validateTenantSqlIdentifier(source.canonicalUserId, "application identity canonical user column"),
     linkStatus: validateTenantSqlIdentifier(source.linkStatus, "application identity link status column"),
     emailVerified: validateTenantSqlIdentifier(source.emailVerified, "application identity email verification column"),
     firstLinkedAt: validateTenantSqlIdentifier(source.firstLinkedAt, "application identity first linked at column"),
    linkedAt: validateTenantSqlIdentifier(source.linkedAt, "application identity linked at column"),
    lastAuthenticatedAt: validateTenantSqlIdentifier(source.lastAuthenticatedAt, "application identity last authenticated column"),
    version: validateTenantSqlIdentifier(source.version, "application identity version column"),
    createdAt: validateTenantSqlIdentifier(source.createdAt, "application identity created at column"),
    updatedAt: validateTenantSqlIdentifier(source.updatedAt, "application identity updated at column"),
  };
}

function normalizeColumns(columns: Partial<IdentitySqlColumns>, tenantColumn: string): IdentitySqlColumns {
  const source = { ...DEFAULT_IDENTITY_COLUMNS, ...columns, tenantId: columns.tenantId ?? tenantColumn };
  return {
    id: validateTenantSqlIdentifier(source.id, "identity id column"),
    tenantId: validateTenantSqlIdentifier(source.tenantId, "identity tenant column"),
    kind: validateTenantSqlIdentifier(source.kind, "identity kind column"),
    provider: validateTenantSqlIdentifier(source.provider, "identity provider column"),
    subject: validateTenantSqlIdentifier(source.subject, "identity subject column"),
    externalId: validateTenantSqlIdentifier(source.externalId, "identity external id column"),
    label: validateTenantSqlIdentifier(source.label, "identity label column"),
    metadata: validateTenantSqlIdentifier(source.metadata, "identity metadata column"),
    version: validateTenantSqlIdentifier(source.version, "identity version column"),
    createdAt: validateTenantSqlIdentifier(source.createdAt, "identity created_at column"),
    updatedAt: validateTenantSqlIdentifier(source.updatedAt, "identity updated_at column"),
    disabledAt: validateTenantSqlIdentifier(source.disabledAt, "identity disabled_at column"),
  };
}

function addColumn(table: string, column: string, definition: string): string | undefined {
  if (!column) return undefined;
  return `ALTER TABLE ${quoteTenantSqlIdentifier(table)} ADD COLUMN IF NOT EXISTS ${quoteTenantSqlIdentifier(column)} ${definition}`;
}

function normalizeId(value: unknown): string {
  return normalizeText(value, "identity id", 512);
}

function normalizeKind(value: unknown): string {
  return normalizeText(value, "identity kind", 128);
}

function normalizeProvider(value: unknown): string {
  return normalizeText(value, "identity provider", 256);
}

function normalizeSubject(value: unknown): string {
  return normalizeText(value, "identity subject", 1024);
}

function normalizeOptionalKeyPart(value: unknown, field: string): string {
  if (value === undefined || value === null || value === "") return "";
  return normalizeText(value, field, 512);
}

function normalizeText(value: unknown, field: string, max: number): string {
  if (typeof value !== "string") throw new TypeError(`${field} must be a string`);
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > max || /[\u0000-\u001f\u007f]/u.test(normalized)) throw new TypeError(`Invalid ${field}`);
  return normalized;
}

function normalizeLimit(value: unknown): number {
  if (value === undefined) return 20;
  const normalized = typeof value === "number" ? value : Number(value);
  if (!Number.isSafeInteger(normalized) || normalized < 1 || normalized > 100) throw new TypeError("Invalid identity page limit");
  return normalized;
}

function storageValue(field: string, value: unknown): unknown {
  if (field === "metadata") return JSON.stringify(value ?? {});
  return value;
}

function encodeIdentityCursor(id: string, tenantId: string): string {
  return Buffer.from(JSON.stringify({ version: 1, tenantId, id }), "utf8").toString("base64url");
}

function decodeIdentityCursor(value: string, tenantId: string): string {
  try {
    const parsed = JSON.parse(Buffer.from(value, "base64url").toString("utf8")) as { version?: unknown; tenantId?: unknown; id?: unknown };
    if (parsed.version !== 1 || parsed.tenantId !== tenantId || typeof parsed.id !== "string") throw new Error("invalid cursor");
    return normalizeId(parsed.id);
  } catch {
    throw new TypeError("Invalid identity pagination cursor");
  }
}

function resultRows(value: unknown): unknown[] | undefined {
  if (Array.isArray(value)) return value;
  if (!isRecord(value)) return undefined;
  return Array.isArray(value.rows) ? value.rows : undefined;
}

function isExecutor(value: unknown): value is TenantSqlExecutor {
  return isRecord(value) && typeof value.query === "function";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function readNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isSafeInteger(value)) return value;
  if (typeof value === "bigint" && value >= 0n && Number.isSafeInteger(Number(value))) return Number(value);
  if (typeof value === "string" && /^\d+$/u.test(value)) {
    const parsed = Number(value);
    return Number.isSafeInteger(parsed) ? parsed : undefined;
  }
  return undefined;
}

function readBoolean(value: unknown): boolean {
  return value === true || value === "true" || value === 1 || value === "1";
}

function readCount(value: unknown): number {
  return readNumber(value) ?? 0;
}

function readAffected(value: unknown): number {
  if (isRecord(value) && typeof value.rowCount === "number") return value.rowCount;
  if (isRecord(value) && typeof value.rowCount === "bigint") return Number(value.rowCount);
  return resultRows(value)?.length ?? 0;
}

function readJson(value: unknown): Record<string, unknown> | undefined {
  if (isRecord(value)) return value;
  if (typeof value !== "string" || value.length === 0) return undefined;
  try {
    const parsed: unknown = JSON.parse(value);
    return isRecord(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function readDate(value: unknown): Date | string | undefined {
  if (value instanceof Date && !Number.isNaN(value.getTime())) return new Date(value.getTime());
  if (typeof value === "string" && value.length <= 128 && !Number.isNaN(new Date(value).getTime())) return value;
  return undefined;
}
