import { randomUUID } from "node:crypto";
import {
  DEFAULT_TENANT_COLUMN,
  createTenantSqlObjectName,
  getTenantTransactionExecutor,
  normalizeTenantConfig,
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

export const DEFAULT_SECRET_BINDING_TABLE = "gb_idaas_secret_binding";
export const DEFAULT_SECRET_BINDING_COLUMNS = {
  id: "id",
  tenantId: "tenant_id",
  subjectType: "subject_type",
  subjectId: "subject_id",
  purpose: "purpose",
  version: "version",
  secretRef: "secret_ref",
  status: "status",
  gracePeriodSeconds: "grace_period_seconds",
  validFrom: "valid_from",
  graceUntil: "grace_until",
  supersededAt: "superseded_at",
  revokedAt: "revoked_at",
  createdAt: "created_at",
  updatedAt: "updated_at",
} as const;

export type SecretBindingStatus = "active" | "retiring" | "revoked";

export interface SecretBindingRecord {
  id: string;
  tenantId: string;
  subjectType: string;
  subjectId: string;
  purpose: string;
  version: number;
  secretRef: string;
  status: SecretBindingStatus;
  gracePeriodSeconds: number;
  validFrom: Date | string;
  graceUntil?: Date | string | null;
  supersededAt?: Date | string | null;
  revokedAt?: Date | string | null;
  createdAt: Date | string;
  updatedAt: Date | string;
  [key: string]: unknown;
}

export interface SecretBindingCreateInput {
  id?: string;
  subjectType: string;
  subjectId: string;
  purpose: string;
  secretRef: string;
  gracePeriodSeconds?: number;
  validFrom?: Date | string;
}

export interface SecretBindingRotateInput {
  secretRef: string;
  gracePeriodSeconds?: number;
  validFrom?: Date | string;
  expectedVersion?: number;
}

export interface SecretBindingListQuery {
  cursor?: string;
  limit?: number;
  offset?: number;
  subjectType?: string;
  subjectId?: string;
  purpose?: string;
  status?: SecretBindingStatus | string;
}

export interface SecretBindingPage {
  items: SecretBindingRecord[];
  nextCursor?: string;
  hasMore: boolean;
  total: number;
}

export interface SecretBindingResolution {
  binding: SecretBindingRecord;
  usedGracePeriod: boolean;
}

export interface SecretBindingSqlTableNames {
  secretBindings: string;
  secretBinding?: string;
}

export interface SecretBindingSqlColumns {
  id: string;
  tenantId: string;
  subjectType: string;
  subjectId: string;
  purpose: string;
  version: string;
  secretRef: string;
  status: string;
  gracePeriodSeconds: string;
  validFrom: string;
  graceUntil: string;
  supersededAt: string;
  revokedAt: string;
  createdAt: string;
  updatedAt: string;
}

export interface SecretBindingRepository {
  readonly tenant: TenantConfig;
  get(id: string): Promise<SecretBindingRecord | undefined>;
  getVersion(subjectType: string, subjectId: string, purpose: string, version: number): Promise<SecretBindingRecord | undefined>;
  findActive(subjectType: string, subjectId: string, purpose: string): Promise<SecretBindingRecord | undefined>;
  resolve(subjectType: string, subjectId: string, purpose: string, at?: Date): Promise<SecretBindingResolution | undefined>;
  resolveSecret?(subjectType: string, subjectId: string, purpose: string, at?: Date): Promise<string | undefined>;
  list(query?: SecretBindingListQuery): Promise<SecretBindingPage>;
  create(input: SecretBindingCreateInput): Promise<SecretBindingRecord>;
  rotate(subjectType: string, subjectId: string, purpose: string, input: SecretBindingRotateInput): Promise<SecretBindingRecord>;
  revoke(id: string, version?: number): Promise<SecretBindingRecord>;
  revokeSubject?(subjectType: string, subjectId: string, purpose: string): Promise<SecretBindingRecord[]>;
  isReady(): Promise<boolean>;
}

export interface SecretBindingSqlRepositoryOptions {
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
  tables?: Partial<SecretBindingSqlTableNames>;
  tableNames?: Partial<SecretBindingSqlTableNames>;
  columns?: Partial<SecretBindingSqlColumns>;
  columnNames?: Partial<SecretBindingSqlColumns>;
}

export interface SecretBindingReadiness extends TenantReadiness {
  table: string;
}

export const SECRET_BINDING_SQL_TABLE = DEFAULT_SECRET_BINDING_TABLE;
export const SECRET_BINDING_SQL_COLUMNS: SecretBindingSqlColumns = { ...DEFAULT_SECRET_BINDING_COLUMNS };

export function createSecretBindingTableMigrationSql(
  table = DEFAULT_SECRET_BINDING_TABLE,
  columns: Partial<SecretBindingSqlColumns> = {},
  tenantColumn = DEFAULT_TENANT_COLUMN,
): string {
  const normalized = normalizeColumns(columns, tenantColumn);
  const definitions = [
    `${quoteTenantSqlIdentifier(normalized.id)} TEXT NOT NULL`,
    `${quoteTenantSqlIdentifier(normalized.tenantId)} TEXT NOT NULL`,
    `${quoteTenantSqlIdentifier(normalized.subjectType)} TEXT NOT NULL`,
    `${quoteTenantSqlIdentifier(normalized.subjectId)} TEXT NOT NULL`,
    `${quoteTenantSqlIdentifier(normalized.purpose)} TEXT NOT NULL`,
    `${quoteTenantSqlIdentifier(normalized.version)} INTEGER NOT NULL CHECK (${quoteTenantSqlIdentifier(normalized.version)} > 0)`,
    `${quoteTenantSqlIdentifier(normalized.secretRef)} TEXT NOT NULL`,
    `${quoteTenantSqlIdentifier(normalized.status)} TEXT NOT NULL DEFAULT 'active' CHECK (${quoteTenantSqlIdentifier(normalized.status)} IN ('active', 'retiring', 'revoked'))`,
    `${quoteTenantSqlIdentifier(normalized.gracePeriodSeconds)} INTEGER NOT NULL DEFAULT 0 CHECK (${quoteTenantSqlIdentifier(normalized.gracePeriodSeconds)} >= 0)`,
    `${quoteTenantSqlIdentifier(normalized.validFrom)} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `${quoteTenantSqlIdentifier(normalized.graceUntil)} TIMESTAMPTZ`,
    `${quoteTenantSqlIdentifier(normalized.supersededAt)} TIMESTAMPTZ`,
    `${quoteTenantSqlIdentifier(normalized.revokedAt)} TIMESTAMPTZ`,
    `${quoteTenantSqlIdentifier(normalized.createdAt)} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `${quoteTenantSqlIdentifier(normalized.updatedAt)} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `PRIMARY KEY (${quoteTenantSqlIdentifier(normalized.tenantId)}, ${quoteTenantSqlIdentifier(normalized.id)})`,
  ];
  const qualifiedTable = quoteTenantSqlIdentifier(table, "secret binding table");
  return [
    `CREATE TABLE IF NOT EXISTS ${qualifiedTable} (${definitions.join(", ")})`,
    ...ensureSecretBindingColumns(table, normalized),
    `CREATE UNIQUE INDEX IF NOT EXISTS ${quoteTenantSqlIdentifier(createTenantSqlObjectName(table, "version_uq"))} ON ${qualifiedTable} (${quoteTenantSqlIdentifier(normalized.tenantId)}, ${quoteTenantSqlIdentifier(normalized.subjectType)}, ${quoteTenantSqlIdentifier(normalized.subjectId)}, ${quoteTenantSqlIdentifier(normalized.purpose)}, ${quoteTenantSqlIdentifier(normalized.version)})`,
    `CREATE UNIQUE INDEX IF NOT EXISTS ${quoteTenantSqlIdentifier(createTenantSqlObjectName(table, "active_uq"))} ON ${qualifiedTable} (${quoteTenantSqlIdentifier(normalized.tenantId)}, ${quoteTenantSqlIdentifier(normalized.subjectType)}, ${quoteTenantSqlIdentifier(normalized.subjectId)}, ${quoteTenantSqlIdentifier(normalized.purpose)}) WHERE ${quoteTenantSqlIdentifier(normalized.status)} = 'active'`,
    `CREATE INDEX IF NOT EXISTS ${quoteTenantSqlIdentifier(createTenantSqlObjectName(table, "resolve_idx"))} ON ${qualifiedTable} (${quoteTenantSqlIdentifier(normalized.tenantId)}, ${quoteTenantSqlIdentifier(normalized.subjectType)}, ${quoteTenantSqlIdentifier(normalized.subjectId)}, ${quoteTenantSqlIdentifier(normalized.purpose)}, ${quoteTenantSqlIdentifier(normalized.status)}, ${quoteTenantSqlIdentifier(normalized.version)} DESC)`,
  ].join(";\n");
}

export function createSecretBindingTableSql(
  table = DEFAULT_SECRET_BINDING_TABLE,
  columns: Partial<SecretBindingSqlColumns> = {},
  tenantColumn = DEFAULT_TENANT_COLUMN,
): string {
  return createSecretBindingTableMigrationSql(table, columns, tenantColumn);
}

export function ensureSecretBindingColumns(
  table: string,
  columns: Partial<SecretBindingSqlColumns> = {},
  tenantColumn = DEFAULT_TENANT_COLUMN,
): string[] {
  const normalized = normalizeColumns(columns, tenantColumn);
  return [
    addColumn(table, normalized.id, "TEXT"),
    addColumn(table, normalized.tenantId, "TEXT"),
    addColumn(table, normalized.subjectType, "TEXT"),
    addColumn(table, normalized.subjectId, "TEXT"),
    addColumn(table, normalized.purpose, "TEXT"),
    addColumn(table, normalized.version, "INTEGER DEFAULT 1"),
    addColumn(table, normalized.secretRef, "TEXT"),
    addColumn(table, normalized.status, "TEXT DEFAULT 'active'"),
    addColumn(table, normalized.gracePeriodSeconds, "INTEGER DEFAULT 0"),
    addColumn(table, normalized.validFrom, "TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP"),
    addColumn(table, normalized.graceUntil, "TIMESTAMPTZ"),
    addColumn(table, normalized.supersededAt, "TIMESTAMPTZ"),
    addColumn(table, normalized.revokedAt, "TIMESTAMPTZ"),
    addColumn(table, normalized.createdAt, "TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP"),
    addColumn(table, normalized.updatedAt, "TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP"),
  ].filter((statement): statement is string => statement !== undefined);
}

export function isSecretBindingUsable(binding: SecretBindingRecord, at = new Date()): boolean {
  const timestamp = dateValue(at);
  if (binding.status !== "active" && binding.status !== "retiring") return false;
  if (binding.status === "retiring") {
    if (binding.graceUntil === undefined || binding.graceUntil === null) return false;
    const grace = dateValue(binding.graceUntil);
    if (!Number.isFinite(grace) || grace <= timestamp) return false;
  }
  const validFrom = dateValue(binding.validFrom);
  if (!Number.isFinite(validFrom) || validFrom > timestamp) return false;
  return true;
}

export const isSecretBindingWithinGracePeriod = isSecretBindingUsable;

export class SqlSecretBindingRepository implements SecretBindingRepository {
  readonly tenant: TenantConfig;
  readonly table: string;
  private readonly executor: TenantSqlExecutor;
  private readonly columns: SecretBindingSqlColumns;
  private readonly scopedExecutors = new WeakSet<object>();

  constructor(options: SecretBindingSqlRepositoryOptions);
  constructor(executor: TenantSqlExecutor, options?: Omit<SecretBindingSqlRepositoryOptions, "executor" | "query">);
  constructor(query: TenantSqlQuery, options?: Omit<SecretBindingSqlRepositoryOptions, "executor" | "query">);
  constructor(input: SecretBindingSqlRepositoryOptions | TenantSqlExecutor | TenantSqlQuery, options?: Omit<SecretBindingSqlRepositoryOptions, "executor" | "query">);
  constructor(
    input: SecretBindingSqlRepositoryOptions | TenantSqlExecutor | TenantSqlQuery,
    second: Omit<SecretBindingSqlRepositoryOptions, "executor" | "query"> = {},
  ) {
    const options = normalizeOptions(input, second);
    assertNoSecretDedicatedFallback(options);
    this.tenant = normalizeTenantConfig({
      ...(options.tenant ?? {}),
      ...(options.tenantConfig ?? {}),
      ...(options.mode === undefined ? {} : { mode: options.mode }),
      ...(options.tenantId === undefined ? {} : { tenantId: options.tenantId }),
      ...(options.tenantColumn === undefined ? {} : { tenantColumn: options.tenantColumn }),
    });
    this.executor = normalizeExecutor(options, this.tenant.mode);
    this.table = qualifyTenantTable(
      options.tables?.secretBindings ?? options.tables?.secretBinding ?? options.tableNames?.secretBindings ?? options.tableNames?.secretBinding ?? options.table ?? DEFAULT_SECRET_BINDING_TABLE,
      this.tenant.schema,
    );
    this.columns = normalizeColumns({
      ...DEFAULT_SECRET_BINDING_COLUMNS,
      ...(options.columns ?? {}),
      ...(options.columnNames ?? {}),
    }, this.tenant.tenantColumn);
  }

  async get(id: string): Promise<SecretBindingRecord | undefined> {
    const values: unknown[] = [this.tenant.tenantId, normalizeId(id)];
    const rows = await this.queryRows(
      `SELECT ${this.select()} FROM ${this.qualifiedTable()} WHERE ${this.quote(this.columns.tenantId)} = $1 AND ${this.quote(this.columns.id)} = $2 LIMIT 1`,
      values,
    );
    return rows[0] === undefined ? undefined : this.map(rows[0]);
  }

  async findActive(subjectType: string, subjectId: string, purpose: string): Promise<SecretBindingRecord | undefined> {
    const values: unknown[] = [this.tenant.tenantId, normalizeText(subjectType, "subject type", 128), normalizeText(subjectId, "subject id", 512), normalizeText(purpose, "purpose", 128)];
    const rows = await this.queryRows(
      `SELECT ${this.select()} FROM ${this.qualifiedTable()} WHERE ${this.quote(this.columns.tenantId)} = $1 AND ${this.quote(this.columns.subjectType)} = $2 AND ${this.quote(this.columns.subjectId)} = $3 AND ${this.quote(this.columns.purpose)} = $4 AND ${this.quote(this.columns.status)} IN ('active', 'retiring') ORDER BY CASE ${this.quote(this.columns.status)} WHEN 'active' THEN 0 ELSE 1 END, ${this.quote(this.columns.version)} DESC LIMIT 1`,
      values,
    );
    return rows[0] === undefined ? undefined : this.map(rows[0]);
  }

  async getVersion(subjectType: string, subjectId: string, purpose: string, version: number): Promise<SecretBindingRecord | undefined> {
    const values: unknown[] = [this.tenant.tenantId, normalizeText(subjectType, "subject type", 128), normalizeText(subjectId, "subject id", 512), normalizeText(purpose, "purpose", 128), normalizeVersion(version)];
    const rows = await this.queryRows(
      `SELECT ${this.select()} FROM ${this.qualifiedTable()} WHERE ${this.quote(this.columns.tenantId)} = $1 AND ${this.quote(this.columns.subjectType)} = $2 AND ${this.quote(this.columns.subjectId)} = $3 AND ${this.quote(this.columns.purpose)} = $4 AND ${this.quote(this.columns.version)} = $5 LIMIT 1`,
      values,
    );
    return rows[0] === undefined ? undefined : this.map(rows[0]);
  }

  async resolve(subjectType: string, subjectId: string, purpose: string, at = new Date()): Promise<SecretBindingResolution | undefined> {
    const values: unknown[] = [this.tenant.tenantId, normalizeText(subjectType, "subject type", 128), normalizeText(subjectId, "subject id", 512), normalizeText(purpose, "purpose", 128)];
    const rows = await this.queryRows(
      `SELECT ${this.select()} FROM ${this.qualifiedTable()} WHERE ${this.quote(this.columns.tenantId)} = $1 AND ${this.quote(this.columns.subjectType)} = $2 AND ${this.quote(this.columns.subjectId)} = $3 AND ${this.quote(this.columns.purpose)} = $4 AND ${this.quote(this.columns.status)} IN ('active', 'retiring') ORDER BY CASE ${this.quote(this.columns.status)} WHEN 'active' THEN 0 ELSE 1 END, ${this.quote(this.columns.version)} DESC`,
      values,
    );
    for (const row of rows) {
      const binding = this.map(row);
      if (isSecretBindingUsable(binding, at)) return { binding, usedGracePeriod: binding.status === "retiring" };
    }
    return undefined;
  }

  async resolveSecret(subjectType: string, subjectId: string, purpose: string, at = new Date()): Promise<string | undefined> {
    return (await this.resolve(subjectType, subjectId, purpose, at))?.binding.secretRef;
  }

  async list(query: SecretBindingListQuery = {}): Promise<SecretBindingPage> {
    const limit = normalizeLimit(query.limit);
    const values: unknown[] = [this.tenant.tenantId];
    const clauses = [`${this.quote(this.columns.tenantId)} = $1`];
    const add = (column: string, value: unknown): void => {
      values.push(value);
      clauses.push(`${this.quote(column)} = $${values.length}`);
    };
    if (query.subjectType !== undefined) add(this.columns.subjectType, normalizeText(query.subjectType, "subject type", 128));
    if (query.subjectId !== undefined) add(this.columns.subjectId, normalizeText(query.subjectId, "subject id", 512));
    if (query.purpose !== undefined) add(this.columns.purpose, normalizeText(query.purpose, "purpose", 128));
    if (query.status !== undefined) add(this.columns.status, normalizeStatus(query.status));
    const decoded = query.cursor === undefined ? undefined : decodeSecretBindingCursor(query.cursor, this.tenant.tenantId);
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
    const page: SecretBindingPage = { items, total, hasMore };
    if (hasMore && items.length > 0) page.nextCursor = encodeSecretBindingCursor(items[items.length - 1].id, this.tenant.tenantId);
    return page;
  }

  async create(input: SecretBindingCreateInput): Promise<SecretBindingRecord> {
    if (this.tenant.requireTransactions && typeof this.executor.transaction !== "function") {
      throw new Error("Tenant-scoped secret binding writes require a transaction");
    }
    const now = new Date();
    const record: SecretBindingRecord = {
      id: normalizeId(input.id ?? randomUUID()),
      tenantId: this.tenant.tenantId,
      subjectType: normalizeText(input.subjectType, "subject type", 128),
      subjectId: normalizeText(input.subjectId, "subject id", 512),
      purpose: normalizeText(input.purpose, "purpose", 128),
      version: 1,
      secretRef: normalizeSecretRef(input.secretRef),
      status: "active",
      gracePeriodSeconds: normalizeGracePeriod(input.gracePeriodSeconds ?? 0),
      validFrom: input.validFrom ?? now,
      graceUntil: null,
      supersededAt: null,
      revokedAt: null,
      createdAt: now,
      updatedAt: now,
    };
    const operation = async (): Promise<SecretBindingRecord> => this.insert(record, getTenantTransactionExecutor(this.executor) ?? this.executor);
    return this.runWrite(operation);
  }

  async rotate(subjectType: string, subjectId: string, purpose: string, input: SecretBindingRotateInput): Promise<SecretBindingRecord> {
    if (this.tenant.requireTransactions && typeof this.executor.transaction !== "function") {
      throw new Error("Tenant-scoped secret binding writes require a transaction");
    }
    return this.runWrite(async () => {
      const current = await this.findActive(subjectType, subjectId, purpose);
      if (current === undefined) throw new Error("Secret binding not found");
      const expectedVersion = input.expectedVersion ?? current.version;
      const now = new Date();
      const gracePeriodSeconds = normalizeGracePeriod(input.gracePeriodSeconds ?? current.gracePeriodSeconds);
      const next: SecretBindingRecord = {
        id: normalizeId(randomUUID()),
        tenantId: this.tenant.tenantId,
        subjectType: current.subjectType,
        subjectId: current.subjectId,
        purpose: current.purpose,
        version: current.version + 1,
        secretRef: normalizeSecretRef(input.secretRef),
        status: "active",
        gracePeriodSeconds,
        validFrom: input.validFrom ?? now,
        graceUntil: null,
        supersededAt: null,
        revokedAt: null,
        createdAt: now,
        updatedAt: now,
      };
      const executor = getTenantTransactionExecutor(this.executor) ?? this.executor;
      const updated = await this.retire(executor, current, expectedVersion, now, gracePeriodSeconds);
      if (!updated) throw new Error("Secret binding version changed");
      return this.insert(next, executor);
    });
  }

  async revoke(id: string, version?: number): Promise<SecretBindingRecord> {
    if (this.tenant.requireTransactions && typeof this.executor.transaction !== "function") {
      throw new Error("Tenant-scoped secret binding writes require a transaction");
    }
    return this.runWrite(async () => {
      const current = await this.get(id);
      if (current === undefined) throw new Error("Secret binding not found");
      if (current.status === "revoked") throw new Error("Secret binding is already revoked");
      const expectedVersion = version ?? current.version;
      const now = new Date();
      const values: unknown[] = ["revoked", now, this.tenant.tenantId, normalizeId(id), expectedVersion];
      const rows = await this.queryRows(
        `UPDATE ${this.qualifiedTable()} SET ${this.quote(this.columns.status)} = $1, ${this.quote(this.columns.revokedAt)} = $2, ${this.quote(this.columns.updatedAt)} = $2, ${this.quote(this.columns.version)} = ${this.quote(this.columns.version)} + 1 WHERE ${this.quote(this.columns.tenantId)} = $3 AND ${this.quote(this.columns.id)} = $4 AND ${this.quote(this.columns.version)} = $5 RETURNING ${this.select()}`,
        values,
      );
      if (rows[0] === undefined) throw new Error("Secret binding version changed");
      return this.map(rows[0]);
    });
  }

  async revokeSubject(subjectType: string, subjectId: string, purpose: string): Promise<SecretBindingRecord[]> {
    if (this.tenant.requireTransactions && typeof this.executor.transaction !== "function") {
      throw new Error("Tenant-scoped secret binding writes require a transaction");
    }
    return this.runWrite(async () => {
      const values: unknown[] = [
        "revoked",
        new Date(),
        this.tenant.tenantId,
        normalizeText(subjectType, "subject type", 128),
        normalizeText(subjectId, "subject id", 512),
        normalizeText(purpose, "purpose", 128),
      ];
      const rows = await this.queryRows(
        `UPDATE ${this.qualifiedTable()} SET ${this.quote(this.columns.status)} = $1, ${this.quote(this.columns.revokedAt)} = $2, ${this.quote(this.columns.updatedAt)} = $2, ${this.quote(this.columns.version)} = ${this.quote(this.columns.version)} + 1 WHERE ${this.quote(this.columns.tenantId)} = $3 AND ${this.quote(this.columns.subjectType)} = $4 AND ${this.quote(this.columns.subjectId)} = $5 AND ${this.quote(this.columns.purpose)} = $6 AND ${this.quote(this.columns.status)} IN ('active', 'retiring') RETURNING ${this.select()}`,
        values,
      );
      if (rows.length === 0) throw new Error("Secret binding not found");
      return rows.map((row) => this.map(row));
    });
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

  async readiness(): Promise<SecretBindingReadiness> {
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

  private async insert(record: SecretBindingRecord, executor: TenantSqlExecutor = this.executor): Promise<SecretBindingRecord> {
    const fields = [
      "id",
      "tenantId",
      "subjectType",
      "subjectId",
      "purpose",
      "version",
      "secretRef",
      "status",
      "gracePeriodSeconds",
      "validFrom",
      "graceUntil",
      "supersededAt",
      "revokedAt",
      "createdAt",
      "updatedAt",
    ];
    const values = fields.map((field) => storageValue(field, record[field as keyof SecretBindingRecord]));
    const columns = fields.map((field) => this.quote(this.columns[field as keyof SecretBindingSqlColumns]));
    const result = await executor.query(
      `INSERT INTO ${this.qualifiedTable()} (${columns.join(", ")}) VALUES (${values.map((_value, index) => `$${index + 1}`).join(", ")}) RETURNING ${this.select()}`,
      values,
    );
    const rows = resultRows(result);
    if (rows === undefined) throw new Error("Secret binding SQL result failed");
    const row = rows.find(isRecord);
    return row === undefined ? record : this.map(row);
  }

  private async retire(
    executor: TenantSqlExecutor,
    current: SecretBindingRecord,
    expectedVersion: number,
    at: Date,
    gracePeriodSeconds: number,
  ): Promise<boolean> {
    const graceUntil = gracePeriodSeconds === 0 ? null : new Date(at.getTime() + gracePeriodSeconds * 1000);
    const result = await executor.query(
      `UPDATE ${this.qualifiedTable()} SET ${this.quote(this.columns.status)} = $1, ${this.quote(this.columns.gracePeriodSeconds)} = $2, ${this.quote(this.columns.graceUntil)} = $3, ${this.quote(this.columns.supersededAt)} = $4, ${this.quote(this.columns.updatedAt)} = $4 WHERE ${this.quote(this.columns.tenantId)} = $5 AND ${this.quote(this.columns.id)} = $6 AND ${this.quote(this.columns.version)} = $7`,
      ["retiring", gracePeriodSeconds, graceUntil, at, this.tenant.tenantId, current.id, expectedVersion],
    );
    return readAffected(result) === 1;
  }

  private select(): string {
    return Object.values(this.columns).map((column) => `${this.quote(column)} AS ${this.quote(column)}`).join(", ");
  }

  private qualifiedTable(): string {
    return quoteTenantSqlIdentifier(this.table, "secret binding table");
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
      throw new Error("Secret binding repository transaction is required");
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
        await active.query("SELECT set_config('app.tenant_id', $1, true)", [this.tenant.tenantId]);
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
    if (rows === undefined) throw new Error("Secret binding SQL result failed");
    return rows.filter(isRecord);
  }

  private map(row: Record<string, unknown>): SecretBindingRecord {
    const value = (field: string, column: string): unknown => row[column] ?? row[field] ?? row[column.toLowerCase()];
    const id = readString(value("id", this.columns.id));
    const subjectType = readString(value("subjectType", this.columns.subjectType));
    const subjectId = readString(value("subjectId", this.columns.subjectId));
     const purpose = readString(value("purpose", this.columns.purpose));
     const secretRef = readString(value("secretRef", this.columns.secretRef));
     const tenantId = readString(value("tenantId", this.columns.tenantId));
     if (id === undefined || subjectType === undefined || subjectId === undefined || purpose === undefined || secretRef === undefined || tenantId !== this.tenant.tenantId) throw new Error("Invalid secret binding row");
     return {
       id,
       tenantId,
      subjectType,
      subjectId,
      purpose,
      version: readNumber(value("version", this.columns.version)) ?? 1,
      secretRef,
      status: normalizeStatus(value("status", this.columns.status)),
      gracePeriodSeconds: readNumber(value("gracePeriodSeconds", this.columns.gracePeriodSeconds)) ?? 0,
      validFrom: readDate(value("validFrom", this.columns.validFrom)) ?? new Date(0),
      graceUntil: readDate(value("graceUntil", this.columns.graceUntil)),
      supersededAt: readDate(value("supersededAt", this.columns.supersededAt)),
      revokedAt: readDate(value("revokedAt", this.columns.revokedAt)),
      createdAt: readDate(value("createdAt", this.columns.createdAt)) ?? new Date(0),
      updatedAt: readDate(value("updatedAt", this.columns.updatedAt)) ?? new Date(0),
    };
  }
}

export class InMemorySecretBindingRepository implements SecretBindingRepository {
  readonly tenant: TenantConfig;
  private readonly bindings = new Map<string, SecretBindingRecord>();

  constructor(options: SecretBindingSqlRepositoryOptions & { bindings?: readonly SecretBindingRecord[] } = {}) {
    this.tenant = normalizeTenantConfig({
      ...(options.tenant ?? {}),
      ...(options.tenantConfig ?? {}),
      ...(options.mode === undefined ? {} : { mode: options.mode }),
      ...(options.tenantId === undefined ? {} : { tenantId: options.tenantId }),
      ...(options.tenantColumn === undefined ? {} : { tenantColumn: options.tenantColumn }),
    });
    for (const binding of options.bindings ?? []) {
      if (binding.tenantId !== this.tenant.tenantId) continue;
      this.bindings.set(this.key(binding.id), { ...binding });
    }
  }

  async get(id: string): Promise<SecretBindingRecord | undefined> {
    const value = this.bindings.get(this.key(id));
    return value === undefined ? undefined : { ...value };
  }

  async findActive(subjectType: string, subjectId: string, purpose: string): Promise<SecretBindingRecord | undefined> {
    const normalizedType = normalizeText(subjectType, "subject type", 128);
    const normalizedId = normalizeText(subjectId, "subject id", 512);
    const normalizedPurpose = normalizeText(purpose, "purpose", 128);
    return [...this.bindings.values()]
      .filter((item) => item.tenantId === this.tenant.tenantId && item.subjectType === normalizedType && item.subjectId === normalizedId && item.purpose === normalizedPurpose && item.status !== "revoked")
      .sort((left, right) => {
        if (left.status !== right.status) return left.status === "active" ? -1 : 1;
        return right.version - left.version;
      })[0];
  }

  async getVersion(subjectType: string, subjectId: string, purpose: string, version: number): Promise<SecretBindingRecord | undefined> {
    const normalizedType = normalizeText(subjectType, "subject type", 128);
    const normalizedId = normalizeText(subjectId, "subject id", 512);
    const normalizedPurpose = normalizeText(purpose, "purpose", 128);
    const normalizedVersion = normalizeVersion(version);
    const value = [...this.bindings.values()].find((item) => item.tenantId === this.tenant.tenantId && item.subjectType === normalizedType && item.subjectId === normalizedId && item.purpose === normalizedPurpose && item.version === normalizedVersion);
    return value === undefined ? undefined : { ...value };
  }

  async resolve(subjectType: string, subjectId: string, purpose: string, at = new Date()): Promise<SecretBindingResolution | undefined> {
    const normalizedType = normalizeText(subjectType, "subject type", 128);
    const normalizedId = normalizeText(subjectId, "subject id", 512);
    const normalizedPurpose = normalizeText(purpose, "purpose", 128);
    const candidates = [...this.bindings.values()]
      .filter((item) => item.tenantId === this.tenant.tenantId && item.subjectType === normalizedType && item.subjectId === normalizedId && item.purpose === normalizedPurpose && item.status !== "revoked")
      .sort((left, right) => {
        if (left.status !== right.status) return left.status === "active" ? -1 : 1;
        return right.version - left.version;
      });
    const binding = candidates.find((item) => isSecretBindingUsable(item, at));
    if (binding === undefined) return undefined;
    return { binding: { ...binding }, usedGracePeriod: binding.status === "retiring" };
  }

  async create(input: SecretBindingCreateInput): Promise<SecretBindingRecord> {
    const now = new Date();
    const record: SecretBindingRecord = {
      id: normalizeId(input.id ?? randomUUID()),
      tenantId: this.tenant.tenantId,
      subjectType: normalizeText(input.subjectType, "subject type", 128),
      subjectId: normalizeText(input.subjectId, "subject id", 512),
      purpose: normalizeText(input.purpose, "purpose", 128),
      version: 1,
      secretRef: normalizeSecretRef(input.secretRef),
      status: "active",
      gracePeriodSeconds: normalizeGracePeriod(input.gracePeriodSeconds ?? 0),
      validFrom: input.validFrom ?? now,
      graceUntil: null,
      supersededAt: null,
      revokedAt: null,
      createdAt: now,
      updatedAt: now,
    };
    if ([...this.bindings.values()].some((item) => item.tenantId === record.tenantId && item.subjectType === record.subjectType && item.subjectId === record.subjectId && item.purpose === record.purpose && (item.version === record.version || item.status === "active"))) {
      throw new Error("Secret binding version already exists");
    }
    this.bindings.set(this.key(record.id), record);
    return { ...record };
  }

  async rotate(subjectType: string, subjectId: string, purpose: string, input: SecretBindingRotateInput): Promise<SecretBindingRecord> {
    const current = await this.findActive(subjectType, subjectId, purpose);
    if (current === undefined) throw new Error("Secret binding not found");
    if (input.expectedVersion !== undefined && input.expectedVersion !== current.version) throw new Error("Secret binding version changed");
    const now = new Date();
    const grace = normalizeGracePeriod(input.gracePeriodSeconds ?? current.gracePeriodSeconds);
    current.status = "retiring";
    current.gracePeriodSeconds = grace;
    current.graceUntil = grace === 0 ? null : new Date(now.getTime() + grace * 1000);
    current.supersededAt = now;
    current.updatedAt = now;
    const next: SecretBindingRecord = {
      id: normalizeId(randomUUID()),
      tenantId: this.tenant.tenantId,
      subjectType,
      subjectId,
      purpose,
      version: current.version + 1,
      secretRef: normalizeSecretRef(input.secretRef),
      status: "active",
      gracePeriodSeconds: grace,
      validFrom: input.validFrom ?? now,
      graceUntil: null,
      supersededAt: null,
      revokedAt: null,
      createdAt: now,
      updatedAt: now,
    };
    this.bindings.set(this.key(next.id), next);
    return { ...next };
  }

  async resolveSecret(subjectType: string, subjectId: string, purpose: string, at = new Date()): Promise<string | undefined> {
    return (await this.resolve(subjectType, subjectId, purpose, at))?.binding.secretRef;
  }

  async list(query: SecretBindingListQuery = {}): Promise<SecretBindingPage> {
    const limit = normalizeLimit(query.limit);
    const filtered = [...this.bindings.values()]
      .filter((item) => item.tenantId === this.tenant.tenantId)
       .filter((item) => query.subjectType === undefined || item.subjectType === normalizeText(query.subjectType, "subject type", 128))
       .filter((item) => query.subjectId === undefined || item.subjectId === normalizeText(query.subjectId, "subject id", 512))
       .filter((item) => query.purpose === undefined || item.purpose === normalizeText(query.purpose, "purpose", 128))
       .filter((item) => query.status === undefined || item.status === normalizeStatus(query.status))
      .sort((left, right) => left.id.localeCompare(right.id));
    const decoded = query.cursor === undefined ? undefined : decodeSecretBindingCursor(query.cursor, this.tenant.tenantId);
    const cursorFiltered = decoded === undefined ? filtered : filtered.filter((item) => item.id > decoded);
    const offset = query.cursor === undefined ? Math.max(0, query.offset ?? 0) : 0;
    const items = cursorFiltered.slice(offset, offset + limit).map((item) => ({ ...item }));
    const hasMore = offset + items.length < cursorFiltered.length;
    return {
      items,
      total: cursorFiltered.length,
      hasMore,
      ...(hasMore && items.length > 0 ? { nextCursor: encodeSecretBindingCursor(items[items.length - 1].id, this.tenant.tenantId) } : {}),
    };
  }

  async isReady(): Promise<boolean> {
    return true;
  }

  async revoke(id: string, version?: number): Promise<SecretBindingRecord> {
    const current = await this.get(id);
    if (current === undefined) throw new Error("Secret binding not found");
    if (current.status === "revoked") throw new Error("Secret binding is already revoked");
    if (version !== undefined && version !== current.version) throw new Error("Secret binding version changed");
    current.status = "revoked";
    current.revokedAt = new Date();
    current.updatedAt = current.revokedAt;
    current.version += 1;
    this.bindings.set(this.key(id), current);
    return { ...current };
  }

  async revokeSubject(subjectType: string, subjectId: string, purpose: string): Promise<SecretBindingRecord[]> {
    const normalizedType = normalizeText(subjectType, "subject type", 128);
    const normalizedId = normalizeText(subjectId, "subject id", 512);
    const normalizedPurpose = normalizeText(purpose, "purpose", 128);
    const now = new Date();
    const records = [...this.bindings.values()].filter((item) =>
      item.tenantId === this.tenant.tenantId &&
      item.subjectType === normalizedType &&
      item.subjectId === normalizedId &&
      item.purpose === normalizedPurpose &&
      item.status !== "revoked",
    );
    if (records.length === 0) throw new Error("Secret binding not found");
    for (const record of records) {
      record.status = "revoked";
      record.revokedAt = now;
      record.updatedAt = now;
      record.version += 1;
      this.bindings.set(this.key(record.id), record);
    }
    return records.map((record) => ({ ...record }));
  }

  private key(id: string): string {
    return tenantQualifiedKey(this.tenant.tenantId, id).key;
  }
}

export function createSecretBindingRepository(
  input: SecretBindingSqlRepositoryOptions | TenantSqlExecutor | TenantSqlQuery,
  options: Omit<SecretBindingSqlRepositoryOptions, "executor" | "query"> = {},
): SqlSecretBindingRepository {
  return new SqlSecretBindingRepository(input as SecretBindingSqlRepositoryOptions, options);
}

function hasSecretBindingRepositoryOptions(value: object): boolean {
  return ["tenantId", "tenant", "tenantConfig", "mode", "tenantColumn", "table", "tables", "tableNames", "columns", "columnNames", "sharedExecutor", "dedicatedExecutor", "fallbackExecutor", "allowSharedFallback"].some((key) => Object.prototype.hasOwnProperty.call(value, key));
}

function assertNoSecretDedicatedFallback(options: SecretBindingSqlRepositoryOptions): void {
  const mode = normalizeTenantMode(options.tenant?.mode ?? options.tenantConfig?.mode ?? options.mode);
  if (mode === "dedicated" && (options.allowSharedFallback === true || options.sharedExecutor !== undefined || options.fallbackExecutor !== undefined)) {
    throw new TypeError("Dedicated tenant mode cannot use a shared pool fallback");
  }
}

function normalizeOptions(
  input: SecretBindingSqlRepositoryOptions | TenantSqlExecutor | TenantSqlQuery,
  second: Omit<SecretBindingSqlRepositoryOptions, "executor" | "query">,
): SecretBindingSqlRepositoryOptions {
  if (typeof input === "function") return { ...second, query: input };
  if (isExecutor(input) && !hasSecretBindingRepositoryOptions(input)) return { ...second, executor: input };
  return { ...input, ...second };
}

function normalizeExecutor(options: SecretBindingSqlRepositoryOptions, mode: TenantMode): TenantSqlExecutor {
  if (options.executor && typeof options.executor.query === "function") return options.executor;
  if (typeof options.query === "function") return { query: options.query };
  if (mode === "shared" && options.sharedExecutor && typeof options.sharedExecutor.query === "function") return options.sharedExecutor;
  if (mode === "dedicated" && options.dedicatedExecutor && typeof options.dedicatedExecutor.query === "function") return options.dedicatedExecutor;
  throw new TypeError("A secret binding SQL query executor is required");
}

function normalizeColumns(columns: Partial<SecretBindingSqlColumns>, tenantColumn: string): SecretBindingSqlColumns {
  const source = { ...DEFAULT_SECRET_BINDING_COLUMNS, ...columns, tenantId: columns.tenantId ?? tenantColumn };
  return {
    id: validateTenantSqlIdentifier(source.id, "secret binding id column"),
    tenantId: validateTenantSqlIdentifier(source.tenantId, "secret binding tenant column"),
    subjectType: validateTenantSqlIdentifier(source.subjectType, "secret binding subject type column"),
    subjectId: validateTenantSqlIdentifier(source.subjectId, "secret binding subject id column"),
    purpose: validateTenantSqlIdentifier(source.purpose, "secret binding purpose column"),
    version: validateTenantSqlIdentifier(source.version, "secret binding version column"),
    secretRef: validateTenantSqlIdentifier(source.secretRef, "secret binding reference column"),
    status: validateTenantSqlIdentifier(source.status, "secret binding status column"),
    gracePeriodSeconds: validateTenantSqlIdentifier(source.gracePeriodSeconds, "secret binding grace period column"),
    validFrom: validateTenantSqlIdentifier(source.validFrom, "secret binding valid from column"),
    graceUntil: validateTenantSqlIdentifier(source.graceUntil, "secret binding grace until column"),
    supersededAt: validateTenantSqlIdentifier(source.supersededAt, "secret binding superseded at column"),
    revokedAt: validateTenantSqlIdentifier(source.revokedAt, "secret binding revoked at column"),
    createdAt: validateTenantSqlIdentifier(source.createdAt, "secret binding created at column"),
    updatedAt: validateTenantSqlIdentifier(source.updatedAt, "secret binding updated at column"),
  };
}

function addColumn(table: string, column: string, definition: string): string | undefined {
  if (!column) return undefined;
  return `ALTER TABLE ${quoteTenantSqlIdentifier(table)} ADD COLUMN IF NOT EXISTS ${quoteTenantSqlIdentifier(column)} ${definition}`;
}

function normalizeId(value: unknown): string {
  return normalizeText(value, "secret binding id", 512);
}

function normalizeText(value: unknown, field: string, max: number): string {
  if (typeof value !== "string") throw new TypeError(`${field} must be a string`);
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > max || /[\u0000-\u001f\u007f]/u.test(normalized)) throw new TypeError(`Invalid ${field}`);
  return normalized;
}

function normalizeSecretRef(value: unknown): string {
  return normalizeText(value, "secret reference", 2048);
}

function normalizeVersion(value: unknown): number {
  const normalized = typeof value === "number" ? value : Number(value);
  if (!Number.isSafeInteger(normalized) || normalized < 1) throw new TypeError("Invalid secret binding version");
  return normalized;
}

function normalizeGracePeriod(value: unknown): number {
  const normalized = typeof value === "number" ? value : Number(value);
  if (!Number.isSafeInteger(normalized) || normalized < 0 || normalized > 31_536_000) throw new TypeError("Invalid secret binding grace period");
  return normalized;
}

function normalizeStatus(value: unknown): SecretBindingStatus {
  if (value === "active" || value === "retiring" || value === "revoked") return value;
  throw new TypeError("Invalid secret binding status");
}

function normalizeLimit(value: unknown): number {
  if (value === undefined) return 20;
  const normalized = typeof value === "number" ? value : Number(value);
  if (!Number.isSafeInteger(normalized) || normalized < 1 || normalized > 100) throw new TypeError("Invalid secret binding page limit");
  return normalized;
}

function storageValue(field: string, value: unknown): unknown {
  return field === "metadata" ? JSON.stringify(value ?? {}) : value;
}

function encodeSecretBindingCursor(id: string, tenantId: string): string {
  return Buffer.from(JSON.stringify({ version: 1, tenantId, id }), "utf8").toString("base64url");
}

function decodeSecretBindingCursor(value: string, tenantId: string): string {
  try {
    const parsed = JSON.parse(Buffer.from(value, "base64url").toString("utf8")) as { version?: unknown; tenantId?: unknown; id?: unknown };
    if (parsed.version !== 1 || parsed.tenantId !== tenantId || typeof parsed.id !== "string") throw new Error("invalid cursor");
    return normalizeId(parsed.id);
  } catch {
    throw new TypeError("Invalid secret binding pagination cursor");
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

function readDate(value: unknown): Date | string | undefined {
  if (value instanceof Date && !Number.isNaN(value.getTime())) return new Date(value.getTime());
  if (typeof value === "string" && value.length <= 128 && !Number.isNaN(new Date(value).getTime())) return value;
  return undefined;
}

function dateValue(value: Date | string): number {
  const result = value instanceof Date ? value.getTime() : new Date(value).getTime();
  return Number.isNaN(result) ? Number.POSITIVE_INFINITY : result;
}
