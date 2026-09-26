import { AsyncLocalStorage } from "node:async_hooks";

export const TENANT_MODES = ["fixed", "shared", "dedicated"] as const;
export type TenantMode = (typeof TENANT_MODES)[number];
export type TenantIsolationMode = TenantMode;

export const DEFAULT_TENANT_ID = "default";
export const DEFAULT_TENANT_COLUMN = "tenant_id";
export const DEFAULT_TENANT_SCHEMA = "public";
export const DEFAULT_TENANT_TABLE = "gb_idaas_tenant";
export const TENANT_CONTEXT_SETTING = "app.tenant_id";

export interface TenantConfigInput {
  mode?: TenantMode | string;
  isolation?: TenantMode | string;
  strategy?: TenantMode | string;
  tenantId?: string;
  tenantColumn?: string | null;
  schema?: string;
  requireRls?: boolean;
  requireTransactions?: boolean;
  allowSharedFallback?: boolean;
  sharedPool?: unknown;
  fallbackPool?: unknown;
}

export interface TenantConfig {
  readonly mode: TenantMode;
  readonly tenantId: string;
  readonly tenantColumn: string;
  readonly schema: string;
  readonly requireRls: boolean;
  readonly requireTransactions: boolean;
  readonly allowSharedFallback: false;
  readonly experimental?: boolean;
  readonly productionReady?: boolean;
}

export interface TenantQualifiedKey {
  readonly tenantId: string;
  readonly id: string;
  readonly key: string;
}

export interface TenantModeRequirements {
  readonly mode: TenantMode;
  readonly tenantColumnRequired: true;
  readonly rlsRequired: boolean;
  readonly transactionsRequired: boolean;
  readonly requestScopedContextRequired: boolean;
  readonly sharedPoolFallbackAllowed: false;
  readonly experimental?: boolean;
  readonly productionSupported?: boolean;
}

export interface TenantReadiness {
  readonly ready: boolean;
  readonly mode: TenantMode;
  readonly rls: boolean;
  readonly transactions: boolean;
  readonly requiredColumns: boolean;
  readonly missingColumns: readonly string[];
  readonly context: boolean;
}

export interface TenantRecord {
  id: string;
  mode: TenantMode;
  status: "active" | "disabled" | string;
  schemaName?: string | null;
  version: number;
  metadata?: Record<string, unknown>;
  createdAt?: Date | string | null;
  updatedAt?: Date | string | null;
  [key: string]: unknown;
}

export interface TenantListQuery {
  cursor?: string;
  limit?: number;
  offset?: number;
  status?: string;
  search?: string;
}

export interface TenantPage {
  items: TenantRecord[];
  nextCursor?: string;
  hasMore: boolean;
  total: number;
}

export interface TenantWriteContext {
  actorId?: string;
  requestId?: string;
  idempotencyKey?: string;
}

export interface TenantSqlQuery {
  (text: string, values?: unknown[]): unknown | Promise<unknown>;
}

export interface TenantRepository {
  readonly tenant: TenantConfig;
  get(id?: string): Promise<TenantRecord | undefined>;
  list(query?: TenantListQuery): Promise<TenantPage>;
  create(input: Partial<TenantRecord> & { id: string; mode?: TenantMode | string; idempotencyKey?: string }): Promise<TenantRecord>;
  update(id: string, input: Partial<TenantRecord> & { version?: number; idempotencyKey?: string }): Promise<TenantRecord>;
  isReady(): Promise<boolean>;
  readiness?(): Promise<TenantReadiness>;
  withTenantContext?<T>(operation: (executor: TenantSqlExecutor) => Promise<T>): Promise<T>;
  withTransaction?<T>(operation: (() => Promise<T>) | ((executor: TenantSqlExecutor) => Promise<T>)): Promise<T>;
}

export interface TenantSqlExecutor {
  query: TenantSqlQuery;
  transaction?<T>(callback: (executor: TenantSqlExecutor) => Promise<T>): Promise<T>;
}

interface TenantTransactionContext {
  root: object;
  executor: TenantSqlExecutor;
}

const tenantTransactionStorage = new AsyncLocalStorage<TenantTransactionContext>();
const tenantRequestContextStorage = new AsyncLocalStorage<TenantRequestContext>();

export interface TenantRequestContext {
  readonly tenantId: string;
  readonly mode: TenantMode;
  readonly executor?: TenantSqlExecutor;
}

export function runWithTenantContext<T>(
  context: TenantRequestContext,
  operation: () => Promise<T>,
): Promise<T> {
  return tenantRequestContextStorage.run({
    tenantId: normalizeTenantId(context.tenantId),
    mode: normalizeTenantMode(context.mode),
    ...(context.executor === undefined ? {} : { executor: context.executor }),
  }, operation);
}

export function getTenantRequestContext(): TenantRequestContext | undefined {
  const context = tenantRequestContextStorage.getStore();
  return context === undefined ? undefined : { ...context };
}

export function runWithTenantTransaction<T>(
  root: object,
  executor: TenantSqlExecutor,
  operation: () => Promise<T>,
): Promise<T> {
  const active = tenantTransactionStorage.getStore();
  if (active?.root === root) return operation();
  return tenantTransactionStorage.run({ root, executor }, operation);
}

export function getTenantTransactionExecutor(root: object): TenantSqlExecutor | undefined {
  const active = tenantTransactionStorage.getStore();
  return active?.root === root ? active.executor : undefined;
}

export interface TenantSqlTableNames {
  tenants: string;
  tenant?: string;
}

export interface TenantSqlColumns {
  id: string;
  mode: string;
  status: string;
  schemaName: string;
  version: string;
  metadata: string;
  createdAt: string;
  updatedAt: string;
}

export interface TenantSqlRepositoryOptions {
  executor?: TenantSqlExecutor;
  query?: TenantSqlQuery;
  sharedExecutor?: TenantSqlExecutor;
  dedicatedExecutor?: TenantSqlExecutor;
  fallbackExecutor?: TenantSqlExecutor;
  allowSharedFallback?: boolean;
  mode?: TenantMode | string;
  tenantId?: string;
  tenantColumn?: string | null;
  schema?: string;
  requireRls?: boolean;
  requireTransactions?: boolean;
  tenant?: TenantConfigInput;
  tenantConfig?: TenantConfigInput;
  table?: string;
  tables?: Partial<TenantSqlTableNames>;
  tableNames?: Partial<TenantSqlTableNames>;
  columns?: Partial<TenantSqlColumns>;
  columnNames?: Partial<TenantSqlColumns>;
}

export const DEFAULT_TENANT_SQL_TABLE = DEFAULT_TENANT_TABLE;
export const DEFAULT_TENANT_SQL_COLUMNS: TenantSqlColumns = {
  id: "id",
  mode: "mode",
  status: "status",
  schemaName: "schema_name",
  version: "version",
  metadata: "metadata",
  createdAt: "created_at",
  updatedAt: "updated_at",
};

export function defineTenantConfig(input: TenantConfigInput = {}): TenantConfig {
  return normalizeTenantConfig(input);
}

export const createTenantConfig = defineTenantConfig;
export const configureTenant = defineTenantConfig;

export function tenantContextSql(): string {
  return `SELECT set_config('${TENANT_CONTEXT_SETTING}', $1, true)`;
}

export function assertTenantRequestContext(mode: TenantMode | string, executor: { transaction?: unknown }): void {
  const normalized = normalizeTenantMode(mode);
  if (normalized === "shared" && typeof executor.transaction !== "function") {
    throw new TypeError("Shared tenant mode requires a request-scoped transaction executor");
  }
}

export function normalizeTenantConfig(input: TenantConfigInput = {}): TenantConfig {
  if (input === null || typeof input !== "object") throw new TypeError("Tenant configuration must be an object");
  const mode = normalizeTenantMode(input.mode ?? input.isolation ?? input.strategy ?? "fixed");
  const tenantId = normalizeTenantId(input.tenantId);
  const tenantColumn = normalizeTenantColumn(input.tenantColumn);
  const schema = validateTenantSchema(input.schema ?? DEFAULT_TENANT_SCHEMA);
  const requiresRls = mode === "shared";
  const requiresTransactions = mode === "shared";
  if (mode === "shared" && input.requireRls === false) {
    throw new TypeError("Shared tenant mode requires RLS");
  }
  if (mode === "shared" && input.requireTransactions === false) {
    throw new TypeError("Shared tenant mode requires transaction capability");
  }
  if (mode === "dedicated" && input.allowSharedFallback === true) {
    throw new TypeError("Dedicated tenant mode cannot use a shared pool fallback");
  }
  if (mode === "dedicated" && (input.sharedPool !== undefined || input.fallbackPool !== undefined)) {
    throw new TypeError("Dedicated tenant mode cannot use a shared pool fallback");
  }
  return {
    mode,
    tenantId,
    tenantColumn,
    schema,
    requireRls: requiresRls || input.requireRls === true,
    requireTransactions: requiresTransactions || input.requireTransactions === true || input.requireRls === true,
    allowSharedFallback: false,
    experimental: mode === "shared",
    productionReady: mode !== "shared",
  };
}

export function tenantModeRequirements(mode: TenantMode | string): TenantModeRequirements {
  const normalized = normalizeTenantMode(mode);
  return {
    mode: normalized,
    tenantColumnRequired: true,
    rlsRequired: normalized === "shared",
    transactionsRequired: normalized === "shared",
    requestScopedContextRequired: normalized === "shared",
    sharedPoolFallbackAllowed: false,
    experimental: normalized === "shared",
    productionSupported: normalized !== "shared",
  };
}

export function isSharedTenantMode(mode: TenantMode | string): boolean {
  return normalizeTenantMode(mode) === "shared";
}

export function isTenantProductionSupported(mode: TenantMode | string): boolean {
  return normalizeTenantMode(mode) !== "shared";
}

export function assertTenantProductionSupported(mode: TenantMode | string, profile: string | undefined): void {
  if (profile === "production" && !isTenantProductionSupported(mode)) {
    throw new Error("[getbrick-idaas] shared tenant mode is experimental and cannot be used in production");
  }
}

export function normalizeTenantMode(value: unknown): TenantMode {
  if (value === undefined) return "fixed";
  if (typeof value !== "string") throw new TypeError("Tenant mode must be a string");
  const normalized = value.trim().toLowerCase();
  if (normalized === "single" || normalized === "fixed") return "fixed";
  if (normalized === "multi" || normalized === "shared") return "shared";
  if (normalized === "isolated" || normalized === "dedicated") return "dedicated";
  throw new TypeError("Tenant mode must be fixed, shared, or dedicated");
}

export function normalizeTenantId(value: unknown): string {
  if (value === undefined) return DEFAULT_TENANT_ID;
  if (typeof value !== "string") throw new TypeError("tenantId must be a string");
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 256 || /[:\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new TypeError("Invalid tenantId");
  }
  return normalized;
}

export function normalizeTenantColumn(value: unknown): string {
  if (value === null) throw new TypeError("Tenant-qualified persistence requires a tenant column");
  return validateTenantSqlIdentifier(value ?? DEFAULT_TENANT_COLUMN, "tenant column");
}

export function validateTenantSqlIdentifier(value: unknown, field = "identifier"): string {
  if (typeof value !== "string") throw new TypeError(`${field} must be a string`);
  const normalized = value.trim();
  if (normalized !== value) throw new TypeError(`Invalid SQL identifier for ${field}`);
  const segments = normalized.split(".");
  if (segments.length < 1 || segments.length > 2 || segments.some((segment) => !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(segment) || segment.length > 63)) {
    throw new TypeError(`Invalid SQL identifier for ${field}`);
  }
  return segments.join(".");
}

export function quoteTenantSqlIdentifier(value: unknown, field = "identifier"): string {
  return validateTenantSqlIdentifier(value, field).split(".").map((segment) => `"${segment}"`).join(".");
}

export function validateTenantSchema(value: unknown): string {
  if (typeof value !== "string") throw new TypeError("tenant schema must be a string");
  const normalized = value.trim();
  if (normalized !== value || !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(normalized) || normalized.length > 63) {
    throw new TypeError("Invalid SQL identifier for tenant schema");
  }
  return normalized;
}

export function qualifyTenantTable(table: unknown, schema: unknown = DEFAULT_TENANT_SCHEMA): string {
  const normalized = validateTenantSqlIdentifier(table, "table");
  const normalizedSchema = validateTenantSchema(schema);
  return normalized.includes(".") || normalizedSchema === DEFAULT_TENANT_SCHEMA ? normalized : `${normalizedSchema}.${normalized}`;
}

export function createTenantSqlObjectName(table: unknown, suffix: unknown): string {
  const normalizedTable = validateTenantSqlIdentifier(table, "table").split(".").at(-1) ?? "";
  const normalizedSuffix = validateTenantSqlIdentifier(suffix, "object suffix").split(".").at(-1) ?? "";
  const prefix = `${normalizedTable}_`;
  const available = Math.max(1, 63 - prefix.length - normalizedSuffix.length);
  return `${normalizedTable.slice(0, available)}_${normalizedSuffix}`;
}

export function tenantQualifiedKey(tenantId: string, id: string): TenantQualifiedKey {
  const tenant = normalizeTenantId(tenantId);
  const resource = normalizeResourceId(id);
  return { tenantId: tenant, id: resource, key: `${tenant}:${resource}` };
}

export function qualifyTenantKey(tenantId: string, id: string): string {
  return tenantQualifiedKey(tenantId, id).key;
}

export function tenantKey(tenantId: string, id: string): string {
  return qualifyTenantKey(tenantId, id);
}

export function parseTenantQualifiedKey(value: string): TenantQualifiedKey {
  if (typeof value !== "string") throw new TypeError("Tenant key must be a string");
  const separator = value.indexOf(":");
  if (separator <= 0 || separator === value.length - 1) throw new TypeError("Invalid tenant key");
  return tenantQualifiedKey(value.slice(0, separator), value.slice(separator + 1));
}

export function createTenantTableMigrationSql(
  table = DEFAULT_TENANT_TABLE,
  columns: Partial<TenantSqlColumns> = {},
): string {
  const normalized = normalizeColumns(columns);
  const definitions = [
    `${quoteTenantSqlIdentifier(normalized.id)} TEXT NOT NULL PRIMARY KEY`,
    `${quoteTenantSqlIdentifier(normalized.mode)} TEXT NOT NULL DEFAULT 'fixed'`,
    `${quoteTenantSqlIdentifier(normalized.status)} TEXT NOT NULL DEFAULT 'active'`,
    `${quoteTenantSqlIdentifier(normalized.schemaName)} TEXT`,
    `${quoteTenantSqlIdentifier(normalized.version)} INTEGER NOT NULL DEFAULT 1`,
    `${quoteTenantSqlIdentifier(normalized.metadata)} JSONB NOT NULL DEFAULT '{}'::jsonb`,
    `${quoteTenantSqlIdentifier(normalized.createdAt)} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `${quoteTenantSqlIdentifier(normalized.updatedAt)} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
  ];
  return [
    `CREATE TABLE IF NOT EXISTS ${quoteTenantSqlIdentifier(table)} (${definitions.join(", ")})`,
    ...ensureTenantColumns(table, normalized),
    `CREATE INDEX IF NOT EXISTS ${quoteTenantSqlIdentifier(createTenantSqlObjectName(table, "status_idx"))} ON ${quoteTenantSqlIdentifier(table)} (${quoteTenantSqlIdentifier(normalized.status)}, ${quoteTenantSqlIdentifier(normalized.id)})`,
  ].join(";\n");
}

export function createTenantTableSql(
  table = DEFAULT_TENANT_TABLE,
  columns: Partial<TenantSqlColumns> = {},
): string {
  return createTenantTableMigrationSql(table, columns);
}

export function ensureTenantColumns(
  table: string,
  columns: Partial<TenantSqlColumns> = {},
): string[] {
  const normalized = normalizeColumns(columns);
  return [
    addColumn(table, normalized.id, "TEXT"),
    addColumn(table, normalized.mode, "TEXT DEFAULT 'fixed'"),
    addColumn(table, normalized.status, "TEXT DEFAULT 'active'"),
    addColumn(table, normalized.schemaName, "TEXT"),
    addColumn(table, normalized.version, "INTEGER DEFAULT 1"),
    addColumn(table, normalized.metadata, "JSONB DEFAULT '{}'::jsonb"),
    addColumn(table, normalized.createdAt, "TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP"),
    addColumn(table, normalized.updatedAt, "TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP"),
  ].filter((statement): statement is string => statement !== undefined);
}

export class SqlTenantRepository implements TenantRepository {
  readonly tenant: TenantConfig;
  private readonly executor: TenantSqlExecutor;
  private readonly table: string;
  private readonly columns: TenantSqlColumns;
  private readonly scopedExecutors = new WeakSet<object>();

  constructor(options: TenantSqlRepositoryOptions);
  constructor(executor: TenantSqlExecutor, options?: Omit<TenantSqlRepositoryOptions, "executor" | "query">);
  constructor(query: TenantSqlQuery, options?: Omit<TenantSqlRepositoryOptions, "executor" | "query">);
  constructor(input: TenantSqlRepositoryOptions | TenantSqlExecutor | TenantSqlQuery, options?: Omit<TenantSqlRepositoryOptions, "executor" | "query">);
  constructor(
    input: TenantSqlRepositoryOptions | TenantSqlExecutor | TenantSqlQuery,
    second: Omit<TenantSqlRepositoryOptions, "executor" | "query"> = {},
  ) {
    const options = normalizeRepositoryOptions(input, second);
    assertNoDedicatedFallback(options);
    this.tenant = normalizeTenantConfig({
      ...(options.tenant ?? {}),
      ...(options.tenantConfig ?? {}),
      ...(options.mode === undefined ? {} : { mode: options.mode }),
      ...(options.tenantId === undefined ? {} : { tenantId: options.tenantId }),
      ...(options.tenantColumn === undefined ? {} : { tenantColumn: options.tenantColumn }),
      ...(options.schema === undefined ? {} : { schema: options.schema }),
      ...(options.requireRls === undefined ? {} : { requireRls: options.requireRls }),
      ...(options.requireTransactions === undefined ? {} : { requireTransactions: options.requireTransactions }),
    });
    this.executor = normalizeExecutor(options, this.tenant.mode);
    this.table = qualifyTenantTable(
      options.tables?.tenants ?? options.tables?.tenant ?? options.table ?? options.tableNames?.tenants ?? options.tableNames?.tenant ?? DEFAULT_TENANT_TABLE,
      this.tenant.schema,
    );
    this.columns = normalizeColumns({ ...DEFAULT_TENANT_SQL_COLUMNS, ...(options.columns ?? {}), ...(options.columnNames ?? {}) });
  }

  async get(id = this.tenant.tenantId): Promise<TenantRecord | undefined> {
    const resource = normalizeResourceId(id);
    const values: unknown[] = [];
    const clauses: string[] = [];
    if (this.tenant.mode === "shared") {
      values.push(this.tenant.tenantId);
      clauses.push(`${this.quote(this.columns.id)} = $1`);
    } else {
      values.push(resource);
      clauses.push(`${this.quote(this.columns.id)} = $1`);
    }
    const rows = await this.queryRows(
      `SELECT ${this.select()} FROM ${this.qualifiedTable()} WHERE ${clauses.join(" AND ")} LIMIT 1`,
      values,
    );
    return rows[0] === undefined ? undefined : this.map(rows[0]);
  }

  async list(query: TenantListQuery = {}): Promise<TenantPage> {
    const limit = normalizeLimit(query.limit);
    const values: unknown[] = [];
    const clauses: string[] = [];
    if (query.status !== undefined) {
      values.push(query.status);
      clauses.push(`LOWER(COALESCE(${this.quote(this.columns.status)}, 'active')) = LOWER($${values.length})`);
    }
    if (query.search !== undefined) {
      values.push(`%${query.search}%`);
      clauses.push(`LOWER(COALESCE(${this.quote(this.columns.id)}, '')) LIKE LOWER($${values.length})`);
    }
    const where = clauses.length === 0 ? "" : ` WHERE ${clauses.join(" AND ")}`;
    const totalRows = await this.queryRows(`SELECT COUNT(*)::int AS "total" FROM ${this.qualifiedTable()}${where}`, values);
    const total = readCount(totalRows[0]?.total);
    const cursor = query.cursor === undefined ? undefined : decodeTenantCursor(query.cursor);
    if (cursor !== undefined) {
      values.push(cursor);
      clauses.push(`${this.quote(this.columns.id)} > $${values.length}`);
    }
    const effectiveWhere = clauses.length === 0 ? "" : ` WHERE ${clauses.join(" AND ")}`;
    const offset = query.cursor === undefined ? Math.max(0, query.offset ?? 0) : 0;
    const rows = await this.queryRows(
      `SELECT ${this.select()} FROM ${this.qualifiedTable()}${effectiveWhere} ORDER BY ${this.quote(this.columns.id)} ASC LIMIT $${values.length + 1}${query.cursor === undefined ? ` OFFSET $${values.length + 2}` : ""}`,
      [...values, limit + 1, ...(query.cursor === undefined ? [offset] : [])],
    );
    const hasMore = query.cursor === undefined ? offset + rows.length < total : rows.length > limit;
    const items = rows.slice(0, limit).map((row) => this.map(row));
    const page: TenantPage = { items, total, hasMore };
    if (hasMore && items.length > 0) page.nextCursor = encodeTenantCursor(items[items.length - 1].id);
    return page;
  }

  async create(input: Partial<TenantRecord> & { id: string; mode?: TenantMode | string; idempotencyKey?: string }): Promise<TenantRecord> {
    if (this.tenant.requireTransactions && typeof this.executor.transaction !== "function") {
      throw new Error("Tenant-scoped writes require a transaction");
    }
    const id = normalizeResourceId(input.id);
    const mode = normalizeTenantMode(input.mode ?? input.isolation ?? input.strategy ?? "fixed");
    if (input.idempotencyKey !== undefined) normalizeIdempotencyKey(input.idempotencyKey);
    const now = new Date();
    const record: TenantRecord = {
      id,
      mode,
      status: input.status ?? "active",
      schemaName: input.schemaName ?? this.tenant.schema,
      version: 1,
      metadata: input.metadata ?? {},
      createdAt: input.createdAt ?? now,
      updatedAt: input.updatedAt ?? now,
    };
    const fields = ["id", "mode", "status", "schemaName", "version", "metadata", "createdAt", "updatedAt"];
    const values = fields.map((field) => storageValue(field, record[field as keyof TenantRecord]));
    const columns = fields.map((field) => this.quote(this.columns[field as keyof TenantSqlColumns]));
    const operation = async (): Promise<TenantRecord> => {
      if (input.idempotencyKey !== undefined) {
        const existing = await this.get(id);
        if (existing !== undefined) return existing;
      }
      const rows = await this.queryRows(
        `INSERT INTO ${this.qualifiedTable()} (${columns.join(", ")}) VALUES (${values.map((_value, index) => `$${index + 1}`).join(", ")}) RETURNING ${this.select()}`,
        values,
      );
      return rows[0] === undefined ? record : this.map(rows[0]);
    };
    return this.runWrite(operation);
  }

  async update(id: string, input: Partial<TenantRecord> & { version?: number; idempotencyKey?: string }): Promise<TenantRecord> {
    if (this.tenant.requireTransactions && typeof this.executor.transaction !== "function") {
      throw new Error("Tenant-scoped writes require a transaction");
    }
    if (input.idempotencyKey !== undefined) normalizeIdempotencyKey(input.idempotencyKey);
    const operation = async (): Promise<TenantRecord> => {
      const current = await this.get(id);
      if (current === undefined) throw new Error("Tenant not found");
      const expectedVersion = input.version ?? current.version;
      const values: Record<string, unknown> = {
        mode: input.mode ?? current.mode,
        status: input.status ?? current.status,
        schemaName: input.schemaName ?? current.schemaName,
        metadata: input.metadata ?? current.metadata,
        updatedAt: new Date(),
        version: current.version + 1,
      };
      const entries = Object.entries(values);
      const where = [`${this.quote(this.columns.id)} = $1`, `${this.quote(this.columns.version)} = $2`];
      const sets = entries.map(([field, value], index) => `${this.quote(this.columns[field as keyof TenantSqlColumns])} = $${index + 3}`);
      const rows = await this.queryRows(
        `UPDATE ${this.qualifiedTable()} SET ${sets.join(", ")} WHERE ${where.join(" AND ")} RETURNING ${this.select()}`,
        [normalizeResourceId(id), expectedVersion, ...entries.map(([field, value]) => storageValue(field, value))],
      );
      if (rows[0] === undefined) throw new Error("Tenant version changed");
      return this.map(rows[0]);
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

  readiness(): Promise<TenantReadiness> {
    return this.isReady().then((ready) => ({
      ready,
      mode: this.tenant.mode,
      rls: !this.tenant.requireRls || ready,
      transactions: !this.tenant.requireTransactions || typeof this.executor.transaction === "function",
      requiredColumns: ready,
      missingColumns: ready ? [] : this.tenant.requireRls ? ["tenant isolation"] : ["tenant table"],
      context: !this.tenant.requireRls || typeof this.executor.transaction === "function",
    }));
  }

  private select(): string {
    return Object.values(this.columns).map((column) => `${this.quote(column)} AS ${this.quote(column)}`).join(", ");
  }

  private qualifiedTable(): string {
    return this.quoteTenantTable();
  }

  private quoteTenantTable(): string {
    return quoteTenantSqlIdentifier(this.table, "tenants table");
  }

  private quote(value: string): string {
    return quoteTenantSqlIdentifier(value, "column");
  }

  private async runWrite<T>(operation: () => Promise<T>): Promise<T> {
    if (typeof this.executor.transaction === "function") return this.withTransaction(operation);
    return operation();
  }

  async withTransaction<T>(operation: (() => Promise<T>) | ((executor: TenantSqlExecutor) => Promise<T>)): Promise<T> {
    if (typeof this.executor.transaction !== "function") {
      throw new Error("Tenant repository transaction is required");
    }
    const active = getTenantTransactionExecutor(this.executor);
    if (active !== undefined) {
      this.scopedExecutors.add(active);
      try {
        await this.setTenantContext(active);
        return await runWithTenantContext({ tenantId: this.tenant.tenantId, mode: this.tenant.mode, executor: active }, async () => {
          if (operation.length > 0) return operation(active);
          return (operation as () => Promise<T>)();
        });
      } finally {
        this.scopedExecutors.delete(active);
      }
    }
    return this.executor.transaction(async (executor) => runWithTenantTransaction(this.executor, executor, async () => {
      this.scopedExecutors.add(executor);
      try {
        await this.setTenantContext(executor);
        return await runWithTenantContext({ tenantId: this.tenant.tenantId, mode: this.tenant.mode, executor }, async () => {
          if (operation.length > 0) return operation(executor);
          return (operation as () => Promise<T>)();
        });
      } finally {
        this.scopedExecutors.delete(executor);
      }
    }));
  }

  async withTenantContext<T>(operation: (executor: TenantSqlExecutor) => Promise<T>): Promise<T> {
    const active = getTenantTransactionExecutor(this.executor);
    if (active !== undefined) {
      this.scopedExecutors.add(active);
      try {
        await this.setTenantContext(active);
        return await runWithTenantContext({ tenantId: this.tenant.tenantId, mode: this.tenant.mode, executor: active }, () => operation(active));
      } finally {
        this.scopedExecutors.delete(active);
      }
    }
    if (!this.tenant.requireRls) return runWithTenantContext({ tenantId: this.tenant.tenantId, mode: this.tenant.mode, executor: this.executor }, () => operation(this.executor));
    if (typeof this.executor.transaction !== "function") throw new Error("Tenant-scoped request context requires a transaction");
    return this.executor.transaction(async (executor) => {
      this.scopedExecutors.add(executor);
      try {
        await this.setTenantContext(executor);
        return await runWithTenantContext({ tenantId: this.tenant.tenantId, mode: this.tenant.mode, executor }, () => operation(executor));
      } finally {
        this.scopedExecutors.delete(executor);
      }
    });
  }

  async setTenantContext(executor: TenantSqlExecutor = getTenantTransactionExecutor(this.executor) ?? this.executor): Promise<void> {
    if (!this.tenant.requireRls) return;
    if (typeof executor.query !== "function") throw new Error("Tenant-scoped request context requires an executor");
    await executor.query("SELECT set_config('app.tenant_id', $1, true)", [this.tenant.tenantId]);
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
    if (rows === undefined) throw new Error("Tenant SQL result failed");
    return rows.filter(isRecord);
  }

  private map(row: Record<string, unknown>): TenantRecord {
    const id = readString(row[this.columns.id] ?? row[this.columns.id.toLowerCase()]);
    if (id === undefined) throw new Error("Invalid tenant row");
    return {
      id,
      mode: normalizeTenantMode(row[this.columns.mode] ?? "fixed"),
      status: readString(row[this.columns.status] ?? "active") ?? "active",
      schemaName: readString(row[this.columns.schemaName] ?? row[this.columns.schemaName.toLowerCase()]),
      version: readNumber(row[this.columns.version] ?? row[this.columns.version.toLowerCase()]) ?? 1,
      metadata: readJson(row[this.columns.metadata] ?? row[this.columns.metadata.toLowerCase()]) ?? {},
      createdAt: readDate(row[this.columns.createdAt] ?? row[this.columns.createdAt.toLowerCase()]),
      updatedAt: readDate(row[this.columns.updatedAt] ?? row[this.columns.updatedAt.toLowerCase()]),
    };
  }
}

export function createTenantRepository(
  input: TenantSqlRepositoryOptions | TenantSqlExecutor | TenantSqlQuery,
  options: Omit<TenantSqlRepositoryOptions, "executor" | "query"> = {},
): SqlTenantRepository {
  return new SqlTenantRepository(input as TenantSqlRepositoryOptions, options);
}

function hasTenantRepositoryOptions(value: object): boolean {
  return ["tenantId", "tenant", "tenantConfig", "mode", "tenantColumn", "schema", "requireRls", "requireTransactions", "table", "tables", "tableNames", "columns", "columnNames", "sharedExecutor", "dedicatedExecutor", "fallbackExecutor", "allowSharedFallback"].some((key) => Object.prototype.hasOwnProperty.call(value, key));
}

function assertNoDedicatedFallback(options: TenantSqlRepositoryOptions): void {
  const configuredMode = options.tenant?.mode ?? options.tenantConfig?.mode ?? options.mode;
  const mode = normalizeTenantMode(configuredMode);
  if (mode !== "dedicated") return;
  if (options.allowSharedFallback === true || options.sharedExecutor !== undefined || options.fallbackExecutor !== undefined) {
    throw new TypeError("Dedicated tenant mode cannot use a shared pool fallback");
  }
}

function normalizeRepositoryOptions(
  input: TenantSqlRepositoryOptions | TenantSqlExecutor | TenantSqlQuery,
  second: Omit<TenantSqlRepositoryOptions, "executor" | "query">,
): TenantSqlRepositoryOptions {
  if (typeof input === "function") return { ...second, query: input };
  if (isExecutor(input) && !hasTenantRepositoryOptions(input)) return { ...second, executor: input };
  return { ...input, ...second };
}

function normalizeExecutor(options: TenantSqlRepositoryOptions, mode: TenantMode): TenantSqlExecutor {
  if (options.executor && typeof options.executor.query === "function") return options.executor;
  if (typeof options.query === "function") return { query: options.query };
  if (mode === "shared" && options.sharedExecutor && typeof options.sharedExecutor.query === "function") return options.sharedExecutor;
  if (mode === "dedicated" && options.dedicatedExecutor && typeof options.dedicatedExecutor.query === "function") return options.dedicatedExecutor;
  throw new TypeError("A tenant SQL query executor is required");
}

function normalizeColumns(columns: Partial<TenantSqlColumns>): TenantSqlColumns {
  return {
    id: validateTenantSqlIdentifier(columns.id ?? DEFAULT_TENANT_SQL_COLUMNS.id, "tenant id column"),
    mode: validateTenantSqlIdentifier(columns.mode ?? DEFAULT_TENANT_SQL_COLUMNS.mode, "tenant mode column"),
    status: validateTenantSqlIdentifier(columns.status ?? DEFAULT_TENANT_SQL_COLUMNS.status, "tenant status column"),
    schemaName: validateTenantSqlIdentifier(columns.schemaName ?? DEFAULT_TENANT_SQL_COLUMNS.schemaName, "tenant schema column"),
    version: validateTenantSqlIdentifier(columns.version ?? DEFAULT_TENANT_SQL_COLUMNS.version, "tenant version column"),
    metadata: validateTenantSqlIdentifier(columns.metadata ?? DEFAULT_TENANT_SQL_COLUMNS.metadata, "tenant metadata column"),
    createdAt: validateTenantSqlIdentifier(columns.createdAt ?? DEFAULT_TENANT_SQL_COLUMNS.createdAt, "tenant created_at column"),
    updatedAt: validateTenantSqlIdentifier(columns.updatedAt ?? DEFAULT_TENANT_SQL_COLUMNS.updatedAt, "tenant updated_at column"),
  };
}

function addColumn(table: string, column: string, definition: string): string | undefined {
  if (!column) return undefined;
  return `ALTER TABLE ${quoteTenantSqlIdentifier(table)} ADD COLUMN IF NOT EXISTS ${quoteTenantSqlIdentifier(column)} ${definition}`;
}

function unqualified(value: string): string {
  return value.split(".").at(-1) ?? value;
}

function normalizeResourceId(value: unknown): string {
  if (typeof value !== "string") throw new TypeError("Resource id must be a string");
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 512 || /[:\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new TypeError("Invalid resource id");
  }
  return normalized;
}

function normalizeIdempotencyKey(value: unknown): string {
  if (typeof value !== "string") throw new TypeError("Idempotency key must be a string");
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 256 || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new TypeError("Invalid idempotency key");
  }
  return normalized;
}

function normalizeLimit(value: unknown): number {
  if (value === undefined) return 20;
  const normalized = typeof value === "number" ? value : Number(value);
  if (!Number.isSafeInteger(normalized) || normalized < 1 || normalized > 100) throw new TypeError("Invalid tenant page limit");
  return normalized;
}

function storageValue(field: string, value: unknown): unknown {
  if (field === "metadata") return JSON.stringify(value ?? {});
  return value;
}

function encodeTenantCursor(id: string): string {
  return Buffer.from(JSON.stringify({ version: 1, id }), "utf8").toString("base64url");
}

function decodeTenantCursor(value: string): string {
  try {
    const parsed = JSON.parse(Buffer.from(value, "base64url").toString("utf8")) as { version?: unknown; id?: unknown };
    if (parsed.version !== 1 || typeof parsed.id !== "string") throw new Error("invalid cursor");
    return normalizeResourceId(parsed.id);
  } catch {
    throw new TypeError("Invalid tenant pagination cursor");
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
  const parsed = readNumber(value);
  return parsed === undefined ? 0 : parsed;
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
