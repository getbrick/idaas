import {
  normalizeCommerceIdempotencyEntry,
  normalizeCommerceIdempotencyRecord,
  normalizeCommerceIdempotencyScope,
  normalizeRetentionMs,
  type CommerceIdempotencyEntry,
  type CommerceIdempotencyPort,
  type CommerceIdempotencyRecord,
  type CommerceIdempotencyScope,
} from "../idempotency.js";
import {
  CommerceSqlRuntime,
  createCommerceSqlRuntime,
  rowValue,
  validateCommerceSqlIdentifier,
  type CommerceSqlRepositoryInput,
  type CommerceSqlRepositorySecondOptions,
} from "./adapter.js";
import {
  COMMERCE_IDEMPOTENCY_COLUMNS,
  COMMERCE_IDEMPOTENCY_FIELDS,
  COMMERCE_IDEMPOTENCY_TABLE,
  OPEN_COMMERCE_IDEMPOTENCY_MIGRATION_NAME,
  OPEN_COMMERCE_IDEMPOTENCY_MIGRATION_VERSION,
  type CommerceIdempotencySqlField,
} from "./migration.js";
import { commerceResourceConflict } from "../errors.js";
import type { CommerceDependencyReadiness } from "../types.js";
import { qualifyTenantTable } from "../../../tenant.js";

export interface SqlCommerceIdempotencyStoreOptions
  extends CommerceSqlRepositorySecondOptions {
  readonly retentionMs?: number;
  readonly table?: string;
}

export type SqlCommerceIdempotencyInput = CommerceSqlRepositoryInput;

export class SqlCommerceIdempotencyStore implements CommerceIdempotencyPort {
  readonly productionReady = true;
  readonly retentionMs: number;
  readonly readiness: CommerceDependencyReadiness;
  private readonly runtime: CommerceSqlRuntime;
  private readonly table: string;

  constructor(options?: SqlCommerceIdempotencyStoreOptions);
  constructor(input: SqlCommerceIdempotencyInput, options?: SqlCommerceIdempotencyStoreOptions);
  constructor(
    input: SqlCommerceIdempotencyInput = {},
    options: SqlCommerceIdempotencyStoreOptions = {},
  ) {
    this.runtime = createCommerceSqlRuntime(input, options);
    this.retentionMs = normalizeRetentionMs(options.retentionMs);
    this.table = quoteCommerceIdempotencyTable(
      validateCommerceSqlIdentifier(
        options.table ?? COMMERCE_IDEMPOTENCY_TABLE,
        "commerce idempotency table",
      ),
      this.runtime.tenant.schema,
    );
    this.readiness = Object.freeze({
      storage: "persistent" as const,
      distributed: this.runtime.distributed,
      ready: async () => {
        if (!this.runtime.distributed) return false;
        try {
          await this.runtime.queryRows(`SELECT 1 FROM ${this.table} LIMIT 0`, []);
          return true;
        } catch {
          return false;
        }
      },
    });
  }

  async get(
    scope: CommerceIdempotencyScope,
  ): Promise<CommerceIdempotencyRecord | undefined> {
    const normalized = normalizeCommerceIdempotencyScope(scope);
    const rows = await this.runtime.queryRows(
      `SELECT ${this.selectColumns()} FROM ${this.table} WHERE ${this.matchColumns()} AND ${this.column("expiresAt")} > $5`,
      [...this.scopeValues(normalized), new Date().toISOString()],
    );
    const row = rows[0];
    if (row === undefined) return undefined;
    return readIdempotencyRow(row);
  }

  async put(entry: CommerceIdempotencyEntry): Promise<CommerceIdempotencyRecord> {
    const normalized = normalizeCommerceIdempotencyEntry(entry, this.retentionMs);
    const result = await this.runtime.executeMutation(
      `INSERT INTO ${this.table} (${this.insertColumns()}) VALUES (${this.insertPlaceholders()}) ` +
        `ON CONFLICT (${this.conflictColumns()}) DO UPDATE SET ` +
        `${this.column("requestHash")} = EXCLUDED.${this.column("requestHash")}, ` +
        `${this.column("result")} = EXCLUDED.${this.column("result")}, ` +
        `${this.column("createdAt")} = EXCLUDED.${this.column("createdAt")}, ` +
        `${this.column("expiresAt")} = EXCLUDED.${this.column("expiresAt")} ` +
        `RETURNING ${this.selectColumns()}`,
      [
        ...this.scopeValues(normalized.scope),
        normalized.requestHash,
        JSON.stringify(normalized.value ?? null),
        normalized.createdAt,
        normalized.expiresAt,
      ],
    );
    const row = result.rows[0];
    if (row === undefined) {
      throw commerceResourceConflict("Commerce idempotency result could not be stored");
    }
    return readIdempotencyRow(row);
  }

  async delete(scope: CommerceIdempotencyScope): Promise<boolean> {
    const normalized = normalizeCommerceIdempotencyScope(scope);
    const result = await this.runtime.executeMutation(
      `DELETE FROM ${this.table} WHERE ${this.matchColumns()}`,
      this.scopeValues(normalized),
    );
    return result.affected > 0;
  }

  async prune(): Promise<number> {
    const result = await this.runtime.executeMutation(
      `DELETE FROM ${this.table} WHERE ${this.column("expiresAt")} <= $1`,
      [new Date().toISOString()],
    );
    return result.affected;
  }

  private column(field: CommerceIdempotencySqlField): string {
    return `"${COMMERCE_IDEMPOTENCY_COLUMNS[field]}"`;
  }

  private selectColumns(): string {
    return COMMERCE_IDEMPOTENCY_FIELDS
      .map((field) => `${this.column(field)} AS "${field}"`)
      .join(", ");
  }

  private insertColumns(): string {
    return [
      this.column("tenantId"),
      this.column("actorId"),
      this.column("operation"),
      this.column("key"),
      this.column("requestHash"),
      this.column("result"),
      this.column("createdAt"),
      this.column("expiresAt"),
    ].join(", ");
  }

  private insertPlaceholders(): string {
    return Array.from({ length: 8 }, (_value, index) => `$${index + 1}`).join(", ");
  }

  private conflictColumns(): string {
    return [
      this.column("tenantId"),
      this.column("actorId"),
      this.column("operation"),
      this.column("key"),
    ].join(", ");
  }

  private matchColumns(): string {
    return [
      `${this.column("tenantId")} = $1`,
      `${this.column("actorId")} = $2`,
      `${this.column("operation")} = $3`,
      `${this.column("key")} = $4`,
    ].join(" AND ");
  }

  private scopeValues(scope: CommerceIdempotencyScope): unknown[] {
    return [scope.tenantId, scope.actorId, scope.operation, scope.key];
  }
}

export function createSqlCommerceIdempotencyStore(
  options?: SqlCommerceIdempotencyStoreOptions,
): SqlCommerceIdempotencyStore;
export function createSqlCommerceIdempotencyStore(
  input: SqlCommerceIdempotencyInput,
  options?: SqlCommerceIdempotencyStoreOptions,
): SqlCommerceIdempotencyStore;
export function createSqlCommerceIdempotencyStore(
  input: SqlCommerceIdempotencyInput = {},
  options: SqlCommerceIdempotencyStoreOptions = {},
): SqlCommerceIdempotencyStore {
  return new SqlCommerceIdempotencyStore(input as SqlCommerceIdempotencyInput, options);
}

export const createPostgresCommerceIdempotencyStore = createSqlCommerceIdempotencyStore;
export const createPersistentCommerceIdempotencyStore = createSqlCommerceIdempotencyStore;
export const createCommerceIdempotencyStore = createSqlCommerceIdempotencyStore;
export const createOpenCommerceIdempotencyStore = createSqlCommerceIdempotencyStore;
export const createOpenPlatformCommerceIdempotencyStore = createSqlCommerceIdempotencyStore;

export const SqlOpenCommerceIdempotencyStore = SqlCommerceIdempotencyStore;
export const CommerceSqlIdempotencyStore = SqlCommerceIdempotencyStore;
export const SQL_COMMERCE_IDEMPOTENCY_MIGRATION_VERSION =
  OPEN_COMMERCE_IDEMPOTENCY_MIGRATION_VERSION;
export const SQL_COMMERCE_IDEMPOTENCY_MIGRATION_NAME =
  OPEN_COMMERCE_IDEMPOTENCY_MIGRATION_NAME;

function quoteCommerceIdempotencyTable(table: string, schema: string): string {
  return qualifyTenantTable(table, schema)
    .split(".")
    .map((segment) => `"${segment}"`)
    .join(".");
}

function readIdempotencyRow(
  row: Record<string, unknown>,
): CommerceIdempotencyRecord {
  const result = rowValue(row, "result");
  return normalizeCommerceIdempotencyRecord({
    scope: {
      tenantId: readRowText(row, "tenantId"),
      actorId: readRowText(row, "actorId"),
      operation: readRowText(row, "operation"),
      key: readRowText(row, "key"),
    },
    requestHash: readRowText(row, "requestHash"),
    value: result === null || result === undefined ? null : result,
    createdAt: readRowText(row, "createdAt"),
    expiresAt: readRowText(row, "expiresAt"),
  });
}

function readRowText(row: Record<string, unknown>, field: string): string {
  const value = rowValue(row, field);
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Invalid commerce idempotency SQL row: ${field}`);
  }
  return value;
}
