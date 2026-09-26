import { createHash, randomUUID } from "node:crypto";

export const DEFAULT_MIGRATION_TABLE = "gb_idaas_schema_migration";
export const DEFAULT_MIGRATION_LOCK_TABLE = "gb_idaas_schema_migration_lock";

export interface MigrationSqlExecutor {
  query(text: string, values?: unknown[]): unknown | Promise<unknown>;
  transaction?<T>(callback: (executor: MigrationSqlExecutor) => Promise<T>): Promise<T>;
}

export type MigrationSqlQuery = MigrationSqlExecutor["query"];

export interface MigrationDefinition {
  version: number;
  name: string;
  sql: string;
  checksum?: string;
  metadata?: Record<string, unknown>;
  scope?: string;
  additive?: boolean;
  requires?: readonly number[];
  supersedes?: readonly number[];
}

export interface MigrationSeries {
  migrations: readonly MigrationDefinition[];
  additive: boolean;
  preserveChecksums: boolean;
}

export interface MigrationDefinitionOptions {
  additive?: boolean;
  requires?: readonly number[];
  supersedes?: readonly number[];
}

export interface NormalizedMigrationDefinition {
  version: number;
  name: string;
  sql: string;
  checksum: string;
  metadata: Record<string, unknown>;
  scope: string;
  additive?: boolean;
  requires?: readonly number[];
  supersedes?: readonly number[];
}

export interface MigrationCoordinatorOptions {
  tableName?: string;
  historyTable?: string;
  lockTableName?: string;
  lockTable?: string;
  lockKey?: string | number;
  lockNamespace?: string;
  scope?: string;
  tenantId?: string;
  mode?: string;
  ownerId?: string;
  requireTransaction?: boolean;
  clock?: () => Date;
  allowSharedFallback?: boolean;
  sharedExecutor?: MigrationSqlExecutor;
  fallbackExecutor?: MigrationSqlExecutor;
}

export interface MigrationPlanEntry extends NormalizedMigrationDefinition {
  applied: boolean;
}

export interface MigrationDryRunResult {
  dryRun: true;
  atomic: boolean;
  lock: {
    key: string;
    scope: string;
    ownerId: string;
  };
  migrations: MigrationPlanEntry[];
  checksum: string;
}

export interface AppliedMigrationResult extends NormalizedMigrationDefinition {
  appliedAt: string;
  executionMs: number;
}

export interface MigrationRunResult {
  dryRun: false;
  atomic: boolean;
  lock: {
    key: string;
    scope: string;
    ownerId: string;
    acquiredAt: string;
    releasedAt?: string;
  };
  applied: AppliedMigrationResult[];
  skipped: MigrationPlanEntry[];
  checksum: string;
}

export interface MigrationLockStatus {
  key: string;
  scope: string;
  ownerId: string;
  acquiredAt?: string;
  heartbeatAt?: string;
  releasedAt?: string;
  metadata?: Record<string, unknown>;
}

export interface MigrationStatus {
  version: number;
  scope: string;
  name: string;
  checksum: string;
  appliedAt?: string;
  executionMs?: number;
  lockKey?: string;
  lockedAt?: string;
  lockedBy?: string;
  metadata?: Record<string, unknown>;
}

export function createMigrationMetadataSql(
  options: Pick<MigrationCoordinatorOptions, "tableName" | "historyTable" | "lockTableName" | "lockTable"> = {},
): string {
  const historyTable = validateIdentifier(options.tableName ?? options.historyTable ?? DEFAULT_MIGRATION_TABLE, "migration history table");
  const lockTable = validateIdentifier(options.lockTableName ?? options.lockTable ?? DEFAULT_MIGRATION_LOCK_TABLE, "migration lock table");
  const quote = (value: string): string => quoteIdentifier(value, "migration column");
  const historyRegclass = quoteIdentifier(historyTable);
  const lockRegclass = quoteIdentifier(lockTable);
  return [
    `CREATE TABLE IF NOT EXISTS ${quoteIdentifier(historyTable)} (${[
      `${quote("scope")} TEXT NOT NULL`,
      `${quote("version")} INTEGER NOT NULL`,
      `${quote("name")} TEXT NOT NULL`,
      `${quote("checksum")} TEXT NOT NULL`,
      `${quote("applied_at")} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
      `${quote("execution_ms")} INTEGER NOT NULL DEFAULT 0`,
      `${quote("lock_key")} TEXT NOT NULL`,
      `${quote("locked_at")} TIMESTAMPTZ NOT NULL`,
      `${quote("locked_by")} TEXT NOT NULL`,
      `${quote("metadata")} JSONB NOT NULL DEFAULT '{}'::jsonb`,
      `PRIMARY KEY (${quote("scope")}, ${quote("version")})`,
    ].join(", ")})`,
    `ALTER TABLE ${quoteIdentifier(historyTable)} ADD COLUMN IF NOT EXISTS ${quote("scope")} TEXT NOT NULL DEFAULT 'legacy'`,
    `ALTER TABLE ${quoteIdentifier(historyTable)} ADD COLUMN IF NOT EXISTS ${quote("version")} INTEGER NOT NULL DEFAULT 0`,
    `ALTER TABLE ${quoteIdentifier(historyTable)} ADD COLUMN IF NOT EXISTS ${quote("name")} TEXT NOT NULL DEFAULT 'legacy'`,
    `ALTER TABLE ${quoteIdentifier(historyTable)} ADD COLUMN IF NOT EXISTS ${quote("checksum")} TEXT NOT NULL DEFAULT ''`,
    `ALTER TABLE ${quoteIdentifier(historyTable)} ADD COLUMN IF NOT EXISTS ${quote("applied_at")} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `ALTER TABLE ${quoteIdentifier(historyTable)} ADD COLUMN IF NOT EXISTS ${quote("execution_ms")} INTEGER NOT NULL DEFAULT 0`,
    `ALTER TABLE ${quoteIdentifier(historyTable)} ADD COLUMN IF NOT EXISTS ${quote("lock_key")} TEXT NOT NULL DEFAULT 'legacy'`,
    `ALTER TABLE ${quoteIdentifier(historyTable)} ADD COLUMN IF NOT EXISTS ${quote("locked_at")} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `ALTER TABLE ${quoteIdentifier(historyTable)} ADD COLUMN IF NOT EXISTS ${quote("locked_by")} TEXT NOT NULL DEFAULT 'legacy'`,
    `ALTER TABLE ${quoteIdentifier(historyTable)} ADD COLUMN IF NOT EXISTS ${quote("metadata")} JSONB NOT NULL DEFAULT '{}'::jsonb`,
    `UPDATE ${quoteIdentifier(historyTable)} SET ${quoteIdentifier("scope")} = 'legacy' WHERE ${quoteIdentifier("scope")} IS NULL`,
    `WITH migration_base AS (SELECT COALESCE(MAX(${quoteIdentifier("version")}), 0) AS max_version FROM ${quoteIdentifier(historyTable)}), migration_numbered AS (SELECT t.ctid, migration_base.max_version + ROW_NUMBER() OVER (ORDER BY t.ctid) AS next_version FROM ${quoteIdentifier(historyTable)} t CROSS JOIN migration_base WHERE t.${quoteIdentifier("version")} IS NULL OR t.${quoteIdentifier("version")} = 0) UPDATE ${quoteIdentifier(historyTable)} t SET ${quoteIdentifier("version")} = migration_numbered.next_version FROM migration_numbered WHERE t.ctid = migration_numbered.ctid`,
    `DO $$ DECLARE legacy_constraint_name text; BEGIN SELECT conname INTO legacy_constraint_name FROM pg_constraint WHERE conrelid = '${historyRegclass}'::regclass AND contype = 'p' AND pg_get_constraintdef(oid) NOT LIKE '%scope%' LIMIT 1; IF legacy_constraint_name IS NOT NULL THEN EXECUTE format('ALTER TABLE ${quoteIdentifier(historyTable)} DROP CONSTRAINT %I', legacy_constraint_name); END IF; IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = '${historyRegclass}'::regclass AND contype = 'p' AND pg_get_constraintdef(oid) LIKE '%scope%') THEN ALTER TABLE ${quoteIdentifier(historyTable)} ADD PRIMARY KEY (${quote("scope")}, ${quote("version")}); END IF; END $$`,
    `CREATE INDEX IF NOT EXISTS ${quoteIdentifier(migrationObjectName(historyTable, "scope_idx"))} ON ${quoteIdentifier(historyTable)} (${quote("scope")}, ${quote("version")})`,
    `CREATE TABLE IF NOT EXISTS ${quoteIdentifier(lockTable)} (${[
      `${quote("scope")} TEXT NOT NULL`,
      `${quote("lock_key")} TEXT NOT NULL`,
      `${quote("owner_id")} TEXT NOT NULL`,
      `${quote("acquired_at")} TIMESTAMPTZ NOT NULL`,
      `${quote("heartbeat_at")} TIMESTAMPTZ NOT NULL`,
      `${quote("released_at")} TIMESTAMPTZ`,
      `${quote("metadata")} JSONB NOT NULL DEFAULT '{}'::jsonb`,
      `PRIMARY KEY (${quote("scope")}, ${quote("lock_key")})`,
    ].join(", ")})`,
    `ALTER TABLE ${quoteIdentifier(lockTable)} ADD COLUMN IF NOT EXISTS ${quote("scope")} TEXT NOT NULL DEFAULT 'legacy'`,
    `ALTER TABLE ${quoteIdentifier(lockTable)} ADD COLUMN IF NOT EXISTS ${quote("lock_key")} TEXT NOT NULL DEFAULT 'legacy'`,
    `ALTER TABLE ${quoteIdentifier(lockTable)} ADD COLUMN IF NOT EXISTS ${quote("owner_id")} TEXT NOT NULL DEFAULT 'legacy'`,
    `ALTER TABLE ${quoteIdentifier(lockTable)} ADD COLUMN IF NOT EXISTS ${quote("acquired_at")} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `ALTER TABLE ${quoteIdentifier(lockTable)} ADD COLUMN IF NOT EXISTS ${quote("heartbeat_at")} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `ALTER TABLE ${quoteIdentifier(lockTable)} ADD COLUMN IF NOT EXISTS ${quote("released_at")} TIMESTAMPTZ`,
    `ALTER TABLE ${quoteIdentifier(lockTable)} ADD COLUMN IF NOT EXISTS ${quote("metadata")} JSONB NOT NULL DEFAULT '{}'::jsonb`,
    `UPDATE ${quoteIdentifier(lockTable)} SET ${quoteIdentifier("scope")} = 'legacy' WHERE ${quoteIdentifier("scope")} IS NULL`,
    `UPDATE ${quoteIdentifier(lockTable)} SET ${quoteIdentifier("lock_key")} = 'legacy-' || md5(ctid::text) WHERE ${quoteIdentifier("lock_key")} IS NULL OR (${quoteIdentifier("lock_key")} = 'legacy' AND ctid IS DISTINCT FROM (SELECT ctid FROM ${quoteIdentifier(lockTable)} WHERE ${quoteIdentifier("lock_key")} = 'legacy' LIMIT 1))`,
    `DO $$ DECLARE legacy_constraint_name text; BEGIN SELECT conname INTO legacy_constraint_name FROM pg_constraint WHERE conrelid = '${lockRegclass}'::regclass AND contype = 'p' AND pg_get_constraintdef(oid) NOT LIKE '%scope%' LIMIT 1; IF legacy_constraint_name IS NOT NULL THEN EXECUTE format('ALTER TABLE ${quoteIdentifier(lockTable)} DROP CONSTRAINT %I', legacy_constraint_name); END IF; IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = '${lockRegclass}'::regclass AND contype = 'p' AND pg_get_constraintdef(oid) LIKE '%scope%') THEN ALTER TABLE ${quoteIdentifier(lockTable)} ADD PRIMARY KEY (${quote("scope")}, ${quote("lock_key")}); END IF; END $$`,
    `CREATE INDEX IF NOT EXISTS ${quoteIdentifier(migrationObjectName(lockTable, "scope_idx"))} ON ${quoteIdentifier(lockTable)} (${quote("scope")}, ${quote("lock_key")})`,
  ].join(";\n");
}

export class MigrationCoordinator {
  readonly executor: MigrationSqlExecutor;
  readonly options: MigrationCoordinatorOptions & {
    tableName: string;
    lockTableName: string;
    lockKey: string;
    lockNamespace: string;
    scope: string;
    ownerId: string;
    requireTransaction: boolean;
    clock: () => Date;
  };
  readonly migrations: readonly MigrationDefinition[];

  private readonly historyTable: string;
  private readonly lockTable: string;
  private readonly lockKey: string;
  private readonly lockNamespace: string;
  private readonly scope: string;
  private readonly ownerId: string;

  constructor(
    executor: MigrationSqlExecutor,
    options?: MigrationCoordinatorOptions,
  );
  constructor(
    executor: MigrationSqlExecutor,
    migrations: readonly MigrationDefinition[],
    options?: MigrationCoordinatorOptions,
  );
  constructor(
    executor: MigrationSqlExecutor,
    migrationsOrOptions: readonly MigrationDefinition[] | MigrationCoordinatorOptions = {},
    maybeOptions: MigrationCoordinatorOptions = {},
  ) {
    this.executor = normalizeExecutor(executor);
    const migrations: readonly MigrationDefinition[] = Array.isArray(migrationsOrOptions) ? migrationsOrOptions : [];
    const options: MigrationCoordinatorOptions = Array.isArray(migrationsOrOptions)
      ? maybeOptions
      : migrationsOrOptions as MigrationCoordinatorOptions;
    assertMigrationScopeOptions(options);
    this.migrations = migrations;
    const inferredScope = options.scope === undefined && migrations.length > 0 && migrations.every((migration) => typeof migration.scope === "string")
      ? migrations[0].scope
      : undefined;
    const defaultScope = options.scope ?? inferredScope ?? migrationScope(options.tenantId, options.mode);
    this.options = {
      tableName: options.tableName ?? options.historyTable ?? DEFAULT_MIGRATION_TABLE,
      lockTableName: options.lockTableName ?? options.lockTable ?? DEFAULT_MIGRATION_LOCK_TABLE,
      lockKey: normalizeLockKey(options.lockKey ?? "getbrick-idaas-schema"),
      lockNamespace: normalizeLockKey(options.lockNamespace ?? defaultScope),
      scope: normalizeScope(defaultScope),
      ownerId: normalizeOwnerId(options.ownerId),
      requireTransaction: options.requireTransaction ?? true,
      clock: options.clock ?? (() => new Date()),
    };
    this.historyTable = validateIdentifier(this.options.tableName, "migration history table");
    this.lockTable = validateIdentifier(this.options.lockTableName, "migration lock table");
    this.lockKey = String(this.options.lockKey);
    this.lockNamespace = this.options.lockNamespace;
    this.scope = this.options.scope;
    this.ownerId = this.options.ownerId;
  }

  plan(definitions: readonly MigrationDefinition[] = this.migrations): MigrationPlanEntry[] {
    return normalizeDefinitions(definitions, this.scope).map((migration) => ({ ...migration, applied: false }));
  }

  checksum(definitions: readonly MigrationDefinition[] = this.migrations): string {
    return checksumDefinitions(normalizeDefinitions(definitions, this.scope));
  }

  dryRun(definitions: readonly MigrationDefinition[] = this.migrations): MigrationDryRunResult {
    const migrations = normalizeDefinitions(definitions, this.scope);
    return {
      dryRun: true,
      atomic: typeof this.executor.transaction === "function",
      lock: { key: this.lockKey, scope: this.scope, ownerId: this.ownerId },
      migrations: migrations.map((migration) => ({ ...migration, applied: false })),
      checksum: migrations.length === 1 ? migrations[0].checksum : checksumDefinitions(migrations),
    };
  }

  async run(definitions: readonly MigrationDefinition[] = this.migrations): Promise<MigrationRunResult> {
    const migrations = normalizeDefinitions(definitions, this.scope);
    for (const migration of migrations) {
      if (migration.scope !== this.scope) throw new Error(`Migration scope mismatch for version ${migration.version}`);
    }
    if (migrations.length === 0) {
      return {
        dryRun: false,
        atomic: typeof this.executor.transaction === "function",
        lock: { key: this.lockKey, scope: this.scope, ownerId: this.ownerId, acquiredAt: this.nowIso(), releasedAt: this.nowIso() },
        applied: [],
        skipped: [],
        checksum: checksumDefinitions(migrations),
      };
    }
    if (this.options.requireTransaction && typeof this.executor.transaction !== "function") {
      throw new Error("Migration execution requires a transaction-capable PostgreSQL executor");
    }
    const operation = async (executor: MigrationSqlExecutor, atomic: boolean): Promise<MigrationRunResult> => {
      const acquiredAt = this.nowIso();
      let lockHeld = false;
      try {
        await executor.query(this.metadataSql());
        await this.acquireLock(executor, acquiredAt, atomic);
        lockHeld = true;
        const existing = await this.readHistory(executor);
        const existingByVersion = new Map(existing.map((item) => [`${item.scope}:${item.version}`, item] as const));
        for (const migration of migrations) {
          const previous = existingByVersion.get(`${this.scope}:${migration.version}`);
          if (previous !== undefined) {
            if (previous.name !== migration.name) {
              throw new Error(`Migration name mismatch for version ${migration.version}`);
            }
            if (normalizeChecksum(previous.checksum) !== migration.checksum) {
              throw new Error(`Migration checksum mismatch for version ${migration.version}`);
            }
          }
        }
        for (const migration of migrations) {
          for (const requiredVersion of migration.requires ?? []) {
            const requiredInBatch = migrations.some((candidate) => candidate.version === requiredVersion);
            const requiredApplied = existingByVersion.has(`${this.scope}:${requiredVersion}`);
            if (!requiredInBatch && !requiredApplied) {
              throw new Error(`Migration ${migration.version} requires applied migration ${requiredVersion}`);
            }
          }
        }
        const applied: AppliedMigrationResult[] = [];
        const skipped: MigrationPlanEntry[] = [];
        for (const migration of migrations) {
          const previous = existingByVersion.get(`${this.scope}:${migration.version}`);
          if (previous !== undefined) {
            skipped.push({ ...migration, applied: true });
            continue;
          }
          const started = Date.now();
          await executor.query(migration.sql);
          const executionMs = Date.now() - started;
          const appliedAt = this.nowIso();
          await executor.query(
             `INSERT INTO ${this.qualifiedHistoryTable()} (${[
               "version",
               "name",
               "checksum",
               "applied_at",
               "execution_ms",
               "lock_key",
               "locked_at",
               "locked_by",
               "metadata",
               "scope",
             ].map((column) => this.quote(column)).join(", ")}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10) ON CONFLICT (${this.quote("scope")}, ${this.quote("version")}) DO NOTHING`,
             [
               migration.version,
               migration.name,
               migration.checksum,
               appliedAt,
               executionMs,
               this.lockKey,
               acquiredAt,
               this.ownerId,
               JSON.stringify(migration.metadata),
               this.scope,
             ],
          );
          await this.heartbeatLock(executor);
          applied.push({ ...migration, appliedAt, executionMs });
        }
        const releasedAt = this.nowIso();
        await this.releaseLock(executor, releasedAt, atomic);
        lockHeld = false;
        return {
          dryRun: false,
          atomic,
          lock: { key: this.lockKey, scope: this.scope, ownerId: this.ownerId, acquiredAt, releasedAt },
          applied,
          skipped,
          checksum: migrations.length === 1 ? migrations[0].checksum : checksumDefinitions(migrations),
        };
      } finally {
        if (lockHeld) {
          try {
            await this.releaseLock(executor, this.nowIso(), atomic);
          } catch {
            undefined;
          }
        }
      }
    };
    if (typeof this.executor.transaction === "function") {
      return this.executor.transaction((executor) => operation(executor, true));
    }
    return operation(this.executor, false);
  }

  async status(): Promise<MigrationStatus[]> {
    return this.readHistory(this.executor);
  }

  async lockStatus(): Promise<MigrationLockStatus | undefined> {
    const result = await this.executor.query(
      `SELECT ${["scope", "lock_key", "owner_id", "acquired_at", "heartbeat_at", "released_at", "metadata"].map((column) => this.quote(column)).join(", ")} FROM ${this.qualifiedLockTable()} WHERE ${this.quote("scope")} = $1 AND ${this.quote("lock_key")} = $2`,
      [this.scope, this.lockKey],
    );
    const row = resultRows(result)?.find(isRecord);
    if (row === undefined) return undefined;
    return {
      scope: readString(row.scope) ?? this.scope,
      key: readString(row.lock_key) ?? this.lockKey,
      ownerId: readString(row.owner_id) ?? "",
      acquiredAt: readString(row.acquired_at),
      heartbeatAt: readString(row.heartbeat_at),
      releasedAt: readString(row.released_at),
      metadata: readJson(row.metadata),
    };
  }

  private async acquireLock(executor: MigrationSqlExecutor, acquiredAt: string, atomic: boolean): Promise<void> {
    const functionName = atomic ? "pg_advisory_xact_lock" : "pg_advisory_lock";
    await executor.query(`SELECT ${functionName}(hashtextextended($1, 0))`, [`${this.lockNamespace}:${this.lockKey}`]);
    await executor.query(
      `INSERT INTO ${this.qualifiedLockTable()} (${[
        "scope",
        "lock_key",
        "owner_id",
        "acquired_at",
        "heartbeat_at",
        "released_at",
        "metadata",
      ].map((column) => this.quote(column)).join(", ")}) VALUES ($1, $2, $3, $4, $4, NULL, $5::jsonb) ON CONFLICT (${this.quote("scope")}, ${this.quote("lock_key")}) DO UPDATE SET ${[
        "owner_id",
        "acquired_at",
        "heartbeat_at",
        "released_at",
      ].map((column) => `${this.quote(column)} = EXCLUDED.${this.quote(column)}`).join(", ")}, ${this.quote("metadata")} = EXCLUDED.${this.quote("metadata")}`,
      [this.scope, this.lockKey, this.ownerId, acquiredAt, JSON.stringify({ ownerId: this.ownerId, scope: this.scope, atomic })],
    );
  }

  private async heartbeatLock(executor: MigrationSqlExecutor): Promise<void> {
    await executor.query(
      `UPDATE ${this.qualifiedLockTable()} SET ${this.quote("heartbeat_at")} = CURRENT_TIMESTAMP WHERE ${this.quote("scope")} = $1 AND ${this.quote("lock_key")} = $2 AND ${this.quote("owner_id")} = $3`,
      [this.scope, this.lockKey, this.ownerId],
    );
  }

  private async releaseLock(executor: MigrationSqlExecutor, releasedAt: string, atomic: boolean): Promise<void> {
    await executor.query(
      `UPDATE ${this.qualifiedLockTable()} SET ${this.quote("released_at")} = $1, ${this.quote("heartbeat_at")} = $1 WHERE ${this.quote("scope")} = $2 AND ${this.quote("lock_key")} = $3 AND ${this.quote("owner_id")} = $4`,
      [releasedAt, this.scope, this.lockKey, this.ownerId],
    );
    if (!atomic) await executor.query(`SELECT pg_advisory_unlock(hashtextextended($1, 0))`, [`${this.lockNamespace}:${this.lockKey}`]);
  }

  private async readHistory(executor: MigrationSqlExecutor): Promise<MigrationStatus[]> {
    const result = await executor.query(
      `SELECT ${[
        "scope",
        "version",
        "name",
        "checksum",
        "applied_at",
        "execution_ms",
        "lock_key",
        "locked_at",
        "locked_by",
        "metadata",
      ].map((column) => this.quote(column)).join(", ")} FROM ${this.qualifiedHistoryTable()} WHERE ${this.quote("scope")} = $1 ORDER BY ${this.quote("version")} ASC`,
      [this.scope],
    );
    const rows = resultRows(result);
    if (rows === undefined) throw new Error("Migration history result failed");
    return rows.filter(isRecord).map((row) => ({
      scope: readString(row.scope) ?? this.scope,
      version: readNumber(row.version) ?? 0,
      name: readString(row.name) ?? "",
      checksum: readString(row.checksum) ?? "",
      appliedAt: readString(row.applied_at),
      executionMs: readNumber(row.execution_ms),
      lockKey: readString(row.lock_key),
      lockedAt: readString(row.locked_at),
      lockedBy: readString(row.locked_by),
      metadata: readJson(row.metadata),
    })).filter((item) => item.scope === this.scope && item.version > 0 && item.name.length > 0 && item.checksum.length > 0);
  }

  private metadataSql(): string {
    return createMigrationMetadataSql({
      tableName: this.historyTable,
      lockTableName: this.lockTable,
    });
  }

  private qualifiedHistoryTable(): string {
    return quoteIdentifier(this.historyTable);
  }

  private qualifiedLockTable(): string {
    return quoteIdentifier(this.lockTable);
  }

  private quote(value: string): string {
    return quoteIdentifier(value, "migration column");
  }

  private nowIso(): string {
    const value = this.options.clock();
    return value.toISOString();
  }
}

export function createMigrationCoordinator(
  executor: MigrationSqlExecutor,
  migrations: readonly MigrationDefinition[] = [],
  options: MigrationCoordinatorOptions = {},
): MigrationCoordinator {
  return new MigrationCoordinator(executor, migrations, options);
}

export function createMigrationDefinition(
  version: number,
  name: string,
  sql: string,
  metadata?: Record<string, unknown>,
  scopeOrOptions?: string | MigrationDefinitionOptions,
  options: MigrationDefinitionOptions = {},
): MigrationDefinition {
  const scope = typeof scopeOrOptions === "string" ? scopeOrOptions : undefined;
  const definitionOptions = typeof scopeOrOptions === "object" && scopeOrOptions !== null ? scopeOrOptions : options;
  return {
    version,
    name,
    sql,
    checksum: migrationChecksum(sql),
    metadata,
    ...(scope === undefined ? {} : { scope }),
    ...(definitionOptions.additive === undefined ? {} : { additive: definitionOptions.additive }),
    ...(definitionOptions.requires === undefined ? {} : { requires: [...definitionOptions.requires] }),
    ...(definitionOptions.supersedes === undefined ? {} : { supersedes: [...definitionOptions.supersedes] }),
  };
}

export function createAdditiveMigrationDefinition(
  version: number,
  name: string,
  sql: string,
  metadata?: Record<string, unknown>,
  scope?: string,
  requires?: readonly number[],
): MigrationDefinition {
  return createMigrationDefinition(version, name, sql, metadata, scope, {
    additive: true,
    requires: requires ?? [version - 1],
  });
}

export function createMigrationSeries(
  migrations: readonly MigrationDefinition[],
  options: { preserveChecksums?: boolean } = {},
): MigrationSeries {
  const normalized = normalizeDefinitions(migrations, "default");
  for (let index = 1; index < normalized.length; index += 1) {
    if (normalized[index].version <= normalized[index - 1].version) throw new TypeError("Migration versions must be strictly increasing");
  }
  return {
    migrations: normalized,
    additive: normalized.some((migration) => migration.additive === true),
    preserveChecksums: options.preserveChecksums !== false,
  };
}

export function assertMigrationSeries(migrations: readonly MigrationDefinition[]): void {
  createMigrationSeries(migrations);
}

export function createMigrationChecksumPin(definition: MigrationDefinition): { version: number; name: string; checksum: string } {
  return {
    version: definition.version,
    name: definition.name,
    checksum: migrationChecksum(definition.sql),
  };
}

export function assertMigrationChecksumPins(
  definitions: readonly MigrationDefinition[],
  pins: readonly { version: number; name: string; checksum: string }[],
): void {
  const byVersion = new Map(pins.map((pin) => [pin.version, pin] as const));
  for (const definition of definitions) {
    const pin = byVersion.get(definition.version);
    if (pin === undefined) continue;
    if (pin.name !== definition.name || normalizeChecksum(pin.checksum) !== migrationChecksum(definition.sql)) {
      throw new TypeError(`Migration checksum pin mismatch for version ${definition.version}`);
    }
  }
}

export function migrationChecksum(sql: string): string {
  return createHash("sha256").update(normalizeSql(sql), "utf8").digest("hex");
}

export const checksumMigrationSql = migrationChecksum;
export const createMigrationChecksum = migrationChecksum;

export const createMigrationPlan = (coordinator: MigrationCoordinator): ReturnType<MigrationCoordinator["plan"]> => coordinator.plan();
export const inspectMigrationPlan = createMigrationPlan;

export async function dryRunMigrations(
  executor: MigrationSqlExecutor,
  migrations: readonly MigrationDefinition[],
  options: MigrationCoordinatorOptions = {},
): Promise<MigrationDryRunResult> {
  return new MigrationCoordinator(executor, migrations, { ...options, requireTransaction: options.requireTransaction ?? false }).dryRun(migrations);
}

export async function runMigrations(
  executor: MigrationSqlExecutor,
  migrations: readonly MigrationDefinition[],
  options: MigrationCoordinatorOptions = {},
): Promise<MigrationRunResult> {
  return new MigrationCoordinator(executor, migrations, options).run(migrations);
}

export const applyMigrations = runMigrations;

function assertMigrationScopeOptions(options: MigrationCoordinatorOptions): void {
  const rawMode = typeof options.mode === "string" ? options.mode.trim().toLowerCase() : "fixed";
  const mode = rawMode === "isolated" || rawMode === "dedicated" ? "dedicated" : rawMode === "multi" || rawMode === "shared" ? "shared" : "fixed";
  if (mode === "dedicated" && (options.allowSharedFallback === true || options.sharedExecutor !== undefined || options.fallbackExecutor !== undefined)) {
    throw new TypeError("Dedicated migration scope cannot use a shared pool fallback");
  }
}

function migrationScope(tenantId: string | undefined, mode: string | undefined): string {
  const normalizedMode = typeof mode === "string" && mode.trim().length > 0 ? mode.trim().toLowerCase() : "fixed";
  const normalizedTenant = typeof tenantId === "string" && tenantId.trim().length > 0 ? tenantId.trim() : "default";
  return `${normalizedMode}:${normalizedTenant}`;
}

function normalizeScope(value: unknown): string {
  if (typeof value !== "string") throw new TypeError("Migration scope must be a string");
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 512 || /[\u0000-\u001f\u007f]/u.test(normalized)) throw new TypeError("Invalid migration scope");
  return normalized;
}

function migrationObjectName(table: string, suffix: string): string {
  const base = table.split(".").at(-1) ?? table;
  const prefix = `${base}_`;
  const available = Math.max(1, 63 - prefix.length - suffix.length);
  return `${base.slice(0, available)}_${suffix}`;
}

function normalizeExecutor(executor: MigrationSqlExecutor): MigrationSqlExecutor {
  if (executor === null || typeof executor !== "object" || typeof executor.query !== "function") {
    throw new TypeError("A migration SQL executor is required");
  }
  return executor;
}

function normalizeDefinitions(definitions: readonly MigrationDefinition[], defaultScope = "default"): NormalizedMigrationDefinition[] {
  if (!Array.isArray(definitions)) throw new TypeError("Migrations must be an array");
  const scope = normalizeScope(defaultScope);
  const seen = new Set<string>();
  const output = definitions.map((definition) => {
    if (definition === null || typeof definition !== "object") throw new TypeError("Migration definition must be an object");
    if (!Number.isSafeInteger(definition.version) || definition.version < 1) throw new TypeError("Migration version must be a positive integer");
    const definitionScope = normalizeScope(definition.scope ?? scope);
    const identity = `${definitionScope}:${definition.version}`;
    if (seen.has(identity)) throw new TypeError(`Duplicate migration version ${definition.version} in scope ${definitionScope}`);
    seen.add(identity);
    if (typeof definition.name !== "string" || definition.name.trim().length === 0 || definition.name.length > 256 || /[\u0000-\u001f\u007f]/u.test(definition.name)) throw new TypeError("Invalid migration name");
    if (typeof definition.sql !== "string" || definition.sql.trim().length === 0) throw new TypeError(`Migration ${definition.version} has no SQL`);
    const checksum = migrationChecksum(definition.sql);
    if (definition.checksum !== undefined && normalizeChecksum(definition.checksum) !== checksum) {
      throw new TypeError(`Migration ${definition.version} checksum does not match SQL`);
    }
    const requires = normalizeVersionList(definition.requires, definition.version, "requires");
    const supersedes = normalizeVersionList(definition.supersedes, definition.version, "supersedes");
    if (definition.additive !== undefined && typeof definition.additive !== "boolean") throw new TypeError(`Migration ${definition.version} additive flag is invalid`);
    return {
      version: definition.version,
      name: definition.name.trim(),
      sql: normalizeSql(definition.sql),
      checksum,
      metadata: isRecord(definition.metadata) ? { ...definition.metadata } : {},
      scope: definitionScope,
      ...(definition.additive === undefined ? {} : { additive: definition.additive }),
      ...(requires === undefined ? {} : { requires }),
      ...(supersedes === undefined ? {} : { supersedes }),
    };
  }).sort((left, right) => left.scope.localeCompare(right.scope) || left.version - right.version);
  return output;
}

function normalizeVersionList(value: readonly number[] | undefined, version: number, field: string): number[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length > 100) throw new TypeError(`Migration ${version} ${field} list is invalid`);
  const output: number[] = [];
  for (const item of value) {
    if (!Number.isSafeInteger(item) || item < 1 || item >= version || output.includes(item)) throw new TypeError(`Migration ${version} ${field} list is invalid`);
    output.push(item);
  }
  return output.sort((left, right) => left - right);
}

function checksumDefinitions(definitions: readonly NormalizedMigrationDefinition[]): string {
  const source = definitions.map((item) => `${item.scope}:${item.version}:${item.name}:${item.checksum}`).join("\n");
  return createHash("sha256").update(source, "utf8").digest("hex");
}

function normalizeSql(sql: string): string {
  return sql.replace(/\r\n/gu, "\n").trim();
}

function normalizeChecksum(value: string): string {
  return value.trim().replace(/^sha256:/iu, "").toLowerCase();
}

function normalizeLockKey(value: string | number): string {
  const normalized = typeof value === "number" ? String(value) : value.trim();
  if (normalized.length === 0 || normalized.length > 256 || /[\u0000-\u001f\u007f]/u.test(normalized)) throw new TypeError("Invalid migration lock key");
  return normalized;
}

function normalizeOwnerId(value: string | undefined): string {
  if (value === undefined) return randomUUID();
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 256 || /[\u0000-\u001f\u007f]/u.test(normalized)) throw new TypeError("Invalid migration owner id");
  return normalized;
}

function validateIdentifier(value: string, field: string): string {
  if (typeof value !== "string") throw new TypeError(`${field} must be a string`);
  const normalized = value.trim();
  if (normalized !== value) throw new TypeError(`Invalid SQL identifier for ${field}`);
  const segments = normalized.split(".");
  if (segments.length < 1 || segments.length > 2 || segments.some((segment) => !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(segment) || segment.length > 63)) throw new TypeError(`Invalid SQL identifier for ${field}`);
  return segments.join(".");
}

function quoteIdentifier(value: string, field = "identifier"): string {
  return validateIdentifier(value, field).split(".").map((segment) => `"${segment}"`).join(".");
}

function resultRows(value: unknown): unknown[] | undefined {
  if (Array.isArray(value)) return value;
  if (!isRecord(value)) return undefined;
  return Array.isArray(value.rows) ? value.rows : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
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

function readJson(value: unknown): Record<string, unknown> | undefined {
  if (isRecord(value)) return value;
  if (typeof value !== "string") return undefined;
  try {
    const parsed: unknown = JSON.parse(value);
    return isRecord(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}
