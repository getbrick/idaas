import {
  MigrationCoordinator,
  createMigrationDefinition,
  createMigrationMetadataSql,
  migrationChecksum,
  type MigrationDefinition,
  type MigrationDryRunResult,
  type MigrationRunResult,
  type MigrationSqlExecutor,
} from "../../../migration-coordinator.js";
import {
  normalizeTenantConfig,
  qualifyTenantTable,
  type TenantConfig,
  type TenantConfigInput,
} from "../../../tenant.js";
import {
  COMMERCE_ALL_TABLES,
  COMMERCE_FOUNDATION_SQL_TABLES,
  COMMERCE_RESERVED_EXISTING_TABLES,
  COMMERCE_RUNTIME_TABLES,
  COMMERCE_SQL_COLUMNS,
  COMMERCE_SQL_TABLES,
  type CommerceDatabaseAdapter,
  type CommerceSqlColumns,
  type CommerceSqlTableKey,
  type CommerceSqlTableNames,
  validateCommerceSqlIdentifier,
} from "./adapter.js";

export const OPEN_COMMERCE_MIGRATION_VERSION = 1;
export const OPEN_COMMERCE_MIGRATION_NAME = "open-platform-commerce-persistence-foundation";
export const OPEN_COMMERCE_IDEMPOTENCY_MIGRATION_VERSION = 2;
export const OPEN_COMMERCE_IDEMPOTENCY_MIGRATION_NAME = "open-platform-commerce-idempotency-store";
export const OPEN_COMMERCE_IDEMPOTENCY_TABLE = "gb_open_commerce_idempotency";
export const OPEN_COMMERCE_INVOICE_DISPUTE_MIGRATION_VERSION = 3;
export const OPEN_COMMERCE_INVOICE_DISPUTE_MIGRATION_NAME =
  "open-platform-commerce-invoice-dispute-evidence";
export const OPEN_COMMERCE_INVOICE_DISPUTE_TABLE = "gb_open_commerce_invoice_dispute";
export const COMMERCE_INVOICE_DISPUTE_TABLE = OPEN_COMMERCE_INVOICE_DISPUTE_TABLE;
export const INVOICE_STATUS_SQL_VALUES =
  "'draft', 'reconciling', 'awaitingPayment', 'invoicing', 'paid', 'completed', 'disputed', 'voided'";
export const INVOICE_DISPUTE_STATUS_SQL_VALUES =
  "'open', 'underReview', 'accepted', 'rejected', 'withdrawn'";
export const OPEN_COMMERCE_INVOICE_DISPUTE_DECISION_MIGRATION_VERSION = 4;
export const OPEN_COMMERCE_INVOICE_DISPUTE_DECISION_MIGRATION_NAME =
  "open-platform-commerce-invoice-dispute-adjudication";
export const OPEN_COMMERCE_LATEST_MIGRATION_VERSION =
  OPEN_COMMERCE_INVOICE_DISPUTE_DECISION_MIGRATION_VERSION;
export const COMMERCE_IDEMPOTENCY_TABLE = OPEN_COMMERCE_IDEMPOTENCY_TABLE;
export const COMMERCE_IDEMPOTENCY_COLUMNS = Object.freeze({
  tenantId: "tenant_id",
  actorId: "actor_id",
  operation: "operation",
  key: "idempotency_key",
  requestHash: "request_hash",
  result: "result",
  createdAt: "created_at",
  expiresAt: "expires_at",
} as const);
export const COMMERCE_IDEMPOTENCY_FIELDS = Object.freeze([
  "tenantId",
  "actorId",
  "operation",
  "key",
  "requestHash",
  "result",
  "createdAt",
  "expiresAt",
] as const);
export type CommerceIdempotencySqlField =
  (typeof COMMERCE_IDEMPOTENCY_FIELDS)[number];
export const OPEN_COMMERCE_PERSISTENCE_MIGRATION_VERSION = OPEN_COMMERCE_MIGRATION_VERSION;
export const OPEN_COMMERCE_PERSISTENCE_MIGRATION_NAME = OPEN_COMMERCE_MIGRATION_NAME;
export const COMMERCE_MIGRATION_VERSION = OPEN_COMMERCE_MIGRATION_VERSION;
export const COMMERCE_MIGRATION_NAME = OPEN_COMMERCE_MIGRATION_NAME;
export const OPEN_COMMERCE_MIGRATION_TABLE = "gb_open_commerce_schema_migration";
export const OPEN_COMMERCE_MIGRATION_LOCK_TABLE = "gb_open_commerce_schema_migration_lock";
export const COMMERCE_MIGRATION_TABLE = OPEN_COMMERCE_MIGRATION_TABLE;
export const COMMERCE_MIGRATION_LOCK_TABLE = OPEN_COMMERCE_MIGRATION_LOCK_TABLE;

export interface OpenCommerceMigrationOptions {
  schema?: string;
  mode?: string;
  tenantId?: string;
  tenantColumn?: string | null;
  tenant?: TenantConfigInput;
  tenantConfig?: TenantConfigInput;
  tenantMode?: string;
  includeRls?: boolean;
  requireRls?: boolean;
  requireTransactions?: boolean;
  tables?: Partial<CommerceSqlTableNames>;
  tableNames?: Partial<CommerceSqlTableNames>;
  columns?: Partial<Record<CommerceSqlTableKey, Record<string, string | null>>>;
  columnNames?: Partial<Record<CommerceSqlTableKey, Record<string, string | null>>>;
  idempotencyTable?: string;
  disputeTable?: string;
  migrationTable?: string;
  migrationHistoryTable?: string;
  migrationLockTable?: string;
  migrationVersion?: number;
  migrationName?: string;
  idempotencyMigrationVersion?: number;
  idempotencyMigrationName?: string;
  disputeMigrationVersion?: number;
  disputeMigrationName?: string;
  disputeDecisionMigrationVersion?: number;
  disputeDecisionMigrationName?: string;
  includeMigrationMetadata?: boolean;
  requireTransaction?: boolean;
  allowNonTransactional?: boolean;
  lockKey?: string | number;
  lockNamespace?: string;
  ownerId?: string;
  clock?: () => Date;
}

export type CommerceMigrationOptions = OpenCommerceMigrationOptions;
export type CommercePersistenceMigrationOptions = OpenCommerceMigrationOptions;

export function createOpenCommerceMigrationSql(
  options: OpenCommerceMigrationOptions = {},
): string {
  const tenant = migrationTenant(options);
  const tables = migrationTables(options, tenant.schema);
  const columns = migrationColumns(options, tenant.tenantColumn);
  const statements: string[] = [
    createPlanTable(tables, columns),
    createEntitlementTable(tables, columns),
    createMeterTable(tables, columns),
    createPriceTable(tables, columns),
    createSubscriptionTable(tables, columns),
    createQuotaTable(tables, columns),
    createQuotaReservationTable(tables, columns),
    createUsageEventTable(tables, columns),
    createUsageAggregateTable(tables, columns),
    createInvoiceTable(tables, columns),
    createInvoiceLineTable(tables, columns),
    createInvoiceStatusEventTable(tables, columns),
    createPartnerAccountTable(tables, columns),
    createMarketplaceListingTable(tables, columns),
    createCommissionRuleTable(tables, columns),
    ...uniqueConstraints(tables, columns),
    ...indexes(tables, columns),
    ...appendOnlyStatements(tables),
    ...immutabilityStatements(tables, columns),
  ];
  if (options.includeRls === true || options.requireRls === true || tenant.requireRls) {
    statements.push(...rlsStatements(tables, columns));
  }
  if (options.includeMigrationMetadata !== false) {
    const metadataTable = qualifyMigrationTable(
      options.migrationTable ?? options.migrationHistoryTable ?? OPEN_COMMERCE_MIGRATION_TABLE,
      tenant.schema,
      "commerce migration table",
    );
    const lockTable = qualifyMigrationTable(
      options.migrationLockTable ?? OPEN_COMMERCE_MIGRATION_LOCK_TABLE,
      tenant.schema,
      "commerce migration lock table",
    );
    statements.push(createMigrationMetadataSql({
      tableName: metadataTable,
      lockTableName: lockTable,
    }));
  }
  return `${statements.join(";\n")};\n`;
}

export const createCommerceMigrationSql = createOpenCommerceMigrationSql;
export const getOpenCommerceMigrationSql = createOpenCommerceMigrationSql;
export const getCommerceMigrationSql = createOpenCommerceMigrationSql;
export const buildOpenCommerceMigrationSql = createOpenCommerceMigrationSql;
export const createOpenPlatformCommerceMigrationSql = createOpenCommerceMigrationSql;
export const getOpenPlatformCommerceMigrationSql = createOpenCommerceMigrationSql;
export const OPEN_COMMERCE_MIGRATION_SQL = createOpenCommerceMigrationSql();
export const OPEN_COMMERCE_PERSISTENCE_MIGRATION_SQL = OPEN_COMMERCE_MIGRATION_SQL;
export const COMMERCE_MIGRATION_SQL = OPEN_COMMERCE_MIGRATION_SQL;

export function getOpenCommerceMigrationDefinition(
  options: OpenCommerceMigrationOptions = {},
): MigrationDefinition {
  return createMigrationDefinition(
    options.migrationVersion ?? OPEN_COMMERCE_MIGRATION_VERSION,
    options.migrationName ?? OPEN_COMMERCE_MIGRATION_NAME,
    createOpenCommerceMigrationSql(options),
    {
      component: "open-platform-commerce-persistence",
      tenantMode: migrationTenant(options).mode,
      tenantId: migrationTenant(options).tenantId,
      schema: migrationTenant(options).schema,
      tables: COMMERCE_FOUNDATION_SQL_TABLES,
      checksumAlgorithm: "sha256",
    },
    migrationScope(options),
  );
}

export const getCommerceMigrationDefinition = getOpenCommerceMigrationDefinition;
export const createOpenCommerceMigrationDefinition = getOpenCommerceMigrationDefinition;
export const createCommerceMigrationDefinition = getOpenCommerceMigrationDefinition;
export const getOpenPlatformCommerceMigrationDefinition = getOpenCommerceMigrationDefinition;

export function createOpenCommerceIdempotencyMigrationSql(
  options: OpenCommerceMigrationOptions = {},
): string {
  const tenant = migrationTenant(options);
  const table = migrationIdempotencyTable(options, tenant.schema);
  const tenantColumn = tenant.tenantColumn;
  const statements: string[] = [
    createTable(table, [
      `${q(tenantColumn)} TEXT NOT NULL`,
      `${q(COMMERCE_IDEMPOTENCY_COLUMNS.actorId)} TEXT NOT NULL`,
      `${q(COMMERCE_IDEMPOTENCY_COLUMNS.operation)} TEXT NOT NULL`,
      `${q(COMMERCE_IDEMPOTENCY_COLUMNS.key)} TEXT NOT NULL`,
      `${q(COMMERCE_IDEMPOTENCY_COLUMNS.requestHash)} TEXT NOT NULL CHECK (${q(COMMERCE_IDEMPOTENCY_COLUMNS.requestHash)} ~ '^[a-f0-9]{64}$')`,
      `${q(COMMERCE_IDEMPOTENCY_COLUMNS.result)} JSONB NOT NULL CHECK (jsonb_typeof(${q(COMMERCE_IDEMPOTENCY_COLUMNS.result)}) <> 'null')`,
      `${q(COMMERCE_IDEMPOTENCY_COLUMNS.createdAt)} TIMESTAMPTZ NOT NULL`,
      `${q(COMMERCE_IDEMPOTENCY_COLUMNS.expiresAt)} TIMESTAMPTZ NOT NULL`,
      `CHECK (${q(COMMERCE_IDEMPOTENCY_COLUMNS.expiresAt)} > ${q(COMMERCE_IDEMPOTENCY_COLUMNS.createdAt)})`,
      `PRIMARY KEY (${q(tenantColumn)}, ${q(COMMERCE_IDEMPOTENCY_COLUMNS.actorId)}, ${q(COMMERCE_IDEMPOTENCY_COLUMNS.operation)}, ${q(COMMERCE_IDEMPOTENCY_COLUMNS.key)})`,
    ]),
    index(table, "expiry_idx", [tenantColumn, COMMERCE_IDEMPOTENCY_COLUMNS.expiresAt]),
  ];  if (options.includeRls === true || options.requireRls === true || tenant.requireRls) {
    statements.push(...idempotencyRlsStatements(table, tenantColumn));
  }
  return `${statements.join(";\n")};\n`;
}

export const createCommerceIdempotencyMigrationSql = createOpenCommerceIdempotencyMigrationSql;
export const getOpenCommerceIdempotencyMigrationSql = createOpenCommerceIdempotencyMigrationSql;
export const OPEN_COMMERCE_IDEMPOTENCY_MIGRATION_SQL = createOpenCommerceIdempotencyMigrationSql();

export function getOpenCommerceIdempotencyMigrationDefinition(
  options: OpenCommerceMigrationOptions = {},
): MigrationDefinition {
  const version = options.idempotencyMigrationVersion ?? OPEN_COMMERCE_IDEMPOTENCY_MIGRATION_VERSION;
  if (!Number.isSafeInteger(version) || version <= OPEN_COMMERCE_MIGRATION_VERSION) {
    throw new TypeError("Commerce idempotency migration version must be greater than the foundation version");
  }
  return createMigrationDefinition(
    version,
    options.idempotencyMigrationName ?? OPEN_COMMERCE_IDEMPOTENCY_MIGRATION_NAME,
    createOpenCommerceIdempotencyMigrationSql(options),
    {
      component: "open-platform-commerce-persistence",
      additive: true,
      baseVersion: OPEN_COMMERCE_MIGRATION_VERSION,
      baseChecksum: getOpenCommerceMigrationChecksum(options),
      tenantMode: migrationTenant(options).mode,
      tenantId: migrationTenant(options).tenantId,
      schema: migrationTenant(options).schema,
      checksumAlgorithm: "sha256",
    },
    migrationScope(options),
    { additive: true, requires: [OPEN_COMMERCE_MIGRATION_VERSION] },
  );
}

export const getCommerceIdempotencyMigrationDefinition = getOpenCommerceIdempotencyMigrationDefinition;
export const createOpenCommerceIdempotencyMigrationDefinition = getOpenCommerceIdempotencyMigrationDefinition;
export const createCommerceIdempotencyMigrationDefinition = getOpenCommerceIdempotencyMigrationDefinition;
export const getOpenPlatformCommerceIdempotencyMigrationDefinition = getOpenCommerceIdempotencyMigrationDefinition;

export function getOpenCommerceIdempotencyMigrationChecksum(
  options: OpenCommerceMigrationOptions = {},
): string {
  return migrationChecksum(createOpenCommerceIdempotencyMigrationSql(options));
}

export const getCommerceIdempotencyMigrationChecksum =
  getOpenCommerceIdempotencyMigrationChecksum;

export function createOpenCommerceInvoiceDisputeMigrationSql(
  options: OpenCommerceMigrationOptions = {},
): string {
  const tenant = migrationTenant(options);
  const tables = migrationTables(options, tenant.schema);
  const columns = migrationColumns(options, tenant.tenantColumn);
  const table = tables.invoiceDisputes;
  const c = columns.invoiceDisputes;
  const statements: string[] = [
    createTable(table, [
      `${q(c.id)} TEXT NOT NULL`,
      `${q(c.tenantId)} TEXT NOT NULL`,
      `${q(c.kind)} TEXT NOT NULL DEFAULT 'invoiceDispute' CHECK (${q(c.kind)} = 'invoiceDispute')`,
      `${q(c.version)} INTEGER NOT NULL DEFAULT 1 CHECK (${q(c.version)} = 1)`,
      `${q(c.event)} TEXT NOT NULL DEFAULT 'invoice.dispute.opened' CHECK (${q(c.event)} = 'invoice.dispute.opened')`,
      `${q(c.invoiceId)} TEXT NOT NULL`,
      `${q(c.subscriptionId)} TEXT NOT NULL`,
      `${q(c.planId)} TEXT NOT NULL`,
      `${q(c.invoiceStatus)} TEXT NOT NULL CHECK (${q(c.invoiceStatus)} IN (${INVOICE_STATUS_SQL_VALUES}))`,
      `${q(c.invoiceVersion)} INTEGER NOT NULL CHECK (${q(c.invoiceVersion)} > 0)`,
      `${q(c.reason)} TEXT NOT NULL CHECK (char_length(${q(c.reason)}) BETWEEN 1 AND 500 AND ${q(c.reason)} !~ '[0-9]{8,}')`,
      hashColumn(c.reasonDigest),
      `${q(c.reasonLength)} INTEGER NOT NULL CHECK (${q(c.reasonLength)} BETWEEN 1 AND 500)`,
      `${q(c.evidenceReference)} TEXT CHECK (${q(c.evidenceReference)} IS NULL OR (char_length(${q(c.evidenceReference)}) BETWEEN 1 AND 128 AND ${q(c.evidenceReference)} !~ '[[:space:]]' AND ${q(c.evidenceReference)} !~ '[0-9]{8,}'))`,
      `${q(c.evidenceReferenceDigest)} TEXT CHECK (${q(c.evidenceReferenceDigest)} IS NULL OR ${q(c.evidenceReferenceDigest)} ~ '^[a-f0-9]{64}$')`,
      `${q(c.evidenceCount)} INTEGER NOT NULL DEFAULT 0 CHECK (${q(c.evidenceCount)} BETWEEN 0 AND 1)`,
      `${q(c.actorId)} TEXT NOT NULL`,
      `${q(c.requestId)} TEXT NOT NULL`,
      `${q(c.idempotencyKey)} TEXT NOT NULL`,
      hashColumn(c.requestHash),
      `${q(c.status)} TEXT NOT NULL DEFAULT 'open' CHECK (${q(c.status)} IN ('open', 'underReview', 'accepted', 'rejected', 'withdrawn'))`,
      `${q(c.resolutionOutcome)} TEXT CHECK (${q(c.resolutionOutcome)} IS NULL OR ${q(c.resolutionOutcome)} IN ('accepted', 'rejected', 'withdrawn'))`,
      `${q(c.resolutionActorId)} TEXT CHECK (${q(c.resolutionActorId)} IS NULL OR char_length(${q(c.resolutionActorId)}) BETWEEN 1 AND 128)`,
      `${q(c.resolutionReference)} TEXT CHECK (${q(c.resolutionReference)} IS NULL OR (char_length(${q(c.resolutionReference)}) BETWEEN 1 AND 128 AND ${q(c.resolutionReference)} !~ '[[:space:]]' AND ${q(c.resolutionReference)} !~ '[0-9]{8,}'))`,
      timestampColumn(c.resolvedAt, true),
      timestampColumn(c.createdAt, false),
      timestampColumn(c.recordedAt, false),
      `CHECK (${q(c.recordedAt)} >= ${q(c.createdAt)})`,
      `CHECK ((${q(c.evidenceReference)} IS NULL) = (${q(c.evidenceReferenceDigest)} IS NULL) AND (${q(c.evidenceReference)} IS NOT NULL) = (${q(c.evidenceCount)} = 1))`,
      `CHECK ((${q(c.status)} IN ('open', 'underReview') AND ${q(c.resolutionOutcome)} IS NULL AND ${q(c.resolvedAt)} IS NULL) OR (${q(c.status)} IN ('accepted', 'rejected', 'withdrawn') AND ${q(c.resolutionOutcome)} IS NOT NULL AND ${q(c.resolutionActorId)} IS NOT NULL AND ${q(c.resolutionReference)} IS NOT NULL AND ${q(c.resolvedAt)} IS NOT NULL AND ${q(c.resolvedAt)} >= ${q(c.createdAt)}))`,
      `PRIMARY KEY (${q(c.tenantId)}, ${q(c.id)})`,
      foreignKey(c, [c.tenantId, c.invoiceId], tables.invoices, [COMMERCE_SQL_COLUMNS.invoices.tenantId, COMMERCE_SQL_COLUMNS.invoices.id]),
      foreignKey(c, [c.tenantId, c.subscriptionId], tables.subscriptions, [COMMERCE_SQL_COLUMNS.subscriptions.tenantId, COMMERCE_SQL_COLUMNS.subscriptions.id]),
      foreignKey(c, [c.tenantId, c.planId], tables.plans, [COMMERCE_SQL_COLUMNS.plans.tenantId, COMMERCE_SQL_COLUMNS.plans.id]),
    ]),
    uniqueIndex(table, "dispute_idempotency_uq", [c.tenantId, c.invoiceId, c.idempotencyKey]),
    index(table, "invoice_idx", [c.tenantId, c.invoiceId, c.createdAt, c.id]),
    index(table, "actor_idx", [c.tenantId, c.actorId, c.createdAt]),
    index(table, "status_idx", [c.tenantId, c.status, c.createdAt]),
    index(table, "idempotency_idx", [c.tenantId, c.idempotencyKey, c.createdAt]),
    ...immutableTrigger(table, "gb_open_commerce_reject_invoice_dispute_mutation", "gb_open_commerce_invoice_dispute is append-only"),
  ];
  if (options.includeRls === true || options.requireRls === true || tenant.requireRls) {
    statements.push(...idempotencyRlsStatements(table, c.tenantId));
  }
  return `${statements.join(";\n")};\n`;
}

export const createCommerceInvoiceDisputeMigrationSql =
  createOpenCommerceInvoiceDisputeMigrationSql;
export const getOpenCommerceInvoiceDisputeMigrationSql =
  createOpenCommerceInvoiceDisputeMigrationSql;
export const OPEN_COMMERCE_INVOICE_DISPUTE_MIGRATION_SQL =
  createOpenCommerceInvoiceDisputeMigrationSql();

export function getOpenCommerceInvoiceDisputeMigrationChecksum(
  options: OpenCommerceMigrationOptions = {},
): string {
  return migrationChecksum(createOpenCommerceInvoiceDisputeMigrationSql(options));
}

export const getCommerceInvoiceDisputeMigrationChecksum =
  getOpenCommerceInvoiceDisputeMigrationChecksum;

export function getOpenCommerceInvoiceDisputeMigrationDefinition(
  options: OpenCommerceMigrationOptions = {},
): MigrationDefinition {
  const version =
    options.disputeMigrationVersion ?? OPEN_COMMERCE_INVOICE_DISPUTE_MIGRATION_VERSION;
  if (
    !Number.isSafeInteger(version) ||
    version <= OPEN_COMMERCE_IDEMPOTENCY_MIGRATION_VERSION
  ) {
    throw new TypeError("Commerce invoice dispute migration version must be greater than the idempotency version");
  }
  return createMigrationDefinition(
    version,
    options.disputeMigrationName ?? OPEN_COMMERCE_INVOICE_DISPUTE_MIGRATION_NAME,
    createOpenCommerceInvoiceDisputeMigrationSql(options),
    {
      component: "open-platform-commerce-persistence",
      additive: true,
      baseVersion: OPEN_COMMERCE_IDEMPOTENCY_MIGRATION_VERSION,
      baseChecksum: getOpenCommerceIdempotencyMigrationChecksum(options),
      tenantMode: migrationTenant(options).mode,
      tenantId: migrationTenant(options).tenantId,
      schema: migrationTenant(options).schema,
      tables: COMMERCE_SQL_TABLES,
      checksumAlgorithm: "sha256",
    },
    migrationScope(options),
    { additive: true, requires: [OPEN_COMMERCE_IDEMPOTENCY_MIGRATION_VERSION] },
  );
}

export const getCommerceInvoiceDisputeMigrationDefinition =
  getOpenCommerceInvoiceDisputeMigrationDefinition;export const createOpenCommerceInvoiceDisputeMigrationDefinition =
  getOpenCommerceInvoiceDisputeMigrationDefinition;
export const createCommerceInvoiceDisputeMigrationDefinition =
  getOpenCommerceInvoiceDisputeMigrationDefinition;
export const getOpenPlatformCommerceInvoiceDisputeMigrationDefinition =
  getOpenCommerceInvoiceDisputeMigrationDefinition;

export function createOpenCommerceInvoiceDisputeDecisionMigrationSql(
  options: OpenCommerceMigrationOptions = {},
): string {
  const tenant = migrationTenant(options);
  const tables = migrationTables(options, tenant.schema);
  const columns = migrationColumns(options, tenant.tenantColumn);
  const table = tables.invoiceDisputes;
  const c = columns.invoiceDisputes;
  const statements: string[] = [
    `ALTER TABLE ${q(table)} ADD COLUMN IF NOT EXISTS ${q(c.updatedAt)} TIMESTAMPTZ`,
    `UPDATE ${q(table)} SET ${q(c.updatedAt)} = ${q(c.recordedAt)} WHERE ${q(c.updatedAt)} IS NULL`,
    `ALTER TABLE ${q(table)} ALTER COLUMN ${q(c.updatedAt)} SET NOT NULL`,
    `ALTER TABLE ${q(table)} ADD COLUMN IF NOT EXISTS ${q(c.resolutionNote)} TEXT CHECK (${q(c.resolutionNote)} IS NULL OR (char_length(${q(c.resolutionNote)}) BETWEEN 1 AND 500 AND ${q(c.resolutionNote)} !~ '[[:cntrl:]]' AND ${q(c.resolutionNote)} !~ '[0-9]{8,}'))`,
    `ALTER TABLE ${q(table)} ADD COLUMN IF NOT EXISTS ${q(c.resolutionNoteLength)} INTEGER CHECK (${q(c.resolutionNoteLength)} IS NULL OR ${q(c.resolutionNoteLength)} BETWEEN 1 AND 500)`,
    `ALTER TABLE ${q(table)} ADD COLUMN IF NOT EXISTS ${q(c.resolutionFromStatus)} TEXT CHECK (${q(c.resolutionFromStatus)} IS NULL OR ${q(c.resolutionFromStatus)} IN ('open', 'underReview'))`,
    `ALTER TABLE ${q(table)} DROP CONSTRAINT IF EXISTS ${q(constraintName(table, "version_check"))}`,
    `ALTER TABLE ${q(table)} ADD CONSTRAINT ${q(constraintName(table, "version_check"))} CHECK (${q(c.version)} > 0)`,
    `ALTER TABLE ${q(table)} DROP CONSTRAINT IF EXISTS ${q(constraintName(table, "updated_at_check"))}`,
    `ALTER TABLE ${q(table)} ADD CONSTRAINT ${q(constraintName(table, "updated_at_check"))} CHECK (${q(c.updatedAt)} >= ${q(c.createdAt)})`,
    `ALTER TABLE ${q(table)} DROP CONSTRAINT IF EXISTS ${q(constraintName(table, "resolution_note_check"))}`,
    `ALTER TABLE ${q(table)} ADD CONSTRAINT ${q(constraintName(table, "resolution_note_check"))} CHECK ((${q(c.resolutionNote)} IS NULL) = (${q(c.resolutionNoteLength)} IS NULL) AND (${q(c.resolutionNote)} IS NULL OR ${q(c.resolutionNoteLength)} = char_length(${q(c.resolutionNote)})))`,
    ...disputeImmutabilityStatements(table, c),
    index(table, "decision_idx", [c.tenantId, c.status, c.updatedAt, c.id]),
    index(table, "resolution_idx", [c.tenantId, c.resolutionOutcome, c.resolvedAt]),
  ];
  if (options.includeRls === true || options.requireRls === true || tenant.requireRls) {
    statements.push(...idempotencyRlsStatements(table, c.tenantId));
  }
  return `${statements.join(";\n")};\n`;
}

export const createCommerceInvoiceDisputeDecisionMigrationSql =
  createOpenCommerceInvoiceDisputeDecisionMigrationSql;
export const getOpenCommerceInvoiceDisputeDecisionMigrationSql =
  createOpenCommerceInvoiceDisputeDecisionMigrationSql;
export const OPEN_COMMERCE_INVOICE_DISPUTE_DECISION_MIGRATION_SQL =
  createOpenCommerceInvoiceDisputeDecisionMigrationSql();

export function getOpenCommerceInvoiceDisputeDecisionMigrationChecksum(
  options: OpenCommerceMigrationOptions = {},
): string {
  return migrationChecksum(
    createOpenCommerceInvoiceDisputeDecisionMigrationSql(options),
  );
}

export const getCommerceInvoiceDisputeDecisionMigrationChecksum =
  getOpenCommerceInvoiceDisputeDecisionMigrationChecksum;

export function getOpenCommerceInvoiceDisputeDecisionMigrationDefinition(
  options: OpenCommerceMigrationOptions = {},
): MigrationDefinition {
  const version =
    options.disputeDecisionMigrationVersion ??
    OPEN_COMMERCE_INVOICE_DISPUTE_DECISION_MIGRATION_VERSION;
  if (
    !Number.isSafeInteger(version) ||
    version <= OPEN_COMMERCE_INVOICE_DISPUTE_MIGRATION_VERSION
  ) {
    throw new TypeError("Commerce invoice dispute decision migration version must be greater than the dispute version");
  }
  return createMigrationDefinition(
    version,
    options.disputeDecisionMigrationName ??
      OPEN_COMMERCE_INVOICE_DISPUTE_DECISION_MIGRATION_NAME,
    createOpenCommerceInvoiceDisputeDecisionMigrationSql(options),
    {
      component: "open-platform-commerce-persistence",
      additive: true,
      baseVersion: OPEN_COMMERCE_INVOICE_DISPUTE_MIGRATION_VERSION,
      baseChecksum: getOpenCommerceInvoiceDisputeMigrationChecksum(options),
      tenantMode: migrationTenant(options).mode,
      tenantId: migrationTenant(options).tenantId,
      schema: migrationTenant(options).schema,
      tables: COMMERCE_SQL_TABLES,
      checksumAlgorithm: "sha256",
    },
    migrationScope(options),
    {
      additive: true,
      requires: [OPEN_COMMERCE_INVOICE_DISPUTE_MIGRATION_VERSION],
    },
  );
}

export const getCommerceInvoiceDisputeDecisionMigrationDefinition =
  getOpenCommerceInvoiceDisputeDecisionMigrationDefinition;
export const createOpenCommerceInvoiceDisputeDecisionMigrationDefinition =
  getOpenCommerceInvoiceDisputeDecisionMigrationDefinition;
export const createCommerceInvoiceDisputeDecisionMigrationDefinition =
  getOpenCommerceInvoiceDisputeDecisionMigrationDefinition;
export const getOpenPlatformCommerceInvoiceDisputeDecisionMigrationDefinition =
  getOpenCommerceInvoiceDisputeDecisionMigrationDefinition;

export function getOpenCommerceMigrations(
  options: OpenCommerceMigrationOptions = {},
): MigrationDefinition[] {
  return [
    getOpenCommerceMigrationDefinition(options),
    getOpenCommerceIdempotencyMigrationDefinition(options),
    getOpenCommerceInvoiceDisputeMigrationDefinition(options),
    getOpenCommerceInvoiceDisputeDecisionMigrationDefinition(options),
  ];
}

export const getCommerceMigrations = getOpenCommerceMigrations;

export function getOpenCommerceMigrationChecksum(
  options: OpenCommerceMigrationOptions = {},
): string {
  return migrationChecksum(createOpenCommerceMigrationSql(options));
}

export const getCommerceMigrationChecksum = getOpenCommerceMigrationChecksum;

export function createOpenCommerceMigrationPlan(
  options: OpenCommerceMigrationOptions = {},
): { version: number; name: string; checksum: string; sql: string } {
  const definition = getOpenCommerceMigrationDefinition(options);
  return {
    version: definition.version,
    name: definition.name,
    checksum: migrationChecksum(definition.sql),
    sql: definition.sql,
  };
}

export const getOpenCommerceMigrationPlan = createOpenCommerceMigrationPlan;
export const getCommerceMigrationPlan = createOpenCommerceMigrationPlan;

export function dryRunOpenCommerceMigration(
  options?: OpenCommerceMigrationOptions,
): MigrationDryRunResult;
export function dryRunOpenCommerceMigration(
  adapter: CommerceDatabaseAdapter,
  options?: OpenCommerceMigrationOptions,
): MigrationDryRunResult;
export function dryRunOpenCommerceMigration(
  input: CommerceDatabaseAdapter | OpenCommerceMigrationOptions = {},
  second: OpenCommerceMigrationOptions = {},
): MigrationDryRunResult {
  const hasAdapter = isAdapter(input);
  const options = hasAdapter ? second : input;
  const definition = getOpenCommerceMigrationDefinition(options);
  const coordinator = new MigrationCoordinator(
    hasAdapter ? input : { query: async () => ({ rows: [] }) },
    [definition],
    migrationCoordinatorOptions(options, false),
  );
  return coordinator.dryRun([definition]);
}

export async function applyVersionedOpenCommerceMigration(
  adapter: CommerceDatabaseAdapter,
  options: OpenCommerceMigrationOptions = {},
): Promise<MigrationRunResult> {
  const definition = getOpenCommerceMigrationDefinition(options);
  const coordinator = new MigrationCoordinator(
    adapter,
    [definition],
    migrationCoordinatorOptions(options, options.requireTransaction ?? options.allowNonTransactional !== true),
  );
  return coordinator.run([definition]);
}

export async function applyOpenCommerceMigration(
  adapter: CommerceDatabaseAdapter,
  options: OpenCommerceMigrationOptions = {},
): Promise<void> {
  await applyVersionedOpenCommerceMigration(adapter, options);
}

export const runOpenCommerceMigration = applyVersionedOpenCommerceMigration;
export const runVersionedOpenCommerceMigration = applyVersionedOpenCommerceMigration;
export const applyCommerceMigration = applyVersionedOpenCommerceMigration;
export const runCommerceMigration = applyVersionedOpenCommerceMigration;
export const applyVersionedCommerceMigration = applyVersionedOpenCommerceMigration;
export const applyOpenPlatformCommerceMigration = applyVersionedOpenCommerceMigration;
export const runOpenPlatformCommerceMigration = applyVersionedOpenCommerceMigration;

function migrationTenant(options: OpenCommerceMigrationOptions): TenantConfig {
  return normalizeTenantConfig({
    ...(options.tenant ?? {}),
    ...(options.tenantConfig ?? {}),
    ...(options.mode === undefined ? {} : { mode: options.mode }),
    ...(options.tenantMode === undefined ? {} : { mode: options.tenantMode }),
    ...(options.tenantId === undefined ? {} : { tenantId: options.tenantId }),
    ...(options.tenantColumn === undefined ? {} : { tenantColumn: options.tenantColumn }),
    ...(options.schema === undefined ? {} : { schema: options.schema }),
    ...(options.requireRls === undefined ? {} : { requireRls: options.requireRls }),
    ...(options.requireTransactions === undefined ? {} : { requireTransactions: options.requireTransactions }),
  });
}

function migrationTables(
  options: OpenCommerceMigrationOptions,
  schema: string,
): Record<CommerceSqlTableKey, string> {
  const configured = {
    ...COMMERCE_SQL_TABLES,
    ...(options.tables ?? {}),
    ...(options.tableNames ?? {}),
    ...(options.tables?.plan === undefined ? {} : { plans: options.tables.plan }),
    ...(options.tableNames?.plan === undefined ? {} : { plans: options.tableNames.plan }),
    ...(options.tables?.entitlement === undefined ? {} : { entitlements: options.tables.entitlement }),
    ...(options.tableNames?.entitlement === undefined ? {} : { entitlements: options.tableNames.entitlement }),
    ...(options.tables?.meter === undefined ? {} : { meters: options.tables.meter }),
    ...(options.tableNames?.meter === undefined ? {} : { meters: options.tableNames.meter }),
    ...(options.tables?.price === undefined ? {} : { prices: options.tables.price }),
    ...(options.tableNames?.price === undefined ? {} : { prices: options.tableNames.price }),
    ...(options.tables?.subscription === undefined ? {} : { subscriptions: options.tables.subscription }),
    ...(options.tableNames?.subscription === undefined ? {} : { subscriptions: options.tableNames.subscription }),
    ...(options.tables?.quota === undefined ? {} : { quotas: options.tables.quota }),
    ...(options.tableNames?.quota === undefined ? {} : { quotas: options.tableNames.quota }),
    ...(options.tables?.quotaReservation === undefined ? {} : { quotaReservations: options.tables.quotaReservation }),
    ...(options.tableNames?.quotaReservation === undefined ? {} : { quotaReservations: options.tableNames.quotaReservation }),
    ...(options.tables?.usageEvent === undefined ? {} : { usageEvents: options.tables.usageEvent }),
    ...(options.tableNames?.usageEvent === undefined ? {} : { usageEvents: options.tableNames.usageEvent }),
    ...(options.tables?.usageAggregate === undefined ? {} : { usageAggregates: options.tables.usageAggregate }),
    ...(options.tableNames?.usageAggregate === undefined ? {} : { usageAggregates: options.tableNames.usageAggregate }),
    ...(options.tables?.invoice === undefined ? {} : { invoices: options.tables.invoice }),
    ...(options.tableNames?.invoice === undefined ? {} : { invoices: options.tableNames.invoice }),
    ...(options.tables?.invoiceLine === undefined ? {} : { invoiceLines: options.tables.invoiceLine }),
    ...(options.tableNames?.invoiceLine === undefined ? {} : { invoiceLines: options.tableNames.invoiceLine }),
    ...(options.tables?.invoiceStatusEvent === undefined ? {} : { invoiceStatusEvents: options.tables.invoiceStatusEvent }),
    ...(options.tableNames?.invoiceStatusEvent === undefined ? {} : { invoiceStatusEvents: options.tableNames.invoiceStatusEvent }),
    ...(options.tables?.invoiceDispute === undefined ? {} : { invoiceDisputes: options.tables.invoiceDispute }),
    ...(options.tableNames?.invoiceDispute === undefined ? {} : { invoiceDisputes: options.tableNames.invoiceDispute }),
    ...(options.tables?.marketplaceListing === undefined ? {} : { marketplaceListings: options.tables.marketplaceListing }),
    ...(options.tableNames?.marketplaceListing === undefined ? {} : { marketplaceListings: options.tableNames.marketplaceListing }),
    ...(options.tables?.partnerAccount === undefined ? {} : { partnerAccounts: options.tables.partnerAccount }),
    ...(options.tableNames?.partnerAccount === undefined ? {} : { partnerAccounts: options.tableNames.partnerAccount }),
    ...(options.tables?.commissionRule === undefined ? {} : { commissionRules: options.tables.commissionRule }),
    ...(options.tableNames?.commissionRule === undefined ? {} : { commissionRules: options.tableNames.commissionRule }),
  } as Record<CommerceSqlTableKey, string>;
  const output = {} as Record<CommerceSqlTableKey, string>;
  for (const key of COMMERCE_RUNTIME_TABLES) {
    const table = validateCommerceSqlIdentifier(configured[key], `${key} table`);
    const base = table.split(".").at(-1) ?? table;
    if (base.toLowerCase().startsWith("gb_idaas_") || COMMERCE_RESERVED_EXISTING_TABLES.includes(base.toLowerCase())) {
      throw new TypeError(`Commerce migration cannot use an existing platform table for ${key}`);
    }
    output[key] = qualifyTenantTable(table, schema);
  }
  return output;
}

function migrationColumns(
  options: OpenCommerceMigrationOptions,
  defaultTenantColumn: string,
): CommerceSqlColumns {
  const output = {} as CommerceSqlColumns;
  const tenantColumn = options.tenantColumn === undefined || options.tenantColumn === null
    ? defaultTenantColumn
    : validateCommerceSqlIdentifier(options.tenantColumn, "tenant column");
  for (const key of COMMERCE_RUNTIME_TABLES) {
    const source = {
      ...COMMERCE_SQL_COLUMNS[key],
      ...(options.columns?.[key] ?? {}),
      ...(options.columnNames?.[key] ?? {}),
    };
    if (source.tenantId === undefined || options.tenantColumn !== undefined) source.tenantId = tenantColumn;
    const normalized: Record<string, string> = {};
    for (const [field, value] of Object.entries(source)) {
      if (typeof value !== "string" || value.length === 0) continue;
      normalized[field] = validateCommerceSqlIdentifier(value, `${key}.${field}`);
    }
    output[key] = normalized;
  }
  return output;
}

function createPlanTable(tables: Record<CommerceSqlTableKey, string>, c: CommerceSqlColumns): string {
  return createTable(tables.plans, [
    ...commonColumns(c.plans, "plan", ["draft", "active", "retired"]),
    `${q(c.plans.code)} TEXT NOT NULL`,
    `${q(c.plans.name)} TEXT NOT NULL`,
    `${q(c.plans.description)} TEXT`,
    `${q(c.plans.priority)} INTEGER NOT NULL DEFAULT 0 CHECK (${q(c.plans.priority)} >= 0)`,
    `${q(c.plans.currency)} TEXT NOT NULL DEFAULT 'CNY' CHECK (${q(c.plans.currency)} = 'CNY')`,
    jsonArray(c.plans.priceIds),
    jsonArray(c.plans.entitlementIds),
    jsonArray(c.plans.quotaIds),
    timestampColumn(c.plans.effectiveFrom, false),
    timestampColumn(c.plans.effectiveTo, true),
    `CHECK (${q(c.plans.effectiveTo)} IS NULL OR ${q(c.plans.effectiveTo)} > ${q(c.plans.effectiveFrom)})`,
  ]);
}

function createEntitlementTable(tables: Record<CommerceSqlTableKey, string>, c: CommerceSqlColumns): string {
  return createTable(tables.entitlements, [
    ...commonColumns(c.entitlements, "entitlement", ["pending", "active", "suspended", "revoked", "expired"]),
    `${q(c.entitlements.feature)} TEXT NOT NULL`,
    `${q(c.entitlements.effect)} TEXT NOT NULL CHECK (${q(c.entitlements.effect)} IN ('allow', 'deny'))`,
    `${q(c.entitlements.valueType)} TEXT CHECK (${q(c.entitlements.valueType)} IN ('boolean', 'integer', 'string'))`,
    `${q(c.entitlements.valueBoolean)} BOOLEAN`,
    `${q(c.entitlements.valueInteger)} BIGINT CHECK (${q(c.entitlements.valueInteger)} IS NULL OR ${q(c.entitlements.valueInteger)} BETWEEN 0 AND 9007199254740991)`,
    `${q(c.entitlements.valueText)} TEXT`,
    `${q(c.entitlements.source)} TEXT NOT NULL CHECK (${q(c.entitlements.source)} IN ('tenant', 'plan', 'subscription'))`,
    `${q(c.entitlements.sourceId)} TEXT NOT NULL`,
    `${q(c.entitlements.priority)} INTEGER NOT NULL DEFAULT 0 CHECK (${q(c.entitlements.priority)} >= 0)`,
    timestampColumn(c.entitlements.effectiveFrom, false),
    timestampColumn(c.entitlements.effectiveTo, true),
    `CHECK (${q(c.entitlements.effectiveTo)} IS NULL OR ${q(c.entitlements.effectiveTo)} > ${q(c.entitlements.effectiveFrom)})`,
    valueCheck(c.entitlements),
  ]);
}

function createMeterTable(tables: Record<CommerceSqlTableKey, string>, c: CommerceSqlColumns): string {
  return createTable(tables.meters, [
    ...commonColumns(c.meters, "meter", ["draft", "active", "retired"]),
    `${q(c.meters.key)} TEXT NOT NULL`,
    `${q(c.meters.name)} TEXT NOT NULL`,
    `${q(c.meters.unit)} TEXT NOT NULL`,
    `${q(c.meters.aggregation)} TEXT NOT NULL CHECK (${q(c.meters.aggregation)} IN ('sum', 'max', 'last'))`,
    jsonArray(c.meters.dimensions),
  ]);
}

function createPriceTable(tables: Record<CommerceSqlTableKey, string>, c: CommerceSqlColumns): string {
  return createTable(tables.prices, [
    ...commonColumns(c.prices, "price", ["draft", "scheduled", "active", "retired"]),
    `${q(c.prices.code)} TEXT NOT NULL`,
    `${q(c.prices.name)} TEXT NOT NULL`,
    `${q(c.prices.currency)} TEXT NOT NULL DEFAULT 'CNY' CHECK (${q(c.prices.currency)} = 'CNY')`,
    `${q(c.prices.roundingMode)} TEXT NOT NULL DEFAULT 'halfUp' CHECK (${q(c.prices.roundingMode)} IN ('halfEven', 'halfUp'))`,
    `${q(c.prices.priceType)} TEXT NOT NULL CHECK (${q(c.prices.priceType)} IN ('fixed', 'perUnit', 'tiered', 'mixed'))`,
    moneyColumn(c.prices.fixedAmountMinor, true),
    `${q(c.prices.meterId)} TEXT`,
    moneyColumn(c.prices.unitAmountMinor, true),
    decimalColumn(c.prices.includedUnits, true, false),
    moneyColumn(c.prices.minimumChargeMinor, true),
    `${q(c.prices.tiers)} JSONB`,
    timestampColumn(c.prices.effectiveFrom, false),
    timestampColumn(c.prices.effectiveTo, true),
    `CHECK (${q(c.prices.effectiveTo)} IS NULL OR ${q(c.prices.effectiveTo)} > ${q(c.prices.effectiveFrom)})`,
    `CHECK (${q(c.prices.priceType)} = 'fixed' OR ${q(c.prices.meterId)} IS NOT NULL)`,
    `CHECK (${q(c.prices.priceType)} NOT IN ('perUnit', 'mixed') OR (${q(c.prices.unitAmountMinor)} IS NOT NULL AND ${q(c.prices.includedUnits)} IS NOT NULL AND ${q(c.prices.minimumChargeMinor)} IS NOT NULL))`,
    `CHECK (${q(c.prices.priceType)} <> 'tiered' OR ${q(c.prices.tiers)} IS NOT NULL)`,
    foreignKey(c.prices, [c.prices.tenantId, c.prices.meterId], tables.meters, [c.meters.tenantId, c.meters.id]),
  ]);
}

function createSubscriptionTable(tables: Record<CommerceSqlTableKey, string>, c: CommerceSqlColumns): string {
  return createTable(tables.subscriptions, [
    ...commonColumns(c.subscriptions, "subscription", ["pending", "trialing", "active", "pastDue", "suspended", "canceled", "expired"]),
    `${q(c.subscriptions.applicationId)} TEXT NOT NULL`,
    `${q(c.subscriptions.planId)} TEXT NOT NULL`,
    `${q(c.subscriptions.name)} TEXT NOT NULL`,
    decimalColumn(c.subscriptions.quantity, false, true),
    timestampColumn(c.subscriptions.currentPeriodStart, false),
    timestampColumn(c.subscriptions.currentPeriodEnd, false),
    `${q(c.subscriptions.cancelAtPeriodEnd)} BOOLEAN NOT NULL DEFAULT FALSE`,
    timestampColumn(c.subscriptions.canceledAt, true),
    `CHECK (${q(c.subscriptions.currentPeriodEnd)} > ${q(c.subscriptions.currentPeriodStart)})`,
    foreignKey(c.subscriptions, [c.subscriptions.tenantId, c.subscriptions.planId], tables.plans, [c.plans.tenantId, c.plans.id]),
  ]);
}

function createQuotaTable(tables: Record<CommerceSqlTableKey, string>, c: CommerceSqlColumns): string {
  return createTable(tables.quotas, [
    ...commonColumns(c.quotas, "quota", ["active", "disabled", "retired"]),
    `${q(c.quotas.planId)} TEXT NOT NULL`,
    `${q(c.quotas.meterId)} TEXT NOT NULL`,
    decimalColumn(c.quotas.limit, false, true),
    decimalColumn(c.quotas.reserved, false, false),
    decimalColumn(c.quotas.consumed, false, false),
    `CHECK (${q(c.quotas.reserved)} + ${q(c.quotas.consumed)} <= ${q(c.quotas.limit)})`,
    foreignKey(c.quotas, [c.quotas.tenantId, c.quotas.planId], tables.plans, [c.plans.tenantId, c.plans.id]),
    foreignKey(c.quotas, [c.quotas.tenantId, c.quotas.meterId], tables.meters, [c.meters.tenantId, c.meters.id]),
  ]);
}

function createQuotaReservationTable(tables: Record<CommerceSqlTableKey, string>, c: CommerceSqlColumns): string {
  return createTable(tables.quotaReservations, [
    ...commonColumns(c.quotaReservations, "quotaReservation", ["reserved", "settled", "released", "expired"]),
    `${q(c.quotaReservations.quotaId)} TEXT NOT NULL`,
    `${q(c.quotaReservations.planId)} TEXT NOT NULL`,
    `${q(c.quotaReservations.subscriptionId)} TEXT NOT NULL`,
    `${q(c.quotaReservations.meterId)} TEXT NOT NULL`,
    decimalColumn(c.quotaReservations.quantity, false, true),
    `${q(c.quotaReservations.operation)} TEXT NOT NULL DEFAULT 'quota.reserve' CHECK (${q(c.quotaReservations.operation)} = 'quota.reserve')`,
    `${q(c.quotaReservations.idempotencyKey)} TEXT NOT NULL`,
    hashColumn(c.quotaReservations.requestHash),
    timestampColumn(c.quotaReservations.expiresAt, false),
    decimalColumn(c.quotaReservations.settledQuantity, true, false),
    timestampColumn(c.quotaReservations.settledAt, true),
    timestampColumn(c.quotaReservations.releasedAt, true),
    `${q(c.quotaReservations.terminalOperation)} TEXT CHECK (${q(c.quotaReservations.terminalOperation)} IN ('quota.settle', 'quota.release'))`,
    `${q(c.quotaReservations.terminalIdempotencyKey)} TEXT`,
    hashColumn(c.quotaReservations.terminalRequestHash, true),
    `CHECK (${q(c.quotaReservations.expiresAt)} > ${q(c.quotaReservations.createdAt)})`,
    foreignKey(c.quotaReservations, [c.quotaReservations.tenantId, c.quotaReservations.quotaId], tables.quotas, [c.quotas.tenantId, c.quotas.id]),
    foreignKey(c.quotaReservations, [c.quotaReservations.tenantId, c.quotaReservations.planId], tables.plans, [c.plans.tenantId, c.plans.id]),
    foreignKey(c.quotaReservations, [c.quotaReservations.tenantId, c.quotaReservations.subscriptionId], tables.subscriptions, [c.subscriptions.tenantId, c.subscriptions.id]),
    foreignKey(c.quotaReservations, [c.quotaReservations.tenantId, c.quotaReservations.meterId], tables.meters, [c.meters.tenantId, c.meters.id]),
  ]);
}

function createUsageEventTable(tables: Record<CommerceSqlTableKey, string>, c: CommerceSqlColumns): string {
  return createTable(tables.usageEvents, [
    `${q(c.usageEvents.id)} TEXT NOT NULL`,
    `${q(c.usageEvents.tenantId)} TEXT NOT NULL`,
    `${q(c.usageEvents.kind)} TEXT NOT NULL DEFAULT 'usageEvent' CHECK (${q(c.usageEvents.kind)} = 'usageEvent')`,
    `${q(c.usageEvents.version)} INTEGER NOT NULL DEFAULT 1 CHECK (${q(c.usageEvents.version)} = 1)`,
    `${q(c.usageEvents.sourceEventId)} TEXT NOT NULL`,
    `${q(c.usageEvents.subscriptionId)} TEXT NOT NULL`,
    `${q(c.usageEvents.meterId)} TEXT NOT NULL`,
    decimalColumn(c.usageEvents.quantity, false, true),
    timestampColumn(c.usageEvents.occurredAt, false),
    timestampColumn(c.usageEvents.periodStart, false),
    timestampColumn(c.usageEvents.periodEnd, false),
    jsonObject(c.usageEvents.dimensions),
    `${q(c.usageEvents.idempotencyKey)} TEXT NOT NULL`,
    hashColumn(c.usageEvents.requestHash),
    hashColumn(c.usageEvents.payloadHash),
    timestampColumn(c.usageEvents.receivedAt, false),
    `PRIMARY KEY (${q(c.usageEvents.tenantId)}, ${q(c.usageEvents.id)})`,
    `CHECK (${q(c.usageEvents.periodEnd)} > ${q(c.usageEvents.periodStart)})`,
    `CHECK (${q(c.usageEvents.occurredAt)} >= ${q(c.usageEvents.periodStart)} AND ${q(c.usageEvents.occurredAt)} < ${q(c.usageEvents.periodEnd)})`,
    foreignKey(c.usageEvents, [c.usageEvents.tenantId, c.usageEvents.subscriptionId], tables.subscriptions, [c.subscriptions.tenantId, c.subscriptions.id]),
    foreignKey(c.usageEvents, [c.usageEvents.tenantId, c.usageEvents.meterId], tables.meters, [c.meters.tenantId, c.meters.id]),
  ]);
}

function createUsageAggregateTable(tables: Record<CommerceSqlTableKey, string>, c: CommerceSqlColumns): string {
  return createTable(tables.usageAggregates, [
    ...commonColumns(c.usageAggregates, "usageAggregate", ["collecting", "closed", "priced", "settled"]),
    `${q(c.usageAggregates.aggregateKey)} TEXT NOT NULL`,
    `${q(c.usageAggregates.subscriptionId)} TEXT NOT NULL`,
    `${q(c.usageAggregates.meterId)} TEXT NOT NULL`,
    `${q(c.usageAggregates.aggregation)} TEXT NOT NULL CHECK (${q(c.usageAggregates.aggregation)} IN ('sum', 'max', 'last'))`,
    decimalColumn(c.usageAggregates.quantity, false, false),
    `${q(c.usageAggregates.unit)} TEXT NOT NULL`,
    timestampColumn(c.usageAggregates.periodStart, false),
    timestampColumn(c.usageAggregates.periodEnd, false),
    jsonObject(c.usageAggregates.dimensions),
    jsonArray(c.usageAggregates.eventIds),
    `CHECK (${q(c.usageAggregates.periodEnd)} > ${q(c.usageAggregates.periodStart)})`,
    foreignKey(c.usageAggregates, [c.usageAggregates.tenantId, c.usageAggregates.subscriptionId], tables.subscriptions, [c.subscriptions.tenantId, c.subscriptions.id]),
    foreignKey(c.usageAggregates, [c.usageAggregates.tenantId, c.usageAggregates.meterId], tables.meters, [c.meters.tenantId, c.meters.id]),
  ]);
}

function createInvoiceTable(tables: Record<CommerceSqlTableKey, string>, c: CommerceSqlColumns): string {
  return createTable(tables.invoices, [
    ...commonColumns(c.invoices, "invoice", ["draft", "reconciling", "awaitingPayment", "invoicing", "paid", "completed", "disputed", "voided"]),
    `${q(c.invoices.subscriptionId)} TEXT NOT NULL`,
    `${q(c.invoices.planId)} TEXT NOT NULL`,
    timestampColumn(c.invoices.periodStart, false),
    timestampColumn(c.invoices.periodEnd, false),
    `${q(c.invoices.currency)} TEXT NOT NULL DEFAULT 'CNY' CHECK (${q(c.invoices.currency)} = 'CNY')`,
    `${q(c.invoices.taxMode)} TEXT NOT NULL CHECK (${q(c.invoices.taxMode)} IN ('exclusive', 'inclusive'))`,
    moneyColumn(c.invoices.subtotalMinor, false),
    moneyColumn(c.invoices.taxMinor, false),
    moneyColumn(c.invoices.totalMinor, false),
    `${q(c.invoices.idempotencyKey)} TEXT NOT NULL`,
    hashColumn(c.invoices.requestHash),
    `${q(c.invoices.mainlandChina)} JSONB`,
    timestampColumn(c.invoices.finalizedAt, true),
    timestampColumn(c.invoices.paidAt, true),
    timestampColumn(c.invoices.voidedAt, true),
    `CHECK (${q(c.invoices.periodEnd)} > ${q(c.invoices.periodStart)})`,
    foreignKey(c.invoices, [c.invoices.tenantId, c.invoices.subscriptionId], tables.subscriptions, [c.subscriptions.tenantId, c.subscriptions.id]),
    foreignKey(c.invoices, [c.invoices.tenantId, c.invoices.planId], tables.plans, [c.plans.tenantId, c.plans.id]),
  ]);
}

function createInvoiceLineTable(tables: Record<CommerceSqlTableKey, string>, c: CommerceSqlColumns): string {
  return createTable(tables.invoiceLines, [
    `${q(c.invoiceLines.id)} TEXT NOT NULL`,
    `${q(c.invoiceLines.tenantId)} TEXT NOT NULL`,
    `${q(c.invoiceLines.kind)} TEXT NOT NULL DEFAULT 'invoiceLine' CHECK (${q(c.invoiceLines.kind)} = 'invoiceLine')`,
    `${q(c.invoiceLines.invoiceId)} TEXT NOT NULL`,
    `${q(c.invoiceLines.type)} TEXT NOT NULL CHECK (${q(c.invoiceLines.type)} IN ('subscription', 'usage', 'adjustment', 'tax'))`,
    `${q(c.invoiceLines.direction)} TEXT NOT NULL CHECK (${q(c.invoiceLines.direction)} IN ('debit', 'credit'))`,
    `${q(c.invoiceLines.description)} TEXT NOT NULL`,
    decimalColumn(c.invoiceLines.quantity, false, false),
    moneyColumn(c.invoiceLines.unitAmountMinor, false),
    moneyColumn(c.invoiceLines.amountMinor, false),
    `${q(c.invoiceLines.currency)} TEXT NOT NULL DEFAULT 'CNY' CHECK (${q(c.invoiceLines.currency)} = 'CNY')`,
    `${q(c.invoiceLines.meterId)} TEXT`,
    `${q(c.invoiceLines.priceId)} TEXT`,
    `${q(c.invoiceLines.aggregateId)} TEXT`,
    `${q(c.invoiceLines.adjustmentType)} TEXT CHECK (${q(c.invoiceLines.adjustmentType)} IN ('discount', 'refund', 'surcharge', 'credit'))`,
    `PRIMARY KEY (${q(c.invoiceLines.tenantId)}, ${q(c.invoiceLines.id)})`,
    foreignKey(c.invoiceLines, [c.invoiceLines.tenantId, c.invoiceLines.invoiceId], tables.invoices, [c.invoices.tenantId, c.invoices.id]),
    foreignKey(c.invoiceLines, [c.invoiceLines.tenantId, c.invoiceLines.meterId], tables.meters, [c.meters.tenantId, c.meters.id]),
    foreignKey(c.invoiceLines, [c.invoiceLines.tenantId, c.invoiceLines.priceId], tables.prices, [c.prices.tenantId, c.prices.id]),
    foreignKey(c.invoiceLines, [c.invoiceLines.tenantId, c.invoiceLines.aggregateId], tables.usageAggregates, [c.usageAggregates.tenantId, c.usageAggregates.id]),
  ]);
}

function createInvoiceStatusEventTable(tables: Record<CommerceSqlTableKey, string>, c: CommerceSqlColumns): string {
  return createTable(tables.invoiceStatusEvents, [
    `${q(c.invoiceStatusEvents.tenantId)} TEXT NOT NULL`,
    `${q(c.invoiceStatusEvents.invoiceId)} TEXT NOT NULL`,
    `${q(c.invoiceStatusEvents.version)} INTEGER NOT NULL CHECK (${q(c.invoiceStatusEvents.version)} > 1)`,
    `${q(c.invoiceStatusEvents.status)} TEXT NOT NULL CHECK (${q(c.invoiceStatusEvents.status)} IN ('draft', 'reconciling', 'awaitingPayment', 'invoicing', 'paid', 'completed', 'disputed', 'voided'))`,
    `${q(c.invoiceStatusEvents.previousStatus)} TEXT NOT NULL CHECK (${q(c.invoiceStatusEvents.previousStatus)} IN ('draft', 'reconciling', 'awaitingPayment', 'invoicing', 'paid', 'completed', 'disputed', 'voided'))`,
    timestampColumn(c.invoiceStatusEvents.occurredAt, false),
    timestampColumn(c.invoiceStatusEvents.paidAt, true),
    timestampColumn(c.invoiceStatusEvents.finalizedAt, true),
    timestampColumn(c.invoiceStatusEvents.voidedAt, true),
    `PRIMARY KEY (${q(c.invoiceStatusEvents.tenantId)}, ${q(c.invoiceStatusEvents.invoiceId)}, ${q(c.invoiceStatusEvents.version)})`,
    foreignKey(c.invoiceStatusEvents, [c.invoiceStatusEvents.tenantId, c.invoiceStatusEvents.invoiceId], tables.invoices, [c.invoices.tenantId, c.invoices.id]),
  ]);
}

function createMarketplaceListingTable(tables: Record<CommerceSqlTableKey, string>, c: CommerceSqlColumns): string {
  return createTable(tables.marketplaceListings, [
    ...commonColumns(c.marketplaceListings, "marketplaceListing", ["draft", "pendingReview", "published", "suspended", "removed"]),
    `${q(c.marketplaceListings.partnerAccountId)} TEXT NOT NULL`,
    `${q(c.marketplaceListings.productId)} TEXT NOT NULL`,
    `${q(c.marketplaceListings.title)} TEXT NOT NULL`,
    `${q(c.marketplaceListings.description)} TEXT NOT NULL`,
    jsonArray(c.marketplaceListings.priceIds),
    jsonArray(c.marketplaceListings.commissionRuleIds),
    timestampColumn(c.marketplaceListings.submittedAt, true),
    timestampColumn(c.marketplaceListings.publishedAt, true),
    timestampColumn(c.marketplaceListings.removedAt, true),
    foreignKey(c.marketplaceListings, [c.marketplaceListings.tenantId, c.marketplaceListings.partnerAccountId], tables.partnerAccounts, [c.partnerAccounts.tenantId, c.partnerAccounts.id]),
  ]);
}

function createPartnerAccountTable(tables: Record<CommerceSqlTableKey, string>, c: CommerceSqlColumns): string {
  return createTable(tables.partnerAccounts, [
    ...commonColumns(c.partnerAccounts, "partnerAccount", ["pending", "underReview", "active", "frozen", "rejected", "closed"]),
    `${q(c.partnerAccounts.legalName)} TEXT NOT NULL`,
    `${q(c.partnerAccounts.partnerCode)} TEXT NOT NULL`,
    `${q(c.partnerAccounts.currency)} TEXT NOT NULL DEFAULT 'CNY' CHECK (${q(c.partnerAccounts.currency)} = 'CNY')`,
    `${q(c.partnerAccounts.settlementReference)} TEXT NOT NULL`,
    timestampColumn(c.partnerAccounts.activatedAt, true),
  ]);
}

function createCommissionRuleTable(tables: Record<CommerceSqlTableKey, string>, c: CommerceSqlColumns): string {
  return createTable(tables.commissionRules, [
    ...commonColumns(c.commissionRules, "commissionRule", ["draft", "scheduled", "active", "suspended", "retired"]),
    `${q(c.commissionRules.partnerAccountId)} TEXT NOT NULL`,
    `${q(c.commissionRules.listingId)} TEXT NOT NULL`,
    `${q(c.commissionRules.name)} TEXT NOT NULL`,
    `${q(c.commissionRules.rateBps)} INTEGER NOT NULL CHECK (${q(c.commissionRules.rateBps)} BETWEEN 0 AND 10000)`,
    `${q(c.commissionRules.capBps)} INTEGER CHECK (${q(c.commissionRules.capBps)} IS NULL OR ${q(c.commissionRules.capBps)} BETWEEN 0 AND 10000)`,
    moneyColumn(c.commissionRules.capAmountMinor, true),
    `${q(c.commissionRules.currency)} TEXT NOT NULL DEFAULT 'CNY' CHECK (${q(c.commissionRules.currency)} = 'CNY')`,
    `${q(c.commissionRules.priority)} INTEGER NOT NULL DEFAULT 0 CHECK (${q(c.commissionRules.priority)} >= 0)`,
    timestampColumn(c.commissionRules.effectiveFrom, false),
    timestampColumn(c.commissionRules.effectiveTo, true),
    `CHECK (${q(c.commissionRules.effectiveTo)} IS NULL OR ${q(c.commissionRules.effectiveTo)} > ${q(c.commissionRules.effectiveFrom)})`,
    foreignKey(c.commissionRules, [c.commissionRules.tenantId, c.commissionRules.partnerAccountId], tables.partnerAccounts, [c.partnerAccounts.tenantId, c.partnerAccounts.id]),
    foreignKey(c.commissionRules, [c.commissionRules.tenantId, c.commissionRules.listingId], tables.marketplaceListings, [c.marketplaceListings.tenantId, c.marketplaceListings.id]),
  ]);
}

function commonColumns(
  columns: Record<string, string>,
  kind: string,
  statuses: readonly string[],
): string[] {
  return [
    `${q(columns.id)} TEXT NOT NULL`,
    `${q(columns.tenantId)} TEXT NOT NULL`,
    `${q(columns.kind)} TEXT NOT NULL DEFAULT '${kind}' CHECK (${q(columns.kind)} = '${kind}')`,
    `${q(columns.status)} TEXT NOT NULL CHECK (${q(columns.status)} IN (${statuses.map((status) => `'${status}'`).join(", ")}))`,
    `${q(columns.version)} INTEGER NOT NULL DEFAULT 1 CHECK (${q(columns.version)} > 0)`,
    timestampColumn(columns.createdAt, false),
    timestampColumn(columns.updatedAt, false),
    `CHECK (${q(columns.updatedAt)} >= ${q(columns.createdAt)})`,
    `PRIMARY KEY (${q(columns.tenantId)}, ${q(columns.id)})`,
  ];
}

function createTable(table: string, definitions: string[]): string {
  return `CREATE TABLE IF NOT EXISTS ${q(table)} (${definitions.join(", ")})`;
}

function jsonArray(column: string): string {
  return `${q(column)} JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(${q(column)}) = 'array')`;
}

function jsonObject(column: string): string {
  return `${q(column)} JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(${q(column)}) = 'object')`;
}

function timestampColumn(column: string, optional: boolean): string {
  return optional
    ? `${q(column)} TIMESTAMPTZ`
    : `${q(column)} TIMESTAMPTZ NOT NULL`;
}

function decimalColumn(column: string, optional: boolean, positive: boolean): string {
  const check = positive ? ` > 0` : ` >= 0`;
  return optional
    ? `${q(column)} NUMERIC(38,18) CHECK (${q(column)} IS NULL OR ${q(column)}${check})`
    : `${q(column)} NUMERIC(38,18) NOT NULL CHECK (${q(column)}${check})`;
}

function moneyColumn(column: string, optional: boolean): string {
  return `${q(column)} BIGINT${optional ? "" : " NOT NULL"}${optional ? ` CHECK (${q(column)} IS NULL OR ${q(column)} BETWEEN 0 AND 9007199254740991)` : ` CHECK (${q(column)} BETWEEN 0 AND 9007199254740991)`}`;
}

function hashColumn(column: string, optional = false): string {
  return `${q(column)} TEXT${optional ? "" : " NOT NULL"}${optional ? ` CHECK (${q(column)} IS NULL OR ${q(column)} ~ '^[a-f0-9]{64}$')` : ` CHECK (${q(column)} ~ '^[a-f0-9]{64}$')`}`;
}

function valueCheck(columns: Record<string, string>): string {
  const type = q(columns.valueType);
  const bool = q(columns.valueBoolean);
  const integer = q(columns.valueInteger);
  const text = q(columns.valueText);
  return `CHECK ((${type} IS NULL AND ${bool} IS NULL AND ${integer} IS NULL AND ${text} IS NULL) OR (${type} = 'boolean' AND ${bool} IS NOT NULL AND ${integer} IS NULL AND ${text} IS NULL) OR (${type} = 'integer' AND ${bool} IS NULL AND ${integer} IS NOT NULL AND ${text} IS NULL) OR (${type} = 'string' AND ${bool} IS NULL AND ${integer} IS NULL AND ${text} IS NOT NULL))`;
}

function foreignKey(
  columns: Record<string, string>,
  source: readonly [string, string],
  table: string,
  target: readonly [string, string],
): string {
  return `FOREIGN KEY (${q(source[0])}, ${q(source[1])}) REFERENCES ${q(table)} (${q(target[0])}, ${q(target[1])})`;
}

function uniqueConstraints(
  tables: Record<CommerceSqlTableKey, string>,
  c: CommerceSqlColumns,
): string[] {
  return [
    uniqueIndex(tables.plans, "code_uq", [c.plans.tenantId, `LOWER(${q(c.plans.code)})`]),
    uniqueIndex(tables.entitlements, "feature_source_uq", [c.entitlements.tenantId, c.entitlements.feature, c.entitlements.source, c.entitlements.sourceId, c.entitlements.priority, c.entitlements.effectiveFrom]),
    uniqueIndex(tables.meters, "key_uq", [c.meters.tenantId, `LOWER(${q(c.meters.key)})`]),
    uniqueIndex(tables.prices, "code_uq", [c.prices.tenantId, `LOWER(${q(c.prices.code)})`]),
    uniqueIndex(tables.subscriptions, "application_period_uq", [c.subscriptions.tenantId, c.subscriptions.applicationId, c.subscriptions.planId, c.subscriptions.currentPeriodStart]),
    uniqueIndex(tables.quotas, "plan_meter_uq", [c.quotas.tenantId, c.quotas.planId, c.quotas.meterId]),
    uniqueIndex(tables.quotaReservations, "reserve_idempotency_uq", [c.quotaReservations.tenantId, c.quotaReservations.quotaId, c.quotaReservations.subscriptionId, c.quotaReservations.idempotencyKey]),
    uniqueIndex(tables.quotaReservations, "terminal_idempotency_uq", [c.quotaReservations.tenantId, c.quotaReservations.quotaId, c.quotaReservations.terminalOperation, c.quotaReservations.terminalIdempotencyKey]),
    uniqueIndex(tables.usageEvents, "idempotency_uq", [c.usageEvents.tenantId, c.usageEvents.idempotencyKey]),
    uniqueIndex(tables.usageEvents, "source_event_uq", [c.usageEvents.tenantId, c.usageEvents.sourceEventId]),
    uniqueIndex(tables.usageAggregates, "aggregate_key_uq", [c.usageAggregates.tenantId, c.usageAggregates.aggregateKey]),
    uniqueIndex(tables.invoices, "idempotency_uq", [c.invoices.tenantId, c.invoices.idempotencyKey]),
    uniqueIndex(tables.marketplaceListings, "partner_product_uq", [c.marketplaceListings.tenantId, c.marketplaceListings.partnerAccountId, c.marketplaceListings.productId]),
    uniqueIndex(tables.partnerAccounts, "partner_code_uq", [c.partnerAccounts.tenantId, `LOWER(${q(c.partnerAccounts.partnerCode)})`]),
    uniqueIndex(tables.commissionRules, "rule_scope_uq", [c.commissionRules.tenantId, c.commissionRules.partnerAccountId, c.commissionRules.listingId, c.commissionRules.priority, c.commissionRules.effectiveFrom]),
  ];
}

function indexes(
  tables: Record<CommerceSqlTableKey, string>,
  c: CommerceSqlColumns,
): string[] {
  return [
    index(tables.plans, "status_idx", [c.plans.tenantId, c.plans.status, c.plans.createdAt]),
    index(tables.entitlements, "lookup_idx", [c.entitlements.tenantId, c.entitlements.feature, c.entitlements.status, c.entitlements.priority]),
    index(tables.meters, "status_idx", [c.meters.tenantId, c.meters.status, c.meters.createdAt]),
    index(tables.prices, "status_idx", [c.prices.tenantId, c.prices.status, c.prices.effectiveFrom]),
    index(tables.subscriptions, "application_idx", [c.subscriptions.tenantId, c.subscriptions.applicationId, c.subscriptions.status]),
    index(tables.quotas, "plan_meter_idx", [c.quotas.tenantId, c.quotas.planId, c.quotas.meterId, c.quotas.status]),
    index(tables.quotaReservations, "expiry_idx", [c.quotaReservations.tenantId, c.quotaReservations.status, c.quotaReservations.expiresAt]),
    index(tables.usageEvents, "occurred_idx", [c.usageEvents.tenantId, c.usageEvents.occurredAt, c.usageEvents.id]),
    index(tables.usageEvents, "subscription_idx", [c.usageEvents.tenantId, c.usageEvents.subscriptionId, c.usageEvents.periodStart, c.usageEvents.periodEnd]),
    index(tables.usageAggregates, "subscription_idx", [c.usageAggregates.tenantId, c.usageAggregates.subscriptionId, c.usageAggregates.periodStart, c.usageAggregates.periodEnd]),
    index(tables.invoices, "subscription_idx", [c.invoices.tenantId, c.invoices.subscriptionId, c.invoices.createdAt]),
    index(tables.invoiceLines, "invoice_idx", [c.invoiceLines.tenantId, c.invoiceLines.invoiceId]),
    index(tables.marketplaceListings, "partner_idx", [c.marketplaceListings.tenantId, c.marketplaceListings.partnerAccountId, c.marketplaceListings.status]),
    index(tables.partnerAccounts, "status_idx", [c.partnerAccounts.tenantId, c.partnerAccounts.status]),
    index(tables.commissionRules, "lookup_idx", [c.commissionRules.tenantId, c.commissionRules.listingId, c.commissionRules.status, c.commissionRules.priority]),
  ];
}

function uniqueIndex(table: string, suffix: string, columns: readonly string[]): string {
  return `CREATE UNIQUE INDEX IF NOT EXISTS ${q(objectName(table, suffix))} ON ${q(table)} (${columns.map((column) => column.includes("(") ? column : q(column)).join(", ")})`;
}

function index(table: string, suffix: string, columns: readonly string[]): string {
  return `CREATE INDEX IF NOT EXISTS ${q(objectName(table, suffix))} ON ${q(table)} (${columns.map(q).join(", ")})`;
}

function appendOnlyStatements(tables: Record<CommerceSqlTableKey, string>): string[] {
  return [
    ...immutableTrigger(tables.usageEvents, "gb_open_commerce_reject_usage_event_mutation", "gb_open_commerce_usage_event is append-only"),
    ...immutableTrigger(tables.invoices, "gb_open_commerce_reject_invoice_mutation", "gb_open_commerce_invoice is append-only"),
    ...immutableTrigger(tables.invoiceLines, "gb_open_commerce_reject_invoice_line_mutation", "gb_open_commerce_invoice_line is append-only"),
    ...immutableTrigger(tables.invoiceStatusEvents, "gb_open_commerce_reject_invoice_status_mutation", "gb_open_commerce_invoice_status_event is append-only"),
  ];
}

function immutabilityStatements(
  tables: Record<CommerceSqlTableKey, string>,
  c: CommerceSqlColumns,
): string[] {
  const functionName = qualifyFunctionName(tables.commissionRules, "gb_open_commerce_reject_commission_mutation");
  const immutableColumns = [
    c.commissionRules.tenantId,
    c.commissionRules.id,
    c.commissionRules.kind,
    c.commissionRules.partnerAccountId,
    c.commissionRules.listingId,
    c.commissionRules.name,
    c.commissionRules.rateBps,
    c.commissionRules.capBps,
    c.commissionRules.capAmountMinor,
    c.commissionRules.currency,
    c.commissionRules.priority,
    c.commissionRules.effectiveFrom,
    c.commissionRules.effectiveTo,
    c.commissionRules.createdAt,
  ];
  return [
    `CREATE OR REPLACE FUNCTION ${q(functionName)}() RETURNS trigger LANGUAGE plpgsql AS $gb_open$ BEGIN IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'gb_open_commerce_commission_rule is immutable' USING ERRCODE = '55000'; END IF; ${immutableColumns.map((column) => `IF NEW.${q(column)} IS DISTINCT FROM OLD.${q(column)} THEN RAISE EXCEPTION 'gb_open_commerce_commission_rule financial fields are immutable' USING ERRCODE = '55000'; END IF;`).join(" ")} RETURN NEW; END; $gb_open$`,
    `DROP TRIGGER IF EXISTS ${q(objectName(tables.commissionRules, "immutable"))} ON ${q(tables.commissionRules)}`,
    `CREATE TRIGGER ${q(objectName(tables.commissionRules, "immutable"))} BEFORE UPDATE OR DELETE ON ${q(tables.commissionRules)} FOR EACH ROW EXECUTE FUNCTION ${q(functionName)}()`,
  ];
}

function immutableTrigger(table: string, functionName: string, message: string): string[] {
  const qualifiedFunction = qualifyFunctionName(table, functionName);
  return [
    `CREATE OR REPLACE FUNCTION ${q(qualifiedFunction)}() RETURNS trigger LANGUAGE plpgsql AS $gb_open$ BEGIN RAISE EXCEPTION '${message}' USING ERRCODE = '55000'; END; $gb_open$`,
    `DROP TRIGGER IF EXISTS ${q(objectName(table, "append_only"))} ON ${q(table)}`,
    `CREATE TRIGGER ${q(objectName(table, "append_only"))} BEFORE UPDATE OR DELETE ON ${q(table)} FOR EACH ROW EXECUTE FUNCTION ${q(qualifiedFunction)}()`,
  ];
}

function disputeImmutabilityStatements(
  table: string,
  c: Record<string, string>,
): string[] {
  const functionName = qualifyFunctionName(
    table,
    "gb_open_commerce_enforce_invoice_dispute_immutability",
  );
  const immutableColumns = [
    c.tenantId,
    c.id,
    c.kind,
    c.event,
    c.invoiceId,
    c.subscriptionId,
    c.planId,
    c.invoiceStatus,
    c.invoiceVersion,
    c.reason,
    c.reasonDigest,
    c.reasonLength,
    c.evidenceReference,
    c.evidenceReferenceDigest,
    c.evidenceCount,
    c.actorId,
    c.requestId,
    c.idempotencyKey,
    c.requestHash,
    c.createdAt,
    c.recordedAt,
  ];
  return [
    `CREATE OR REPLACE FUNCTION ${q(functionName)}() RETURNS trigger LANGUAGE plpgsql AS $gb_open$ BEGIN IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'gb_open_commerce_invoice_dispute evidence is immutable' USING ERRCODE = '55000'; END IF; ${immutableColumns.map((column) => `IF NEW.${q(column)} IS DISTINCT FROM OLD.${q(column)} THEN RAISE EXCEPTION 'gb_open_commerce_invoice_dispute evidence is immutable' USING ERRCODE = '55000'; END IF;`).join(" ")} RETURN NEW; END; $gb_open$`,
    `DROP TRIGGER IF EXISTS ${q(objectName(table, "append_only"))} ON ${q(table)}`,
    `DROP TRIGGER IF EXISTS ${q(objectName(table, "immutable"))} ON ${q(table)}`,
    `CREATE TRIGGER ${q(objectName(table, "immutable"))} BEFORE UPDATE OR DELETE ON ${q(table)} FOR EACH ROW EXECUTE FUNCTION ${q(functionName)}()`,
  ];
}

function rlsStatements(
  tables: Record<CommerceSqlTableKey, string>,
  c: CommerceSqlColumns,
): string[] {
  const statements: string[] = [];
  for (const key of COMMERCE_ALL_TABLES) {
    const table = tables[key];
    const policy = objectName(table, "tenant_policy");
    statements.push(
      `ALTER TABLE ${q(table)} ENABLE ROW LEVEL SECURITY`,
      `ALTER TABLE ${q(table)} FORCE ROW LEVEL SECURITY`,
      `DROP POLICY IF EXISTS ${q(policy)} ON ${q(table)}`,
      `CREATE POLICY ${q(policy)} ON ${q(table)} USING (${q(c[key].tenantId)} = current_setting('app.tenant_id', true)) WITH CHECK (${q(c[key].tenantId)} = current_setting('app.tenant_id', true))`,
    );
  }
  return statements;
}

function migrationIdempotencyTable(
  options: OpenCommerceMigrationOptions,
  schema: string,
): string {
  const table = validateCommerceSqlIdentifier(
    options.idempotencyTable ?? OPEN_COMMERCE_IDEMPOTENCY_TABLE,
    "idempotency table",
  );
  const base = table.split(".").at(-1) ?? table;
  if (
    base.toLowerCase().startsWith("gb_idaas_") ||
    COMMERCE_RESERVED_EXISTING_TABLES.includes(base.toLowerCase()) ||
    COMMERCE_RUNTIME_TABLES.some((key) => (COMMERCE_SQL_TABLES[key] ?? "").toLowerCase() === base.toLowerCase())
  ) {
    throw new TypeError(`Commerce migration cannot use an existing platform table for idempotency`);
  }
  return qualifyTenantTable(table, schema);
}

function idempotencyRlsStatements(table: string, tenantColumn: string): string[] {
  const policy = objectName(table, "tenant_policy");
  return [
    `ALTER TABLE ${q(table)} ENABLE ROW LEVEL SECURITY`,
    `ALTER TABLE ${q(table)} FORCE ROW LEVEL SECURITY`,
    `DROP POLICY IF EXISTS ${q(policy)} ON ${q(table)}`,
    `CREATE POLICY ${q(policy)} ON ${q(table)} USING (${q(tenantColumn)} = current_setting('app.tenant_id', true)) WITH CHECK (${q(tenantColumn)} = current_setting('app.tenant_id', true))`,
  ];
}

function migrationScope(options: OpenCommerceMigrationOptions): string {
  const tenant = migrationTenant(options);
  return `open-platform-commerce:${tenant.mode}:${tenant.schema}:${tenant.tenantId}`;
}

function migrationCoordinatorOptions(
  options: OpenCommerceMigrationOptions,
  requireTransaction: boolean,
): {
  tableName: string;
  lockTableName: string;
  lockKey: string;
  lockNamespace: string;
  scope: string;
  ownerId?: string;
  requireTransaction: boolean;
  clock?: () => Date;
} {
  const tenant = migrationTenant(options);
  const tableName = qualifyMigrationTable(
    options.migrationTable ?? options.migrationHistoryTable ?? OPEN_COMMERCE_MIGRATION_TABLE,
    tenant.schema,
    "commerce migration table",
  );
  const lockTable = qualifyMigrationTable(
    options.migrationLockTable ?? OPEN_COMMERCE_MIGRATION_LOCK_TABLE,
    tenant.schema,
    "commerce migration lock table",
  );
  return {
    tableName,
    lockTableName: lockTable,
    lockKey: String(options.lockKey ?? "getbrick-open-commerce-schema"),
    lockNamespace: options.lockNamespace ?? `open-platform-commerce:${tenant.schema}`,
    scope: migrationScope(options),
    ...(options.ownerId === undefined ? {} : { ownerId: options.ownerId }),
    requireTransaction,
    ...(options.clock === undefined ? {} : { clock: options.clock }),
  };
}

function qualifyMigrationTable(value: string, schema: string, field: string): string {
  const table = validateCommerceSqlIdentifier(value, field);
  const base = table.split(".").at(-1) ?? table;
  if (base.toLowerCase().startsWith("gb_idaas_") || COMMERCE_RESERVED_EXISTING_TABLES.includes(base.toLowerCase())) {
    throw new TypeError(`Commerce migration cannot use an existing platform table for ${field}`);
  }
  return qualifyTenantTable(table, schema);
}

function qualifyFunctionName(table: string, functionName: string): string {
  const segments = table.split(".");
  return segments.length === 2 ? `${segments[0]}.${functionName}` : functionName;
}

function objectName(table: string, suffix: string): string {
  const base = table.split(".").at(-1) ?? table;
  const available = Math.max(1, 63 - base.length - suffix.length - 1);
  return `${base.slice(0, available)}_${suffix}`;
}

function constraintName(table: string, suffix: string): string {
  const base = table.split(".").at(-1) ?? table;
  const name = `${base}_${suffix}`;
  return name.length > 63 ? name.slice(0, 63) : name;
}

function q(value: string): string {
  return validateCommerceSqlIdentifier(value, "SQL identifier").split(".").map((segment) => `"${segment}"`).join(".");
}

function isAdapter(value: unknown): value is CommerceDatabaseAdapter {
  return typeof value === "object" && value !== null && typeof (value as { query?: unknown }).query === "function";
}

export type OpenCommerceMigrationExecutor = CommerceDatabaseAdapter;
export type OpenCommerceMigrationOptionsWithExecutor = OpenCommerceMigrationOptions & {
  adapter?: CommerceDatabaseAdapter;
};

export function getOpenCommerceMigrationChecksumForAdapter(
  adapter: CommerceDatabaseAdapter,
  options: OpenCommerceMigrationOptions = {},
): string {
  if (!isAdapter(adapter)) throw new TypeError("A commerce SQL adapter is required");
  return getOpenCommerceMigrationChecksum(options);
}
