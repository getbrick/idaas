import {
  createMigrationDefinition,
  createMigrationMetadataSql,
  MigrationCoordinator,
  migrationChecksum,
  type MigrationDefinition,
  type MigrationDryRunResult,
  type MigrationRunResult,
} from "../../migration-coordinator.js";
import { normalizeTenantConfig, qualifyTenantTable, type TenantConfig } from "../../tenant.js";
import {
  OPEN_PLATFORM_FOUNDATION_SQL_TABLE_KEYS,
  OPEN_PLATFORM_SQL_TABLES,
  type DatabaseAdapter,
  type OpenPlatformSqlTableNames,
  type OpenPlatformSqlTableKey,
  validateOpenPlatformSqlIdentifier,
} from "./adapter.js";

export const OPEN_PLATFORM_MIGRATION_VERSION = 1;
export const OPEN_PLATFORM_MIGRATION_NAME = "open-platform-persistence-foundation";
export const OPEN_PLATFORM_PERSISTENCE_MIGRATION_VERSION = OPEN_PLATFORM_MIGRATION_VERSION;
export const OPEN_PLATFORM_PERSISTENCE_MIGRATION_NAME = OPEN_PLATFORM_MIGRATION_NAME;
export const OPEN_PLATFORM_MANAGEMENT_MIGRATION_VERSION = 2;
export const OPEN_PLATFORM_MANAGEMENT_MIGRATION_NAME = "open-platform-management-audit-webhook";
export const OPEN_PLATFORM_AUDIT_WEBHOOK_MIGRATION_VERSION = OPEN_PLATFORM_MANAGEMENT_MIGRATION_VERSION;
export const OPEN_PLATFORM_AUDIT_WEBHOOK_MIGRATION_NAME = OPEN_PLATFORM_MANAGEMENT_MIGRATION_NAME;
export const OPEN_PLATFORM_DELIVERY_LEASE_MIGRATION_VERSION = 3;
export const OPEN_PLATFORM_DELIVERY_LEASE_MIGRATION_NAME = "open-platform-webhook-delivery-lease";
export const OPEN_PLATFORM_WEBHOOK_DELIVERY_LEASE_MIGRATION_VERSION = OPEN_PLATFORM_DELIVERY_LEASE_MIGRATION_VERSION;
export const OPEN_PLATFORM_WEBHOOK_DELIVERY_LEASE_MIGRATION_NAME = OPEN_PLATFORM_DELIVERY_LEASE_MIGRATION_NAME;
export const OPEN_PLATFORM_DOMAIN_EVENT_MIGRATION_VERSION = 4;
export const OPEN_PLATFORM_DOMAIN_EVENT_MIGRATION_NAME = "open-platform-domain-event-outbox";
export const OPEN_PLATFORM_OUTBOX_MIGRATION_VERSION = OPEN_PLATFORM_DOMAIN_EVENT_MIGRATION_VERSION;
export const OPEN_PLATFORM_OUTBOX_MIGRATION_NAME = OPEN_PLATFORM_DOMAIN_EVENT_MIGRATION_NAME;
export const OPEN_PLATFORM_LATEST_MIGRATION_VERSION = OPEN_PLATFORM_DOMAIN_EVENT_MIGRATION_VERSION;
export const OPEN_PLATFORM_MIGRATION_TABLE = "gb_open_schema_migration";
export const OPEN_PLATFORM_MIGRATION_LOCK_TABLE = "gb_open_schema_migration_lock";

export interface OpenPlatformMigrationOptions {
  schema?: string;
  mode?: string;
  tenantId?: string;
  tenantColumn?: string;
  includeRls?: boolean;
  requireRls?: boolean;
  tables?: Partial<OpenPlatformSqlTableNames>;
  tableNames?: Partial<OpenPlatformSqlTableNames>;
  migrationTable?: string;
  migrationHistoryTable?: string;
  migrationLockTable?: string;
  migrationVersion?: number;
  migrationName?: string;
  requireTransaction?: boolean;
  allowNonTransactional?: boolean;
  lockKey?: string | number;
  lockNamespace?: string;
  ownerId?: string;
  clock?: () => Date;
  includeManagementMigration?: boolean;
  includeAuditWebhookMigration?: boolean;
  includeWebhookMigration?: boolean;
  includeDeliveryLeaseMigration?: boolean;
  includeDomainEventMigration?: boolean;
  includeOutboxMigration?: boolean;
}

export function createOpenPlatformMigrationSql(
  options: OpenPlatformMigrationOptions = {},
): string {
  const tenant = migrationTenant(options);
  const tables = migrationTables(options, tenant.schema, false);
  const columns = migrationColumns(options, tenant.tenantColumn);
  const migrationTable = qualifyMigrationMetadataTable(
    options.migrationTable ?? options.migrationHistoryTable ?? OPEN_PLATFORM_MIGRATION_TABLE,
    tenant.schema,
    "migration table",
  );
  const migrationLockTable = qualifyMigrationMetadataTable(
    options.migrationLockTable ?? OPEN_PLATFORM_MIGRATION_LOCK_TABLE,
    tenant.schema,
    "migration lock table",
  );
  const statements: string[] = [
    createTenantTable(tables.tenants, columns.tenantId),
    createOrganizationTable(tables, columns.tenantId),
    createApplicationTable(tables, columns.tenantId),
    createEnvironmentTable(tables, columns.tenantId),
    createProductTable(tables, columns.tenantId),
    createVersionTable(tables, columns.tenantId),
    createCredentialTable(tables, columns.tenantId),
    createSubscriptionTable(tables, columns.tenantId),
    createScopeGrantTable(tables, columns.tenantId),
    createUsageTable(tables, columns.tenantId),
    createIdempotencyTable(tables, columns.tenantId),
    ...uniqueConstraints(tables, columns.tenantId),
    ...indexes(tables, columns.tenantId),
    ...usageImmutability(tables.usage),
  ];
  if (options.includeRls === true || options.requireRls === true || tenant.mode === "shared") {
    statements.push(...rlsStatements(tables, columns.tenantId));
  }
  statements.push(
    createMigrationMetadataSql({
      tableName: migrationTable,
      lockTableName: migrationLockTable,
    }),
  );
  return `${statements.join(";\n")};\n`;
}

export const createOpenPlatformPersistenceMigrationSql = createOpenPlatformMigrationSql;
export const getOpenPlatformMigrationSql = createOpenPlatformMigrationSql;
export const openPlatformMigrationSql = createOpenPlatformMigrationSql;
export const OPEN_PLATFORM_MIGRATION_SQL = createOpenPlatformMigrationSql();
export const OPEN_PLATFORM_PERSISTENCE_MIGRATION_SQL = OPEN_PLATFORM_MIGRATION_SQL;
export const OPEN_PLATFORM_MANAGEMENT_MIGRATION_SQL = createOpenPlatformManagementMigrationSql();
export const OPEN_PLATFORM_DELIVERY_LEASE_MIGRATION_SQL = createOpenPlatformDeliveryLeaseMigrationSql();
export const OPEN_PLATFORM_DOMAIN_EVENT_MIGRATION_SQL = createOpenPlatformDomainEventMigrationSql();

export function createOpenPlatformManagementMigrationSql(
  options: OpenPlatformMigrationOptions = {},
): string {
  const tenant = migrationTenant(options);
  const tables = migrationTables(options, tenant.schema, true);
  const columns = migrationColumns(options, tenant.tenantColumn);
  const migrationTable = qualifyMigrationMetadataTable(
    options.migrationTable ?? options.migrationHistoryTable ?? OPEN_PLATFORM_MIGRATION_TABLE,
    tenant.schema,
    "migration table",
  );
  const migrationLockTable = qualifyMigrationMetadataTable(
    options.migrationLockTable ?? OPEN_PLATFORM_MIGRATION_LOCK_TABLE,
    tenant.schema,
    "migration lock table",
  );
  const statements: string[] = [
    createWebhookTable(tables, columns.tenantId),
    createWebhookDeliveryTable(tables, columns.tenantId),
    createAuditEventTable(tables, columns.tenantId),
    ...managementIndexes(tables, columns.tenantId),
    ...auditImmutability(tables.auditEvents),
  ];
  if (options.includeRls === true || options.requireRls === true || tenant.mode === "shared") {
    statements.push(...rlsStatementsForKeys(tables, columns.tenantId, ["webhooks", "webhookDeliveries", "auditEvents"]));
  }
  statements.push(createMigrationMetadataSql({
    tableName: migrationTable,
    lockTableName: migrationLockTable,
  }));
  return `${statements.join(";\n")};\n`;
}

export const createOpenPlatformAuditWebhookMigrationSql = createOpenPlatformManagementMigrationSql;
export const createOpenPlatformWebhookMigrationSql = createOpenPlatformManagementMigrationSql;

export function createOpenPlatformDeliveryLeaseMigrationSql(
  options: OpenPlatformMigrationOptions = {},
): string {
  const tenant = migrationTenant(options);
  const tables = migrationTables(options, tenant.schema, true);
  const columns = migrationColumns(options, tenant.tenantColumn);
  const migrationTable = qualifyMigrationMetadataTable(
    options.migrationTable ?? options.migrationHistoryTable ?? OPEN_PLATFORM_MIGRATION_TABLE,
    tenant.schema,
    "migration table",
  );
  const migrationLockTable = qualifyMigrationMetadataTable(
    options.migrationLockTable ?? OPEN_PLATFORM_MIGRATION_LOCK_TABLE,
    tenant.schema,
    "migration lock table",
  );
  const deliveries = tables.webhookDeliveries;
  const statements: string[] = [
    `ALTER TABLE ${q(deliveries)} ADD COLUMN IF NOT EXISTS ${q("lease_id")} TEXT`,
    `ALTER TABLE ${q(deliveries)} ADD COLUMN IF NOT EXISTS ${q("lease_expires_at")} TIMESTAMPTZ`,
    `CREATE INDEX IF NOT EXISTS ${q(objectName(deliveries, "lease_idx"))} ON ${q(deliveries)} (${q(columns.tenantId)}, ${q("status")}, ${q("lease_expires_at")}, ${q("next_attempt_at")})`,
    createMigrationMetadataSql({
      tableName: migrationTable,
      lockTableName: migrationLockTable,
    }),
  ];
  return `${statements.join(";\n")};\n`;
}

export function getOpenPlatformDeliveryLeaseMigrationDefinition(
  options: OpenPlatformMigrationOptions = {},
): MigrationDefinition {
  return createMigrationDefinition(
    OPEN_PLATFORM_DELIVERY_LEASE_MIGRATION_VERSION,
    options.migrationName ?? OPEN_PLATFORM_DELIVERY_LEASE_MIGRATION_NAME,
    createOpenPlatformDeliveryLeaseMigrationSql(options),
    {
      component: "open-platform-webhook-delivery",
      tenantMode: migrationTenant(options).mode,
      tenantId: migrationTenant(options).tenantId,
      checksumAlgorithm: "sha256",
      tables: {
        webhookDeliveries: OPEN_PLATFORM_SQL_TABLES.webhookDeliveries,
      },
    },
    migrationScope(options),
    { additive: true, requires: [OPEN_PLATFORM_MANAGEMENT_MIGRATION_VERSION] },
  );
}

export const getOpenPlatformWebhookDeliveryLeaseMigrationDefinition = getOpenPlatformDeliveryLeaseMigrationDefinition;
export const createOpenPlatformWebhookDeliveryLeaseMigrationSql = createOpenPlatformDeliveryLeaseMigrationSql;

export function createOpenPlatformDomainEventMigrationSql(
  options: OpenPlatformMigrationOptions = {},
): string {
  const tenant = migrationTenant(options);
  const tables = migrationTables(options, tenant.schema, true);
  const columns = migrationColumns(options, tenant.tenantColumn);
  const migrationTable = qualifyMigrationMetadataTable(
    options.migrationTable ?? options.migrationHistoryTable ?? OPEN_PLATFORM_MIGRATION_TABLE,
    tenant.schema,
    "migration table",
  );
  const migrationLockTable = qualifyMigrationMetadataTable(
    options.migrationLockTable ?? OPEN_PLATFORM_MIGRATION_LOCK_TABLE,
    tenant.schema,
    "migration lock table",
  );
  const events = tables.domainEvents;
  const statements: string[] = [
    createDomainEventTable(events, columns.tenantId, tables.tenants),
    ...domainEventIndexes(events, columns.tenantId),
    ...domainEventImmutability(events, columns.tenantId),
  ];
  if (options.includeRls === true || options.requireRls === true || tenant.mode === "shared") {
    statements.push(...rlsStatementsForKeys(tables, columns.tenantId, ["domainEvents"]));
  }
  statements.push(createMigrationMetadataSql({
    tableName: migrationTable,
    lockTableName: migrationLockTable,
  }));
  return `${statements.join(";\n")};\n`;
}

export const createOpenPlatformOutboxMigrationSql = createOpenPlatformDomainEventMigrationSql;

export function getOpenPlatformDomainEventMigrationDefinition(
  options: OpenPlatformMigrationOptions = {},
): MigrationDefinition {
  return createMigrationDefinition(
    OPEN_PLATFORM_DOMAIN_EVENT_MIGRATION_VERSION,
    options.migrationName ?? OPEN_PLATFORM_DOMAIN_EVENT_MIGRATION_NAME,
    createOpenPlatformDomainEventMigrationSql(options),
    {
      component: "open-platform-domain-event",
      tenantMode: migrationTenant(options).mode,
      tenantId: migrationTenant(options).tenantId,
      checksumAlgorithm: "sha256",
      tables: {
        domainEvents: OPEN_PLATFORM_SQL_TABLES.domainEvents,
      },
    },
    migrationScope(options),
    { additive: true, requires: [OPEN_PLATFORM_DELIVERY_LEASE_MIGRATION_VERSION] },
  );
}

export const getOpenPlatformOutboxMigrationDefinition = getOpenPlatformDomainEventMigrationDefinition;
export const getOpenPlatformEventOutboxMigrationDefinition = getOpenPlatformDomainEventMigrationDefinition;

export function getOpenPlatformManagementMigrationDefinition(
  options: OpenPlatformMigrationOptions = {},
): MigrationDefinition {
  return createMigrationDefinition(
    OPEN_PLATFORM_MANAGEMENT_MIGRATION_VERSION,
    options.migrationName ?? OPEN_PLATFORM_MANAGEMENT_MIGRATION_NAME,
    createOpenPlatformManagementMigrationSql(options),
    {
      component: "open-platform-management",
      tenantMode: migrationTenant(options).mode,
      tenantId: migrationTenant(options).tenantId,
      checksumAlgorithm: "sha256",
      tables: {
        webhooks: OPEN_PLATFORM_SQL_TABLES.webhooks,
        webhookDeliveries: OPEN_PLATFORM_SQL_TABLES.webhookDeliveries,
        auditEvents: OPEN_PLATFORM_SQL_TABLES.auditEvents,
      },
    },
    migrationScope(options),
  );
}

export const getOpenPlatformAuditWebhookMigrationDefinition = getOpenPlatformManagementMigrationDefinition;
export const getOpenPlatformWebhookMigrationDefinition = getOpenPlatformManagementMigrationDefinition;

export function getOpenPlatformMigrationDefinition(
  options: OpenPlatformMigrationOptions = {},
): MigrationDefinition {
  return createMigrationDefinition(
    options.migrationVersion ?? OPEN_PLATFORM_MIGRATION_VERSION,
    options.migrationName ?? OPEN_PLATFORM_MIGRATION_NAME,
    createOpenPlatformMigrationSql(options),
    {
      component: "open-platform-persistence",
      tenantMode: migrationTenant(options).mode,
      tenantId: migrationTenant(options).tenantId,
      checksumAlgorithm: "sha256",
      tables: Object.fromEntries(OPEN_PLATFORM_FOUNDATION_SQL_TABLE_KEYS.map((key) => [key, OPEN_PLATFORM_SQL_TABLES[key]])),
    },
    migrationScope(options),
  );
}

export const createOpenPlatformMigrationDefinition = getOpenPlatformMigrationDefinition;
export const getOpenPlatformPersistenceMigrationDefinition = getOpenPlatformMigrationDefinition;

export function getOpenPlatformMigrations(
  options: OpenPlatformMigrationOptions = {},
): MigrationDefinition[] {
  const migrations: MigrationDefinition[] = [getOpenPlatformMigrationDefinition(options)];
  const includeManagement = options.includeManagementMigration !== false &&
    options.includeAuditWebhookMigration !== false &&
    options.includeWebhookMigration !== false;
  if (includeManagement) migrations.push(getOpenPlatformManagementMigrationDefinition(options));
  if (includeManagement && options.includeDeliveryLeaseMigration !== false) {
    migrations.push(getOpenPlatformDeliveryLeaseMigrationDefinition(options));
  }
  if (options.includeDomainEventMigration !== false && options.includeOutboxMigration !== false) {
    migrations.push(getOpenPlatformDomainEventMigrationDefinition(options));
  }
  return migrations;
}

export const getOpenPlatformPersistenceMigrations = getOpenPlatformMigrations;

export function createOpenPlatformMigrationsPlan(
  options: OpenPlatformMigrationOptions = {},
): Array<{ version: number; name: string; checksum: string; sql: string }> {
  return getOpenPlatformMigrations(options).map((definition) => ({
    version: definition.version,
    name: definition.name,
    checksum: migrationChecksum(definition.sql),
    sql: definition.sql,
  }));
}

export const createOpenPlatformPersistenceMigrationsPlan = createOpenPlatformMigrationsPlan;

export function getOpenPlatformMigrationChecksum(
  options: OpenPlatformMigrationOptions = {},
): string {
  return migrationChecksum(createOpenPlatformMigrationSql(options));
}

export function createOpenPlatformMigrationPlan(
  options: OpenPlatformMigrationOptions = {},
): { version: number; name: string; checksum: string; sql: string } {
  const definition = getOpenPlatformMigrationDefinition(options);
  return {
    version: definition.version,
    name: definition.name,
    checksum: migrationChecksum(definition.sql),
    sql: definition.sql,
  };
}

export function dryRunOpenPlatformMigration(
  options?: OpenPlatformMigrationOptions,
): MigrationDryRunResult;
export function dryRunOpenPlatformMigration(
  adapter: DatabaseAdapter,
  options?: OpenPlatformMigrationOptions,
): MigrationDryRunResult;
export function dryRunOpenPlatformMigration(
  input: DatabaseAdapter | OpenPlatformMigrationOptions = {},
  second: OpenPlatformMigrationOptions = {},
): MigrationDryRunResult {
  const hasAdapter = isAdapter(input);
  const options = hasAdapter ? second : input;
  const definitions = getOpenPlatformMigrations(options);
  const coordinator = new MigrationCoordinator(
    hasAdapter ? input : { query: async () => ({ rows: [] }) },
    definitions,
    migrationCoordinatorOptions(options, false),
  );
  return coordinator.dryRun(definitions);
}

export async function applyVersionedOpenPlatformMigration(
  adapter: DatabaseAdapter,
  options: OpenPlatformMigrationOptions = {},
): Promise<MigrationRunResult> {
  const definitions = getOpenPlatformMigrations(options);
  const coordinator = new MigrationCoordinator(
    adapter,
    definitions,
    migrationCoordinatorOptions(options, options.requireTransaction ?? options.allowNonTransactional !== true),
  );
  return coordinator.run(definitions);
}

export async function applyOpenPlatformMigration(
  adapter: DatabaseAdapter,
  options: OpenPlatformMigrationOptions = {},
): Promise<void> {
  await applyVersionedOpenPlatformMigration(adapter, options);
}

export const runOpenPlatformMigration = applyVersionedOpenPlatformMigration;
export const runVersionedOpenPlatformMigration = applyVersionedOpenPlatformMigration;
export const applyOpenPlatformPersistenceMigration = applyVersionedOpenPlatformMigration;

type MigrationTables = Record<OpenPlatformSqlTableKey, string>;
type MigrationColumns = { tenantId: string };

function migrationTenant(options: OpenPlatformMigrationOptions): TenantConfig {
  return normalizeTenantConfig({
    ...(options.mode === undefined ? {} : { mode: options.mode }),
    ...(options.tenantId === undefined ? {} : { tenantId: options.tenantId }),
    ...(options.tenantColumn === undefined ? {} : { tenantColumn: options.tenantColumn }),
    ...(options.schema === undefined ? {} : { schema: options.schema }),
    ...(options.requireRls === undefined ? {} : { requireRls: options.requireRls }),
  });
}

function migrationTables(
  options: OpenPlatformMigrationOptions,
  schema: string,
  includeExtensions = true,
): MigrationTables {
  const configured = {
    ...OPEN_PLATFORM_SQL_TABLES,
    ...(options.tables ?? {}),
    ...(options.tableNames ?? {}),
    ...(options.tables?.developerOrganization === undefined ? {} : { developerOrganizations: options.tables.developerOrganization }),
    ...(options.tableNames?.developerOrganization === undefined ? {} : { developerOrganizations: options.tableNames.developerOrganization }),
    ...(options.tables?.applicationEnvironment === undefined ? {} : { applicationEnvironments: options.tables.applicationEnvironment }),
    ...(options.tableNames?.applicationEnvironment === undefined ? {} : { applicationEnvironments: options.tableNames.applicationEnvironment }),
    ...(options.tables?.apiProduct === undefined ? {} : { apiProducts: options.tables.apiProduct }),
    ...(options.tableNames?.apiProduct === undefined ? {} : { apiProducts: options.tableNames.apiProduct }),
    ...(options.tables?.apiVersion === undefined ? {} : { apiVersions: options.tables.apiVersion }),
    ...(options.tableNames?.apiVersion === undefined ? {} : { apiVersions: options.tableNames.apiVersion }),
    ...(options.tables?.credential === undefined ? {} : { credentials: options.tables.credential }),
    ...(options.tableNames?.credential === undefined ? {} : { credentials: options.tableNames.credential }),
    ...(options.tables?.subscription === undefined ? {} : { subscriptions: options.tables.subscription }),
    ...(options.tableNames?.subscription === undefined ? {} : { subscriptions: options.tableNames.subscription }),
    ...(options.tables?.scopeGrant === undefined ? {} : { scopeGrants: options.tables.scopeGrant }),
    ...(options.tableNames?.scopeGrant === undefined ? {} : { scopeGrants: options.tableNames.scopeGrant }),
  } as MigrationTables;
  const output = {} as MigrationTables;
  for (const key of (includeExtensions
    ? Object.keys(OPEN_PLATFORM_SQL_TABLES) as OpenPlatformSqlTableKey[]
    : OPEN_PLATFORM_FOUNDATION_SQL_TABLE_KEYS)) {
    const table = validateOpenPlatformSqlIdentifier(configured[key], `${key} table`);
    const base = table.split(".").at(-1) ?? table;
    if (base.toLowerCase().startsWith("gb_idaas_")) {
      throw new TypeError(`Open platform migration cannot use existing IDaaS table for ${key}`);
    }
    output[key] = qualifyTenantTable(table, schema);
  }
  return output;
}

function migrationColumns(options: OpenPlatformMigrationOptions, defaultTenantColumn: string): MigrationColumns {
  const tenantColumn = options.tenantColumn === undefined ? defaultTenantColumn : validateOpenPlatformSqlIdentifier(options.tenantColumn, "tenant column");
  return { tenantId: tenantColumn };
}

function createTenantTable(table: string, tenantId: string): string {
  return `CREATE TABLE IF NOT EXISTS ${q(table)} (${[
    `${q("id")} TEXT NOT NULL`,
    `${q(tenantId)} TEXT NOT NULL`,
    `${q("kind")} TEXT NOT NULL DEFAULT 'tenant'`,
    `${q("name")} TEXT NOT NULL`,
    `${q("status")} TEXT NOT NULL DEFAULT 'draft' CHECK (${q("status")} IN ('draft', 'published', 'disabled', 'archived'))`,
    `${q("version")} INTEGER NOT NULL DEFAULT 1 CHECK (${q("version")} > 0)`,
    `${q("etag")} TEXT NOT NULL`,
    `${q("created_at")} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `${q("updated_at")} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `${q("archived_at")} TIMESTAMPTZ`,
    `PRIMARY KEY (${q(tenantId)}, ${q("id")})`,
    `UNIQUE (${q(tenantId)})`,
  ].join(", ")})`;
}

function createOrganizationTable(tables: MigrationTables, tenantId: string): string {
  return `CREATE TABLE IF NOT EXISTS ${q(tables.developerOrganizations)} (${[
    ...commonResourceColumns(tables.tenants, tenantId, "developerOrganization", "draft"),
    `${q("name")} TEXT NOT NULL`,
    `${q("description")} TEXT`,
  ].join(", ")})`;
}

function createApplicationTable(tables: MigrationTables, tenantId: string): string {
  return `CREATE TABLE IF NOT EXISTS ${q(tables.applications)} (${[
    ...commonResourceColumns(tables.tenants, tenantId, "application", "draft"),
    `${q("organization_id")} TEXT NOT NULL`,
    `${q("name")} TEXT NOT NULL`,
    `${q("description")} TEXT`,
    `FOREIGN KEY (${q(tenantId)}, ${q("organization_id")}) REFERENCES ${q(tables.developerOrganizations)} (${q(tenantId)}, ${q("id")})`,
  ].join(", ")})`;
}

function createEnvironmentTable(tables: MigrationTables, tenantId: string): string {
  return `CREATE TABLE IF NOT EXISTS ${q(tables.applicationEnvironments)} (${[
    ...commonResourceColumns(tables.tenants, tenantId, "applicationEnvironment", "draft"),
    `${q("application_id")} TEXT NOT NULL`,
    `${q("name")} TEXT NOT NULL`,
    `FOREIGN KEY (${q(tenantId)}, ${q("application_id")}) REFERENCES ${q(tables.applications)} (${q(tenantId)}, ${q("id")})`,
  ].join(", ")})`;
}

function createProductTable(tables: MigrationTables, tenantId: string): string {
  return `CREATE TABLE IF NOT EXISTS ${q(tables.apiProducts)} (${[
    ...commonResourceColumns(tables.tenants, tenantId, "apiProduct", "draft"),
    `${q("name")} TEXT NOT NULL`,
    `${q("description")} TEXT`,
    `${q("scopes")} JSONB NOT NULL DEFAULT '[]'::jsonb`,
  ].join(", ")})`;
}

function createVersionTable(tables: MigrationTables, tenantId: string): string {
  return `CREATE TABLE IF NOT EXISTS ${q(tables.apiVersions)} (${[
    ...commonResourceColumns(tables.tenants, tenantId, "apiVersion", "draft"),
    `${q("product_id")} TEXT NOT NULL`,
    `${q("api_version")} TEXT NOT NULL`,
    `${q("description")} TEXT`,
    `${q("scopes")} JSONB NOT NULL DEFAULT '[]'::jsonb`,
    `FOREIGN KEY (${q(tenantId)}, ${q("product_id")}) REFERENCES ${q(tables.apiProducts)} (${q(tenantId)}, ${q("id")})`,
  ].join(", ")})`;
}

function createCredentialTable(tables: MigrationTables, tenantId: string): string {
  return `CREATE TABLE IF NOT EXISTS ${q(tables.credentials)} (${[
    `${q("id")} TEXT NOT NULL`,
    `${q(tenantId)} TEXT NOT NULL`,
    `${q("kind")} TEXT NOT NULL DEFAULT 'credential'`,
    `${q("application_id")} TEXT NOT NULL`,
    `${q("environment_id")} TEXT`,
    `${q("name")} TEXT NOT NULL`,
    `${q("status")} TEXT NOT NULL DEFAULT 'active' CHECK (${q("status")} IN ('active', 'rotated', 'revoked'))`,
    `${q("scopes")} JSONB NOT NULL DEFAULT '[]'::jsonb`,
    `${q("secret_digest")} TEXT NOT NULL CHECK (${q("secret_digest")} ~ '^sha256:[0-9a-f]{64}$')`,
    `${q("secret_reference")} TEXT`,
    `${q("fingerprint")} TEXT NOT NULL`,
    `${q("expires_at")} TIMESTAMPTZ`,
    `${q("rotated_at")} TIMESTAMPTZ`,
    `${q("revoked_at")} TIMESTAMPTZ`,
    `${q("replaced_by_credential_id")} TEXT`,
    `${q("previous_credential_id")} TEXT`,
    `${q("version")} INTEGER NOT NULL DEFAULT 1 CHECK (${q("version")} > 0)`,
    `${q("etag")} TEXT NOT NULL`,
    `${q("created_at")} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `${q("updated_at")} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `PRIMARY KEY (${q(tenantId)}, ${q("id")})`,
    `FOREIGN KEY (${q(tenantId)}) REFERENCES ${q(tables.tenants)} (${q(tenantId)})`,
    `FOREIGN KEY (${q(tenantId)}, ${q("application_id")}) REFERENCES ${q(tables.applications)} (${q(tenantId)}, ${q("id")})`,
    `FOREIGN KEY (${q(tenantId)}, ${q("environment_id")}) REFERENCES ${q(tables.applicationEnvironments)} (${q(tenantId)}, ${q("id")})`,
    `FOREIGN KEY (${q(tenantId)}, ${q("replaced_by_credential_id")}) REFERENCES ${q(tables.credentials)} (${q(tenantId)}, ${q("id")})`,
    `FOREIGN KEY (${q(tenantId)}, ${q("previous_credential_id")}) REFERENCES ${q(tables.credentials)} (${q(tenantId)}, ${q("id")})`,
  ].join(", ")})`;
}

function createSubscriptionTable(tables: MigrationTables, tenantId: string): string {
  return `CREATE TABLE IF NOT EXISTS ${q(tables.subscriptions)} (${[
    ...commonResourceColumns(tables.tenants, tenantId, "subscription", "draft"),
    `${q("application_id")} TEXT NOT NULL`,
    `${q("product_id")} TEXT NOT NULL`,
    `${q("api_version_id")} TEXT`,
    `${q("name")} TEXT NOT NULL`,
    `${q("scopes")} JSONB NOT NULL DEFAULT '[]'::jsonb`,
    `FOREIGN KEY (${q(tenantId)}, ${q("application_id")}) REFERENCES ${q(tables.applications)} (${q(tenantId)}, ${q("id")})`,
    `FOREIGN KEY (${q(tenantId)}, ${q("product_id")}) REFERENCES ${q(tables.apiProducts)} (${q(tenantId)}, ${q("id")})`,
    `FOREIGN KEY (${q(tenantId)}, ${q("api_version_id")}) REFERENCES ${q(tables.apiVersions)} (${q(tenantId)}, ${q("id")})`,
  ].join(", ")})`;
}

function createScopeGrantTable(tables: MigrationTables, tenantId: string): string {
  return `CREATE TABLE IF NOT EXISTS ${q(tables.scopeGrants)} (${[
    `${q("id")} TEXT NOT NULL`,
    `${q(tenantId)} TEXT NOT NULL`,
    `${q("kind")} TEXT NOT NULL DEFAULT 'scopeGrant'`,
    `${q("credential_id")} TEXT NOT NULL`,
    `${q("application_id")} TEXT NOT NULL`,
    `${q("product_id")} TEXT NOT NULL`,
    `${q("api_version_id")} TEXT`,
    `${q("scopes")} JSONB NOT NULL DEFAULT '[]'::jsonb`,
    `${q("status")} TEXT NOT NULL DEFAULT 'active' CHECK (${q("status")} IN ('active', 'revoked'))`,
    `${q("granted_at")} TIMESTAMPTZ NOT NULL`,
    `${q("revoked_at")} TIMESTAMPTZ`,
    `${q("version")} INTEGER NOT NULL DEFAULT 1 CHECK (${q("version")} > 0)`,
    `${q("etag")} TEXT NOT NULL`,
    `${q("created_at")} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `${q("updated_at")} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `PRIMARY KEY (${q(tenantId)}, ${q("id")})`,
    `FOREIGN KEY (${q(tenantId)}) REFERENCES ${q(tables.tenants)} (${q(tenantId)})`,
    `FOREIGN KEY (${q(tenantId)}, ${q("credential_id")}) REFERENCES ${q(tables.credentials)} (${q(tenantId)}, ${q("id")})`,
    `FOREIGN KEY (${q(tenantId)}, ${q("application_id")}) REFERENCES ${q(tables.applications)} (${q(tenantId)}, ${q("id")})`,
    `FOREIGN KEY (${q(tenantId)}, ${q("product_id")}) REFERENCES ${q(tables.apiProducts)} (${q(tenantId)}, ${q("id")})`,
    `FOREIGN KEY (${q(tenantId)}, ${q("api_version_id")}) REFERENCES ${q(tables.apiVersions)} (${q(tenantId)}, ${q("id")})`,
  ].join(", ")})`;
}

function createUsageTable(tables: MigrationTables, tenantId: string): string {
  return `CREATE TABLE IF NOT EXISTS ${q(tables.usage)} (${[
    `${q("id")} TEXT NOT NULL`,
    `${q(tenantId)} TEXT NOT NULL`,
    `${q("kind")} TEXT NOT NULL DEFAULT 'usage'`,
    `${q("subscription_id")} TEXT NOT NULL`,
    `${q("credential_id")} TEXT`,
    `${q("product_id")} TEXT NOT NULL`,
    `${q("api_version_id")} TEXT`,
    `${q("metric")} TEXT NOT NULL`,
    `${q("quantity")} NUMERIC NOT NULL CHECK (${q("quantity")} > 0)`,
    `${q("occurred_at")} TIMESTAMPTZ NOT NULL`,
    `${q("idempotency_key")} TEXT NOT NULL`,
    `${q("version")} INTEGER NOT NULL DEFAULT 1 CHECK (${q("version")} = 1)`,
    `${q("etag")} TEXT NOT NULL`,
    `${q("created_at")} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `${q("updated_at")} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `PRIMARY KEY (${q(tenantId)}, ${q("id")})`,
    `FOREIGN KEY (${q(tenantId)}) REFERENCES ${q(tables.tenants)} (${q(tenantId)})`,
    `FOREIGN KEY (${q(tenantId)}, ${q("subscription_id")}) REFERENCES ${q(tables.subscriptions)} (${q(tenantId)}, ${q("id")})`,
    `FOREIGN KEY (${q(tenantId)}, ${q("credential_id")}) REFERENCES ${q(tables.credentials)} (${q(tenantId)}, ${q("id")})`,
    `FOREIGN KEY (${q(tenantId)}, ${q("product_id")}) REFERENCES ${q(tables.apiProducts)} (${q(tenantId)}, ${q("id")})`,
    `FOREIGN KEY (${q(tenantId)}, ${q("api_version_id")}) REFERENCES ${q(tables.apiVersions)} (${q(tenantId)}, ${q("id")})`,
  ].join(", ")})`;
}

function createIdempotencyTable(tables: MigrationTables, tenantId: string): string {
  return `CREATE TABLE IF NOT EXISTS ${q(tables.idempotency)} (${[
    `${q(tenantId)} TEXT NOT NULL`,
    `${q("actor_id")} TEXT NOT NULL`,
    `${q("operation")} TEXT NOT NULL`,
    `${q("idempotency_key")} TEXT NOT NULL`,
    `${q("request_hash")} TEXT NOT NULL CHECK (${q("request_hash")} ~ '^[a-f0-9]{64}$')`,
    `${q("state")} TEXT NOT NULL CHECK (${q("state")} IN ('inProgress', 'completed'))`,
    `${q("lease_token")} TEXT`,
    `${q("lease_expires_at")} TIMESTAMPTZ NOT NULL`,
    `${q("expires_at")} TIMESTAMPTZ NOT NULL`,
    `${q("created_at")} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `${q("updated_at")} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `${q("completed_at")} TIMESTAMPTZ`,
    `${q("response")} JSONB`,
    `PRIMARY KEY (${q(tenantId)}, ${q("actor_id")}, ${q("operation")}, ${q("idempotency_key")})`,
    `FOREIGN KEY (${q(tenantId)}) REFERENCES ${q(tables.tenants)} (${q(tenantId)})`,
    `CHECK (${q("lease_expires_at")} >= ${q("created_at")})`,
    `CHECK (${q("expires_at")} > ${q("created_at")})`,
  ].join(", ")})`;
}

function createWebhookTable(tables: MigrationTables, tenantId: string): string {
  return `CREATE TABLE IF NOT EXISTS ${q(tables.webhooks)} (${[
    `${q("id")} TEXT NOT NULL`,
    `${q(tenantId)} TEXT NOT NULL`,
    `${q("kind")} TEXT NOT NULL DEFAULT 'webhook' CHECK (${q("kind")} = 'webhook')`,
    `${q("developer_organization_id")} TEXT NOT NULL`,
    `${q("application_id")} TEXT NOT NULL`,
    `${q("environment_id")} TEXT NOT NULL`,
    `${q("name")} TEXT NOT NULL`,
    `${q("endpoint_url")} TEXT NOT NULL`,
    `${q("status")} TEXT NOT NULL DEFAULT 'active' CHECK (${q("status")} IN ('active', 'paused', 'failing', 'disabled'))`,
    `${q("events")} JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(${q("events")}) = 'array')`,
    `${q("signing_algorithm")} TEXT NOT NULL DEFAULT 'hmac-sha256' CHECK (${q("signing_algorithm")} = 'hmac-sha256')`,
    `${q("signing_secret_reference")} TEXT NOT NULL`,
    `${q("secret_version")} INTEGER NOT NULL DEFAULT 1 CHECK (${q("secret_version")} > 0)`,
    `${q("failure_count")} INTEGER NOT NULL DEFAULT 0 CHECK (${q("failure_count")} >= 0)`,
    `${q("next_delivery_at")} TIMESTAMPTZ`,
    `${q("last_delivery_at")} TIMESTAMPTZ`,
    `${q("version")} INTEGER NOT NULL DEFAULT 1 CHECK (${q("version")} > 0)`,
    `${q("created_at")} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `${q("updated_at")} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `PRIMARY KEY (${q(tenantId)}, ${q("id")})`,
    `FOREIGN KEY (${q(tenantId)}) REFERENCES ${q(tables.tenants)} (${q(tenantId)})`,
  ].join(", ")})`;
}

function createWebhookDeliveryTable(tables: MigrationTables, tenantId: string): string {
  return `CREATE TABLE IF NOT EXISTS ${q(tables.webhookDeliveries)} (${[
    `${q("id")} TEXT NOT NULL`,
    `${q(tenantId)} TEXT NOT NULL`,
    `${q("webhook_id")} TEXT NOT NULL`,
    `${q("event_id")} TEXT NOT NULL`,
    `${q("event_type")} TEXT NOT NULL`,
    `${q("status")} TEXT NOT NULL DEFAULT 'pending' CHECK (${q("status")} IN ('pending', 'delivering', 'succeeded', 'failed', 'dead_lettered'))`,
    `${q("attempt")} INTEGER NOT NULL DEFAULT 0 CHECK (${q("attempt")} >= 0)`,
    `${q("max_attempts")} INTEGER NOT NULL DEFAULT 5 CHECK (${q("max_attempts")} > 0)`,
    `${q("idempotency_key")} TEXT NOT NULL`,
    `${q("payload")} TEXT NOT NULL`,
    `${q("body")} TEXT NOT NULL`,
    `${q("secret_version")} INTEGER NOT NULL CHECK (${q("secret_version")} > 0)`,
    `${q("next_attempt_at")} TIMESTAMPTZ`,
    `${q("delivered_at")} TIMESTAMPTZ`,
    `${q("response_status_code")} INTEGER CHECK (${q("response_status_code")} BETWEEN 100 AND 599)`,
    `${q("response_body_excerpt")} TEXT`,
    `${q("error_code")} TEXT`,
    `${q("created_at")} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `${q("updated_at")} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `PRIMARY KEY (${q(tenantId)}, ${q("id")})`,
    `UNIQUE (${q(tenantId)}, ${q("webhook_id")}, ${q("event_id")})`,
    `FOREIGN KEY (${q(tenantId)}) REFERENCES ${q(tables.tenants)} (${q(tenantId)})`,
    `FOREIGN KEY (${q(tenantId)}, ${q("webhook_id")}) REFERENCES ${q(tables.webhooks)} (${q(tenantId)}, ${q("id")})`,
  ].join(", ")})`;
}

function createAuditEventTable(tables: MigrationTables, tenantId: string): string {
  return `CREATE TABLE IF NOT EXISTS ${q(tables.auditEvents)} (${[
    `${q("id")} TEXT NOT NULL`,
    `${q(tenantId)} TEXT NOT NULL`,
    `${q("action")} TEXT NOT NULL`,
    `${q("outcome")} TEXT NOT NULL CHECK (${q("outcome")} IN ('success', 'failure', 'denied'))`,
    `${q("actor_type")} TEXT NOT NULL CHECK (${q("actor_type")} IN ('user', 'service', 'system'))`,
    `${q("actor_id")} TEXT NOT NULL`,
    `${q("actor_display_name")} TEXT`,
    `${q("actor_ip_address")} TEXT`,
    `${q("actor_user_agent")} TEXT`,
    `${q("target_type")} TEXT NOT NULL`,
    `${q("target_id")} TEXT NOT NULL`,
    `${q("target_display_name")} TEXT`,
    `${q("request_id")} TEXT`,
    `${q("metadata")} JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(${q("metadata")}) = 'object')`,
    `${q("occurred_at")} TIMESTAMPTZ NOT NULL`,
    `${q("sequence")} BIGINT NOT NULL CHECK (${q("sequence")} > 0)`,
    `${q("source")} TEXT NOT NULL DEFAULT 'open-platform'`,
    `${q("previous_hash")} TEXT CHECK (${q("previous_hash")} IS NULL OR ${q("previous_hash")} ~ '^[a-f0-9]{64}$')`,
    `${q("event_hash")} TEXT NOT NULL CHECK (${q("event_hash")} ~ '^[a-f0-9]{64}$')`,
    `${q("created_at")} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `PRIMARY KEY (${q(tenantId)}, ${q("id")})`,
    `UNIQUE (${q(tenantId)}, ${q("sequence")})`,
    `FOREIGN KEY (${q(tenantId)}) REFERENCES ${q(tables.tenants)} (${q(tenantId)})`,
  ].join(", ")})`;
}

function createDomainEventTable(
  table: string,
  tenantId: string,
  tenantTable: string,
): string {
  return `CREATE TABLE IF NOT EXISTS ${q(table)} (${[
    `${q("event_id")} TEXT NOT NULL`,
    `${q(tenantId)} TEXT NOT NULL`,
    `${q("event_type")} TEXT NOT NULL CHECK (${q("event_type")} ~ '^[a-z][a-z0-9_]{2,63}\\.[a-z][a-z0-9_]{2,63}$')`,
    `${q("resource_type")} TEXT NOT NULL`,
    `${q("resource_id")} TEXT NOT NULL`,
    `${q("resource_version")} INTEGER CHECK (${q("resource_version")} IS NULL OR ${q("resource_version")} > 0)`,
    `${q("resource_status")} TEXT`,
    `${q("actor_id")} TEXT`,
    `${q("request_id")} TEXT`,
    `${q("occurred_at")} TIMESTAMPTZ NOT NULL`,
    `${q("schema_version")} TEXT NOT NULL`,
    `${q("data")} JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(${q("data")}) = 'object')`,
    `${q("status")} TEXT NOT NULL DEFAULT 'pending' CHECK (${q("status")} IN ('pending', 'delivering', 'published', 'failed', 'dead_lettered'))`,
    `${q("sequence")} BIGINT NOT NULL CHECK (${q("sequence")} > 0)`,
    `${q("attempt")} INTEGER NOT NULL DEFAULT 0 CHECK (${q("attempt")} >= 0)`,
    `${q("max_attempts")} INTEGER NOT NULL DEFAULT 5 CHECK (${q("max_attempts")} > 0)`,
    `${q("next_attempt_at")} TIMESTAMPTZ`,
    `${q("published_at")} TIMESTAMPTZ`,
    `${q("error_code")} TEXT`,
    `${q("lease_id")} TEXT`,
    `${q("lease_expires_at")} TIMESTAMPTZ`,
    `${q("created_at")} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `${q("updated_at")} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `PRIMARY KEY (${q(tenantId)}, ${q("event_id")})`,
    `UNIQUE (${q(tenantId)}, ${q("sequence")})`,
    `FOREIGN KEY (${q(tenantId)}) REFERENCES ${q(tenantTable)} (${q(tenantId)})`,
    `CHECK (${q("attempt")} <= ${q("max_attempts")})`,
  ].join(", ")})`;
}

function domainEventIndexes(table: string, tenantId: string): string[] {
  return [
    `CREATE INDEX IF NOT EXISTS ${q(objectName(table, "pending_idx"))} ON ${q(table)} (${q(tenantId)}, ${q("status")}, ${q("next_attempt_at")}, ${q("sequence")})`,
    `CREATE INDEX IF NOT EXISTS ${q(objectName(table, "lease_idx"))} ON ${q(table)} (${q(tenantId)}, ${q("status")}, ${q("lease_expires_at")})`,
    `CREATE INDEX IF NOT EXISTS ${q(objectName(table, "resource_idx"))} ON ${q(table)} (${q(tenantId)}, ${q("resource_type")}, ${q("resource_id")}, ${q("sequence")})`,
    `CREATE INDEX IF NOT EXISTS ${q(objectName(table, "type_idx"))} ON ${q(table)} (${q(tenantId)}, ${q("event_type")}, ${q("sequence")})`,
  ];
}

function domainEventImmutability(table: string, tenantId: string): string[] {
  const schema = table.split(".").length === 2 ? table.split(".")[0] : undefined;
  const immutableFunction = schema === undefined
    ? "gb_open_reject_domain_event_mutation"
    : `${schema}.gb_open_reject_domain_event_mutation`;
  const statusFunction = schema === undefined
    ? "gb_open_domain_event_state_guard"
    : `${schema}.gb_open_domain_event_state_guard`;
  return [
    `CREATE OR REPLACE FUNCTION ${q(immutableFunction)}() RETURNS trigger LANGUAGE plpgsql AS $gb_open$ BEGIN RAISE EXCEPTION 'gb_open_domain_event is append-only' USING ERRCODE = '55000'; END; $gb_open$`,
    `DROP TRIGGER IF EXISTS ${q("gb_open_domain_event_immutable")} ON ${q(table)}`,
    `CREATE TRIGGER ${q("gb_open_domain_event_immutable")} BEFORE DELETE ON ${q(table)} FOR EACH ROW EXECUTE FUNCTION ${q(immutableFunction)}()`,
    `CREATE OR REPLACE FUNCTION ${q(statusFunction)}() RETURNS trigger LANGUAGE plpgsql AS $gb_open$ BEGIN IF NEW.${q("event_id")} IS DISTINCT FROM OLD.${q("event_id")} OR NEW.${q(tenantId)} IS DISTINCT FROM OLD.${q(tenantId)} OR NEW.${q("event_type")} IS DISTINCT FROM OLD.${q("event_type")} OR NEW.${q("resource_type")} IS DISTINCT FROM OLD.${q("resource_type")} OR NEW.${q("resource_id")} IS DISTINCT FROM OLD.${q("resource_id")} OR NEW.${q("occurred_at")} IS DISTINCT FROM OLD.${q("occurred_at")} OR NEW.${q("schema_version")} IS DISTINCT FROM OLD.${q("schema_version")} OR NEW.${q("data")} IS DISTINCT FROM OLD.${q("data")} OR NEW.${q("sequence")} IS DISTINCT FROM OLD.${q("sequence")} THEN RAISE EXCEPTION 'gb_open_domain_event payload is append-only' USING ERRCODE = '55000'; END IF; RETURN NEW; END; $gb_open$`,
    `DROP TRIGGER IF EXISTS ${q("gb_open_domain_event_payload_guard")} ON ${q(table)}`,
    `CREATE TRIGGER ${q("gb_open_domain_event_payload_guard")} BEFORE UPDATE ON ${q(table)} FOR EACH ROW EXECUTE FUNCTION ${q(statusFunction)}()`,
  ];
}

function managementIndexes(tables: MigrationTables, tenantId: string): string[] {
  return [
    `CREATE INDEX IF NOT EXISTS ${q(objectName(tables.webhooks, "tenant_status_idx"))} ON ${q(tables.webhooks)} (${q(tenantId)}, ${q("status")}, ${q("created_at")}, ${q("id")})`,
    `CREATE INDEX IF NOT EXISTS ${q(objectName(tables.webhooks, "application_idx"))} ON ${q(tables.webhooks)} (${q(tenantId)}, ${q("application_id")}, ${q("environment_id")}, ${q("status")})`,
    `CREATE INDEX IF NOT EXISTS ${q(objectName(tables.webhookDeliveries, "event_idx"))} ON ${q(tables.webhookDeliveries)} (${q(tenantId)}, ${q("webhook_id")}, ${q("event_id")})`,
    `CREATE INDEX IF NOT EXISTS ${q(objectName(tables.webhookDeliveries, "retry_idx"))} ON ${q(tables.webhookDeliveries)} (${q(tenantId)}, ${q("status")}, ${q("next_attempt_at")})`,
    `CREATE INDEX IF NOT EXISTS ${q(objectName(tables.auditEvents, "sequence_idx"))} ON ${q(tables.auditEvents)} (${q(tenantId)}, ${q("sequence")} DESC)`,
    `CREATE INDEX IF NOT EXISTS ${q(objectName(tables.auditEvents, "occurred_idx"))} ON ${q(tables.auditEvents)} (${q(tenantId)}, ${q("occurred_at")} DESC, ${q("id")})`,
    `CREATE INDEX IF NOT EXISTS ${q(objectName(tables.auditEvents, "target_idx"))} ON ${q(tables.auditEvents)} (${q(tenantId)}, ${q("target_id")}, ${q("occurred_at")} DESC)`,
  ];
}

function auditImmutability(table: string): string[] {
  const schema = table.split(".").length === 2 ? table.split(".")[0] : undefined;
  const functionName = schema === undefined
    ? "gb_open_reject_audit_mutation"
    : `${schema}.gb_open_reject_audit_mutation`;
  return [
    `CREATE OR REPLACE FUNCTION ${q(functionName)}() RETURNS trigger LANGUAGE plpgsql AS $gb_open$ BEGIN RAISE EXCEPTION 'gb_open_audit_event is append-only' USING ERRCODE = '55000'; END; $gb_open$`,
    `DROP TRIGGER IF EXISTS ${q("gb_open_audit_immutable")} ON ${q(table)}`,
    `CREATE TRIGGER ${q("gb_open_audit_immutable")} BEFORE UPDATE OR DELETE ON ${q(table)} FOR EACH ROW EXECUTE FUNCTION ${q(functionName)}()`,
  ];
}

function rlsStatementsForKeys(
  tables: MigrationTables,
  tenantId: string,
  keys: readonly OpenPlatformSqlTableKey[],
): string[] {
  const selected = Object.fromEntries(keys.map((key) => [key, tables[key]])) as MigrationTables;
  return rlsStatements(selected, tenantId);
}

function commonResourceColumns(tenantTable: string, tenantId: string, kind: string, status: string): string[] {
  return [
    `${q("id")} TEXT NOT NULL`,
    `${q(tenantId)} TEXT NOT NULL`,
    `${q("kind")} TEXT NOT NULL DEFAULT '${kind}'`,
    `${q("status")} TEXT NOT NULL DEFAULT '${status}' CHECK (${q("status")} IN ('draft', 'published', 'disabled', 'archived'))`,
    `${q("version")} INTEGER NOT NULL DEFAULT 1 CHECK (${q("version")} > 0)`,
    `${q("etag")} TEXT NOT NULL`,
    `${q("created_at")} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `${q("updated_at")} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `${q("archived_at")} TIMESTAMPTZ`,
    `PRIMARY KEY (${q(tenantId)}, ${q("id")})`,
    `FOREIGN KEY (${q(tenantId)}) REFERENCES ${q(tenantTable)} (${q(tenantId)})`,
  ];
}

function uniqueConstraints(tables: MigrationTables, tenantId: string): string[] {
  return [
    `CREATE UNIQUE INDEX IF NOT EXISTS ${q(objectName(tables.apiVersions, "product_version_uq"))} ON ${q(tables.apiVersions)} (${q(tenantId)}, ${q("product_id")}, LOWER(${q("api_version")}))`,
    `CREATE UNIQUE INDEX IF NOT EXISTS ${q(objectName(tables.scopeGrants, "active_product_uq"))} ON ${q(tables.scopeGrants)} (${q(tenantId)}, ${q("credential_id")}, ${q("product_id")}) WHERE ${q("status")} = 'active' AND ${q("api_version_id")} IS NULL`,
    `CREATE UNIQUE INDEX IF NOT EXISTS ${q(objectName(tables.scopeGrants, "active_version_uq"))} ON ${q(tables.scopeGrants)} (${q(tenantId)}, ${q("credential_id")}, ${q("product_id")}, ${q("api_version_id")}) WHERE ${q("status")} = 'active' AND ${q("api_version_id")} IS NOT NULL`,
    `CREATE UNIQUE INDEX IF NOT EXISTS ${q(objectName(tables.subscriptions, "application_product_uq"))} ON ${q(tables.subscriptions)} (${q(tenantId)}, ${q("application_id")}, ${q("product_id")}) WHERE ${q("api_version_id")} IS NULL AND ${q("status")} <> 'archived'`,
    `CREATE UNIQUE INDEX IF NOT EXISTS ${q(objectName(tables.subscriptions, "application_version_uq"))} ON ${q(tables.subscriptions)} (${q(tenantId)}, ${q("application_id")}, ${q("product_id")}, ${q("api_version_id")}) WHERE ${q("api_version_id")} IS NOT NULL AND ${q("status")} <> 'archived'`,
    `CREATE UNIQUE INDEX IF NOT EXISTS ${q(objectName(tables.usage, "scope_idempotency_uq"))} ON ${q(tables.usage)} (${q(tenantId)}, ${q("subscription_id")}, COALESCE(${q("credential_id")}, ''), ${q("idempotency_key")})`,
  ];
}

function indexes(tables: MigrationTables, tenantId: string): string[] {
  return [
    `CREATE INDEX IF NOT EXISTS ${q(objectName(tables.applications, "tenant_status_idx"))} ON ${q(tables.applications)} (${q(tenantId)}, ${q("status")}, ${q("created_at")})`,
    `CREATE INDEX IF NOT EXISTS ${q(objectName(tables.applicationEnvironments, "application_idx"))} ON ${q(tables.applicationEnvironments)} (${q(tenantId)}, ${q("application_id")}, ${q("status")})`,
    `CREATE INDEX IF NOT EXISTS ${q(objectName(tables.apiProducts, "tenant_status_idx"))} ON ${q(tables.apiProducts)} (${q(tenantId)}, ${q("status")}, ${q("created_at")})`,
    `CREATE INDEX IF NOT EXISTS ${q(objectName(tables.apiVersions, "product_idx"))} ON ${q(tables.apiVersions)} (${q(tenantId)}, ${q("product_id")}, ${q("status")})`,
    `CREATE INDEX IF NOT EXISTS ${q(objectName(tables.credentials, "application_idx"))} ON ${q(tables.credentials)} (${q(tenantId)}, ${q("application_id")}, ${q("environment_id")}, ${q("status")})`,
    `CREATE INDEX IF NOT EXISTS ${q(objectName(tables.subscriptions, "application_idx"))} ON ${q(tables.subscriptions)} (${q(tenantId)}, ${q("application_id")}, ${q("status")})`,
    `CREATE INDEX IF NOT EXISTS ${q(objectName(tables.scopeGrants, "lookup_idx"))} ON ${q(tables.scopeGrants)} (${q(tenantId)}, ${q("credential_id")}, ${q("product_id")}, ${q("api_version_id")}, ${q("status")})`,
    `CREATE INDEX IF NOT EXISTS ${q(objectName(tables.usage, "occurred_idx"))} ON ${q(tables.usage)} (${q(tenantId)}, ${q("occurred_at")}, ${q("id")})`,
    `CREATE INDEX IF NOT EXISTS ${q(objectName(tables.usage, "subscription_idx"))} ON ${q(tables.usage)} (${q(tenantId)}, ${q("subscription_id")}, ${q("occurred_at")})`,
    `CREATE INDEX IF NOT EXISTS ${q(objectName(tables.idempotency, "lease_idx"))} ON ${q(tables.idempotency)} (${q(tenantId)}, ${q("state")}, ${q("lease_expires_at")})`,
    `CREATE INDEX IF NOT EXISTS ${q(objectName(tables.idempotency, "expiry_idx"))} ON ${q(tables.idempotency)} (${q(tenantId)}, ${q("expires_at")})`,
  ];
}

function usageImmutability(table: string): string[] {
  const schema = table.split(".").length === 2 ? table.split(".")[0] : undefined;
  const functionName = schema === undefined
    ? "gb_open_reject_usage_mutation"
    : `${schema}.gb_open_reject_usage_mutation`;
  return [
    `CREATE OR REPLACE FUNCTION ${q(functionName)}() RETURNS trigger LANGUAGE plpgsql AS $gb_open$ BEGIN RAISE EXCEPTION 'gb_open_usage is append-only' USING ERRCODE = '55000'; END; $gb_open$`,
    `DROP TRIGGER IF EXISTS ${q("gb_open_usage_immutable")} ON ${q(table)}`,
    `CREATE TRIGGER ${q("gb_open_usage_immutable")} BEFORE UPDATE OR DELETE ON ${q(table)} FOR EACH ROW EXECUTE FUNCTION ${q(functionName)}()`,
  ];
}

function rlsStatements(tables: MigrationTables, tenantId: string): string[] {
  const statements: string[] = [];
  for (const table of Object.values(tables)) {
    const policy = objectName(table, "tenant_policy");
    statements.push(
      `ALTER TABLE ${q(table)} ENABLE ROW LEVEL SECURITY`,
      `ALTER TABLE ${q(table)} FORCE ROW LEVEL SECURITY`,
      `DROP POLICY IF EXISTS ${q(policy)} ON ${q(table)}`,
      `CREATE POLICY ${q(policy)} ON ${q(table)} USING (${q(tenantId)} = current_setting('app.tenant_id', true)) WITH CHECK (${q(tenantId)} = current_setting('app.tenant_id', true))`,
    );
  }
  return statements;
}

function migrationScope(options: OpenPlatformMigrationOptions): string {
  const tenant = migrationTenant(options);
  return `open-platform:${tenant.mode}:${tenant.schema}:${tenant.tenantId}`;
}

function migrationCoordinatorOptions(
  options: OpenPlatformMigrationOptions,
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
  const tableName = qualifyMigrationMetadataTable(
    options.migrationTable ?? options.migrationHistoryTable ?? OPEN_PLATFORM_MIGRATION_TABLE,
    tenant.schema,
    "migration table",
  );
  const lockTableName = qualifyMigrationMetadataTable(
    options.migrationLockTable ?? OPEN_PLATFORM_MIGRATION_LOCK_TABLE,
    tenant.schema,
    "migration lock table",
  );
  return {
    tableName,
    lockTableName,
    lockKey: String(options.lockKey ?? "getbrick-open-platform-schema"),
    lockNamespace: options.lockNamespace ?? `open-platform:${tenant.schema}`,
    scope: migrationScope(options),
    ...(options.ownerId === undefined ? {} : { ownerId: options.ownerId }),
    requireTransaction,
    ...(options.clock === undefined ? {} : { clock: options.clock }),
  };
}

function qualifyMigrationMetadataTable(value: string, schema: string, field: string): string {
  const table = validateOpenPlatformSqlIdentifier(value, field);
  const base = table.split(".").at(-1) ?? table;
  if (base.toLowerCase().startsWith("gb_idaas_")) {
    throw new TypeError(`Open platform migration cannot use existing IDaaS table for ${field}`);
  }
  return qualifyTenantTable(table, schema);
}

function objectName(table: string, suffix: string): string {
  const base = table.split(".").at(-1) ?? table;
  const available = Math.max(1, 63 - base.length - suffix.length - 1);
  return `${base.slice(0, available)}_${suffix}`;
}

function q(value: string): string {
  return value.split(".").map((segment) => `"${segment.replace(/"/gu, '""')}"`).join(".");
}

function isAdapter(value: unknown): value is DatabaseAdapter {
  return typeof value === "object" && value !== null && typeof (value as { query?: unknown }).query === "function";
}
