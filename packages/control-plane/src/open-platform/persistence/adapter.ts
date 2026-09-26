import { AsyncLocalStorage } from "node:async_hooks";
import {
  getTenantTransactionExecutor,
  normalizeTenantConfig,
  qualifyTenantTable,
  runWithTenantContext,
  runWithTenantTransaction,
  type TenantConfig,
  type TenantConfigInput,
  type TenantSqlExecutor,
} from "../../tenant.js";
import { resourceConflict, resourceNotFound } from "../errors.js";
import type {
  OpenPlatformEntityKind,
  OpenPlatformRecord,
  TenantScopedRepository,
} from "../types.js";

export type DatabaseAdapter = TenantSqlExecutor;
export type OpenPlatformDatabaseAdapter = DatabaseAdapter;
export type PersistenceDatabaseAdapter = DatabaseAdapter;
export type OpenPlatformSqlExecutor = DatabaseAdapter;
export type OpenPlatformSqlQuery = DatabaseAdapter["query"];

export interface OpenPlatformSqlTableNames {
  tenants: string;
  developerOrganizations: string;
  applications: string;
  applicationEnvironments: string;
  apiProducts: string;
  apiVersions: string;
  credentials: string;
  subscriptions: string;
  scopeGrants: string;
  usage: string;
  idempotency: string;
  webhooks: string;
  webhookDeliveries: string;
  auditEvents: string;
  domainEvents: string;
  relayLeases: string;
  developerOrganization?: string;
  applicationEnvironment?: string;
  apiProduct?: string;
  apiVersion?: string;
  credential?: string;
  subscription?: string;
  scopeGrant?: string;
  webhook?: string;
  webhookDelivery?: string;
  auditEvent?: string;
  domainEvent?: string;
  outbox?: string;
  outboxEvents?: string;
}

export type OpenPlatformSqlTableKey =
  | "tenants"
  | "developerOrganizations"
  | "applications"
  | "applicationEnvironments"
  | "apiProducts"
  | "apiVersions"
  | "credentials"
  | "subscriptions"
  | "scopeGrants"
  | "usage"
  | "idempotency"
  | "webhooks"
  | "webhookDeliveries"
  | "auditEvents"
  | "domainEvents"
  | "relayLeases";
export type OpenPlatformSqlColumns = Record<
  OpenPlatformSqlTableKey,
  Record<string, string>
>;

export interface OpenPlatformSqlRepositoryOptions {
  adapter?: DatabaseAdapter;
  databaseAdapter?: DatabaseAdapter;
  db?: DatabaseAdapter;
  executor?: DatabaseAdapter;
  query?: OpenPlatformSqlQuery;
  sharedExecutor?: DatabaseAdapter;
  dedicatedExecutor?: DatabaseAdapter;
  fallbackExecutor?: DatabaseAdapter;
  allowSharedFallback?: boolean;
  tenantId?: string;
  tenant?: TenantConfigInput;
  tenantConfig?: TenantConfigInput;
  tenantMode?: string;
  mode?: string;
  tenantColumn?: string;
  schema?: string;
  requireRls?: boolean;
  requireTransactions?: boolean;
  tables?: Partial<OpenPlatformSqlTableNames>;
  tableNames?: Partial<OpenPlatformSqlTableNames>;
  columns?: Partial<Record<OpenPlatformSqlTableKey, Record<string, string | null>>>;
  columnNames?: Partial<Record<OpenPlatformSqlTableKey, Record<string, string | null>>>;
}

export type OpenPlatformSqlRepositorySecondOptions = Omit<
  OpenPlatformSqlRepositoryOptions,
  "adapter" | "databaseAdapter" | "db" | "executor" | "query"
>;

export type OpenPlatformSqlRepositoryInput =
  | OpenPlatformSqlRuntime
  | OpenPlatformSqlRepositoryOptions
  | DatabaseAdapter
  | OpenPlatformSqlQuery;

export const OPEN_PLATFORM_SQL_TABLES: OpenPlatformSqlTableNames = Object.freeze({
  tenants: "gb_open_tenant",
  developerOrganizations: "gb_open_developer_organization",
  applications: "gb_open_application",
  applicationEnvironments: "gb_open_application_environment",
  apiProducts: "gb_open_api_product",
  apiVersions: "gb_open_api_version",
  credentials: "gb_open_credential",
  subscriptions: "gb_open_subscription",
  scopeGrants: "gb_open_scope_grant",
  usage: "gb_open_usage",
  idempotency: "gb_open_idempotency",
  webhooks: "gb_open_webhook",
  webhookDeliveries: "gb_open_webhook_delivery",
  auditEvents: "gb_open_audit_event",
  domainEvents: "gb_open_domain_event",
  relayLeases: "gb_open_relay_lease",
});

export const OPEN_PLATFORM_SQL_FIELDS: Readonly<Record<OpenPlatformSqlTableKey, readonly string[]>> = Object.freeze({
  tenants: ["id", "tenantId", "kind", "name", "status", "version", "etag", "createdAt", "updatedAt", "archivedAt"],
  developerOrganizations: ["id", "tenantId", "kind", "name", "description", "status", "version", "etag", "createdAt", "updatedAt", "archivedAt"],
  applications: ["id", "tenantId", "kind", "organizationId", "name", "description", "status", "version", "etag", "createdAt", "updatedAt", "archivedAt"],
  applicationEnvironments: ["id", "tenantId", "kind", "applicationId", "name", "status", "version", "etag", "createdAt", "updatedAt", "archivedAt"],
  apiProducts: ["id", "tenantId", "kind", "name", "description", "scopes", "status", "version", "etag", "createdAt", "updatedAt", "archivedAt"],
  apiVersions: ["id", "tenantId", "kind", "productId", "apiVersion", "description", "scopes", "status", "version", "etag", "createdAt", "updatedAt", "archivedAt"],
  credentials: ["id", "tenantId", "kind", "applicationId", "environmentId", "name", "status", "scopes", "secretDigest", "secretReference", "fingerprint", "expiresAt", "rotatedAt", "revokedAt", "replacedByCredentialId", "previousCredentialId", "version", "etag", "createdAt", "updatedAt"],
  subscriptions: ["id", "tenantId", "kind", "applicationId", "productId", "apiVersionId", "name", "scopes", "status", "version", "etag", "createdAt", "updatedAt", "archivedAt"],
  scopeGrants: ["id", "tenantId", "kind", "credentialId", "applicationId", "productId", "apiVersionId", "scopes", "status", "grantedAt", "revokedAt", "version", "etag", "createdAt", "updatedAt"],
  usage: ["id", "tenantId", "kind", "subscriptionId", "credentialId", "productId", "apiVersionId", "metric", "quantity", "occurredAt", "idempotencyKey", "version", "etag", "createdAt", "updatedAt"],
  idempotency: ["tenantId", "actorId", "operation", "key", "requestHash", "state", "leaseToken", "leaseExpiresAt", "expiresAt", "createdAt", "updatedAt", "completedAt", "response"],
  webhooks: ["id", "tenantId", "kind", "developerOrganizationId", "applicationId", "environmentId", "name", "endpointUrl", "status", "events", "signingAlgorithm", "signingSecretReference", "secretVersion", "failureCount", "nextDeliveryAt", "lastDeliveryAt", "version", "createdAt", "updatedAt"],
  webhookDeliveries: ["id", "tenantId", "webhookId", "eventId", "event", "eventType", "status", "attempt", "maxAttempts", "idempotencyKey", "payload", "body", "secretVersion", "nextAttemptAt", "deliveredAt", "responseStatusCode", "responseBodyExcerpt", "errorCode", "createdAt", "updatedAt"],
  auditEvents: ["id", "tenantId", "action", "outcome", "actorType", "actorId", "actorDisplayName", "actorIpAddress", "actorUserAgent", "targetType", "targetId", "targetDisplayName", "requestId", "metadata", "occurredAt", "sequence", "source", "previousHash", "eventHash", "createdAt"],
  domainEvents: ["id", "tenantId", "eventType", "resourceType", "resourceId", "resourceVersion", "resourceStatus", "actorId", "requestId", "occurredAt", "schemaVersion", "data", "status", "sequence", "attempt", "maxAttempts", "nextAttemptAt", "publishedAt", "errorCode", "leaseId", "leaseExpiresAt", "createdAt", "updatedAt"],
  relayLeases: ["leaseKey", "ownerId", "acquiredAt", "expiresAt", "updatedAt"],
});

const DEFAULT_COLUMNS: OpenPlatformSqlColumns = {
  tenants: {
    id: "id",
    tenantId: "tenant_id",
    kind: "kind",
    name: "name",
    status: "status",
    version: "version",
    etag: "etag",
    createdAt: "created_at",
    updatedAt: "updated_at",
    archivedAt: "archived_at",
  },
  developerOrganizations: {
    id: "id",
    tenantId: "tenant_id",
    kind: "kind",
    name: "name",
    description: "description",
    status: "status",
    version: "version",
    etag: "etag",
    createdAt: "created_at",
    updatedAt: "updated_at",
    archivedAt: "archived_at",
  },
  applications: {
    id: "id",
    tenantId: "tenant_id",
    kind: "kind",
    organizationId: "organization_id",
    name: "name",
    description: "description",
    status: "status",
    version: "version",
    etag: "etag",
    createdAt: "created_at",
    updatedAt: "updated_at",
    archivedAt: "archived_at",
  },
  applicationEnvironments: {
    id: "id",
    tenantId: "tenant_id",
    kind: "kind",
    applicationId: "application_id",
    name: "name",
    status: "status",
    version: "version",
    etag: "etag",
    createdAt: "created_at",
    updatedAt: "updated_at",
    archivedAt: "archived_at",
  },
  apiProducts: {
    id: "id",
    tenantId: "tenant_id",
    kind: "kind",
    name: "name",
    description: "description",
    scopes: "scopes",
    status: "status",
    version: "version",
    etag: "etag",
    createdAt: "created_at",
    updatedAt: "updated_at",
    archivedAt: "archived_at",
  },
  apiVersions: {
    id: "id",
    tenantId: "tenant_id",
    kind: "kind",
    productId: "product_id",
    apiVersion: "api_version",
    description: "description",
    scopes: "scopes",
    status: "status",
    version: "version",
    etag: "etag",
    createdAt: "created_at",
    updatedAt: "updated_at",
    archivedAt: "archived_at",
  },
  credentials: {
    id: "id",
    tenantId: "tenant_id",
    kind: "kind",
    applicationId: "application_id",
    environmentId: "environment_id",
    name: "name",
    status: "status",
    scopes: "scopes",
    secretDigest: "secret_digest",
    secretReference: "secret_reference",
    fingerprint: "fingerprint",
    expiresAt: "expires_at",
    rotatedAt: "rotated_at",
    revokedAt: "revoked_at",
    replacedByCredentialId: "replaced_by_credential_id",
    previousCredentialId: "previous_credential_id",
    version: "version",
    etag: "etag",
    createdAt: "created_at",
    updatedAt: "updated_at",
  },
  subscriptions: {
    id: "id",
    tenantId: "tenant_id",
    kind: "kind",
    applicationId: "application_id",
    productId: "product_id",
    apiVersionId: "api_version_id",
    name: "name",
    scopes: "scopes",
    status: "status",
    version: "version",
    etag: "etag",
    createdAt: "created_at",
    updatedAt: "updated_at",
    archivedAt: "archived_at",
  },
  scopeGrants: {
    id: "id",
    tenantId: "tenant_id",
    kind: "kind",
    credentialId: "credential_id",
    applicationId: "application_id",
    productId: "product_id",
    apiVersionId: "api_version_id",
    scopes: "scopes",
    status: "status",
    grantedAt: "granted_at",
    revokedAt: "revoked_at",
    version: "version",
    etag: "etag",
    createdAt: "created_at",
    updatedAt: "updated_at",
  },
  usage: {
    id: "id",
    tenantId: "tenant_id",
    kind: "kind",
    subscriptionId: "subscription_id",
    credentialId: "credential_id",
    productId: "product_id",
    apiVersionId: "api_version_id",
    metric: "metric",
    quantity: "quantity",
    occurredAt: "occurred_at",
    idempotencyKey: "idempotency_key",
    version: "version",
    etag: "etag",
    createdAt: "created_at",
    updatedAt: "updated_at",
  },
  idempotency: {
    tenantId: "tenant_id",
    actorId: "actor_id",
    operation: "operation",
    key: "idempotency_key",
    requestHash: "request_hash",
    state: "state",
    leaseToken: "lease_token",
    leaseExpiresAt: "lease_expires_at",
    expiresAt: "expires_at",
    createdAt: "created_at",
    updatedAt: "updated_at",
    completedAt: "completed_at",
    response: "response",
  },
  webhooks: {
    id: "id",
    tenantId: "tenant_id",
    kind: "kind",
    developerOrganizationId: "developer_organization_id",
    applicationId: "application_id",
    environmentId: "environment_id",
    name: "name",
    endpointUrl: "endpoint_url",
    status: "status",
    events: "events",
    signingAlgorithm: "signing_algorithm",
    signingSecretReference: "signing_secret_reference",
    secretVersion: "secret_version",
    failureCount: "failure_count",
    nextDeliveryAt: "next_delivery_at",
    lastDeliveryAt: "last_delivery_at",
    version: "version",
    createdAt: "created_at",
    updatedAt: "updated_at",
  },
  webhookDeliveries: {
    id: "id",
    tenantId: "tenant_id",
    webhookId: "webhook_id",
    eventId: "event_id",
    event: "event_type",
    eventType: "event_type",
    status: "status",
    attempt: "attempt",
    maxAttempts: "max_attempts",
    idempotencyKey: "idempotency_key",
    payload: "payload",
    body: "body",
    secretVersion: "secret_version",
    nextAttemptAt: "next_attempt_at",
    deliveredAt: "delivered_at",
    responseStatusCode: "response_status_code",
    responseBodyExcerpt: "response_body_excerpt",
    errorCode: "error_code",
    createdAt: "created_at",
    updatedAt: "updated_at",
  },
  auditEvents: {
    id: "id",
    tenantId: "tenant_id",
    action: "action",
    outcome: "outcome",
    actorType: "actor_type",
    actorId: "actor_id",
    actorDisplayName: "actor_display_name",
    actorIpAddress: "actor_ip_address",
    actorUserAgent: "actor_user_agent",
    targetType: "target_type",
    targetId: "target_id",
    targetDisplayName: "target_display_name",
    requestId: "request_id",
    metadata: "metadata",
    occurredAt: "occurred_at",
    sequence: "sequence",
    source: "source",
    previousHash: "previous_hash",
    eventHash: "event_hash",
    createdAt: "created_at",
  },
  domainEvents: {
    id: "event_id",
    tenantId: "tenant_id",
    eventType: "event_type",
    resourceType: "resource_type",
    resourceId: "resource_id",
    resourceVersion: "resource_version",
    resourceStatus: "resource_status",
    actorId: "actor_id",
    requestId: "request_id",
    occurredAt: "occurred_at",
    schemaVersion: "schema_version",
    data: "data",
    status: "status",
    sequence: "sequence",
    attempt: "attempt",
    maxAttempts: "max_attempts",
    nextAttemptAt: "next_attempt_at",
    publishedAt: "published_at",
    errorCode: "error_code",
    leaseId: "lease_id",
    leaseExpiresAt: "lease_expires_at",
    createdAt: "created_at",
    updatedAt: "updated_at",
  },
  relayLeases: {
    leaseKey: "lease_key",
    ownerId: "owner_id",
    acquiredAt: "acquired_at",
    expiresAt: "expires_at",
    updatedAt: "updated_at",
  },
};

export const OPEN_PLATFORM_SQL_COLUMNS: OpenPlatformSqlColumns = Object.freeze(DEFAULT_COLUMNS);

export const OPEN_PLATFORM_FOUNDATION_SQL_TABLE_KEYS: readonly OpenPlatformSqlTableKey[] = Object.freeze([
  "tenants",
  "developerOrganizations",
  "applications",
  "applicationEnvironments",
  "apiProducts",
  "apiVersions",
  "credentials",
  "subscriptions",
  "scopeGrants",
  "usage",
  "idempotency",
]);

export const OPEN_PLATFORM_ALL_TABLES: readonly OpenPlatformSqlTableKey[] = Object.freeze([
  "tenants",
  "developerOrganizations",
  "applications",
  "applicationEnvironments",
  "apiProducts",
  "apiVersions",
  "credentials",
  "subscriptions",
  "scopeGrants",
  "usage",
  "idempotency",
  "webhooks",
  "webhookDeliveries",
  "auditEvents",
  "domainEvents",
  "relayLeases",
]);

export interface OpenPlatformSqlReadiness {
  ready: boolean;
  mode: TenantConfig["mode"];
  rls: boolean;
  transactions: boolean;
  requiredTables: boolean;
  missingColumns: readonly string[];
  context: boolean;
}

export interface OpenPlatformMutationResult {
  rows: Record<string, unknown>[];
  affected: number;
}

export class OpenPlatformSqlRuntime {
  readonly tenant: TenantConfig;
  readonly tenantId: string;
  readonly adapter: DatabaseAdapter;
  readonly tables: Readonly<Record<OpenPlatformSqlTableKey, string>>;
  readonly columns: Readonly<Record<OpenPlatformSqlTableKey, Record<string, string>>>;
  private readonly transactionContext = new AsyncLocalStorage<DatabaseAdapter>();
  private readonly scopedExecutors = new WeakSet<object>();

  constructor(options?: OpenPlatformSqlRepositoryOptions);
  constructor(adapter: DatabaseAdapter, options?: OpenPlatformSqlRepositorySecondOptions);
  constructor(query: OpenPlatformSqlQuery, options?: OpenPlatformSqlRepositorySecondOptions);
  constructor(input: OpenPlatformSqlRepositoryInput, options?: OpenPlatformSqlRepositorySecondOptions);
  constructor(
    input: OpenPlatformSqlRepositoryInput = {},
    second: OpenPlatformSqlRepositorySecondOptions = {},
  ) {
    const options = normalizeRuntimeOptions(input, second);
    this.tenant = normalizeTenantConfig({
      ...(options.tenant ?? {}),
      ...(options.tenantConfig ?? {}),
      ...(options.tenantMode === undefined ? {} : { mode: options.tenantMode }),
      ...(options.mode === undefined ? {} : { mode: options.mode }),
      ...(options.tenantId === undefined ? {} : { tenantId: options.tenantId }),
      ...(options.tenantColumn === undefined ? {} : { tenantColumn: options.tenantColumn }),
      ...(options.schema === undefined ? {} : { schema: options.schema }),
      ...(options.requireRls === undefined ? {} : { requireRls: options.requireRls }),
      ...(options.requireTransactions === undefined ? {} : { requireTransactions: options.requireTransactions }),
    });
    assertNoDedicatedFallback(options);
    this.adapter = selectAdapter(options, this.tenant.mode);
    this.tenantId = this.tenant.tenantId;
    this.tables = normalizeTables(options, this.tenant.schema);
    this.columns = normalizeColumns(options, this.tenant.tenantColumn);
  }

  get distributed(): boolean {
    return typeof this.adapter.transaction === "function";
  }

  supportsTransactions(): boolean {
    return typeof this.adapter.transaction === "function";
  }

  table(key: OpenPlatformSqlTableKey): string {
    return quoteQualifiedIdentifier(this.tables[key]);
  }

  rawTable(key: OpenPlatformSqlTableKey): string {
    return this.tables[key];
  }

  column(key: OpenPlatformSqlTableKey, field: string): string {
    const value = this.columns[key][field];
    if (typeof value !== "string" || value.length === 0) {
      throw new TypeError(`SQL column ${key}.${field} is not configured`);
    }
    return quoteIdentifier(value);
  }

  select(
    key: OpenPlatformSqlTableKey,
    fields: readonly string[] = OPEN_PLATFORM_SQL_FIELDS[key],
  ): string {
    const entries = fields
      .map((field) => [field, this.columns[key][field]] as const)
      .filter((entry): entry is readonly [string, string] => typeof entry[1] === "string");
    if (entries.length === 0) throw new TypeError(`No SQL columns configured for ${key}`);
    return entries
      .map(([field, column]) => `${quoteIdentifier(column)} AS ${quoteIdentifier(field)}`)
      .join(", ");
  }

  async withTransaction<T>(
    operation: (executor: DatabaseAdapter) => Promise<T>,
  ): Promise<T> {
    if (this.tenant.requireTransactions && !this.supportsTransactions()) {
      throw new Error("Open platform SQL persistence requires a transaction-capable adapter");
    }
    const active = this.activeExecutor();
    if (active !== undefined) return this.withTenantContextOn(active, operation);
    if (!this.supportsTransactions()) return operation(this.adapter);
    const transaction = this.adapter.transaction;
    if (typeof transaction !== "function") return operation(this.adapter);
    return transaction.call(this.adapter, async (executor) => {
      const typed = executor as DatabaseAdapter;
      return runWithTenantTransaction(
        this.adapter,
        typed,
        () => this.transactionContext.run(typed, () => runWithTenantContext(
          { tenantId: this.tenant.tenantId, mode: this.tenant.mode, executor: typed },
          () => this.withTenantContextOn(typed, operation),
        )),
      );
    }) as Promise<T>;
  }

  async withTenantContext<T>(
    operation: (executor: DatabaseAdapter) => Promise<T>,
  ): Promise<T> {
    const active = this.activeExecutor();
    if (active !== undefined) return this.withTenantContextOn(active, operation);
    if (!this.tenant.requireRls) return operation(this.adapter);
    if (!this.supportsTransactions()) {
      throw new Error("Tenant-scoped request context requires a transaction");
    }
    return this.withTransaction(operation);
  }

  async queryRows(
    text: string,
    values: readonly unknown[] = [],
    executor?: DatabaseAdapter,
  ): Promise<Record<string, unknown>[]> {
    const active = this.activeExecutor(executor);
    if (this.tenant.requireRls && (active === undefined || active === this.adapter) && !this.scopedExecutors.has(this.adapter)) {
      return this.withTenantContext((scoped) => this.queryRows(text, values, scoped));
    }
    const result = await this.query(text, values, active ?? this.adapter);
    return resultRows(result);
  }

  async executeMutation(
    text: string,
    values: readonly unknown[] = [],
    executor?: DatabaseAdapter,
  ): Promise<OpenPlatformMutationResult> {
    const active = this.activeExecutor(executor);
    if (this.tenant.requireRls && (active === undefined || active === this.adapter) && !this.scopedExecutors.has(this.adapter)) {
      return this.withTenantContext((scoped) => this.executeMutation(text, values, scoped));
    }
    const result = await this.query(text, values, active ?? this.adapter);
    const rows = resultRows(result);
    return {
      rows,
      affected: affectedCount(result, rows.length),
    };
  }

  async isReady(keys: readonly OpenPlatformSqlTableKey[] = OPEN_PLATFORM_ALL_TABLES): Promise<boolean> {
    try {
      if (this.missingRequiredColumns(keys).length > 0) return false;
      if (this.tenant.requireTransactions && !this.supportsTransactions()) return false;
      if (this.tenant.requireRls && !this.supportsTransactions()) return false;
      if (this.tenant.requireRls) {
        const role = await this.queryRows(
          `SELECT r.rolsuper AS "superuser", r.rolbypassrls AS "bypassRls" FROM pg_roles r WHERE r.rolname = current_user`,
          [],
        );
        if (role[0] !== undefined && (readBoolean(role[0].superuser) || readBoolean(role[0].bypassRls))) return false;
      }
      for (const key of keys) {
        await this.queryRows(`SELECT 1 FROM ${this.table(key)} LIMIT 0`, []);
      }
      if (this.tenant.requireRls) {
        for (const key of keys) {
          const result = await this.queryRows(
            `SELECT c.relrowsecurity AS "rls", c.relforcerowsecurity AS "forceRls", EXISTS (SELECT 1 FROM pg_policies p WHERE p.schemaname = n.nspname AND p.tablename = c.relname AND p.qual IS NOT NULL AND p.with_check IS NOT NULL) AS "policy" FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = $1::regclass`,
            [this.rawTable(key)],
          );
          if (!readBoolean(result[0]?.rls) || !readBoolean(result[0]?.forceRls) || !readBoolean(result[0]?.policy)) return false;
        }
      }
      return true;
    } catch {
      return false;
    }
  }

  async readiness(keys: readonly OpenPlatformSqlTableKey[] = OPEN_PLATFORM_ALL_TABLES): Promise<OpenPlatformSqlReadiness> {
    const missingColumns = this.missingRequiredColumns(keys);
    const ready = await this.isReady(keys);
    return {
      ready,
      mode: this.tenant.mode,
      rls: !this.tenant.requireRls || ready,
      transactions: !this.tenant.requireTransactions || this.supportsTransactions(),
      requiredTables: ready,
      missingColumns: ready ? [] : missingColumns,
      context: !this.tenant.requireRls || this.supportsTransactions(),
    };
  }

  quote(value: string): string {
    return quoteIdentifier(value);
  }

  addTenantPredicate(
    key: OpenPlatformSqlTableKey,
    values: unknown[],
    clauses: string[],
    tenantId = this.tenantId,
  ): void {
    values.push(tenantId);
    clauses.push(`${this.column(key, "tenantId")} = $${values.length}`);
  }

  missingRequiredColumns(keys: readonly OpenPlatformSqlTableKey[] = OPEN_PLATFORM_ALL_TABLES): string[] {
    const missing: string[] = [];
    for (const key of keys) {
      for (const field of requiredFields(key)) {
        if (typeof this.columns[key][field] !== "string") missing.push(`${key}.${field}`);
      }
    }
    return missing;
  }

  async setTenantContext(executor: DatabaseAdapter): Promise<void> {
    if (!this.tenant.requireRls) return;
    await executor.query("SELECT set_config('app.tenant_id', $1, true)", [this.tenantId]);
  }

  private activeExecutor(executor?: DatabaseAdapter): DatabaseAdapter | undefined {
    return this.transactionContext.getStore() ??
      (getTenantTransactionExecutor(this.adapter) as DatabaseAdapter | undefined) ??
      executor;
  }

  private async withTenantContextOn<T>(
    executor: DatabaseAdapter,
    operation: (executor: DatabaseAdapter) => Promise<T>,
  ): Promise<T> {
    this.scopedExecutors.add(executor);
    try {
      await this.setTenantContext(executor);
      return await operation(executor);
    } finally {
      this.scopedExecutors.delete(executor);
    }
  }

  private async query(
    text: string,
    values: readonly unknown[],
    executor: DatabaseAdapter,
  ): Promise<unknown> {
    try {
      return await executor.query(text, [...values]);
    } catch (error) {
      if (isUniqueViolation(error)) throw resourceConflict("Open platform resource already exists");
      throw error;
    }
  }
}

export type OpenPlatformSqlRecord<T extends OpenPlatformRecord> = T & {
  readonly etag: string;
};

export interface OpenPlatformSaveOptions {
  expectedVersion?: number;
  expectedEtag?: string;
  expectedStatus?: string;
}

export abstract class OpenPlatformSqlRepository<T extends OpenPlatformRecord>
  implements TenantScopedRepository<T> {
  protected readonly runtime: OpenPlatformSqlRuntime;
  protected readonly tableKey: OpenPlatformSqlTableKey;
  protected readonly entityKind: OpenPlatformEntityKind;

  constructor(
    runtime: OpenPlatformSqlRuntime,
    tableKey: OpenPlatformSqlTableKey,
    entityKind: OpenPlatformEntityKind,
  ) {
    this.runtime = runtime;
    this.tableKey = tableKey;
    this.entityKind = entityKind;
  }

  async create(record: T): Promise<OpenPlatformSqlRecord<T>> {
    const normalized = this.prepareCreate(record);
    return this.runtime.withTransaction(async (executor) => {
      const fields = OPEN_PLATFORM_SQL_FIELDS[this.tableKey];
      const values = this.insertValues(normalized);
      const result = await this.runtime.executeMutation(
        `INSERT INTO ${this.runtime.table(this.tableKey)} (${fields.map((field) => this.runtime.column(this.tableKey, field)).join(", ")}) VALUES (${fields.map((_field, index) => `$${index + 1}`).join(", ")}) RETURNING ${this.runtime.select(this.tableKey, fields)}`,
        values,
        executor,
      );
      if (result.affected !== 1) throw resourceConflict("Open platform resource already exists");
      const row = result.rows[0];
      return row === undefined ? withEtag(normalized, createEtag(this.entityKind, normalized.id, normalized.version)) : this.mapRow(row);
    });
  }

  async withTransaction<T>(
    operation: (() => Promise<T>) | ((executor: DatabaseAdapter) => Promise<T>),
  ): Promise<T> {
    return this.runtime.withTransaction(async (executor) => {
      if (operation.length > 0) return operation(executor);
      return (operation as () => Promise<T>)();
    });
  }

  async withTenantContext<T>(
    operation: (executor: DatabaseAdapter) => Promise<T>,
  ): Promise<T> {
    return this.runtime.withTenantContext(operation);
  }

  async isReady(): Promise<boolean> {
    return this.runtime.isReady([this.tableKey]);
  }

  async readiness(): Promise<OpenPlatformSqlReadiness> {
    return this.runtime.readiness([this.tableKey]);
  }

  async get(tenantId: string, id: string): Promise<OpenPlatformSqlRecord<T> | undefined> {
    const tenant = normalizeTenant(tenantId);
    const identifier = normalizeStorageId(id);
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.runtime.addTenantPredicate(this.tableKey, values, clauses, tenant);
    values.push(identifier);
    clauses.push(`${this.runtime.column(this.tableKey, "id")} = $${values.length}`);
    const rows = await this.runtime.queryRows(
      `SELECT ${this.runtime.select(this.tableKey)} FROM ${this.runtime.table(this.tableKey)} WHERE ${clauses.join(" AND ")} LIMIT 1`,
      values,
    );
    if (rows.length === 0) return undefined;
    const record = this.mapRow(rows[0]);
    return record.tenantId === this.runtime.tenantId ? record : undefined;
  }

  async list(tenantId: string): Promise<OpenPlatformSqlRecord<T>[]> {
    const tenant = normalizeTenant(tenantId);
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.runtime.addTenantPredicate(this.tableKey, values, clauses, tenant);
    const rows = await this.runtime.queryRows(
      `SELECT ${this.runtime.select(this.tableKey)} FROM ${this.runtime.table(this.tableKey)} WHERE ${clauses.join(" AND ")} ORDER BY ${this.runtime.column(this.tableKey, "createdAt")} ASC, ${this.runtime.column(this.tableKey, "id")} ASC`,
      values,
    );
    return rows
      .map((row) => this.mapRow(row))
      .filter((record) => record.tenantId === this.runtime.tenantId);
  }

  async save(
    record: T,
    options: OpenPlatformSaveOptions = {},
  ): Promise<OpenPlatformSqlRecord<T>> {
    const normalized = this.prepareSave(record);
    return this.runtime.withTransaction(async (executor) => {
      const current = await this.requireCurrent(normalized.tenantId, normalized.id, executor);
      if (normalized.kind !== current.kind || normalized.tenantId !== current.tenantId || normalized.id !== current.id || normalized.createdAt !== current.createdAt) {
        throw resourceConflict("Open platform resource identity is immutable");
      }
      const expectedVersion = options.expectedVersion ?? normalized.version - 1;
      if (expectedVersion !== current.version) {
        throw resourceConflict("Open platform resource version is stale");
      }
      const currentEtag = createEtag(this.entityKind, current.id, current.version);
      if (options.expectedStatus !== undefined && options.expectedStatus !== currentStatus(current)) {
        throw resourceConflict("Open platform resource status is stale");
      }
      const suppliedEtag = options.expectedEtag ?? readEtag(record);
      if (suppliedEtag !== undefined && suppliedEtag !== currentEtag) {
        throw resourceConflict("Open platform resource ETag is stale");
      }
      if (normalized.version !== current.version + 1) {
        throw resourceConflict("Open platform resource version is stale");
      }
      this.validateTransition(current, normalized);
      const result = await this.updateValues(normalized, current, executor);
      if (result.affected !== 1) {
        throw resourceConflict("Open platform resource version is stale");
      }
      const row = result.rows[0];
      return row === undefined ? withEtag(normalized, createEtag(this.entityKind, normalized.id, normalized.version)) : this.mapRow(row);
    });
  }

  protected prepareCreate(record: T): T {
    this.validateIdentity(record);
    if (record.version !== 1) throw resourceConflict("Open platform resource version is invalid");
    return cloneRecord(record);
  }

  protected prepareSave(record: T): T {
    this.validateIdentity(record);
    if (!Number.isSafeInteger(record.version) || record.version < 2) {
      throw resourceConflict("Open platform resource version is invalid");
    }
    return cloneRecord(record);
  }

  protected validateIdentity(record: T): void {
    if (record === null || typeof record !== "object" || record.kind !== this.entityKind) {
      throw new TypeError(`Open platform ${this.entityKind} record is invalid`);
    }
    if (record.tenantId !== this.runtime.tenantId) {
      throw new TypeError("Open platform tenant scope does not match repository");
    }
    const identifier = normalizeStorageId(record.id);
    const tenant = normalizeTenant(record.tenantId);
    if (identifier !== record.id || tenant !== record.tenantId) {
      throw new TypeError("Open platform resource identity is not canonical");
    }
    if (readDate(record.createdAt) === undefined || readDate(record.updatedAt) === undefined) {
      throw new TypeError("Open platform resource timestamps are invalid");
    }
    if (!Number.isSafeInteger(record.version) || record.version < 1) {
      throw new TypeError("Open platform resource version is invalid");
    }
  }

  protected validateTransition(_current: T, _next: T): void {}

  protected async requireCurrent(
    tenantId: string,
    id: string,
    executor?: DatabaseAdapter,
  ): Promise<OpenPlatformSqlRecord<T>> {
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.runtime.addTenantPredicate(this.tableKey, values, clauses, tenantId);
    values.push(id);
    clauses.push(`${this.runtime.column(this.tableKey, "id")} = $${values.length}`);
    const rows = await this.runtime.queryRows(
      `SELECT ${this.runtime.select(this.tableKey)} FROM ${this.runtime.table(this.tableKey)} WHERE ${clauses.join(" AND ")} LIMIT 1`,
      values,
      executor,
    );
    if (rows.length === 0) throw resourceNotFound(this.entityKind);
    const record = this.mapRow(rows[0]);
    if (record.tenantId !== this.runtime.tenantId) throw resourceNotFound(this.entityKind);
    return record;
  }

  protected async updateValues(
    next: T,
    current: OpenPlatformSqlRecord<T>,
    executor: DatabaseAdapter,
  ): Promise<OpenPlatformMutationResult> {
    const fields = OPEN_PLATFORM_SQL_FIELDS[this.tableKey]
      .filter((field) => !["id", "tenantId", "kind", "createdAt"].includes(field));
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.runtime.addTenantPredicate(this.tableKey, values, clauses, next.tenantId);
    values.push(next.id, current.version, currentStatus(current));
    clauses.push(`${this.runtime.column(this.tableKey, "id")} = $${values.length - 2}`);
    clauses.push(`${this.runtime.column(this.tableKey, "version")} = $${values.length - 1}`);
    clauses.push(`${this.runtime.column(this.tableKey, "status")} = $${values.length}`);
    const setValues: unknown[] = [];
    const assignments: string[] = [];
    for (const field of fields) {
      assignments.push(`${this.runtime.column(this.tableKey, field)} = $${values.length + setValues.length + 1}`);
      setValues.push(
        field === "etag"
          ? createEtag(this.entityKind, next.id, next.version)
          : storageValue(field, (next as unknown as Record<string, unknown>)[field]),
      );
    }
    return this.runtime.executeMutation(
      `UPDATE ${this.runtime.table(this.tableKey)} SET ${assignments.join(", ")} WHERE ${clauses.join(" AND ")} RETURNING ${this.runtime.select(this.tableKey)}`,
      [...values, ...setValues],
      executor,
    );
  }

  protected insertValues(record: T): unknown[] {
    return OPEN_PLATFORM_SQL_FIELDS[this.tableKey].map((field) =>
      field === "etag"
        ? createEtag(this.entityKind, record.id, record.version)
        : storageValue(field, (record as unknown as Record<string, unknown>)[field]),
    );
  }

  protected normalizeTenant(value: string): string {
    const tenant = normalizeTenant(value);
    if (tenant !== this.runtime.tenantId) {
      throw new TypeError("Open platform tenant scope does not match repository");
    }
    return tenant;
  }

  protected abstract mapRow(row: Record<string, unknown>): OpenPlatformSqlRecord<T>;
}

export function createOpenPlatformSqlRuntime(
  input: OpenPlatformSqlRepositoryInput,
  second: OpenPlatformSqlRepositorySecondOptions = {},
): OpenPlatformSqlRuntime {
  if (input instanceof OpenPlatformSqlRuntime) return input;
  return new OpenPlatformSqlRuntime(input, second);
}

export function createEtag(kind: OpenPlatformEntityKind, id: string, version: number): string {
  return `${kind}:${id}:${version}`;
}

export function withEtag<T extends OpenPlatformRecord>(record: T, etag: string): OpenPlatformSqlRecord<T> {
  return Object.assign(cloneRecord(record), { etag });
}

export function normalizeStorageId(value: unknown): string {
  if (typeof value !== "string") throw new TypeError("Open platform resource identifier is invalid");
  const normalized = value.trim();
  if (normalized.length < 1 || normalized.length > 512 || /[\u0000-\u001f\u007f]/su.test(normalized)) {
    throw new TypeError("Open platform resource identifier is invalid");
  }
  return normalized;
}

export function normalizeTenant(value: unknown): string {
  if (typeof value !== "string") throw new TypeError("Open platform tenant identifier is invalid");
  const normalized = value.trim();
  if (normalized.length < 1 || normalized.length > 128 || !/^[a-z][a-z0-9-]{0,127}$/su.test(normalized)) {
    throw new TypeError("Open platform tenant identifier is invalid");
  }
  return normalized;
}

export function storageValue(field: string, value: unknown): unknown {
  if (["scopes", "events", "payload", "metadata"].includes(field)) return JSON.stringify(value === undefined ? (field === "events" || field === "scopes" ? [] : {}) : value);
  if (field === "response") return value === undefined ? null : JSON.stringify(value);
  if (["archivedAt", "environmentId", "description", "apiVersionId", "secretDigest", "secretReference", "expiresAt", "rotatedAt", "revokedAt", "replacedByCredentialId", "previousCredentialId", "credentialId", "nextDeliveryAt", "lastDeliveryAt", "nextAttemptAt", "deliveredAt", "previousHash"].includes(field)) {
    return value === undefined ? null : value;
  }
  return value;
}

export function readEtag(value: unknown): string | undefined {
  if (value === null || typeof value !== "object") return undefined;
  const etag = (value as Record<string, unknown>).etag;
  return typeof etag === "string" && etag.length > 0 ? etag : undefined;
}

export function currentStatus(value: unknown): string {
  if (value !== null && typeof value === "object") {
    const status = (value as Record<string, unknown>).status;
    if (typeof status === "string") return status;
  }
  return "draft";
}

export function rowValue(row: Record<string, unknown>, field: string): unknown {
  const snake = field.replace(/[A-Z]/gu, (letter) => `_${letter.toLowerCase()}`);
  const candidates = [field, snake, snake.toLowerCase()];
  for (const candidate of candidates) {
    if (Object.prototype.hasOwnProperty.call(row, candidate)) return row[candidate];
  }
  return undefined;
}

export function readText(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  return normalized.length > 0 && !/[\u0000-\u001f\u007f]/su.test(normalized) ? normalized : undefined;
}

export function readNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isSafeInteger(value)) return value;
  if (typeof value === "bigint" && value >= 0n && Number.isSafeInteger(Number(value))) return Number(value);
  if (typeof value === "string" && /^\d+$/u.test(value)) {
    const parsed = Number(value);
    return Number.isSafeInteger(parsed) ? parsed : undefined;
  }
  return undefined;
}

export function readDecimalQuantity(value: unknown): number | undefined {
  if (typeof value === "number") {
    return Number.isFinite(value) && value > 0 && value <= Number.MAX_SAFE_INTEGER
      ? value
      : undefined;
  }
  if (typeof value === "bigint") {
    if (value <= 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) return undefined;
    return Number(value);
  }
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  if (normalized.length < 1 || normalized.length > 128 || !/^(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$/u.test(normalized)) return undefined;
  const parsed = Number(normalized);
  return Number.isFinite(parsed) && parsed > 0 && parsed <= Number.MAX_SAFE_INTEGER
    ? parsed
    : undefined;
}

export function readDate(value: unknown): string | undefined {
  if (value instanceof Date && Number.isFinite(value.getTime())) return value.toISOString();
  if (typeof value === "string" && value.length <= 128 && Number.isFinite(Date.parse(value))) {
    return new Date(Date.parse(value)).toISOString();
  }
  return undefined;
}

export function readJson(value: unknown): unknown {
  if (typeof value !== "string") return value;
  if (value.trim().length === 0) return undefined;
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return undefined;
  }
}

export function readStringArray(value: unknown): string[] {
  const parsed = Array.isArray(value) ? value : readJson(value);
  if (!Array.isArray(parsed)) return [];
  return parsed.filter((item): item is string => typeof item === "string");
}

export function cloneRecord<T>(value: T): T {
  return structuredClone(value);
}

export function resultRows(value: unknown): Record<string, unknown>[] {
  const rows = Array.isArray(value)
    ? value
    : isRecord(value) && Array.isArray(value.rows)
      ? value.rows
      : isRecord(value) && (typeof value.rowCount === "number" || typeof value.rowCount === "bigint")
        ? []
        : undefined;
  if (rows === undefined) throw new Error("Open platform SQL result failed");
  return rows.filter(isRecord);
}

export function affectedCount(value: unknown, rowCount: number): number {
  if (isRecord(value) && typeof value.rowCount === "number" && Number.isSafeInteger(value.rowCount) && value.rowCount >= 0) return value.rowCount;
  if (isRecord(value) && typeof value.rowCount === "bigint" && value.rowCount >= 0n && Number.isSafeInteger(Number(value.rowCount))) return Number(value.rowCount);
  return rowCount;
}

export function isUniqueViolation(error: unknown): boolean {
  if (!isRecord(error)) return false;
  return error.code === "23505" || (typeof error.message === "string" && /unique|duplicate key/iu.test(error.message));
}

export function readBoolean(value: unknown): boolean {
  return value === true || value === "true" || value === 1 || value === "1";
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function quoteIdentifier(value: string): string {
  const segments = value.split(".");
  if (segments.length < 1 || segments.length > 2 || segments.some((segment) => !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(segment) || segment.length > 63)) {
    throw new TypeError(`Invalid SQL identifier: ${value}`);
  }
  return segments.map((segment) => `"${segment}"`).join(".");
}

function quoteQualifiedIdentifier(value: string): string {
  return quoteIdentifier(value);
}

function normalizeRuntimeOptions(
  input: OpenPlatformSqlRepositoryInput,
  second: OpenPlatformSqlRepositorySecondOptions,
): OpenPlatformSqlRepositoryOptions {
  if (typeof input === "function") return { ...second, query: input };
  if (isRecord(input) && typeof input.query === "function" && !hasOptionProperties(input)) {
    return { ...second, adapter: assertAdapter(input) };
  }
  return { ...(input as OpenPlatformSqlRepositoryOptions), ...second };
}

function hasOptionProperties(value: Record<string, unknown>): boolean {
  return [
    "adapter",
    "databaseAdapter",
    "db",
    "executor",
    "query",
    "sharedExecutor",
    "dedicatedExecutor",
    "fallbackExecutor",
    "allowSharedFallback",
    "tenantId",
    "tenant",
    "tenantConfig",
    "tenantMode",
    "mode",
    "tenantColumn",
    "schema",
    "requireRls",
    "requireTransactions",
    "tables",
    "tableNames",
    "columns",
    "columnNames",
  ].some((key) => Object.prototype.hasOwnProperty.call(value, key));
}

function selectAdapter(options: OpenPlatformSqlRepositoryOptions, mode: TenantConfig["mode"]): DatabaseAdapter {
  if (options.adapter !== undefined) return assertAdapter(options.adapter);
  if (options.databaseAdapter !== undefined) return assertAdapter(options.databaseAdapter);
  if (options.db !== undefined) return assertAdapter(options.db);
  if (options.executor !== undefined) return assertAdapter(options.executor);
  if (options.query !== undefined) return { query: options.query };
  if (mode === "shared" && options.sharedExecutor !== undefined) return assertAdapter(options.sharedExecutor);
  if (mode === "dedicated" && options.dedicatedExecutor !== undefined) return assertAdapter(options.dedicatedExecutor);
  throw new TypeError("An open platform SQL adapter is required");
}

function assertAdapter(value: unknown): DatabaseAdapter {
  if (!isRecord(value) || typeof value.query !== "function") {
    throw new TypeError("An open platform SQL adapter is required");
  }
  return value as unknown as DatabaseAdapter;
}

function assertNoDedicatedFallback(options: OpenPlatformSqlRepositoryOptions): void {
  const mode = options.tenant?.mode ?? options.tenantConfig?.mode ?? options.tenantMode ?? options.mode;
  if (typeof mode === "string" && mode.trim().toLowerCase() === "dedicated" && (options.allowSharedFallback === true || options.sharedExecutor !== undefined || options.fallbackExecutor !== undefined)) {
    throw new TypeError("Dedicated tenant mode cannot use a shared pool fallback");
  }
}

function normalizeTables(
  options: OpenPlatformSqlRepositoryOptions,
  schema: string,
): Readonly<Record<OpenPlatformSqlTableKey, string>> {
  const tables = {
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
     ...(options.tables?.webhook === undefined ? {} : { webhooks: options.tables.webhook }),
     ...(options.tableNames?.webhook === undefined ? {} : { webhooks: options.tableNames.webhook }),
     ...(options.tables?.webhookDelivery === undefined ? {} : { webhookDeliveries: options.tables.webhookDelivery }),
     ...(options.tableNames?.webhookDelivery === undefined ? {} : { webhookDeliveries: options.tableNames.webhookDelivery }),
     ...(options.tables?.auditEvent === undefined ? {} : { auditEvents: options.tables.auditEvent }),
     ...(options.tableNames?.auditEvent === undefined ? {} : { auditEvents: options.tableNames.auditEvent }),
     ...(options.tables?.domainEvent === undefined ? {} : { domainEvents: options.tables.domainEvent }),
     ...(options.tableNames?.domainEvent === undefined ? {} : { domainEvents: options.tableNames.domainEvent }),
     ...(options.tables?.outbox === undefined ? {} : { domainEvents: options.tables.outbox }),
     ...(options.tableNames?.outbox === undefined ? {} : { domainEvents: options.tableNames.outbox }),

  } as Record<OpenPlatformSqlTableKey, string>;
  const output = {} as Record<OpenPlatformSqlTableKey, string>;
  for (const key of OPEN_PLATFORM_ALL_TABLES) {
    assertIndependentTableName(tables[key], key);
    output[key] = qualifyTenantTable(tables[key], schema);
  }
  return Object.freeze(output);
}

function normalizeColumns(
  options: OpenPlatformSqlRepositoryOptions,
  tenantColumn: string,
): Readonly<Record<OpenPlatformSqlTableKey, Record<string, string>>> {
  const output = {} as Record<OpenPlatformSqlTableKey, Record<string, string>>;
  for (const key of OPEN_PLATFORM_ALL_TABLES) {
    const source = {
      ...DEFAULT_COLUMNS[key],
      ...(options.columns?.[key] ?? {}),
      ...(options.columnNames?.[key] ?? {}),
    };
    if (options.tenantColumn !== undefined) source.tenantId = options.tenantColumn;
    else if (tenantColumn !== "tenant_id") source.tenantId = tenantColumn;
    const normalized: Record<string, string> = {};
    for (const [field, value] of Object.entries(source)) {
      if (typeof value !== "string" || value.length === 0) continue;
      normalized[field] = validateColumnIdentifier(value, `${key}.${field}`);
    }
    output[key] = normalized;
  }
  return Object.freeze(output);
}

function requiredFields(key: OpenPlatformSqlTableKey): readonly string[] {
  const optional: Record<OpenPlatformSqlTableKey, readonly string[]> = {
    tenants: ["archivedAt"],
    developerOrganizations: ["description", "archivedAt"],
    applications: ["description", "archivedAt"],
    applicationEnvironments: ["archivedAt"],
    apiProducts: ["description", "archivedAt"],
    apiVersions: ["description", "archivedAt"],
    credentials: ["environmentId", "expiresAt", "rotatedAt", "revokedAt", "replacedByCredentialId", "previousCredentialId"],
    subscriptions: ["apiVersionId", "archivedAt"],
    scopeGrants: ["apiVersionId", "revokedAt"],
    usage: ["credentialId", "apiVersionId"],
    idempotency: ["leaseToken", "completedAt", "response"],
    webhooks: ["nextDeliveryAt", "lastDeliveryAt"],
    webhookDeliveries: ["eventType", "body", "nextAttemptAt", "deliveredAt", "responseStatusCode", "responseBodyExcerpt", "errorCode"],
    auditEvents: ["actorDisplayName", "actorIpAddress", "actorUserAgent", "targetDisplayName", "requestId", "previousHash"],
    domainEvents: ["resourceVersion", "resourceStatus", "actorId", "requestId", "nextAttemptAt", "publishedAt", "errorCode", "leaseId", "leaseExpiresAt"],
    relayLeases: [],
  };
  return OPEN_PLATFORM_SQL_FIELDS[key].filter((field) => !optional[key].includes(field));
}

function assertIndependentTableName(value: string, field: string): void {
  const base = value.split(".").at(-1) ?? value;
  if (base.toLowerCase().startsWith("gb_idaas_")) {
    throw new TypeError(`Open platform persistence cannot use existing IDaaS table for ${field}`);
  }
}

function validateColumnIdentifier(value: string, field: string): string {
  const normalized = value.replace(/[-_]/gu, "").toLowerCase();
  if (["secret", "clientsecret", "token", "accesstoken", "refreshtoken", "idtoken", "privatekey"].includes(normalized)) {
    throw new TypeError(`Sensitive SQL column name for ${field} is not allowed`);
  }
  return value;
}

export function quoteColumn(value: string): string {
  return quoteIdentifier(value);
}

export function validateOpenPlatformSqlIdentifier(value: unknown, field = "identifier"): string {
  if (typeof value !== "string") throw new TypeError(`${field} must be a string`);
  const normalized = value.trim();
  if (normalized !== value) throw new TypeError(`Invalid SQL identifier for ${field}`);
  const segments = normalized.split(".");
  if (segments.length < 1 || segments.length > 2 || segments.some((segment) => !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(segment) || segment.length > 63)) {
    throw new TypeError(`Invalid SQL identifier for ${field}`);
  }
  return segments.join(".");
}
