import { configurationError } from "../errors.js";
import type {
  OpenPlatformDependencyReadiness,
  OpenPlatformRepositories,
} from "../types.js";
import {
  OpenPlatformSqlRuntime,
  isRecord,
  type DatabaseAdapter,
  type OpenPlatformSqlQuery,
  type OpenPlatformSqlReadiness,
  type OpenPlatformSqlRepositoryOptions,
  type OpenPlatformSqlRepositorySecondOptions,
} from "./adapter.js";
import { SqlIdempotencyStore } from "./idempotency.js";
import {
  SqlApiProductRepository,
  SqlApiVersionRepository,
  SqlApplicationEnvironmentRepository,
  SqlApplicationRepository,
  SqlCredentialRepository,
  SqlDeveloperOrganizationRepository,
  SqlScopeGrantRepository,
  SqlSubscriptionRepository,
  SqlTenantRepository,
  SqlUsageRepository,
} from "./repositories.js";
import { SqlAuditEventRepository } from "./audit.js";
import {
  SqlWebhookDeliveryRepository,
  SqlWebhookRepository,
} from "./webhook.js";
import { SqlDomainEventOutboxRepository } from "./events.js";

export interface SqlOpenPlatformRepositoriesOptions
  extends OpenPlatformSqlRepositoryOptions {
  requireDistributed?: boolean;
  production?: boolean;
}

export type SqlOpenPlatformRepositoriesInput =
  | SqlOpenPlatformRepositoriesOptions
  | DatabaseAdapter
  | OpenPlatformSqlQuery;

export type SqlOpenPlatformRepositoriesSecondOptions = Omit<
  SqlOpenPlatformRepositoriesOptions,
  "adapter" | "databaseAdapter" | "db" | "executor" | "query"
>;

export class SqlOpenPlatformRepositories implements OpenPlatformRepositories {
  readonly runtime: OpenPlatformSqlRuntime;
  readonly readiness: OpenPlatformDependencyReadiness;
  readonly tenants: SqlTenantRepository;
  readonly developerOrganizations: SqlDeveloperOrganizationRepository;
  readonly applications: SqlApplicationRepository;
  readonly applicationEnvironments: SqlApplicationEnvironmentRepository;
  readonly apiProducts: SqlApiProductRepository;
  readonly apiVersions: SqlApiVersionRepository;
  readonly credentials: SqlCredentialRepository;
  readonly subscriptions: SqlSubscriptionRepository;
  readonly scopeGrants: SqlScopeGrantRepository;
  readonly usage: SqlUsageRepository;
  readonly idempotency: SqlIdempotencyStore;
  readonly auditEvents: SqlAuditEventRepository;
  readonly webhooks: SqlWebhookRepository;
  readonly webhookDeliveries: SqlWebhookDeliveryRepository;
  readonly domainEvents: SqlDomainEventOutboxRepository;

  constructor(options?: SqlOpenPlatformRepositoriesOptions);
  constructor(adapter: DatabaseAdapter, options?: SqlOpenPlatformRepositoriesSecondOptions);
  constructor(query: OpenPlatformSqlQuery, options?: SqlOpenPlatformRepositoriesSecondOptions);
  constructor(input: SqlOpenPlatformRepositoriesInput, options?: SqlOpenPlatformRepositoriesSecondOptions);
  constructor(
    input: SqlOpenPlatformRepositoriesInput = {},
    second: SqlOpenPlatformRepositoriesSecondOptions = {},
  ) {
    const options = normalizeFactoryOptions(input, second);
    if (options.production === true && options.requireDistributed === false) {
      throw configurationError("Production open platform persistence requires distributed SQL dependencies");
    }
    if (options.production === true && options.requireDistributed !== false) {
      const runtime = new OpenPlatformSqlRuntime(options);
      if (!runtime.distributed) {
        throw configurationError("Production open platform persistence requires a transaction-capable SQL adapter");
      }
    }
    this.runtime = new OpenPlatformSqlRuntime(options);
    this.tenants = new SqlTenantRepository(this.runtime);
    this.developerOrganizations = new SqlDeveloperOrganizationRepository(this.runtime);
    this.applications = new SqlApplicationRepository(this.runtime);
    this.applicationEnvironments = new SqlApplicationEnvironmentRepository(this.runtime);
    this.apiProducts = new SqlApiProductRepository(this.runtime);
    this.apiVersions = new SqlApiVersionRepository(this.runtime);
    this.credentials = new SqlCredentialRepository(this.runtime);
    this.subscriptions = new SqlSubscriptionRepository(this.runtime);
    this.scopeGrants = new SqlScopeGrantRepository(this.runtime);
    this.usage = new SqlUsageRepository(this.runtime);
    this.idempotency = new SqlIdempotencyStore(this.runtime);
    this.auditEvents = new SqlAuditEventRepository(this.runtime);
    this.webhooks = new SqlWebhookRepository(this.runtime);
    this.webhookDeliveries = new SqlWebhookDeliveryRepository(this.runtime);
    this.domainEvents = new SqlDomainEventOutboxRepository(this.runtime);
    const requireDistributed = options.requireDistributed !== false;
    this.readiness = Object.freeze({
      storage: "persistent" as const,
      distributed: this.runtime.distributed && (requireDistributed || this.runtime.tenant.mode !== "shared"),
      ready: async () => {
        if (requireDistributed && !this.runtime.distributed) return false;
        if (this.runtime.tenant.mode === "shared" && !this.runtime.distributed) return false;
        return this.runtime.isReady();
      },
    });
  }

  async isReady(): Promise<boolean> {
    return this.readiness.ready();
  }

  async readinessDetails(): Promise<OpenPlatformSqlReadiness> {
    return this.runtime.readiness();
  }

  async productionReady(): Promise<boolean> {
    return this.readiness.storage === "persistent" &&
      this.readiness.distributed &&
      await this.isReady();
  }

  assertProductionDependencies(): void {
    if (this.readiness.storage !== "persistent" || !this.readiness.distributed) {
      throw configurationError("Production open platform requires persistent distributed SQL persistence");
    }
  }

  async assertProductionReady(): Promise<void> {
    if (!(await this.productionReady())) {
      throw configurationError("Production open platform persistence is not ready");
    }
  }
}

export function createSqlOpenPlatformRepositories(
  options?: SqlOpenPlatformRepositoriesOptions,
): SqlOpenPlatformRepositories;
export function createSqlOpenPlatformRepositories(
  adapter: DatabaseAdapter,
  options?: SqlOpenPlatformRepositoriesSecondOptions,
): SqlOpenPlatformRepositories;
export function createSqlOpenPlatformRepositories(
  query: OpenPlatformSqlQuery,
  options?: SqlOpenPlatformRepositoriesSecondOptions,
): SqlOpenPlatformRepositories;
export function createSqlOpenPlatformRepositories(
  input: SqlOpenPlatformRepositoriesInput = {},
  second: SqlOpenPlatformRepositoriesSecondOptions = {},
): SqlOpenPlatformRepositories {
  return new SqlOpenPlatformRepositories(input, second);
}

export const createOpenPlatformPersistence = createSqlOpenPlatformRepositories;
export const createOpenPlatformRepositories = createSqlOpenPlatformRepositories;
export const createPersistentOpenPlatformRepositories = createSqlOpenPlatformRepositories;
export const createPostgresOpenPlatformRepositories = createSqlOpenPlatformRepositories;
export const createOpenPlatformSqlRepositories = createSqlOpenPlatformRepositories;
export const createOpenPlatformPersistenceRepositories = createSqlOpenPlatformRepositories;

export function assertOpenPlatformPersistenceProductionReady(
  repositories: SqlOpenPlatformRepositories,
): void {
  repositories.assertProductionDependencies();
}

export async function assertOpenPlatformPersistenceReady(
  repositories: SqlOpenPlatformRepositories,
): Promise<void> {
  await repositories.assertProductionReady();
}

function normalizeFactoryOptions(
  input: SqlOpenPlatformRepositoriesInput,
  second: SqlOpenPlatformRepositoriesSecondOptions,
): SqlOpenPlatformRepositoriesOptions {
  if (typeof input === "function") return { ...second, query: input };
  if (isRecord(input) && typeof input.query === "function" && !hasFactoryOptionProperties(input)) {
    return { ...second, adapter: input as unknown as DatabaseAdapter };
  }
  return { ...(input as SqlOpenPlatformRepositoriesOptions), ...second };
}

function hasFactoryOptionProperties(value: Record<string, unknown>): boolean {
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
    "requireDistributed",
    "production",
  ].some((key) => Object.prototype.hasOwnProperty.call(value, key));
}
