import { assertTenantProductionSupported } from "../../../tenant.js";
import type {
  CommerceDependencyReadiness,
  CommercePersistenceReadinessPort,
  CommerceRepositories,
} from "../types.js";
import {
  CommerceSqlRuntime,
  COMMERCE_ALL_TABLES,
  type CommerceDatabaseAdapter,
  type CommerceSqlQuery,
  type CommerceSqlReadiness,
  type CommerceSqlRepositoryInput,
  type CommerceSqlRepositoryOptions,
  type CommerceSqlRepositorySecondOptions,
} from "./adapter.js";
import {
  SqlCommissionRuleRepository,
  SqlEntitlementRepository,
  SqlInvoiceDisputeRepository,
  SqlInvoiceLineRepository,
  SqlInvoiceRepository,
  SqlMarketplaceListingRepository,
  SqlMeterRepository,
  SqlPartnerAccountRepository,
  SqlPlanRepository,
  SqlPriceRepository,
  SqlQuotaRepository,
  SqlQuotaReservationRepository,
  SqlSubscriptionRepository,
  SqlUsageAggregateRepository,
  SqlUsageEventRepository,
} from "./repositories.js";

export interface SqlCommerceRepositoriesOptions
  extends CommerceSqlRepositoryOptions {
  requireDistributed?: boolean;
  production?: boolean;
  productionReady?: boolean;
}

export type SqlCommerceRepositoriesInput =
  | SqlCommerceRepositoriesOptions
  | CommerceDatabaseAdapter
  | CommerceSqlQuery;

export type SqlCommerceRepositoriesSecondOptions = Omit<
  SqlCommerceRepositoriesOptions,
  "adapter" | "databaseAdapter" | "db" | "executor" | "query"
>;
export type CommercePersistenceOptions = SqlCommerceRepositoriesOptions;
export type SqlCommercePersistenceOptions = SqlCommerceRepositoriesOptions;

export class SqlCommerceRepositories implements CommerceRepositories {
  readonly runtime: CommerceSqlRuntime;
  readonly readiness: CommercePersistenceReadinessPort;
  private readonly allowExperimentalShared: boolean;
  readonly plans: SqlPlanRepository;
  readonly entitlements: SqlEntitlementRepository;
  readonly meters: SqlMeterRepository;
  readonly prices: SqlPriceRepository;
  readonly subscriptions: SqlSubscriptionRepository;
  readonly quotas: SqlQuotaRepository;
  readonly quotaReservations: SqlQuotaReservationRepository;
  readonly usageEvents: SqlUsageEventRepository;
  readonly usageAggregates: SqlUsageAggregateRepository;
  readonly invoices: SqlInvoiceRepository;
  readonly invoiceLines: SqlInvoiceLineRepository;
  readonly invoiceDisputes: SqlInvoiceDisputeRepository;
  readonly marketplaceListings: SqlMarketplaceListingRepository;
  readonly partnerAccounts: SqlPartnerAccountRepository;
  readonly commissionRules: SqlCommissionRuleRepository;

  constructor(options?: SqlCommerceRepositoriesOptions);
  constructor(adapter: CommerceDatabaseAdapter, options?: SqlCommerceRepositoriesSecondOptions);
  constructor(query: CommerceSqlQuery, options?: SqlCommerceRepositoriesSecondOptions);
  constructor(input: SqlCommerceRepositoriesInput, options?: SqlCommerceRepositoriesSecondOptions);
  constructor(
    input: SqlCommerceRepositoriesInput = {},
    second: SqlCommerceRepositoriesSecondOptions = {},
  ) {
    const options = normalizeFactoryOptions(input, second);
    if (options.production === true && options.requireDistributed === false) {
      throw new TypeError("Production commerce persistence requires distributed SQL dependencies");
    }
    this.runtime = new CommerceSqlRuntime(options);
    this.allowExperimentalShared = options.productionReady === true;
    if (options.production === true) this.assertTenantProductionGate();
    if (options.production === true && !this.runtime.distributed) {
      throw new TypeError("Production commerce persistence requires a transaction-capable SQL adapter");
    }
    this.plans = new SqlPlanRepository(this.runtime);
    this.entitlements = new SqlEntitlementRepository(this.runtime);
    this.meters = new SqlMeterRepository(this.runtime);
    this.prices = new SqlPriceRepository(this.runtime);
    this.subscriptions = new SqlSubscriptionRepository(this.runtime);
    this.quotaReservations = new SqlQuotaReservationRepository(this.runtime);
    this.quotas = new SqlQuotaRepository(this.runtime);
    this.usageEvents = new SqlUsageEventRepository(this.runtime);
    this.usageAggregates = new SqlUsageAggregateRepository(this.runtime);
    this.invoices = new SqlInvoiceRepository(this.runtime);
    this.invoiceLines = new SqlInvoiceLineRepository(this.runtime);
    this.invoiceDisputes = new SqlInvoiceDisputeRepository(this.runtime);
    this.marketplaceListings = new SqlMarketplaceListingRepository(this.runtime);
    this.partnerAccounts = new SqlPartnerAccountRepository(this.runtime);
    this.commissionRules = new SqlCommissionRuleRepository(this.runtime);
    const requireDistributed = options.requireDistributed !== false;
    this.readiness = Object.freeze({
      storage: "persistent" as const,
      distributed: this.runtime.distributed && (requireDistributed || this.runtime.tenant.mode !== "shared"),
      ready: async () => {
        if (requireDistributed && !this.runtime.distributed) return false;
        if (this.runtime.tenant.mode === "shared" && !this.runtime.distributed) return false;
        return this.runtime.isReady(COMMERCE_ALL_TABLES);
      },
    });
  }

  async isReady(): Promise<boolean> {
    return this.readiness.ready();
  }

  async readinessDetails(): Promise<CommerceSqlReadiness> {
    return this.runtime.readiness(COMMERCE_ALL_TABLES);
  }

  async productionReady(): Promise<boolean> {
    try {
      this.assertTenantProductionGate();
    } catch {
      return false;
    }
    return this.readiness.storage === "persistent" &&
      this.readiness.distributed &&
      await this.isReady();
  }

  assertProductionDependencies(): void {
    this.assertTenantProductionGate();
    if (this.readiness.storage !== "persistent" || !this.readiness.distributed) {
      throw new TypeError("Production commerce requires persistent distributed SQL persistence");
    }
  }

  async assertProductionReady(): Promise<void> {
    this.assertProductionDependencies();
    if (!(await this.productionReady())) {
      throw new TypeError("Production commerce persistence is not ready");
    }
  }

  private assertTenantProductionGate(): void {
    if (this.runtime.tenant.mode === "shared" && !this.allowExperimentalShared) {
      assertTenantProductionSupported(this.runtime.tenant.mode, "production");
    }
  }
}

export function createSqlCommerceRepositories(
  options?: SqlCommerceRepositoriesOptions,
): SqlCommerceRepositories;
export function createSqlCommerceRepositories(
  adapter: CommerceDatabaseAdapter,
  options?: SqlCommerceRepositoriesSecondOptions,
): SqlCommerceRepositories;
export function createSqlCommerceRepositories(
  query: CommerceSqlQuery,
  options?: SqlCommerceRepositoriesSecondOptions,
): SqlCommerceRepositories;
export function createSqlCommerceRepositories(
  input: SqlCommerceRepositoriesInput = {},
  second: SqlCommerceRepositoriesSecondOptions = {},
): SqlCommerceRepositories {
  return new SqlCommerceRepositories(input, second);
}

export const createCommercePersistence = createSqlCommerceRepositories;
export const createCommerceRepositories = createSqlCommerceRepositories;
export const createPersistentCommerceRepositories = createSqlCommerceRepositories;
export const createPostgresCommerceRepositories = createSqlCommerceRepositories;
export const createOpenCommercePersistence = createSqlCommerceRepositories;
export const createOpenCommerceRepositories = createSqlCommerceRepositories;
export const createOpenCommerceSqlRepositories = createSqlCommerceRepositories;
export const createOpenPlatformCommercePersistence = createSqlCommerceRepositories;
export const createSqlOpenCommerceRepositories = createSqlCommerceRepositories;
export const createOpenCommercePersistenceRepositories = createSqlCommerceRepositories;
export const createPostgresOpenCommerceRepositories = createSqlCommerceRepositories;

export function assertCommercePersistenceProductionReady(
  repositories: SqlCommerceRepositories,
): void {
  repositories.assertProductionDependencies();
}

export async function assertCommercePersistenceReady(
  repositories: SqlCommerceRepositories,
): Promise<void> {
  await repositories.assertProductionReady();
}

function normalizeFactoryOptions(
  input: SqlCommerceRepositoriesInput,
  second: SqlCommerceRepositoriesSecondOptions,
): SqlCommerceRepositoriesOptions {
  if (typeof input === "function") return { ...second, query: input };
  if (isRecord(input) && typeof input.query === "function" && !hasFactoryOptionProperties(input)) {
    return { ...second, adapter: input as unknown as CommerceDatabaseAdapter };
  }
  return { ...(input as SqlCommerceRepositoriesOptions), ...second };
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
    "productionReady",
  ].some((key) => Object.prototype.hasOwnProperty.call(value, key));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export const PostgresCommerceRepositories = SqlCommerceRepositories;
export const PostgreSqlCommerceRepositories = SqlCommerceRepositories;
export const OpenCommerceSqlRepositories = SqlCommerceRepositories;
export const CommerceSqlRepositories = SqlCommerceRepositories;
export const SqlOpenCommerceRepositories = SqlCommerceRepositories;
export const OpenCommercePersistenceRepositories = SqlCommerceRepositories;
export const PostgresOpenCommerceRepositories = SqlCommerceRepositories;

export type CommercePersistenceReadiness = CommerceDependencyReadiness;
export type { CommerceSqlRepositoryInput, CommerceSqlRepositoryOptions, CommerceSqlRepositorySecondOptions };
