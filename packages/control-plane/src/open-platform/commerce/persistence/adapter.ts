import { AsyncLocalStorage } from "node:async_hooks";
import {
  getTenantTransactionExecutor,
  normalizeTenantConfig,
  qualifyTenantTable,
  runWithTenantContext as runTenantContext,
  runWithTenantTransaction,
  type TenantConfig,
  type TenantConfigInput,
  type TenantSqlExecutor,
} from "../../../tenant.js";
import { commerceResourceConflict } from "../errors.js";
import { assertDecimalString, normalizeDecimalString } from "../money.js";
import type { DecimalString, Money } from "../types.js";

export type CommerceDatabaseAdapter = TenantSqlExecutor;
export type DatabaseAdapter = CommerceDatabaseAdapter;
export type CommerceSqlExecutor = CommerceDatabaseAdapter;
export type CommerceSqlQuery = CommerceDatabaseAdapter["query"];

export interface CommerceSqlTableNames {
  plans: string;
  entitlements: string;
  meters: string;
  prices: string;
  subscriptions: string;
  quotas: string;
  quotaReservations: string;
  usageEvents: string;
  usageAggregates: string;
  invoices: string;
  invoiceLines: string;
  invoiceStatusEvents: string;
  invoiceDisputes: string;
  marketplaceListings: string;
  partnerAccounts: string;
  commissionRules: string;
  plan?: string;
  entitlement?: string;
  meter?: string;
  price?: string;
  subscription?: string;
  quota?: string;
  quotaReservation?: string;
  usageEvent?: string;
  usageAggregate?: string;
  invoice?: string;
  invoiceLine?: string;
  invoiceStatusEvent?: string;
  invoiceDispute?: string;
  marketplaceListing?: string;
  partnerAccount?: string;
  commissionRule?: string;
}

export type CommerceSqlTableKey =
  | "plans"
  | "entitlements"
  | "meters"
  | "prices"
  | "subscriptions"
  | "quotas"
  | "quotaReservations"
  | "usageEvents"
  | "usageAggregates"
  | "invoices"
  | "invoiceLines"
  | "invoiceStatusEvents"
  | "invoiceDisputes"
  | "marketplaceListings"
  | "partnerAccounts"
  | "commissionRules";

export type CommerceSqlColumns = Record<
  CommerceSqlTableKey,
  Record<string, string>
>;

export const COMMERCE_SQL_TABLES: Readonly<Record<CommerceSqlTableKey, string>> = Object.freeze({
  plans: "gb_open_commerce_plan",
  entitlements: "gb_open_commerce_entitlement",
  meters: "gb_open_commerce_meter",
  prices: "gb_open_commerce_price",
  subscriptions: "gb_open_commerce_subscription",
  quotas: "gb_open_commerce_quota",
  quotaReservations: "gb_open_commerce_quota_reservation",
  usageEvents: "gb_open_commerce_usage_event",
  usageAggregates: "gb_open_commerce_usage_aggregate",
  invoices: "gb_open_commerce_invoice",
  invoiceLines: "gb_open_commerce_invoice_line",
  invoiceStatusEvents: "gb_open_commerce_invoice_status_event",
  invoiceDisputes: "gb_open_commerce_invoice_dispute",
  marketplaceListings: "gb_open_commerce_marketplace_listing",
  partnerAccounts: "gb_open_commerce_partner_account",
  commissionRules: "gb_open_commerce_commission_rule",
});

export const OPEN_COMMERCE_SQL_TABLES = COMMERCE_SQL_TABLES;
export const COMMERCE_RESERVED_EXISTING_TABLES: readonly string[] = Object.freeze([
  "gb_open_tenant",
  "gb_open_developer_organization",
  "gb_open_application",
  "gb_open_application_environment",
  "gb_open_api_product",
  "gb_open_api_version",
  "gb_open_credential",
  "gb_open_subscription",
  "gb_open_scope_grant",
  "gb_open_usage",
  "gb_open_idempotency",
]);

export const COMMERCE_SQL_FIELDS: Readonly<Record<CommerceSqlTableKey, readonly string[]>> = Object.freeze({
  plans: ["id", "tenantId", "kind", "code", "name", "description", "status", "priority", "currency", "priceIds", "entitlementIds", "quotaIds", "effectiveFrom", "effectiveTo", "version", "createdAt", "updatedAt"],
  entitlements: ["id", "tenantId", "kind", "feature", "effect", "valueType", "valueBoolean", "valueInteger", "valueText", "source", "sourceId", "priority", "status", "effectiveFrom", "effectiveTo", "version", "createdAt", "updatedAt"],
  meters: ["id", "tenantId", "kind", "key", "name", "unit", "aggregation", "dimensions", "status", "version", "createdAt", "updatedAt"],
  prices: ["id", "tenantId", "kind", "code", "name", "status", "currency", "roundingMode", "priceType", "fixedAmountMinor", "meterId", "unitAmountMinor", "includedUnits", "minimumChargeMinor", "tiers", "effectiveFrom", "effectiveTo", "version", "createdAt", "updatedAt"],
  subscriptions: ["id", "tenantId", "kind", "applicationId", "planId", "name", "status", "quantity", "currentPeriodStart", "currentPeriodEnd", "cancelAtPeriodEnd", "canceledAt", "version", "createdAt", "updatedAt"],
  quotas: ["id", "tenantId", "kind", "planId", "meterId", "limit", "reserved", "consumed", "status", "version", "createdAt", "updatedAt"],
  quotaReservations: ["id", "tenantId", "kind", "quotaId", "planId", "subscriptionId", "meterId", "quantity", "status", "operation", "idempotencyKey", "requestHash", "expiresAt", "settledQuantity", "settledAt", "releasedAt", "terminalOperation", "terminalIdempotencyKey", "terminalRequestHash", "version", "createdAt", "updatedAt"],
  usageEvents: ["id", "tenantId", "kind", "version", "sourceEventId", "subscriptionId", "meterId", "quantity", "occurredAt", "periodStart", "periodEnd", "dimensions", "idempotencyKey", "requestHash", "payloadHash", "receivedAt"],
  usageAggregates: ["id", "tenantId", "kind", "aggregateKey", "subscriptionId", "meterId", "aggregation", "quantity", "unit", "periodStart", "periodEnd", "dimensions", "eventIds", "status", "version", "createdAt", "updatedAt"],
  invoices: ["id", "tenantId", "kind", "version", "subscriptionId", "planId", "periodStart", "periodEnd", "status", "currency", "taxMode", "subtotalMinor", "taxMinor", "totalMinor", "idempotencyKey", "requestHash", "mainlandChina", "finalizedAt", "paidAt", "voidedAt", "createdAt", "updatedAt"],
  invoiceLines: ["id", "tenantId", "kind", "invoiceId", "type", "direction", "description", "quantity", "unitAmountMinor", "amountMinor", "currency", "meterId", "priceId", "aggregateId", "adjustmentType"],
  invoiceStatusEvents: ["tenantId", "invoiceId", "version", "status", "previousStatus", "occurredAt", "paidAt", "finalizedAt", "voidedAt"],
  invoiceDisputes: ["id", "tenantId", "kind", "version", "event", "invoiceId", "subscriptionId", "planId", "invoiceStatus", "invoiceVersion", "reason", "reasonDigest", "reasonLength", "evidenceReference", "evidenceReferenceDigest", "evidenceCount", "actorId", "requestId", "idempotencyKey", "requestHash", "status", "resolutionOutcome", "resolutionActorId", "resolutionReference", "resolutionNote", "resolutionNoteLength", "resolutionFromStatus", "resolvedAt", "createdAt", "updatedAt", "recordedAt"],
  marketplaceListings: ["id", "tenantId", "kind", "partnerAccountId", "productId", "title", "description", "status", "priceIds", "commissionRuleIds", "submittedAt", "publishedAt", "removedAt", "version", "createdAt", "updatedAt"],
  partnerAccounts: ["id", "tenantId", "kind", "legalName", "partnerCode", "status", "currency", "settlementReference", "activatedAt", "version", "createdAt", "updatedAt"],
  commissionRules: ["id", "tenantId", "kind", "partnerAccountId", "listingId", "name", "status", "rateBps", "capBps", "capAmountMinor", "currency", "priority", "effectiveFrom", "effectiveTo", "version", "createdAt", "updatedAt"],
});

export const OPEN_COMMERCE_SQL_FIELDS = COMMERCE_SQL_FIELDS;

const DEFAULT_COLUMNS: CommerceSqlColumns = {
  plans: {
    id: "id",
    tenantId: "tenant_id",
    kind: "kind",
    code: "code",
    name: "name",
    description: "description",
    status: "status",
    priority: "priority",
    currency: "currency",
    priceIds: "price_ids",
    entitlementIds: "entitlement_ids",
    quotaIds: "quota_ids",
    effectiveFrom: "effective_from",
    effectiveTo: "effective_to",
    version: "version",
    createdAt: "created_at",
    updatedAt: "updated_at",
  },
  entitlements: {
    id: "id",
    tenantId: "tenant_id",
    kind: "kind",
    feature: "feature",
    effect: "effect",
    valueType: "value_type",
    valueBoolean: "value_boolean",
    valueInteger: "value_integer",
    valueText: "value_text",
    source: "source",
    sourceId: "source_id",
    priority: "priority",
    status: "status",
    effectiveFrom: "effective_from",
    effectiveTo: "effective_to",
    version: "version",
    createdAt: "created_at",
    updatedAt: "updated_at",
  },
  meters: {
    id: "id",
    tenantId: "tenant_id",
    kind: "kind",
    key: "key",
    name: "name",
    unit: "unit",
    aggregation: "aggregation",
    dimensions: "dimensions",
    status: "status",
    version: "version",
    createdAt: "created_at",
    updatedAt: "updated_at",
  },
  prices: {
    id: "id",
    tenantId: "tenant_id",
    kind: "kind",
    code: "code",
    name: "name",
    status: "status",
    currency: "currency",
    roundingMode: "rounding_mode",
    priceType: "price_type",
    fixedAmountMinor: "fixed_amount_minor",
    meterId: "meter_id",
    unitAmountMinor: "unit_amount_minor",
    includedUnits: "included_units",
    minimumChargeMinor: "minimum_charge_minor",
    tiers: "tiers",
    effectiveFrom: "effective_from",
    effectiveTo: "effective_to",
    version: "version",
    createdAt: "created_at",
    updatedAt: "updated_at",
  },
  subscriptions: {
    id: "id",
    tenantId: "tenant_id",
    kind: "kind",
    applicationId: "application_id",
    planId: "plan_id",
    name: "name",
    status: "status",
    quantity: "quantity",
    currentPeriodStart: "current_period_start",
    currentPeriodEnd: "current_period_end",
    cancelAtPeriodEnd: "cancel_at_period_end",
    canceledAt: "canceled_at",
    version: "version",
    createdAt: "created_at",
    updatedAt: "updated_at",
  },
  quotas: {
    id: "id",
    tenantId: "tenant_id",
    kind: "kind",
    planId: "plan_id",
    meterId: "meter_id",
    limit: "limit",
    reserved: "reserved",
    consumed: "consumed",
    status: "status",
    version: "version",
    createdAt: "created_at",
    updatedAt: "updated_at",
  },
  quotaReservations: {
    id: "id",
    tenantId: "tenant_id",
    kind: "kind",
    quotaId: "quota_id",
    planId: "plan_id",
    subscriptionId: "subscription_id",
    meterId: "meter_id",
    quantity: "quantity",
    status: "status",
    operation: "operation",
    idempotencyKey: "idempotency_key",
    requestHash: "request_hash",
    expiresAt: "expires_at",
    settledQuantity: "settled_quantity",
    settledAt: "settled_at",
    releasedAt: "released_at",
    terminalOperation: "terminal_operation",
    terminalIdempotencyKey: "terminal_idempotency_key",
    terminalRequestHash: "terminal_request_hash",
    version: "version",
    createdAt: "created_at",
    updatedAt: "updated_at",
  },
  usageEvents: {
    id: "id",
    tenantId: "tenant_id",
    kind: "kind",
    version: "version",
    sourceEventId: "source_event_id",
    subscriptionId: "subscription_id",
    meterId: "meter_id",
    quantity: "quantity",
    occurredAt: "occurred_at",
    periodStart: "period_start",
    periodEnd: "period_end",
    dimensions: "dimensions",
    idempotencyKey: "idempotency_key",
    requestHash: "request_hash",
    payloadHash: "payload_hash",
    receivedAt: "received_at",
  },
  usageAggregates: {
    id: "id",
    tenantId: "tenant_id",
    kind: "kind",
    aggregateKey: "aggregate_key",
    subscriptionId: "subscription_id",
    meterId: "meter_id",
    aggregation: "aggregation",
    quantity: "quantity",
    unit: "unit",
    periodStart: "period_start",
    periodEnd: "period_end",
    dimensions: "dimensions",
    eventIds: "event_ids",
    status: "status",
    version: "version",
    createdAt: "created_at",
    updatedAt: "updated_at",
  },
  invoices: {
    id: "id",
    tenantId: "tenant_id",
    kind: "kind",
    version: "version",
    subscriptionId: "subscription_id",
    planId: "plan_id",
    periodStart: "period_start",
    periodEnd: "period_end",
    status: "status",
    currency: "currency",
    taxMode: "tax_mode",
    subtotalMinor: "subtotal_minor",
    taxMinor: "tax_minor",
    totalMinor: "total_minor",
    idempotencyKey: "idempotency_key",
    requestHash: "request_hash",
    mainlandChina: "mainland_china",
    finalizedAt: "finalized_at",
    paidAt: "paid_at",
    voidedAt: "voided_at",
    createdAt: "created_at",
    updatedAt: "updated_at",
  },
  invoiceLines: {
    id: "id",
    tenantId: "tenant_id",
    kind: "kind",
    invoiceId: "invoice_id",
    type: "type",
    direction: "direction",
    description: "description",
    quantity: "quantity",
    unitAmountMinor: "unit_amount_minor",
    amountMinor: "amount_minor",
    currency: "currency",
    meterId: "meter_id",
    priceId: "price_id",
    aggregateId: "aggregate_id",
    adjustmentType: "adjustment_type",
  },
  invoiceStatusEvents: {
    tenantId: "tenant_id",
    invoiceId: "invoice_id",
    version: "version",
    status: "status",
    previousStatus: "previous_status",
    occurredAt: "occurred_at",
    paidAt: "paid_at",
    finalizedAt: "finalized_at",
    voidedAt: "voided_at",
  },
  invoiceDisputes: {
    id: "id",
    tenantId: "tenant_id",
    kind: "kind",
    version: "version",
    event: "event",
    invoiceId: "invoice_id",
    subscriptionId: "subscription_id",
    planId: "plan_id",
    invoiceStatus: "invoice_status",
    invoiceVersion: "invoice_version",
    reason: "reason",
    reasonDigest: "reason_digest",
    reasonLength: "reason_length",
    evidenceReference: "evidence_reference",
    evidenceReferenceDigest: "evidence_reference_digest",
    evidenceCount: "evidence_count",
    actorId: "actor_id",
    requestId: "request_id",
    idempotencyKey: "idempotency_key",
    requestHash: "request_hash",
    status: "status",
    resolutionOutcome: "resolution_outcome",
    resolutionActorId: "resolution_actor_id",
    resolutionReference: "resolution_reference",
    resolutionNote: "resolution_note",
    resolutionNoteLength: "resolution_note_length",
    resolutionFromStatus: "resolution_from_status",
    resolvedAt: "resolved_at",
    createdAt: "created_at",
    updatedAt: "updated_at",
    recordedAt: "recorded_at",
  },
  marketplaceListings: {
    id: "id",
    tenantId: "tenant_id",
    kind: "kind",
    partnerAccountId: "partner_account_id",
    productId: "product_id",
    title: "title",
    description: "description",
    status: "status",
    priceIds: "price_ids",
    commissionRuleIds: "commission_rule_ids",
    submittedAt: "submitted_at",
    publishedAt: "published_at",
    removedAt: "removed_at",
    version: "version",
    createdAt: "created_at",
    updatedAt: "updated_at",
  },
  partnerAccounts: {
    id: "id",
    tenantId: "tenant_id",
    kind: "kind",
    legalName: "legal_name",
    partnerCode: "partner_code",
    status: "status",
    currency: "currency",
    settlementReference: "settlement_reference",
    activatedAt: "activated_at",
    version: "version",
    createdAt: "created_at",
    updatedAt: "updated_at",
  },
  commissionRules: {
    id: "id",
    tenantId: "tenant_id",
    kind: "kind",
    partnerAccountId: "partner_account_id",
    listingId: "listing_id",
    name: "name",
    status: "status",
    rateBps: "rate_bps",
    capBps: "cap_bps",
    capAmountMinor: "cap_amount_minor",
    currency: "currency",
    priority: "priority",
    effectiveFrom: "effective_from",
    effectiveTo: "effective_to",
    version: "version",
    createdAt: "created_at",
    updatedAt: "updated_at",
  },
};

const OPTIONAL_FIELDS: Readonly<Record<CommerceSqlTableKey, readonly string[]>> = Object.freeze({
  plans: ["description", "effectiveTo"],
  entitlements: ["valueType", "valueBoolean", "valueInteger", "valueText", "effectiveTo"],
  meters: [],
  prices: ["fixedAmountMinor", "meterId", "unitAmountMinor", "includedUnits", "minimumChargeMinor", "tiers", "effectiveTo"],
  subscriptions: ["canceledAt"],
  quotas: [],
  quotaReservations: ["settledQuantity", "settledAt", "releasedAt", "terminalOperation", "terminalIdempotencyKey", "terminalRequestHash"],
  usageEvents: [],
  usageAggregates: [],
  invoices: ["mainlandChina", "finalizedAt", "paidAt", "voidedAt"],
  invoiceLines: ["meterId", "priceId", "aggregateId", "adjustmentType"],
  invoiceStatusEvents: ["paidAt", "finalizedAt", "voidedAt"],
  invoiceDisputes: ["evidenceReference", "evidenceReferenceDigest", "resolutionOutcome", "resolutionActorId", "resolutionReference", "resolutionNote", "resolutionNoteLength", "resolutionFromStatus", "resolvedAt"],
  marketplaceListings: ["submittedAt", "publishedAt", "removedAt"],
  partnerAccounts: ["activatedAt"],
  commissionRules: ["capBps", "capAmountMinor", "effectiveTo"],
});

export const COMMERCE_ALL_TABLES: readonly CommerceSqlTableKey[] = Object.freeze([
  "plans",
  "entitlements",
  "meters",
  "prices",
  "subscriptions",
  "quotas",
  "quotaReservations",
  "usageEvents",
  "usageAggregates",
  "invoices",
  "invoiceLines",
  "invoiceStatusEvents",
  "marketplaceListings",
  "partnerAccounts",
  "commissionRules",
]);
export const OPEN_COMMERCE_ALL_TABLES = COMMERCE_ALL_TABLES;

export const COMMERCE_FOUNDATION_SQL_TABLES: Readonly<
  Record<CommerceSqlTableKey, string>
> = Object.freeze(
  Object.fromEntries(
    COMMERCE_ALL_TABLES.map((key) => [key, COMMERCE_SQL_TABLES[key]]),
  ) as Record<CommerceSqlTableKey, string>,
);

export const COMMERCE_RUNTIME_TABLES: readonly CommerceSqlTableKey[] =
  Object.freeze([...COMMERCE_ALL_TABLES, "invoiceDisputes"]);
export const OPEN_COMMERCE_RUNTIME_TABLES = COMMERCE_RUNTIME_TABLES;
export const COMMERCE_LATEST_TABLES = COMMERCE_RUNTIME_TABLES;

export const COMMERCE_SQL_COLUMNS: Readonly<CommerceSqlColumns> = Object.freeze(DEFAULT_COLUMNS);

export interface CommerceSqlRepositoryOptions {
  adapter?: CommerceDatabaseAdapter;
  databaseAdapter?: CommerceDatabaseAdapter;
  db?: CommerceDatabaseAdapter;
  executor?: CommerceDatabaseAdapter;
  query?: CommerceSqlQuery;
  sharedExecutor?: CommerceDatabaseAdapter;
  dedicatedExecutor?: CommerceDatabaseAdapter;
  fallbackExecutor?: CommerceDatabaseAdapter;
  allowSharedFallback?: boolean;
  tenantId?: string;
  tenant?: TenantConfigInput;
  tenantConfig?: TenantConfigInput;
  tenantMode?: string;
  mode?: string;
  tenantColumn?: string | null;
  schema?: string;
  requireRls?: boolean;
  requireTransactions?: boolean;
  tables?: Partial<CommerceSqlTableNames>;
  tableNames?: Partial<CommerceSqlTableNames>;
  columns?: Partial<Record<CommerceSqlTableKey, Record<string, string | null>>>;
  columnNames?: Partial<Record<CommerceSqlTableKey, Record<string, string | null>>>;
}

export type CommerceSqlRepositorySecondOptions = Omit<
  CommerceSqlRepositoryOptions,
  "adapter" | "databaseAdapter" | "db" | "executor" | "query"
>;

export type CommerceSqlRepositoryInput =
  | CommerceSqlRuntime
  | CommerceSqlRepositoryOptions
  | CommerceDatabaseAdapter
  | CommerceSqlQuery;

export interface CommerceSqlReadiness {
  ready: boolean;
  mode: TenantConfig["mode"];
  rls: boolean;
  transactions: boolean;
  requiredTables: boolean;
  requiredColumns: boolean;
  missingColumns: readonly string[];
  context: boolean;
}

export interface CommerceMutationResult {
  rows: Record<string, unknown>[];
  affected: number;
}

export class CommerceSqlRuntime {
  readonly tenant: TenantConfig;
  readonly tenantId: string;
  readonly adapter: CommerceDatabaseAdapter;
  readonly tables: Readonly<Record<CommerceSqlTableKey, string>>;
  readonly columns: Readonly<CommerceSqlColumns>;
  private readonly transactionContext = new AsyncLocalStorage<CommerceDatabaseAdapter>();
  private readonly scopedExecutors = new WeakSet<object>();

  constructor(options?: CommerceSqlRepositoryOptions);
  constructor(adapter: CommerceDatabaseAdapter, options?: CommerceSqlRepositorySecondOptions);
  constructor(query: CommerceSqlQuery, options?: CommerceSqlRepositorySecondOptions);
  constructor(input: CommerceSqlRepositoryInput, options?: CommerceSqlRepositorySecondOptions);
  constructor(
    input: CommerceSqlRepositoryInput = {},
    second: CommerceSqlRepositorySecondOptions = {},
  ) {
    if (input instanceof CommerceSqlRuntime) {
      this.tenant = input.tenant;
      this.tenantId = input.tenantId;
      this.adapter = input.adapter;
      this.tables = input.tables;
      this.columns = input.columns;
      return;
    }
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
      ...(options.allowSharedFallback === undefined ? {} : { allowSharedFallback: options.allowSharedFallback }),
    });
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

  table(key: CommerceSqlTableKey): string {
    return quoteIdentifier(this.tables[key]);
  }

  rawTable(key: CommerceSqlTableKey): string {
    return this.tables[key];
  }

  column(key: CommerceSqlTableKey, field: string): string {
    const value = this.columns[key]?.[field];
    if (typeof value !== "string" || value.length === 0) {
      throw new TypeError(`Commerce SQL column ${key}.${field} is not configured`);
    }
    return quoteIdentifier(value);
  }

  select(
    key: CommerceSqlTableKey,
    fields: readonly string[] = COMMERCE_SQL_FIELDS[key],
  ): string {
    const entries = fields
      .map((field) => [field, this.columns[key]?.[field]] as const)
      .filter((entry): entry is readonly [string, string] => typeof entry[1] === "string");
    if (entries.length === 0) throw new TypeError(`No commerce SQL columns configured for ${key}`);
    return entries
      .map(([field, column]) => `${quoteIdentifier(column)} AS ${quoteIdentifier(field)}`)
      .join(", ");
  }

  addTenantPredicate(
    key: CommerceSqlTableKey,
    values: unknown[],
    clauses: string[],
    tenantId = this.tenantId,
  ): void {
    values.push(tenantId);
    clauses.push(`${this.column(key, "tenantId")} = $${values.length}`);
  }

  async withTransaction<T>(
    operation: (executor: CommerceDatabaseAdapter) => Promise<T>,
  ): Promise<T> {
    if (this.tenant.requireTransactions && !this.supportsTransactions()) {
      throw new Error("Commerce SQL persistence requires a transaction-capable adapter");
    }
    const active = this.activeExecutor();
    if (active !== undefined) return this.withTenantContextOn(active, operation);
    if (!this.supportsTransactions()) return operation(this.adapter);
    const transaction = this.adapter.transaction;
    if (typeof transaction !== "function") return operation(this.adapter);
    return transaction.call(this.adapter, async (executor) => {
      const typed = executor as CommerceDatabaseAdapter;
      return runWithTenantTransaction(
        this.adapter,
        typed,
        () => this.transactionContext.run(typed, () => runTenantContext(
          { tenantId: this.tenant.tenantId, mode: this.tenant.mode, executor: typed },
          () => this.withTenantContextOn(typed, operation),
        )),
      );
    }) as Promise<T>;
  }

  async withTenantContext<T>(
    operation: (executor: CommerceDatabaseAdapter) => Promise<T>,
  ): Promise<T> {
    const active = this.activeExecutor();
    if (active !== undefined) return this.withTenantContextOn(active, operation);
    if (!this.tenant.requireRls) return operation(this.adapter);
    if (!this.supportsTransactions()) {
      throw new Error("Commerce tenant context requires a transaction");
    }
    return this.withTransaction(operation);
  }

  async queryRows(
    text: string,
    values: readonly unknown[] = [],
    executor?: CommerceDatabaseAdapter,
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
    executor?: CommerceDatabaseAdapter,
  ): Promise<CommerceMutationResult> {
    const active = this.activeExecutor(executor);
    if (this.tenant.requireRls && (active === undefined || active === this.adapter) && !this.scopedExecutors.has(this.adapter)) {
      return this.withTenantContext((scoped) => this.executeMutation(text, values, scoped));
    }
    const result = await this.query(text, values, active ?? this.adapter);
    const rows = resultRows(result);
    return { rows, affected: affectedCount(result, rows.length) };
  }

  async isReady(keys: readonly CommerceSqlTableKey[] = COMMERCE_ALL_TABLES): Promise<boolean> {
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
          const table = await this.queryRows(
            `SELECT c.relrowsecurity AS "rls", c.relforcerowsecurity AS "forceRls" FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = $1::regclass`,
            [this.rawTable(key)],
          );
          if (!readBoolean(table[0]?.rls) || !readBoolean(table[0]?.forceRls)) return false;
          const policies = await this.queryRows(
            `SELECT p.policyname AS "policyName", p.permissive AS "permissive", p.qual AS "qual", p.with_check AS "withCheck", p.roles AS "roles" FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace JOIN pg_policies p ON p.schemaname = n.nspname AND p.tablename = c.relname WHERE c.oid = $1::regclass`,
            [this.rawTable(key)],
          );
          if (!hasExpectedTenantPolicy(policies, this.tenant.tenantColumn, this.rawTable(key))) return false;
        }
      }
      return true;
    } catch {
      return false;
    }
  }

  async readiness(keys: readonly CommerceSqlTableKey[] = COMMERCE_ALL_TABLES): Promise<CommerceSqlReadiness> {
    const missingColumns = this.missingRequiredColumns(keys);
    const ready = await this.isReady(keys);
    return {
      ready,
      mode: this.tenant.mode,
      rls: !this.tenant.requireRls || ready,
      transactions: !this.tenant.requireTransactions || this.supportsTransactions(),
      requiredTables: ready,
      requiredColumns: missingColumns.length === 0,
      missingColumns: ready ? [] : missingColumns,
      context: !this.tenant.requireRls || this.supportsTransactions(),
    };
  }

  missingRequiredColumns(keys: readonly CommerceSqlTableKey[] = COMMERCE_ALL_TABLES): string[] {
    const missing: string[] = [];
    for (const key of keys) {
      for (const field of COMMERCE_SQL_FIELDS[key]) {
        if (OPTIONAL_FIELDS[key].includes(field)) continue;
        if (typeof this.columns[key]?.[field] !== "string") missing.push(`${key}.${field}`);
      }
    }
    return missing;
  }

  async setTenantContext(executor: CommerceDatabaseAdapter): Promise<void> {
    if (!this.tenant.requireRls) return;
    await executor.query("SELECT set_config('app.tenant_id', $1, true)", [this.tenantId]);
  }

  private activeExecutor(executor?: CommerceDatabaseAdapter): CommerceDatabaseAdapter | undefined {
    return this.transactionContext.getStore() ??
      (getTenantTransactionExecutor(this.adapter) as CommerceDatabaseAdapter | undefined) ??
      executor;
  }

  private async withTenantContextOn<T>(
    executor: CommerceDatabaseAdapter,
    operation: (executor: CommerceDatabaseAdapter) => Promise<T>,
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
    executor: CommerceDatabaseAdapter,
  ): Promise<unknown> {
    try {
      return await executor.query(text, [...values]);
    } catch (error) {
      if (isUniqueViolation(error)) throw commerceResourceConflict();
      throw error;
    }
  }
}

export const OpenCommerceSqlRuntime = CommerceSqlRuntime;
export const OpenPlatformCommerceSqlRuntime = CommerceSqlRuntime;

export function createCommerceSqlRuntime(
  input: CommerceSqlRepositoryInput,
  second: CommerceSqlRepositorySecondOptions = {},
): CommerceSqlRuntime {
  if (input instanceof CommerceSqlRuntime) return input;
  return new CommerceSqlRuntime(input, second);
}

export function createOpenCommerceSqlRuntime(
  input: CommerceSqlRepositoryInput,
  second: CommerceSqlRepositorySecondOptions = {},
): CommerceSqlRuntime {
  return createCommerceSqlRuntime(input, second);
}

export function storageValue(field: string, value: unknown): unknown {
  if (value === undefined) return null;
  if (["priceIds", "entitlementIds", "quotaIds", "dimensions", "eventIds", "mainlandChina", "tiers", "commissionRuleIds"].includes(field)) {
    return JSON.stringify(value);
  }
  if (["quantity", "includedUnits", "limit", "reserved", "consumed", "settledQuantity"].includes(field) && typeof value === "string") {
    return normalizeDecimalString(assertDecimalString(value, field));
  }
  return value;
}

export function rowValue(row: Record<string, unknown>, field: string): unknown {
  const snake = field.replace(/[A-Z]/gu, (letter) => `_${letter.toLowerCase()}`);
  const candidates = [field, snake, snake.toLowerCase(), field.toLowerCase()];
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

export function readRequiredText(value: unknown, field: string): string {
  const text = readText(value);
  if (text === undefined) throw new Error(`Invalid commerce SQL row: ${field}`);
  return text;
}

export function readNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isSafeInteger(value)) return value;
  if (typeof value === "bigint" && value >= 0n && value <= BigInt(Number.MAX_SAFE_INTEGER)) return Number(value);
  if (typeof value === "string" && /^\d+$/u.test(value)) {
    const parsed = Number(value);
    return Number.isSafeInteger(parsed) ? parsed : undefined;
  }
  return undefined;
}

export function readRequiredNumber(value: unknown, field: string): number {
  const number = readNumber(value);
  if (number === undefined) throw new Error(`Invalid commerce SQL row: ${field}`);
  return number;
}

export function readDecimalString(value: unknown, field = "quantity"): DecimalString {
  if (typeof value === "string") return normalizeDecimalString(assertDecimalString(value, field));
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return String(value);
  throw new Error(`Invalid commerce decimal SQL row: ${field}`);
}

export function readRequiredDecimalString(value: unknown, field = "quantity"): DecimalString {
  if (value === null || value === undefined) throw new Error(`Invalid commerce decimal SQL row: ${field}`);
  return readDecimalString(value, field);
}

export function readMoney(value: unknown, currency: string, field = "amount"): Money {
  if (currency !== "CNY") throw new Error(`Invalid commerce money currency SQL row: ${field}`);
  const amountMinor = readRequiredNumber(value, field);
  if (amountMinor < 0) throw new Error(`Invalid commerce money SQL row: ${field}`);
  return { amountMinor, currency: "CNY" };
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

export function readDate(value: unknown): string | undefined {
  if (value instanceof Date && Number.isFinite(value.getTime())) return value.toISOString();
  if (typeof value === "string" && Number.isFinite(Date.parse(value))) return new Date(Date.parse(value)).toISOString();
  return undefined;
}

export function readRequiredDate(value: unknown, field: string): string {
  const date = readDate(value);
  if (date === undefined) throw new Error(`Invalid commerce timestamp SQL row: ${field}`);
  return date;
}

export function readOptionalDate(value: unknown): string | undefined {
  return readDate(value);
}

export function resultRows(value: unknown): Record<string, unknown>[] {
  if (Array.isArray(value)) return value.filter(isRecord);
  if (isRecord(value) && Array.isArray(value.rows)) return value.rows.filter(isRecord);
  if (isRecord(value) && (typeof value.rowCount === "number" || typeof value.rowCount === "bigint")) return [];
  throw new Error("Commerce SQL result failed");
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
    throw new TypeError(`Invalid commerce SQL identifier: ${value}`);
  }
  return segments.map((segment) => `"${segment}"`).join(".");
}

export function validateCommerceSqlIdentifier(value: unknown, field = "identifier"): string {
  if (typeof value !== "string") throw new TypeError(`${field} must be a string`);
  const normalized = value.trim();
  if (normalized !== value) throw new TypeError(`Invalid SQL identifier for ${field}`);
  const segments = normalized.split(".");
  if (segments.length < 1 || segments.length > 2 || segments.some((segment) => !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(segment) || segment.length > 63)) {
    throw new TypeError(`Invalid SQL identifier for ${field}`);
  }
  return normalized;
}

function hasExpectedTenantPolicy(
  rows: Record<string, unknown>[],
  tenantColumn: string,
  table: string,
): boolean {
  const expectedName = commerceObjectName(table, "tenant_policy");
  const expectedPredicate = normalizePolicyExpression(`${tenantColumn} = current_setting('app.tenant_id', true)`);
  let expectedFound = false;
  for (const row of rows) {
    const name = readText(rowValue(row, "policyName"));
    const mode = policyMode(rowValue(row, "permissive"));
    const qual = readText(rowValue(row, "qual"));
    const withCheck = readText(rowValue(row, "withCheck"));
    if (mode === undefined) return false;
    if (name === expectedName) {
      if (expectedFound || mode !== "PERMISSIVE") return false;
      if (normalizePolicyExpression(qual ?? "") !== expectedPredicate) return false;
      if (normalizePolicyExpression(withCheck ?? "") !== expectedPredicate) return false;
      expectedFound = true;
      continue;
    }
    const normalizedQual = normalizePolicyExpression(qual ?? "");
    const normalizedWithCheck = normalizePolicyExpression(withCheck ?? "");
    if (normalizedQual === "true" || normalizedWithCheck === "true") return false;
    if (mode === "PERMISSIVE" && (normalizedQual !== expectedPredicate || normalizedWithCheck !== expectedPredicate)) return false;
  }
  return expectedFound;
}

function policyMode(value: unknown): "PERMISSIVE" | "RESTRICTIVE" | undefined {
  if (value === true || value === "true" || value === "PERMISSIVE" || value === "permissive") return "PERMISSIVE";
  if (value === false || value === "false" || value === "RESTRICTIVE" || value === "restrictive") return "RESTRICTIVE";
  return undefined;
}

function normalizePolicyExpression(value: string): string {
  return value
    .replace(/::[a-z_]+/giu, "")
    .replace(/["`]/gu, "")
    .replace(/[()\s]/gu, "")
    .toLowerCase();
}

function commerceObjectName(table: string, suffix: string): string {
  const base = table.split(".").at(-1) ?? table;
  const available = Math.max(1, 63 - base.length - suffix.length - 1);
  return `${base.slice(0, available)}_${suffix}`;
}

function normalizeRuntimeOptions(
  input: CommerceSqlRepositoryInput,
  second: CommerceSqlRepositorySecondOptions,
): CommerceSqlRepositoryOptions {
  if (typeof input === "function") return { ...second, query: input };
  if (isRecord(input) && typeof input.query === "function" && !hasOptionProperties(input)) {
    return { ...second, adapter: input as unknown as CommerceDatabaseAdapter };
  }
  return { ...(input as CommerceSqlRepositoryOptions), ...second };
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

function selectAdapter(options: CommerceSqlRepositoryOptions, mode: TenantConfig["mode"]): CommerceDatabaseAdapter {
  if (options.adapter !== undefined) return assertAdapter(options.adapter);
  if (options.databaseAdapter !== undefined) return assertAdapter(options.databaseAdapter);
  if (options.db !== undefined) return assertAdapter(options.db);
  if (options.executor !== undefined) return assertAdapter(options.executor);
  if (options.query !== undefined) return { query: options.query };
  if (mode === "shared" && options.sharedExecutor !== undefined) return assertAdapter(options.sharedExecutor);
  if (mode === "dedicated" && options.dedicatedExecutor !== undefined) return assertAdapter(options.dedicatedExecutor);
  throw new TypeError("A commerce SQL adapter is required");
}

function assertAdapter(value: unknown): CommerceDatabaseAdapter {
  if (!isRecord(value) || typeof value.query !== "function") {
    throw new TypeError("A commerce SQL adapter is required");
  }
  return value as unknown as CommerceDatabaseAdapter;
}

function normalizeTables(
  options: CommerceSqlRepositoryOptions,
  schema: string,
): Readonly<Record<CommerceSqlTableKey, string>> {
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
      throw new TypeError(`Commerce persistence cannot use an existing platform table for ${key}`);
    }
    output[key] = qualifyTenantTable(table, schema);
  }
  return Object.freeze(output);
}

function normalizeColumns(
  options: CommerceSqlRepositoryOptions,
  tenantColumn: string,
): Readonly<CommerceSqlColumns> {
  const output = {} as CommerceSqlColumns;
  for (const key of COMMERCE_RUNTIME_TABLES) {
    const source = {
      ...DEFAULT_COLUMNS[key],
      ...(options.columns?.[key] ?? {}),
      ...(options.columnNames?.[key] ?? {}),
    };
    const columnTenantConfigured = options.columns?.[key]?.tenantId !== undefined ||
      options.columnNames?.[key]?.tenantId !== undefined;
    if (options.tenantColumn !== undefined) {
      if (options.tenantColumn === null) delete source.tenantId;
      else source.tenantId = options.tenantColumn;
    } else if (!columnTenantConfigured && source.tenantId !== tenantColumn) {
      source.tenantId = tenantColumn;
    }
    const normalized: Record<string, string> = {};
    for (const [field, value] of Object.entries(source)) {
      if (typeof value !== "string" || value.length === 0) continue;
      normalized[field] = validateCommerceSqlIdentifier(value, `${key}.${field}`);
    }
    output[key] = normalized;
  }
  return Object.freeze(output);
}
