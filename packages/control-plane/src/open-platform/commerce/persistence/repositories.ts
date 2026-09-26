import {
  addDecimalStrings,
  assertDecimalString,
  assertMoney,
  compareDecimalStrings,
  normalizeDecimalString,
  subtractDecimalStrings,
} from "../money.js";
import {
  commerceIdempotencyKeyReused,
  commerceInvalidTotal,
  commerceQuotaExceeded,
  commerceResourceConflict,
  commerceResourceNotFound,
  commerceValidationError,
} from "../errors.js";
import {
  assertCommissionRuleTransition,
  assertEntitlementTransition,
  assertInvoiceDisputeTransition,
  assertInvoiceTransition,
  assertMarketplaceListingTransition,
  assertMeterTransition,
  assertPartnerAccountTransition,
  assertPlanTransition,
  assertPriceTransition,
  assertQuotaReservationTransition,
  assertQuotaTransition,
  assertSubscriptionTransition,
  assertUsageAggregateTransition,
} from "../state-machine.js";
import {
  INVOICE_DISPUTE_EVENTS,
  INVOICE_DISPUTE_OUTCOMES,
  INVOICE_DISPUTE_STATUSES,
  INVOICE_STATUSES,
} from "../types.js";
import type {
  CommissionRule,
  CommerceEntityKind,
  CommerceRecord,
  DecimalString,
  Entitlement,
  Invoice,
  InvoiceDispute,
  InvoiceDisputeAppendResult,
  InvoiceDisputeDecision,
  InvoiceDisputeListQuery,
  InvoiceDisputeOutcome,
  InvoiceDisputeRepository,
  InvoiceDisputeStatus,
  InvoiceIdempotentCreateRequest,
  InvoiceIdempotentCreateResult,
  InvoiceLine,
  InvoiceRepository,
  InvoiceStatus,
  MarketplaceListing,
  Meter,
  Money,
  PartnerAccount,
  Plan,
  Price,
  PriceTier,
  Quota,
  QuotaReleaseRequest,
  QuotaRepository,
  QuotaReserveRequest,
  QuotaReserveResult,
  QuotaReservation,
  QuotaReservationRepository,
  QuotaSettlementRequest,
  QuotaTerminalResult,
  Subscription,
  TenantScopedRepository,
  UsageAggregate,
  UsageAggregateRepository,
  UsageEvent,
  UsageEventAppendResult,
  UsageEventRepository,
} from "../types.js";
import {
  assertCommerceHasNoSensitiveValue,
  assertCommerceId,
  cloneCommerceValue,
  normalizeCommerceLimit,
  normalizeCommerceTenantId,
  normalizeCommerceTimestamp,
  normalizeIdempotencyKey,
  normalizeMainlandChinaInvoiceMetadata,
  normalizePeriod,
  requireCommerceDisputeReason,
  requireCommerceDisputeResolutionNote,
  requireCommerceEvidenceReference,
  requireCommerceCode,
  requireCommerceIdentifier,
  requireCommerceText,
} from "../validation.js";
import {
  CommerceSqlRuntime,
  COMMERCE_SQL_FIELDS,
  createCommerceSqlRuntime,
  isRecord,
  readDate,
  readDecimalString,
  readJson,
  readMoney,
  readNumber,
  readOptionalDate,
  readRequiredDate,
  readRequiredDecimalString,
  readRequiredNumber,
  readRequiredText,
  readStringArray,
  readText,
  rowValue,
  storageValue,
  type CommerceDatabaseAdapter,
  type CommerceSqlRepositoryInput,
  type CommerceSqlRepositoryOptions,
  type CommerceSqlRepositorySecondOptions,
  type CommerceSqlTableKey,
} from "./adapter.js";

const MONEY_CURRENCY = "CNY" as const;
const MONEY_MAX = BigInt(Number.MAX_SAFE_INTEGER);

type SqlRow = Record<string, unknown>;
type SqlValues = Record<string, unknown>;

type StatusValue<T extends string> = T;

const STATUS_VALUES: Readonly<Record<CommerceEntityKind, readonly string[]>> = Object.freeze({
  plan: ["draft", "active", "retired"],
  entitlement: ["pending", "active", "suspended", "revoked", "expired"],
  meter: ["draft", "active", "retired"],
  price: ["draft", "scheduled", "active", "retired"],
  subscription: ["pending", "trialing", "active", "pastDue", "suspended", "canceled", "expired"],
  quota: ["active", "disabled", "retired"],
  quotaReservation: ["reserved", "settled", "released", "expired"],
  usageAggregate: ["collecting", "closed", "priced", "settled"],
  marketplaceListing: ["draft", "pendingReview", "published", "suspended", "removed"],
  partnerAccount: ["pending", "underReview", "active", "frozen", "rejected", "closed"],
  commissionRule: ["draft", "scheduled", "active", "suspended", "retired"],
});

export abstract class SqlCommerceRepository<T extends CommerceRecord> implements TenantScopedRepository<T> {
  protected readonly runtime: CommerceSqlRuntime;
  protected abstract readonly tableKey: CommerceSqlTableKey;
  protected abstract readonly entityKind: CommerceEntityKind;
  protected abstract readonly fields: readonly string[];
  protected abstract toStorage(record: T): SqlValues;
  protected abstract mapRow(row: SqlRow): T;
  protected validateTransition(_current: T, _next: T): void {}
  protected assertGenericSaveAllowed(_current: T, _next: T): void {}

  protected constructor(runtime: CommerceSqlRuntime) {
    this.runtime = runtime;
  }

  async create(record: T): Promise<T> {
    const normalized = this.prepareCreate(record);
    return this.runtime.withTransaction(async (executor) => {
      const result = await this.runtime.executeMutation(
        `INSERT INTO ${this.runtime.table(this.tableKey)} (${this.insertColumns()}) VALUES (${this.insertPlaceholders()}) RETURNING ${this.runtime.select(this.tableKey, this.fields)}`,
        this.storageValues(normalized),
        executor,
      );
      if (result.affected !== 1) throw commerceResourceConflict(`${this.entityKind} already exists`);
      return result.rows[0] === undefined ? normalized : this.mapRow(result.rows[0]);
    });
  }

  async get(tenantId: string, id: string): Promise<T | undefined> {
    const tenant = normalizeCommerceTenantId(tenantId);
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.runtime.addTenantPredicate(this.tableKey, values, clauses, tenant);
    values.push(assertCommerceId(id, this.entityKind, "id"));
    clauses.push(`${this.runtime.column(this.tableKey, "id")} = $${values.length}`);
    const rows = await this.runtime.queryRows(
      `SELECT ${this.runtime.select(this.tableKey, this.fields)} FROM ${this.runtime.table(this.tableKey)} WHERE ${clauses.join(" AND ")} LIMIT 1`,
      values,
    );
    if (rows[0] === undefined) return undefined;
    const record = this.mapRow(rows[0]);
    return record.tenantId === tenant && record.tenantId === this.runtime.tenantId ? record : undefined;
  }

  async list(tenantId: string): Promise<T[]> {
    const tenant = normalizeCommerceTenantId(tenantId);
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.runtime.addTenantPredicate(this.tableKey, values, clauses, tenant);
    const rows = await this.runtime.queryRows(
      `SELECT ${this.runtime.select(this.tableKey, this.fields)} FROM ${this.runtime.table(this.tableKey)} WHERE ${clauses.join(" AND ")} ORDER BY ${this.runtime.column(this.tableKey, "createdAt")} ASC, ${this.runtime.column(this.tableKey, "id")} ASC`,
      values,
    );
    return rows.map((row) => this.mapRow(row)).filter((record) => record.tenantId === tenant && record.tenantId === this.runtime.tenantId);
  }

  async save(record: T): Promise<T> {
    const normalized = this.prepareSave(record);
    return this.runtime.withTransaction(async (executor) => {
      const current = await this.requireCurrent(normalized.tenantId, normalized.id, executor);
      this.assertGenericSaveAllowed(current, normalized);
      this.assertSave(current, normalized);
      const updateFields = this.updateFields();
      const values: unknown[] = [normalized.tenantId, normalized.id, current.version, current.status];
      const clauses: string[] = [
        `${this.runtime.column(this.tableKey, "tenantId")} = $1`,
        `${this.runtime.column(this.tableKey, "id")} = $2`,
        `${this.runtime.column(this.tableKey, "version")} = $3`,
        `${this.runtime.column(this.tableKey, "status")} = $4`,
      ];
      const storage = this.toStorage(normalized);
      const assignments: string[] = [];
      for (const field of updateFields) {
        values.push(storageValue(field, storage[field]));
        assignments.push(`${this.runtime.column(this.tableKey, field)} = $${values.length}`);
      }
      const result = await this.runtime.executeMutation(
        `UPDATE ${this.runtime.table(this.tableKey)} SET ${assignments.join(", ")} WHERE ${clauses.join(" AND ")} RETURNING ${this.runtime.select(this.tableKey, this.fields)}`,
        values,
        executor,
      );
      if (result.affected !== 1) throw commerceResourceConflict(`${this.entityKind} version is stale`);
      return result.rows[0] === undefined ? normalized : this.mapRow(result.rows[0]);
    });
  }

  async isReady(): Promise<boolean> {
    return this.runtime.isReady([this.tableKey]);
  }

  async readiness() {
    return this.runtime.readiness([this.tableKey]);
  }

  async withTransaction<T>(operation: (executor: CommerceDatabaseAdapter) => Promise<T>): Promise<T> {
    return this.runtime.withTransaction(operation);
  }

  protected prepareCreate(record: T): T {
    this.assertIdentity(record);
    if (record.version !== 1) throw commerceValidationError("Commerce record version is invalid", "version");
    if (!STATUS_VALUES[this.entityKind].includes(record.status)) throw commerceValidationError("Commerce record status is invalid", "status");
    return cloneCommerceValue(record);
  }

  protected prepareSave(record: T): T {
    this.assertIdentity(record);
    if (!Number.isSafeInteger(record.version) || record.version < 2) throw commerceValidationError("Commerce record version is invalid", "version");
    return cloneCommerceValue(record);
  }

  protected assertIdentity(record: T): void {
    if (record === null || typeof record !== "object") throw commerceValidationError("Commerce record is invalid");
    assertCommerceId(record.id, this.entityKind, "id");
    const tenantId = normalizeCommerceTenantId(record.tenantId);
    if (tenantId !== record.tenantId || tenantId !== this.runtime.tenantId) throw commerceValidationError("Commerce record tenant scope is invalid", "tenantId");
    if (record.kind !== this.entityKind) throw commerceValidationError("Commerce record kind is invalid", "kind");
    if (normalizeCommerceTimestamp(record.createdAt, "createdAt") !== record.createdAt || normalizeCommerceTimestamp(record.updatedAt, "updatedAt") !== record.updatedAt) throw commerceValidationError("Commerce record timestamps are invalid");
    if (Date.parse(record.updatedAt) < Date.parse(record.createdAt)) throw commerceValidationError("Commerce record timestamps are invalid", "updatedAt");
    if (!Number.isSafeInteger(record.version) || record.version < 1) throw commerceValidationError("Commerce record version is invalid", "version");
  }

  protected async requireCurrent(
    tenantId: string,
    id: string,
    executor?: CommerceDatabaseAdapter,
  ): Promise<T> {
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.runtime.addTenantPredicate(this.tableKey, values, clauses, tenantId);
    values.push(id);
    clauses.push(`${this.runtime.column(this.tableKey, "id")} = $${values.length}`);
    const rows = await this.runtime.queryRows(
      `SELECT ${this.runtime.select(this.tableKey, this.fields)} FROM ${this.runtime.table(this.tableKey)} WHERE ${clauses.join(" AND ")} LIMIT 1 FOR UPDATE`,
      values,
      executor,
    );
    if (rows[0] === undefined) throw commerceResourceNotFound(this.entityKind);
    const current = this.mapRow(rows[0]);
    if (current.tenantId !== this.runtime.tenantId) throw commerceResourceNotFound(this.entityKind);
    return current;
  }

  protected async findById(
    tenantId: string,
    id: string,
    executor?: CommerceDatabaseAdapter,
  ): Promise<T | undefined> {
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.runtime.addTenantPredicate(this.tableKey, values, clauses, normalizeCommerceTenantId(tenantId));
    values.push(assertCommerceId(id, this.entityKind, "id"));
    clauses.push(`${this.runtime.column(this.tableKey, "id")} = $${values.length}`);
    const rows = await this.runtime.queryRows(
      `SELECT ${this.runtime.select(this.tableKey, this.fields)} FROM ${this.runtime.table(this.tableKey)} WHERE ${clauses.join(" AND ")} LIMIT 1 FOR UPDATE`,
      values,
      executor,
    );
    return rows[0] === undefined ? undefined : this.mapRow(rows[0]);
  }

  protected updateFields(): readonly string[] {
    return this.fields.filter((field) => !["id", "tenantId", "kind", "createdAt"].includes(field));
  }

  protected storageValues(record: T): unknown[] {
    const values = this.toStorage(record);
    return this.fields.map((field) => storageValue(field, values[field]));
  }

  protected insertColumns(): string {
    return this.fields.map((field) => this.runtime.column(this.tableKey, field)).join(", ");
  }

  protected insertPlaceholders(): string {
    return this.fields.map((_field, index) => `$${index + 1}`).join(", ");
  }

  protected assertSave(current: T, next: T): void {
    if (current.kind !== next.kind || current.tenantId !== next.tenantId || current.id !== next.id || current.createdAt !== next.createdAt) throw commerceResourceConflict("Commerce record identity is immutable");
    if (next.version !== current.version + 1) throw commerceResourceConflict("Commerce record version is stale");
    if (!STATUS_VALUES[this.entityKind].includes(next.status)) throw commerceValidationError("Commerce record status is invalid", "status");
    this.validateTransition(current, next);
    if (stableSerialize(immutableProjection(current)) !== stableSerialize(immutableProjection(next))) throw commerceResourceConflict("Commerce financial or identity fields are immutable");
  }
}

export const SqlTenantScopedCommerceRepository = SqlCommerceRepository;

export class SqlPlanRepository
  extends SqlCommerceRepository<Plan>
  implements TenantScopedRepository<Plan> {
  protected readonly tableKey: CommerceSqlTableKey = "plans";
  protected readonly entityKind: CommerceEntityKind = "plan";
  protected readonly fields = COMMERCE_SQL_FIELDS.plans;

  constructor(
    input: CommerceSqlRepositoryInput,
    options?: CommerceSqlRepositorySecondOptions,
  ) {
    super(createCommerceSqlRuntime(input, options));
  }

  protected override validateTransition(current: Plan, next: Plan): void {
    if (current.status !== next.status) assertPlanTransition(current.status, next.status);
  }

  protected toStorage(record: Plan): SqlValues {
    const normalized = normalizePlan(record, this.runtime.tenantId);
    return {
      id: normalized.id,
      tenantId: normalized.tenantId,
      kind: "plan",
      code: normalized.code,
      name: normalized.name,
      description: normalized.description,
      status: normalized.status,
      priority: normalized.priority,
      currency: normalized.currency,
      priceIds: normalized.priceIds,
      entitlementIds: normalized.entitlementIds,
      quotaIds: normalized.quotaIds,
      effectiveFrom: normalized.effectiveFrom,
      effectiveTo: normalized.effectiveTo,
      version: normalized.version,
      createdAt: normalized.createdAt,
      updatedAt: normalized.updatedAt,
    };
  }

  protected override mapRow(row: SqlRow): Plan {
    return {
      id: readRequiredText(rowValue(row, "id"), "plan.id"),
      tenantId: readRequiredText(rowValue(row, "tenantId"), "plan.tenantId"),
      kind: "plan",
      code: readRequiredText(rowValue(row, "code"), "plan.code"),
      name: readRequiredText(rowValue(row, "name"), "plan.name"),
      ...optionalText("description", rowValue(row, "description")),
      status: statusValue<Plan["status"]>(rowValue(row, "status"), ["draft", "active", "retired"], "plan.status"),
      priority: readRequiredNumber(rowValue(row, "priority"), "plan.priority"),
      currency: readRequiredText(rowValue(row, "currency"), "plan.currency") as Plan["currency"],
      priceIds: readStringArray(rowValue(row, "priceIds")),
      entitlementIds: readStringArray(rowValue(row, "entitlementIds")),
      quotaIds: readStringArray(rowValue(row, "quotaIds")),
      effectiveFrom: readRequiredDate(rowValue(row, "effectiveFrom"), "plan.effectiveFrom"),
      ...optionalDate("effectiveTo", rowValue(row, "effectiveTo")),
      version: readRequiredNumber(rowValue(row, "version"), "plan.version"),
      createdAt: readRequiredDate(rowValue(row, "createdAt"), "plan.createdAt"),
      updatedAt: readRequiredDate(rowValue(row, "updatedAt"), "plan.updatedAt"),
    };
  }
}

export class SqlEntitlementRepository
  extends SqlCommerceRepository<Entitlement>
  implements TenantScopedRepository<Entitlement> {
  protected readonly tableKey: CommerceSqlTableKey = "entitlements";
  protected readonly entityKind: CommerceEntityKind = "entitlement";
  protected readonly fields = COMMERCE_SQL_FIELDS.entitlements;

  constructor(
    input: CommerceSqlRepositoryInput,
    options?: CommerceSqlRepositorySecondOptions,
  ) {
    super(createCommerceSqlRuntime(input, options));
  }

  protected override validateTransition(current: Entitlement, next: Entitlement): void {
    if (current.status !== next.status) assertEntitlementTransition(current.status, next.status);
  }

  protected toStorage(record: Entitlement): SqlValues {
    const normalized = normalizeEntitlement(record, this.runtime.tenantId);
    const value = normalized.value;
    return {
      id: normalized.id,
      tenantId: normalized.tenantId,
      kind: "entitlement",
      feature: normalized.feature,
      effect: normalized.effect,
      valueType: value === undefined ? null : typeof value === "number" ? "integer" : typeof value,
      valueBoolean: typeof value === "boolean" ? value : null,
      valueInteger: typeof value === "number" ? value : null,
      valueText: typeof value === "string" ? value : null,
      source: normalized.source,
      sourceId: normalized.sourceId,
      priority: normalized.priority,
      status: normalized.status,
      effectiveFrom: normalized.effectiveFrom,
      effectiveTo: normalized.effectiveTo,
      version: normalized.version,
      createdAt: normalized.createdAt,
      updatedAt: normalized.updatedAt,
    };
  }

  protected override mapRow(row: SqlRow): Entitlement {
    const valueType = rowValue(row, "valueType");
    let value: boolean | number | string | undefined;
    if (valueType === "boolean") value = rowValue(row, "valueBoolean") === true || rowValue(row, "valueBoolean") === "true";
    if (valueType === "integer" || valueType === "number") value = readRequiredNumber(rowValue(row, "valueInteger") ?? rowValue(row, "value"), "entitlement.valueInteger");
    if (valueType === "string") value = readRequiredText(rowValue(row, "valueText"), "entitlement.valueText");
    if (value === undefined) {
      const rawValue = rowValue(row, "value");
      if (typeof rawValue === "boolean" || typeof rawValue === "string") value = rawValue;
      if (typeof rawValue === "number") value = readRequiredNumber(rawValue, "entitlement.value");
    }
    return {
      id: readRequiredText(rowValue(row, "id"), "entitlement.id"),
      tenantId: readRequiredText(rowValue(row, "tenantId"), "entitlement.tenantId"),
      kind: "entitlement",
      feature: readRequiredText(rowValue(row, "feature"), "entitlement.feature"),
      effect: statusValue<Entitlement["effect"]>(rowValue(row, "effect"), ["allow", "deny"], "entitlement.effect"),
      ...(value === undefined ? {} : { value }),
      source: statusValue<Entitlement["source"]>(rowValue(row, "source"), ["tenant", "plan", "subscription"], "entitlement.source"),
      sourceId: readRequiredText(rowValue(row, "sourceId"), "entitlement.sourceId"),
      priority: readRequiredNumber(rowValue(row, "priority"), "entitlement.priority"),
      status: statusValue<Entitlement["status"]>(rowValue(row, "status"), ["pending", "active", "suspended", "revoked", "expired"], "entitlement.status"),
      effectiveFrom: readRequiredDate(rowValue(row, "effectiveFrom"), "entitlement.effectiveFrom"),
      ...optionalDate("effectiveTo", rowValue(row, "effectiveTo")),
      version: readRequiredNumber(rowValue(row, "version"), "entitlement.version"),
      createdAt: readRequiredDate(rowValue(row, "createdAt"), "entitlement.createdAt"),
      updatedAt: readRequiredDate(rowValue(row, "updatedAt"), "entitlement.updatedAt"),
    };
  }
}

export class SqlMeterRepository
  extends SqlCommerceRepository<Meter>
  implements TenantScopedRepository<Meter> {
  protected readonly tableKey: CommerceSqlTableKey = "meters";
  protected readonly entityKind: CommerceEntityKind = "meter";
  protected readonly fields = COMMERCE_SQL_FIELDS.meters;

  constructor(
    input: CommerceSqlRepositoryInput,
    options?: CommerceSqlRepositorySecondOptions,
  ) {
    super(createCommerceSqlRuntime(input, options));
  }

  protected override validateTransition(current: Meter, next: Meter): void {
    if (current.status !== next.status) assertMeterTransition(current.status, next.status);
  }

  protected toStorage(record: Meter): SqlValues {
    const normalized = normalizeMeter(record, this.runtime.tenantId);
    return {
      id: normalized.id,
      tenantId: normalized.tenantId,
      kind: "meter",
      key: normalized.key,
      name: normalized.name,
      unit: normalized.unit,
      aggregation: normalized.aggregation,
      dimensions: normalized.dimensions,
      status: normalized.status,
      version: normalized.version,
      createdAt: normalized.createdAt,
      updatedAt: normalized.updatedAt,
    };
  }

  protected override mapRow(row: SqlRow): Meter {
    return {
      id: readRequiredText(rowValue(row, "id"), "meter.id"),
      tenantId: readRequiredText(rowValue(row, "tenantId"), "meter.tenantId"),
      kind: "meter",
      key: readRequiredText(rowValue(row, "key"), "meter.key"),
      name: readRequiredText(rowValue(row, "name"), "meter.name"),
      unit: readRequiredText(rowValue(row, "unit"), "meter.unit"),
      aggregation: statusValue<Meter["aggregation"]>(rowValue(row, "aggregation"), ["sum", "max", "last"], "meter.aggregation"),
      dimensions: readStringArray(rowValue(row, "dimensions")),
      status: statusValue<Meter["status"]>(rowValue(row, "status"), ["draft", "active", "retired"], "meter.status"),
      version: readRequiredNumber(rowValue(row, "version"), "meter.version"),
      createdAt: readRequiredDate(rowValue(row, "createdAt"), "meter.createdAt"),
      updatedAt: readRequiredDate(rowValue(row, "updatedAt"), "meter.updatedAt"),
    };
  }
}

export class SqlPriceRepository
  extends SqlCommerceRepository<Price>
  implements TenantScopedRepository<Price> {
  protected readonly tableKey: CommerceSqlTableKey = "prices";
  protected readonly entityKind: CommerceEntityKind = "price";
  protected readonly fields = COMMERCE_SQL_FIELDS.prices;

  constructor(
    input: CommerceSqlRepositoryInput,
    options?: CommerceSqlRepositorySecondOptions,
  ) {
    super(createCommerceSqlRuntime(input, options));
  }

  protected override validateTransition(current: Price, next: Price): void {
    if (current.status !== next.status) assertPriceTransition(current.status, next.status);
  }

  protected toStorage(record: Price): SqlValues {
    const normalized = normalizePrice(record, this.runtime.tenantId);
    const base: SqlValues = {
      id: normalized.id,
      tenantId: normalized.tenantId,
      kind: "price",
      code: normalized.code,
      name: normalized.name,
      status: normalized.status,
      currency: normalized.currency,
      roundingMode: normalized.roundingMode,
      priceType: normalized.priceType,
      effectiveFrom: normalized.effectiveFrom,
      effectiveTo: normalized.effectiveTo,
      version: normalized.version,
      createdAt: normalized.createdAt,
      updatedAt: normalized.updatedAt,
      fixedAmountMinor: undefined,
      meterId: undefined,
      unitAmountMinor: undefined,
      includedUnits: undefined,
      minimumChargeMinor: undefined,
      tiers: undefined,
    };
    if (normalized.priceType === "fixed") {
      base.fixedAmountMinor = normalized.fixedAmount.amountMinor;
    } else {
      base.meterId = normalized.meterId;
      base.tiers = normalized.priceType === "tiered" ? normalized.tiers : undefined;
    }
    if (normalized.priceType === "perUnit" || normalized.priceType === "mixed") {
      base.unitAmountMinor = normalized.unitAmount.amountMinor;
      base.includedUnits = normalized.includedUnits;
      base.minimumChargeMinor = normalized.minimumCharge.amountMinor;
    }
    if (normalized.priceType === "mixed") base.fixedAmountMinor = normalized.fixedAmount.amountMinor;
    return base;
  }

  protected override mapRow(row: SqlRow): Price {
    const base = {
      id: readRequiredText(rowValue(row, "id"), "price.id"),
      tenantId: readRequiredText(rowValue(row, "tenantId"), "price.tenantId"),
      kind: "price" as const,
      code: readRequiredText(rowValue(row, "code"), "price.code"),
      name: readRequiredText(rowValue(row, "name"), "price.name"),
      status: statusValue<Price["status"]>(rowValue(row, "status"), ["draft", "scheduled", "active", "retired"], "price.status"),
      currency: readRequiredText(rowValue(row, "currency"), "price.currency") as Price["currency"],
      roundingMode: statusValue<Price["roundingMode"]>(rowValue(row, "roundingMode"), ["halfEven", "halfUp"], "price.roundingMode"),
      effectiveFrom: readRequiredDate(rowValue(row, "effectiveFrom"), "price.effectiveFrom"),
      ...(optionalDate("effectiveTo", rowValue(row, "effectiveTo"))),
      version: readRequiredNumber(rowValue(row, "version"), "price.version"),
      createdAt: readRequiredDate(rowValue(row, "createdAt"), "price.createdAt"),
      updatedAt: readRequiredDate(rowValue(row, "updatedAt"), "price.updatedAt"),
    };
    const priceType = statusValue<Price["priceType"]>(rowValue(row, "priceType"), ["fixed", "perUnit", "tiered", "mixed"], "price.priceType");
    if (priceType === "fixed") {
      return {
        ...base,
        priceType,
        fixedAmount: readMoney(rowValue(row, "fixedAmountMinor"), base.currency, "price.fixedAmountMinor"),
      };
    }
    const meterId = readRequiredText(rowValue(row, "meterId"), "price.meterId");
    if (priceType === "tiered") {
      return {
        ...base,
        priceType,
        meterId,
        tiers: readTiers(rowValue(row, "tiers"), base.currency),
      };
    }
    if (priceType === "perUnit") {
      return {
        ...base,
        priceType,
        meterId,
        unitAmount: readMoney(rowValue(row, "unitAmountMinor"), base.currency, "price.unitAmountMinor"),
        includedUnits: readRequiredDecimalString(rowValue(row, "includedUnits"), "price.includedUnits"),
        minimumCharge: readMoney(rowValue(row, "minimumChargeMinor"), base.currency, "price.minimumChargeMinor"),
      };
    }
    return {
      ...base,
      priceType,
      meterId,
      fixedAmount: readMoney(rowValue(row, "fixedAmountMinor"), base.currency, "price.fixedAmountMinor"),
      unitAmount: readMoney(rowValue(row, "unitAmountMinor"), base.currency, "price.unitAmountMinor"),
      includedUnits: readRequiredDecimalString(rowValue(row, "includedUnits"), "price.includedUnits"),
      minimumCharge: readMoney(rowValue(row, "minimumChargeMinor"), base.currency, "price.minimumChargeMinor"),
    };
  }
}

export class SqlSubscriptionRepository
  extends SqlCommerceRepository<Subscription>
  implements TenantScopedRepository<Subscription> {
  protected readonly tableKey: CommerceSqlTableKey = "subscriptions";
  protected readonly entityKind: CommerceEntityKind = "subscription";
  protected readonly fields = COMMERCE_SQL_FIELDS.subscriptions;

  constructor(
    input: CommerceSqlRepositoryInput,
    options?: CommerceSqlRepositorySecondOptions,
  ) {
    super(createCommerceSqlRuntime(input, options));
  }

  protected override validateTransition(current: Subscription, next: Subscription): void {
    if (current.status !== next.status) assertSubscriptionTransition(current.status, next.status);
  }

  protected toStorage(record: Subscription): SqlValues {
    const normalized = normalizeSubscription(record, this.runtime.tenantId);
    return {
      id: normalized.id,
      tenantId: normalized.tenantId,
      kind: "subscription",
      applicationId: normalized.applicationId,
      planId: normalized.planId,
      name: normalized.name,
      status: normalized.status,
      quantity: normalized.quantity,
      currentPeriodStart: normalized.currentPeriodStart,
      currentPeriodEnd: normalized.currentPeriodEnd,
      cancelAtPeriodEnd: normalized.cancelAtPeriodEnd,
      canceledAt: normalized.canceledAt,
      version: normalized.version,
      createdAt: normalized.createdAt,
      updatedAt: normalized.updatedAt,
    };
  }

  protected override mapRow(row: SqlRow): Subscription {
    return {
      id: readRequiredText(rowValue(row, "id"), "subscription.id"),
      tenantId: readRequiredText(rowValue(row, "tenantId"), "subscription.tenantId"),
      kind: "subscription",
      applicationId: readRequiredText(rowValue(row, "applicationId"), "subscription.applicationId"),
      planId: readRequiredText(rowValue(row, "planId"), "subscription.planId"),
      name: readRequiredText(rowValue(row, "name"), "subscription.name"),
      status: statusValue<Subscription["status"]>(rowValue(row, "status"), ["pending", "trialing", "active", "pastDue", "suspended", "canceled", "expired"], "subscription.status"),
      quantity: readRequiredDecimalString(rowValue(row, "quantity"), "subscription.quantity"),
      currentPeriodStart: readRequiredDate(rowValue(row, "currentPeriodStart"), "subscription.currentPeriodStart"),
      currentPeriodEnd: readRequiredDate(rowValue(row, "currentPeriodEnd"), "subscription.currentPeriodEnd"),
      cancelAtPeriodEnd: readBooleanValue(rowValue(row, "cancelAtPeriodEnd"), "subscription.cancelAtPeriodEnd"),
      ...optionalDate("canceledAt", rowValue(row, "canceledAt")),
      version: readRequiredNumber(rowValue(row, "version"), "subscription.version"),
      createdAt: readRequiredDate(rowValue(row, "createdAt"), "subscription.createdAt"),
      updatedAt: readRequiredDate(rowValue(row, "updatedAt"), "subscription.updatedAt"),
    };
  }
}

export class SqlQuotaReservationRepository
  extends SqlCommerceRepository<QuotaReservation>
  implements QuotaReservationRepository {
  protected readonly tableKey: CommerceSqlTableKey = "quotaReservations";
  protected readonly entityKind: CommerceEntityKind = "quotaReservation";
  protected readonly fields = COMMERCE_SQL_FIELDS.quotaReservations;

  constructor(
    input: CommerceSqlRepositoryInput,
    options?: CommerceSqlRepositorySecondOptions,
  ) {
    super(createCommerceSqlRuntime(input, options));
  }

  protected override validateTransition(current: QuotaReservation, next: QuotaReservation): void {
    if (current.status !== next.status) assertQuotaReservationTransition(current.status, next.status);
  }

  protected override updateFields(): readonly string[] {
    return ["status", "version", "updatedAt"];
  }

  protected override assertGenericSaveAllowed(current: QuotaReservation, next: QuotaReservation): void {
    if (
      current.status !== next.status ||
      current.settledQuantity !== next.settledQuantity ||
      current.settledAt !== next.settledAt ||
      current.releasedAt !== next.releasedAt ||
      current.terminalOperation !== next.terminalOperation ||
      current.terminalIdempotencyKey !== next.terminalIdempotencyKey ||
      current.terminalRequestHash !== next.terminalRequestHash
    ) {
      throw commerceResourceConflict("Quota reservation terminal state requires terminalTransitionAtomic");
    }
  }

  async terminalTransitionAtomic(record: QuotaReservation): Promise<QuotaReservation> {
    const normalized = normalizeReservation(record, this.runtime.tenantId);
    if (normalized.status !== "settled" && normalized.status !== "released") {
      throw commerceValidationError("Quota reservation terminal status is invalid", "status");
    }
    if (normalized.terminalOperation === undefined || normalized.terminalIdempotencyKey === undefined || normalized.terminalRequestHash === undefined) {
      throw commerceValidationError("Quota reservation terminal metadata is required", "terminalOperation");
    }
    if (normalized.status === "settled" && normalized.terminalOperation !== "quota.settle") {
      throw commerceValidationError("Quota reservation terminal operation is invalid", "terminalOperation");
    }
    if (normalized.status === "released" && normalized.terminalOperation !== "quota.release") {
      throw commerceValidationError("Quota reservation terminal operation is invalid", "terminalOperation");
    }
    return this.runtime.withTransaction(async (executor) => {
      const current = await this.requireCurrent(normalized.tenantId, normalized.id, executor);
      this.assertSave(current, normalized);
      const storage = this.toStorage(normalized);
      const values: unknown[] = [
        normalized.tenantId,
        normalized.id,
        current.version,
        current.status,
        storageValue("status", storage.status),
        normalized.version,
        storageValue("settledQuantity", storage.settledQuantity),
        storageValue("settledAt", storage.settledAt),
        storageValue("releasedAt", storage.releasedAt),
        storageValue("terminalOperation", storage.terminalOperation),
        storageValue("terminalIdempotencyKey", storage.terminalIdempotencyKey),
        storageValue("terminalRequestHash", storage.terminalRequestHash),
        storageValue("updatedAt", storage.updatedAt),
      ];
      const result = await this.runtime.executeMutation(
        `UPDATE ${this.runtime.table(this.tableKey)} SET ${this.runtime.column(this.tableKey, "status")} = $5, ${this.runtime.column(this.tableKey, "version")} = $6, ${this.runtime.column(this.tableKey, "settledQuantity")} = $7::numeric, ${this.runtime.column(this.tableKey, "settledAt")} = $8, ${this.runtime.column(this.tableKey, "releasedAt")} = $9, ${this.runtime.column(this.tableKey, "terminalOperation")} = $10, ${this.runtime.column(this.tableKey, "terminalIdempotencyKey")} = $11, ${this.runtime.column(this.tableKey, "terminalRequestHash")} = $12, ${this.runtime.column(this.tableKey, "updatedAt")} = $13 WHERE ${this.runtime.column(this.tableKey, "tenantId")} = $1 AND ${this.runtime.column(this.tableKey, "id")} = $2 AND ${this.runtime.column(this.tableKey, "version")} = $3 AND ${this.runtime.column(this.tableKey, "status")} = $4 RETURNING ${this.runtime.select(this.tableKey, this.fields)}`,
        values,
        executor,
      );
      if (result.affected !== 1) throw commerceResourceConflict("Quota reservation version is stale");
      return result.rows[0] === undefined ? normalized : this.mapRow(result.rows[0]);
    });
  }

  async settleAtomic(record: QuotaReservation): Promise<QuotaReservation> {
    return this.terminalTransitionAtomic(record);
  }

  async releaseAtomic(record: QuotaReservation): Promise<QuotaReservation> {
    return this.terminalTransitionAtomic(record);
  }

  async transitionTerminalAtomic(record: QuotaReservation): Promise<QuotaReservation> {
    return this.terminalTransitionAtomic(record);
  }

  async insertIfAbsent(
    record: QuotaReservation,
    executor?: CommerceDatabaseAdapter,
  ): Promise<{ readonly reservation?: QuotaReservation; readonly inserted: boolean }> {
    const normalized = this.prepareCreate(record);
    const values = this.storageValues(normalized);
    const result = await this.runtime.executeMutation(
      `INSERT INTO ${this.runtime.table(this.tableKey)} (${this.insertColumns()}) VALUES (${this.insertPlaceholders()}) ON CONFLICT DO NOTHING RETURNING ${this.runtime.select(this.tableKey, this.fields)}`,
      values,
      executor,
    );
    if (result.affected === 1) {
      return {
        reservation: result.rows[0] === undefined ? normalized : this.mapRow(result.rows[0]),
        inserted: true,
      };
    }
    return { inserted: false };
  }

  async findReserveByIdempotency(
    tenantId: string,
    quotaId: string,
    subscriptionId: string,
    idempotencyKey: string,
    executor?: CommerceDatabaseAdapter,
  ): Promise<QuotaReservation | undefined> {
    const tenant = normalizeCommerceTenantId(tenantId);
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.runtime.addTenantPredicate(this.tableKey, values, clauses, tenant);
    values.push(
      assertCommerceId(quotaId, "quota", "quotaId"),
      assertCommerceId(subscriptionId, "subscription", "subscriptionId"),
      normalizeIdempotencyKey(idempotencyKey),
    );
    clauses.push(`${this.runtime.column(this.tableKey, "quotaId")} = $${values.length - 2}`);
    clauses.push(`${this.runtime.column(this.tableKey, "subscriptionId")} = $${values.length - 1}`);
    clauses.push(`${this.runtime.column(this.tableKey, "idempotencyKey")} = $${values.length}`);
    const rows = await this.runtime.queryRows(
      `SELECT ${this.runtime.select(this.tableKey, this.fields)} FROM ${this.runtime.table(this.tableKey)} WHERE ${clauses.join(" AND ")} FOR UPDATE`,
      values,
      executor,
    );
    if (rows[0] === undefined) return undefined;
    const reservation = this.mapRow(rows[0]);
    return reservation.tenantId === tenant && reservation.tenantId === this.runtime.tenantId ? reservation : undefined;
  }

  async getInTransaction(
    tenantId: string,
    id: string,
    executor: CommerceDatabaseAdapter,
  ): Promise<QuotaReservation | undefined> {
    return this.findById(tenantId, id, executor);
  }

  protected toStorage(record: QuotaReservation): SqlValues {
    const normalized = normalizeReservation(record, this.runtime.tenantId);
    return {
      id: normalized.id,
      tenantId: normalized.tenantId,
      kind: "quotaReservation",
      quotaId: normalized.quotaId,
      planId: normalized.planId,
      subscriptionId: normalized.subscriptionId,
      meterId: normalized.meterId,
      quantity: normalized.quantity,
      status: normalized.status,
      operation: normalized.operation,
      idempotencyKey: normalized.idempotencyKey,
      requestHash: normalized.requestHash,
      expiresAt: normalized.expiresAt,
      settledQuantity: normalized.settledQuantity,
      settledAt: normalized.settledAt,
      releasedAt: normalized.releasedAt,
      terminalOperation: normalized.terminalOperation,
      terminalIdempotencyKey: normalized.terminalIdempotencyKey,
      terminalRequestHash: normalized.terminalRequestHash,
      version: normalized.version,
      createdAt: normalized.createdAt,
      updatedAt: normalized.updatedAt,
    };
  }

  protected override mapRow(row: SqlRow): QuotaReservation {
    const settledQuantity = rowValue(row, "settledQuantity");
    return {
      id: readRequiredText(rowValue(row, "id"), "quotaReservation.id"),
      tenantId: readRequiredText(rowValue(row, "tenantId"), "quotaReservation.tenantId"),
      kind: "quotaReservation",
      quotaId: readRequiredText(rowValue(row, "quotaId"), "quotaReservation.quotaId"),
      planId: readRequiredText(rowValue(row, "planId"), "quotaReservation.planId"),
      subscriptionId: readRequiredText(rowValue(row, "subscriptionId"), "quotaReservation.subscriptionId"),
      meterId: readRequiredText(rowValue(row, "meterId"), "quotaReservation.meterId"),
      quantity: readRequiredDecimalString(rowValue(row, "quantity"), "quotaReservation.quantity"),
      status: statusValue<QuotaReservation["status"]>(rowValue(row, "status"), ["reserved", "settled", "released", "expired"], "quotaReservation.status"),
      operation: "quota.reserve",
      idempotencyKey: readRequiredText(rowValue(row, "idempotencyKey"), "quotaReservation.idempotencyKey"),
      requestHash: readRequiredText(rowValue(row, "requestHash"), "quotaReservation.requestHash"),
      expiresAt: readRequiredDate(rowValue(row, "expiresAt"), "quotaReservation.expiresAt"),
      ...(settledQuantity === null || settledQuantity === undefined ? {} : { settledQuantity: readRequiredDecimalString(settledQuantity, "quotaReservation.settledQuantity") }),
      ...optionalDate("settledAt", rowValue(row, "settledAt")),
      ...optionalDate("releasedAt", rowValue(row, "releasedAt")),
      ...(rowValue(row, "terminalOperation") === null || rowValue(row, "terminalOperation") === undefined ? {} : { terminalOperation: statusValue<"quota.settle" | "quota.release">(rowValue(row, "terminalOperation"), ["quota.settle", "quota.release"], "quotaReservation.terminalOperation") }),
      ...optionalText("terminalIdempotencyKey", rowValue(row, "terminalIdempotencyKey")),
      ...optionalText("terminalRequestHash", rowValue(row, "terminalRequestHash")),
      version: readRequiredNumber(rowValue(row, "version"), "quotaReservation.version"),
      createdAt: readRequiredDate(rowValue(row, "createdAt"), "quotaReservation.createdAt"),
      updatedAt: readRequiredDate(rowValue(row, "updatedAt"), "quotaReservation.updatedAt"),
    };
  }
}

export class SqlQuotaRepository
  extends SqlCommerceRepository<Quota>
  implements QuotaRepository {
  protected readonly tableKey: CommerceSqlTableKey = "quotas";
  protected readonly entityKind: CommerceEntityKind = "quota";
  protected readonly fields = COMMERCE_SQL_FIELDS.quotas;
  private readonly reservationRepository: SqlQuotaReservationRepository;

  constructor(
    input: CommerceSqlRepositoryInput,
    options?: CommerceSqlRepositorySecondOptions,
  ) {
    super(createCommerceSqlRuntime(input, options));
    this.reservationRepository = new SqlQuotaReservationRepository(this.runtime);
  }

  protected override validateTransition(current: Quota, next: Quota): void {
    if (current.status !== next.status) assertQuotaTransition(current.status, next.status);
  }

  protected override updateFields(): readonly string[] {
    return ["status", "version", "updatedAt"];
  }

  protected override assertGenericSaveAllowed(current: Quota, next: Quota): void {
    if (compareDecimalStrings(current.reserved, next.reserved) !== 0 || compareDecimalStrings(current.consumed, next.consumed) !== 0) {
      throw commerceResourceConflict("Quota counters require an atomic reserve, settle, or release operation");
    }
  }

  async reserveAtomic(request: QuotaReserveRequest): Promise<QuotaReserveResult> {
    const tenantId = normalizeCommerceTenantId(request.tenantId);
    const quotaId = assertCommerceId(request.quotaId, "quota", "quotaId");
    if (request.operation !== "quota.reserve") throw commerceValidationError("Quota operation is invalid", "operation");
    const reservation = normalizeReservation(request.reservation, this.runtime.tenantId);
    if (reservation.tenantId !== tenantId || reservation.quotaId !== quotaId || reservation.status !== "reserved" || reservation.operation !== "quota.reserve" || reservation.version !== 1) {
      throw commerceValidationError("Quota reservation is inconsistent", "reservation");
    }
    return this.runtime.withTransaction(async (executor) => {
      const existing = await this.reservationRepository.findReserveByIdempotency(tenantId, quotaId, reservation.subscriptionId, reservation.idempotencyKey, executor);
      if (existing !== undefined) {
        if (existing.requestHash !== reservation.requestHash) throw commerceIdempotencyKeyReused();
        const quota = await this.requireCurrent(tenantId, quotaId, executor);
        return { quota, reservation: existing, replayed: true };
      }
      const inserted = await this.reservationRepository.insertIfAbsent(reservation, executor);
      if (!inserted.inserted || inserted.reservation === undefined) {
        const raced = await this.reservationRepository.findReserveByIdempotency(tenantId, quotaId, reservation.subscriptionId, reservation.idempotencyKey, executor);
        if (raced === undefined) throw commerceResourceConflict("Quota reservation already exists");
        if (raced.requestHash !== reservation.requestHash) throw commerceIdempotencyKeyReused();
        const quota = await this.requireCurrent(tenantId, quotaId, executor);
        return { quota, reservation: raced, replayed: true };
      }
      const at = reservation.createdAt;
      const result = await this.runtime.executeMutation(
        `UPDATE ${this.runtime.table(this.tableKey)} SET ${this.runtime.column(this.tableKey, "reserved")} = ${this.runtime.column(this.tableKey, "reserved")} + $3::numeric, ${this.runtime.column(this.tableKey, "version")} = ${this.runtime.column(this.tableKey, "version")} + 1, ${this.runtime.column(this.tableKey, "updatedAt")} = $4 WHERE ${this.runtime.column(this.tableKey, "tenantId")} = $1 AND ${this.runtime.column(this.tableKey, "id")} = $2 AND ${this.runtime.column(this.tableKey, "status")} = 'active' AND ${this.runtime.column(this.tableKey, "reserved")} + ${this.runtime.column(this.tableKey, "consumed")} + $3::numeric <= ${this.runtime.column(this.tableKey, "limit")} RETURNING ${this.runtime.select(this.tableKey, this.fields)}`,
        [tenantId, quotaId, reservation.quantity, at],
        executor,
      );
      if (result.affected !== 1) {
        const current = await this.requireCurrent(tenantId, quotaId, executor);
        if (current.status !== "active") throw commerceResourceConflict("Quota is not active");
        throw commerceQuotaExceeded();
      }
      const quota = result.rows[0] === undefined
        ? await this.requireCurrent(tenantId, quotaId, executor)
        : this.mapRow(result.rows[0]);
      return { quota, reservation: inserted.reservation, replayed: false };
    });
  }

  async settleAtomic(request: QuotaSettlementRequest): Promise<QuotaTerminalResult> {
    return this.terminateReservation(request, "settled");
  }

  async releaseAtomic(request: QuotaReleaseRequest): Promise<QuotaTerminalResult> {
    return this.terminateReservation(request, "released");
  }

  protected toStorage(record: Quota): SqlValues {
    const normalized = normalizeQuota(record, this.runtime.tenantId);
    return {
      id: normalized.id,
      tenantId: normalized.tenantId,
      kind: "quota",
      planId: normalized.planId,
      meterId: normalized.meterId,
      limit: normalized.limit,
      reserved: normalized.reserved,
      consumed: normalized.consumed,
      status: normalized.status,
      version: normalized.version,
      createdAt: normalized.createdAt,
      updatedAt: normalized.updatedAt,
    };
  }

  protected override mapRow(row: SqlRow): Quota {
    return {
      id: readRequiredText(rowValue(row, "id"), "quota.id"),
      tenantId: readRequiredText(rowValue(row, "tenantId"), "quota.tenantId"),
      kind: "quota",
      planId: readRequiredText(rowValue(row, "planId"), "quota.planId"),
      meterId: readRequiredText(rowValue(row, "meterId"), "quota.meterId"),
      limit: readRequiredDecimalString(rowValue(row, "limit"), "quota.limit"),
      reserved: readRequiredDecimalString(rowValue(row, "reserved"), "quota.reserved"),
      consumed: readRequiredDecimalString(rowValue(row, "consumed"), "quota.consumed"),
      status: statusValue<Quota["status"]>(rowValue(row, "status"), ["active", "disabled", "retired"], "quota.status"),
      version: readRequiredNumber(rowValue(row, "version"), "quota.version"),
      createdAt: readRequiredDate(rowValue(row, "createdAt"), "quota.createdAt"),
      updatedAt: readRequiredDate(rowValue(row, "updatedAt"), "quota.updatedAt"),
    };
  }

  private async terminateReservation(
    request: QuotaSettlementRequest | QuotaReleaseRequest,
    target: "settled" | "released",
  ): Promise<QuotaTerminalResult> {
    const tenantId = normalizeCommerceTenantId(request.tenantId);
    const quotaId = assertCommerceId(request.quotaId, "quota", "quotaId");
    const reservationId = assertCommerceId(request.reservationId, "quotaReservation", "reservationId");
    const expectedOperation = target === "settled" ? "quota.settle" : "quota.release";
    if (request.operation !== expectedOperation) throw commerceValidationError("Quota operation is invalid", "operation");
    if (!/^[a-f0-9]{64}$/u.test(request.requestHash)) throw commerceValidationError("Quota request hash is invalid", "requestHash");
    const idempotencyKey = normalizeIdempotencyKey(request.idempotencyKey);
    const at = normalizeCommerceTimestamp(
      target === "settled"
        ? (request as QuotaSettlementRequest).settledAt
        : (request as QuotaReleaseRequest).releasedAt,
      "at",
    );
    const actualQuantity = target === "settled"
      ? assertDecimalString((request as QuotaSettlementRequest).actualQuantity, "actualQuantity")
      : "0";
    return this.runtime.withTransaction(async (executor) => {
      const reservation = await this.reservationRepository.getInTransaction(tenantId, reservationId, executor);
      if (reservation === undefined || reservation.quotaId !== quotaId) throw commerceResourceNotFound("quotaReservation");
      if (reservation.status !== "reserved") {
        if (reservation.terminalOperation === expectedOperation && reservation.terminalIdempotencyKey === idempotencyKey) {
          if (reservation.terminalRequestHash !== request.requestHash) throw commerceIdempotencyKeyReused();
          const quota = await this.requireCurrent(tenantId, quotaId, executor);
          return { quota, reservation, replayed: true };
        }
        throw commerceResourceConflict("Quota reservation is already terminal");
      }
      const quota = await this.requireCurrent(tenantId, quotaId, executor);
      if (quota.planId !== reservation.planId || quota.meterId !== reservation.meterId) throw commerceResourceConflict("Quota reservation does not match quota");
      if (Date.parse(at) < Date.parse(reservation.createdAt)) throw commerceValidationError("Quota terminal time is invalid", "at");
      if (compareDecimalStrings(actualQuantity, reservation.quantity) > 0) throw commerceValidationError("Quota settlement cannot exceed the reservation", "actualQuantity");
      const consumedDelta = target === "settled" ? actualQuantity : "0";
      const updated = await this.runtime.executeMutation(
        `UPDATE ${this.runtime.table(this.tableKey)} SET ${this.runtime.column(this.tableKey, "reserved")} = ${this.runtime.column(this.tableKey, "reserved")} - $3::numeric, ${this.runtime.column(this.tableKey, "consumed")} = ${this.runtime.column(this.tableKey, "consumed")} + $4::numeric, ${this.runtime.column(this.tableKey, "version")} = ${this.runtime.column(this.tableKey, "version")} + 1, ${this.runtime.column(this.tableKey, "updatedAt")} = $5 WHERE ${this.runtime.column(this.tableKey, "tenantId")} = $1 AND ${this.runtime.column(this.tableKey, "id")} = $2 AND ${this.runtime.column(this.tableKey, "reserved")} >= $3::numeric AND ${this.runtime.column(this.tableKey, "consumed")} + $4::numeric + ${this.runtime.column(this.tableKey, "reserved")} - $3::numeric <= ${this.runtime.column(this.tableKey, "limit")} RETURNING ${this.runtime.select(this.tableKey, this.fields)}`,
        [tenantId, quotaId, reservation.quantity, consumedDelta, at],
        executor,
      );
      if (updated.affected !== 1) throw commerceResourceConflict("Quota changed concurrently");
      const nextReservation: QuotaReservation = {
        ...reservation,
        status: target,
        version: reservation.version + 1,
        updatedAt: at,
        ...(target === "settled" ? { settledQuantity: actualQuantity, settledAt: at } : { releasedAt: at }),
        terminalOperation: expectedOperation,
        terminalIdempotencyKey: idempotencyKey,
        terminalRequestHash: request.requestHash,
      };
      const savedReservation = await this.reservationRepository.terminalTransitionAtomic(nextReservation);
      const updatedQuota = updated.rows[0] === undefined
        ? await this.requireCurrent(tenantId, quotaId, executor)
        : this.mapRow(updated.rows[0]);
      return { quota: updatedQuota, reservation: savedReservation, replayed: false };
    });
  }
}

export class SqlUsageAggregateRepository
  extends SqlCommerceRepository<UsageAggregate>
  implements UsageAggregateRepository {
  protected readonly tableKey: CommerceSqlTableKey = "usageAggregates";
  protected readonly entityKind: CommerceEntityKind = "usageAggregate";
  protected readonly fields = COMMERCE_SQL_FIELDS.usageAggregates;

  constructor(
    input: CommerceSqlRepositoryInput,
    options?: CommerceSqlRepositorySecondOptions,
  ) {
    super(createCommerceSqlRuntime(input, options));
  }

  async findByKey(tenantId: string, aggregateKey: string): Promise<UsageAggregate | undefined> {
    const tenant = normalizeCommerceTenantId(tenantId);
    const key = requireCommerceIdentifier(aggregateKey, "aggregateKey");
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.runtime.addTenantPredicate(this.tableKey, values, clauses, tenant);
    values.push(key);
    clauses.push(`${this.runtime.column(this.tableKey, "aggregateKey")} = $${values.length}`);
    const rows = await this.runtime.queryRows(
      `SELECT ${this.runtime.select(this.tableKey, this.fields)} FROM ${this.runtime.table(this.tableKey)} WHERE ${clauses.join(" AND ")} LIMIT 1`,
      values,
    );
    if (rows[0] === undefined) return undefined;
    const record = this.mapRow(rows[0]);
    return record.tenantId === tenant && record.tenantId === this.runtime.tenantId ? record : undefined;
  }

  protected override validateTransition(current: UsageAggregate, next: UsageAggregate): void {
    if (current.status !== next.status) assertUsageAggregateTransition(current.status, next.status);
  }

  protected override updateFields(): readonly string[] {
    return ["status", "version", "updatedAt"];
  }

  protected override assertGenericSaveAllowed(current: UsageAggregate, next: UsageAggregate): void {
    if (compareDecimalStrings(current.quantity, next.quantity) !== 0 || !sameStringArray(current.eventIds, next.eventIds)) {
      throw commerceResourceConflict("Usage aggregate counters require saveAggregateAtomic");
    }
  }

  async saveAggregateAtomic(record: UsageAggregate): Promise<UsageAggregate> {
    const normalized = this.prepareSave(record);
    return this.runtime.withTransaction(async (executor) => {
      const current = await this.requireCurrent(normalized.tenantId, normalized.id, executor);
      this.assertSave(current, normalized);
      const storage = this.toStorage(normalized);
      const values: unknown[] = [
        normalized.tenantId,
        normalized.id,
        current.version,
        current.status,
        storageValue("quantity", storage.quantity),
        storageValue("eventIds", storage.eventIds),
        storageValue("status", storage.status),
        normalized.version,
        storageValue("updatedAt", storage.updatedAt),
      ];
      const result = await this.runtime.executeMutation(
        `UPDATE ${this.runtime.table(this.tableKey)} SET ${this.runtime.column(this.tableKey, "quantity")} = $5::numeric, ${this.runtime.column(this.tableKey, "eventIds")} = $6::jsonb, ${this.runtime.column(this.tableKey, "status")} = $7, ${this.runtime.column(this.tableKey, "version")} = $8, ${this.runtime.column(this.tableKey, "updatedAt")} = $9 WHERE ${this.runtime.column(this.tableKey, "tenantId")} = $1 AND ${this.runtime.column(this.tableKey, "id")} = $2 AND ${this.runtime.column(this.tableKey, "version")} = $3 AND ${this.runtime.column(this.tableKey, "status")} = $4 RETURNING ${this.runtime.select(this.tableKey, this.fields)}`,
        values,
        executor,
      );
      if (result.affected !== 1) throw commerceResourceConflict("Usage aggregate version is stale");
      return result.rows[0] === undefined ? normalized : this.mapRow(result.rows[0]);
    });
  }

  async saveAtomic(record: UsageAggregate): Promise<UsageAggregate> {
    return this.saveAggregateAtomic(record);
  }

  async replaceAtomic(record: UsageAggregate): Promise<UsageAggregate> {
    return this.saveAggregateAtomic(record);
  }

  async updateAggregateAtomic(record: UsageAggregate): Promise<UsageAggregate> {
    return this.saveAggregateAtomic(record);
  }

  async replaceAggregateAtomic(record: UsageAggregate): Promise<UsageAggregate> {
    return this.saveAggregateAtomic(record);
  }

  protected toStorage(record: UsageAggregate): SqlValues {
    const normalized = normalizeAggregate(record, this.runtime.tenantId);
    return {
      id: normalized.id,
      tenantId: normalized.tenantId,
      kind: "usageAggregate",
      aggregateKey: normalized.aggregateKey,
      subscriptionId: normalized.subscriptionId,
      meterId: normalized.meterId,
      aggregation: normalized.aggregation,
      quantity: normalized.quantity,
      unit: normalized.unit,
      periodStart: normalized.periodStart,
      periodEnd: normalized.periodEnd,
      dimensions: normalized.dimensions,
      eventIds: normalized.eventIds,
      status: normalized.status,
      version: normalized.version,
      createdAt: normalized.createdAt,
      updatedAt: normalized.updatedAt,
    };
  }

  protected override mapRow(row: SqlRow): UsageAggregate {
    return {
      id: readRequiredText(rowValue(row, "id"), "usageAggregate.id"),
      tenantId: readRequiredText(rowValue(row, "tenantId"), "usageAggregate.tenantId"),
      kind: "usageAggregate",
      aggregateKey: readRequiredText(rowValue(row, "aggregateKey"), "usageAggregate.aggregateKey"),
      subscriptionId: readRequiredText(rowValue(row, "subscriptionId"), "usageAggregate.subscriptionId"),
      meterId: readRequiredText(rowValue(row, "meterId"), "usageAggregate.meterId"),
      aggregation: statusValue<UsageAggregate["aggregation"]>(rowValue(row, "aggregation"), ["sum", "max", "last"], "usageAggregate.aggregation"),
      quantity: readRequiredDecimalString(rowValue(row, "quantity"), "usageAggregate.quantity"),
      unit: readRequiredText(rowValue(row, "unit"), "usageAggregate.unit"),
      periodStart: readRequiredDate(rowValue(row, "periodStart"), "usageAggregate.periodStart"),
      periodEnd: readRequiredDate(rowValue(row, "periodEnd"), "usageAggregate.periodEnd"),
      dimensions: readDimensions(rowValue(row, "dimensions"), "usageAggregate.dimensions"),
      eventIds: readStringArray(rowValue(row, "eventIds")),
      status: statusValue<UsageAggregate["status"]>(rowValue(row, "status"), ["collecting", "closed", "priced", "settled"], "usageAggregate.status"),
      version: readRequiredNumber(rowValue(row, "version"), "usageAggregate.version"),
      createdAt: readRequiredDate(rowValue(row, "createdAt"), "usageAggregate.createdAt"),
      updatedAt: readRequiredDate(rowValue(row, "updatedAt"), "usageAggregate.updatedAt"),
    };
  }
}

export class SqlUsageEventRepository implements UsageEventRepository {
  private readonly runtime: CommerceSqlRuntime;
  private readonly fields = COMMERCE_SQL_FIELDS.usageEvents;

  constructor(
    input: CommerceSqlRepositoryInput,
    options?: CommerceSqlRepositorySecondOptions,
  ) {
    this.runtime = createCommerceSqlRuntime(input, options);
  }

  async append(event: UsageEvent): Promise<UsageEventAppendResult> {
    const normalized = normalizeUsageEvent(event, this.runtime.tenantId);
    return this.runtime.withTransaction(async (executor) => {
      const values = [
        normalized.id,
        normalized.tenantId,
        normalized.kind,
        normalized.version,
        normalized.sourceEventId,
        normalized.subscriptionId,
        normalized.meterId,
        normalized.quantity,
        normalized.occurredAt,
        normalized.periodStart,
        normalized.periodEnd,
        storageValue("dimensions", normalized.dimensions),
        normalized.idempotencyKey,
        normalized.requestHash,
        normalized.payloadHash,
        normalized.receivedAt,
      ];
      const inserted = await this.runtime.executeMutation(
        `INSERT INTO ${this.runtime.table("usageEvents")} (${this.fields.map((field) => this.runtime.column("usageEvents", field)).join(", ")}) VALUES (${this.fields.map((_field, index) => `$${index + 1}`).join(", ")}) ON CONFLICT DO NOTHING RETURNING ${this.runtime.select("usageEvents", this.fields)}`,
        values,
        executor,
      );
      if (inserted.affected === 1) {
        return {
          event: inserted.rows[0] === undefined ? normalized : this.mapRow(inserted.rows[0]),
          accepted: true,
        };
      }
      const existing = await this.findExisting(normalized, executor);
      if (existing === undefined) throw commerceResourceConflict("Usage event already exists");
      if (existing.requestHash !== normalized.requestHash && existing.idempotencyKey === normalized.idempotencyKey) {
        throw commerceIdempotencyKeyReused();
      }
      if (existing.payloadHash !== normalized.payloadHash && existing.sourceEventId === normalized.sourceEventId) {
        throw commerceResourceConflict("Usage source event conflicts with existing state");
      }
      return { event: existing, accepted: false };
    });
  }

  async get(tenantId: string, id: string): Promise<UsageEvent | undefined> {
    const tenant = normalizeCommerceTenantId(tenantId);
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.runtime.addTenantPredicate("usageEvents", values, clauses, tenant);
    values.push(assertCommerceId(id, "usageEvent", "id"));
    clauses.push(`${this.runtime.column("usageEvents", "id")} = $${values.length}`);
    const rows = await this.runtime.queryRows(
      `SELECT ${this.runtime.select("usageEvents", this.fields)} FROM ${this.runtime.table("usageEvents")} WHERE ${clauses.join(" AND ")} LIMIT 1`,
      values,
    );
    if (rows[0] === undefined) return undefined;
    const event = this.mapRow(rows[0]);
    return event.tenantId === tenant && event.tenantId === this.runtime.tenantId ? event : undefined;
  }

  async list(tenantId: string): Promise<UsageEvent[]> {
    const tenant = normalizeCommerceTenantId(tenantId);
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.runtime.addTenantPredicate("usageEvents", values, clauses, tenant);
    const rows = await this.runtime.queryRows(
      `SELECT ${this.runtime.select("usageEvents", this.fields)} FROM ${this.runtime.table("usageEvents")} WHERE ${clauses.join(" AND ")} ORDER BY ${this.runtime.column("usageEvents", "occurredAt")} ASC, ${this.runtime.column("usageEvents", "id")} ASC`,
      values,
    );
    return rows.map((row) => this.mapRow(row)).filter((event) => event.tenantId === tenant && event.tenantId === this.runtime.tenantId);
  }

  async findByIdempotencyKey(tenantId: string, idempotencyKey: string): Promise<UsageEvent | undefined> {
    const tenant = normalizeCommerceTenantId(tenantId);
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.runtime.addTenantPredicate("usageEvents", values, clauses, tenant);
    values.push(normalizeIdempotencyKey(idempotencyKey));
    clauses.push(`${this.runtime.column("usageEvents", "idempotencyKey")} = $${values.length}`);
    const rows = await this.runtime.queryRows(
      `SELECT ${this.runtime.select("usageEvents", this.fields)} FROM ${this.runtime.table("usageEvents")} WHERE ${clauses.join(" AND ")} LIMIT 1`,
      values,
    );
    if (rows[0] === undefined) return undefined;
    const event = this.mapRow(rows[0]);
    return event.tenantId === tenant && event.tenantId === this.runtime.tenantId ? event : undefined;
  }

  async isReady(): Promise<boolean> {
    return this.runtime.isReady(["usageEvents"]);
  }

  async readiness() {
    return this.runtime.readiness(["usageEvents"]);
  }

  private async findExisting(
    event: UsageEvent,
    executor: CommerceDatabaseAdapter,
  ): Promise<UsageEvent | undefined> {
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.runtime.addTenantPredicate("usageEvents", values, clauses, event.tenantId);
    values.push(event.idempotencyKey, event.sourceEventId);
    clauses.push(`(${this.runtime.column("usageEvents", "idempotencyKey")} = $${values.length - 1} OR ${this.runtime.column("usageEvents", "sourceEventId")} = $${values.length})`);
    const rows = await this.runtime.queryRows(
      `SELECT ${this.runtime.select("usageEvents", this.fields)} FROM ${this.runtime.table("usageEvents")} WHERE ${clauses.join(" AND ")} ORDER BY ${this.runtime.column("usageEvents", "receivedAt")} ASC LIMIT 1 FOR UPDATE`,
      values,
      executor,
    );
    if (rows[0] === undefined) return undefined;
    const existing = this.mapRow(rows[0]);
    return existing.tenantId === event.tenantId && existing.tenantId === this.runtime.tenantId ? existing : undefined;
  }

  private mapRow(row: SqlRow): UsageEvent {
    return {
      id: readRequiredText(rowValue(row, "id"), "usageEvent.id"),
      tenantId: readRequiredText(rowValue(row, "tenantId"), "usageEvent.tenantId"),
      kind: "usageEvent",
      version: 1,
      sourceEventId: readRequiredText(rowValue(row, "sourceEventId"), "usageEvent.sourceEventId"),
      subscriptionId: readRequiredText(rowValue(row, "subscriptionId"), "usageEvent.subscriptionId"),
      meterId: readRequiredText(rowValue(row, "meterId"), "usageEvent.meterId"),
      quantity: readRequiredDecimalString(rowValue(row, "quantity"), "usageEvent.quantity"),
      occurredAt: readRequiredDate(rowValue(row, "occurredAt"), "usageEvent.occurredAt"),
      periodStart: readRequiredDate(rowValue(row, "periodStart"), "usageEvent.periodStart"),
      periodEnd: readRequiredDate(rowValue(row, "periodEnd"), "usageEvent.periodEnd"),
      dimensions: readDimensions(rowValue(row, "dimensions"), "usageEvent.dimensions"),
      idempotencyKey: readRequiredText(rowValue(row, "idempotencyKey"), "usageEvent.idempotencyKey"),
      requestHash: readRequiredText(rowValue(row, "requestHash"), "usageEvent.requestHash"),
      payloadHash: readRequiredText(rowValue(row, "payloadHash"), "usageEvent.payloadHash"),
      receivedAt: readRequiredDate(rowValue(row, "receivedAt"), "usageEvent.receivedAt"),
    };
  }
}

export class SqlInvoiceLineRepository {
  private readonly runtime: CommerceSqlRuntime;
  private readonly fields = COMMERCE_SQL_FIELDS.invoiceLines;

  constructor(
    input: CommerceSqlRepositoryInput,
    options?: CommerceSqlRepositorySecondOptions,
  ) {
    this.runtime = createCommerceSqlRuntime(input, options);
  }

  async create(line: InvoiceLine): Promise<InvoiceLine> {
    const normalized = normalizeInvoiceLine(line, this.assertTenant(line.tenantId));
    return this.insert(normalized);
  }

  async insert(line: InvoiceLine, executor?: CommerceDatabaseAdapter): Promise<InvoiceLine> {
    const normalized = normalizeInvoiceLine(line, this.assertTenant(line.tenantId));
    const result = await this.runtime.executeMutation(
      `INSERT INTO ${this.runtime.table("invoiceLines")} (${this.fields.map((field) => this.runtime.column("invoiceLines", field)).join(", ")}) VALUES (${this.fields.map((_field, index) => `$${index + 1}`).join(", ")}) RETURNING ${this.runtime.select("invoiceLines", this.fields)}`,
      this.values(normalized),
      executor,
    );
    if (result.affected !== 1) throw commerceResourceConflict("Invoice line already exists");
    return result.rows[0] === undefined ? normalized : this.mapRow(result.rows[0]);
  }

  async get(tenantId: string, id: string): Promise<InvoiceLine | undefined> {
    const tenant = this.assertTenant(tenantId);
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.runtime.addTenantPredicate("invoiceLines", values, clauses, tenant);
    values.push(assertCommerceId(id, "invoiceLine", "id"));
    clauses.push(`${this.runtime.column("invoiceLines", "id")} = $${values.length}`);
    const rows = await this.runtime.queryRows(
      `SELECT ${this.runtime.select("invoiceLines", this.fields)} FROM ${this.runtime.table("invoiceLines")} WHERE ${clauses.join(" AND ")} LIMIT 1`,
      values,
    );
    if (rows[0] === undefined) return undefined;
    const line = this.mapRow(rows[0]);
    return line.tenantId === tenant && line.tenantId === this.runtime.tenantId ? line : undefined;
  }

  async list(tenantId: string, invoiceId?: string): Promise<InvoiceLine[]> {
    const tenant = this.assertTenant(tenantId);
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.runtime.addTenantPredicate("invoiceLines", values, clauses, tenant);
    if (invoiceId !== undefined) {
      values.push(assertCommerceId(invoiceId, "invoice", "invoiceId"));
      clauses.push(`${this.runtime.column("invoiceLines", "invoiceId")} = $${values.length}`);
    }
    const rows = await this.runtime.queryRows(
      `SELECT ${this.runtime.select("invoiceLines", this.fields)} FROM ${this.runtime.table("invoiceLines")} WHERE ${clauses.join(" AND ")} ORDER BY ${this.runtime.column("invoiceLines", "id")} ASC`,
      values,
    );
    return rows.map((row) => this.mapRow(row)).filter((line) => line.tenantId === tenant && line.tenantId === this.runtime.tenantId);
  }

  async listForInvoice(
    tenantId: string,
    invoiceId: string,
    executor?: CommerceDatabaseAdapter,
  ): Promise<InvoiceLine[]> {
    const tenant = this.assertTenant(tenantId);
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.runtime.addTenantPredicate("invoiceLines", values, clauses, tenant);
    values.push(assertCommerceId(invoiceId, "invoice", "invoiceId"));
    clauses.push(`${this.runtime.column("invoiceLines", "invoiceId")} = $${values.length}`);
    const rows = await this.runtime.queryRows(
      `SELECT ${this.runtime.select("invoiceLines", this.fields)} FROM ${this.runtime.table("invoiceLines")} WHERE ${clauses.join(" AND ")} ORDER BY ${this.runtime.column("invoiceLines", "id")} ASC`,
      values,
      executor,
    );
    return rows.map((row) => this.mapRow(row)).filter((line) => line.tenantId === tenant && line.tenantId === this.runtime.tenantId);
  }

  async getByInvoice(tenantId: string, invoiceId: string): Promise<InvoiceLine[]> {
    return this.listForInvoice(tenantId, invoiceId);
  }

  async isReady(): Promise<boolean> {
    return this.runtime.isReady(["invoiceLines"]);
  }

  async readiness() {
    return this.runtime.readiness(["invoiceLines"]);
  }

  private assertTenant(tenantId: string): string {
    const tenant = normalizeCommerceTenantId(tenantId);
    if (tenant !== this.runtime.tenantId) throw commerceValidationError("Invoice line tenant scope does not match the runtime tenant", "tenantId");
    return tenant;
  }

  private values(line: InvoiceLine): unknown[] {
    return [
      line.id,
      line.tenantId,
      line.kind,
      line.invoiceId,
      line.type,
      line.direction,
      line.description,
      line.quantity,
      line.unitAmount.amountMinor,
      line.amount.amountMinor,
      line.unitAmount.currency,
      line.meterId,
      line.priceId,
      line.aggregateId,
      line.adjustmentType,
    ];
  }

  private mapRow(row: SqlRow): InvoiceLine {
    const currency = readRequiredText(rowValue(row, "currency"), "invoiceLine.currency");
    return {
      id: readRequiredText(rowValue(row, "id"), "invoiceLine.id"),
      tenantId: readRequiredText(rowValue(row, "tenantId"), "invoiceLine.tenantId"),
      kind: "invoiceLine",
      invoiceId: readRequiredText(rowValue(row, "invoiceId"), "invoiceLine.invoiceId"),
      type: statusValue<InvoiceLine["type"]>(rowValue(row, "type"), ["subscription", "usage", "adjustment", "tax"], "invoiceLine.type"),
      direction: statusValue<InvoiceLine["direction"]>(rowValue(row, "direction"), ["debit", "credit"], "invoiceLine.direction"),
      description: readRequiredText(rowValue(row, "description"), "invoiceLine.description"),
      quantity: readRequiredDecimalString(rowValue(row, "quantity"), "invoiceLine.quantity"),
      unitAmount: readMoney(rowValue(row, "unitAmountMinor"), currency, "invoiceLine.unitAmountMinor"),
      amount: readMoney(rowValue(row, "amountMinor"), currency, "invoiceLine.amountMinor"),
      ...optionalText("meterId", rowValue(row, "meterId")),
      ...optionalText("priceId", rowValue(row, "priceId")),
      ...optionalText("aggregateId", rowValue(row, "aggregateId")),
      ...optionalText("adjustmentType", rowValue(row, "adjustmentType")),
    };
  }
}

export class SqlInvoiceRepository implements InvoiceRepository {
  private readonly runtime: CommerceSqlRuntime;
  private readonly fields = COMMERCE_SQL_FIELDS.invoices;
  private readonly lineRepository: SqlInvoiceLineRepository;

  constructor(
    input: CommerceSqlRepositoryInput,
    options?: CommerceSqlRepositorySecondOptions,
  ) {
    this.runtime = createCommerceSqlRuntime(input, options);
    this.lineRepository = new SqlInvoiceLineRepository(this.runtime);
  }

  async createIdempotent(request: InvoiceIdempotentCreateRequest): Promise<InvoiceIdempotentCreateResult> {
    const tenantId = this.assertTenant(request.tenantId);
    const idempotencyKey = normalizeIdempotencyKey(request.idempotencyKey);
    if (!/^[a-f0-9]{64}$/u.test(request.requestHash)) throw commerceValidationError("Invoice request hash is invalid", "requestHash");
    const invoice = normalizeInvoice(request.invoice, this.runtime.tenantId);
    if (invoice.requestHash !== request.requestHash) throw commerceValidationError("Invoice request hash does not match the invoice", "requestHash");
    if (invoice.tenantId !== tenantId || invoice.idempotencyKey !== idempotencyKey) throw commerceValidationError("Invoice tenant scope or idempotency key is invalid", "tenantId");
    return this.runtime.withTransaction(async (executor) => {
      const values = this.values(invoice);
      const result = await this.runtime.executeMutation(
        `INSERT INTO ${this.runtime.table("invoices")} (${this.fields.map((field) => this.runtime.column("invoices", field)).join(", ")}) VALUES (${this.fields.map((_field, index) => `$${index + 1}`).join(", ")}) ON CONFLICT (${this.runtime.column("invoices", "tenantId")}, ${this.runtime.column("invoices", "idempotencyKey")}) DO NOTHING RETURNING ${this.runtime.select("invoices", this.fields)}`,
        values,
        executor,
      );
      if (result.affected === 1) {
        for (const line of invoice.lines) await this.lineRepository.insert(line, executor);
        return { invoice, replayed: false };
      }
      const existing = await this.findByIdempotency(tenantId, idempotencyKey, executor);
      if (existing === undefined) throw commerceResourceConflict("Invoice already exists");
      if (existing.requestHash !== request.requestHash) throw commerceIdempotencyKeyReused();
      return { invoice: existing, replayed: true };
    });
  }

  async get(tenantId: string, id: string): Promise<Invoice | undefined> {
    const tenant = this.assertTenant(tenantId);
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.runtime.addTenantPredicate("invoices", values, clauses, tenant);
    values.push(assertCommerceId(id, "invoice", "id"));
    clauses.push(`${this.runtime.column("invoices", "id")} = $${values.length}`);
    const rows = await this.runtime.queryRows(
      `SELECT ${this.runtime.select("invoices", this.fields)} FROM ${this.runtime.table("invoices")} WHERE ${clauses.join(" AND ")} LIMIT 1`,
      values,
    );
    if (rows[0] === undefined) return undefined;
    const invoice = await this.hydrate(rows[0], undefined, tenant);
    return invoice.tenantId === tenant && invoice.tenantId === this.runtime.tenantId ? invoice : undefined;
  }

  async list(tenantId: string): Promise<Invoice[]> {
    const tenant = this.assertTenant(tenantId);
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.runtime.addTenantPredicate("invoices", values, clauses, tenant);
    const rows = await this.runtime.queryRows(
      `SELECT ${this.runtime.select("invoices", this.fields)} FROM ${this.runtime.table("invoices")} WHERE ${clauses.join(" AND ")} ORDER BY ${this.runtime.column("invoices", "createdAt")} ASC, ${this.runtime.column("invoices", "id")} ASC`,
      values,
    );
    const invoices: Invoice[] = [];
    for (const row of rows) {
      const invoice = await this.hydrate(row, undefined, tenant);
      if (invoice.tenantId === tenant && invoice.tenantId === this.runtime.tenantId) invoices.push(invoice);
    }
    return invoices;
  }

  async transition(
    tenantId: string,
    id: string,
    targetStatus: InvoiceStatus,
    at: string,
  ): Promise<Invoice> {
    const tenant = this.assertTenant(tenantId);
    const invoiceId = assertCommerceId(id, "invoice", "id");
    if (!["draft", "reconciling", "awaitingPayment", "invoicing", "paid", "completed", "disputed", "voided"].includes(targetStatus)) throw commerceValidationError("Invoice target status is invalid", "targetStatus");
    const timestamp = normalizeCommerceTimestamp(at, "at");
    return this.runtime.withTransaction(async (executor) => {
      const current = await this.requireInvoice(tenant, invoiceId, executor);
      assertInvoiceTransition(current.status, targetStatus);
      const next: Invoice = {
        ...current,
        status: targetStatus,
        version: current.version + 1,
        updatedAt: timestamp,
        ...(targetStatus === "paid" ? { paidAt: timestamp } : {}),
        ...(targetStatus === "completed" ? { finalizedAt: timestamp } : {}),
        ...(targetStatus === "voided" ? { voidedAt: timestamp } : {}),
      };
      const eventValues = [
        tenant,
        invoiceId,
        next.version,
        targetStatus,
        current.status,
        timestamp,
        next.paidAt ?? null,
        next.finalizedAt ?? null,
        next.voidedAt ?? null,
      ];
      const eventFields = COMMERCE_SQL_FIELDS.invoiceStatusEvents;
      const invoiceTable = this.runtime.table("invoices");
      const eventTable = this.runtime.table("invoiceStatusEvents");
      const tenantColumn = this.runtime.column("invoiceStatusEvents", "tenantId");
      const eventInvoiceIdColumn = this.runtime.column("invoiceStatusEvents", "invoiceId");
      const eventVersionColumn = this.runtime.column("invoiceStatusEvents", "version");
      const eventStatusColumn = this.runtime.column("invoiceStatusEvents", "status");
      const invoiceTenantColumn = this.runtime.column("invoices", "tenantId");
      const invoiceIdColumn = this.runtime.column("invoices", "id");
      const invoiceVersionColumn = this.runtime.column("invoices", "version");
      const invoiceStatusColumn = this.runtime.column("invoices", "status");
      const result = await this.runtime.executeMutation(
        `WITH current_state AS (SELECT COALESCE(latest.${eventVersionColumn}, invoice.${invoiceVersionColumn}) AS ${eventVersionColumn}, COALESCE(latest.${eventStatusColumn}, invoice.${invoiceStatusColumn}) AS ${eventStatusColumn} FROM ${invoiceTable} AS invoice LEFT JOIN LATERAL (SELECT ${eventVersionColumn}, ${eventStatusColumn} FROM ${eventTable} WHERE ${tenantColumn} = $1 AND ${eventInvoiceIdColumn} = $2 ORDER BY ${eventVersionColumn} DESC LIMIT 1) AS latest ON TRUE WHERE invoice.${invoiceTenantColumn} = $1 AND invoice.${invoiceIdColumn} = $2) INSERT INTO ${eventTable} (${eventFields.map((field) => this.runtime.column("invoiceStatusEvents", field)).join(", ")}) SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9 FROM current_state WHERE current_state.${eventVersionColumn} + 1 = $3 AND current_state.${eventStatusColumn} = $5 RETURNING ${this.runtime.select("invoiceStatusEvents", eventFields)}`,
        eventValues,
        executor,
      );
      if (result.affected !== 1) throw commerceResourceConflict("Invoice version is stale");
      return { ...next, lines: current.lines };
    });
  }

  async isReady(): Promise<boolean> {
    return this.runtime.isReady(["invoices", "invoiceLines", "invoiceStatusEvents"]);
  }

  async readiness() {
    return this.runtime.readiness(["invoices", "invoiceLines", "invoiceStatusEvents"]);
  }

  get lineReader(): SqlInvoiceLineRepository {
    return this.lineRepository;
  }

  async getLines(tenantId: string, invoiceId: string): Promise<InvoiceLine[]> {
    return this.lineRepository.listForInvoice(this.assertTenant(tenantId), invoiceId);
  }

  private assertTenant(tenantId: string): string {
    const tenant = normalizeCommerceTenantId(tenantId);
    if (tenant !== this.runtime.tenantId) throw commerceValidationError("Invoice tenant scope does not match the runtime tenant", "tenantId");
    return tenant;
  }

  private async findByIdempotency(
    tenantId: string,
    idempotencyKey: string,
    executor?: CommerceDatabaseAdapter,
  ): Promise<Invoice | undefined> {
    const tenant = this.assertTenant(tenantId);
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.runtime.addTenantPredicate("invoices", values, clauses, tenant);
    values.push(idempotencyKey);
    clauses.push(`${this.runtime.column("invoices", "idempotencyKey")} = $${values.length}`);
    const rows = await this.runtime.queryRows(
      `SELECT ${this.runtime.select("invoices", this.fields)} FROM ${this.runtime.table("invoices")} WHERE ${clauses.join(" AND ")} LIMIT 1 FOR UPDATE`,
      values,
      executor,
    );
    return rows[0] === undefined ? undefined : this.hydrate(rows[0], executor, tenant);
  }

  private async requireInvoice(
    tenantId: string,
    id: string,
    executor: CommerceDatabaseAdapter,
  ): Promise<Invoice> {
    const tenant = this.assertTenant(tenantId);
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.runtime.addTenantPredicate("invoices", values, clauses, tenant);
    values.push(id);
    clauses.push(`${this.runtime.column("invoices", "id")} = $${values.length}`);
    const rows = await this.runtime.queryRows(
      `SELECT ${this.runtime.select("invoices", this.fields)} FROM ${this.runtime.table("invoices")} WHERE ${clauses.join(" AND ")} LIMIT 1 FOR UPDATE`,
      values,
      executor,
    );
    if (rows[0] === undefined) throw commerceResourceNotFound("invoice");
    return this.hydrate(rows[0], executor, tenant);
  }

  private async hydrate(
    row: SqlRow,
    executor: CommerceDatabaseAdapter | undefined,
    tenantId: string,
  ): Promise<Invoice> {
    const base = this.mapRow(row);
    const statusRows = await this.runtime.queryRows(
      `SELECT ${this.runtime.select("invoiceStatusEvents")} FROM ${this.runtime.table("invoiceStatusEvents")} WHERE ${this.runtime.column("invoiceStatusEvents", "tenantId")} = $1 AND ${this.runtime.column("invoiceStatusEvents", "invoiceId")} = $2 ORDER BY ${this.runtime.column("invoiceStatusEvents", "version")} DESC LIMIT 1`,
      [tenantId, base.id],
      executor,
    );
    const statusRow = statusRows[0];
    const lines = await this.lineRepository.listForInvoice(tenantId, base.id, executor);
    if (statusRow === undefined) return { ...base, lines };
    return {
      ...base,
      status: statusValue<InvoiceStatus>(rowValue(statusRow, "status"), ["draft", "reconciling", "awaitingPayment", "invoicing", "paid", "completed", "disputed", "voided"], "invoice.status"),
      version: readRequiredNumber(rowValue(statusRow, "version"), "invoice.version"),
      updatedAt: readRequiredDate(rowValue(statusRow, "occurredAt"), "invoice.updatedAt"),
      ...optionalDate("finalizedAt", rowValue(statusRow, "finalizedAt")),
      ...optionalDate("paidAt", rowValue(statusRow, "paidAt")),
      ...optionalDate("voidedAt", rowValue(statusRow, "voidedAt")),
      lines,
    };
  }

  private values(invoice: Invoice): unknown[] {
    return [
      invoice.id,
      invoice.tenantId,
      invoice.kind,
      invoice.version,
      invoice.subscriptionId,
      invoice.planId,
      invoice.periodStart,
      invoice.periodEnd,
      invoice.status,
      invoice.currency,
      invoice.taxMode,
      invoice.subtotal.amountMinor,
      invoice.tax.amountMinor,
      invoice.total.amountMinor,
      invoice.idempotencyKey,
      invoice.requestHash,
      storageValue("mainlandChina", invoice.mainlandChina),
      invoice.finalizedAt,
      invoice.paidAt,
      invoice.voidedAt,
      invoice.createdAt,
      invoice.updatedAt,
    ];
  }

  private mapRow(row: SqlRow): Invoice {
    const currency = readRequiredText(rowValue(row, "currency"), "invoice.currency");
    const lines: InvoiceLine[] = [];
    const rawMainlandChina = readJson(rowValue(row, "mainlandChina"));
    const mainlandChina = rawMainlandChina === undefined || rawMainlandChina === null
      ? undefined
      : normalizeMainlandChinaInvoiceMetadata(
        rawMainlandChina,
        isRecord(rawMainlandChina) ? rawMainlandChina.taxRateBps : undefined,
      );
    const base = {
      id: readRequiredText(rowValue(row, "id"), "invoice.id"),
      tenantId: readRequiredText(rowValue(row, "tenantId"), "invoice.tenantId"),
      kind: "invoice" as const,
      version: readRequiredNumber(rowValue(row, "version"), "invoice.version"),
      subscriptionId: readRequiredText(rowValue(row, "subscriptionId"), "invoice.subscriptionId"),
      planId: readRequiredText(rowValue(row, "planId"), "invoice.planId"),
      periodStart: readRequiredDate(rowValue(row, "periodStart"), "invoice.periodStart"),
      periodEnd: readRequiredDate(rowValue(row, "periodEnd"), "invoice.periodEnd"),
      status: statusValue<InvoiceStatus>(rowValue(row, "status"), ["draft", "reconciling", "awaitingPayment", "invoicing", "paid", "completed", "disputed", "voided"], "invoice.status"),
      currency: currency as Invoice["currency"],
      taxMode: statusValue<Invoice["taxMode"]>(rowValue(row, "taxMode"), ["exclusive", "inclusive"], "invoice.taxMode"),
      lines,
      subtotal: readMoney(rowValue(row, "subtotalMinor"), currency, "invoice.subtotalMinor"),
      tax: readMoney(rowValue(row, "taxMinor"), currency, "invoice.taxMinor"),
      total: readMoney(rowValue(row, "totalMinor"), currency, "invoice.totalMinor"),
      idempotencyKey: readRequiredText(rowValue(row, "idempotencyKey"), "invoice.idempotencyKey"),
      requestHash: readRequiredText(rowValue(row, "requestHash"), "invoice.requestHash"),
       ...(mainlandChina === undefined ? {} : { mainlandChina }),

      ...optionalDate("finalizedAt", rowValue(row, "finalizedAt")),
      ...optionalDate("paidAt", rowValue(row, "paidAt")),
      ...optionalDate("voidedAt", rowValue(row, "voidedAt")),
      createdAt: readRequiredDate(rowValue(row, "createdAt"), "invoice.createdAt"),
      updatedAt: readRequiredDate(rowValue(row, "updatedAt"), "invoice.updatedAt"),
    };
    return base;
  }
}

export class SqlInvoiceDisputeRepository implements InvoiceDisputeRepository {
  private readonly runtime: CommerceSqlRuntime;
  private readonly fields = COMMERCE_SQL_FIELDS.invoiceDisputes;

  constructor(
    input: CommerceSqlRepositoryInput,
    options?: CommerceSqlRepositorySecondOptions,
  ) {
    this.runtime = createCommerceSqlRuntime(input, options);
  }

  async append(dispute: InvoiceDispute): Promise<InvoiceDisputeAppendResult> {
    const tenant = this.assertTenant(dispute?.tenantId);
    const normalized = normalizeInvoiceDispute(dispute, tenant);
    return this.runtime.withTransaction(async (executor) => {
      const inserted = await this.runtime.executeMutation(
        `INSERT INTO ${this.runtime.table("invoiceDisputes")} (${this.fields.map((field) => this.runtime.column("invoiceDisputes", field)).join(", ")}) VALUES (${this.fields.map((_field, index) => `$${index + 1}`).join(", ")}) ON CONFLICT DO NOTHING RETURNING ${this.runtime.select("invoiceDisputes", this.fields)}`,
        this.values(normalized),
        executor,
      );
      if (inserted.affected === 1) {
        return {
          dispute:
            inserted.rows[0] === undefined
              ? normalized
              : this.mapRow(inserted.rows[0]),
          accepted: true,
        };
      }
      const existing = await this.findExisting(normalized, executor);
      if (existing === undefined) {
        throw commerceResourceConflict("Invoice dispute already exists");
      }
      if (existing.requestHash !== normalized.requestHash) {
        throw commerceIdempotencyKeyReused();
      }
      return { dispute: existing, accepted: false };
    });
  }

  async get(tenantId: string, id: string): Promise<InvoiceDispute | undefined> {
    const tenant = this.assertTenant(tenantId);
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.runtime.addTenantPredicate("invoiceDisputes", values, clauses, tenant);
    values.push(assertCommerceId(id, "invoiceDispute", "id"));
    clauses.push(`${this.runtime.column("invoiceDisputes", "id")} = $${values.length}`);
    const rows = await this.runtime.queryRows(
      `SELECT ${this.runtime.select("invoiceDisputes", this.fields)} FROM ${this.runtime.table("invoiceDisputes")} WHERE ${clauses.join(" AND ")} LIMIT 1`,
      values,
    );
    if (rows[0] === undefined) return undefined;
    const dispute = this.mapRow(rows[0]);
    return dispute.tenantId === tenant ? dispute : undefined;
  }

  async list(
    tenantId: string,
    query: InvoiceDisputeListQuery = {},
  ): Promise<InvoiceDispute[]> {
    const tenant = this.assertTenant(tenantId);
    const options = normalizeInvoiceDisputeListQuery(query);
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.runtime.addTenantPredicate("invoiceDisputes", values, clauses, tenant);
    if (options.invoiceId !== undefined) {
      values.push(options.invoiceId);
      clauses.push(`${this.runtime.column("invoiceDisputes", "invoiceId")} = $${values.length}`);
    }
    if (options.actorId !== undefined) {
      values.push(options.actorId);
      clauses.push(`${this.runtime.column("invoiceDisputes", "actorId")} = $${values.length}`);
    }
    if (options.status !== undefined) {
      values.push(options.status);
      clauses.push(`${this.runtime.column("invoiceDisputes", "status")} = $${values.length}`);
    }
    if (options.from !== undefined) {
      values.push(options.from);
      clauses.push(`${this.runtime.column("invoiceDisputes", "createdAt")} >= $${values.length}`);
    }
    if (options.to !== undefined) {
      values.push(options.to);
      clauses.push(`${this.runtime.column("invoiceDisputes", "createdAt")} <= $${values.length}`);
    }
    const rows = await this.runtime.queryRows(
      `SELECT ${this.runtime.select("invoiceDisputes", this.fields)} FROM ${this.runtime.table("invoiceDisputes")} WHERE ${clauses.join(" AND ")} ORDER BY ${this.runtime.column("invoiceDisputes", "createdAt")} ASC, ${this.runtime.column("invoiceDisputes", "id")} ASC LIMIT ${options.limit}`,
      values,
    );
    return rows
      .map((row) => this.mapRow(row))
      .filter((dispute) => dispute.tenantId === tenant);
  }

  async findByIdempotency(
    tenantId: string,
    idempotencyKey: string,
    query: Pick<InvoiceDisputeListQuery, "invoiceId"> = {},
  ): Promise<InvoiceDispute | undefined> {
    const tenant = this.assertTenant(tenantId);
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.runtime.addTenantPredicate("invoiceDisputes", values, clauses, tenant);
    values.push(normalizeIdempotencyKey(idempotencyKey));
    clauses.push(`${this.runtime.column("invoiceDisputes", "idempotencyKey")} = $${values.length}`);
    if (query.invoiceId !== undefined) {
      values.push(assertCommerceId(query.invoiceId, "invoice", "invoiceId"));
      clauses.push(`${this.runtime.column("invoiceDisputes", "invoiceId")} = $${values.length}`);
    }
    const rows = await this.runtime.queryRows(
      `SELECT ${this.runtime.select("invoiceDisputes", this.fields)} FROM ${this.runtime.table("invoiceDisputes")} WHERE ${clauses.join(" AND ")} ORDER BY ${this.runtime.column("invoiceDisputes", "createdAt")} ASC, ${this.runtime.column("invoiceDisputes", "id")} ASC LIMIT 1`,
      values,
    );
    if (rows[0] === undefined) return undefined;
    const dispute = this.mapRow(rows[0]);
    return dispute.tenantId === tenant ? dispute : undefined;
  }

  async decide(
    tenantId: string,
    id: string,
    decision: InvoiceDisputeDecision,
  ): Promise<InvoiceDispute> {
    const tenant = this.assertTenant(tenantId);
    const disputeId = assertCommerceId(id, "invoiceDispute", "id");
    const normalized = normalizeInvoiceDisputeDecision(decision);
    return this.runtime.withTransaction(async (executor) => {
      const current = await this.requireDispute(tenant, disputeId, executor);
      if (current.version !== normalized.expectedVersion) {
        throw commerceResourceConflict("Invoice dispute version is stale");
      }
      assertInvoiceDisputeTransition(current.status, normalized.targetStatus);
      const terminal = (INVOICE_DISPUTE_OUTCOMES as readonly InvoiceDisputeStatus[])
        .includes(normalized.targetStatus);
      const terminalStatus = terminal
        ? (normalized.targetStatus as InvoiceDisputeOutcome)
        : undefined;
      const note = normalized.resolutionNote;
      const values = [
        tenant,
        disputeId,
        normalized.expectedVersion,
        normalized.targetStatus,
        terminalStatus ?? null,
        normalized.decidedBy,
        normalized.reference ?? null,
        note ?? null,
        note === undefined ? null : note.length,
        terminal ? normalized.decidedAt : null,
        normalized.decidedAt,
        normalized.expectedVersion + 1,
      ];
      const result = await this.runtime.executeMutation(
        `UPDATE ${this.runtime.table("invoiceDisputes")} SET ${this.runtime.column("invoiceDisputes", "status")} = $4, ${this.runtime.column("invoiceDisputes", "resolutionOutcome")} = $5, ${this.runtime.column("invoiceDisputes", "resolutionActorId")} = $6, ${this.runtime.column("invoiceDisputes", "resolutionReference")} = $7, ${this.runtime.column("invoiceDisputes", "resolutionNote")} = $8, ${this.runtime.column("invoiceDisputes", "resolutionNoteLength")} = $9, ${this.runtime.column("invoiceDisputes", "resolvedAt")} = $10, ${this.runtime.column("invoiceDisputes", "updatedAt")} = $11, ${this.runtime.column("invoiceDisputes", "version")} = $12 WHERE ${this.runtime.column("invoiceDisputes", "tenantId")} = $1 AND ${this.runtime.column("invoiceDisputes", "id")} = $2 AND ${this.runtime.column("invoiceDisputes", "version")} = $3 RETURNING ${this.runtime.select("invoiceDisputes", this.fields)}`,
        values,
        executor,
      );
      if (result.affected !== 1 || result.rows[0] === undefined) {
        throw commerceResourceConflict("Invoice dispute version is stale");
      }
      const decided = this.mapRow(result.rows[0]);
      return decided.tenantId === tenant ? decided : current;
    });
  }

  async withTransaction<T>(operation: () => Promise<T>): Promise<T> {
    return this.runtime.withTransaction(() => operation());
  }

  async isReady(): Promise<boolean> {
    return this.runtime.isReady(["invoiceDisputes"]);
  }

  async readiness() {
    return this.runtime.readiness(["invoiceDisputes"]);
  }

  private assertTenant(tenantId: string): string {
    const tenant = normalizeCommerceTenantId(tenantId);
    if (tenant !== this.runtime.tenantId) {
      throw commerceValidationError(
        "Invoice dispute tenant scope does not match the runtime tenant",
        "tenantId",
      );
    }
    return tenant;
  }

  private async requireDispute(
    tenantId: string,
    id: string,
    executor?: CommerceDatabaseAdapter,
  ): Promise<InvoiceDispute> {
    const tenant = this.assertTenant(tenantId);
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.runtime.addTenantPredicate("invoiceDisputes", values, clauses, tenant);
    values.push(assertCommerceId(id, "invoiceDispute", "id"));
    clauses.push(`${this.runtime.column("invoiceDisputes", "id")} = $${values.length}`);
    const rows = await this.runtime.queryRows(
      `SELECT ${this.runtime.select("invoiceDisputes", this.fields)} FROM ${this.runtime.table("invoiceDisputes")} WHERE ${clauses.join(" AND ")} LIMIT 1 FOR UPDATE`,
      values,
      executor,
    );
    if (rows[0] === undefined) throw commerceResourceNotFound("invoiceDispute");
    const dispute = this.mapRow(rows[0]);
    if (dispute.tenantId !== tenant) throw commerceResourceNotFound("invoiceDispute");
    return dispute;
  }

  private async findExisting(
    dispute: InvoiceDispute,
    executor?: CommerceDatabaseAdapter,
  ): Promise<InvoiceDispute | undefined> {
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.runtime.addTenantPredicate("invoiceDisputes", values, clauses, dispute.tenantId);
    values.push(dispute.id, dispute.idempotencyKey);
    clauses.push(
      `(${this.runtime.column("invoiceDisputes", "id")} = $${values.length - 1} OR ${this.runtime.column("invoiceDisputes", "idempotencyKey")} = $${values.length})`,
    );
    const rows = await this.runtime.queryRows(
      `SELECT ${this.runtime.select("invoiceDisputes", this.fields)} FROM ${this.runtime.table("invoiceDisputes")} WHERE ${clauses.join(" AND ")} ORDER BY ${this.runtime.column("invoiceDisputes", "createdAt")} ASC, ${this.runtime.column("invoiceDisputes", "id")} ASC LIMIT 1 FOR UPDATE`,
      values,
      executor,
    );
    if (rows[0] === undefined) return undefined;
    const existing = this.mapRow(rows[0]);
    return existing.tenantId === dispute.tenantId ? existing : undefined;
  }

  private values(dispute: InvoiceDispute): unknown[] {
    return [
      dispute.id,
      dispute.tenantId,
      dispute.kind,
      dispute.version,
      dispute.event,
      dispute.invoiceId,
      dispute.subscriptionId,
      dispute.planId,
      dispute.invoiceStatus,
      dispute.invoiceVersion,
      dispute.reason,
      dispute.reasonDigest,
      dispute.reasonLength,
      dispute.evidenceReference ?? null,
      dispute.evidenceReferenceDigest ?? null,
      dispute.evidenceCount,
      dispute.actorId,
      dispute.requestId,
      dispute.idempotencyKey,
      dispute.requestHash,
      dispute.status,
      dispute.resolution?.outcome ?? null,
      dispute.resolution?.actorId ?? null,
      dispute.resolution?.reference ?? null,
      dispute.resolution?.note ?? null,
      dispute.resolution?.noteLength ?? null,
      dispute.resolvedAt ?? null,
      dispute.createdAt,
      dispute.updatedAt,
      dispute.recordedAt,
    ];
  }

  private mapRow(row: SqlRow): InvoiceDispute {
    const resolutionOutcome = readText(
      rowValue(row, "resolutionOutcome"),
    );
    const resolutionActorId = readText(
      rowValue(row, "resolutionActorId"),
    );
    const resolutionReference = readText(
      rowValue(row, "resolutionReference"),
    );
    const resolutionNote = readText(rowValue(row, "resolutionNote"));
    const resolutionNoteLength = readNumber(rowValue(row, "resolutionNoteLength"));
    const resolutionFromStatus = readText(rowValue(row, "resolutionFromStatus"));
    const resolvedAt = readOptionalDate(rowValue(row, "resolvedAt"));
    const resolution =
      resolutionOutcome === undefined ||
      resolutionActorId === undefined ||
      resolutionReference === undefined ||
      resolvedAt === undefined
        ? undefined
        : {
            outcome: statusValue<InvoiceDisputeOutcome>(
              resolutionOutcome,
              INVOICE_DISPUTE_OUTCOMES,
              "invoiceDispute.resolutionOutcome",
            ),
            actorId: resolutionActorId,
            reference: resolutionReference,
            resolvedAt,
            ...(resolutionNote === undefined ? {} : { note: resolutionNote }),
            ...(resolutionNoteLength === undefined
              ? {}
              : { noteLength: resolutionNoteLength }),
            ...(resolutionFromStatus === undefined
              ? {}
              : {
                  fromStatus: statusValue<InvoiceDisputeStatus>(
                    resolutionFromStatus,
                    INVOICE_DISPUTE_STATUSES,
                    "invoiceDispute.resolutionFromStatus",
                  ),
                }),
          };
    return {
      id: readRequiredText(rowValue(row, "id"), "invoiceDispute.id"),
      tenantId: readRequiredText(rowValue(row, "tenantId"), "invoiceDispute.tenantId"),
      kind: "invoiceDispute",
      version: readRequiredNumber(rowValue(row, "version"), "invoiceDispute.version"),
      event: "invoice.dispute.opened",
      invoiceId: readRequiredText(rowValue(row, "invoiceId"), "invoiceDispute.invoiceId"),
      subscriptionId: readRequiredText(
        rowValue(row, "subscriptionId"),
        "invoiceDispute.subscriptionId",
      ),
      planId: readRequiredText(rowValue(row, "planId"), "invoiceDispute.planId"),
      invoiceStatus: statusValue<InvoiceStatus>(
        rowValue(row, "invoiceStatus"),
        INVOICE_STATUSES,
        "invoiceDispute.invoiceStatus",
      ),
      invoiceVersion: readRequiredNumber(
        rowValue(row, "invoiceVersion"),
        "invoiceDispute.invoiceVersion",
      ),
      reason: readRequiredText(rowValue(row, "reason"), "invoiceDispute.reason"),
      reasonDigest: readRequiredText(
        rowValue(row, "reasonDigest"),
        "invoiceDispute.reasonDigest",
      ),
      reasonLength: readRequiredNumber(
        rowValue(row, "reasonLength"),
        "invoiceDispute.reasonLength",
      ),
      ...optionalText("evidenceReference", rowValue(row, "evidenceReference")),
      ...optionalText(
        "evidenceReferenceDigest",
        rowValue(row, "evidenceReferenceDigest"),
      ),
      evidenceCount: readRequiredNumber(
        rowValue(row, "evidenceCount"),
        "invoiceDispute.evidenceCount",
      ),
      actorId: readRequiredText(rowValue(row, "actorId"), "invoiceDispute.actorId"),
      requestId: readRequiredText(rowValue(row, "requestId"), "invoiceDispute.requestId"),
      idempotencyKey: readRequiredText(
        rowValue(row, "idempotencyKey"),
        "invoiceDispute.idempotencyKey",
      ),
      requestHash: readRequiredText(
        rowValue(row, "requestHash"),
        "invoiceDispute.requestHash",
      ),
      status: statusValue<InvoiceDisputeStatus>(
        rowValue(row, "status"),
        INVOICE_DISPUTE_STATUSES,
        "invoiceDispute.status",
      ),
      ...(resolution === undefined ? {} : { resolution }),
      ...optionalDate("resolvedAt", rowValue(row, "resolvedAt")),
      createdAt: readRequiredDate(rowValue(row, "createdAt"), "invoiceDispute.createdAt"),
      updatedAt: readRequiredDate(rowValue(row, "updatedAt"), "invoiceDispute.updatedAt"),
      recordedAt: readRequiredDate(rowValue(row, "recordedAt"), "invoiceDispute.recordedAt"),
    };
  }
}

export class SqlMarketplaceListingRepository
  extends SqlCommerceRepository<MarketplaceListing>
  implements TenantScopedRepository<MarketplaceListing> {
  protected readonly tableKey: CommerceSqlTableKey = "marketplaceListings";
  protected readonly entityKind: CommerceEntityKind = "marketplaceListing";
  protected readonly fields = COMMERCE_SQL_FIELDS.marketplaceListings;

  constructor(
    input: CommerceSqlRepositoryInput,
    options?: CommerceSqlRepositorySecondOptions,
  ) {
    super(createCommerceSqlRuntime(input, options));
  }

  protected override validateTransition(current: MarketplaceListing, next: MarketplaceListing): void {
    if (current.status !== next.status) assertMarketplaceListingTransition(current.status, next.status);
  }

  protected toStorage(record: MarketplaceListing): SqlValues {
    const normalized = normalizeListing(record, this.runtime.tenantId);
    return {
      id: normalized.id,
      tenantId: normalized.tenantId,
      kind: "marketplaceListing",
      partnerAccountId: normalized.partnerAccountId,
      productId: normalized.productId,
      title: normalized.title,
      description: normalized.description,
      status: normalized.status,
      priceIds: normalized.priceIds,
      commissionRuleIds: normalized.commissionRuleIds,
      submittedAt: normalized.submittedAt,
      publishedAt: normalized.publishedAt,
      removedAt: normalized.removedAt,
      version: normalized.version,
      createdAt: normalized.createdAt,
      updatedAt: normalized.updatedAt,
    };
  }

  protected override mapRow(row: SqlRow): MarketplaceListing {
    return {
      id: readRequiredText(rowValue(row, "id"), "marketplaceListing.id"),
      tenantId: readRequiredText(rowValue(row, "tenantId"), "marketplaceListing.tenantId"),
      kind: "marketplaceListing",
      partnerAccountId: readRequiredText(rowValue(row, "partnerAccountId"), "marketplaceListing.partnerAccountId"),
      productId: readRequiredText(rowValue(row, "productId"), "marketplaceListing.productId"),
      title: readRequiredText(rowValue(row, "title"), "marketplaceListing.title"),
      description: readRequiredText(rowValue(row, "description"), "marketplaceListing.description"),
      status: statusValue<MarketplaceListing["status"]>(rowValue(row, "status"), ["draft", "pendingReview", "published", "suspended", "removed"], "marketplaceListing.status"),
      priceIds: readStringArray(rowValue(row, "priceIds")),
      commissionRuleIds: readStringArray(rowValue(row, "commissionRuleIds")),
      ...optionalDate("submittedAt", rowValue(row, "submittedAt")),
      ...optionalDate("publishedAt", rowValue(row, "publishedAt")),
      ...optionalDate("removedAt", rowValue(row, "removedAt")),
      version: readRequiredNumber(rowValue(row, "version"), "marketplaceListing.version"),
      createdAt: readRequiredDate(rowValue(row, "createdAt"), "marketplaceListing.createdAt"),
      updatedAt: readRequiredDate(rowValue(row, "updatedAt"), "marketplaceListing.updatedAt"),
    };
  }
}

export class SqlPartnerAccountRepository
  extends SqlCommerceRepository<PartnerAccount>
  implements TenantScopedRepository<PartnerAccount> {
  protected readonly tableKey: CommerceSqlTableKey = "partnerAccounts";
  protected readonly entityKind: CommerceEntityKind = "partnerAccount";
  protected readonly fields = COMMERCE_SQL_FIELDS.partnerAccounts;

  constructor(
    input: CommerceSqlRepositoryInput,
    options?: CommerceSqlRepositorySecondOptions,
  ) {
    super(createCommerceSqlRuntime(input, options));
  }

  protected override validateTransition(current: PartnerAccount, next: PartnerAccount): void {
    if (current.status !== next.status) assertPartnerAccountTransition(current.status, next.status);
  }

  protected toStorage(record: PartnerAccount): SqlValues {
    const normalized = normalizePartnerAccount(record, this.runtime.tenantId);
    return {
      id: normalized.id,
      tenantId: normalized.tenantId,
      kind: "partnerAccount",
      legalName: normalized.legalName,
      partnerCode: normalized.partnerCode,
      status: normalized.status,
      currency: normalized.currency,
      settlementReference: normalized.settlementReference,
      activatedAt: normalized.activatedAt,
      version: normalized.version,
      createdAt: normalized.createdAt,
      updatedAt: normalized.updatedAt,
    };
  }

  protected override mapRow(row: SqlRow): PartnerAccount {
    return {
      id: readRequiredText(rowValue(row, "id"), "partnerAccount.id"),
      tenantId: readRequiredText(rowValue(row, "tenantId"), "partnerAccount.tenantId"),
      kind: "partnerAccount",
      legalName: readRequiredText(rowValue(row, "legalName"), "partnerAccount.legalName"),
      partnerCode: readRequiredText(rowValue(row, "partnerCode"), "partnerAccount.partnerCode"),
      status: statusValue<PartnerAccount["status"]>(rowValue(row, "status"), ["pending", "underReview", "active", "frozen", "rejected", "closed"], "partnerAccount.status"),
      currency: readRequiredText(rowValue(row, "currency"), "partnerAccount.currency") as PartnerAccount["currency"],
      settlementReference: readRequiredText(rowValue(row, "settlementReference"), "partnerAccount.settlementReference"),
      ...optionalDate("activatedAt", rowValue(row, "activatedAt")),
      version: readRequiredNumber(rowValue(row, "version"), "partnerAccount.version"),
      createdAt: readRequiredDate(rowValue(row, "createdAt"), "partnerAccount.createdAt"),
      updatedAt: readRequiredDate(rowValue(row, "updatedAt"), "partnerAccount.updatedAt"),
    };
  }
}

export class SqlCommissionRuleRepository
  extends SqlCommerceRepository<CommissionRule>
  implements TenantScopedRepository<CommissionRule> {
  protected readonly tableKey: CommerceSqlTableKey = "commissionRules";
  protected readonly entityKind: CommerceEntityKind = "commissionRule";
  protected readonly fields = COMMERCE_SQL_FIELDS.commissionRules;

  constructor(
    input: CommerceSqlRepositoryInput,
    options?: CommerceSqlRepositorySecondOptions,
  ) {
    super(createCommerceSqlRuntime(input, options));
  }

  protected override validateTransition(current: CommissionRule, next: CommissionRule): void {
    if (current.status !== next.status) assertCommissionRuleTransition(current.status, next.status);
  }

  protected override updateFields(): readonly string[] {
    return ["status", "version", "updatedAt"];
  }

  protected toStorage(record: CommissionRule): SqlValues {
    const normalized = normalizeCommissionRule(record, this.runtime.tenantId);
    return {
      id: normalized.id,
      tenantId: normalized.tenantId,
      kind: "commissionRule",
      partnerAccountId: normalized.partnerAccountId,
      listingId: normalized.listingId,
      name: normalized.name,
      status: normalized.status,
      rateBps: normalized.rateBps,
      capBps: normalized.capBps,
      capAmountMinor: normalized.capAmount?.amountMinor,
      currency: MONEY_CURRENCY,
      priority: normalized.priority,
      effectiveFrom: normalized.effectiveFrom,
      effectiveTo: normalized.effectiveTo,
      version: normalized.version,
      createdAt: normalized.createdAt,
      updatedAt: normalized.updatedAt,
    };
  }

  protected override mapRow(row: SqlRow): CommissionRule {
    const rawCurrency = rowValue(row, "currency");
    const currency = rawCurrency === null || rawCurrency === undefined
      ? MONEY_CURRENCY
      : readRequiredText(rawCurrency, "commissionRule.currency");
    if (currency !== MONEY_CURRENCY) throw new Error("Invalid commissionRule.currency SQL row");
    const capAmountMinor = rowValue(row, "capAmountMinor");
    return {
      id: readRequiredText(rowValue(row, "id"), "commissionRule.id"),
      tenantId: readRequiredText(rowValue(row, "tenantId"), "commissionRule.tenantId"),
      kind: "commissionRule",
      partnerAccountId: readRequiredText(rowValue(row, "partnerAccountId"), "commissionRule.partnerAccountId"),
      listingId: readRequiredText(rowValue(row, "listingId"), "commissionRule.listingId"),
      name: readRequiredText(rowValue(row, "name"), "commissionRule.name"),
      status: statusValue<CommissionRule["status"]>(rowValue(row, "status"), ["draft", "scheduled", "active", "suspended", "retired"], "commissionRule.status"),
      rateBps: readRequiredNumber(rowValue(row, "rateBps"), "commissionRule.rateBps"),
      ...(rowValue(row, "capBps") === null || rowValue(row, "capBps") === undefined ? {} : { capBps: readRequiredNumber(rowValue(row, "capBps"), "commissionRule.capBps") }),
      ...(capAmountMinor === null || capAmountMinor === undefined ? {} : { capAmount: readMoney(capAmountMinor, currency, "commissionRule.capAmountMinor") }),
      priority: readRequiredNumber(rowValue(row, "priority"), "commissionRule.priority"),
      effectiveFrom: readRequiredDate(rowValue(row, "effectiveFrom"), "commissionRule.effectiveFrom"),
      ...optionalDate("effectiveTo", rowValue(row, "effectiveTo")),
      version: readRequiredNumber(rowValue(row, "version"), "commissionRule.version"),
      createdAt: readRequiredDate(rowValue(row, "createdAt"), "commissionRule.createdAt"),
      updatedAt: readRequiredDate(rowValue(row, "updatedAt"), "commissionRule.updatedAt"),
    };
  }
}

export function createSqlPlanRepository(input: CommerceSqlRepositoryInput, options?: CommerceSqlRepositorySecondOptions): SqlPlanRepository {
  return new SqlPlanRepository(input, options);
}

export function createSqlEntitlementRepository(input: CommerceSqlRepositoryInput, options?: CommerceSqlRepositorySecondOptions): SqlEntitlementRepository {
  return new SqlEntitlementRepository(input, options);
}

export function createSqlMeterRepository(input: CommerceSqlRepositoryInput, options?: CommerceSqlRepositorySecondOptions): SqlMeterRepository {
  return new SqlMeterRepository(input, options);
}

export function createSqlPriceRepository(input: CommerceSqlRepositoryInput, options?: CommerceSqlRepositorySecondOptions): SqlPriceRepository {
  return new SqlPriceRepository(input, options);
}

export function createSqlSubscriptionRepository(input: CommerceSqlRepositoryInput, options?: CommerceSqlRepositorySecondOptions): SqlSubscriptionRepository {
  return new SqlSubscriptionRepository(input, options);
}

export function createSqlQuotaRepository(input: CommerceSqlRepositoryInput, options?: CommerceSqlRepositorySecondOptions): SqlQuotaRepository {
  return new SqlQuotaRepository(input, options);
}

export function createSqlQuotaReservationRepository(input: CommerceSqlRepositoryInput, options?: CommerceSqlRepositorySecondOptions): SqlQuotaReservationRepository {
  return new SqlQuotaReservationRepository(input, options);
}

export function createSqlUsageEventRepository(input: CommerceSqlRepositoryInput, options?: CommerceSqlRepositorySecondOptions): SqlUsageEventRepository {
  return new SqlUsageEventRepository(input, options);
}

export function createSqlUsageAggregateRepository(input: CommerceSqlRepositoryInput, options?: CommerceSqlRepositorySecondOptions): SqlUsageAggregateRepository {
  return new SqlUsageAggregateRepository(input, options);
}

export function createSqlInvoiceRepository(input: CommerceSqlRepositoryInput, options?: CommerceSqlRepositorySecondOptions): SqlInvoiceRepository {
  return new SqlInvoiceRepository(input, options);
}

export function createSqlInvoiceLineRepository(input: CommerceSqlRepositoryInput, options?: CommerceSqlRepositorySecondOptions): SqlInvoiceLineRepository {
  return new SqlInvoiceLineRepository(input, options);
}

export function createSqlInvoiceDisputeRepository(input: CommerceSqlRepositoryInput, options?: CommerceSqlRepositorySecondOptions): SqlInvoiceDisputeRepository {
  return new SqlInvoiceDisputeRepository(input, options);
}

export function createSqlMarketplaceListingRepository(input: CommerceSqlRepositoryInput, options?: CommerceSqlRepositorySecondOptions): SqlMarketplaceListingRepository {
  return new SqlMarketplaceListingRepository(input, options);
}

export function createSqlPartnerAccountRepository(input: CommerceSqlRepositoryInput, options?: CommerceSqlRepositorySecondOptions): SqlPartnerAccountRepository {
  return new SqlPartnerAccountRepository(input, options);
}

export function createSqlCommissionRuleRepository(input: CommerceSqlRepositoryInput, options?: CommerceSqlRepositorySecondOptions): SqlCommissionRuleRepository {
  return new SqlCommissionRuleRepository(input, options);
}

export const SqlOpenPlanRepository = SqlPlanRepository;
export const SqlOpenEntitlementRepository = SqlEntitlementRepository;
export const SqlOpenMeterRepository = SqlMeterRepository;
export const SqlOpenPriceRepository = SqlPriceRepository;
export const SqlOpenSubscriptionRepository = SqlSubscriptionRepository;
export const SqlOpenQuotaRepository = SqlQuotaRepository;
export const SqlOpenQuotaReservationRepository = SqlQuotaReservationRepository;
export const SqlOpenUsageEventRepository = SqlUsageEventRepository;
export const SqlOpenUsageAggregateRepository = SqlUsageAggregateRepository;
export const SqlOpenInvoiceRepository = SqlInvoiceRepository;
export const SqlOpenInvoiceLineRepository = SqlInvoiceLineRepository;
export const SqlOpenInvoiceDisputeRepository = SqlInvoiceDisputeRepository;
export const SqlOpenMarketplaceListingRepository = SqlMarketplaceListingRepository;
export const SqlOpenPartnerAccountRepository = SqlPartnerAccountRepository;
export const SqlOpenCommissionRuleRepository = SqlCommissionRuleRepository;
export const PostgresPlanRepository = SqlPlanRepository;
export const PostgresEntitlementRepository = SqlEntitlementRepository;
export const PostgresMeterRepository = SqlMeterRepository;
export const PostgresPriceRepository = SqlPriceRepository;
export const PostgresSubscriptionRepository = SqlSubscriptionRepository;
export const PostgresQuotaRepository = SqlQuotaRepository;
export const PostgresQuotaReservationRepository = SqlQuotaReservationRepository;
export const PostgresUsageEventRepository = SqlUsageEventRepository;
export const PostgresUsageAggregateRepository = SqlUsageAggregateRepository;
export const PostgresInvoiceRepository = SqlInvoiceRepository;
export const PostgresInvoiceLineRepository = SqlInvoiceLineRepository;
export const PostgresInvoiceDisputeRepository = SqlInvoiceDisputeRepository;
export const PostgresMarketplaceListingRepository = SqlMarketplaceListingRepository;
export const PostgresPartnerAccountRepository = SqlPartnerAccountRepository;
export const PostgresCommissionRuleRepository = SqlCommissionRuleRepository;
export const SqlCommercePlanRepository = SqlPlanRepository;
export const SqlCommerceEntitlementRepository = SqlEntitlementRepository;
export const SqlCommerceMeterRepository = SqlMeterRepository;
export const SqlCommercePriceRepository = SqlPriceRepository;
export const SqlCommerceSubscriptionRepository = SqlSubscriptionRepository;
export const SqlCommerceQuotaRepository = SqlQuotaRepository;
export const SqlCommerceQuotaReservationRepository = SqlQuotaReservationRepository;
export const SqlCommerceUsageEventRepository = SqlUsageEventRepository;
export const SqlCommerceUsageAggregateRepository = SqlUsageAggregateRepository;
export const SqlCommerceInvoiceRepository = SqlInvoiceRepository;
export const SqlCommerceInvoiceLineRepository = SqlInvoiceLineRepository;
export const SqlCommerceInvoiceDisputeRepository = SqlInvoiceDisputeRepository;
export const SqlCommerceMarketplaceListingRepository = SqlMarketplaceListingRepository;
export const SqlCommercePartnerAccountRepository = SqlPartnerAccountRepository;
export const SqlCommerceCommissionRuleRepository = SqlCommissionRuleRepository;

function normalizePlan(record: Plan, tenantId: string): Plan {
  assertCommerceId(record.id, "plan", "id");
  normalizeCommerceTenantId(record.tenantId);
  if (record.tenantId !== tenantId || record.kind !== "plan") throw commerceValidationError("Plan scope is invalid", "tenantId");
  requireCommerceCode(record.code, "code");
  requireCommerceText(record.name, "name", 200);
  if (record.description !== undefined) requireCommerceText(record.description, "description", 2000);
  validateIdList(record.priceIds, "plan", "priceIds");
  validateIdList(record.entitlementIds, "entitlement", "entitlementIds");
  validateIdList(record.quotaIds, "quota", "quotaIds");
  if (record.effectiveTo !== undefined && Date.parse(record.effectiveTo) <= Date.parse(record.effectiveFrom)) throw commerceValidationError("Commerce effective range is invalid", "effectiveTo");
  return record;
}

function normalizeEntitlement(record: Entitlement, tenantId: string): Entitlement {
  assertCommerceId(record.id, "entitlement", "id");
  normalizeCommerceTenantId(record.tenantId);
  if (record.tenantId !== tenantId || record.kind !== "entitlement") throw commerceValidationError("Entitlement scope is invalid", "tenantId");
  requireCommerceIdentifier(record.feature, "feature");
  if (record.effect !== "allow" && record.effect !== "deny") throw commerceValidationError("Entitlement effect is invalid", "effect");
  if (record.source === "tenant" && record.sourceId !== tenantId) throw commerceValidationError("Entitlement source is invalid", "sourceId");
  if (record.source === "plan") assertCommerceId(record.sourceId, "plan", "sourceId");
  if (record.source === "subscription") assertCommerceId(record.sourceId, "subscription", "sourceId");
  if (record.value !== undefined && typeof record.value !== "boolean" && typeof record.value !== "string" && (typeof record.value !== "number" || !Number.isSafeInteger(record.value))) throw commerceValidationError("Entitlement value is invalid", "value");
  if (typeof record.value === "string") requireCommerceIdentifier(record.value, "value");
  if (record.effectiveTo !== undefined && Date.parse(record.effectiveTo) <= Date.parse(record.effectiveFrom)) throw commerceValidationError("Commerce effective range is invalid", "effectiveTo");
  return record;
}

function normalizeMeter(record: Meter, tenantId: string): Meter {
  assertCommerceId(record.id, "meter", "id");
  normalizeCommerceTenantId(record.tenantId);
  if (record.tenantId !== tenantId || record.kind !== "meter") throw commerceValidationError("Meter scope is invalid", "tenantId");
  requireCommerceCode(record.key, "key");
  requireCommerceText(record.name, "name", 200);
  requireCommerceIdentifier(record.unit, "unit");
  if (!Array.isArray(record.dimensions)) throw commerceValidationError("Meter dimensions are invalid", "dimensions");
  record.dimensions.forEach((value) => requireCommerceIdentifier(value, "dimensions"));
  return record;
}

function normalizePrice(record: Price, tenantId: string): Price {
  assertCommerceId(record.id, "price", "id");
  normalizeCommerceTenantId(record.tenantId);
  if (record.tenantId !== tenantId || record.kind !== "price") throw commerceValidationError("Price scope is invalid", "tenantId");
  requireCommerceCode(record.code, "code");
  requireCommerceText(record.name, "name", 200);
  if (record.currency !== "CNY") throw commerceValidationError("Only CNY prices are supported", "currency");
  if (record.priceType === "fixed") assertMoney(record.fixedAmount, "fixedAmount");
  else {
    assertCommerceId(record.meterId, "meter", "meterId");
    if (record.priceType === "tiered") {
      if (!Array.isArray(record.tiers) || record.tiers.length === 0) throw commerceValidationError("Tiered price requires tiers", "tiers");
      record.tiers.forEach((tier) => validateTier(tier, record.currency));
    } else {
      assertMoney(record.unitAmount, "unitAmount");
      assertDecimalString(record.includedUnits, "includedUnits");
      assertMoney(record.minimumCharge, "minimumCharge");
      if (record.priceType === "mixed") assertMoney(record.fixedAmount, "fixedAmount");
    }
  }
  if (record.effectiveTo !== undefined && Date.parse(record.effectiveTo) <= Date.parse(record.effectiveFrom)) throw commerceValidationError("Commerce effective range is invalid", "effectiveTo");
  return record;
}

function validateTier(tier: PriceTier, currency: "CNY"): void {
  if (tier.upTo !== null) assertDecimalString(tier.upTo, "tiers.upTo");
  if (tier.unitAmount.currency !== currency) throw commerceValidationError("Tier currency is invalid", "tiers");
  assertMoney(tier.unitAmount, "tiers.unitAmount");
}

function normalizeSubscription(record: Subscription, tenantId: string): Subscription {
  assertCommerceId(record.id, "subscription", "id");
  normalizeCommerceTenantId(record.tenantId);
  if (record.tenantId !== tenantId || record.kind !== "subscription") throw commerceValidationError("Subscription scope is invalid", "tenantId");
  requireCommerceIdentifier(record.applicationId, "applicationId");
  assertCommerceId(record.planId, "plan", "planId");
  requireCommerceText(record.name, "name", 200);
  assertDecimalString(record.quantity, "quantity", false);
  normalizePeriod(record.currentPeriodStart, record.currentPeriodEnd);
  return record;
}

function normalizeQuota(record: Quota, tenantId: string): Quota {
  assertCommerceId(record.id, "quota", "id");
  normalizeCommerceTenantId(record.tenantId);
  if (record.tenantId !== tenantId || record.kind !== "quota") throw commerceValidationError("Quota scope is invalid", "tenantId");
  assertCommerceId(record.planId, "plan", "planId");
  assertCommerceId(record.meterId, "meter", "meterId");
  assertDecimalString(record.limit, "limit", false);
  assertDecimalString(record.reserved, "reserved");
  assertDecimalString(record.consumed, "consumed");
  if (compareDecimalStrings(addDecimalStrings(record.reserved, record.consumed), record.limit) > 0) throw commerceValidationError("Quota counters exceed the limit", "limit");
  return record;
}

function normalizeReservation(record: QuotaReservation, tenantId: string): QuotaReservation {
  assertCommerceId(record.id, "quotaReservation", "id");
  normalizeCommerceTenantId(record.tenantId);
  if (record.tenantId !== tenantId || record.kind !== "quotaReservation" || record.operation !== "quota.reserve") throw commerceValidationError("Quota reservation scope is invalid", "tenantId");
  assertCommerceId(record.quotaId, "quota", "quotaId");
  assertCommerceId(record.planId, "plan", "planId");
  assertCommerceId(record.subscriptionId, "subscription", "subscriptionId");
  assertCommerceId(record.meterId, "meter", "meterId");
  assertDecimalString(record.quantity, "quantity", false);
  normalizeIdempotencyKey(record.idempotencyKey);
  if (!/^[a-f0-9]{64}$/u.test(record.requestHash)) throw commerceValidationError("Quota request hash is invalid", "requestHash");
  normalizeCommerceTimestamp(record.expiresAt, "expiresAt");
  if (record.settledQuantity !== undefined) assertDecimalString(record.settledQuantity, "settledQuantity");
  return record;
}

function normalizeAggregate(record: UsageAggregate, tenantId: string): UsageAggregate {
  assertCommerceId(record.id, "usageAggregate", "id");
  normalizeCommerceTenantId(record.tenantId);
  if (record.tenantId !== tenantId || record.kind !== "usageAggregate") throw commerceValidationError("Usage aggregate scope is invalid", "tenantId");
  requireCommerceIdentifier(record.aggregateKey, "aggregateKey");
  assertCommerceId(record.subscriptionId, "subscription", "subscriptionId");
  assertCommerceId(record.meterId, "meter", "meterId");
  requireCommerceIdentifier(record.unit, "unit");
  assertDecimalString(record.quantity, "quantity");
  normalizePeriod(record.periodStart, record.periodEnd);
  if (!Array.isArray(record.eventIds)) throw commerceValidationError("Usage aggregate eventIds are invalid", "eventIds");
  record.eventIds.forEach((id) => assertCommerceId(id, "usageEvent", "eventIds"));
  return record;
}

function normalizeListing(record: MarketplaceListing, tenantId: string): MarketplaceListing {
  assertCommerceId(record.id, "marketplaceListing", "id");
  normalizeCommerceTenantId(record.tenantId);
  if (record.tenantId !== tenantId || record.kind !== "marketplaceListing") throw commerceValidationError("Listing scope is invalid", "tenantId");
  assertCommerceId(record.partnerAccountId, "partnerAccount", "partnerAccountId");
  requireCommerceIdentifier(record.productId, "productId");
  requireCommerceText(record.title, "title", 200);
  requireCommerceText(record.description, "description", 4000);
  validateIdList(record.priceIds, "price", "priceIds");
  validateIdList(record.commissionRuleIds, "commissionRule", "commissionRuleIds");
  return record;
}

function normalizePartnerAccount(record: PartnerAccount, tenantId: string): PartnerAccount {
  assertCommerceId(record.id, "partnerAccount", "id");
  normalizeCommerceTenantId(record.tenantId);
  if (record.tenantId !== tenantId || record.kind !== "partnerAccount") throw commerceValidationError("Partner account scope is invalid", "tenantId");
  requireCommerceText(record.legalName, "legalName", 200);
  requireCommerceCode(record.partnerCode, "partnerCode");
  if (record.currency !== "CNY") throw commerceValidationError("Only CNY partner accounts are supported", "currency");
  requireCommerceIdentifier(record.settlementReference, "settlementReference");
  return record;
}

function normalizeCommissionRule(record: CommissionRule, tenantId: string): CommissionRule {
  assertCommerceId(record.id, "commissionRule", "id");
  normalizeCommerceTenantId(record.tenantId);
  if (record.tenantId !== tenantId || record.kind !== "commissionRule") throw commerceValidationError("Commission rule scope is invalid", "tenantId");
  assertCommerceId(record.partnerAccountId, "partnerAccount", "partnerAccountId");
  assertCommerceId(record.listingId, "marketplaceListing", "listingId");
  requireCommerceText(record.name, "name", 200);
  if (!Number.isSafeInteger(record.rateBps) || record.rateBps < 0 || record.rateBps > 10_000) throw commerceValidationError("Commission rate is invalid", "rateBps");
  if (record.capBps !== undefined && (!Number.isSafeInteger(record.capBps) || record.capBps < 0 || record.capBps > 10_000)) throw commerceValidationError("Commission cap is invalid", "capBps");
  if (record.capAmount !== undefined) assertMoney(record.capAmount, "capAmount");
  if (!Number.isSafeInteger(record.priority) || record.priority < 0) throw commerceValidationError("Commission priority is invalid", "priority");
  if (record.effectiveTo !== undefined && Date.parse(record.effectiveTo) <= Date.parse(record.effectiveFrom)) throw commerceValidationError("Commerce effective range is invalid", "effectiveTo");
  return record;
}

function normalizeUsageEvent(event: UsageEvent, tenantId: string): UsageEvent {
  if (event === null || typeof event !== "object") throw commerceValidationError("Usage event is invalid");
  assertCommerceId(event.id, "usageEvent", "id");
  normalizeCommerceTenantId(event.tenantId);
  if (event.tenantId !== tenantId || event.kind !== "usageEvent" || event.version !== 1) throw commerceValidationError("Usage event identity is invalid");
  requireCommerceIdentifier(event.sourceEventId, "sourceEventId");
  assertCommerceId(event.subscriptionId, "subscription", "subscriptionId");
  assertCommerceId(event.meterId, "meter", "meterId");
  assertDecimalString(event.quantity, "quantity", false);
  normalizeIdempotencyKey(event.idempotencyKey);
  if (normalizeCommerceTimestamp(event.occurredAt, "occurredAt") !== event.occurredAt || normalizeCommerceTimestamp(event.receivedAt, "receivedAt") !== event.receivedAt) throw commerceValidationError("Usage event timestamp is not canonical", "occurredAt");
  if (!/^[a-f0-9]{64}$/u.test(event.requestHash) || !/^[a-f0-9]{64}$/u.test(event.payloadHash)) throw commerceValidationError("Usage event hash is invalid", "requestHash");
  const period = normalizePeriod(event.periodStart, event.periodEnd);
  if (period.periodStart !== event.periodStart || period.periodEnd !== event.periodEnd) throw commerceValidationError("Usage period is invalid", "periodStart");
  return event;
}

function normalizeInvoice(invoice: Invoice, tenantId: string): Invoice {
  if (invoice === null || typeof invoice !== "object" || invoice.kind !== "invoice") throw commerceValidationError("Invoice is invalid");
  assertCommerceId(invoice.id, "invoice", "id");
  normalizeCommerceTenantId(invoice.tenantId);
  if (invoice.tenantId !== tenantId) throw commerceValidationError("Invoice tenant scope is invalid", "tenantId");
  assertCommerceId(invoice.subscriptionId, "subscription", "subscriptionId");
  assertCommerceId(invoice.planId, "plan", "planId");
  normalizeIdempotencyKey(invoice.idempotencyKey);
  if (!/^[a-f0-9]{64}$/u.test(invoice.requestHash)) throw commerceValidationError("Invoice request hash is invalid", "requestHash");
  normalizePeriod(invoice.periodStart, invoice.periodEnd);
  if (invoice.currency !== "CNY" || invoice.subtotal.currency !== "CNY" || invoice.tax.currency !== "CNY" || invoice.total.currency !== "CNY") throw commerceValidationError("Invoices require CNY", "currency");
  if (!Array.isArray(invoice.lines)) throw commerceValidationError("Invoice lines are invalid", "lines");
  const lineIds = new Set<string>();
  for (const line of invoice.lines) {
    if (line.tenantId !== invoice.tenantId || line.invoiceId !== invoice.id) throw commerceValidationError("Invoice line scope is invalid", "tenantId");
    normalizeInvoiceLine(line, invoice.tenantId);
    if (!["subscription", "usage", "adjustment", "tax"].includes(line.type)) throw commerceValidationError("Invoice line type is invalid", "type");
    if (lineIds.has(line.id)) throw commerceValidationError("Invoice line identifier is duplicated", "id");
    lineIds.add(line.id);
  }
  const nonTaxTotal = invoice.lines
    .filter((line) => line.type !== "tax")
    .reduce((total, line) => total + (line.direction === "debit" ? BigInt(line.amount.amountMinor) : -BigInt(line.amount.amountMinor)), 0n);
  const taxLineTotal = invoice.lines
    .filter((line) => line.type === "tax")
    .reduce((total, line) => total + BigInt(line.amount.amountMinor), 0n);
  const expectedSubtotal = invoice.taxMode === "inclusive"
    ? BigInt(invoice.subtotal.amountMinor) + BigInt(invoice.tax.amountMinor)
    : BigInt(invoice.subtotal.amountMinor);
  const expectedTotal = invoice.taxMode === "inclusive"
    ? BigInt(invoice.subtotal.amountMinor)
    : BigInt(invoice.subtotal.amountMinor) + BigInt(invoice.tax.amountMinor);
  if ((invoice.taxMode !== "inclusive" && invoice.taxMode !== "exclusive") || nonTaxTotal !== expectedSubtotal || taxLineTotal !== BigInt(invoice.tax.amountMinor) || BigInt(invoice.total.amountMinor) !== expectedTotal) {
    throw commerceInvalidTotal("Invoice totals do not match invoice lines");
  }
  if (invoice.mainlandChina !== undefined) {
    normalizeMainlandChinaInvoiceMetadata(
      invoice.mainlandChina,
      invoice.mainlandChina.taxRateBps,
    );
  }
  if (!Number.isSafeInteger(invoice.version) || invoice.version < 1) throw commerceValidationError("Invoice version is invalid", "version");
  return invoice;
}

function normalizeInvoiceLine(line: InvoiceLine, tenantId: string): InvoiceLine {
  if (line === null || typeof line !== "object" || line.kind !== "invoiceLine") throw commerceValidationError("Invoice line is invalid");
  assertCommerceId(line.id, "invoiceLine", "id");
  normalizeCommerceTenantId(line.tenantId);
  if (line.tenantId !== tenantId) throw commerceValidationError("Invoice line tenant scope is invalid", "tenantId");
  assertCommerceId(line.invoiceId, "invoice", "invoiceId");
  assertDecimalString(line.quantity, "quantity");
  assertMoney(line.unitAmount, "unitAmount");
  assertMoney(line.amount, "amount");
  if (line.unitAmount.currency !== "CNY" || line.amount.currency !== "CNY") throw commerceValidationError("Invoice line currency is invalid", "currency");
  if (line.direction !== "debit" && line.direction !== "credit") throw commerceValidationError("Invoice line direction is invalid", "direction");
  return line;
}

function normalizeInvoiceDispute(
  dispute: InvoiceDispute,
  tenantId: string,
): InvoiceDispute {
  if (dispute === null || typeof dispute !== "object") {
    throw commerceValidationError("Invoice dispute is invalid");
  }
  assertCommerceId(dispute.id, "invoiceDispute", "id");
  normalizeCommerceTenantId(dispute.tenantId);
  if (
    dispute.tenantId !== tenantId ||
    dispute.kind !== "invoiceDispute" ||
    !Number.isSafeInteger(dispute.version) ||
    dispute.version < 1
  ) {
    throw commerceValidationError("Invoice dispute identity is invalid", "tenantId");
  }
  assertCommerceId(dispute.invoiceId, "invoice", "invoiceId");
  assertCommerceId(dispute.subscriptionId, "subscription", "subscriptionId");
  assertCommerceId(dispute.planId, "plan", "planId");
  if (!INVOICE_DISPUTE_EVENTS.includes(dispute.event)) {
    throw commerceValidationError("Invoice dispute event is invalid", "event");
  }
  requireCommerceDisputeReason(dispute.reason);
  assertCommerceDisputeHash(dispute.reasonDigest, "reasonDigest");
  if (
    !Number.isSafeInteger(dispute.reasonLength) ||
    dispute.reasonLength !== dispute.reason.length
  ) {
    throw commerceValidationError("Invoice dispute reason length is invalid", "reasonLength");
  }
  if (dispute.evidenceReference !== undefined) {
    requireCommerceEvidenceReference(dispute.evidenceReference);
    assertCommerceDisputeHash(dispute.evidenceReferenceDigest, "evidenceReferenceDigest");
  } else if (dispute.evidenceReferenceDigest !== undefined) {
    throw commerceValidationError(
      "Invoice dispute evidence digest is invalid",
      "evidenceReferenceDigest",
    );
  }
  if (
    !Number.isSafeInteger(dispute.evidenceCount) ||
    dispute.evidenceCount !== (dispute.evidenceReference === undefined ? 0 : 1)
  ) {
    throw commerceValidationError("Invoice dispute evidence count is invalid", "evidenceCount");
  }
  requireCommerceIdentifier(dispute.actorId, "actorId");
  requireCommerceIdentifier(dispute.requestId, "requestId");
  normalizeIdempotencyKey(dispute.idempotencyKey);
  assertCommerceDisputeHash(dispute.requestHash, "requestHash");
  if (!INVOICE_STATUSES.includes(dispute.invoiceStatus)) {
    throw commerceValidationError("Invoice dispute invoice status is invalid", "invoiceStatus");
  }
  if (!Number.isSafeInteger(dispute.invoiceVersion) || dispute.invoiceVersion < 1) {
    throw commerceValidationError("Invoice dispute invoice version is invalid", "invoiceVersion");
  }
  if (!INVOICE_DISPUTE_STATUSES.includes(dispute.status)) {
    throw commerceValidationError("Invoice dispute status is invalid", "status");
  }
  assertInvoiceDisputeResolution(dispute);
  if (
    normalizeCommerceTimestamp(dispute.createdAt, "createdAt") !== dispute.createdAt ||
    normalizeCommerceTimestamp(dispute.updatedAt, "updatedAt") !== dispute.updatedAt ||
    normalizeCommerceTimestamp(dispute.recordedAt, "recordedAt") !== dispute.recordedAt ||
    Date.parse(dispute.recordedAt) < Date.parse(dispute.createdAt) ||
    Date.parse(dispute.updatedAt) < Date.parse(dispute.createdAt)
  ) {
    throw commerceValidationError("Invoice dispute timestamps are invalid", "createdAt");
  }
  return cloneCommerceValue(dispute);
}

function normalizeInvoiceDisputeDecision(
  decision: InvoiceDisputeDecision,
): InvoiceDisputeDecision {
  if (decision === null || typeof decision !== "object") {
    throw commerceValidationError("Invoice dispute decision is invalid");
  }
  if (!INVOICE_DISPUTE_STATUSES.includes(decision.targetStatus)) {
    throw commerceValidationError(
      "Invoice dispute decision target status is invalid",
      "targetStatus",
    );
  }
  if (
    !Number.isSafeInteger(decision.expectedVersion) ||
    decision.expectedVersion < 1
  ) {
    throw commerceValidationError(
      "Invoice dispute decision version is invalid",
      "expectedVersion",
    );
  }
  requireCommerceIdentifier(decision.decidedBy, "decidedBy");
  const decidedAt = normalizeCommerceTimestamp(decision.decidedAt, "decidedAt");
  if (decidedAt !== decision.decidedAt) {
    throw commerceValidationError(
      "Invoice dispute decision time is invalid",
      "decidedAt",
    );
  }
  const terminal = (INVOICE_DISPUTE_OUTCOMES as readonly InvoiceDisputeStatus[])
    .includes(decision.targetStatus);
  if (terminal && decision.reference === undefined) {
    throw commerceValidationError(
      "Invoice dispute decision reference is required",
      "reference",
    );
  }
  return {
    targetStatus: decision.targetStatus,
    expectedVersion: decision.expectedVersion,
    decidedBy: decision.decidedBy,
    decidedAt,
    ...(decision.reference === undefined
      ? {}
      : { reference: requireCommerceEvidenceReference(decision.reference) }),
    ...(decision.resolutionNote === undefined
      ? {}
      : {
          resolutionNote: requireCommerceDisputeResolutionNote(
            decision.resolutionNote,
          ),
        }),
  };
}

function assertInvoiceDisputeResolution(dispute: InvoiceDispute): void {
  if (dispute.resolution === undefined) {
    if (
      dispute.resolvedAt !== undefined ||
      (dispute.status !== "open" && dispute.status !== "underReview")
    ) {
      throw commerceValidationError("Invoice dispute resolution is invalid", "resolution");
    }
    return;
  }
  const resolution = dispute.resolution;
  if (resolution === null || typeof resolution !== "object") {
    throw commerceValidationError("Invoice dispute resolution is invalid", "resolution");
  }
  if (!INVOICE_DISPUTE_OUTCOMES.includes(resolution.outcome)) {
    throw commerceValidationError("Invoice dispute resolution outcome is invalid", "resolution");
  }
  requireCommerceIdentifier(resolution.actorId, "resolution.actorId");
  const reference = requireCommerceEvidenceReference(resolution.reference);
  assertCommerceHasNoSensitiveValue(reference, "resolution.reference");
  if (resolution.note !== undefined) {
    requireCommerceDisputeResolutionNote(resolution.note);
  }
  if (
    resolution.noteLength !== undefined
      ? !Number.isSafeInteger(resolution.noteLength) ||
        resolution.noteLength !== (resolution.note ?? "").length
      : resolution.note !== undefined
  ) {
    throw commerceValidationError(
      "Invoice dispute resolution note length is invalid",
      "resolution.noteLength",
    );
  }
  if (
    resolution.fromStatus !== undefined &&
    !INVOICE_DISPUTE_STATUSES.includes(resolution.fromStatus)
  ) {
    throw commerceValidationError(
      "Invoice dispute resolution origin status is invalid",
      "resolution.fromStatus",
    );
  }
  if (
    normalizeCommerceTimestamp(resolution.resolvedAt, "resolvedAt") !== resolution.resolvedAt ||
    dispute.resolvedAt !== resolution.resolvedAt ||
    dispute.status !== resolution.outcome ||
    Date.parse(resolution.resolvedAt) < Date.parse(dispute.createdAt)
  ) {
    throw commerceValidationError(
      "Invoice dispute resolution timestamp is invalid",
      "resolvedAt",
    );
  }
}

function assertCommerceDisputeHash(value: unknown, field: string): void {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/u.test(value)) {
    throw commerceValidationError("Invoice dispute hash is invalid", field);
  }
}

function normalizeInvoiceDisputeListQuery(
  value: InvoiceDisputeListQuery,
): InvoiceDisputeListQuery & { readonly limit: number } {
  const input = value ?? {};
  if (
    input.status !== undefined &&
    (typeof input.status !== "string" ||
      !(INVOICE_DISPUTE_STATUSES as readonly string[]).includes(input.status))
  ) {
    throw commerceValidationError("Invoice dispute status filter is invalid", "status");
  }
  const from = input.from === undefined
    ? undefined
    : normalizeCommerceTimestamp(input.from, "from");
  const to = input.to === undefined
    ? undefined
    : normalizeCommerceTimestamp(input.to, "to");
  if (from !== undefined && to !== undefined && Date.parse(from) > Date.parse(to)) {
    throw commerceValidationError("Invoice dispute date range is invalid", "to");
  }
  return {
    limit: normalizeCommerceLimit(input.limit),
    ...(input.invoiceId === undefined
      ? {}
      : { invoiceId: assertCommerceId(input.invoiceId, "invoice", "invoiceId") }),
    ...(input.actorId === undefined
      ? {}
      : { actorId: requireCommerceIdentifier(input.actorId, "actorId") }),
    ...(input.status === undefined ? {} : { status: input.status }),
    ...(from === undefined ? {} : { from }),
    ...(to === undefined ? {} : { to }),
  };
}

function validateIdList(values: readonly string[], kind: CommerceEntityKind, field: string): void {
  if (!Array.isArray(values)) throw commerceValidationError("Commerce identifier list is invalid", field);
  values.forEach((value) => assertCommerceId(value, kind, field));
}

function readTiers(value: unknown, currency: "CNY"): PriceTier[] {
  const parsed = readJson(value);
  if (!Array.isArray(parsed)) throw new Error("Invalid commerce price tiers SQL row");
  return parsed.map((item) => {
    if (!isRecord(item)) throw new Error("Invalid commerce price tier SQL row");
    const upTo = item.upTo;
    const unitAmount = item.unitAmount;
    if (!isRecord(unitAmount)) throw new Error("Invalid commerce price tier amount SQL row");
    return {
      upTo: upTo === null ? null : readRequiredDecimalString(upTo, "price.tiers.upTo"),
      unitAmount: readMoney(unitAmount.amountMinor, currency, "price.tiers.unitAmountMinor"),
    };
  });
}

function readDimensions(value: unknown, field: string): Record<string, string> {
  const parsed = readJson(value);
  if (!isRecord(parsed)) throw new Error(`Invalid commerce dimensions SQL row: ${field}`);
  const output: Record<string, string> = {};
  for (const [key, item] of Object.entries(parsed)) {
    if (typeof item !== "string") throw new Error(`Invalid commerce dimensions SQL row: ${field}`);
    output[key] = item;
  }
  return output;
}

function readBooleanValue(value: unknown, field: string): boolean {
  if (value === true || value === "true" || value === 1 || value === "1") return true;
  if (value === false || value === "false" || value === 0 || value === "0") return false;
  throw new Error(`Invalid commerce boolean SQL row: ${field}`);
}

function statusValue<T extends string>(value: unknown, allowed: readonly string[], field: string): StatusValue<T> {
  const text = readRequiredText(value, field);
  if (!allowed.includes(text)) throw new Error(`Invalid commerce SQL row: ${field}`);
  return text as T;
}

function optionalText(field: string, value: unknown): Record<string, string> {
  const text = typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
  return text === undefined ? {} : { [field]: text };
}

function optionalDate(field: string, value: unknown): Record<string, string> {
  const date = readOptionalDate(value);
  return date === undefined ? {} : { [field]: date };
}

function immutableProjection(record: CommerceRecord): unknown {
  switch (record.kind) {
    case "plan": {
      const { status: _status, version: _version, updatedAt: _updatedAt, ...rest } = record;
      return rest;
    }
    case "entitlement": {
      const { status: _status, version: _version, updatedAt: _updatedAt, ...rest } = record;
      return rest;
    }
    case "meter": {
      const { status: _status, version: _version, updatedAt: _updatedAt, ...rest } = record;
      return rest;
    }
    case "price": {
      const { status: _status, version: _version, updatedAt: _updatedAt, ...rest } = record;
      return rest;
    }
    case "subscription": {
      const { status: _status, version: _version, updatedAt: _updatedAt, cancelAtPeriodEnd: _cancel, canceledAt: _canceled, ...rest } = record;
      return rest;
    }
    case "quota": {
      const { status: _status, version: _version, updatedAt: _updatedAt, reserved: _reserved, consumed: _consumed, ...rest } = record;
      return rest;
    }
    case "quotaReservation": {
      const { status: _status, version: _version, updatedAt: _updatedAt, settledQuantity: _settledQuantity, settledAt: _settledAt, releasedAt: _releasedAt, terminalOperation: _terminal, terminalIdempotencyKey: _terminalKey, terminalRequestHash: _terminalHash, ...rest } = record;
      return rest;
    }
    case "usageAggregate":
      return {
        id: record.id,
        tenantId: record.tenantId,
        kind: record.kind,
        createdAt: record.createdAt,
        aggregateKey: record.aggregateKey,
        subscriptionId: record.subscriptionId,
        meterId: record.meterId,
        aggregation: record.aggregation,
        unit: record.unit,
        periodStart: record.periodStart,
        periodEnd: record.periodEnd,
        dimensions: record.dimensions,
      };
    case "marketplaceListing": {
      const { status: _status, version: _version, updatedAt: _updatedAt, submittedAt: _submitted, publishedAt: _published, removedAt: _removed, ...rest } = record;
      return rest;
    }
    case "partnerAccount": {
      const { status: _status, version: _version, updatedAt: _updatedAt, activatedAt: _activated, ...rest } = record;
      return rest;
    }
    case "commissionRule": {
      const { status: _status, version: _version, updatedAt: _updatedAt, ...rest } = record;
      return rest;
    }
  }
}

function sameStringArray(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function stableSerialize(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => stableSerialize(item)).join(",")}]`;
  return `{${Object.entries(value as Record<string, unknown>).sort(([left], [right]) => left.localeCompare(right)).map(([key, item]) => `${JSON.stringify(key)}:${stableSerialize(item)}`).join(",")}}`;
}

