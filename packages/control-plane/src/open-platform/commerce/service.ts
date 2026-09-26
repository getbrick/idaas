import { randomUUID } from "node:crypto";
import {
  commerceEntitlementDenied,
  commerceIdempotencyKeyReused,
  commerceInvalidTotal,
  commerceNegativeAmount,
  commerceResourceConflict,
  commerceResourceNotFound,
  commerceStorageUnavailable,
  commerceValidationError,
  isOpenPlatformCommerceError,
  normalizeCommerceCalculationError,
  OPEN_PLATFORM_COMMERCE_ERROR_CODES,
} from "./errors.js";
import type {
  OpenPlatformDomainEventDescriptor,
  OpenPlatformDomainEventFactory,
  OpenPlatformEventPublisherPort,
} from "../events.js";
import {
  commerceCreatedDomainEventFactory,
  commerceDisputeDecidedEvent,
  commerceDisputeOpenedEvent,
  commerceDisputeStatusChangedEvent,
  commerceDomainEventId,
  commerceStatusChangedDomainEventFactory,
} from "./events.js";
import type {
  CommerceAuditPort,
  CommerceAuditResourceType,
} from "./audit.js";
import { COMMERCE_AUDIT_RESOURCE_TYPES } from "./audit.js";
import {
  addDecimalStrings,
  addMoney,
  assertDecimalString,
  assertMoney,
  compareDecimalStrings,
  extractInclusiveTax,
  isZeroDecimalString,
  maxDecimalStrings,
  multiplyMoneyByBasisPoints,
  normalizeDecimalString,
  subtractDecimalStrings,
  subtractMoney,
  zeroMoney,
} from "./money.js";
import {
  calculateMarketplaceCommission,
  calculatePrice,
} from "./pricing.js";
import {
  assertCommissionRuleTransition,
  assertEntitlementTransition,
  assertInvoiceTransition,
  assertMarketplaceListingTransition,
  assertMeterTransition,
  assertPartnerAccountTransition,
  assertPlanTransition,
  assertPriceTransition,
  assertQuotaTransition,
  assertSubscriptionTransition,
  assertUsageAggregateTransition,
} from "./state-machine.js";
import type {
  AggregateUsageCommand,
  AggregateUsageResult,
  BillingAccountView,
  CalculateCommissionCommand,
  CalculatePlanPriceCommand,
  CalculatePriceCommand,
  CommissionCalculation,
  CommissionRule,
  CommissionRuleQuery,
  CommissionRuleStatus,
  CommissionRuleView,
  CommercePage,
  CommerceResourceGetQuery,
  CommerceTransitionResult,
  CreateCommissionRuleCommand,
  CreateMarketplaceListingCommand,
  CreateMeterCommand,
  CreatePartnerAccountCommand,
  CreatePlanCommand,
  CreatePriceCommand,
  CreateQuotaCommand,
  CreateSubscriptionCommand,
  DecimalString,
  Entitlement,
  EntitlementResolution,
  EntitlementStatus,
  GenerateInvoiceCommand,
  GenerateInvoiceResult,
  GrantEntitlementCommand,
  DisputeInvoiceCommand,
  DisputeInvoiceResult,
  DecideInvoiceDisputeCommand,
  Invoice,
  InvoiceAdjustment,
  InvoiceDispute,
  InvoiceDisputeQuery,
  InvoiceDisputeResult,
  InvoiceDisputeStatus,
  InvoiceDisputeView,
  InvoiceLine,
  InvoiceQuery,
  InvoiceService,
  InvoiceStatus,
  InvoiceView,
  MarketplaceListing,
  MarketplaceListingQuery,
  MarketplaceListingStatus,
  MarketplaceListingView,
  MarketplaceService,
  Meter,
  MeterStatus,
  PartnerAccount,
  PartnerAccountQuery,
  PartnerAccountStatus,
  PartnerAccountView,
  Plan,
  PlanPriceCalculation,
  PlanStatus,
  Price,
  PriceCalculation,
  PriceStatus,
  PriceTier,
  PricingService,
  Quota,
  QuotaOperationResult,
  QuotaReservation,
  QuotaService,
  RecordUsageEventCommand,
  RecordUsageEventResult,
  ReleaseQuotaCommand,
  ReserveQuotaCommand,
  ReserveQuotaResult,
  ResolveEntitlementsQuery,
  ResolveEntitlementsResult,
  ReviewInvoiceDisputeCommand,
  SettleQuotaCommand,
  Subscription,
  SubscriptionStatus,
  TransitionCommerceResourceCommand,
  UsageAggregate,
  UsageAggregateStatus,
  UsageEvent,
  WithdrawInvoiceDisputeCommand,
} from "./types.js";
import type {
  CommerceEntityKind,
  CommerceDependencyReadiness,
  CommerceReadiness,
  CommerceRecord,
  CommerceRepositories,
  CommerceService,
  EntitlementService,
  UsageAggregationService,
} from "./types.js";
import {
  COMMERCE_MAX_PAGE_SIZE,
  INVOICE_DISPUTE_EVENTS,
  INVOICE_DISPUTE_OUTCOMES,
} from "./types.js";
import { InMemoryCommerceRepositories } from "./repositories.js";
import {
  toCommerceBillingAccountView,
  toCommerceCommissionRuleView,
  toCommerceInvoiceDisputeView,
  toCommerceInvoiceView,
  toCommerceMarketplaceListingView,
  toCommercePartnerAccountView,
} from "./read.js";
import {
  assertCommerceId,
  cloneCommerceValue,
  decodeCommerceCursor,
  encodeCommerceCursor,
  hashCommerceRequest,
  isEffectiveAt,
  normalizeCommissionRuleQuery,
  normalizeCommercePageQuery,
  normalizeCommerceTenantId,
  normalizeCommerceTimestamp,
  normalizeDecimal,
  normalizeDimensions,
  normalizeIdempotencyKey,
  normalizeInteger,
  normalizeInvoiceDisputeQuery,
  normalizeInvoiceQuery,
  normalizeMainlandChinaInvoiceMetadata,
  normalizeMarketplaceListingQuery,
  normalizeMoney,
  normalizePartnerAccountQuery,
  normalizePeriod,
  requireCommerceCode,
  requireCommerceDisputeReason,
  requireCommerceDisputeResolutionNote,
  requireCommerceEvidenceReference,
  requireCommerceIdentifier,
  requireCommerceText,
  requireEffectiveRange,
  sameStringSet,
} from "./validation.js";
import {
  COMMERCE_IDEMPOTENCY_SERVICE_ACTOR,
  InMemoryCommerceIdempotencyStore,
  commerceIdempotencyScopeKey,
  normalizeCommerceIdempotencyScope,
  type CommerceIdempotencyPort,
  type CommerceIdempotencyScope,
} from "./idempotency.js";

export interface CommerceServiceOptions {
  readonly repositories?: CommerceRepositories;
  readonly clock?: () => Date;
  readonly idGenerator?: (
    kind: CommerceEntityKind | "invoice" | "invoiceLine" | "usageEvent" | "invoiceDispute",
  ) => string;
  readonly production?: boolean;
  readonly idempotency?: CommerceIdempotencyPort;
  readonly idempotencyRetentionMs?: number;
  readonly idempotencyMaxEntries?: number;
  readonly eventPublisher?: OpenPlatformEventPublisherPort;
  readonly eventsEnabled?: boolean;
  readonly audit?: CommerceAuditPort;
}

export interface CommerceDomainEventScope {
  readonly tenantId: string;
  readonly actorId: string;
  readonly operation: string;
  readonly idempotencyKey: string;
  readonly requestId?: string;
}

const MONTH_MILLISECONDS = 31_584_000_000;
const INVOICE_DISPUTE_OPENED_EVENT = INVOICE_DISPUTE_EVENTS[0];

export class CommerceDomainService implements CommerceService {
  readonly repositories: CommerceRepositories;
  readonly idempotency: CommerceIdempotencyPort;
  readonly eventPublisher: OpenPlatformEventPublisherPort | undefined;
  private readonly clock: () => Date;
  private readonly idGenerator: (
    kind: CommerceEntityKind | "invoice" | "invoiceLine" | "usageEvent" | "invoiceDispute",
  ) => string;
  private readonly idempotencyLocks = new Map<string, Promise<void>>();
  private readonly production: boolean;
  private readonly eventsEnabled: boolean;
  private readonly audit: CommerceAuditPort | undefined;

  constructor(options: CommerceServiceOptions = {}) {
    this.clock = options.clock ?? (() => new Date());
    this.idGenerator = options.idGenerator ?? ((kind) => commerceId(kind));
    this.production = options.production === true;
    this.eventPublisher = options.eventPublisher;
    this.eventsEnabled = this.eventPublisher !== undefined &&
      options.eventsEnabled !== false;
    this.audit = options.audit;
    this.repositories = options.repositories ?? new InMemoryCommerceRepositories({
      production: options.production,
    });
    this.idempotency = options.idempotency ?? new InMemoryCommerceIdempotencyStore({
      ...(options.clock === undefined ? {} : { clock: options.clock }),
      ...(options.idempotencyRetentionMs === undefined
        ? {}
        : { retentionMs: options.idempotencyRetentionMs }),
      ...(options.idempotencyMaxEntries === undefined
        ? {}
        : { maxEntries: options.idempotencyMaxEntries }),
      production: options.production,
    });
  }

  async isReady(): Promise<CommerceReadiness> {
    const [repositoriesReady, idempotencyReady, eventsReady] = await Promise.all([
      safeCommerceReadiness(this.repositories.readiness),
      safeCommerceReadiness(this.idempotency.readiness),
      this.eventsOperationalReady(),
    ]);
    return {
      ready: repositoriesReady && idempotencyReady && eventsReady,
      storage: this.repositories.readiness.storage === "persistent" &&
        this.idempotency.readiness?.storage === "persistent"
        ? "persistent"
        : "memory",
      distributed: this.repositories.readiness.distributed &&
        (this.idempotency.readiness?.distributed ?? false),
    };
  }

  listMarketplaceListings(
    query: MarketplaceListingQuery,
  ): Promise<CommercePage<MarketplaceListingView>>;
  listMarketplaceListings(
    tenantId: string,
    query?: Omit<MarketplaceListingQuery, "tenantId">,
  ): Promise<CommercePage<MarketplaceListingView>>;
  async listMarketplaceListings(
    queryOrTenant: MarketplaceListingQuery | string,
    options: Omit<MarketplaceListingQuery, "tenantId"> = {},
  ): Promise<CommercePage<MarketplaceListingView>> {
    const query = typeof queryOrTenant === "string"
      ? { tenantId: queryOrTenant, ...options }
      : queryOrTenant;
    const normalized = normalizeMarketplaceListingQuery(query);
    const records = (await this.repositories.marketplaceListings.list(normalized.tenantId))
      .filter((record) => record.kind === "marketplaceListing")
      .filter((record) => record.tenantId === normalized.tenantId)
      .filter((record) => normalized.id === undefined || record.id === normalized.id)
      .filter((record) => normalized.status === undefined || record.status === normalized.status)
      .filter((record) => normalized.partnerAccountId === undefined || record.partnerAccountId === normalized.partnerAccountId)
      .filter((record) => normalized.productId === undefined || record.productId === normalized.productId)
      .filter((record) => normalized.search === undefined || listingMatchesSearch(record, normalized.search));
    return this.pageCommerceRecords(
      records,
      normalized,
      "marketplaceListing",
      commerceQueryScope("marketplaceListing", normalized),
      toCommerceMarketplaceListingView,
    );
  }

  getMarketplaceListing(
    query: CommerceResourceGetQuery,
  ): Promise<MarketplaceListingView>;
  getMarketplaceListing(
    tenantId: string,
    id: string,
  ): Promise<MarketplaceListingView>;
  async getMarketplaceListing(
    queryOrTenant: CommerceResourceGetQuery | string,
    id?: string,
  ): Promise<MarketplaceListingView> {
    const query = typeof queryOrTenant === "string"
      ? { tenantId: queryOrTenant, id: id ?? "" }
      : queryOrTenant;
    const tenantId = normalizeCommerceTenantId(query?.tenantId);
    const resourceId = assertCommerceId(query?.id, "marketplaceListing");
    const record = await this.requireListing(tenantId, resourceId);
    if (record.kind !== "marketplaceListing" || record.tenantId !== tenantId) {
      throw commerceResourceNotFound("marketplaceListing");
    }
    return toCommerceMarketplaceListingView(record);
  }

  listPartnerAccounts(
    query: PartnerAccountQuery,
  ): Promise<CommercePage<PartnerAccountView>>;
  listPartnerAccounts(
    tenantId: string,
    query?: Omit<PartnerAccountQuery, "tenantId">,
  ): Promise<CommercePage<PartnerAccountView>>;
  async listPartnerAccounts(
    queryOrTenant: PartnerAccountQuery | string,
    options: Omit<PartnerAccountQuery, "tenantId"> = {},
  ): Promise<CommercePage<PartnerAccountView>> {
    const query = typeof queryOrTenant === "string"
      ? { tenantId: queryOrTenant, ...options }
      : queryOrTenant;
    const normalized = normalizePartnerAccountQuery(query);
    const records = (await this.repositories.partnerAccounts.list(normalized.tenantId))
      .filter((record) => record.kind === "partnerAccount")
      .filter((record) => record.tenantId === normalized.tenantId)
      .filter((record) => normalized.id === undefined || record.id === normalized.id)
      .filter((record) => normalized.status === undefined || record.status === normalized.status)
      .filter((record) => normalized.partnerCode === undefined || record.partnerCode === normalized.partnerCode)
      .filter((record) => normalized.search === undefined || partnerMatchesSearch(record, normalized.search));
    return this.pageCommerceRecords(
      records,
      normalized,
      "partnerAccount",
      commerceQueryScope("partnerAccount", normalized),
      toCommercePartnerAccountView,
    );
  }

  getPartnerAccount(
    query: CommerceResourceGetQuery,
  ): Promise<PartnerAccountView>;
  getPartnerAccount(
    tenantId: string,
    id: string,
  ): Promise<PartnerAccountView>;
  async getPartnerAccount(
    queryOrTenant: CommerceResourceGetQuery | string,
    id?: string,
  ): Promise<PartnerAccountView> {
    const query = typeof queryOrTenant === "string"
      ? { tenantId: queryOrTenant, id: id ?? "" }
      : queryOrTenant;
    const tenantId = normalizeCommerceTenantId(query?.tenantId);
    const resourceId = assertCommerceId(query?.id, "partnerAccount");
    const record = await this.requirePartnerAccount(tenantId, resourceId);
    if (record.kind !== "partnerAccount" || record.tenantId !== tenantId) {
      throw commerceResourceNotFound("partnerAccount");
    }
    return toCommercePartnerAccountView(record);
  }

  listCommissionRules(
    query: CommissionRuleQuery,
  ): Promise<CommercePage<CommissionRuleView>>;
  listCommissionRules(
    tenantId: string,
    query?: Omit<CommissionRuleQuery, "tenantId">,
  ): Promise<CommercePage<CommissionRuleView>>;
  async listCommissionRules(
    queryOrTenant: CommissionRuleQuery | string,
    options: Omit<CommissionRuleQuery, "tenantId"> = {},
  ): Promise<CommercePage<CommissionRuleView>> {
    const query = typeof queryOrTenant === "string"
      ? { tenantId: queryOrTenant, ...options }
      : queryOrTenant;
    const normalized = normalizeCommissionRuleQuery(query);
    const records = (await this.repositories.commissionRules.list(normalized.tenantId))
      .filter((record) => record.kind === "commissionRule")
      .filter((record) => record.tenantId === normalized.tenantId)
      .filter((record) => normalized.id === undefined || record.id === normalized.id)
      .filter((record) => normalized.listingId === undefined || record.listingId === normalized.listingId)
      .filter((record) => normalized.partnerAccountId === undefined || record.partnerAccountId === normalized.partnerAccountId)
      .filter((record) => normalized.status === undefined || record.status === normalized.status);
    return this.pageCommerceRecords(
      records,
      normalized,
      "commissionRule",
      commerceQueryScope("commissionRule", normalized),
      toCommerceCommissionRuleView,
    );
  }

  getCommissionRule(
    query: CommerceResourceGetQuery,
  ): Promise<CommissionRuleView>;
  getCommissionRule(
    tenantId: string,
    id: string,
  ): Promise<CommissionRuleView>;
  async getCommissionRule(
    queryOrTenant: CommerceResourceGetQuery | string,
    id?: string,
  ): Promise<CommissionRuleView> {
    const query = typeof queryOrTenant === "string"
      ? { tenantId: queryOrTenant, id: id ?? "" }
      : queryOrTenant;
    const tenantId = normalizeCommerceTenantId(query?.tenantId);
    const resourceId = assertCommerceId(query?.id, "commissionRule");
    const record = await this.requireCommissionRule(tenantId, resourceId);
    if (record.kind !== "commissionRule" || record.tenantId !== tenantId) {
      throw commerceResourceNotFound("commissionRule");
    }
    return toCommerceCommissionRuleView(record);
  }

  listInvoices(
    query: InvoiceQuery,
  ): Promise<CommercePage<InvoiceView>>;
  listInvoices(
    tenantId: string,
    query?: Omit<InvoiceQuery, "tenantId">,
  ): Promise<CommercePage<InvoiceView>>;
  async listInvoices(
    queryOrTenant: InvoiceQuery | string,
    options: Omit<InvoiceQuery, "tenantId"> = {},
  ): Promise<CommercePage<InvoiceView>> {
    const query = typeof queryOrTenant === "string"
      ? { tenantId: queryOrTenant, ...options }
      : queryOrTenant;
    const normalized = normalizeInvoiceQuery(query);
    const records = (await this.repositories.invoices.list(normalized.tenantId))
      .filter((record) => record.kind === "invoice")
      .filter((record) => record.tenantId === normalized.tenantId)
      .filter((record) => normalized.id === undefined || record.id === normalized.id)
      .filter((record) => normalized.subscriptionId === undefined || record.subscriptionId === normalized.subscriptionId)
      .filter((record) => normalized.planId === undefined || record.planId === normalized.planId)
      .filter((record) => normalized.status === undefined || record.status === normalized.status)
      .filter((record) => normalized.periodStart === undefined || record.periodStart === normalized.periodStart)
      .filter((record) => normalized.periodEnd === undefined || record.periodEnd === normalized.periodEnd)
      .filter((record) => normalized.from === undefined || record.createdAt >= normalized.from)
      .filter((record) => normalized.to === undefined || record.createdAt <= normalized.to);
    return this.pageCommerceRecords(
      records,
      normalized,
      "invoice",
      commerceQueryScope("invoice", normalized),
      toCommerceInvoiceView,
    );
  }

  getInvoice(query: CommerceResourceGetQuery): Promise<InvoiceView>;
  getInvoice(tenantId: string, id: string): Promise<InvoiceView>;
  async getInvoice(
    queryOrTenant: CommerceResourceGetQuery | string,
    id?: string,
  ): Promise<InvoiceView> {
    const query = typeof queryOrTenant === "string"
      ? { tenantId: queryOrTenant, id: id ?? "" }
      : queryOrTenant;
    const tenantId = normalizeCommerceTenantId(query?.tenantId);
    const resourceId = assertCommerceId(query?.id, "invoice");
    const invoice = await this.repositories.invoices.get(tenantId, resourceId);
    if (
      invoice === undefined ||
      invoice.kind !== "invoice" ||
      invoice.tenantId !== tenantId ||
      invoice.id !== resourceId
    ) {
      throw commerceResourceNotFound("invoice");
    }
    return toCommerceInvoiceView(invoice);
  }

  listBillingAccounts(
    query: PartnerAccountQuery,
  ): Promise<CommercePage<BillingAccountView>>;
  listBillingAccounts(
    tenantId: string,
    query?: Omit<PartnerAccountQuery, "tenantId">,
  ): Promise<CommercePage<BillingAccountView>>;
  async listBillingAccounts(
    queryOrTenant: PartnerAccountQuery | string,
    options: Omit<PartnerAccountQuery, "tenantId"> = {},
  ): Promise<CommercePage<BillingAccountView>> {
    return typeof queryOrTenant === "string"
      ? this.listPartnerAccounts(queryOrTenant, options)
      : this.listPartnerAccounts(queryOrTenant);
  }

  getBillingAccount(
    query: CommerceResourceGetQuery,
  ): Promise<BillingAccountView>;
  getBillingAccount(
    tenantId: string,
    id: string,
  ): Promise<BillingAccountView>;
  async getBillingAccount(
    queryOrTenant: CommerceResourceGetQuery | string,
    id?: string,
  ): Promise<BillingAccountView> {
    return typeof queryOrTenant === "string"
      ? this.getPartnerAccount(queryOrTenant, id ?? "")
      : this.getPartnerAccount(queryOrTenant);
  }

  async listMarketplaceListing(
    queryOrTenant: MarketplaceListingQuery | string,
    options: Omit<MarketplaceListingQuery, "tenantId"> = {},
  ): Promise<CommercePage<MarketplaceListingView>> {
    return typeof queryOrTenant === "string"
      ? this.listMarketplaceListings(queryOrTenant, options)
      : this.listMarketplaceListings(queryOrTenant);
  }

  async listPartners(
    queryOrTenant: PartnerAccountQuery | string,
    options: Omit<PartnerAccountQuery, "tenantId"> = {},
  ): Promise<CommercePage<PartnerAccountView>> {
    return typeof queryOrTenant === "string"
      ? this.listPartnerAccounts(queryOrTenant, options)
      : this.listPartnerAccounts(queryOrTenant);
  }

  async listPartnerCommissionRules(
    queryOrTenant: CommissionRuleQuery | string,
    options: Omit<CommissionRuleQuery, "tenantId"> = {},
  ): Promise<CommercePage<CommissionRuleView>> {
    return typeof queryOrTenant === "string"
      ? this.listCommissionRules(queryOrTenant, options)
      : this.listCommissionRules(queryOrTenant);
  }

  async getListing(
    queryOrTenant: CommerceResourceGetQuery | string,
    id?: string,
  ): Promise<MarketplaceListingView> {
    return typeof queryOrTenant === "string"
      ? this.getMarketplaceListing(queryOrTenant, id ?? "")
      : this.getMarketplaceListing(queryOrTenant);
  }

  async getPartner(
    queryOrTenant: CommerceResourceGetQuery | string,
    id?: string,
  ): Promise<PartnerAccountView> {
    return typeof queryOrTenant === "string"
      ? this.getPartnerAccount(queryOrTenant, id ?? "")
      : this.getPartnerAccount(queryOrTenant);
  }

  async getRule(
    queryOrTenant: CommerceResourceGetQuery | string,
    id?: string,
  ): Promise<CommissionRuleView> {
    return typeof queryOrTenant === "string"
      ? this.getCommissionRule(queryOrTenant, id ?? "")
      : this.getCommissionRule(queryOrTenant);
  }

  async createPlan(command: CreatePlanCommand): Promise<Plan> {
    const tenantId = normalizeCommerceTenantId(command?.tenantId);
    const effectiveFrom = normalizeCommerceTimestamp(
      command.effectiveFrom ?? this.timestamp(),
      "effectiveFrom",
    );
    const effectiveTo = command.effectiveTo === undefined
      ? undefined
      : normalizeCommerceTimestamp(command.effectiveTo, "effectiveTo");
    requireEffectiveRange(effectiveFrom, effectiveTo);
    const at = this.timestamp();
    return this.repositories.plans.create({
      id: this.newId("plan"),
      tenantId,
      kind: "plan",
      code: requireCommerceCode(command.code, "code"),
      name: requireCommerceText(command.name, "name", 200),
      ...(command.description === undefined
        ? {}
        : {
            description: requireCommerceText(
              command.description,
              "description",
              2000,
          ),
          }),
      status: "draft",
      priority: normalizeInteger(command.priority ?? 0, "priority"),
      currency: normalizeCurrency(command.currency),
      priceIds: normalizeIdList(command.priceIds, "price"),
      entitlementIds: normalizeIdList(command.entitlementIds, "entitlement"),
      quotaIds: normalizeIdList(command.quotaIds, "quota"),
      effectiveFrom,
      ...(effectiveTo === undefined ? {} : { effectiveTo }),
      version: 1,
      createdAt: at,
      updatedAt: at,
    });
  }

  async grantEntitlement(
    command: GrantEntitlementCommand,
  ): Promise<Entitlement> {
    const tenantId = normalizeCommerceTenantId(command?.tenantId);
    const sourceId = normalizeEntitlementSource(tenantId, command);
    const effectiveFrom = normalizeCommerceTimestamp(
      command.effectiveFrom ?? this.timestamp(),
      "effectiveFrom",
    );
    const effectiveTo = command.effectiveTo === undefined
      ? undefined
      : normalizeCommerceTimestamp(command.effectiveTo, "effectiveTo");
    requireEffectiveRange(effectiveFrom, effectiveTo);
    if (
      command.value !== undefined &&
      typeof command.value !== "boolean" &&
      typeof command.value !== "string" &&
      (typeof command.value !== "number" ||
        !Number.isSafeInteger(command.value))
    ) {
      throw commerceValidationError("Entitlement value is invalid", "value");
    }
    if (typeof command.value === "string") {
      requireCommerceIdentifier(command.value, "value");
    }
    const at = this.timestamp();
    return this.repositories.entitlements.create({
      id: this.newId("entitlement"),
      tenantId,
      kind: "entitlement",
      feature: requireCommerceIdentifier(command.feature, "feature"),
      effect: command.effect,
      ...(command.value === undefined ? {} : { value: command.value }),
      source: command.source,
      sourceId,
      priority: normalizeInteger(command.priority ?? 0, "priority"),
      status: "pending",
      effectiveFrom,
      ...(effectiveTo === undefined ? {} : { effectiveTo }),
      version: 1,
      createdAt: at,
      updatedAt: at,
    });
  }

  async createMeter(command: CreateMeterCommand): Promise<Meter> {
    const tenantId = normalizeCommerceTenantId(command?.tenantId);
    if (!isUsageAggregation(command.aggregation)) {
      throw commerceValidationError("Meter aggregation is invalid", "aggregation");
    }
    const dimensions = normalizeStringList(command.dimensions ?? []);
    const at = this.timestamp();
    return this.repositories.meters.create({
      id: this.newId("meter"),
      tenantId,
      kind: "meter",
      key: requireCommerceCode(command.key, "key"),
      name: requireCommerceText(command.name, "name", 200),
      unit: requireCommerceIdentifier(command.unit, "unit"),
      aggregation: command.aggregation,
      dimensions,
      status: "draft",
      version: 1,
      createdAt: at,
      updatedAt: at,
    });
  }

  async createPrice(command: CreatePriceCommand): Promise<Price> {
    const tenantId = normalizeCommerceTenantId(command?.tenantId);
    if (
      command.priceType !== "fixed" &&
      command.priceType !== "perUnit" &&
      command.priceType !== "tiered" &&
      command.priceType !== "mixed"
    ) {
      throw commerceValidationError("Price type is invalid", "priceType");
    }
    const currency = normalizeCurrency(command.currency);
    const roundingMode = command.roundingMode ?? "halfUp";
    if (roundingMode !== "halfUp" && roundingMode !== "halfEven") {
      throw commerceValidationError("Price rounding mode is invalid", "roundingMode");
    }
    const effectiveFrom = normalizeCommerceTimestamp(
      command.effectiveFrom ?? this.timestamp(),
      "effectiveFrom",
    );
    const effectiveTo = command.effectiveTo === undefined
      ? undefined
      : normalizeCommerceTimestamp(command.effectiveTo, "effectiveTo");
    requireEffectiveRange(effectiveFrom, effectiveTo);
    const at = this.timestamp();
    const base = {
      id: this.newId("price"),
      tenantId,
      kind: "price" as const,
      code: requireCommerceCode(command.code, "code"),
      name: requireCommerceText(command.name, "name", 200),
      status: "draft" as const,
      currency,
      roundingMode,
      effectiveFrom,
      ...(effectiveTo === undefined ? {} : { effectiveTo }),
      version: 1,
      createdAt: at,
      updatedAt: at,
    };
    if (command.priceType === "fixed") {
      return this.repositories.prices.create({
        ...base,
        priceType: "fixed",
        fixedAmount: normalizeMoney(
          requiredValue(command.fixedAmount, "fixedAmount"),
          "fixedAmount",
        ),
      });
    }
    const meterId = assertCommerceId(
      requiredValue(command.meterId, "meterId"),
      "meter",
      "meterId",
    );
    await this.requireMeter(tenantId, meterId);
    if (command.priceType === "tiered") {
      return this.repositories.prices.create({
        ...base,
        priceType: "tiered",
        meterId,
        tiers: normalizePriceTiers(requiredValue(command.tiers, "tiers")),
      });
    }
    const common = {
      ...base,
      priceType: command.priceType,
      meterId,
      unitAmount: normalizeMoney(
        requiredValue(command.unitAmount, "unitAmount"),
        "unitAmount",
      ),
      includedUnits: normalizeDecimal(
        command.includedUnits ?? "0",
        "includedUnits",
      ),
      minimumCharge: normalizeMoney(
        command.minimumCharge ?? zeroMoney(currency),
        "minimumCharge",
      ),
    };
    if (common.priceType === "mixed") {
      return this.repositories.prices.create({
        ...common,
        fixedAmount: normalizeMoney(
          requiredValue(command.fixedAmount, "fixedAmount"),
          "fixedAmount",
        ),
      });
    }
    return this.repositories.prices.create({
      ...common,
      priceType: "perUnit",
    });
  }

  async createSubscription(
    command: CreateSubscriptionCommand,
  ): Promise<Subscription> {
    const tenantId = normalizeCommerceTenantId(command?.tenantId);
    const planId = assertCommerceId(command.planId, "plan", "planId");
    const plan = await this.requirePlan(tenantId, planId);
    const planActiveAt = this.timestamp();
    if (
      plan.status !== "active" ||
      !isEffectiveAt(plan.effectiveFrom, plan.effectiveTo, planActiveAt)
    ) {
      throw commerceResourceConflict("Plan is not active and effective");
    }
    const now = planActiveAt;
    const currentPeriodStart = command.currentPeriodStart === undefined
      ? now
      : normalizeCommerceTimestamp(
        command.currentPeriodStart,
        "currentPeriodStart",
      );
    const currentPeriodEnd = command.currentPeriodEnd === undefined
      ? new Date(Date.parse(currentPeriodStart) + MONTH_MILLISECONDS).toISOString()
      : normalizeCommerceTimestamp(command.currentPeriodEnd, "currentPeriodEnd");
    if (Date.parse(currentPeriodEnd) <= Date.parse(currentPeriodStart)) {
      throw commerceValidationError(
        "Subscription period is invalid",
        "currentPeriodEnd",
      );
    }
    return this.repositories.subscriptions.create({
      id: this.newId("subscription"),
      tenantId,
      kind: "subscription",
      applicationId: assertExternalReferenceId(
        command.applicationId,
        "app",
        "applicationId",
      ),
      planId,
      name: requireCommerceText(command.name, "name", 200),
      status: "pending",
      quantity: normalizeDecimal(command.quantity ?? "1", "quantity", false),
      currentPeriodStart,
      currentPeriodEnd,
      cancelAtPeriodEnd: false,
      version: 1,
      createdAt: now,
      updatedAt: now,
    });
  }

  async createQuota(command: CreateQuotaCommand): Promise<Quota> {
    const tenantId = normalizeCommerceTenantId(command?.tenantId);
    const planId = assertCommerceId(command.planId, "plan", "planId");
    const meterId = assertCommerceId(command.meterId, "meter", "meterId");
    await this.requirePlan(tenantId, planId);
    await this.requireMeter(tenantId, meterId);
    const at = this.timestamp();
    return this.repositories.quotas.create({
      id: this.newId("quota"),
      tenantId,
      kind: "quota",
      planId,
      meterId,
      limit: normalizeDecimal(command.limit, "limit", false),
      reserved: "0",
      consumed: "0",
      status: "active",
      version: 1,
      createdAt: at,
      updatedAt: at,
    });
  }

  async createPartnerAccount(
    command: CreatePartnerAccountCommand,
  ): Promise<PartnerAccount> {
    const tenantId = normalizeCommerceTenantId(command?.tenantId);
    const at = this.timestamp();
    const created = await this.repositories.partnerAccounts.create({
      id: this.newId("partnerAccount"),
      tenantId,
      kind: "partnerAccount",
      legalName: requireCommerceText(command.legalName, "legalName", 200),
      partnerCode: requireCommerceCode(command.partnerCode, "partnerCode"),
      status: "pending",
      currency: normalizeCurrency(command.currency),
      settlementReference: requireCommerceIdentifier(
        command.settlementReference,
        "settlementReference",
      ),
      version: 1,
      createdAt: at,
      updatedAt: at,
    });
    await this.publishCommerceDomainEvent(
      {
        tenantId,
        actorId: COMMERCE_IDEMPOTENCY_SERVICE_ACTOR,
        operation: "partnerAccount.create",
        idempotencyKey: created.id,
      },
      commerceCreatedDomainEventFactory(created),
      created,
    );
    return created;
  }

  async createMarketplaceListing(
    command: CreateMarketplaceListingCommand,
  ): Promise<MarketplaceListing> {
    const tenantId = normalizeCommerceTenantId(command?.tenantId);
    const partnerAccountId = assertCommerceId(
      command.partnerAccountId,
      "partnerAccount",
      "partnerAccountId",
    );
    await this.requirePartnerAccount(tenantId, partnerAccountId);
    const normalized = {
      tenantId,
      partnerAccountId,
      productId: assertExternalReferenceId(
        command.productId,
        "product",
        "productId",
      ),
      title: requireCommerceText(command.title, "title", 200),
      description: requireCommerceText(command.description, "description", 4000),
      priceIds: normalizeIdList(command.priceIds, "price"),
      commissionRuleIds: normalizeIdList(
        command.commissionRuleIds,
        "commissionRule",
      ),
    };
    const create = async (): Promise<MarketplaceListing> => {
      const at = this.timestamp();
      return this.repositories.marketplaceListings.create({
        id: this.newId("marketplaceListing"),
        ...normalized,
        kind: "marketplaceListing",
        status: "draft",
        version: 1,
        createdAt: at,
        updatedAt: at,
      });
    };
    if (command.idempotencyKey === undefined) {
      const created = await create();
      await this.publishCommerceDomainEvent(
        {
          tenantId,
          actorId: command.actorId ?? COMMERCE_IDEMPOTENCY_SERVICE_ACTOR,
          operation: "marketplaceListing.create",
          idempotencyKey: created.id,
        },
        commerceCreatedDomainEventFactory(created),
        created,
      );
      return created;
    }
    const idempotencyKey = normalizeIdempotencyKey(command.idempotencyKey);
    const actorId = command.actorId ?? COMMERCE_IDEMPOTENCY_SERVICE_ACTOR;
    const result = await this.executeCommerceIdempotent(
      {
        tenantId,
        actorId,
        operation: "marketplaceListing.create",
        key: idempotencyKey,
      },
      hashCommerceRequest(normalized),
      create,
    );
    await this.publishCommerceDomainEvent(
      {
        tenantId,
        actorId,
        operation: "marketplaceListing.create",
        idempotencyKey,
      },
      commerceCreatedDomainEventFactory(result.value),
      result.value,
    );
    return result.value;
  }

  async createCommissionRule(
    command: CreateCommissionRuleCommand,
  ): Promise<CommissionRule> {
    const tenantId = normalizeCommerceTenantId(command?.tenantId);
    const partnerAccountId = assertCommerceId(
      command.partnerAccountId,
      "partnerAccount",
      "partnerAccountId",
    );
    const listingId = assertCommerceId(
      command.listingId,
      "marketplaceListing",
      "listingId",
    );
    await this.requirePartnerAccount(tenantId, partnerAccountId);
    const listing = await this.requireListing(tenantId, listingId);
    if (listing.partnerAccountId !== partnerAccountId) {
      throw commerceResourceNotFound("marketplaceListing");
    }
    const rateBps = normalizeInteger(command.rateBps, "rateBps", 0, 10_000);
    const capBps = command.capBps === undefined
      ? undefined
      : normalizeInteger(command.capBps, "capBps", 0, 10_000);
    const capAmount = command.capAmount === undefined
      ? undefined
      : normalizeMoney(command.capAmount, "capAmount");
    const effectiveFrom = normalizeCommerceTimestamp(
      command.effectiveFrom ?? this.timestamp(),
      "effectiveFrom",
    );
    const effectiveTo = command.effectiveTo === undefined
      ? undefined
      : normalizeCommerceTimestamp(command.effectiveTo, "effectiveTo");
    requireEffectiveRange(effectiveFrom, effectiveTo);
    if (capAmount !== undefined && capAmount.currency !== normalizeCurrency()) {
      throw commerceValidationError("Commission cap currency is invalid", "capAmount");
    }
    const at = this.timestamp();
    const created = await this.repositories.commissionRules.create({
      id: this.newId("commissionRule"),
      tenantId,
      kind: "commissionRule",
      partnerAccountId,
      listingId,
      name: requireCommerceText(command.name, "name", 200),
      status: "draft",
      rateBps,
      ...(capBps === undefined ? {} : { capBps }),
      ...(capAmount === undefined ? {} : { capAmount }),
      priority: normalizeInteger(command.priority ?? 0, "priority"),
      effectiveFrom,
      ...(effectiveTo === undefined ? {} : { effectiveTo }),
      version: 1,
      createdAt: at,
      updatedAt: at,
    });
    await this.publishCommerceDomainEvent(
      {
        tenantId,
        actorId: COMMERCE_IDEMPOTENCY_SERVICE_ACTOR,
        operation: "commissionRule.create",
        idempotencyKey: created.id,
      },
      commerceCreatedDomainEventFactory(created),
      created,
    );
    return created;
  }

  async resolveEntitlements(
    query: ResolveEntitlementsQuery,
  ): Promise<ResolveEntitlementsResult> {
    const tenantId = normalizeCommerceTenantId(query?.tenantId);
    const at = normalizeCommerceTimestamp(query.at ?? this.timestamp(), "at");
    const planId = query.planId === undefined
      ? undefined
      : assertCommerceId(query.planId, "plan", "planId");
    const subscriptionId = query.subscriptionId === undefined
      ? undefined
      : assertCommerceId(query.subscriptionId, "subscription", "subscriptionId");
    if (planId !== undefined) {
      const plan = await this.requirePlan(tenantId, planId);
      if (
        plan.status !== "active" ||
        !isEffectiveAt(plan.effectiveFrom, plan.effectiveTo, at)
      ) {
        throw commerceResourceConflict("Plan is not effective for entitlement resolution");
      }
    }
    if (subscriptionId !== undefined) {
      const subscription = await this.requireSubscription(tenantId, subscriptionId);
      if (
        (subscription.status !== "active" &&
          subscription.status !== "trialing") ||
        at < subscription.currentPeriodStart ||
        at >= subscription.currentPeriodEnd
      ) {
        throw commerceResourceConflict(
          "Subscription is not effective for entitlement resolution",
        );
      }
    }
    const features = [...new Set(
      query.features.map((feature) =>
        requireCommerceIdentifier(feature, "features")
      ),
    )].sort((left, right) => left.localeCompare(right));
    if (features.length === 0) {
      throw commerceValidationError("At least one feature is required", "features");
    }
    const all = await this.repositories.entitlements.list(tenantId);
    const resolutions = features.map<EntitlementResolution>((feature) => {
      const candidates = all.filter((entitlement) =>
        entitlement.feature === feature &&
        entitlement.status === "active" &&
        isEffectiveAt(entitlement.effectiveFrom, entitlement.effectiveTo, at) &&
        matchesEntitlementSource(entitlement, tenantId, planId, subscriptionId)
      );
      candidates.sort(compareEntitlementPriority);
      const winner = candidates[0];
      if (winner === undefined) {
        return { feature, allowed: false, reason: "defaultDenied" };
      }
      return {
        feature,
        allowed: winner.effect === "allow",
        ...(winner.value === undefined ? {} : { value: winner.value }),
        entitlementId: winner.id,
        source: winner.source,
        sourceId: winner.sourceId,
        priority: winner.priority,
        reason: winner.effect === "allow" ? "granted" : "denied",
      };
    });
    return { tenantId, resolvedAt: at, entitlements: resolutions };
  }

  async requireFeature(
    query: ResolveEntitlementsQuery,
  ): Promise<EntitlementResolution> {
    const result = await this.resolveEntitlements(query);
    const resolution = result.entitlements[0];
    if (resolution === undefined || !resolution.allowed) {
      throw commerceEntitlementDenied(resolution?.feature ?? "unknown");
    }
    return resolution;
  }

  async recordUsageEvent(
    command: RecordUsageEventCommand,
  ): Promise<RecordUsageEventResult> {
    const normalized = await this.normalizeUsageCommand(command);
    const meter = await this.requireMeter(normalized.tenantId, normalized.meterId);
    if (meter.status !== "active") {
      throw commerceResourceConflict("Meter is not active");
    }
    await this.requireUsableSubscription(
      normalized.tenantId,
      normalized.subscriptionId,
    );
    const requestHash = hashCommerceRequest(normalized);
    const payloadHash = hashCommerceRequest({
      tenantId: normalized.tenantId,
      subscriptionId: normalized.subscriptionId,
      meterId: normalized.meterId,
      quantity: normalized.quantity,
      occurredAt: normalized.occurredAt,
      periodStart: normalized.periodStart,
      periodEnd: normalized.periodEnd,
      dimensions: normalized.dimensions,
      sourceEventId: normalized.sourceEventId,
    });
    const event: UsageEvent = {
      id: this.newId("usageEvent"),
      tenantId: normalized.tenantId,
      kind: "usageEvent",
      version: 1,
      sourceEventId: normalized.sourceEventId,
      subscriptionId: normalized.subscriptionId,
      meterId: normalized.meterId,
      quantity: normalized.quantity,
      occurredAt: normalized.occurredAt,
      periodStart: normalized.periodStart,
      periodEnd: normalized.periodEnd,
      dimensions: normalized.dimensions,
      idempotencyKey: normalized.idempotencyKey,
      requestHash,
      payloadHash,
      receivedAt: this.timestamp(),
    };
    const result = await this.repositories.usageEvents.append(event);
    return { event: result.event, accepted: result.accepted };
  }

  async aggregateUsage(
    command: AggregateUsageCommand,
  ): Promise<AggregateUsageResult> {
    const tenantId = normalizeCommerceTenantId(command?.tenantId);
    const subscriptionId = assertCommerceId(
      command.subscriptionId,
      "subscription",
      "subscriptionId",
    );
    const meterId = assertCommerceId(command.meterId, "meter", "meterId");
    const meter = await this.requireMeter(tenantId, meterId);
    await this.requireSubscription(tenantId, subscriptionId);
    const period = normalizePeriod(command.periodStart, command.periodEnd);
    const dimensions = normalizeDimensions(command.dimensions, meter.dimensions);
    const aggregateKey = hashCommerceRequest({
      tenantId,
      subscriptionId,
      meterId,
      periodStart: period.periodStart,
      periodEnd: period.periodEnd,
      dimensions,
    });
    for (let attempt = 0; attempt < 32; attempt += 1) {
      const events = (await this.repositories.usageEvents.list(tenantId))
        .filter((event) =>
          event.subscriptionId === subscriptionId &&
          event.meterId === meterId &&
          event.periodStart === period.periodStart &&
          event.periodEnd === period.periodEnd &&
          sameDimensions(event.dimensions, dimensions)
        )
        .sort((left, right) => {
          const occurred = left.occurredAt.localeCompare(right.occurredAt);
          return occurred === 0
            ? left.sourceEventId.localeCompare(right.sourceEventId)
            : occurred;
        });
      const quantity = aggregateQuantities(events, meter.aggregation);
      const eventIds = events.map((event) => event.id);
      const existing = await this.repositories.usageAggregates.findByKey(
        tenantId,
        aggregateKey,
      );
      if (existing !== undefined && existing.status === "settled") {
        return { aggregate: existing, replayed: true };
      }
      if (
        existing !== undefined &&
        existing.quantity === quantity &&
        sameStringArray(existing.eventIds, eventIds)
      ) {
        return { aggregate: existing, replayed: true };
      }
      const at = this.timestamp();
      const next: UsageAggregate = {
        id: existing?.id ?? this.newId("usageAggregate"),
        tenantId,
        kind: "usageAggregate",
        aggregateKey,
        subscriptionId,
        meterId,
        aggregation: meter.aggregation,
        quantity,
        unit: meter.unit,
        periodStart: period.periodStart,
        periodEnd: period.periodEnd,
        dimensions,
        eventIds,
        status: existing?.status ?? "collecting",
        version: existing === undefined ? 1 : existing.version + 1,
        createdAt: existing?.createdAt ?? at,
        updatedAt: at,
      };
      try {
        const aggregate = existing === undefined
          ? await this.repositories.usageAggregates.create(next)
          : await this.repositories.usageAggregates.save(next);
        return { aggregate, replayed: false };
      } catch (error) {
        if (isCommerceConflict(error)) continue;
        throw error;
      }
    }
    throw commerceResourceConflict("Usage aggregate concurrency limit exceeded");
  }

  async recordAndAggregate(command: RecordUsageEventCommand): Promise<{
    readonly event: RecordUsageEventResult;
    readonly aggregate: AggregateUsageResult;
  }> {
    const event = await this.recordUsageEvent(command);
    const aggregate = await this.aggregateUsage({
      tenantId: command.tenantId,
      subscriptionId: command.subscriptionId,
      meterId: command.meterId,
      periodStart: command.periodStart,
      periodEnd: command.periodEnd,
      dimensions: command.dimensions,
    });
    return { event, aggregate };
  }

  async calculate(command: CalculatePriceCommand): Promise<PriceCalculation> {
    try {
      return await this.calculateUnsafe(command);
    } catch (error) {
      throw normalizeCommerceCalculationError(error);
    }
  }

  private async calculateUnsafe(
    command: CalculatePriceCommand,
  ): Promise<PriceCalculation> {
    const tenantId = normalizeCommerceTenantId(command?.tenantId);
    const priceId = assertCommerceId(command.priceId, "price", "priceId");
    const price = await this.requirePrice(tenantId, priceId);
    const at = normalizeCommerceTimestamp(command.at ?? this.timestamp(), "at");
    validatePriceRecord(price, at);
    const usageByMeter = await this.normalizePriceUsage(
      tenantId,
      price,
      command.usage,
    );
    const calculation = calculatePrice(tenantId, price, usageByMeter.quantities);
    const aggregateIds = usageByMeter.aggregateIds;
    return {
      ...calculation,
      charges: calculation.charges.map((charge) => ({
        ...charge,
        aggregateIds: charge.meterId === undefined
          ? []
          : aggregateIds.get(charge.meterId) ?? [],
      })),
    };
  }

  async calculatePlan(
    command: CalculatePlanPriceCommand,
  ): Promise<PlanPriceCalculation> {
    const tenantId = normalizeCommerceTenantId(command?.tenantId);
    const priceIds = normalizeIdList(command.priceIds, "price");
    if (priceIds.length === 0) {
      throw commerceValidationError("At least one price is required", "priceIds");
    }
    const calculations: PriceCalculation[] = [];
    for (const priceId of priceIds) {
      calculations.push(await this.calculate({
        tenantId,
        priceId,
        usage: command.usage,
        ...(command.at === undefined ? {} : { at: command.at }),
      }));
    }
    const currency = calculations[0]?.currency ?? "CNY";
    const subtotal = calculations.reduce(
      (sum, calculation) => addMoney(sum, calculation.subtotal),
      zeroMoney(currency),
    );
    const total = calculations.reduce(
      (sum, calculation) => addMoney(sum, calculation.total),
      zeroMoney(currency),
    );
    return { tenantId, currency, calculations, subtotal, total };
  }

  async reserve(command: ReserveQuotaCommand): Promise<ReserveQuotaResult> {
    const tenantId = normalizeCommerceTenantId(command?.tenantId);
    const subscriptionId = assertCommerceId(
      command.subscriptionId,
      "subscription",
      "subscriptionId",
    );
    const quotaId = assertCommerceId(command.quotaId, "quota", "quotaId");
    const quantity = normalizeDecimal(command.quantity, "quantity", false);
    const expiresAt = normalizeCommerceTimestamp(command.expiresAt, "expiresAt");
    const idempotencyKey = normalizeIdempotencyKey(command.idempotencyKey);
    const at = this.timestamp();
    if (Date.parse(expiresAt) <= Date.parse(at)) {
      throw commerceValidationError(
        "Quota reservation expiry must be in the future",
        "expiresAt",
      );
    }
    const subscription = await this.requireUsableSubscription(
      tenantId,
      subscriptionId,
    );
    const plan = await this.requirePlan(tenantId, subscription.planId);
    if (
      plan.status !== "active" ||
      !isEffectiveAt(plan.effectiveFrom, plan.effectiveTo, at)
    ) {
      throw commerceResourceConflict("Plan is not effective");
    }
    const quota = await this.requireQuota(tenantId, quotaId);
    if (
      quota.planId !== plan.id ||
      quota.status !== "active"
    ) {
      throw commerceResourceConflict("Quota is not available to the plan");
    }
    if (
      at < subscription.currentPeriodStart ||
      at >= subscription.currentPeriodEnd ||
      Date.parse(expiresAt) > Date.parse(subscription.currentPeriodEnd)
    ) {
      throw commerceValidationError(
        "Quota reservation is outside the subscription period",
        "expiresAt",
      );
    }
    const requestHash = hashCommerceRequest({
      tenantId,
      operation: "quota.reserve",
      subscriptionId,
      quotaId,
      quantity,
      expiresAt,
    });
    const existing = (await this.repositories.quotaReservations.list(tenantId))
      .find((reservation) =>
        reservation.operation === "quota.reserve" &&
        reservation.quotaId === quotaId &&
        reservation.subscriptionId === subscriptionId &&
        reservation.idempotencyKey === idempotencyKey
      );
    if (existing !== undefined) {
      if (existing.requestHash !== requestHash) {
        throw commerceIdempotencyKeyReused();
      }
      const currentQuota = await this.requireQuota(tenantId, existing.quotaId);
      return {
        quota: currentQuota,
        reservation: existing,
        replayed: true,
      };
    }
    const reservation: QuotaReservation = {
      id: this.newId("quotaReservation"),
      tenantId,
      kind: "quotaReservation",
      quotaId,
      planId: plan.id,
      subscriptionId,
      meterId: quota.meterId,
      quantity,
      status: "reserved",
      operation: "quota.reserve",
      idempotencyKey,
      requestHash,
      expiresAt,
      version: 1,
      createdAt: at,
      updatedAt: at,
    };
    const result = await this.repositories.quotas.reserveAtomic({
      tenantId,
      operation: "quota.reserve",
      quotaId,
      reservation,
    });
    return result;
  }

  async settle(command: SettleQuotaCommand): Promise<QuotaOperationResult> {
    const terminal = await this.terminateQuota(command, "settled");
    return terminal;
  }

  async release(command: ReleaseQuotaCommand): Promise<QuotaOperationResult> {
    const terminal = await this.terminateQuota(command, "released");
    return terminal;
  }

  async generateInvoice(
    command: GenerateInvoiceCommand,
  ): Promise<GenerateInvoiceResult> {
    try {
      return await this.generateInvoiceUnsafe(command);
    } catch (error) {
      throw normalizeCommerceCalculationError(error);
    }
  }

  private async generateInvoiceUnsafe(
    command: GenerateInvoiceCommand,
  ): Promise<GenerateInvoiceResult> {
    const tenantId = normalizeCommerceTenantId(command?.tenantId);
    const subscriptionId = assertCommerceId(
      command.subscriptionId,
      "subscription",
      "subscriptionId",
    );
    const period = normalizePeriod(command.periodStart, command.periodEnd);
    const idempotencyKey = normalizeIdempotencyKey(command.idempotencyKey);
    const taxRateBps = normalizeInteger(
      command.taxRateBps,
      "taxRateBps",
      0,
      10_000,
    );
    if (command.taxMode !== "exclusive" && command.taxMode !== "inclusive") {
      throw commerceValidationError("Invoice tax mode is invalid", "taxMode");
    }
    const subscription = await this.requireUsableSubscription(
      tenantId,
      subscriptionId,
    );
    if (subscription.status !== "active") {
      throw commerceResourceConflict("Only active subscriptions can be invoiced");
    }
    if (
      subscription.currentPeriodStart !== period.periodStart ||
      subscription.currentPeriodEnd !== period.periodEnd
    ) {
      throw commerceValidationError(
        "Invoice period must match the subscription period",
        "periodStart",
      );
    }
    const plan = await this.requirePlan(tenantId, subscription.planId);
    const at = this.timestamp();
    if (
      plan.status !== "active" ||
      !isEffectiveAt(plan.effectiveFrom, plan.effectiveTo, at)
    ) {
      throw commerceResourceConflict("Plan is not effective for invoicing");
    }
    const priceIds = [...new Set(plan.priceIds)].sort((left, right) =>
      left.localeCompare(right)
    );
    const aggregates = (await this.repositories.usageAggregates.list(tenantId))
      .filter((aggregate) =>
        aggregate.subscriptionId === subscriptionId &&
        aggregate.periodStart === period.periodStart &&
        aggregate.periodEnd === period.periodEnd &&
        aggregate.status !== "collecting"
      );
    const priceCalculations: PriceCalculation[] = [];
    for (const priceId of priceIds) {
      const calculation = await this.calculate({
        tenantId,
        priceId,
        usage: aggregates.map((aggregate) => ({
          meterId: aggregate.meterId,
          quantity: aggregate.quantity,
          aggregateId: aggregate.id,
        })),
        at: period.periodEnd,
      });
      priceCalculations.push(calculation);
    }
    const currency = priceCalculations[0]?.currency ?? plan.currency;
    if (priceCalculations.some((calculation) => calculation.currency !== currency)) {
      throw commerceValidationError("Plan prices must use one currency", "priceIds");
    }
    const invoiceId = this.newId("invoice");
    const atTimestamp = this.timestamp();
    const lines: InvoiceLine[] = [];
    for (const calculation of priceCalculations) {
      for (const charge of calculation.charges) {
        lines.push({
          id: this.newId("invoiceLine"),
          tenantId,
          kind: "invoiceLine",
          invoiceId,
          type: charge.priceType === "fixed" ? "subscription" : "usage",
          direction: "debit",
          description: `${charge.priceType}:${charge.priceId}`,
          quantity: charge.billableQuantity,
          unitAmount: charge.unitAmount,
          amount: charge.amount,
          ...(charge.meterId === undefined ? {} : { meterId: charge.meterId }),
          priceId: charge.priceId,
          ...(charge.aggregateIds[0] === undefined
            ? {}
            : { aggregateId: charge.aggregateIds[0] }),
        });
      }
    }
    const baseSubtotal = priceCalculations.reduce(
      (sum, calculation) => addMoney(sum, calculation.total),
      zeroMoney(currency),
    );
    const adjustments = normalizeInvoiceAdjustments(command.adjustments ?? [], currency);
    let subtotal = baseSubtotal;
    for (const adjustment of adjustments) {
      if (adjustment.direction === "credit") {
        subtotal = subtractMoney(subtotal, adjustment.amount);
      } else {
        subtotal = addMoney(subtotal, adjustment.amount);
      }
      lines.push({
        id: this.newId("invoiceLine"),
        tenantId,
        kind: "invoiceLine",
        invoiceId,
        type: "adjustment",
        direction: adjustment.direction,
        description: `${adjustment.type}:${adjustment.reason}`,
        quantity: "1",
        unitAmount: adjustment.amount,
        amount: adjustment.amount,
        adjustmentType: adjustment.type,
      });
    }
    const tax = command.taxMode === "exclusive"
      ? multiplyMoneyByBasisPoints(subtotal, taxRateBps, "halfUp")
      : extractInclusiveTax(subtotal, taxRateBps);
    if (tax.amountMinor < 0 || tax.amountMinor > subtotal.amountMinor) {
      throw commerceInvalidTotal("Invoice tax is invalid");
    }
    if (tax.amountMinor > 0) {
      lines.push({
        id: this.newId("invoiceLine"),
        tenantId,
        kind: "invoiceLine",
        invoiceId,
        type: "tax",
        direction: "debit",
        description: `CNY tax ${taxRateBps}bps`,
        quantity: "1",
        unitAmount: tax,
        amount: tax,
      });
    }
    const total = command.taxMode === "inclusive"
      ? subtotal
      : addMoney(subtotal, tax);
    const normalizedMetadata = command.mainlandChina === undefined
      ? undefined
      : normalizeMainlandChinaInvoiceMetadata(
        command.mainlandChina,
        taxRateBps,
      );
    const normalizedCommand = {
      tenantId,
      subscriptionId,
      periodStart: period.periodStart,
      periodEnd: period.periodEnd,
      idempotencyKey,
      taxRateBps,
      taxMode: command.taxMode,
      adjustments,
      ...(normalizedMetadata === undefined ? {} : { mainlandChina: normalizedMetadata }),
    };
    const invoice: Invoice = {
      id: invoiceId,
      tenantId,
      kind: "invoice",
      version: 1,
      subscriptionId,
      planId: plan.id,
      periodStart: period.periodStart,
      periodEnd: period.periodEnd,
      status: "draft",
      currency,
      taxMode: command.taxMode,
      lines,
      subtotal,
      tax,
      total,
      idempotencyKey,
      requestHash: hashCommerceRequest(normalizedCommand),
      ...(normalizedMetadata === undefined
        ? {}
        : { mainlandChina: normalizedMetadata }),
      createdAt: atTimestamp,
      updatedAt: atTimestamp,
    };
    const generated = await this.repositories.invoices.createIdempotent({
      tenantId,
      idempotencyKey,
      requestHash: invoice.requestHash,
      invoice,
    });
    await this.publishCommerceDomainEvent(
      {
        tenantId,
        actorId: COMMERCE_IDEMPOTENCY_SERVICE_ACTOR,
        operation: "invoice.create",
        idempotencyKey,
      },
      commerceCreatedDomainEventFactory(generated.invoice),
      generated.invoice,
    );
    return generated;
  }

  async calculateCommission(
    command: CalculateCommissionCommand,
  ): Promise<CommissionCalculation> {
    try {
      return await this.calculateCommissionUnsafe(command);
    } catch (error) {
      throw normalizeCommerceCalculationError(error);
    }
  }

  private async calculateCommissionUnsafe(
    command: CalculateCommissionCommand,
  ): Promise<CommissionCalculation> {
    const tenantId = normalizeCommerceTenantId(command?.tenantId);
    const listingId = assertCommerceId(
      command.listingId,
      "marketplaceListing",
      "listingId",
    );
    const grossAmount = normalizeMoney(command.grossAmount, "grossAmount");
    const at = normalizeCommerceTimestamp(command.at ?? this.timestamp(), "at");
    const listing = await this.requireListing(tenantId, listingId);
    if (listing.status !== "published") {
      throw commerceResourceConflict("Marketplace listing is not published");
    }
    const partner = await this.requirePartnerAccount(
      tenantId,
      listing.partnerAccountId,
    );
    if (partner.status !== "active" || partner.currency !== grossAmount.currency) {
      throw commerceResourceConflict("Partner account is not available");
    }
    const rules = (await this.repositories.commissionRules.list(tenantId))
      .filter((rule) =>
        (listing.commissionRuleIds.length === 0 ||
          listing.commissionRuleIds.includes(rule.id)) &&
        rule.partnerAccountId === partner.id &&
        rule.listingId === listing.id &&
        rule.status === "active" &&
        isEffectiveAt(rule.effectiveFrom, rule.effectiveTo, at)
      )
      .sort((left, right) =>
        right.priority - left.priority ||
        right.effectiveFrom.localeCompare(left.effectiveFrom) ||
        left.id.localeCompare(right.id)
      );
    const rule = rules[0];
    if (rule === undefined) {
      throw commerceResourceConflict("No effective commission rule exists");
    }
    return calculateMarketplaceCommission(tenantId, grossAmount, rule);
  }

  async transition(
    command: TransitionCommerceResourceCommand,
  ): Promise<CommerceRecord | Invoice> {
    const tenantId = normalizeCommerceTenantId(command?.tenantId);
    const at = normalizeCommerceTimestamp(command.at ?? this.timestamp(), "at");
    switch (command.resource) {
      case "plan": {
        const record = await this.requirePlan(
          tenantId,
          assertCommerceId(command.id, "plan"),
        );
        const target = planStatus(command.targetStatus);
        assertPlanTransition(record.status, target);
        return this.repositories.plans.save({
          ...record,
          status: target,
          version: record.version + 1,
          updatedAt: at,
        });
      }
      case "entitlement": {
        const record = await this.requireEntitlement(
          tenantId,
          assertCommerceId(command.id, "entitlement"),
        );
        const target = entitlementStatus(command.targetStatus);
        assertEntitlementTransition(record.status, target);
        return this.repositories.entitlements.save({
          ...record,
          status: target,
          version: record.version + 1,
          updatedAt: at,
        });
      }
      case "meter": {
        const record = await this.requireMeter(
          tenantId,
          assertCommerceId(command.id, "meter"),
        );
        const target = meterStatus(command.targetStatus);
        assertMeterTransition(record.status, target);
        return this.repositories.meters.save({
          ...record,
          status: target,
          version: record.version + 1,
          updatedAt: at,
        });
      }
      case "price": {
        const record = await this.requirePrice(
          tenantId,
          assertCommerceId(command.id, "price"),
        );
        const target = priceStatus(command.targetStatus);
        assertPriceTransition(record.status, target);
        return this.repositories.prices.save({
          ...record,
          status: target,
          version: record.version + 1,
          updatedAt: at,
        });
      }
      case "subscription": {
        const record = await this.requireSubscription(
          tenantId,
          assertCommerceId(command.id, "subscription"),
        );
        const target = subscriptionStatus(command.targetStatus);
        assertSubscriptionTransition(record.status, target);
        return this.repositories.subscriptions.save({
          ...record,
          status: target,
          version: record.version + 1,
          updatedAt: at,
          ...(target === "canceled" ? { canceledAt: at } : {}),
        });
      }
      case "quota": {
        const record = await this.requireQuota(
          tenantId,
          assertCommerceId(command.id, "quota"),
        );
        const target = quotaStatus(command.targetStatus);
        assertQuotaTransition(record.status, target);
        return this.repositories.quotas.save({
          ...record,
          status: target,
          version: record.version + 1,
          updatedAt: at,
        });
      }
      case "usageAggregate": {
        const record = await this.repositories.usageAggregates.get(
          tenantId,
          assertCommerceId(command.id, "usageAggregate"),
        );
        if (record === undefined) throw commerceResourceNotFound("usageAggregate");
        const target = usageAggregateStatus(command.targetStatus);
        assertUsageAggregateTransition(record.status, target);
        return this.repositories.usageAggregates.save({
          ...record,
          status: target,
          version: record.version + 1,
          updatedAt: at,
        });
      }
      case "marketplaceListing": {
        const record = await this.requireListing(
          tenantId,
          assertCommerceId(command.id, "marketplaceListing"),
        );
        const target = marketplaceListingStatus(command.targetStatus);
        assertMarketplaceListingTransition(record.status, target);
        return this.repositories.marketplaceListings.save({
          ...record,
          status: target,
          version: record.version + 1,
          updatedAt: at,
          ...(target === "pendingReview" ? { submittedAt: at } : {}),
          ...(target === "published" ? { publishedAt: at } : {}),
          ...(target === "removed" ? { removedAt: at } : {}),
        });
      }
      case "partnerAccount": {
        const record = await this.requirePartnerAccount(
          tenantId,
          assertCommerceId(command.id, "partnerAccount"),
        );
        const target = partnerAccountStatus(command.targetStatus);
        assertPartnerAccountTransition(record.status, target);
        return this.repositories.partnerAccounts.save({
          ...record,
          status: target,
          version: record.version + 1,
          updatedAt: at,
          ...(target === "active" ? { activatedAt: at } : {}),
        });
      }
      case "commissionRule": {
        const record = await this.requireCommissionRule(
          tenantId,
          assertCommerceId(command.id, "commissionRule"),
        );
        const target = commissionRuleStatus(command.targetStatus);
        assertCommissionRuleTransition(record.status, target);
        return this.repositories.commissionRules.save({
          ...record,
          status: target,
          version: record.version + 1,
          updatedAt: at,
        });
      }
      case "invoice": {
        const target = invoiceStatus(command.targetStatus);
        return this.repositories.invoices.transition(
          tenantId,
          assertCommerceId(command.id, "invoice"),
          target,
          at,
        );
      }
    }
  }

  async transitionWithIdempotency(
    command: TransitionCommerceResourceCommand & { readonly idempotencyKey: string },
  ): Promise<CommerceTransitionResult> {
    const idempotencyKey = normalizeIdempotencyKey(command?.idempotencyKey);
    const tenantId = normalizeCommerceTenantId(command?.tenantId);
    const actorId = command.actorId ?? COMMERCE_IDEMPOTENCY_SERVICE_ACTOR;
    const operation = `${command.resource}.transition`;
    const requestHash = hashCommerceRequest({
      tenantId,
      resource: command.resource,
      id: command.id,
      targetStatus: command.targetStatus,
      at: command.at,
    });
    const fromStatus = this.eventsEnabled
      ? await this.commerceEventFromStatus(tenantId, command.resource, command.id)
      : undefined;
    const result = await this.executeCommerceIdempotent(
      {
        tenantId,
        actorId,
        operation,
        key: idempotencyKey,
      },
      requestHash,
      async () => this.transition({ ...command, idempotencyKey: undefined }),
    );
    await this.publishCommerceDomainEvent(
      {
        tenantId,
        actorId,
        operation,
        idempotencyKey,
      },
      commerceStatusChangedDomainEventFactory(result.value, fromStatus),
      result.value,
    );
    return { record: result.value, replayed: result.replayed };
  }

  async disputeInvoice(
    command: DisputeInvoiceCommand,
  ): Promise<DisputeInvoiceResult> {
    const tenantId = normalizeCommerceTenantId(command?.tenantId);
    const invoiceId = assertCommerceId(command.invoiceId, "invoice", "invoiceId");
    const idempotencyKey = normalizeIdempotencyKey(command.idempotencyKey);
    const reason = requireCommerceDisputeReason(command.reason);
    const evidenceReference = command.evidenceReference === undefined
      ? undefined
      : requireCommerceEvidenceReference(command.evidenceReference);
    const actorId = command.actorId === undefined
      ? COMMERCE_IDEMPOTENCY_SERVICE_ACTOR
      : requireCommerceIdentifier(command.actorId, "actorId");
    const requestId = command.requestId === undefined
      ? idempotencyKey
      : requireCommerceIdentifier(command.requestId, "requestId");
    const requestHash = hashCommerceRequest({
      tenantId,
      invoiceId,
      reason,
      evidenceReference,
    });
    const result = await this.executeCommerceIdempotent(
      {
        tenantId,
        actorId,
        operation: "invoice.dispute",
        key: idempotencyKey,
      },
      requestHash,
      async () => {
        const at = this.timestamp();
        const appended = await this.appendInvoiceDispute({
          tenantId,
          invoiceId,
          reason,
          evidenceReference,
          actorId,
          requestId,
          idempotencyKey,
          requestHash,
          at,
        });
        return {
          invoice: toCommerceInvoiceView(appended.invoice),
          dispute: toCommerceInvoiceDisputeView(appended.dispute),
          replayed: false,
        } satisfies DisputeInvoiceResult;
      },
    );
    await this.publishCommerceDomainEvent(
      {
        tenantId,
        actorId,
        operation: "invoice.dispute",
        idempotencyKey,
        requestId,
      },
      (value) => commerceDisputeOpenedEvent(value.dispute),
      result.value,
    );
    return {
      invoice: cloneCommerceValue(result.value.invoice),
      dispute: cloneCommerceValue(result.value.dispute),
      replayed: result.replayed,
    };
  }

  private async appendInvoiceDispute(input: {
    readonly tenantId: string;
    readonly invoiceId: string;
    readonly reason: string;
    readonly evidenceReference: string | undefined;
    readonly actorId: string;
    readonly requestId: string;
    readonly idempotencyKey: string;
    readonly requestHash: string;
    readonly at: string;
  }): Promise<{ readonly dispute: InvoiceDispute; readonly invoice: Invoice }> {
    const current = await this.repositories.invoices.get(input.tenantId, input.invoiceId);
    if (
      current === undefined ||
      current.kind !== "invoice" ||
      current.tenantId !== input.tenantId ||
      current.id !== input.invoiceId
    ) {
      throw commerceResourceNotFound("invoice");
    }
    const dispute: InvoiceDispute = {
      id: this.newId("invoiceDispute"),
      tenantId: input.tenantId,
      kind: "invoiceDispute",
      version: 1,
      event: INVOICE_DISPUTE_OPENED_EVENT,
      invoiceId: input.invoiceId,
      subscriptionId: current.subscriptionId,
      planId: current.planId,
      invoiceStatus: current.status,
      invoiceVersion: current.version,
      reason: input.reason,
      reasonDigest: hashCommerceRequest(input.reason),
      reasonLength: input.reason.length,
      ...(input.evidenceReference === undefined
        ? {}
        : {
            evidenceReference: input.evidenceReference,
            evidenceReferenceDigest: hashCommerceRequest(input.evidenceReference),
          }),
      evidenceCount: input.evidenceReference === undefined ? 0 : 1,
      actorId: input.actorId,
      requestId: input.requestId,
      idempotencyKey: input.idempotencyKey,
      requestHash: input.requestHash,
      status: "open",
      createdAt: input.at,
      updatedAt: input.at,
      recordedAt: input.at,
    };
    return this.repositories.invoiceDisputes.withTransaction(async () => {
      const appended = await this.repositories.invoiceDisputes.append(dispute);
      if (!appended.accepted) return { dispute: appended.dispute, invoice: current };
      if (current.status === "disputed") {
        throw commerceResourceConflict("Invoice is already disputed");
      }
      const transitioned = await this.transition({
        tenantId: input.tenantId,
        resource: "invoice",
        id: input.invoiceId,
        targetStatus: "disputed",
        at: input.at,
      });
      if (transitioned.kind !== "invoice") {
        throw commerceResourceConflict("Invoice resource is invalid");
      }
      return { dispute: appended.dispute, invoice: transitioned };
    });
  }

  async listInvoiceDisputes(
    query: InvoiceDisputeQuery,
  ): Promise<CommercePage<InvoiceDisputeView>>;
  async listInvoiceDisputes(
    tenantId: string,
    query?: Omit<InvoiceDisputeQuery, "tenantId">,
  ): Promise<CommercePage<InvoiceDisputeView>>;
  async listInvoiceDisputes(
    queryOrTenant: InvoiceDisputeQuery | string,
    options: Omit<InvoiceDisputeQuery, "tenantId"> = {},
  ): Promise<CommercePage<InvoiceDisputeView>> {
    const query = typeof queryOrTenant === "string"
      ? { tenantId: queryOrTenant, ...options }
      : queryOrTenant;
    const normalized = normalizeInvoiceDisputeQuery(query);
    const records = await this.repositories.invoiceDisputes.list(
      normalized.tenantId,
      {
        limit: COMMERCE_MAX_PAGE_SIZE,
        ...(normalized.invoiceId === undefined
          ? {}
          : { invoiceId: normalized.invoiceId }),
        ...(normalized.actorId === undefined
          ? {}
          : { actorId: normalized.actorId }),
        ...(normalized.status === undefined
          ? {}
          : { status: normalized.status }),
        ...(normalized.from === undefined ? {} : { from: normalized.from }),
        ...(normalized.to === undefined ? {} : { to: normalized.to }),
      },
    );
    return this.pageCommerceRecords(
      records,
      normalized,
      "invoiceDispute",
      commerceQueryScope("invoiceDispute", normalized),
      toCommerceInvoiceDisputeView,
    );
  }

  async getInvoiceDispute(
    query: CommerceResourceGetQuery,
  ): Promise<InvoiceDisputeView>;
  async getInvoiceDispute(
    tenantId: string,
    id: string,
  ): Promise<InvoiceDisputeView>;
  async getInvoiceDispute(
    queryOrTenant: CommerceResourceGetQuery | string,
    id?: string,
  ): Promise<InvoiceDisputeView> {
    const query = typeof queryOrTenant === "string"
      ? { tenantId: queryOrTenant, id: id ?? "" }
      : queryOrTenant;
    const tenantId = normalizeCommerceTenantId(query?.tenantId);
    const dispute = await this.requireInvoiceDispute(
      tenantId,
      assertCommerceId(query?.id, "invoiceDispute"),
    );
    return toCommerceInvoiceDisputeView(dispute);
  }

  async startInvoiceDisputeReview(
    command: ReviewInvoiceDisputeCommand,
  ): Promise<InvoiceDisputeResult> {
    return this.adjudicateInvoiceDispute({
      operation: "invoice.dispute.review",
      targetStatus: "underReview",
      ...command,
    });
  }

  async decideInvoiceDispute(
    command: DecideInvoiceDisputeCommand,
  ): Promise<InvoiceDisputeResult> {
    const outcome = command?.outcome;
    if (
      outcome !== "accepted" &&
      outcome !== "rejected" &&
      outcome !== "withdrawn"
    ) {
      throw commerceValidationError(
        "Invoice dispute decision outcome is invalid",
        "outcome",
      );
    }
    return this.adjudicateInvoiceDispute({
      operation: "invoice.dispute.decide",
      targetStatus: outcome,
      ...command,
    });
  }

  async withdrawInvoiceDispute(
    command: WithdrawInvoiceDisputeCommand,
  ): Promise<InvoiceDisputeResult> {
    return this.adjudicateInvoiceDispute({
      operation: "invoice.dispute.withdraw",
      targetStatus: "withdrawn",
      ...command,
    });
  }

  private async adjudicateInvoiceDispute(input: {
    readonly operation: string;
    readonly targetStatus: InvoiceDisputeStatus;
    readonly tenantId: string;
    readonly invoiceId: string;
    readonly disputeId: string;
    readonly idempotencyKey: string;
    readonly actorId?: string;
    readonly requestId?: string;
    readonly at?: string;
    readonly reference?: string;
    readonly resolutionNote?: string;
  }): Promise<InvoiceDisputeResult> {
    const tenantId = normalizeCommerceTenantId(input.tenantId);
    const invoiceId = assertCommerceId(input.invoiceId, "invoice", "invoiceId");
    const disputeId = assertCommerceId(input.disputeId, "invoiceDispute", "disputeId");
    const idempotencyKey = normalizeIdempotencyKey(input.idempotencyKey);
    const actorId = input.actorId === undefined
      ? COMMERCE_IDEMPOTENCY_SERVICE_ACTOR
      : requireCommerceIdentifier(input.actorId, "actorId");
    const requestId = input.requestId === undefined
      ? idempotencyKey
      : requireCommerceIdentifier(input.requestId, "requestId");
    const terminal = (INVOICE_DISPUTE_OUTCOMES as readonly InvoiceDisputeStatus[])
      .includes(input.targetStatus);
    const adjudicated = input.targetStatus === "accepted" ||
      input.targetStatus === "rejected";
    const reference = terminal
      ? requireCommerceEvidenceReference(input.reference)
      : input.reference === undefined
        ? undefined
        : requireCommerceEvidenceReference(input.reference);
    const resolutionNote = input.resolutionNote === undefined
      ? undefined
      : requireCommerceDisputeResolutionNote(input.resolutionNote);
    const requestHash = hashCommerceRequest({
      tenantId,
      operation: input.operation,
      invoiceId,
      disputeId,
      targetStatus: input.targetStatus,
      reference,
      resolutionNote,
    });
    const result = await this.executeCommerceIdempotent(
      {
        tenantId,
        actorId,
        operation: input.operation,
        key: idempotencyKey,
      },
      requestHash,
      async () => {
        const dispute = await this.requireInvoiceDispute(tenantId, disputeId);
        if (dispute.invoiceId !== invoiceId) {
          throw commerceResourceNotFound("invoiceDispute");
        }
        const decidedAt = input.at === undefined
          ? this.timestamp()
          : normalizeCommerceTimestamp(input.at, "at");
        const decided = await this.repositories.invoiceDisputes.decide(
          tenantId,
          disputeId,
          {
            targetStatus: input.targetStatus,
            expectedVersion: dispute.version,
            decidedBy: actorId,
            decidedAt,
            ...(reference === undefined ? {} : { reference }),
            ...(resolutionNote === undefined ? {} : { resolutionNote }),
          },
        );
        return {
          dispute: toCommerceInvoiceDisputeView(decided),
          fromStatus: dispute.status,
          replayed: false,
        } satisfies InvoiceDisputeResult;
      },
    );
    await this.publishCommerceDomainEvent(
      {
        tenantId,
        actorId,
        operation: input.operation,
        idempotencyKey,
        requestId,
      },
      (value) => adjudicated
        ? commerceDisputeDecidedEvent(value.dispute)
        : commerceDisputeStatusChangedEvent(value.dispute, value.fromStatus),
      result.value,
    );
    return {
      dispute: cloneCommerceValue(result.value.dispute),
      fromStatus: result.value.fromStatus,
      replayed: result.replayed,
    };
  }

  private async requireInvoiceDispute(
    tenantId: string,
    id: string,
  ): Promise<InvoiceDispute> {
    const dispute = await this.repositories.invoiceDisputes.get(tenantId, id);
    if (
      dispute === undefined ||
      dispute.tenantId !== tenantId ||
      dispute.id !== id
    ) {
      throw commerceResourceNotFound("invoiceDispute");
    }
    return dispute;
  }

  private async eventsOperationalReady(): Promise<boolean> {
    if (!this.eventsEnabled) return true;
    const readiness = this.eventPublisher?.readiness;
    return readiness === undefined ? true : safeCommerceReadiness(readiness);
  }

  private async commerceEventFromStatus(
    tenantId: string,
    resource: string,
    id: string,
  ): Promise<string | undefined> {
    try {
      switch (resource) {
        case "marketplaceListing":
          return (await this.repositories.marketplaceListings.get(tenantId, id))?.status;
        case "partnerAccount":
          return (await this.repositories.partnerAccounts.get(tenantId, id))?.status;
        case "commissionRule":
          return (await this.repositories.commissionRules.get(tenantId, id))?.status;
        case "invoice":
          return (await this.repositories.invoices.get(tenantId, id))?.status;
        default:
          return undefined;
      }
    } catch {
      return undefined;
    }
  }

  private async publishCommerceDomainEvent<T>(
    scope: CommerceDomainEventScope,
    factory: OpenPlatformDomainEventFactory<T>,
    result: T,
  ): Promise<void> {
    const publisher = this.eventPublisher;
    if (!this.eventsEnabled || publisher === undefined) return;
    let descriptor: OpenPlatformDomainEventDescriptor | undefined;
    try {
      descriptor = factory(result);
    } catch {
      return;
    }
    if (descriptor === undefined) return;
    try {
      const record = await publisher.record({
        eventId: commerceDomainEventId(scope),
        tenantId: scope.tenantId,
        eventType: descriptor.eventType,
        resourceType: descriptor.resourceType,
        resourceId: descriptor.resourceId,
        ...(descriptor.resourceVersion === undefined
          ? {}
          : { resourceVersion: descriptor.resourceVersion }),
        ...(descriptor.resourceStatus === undefined
          ? {}
          : { resourceStatus: descriptor.resourceStatus }),
        actorId: scope.actorId,
        ...(scope.requestId === undefined ? {} : { requestId: scope.requestId }),
        occurredAt: this.timestamp(),
        ...(descriptor.data === undefined ? {} : { data: descriptor.data }),
      });
      await publisher.publish(record);
    } catch (error) {
      if (!this.production) return;
      await this.appendCommerceEventFailureAudit(scope, descriptor, error);
      throw commerceStorageUnavailable();
    }
  }

  private async appendCommerceEventFailureAudit(
    scope: CommerceDomainEventScope,
    descriptor: OpenPlatformDomainEventDescriptor,
    error: unknown,
  ): Promise<void> {
    const audit = this.audit;
    if (audit === undefined) return;
    try {
      await audit.append({
        tenantId: scope.tenantId,
        action: `${scope.operation}.event`,
        outcome: "failure",
        actor: { type: "user", id: scope.actorId },
        target: {
          type: commerceAuditTargetType(descriptor.resourceType),
          id: descriptor.resourceId,
        },
        ...(scope.requestId === undefined ? {} : { requestId: scope.requestId }),
        metadata: {
          errorCode: isOpenPlatformCommerceError(error)
            ? error.code
            : OPEN_PLATFORM_COMMERCE_ERROR_CODES.STORAGE_UNAVAILABLE,
          eventType: descriptor.eventType,
        },
      });
    } catch {
      return;
    }
  }

  private async executeCommerceIdempotent<T>(
    scope: CommerceIdempotencyScope,
    requestHash: string,
    action: () => Promise<T>,
  ): Promise<{ readonly value: T; readonly replayed: boolean }> {
    const normalized = normalizeCommerceIdempotencyScope(scope);
    const storageKey = commerceIdempotencyScopeKey(normalized);
    const existing = await this.replayCommerceIdempotent<T>(normalized, requestHash);
    if (existing !== undefined) return existing;
    const previous = this.idempotencyLocks.get(storageKey);
    if (previous !== undefined) {
      await previous;
      const raced = await this.replayCommerceIdempotent<T>(normalized, requestHash);
      if (raced === undefined) {
        throw commerceResourceConflict("Commerce idempotency operation is still in progress");
      }
      return raced;
    }
    let release!: () => void;
    const current = new Promise<void>((resolve) => {
      release = resolve;
    });
    this.idempotencyLocks.set(storageKey, current);
    try {
      const value = await action();
      await this.idempotency.put({
        scope: normalized,
        requestHash,
        value: cloneCommerceValue(value),
        createdAt: this.timestamp(),
      });
      return { value, replayed: false };
    } finally {
      release();
      if (this.idempotencyLocks.get(storageKey) === current) {
        this.idempotencyLocks.delete(storageKey);
      }
    }
  }

  private async replayCommerceIdempotent<T>(
    scope: CommerceIdempotencyScope,
    requestHash: string,
  ): Promise<{ readonly value: T; readonly replayed: boolean } | undefined> {
    const record = await this.idempotency.get(scope);
    if (record === undefined) return undefined;
    if (Date.parse(record.expiresAt) <= Date.parse(this.timestamp())) {
      await this.idempotency.delete(scope);
      return undefined;
    }
    if (record.requestHash !== requestHash) {
      throw commerceIdempotencyKeyReused();
    }
    return {
      value: cloneCommerceValue(record.value) as T,
      replayed: true,
    };
  }

  private pageCommerceRecords<T extends { readonly id: string; readonly createdAt: string }, R>(
    records: readonly T[],
    query: {
      readonly tenantId: string;
      readonly cursor?: string;
      readonly limit?: number | string;
      readonly pageSize?: number | string;
    },
    kind: string,
    scope: string,
    mapper: (record: T) => R,
  ): CommercePage<R> {
    const page = normalizeCommercePageQuery(query);
    const ordered = [...records].sort((left, right) => {
      const created = left.createdAt.localeCompare(right.createdAt);
      return created === 0 ? left.id.localeCompare(right.id) : created;
    });
    const offset = page.cursor === undefined
      ? 0
      : decodeCommerceCursor(page.cursor, kind, scope);
    const items = ordered.slice(offset, offset + page.limit).map(mapper);
    const hasMore = offset + items.length < ordered.length;
    return {
      items,
      hasMore,
      total: ordered.length,
      ...(hasMore
        ? { nextCursor: encodeCommerceCursor({ version: 1, kind, scope, offset: offset + items.length }) }
        : {}),
    };
  }

  private async terminateQuota(
    command: SettleQuotaCommand | ReleaseQuotaCommand,
    target: "settled" | "released",
  ): Promise<QuotaOperationResult> {
    const tenantId = normalizeCommerceTenantId(command?.tenantId);
    const quotaId = assertCommerceId(command.quotaId, "quota", "quotaId");
    const reservationId = assertCommerceId(
      command.reservationId,
      "quotaReservation",
      "reservationId",
    );
    const idempotencyKey = normalizeIdempotencyKey(command.idempotencyKey);
    const actualQuantity = target === "settled"
      ? normalizeDecimal(
        (command as SettleQuotaCommand).actualQuantity,
        "actualQuantity",
      )
      : "0";
    const reservation = await this.repositories.quotaReservations.get(
      tenantId,
      reservationId,
    );
    if (
      reservation === undefined ||
      reservation.quotaId !== quotaId
    ) {
      throw commerceResourceNotFound("quotaReservation");
    }
    const at = this.timestamp();
    const requestHash = hashCommerceRequest({
      tenantId,
      operation: target,
      quotaId,
      reservationId,
      idempotencyKey,
      ...(target === "settled" ? { actualQuantity } : {}),
    });
    if (target === "settled") {
      return this.repositories.quotas.settleAtomic({
        tenantId,
        operation: "quota.settle",
        quotaId,
        reservationId,
        actualQuantity,
        requestHash,
        settledAt: at,
        idempotencyKey,
      });
    }
    return this.repositories.quotas.releaseAtomic({
      tenantId,
      operation: "quota.release",
      quotaId,
      reservationId,
      requestHash,
      releasedAt: at,
      idempotencyKey,
    });
  }

  private async normalizeUsageCommand(command: RecordUsageEventCommand): Promise<RecordUsageEventCommand> {
    const tenantId = normalizeCommerceTenantId(command?.tenantId);
    const subscriptionId = assertCommerceId(
      command.subscriptionId,
      "subscription",
      "subscriptionId",
    );
    const meterId = assertCommerceId(command.meterId, "meter", "meterId");
    const meter = await this.requireMeter(tenantId, meterId);
    const period = normalizePeriod(command.periodStart, command.periodEnd);
    const occurredAt = normalizeCommerceTimestamp(command.occurredAt, "occurredAt");
    if (
      Date.parse(occurredAt) < Date.parse(period.periodStart) ||
      Date.parse(occurredAt) >= Date.parse(period.periodEnd)
    ) {
      throw commerceValidationError(
        "Usage event must occur inside its billing period",
        "occurredAt",
      );
    }
    return {
      tenantId,
      subscriptionId,
      meterId,
      quantity: normalizeDecimal(command.quantity, "quantity", false),
      occurredAt,
      periodStart: period.periodStart,
      periodEnd: period.periodEnd,
      dimensions: normalizeDimensions(command.dimensions, meter.dimensions),
      sourceEventId: requireCommerceIdentifier(
        command.sourceEventId,
        "sourceEventId",
      ),
      idempotencyKey: normalizeIdempotencyKey(command.idempotencyKey),
    };
  }

  private async normalizePriceUsage(
    tenantId: string,
    price: Price,
    usage: readonly {
      readonly meterId: string;
      readonly quantity: DecimalString;
      readonly aggregateId?: string;
    }[],
  ): Promise<{
    quantities: Readonly<Record<string, DecimalString>>;
    aggregateIds: ReadonlyMap<string, string[]>;
  }> {
    if (price.priceType === "fixed") {
      return { quantities: {}, aggregateIds: new Map() };
    }
    await this.requireMeter(tenantId, price.meterId);
    const relevant = usage.filter((item) => item.meterId === price.meterId);
    if (relevant.length === 0) {
      return { quantities: { [price.meterId]: "0" }, aggregateIds: new Map() };
    }
    const meter = await this.requireMeter(tenantId, price.meterId);
    const quantities: Record<string, DecimalString> = {};
    for (const item of relevant) {
      const quantity = normalizeDecimal(item.quantity, "quantity");
      if (item.aggregateId !== undefined) {
        const aggregate = await this.repositories.usageAggregates.get(
          tenantId,
          item.aggregateId,
        );
        if (aggregate === undefined) {
          throw commerceResourceNotFound("usageAggregate");
        }
      }
      quantities[price.meterId] = quantities[price.meterId] === undefined
        ? quantity
        : combineAggregateQuantity(meter.aggregation, quantities[price.meterId], quantity);
    }
    const aggregateIds = new Map<string, string[]>();
    for (const item of relevant) {
      if (item.aggregateId === undefined) continue;
      const aggregate = await this.repositories.usageAggregates.get(
        tenantId,
        item.aggregateId,
      );
      if (aggregate === undefined) {
        throw commerceResourceNotFound("usageAggregate");
      }
      const ids = aggregateIds.get(item.meterId) ?? [];
      ids.push(item.aggregateId);
      aggregateIds.set(item.meterId, ids);
    }
    return { quantities, aggregateIds };
  }

  private async requirePlan(tenantId: string, id: string): Promise<Plan> {
    const record = await this.repositories.plans.get(tenantId, id);
    if (record === undefined) throw commerceResourceNotFound("plan");
    return record;
  }

  private async requireEntitlement(
    tenantId: string,
    id: string,
  ): Promise<Entitlement> {
    const record = await this.repositories.entitlements.get(tenantId, id);
    if (record === undefined) throw commerceResourceNotFound("entitlement");
    return record;
  }

  private async requireMeter(tenantId: string, id: string): Promise<Meter> {
    const record = await this.repositories.meters.get(tenantId, id);
    if (record === undefined) throw commerceResourceNotFound("meter");
    return record;
  }

  private async requirePrice(tenantId: string, id: string): Promise<Price> {
    const record = await this.repositories.prices.get(tenantId, id);
    if (record === undefined) throw commerceResourceNotFound("price");
    return record;
  }

  private async requireSubscription(
    tenantId: string,
    id: string,
  ): Promise<Subscription> {
    const record = await this.repositories.subscriptions.get(tenantId, id);
    if (record === undefined) throw commerceResourceNotFound("subscription");
    return record;
  }

  private async requireUsableSubscription(
    tenantId: string,
    id: string,
  ): Promise<Subscription> {
    const subscription = await this.requireSubscription(tenantId, id);
    if (
      subscription.status !== "active" &&
      subscription.status !== "trialing"
    ) {
      throw commerceResourceConflict("Subscription is not usable");
    }
    return subscription;
  }

  private async requireQuota(tenantId: string, id: string): Promise<Quota> {
    const record = await this.repositories.quotas.get(tenantId, id);
    if (record === undefined) throw commerceResourceNotFound("quota");
    return record;
  }

  private async requireListing(
    tenantId: string,
    id: string,
  ): Promise<MarketplaceListing> {
    const record = await this.repositories.marketplaceListings.get(tenantId, id);
    if (record === undefined) throw commerceResourceNotFound("marketplaceListing");
    return record;
  }

  private async requirePartnerAccount(
    tenantId: string,
    id: string,
  ): Promise<PartnerAccount> {
    const record = await this.repositories.partnerAccounts.get(tenantId, id);
    if (record === undefined) throw commerceResourceNotFound("partnerAccount");
    return record;
  }

  private async requireCommissionRule(
    tenantId: string,
    id: string,
  ): Promise<CommissionRule> {
    const record = await this.repositories.commissionRules.get(tenantId, id);
    if (record === undefined) throw commerceResourceNotFound("commissionRule");
    return record;
  }

  private newId(
    kind: CommerceEntityKind | "invoice" | "invoiceLine" | "usageEvent" | "invoiceDispute",
  ): string {
    return this.idGenerator(kind);
  }

  private timestamp(): string {
    const value = this.clock();
    if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
      throw commerceValidationError("Commerce clock returned an invalid date", "clock");
    }
    return value.toISOString();
  }
}

export function createCommerceService(
  options: CommerceServiceOptions = {},
): CommerceDomainService {
  return new CommerceDomainService(options);
}

function commerceQueryScope(
  kind: string,
  query: {
    readonly tenantId: string;
    readonly id?: string;
    readonly status?: string;
    readonly partnerAccountId?: string;
    readonly productId?: string;
    readonly search?: string;
    readonly partnerCode?: string;
    readonly listingId?: string;
    readonly subscriptionId?: string;
    readonly planId?: string;
    readonly periodStart?: string;
    readonly periodEnd?: string;
    readonly from?: string;
    readonly to?: string;
  },
): string {
  return hashCommerceRequest({
    kind,
    tenantId: query.tenantId,
    id: query.id,
    status: query.status,
    partnerAccountId: query.partnerAccountId,
    productId: query.productId,
    search: query.search,
    partnerCode: query.partnerCode,
    listingId: query.listingId,
    subscriptionId: query.subscriptionId,
    planId: query.planId,
    periodStart: query.periodStart,
    periodEnd: query.periodEnd,
    from: query.from,
    to: query.to,
  });
}

function listingMatchesSearch(
  listing: MarketplaceListing,
  search: string,
): boolean {
  const normalized = search.toLocaleLowerCase();
  return [listing.title, listing.description, listing.productId]
    .some((value) => value.toLocaleLowerCase().includes(normalized));
}

function partnerMatchesSearch(
  partner: PartnerAccount,
  search: string,
): boolean {
  const normalized = search.toLocaleLowerCase();
  return [partner.legalName, partner.partnerCode]
    .some((value) => value.toLocaleLowerCase().includes(normalized));
}

function aggregateQuantities(
  events: readonly UsageEvent[],
  aggregation: Meter["aggregation"],
): DecimalString {
  if (events.length === 0) return "0";
  if (aggregation === "sum") {
    return events.reduce(
      (sum, event) => addDecimalStrings(sum, event.quantity),
      "0",
    );
  }
  if (aggregation === "max") {
    return events.reduce(
      (maximum, event) => maxDecimalStrings(maximum, event.quantity),
      events[0]?.quantity ?? "0",
    );
  }
  return events[events.length - 1]?.quantity ?? "0";
}

function combineAggregateQuantity(
  aggregation: Meter["aggregation"],
  left: DecimalString,
  right: DecimalString,
): DecimalString {
  if (aggregation === "sum") return addDecimalStrings(left, right);
  if (aggregation === "max") return maxDecimalStrings(left, right);
  return right;
}

function matchesEntitlementSource(
  entitlement: Entitlement,
  tenantId: string,
  planId: string | undefined,
  subscriptionId: string | undefined,
): boolean {
  if (entitlement.source === "tenant") {
    return entitlement.sourceId === tenantId;
  }
  if (entitlement.source === "plan") {
    return planId !== undefined && entitlement.sourceId === planId;
  }
  return (
    subscriptionId !== undefined &&
    entitlement.sourceId === subscriptionId
  );
}

function compareEntitlementPriority(left: Entitlement, right: Entitlement): number {
  if (left.priority !== right.priority) return right.priority - left.priority;
  const sourcePriority = sourceSpecificity(right.source) - sourceSpecificity(left.source);
  if (sourcePriority !== 0) return sourcePriority;
  if (left.effect !== right.effect) return left.effect === "deny" ? -1 : 1;
  const effective = right.effectiveFrom.localeCompare(left.effectiveFrom);
  if (effective !== 0) return effective;
  const created = right.createdAt.localeCompare(left.createdAt);
  return created === 0 ? left.id.localeCompare(right.id) : created;
}

function sourceSpecificity(source: Entitlement["source"]): number {
  return source === "subscription" ? 3 : source === "plan" ? 2 : 1;
}

function validatePriceRecord(price: Price, at: string): void {
  if (price.status !== "active") {
    throw commerceResourceConflict("Price is not active");
  }
  if (!isEffectiveAt(price.effectiveFrom, price.effectiveTo, at)) {
    throw commerceResourceConflict("Price is not effective");
  }
  if (price.currency !== "CNY") {
    throw commerceValidationError("Only CNY prices are supported", "currency");
  }
  if (price.priceType === "fixed") {
    assertMoney(price.fixedAmount, "fixedAmount");
    return;
  }
  if (price.priceType === "tiered") {
    if (!Array.isArray(price.tiers) || price.tiers.length === 0) {
      throw commerceValidationError("Tiered price is invalid", "tiers");
    }
    return;
  }
  assertMoney(price.unitAmount, "unitAmount");
  assertDecimalString(price.includedUnits, "includedUnits");
  assertMoney(price.minimumCharge, "minimumCharge");
  if (price.priceType === "mixed") {
    assertMoney(price.fixedAmount, "fixedAmount");
  }
}

function requiredValue<T>(value: T | undefined, field: string): T {
  if (value === undefined) {
    throw commerceValidationError("Commerce value is required", field);
  }
  return value;
}

function normalizePriceTiers(values: readonly PriceTier[]): PriceTier[] {
  if (values.length === 0) {
    throw commerceValidationError("Tiered price requires tiers", "tiers");
  }
  return values.map((tier, index) => ({
    upTo: tier.upTo === null
      ? null
      : normalizeDecimal(tier.upTo, `tiers.${index}.upTo`, false),
    unitAmount: normalizeMoney(
      tier.unitAmount,
      `tiers.${index}.unitAmount`,
    ),
  }));
}

function normalizeCurrency(value?: string): "CNY" {
  if (value !== undefined && value !== "CNY") {
    throw commerceValidationError("Only CNY is supported", "currency");
  }
  return "CNY";
}

function normalizeIdList(
  values: readonly string[] | undefined,
  kind: CommerceEntityKind,
): string[] {
  const normalized = (values ?? []).map((value) => assertCommerceId(value, kind));
  return [...new Set(normalized)].sort((left, right) => left.localeCompare(right));
}

function normalizeStringList(values: readonly string[]): string[] {
  const normalized = values.map((value) => requireCommerceIdentifier(value, "dimensions"));
  return [...new Set(normalized)].sort((left, right) => left.localeCompare(right));
}

function normalizeEntitlementSource(
  tenantId: string,
  command: GrantEntitlementCommand,
): string {
  if (command.source === "tenant") {
    if (command.sourceId !== tenantId) {
      throw commerceValidationError("Tenant entitlement source is invalid", "sourceId");
    }
    return tenantId;
  }
  if (command.source === "plan") {
    return assertCommerceId(command.sourceId, "plan", "sourceId");
  }
  if (command.source === "subscription") {
    return assertCommerceId(
      command.sourceId,
      "subscription",
      "sourceId",
    );
  }
  throw commerceValidationError("Entitlement source is invalid", "source");
}

function normalizeInvoiceAdjustments(
  values: readonly InvoiceAdjustment[],
  currency: "CNY",
): InvoiceAdjustment[] {
  const ids = new Set<string>();
  return values
    .map((adjustment) => {
      const id = requireCommerceIdentifier(adjustment.id, "adjustment.id");
      if (ids.has(id)) {
        throw commerceValidationError("Invoice adjustment identifier is duplicated", "id");
      }
      ids.add(id);
      if (
        adjustment.type !== "discount" &&
        adjustment.type !== "refund" &&
        adjustment.type !== "surcharge" &&
        adjustment.type !== "credit"
      ) {
        throw commerceValidationError("Invoice adjustment type is invalid", "type");
      }
      if (adjustment.direction !== "debit" && adjustment.direction !== "credit") {
        throw commerceValidationError("Invoice adjustment direction is invalid", "direction");
      }
      const amount = normalizeMoney(adjustment.amount, "adjustment.amount", false);
      if (amount.currency !== currency) {
        throw commerceValidationError("Invoice adjustment currency is invalid", "amount");
      }
      return {
        id,
        type: adjustment.type,
        direction: adjustment.direction,
        amount,
        reason: requireCommerceText(adjustment.reason, "adjustment.reason", 500),
        ...(adjustment.evidenceReference === undefined
          ? {}
          : {
              evidenceReference: requireCommerceIdentifier(
                adjustment.evidenceReference,
                "adjustment.evidenceReference",
              ),
            }),
      };
    })
    .sort((left, right) => left.id.localeCompare(right.id));
}

function assertExternalReferenceId(
  value: unknown,
  prefix: string,
  field: string,
): string {
  if (typeof value !== "string") {
    throw commerceValidationError("External commerce reference is invalid", field);
  }
  const normalized = value.trim();
  if (
    !normalized.startsWith(`${prefix}_`) ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
      normalized.slice(prefix.length + 1),
    )
  ) {
    throw commerceValidationError("External commerce reference is invalid", field);
  }
  return normalized;
}

function sameDimensions(
  left: Readonly<Record<string, string>>,
  right: Readonly<Record<string, string>>,
): boolean {
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  return (
    leftKeys.length === rightKeys.length &&
    leftKeys.every((key, index) =>
      key === rightKeys[index] && left[key] === right[key]
    )
  );
}

function sameStringArray(
  left: readonly string[],
  right: readonly string[],
): boolean {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

function commerceAuditTargetType(
  resourceType: string,
): CommerceAuditResourceType {
  if (resourceType === "invoiceDispute") return "invoice";
  return (COMMERCE_AUDIT_RESOURCE_TYPES as readonly string[]).includes(resourceType)
    ? resourceType as CommerceAuditResourceType
    : "invoice";
}

function isCommerceConflict(error: unknown): boolean {
  return error instanceof Error &&
    error.name === "OpenPlatformCommerceError" &&
    "code" in error &&
    (error as { code?: string }).code ===
      "OPEN_PLATFORM_COMMERCE_RESOURCE_CONFLICT";
}

async function safeCommerceReadiness(
  readiness: CommerceDependencyReadiness | undefined,
): Promise<boolean> {
  if (readiness === undefined || typeof readiness.ready !== "function") return false;
  try {
    return (await readiness.ready()) === true;
  } catch {
    return false;
  }
}

function isUsageAggregation(value: unknown): value is Meter["aggregation"] {
  return value === "sum" || value === "max" || value === "last";
}

function planStatus(value: string): PlanStatus {
  if (value === "draft" || value === "active" || value === "retired") return value;
  throw commerceValidationError("Plan status is invalid", "targetStatus");
}

function entitlementStatus(value: string): EntitlementStatus {
  if (
    value === "pending" ||
    value === "active" ||
    value === "suspended" ||
    value === "revoked" ||
    value === "expired"
  ) return value;
  throw commerceValidationError("Entitlement status is invalid", "targetStatus");
}

function meterStatus(value: string): MeterStatus {
  if (value === "draft" || value === "active" || value === "retired") return value;
  throw commerceValidationError("Meter status is invalid", "targetStatus");
}

function priceStatus(value: string): PriceStatus {
  if (
    value === "draft" ||
    value === "scheduled" ||
    value === "active" ||
    value === "retired"
  ) return value;
  throw commerceValidationError("Price status is invalid", "targetStatus");
}

function subscriptionStatus(value: string): SubscriptionStatus {
  if (
    value === "pending" ||
    value === "trialing" ||
    value === "active" ||
    value === "pastDue" ||
    value === "suspended" ||
    value === "canceled" ||
    value === "expired"
  ) return value;
  throw commerceValidationError("Subscription status is invalid", "targetStatus");
}

function quotaStatus(value: string): "active" | "disabled" | "retired" {
  if (value === "active" || value === "disabled" || value === "retired") return value;
  throw commerceValidationError("Quota status is invalid", "targetStatus");
}

function usageAggregateStatus(value: string): UsageAggregateStatus {
  if (
    value === "collecting" ||
    value === "closed" ||
    value === "priced" ||
    value === "settled"
  ) return value;
  throw commerceValidationError("Usage aggregate status is invalid", "targetStatus");
}

function marketplaceListingStatus(value: string): MarketplaceListingStatus {
  if (
    value === "draft" ||
    value === "pendingReview" ||
    value === "published" ||
    value === "suspended" ||
    value === "removed"
  ) return value;
  throw commerceValidationError("Marketplace listing status is invalid", "targetStatus");
}

function partnerAccountStatus(value: string): PartnerAccountStatus {
  if (
    value === "pending" ||
    value === "underReview" ||
    value === "active" ||
    value === "frozen" ||
    value === "rejected" ||
    value === "closed"
  ) return value;
  throw commerceValidationError("Partner account status is invalid", "targetStatus");
}

function commissionRuleStatus(value: string): CommissionRuleStatus {
  if (
    value === "draft" ||
    value === "scheduled" ||
    value === "active" ||
    value === "suspended" ||
    value === "retired"
  ) return value;
  throw commerceValidationError("Commission rule status is invalid", "targetStatus");
}

function invoiceStatus(value: string): InvoiceStatus {
  if (
    value === "draft" ||
    value === "reconciling" ||
    value === "awaitingPayment" ||
    value === "invoicing" ||
    value === "paid" ||
    value === "completed" ||
    value === "disputed" ||
    value === "voided"
  ) return value;
  throw commerceValidationError("Invoice status is invalid", "targetStatus");
}

function commerceId(
  kind: CommerceEntityKind | "invoice" | "invoiceLine" | "usageEvent" | "invoiceDispute",
): string {
  const prefixes = {
    plan: "plan",
    entitlement: "entitlement",
    meter: "meter",
    price: "price",
    subscription: "subscription",
    quota: "quota",
    quotaReservation: "quota-reservation",
    usageAggregate: "usage-aggregate",
    marketplaceListing: "listing",
    partnerAccount: "partner",
    commissionRule: "commission-rule",
    usageEvent: "usage-event",
    invoice: "invoice",
    invoiceLine: "invoice-line",
    invoiceDispute: "invoice-dispute",
  } as const;
  return `${prefixes[kind]}_${randomUUID()}`;
}
