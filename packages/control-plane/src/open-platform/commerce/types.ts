export const COMMERCE_CURRENCIES = ["CNY"] as const;
export type CommerceCurrency = (typeof COMMERCE_CURRENCIES)[number];
export type DecimalString = string;
export type RoundingMode = "halfEven" | "halfUp";
export type MaybePromise<T> = T | Promise<T>;
export const COMMERCE_DEFAULT_PAGE_SIZE = 20;
export const COMMERCE_MAX_PAGE_SIZE = 100;
export const COMMERCE_PAGE_DEFAULT_LIMIT = COMMERCE_DEFAULT_PAGE_SIZE;
export const COMMERCE_PAGE_MAX_LIMIT = COMMERCE_MAX_PAGE_SIZE;

export const COMMERCE_ENTITY_KINDS = [
  "plan",
  "entitlement",
  "meter",
  "price",
  "subscription",
  "quota",
  "quotaReservation",
  "usageAggregate",
  "marketplaceListing",
  "partnerAccount",
  "commissionRule",
] as const;
export type CommerceEntityKind = (typeof COMMERCE_ENTITY_KINDS)[number];

export const COMMERCE_ENTITY_PREFIXES = Object.freeze({
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
} satisfies Readonly<Record<string, string>>);

export interface TenantScopedRecord {
  readonly id: string;
  readonly tenantId: string;
  readonly kind: CommerceEntityKind;
  readonly version: number;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface Money {
  readonly amountMinor: number;
  readonly currency: CommerceCurrency;
}

export const PLAN_STATUSES = ["draft", "active", "retired"] as const;
export type PlanStatus = (typeof PLAN_STATUSES)[number];

export const ENTITLEMENT_STATUSES = [
  "pending",
  "active",
  "suspended",
  "revoked",
  "expired",
] as const;
export type EntitlementStatus = (typeof ENTITLEMENT_STATUSES)[number];

export const METER_STATUSES = ["draft", "active", "retired"] as const;
export type MeterStatus = (typeof METER_STATUSES)[number];

export const PRICE_STATUSES = [
  "draft",
  "scheduled",
  "active",
  "retired",
] as const;
export type PriceStatus = (typeof PRICE_STATUSES)[number];

export const SUBSCRIPTION_STATUSES = [
  "pending",
  "trialing",
  "active",
  "pastDue",
  "suspended",
  "canceled",
  "expired",
] as const;
export type SubscriptionStatus = (typeof SUBSCRIPTION_STATUSES)[number];

export const QUOTA_STATUSES = ["active", "disabled", "retired"] as const;
export type QuotaStatus = (typeof QUOTA_STATUSES)[number];

export const QUOTA_RESERVATION_STATUSES = [
  "reserved",
  "settled",
  "released",
  "expired",
] as const;
export type QuotaReservationStatus =
  (typeof QUOTA_RESERVATION_STATUSES)[number];

export const QUOTA_RESERVATION_OPERATIONS = [
  "quota.reserve",
  "quota.settle",
  "quota.release",
] as const;
export type QuotaReservationOperation =
  (typeof QUOTA_RESERVATION_OPERATIONS)[number];

export const USAGE_AGGREGATION_METHODS = ["sum", "max", "last"] as const;
export type UsageAggregationMethod =
  (typeof USAGE_AGGREGATION_METHODS)[number];

export const USAGE_AGGREGATE_STATUSES = [
  "collecting",
  "closed",
  "priced",
  "settled",
] as const;
export type UsageAggregateStatus =
  (typeof USAGE_AGGREGATE_STATUSES)[number];

export const INVOICE_STATUSES = [
  "draft",
  "reconciling",
  "awaitingPayment",
  "invoicing",
  "paid",
  "completed",
  "disputed",
  "voided",
] as const;
export type InvoiceStatus = (typeof INVOICE_STATUSES)[number];

export const COMMERCE_DISPUTE_REASON_MAX_LENGTH = 500;
export const COMMERCE_DISPUTE_EVIDENCE_MAX_LENGTH = 128;

export const INVOICE_DISPUTE_STATUSES = [
  "open",
  "underReview",
  "accepted",
  "rejected",
  "withdrawn",
] as const;
export type InvoiceDisputeStatus = (typeof INVOICE_DISPUTE_STATUSES)[number];

export const INVOICE_DISPUTE_OUTCOMES = [
  "accepted",
  "rejected",
  "withdrawn",
] as const;
export type InvoiceDisputeOutcome = (typeof INVOICE_DISPUTE_OUTCOMES)[number];

export const COMMERCE_DISPUTE_RESOLUTION_NOTE_MAX_LENGTH =
  COMMERCE_DISPUTE_REASON_MAX_LENGTH;

export const INVOICE_DISPUTE_EVENTS = ["invoice.dispute.opened"] as const;
export type InvoiceDisputeEventType = (typeof INVOICE_DISPUTE_EVENTS)[number];

export const MARKETPLACE_LISTING_STATUSES = [
  "draft",
  "pendingReview",
  "published",
  "suspended",
  "removed",
] as const;
export type MarketplaceListingStatus =
  (typeof MARKETPLACE_LISTING_STATUSES)[number];

export const PARTNER_ACCOUNT_STATUSES = [
  "pending",
  "underReview",
  "active",
  "frozen",
  "rejected",
  "closed",
] as const;
export type PartnerAccountStatus =
  (typeof PARTNER_ACCOUNT_STATUSES)[number];

export const COMMISSION_RULE_STATUSES = [
  "draft",
  "scheduled",
  "active",
  "suspended",
  "retired",
] as const;
export type CommissionRuleStatus =
  (typeof COMMISSION_RULE_STATUSES)[number];

export interface Plan extends TenantScopedRecord {
  readonly kind: "plan";
  readonly code: string;
  readonly name: string;
  readonly description?: string;
  readonly status: PlanStatus;
  readonly priority: number;
  readonly currency: CommerceCurrency;
  readonly priceIds: readonly string[];
  readonly entitlementIds: readonly string[];
  readonly quotaIds: readonly string[];
  readonly effectiveFrom: string;
  readonly effectiveTo?: string;
}

export type EntitlementSource = "tenant" | "plan" | "subscription";

export interface Entitlement extends TenantScopedRecord {
  readonly kind: "entitlement";
  readonly feature: string;
  readonly effect: "allow" | "deny";
  readonly value?: boolean | number | string;
  readonly source: EntitlementSource;
  readonly sourceId: string;
  readonly priority: number;
  readonly status: EntitlementStatus;
  readonly effectiveFrom: string;
  readonly effectiveTo?: string;
}

export interface Meter extends TenantScopedRecord {
  readonly kind: "meter";
  readonly key: string;
  readonly name: string;
  readonly unit: string;
  readonly aggregation: UsageAggregationMethod;
  readonly dimensions: readonly string[];
  readonly status: MeterStatus;
}

export interface PriceTier {
  readonly upTo: DecimalString | null;
  readonly unitAmount: Money;
}

interface PriceBase extends TenantScopedRecord {
  readonly kind: "price";
  readonly code: string;
  readonly name: string;
  readonly status: PriceStatus;
  readonly currency: CommerceCurrency;
  readonly roundingMode: RoundingMode;
  readonly effectiveFrom: string;
  readonly effectiveTo?: string;
}

export interface FixedPrice extends PriceBase {
  readonly priceType: "fixed";
  readonly fixedAmount: Money;
}

export interface UsagePrice extends PriceBase {
  readonly priceType: "perUnit";
  readonly meterId: string;
  readonly unitAmount: Money;
  readonly includedUnits: DecimalString;
  readonly minimumCharge: Money;
}

export interface TieredPrice extends PriceBase {
  readonly priceType: "tiered";
  readonly meterId: string;
  readonly tiers: readonly PriceTier[];
}

export interface MixedPrice extends PriceBase {
  readonly priceType: "mixed";
  readonly fixedAmount: Money;
  readonly meterId: string;
  readonly unitAmount: Money;
  readonly includedUnits: DecimalString;
  readonly minimumCharge: Money;
}

export type Price = FixedPrice | UsagePrice | TieredPrice | MixedPrice;

export interface Subscription extends TenantScopedRecord {
  readonly kind: "subscription";
  readonly applicationId: string;
  readonly planId: string;
  readonly name: string;
  readonly status: SubscriptionStatus;
  readonly quantity: DecimalString;
  readonly currentPeriodStart: string;
  readonly currentPeriodEnd: string;
  readonly cancelAtPeriodEnd: boolean;
  readonly canceledAt?: string;
}

export interface Quota extends TenantScopedRecord {
  readonly kind: "quota";
  readonly planId: string;
  readonly meterId: string;
  readonly limit: DecimalString;
  readonly reserved: DecimalString;
  readonly consumed: DecimalString;
  readonly status: QuotaStatus;
}

export interface QuotaReservation extends TenantScopedRecord {
  readonly kind: "quotaReservation";
  readonly quotaId: string;
  readonly planId: string;
  readonly subscriptionId: string;
  readonly meterId: string;
  readonly quantity: DecimalString;
  readonly status: QuotaReservationStatus;
  readonly operation: "quota.reserve";
  readonly idempotencyKey: string;
  readonly requestHash: string;
  readonly expiresAt: string;
  readonly settledQuantity?: DecimalString;
  readonly settledAt?: string;
  readonly releasedAt?: string;
  readonly terminalOperation?: "quota.settle" | "quota.release";
  readonly terminalIdempotencyKey?: string;
  readonly terminalRequestHash?: string;
}

export interface UsageEvent {
  readonly id: string;
  readonly tenantId: string;
  readonly kind: "usageEvent";
  readonly version: 1;
  readonly sourceEventId: string;
  readonly subscriptionId: string;
  readonly meterId: string;
  readonly quantity: DecimalString;
  readonly occurredAt: string;
  readonly periodStart: string;
  readonly periodEnd: string;
  readonly dimensions: Readonly<Record<string, string>>;
  readonly idempotencyKey: string;
  readonly requestHash: string;
  readonly payloadHash: string;
  readonly receivedAt: string;
}

export interface UsageAggregate extends TenantScopedRecord {
  readonly kind: "usageAggregate";
  readonly aggregateKey: string;
  readonly subscriptionId: string;
  readonly meterId: string;
  readonly aggregation: UsageAggregationMethod;
  readonly quantity: DecimalString;
  readonly unit: string;
  readonly periodStart: string;
  readonly periodEnd: string;
  readonly dimensions: Readonly<Record<string, string>>;
  readonly eventIds: readonly string[];
  readonly status: UsageAggregateStatus;
}

export const INVOICE_LINE_TYPES = [
  "subscription",
  "usage",
  "adjustment",
  "tax",
] as const;
export type InvoiceLineType = (typeof INVOICE_LINE_TYPES)[number];

export const INVOICE_ADJUSTMENT_TYPES = [
  "discount",
  "refund",
  "surcharge",
  "credit",
] as const;
export type InvoiceAdjustmentType =
  (typeof INVOICE_ADJUSTMENT_TYPES)[number];

export interface InvoiceAdjustment {
  readonly id: string;
  readonly type: InvoiceAdjustmentType;
  readonly direction: "debit" | "credit";
  readonly amount: Money;
  readonly reason: string;
  readonly evidenceReference?: string;
}

export interface InvoiceLine {
  readonly id: string;
  readonly tenantId: string;
  readonly kind: "invoiceLine";
  readonly invoiceId: string;
  readonly type: InvoiceLineType;
  readonly direction: "debit" | "credit";
  readonly description: string;
  readonly quantity: DecimalString;
  readonly unitAmount: Money;
  readonly amount: Money;
  readonly meterId?: string;
  readonly priceId?: string;
  readonly aggregateId?: string;
  readonly adjustmentType?: InvoiceAdjustmentType;
}

export interface MainlandChinaInvoiceMetadata {
  readonly invoiceType: "vatSpecial" | "vatNormal" | "electronic";
  readonly buyerName: string;
  readonly unifiedSocialCreditCode?: string;
  readonly buyerAddress?: string;
  readonly buyerPhone?: string;
  readonly buyerBankName?: string;
  readonly buyerBankAccount?: string;
  readonly taxRateBps: number;
  readonly issueMode: "platform" | "selfIssued";
  readonly invoiceCode?: string;
  readonly invoiceNumber?: string;
}

export interface Invoice {
  readonly id: string;
  readonly tenantId: string;
  readonly kind: "invoice";
  readonly version: number;
  readonly subscriptionId: string;
  readonly planId: string;
  readonly periodStart: string;
  readonly periodEnd: string;
  readonly status: InvoiceStatus;
  readonly currency: CommerceCurrency;
  readonly taxMode: InvoiceTaxMode;
  readonly lines: readonly InvoiceLine[];
  readonly subtotal: Money;
  readonly tax: Money;
  readonly total: Money;
  readonly idempotencyKey: string;
  readonly requestHash: string;
  readonly mainlandChina?: MainlandChinaInvoiceMetadata;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly finalizedAt?: string;
  readonly paidAt?: string;
  readonly voidedAt?: string;
}

export type MainlandChinaInvoiceMetadataView = Omit<
  MainlandChinaInvoiceMetadata,
  "buyerPhone" | "buyerAddress" | "buyerBankAccount"
> & {
  readonly buyerPhone?: string;
  readonly buyerAddress?: string;
  readonly buyerBankAccount?: string;
};

export type InvoiceView = Omit<
  Invoice,
  "idempotencyKey" | "requestHash" | "mainlandChina"
> & {
  readonly mainlandChina?: MainlandChinaInvoiceMetadataView;
};

export interface InvoiceDisputeResolution {
  readonly outcome: InvoiceDisputeOutcome;
  readonly actorId: string;
  readonly reference: string;
  readonly resolvedAt: string;
  readonly note?: string;
  readonly noteLength?: number;
  readonly fromStatus?: InvoiceDisputeStatus;
}

export interface InvoiceDispute {
  readonly id: string;
  readonly tenantId: string;
  readonly kind: "invoiceDispute";
  readonly version: number;
  readonly event: InvoiceDisputeEventType;
  readonly invoiceId: string;
  readonly subscriptionId: string;
  readonly planId: string;
  readonly invoiceStatus: InvoiceStatus;
  readonly invoiceVersion: number;
  readonly reason: string;
  readonly reasonDigest: string;
  readonly reasonLength: number;
  readonly evidenceReference?: string;
  readonly evidenceReferenceDigest?: string;
  readonly evidenceCount: number;
  readonly actorId: string;
  readonly requestId: string;
  readonly idempotencyKey: string;
  readonly requestHash: string;
  readonly status: InvoiceDisputeStatus;
  readonly resolution?: InvoiceDisputeResolution;
  readonly resolvedAt?: string;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly recordedAt: string;
}

export type InvoiceDisputeView = Omit<
  InvoiceDispute,
  "requestHash" | "idempotencyKey" | "reasonDigest" | "evidenceReferenceDigest"
>;

export interface InvoiceDisputeListQuery {
  readonly invoiceId?: string;
  readonly actorId?: string;
  readonly status?: InvoiceDisputeStatus | string;
  readonly from?: string;
  readonly to?: string;
  readonly limit?: number | string;
}

export interface InvoiceDisputeQuery extends CommercePageQuery {
  readonly tenantId: string;
  readonly invoiceId?: string;
  readonly actorId?: string;
  readonly status?: InvoiceDisputeStatus | string;
  readonly from?: string;
  readonly to?: string;
}

export interface InvoiceDisputeDecision {
  readonly targetStatus: InvoiceDisputeStatus;
  readonly expectedVersion: number;
  readonly decidedBy: string;
  readonly decidedAt: string;
  readonly reference?: string;
  readonly resolutionNote?: string;
}

export interface PartnerAccountView extends Omit<PartnerAccount, "settlementReference"> {
  readonly settlementReference: string;
}

export type MarketplaceListingView = MarketplaceListing;
export type CommissionRuleView = CommissionRule;
export type BillingAccountView = PartnerAccountView;

export interface CommercePage<T> {
  readonly items: readonly T[];
  readonly nextCursor?: string;
  readonly hasMore: boolean;
  readonly total: number;
}

export interface CommercePageQuery {
  readonly cursor?: string;
  readonly limit?: number | string;
  readonly pageSize?: number | string;
}

export interface MarketplaceListingQuery extends CommercePageQuery {
  readonly tenantId: string;
  readonly id?: string;
  readonly status?: MarketplaceListingStatus | string;
  readonly partnerAccountId?: string;
  readonly productId?: string;
  readonly search?: string;
  readonly q?: string;
}

export interface PartnerAccountQuery extends CommercePageQuery {
  readonly tenantId: string;
  readonly id?: string;
  readonly status?: PartnerAccountStatus | string;
  readonly partnerCode?: string;
  readonly search?: string;
  readonly q?: string;
}

export interface CommissionRuleQuery extends CommercePageQuery {
  readonly tenantId: string;
  readonly id?: string;
  readonly listingId?: string;
  readonly partnerAccountId?: string;
  readonly status?: CommissionRuleStatus | string;
}

export interface InvoiceQuery extends CommercePageQuery {
  readonly tenantId: string;
  readonly id?: string;
  readonly subscriptionId?: string;
  readonly planId?: string;
  readonly status?: InvoiceStatus | string;
  readonly periodStart?: string;
  readonly periodEnd?: string;
  readonly from?: string;
  readonly to?: string;
}

export interface CommerceResourceGetQuery {
  readonly tenantId: string;
  readonly id: string;
}

export interface DisputeInvoiceCommand {
  readonly tenantId: string;
  readonly invoiceId: string;
  readonly reason: string;
  readonly idempotencyKey: string;
  readonly evidenceReference?: string;
  readonly actorId?: string;
  readonly requestId?: string;
}

export interface DisputeInvoiceResult {
  readonly invoice: InvoiceView;
  readonly dispute: InvoiceDisputeView;
  readonly replayed: boolean;
}

export interface ReviewInvoiceDisputeCommand {
  readonly tenantId: string;
  readonly invoiceId: string;
  readonly disputeId: string;
  readonly idempotencyKey: string;
  readonly actorId?: string;
  readonly requestId?: string;
  readonly at?: string;
}

export interface DecideInvoiceDisputeCommand extends ReviewInvoiceDisputeCommand {
  readonly outcome: InvoiceDisputeOutcome;
  readonly reference: string;
  readonly resolutionNote?: string;
}

export interface WithdrawInvoiceDisputeCommand extends ReviewInvoiceDisputeCommand {
  readonly reference: string;
  readonly resolutionNote?: string;
}

export interface InvoiceDisputeResult {
  readonly dispute: InvoiceDisputeView;
  readonly fromStatus: InvoiceDisputeStatus;
  readonly replayed: boolean;
}

export interface CommerceTransitionResult {
  readonly record: CommerceRecord | Invoice;
  readonly replayed: boolean;
}

export interface PartnerAccount extends TenantScopedRecord {
  readonly kind: "partnerAccount";
  readonly legalName: string;
  readonly partnerCode: string;
  readonly status: PartnerAccountStatus;
  readonly currency: CommerceCurrency;
  readonly settlementReference: string;
  readonly activatedAt?: string;
}

export interface MarketplaceListing extends TenantScopedRecord {
  readonly kind: "marketplaceListing";
  readonly partnerAccountId: string;
  readonly productId: string;
  readonly title: string;
  readonly description: string;
  readonly status: MarketplaceListingStatus;
  readonly priceIds: readonly string[];
  readonly commissionRuleIds: readonly string[];
  readonly submittedAt?: string;
  readonly publishedAt?: string;
  readonly removedAt?: string;
}

export interface CommissionRule extends TenantScopedRecord {
  readonly kind: "commissionRule";
  readonly partnerAccountId: string;
  readonly listingId: string;
  readonly name: string;
  readonly status: CommissionRuleStatus;
  readonly rateBps: number;
  readonly capBps?: number;
  readonly capAmount?: Money;
  readonly priority: number;
  readonly effectiveFrom: string;
  readonly effectiveTo?: string;
}

export type CommerceRecord =
  | Plan
  | Entitlement
  | Meter
  | Price
  | Subscription
  | Quota
  | QuotaReservation
  | UsageAggregate
  | MarketplaceListing
  | PartnerAccount
  | CommissionRule;

export interface CommerceDependencyReadiness {
  readonly storage: "memory" | "persistent";
  readonly distributed: boolean;
  ready(): MaybePromise<boolean>;
}

export interface CommercePersistenceReadinessPort
  extends CommerceDependencyReadiness {
  readonly storage: "persistent";
}

export interface TenantScopedRepository<T extends CommerceRecord> {
  create(record: T): Promise<T>;
  get(tenantId: string, id: string): Promise<T | undefined>;
  list(tenantId: string): Promise<T[]>;
  save(record: T): Promise<T>;
}

export type PlanRepository = TenantScopedRepository<Plan>;
export type EntitlementRepository = TenantScopedRepository<Entitlement>;
export type MeterRepository = TenantScopedRepository<Meter>;
export type PriceRepository = TenantScopedRepository<Price>;
export type SubscriptionRepository = TenantScopedRepository<Subscription>;
export type MarketplaceListingRepository =
  TenantScopedRepository<MarketplaceListing>;
export type PartnerAccountRepository =
  TenantScopedRepository<PartnerAccount>;
export type CommissionRuleRepository =
  TenantScopedRepository<CommissionRule>;
export type QuotaReservationRepository =
  TenantScopedRepository<QuotaReservation>;

export interface UsageEventAppendResult {
  readonly event: UsageEvent;
  readonly accepted: boolean;
}

export interface UsageEventRepository {
  append(event: UsageEvent): Promise<UsageEventAppendResult>;
  get(tenantId: string, id: string): Promise<UsageEvent | undefined>;
  list(tenantId: string): Promise<UsageEvent[]>;
  findByIdempotencyKey(
    tenantId: string,
    idempotencyKey: string,
  ): Promise<UsageEvent | undefined>;
}

export interface UsageAggregateRepository
  extends TenantScopedRepository<UsageAggregate> {
  findByKey(
    tenantId: string,
    aggregateKey: string,
  ): Promise<UsageAggregate | undefined>;
}

export interface InvoiceDisputeAppendResult {
  readonly dispute: InvoiceDispute;
  readonly accepted: boolean;
}

export interface InvoiceDisputeRepository {
  append(dispute: InvoiceDispute): Promise<InvoiceDisputeAppendResult>;
  get(tenantId: string, id: string): Promise<InvoiceDispute | undefined>;
  list(
    tenantId: string,
    query?: InvoiceDisputeListQuery,
  ): Promise<InvoiceDispute[]>;
  findByIdempotency(
    tenantId: string,
    idempotencyKey: string,
    query?: Pick<InvoiceDisputeListQuery, "invoiceId">,
  ): Promise<InvoiceDispute | undefined>;
  decide(
    tenantId: string,
    id: string,
    decision: InvoiceDisputeDecision,
  ): Promise<InvoiceDispute>;
  withTransaction<T>(operation: () => Promise<T>): Promise<T>;
}

export interface InvoiceIdempotentCreateRequest {
  readonly tenantId: string;
  readonly idempotencyKey: string;
  readonly requestHash: string;
  readonly invoice: Invoice;
}

export interface InvoiceIdempotentCreateResult {
  readonly invoice: Invoice;
  readonly replayed: boolean;
}

export interface InvoiceRepository {
  createIdempotent(
    request: InvoiceIdempotentCreateRequest,
  ): Promise<InvoiceIdempotentCreateResult>;
  get(tenantId: string, id: string): Promise<Invoice | undefined>;
  list(tenantId: string): Promise<Invoice[]>;
  transition(
    tenantId: string,
    id: string,
    targetStatus: InvoiceStatus,
    at: string,
  ): Promise<Invoice>;
}

export interface QuotaReserveRequest {
  readonly tenantId: string;
  readonly operation: "quota.reserve";
  readonly quotaId: string;
  readonly reservation: QuotaReservation;
}

export interface QuotaReserveResult {
  readonly quota: Quota;
  readonly reservation: QuotaReservation;
  readonly replayed: boolean;
}

export interface QuotaSettlementRequest {
  readonly tenantId: string;
  readonly operation: "quota.settle";
  readonly quotaId: string;
  readonly reservationId: string;
  readonly actualQuantity: DecimalString;
  readonly requestHash: string;
  readonly settledAt: string;
  readonly idempotencyKey: string;
}

export interface QuotaReleaseRequest {
  readonly tenantId: string;
  readonly operation: "quota.release";
  readonly quotaId: string;
  readonly reservationId: string;
  readonly requestHash: string;
  readonly releasedAt: string;
  readonly idempotencyKey: string;
}

export type QuotaTerminalResult = QuotaReserveResult;

export interface QuotaRepository extends TenantScopedRepository<Quota> {
  reserveAtomic(request: QuotaReserveRequest): Promise<QuotaReserveResult>;
  settleAtomic(
    request: QuotaSettlementRequest,
  ): Promise<QuotaTerminalResult>;
  releaseAtomic(
    request: QuotaReleaseRequest,
  ): Promise<QuotaTerminalResult>;
}

export interface CommerceRepositories {
  readonly readiness: CommerceDependencyReadiness;
  readonly plans: PlanRepository;
  readonly entitlements: EntitlementRepository;
  readonly meters: MeterRepository;
  readonly prices: PriceRepository;
  readonly subscriptions: SubscriptionRepository;
  readonly quotas: QuotaRepository;
  readonly quotaReservations: QuotaReservationRepository;
  readonly usageEvents: UsageEventRepository;
  readonly usageAggregates: UsageAggregateRepository;
  readonly invoices: InvoiceRepository;
  readonly invoiceDisputes: InvoiceDisputeRepository;
  readonly marketplaceListings: MarketplaceListingRepository;
  readonly partnerAccounts: PartnerAccountRepository;
  readonly commissionRules: CommissionRuleRepository;
}

export interface ResolveEntitlementsQuery {
  readonly tenantId: string;
  readonly planId?: string;
  readonly subscriptionId?: string;
  readonly features: readonly string[];
  readonly at?: string;
}

export interface EntitlementResolution {
  readonly feature: string;
  readonly allowed: boolean;
  readonly value?: boolean | number | string;
  readonly entitlementId?: string;
  readonly source?: EntitlementSource;
  readonly sourceId?: string;
  readonly priority?: number;
  readonly reason: "granted" | "denied" | "defaultDenied";
}

export interface ResolveEntitlementsResult {
  readonly tenantId: string;
  readonly resolvedAt: string;
  readonly entitlements: readonly EntitlementResolution[];
}

export interface RecordUsageEventCommand {
  readonly tenantId: string;
  readonly subscriptionId: string;
  readonly meterId: string;
  readonly quantity: DecimalString;
  readonly occurredAt: string;
  readonly periodStart: string;
  readonly periodEnd: string;
  readonly dimensions: Readonly<Record<string, string>>;
  readonly sourceEventId: string;
  readonly idempotencyKey: string;
}

export interface RecordUsageEventResult {
  readonly event: UsageEvent;
  readonly accepted: boolean;
}

export interface AggregateUsageCommand {
  readonly tenantId: string;
  readonly subscriptionId: string;
  readonly meterId: string;
  readonly periodStart: string;
  readonly periodEnd: string;
  readonly dimensions: Readonly<Record<string, string>>;
}

export interface AggregateUsageResult {
  readonly aggregate: UsageAggregate;
  readonly replayed: boolean;
}

export interface PriceUsageInput {
  readonly meterId: string;
  readonly quantity: DecimalString;
  readonly aggregateId?: string;
}

export interface CalculatePriceCommand {
  readonly tenantId: string;
  readonly priceId: string;
  readonly usage: readonly PriceUsageInput[];
  readonly at?: string;
}

export interface PriceCharge {
  readonly priceId: string;
  readonly priceVersion: number;
  readonly priceType: Price["priceType"];
  readonly meterId?: string;
  readonly quantity: DecimalString;
  readonly includedQuantity: DecimalString;
  readonly billableQuantity: DecimalString;
  readonly unitAmount: Money;
  readonly amount: Money;
  readonly aggregateIds: readonly string[];
}

export interface PriceCalculation {
  readonly tenantId: string;
  readonly currency: CommerceCurrency;
  readonly charges: readonly PriceCharge[];
  readonly subtotal: Money;
  readonly minimumChargeAdjustment: Money;
  readonly total: Money;
}

export interface CalculatePlanPriceCommand {
  readonly tenantId: string;
  readonly priceIds: readonly string[];
  readonly usage: readonly PriceUsageInput[];
  readonly at?: string;
}

export interface PlanPriceCalculation {
  readonly tenantId: string;
  readonly currency: CommerceCurrency;
  readonly calculations: readonly PriceCalculation[];
  readonly subtotal: Money;
  readonly total: Money;
}

export type InvoiceTaxMode = "exclusive" | "inclusive";

export interface GenerateInvoiceCommand {
  readonly tenantId: string;
  readonly subscriptionId: string;
  readonly periodStart: string;
  readonly periodEnd: string;
  readonly idempotencyKey: string;
  readonly taxRateBps: number;
  readonly taxMode: InvoiceTaxMode;
  readonly adjustments?: readonly InvoiceAdjustment[];
  readonly mainlandChina?: MainlandChinaInvoiceMetadata;
}

export interface GenerateInvoiceResult {
  readonly invoice: Invoice;
  readonly replayed: boolean;
}

export interface ReserveQuotaCommand {
  readonly tenantId: string;
  readonly subscriptionId: string;
  readonly quotaId: string;
  readonly quantity: DecimalString;
  readonly expiresAt: string;
  readonly idempotencyKey: string;
}

export interface ReserveQuotaResult {
  readonly quota: Quota;
  readonly reservation: QuotaReservation;
  readonly replayed: boolean;
}

export interface SettleQuotaCommand {
  readonly tenantId: string;
  readonly quotaId: string;
  readonly reservationId: string;
  readonly actualQuantity: DecimalString;
  readonly idempotencyKey: string;
}

export interface ReleaseQuotaCommand {
  readonly tenantId: string;
  readonly quotaId: string;
  readonly reservationId: string;
  readonly idempotencyKey: string;
}

export interface QuotaOperationResult extends ReserveQuotaResult {
  readonly replayed: boolean;
}

export interface CalculateCommissionCommand {
  readonly tenantId: string;
  readonly listingId: string;
  readonly grossAmount: Money;
  readonly at?: string;
}

export interface CommissionCalculation {
  readonly tenantId: string;
  readonly partnerAccountId: string;
  readonly listingId: string;
  readonly ruleId: string;
  readonly grossAmount: Money;
  readonly rateBps: number;
  readonly uncappedAmount: Money;
  readonly commissionAmount: Money;
  readonly partnerAmount: Money;
  readonly capped: boolean;
}

export interface CreatePlanCommand {
  readonly tenantId: string;
  readonly code: string;
  readonly name: string;
  readonly description?: string;
  readonly priority?: number;
  readonly currency?: CommerceCurrency;
  readonly priceIds?: readonly string[];
  readonly entitlementIds?: readonly string[];
  readonly quotaIds?: readonly string[];
  readonly effectiveFrom?: string;
  readonly effectiveTo?: string;
}

export interface GrantEntitlementCommand {
  readonly tenantId: string;
  readonly feature: string;
  readonly effect: "allow" | "deny";
  readonly value?: boolean | number | string;
  readonly source: EntitlementSource;
  readonly sourceId: string;
  readonly priority?: number;
  readonly effectiveFrom?: string;
  readonly effectiveTo?: string;
}

export interface CreateMeterCommand {
  readonly tenantId: string;
  readonly key: string;
  readonly name: string;
  readonly unit: string;
  readonly aggregation: UsageAggregationMethod;
  readonly dimensions?: readonly string[];
}

export interface CreatePriceCommand {
  readonly tenantId: string;
  readonly code: string;
  readonly name: string;
  readonly priceType: Price["priceType"];
  readonly currency?: CommerceCurrency;
  readonly roundingMode?: RoundingMode;
  readonly meterId?: string;
  readonly fixedAmount?: Money;
  readonly unitAmount?: Money;
  readonly includedUnits?: DecimalString;
  readonly minimumCharge?: Money;
  readonly tiers?: readonly PriceTier[];
  readonly effectiveFrom?: string;
  readonly effectiveTo?: string;
}

export interface CreateSubscriptionCommand {
  readonly tenantId: string;
  readonly applicationId: string;
  readonly planId: string;
  readonly name: string;
  readonly quantity?: DecimalString;
  readonly currentPeriodStart?: string;
  readonly currentPeriodEnd?: string;
}

export interface CreateQuotaCommand {
  readonly tenantId: string;
  readonly planId: string;
  readonly meterId: string;
  readonly limit: DecimalString;
}

export interface CreatePartnerAccountCommand {
  readonly tenantId: string;
  readonly legalName: string;
  readonly partnerCode: string;
  readonly currency?: CommerceCurrency;
  readonly settlementReference: string;
}

export interface CreateMarketplaceListingCommand {
  readonly tenantId: string;
  readonly partnerAccountId: string;
  readonly productId: string;
  readonly title: string;
  readonly description: string;
  readonly priceIds?: readonly string[];
  readonly commissionRuleIds?: readonly string[];
  readonly idempotencyKey?: string;
  readonly actorId?: string;
}

export interface CreateCommissionRuleCommand {
  readonly tenantId: string;
  readonly partnerAccountId: string;
  readonly listingId: string;
  readonly name: string;
  readonly rateBps: number;
  readonly capBps?: number;
  readonly capAmount?: Money;
  readonly priority?: number;
  readonly effectiveFrom?: string;
  readonly effectiveTo?: string;
}

export type CommerceLifecycleResource =
  | "plan"
  | "entitlement"
  | "meter"
  | "price"
  | "subscription"
  | "quota"
  | "usageAggregate"
  | "marketplaceListing"
  | "partnerAccount"
  | "commissionRule"
  | "invoice";

export interface TransitionCommerceResourceCommand {
  readonly tenantId: string;
  readonly resource: CommerceLifecycleResource;
  readonly id: string;
  readonly targetStatus: string;
  readonly at?: string;
  readonly idempotencyKey?: string;
  readonly actorId?: string;
}

export interface CommerceReadiness {
  readonly ready: boolean;
  readonly storage: "memory" | "persistent";
  readonly distributed: boolean;
}

export interface EntitlementService {
  resolveEntitlements(
    query: ResolveEntitlementsQuery,
  ): Promise<ResolveEntitlementsResult>;
}

export interface UsageAggregationService {
  recordUsageEvent(
    command: RecordUsageEventCommand,
  ): Promise<RecordUsageEventResult>;
  aggregateUsage(
    command: AggregateUsageCommand,
  ): Promise<AggregateUsageResult>;
  recordAndAggregate(
    command: RecordUsageEventCommand,
  ): Promise<{
    readonly event: RecordUsageEventResult;
    readonly aggregate: AggregateUsageResult;
  }>;
}

export interface PricingService {
  calculate(command: CalculatePriceCommand): Promise<PriceCalculation>;
  calculatePlan(command: CalculatePlanPriceCommand): Promise<PlanPriceCalculation>;
}

export interface QuotaService {
  reserve(command: ReserveQuotaCommand): Promise<ReserveQuotaResult>;
  settle(command: SettleQuotaCommand): Promise<QuotaOperationResult>;
  release(command: ReleaseQuotaCommand): Promise<QuotaOperationResult>;
}

export interface InvoiceService {
  generateInvoice(command: GenerateInvoiceCommand): Promise<GenerateInvoiceResult>;
}

export interface MarketplaceService {
  calculateCommission(
    command: CalculateCommissionCommand,
  ): Promise<CommissionCalculation>;
}

export interface CommerceReadService {
  listMarketplaceListings(
    query: MarketplaceListingQuery,
  ): Promise<CommercePage<MarketplaceListingView>>;
  listMarketplaceListings(
    tenantId: string,
    query?: Omit<MarketplaceListingQuery, "tenantId">,
  ): Promise<CommercePage<MarketplaceListingView>>;
  getMarketplaceListing(
    query: CommerceResourceGetQuery,
  ): Promise<MarketplaceListingView>;
  getMarketplaceListing(
    tenantId: string,
    id: string,
  ): Promise<MarketplaceListingView>;
  listPartnerAccounts(
    query: PartnerAccountQuery,
  ): Promise<CommercePage<PartnerAccountView>>;
  listPartnerAccounts(
    tenantId: string,
    query?: Omit<PartnerAccountQuery, "tenantId">,
  ): Promise<CommercePage<PartnerAccountView>>;
  getPartnerAccount(
    query: CommerceResourceGetQuery,
  ): Promise<PartnerAccountView>;
  getPartnerAccount(
    tenantId: string,
    id: string,
  ): Promise<PartnerAccountView>;
  listCommissionRules(
    query: CommissionRuleQuery,
  ): Promise<CommercePage<CommissionRuleView>>;
  listCommissionRules(
    tenantId: string,
    query?: Omit<CommissionRuleQuery, "tenantId">,
  ): Promise<CommercePage<CommissionRuleView>>;
  getCommissionRule(
    query: CommerceResourceGetQuery,
  ): Promise<CommissionRuleView>;
  getCommissionRule(
    tenantId: string,
    id: string,
  ): Promise<CommissionRuleView>;
  listInvoices(
    query: InvoiceQuery,
  ): Promise<CommercePage<InvoiceView>>;
  listInvoices(
    tenantId: string,
    query?: Omit<InvoiceQuery, "tenantId">,
  ): Promise<CommercePage<InvoiceView>>;
  getInvoice(
    query: CommerceResourceGetQuery,
  ): Promise<InvoiceView>;
  getInvoice(
    tenantId: string,
    id: string,
  ): Promise<InvoiceView>;
  listInvoiceDisputes(
    query: InvoiceDisputeQuery,
  ): Promise<CommercePage<InvoiceDisputeView>>;
  listInvoiceDisputes(
    tenantId: string,
    query?: Omit<InvoiceDisputeQuery, "tenantId">,
  ): Promise<CommercePage<InvoiceDisputeView>>;
  getInvoiceDispute(
    query: CommerceResourceGetQuery,
  ): Promise<InvoiceDisputeView>;
  getInvoiceDispute(
    tenantId: string,
    id: string,
  ): Promise<InvoiceDisputeView>;
  listBillingAccounts(
    query: PartnerAccountQuery,
  ): Promise<CommercePage<BillingAccountView>>;
  listBillingAccounts(
    tenantId: string,
    query?: Omit<PartnerAccountQuery, "tenantId">,
  ): Promise<CommercePage<BillingAccountView>>;
  getBillingAccount(
    query: CommerceResourceGetQuery,
  ): Promise<BillingAccountView>;
  getBillingAccount(
    tenantId: string,
    id: string,
  ): Promise<BillingAccountView>;
}

export interface CommerceLifecycleService {
  transition(
    command: TransitionCommerceResourceCommand,
  ): Promise<CommerceRecord | Invoice>;
  transitionWithIdempotency(
    command: TransitionCommerceResourceCommand & { readonly idempotencyKey: string },
  ): Promise<CommerceTransitionResult>;
  disputeInvoice(
    command: DisputeInvoiceCommand,
  ): Promise<DisputeInvoiceResult>;
  startInvoiceDisputeReview(
    command: ReviewInvoiceDisputeCommand,
  ): Promise<InvoiceDisputeResult>;
  decideInvoiceDispute(
    command: DecideInvoiceDisputeCommand,
  ): Promise<InvoiceDisputeResult>;
  withdrawInvoiceDispute(
    command: WithdrawInvoiceDisputeCommand,
  ): Promise<InvoiceDisputeResult>;
}

export interface CommerceService
  extends EntitlementService,
    UsageAggregationService,
    PricingService,
    QuotaService,
    InvoiceService,
    MarketplaceService,
    CommerceReadService,
    CommerceLifecycleService {
  readonly repositories: CommerceRepositories;
  isReady(): Promise<CommerceReadiness>;
  createPlan(command: CreatePlanCommand): Promise<Plan>;
  grantEntitlement(command: GrantEntitlementCommand): Promise<Entitlement>;
  createMeter(command: CreateMeterCommand): Promise<Meter>;
  createPrice(command: CreatePriceCommand): Promise<Price>;
  createSubscription(command: CreateSubscriptionCommand): Promise<Subscription>;
  createQuota(command: CreateQuotaCommand): Promise<Quota>;
  createPartnerAccount(
    command: CreatePartnerAccountCommand,
  ): Promise<PartnerAccount>;
  createMarketplaceListing(
    command: CreateMarketplaceListingCommand,
  ): Promise<MarketplaceListing>;
  createCommissionRule(
    command: CreateCommissionRuleCommand,
  ): Promise<CommissionRule>;
}
