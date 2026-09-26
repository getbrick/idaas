import {
  commerceInvalidStateTransition,
  commerceResourceConflict,
  commerceValidationError,
} from "./errors.js";
import type {
  CommissionRuleStatus,
  EntitlementStatus,
  InvoiceDispute,
  InvoiceDisputeDecision,
  InvoiceDisputeOutcome,
  InvoiceDisputeStatus,
  InvoiceStatus,
  MarketplaceListingStatus,
  MeterStatus,
  PartnerAccountStatus,
  PlanStatus,
  PriceStatus,
  QuotaReservationStatus,
  QuotaStatus,
  SubscriptionStatus,
  UsageAggregateStatus,
} from "./types.js";
import { INVOICE_DISPUTE_OUTCOMES } from "./types.js";

export const PLAN_TRANSITIONS = Object.freeze({
  draft: Object.freeze(["active", "retired"]),
  active: Object.freeze(["retired"]),
  retired: Object.freeze([]),
} satisfies Readonly<Record<PlanStatus, readonly PlanStatus[]>>);

export const ENTITLEMENT_TRANSITIONS = Object.freeze({
  pending: Object.freeze(["active", "revoked", "expired"]),
  active: Object.freeze(["suspended", "revoked", "expired"]),
  suspended: Object.freeze(["active", "revoked", "expired"]),
  revoked: Object.freeze([]),
  expired: Object.freeze([]),
} satisfies Readonly<Record<EntitlementStatus, readonly EntitlementStatus[]>>);

export const METER_TRANSITIONS = Object.freeze({
  draft: Object.freeze(["active", "retired"]),
  active: Object.freeze(["retired"]),
  retired: Object.freeze([]),
} satisfies Readonly<Record<MeterStatus, readonly MeterStatus[]>>);

export const PRICE_TRANSITIONS = Object.freeze({
  draft: Object.freeze(["scheduled", "active", "retired"]),
  scheduled: Object.freeze(["draft", "active", "retired"]),
  active: Object.freeze(["retired"]),
  retired: Object.freeze([]),
} satisfies Readonly<Record<PriceStatus, readonly PriceStatus[]>>);

export const SUBSCRIPTION_TRANSITIONS = Object.freeze({
  pending: Object.freeze(["trialing", "active", "canceled", "expired"]),
  trialing: Object.freeze(["active", "canceled", "expired"]),
  active: Object.freeze([
    "pastDue",
    "suspended",
    "canceled",
    "expired",
  ]),
  pastDue: Object.freeze([
    "active",
    "suspended",
    "canceled",
    "expired",
  ]),
  suspended: Object.freeze(["active", "canceled", "expired"]),
  canceled: Object.freeze([]),
  expired: Object.freeze([]),
} satisfies Readonly<Record<SubscriptionStatus, readonly SubscriptionStatus[]>>);

export const QUOTA_TRANSITIONS = Object.freeze({
  active: Object.freeze(["disabled", "retired"]),
  disabled: Object.freeze(["active", "retired"]),
  retired: Object.freeze([]),
} satisfies Readonly<Record<QuotaStatus, readonly QuotaStatus[]>>);

export const QUOTA_RESERVATION_TRANSITIONS = Object.freeze({
  reserved: Object.freeze(["settled", "released", "expired"]),
  settled: Object.freeze([]),
  released: Object.freeze([]),
  expired: Object.freeze([]),
} satisfies Readonly<
  Record<QuotaReservationStatus, readonly QuotaReservationStatus[]>
>);

export const USAGE_AGGREGATE_TRANSITIONS = Object.freeze({
  collecting: Object.freeze(["closed"]),
  closed: Object.freeze(["collecting", "priced"]),
  priced: Object.freeze(["closed", "settled"]),
  settled: Object.freeze([]),
} satisfies Readonly<
  Record<UsageAggregateStatus, readonly UsageAggregateStatus[]>
>);

export const INVOICE_TRANSITIONS = Object.freeze({
  draft: Object.freeze(["reconciling", "voided"]),
  reconciling: Object.freeze(["draft", "awaitingPayment", "voided"]),
  awaitingPayment: Object.freeze(["paid", "disputed", "voided"]),
  invoicing: Object.freeze(["completed", "disputed", "voided"]),
  paid: Object.freeze(["invoicing", "disputed", "completed"]),
  completed: Object.freeze(["disputed"]),
  disputed: Object.freeze([
    "awaitingPayment",
    "invoicing",
    "completed",
    "voided",
  ]),
  voided: Object.freeze([]),
} satisfies Readonly<Record<InvoiceStatus, readonly InvoiceStatus[]>>);

export const INVOICE_DISPUTE_TRANSITIONS = Object.freeze({
  open: Object.freeze(["underReview", "accepted", "rejected", "withdrawn"]),
  underReview: Object.freeze(["accepted", "rejected", "withdrawn"]),
  accepted: Object.freeze([]),
  rejected: Object.freeze([]),
  withdrawn: Object.freeze([]),
} satisfies Readonly<Record<InvoiceDisputeStatus, readonly InvoiceDisputeStatus[]>>);

export const MARKETPLACE_LISTING_TRANSITIONS = Object.freeze({
  draft: Object.freeze(["pendingReview", "removed"]),
  pendingReview: Object.freeze(["draft", "published", "removed"]),
  published: Object.freeze(["suspended", "removed"]),
  suspended: Object.freeze(["published", "removed"]),
  removed: Object.freeze([]),
} satisfies Readonly<
  Record<MarketplaceListingStatus, readonly MarketplaceListingStatus[]>
>);

export const PARTNER_ACCOUNT_TRANSITIONS = Object.freeze({
  pending: Object.freeze(["underReview", "rejected"]),
  underReview: Object.freeze(["active", "rejected"]),
  active: Object.freeze(["frozen", "closed"]),
  frozen: Object.freeze(["active", "closed"]),
  rejected: Object.freeze([]),
  closed: Object.freeze([]),
} satisfies Readonly<
  Record<PartnerAccountStatus, readonly PartnerAccountStatus[]>
>);

export const COMMISSION_RULE_TRANSITIONS = Object.freeze({
  draft: Object.freeze(["scheduled", "active", "retired"]),
  scheduled: Object.freeze(["draft", "active", "retired"]),
  active: Object.freeze(["suspended", "retired"]),
  suspended: Object.freeze(["active", "retired"]),
  retired: Object.freeze([]),
} satisfies Readonly<
  Record<CommissionRuleStatus, readonly CommissionRuleStatus[]>
>);

export function canTransitionPlan(from: PlanStatus, to: PlanStatus): boolean {
  const transitions: readonly PlanStatus[] = PLAN_TRANSITIONS[from];
  return transitions.includes(to);
}

export function canTransitionEntitlement(
  from: EntitlementStatus,
  to: EntitlementStatus,
): boolean {
  const transitions: readonly EntitlementStatus[] =
    ENTITLEMENT_TRANSITIONS[from];
  return transitions.includes(to);
}

export function canTransitionMeter(from: MeterStatus, to: MeterStatus): boolean {
  const transitions: readonly MeterStatus[] = METER_TRANSITIONS[from];
  return transitions.includes(to);
}

export function canTransitionPrice(from: PriceStatus, to: PriceStatus): boolean {
  const transitions: readonly PriceStatus[] = PRICE_TRANSITIONS[from];
  return transitions.includes(to);
}

export function canTransitionSubscription(
  from: SubscriptionStatus,
  to: SubscriptionStatus,
): boolean {
  const transitions: readonly SubscriptionStatus[] =
    SUBSCRIPTION_TRANSITIONS[from];
  return transitions.includes(to);
}

export function canTransitionQuota(from: QuotaStatus, to: QuotaStatus): boolean {
  const transitions: readonly QuotaStatus[] = QUOTA_TRANSITIONS[from];
  return transitions.includes(to);
}

export function canTransitionQuotaReservation(
  from: QuotaReservationStatus,
  to: QuotaReservationStatus,
): boolean {
  const transitions: readonly QuotaReservationStatus[] =
    QUOTA_RESERVATION_TRANSITIONS[from];
  return transitions.includes(to);
}

export function canTransitionUsageAggregate(
  from: UsageAggregateStatus,
  to: UsageAggregateStatus,
): boolean {
  const transitions: readonly UsageAggregateStatus[] =
    USAGE_AGGREGATE_TRANSITIONS[from];
  return transitions.includes(to);
}

export function canTransitionInvoice(
  from: InvoiceStatus,
  to: InvoiceStatus,
): boolean {
  const transitions: readonly InvoiceStatus[] = INVOICE_TRANSITIONS[from];
  return transitions.includes(to);
}

export function canTransitionInvoiceDispute(
  from: InvoiceDisputeStatus,
  to: InvoiceDisputeStatus,
): boolean {
  const transitions: readonly InvoiceDisputeStatus[] =
    INVOICE_DISPUTE_TRANSITIONS[from];
  return transitions.includes(to);
}

export function isTerminalInvoiceDisputeStatus(
  status: InvoiceDisputeStatus,
): boolean {
  return INVOICE_DISPUTE_TRANSITIONS[status].length === 0;
}

export function canTransitionMarketplaceListing(
  from: MarketplaceListingStatus,
  to: MarketplaceListingStatus,
): boolean {
  const transitions: readonly MarketplaceListingStatus[] =
    MARKETPLACE_LISTING_TRANSITIONS[from];
  return transitions.includes(to);
}

export function canTransitionPartnerAccount(
  from: PartnerAccountStatus,
  to: PartnerAccountStatus,
): boolean {
  const transitions: readonly PartnerAccountStatus[] =
    PARTNER_ACCOUNT_TRANSITIONS[from];
  return transitions.includes(to);
}

export function canTransitionCommissionRule(
  from: CommissionRuleStatus,
  to: CommissionRuleStatus,
): boolean {
  const transitions: readonly CommissionRuleStatus[] =
    COMMISSION_RULE_TRANSITIONS[from];
  return transitions.includes(to);
}

export function assertPlanTransition(from: PlanStatus, to: PlanStatus): void {
  assertCommerceTransition(canTransitionPlan(from, to), from, to);
}

export function assertEntitlementTransition(
  from: EntitlementStatus,
  to: EntitlementStatus,
): void {
  assertCommerceTransition(canTransitionEntitlement(from, to), from, to);
}

export function assertMeterTransition(from: MeterStatus, to: MeterStatus): void {
  assertCommerceTransition(canTransitionMeter(from, to), from, to);
}

export function assertPriceTransition(from: PriceStatus, to: PriceStatus): void {
  assertCommerceTransition(canTransitionPrice(from, to), from, to);
}

export function assertSubscriptionTransition(
  from: SubscriptionStatus,
  to: SubscriptionStatus,
): void {
  assertCommerceTransition(canTransitionSubscription(from, to), from, to);
}

export function assertQuotaTransition(from: QuotaStatus, to: QuotaStatus): void {
  assertCommerceTransition(canTransitionQuota(from, to), from, to);
}

export function assertQuotaReservationTransition(
  from: QuotaReservationStatus,
  to: QuotaReservationStatus,
): void {
  assertCommerceTransition(
    canTransitionQuotaReservation(from, to),
    from,
    to,
  );
}

export function assertUsageAggregateTransition(
  from: UsageAggregateStatus,
  to: UsageAggregateStatus,
): void {
  assertCommerceTransition(canTransitionUsageAggregate(from, to), from, to);
}

export function assertInvoiceTransition(
  from: InvoiceStatus,
  to: InvoiceStatus,
): void {
  assertCommerceTransition(canTransitionInvoice(from, to), from, to);
}

export function assertInvoiceDisputeTransition(
  from: InvoiceDisputeStatus,
  to: InvoiceDisputeStatus,
): void {
  assertCommerceTransition(canTransitionInvoiceDispute(from, to), from, to);
}

export function transitionInvoiceDispute(
  dispute: InvoiceDispute,
  decision: InvoiceDisputeDecision,
): InvoiceDispute {
  assertInvoiceDisputeTransition(dispute.status, decision.targetStatus);
  if (
    !Number.isSafeInteger(decision.expectedVersion) ||
    decision.expectedVersion !== dispute.version
  ) {
    throw commerceResourceConflict("Invoice dispute version is stale");
  }
  const terminal = (INVOICE_DISPUTE_OUTCOMES as readonly InvoiceDisputeStatus[])
    .includes(decision.targetStatus);
  if (!terminal) {
    return {
      ...dispute,
      status: decision.targetStatus,
      version: dispute.version + 1,
      updatedAt: decision.decidedAt,
    };
  }
  if (decision.reference === undefined) {
    throw commerceValidationError(
      "Invoice dispute decision reference is required",
      "reference",
    );
  }
  return {
    ...dispute,
    status: decision.targetStatus,
    version: dispute.version + 1,
    resolution: {
      outcome: decision.targetStatus as InvoiceDisputeOutcome,
      actorId: decision.decidedBy,
      reference: decision.reference,
      resolvedAt: decision.decidedAt,
      ...(decision.resolutionNote === undefined
        ? {}
        : {
            note: decision.resolutionNote,
            noteLength: decision.resolutionNote.length,
          }),
      fromStatus: dispute.status,
    },
    resolvedAt: decision.decidedAt,
    updatedAt: decision.decidedAt,
  };
}

export function assertMarketplaceListingTransition(
  from: MarketplaceListingStatus,
  to: MarketplaceListingStatus,
): void {
  assertCommerceTransition(
    canTransitionMarketplaceListing(from, to),
    from,
    to,
  );
}

export function assertPartnerAccountTransition(
  from: PartnerAccountStatus,
  to: PartnerAccountStatus,
): void {
  assertCommerceTransition(canTransitionPartnerAccount(from, to), from, to);
}

export function assertCommissionRuleTransition(
  from: CommissionRuleStatus,
  to: CommissionRuleStatus,
): void {
  assertCommerceTransition(canTransitionCommissionRule(from, to), from, to);
}

function assertCommerceTransition(
  allowed: boolean,
  from: string,
  to: string,
): void {
  if (!allowed) throw commerceInvalidStateTransition(from, to);
}
