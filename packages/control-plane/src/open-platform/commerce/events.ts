import { createHash } from "node:crypto";
import type {
  OpenPlatformDomainEventDescriptor,
  OpenPlatformDomainEventFactory,
  OpenPlatformDomainEventResourceType,
  OpenPlatformDomainEventType,
} from "../events.js";
import { formatMoneyAsDecimalString } from "./money.js";
import type {
  CommissionRule,
  CommerceRecord,
  DecimalString,
  Invoice,
  MarketplaceListing,
  Money,
  PartnerAccount,
} from "./types.js";

export const COMMERCE_DOMAIN_EVENT_ID_PREFIX = "open_platform_event_";

export const COMMERCE_DOMAIN_EVENT_TYPES = Object.freeze({
  listingCreated: "commerce_listing.created",
  listingStatusChanged: "commerce_listing.status_changed",
  listingDeprecated: "commerce_listing.deprecated",
  partnerCreated: "commerce_partner.created",
  partnerStatusChanged: "commerce_partner.status_changed",
  commissionCreated: "commerce_commission.created",
  commissionStatusChanged: "commerce_commission.status_changed",
  invoiceCreated: "commerce_invoice.created",
  invoiceStatusChanged: "commerce_invoice.status_changed",
  disputeCreated: "commerce_dispute.created",
  disputeStatusChanged: "commerce_dispute.status_changed",
  disputeDecided: "commerce_dispute.decided",
} as const satisfies Readonly<Record<string, OpenPlatformDomainEventType>>);

export type CommerceDomainEventKey = keyof typeof COMMERCE_DOMAIN_EVENT_TYPES;

export const COMMERCE_DOMAIN_EVENT_RESOURCE_TYPES = Object.freeze({
  marketplaceListing: "marketplaceListing",
  partnerAccount: "partnerAccount",
  commissionRule: "commissionRule",
  invoice: "invoice",
  invoiceDispute: "invoiceDispute",
} as const satisfies Readonly<Record<string, OpenPlatformDomainEventResourceType>>);

export type CommerceDomainEventResourceKind =
  keyof typeof COMMERCE_DOMAIN_EVENT_RESOURCE_TYPES;

export const COMMERCE_LISTING_DEPRECATED_STATUSES = Object.freeze([
  "removed",
] as const);

export interface CommerceDomainEventIdInput {
  readonly tenantId: string;
  readonly actorId: string;
  readonly operation: string;
  readonly idempotencyKey: string;
}

export interface CommerceDisputeEventSource {
  readonly id: string;
  readonly version: number;
  readonly status: string;
  readonly invoiceId: string;
  readonly subscriptionId: string;
  readonly planId: string;
  readonly invoiceStatus: string;
  readonly invoiceVersion: number;
  readonly reasonLength: number;
  readonly evidenceCount: number;
  readonly resolution?: {
    readonly outcome: string;
    readonly resolvedAt: string;
  };
}

export type {
  OpenPlatformDomainEventDescriptor,
  OpenPlatformDomainEventFactory,
};

export function commerceDomainEventId(input: CommerceDomainEventIdInput): string {
  const digest = createHash("sha256")
    .update(
      [
        commerceEventIdPart(input.tenantId),
        commerceEventIdPart(input.actorId),
        commerceEventIdPart(input.operation),
        commerceEventIdPart(input.idempotencyKey),
      ].join("\u0000"),
      "utf8",
    )
    .digest("hex")
    .slice(0, 32);
  return `${COMMERCE_DOMAIN_EVENT_ID_PREFIX}${digest}`;
}

export function isCommerceListingDeprecatedStatus(status: unknown): boolean {
  return typeof status === "string" &&
    (COMMERCE_LISTING_DEPRECATED_STATUSES as readonly string[]).includes(status);
}

export function commerceListingCreatedEvent(
  listing: MarketplaceListing,
): OpenPlatformDomainEventDescriptor | undefined {
  return commerceRecordEvent(
    COMMERCE_DOMAIN_EVENT_TYPES.listingCreated,
    COMMERCE_DOMAIN_EVENT_RESOURCE_TYPES.marketplaceListing,
    listing,
    () => ({
      partnerAccountId: listing.partnerAccountId,
      productId: listing.productId,
      status: listing.status,
      priceCount: listing.priceIds.length,
      commissionRuleCount: listing.commissionRuleIds.length,
    }),
  );
}

export function commerceListingStatusChangedEvent(
  listing: MarketplaceListing,
  fromStatus?: string,
): OpenPlatformDomainEventDescriptor | undefined {
  return commerceRecordEvent(
    isCommerceListingDeprecatedStatus(listing.status)
      ? COMMERCE_DOMAIN_EVENT_TYPES.listingDeprecated
      : COMMERCE_DOMAIN_EVENT_TYPES.listingStatusChanged,
    COMMERCE_DOMAIN_EVENT_RESOURCE_TYPES.marketplaceListing,
    listing,
    () => ({
      ...(fromStatus === undefined ? {} : { fromStatus }),
      toStatus: listing.status,
      partnerAccountId: listing.partnerAccountId,
      productId: listing.productId,
    }),
  );
}

export function commercePartnerCreatedEvent(
  partner: PartnerAccount,
): OpenPlatformDomainEventDescriptor | undefined {
  return commerceRecordEvent(
    COMMERCE_DOMAIN_EVENT_TYPES.partnerCreated,
    COMMERCE_DOMAIN_EVENT_RESOURCE_TYPES.partnerAccount,
    partner,
    () => ({
      partnerCode: partner.partnerCode,
      status: partner.status,
      currency: partner.currency,
    }),
  );
}

export function commercePartnerStatusChangedEvent(
  partner: PartnerAccount,
  fromStatus?: string,
): OpenPlatformDomainEventDescriptor | undefined {
  return commerceRecordEvent(
    COMMERCE_DOMAIN_EVENT_TYPES.partnerStatusChanged,
    COMMERCE_DOMAIN_EVENT_RESOURCE_TYPES.partnerAccount,
    partner,
    () => ({
      ...(fromStatus === undefined ? {} : { fromStatus }),
      toStatus: partner.status,
      partnerCode: partner.partnerCode,
      currency: partner.currency,
    }),
  );
}

export function commerceCommissionRuleCreatedEvent(
  rule: CommissionRule,
): OpenPlatformDomainEventDescriptor | undefined {
  return commerceRecordEvent(
    COMMERCE_DOMAIN_EVENT_TYPES.commissionCreated,
    COMMERCE_DOMAIN_EVENT_RESOURCE_TYPES.commissionRule,
    rule,
    () => commissionRuleData(rule),
  );
}

export function commerceCommissionRuleStatusChangedEvent(
  rule: CommissionRule,
  fromStatus?: string,
): OpenPlatformDomainEventDescriptor | undefined {
  return commerceRecordEvent(
    COMMERCE_DOMAIN_EVENT_TYPES.commissionStatusChanged,
    COMMERCE_DOMAIN_EVENT_RESOURCE_TYPES.commissionRule,
    rule,
    () => ({
      ...commissionRuleData(rule),
      ...(fromStatus === undefined ? {} : { fromStatus }),
    }),
  );
}

export function commerceInvoiceCreatedEvent(
  invoice: Invoice,
): OpenPlatformDomainEventDescriptor | undefined {
  return commerceRecordEvent(
    COMMERCE_DOMAIN_EVENT_TYPES.invoiceCreated,
    COMMERCE_DOMAIN_EVENT_RESOURCE_TYPES.invoice,
    invoice,
    () => ({
      subscriptionId: invoice.subscriptionId,
      planId: invoice.planId,
      status: invoice.status,
      currency: invoice.currency,
      lineCount: invoice.lines.length,
      subtotal: commerceMoneyValue(invoice.subtotal),
      tax: commerceMoneyValue(invoice.tax),
      total: commerceMoneyValue(invoice.total),
    }),
  );
}

export function commerceInvoiceStatusChangedEvent(
  invoice: Invoice,
  fromStatus?: string,
): OpenPlatformDomainEventDescriptor | undefined {
  return commerceRecordEvent(
    COMMERCE_DOMAIN_EVENT_TYPES.invoiceStatusChanged,
    COMMERCE_DOMAIN_EVENT_RESOURCE_TYPES.invoice,
    invoice,
    () => ({
      ...(fromStatus === undefined ? {} : { fromStatus }),
      toStatus: invoice.status,
      subscriptionId: invoice.subscriptionId,
      planId: invoice.planId,
      currency: invoice.currency,
      total: commerceMoneyValue(invoice.total),
    }),
  );
}

export function commerceDisputeOpenedEvent(
  dispute: CommerceDisputeEventSource,
): OpenPlatformDomainEventDescriptor | undefined {
  return commerceDisputeEvent(
    COMMERCE_DOMAIN_EVENT_TYPES.disputeCreated,
    dispute,
    () => ({
      invoiceId: dispute.invoiceId,
      subscriptionId: dispute.subscriptionId,
      planId: dispute.planId,
      status: dispute.status,
      invoiceStatus: dispute.invoiceStatus,
      invoiceVersion: dispute.invoiceVersion,
      reasonLength: dispute.reasonLength,
      evidenceCount: dispute.evidenceCount,
    }),
  );
}

export function commerceDisputeDecidedEvent(
  dispute: CommerceDisputeEventSource,
): OpenPlatformDomainEventDescriptor | undefined {
  const resolution = dispute.resolution;
  if (resolution === undefined) return undefined;
  return commerceDisputeEvent(
    COMMERCE_DOMAIN_EVENT_TYPES.disputeDecided,
    dispute,
    () => ({
      invoiceId: dispute.invoiceId,
      subscriptionId: dispute.subscriptionId,
      status: dispute.status,
      outcome: resolution.outcome,
      resolvedAt: resolution.resolvedAt,
    }),
  );
}

export function commerceDisputeStatusChangedEvent(
  dispute: CommerceDisputeEventSource,
  fromStatus?: string,
): OpenPlatformDomainEventDescriptor | undefined {
  return commerceDisputeEvent(
    COMMERCE_DOMAIN_EVENT_TYPES.disputeStatusChanged,
    dispute,
    () => ({
      invoiceId: dispute.invoiceId,
      subscriptionId: dispute.subscriptionId,
      ...(fromStatus === undefined ? {} : { fromStatus }),
      toStatus: dispute.status,
    }),
  );
}

export function commerceCreatedDomainEventFactory<T extends CommerceRecord | Invoice>(
  record: T,
): OpenPlatformDomainEventFactory<T> {
  return () => {
    switch (record.kind) {
      case "marketplaceListing":
        return commerceListingCreatedEvent(record);
      case "partnerAccount":
        return commercePartnerCreatedEvent(record);
      case "commissionRule":
        return commerceCommissionRuleCreatedEvent(record);
      case "invoice":
        return commerceInvoiceCreatedEvent(record);
      default:
        return undefined;
    }
  };
}

export function commerceStatusChangedDomainEventFactory<T extends CommerceRecord | Invoice>(
  record: T,
  fromStatus?: string,
): OpenPlatformDomainEventFactory<T> {
  return () => {
    switch (record.kind) {
      case "marketplaceListing":
        return commerceListingStatusChangedEvent(record, fromStatus);
      case "partnerAccount":
        return commercePartnerStatusChangedEvent(record, fromStatus);
      case "commissionRule":
        return commerceCommissionRuleStatusChangedEvent(record, fromStatus);
      case "invoice":
        return commerceInvoiceStatusChangedEvent(record, fromStatus);
      default:
        return undefined;
    }
  };
}

function commerceRecordEvent(
  eventType: OpenPlatformDomainEventType,
  resourceType: OpenPlatformDomainEventResourceType,
  record: {
    readonly id: unknown;
    readonly version: unknown;
    readonly status: unknown;
  },
  data: () => Readonly<Record<string, unknown>>,
): OpenPlatformDomainEventDescriptor | undefined {
  const resourceId = commerceEventResourceId(record);
  if (resourceId === undefined) return undefined;
  const resourceVersion = commerceEventResourceVersion(record);
  const resourceStatus = commerceEventResourceStatus(record);
  return {
    eventType,
    resourceType,
    resourceId,
    ...(resourceVersion === undefined ? {} : { resourceVersion }),
    ...(resourceStatus === undefined ? {} : { resourceStatus }),
    data: data(),
  };
}

function commerceDisputeEvent(
  eventType: OpenPlatformDomainEventType,
  dispute: CommerceDisputeEventSource,
  data: () => Readonly<Record<string, unknown>>,
): OpenPlatformDomainEventDescriptor | undefined {
  return commerceRecordEvent(
    eventType,
    COMMERCE_DOMAIN_EVENT_RESOURCE_TYPES.invoiceDispute,
    dispute,
    data,
  );
}

function commissionRuleData(
  rule: CommissionRule,
): Readonly<Record<string, unknown>> {
  return {
    partnerAccountId: rule.partnerAccountId,
    listingId: rule.listingId,
    status: rule.status,
    rateBps: rule.rateBps,
    ...(rule.capBps === undefined ? {} : { capBps: rule.capBps }),
    ...(rule.capAmount === undefined
      ? {}
      : { capAmount: commerceMoneyValue(rule.capAmount) }),
    priority: rule.priority,
  };
}

function commerceMoneyValue(amount: Money): DecimalString | string {
  try {
    return formatMoneyAsDecimalString(amount);
  } catch {
    return amount.currency;
  }
}

function commerceEventResourceId(record: { readonly id: unknown }): string | undefined {
  const value = record.id;
  if (typeof value !== "string" || value.length === 0) return undefined;
  return value;
}

function commerceEventResourceVersion(
  record: { readonly version: unknown },
): number | undefined {
  const value = record.version;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
    return undefined;
  }
  return value;
}

function commerceEventResourceStatus(
  record: { readonly status: unknown },
): string | undefined {
  return typeof record.status === "string" ? record.status : undefined;
}

function commerceEventIdPart(value: unknown): string {
  return typeof value === "string" ? value : "";
}
