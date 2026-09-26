import type {
  BillingAccountView,
  CommissionRule,
  CommissionRuleView,
  Invoice,
  InvoiceDispute,
  InvoiceDisputeView,
  InvoiceLine,
  InvoiceView,
  MarketplaceListing,
  MarketplaceListingView,
  MainlandChinaInvoiceMetadataView,
  PartnerAccount,
  PartnerAccountView,
} from "./types.js";
import { cloneCommerceValue } from "./validation.js";

export const COMMERCE_REDACTED_VALUE = "[redacted]";

export function toCommerceMarketplaceListingView(
  record: MarketplaceListing,
): MarketplaceListingView {
  return {
    id: record.id,
    tenantId: record.tenantId,
    kind: record.kind,
    partnerAccountId: record.partnerAccountId,
    productId: record.productId,
    title: record.title,
    description: record.description,
    status: record.status,
    priceIds: [...record.priceIds],
    commissionRuleIds: [...record.commissionRuleIds],
    ...(record.submittedAt === undefined ? {} : { submittedAt: record.submittedAt }),
    ...(record.publishedAt === undefined ? {} : { publishedAt: record.publishedAt }),
    ...(record.removedAt === undefined ? {} : { removedAt: record.removedAt }),
    version: record.version,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
  };
}

export function toCommercePartnerAccountView(
  record: PartnerAccount,
): PartnerAccountView {
  return {
    id: record.id,
    tenantId: record.tenantId,
    kind: record.kind,
    legalName: record.legalName,
    partnerCode: record.partnerCode,
    status: record.status,
    currency: record.currency,
    settlementReference: COMMERCE_REDACTED_VALUE,
    ...(record.activatedAt === undefined ? {} : { activatedAt: record.activatedAt }),
    version: record.version,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
  };
}

export function toCommerceCommissionRuleView(
  record: CommissionRule,
): CommissionRuleView {
  return {
    id: record.id,
    tenantId: record.tenantId,
    kind: record.kind,
    partnerAccountId: record.partnerAccountId,
    listingId: record.listingId,
    name: record.name,
    status: record.status,
    rateBps: record.rateBps,
    ...(record.capBps === undefined ? {} : { capBps: record.capBps }),
    ...(record.capAmount === undefined
      ? {}
      : { capAmount: cloneCommerceValue(record.capAmount) }),
    priority: record.priority,
    effectiveFrom: record.effectiveFrom,
    ...(record.effectiveTo === undefined ? {} : { effectiveTo: record.effectiveTo }),
    version: record.version,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
  };
}

export function toCommerceInvoiceView(record: Invoice): InvoiceView {
  const mainlandChina = record.mainlandChina === undefined
    ? undefined
    : toMainlandChinaInvoiceMetadataView(record.mainlandChina);
  return {
    id: record.id,
    tenantId: record.tenantId,
    kind: record.kind,
    version: record.version,
    subscriptionId: record.subscriptionId,
    planId: record.planId,
    periodStart: record.periodStart,
    periodEnd: record.periodEnd,
    status: record.status,
    currency: record.currency,
    taxMode: record.taxMode,
    lines: record.lines.map((line) => toInvoiceLineView(line)),
    subtotal: cloneCommerceValue(record.subtotal),
    tax: cloneCommerceValue(record.tax),
    total: cloneCommerceValue(record.total),
    ...(mainlandChina === undefined ? {} : { mainlandChina }),
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    ...(record.finalizedAt === undefined ? {} : { finalizedAt: record.finalizedAt }),
    ...(record.paidAt === undefined ? {} : { paidAt: record.paidAt }),
    ...(record.voidedAt === undefined ? {} : { voidedAt: record.voidedAt }),
  };
}

export function toCommerceBillingAccountView(
  record: PartnerAccount,
): BillingAccountView {
  return toCommercePartnerAccountView(record);
}

export function toCommerceInvoiceDisputeView(
  record: InvoiceDispute,
): InvoiceDisputeView {
  return {
    id: record.id,
    tenantId: record.tenantId,
    kind: record.kind,
    version: record.version,
    event: record.event,
    invoiceId: record.invoiceId,
    subscriptionId: record.subscriptionId,
    planId: record.planId,
    invoiceStatus: record.invoiceStatus,
    invoiceVersion: record.invoiceVersion,
    reason: record.reason,
    reasonLength: record.reasonLength,
    ...(record.evidenceReference === undefined
      ? {}
      : { evidenceReference: record.evidenceReference }),
    evidenceCount: record.evidenceCount,
    actorId: record.actorId,
    requestId: record.requestId,
    status: record.status,
    ...(record.resolution === undefined
      ? {}
      : { resolution: cloneCommerceValue(record.resolution) }),
    ...(record.resolvedAt === undefined ? {} : { resolvedAt: record.resolvedAt }),
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    recordedAt: record.recordedAt,
  };
}

export function maskCommerceSettlementReference(
  _value: unknown,
): string {
  return COMMERCE_REDACTED_VALUE;
}

export function maskCommerceBankAccount(
  value: unknown,
): string {
  return maskTail(value);
}

export function maskCommercePhone(
  value: unknown,
): string {
  return maskTail(value);
}

export function maskCommerceAddress(
  _value: unknown,
): string {
  return COMMERCE_REDACTED_VALUE;
}

function maskTail(value: unknown): string {
  if (typeof value !== "string" || value.length <= 4) return "****";
  return `****${value.slice(-4)}`;
}

function toMainlandChinaInvoiceMetadataView(
  value: NonNullable<Invoice["mainlandChina"]>,
): MainlandChinaInvoiceMetadataView {
  return {
    invoiceType: value.invoiceType,
    buyerName: value.buyerName,
    ...(value.unifiedSocialCreditCode === undefined
      ? {}
      : { unifiedSocialCreditCode: value.unifiedSocialCreditCode }),
    ...(value.buyerAddress === undefined
      ? {}
      : { buyerAddress: maskCommerceAddress(value.buyerAddress) }),
    ...(value.buyerPhone === undefined
      ? {}
      : { buyerPhone: maskCommercePhone(value.buyerPhone) }),
    ...(value.buyerBankName === undefined
      ? {}
      : { buyerBankName: value.buyerBankName }),
    ...(value.buyerBankAccount === undefined
      ? {}
      : { buyerBankAccount: maskCommerceBankAccount(value.buyerBankAccount) }),
    taxRateBps: value.taxRateBps,
    issueMode: value.issueMode,
    ...(value.invoiceCode === undefined ? {} : { invoiceCode: value.invoiceCode }),
    ...(value.invoiceNumber === undefined
      ? {}
      : { invoiceNumber: value.invoiceNumber }),
  };
}

function toInvoiceLineView(line: InvoiceLine): InvoiceLine {
  return cloneCommerceValue(line);
}
