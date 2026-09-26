import type { ReactNode } from "react";
import type { OpenPlatformClassNamespaceProps } from "./theme.js";

export type AppLifecycleStatus =
  | "draft"
  | "pending"
  | "pending_review"
  | "active"
  | "disabled"
  | "suspended"
  | "rejected"
  | "archived"
  | "purged"
  | (string & {});

export type AppLifecycleStatusTone = "neutral" | "info" | "success" | "warning" | "danger";

export type AppLifecycleStatusValue =
  | "draft"
  | "pending_review"
  | "active"
  | "disabled"
  | "suspended"
  | "rejected"
  | "archived"
  | "purged"
  | "unknown";

export interface AppLifecycleStatusDescriptor {
  status: AppLifecycleStatusValue;
  label: string;
  tone: AppLifecycleStatusTone;
}

export type OpenPlatformErrorCode =
  | "validation_error"
  | "unauthorized"
  | "forbidden"
  | "not_found"
  | "conflict"
  | "rate_limited"
  | "network_error"
  | "timeout"
  | "service_unavailable"
  | "internal_error"
  | "configuration_error"
  | "request_error"
  | "invalid_response"
  | "aborted"
  | "unknown";

export interface DeveloperPortalNavigationItem {
  id: string;
  label: string;
  href?: string | null;
  badge?: ReactNode;
  disabled?: boolean;
  onSelect?: (item: DeveloperPortalNavigationItem) => void;
}

export type OpenPlatformOperationsNavigationItem = DeveloperPortalNavigationItem;

export interface ApiProduct {
  id: string;
  name: string;
  description?: string | null;
  category?: string | null;
  version?: string | number | null;
  status?: AppLifecycleStatus;
  href?: string | null;
}

export type OpenPlatformErrorValue = unknown;

export type OpenPlatformUnknownRecord = Readonly<Record<string, unknown>>;

export interface OpenPlatformPage<T> {
  readonly items: readonly T[];
  readonly nextCursor?: string;
  readonly previousCursor?: string;
  readonly hasMore?: boolean;
  readonly next_cursor?: string;
  readonly previous_cursor?: string;
  readonly has_more?: boolean;
  readonly nextSequence?: number;
  readonly previousSequence?: number;
  readonly total?: number;
}

export type OpenPlatformListPage<T> = OpenPlatformPage<T>;
export type OpenPlatformCursorPage<T> = OpenPlatformPage<T>;
export type OpenPlatformPageResult<T> = OpenPlatformPage<T>;

export type OpenPlatformStatusTone = AppLifecycleStatusTone;

export interface OpenPlatformStatusDescriptor {
  readonly status: string;
  readonly label: string;
  readonly tone: OpenPlatformStatusTone;
}

export interface OpenPlatformPaginationState {
  readonly cursor?: string;
  readonly nextCursor?: string;
  readonly previousCursor?: string;
  readonly hasMore?: boolean;
  readonly nextSequence?: number;
  readonly previousSequence?: number;
  readonly page?: number;
  readonly pageSize?: number;
  readonly total?: number;
  readonly hasNextPage?: boolean;
  readonly hasPreviousPage?: boolean;
  readonly hasNext?: boolean;
  readonly hasPrevious?: boolean;
  readonly onCursorChange?: (cursor?: string) => void;
  readonly onNext?: () => void;
  readonly onPrevious?: () => void;
  readonly onNextPage?: () => void;
  readonly onPreviousPage?: () => void;
  readonly onLoadMore?: () => void;
  readonly onPageChange?: (page: number) => void;
}

export interface OpenPlatformListQuery {
  cursor?: string;
  limit?: number | string;
  pageSize?: number | string;
  page_size?: number | string;
  search?: string;
  q?: string;
  status?: string;
  sort?: string;
  id?: string;
  tenantId?: string;
  tenant_id?: string;
  action?: string;
  outcome?: string;
  targetId?: string;
  target_id?: string;
  applicationId?: string;
  application_id?: string;
  environmentId?: string;
  environment_id?: string;
  productId?: string;
  partnerAccountId?: string;
  subscriptionId?: string;
  planId?: string;
  eventType?: string;
  resourceType?: string;
  resourceId?: string;
  sequence?: number | string;
  from?: string;
  to?: string;
  [key: string]: unknown;
}

export interface OpenPlatformListBaseProps extends OpenPlatformClassNamespaceProps {
  title?: string;
  caption?: ReactNode;
  actions?: ReactNode;
  loading?: boolean;
  isLoading?: boolean;
  error?: OpenPlatformErrorValue;
  onRetry?: () => void;
  emptyTitle?: string;
  emptyMessage?: string;
  errorTitle?: string;
  loadingLabel?: string;
  retryLabel?: string;
}

export interface OpenPlatformWebhookEndpoint extends OpenPlatformUnknownRecord {
  readonly id: string;
  readonly webhookId?: string | null;
  readonly name?: string | null;
  readonly endpointUrl?: string | null;
  readonly endpoint_url?: string | null;
  readonly endpointURL?: string | null;
  readonly endpoint?: string | null;
  readonly url?: string | null;
  readonly applicationId?: string | null;
  readonly application_id?: string | null;
  readonly environmentId?: string | null;
  readonly environment_id?: string | null;
  readonly status?: string | null;
  readonly events?: readonly (string | null | undefined)[];
  readonly signingSecretReference?: string | null;
  readonly signing_secret_reference?: string | null;
  readonly signingSecretRef?: string | null;
  readonly secretReference?: string | null;
  readonly secretRef?: string | null;
  readonly signingAlgorithm?: string | null;
  readonly secretVersion?: number | string | null;
  readonly createdAt?: string | Date | null;
  readonly updatedAt?: string | Date | null;
  readonly lastDeliveryAt?: string | Date | null;
  readonly failureCount?: number | null;
  readonly nextDeliveryAt?: string | Date | null;
}

export type WebhookEndpoint = OpenPlatformWebhookEndpoint;

export interface OpenPlatformAuditActor extends OpenPlatformUnknownRecord {
  readonly id?: string | null;
  readonly type?: string | null;
  readonly displayName?: string | null;
  readonly name?: string | null;
  readonly email?: string | null;
}

export interface OpenPlatformAuditTarget extends OpenPlatformUnknownRecord {
  readonly id?: string | null;
  readonly type?: string | null;
  readonly displayName?: string | null;
  readonly name?: string | null;
}

export interface OpenPlatformAuditEvent extends OpenPlatformUnknownRecord {
  readonly id: string;
  readonly action?: string | null;
  readonly event?: string | null;
  readonly type?: string | null;
  readonly outcome?: string | null;
  readonly actor?: string | OpenPlatformAuditActor | null;
  readonly target?: string | OpenPlatformAuditTarget | null;
  readonly requestId?: string | null;
  readonly request_id?: string | null;
  readonly metadata?: Readonly<Record<string, unknown>> | null;
  readonly detail?: unknown;
  readonly occurredAt?: string | Date | null;
  readonly occurred_at?: string | Date | null;
  readonly createdAt?: string | Date | null;
  readonly source?: string | null;
  readonly sequence?: number | null;
}

export type OpenPlatformAuditEventSummary = OpenPlatformAuditEvent;

export interface OpenPlatformMarketplaceListing extends OpenPlatformUnknownRecord {
  readonly id: string;
  readonly title?: string | null;
  readonly name?: string | null;
  readonly listingName?: string | null;
  readonly productName?: string | null;
  readonly description?: string | null;
  readonly status?: string | null;
  readonly partnerAccountId?: string | null;
  readonly partner_account_id?: string | null;
  readonly partnerId?: string | null;
  readonly productId?: string | null;
  readonly product_id?: string | null;
  readonly priceIds?: readonly string[];
  readonly price_ids?: readonly string[];
  readonly commissionRuleIds?: readonly string[];
  readonly commission_rule_ids?: readonly string[];
  readonly submittedAt?: string | Date | null;
  readonly publishedAt?: string | Date | null;
  readonly removedAt?: string | Date | null;
  readonly createdAt?: string | Date | null;
  readonly updatedAt?: string | Date | null;
  readonly version?: number | string | null;
  readonly href?: string | null;
}

export type MarketplaceListing = OpenPlatformMarketplaceListing;

export interface OpenPlatformMoney extends OpenPlatformUnknownRecord {
  readonly amountMinor?: number | null;
  readonly amount?: number | string | null;
  readonly currency?: string | null;
}

export interface OpenPlatformInvoiceLine extends OpenPlatformUnknownRecord {
  readonly id?: string | null;
  readonly description?: string | null;
  readonly quantity?: number | string | null;
  readonly amount?: OpenPlatformMoney | number | string | null;
  readonly unitAmount?: OpenPlatformMoney | number | string | null;
  readonly type?: string | null;
}

export interface OpenPlatformInvoiceMetadata extends OpenPlatformUnknownRecord {
  readonly buyerName?: string | null;
  readonly buyer_name?: string | null;
  readonly unifiedSocialCreditCode?: string | null;
  readonly buyerAddress?: string | null;
  readonly buyer_address?: string | null;
  readonly address?: string | null;
  readonly buyerPhone?: string | null;
  readonly buyer_phone?: string | null;
  readonly phone?: string | null;
  readonly buyerBankName?: string | null;
  readonly buyerBankAccount?: string | null;
  readonly buyer_bank_account?: string | null;
  readonly bankAccount?: string | null;
  readonly bankAccountNumber?: string | null;
  readonly settlementReference?: string | null;
  readonly settlement_reference?: string | null;
  readonly settlementRef?: string | null;
  readonly secretReference?: string | null;
  readonly secret_reference?: string | null;
  readonly invoiceType?: string | null;
  readonly issueMode?: string | null;
  readonly taxRateBps?: number | null;
  readonly invoiceCode?: string | null;
  readonly invoiceNumber?: string | null;
}

export interface OpenPlatformInvoice extends OpenPlatformUnknownRecord {
  readonly id: string;
  readonly invoiceId?: string | null;
  readonly invoice_id?: string | null;
  readonly invoiceNumber?: string | null;
  readonly invoiceNumberText?: string | null;
  readonly invoiceCode?: string | null;
  readonly status?: string | null;
  readonly currency?: string | null;
  readonly periodStart?: string | Date | null;
  readonly period_start?: string | Date | null;
  readonly periodEnd?: string | Date | null;
  readonly period_end?: string | Date | null;
  readonly total?: OpenPlatformMoney | number | string | null;
  readonly totalAmount?: OpenPlatformMoney | number | string | null;
  readonly amount?: OpenPlatformMoney | number | string | null;
  readonly subtotal?: OpenPlatformMoney | number | string | null;
  readonly tax?: OpenPlatformMoney | number | string | null;
  readonly lines?: readonly OpenPlatformInvoiceLine[];
  readonly mainlandChina?: OpenPlatformInvoiceMetadata | null;
  readonly mainland_china?: OpenPlatformInvoiceMetadata | null;
  readonly invoiceMetadata?: OpenPlatformInvoiceMetadata | null;
  readonly metadata?: OpenPlatformInvoiceMetadata | null;
  readonly buyerName?: string | null;
  readonly buyer_name?: string | null;
  readonly customerName?: string | null;
  readonly buyer?: OpenPlatformUnknownRecord | null;
  readonly billingAddress?: string | null;
  readonly buyerAddress?: string | null;
  readonly buyer_address?: string | null;
  readonly address?: string | null;
  readonly buyerPhone?: string | null;
  readonly buyer_phone?: string | null;
  readonly phone?: string | null;
  readonly buyerBankAccount?: string | null;
  readonly buyer_bank_account?: string | null;
  readonly bankAccount?: string | null;
  readonly bankAccountNumber?: string | null;
  readonly settlementReference?: string | null;
  readonly settlement_reference?: string | null;
  readonly settlementRef?: string | null;
  readonly secretReference?: string | null;
  readonly secret_reference?: string | null;
  readonly secretRef?: string | null;
  readonly secret_ref?: string | null;
  readonly createdAt?: string | Date | null;
  readonly updatedAt?: string | Date | null;
  readonly paidAt?: string | Date | null;
}

export type Invoice = OpenPlatformInvoice;
export type InvoiceMetadata = OpenPlatformInvoiceMetadata;
export type OpenPlatformWebhookPage = OpenPlatformPage<OpenPlatformWebhookEndpoint>;
export type OpenPlatformAuditEventPage = OpenPlatformPage<OpenPlatformAuditEvent>;
export type OpenPlatformMarketplaceListingPage = OpenPlatformPage<OpenPlatformMarketplaceListing>;
export type OpenPlatformInvoicePage = OpenPlatformPage<OpenPlatformInvoice>;
export type WebhookPage = OpenPlatformWebhookPage;
export type AuditEventPage = OpenPlatformAuditEventPage;
export type MarketplaceListingPage = OpenPlatformMarketplaceListingPage;
export type InvoicePage = OpenPlatformInvoicePage;

export type OpenPlatformComplianceDataAssetStatus = "draft" | "registered" | "active" | "retired" | (string & {});

export type OpenPlatformCompliancePrivacyRequestStatus =
  | "submitted"
  | "verifyingIdentity"
  | "verified"
  | "inProgress"
  | "fulfilled"
  | "partiallyFulfilled"
  | "rejected"
  | "cancelled"
  | (string & {});

export type OpenPlatformCompliancePrivacyRequestType =
  | "access"
  | "deletion"
  | "correction"
  | "revocation"
  | "portability"
  | (string & {});

export type OpenPlatformCompliancePrivacyRequestSlaState =
  | "withinSla"
  | "dueSoon"
  | "breached"
  | "closedMet"
  | "closedBreached"
  | (string & {});

export type OpenPlatformComplianceEvidenceKind =
  | "document"
  | "systemRecord"
  | "ticket"
  | "attestation"
  | (string & {});

export type OpenPlatformDomainEventStatus =
  | "pending"
  | "delivering"
  | "published"
  | "failed"
  | "dead_lettered"
  | (string & {});

export interface OpenPlatformComplianceEvidenceReference extends OpenPlatformUnknownRecord {
  readonly reference?: string | null;
  readonly kind?: OpenPlatformComplianceEvidenceKind | null;
  readonly recordedAt?: string | Date | null;
}

export interface OpenPlatformComplianceDataAsset extends OpenPlatformUnknownRecord {
  readonly id: string;
  readonly code?: string | null;
  readonly name?: string | null;
  readonly status?: OpenPlatformComplianceDataAssetStatus | null;
  readonly classification?: string | null;
  readonly categories?: readonly (string | null | undefined)[];
  readonly personalData?: boolean | null;
  readonly sensitivePersonalData?: boolean | null;
  readonly legalBasis?: string | null;
  readonly purposes?: readonly (string | null | undefined)[];
  readonly dataSubjects?: readonly (string | null | undefined)[];
  readonly residencyRegions?: readonly (string | null | undefined)[];
  readonly retentionPolicyId?: string | null;
  readonly retentionDays?: number | null;
  readonly crossBorder?: boolean | null;
  readonly evidence?: readonly (OpenPlatformComplianceEvidenceReference | null | undefined)[];
  readonly createdAt?: string | Date | null;
  readonly updatedAt?: string | Date | null;
}

export interface OpenPlatformComplianceIdentityVerification extends OpenPlatformUnknownRecord {
  readonly status?: string | null;
  readonly method?: string | null;
  readonly attempts?: number | null;
  readonly verifiedAt?: string | Date | null;
  readonly verifiedByRef?: string | null;
  readonly evidence?: readonly (OpenPlatformComplianceEvidenceReference | null | undefined)[];
}

export interface OpenPlatformCompliancePrivacyRequestSla extends OpenPlatformUnknownRecord {
  readonly policyCode?: string | null;
  readonly responseDays?: number | null;
  readonly dueAt?: string | Date | null;
  readonly respondedAt?: string | Date | null;
  readonly closedAt?: string | Date | null;
  readonly state?: OpenPlatformCompliancePrivacyRequestSlaState | null;
  readonly millisecondsRemaining?: number | null;
}

export interface OpenPlatformCompliancePrivacyRequestDecision extends OpenPlatformUnknownRecord {
  readonly decision?: string | null;
  readonly decidedAt?: string | Date | null;
  readonly decidedByRef?: string | null;
  readonly rationale?: string | null;
  readonly evidence?: readonly (OpenPlatformComplianceEvidenceReference | null | undefined)[];
}

export interface OpenPlatformCompliancePrivacyRequestAction extends OpenPlatformUnknownRecord {
  readonly action?: string | null;
  readonly dataAssetId?: string | null;
  readonly executedAt?: string | Date | null;
  readonly affectedRecords?: number | null;
  readonly executionRef?: string | null;
}

export interface OpenPlatformCompliancePrivacyRequest extends OpenPlatformUnknownRecord {
  readonly id: string;
  readonly requestType?: OpenPlatformCompliancePrivacyRequestType | null;
  readonly status?: OpenPlatformCompliancePrivacyRequestStatus | null;
  readonly statusReason?: string | null;
  readonly subjectRefMasked?: string | null;
  readonly subjectRef?: string | null;
  readonly subjectCount?: number | null;
  readonly dataAssetIds?: readonly (string | null | undefined)[];
  readonly identityVerification?: OpenPlatformComplianceIdentityVerification | null;
  readonly sla?: OpenPlatformCompliancePrivacyRequestSla | null;
  readonly decision?: OpenPlatformCompliancePrivacyRequestDecision | null;
  readonly actions?: readonly (OpenPlatformCompliancePrivacyRequestAction | null | undefined)[];
  readonly duplicateOfId?: string | null;
  readonly receivedAt?: string | Date | null;
  readonly createdAt?: string | Date | null;
  readonly updatedAt?: string | Date | null;
}

export interface OpenPlatformComplianceCountBreakdown extends OpenPlatformUnknownRecord {
  readonly total?: number | null;
  readonly counts?: Readonly<Record<string, number>> | null;
}

export interface OpenPlatformComplianceReportGap extends OpenPlatformUnknownRecord {
  readonly code?: string | null;
  readonly count?: number | null;
  readonly resourceIds?: readonly (string | null | undefined)[];
}

export interface OpenPlatformComplianceReport extends OpenPlatformUnknownRecord {
  readonly contractVersion?: number | null;
  readonly generatedAt?: string | Date | null;
  readonly period?: OpenPlatformUnknownRecord | null;
  readonly redaction?: OpenPlatformUnknownRecord | null;
  readonly dataCatalog?: OpenPlatformUnknownRecord | null;
  readonly consent?: OpenPlatformUnknownRecord | null;
  readonly privacyRequests?: OpenPlatformUnknownRecord | null;
  readonly retention?: OpenPlatformUnknownRecord | null;
  readonly crossBorder?: OpenPlatformUnknownRecord | null;
  readonly vendors?: OpenPlatformUnknownRecord | null;
  readonly gaps?: readonly (OpenPlatformComplianceReportGap | null | undefined)[];
  readonly limitations?: readonly (string | null | undefined)[];
}

export interface OpenPlatformDomainEventResourceSummary extends OpenPlatformUnknownRecord {
  readonly type?: string | null;
  readonly id?: string | null;
}

export interface OpenPlatformDomainEventSummary extends OpenPlatformUnknownRecord {
  readonly eventId?: string | null;
  readonly type?: string | null;
  readonly eventType?: string | null;
  readonly resource?: OpenPlatformDomainEventResourceSummary | null;
  readonly status?: OpenPlatformDomainEventStatus | null;
  readonly attempt?: number | null;
  readonly occurredAt?: string | Date | null;
  readonly errorCode?: string | null;
  readonly nextAttemptAt?: string | Date | null;
}

export interface OpenPlatformDomainEventRetryResult extends OpenPlatformUnknownRecord {
  readonly eventId?: string | null;
  readonly delivered?: number | null;
  readonly deadLettered?: boolean | null;
}

export interface OpenPlatformDomainEventRetrySummary extends OpenPlatformUnknownRecord {
  readonly flushed?: number | null;
  readonly replayed?: boolean | null;
  readonly results?: readonly (OpenPlatformDomainEventRetryResult | null | undefined)[];
}

export interface OpenPlatformComplianceListQuery {
  readonly cursor?: string;
  readonly limit?: number | string;
  readonly pageSize?: number | string;
  readonly page_size?: number | string;
  readonly status?: string;
  readonly ids?: readonly string[];
  readonly tenantId?: string;
  readonly tenant_id?: string;
  readonly [key: string]: unknown;
}

export interface OpenPlatformComplianceReportQuery {
  readonly from?: string;
  readonly to?: string;
  readonly generatedAt?: string;
  readonly tenantId?: string;
}

export interface OpenPlatformDomainEventListQuery {
  readonly cursor?: string;
  readonly sequence?: number | string;
  readonly limit?: number | string;
  readonly pageSize?: number | string;
  readonly page_size?: number | string;
  readonly status?: string;
  readonly eventType?: string;
  readonly resourceType?: string;
  readonly resourceId?: string;
  readonly tenantId?: string;
  readonly tenant_id?: string;
  readonly [key: string]: unknown;
}

export interface OpenPlatformDomainEventRetryInput {
  readonly eventType?: string;
  readonly limit?: number;
  readonly tenantId?: string;
  readonly idempotencyKey?: string;
}

export type ComplianceDataAsset = OpenPlatformComplianceDataAsset;
export type CompliancePrivacyRequest = OpenPlatformCompliancePrivacyRequest;
export type ComplianceReport = OpenPlatformComplianceReport;
export type ComplianceEvidence = OpenPlatformComplianceEvidenceReference;
export type ComplianceListQuery = OpenPlatformComplianceListQuery;
export type ComplianceReportQuery = OpenPlatformComplianceReportQuery;
export type DomainEventSummary = OpenPlatformDomainEventSummary;
export type DomainEventRetryInput = OpenPlatformDomainEventRetryInput;
export type DomainEventRetrySummary = OpenPlatformDomainEventRetrySummary;
export type DomainEventListQuery = OpenPlatformDomainEventListQuery;
export type OpenPlatformComplianceDataAssetPage = OpenPlatformPage<OpenPlatformComplianceDataAsset>;
export type OpenPlatformCompliancePrivacyRequestPage = OpenPlatformPage<OpenPlatformCompliancePrivacyRequest>;
export type OpenPlatformDomainEventPage = OpenPlatformPage<OpenPlatformDomainEventSummary>;
export type OpenPlatformOutboxPage = OpenPlatformDomainEventPage;
export type ComplianceDataAssetPage = OpenPlatformComplianceDataAssetPage;
export type CompliancePrivacyRequestPage = OpenPlatformCompliancePrivacyRequestPage;
export type DomainEventPage = OpenPlatformDomainEventPage;
