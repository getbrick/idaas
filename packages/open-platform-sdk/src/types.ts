import type { OpenPlatformWebhookEvent as OpenPlatformContractWebhookEvent } from "@getbrick/idaas-contracts";

export const OPEN_PLATFORM_SDK_API_PATH = "/api/open/v1" as const;
export const OPEN_PLATFORM_TENANT_HEADER = "X-Tenant-Id" as const;
export const OPEN_PLATFORM_REQUEST_HEADER = "X-Request-Id" as const;
export const OPEN_PLATFORM_IDEMPOTENCY_HEADER = "Idempotency-Key" as const;
export const OPEN_PLATFORM_WEBHOOK_SIGNATURE_HEADER = "X-Webhook-Signature" as const;
export const OPEN_PLATFORM_WEBHOOK_TIMESTAMP_HEADER = "X-Webhook-Timestamp" as const;
export const OPEN_PLATFORM_WEBHOOK_SECRET_VERSION_HEADER = "X-Webhook-Secret-Version" as const;
export const OPEN_PLATFORM_WEBHOOK_EVENT_ID_HEADER = "X-Webhook-Event-Id" as const;
export const OPEN_PLATFORM_WEBHOOK_EVENT_TYPE_HEADER = "X-Webhook-Event-Type" as const;
export const OPEN_PLATFORM_WEBHOOK_SIGNATURE_VERSION = "v1" as const;

export type MaybePromise<T> = T | Promise<T>;
export type OpenPlatformHttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS";
export type OpenPlatformRequestCache = "default" | "no-store" | "reload" | "no-cache" | "force-cache" | "only-if-cached";

export type OpenPlatformQueryValue =
  | string
  | number
  | boolean
  | null
  | undefined
  | readonly OpenPlatformQueryValue[]
  | { readonly [key: string]: OpenPlatformQueryValue };

export type OpenPlatformQuery =
  | Readonly<Record<string, OpenPlatformQueryValue>>
  | URLSearchParams;

export interface OpenPlatformFetchInit {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  signal?: AbortSignal;
  cache?: OpenPlatformRequestCache;
  credentials?: "omit" | "same-origin" | "include";
  redirect?: "follow" | "error" | "manual";
}

export type OpenPlatformFetch = (input: string, init?: OpenPlatformFetchInit) => Promise<Response>;

export interface OpenPlatformToken {
  readonly accessToken: string;
  readonly tokenType?: string;
}

export interface OpenPlatformTokenProvider {
  getToken?: () => MaybePromise<string | OpenPlatformToken | null | undefined>;
  getAccessToken?: MaybePromise<string | OpenPlatformToken | null | undefined> | (() => MaybePromise<string | OpenPlatformToken | null | undefined>);
}

export type OpenPlatformTokenSource =
  | string
  | OpenPlatformToken
  | (() => MaybePromise<string | OpenPlatformToken | null | undefined>)
  | OpenPlatformTokenProvider;

export interface OpenPlatformPage<T> {
  items: T[];
  nextCursor?: string;
  previousCursor?: string;
  hasMore: boolean;
  total?: number;
}

export interface OpenPlatformPageQuery {
  cursor?: string;
  limit?: number | string;
  pageSize?: number | string;
}

export interface OpenPlatformListQuery extends OpenPlatformPageQuery {
  id?: string;
  search?: string;
  status?: string;
  sort?: string;
}

export interface OpenPlatformRetryContext {
  readonly attempt: number;
  readonly method: OpenPlatformHttpMethod;
  readonly status?: number;
  readonly error?: OpenPlatformErrorLike;
}

export interface OpenPlatformErrorLike {
  readonly code: string;
  readonly status: number;
  readonly statusCode?: number;
  readonly retryable: boolean;
  readonly retryAfterMs?: number;
}

export interface OpenPlatformRetryOptions {
  maxRetries?: number;
  maxAttempts?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
  jitter?: boolean | number;
  retryableStatuses?: readonly number[];
  shouldRetry?: (context: OpenPlatformRetryContext) => boolean;
}

export interface OpenPlatformCallOptions {
  headers?: HeadersInit;
  signal?: AbortSignal;
  timeoutMs?: number;
  tenantId?: string;
  requestId?: string;
  idempotencyKey?: string;
  retry?: boolean | OpenPlatformRetryOptions | number;
  authenticated?: boolean;
  sensitive?: boolean;
  unwrapData?: boolean;
}

export interface OpenPlatformRequestOptions extends OpenPlatformCallOptions {
  method?: OpenPlatformHttpMethod;
  query?: OpenPlatformQuery;
  body?: unknown;
  data?: unknown;
  cache?: OpenPlatformRequestCache;
}

export interface OpenPlatformClientOptions {
  baseUrl?: string | URL;
  baseURL?: string | URL;
  tenantId?: string;
  tokenProvider?: OpenPlatformTokenSource;
  accessTokenProvider?: OpenPlatformTokenSource;
  getToken?: OpenPlatformTokenSource;
  getAccessToken?: OpenPlatformTokenSource;
  accessToken?: OpenPlatformTokenSource;
  refreshTokenProvider?: OpenPlatformTokenSource;
  refreshAccessToken?: OpenPlatformTokenSource;
  tokenRefresher?: OpenPlatformTokenSource;
  fetch?: OpenPlatformFetch;
  fetcher?: OpenPlatformFetch;
  timeoutMs?: number;
  retry?: boolean | OpenPlatformRetryOptions | number;
  defaultHeaders?: HeadersInit;
  headers?: HeadersInit;
  requestIdFactory?: () => string;
  apiPath?: string | false;
  retryOnUnauthorized?: boolean;
  refreshOnUnauthorized?: boolean;
  allowInsecureHttp?: boolean;
}

export type OpenPlatformResourceStatus = "draft" | "published" | "disabled" | "archived";

export interface OpenPlatformResourceBase {
  readonly id: string;
  readonly tenantId: string;
  readonly kind?: string;
  readonly status: OpenPlatformResourceStatus | string;
  readonly version?: number | string;
  readonly createdAt: string;
  readonly updatedAt?: string;
}

export interface OpenPlatformApplication extends OpenPlatformResourceBase {
  readonly organizationId?: string;
  readonly name: string;
  readonly description?: string;
  readonly slug?: string;
}

export interface OpenPlatformApplicationEnvironment extends OpenPlatformResourceBase {
  readonly applicationId: string;
  readonly name: string;
}

export interface OpenPlatformApiVersion extends OpenPlatformResourceBase {
  readonly productId?: string;
  readonly apiProductId?: string;
  readonly apiVersion?: string;
  readonly version?: string;
  readonly description?: string;
  readonly scopes: readonly string[];
  readonly basePath?: string;
}

export interface OpenPlatformApiProduct extends OpenPlatformResourceBase {
  readonly applicationId?: string;
  readonly name: string;
  readonly slug?: string;
  readonly description?: string;
  readonly scopes: readonly string[];
  readonly versions?: readonly OpenPlatformApiVersion[];
}

export interface OpenPlatformCredential extends OpenPlatformResourceBase {
  readonly applicationId: string;
  readonly environmentId?: string;
  readonly clientId?: string;
  readonly name: string;
  readonly credentialKind?: string;
  readonly scopes: readonly string[];
  readonly keyPrefix?: string;
  readonly lastFour?: string;
  readonly expiresAt?: string;
  readonly rotatedAt?: string;
  readonly revokedAt?: string;
  readonly previousCredentialId?: string;
  readonly replacedByCredentialId?: string;
}

export interface OpenPlatformCredentialSecret {
  readonly credentialId?: string;
  readonly value: string;
  readonly expiresAt?: string;
}

export interface OpenPlatformCredentialIssueResult {
  readonly credential: OpenPlatformCredential;
  readonly secret?: string | OpenPlatformCredentialSecret;
  readonly replayed?: boolean;
}

export interface OpenPlatformCredentialRotationResult extends OpenPlatformCredentialIssueResult {
  readonly previousCredential: OpenPlatformCredential;
}

export interface OpenPlatformUsage extends OpenPlatformResourceBase {
  readonly subscriptionId: string;
  readonly credentialId?: string;
  readonly productId?: string;
  readonly apiVersionId?: string;
  readonly metric: string;
  readonly quantity: number;
  readonly unit?: string;
  readonly occurredAt?: string;
  readonly periodStart?: string;
  readonly periodEnd?: string;
  readonly dimensions?: Readonly<Record<string, string>>;
  readonly sourceEventId?: string;
}

export interface OpenPlatformSubscription extends OpenPlatformResourceBase {
  readonly applicationId: string;
  readonly productId?: string;
  readonly apiProductId?: string;
  readonly apiVersionId?: string;
  readonly name: string;
  readonly scopes: readonly string[];
  readonly billingStatus?: string;
  readonly quantity?: number;
  readonly currentPeriodStart?: string;
  readonly currentPeriodEnd?: string;
  readonly cancelAtPeriodEnd?: boolean;
  readonly canceledAt?: string;
}

export type OpenPlatformDecimalString = string;
export type OpenPlatformExactAmount = number | OpenPlatformDecimalString;

export const OPEN_PLATFORM_COMMERCE_CURRENCIES = ["CNY"] as const;
export type OpenPlatformCommerceCurrency = (typeof OPEN_PLATFORM_COMMERCE_CURRENCIES)[number];

export interface OpenPlatformMoney {
  readonly amountMinor: OpenPlatformExactAmount;
  readonly currency: OpenPlatformCommerceCurrency | string;
}

export const OPEN_PLATFORM_MARKETPLACE_LISTING_STATUSES = [
  "draft",
  "pendingReview",
  "published",
  "suspended",
  "removed",
] as const;
export type OpenPlatformMarketplaceListingStatus =
  (typeof OPEN_PLATFORM_MARKETPLACE_LISTING_STATUSES)[number] | string;

export const OPEN_PLATFORM_PARTNER_ACCOUNT_STATUSES = [
  "pending",
  "underReview",
  "active",
  "frozen",
  "rejected",
  "closed",
] as const;
export type OpenPlatformPartnerAccountStatus =
  (typeof OPEN_PLATFORM_PARTNER_ACCOUNT_STATUSES)[number] | string;

export const OPEN_PLATFORM_COMMISSION_RULE_STATUSES = [
  "draft",
  "scheduled",
  "active",
  "suspended",
  "retired",
] as const;
export type OpenPlatformCommissionRuleStatus =
  (typeof OPEN_PLATFORM_COMMISSION_RULE_STATUSES)[number] | string;

export const OPEN_PLATFORM_INVOICE_STATUSES = [
  "draft",
  "reconciling",
  "awaitingPayment",
  "invoicing",
  "paid",
  "completed",
  "disputed",
  "voided",
] as const;
export type OpenPlatformInvoiceStatus =
  (typeof OPEN_PLATFORM_INVOICE_STATUSES)[number] | string;

export interface OpenPlatformMarketplaceListing {
  readonly id: string;
  readonly tenantId: string;
  readonly kind: "marketplaceListing" | string;
  readonly partnerAccountId: string;
  readonly productId: string;
  readonly title: string;
  readonly description: string;
  readonly status: OpenPlatformMarketplaceListingStatus;
  readonly priceIds: readonly string[];
  readonly commissionRuleIds: readonly string[];
  readonly submittedAt?: string;
  readonly publishedAt?: string;
  readonly removedAt?: string;
  readonly version?: number | string;
  readonly createdAt: string;
  readonly updatedAt?: string;
}

export interface OpenPlatformPartnerAccount {
  readonly id: string;
  readonly tenantId: string;
  readonly kind: "partnerAccount" | string;
  readonly legalName: string;
  readonly partnerCode: string;
  readonly status: OpenPlatformPartnerAccountStatus;
  readonly currency: OpenPlatformCommerceCurrency | string;
  readonly settlementReference: string;
  readonly activatedAt?: string;
  readonly version?: number | string;
  readonly createdAt: string;
  readonly updatedAt?: string;
}

export interface OpenPlatformCommissionRule {
  readonly id: string;
  readonly tenantId: string;
  readonly kind: "commissionRule" | string;
  readonly partnerAccountId: string;
  readonly listingId: string;
  readonly name: string;
  readonly status: OpenPlatformCommissionRuleStatus;
  readonly rateBps: number;
  readonly capBps?: number;
  readonly capAmount?: OpenPlatformMoney;
  readonly priority: number;
  readonly effectiveFrom: string;
  readonly effectiveTo?: string;
  readonly version?: number | string;
  readonly createdAt: string;
  readonly updatedAt?: string;
}

export type OpenPlatformBillingAccount = OpenPlatformPartnerAccount;

export interface OpenPlatformInvoiceLine {
  readonly id: string;
  readonly tenantId: string;
  readonly kind: "invoiceLine" | string;
  readonly invoiceId: string;
  readonly type: "subscription" | "usage" | "adjustment" | "tax" | string;
  readonly direction: "debit" | "credit";
  readonly description: string;
  readonly quantity: OpenPlatformDecimalString;
  readonly unitAmount: OpenPlatformMoney;
  readonly amount: OpenPlatformMoney;
  readonly meterId?: string;
  readonly priceId?: string;
  readonly aggregateId?: string;
  readonly adjustmentType?: string;
}

export interface OpenPlatformMainlandChinaInvoiceMetadata {
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

export interface OpenPlatformInvoice {
  readonly id: string;
  readonly tenantId: string;
  readonly kind: "invoice" | string;
  readonly version: number | string;
  readonly subscriptionId: string;
  readonly planId: string;
  readonly periodStart: string;
  readonly periodEnd: string;
  readonly status: OpenPlatformInvoiceStatus;
  readonly currency: OpenPlatformCommerceCurrency | string;
  readonly taxMode: "exclusive" | "inclusive";
  readonly lines: readonly OpenPlatformInvoiceLine[];
  readonly subtotal: OpenPlatformMoney;
  readonly tax: OpenPlatformMoney;
  readonly total: OpenPlatformMoney;
  readonly mainlandChina?: OpenPlatformMainlandChinaInvoiceMetadata;
  readonly createdAt: string;
  readonly updatedAt?: string;
  readonly finalizedAt?: string;
  readonly paidAt?: string;
  readonly voidedAt?: string;
}

export interface OpenPlatformInvoiceDisputeResult {
  readonly invoice: OpenPlatformInvoice;
  readonly replayed: boolean;
  readonly dispute?: OpenPlatformInvoiceDisputeView;
}

export interface CreateOpenPlatformMarketplaceListingInput {
  partnerAccountId: string;
  productId: string;
  title: string;
  description: string;
  priceIds?: readonly string[];
  commissionRuleIds?: readonly string[];
  tenantId?: string;
  idempotencyKey?: string;
}

export interface OpenPlatformMarketplaceListingListQuery extends OpenPlatformListQuery {
  partnerAccountId?: string;
  productId?: string;
  q?: string;
}

export interface OpenPlatformPartnerAccountListQuery extends OpenPlatformListQuery {
  partnerCode?: string;
  q?: string;
}

export type OpenPlatformPartnerListQuery = OpenPlatformPartnerAccountListQuery;

export interface OpenPlatformCommissionRuleListQuery extends OpenPlatformListQuery {
  listingId?: string;
  partnerAccountId?: string;
}

export interface OpenPlatformBillingAccountListQuery extends OpenPlatformPartnerAccountListQuery {}

export interface OpenPlatformInvoiceListQuery extends OpenPlatformListQuery {
  subscriptionId?: string;
  planId?: string;
  periodStart?: string;
  periodEnd?: string;
  from?: string;
  to?: string;
}

export interface OpenPlatformInvoiceDisputeInput {
  reason: string;
  evidenceReference?: string;
  tenantId?: string;
  idempotencyKey?: string;
}

export type OpenPlatformInvoiceDisputeStatus =
  | "open"
  | "underReview"
  | "accepted"
  | "rejected"
  | "withdrawn";

export type OpenPlatformInvoiceDisputeOutcome =
  | "accepted"
  | "rejected"
  | "withdrawn";

export interface OpenPlatformInvoiceDisputeResolution {
  readonly outcome: OpenPlatformInvoiceDisputeOutcome;
  readonly actorId: string;
  readonly reference: string;
  readonly resolvedAt: string;
  readonly note?: string;
  readonly noteLength?: number;
  readonly fromStatus?: OpenPlatformInvoiceDisputeStatus;
}

export interface OpenPlatformInvoiceDisputeView {
  readonly id: string;
  readonly tenantId: string;
  readonly kind: "invoiceDispute" | string;
  readonly version: number | string;
  readonly event: string;
  readonly invoiceId: string;
  readonly subscriptionId: string;
  readonly planId: string;
  readonly invoiceStatus: OpenPlatformInvoiceStatus;
  readonly invoiceVersion: number | string;
  readonly reason: string;
  readonly reasonLength: number | string;
  readonly evidenceReference?: string;
  readonly evidenceCount: number | string;
  readonly actorId: string;
  readonly requestId: string;
  readonly status: OpenPlatformInvoiceDisputeStatus;
  readonly resolution?: OpenPlatformInvoiceDisputeResolution;
  readonly resolvedAt?: string;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly recordedAt: string;
}

export type OpenPlatformInvoiceDispute = OpenPlatformInvoiceDisputeView;

export interface OpenPlatformInvoiceDisputeListQuery extends OpenPlatformListQuery {
  status?: OpenPlatformInvoiceDisputeStatus | string;
  from?: string;
  to?: string;
}

export interface OpenPlatformInvoiceDisputeActionInput {
  tenantId?: string;
  idempotencyKey?: string;
  reference?: string;
  resolutionNote?: string;
}

export interface OpenPlatformInvoiceDisputeDecisionInput
  extends OpenPlatformInvoiceDisputeActionInput {
  outcome: OpenPlatformInvoiceDisputeOutcome;
}

export interface OpenPlatformInvoiceDisputeDecisionResult {
  readonly dispute: OpenPlatformInvoiceDisputeView;
  readonly fromStatus: OpenPlatformInvoiceDisputeStatus;
  readonly replayed: boolean;
}

export interface OpenPlatformApplicationListQuery extends OpenPlatformListQuery {
  organizationId?: string;
}

export interface OpenPlatformApiProductListQuery extends OpenPlatformListQuery {
  applicationId?: string;
}

export interface OpenPlatformCredentialListQuery extends OpenPlatformListQuery {
  applicationId?: string;
  environmentId?: string;
}

export interface OpenPlatformUsageListQuery extends OpenPlatformListQuery {
  subscriptionId?: string;
  credentialId?: string;
  from?: string;
  to?: string;
}

export interface OpenPlatformSubscriptionListQuery extends OpenPlatformListQuery {
  applicationId?: string;
  productId?: string;
  apiVersionId?: string;
}

export type OpenPlatformWebhookStatus = "active" | "paused" | "failing" | "disabled";
export type OpenPlatformWebhookEvent =
  | OpenPlatformContractWebhookEvent
  | (string & {});

export interface OpenPlatformWebhook {
  readonly id: string;
  readonly tenantId: string;
  readonly developerOrganizationId?: string;
  readonly applicationId: string;
  readonly environmentId: string;
  readonly name: string;
  readonly endpointUrl: string;
  readonly status: OpenPlatformWebhookStatus;
  readonly events: readonly OpenPlatformWebhookEvent[];
  readonly signingAlgorithm: "hmac-sha256";
  readonly secretVersion?: number;
  readonly createdAt: string;
  readonly updatedAt?: string;
  readonly lastDeliveryAt?: string;
  readonly failureCount?: number;
  readonly nextDeliveryAt?: string;
}

export interface OpenPlatformWebhookDelivery {
  readonly id: string;
  readonly tenantId?: string;
  readonly webhookId: string;
  readonly eventId?: string;
  readonly event: OpenPlatformWebhookEvent;
  readonly eventType?: OpenPlatformWebhookEvent;
  readonly status: "pending" | "delivering" | "succeeded" | "failed" | "dead_lettered";
  readonly attempt: number;
  readonly maxAttempts?: number;
  readonly idempotencyKey: string;
  readonly createdAt: string;
  readonly updatedAt?: string;
  readonly nextAttemptAt?: string;
  readonly deliveredAt?: string;
  readonly responseStatusCode?: number;
  readonly responseBodyExcerpt?: string;
  readonly errorCode?: string;
}

export interface OpenPlatformWebhookListQuery extends OpenPlatformListQuery {
  status?: OpenPlatformWebhookStatus;
  applicationId?: string;
  environmentId?: string;
}

export interface OpenPlatformWebhookDeliveryListQuery extends OpenPlatformListQuery {
  eventId?: string;
  status?: OpenPlatformWebhookDelivery["status"];
}

export interface CreateOpenPlatformWebhookInput {
  applicationId: string;
  environmentId: string;
  developerOrganizationId?: string;
  name: string;
  endpointUrl: string;
  events: readonly OpenPlatformWebhookEvent[];
  tenantId?: string;
  idempotencyKey?: string;
}

export interface OpenPlatformWebhookSecretResult {
  webhook: OpenPlatformWebhook;
  secret: string;
  secretVersion: number;
  replayed?: boolean;
}

export interface OpenPlatformWebhookDispatchResult {
  delivery: OpenPlatformWebhookDelivery;
  deliveries: OpenPlatformWebhookDelivery[];
  attempts: number;
  duplicate: boolean;
  deadLettered: boolean;
}

export interface OpenPlatformAuditActor {
  readonly type: "user" | "service" | "system";
  readonly id: string;
  readonly displayName?: string;
  readonly ipAddress?: string;
  readonly userAgent?: string;
}

export interface OpenPlatformAuditTarget {
  readonly type: string;
  readonly id: string;
  readonly displayName?: string;
}

export interface OpenPlatformAuditEvent {
  readonly id: string;
  readonly tenantId: string;
  readonly action: string;
  readonly outcome: "success" | "failure" | "denied";
  readonly actor: OpenPlatformAuditActor;
  readonly target: OpenPlatformAuditTarget;
  readonly requestId?: string;
  readonly metadata: Readonly<Record<string, string | number | boolean | null>>;
  readonly occurredAt: string;
  readonly sequence: number;
  readonly source?: string;
  readonly previousHash?: string;
  readonly eventHash: string;
}

export interface OpenPlatformAuditEventListQuery extends OpenPlatformListQuery {
  action?: string;
  outcome?: OpenPlatformAuditEvent["outcome"];
  targetId?: string;
}

export interface OpenPlatformWebhookEventEnvelope {
  eventId?: string;
  eventType?: OpenPlatformWebhookEvent;
  type?: OpenPlatformWebhookEvent;
  occurredAt?: string;
  tenantId: string;
  actor?: { readonly type: "user" | "service" | "system"; readonly id: string };
  resource?: { readonly type: string; readonly id: string; readonly version?: number; readonly status?: string };
  data?: Readonly<Record<string, unknown>>;
  schemaVersion?: string;
  requestId?: string;
  traceId?: string;
}

export interface OpenPlatformWebhookSignatureInput {
  timestamp: string | number;
  body: string | Uint8Array;
  secret: string;
  secretVersion: string | number;
}

export interface OpenPlatformWebhookSignatureHeaders {
  signature: string;
  timestamp: string;
  secretVersion: string;
}

export interface CreateOpenPlatformApplicationInput {
  organizationId: string;
  name: string;
  description?: string;
  tenantId?: string;
  idempotencyKey?: string;
}

export interface CreateOpenPlatformEnvironmentInput {
  name: string;
  tenantId?: string;
  idempotencyKey?: string;
}

export interface CreateOpenPlatformApiProductInput {
  name: string;
  description?: string;
  scopes: readonly string[];
  tenantId?: string;
  idempotencyKey?: string;
}

export interface CreateOpenPlatformApiVersionInput {
  apiVersion: string;
  description?: string;
  scopes: readonly string[];
  tenantId?: string;
  idempotencyKey?: string;
}

export interface IssueOpenPlatformCredentialInput {
  applicationId: string;
  environmentId?: string;
  name: string;
  scopes: readonly string[];
  expiresAt?: string;
  tenantId?: string;
  idempotencyKey?: string;
}

export interface RecordOpenPlatformUsageInput {
  subscriptionId: string;
  metric: string;
  quantity: number;
  occurredAt?: string;
  credentialId?: string;
  tenantId?: string;
  idempotencyKey?: string;
}

export interface CreateOpenPlatformSubscriptionInput {
  applicationId: string;
  productId: string;
  apiVersionId?: string;
  name: string;
  scopes: readonly string[];
  tenantId?: string;
  idempotencyKey?: string;
}

export type Application = OpenPlatformApplication;
export type ApplicationEnvironment = OpenPlatformApplicationEnvironment;
export type ApiProduct = OpenPlatformApiProduct;
export type ApiVersion = OpenPlatformApiVersion;
export type Credential = OpenPlatformCredential;
export type Usage = OpenPlatformUsage;
export type Subscription = OpenPlatformSubscription;
export type Page<T> = OpenPlatformPage<T>;
export type PageQuery = OpenPlatformPageQuery;
export type ApplicationPage = OpenPlatformPage<OpenPlatformApplication>;
export type ApiProductPage = OpenPlatformPage<OpenPlatformApiProduct>;
export type CredentialPage = OpenPlatformPage<OpenPlatformCredential>;
export type UsagePage = OpenPlatformPage<OpenPlatformUsage>;
export type SubscriptionPage = OpenPlatformPage<OpenPlatformSubscription>;
export type CredentialIssueResult = OpenPlatformCredentialIssueResult;
export type CredentialRotationResult = OpenPlatformCredentialRotationResult;
export type CredentialSecret = OpenPlatformCredentialSecret;
export type OpenPlatformAPIProduct = OpenPlatformApiProduct;
export type OpenPlatformAPIProductResource = OpenPlatformApiProduct;
export type OpenPlatformApplicationResource = OpenPlatformApplication;
export type OpenPlatformApplicationRecord = OpenPlatformApplication;
export type OpenPlatformApiProductRecord = OpenPlatformApiProduct;
export type OpenPlatformCredentialResource = OpenPlatformCredential;
export type OpenPlatformCredentialRecord = OpenPlatformCredential;
export type OpenPlatformUsageRecord = OpenPlatformUsage;
export type OpenPlatformSubscriptionResource = OpenPlatformSubscription;
export type OpenPlatformSubscriptionRecord = OpenPlatformSubscription;
export type OpenPlatformApplicationDto = OpenPlatformApplication;
export type OpenPlatformApiProductDto = OpenPlatformApiProduct;
export type OpenPlatformCredentialDto = OpenPlatformCredential;
export type OpenPlatformSubscriptionDto = OpenPlatformSubscription;
export type OpenPlatformWebhookDto = OpenPlatformWebhook;
export type OpenPlatformWebhookRecord = OpenPlatformWebhook;
export type OpenPlatformWebhookDeliveryRecord = OpenPlatformWebhookDelivery;
export type OpenPlatformAuditEventDto = OpenPlatformAuditEvent;
export type OpenPlatformAuditEventRecord = OpenPlatformAuditEvent;
export type Webhook = OpenPlatformWebhook;
export type WebhookDelivery = OpenPlatformWebhookDelivery;
export type AuditEvent = OpenPlatformAuditEvent;
export type Money = OpenPlatformMoney;
export type DecimalString = OpenPlatformDecimalString;
export type MarketplaceListing = OpenPlatformMarketplaceListing;
export type OpenPlatformListing = OpenPlatformMarketplaceListing;
export type MarketplaceListingView = OpenPlatformMarketplaceListing;
export type PartnerAccount = OpenPlatformPartnerAccount;
export type OpenPlatformPartner = OpenPlatformPartnerAccount;
export type PartnerAccountView = OpenPlatformPartnerAccount;
export type BillingAccount = OpenPlatformBillingAccount;
export type BillingAccountView = OpenPlatformBillingAccount;
export type CommissionRule = OpenPlatformCommissionRule;
export type CommissionRuleView = OpenPlatformCommissionRule;
export type Invoice = OpenPlatformInvoice;
export type InvoiceView = OpenPlatformInvoice;
export type InvoiceLine = OpenPlatformInvoiceLine;
export type MainlandChinaInvoiceMetadata = OpenPlatformMainlandChinaInvoiceMetadata;
export type InvoiceDisputeResult = OpenPlatformInvoiceDisputeResult;
export type InvoiceDispute = OpenPlatformInvoiceDispute;
export type InvoiceDisputeView = OpenPlatformInvoiceDisputeView;
export type InvoiceDisputeStatus = OpenPlatformInvoiceDisputeStatus;
export type InvoiceDisputeOutcome = OpenPlatformInvoiceDisputeOutcome;
export type InvoiceDisputeResolution = OpenPlatformInvoiceDisputeResolution;
export type InvoiceDisputeListQuery = OpenPlatformInvoiceDisputeListQuery;
export type InvoiceDisputeActionInput = OpenPlatformInvoiceDisputeActionInput;
export type InvoiceDisputeDecisionInput = OpenPlatformInvoiceDisputeDecisionInput;
export type InvoiceDisputeDecisionResult = OpenPlatformInvoiceDisputeDecisionResult;
export type CreateMarketplaceListingInput = CreateOpenPlatformMarketplaceListingInput;
export type MarketplaceListingListQuery = OpenPlatformMarketplaceListingListQuery;
export type PartnerAccountListQuery = OpenPlatformPartnerAccountListQuery;
export type CommissionRuleListQuery = OpenPlatformCommissionRuleListQuery;
export type BillingAccountListQuery = OpenPlatformBillingAccountListQuery;
export type InvoiceListQuery = OpenPlatformInvoiceListQuery;
export type InvoiceDisputeInput = OpenPlatformInvoiceDisputeInput;
export type MarketplaceListingPage = OpenPlatformPage<OpenPlatformMarketplaceListing>;
export type PartnerAccountPage = OpenPlatformPage<OpenPlatformPartnerAccount>;
export type BillingAccountPage = OpenPlatformPage<OpenPlatformBillingAccount>;
export type CommissionRulePage = OpenPlatformPage<OpenPlatformCommissionRule>;
export type InvoicePage = OpenPlatformPage<OpenPlatformInvoice>;
export type OpenPlatformMarketplaceListingResource = OpenPlatformMarketplaceListing;
export type OpenPlatformPartnerAccountResource = OpenPlatformPartnerAccount;
export type OpenPlatformCommissionRuleResource = OpenPlatformCommissionRule;
export type OpenPlatformInvoiceResource = OpenPlatformInvoice;
export type OpenPlatformInvoiceDisputeResource = OpenPlatformInvoiceDisputeResult;
export type OpenPlatformMarketplaceQuery = OpenPlatformMarketplaceListingListQuery;
export type OpenPlatformPartnerQuery = OpenPlatformPartnerAccountListQuery;
export type OpenPlatformCommissionRuleQuery = OpenPlatformCommissionRuleListQuery;
export type OpenPlatformBillingQuery = OpenPlatformBillingAccountListQuery;
export type OpenPlatformInvoiceQuery = OpenPlatformInvoiceListQuery;
export type CreateOpenPlatformListingInput = CreateOpenPlatformMarketplaceListingInput;
export type DisputeOpenPlatformInvoiceInput = OpenPlatformInvoiceDisputeInput;
export type OpenPlatformMarketplaceListingDto = OpenPlatformMarketplaceListing;
export type OpenPlatformPartnerAccountDto = OpenPlatformPartnerAccount;
export type OpenPlatformCommissionRuleDto = OpenPlatformCommissionRule;
export type OpenPlatformBillingAccountDto = OpenPlatformBillingAccount;
export type OpenPlatformInvoiceDto = OpenPlatformInvoice;
export type OpenPlatformInvoiceDisputeDto = OpenPlatformInvoiceDisputeResult;
export type OpenPlatformMoneyAmount = OpenPlatformExactAmount;
