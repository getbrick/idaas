import { randomUUID } from "node:crypto";
import { assertIdempotencyKey, generateIdempotencyKey } from "./idempotency.js";
import {
  OpenPlatformAbortError,
  OpenPlatformApiError,
  OpenPlatformAuthenticationProviderError,
  OpenPlatformConfigurationError,
  OpenPlatformNetworkError,
  OpenPlatformProtocolError,
  OpenPlatformRequestError,
  OpenPlatformTimeoutError,
  parseOpenPlatformErrorResponse,
} from "./errors.js";
import {
  collectOpenPlatformPages,
  normalizeOpenPlatformPage,
} from "./pagination.js";
import {
  normalizeOpenPlatformDomainEventPage,
  normalizeOpenPlatformDomainEventRetry,
} from "./domain-events.js";
import { redactOpenPlatformComplianceSubjects } from "./compliance.js";
import type {
  CreateOpenPlatformComplianceConsentRecordInput,
  CreateOpenPlatformComplianceCrossBorderAssessmentInput,
  CreateOpenPlatformComplianceDataAssetInput,
  CreateOpenPlatformCompliancePrivacyRequestInput,
  CreateOpenPlatformComplianceRetentionPolicyInput,
  CreateOpenPlatformComplianceVendorInput,
  DecideOpenPlatformCompliancePrivacyRequestInput,
  ExpireOpenPlatformComplianceConsentInput,
  GenerateOpenPlatformComplianceReportInput,
  GrantOpenPlatformComplianceConsentInput,
  OpenPlatformComplianceConsentRecord,
  OpenPlatformComplianceCrossBorderAssessment,
  OpenPlatformComplianceDataAsset,
  OpenPlatformComplianceListQuery,
  OpenPlatformCompliancePrivacyRequest,
  OpenPlatformCompliancePrivacyRequestSla,
  OpenPlatformComplianceReportQuery,
  OpenPlatformComplianceReportView,
  OpenPlatformComplianceRetentionExecution,
  OpenPlatformComplianceRetentionPolicy,
  OpenPlatformComplianceVendor,
  RecordOpenPlatformComplianceIdentityVerificationInput,
  RecordOpenPlatformCompliancePrivacyRequestActionInput,
  RecordOpenPlatformComplianceRetentionExecutionInput,
  RecordOpenPlatformComplianceVendorAssessmentInput,
  TransitionOpenPlatformComplianceCrossBorderAssessmentInput,
  TransitionOpenPlatformComplianceDataAssetInput,
  TransitionOpenPlatformCompliancePrivacyRequestInput,
  TransitionOpenPlatformComplianceRetentionPolicyInput,
  TransitionOpenPlatformComplianceVendorInput,
  UpdateOpenPlatformComplianceDataAssetInput,
  WithdrawOpenPlatformComplianceConsentInput,
} from "./compliance.js";
import type {
  OpenPlatformDomainEventListQuery,
  OpenPlatformDomainEventPage,
  OpenPlatformDomainEventRetryResultSummary,
  OpenPlatformDomainEventSummary,
  RetryOpenPlatformDomainEventInput,
} from "./domain-events.js";
import type {
  CreateOpenPlatformApiProductInput,
  CreateOpenPlatformApiVersionInput,
  CreateOpenPlatformApplicationInput,
  CreateOpenPlatformEnvironmentInput,
  CreateOpenPlatformMarketplaceListingInput,
  CreateOpenPlatformSubscriptionInput,
  CreateOpenPlatformWebhookInput,
  IssueOpenPlatformCredentialInput,
  OpenPlatformApiProduct,
  OpenPlatformApiProductListQuery,
  OpenPlatformApiVersion,
  OpenPlatformApplication,
  OpenPlatformAuditEvent,
  OpenPlatformAuditEventListQuery,
  OpenPlatformApplicationEnvironment,
  OpenPlatformApplicationListQuery,
  OpenPlatformBillingAccount,
  OpenPlatformBillingAccountListQuery,
  OpenPlatformCallOptions,
  OpenPlatformClientOptions,
  OpenPlatformCommissionRule,
  OpenPlatformCommissionRuleListQuery,
  OpenPlatformCredential,
  OpenPlatformCredentialIssueResult,
  OpenPlatformCredentialListQuery,
  OpenPlatformCredentialRotationResult,
  OpenPlatformFetch,
  OpenPlatformFetchInit,
  OpenPlatformHttpMethod,
  OpenPlatformInvoice,
  OpenPlatformInvoiceDispute,
  OpenPlatformInvoiceDisputeActionInput,
  OpenPlatformInvoiceDisputeDecisionInput,
  OpenPlatformInvoiceDisputeDecisionResult,
  OpenPlatformInvoiceDisputeInput,
  OpenPlatformInvoiceDisputeListQuery,
  OpenPlatformInvoiceDisputeOutcome,
  OpenPlatformInvoiceDisputeResult,
  OpenPlatformInvoiceDisputeStatus,
  OpenPlatformInvoiceDisputeView,
  OpenPlatformInvoiceListQuery,
  OpenPlatformListQuery,
  OpenPlatformMarketplaceListing,
  OpenPlatformMarketplaceListingListQuery,
  OpenPlatformPage,
  OpenPlatformPartnerAccount,
  OpenPlatformPartnerAccountListQuery,
  OpenPlatformQuery,
  OpenPlatformRequestCache,
  OpenPlatformRequestOptions,
  OpenPlatformResourceBase,
  OpenPlatformRetryOptions,
  OpenPlatformSubscription,
  OpenPlatformSubscriptionListQuery,
  OpenPlatformToken,
  OpenPlatformTokenSource,
  OpenPlatformUsage,
  OpenPlatformUsageListQuery,
  OpenPlatformWebhook,
  OpenPlatformWebhookDelivery,
  OpenPlatformWebhookDeliveryListQuery,
  OpenPlatformWebhookDispatchResult,
  OpenPlatformWebhookListQuery,
  OpenPlatformWebhookSecretResult,
  RecordOpenPlatformUsageInput,
} from "./types.js";
import {
  OPEN_PLATFORM_IDEMPOTENCY_HEADER,
  OPEN_PLATFORM_REQUEST_HEADER,
  OPEN_PLATFORM_SDK_API_PATH,
  OPEN_PLATFORM_TENANT_HEADER,
} from "./types.js";

const DEFAULT_TIMEOUT_MS = 15_000;
const MAX_TIMEOUT_MS = 120_000;
const DEFAULT_MAX_RETRIES = 2;
const DEFAULT_BASE_DELAY_MS = 100;
const DEFAULT_MAX_DELAY_MS = 2_000;
const RETRYABLE_STATUSES = new Set([408, 425, 429, 500, 502, 503, 504]);
const SAFE_METHODS = new Set<OpenPlatformHttpMethod>(["GET", "HEAD", "OPTIONS"]);
const INVALID_RESPONSE = Symbol("open-platform-invalid-response");
const CALL_OPTION_KEYS = new Set([
  "headers",
  "signal",
  "timeoutMs",
  "tenantId",
  "requestId",
  "idempotencyKey",
  "retry",
  "authenticated",
  "sensitive",
  "unwrapData",
]);

interface NormalizedRetryOptions {
  readonly maxRetries: number;
  readonly baseDelayMs: number;
  readonly maxDelayMs: number;
  readonly jitter: boolean | number;
  readonly retryableStatuses: ReadonlySet<number>;
  readonly shouldRetry?: (context: {
    attempt: number;
    method: OpenPlatformHttpMethod;
    status?: number;
    error?: OpenPlatformErrorLike;
  }) => boolean;
}

interface OpenPlatformErrorLike {
  readonly code: string;
  readonly status: number;
  readonly statusCode?: number;
  readonly retryable: boolean;
  readonly retryAfterMs?: number;
}

interface RequestContext {
  readonly method: OpenPlatformHttpMethod;
  readonly requestId: string;
  readonly tenantId?: string;
  readonly idempotencyKey?: string;
  readonly signal?: AbortSignal;
  readonly timeoutMs?: number;
  readonly sensitive: boolean;
  readonly retry: NormalizedRetryOptions;
  readonly unwrapData: boolean;
  readonly sensitiveValues: readonly string[];
}

interface SplitListOptions {
  readonly query: Record<string, unknown>;
  readonly options: OpenPlatformCallOptions;
}

interface ResolvedToken {
  readonly value: string;
  readonly type: string;
}

export class OpenPlatformClient {
  readonly baseUrl: string;
  readonly apiPath: string;
  readonly applications: OpenPlatformApplicationsResource;
  readonly apiProducts: OpenPlatformApiProductsResource;
  readonly products: OpenPlatformApiProductsResource;
  readonly credentials: OpenPlatformCredentialsResource;
  readonly usage: OpenPlatformUsageResource;
  readonly subscriptions: OpenPlatformSubscriptionsResource;
  readonly webhooks: OpenPlatformWebhooksResource;
  readonly webhook: OpenPlatformWebhooksResource;
  readonly auditEvents: OpenPlatformAuditEventsResource;
  readonly audit: OpenPlatformAuditEventsResource;
  readonly marketplace: OpenPlatformMarketplaceResource;
  readonly marketplaceListings: OpenPlatformMarketplaceResource;
  readonly listings: OpenPlatformMarketplaceListingsResource;
  readonly partners: OpenPlatformPartnersResource;
  readonly commissionRules: OpenPlatformCommissionRulesResource;
  readonly billing: OpenPlatformBillingResource;
  readonly billingAccounts: OpenPlatformBillingAccountsResource;
  readonly invoices: OpenPlatformInvoicesResource;
  readonly compliance: OpenPlatformComplianceResource;
  readonly complianceCatalog: OpenPlatformComplianceResource;
  readonly domainEvents: OpenPlatformDomainEventsResource;
  readonly events: OpenPlatformDomainEventsResource;

  private readonly tenantId: string | undefined;
  private readonly tokenSource: OpenPlatformTokenSource | undefined;
  private readonly tokenRefreshSource: OpenPlatformTokenSource | undefined;
  private readonly fetchImpl: OpenPlatformFetch;
  private readonly defaultHeaders: Headers;
  private readonly requestIdFactory: () => string;
  private readonly retrySetting: boolean | OpenPlatformRetryOptions | number | undefined;
  private readonly retryOptions: NormalizedRetryOptions;
  private readonly retryOnUnauthorized: boolean;
  private readonly defaultTimeoutMs: number | undefined;
  private readonly allowInsecureHttp: boolean;
  private readonly basePath: string;

  constructor(options: OpenPlatformClientOptions) {
    if (options === null || typeof options !== "object") throw new OpenPlatformConfigurationError();
    const baseUrl = options.baseUrl ?? options.baseURL;
    if (baseUrl === undefined) throw new OpenPlatformConfigurationError();
    this.allowInsecureHttp = options.allowInsecureHttp === true;
    const resolvedBase = resolveOpenPlatformBaseUrl(baseUrl, options.apiPath, this.allowInsecureHttp);
    this.baseUrl = resolvedBase.baseUrl;
    this.apiPath = resolvedBase.apiPath;
    this.basePath = new URL(this.baseUrl).pathname.replace(/\/$/u, "");
    this.tenantId = options.tenantId === undefined ? undefined : safeIdentifier(options.tenantId, "tenantId");
    this.tokenSource = options.tokenProvider ?? options.accessTokenProvider ?? options.getToken ?? options.getAccessToken ?? options.accessToken;
    this.tokenRefreshSource = options.refreshTokenProvider ?? options.refreshAccessToken ?? options.tokenRefresher;
    const selectedFetch = options.fetch ?? options.fetcher ?? globalThis.fetch;
    if (typeof selectedFetch !== "function") throw new OpenPlatformConfigurationError();
    this.fetchImpl = selectedFetch.bind(globalThis);
    try {
      this.defaultHeaders = new Headers(options.defaultHeaders ?? options.headers);
    } catch {
      throw new OpenPlatformConfigurationError();
    }
    this.requestIdFactory = options.requestIdFactory ?? (() => randomUUID());
    if (typeof this.requestIdFactory !== "function") throw new OpenPlatformConfigurationError();
    this.defaultTimeoutMs = normalizeTimeout(options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
    this.retrySetting = options.retry;
    this.retryOptions = normalizeRetryOptions(options.retry);
    this.retryOnUnauthorized = options.retryOnUnauthorized === true || options.refreshOnUnauthorized === true;
    this.applications = new OpenPlatformApplicationsResource(this);
    this.apiProducts = new OpenPlatformApiProductsResource(this);
    this.products = this.apiProducts;
    this.credentials = new OpenPlatformCredentialsResource(this);
    this.usage = new OpenPlatformUsageResource(this);
    this.subscriptions = new OpenPlatformSubscriptionsResource(this);
    this.webhooks = new OpenPlatformWebhooksResource(this);
    this.webhook = this.webhooks;
    this.auditEvents = new OpenPlatformAuditEventsResource(this);
    this.audit = this.auditEvents;
    this.marketplace = new OpenPlatformMarketplaceResource(this);
    this.marketplaceListings = this.marketplace;
    this.listings = this.marketplace.listings;
    this.partners = new OpenPlatformPartnersResource(this);
    this.commissionRules = new OpenPlatformCommissionRulesResource(this);
    this.billing = new OpenPlatformBillingResource(this);
    this.billingAccounts = this.billing.accounts;
    this.invoices = this.billing.invoices;
    this.compliance = new OpenPlatformComplianceResource(this);
    this.complianceCatalog = this.compliance;
    this.domainEvents = new OpenPlatformDomainEventsResource(this);
    this.events = this.domainEvents;
  }

  path(...segments: string[]): string {
    if (segments.length === 0) return "/";
    return `/${segments.map((segment) => encodeURIComponent(safeIdentifier(segment, "path"))).join("/")}`;
  }

  async request<T>(path: string, options: OpenPlatformRequestOptions = {}): Promise<T> {
    if (options === null || typeof options !== "object") throw new OpenPlatformRequestError();
    const method = normalizeMethod(options.method);
    const body = options.body !== undefined ? options.body : options.data;
    if (body !== undefined) assertNoPlaintextBody(body);
    const tenantId = options.tenantId === undefined
      ? this.tenantId
      : safeIdentifier(options.tenantId, "tenantId");
    const requestId = options.requestId === undefined
      ? this.resolveRequestId(this.defaultHeaders.get(OPEN_PLATFORM_REQUEST_HEADER))
      : safeIdentifier(options.requestId, "requestId");
    const idempotencyKey = options.idempotencyKey === undefined
      ? undefined
      : assertIdempotencyKey(options.idempotencyKey);
    const url = this.resolveUrl(path, options.query);
    const sensitive = options.sensitive === true || isSensitivePath(path);
    const serializedBody = body === undefined ? undefined : serializeBody(body);
    const makeInit = (resolvedToken: ResolvedToken | undefined): OpenPlatformFetchInit => {
      const headers = this.createHeaders(
        options.headers,
        resolvedToken,
        tenantId,
        requestId,
        idempotencyKey,
        body !== undefined,
        options.authenticated !== false,
      );
      if (sensitive) headers["cache-control"] = "no-store";
      const cache: OpenPlatformRequestCache = sensitive ? "no-store" : options.cache ?? "default";
      return {
        method,
        headers,
        cache,
        credentials: "omit",
        redirect: "error",
        ...(serializedBody === undefined ? {} : { body: serializedBody }),
      };
    };
    if (options.signal?.aborted) throw new OpenPlatformAbortError();
    const token = options.authenticated === false ? undefined : await resolveToken(this.tokenSource);
    if (options.signal?.aborted) throw new OpenPlatformAbortError();
    let init = makeInit(token);
    const context: RequestContext = {
      method,
      requestId,
      tenantId,
      idempotencyKey,
      signal: options.signal,
      timeoutMs: normalizeTimeout(options.timeoutMs ?? this.defaultTimeoutMs),
      sensitive,
      retry: normalizeRetryOptions(options.retry === undefined ? this.retrySetting : options.retry),
      unwrapData: options.unwrapData !== false,
      sensitiveValues: authorizationSensitiveValues(init.headers),
    };
    try {
      const result = await this.execute(url, init, context);
      return this.normalizeResult<T>(path, context.unwrapData ? unwrapPayload(result) : result);
    } catch (error) {
      if (!this.shouldRefreshUnauthorized(error, options.authenticated)) throw error;
      if (options.signal?.aborted) throw new OpenPlatformAbortError();
      const refreshedToken = await resolveToken(this.tokenRefreshSource ?? this.tokenSource);
      if (options.signal?.aborted) throw new OpenPlatformAbortError();
      if (refreshedToken === undefined) throw error;
      init = makeInit(refreshedToken);
      const refreshedContext: RequestContext = {
        ...context,
        sensitiveValues: [
          ...context.sensitiveValues,
          ...authorizationSensitiveValues(init.headers),
        ],
      };
      const result = await this.execute(url, init, refreshedContext);
      return this.normalizeResult<T>(
        path,
        refreshedContext.unwrapData ? unwrapPayload(result) : result,
      );
    }
  }

  async listApplications(
    query: OpenPlatformApplicationListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformApplication>> {
    return this.applications.list(query, options);
  }

  async getApplication(
    applicationId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformApplication> {
    return this.applications.get(applicationId, options);
  }

  async createApplication(
    input: CreateOpenPlatformApplicationInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformApplication> {
    return this.applications.create(input, options);
  }

  async publishApplication(
    applicationId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformApplication> {
    return this.applications.publish(applicationId, options);
  }

  async enableApplication(
    applicationId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformApplication> {
    return this.applications.enable(applicationId, options);
  }

  async disableApplication(
    applicationId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformApplication> {
    return this.applications.disable(applicationId, options);
  }

  async archiveApplication(
    applicationId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformApplication> {
    return this.applications.archive(applicationId, options);
  }

  async listApplicationEnvironments(
    applicationId: string,
    query: OpenPlatformListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformApplicationEnvironment>> {
    return this.applications.listEnvironments(applicationId, query, options);
  }

  async createApplicationEnvironment(
    applicationId: string,
    input: CreateOpenPlatformEnvironmentInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformApplicationEnvironment> {
    return this.applications.createEnvironment(applicationId, input, options);
  }

  async getApplicationEnvironment(
    applicationId: string,
    environmentId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformApplicationEnvironment> {
    return this.applications.getEnvironment(applicationId, environmentId, options);
  }

  async listApiProducts(
    query: OpenPlatformApiProductListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformApiProduct>> {
    return this.apiProducts.list(query, options);
  }

  async getApiProduct(
    productId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformApiProduct> {
    return this.apiProducts.get(productId, options);
  }

  async createApiProduct(
    input: CreateOpenPlatformApiProductInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformApiProduct> {
    return this.apiProducts.create(input, options);
  }

  async publishApiProduct(
    productId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformApiProduct> {
    return this.apiProducts.publish(productId, options);
  }

  async disableApiProduct(
    productId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformApiProduct> {
    return this.apiProducts.disable(productId, options);
  }

  async archiveApiProduct(
    productId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformApiProduct> {
    return this.apiProducts.archive(productId, options);
  }

  async listApiVersions(
    productId: string,
    query: OpenPlatformListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformApiVersion>> {
    return this.apiProducts.listVersions(productId, query, options);
  }

  async listApiProductVersions(
    productId: string,
    query: OpenPlatformListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformApiVersion>> {
    return this.apiProducts.listVersions(productId, query, options);
  }

  async getApiVersion(
    productId: string,
    versionId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformApiVersion> {
    return this.apiProducts.getVersion(productId, versionId, options);
  }

  async createApiVersion(
    productId: string,
    input: CreateOpenPlatformApiVersionInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformApiVersion> {
    return this.apiProducts.createVersion(productId, input, options);
  }

  async publishApiVersion(
    productId: string,
    versionId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformApiVersion> {
    return this.apiProducts.publishVersion(productId, versionId, options);
  }

  async deprecateApiVersion(
    productId: string,
    versionId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformApiVersion> {
    return this.apiProducts.deprecateVersion(productId, versionId, options);
  }

  async disableApiVersion(
    productId: string,
    versionId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformApiVersion> {
    return this.apiProducts.disableVersion(productId, versionId, options);
  }

  async archiveApiVersion(
    productId: string,
    versionId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformApiVersion> {
    return this.apiProducts.archiveVersion(productId, versionId, options);
  }

  async listCredentials(
    query: OpenPlatformCredentialListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformCredential>> {
    return this.credentials.list(query, options);
  }

  async getCredential(
    credentialId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformCredential> {
    return this.credentials.get(credentialId, options);
  }

  async issueCredential(
    input: IssueOpenPlatformCredentialInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformCredentialIssueResult> {
    return this.credentials.issue(input, options);
  }

  async createCredential(
    input: IssueOpenPlatformCredentialInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformCredentialIssueResult> {
    return this.credentials.issue(input, options);
  }

  async rotateCredential(
    credentialId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformCredentialRotationResult> {
    return this.credentials.rotate(credentialId, options);
  }

  async revokeCredential(
    credentialId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformCredential> {
    return this.credentials.revoke(credentialId, options);
  }

  async listUsage(
    query: OpenPlatformUsageListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformUsage>> {
    return this.usage.list(query, options);
  }

  async recordUsage(
    input: RecordOpenPlatformUsageInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformUsage> {
    return this.usage.record(input, options);
  }

  async createUsage(
    input: RecordOpenPlatformUsageInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformUsage> {
    return this.usage.record(input, options);
  }

  async listSubscriptions(
    query: OpenPlatformSubscriptionListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformSubscription>> {
    return this.subscriptions.list(query, options);
  }

  async getSubscription(
    subscriptionId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformSubscription> {
    return this.subscriptions.get(subscriptionId, options);
  }

  async createSubscription(
    input: CreateOpenPlatformSubscriptionInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformSubscription> {
    return this.subscriptions.create(input, options);
  }

  async publishSubscription(
    subscriptionId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformSubscription> {
    return this.subscriptions.publish(subscriptionId, options);
  }

  async disableSubscription(
    subscriptionId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformSubscription> {
    return this.subscriptions.disable(subscriptionId, options);
  }

  async archiveSubscription(
    subscriptionId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformSubscription> {
    return this.subscriptions.archive(subscriptionId, options);
  }

  async listWebhooks(
    query: OpenPlatformWebhookListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformWebhook>> {
    return this.webhooks.list(query, options);
  }

  async getWebhook(
    webhookId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformWebhook> {
    return this.webhooks.get(webhookId, options);
  }

  async createWebhook(
    input: CreateOpenPlatformWebhookInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformWebhookSecretResult> {
    return this.webhooks.create(input, options);
  }

  async pauseWebhook(
    webhookId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformWebhook> {
    return this.webhooks.pause(webhookId, options);
  }

  async disableWebhook(
    webhookId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformWebhook> {
    return this.webhooks.disable(webhookId, options);
  }

  async resumeWebhook(
    webhookId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformWebhook> {
    return this.webhooks.resume(webhookId, options);
  }

  async rotateWebhookSecret(
    webhookId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformWebhookSecretResult> {
    return this.webhooks.rotateSecret(webhookId, options);
  }

  async testWebhook(
    webhookId: string,
    input: Record<string, unknown>,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformWebhookDispatchResult> {
    return this.webhooks.test(webhookId, input, options);
  }

  async replayWebhookDelivery(
    webhookId: string,
    deliveryId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformWebhookDispatchResult> {
    return this.webhooks.replayDelivery(webhookId, deliveryId, options);
  }

  async listWebhookDeliveries(
    webhookId: string,
    query: OpenPlatformWebhookDeliveryListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformWebhookDelivery>> {
    return this.webhooks.listDeliveries(webhookId, query, options);
  }

  async listAuditEvents(
    query: OpenPlatformAuditEventListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformAuditEvent>> {
    return this.auditEvents.list(query, options);
  }

  async getAuditEvent(
    auditEventId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformAuditEvent> {
    return this.auditEvents.get(auditEventId, options);
  }

  async listMarketplaceListings(
    query: OpenPlatformMarketplaceListingListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformMarketplaceListing>> {
    return this.marketplace.list(query, options);
  }

  async listMarketplaceListing(
    query: OpenPlatformMarketplaceListingListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformMarketplaceListing>> {
    return this.marketplace.list(query, options);
  }

  async getMarketplaceListing(
    listingId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformMarketplaceListing> {
    return this.marketplace.get(listingId, options);
  }

  async createMarketplaceListing(
    input: CreateOpenPlatformMarketplaceListingInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformMarketplaceListing> {
    return this.marketplace.create(input, options);
  }

  async createListing(
    input: CreateOpenPlatformMarketplaceListingInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformMarketplaceListing> {
    return this.marketplace.create(input, options);
  }

  async submitMarketplaceListingReview(
    listingId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformMarketplaceListing> {
    return this.marketplace.submitReview(listingId, options);
  }

  async submitMarketplaceListing(
    listingId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformMarketplaceListing> {
    return this.marketplace.submitReview(listingId, options);
  }

  async submitListingReview(
    listingId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformMarketplaceListing> {
    return this.marketplace.submitReview(listingId, options);
  }

  async publishMarketplaceListing(
    listingId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformMarketplaceListing> {
    return this.marketplace.publish(listingId, options);
  }

  async publishListing(
    listingId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformMarketplaceListing> {
    return this.marketplace.publish(listingId, options);
  }

  async suspendMarketplaceListing(
    listingId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformMarketplaceListing> {
    return this.marketplace.suspend(listingId, options);
  }

  async suspendListing(
    listingId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformMarketplaceListing> {
    return this.marketplace.suspend(listingId, options);
  }

  async removeMarketplaceListing(
    listingId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformMarketplaceListing> {
    return this.marketplace.remove(listingId, options);
  }

  async removeListing(
    listingId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformMarketplaceListing> {
    return this.marketplace.remove(listingId, options);
  }

  async listPartners(
    query: OpenPlatformPartnerAccountListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformPartnerAccount>> {
    return this.partners.list(query, options);
  }

  async getPartner(
    partnerId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPartnerAccount> {
    return this.partners.get(partnerId, options);
  }

  async listPartnerAccounts(
    query: OpenPlatformPartnerAccountListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformPartnerAccount>> {
    return this.partners.list(query, options);
  }

  async getPartnerAccount(
    partnerId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPartnerAccount> {
    return this.partners.get(partnerId, options);
  }

  async listCommissionRules(
    query: OpenPlatformCommissionRuleListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformCommissionRule>> {
    return this.commissionRules.list(query, options);
  }

  async getCommissionRule(
    commissionRuleId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformCommissionRule> {
    return this.commissionRules.get(commissionRuleId, options);
  }

  async listBillingAccounts(
    query: OpenPlatformBillingAccountListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformBillingAccount>> {
    return this.billing.accounts.list(query, options);
  }

  async getBillingAccount(
    accountId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformBillingAccount> {
    return this.billing.accounts.get(accountId, options);
  }

  async listAccounts(
    query: OpenPlatformBillingAccountListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformBillingAccount>> {
    return this.billing.accounts.list(query, options);
  }

  async getAccount(
    accountId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformBillingAccount> {
    return this.billing.accounts.get(accountId, options);
  }

  async listInvoices(
    query: OpenPlatformInvoiceListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformInvoice>> {
    return this.billing.invoices.list(query, options);
  }

  async listBillingInvoices(
    query: OpenPlatformInvoiceListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformInvoice>> {
    return this.billing.invoices.list(query, options);
  }

  async getInvoice(
    invoiceId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformInvoice> {
    return this.billing.invoices.get(invoiceId, options);
  }

  async getBillingInvoice(
    invoiceId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformInvoice> {
    return this.billing.invoices.get(invoiceId, options);
  }

  async disputeInvoice(
    invoiceId: string,
    input: OpenPlatformInvoiceDisputeInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformInvoiceDisputeResult> {
    return this.billing.invoices.dispute(invoiceId, input, options);
  }

  async createInvoiceDispute(
    invoiceId: string,
    input: OpenPlatformInvoiceDisputeInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformInvoiceDisputeResult> {
    return this.billing.invoices.dispute(invoiceId, input, options);
  }

  async disputeBillingInvoice(
    invoiceId: string,
    input: OpenPlatformInvoiceDisputeInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformInvoiceDisputeResult> {
    return this.billing.invoices.dispute(invoiceId, input, options);
  }

  async listInvoiceDisputes(
    invoiceId: string,
    query: OpenPlatformInvoiceDisputeListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformInvoiceDispute>> {
    return this.billing.disputes.list(invoiceId, query, options);
  }

  async getInvoiceDispute(
    disputeId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformInvoiceDispute> {
    return this.billing.disputes.get(disputeId, options);
  }

  async startInvoiceDisputeReview(
    invoiceId: string,
    disputeId: string,
    input: OpenPlatformInvoiceDisputeActionInput = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformInvoiceDisputeDecisionResult> {
    return this.billing.disputes.startReview(invoiceId, disputeId, input, options);
  }

  async reviewInvoiceDispute(
    invoiceId: string,
    disputeId: string,
    input: OpenPlatformInvoiceDisputeActionInput = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformInvoiceDisputeDecisionResult> {
    return this.billing.disputes.startReview(invoiceId, disputeId, input, options);
  }

  async decideInvoiceDispute(
    invoiceId: string,
    disputeId: string,
    input: OpenPlatformInvoiceDisputeDecisionInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformInvoiceDisputeDecisionResult> {
    return this.billing.disputes.decide(invoiceId, disputeId, input, options);
  }

  async withdrawInvoiceDispute(
    invoiceId: string,
    disputeId: string,
    input: OpenPlatformInvoiceDisputeActionInput = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformInvoiceDisputeDecisionResult> {
    return this.billing.disputes.withdraw(invoiceId, disputeId, input, options);
  }

  async listDataAssets(
    query: OpenPlatformComplianceListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformComplianceDataAsset>> {
    return this.compliance.dataAssets.list(query, options);
  }

  async getDataAsset(
    dataAssetId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceDataAsset> {
    return this.compliance.dataAssets.get(dataAssetId, options);
  }

  async createDataAsset(
    input: CreateOpenPlatformComplianceDataAssetInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceDataAsset> {
    return this.compliance.dataAssets.create(input, options);
  }

  async updateDataAsset(
    dataAssetId: string,
    input: UpdateOpenPlatformComplianceDataAssetInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceDataAsset> {
    return this.compliance.dataAssets.update(dataAssetId, input, options);
  }

  async transitionDataAssetStatus(
    dataAssetId: string,
    input: TransitionOpenPlatformComplianceDataAssetInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceDataAsset> {
    return this.compliance.dataAssets.transitionStatus(dataAssetId, input, options);
  }

  async listConsents(
    query: OpenPlatformComplianceListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformComplianceConsentRecord>> {
    return this.compliance.consents.list(query, options);
  }

  async getConsentRecord(
    consentId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceConsentRecord> {
    return this.compliance.consents.get(consentId, options);
  }

  async listPrivacyRequests(
    query: OpenPlatformComplianceListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformCompliancePrivacyRequest>> {
    return this.compliance.privacyRequests.list(query, options);
  }

  async getPrivacyRequest(
    privacyRequestId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformCompliancePrivacyRequest> {
    return this.compliance.privacyRequests.get(privacyRequestId, options);
  }

  async getPrivacyRequestSla(
    privacyRequestId: string,
    query: { readonly at?: string } & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformCompliancePrivacyRequestSla> {
    return this.compliance.privacyRequests.getSla(privacyRequestId, query, options);
  }

  async listRetentionPolicies(
    query: OpenPlatformComplianceListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformComplianceRetentionPolicy>> {
    return this.compliance.retentionPolicies.list(query, options);
  }

  async getRetentionPolicy(
    retentionPolicyId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceRetentionPolicy> {
    return this.compliance.retentionPolicies.get(retentionPolicyId, options);
  }

  async listRetentionExecutions(
    query: OpenPlatformComplianceListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformComplianceRetentionExecution>> {
    return this.compliance.retentionExecutions.list(query, options);
  }

  async recordRetentionExecution(
    input: RecordOpenPlatformComplianceRetentionExecutionInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceRetentionExecution> {
    return this.compliance.retentionExecutions.record(input, options);
  }

  async listCrossBorderAssessments(
    query: OpenPlatformComplianceListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformComplianceCrossBorderAssessment>> {
    return this.compliance.crossBorderAssessments.list(query, options);
  }

  async getCrossBorderAssessment(
    crossBorderAssessmentId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceCrossBorderAssessment> {
    return this.compliance.crossBorderAssessments.get(crossBorderAssessmentId, options);
  }

  async listVendors(
    query: OpenPlatformComplianceListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformComplianceVendor>> {
    return this.compliance.vendors.list(query, options);
  }

  async getVendor(
    vendorId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceVendor> {
    return this.compliance.vendors.get(vendorId, options);
  }

  async getComplianceReport(
    query: OpenPlatformComplianceReportQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceReportView> {
    return this.compliance.report.get(query, options);
  }

  async generateComplianceReport(
    input: GenerateOpenPlatformComplianceReportInput = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceReportView> {
    return this.compliance.report.generate(input, options);
  }

  async listDomainEvents(
    query: OpenPlatformDomainEventListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformDomainEventPage> {
    return this.domainEvents.list(query, options);
  }

  async listDomainEventsAll(
    query: OpenPlatformDomainEventListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions & { maxPages?: number },
  ): Promise<OpenPlatformDomainEventPage["items"]> {
    return this.domainEvents.listAll(query, options);
  }

  async retryDomainEvents(
    input: RetryOpenPlatformDomainEventInput = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformDomainEventRetryResultSummary> {
    return this.domainEvents.retry(input, options);
  }

  private normalizeResult<T>(path: string, value: unknown): T {
    if (isCompliancePath(path)) return redactOpenPlatformComplianceSubjects(value) as T;
    return value as T;
  }

  private resolveUrl(path: string, query: OpenPlatformQuery | undefined): URL {
    if (typeof path !== "string" || path.length === 0 || /[?#\u0000-\u001f\u007f\s]/u.test(path)) {
      throw new OpenPlatformRequestError();
    }
    const base = new URL(`${this.baseUrl}/`);
    const relative = path.replace(/^\/+/u, "");
    let url: URL;
    try {
      url = new URL(relative, base);
    } catch {
      throw new OpenPlatformRequestError();
    }
    if (url.origin !== base.origin || !isWithinBasePath(url.pathname, this.basePath)) {
      throw new OpenPlatformRequestError();
    }
    if (query !== undefined) appendQuery(url, query);
    return url;
  }

  private createHeaders(
    supplied: HeadersInit | undefined,
    token: ResolvedToken | undefined,
    tenantId: string | undefined,
    requestId: string,
    idempotencyKey: string | undefined,
    hasBody: boolean,
    authenticated: boolean,
  ): Record<string, string> {
    const headers = new Headers(this.defaultHeaders);
    if (supplied !== undefined) {
      try {
        const suppliedHeaders = new Headers(supplied);
        suppliedHeaders.forEach((value, key) => headers.set(key, value));
      } catch {
        throw new OpenPlatformRequestError();
      }
    }
    if (token !== undefined) headers.set("authorization", formatAuthorization(token));
    if (!authenticated || (token === undefined && this.tokenSource !== undefined)) headers.delete("authorization");
    if (tenantId !== undefined) headers.set(OPEN_PLATFORM_TENANT_HEADER, tenantId);
    headers.set(OPEN_PLATFORM_REQUEST_HEADER, requestId);
    if (idempotencyKey !== undefined) headers.set(OPEN_PLATFORM_IDEMPOTENCY_HEADER, idempotencyKey);
    if (!headers.has("accept")) headers.set("accept", "application/json");
    if (hasBody && !headers.has("content-type")) headers.set("content-type", "application/json");
    const output: Record<string, string> = {};
    headers.forEach((value, key) => {
      output[key] = value;
    });
    return output;
  }

  private resolveRequestId(value: string | null): string {
    if (value === null) return safeIdentifier(this.requestIdFactory(), "requestId");
    return safeIdentifier(value, "requestId");
  }

  private shouldRefreshUnauthorized(error: unknown, authenticated: boolean | undefined): boolean {
    const refreshSource = this.tokenRefreshSource ?? this.tokenSource;
    return authenticated !== false &&
      this.retryOnUnauthorized &&
      error instanceof OpenPlatformApiError &&
      error.status === 401 &&
      refreshSource !== undefined;
  }

  private async execute<T>(url: URL, init: OpenPlatformFetchInit, context: RequestContext): Promise<T> {
    let attempt = 0;
    while (true) {
      attempt += 1;
      let response: Response;
      try {
        response = await this.fetchWithTimeout(url, init, context.timeoutMs, context.signal);
      } catch (error) {
        const normalized = normalizeTransportError(error);
        if (this.shouldRetry(context, attempt, normalized)) {
          await waitForRetry(this.retryDelay(attempt, normalized.retryAfterMs, context.retry), context.signal);
          continue;
        }
        throw normalized;
      }
      let body: unknown;
      try {
        body = await readResponseBody(response);
      } catch (error) {
        if (error instanceof OpenPlatformProtocolError) {
          body = INVALID_RESPONSE;
        } else {
          const normalized = new OpenPlatformNetworkError();
          if (this.shouldRetry(context, attempt, normalized)) {
            await waitForRetry(this.retryDelay(attempt, undefined, context.retry), context.signal);
            continue;
          }
          throw normalized;
        }
      }
      const ok = response.status >= 200 && response.status < 300;
      if (!ok) {
        const parsed = parseOpenPlatformErrorResponse(
          body,
          response.status,
          response.headers,
          undefined,
          context.sensitiveValues,
        );
        if (this.shouldRetry(context, attempt, parsed, response.status)) {
          await waitForRetry(this.retryDelay(attempt, parsed.retryAfterMs, context.retry), context.signal);
          continue;
        }
        throw parsed;
      }
      if (body === INVALID_RESPONSE) throw new OpenPlatformProtocolError();
      return body as T;
    }
  }

  private async fetchWithTimeout(
    url: URL,
    init: OpenPlatformFetchInit,
    timeoutMs: number | undefined,
    externalSignal: AbortSignal | undefined,
  ): Promise<Response> {
    if (externalSignal?.aborted) throw new OpenPlatformAbortError();
    const controller = new AbortController();
    let timedOut = false;
    let externallyAborted = false;
    let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
    let abortHandler: (() => void) | undefined;
    const abortPromise = new Promise<never>((_, reject) => {
      abortHandler = () => {
        externallyAborted = true;
        controller.abort();
        reject(new OpenPlatformAbortError());
      };
      if (externalSignal !== undefined) {
        externalSignal.addEventListener("abort", abortHandler, { once: true });
        if (externalSignal.aborted) abortHandler();
      }
    });
    const timeoutPromise = timeoutMs === undefined
      ? undefined
      : new Promise<never>((_, reject) => {
        timeoutHandle = setTimeout(() => {
          timedOut = true;
          controller.abort();
          reject(new OpenPlatformTimeoutError());
        }, timeoutMs);
      });
    const fetchPromise = Promise.resolve().then(() => this.fetchImpl(url.toString(), {
      ...init,
      signal: controller.signal,
    }));
    try {
      const races: Promise<Response>[] = [fetchPromise, abortPromise];
      if (timeoutPromise !== undefined) races.push(timeoutPromise);
      return await Promise.race(races);
    } catch (error) {
      if (timedOut) throw new OpenPlatformTimeoutError();
      if (externallyAborted || externalSignal?.aborted || isAbortError(error)) {
        throw new OpenPlatformAbortError();
      }
      throw error;
    } finally {
      if (timeoutHandle !== undefined) clearTimeout(timeoutHandle);
      if (abortHandler !== undefined && externalSignal !== undefined) {
        externalSignal.removeEventListener("abort", abortHandler);
      }
    }
  }

  private shouldRetry(
    context: RequestContext,
    attempt: number,
    error: OpenPlatformErrorLike,
    status?: number,
  ): boolean {
    if (attempt > context.retry.maxRetries) return false;
    if (status === 401) return false;
    if (!SAFE_METHODS.has(context.method) && context.idempotencyKey === undefined) return false;
    if (context.retry.shouldRetry !== undefined) {
      try {
        return context.retry.shouldRetry({
          attempt,
          method: context.method,
          ...(status === undefined ? {} : { status }),
          error,
        });
      } catch {
        return false;
      }
    }
    if (status !== undefined) return context.retry.retryableStatuses.has(status);
    return error.retryable;
  }

  private retryDelay(
    attempt: number,
    retryAfterMs?: number,
    retry: NormalizedRetryOptions = this.retryOptions,
  ): number {
    if (retryAfterMs !== undefined) return Math.min(retryAfterMs, retry.maxDelayMs);
    const base = Math.min(
      retry.maxDelayMs,
      retry.baseDelayMs * (2 ** Math.max(attempt - 1, 0)),
    );
    if (retry.jitter === false) return base;
    const ratio = typeof retry.jitter === "number" ? retry.jitter : 0.2;
    const bounded = Math.max(0, Math.min(1, ratio));
    return Math.min(retry.maxDelayMs, Math.floor(base * (1 - bounded + Math.random() * bounded * 2)));
  }
}

export class OpenPlatformApplicationsResource {
  constructor(readonly client: OpenPlatformClient) {}

  async list(
    query: OpenPlatformApplicationListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformApplication>> {
    const split = splitListOptions(query, options);
    return requestPage(this.client, "/applications", split.query, split.options);
  }

  async listAll(
    query: OpenPlatformApplicationListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions & { maxPages?: number },
  ): Promise<OpenPlatformApplication[]> {
    return listAll(this, query, options);
  }

  async get(applicationId: string, options?: OpenPlatformCallOptions): Promise<OpenPlatformApplication> {
    return this.client.request(this.client.path("applications", applicationId), {
      ...options,
      method: "GET",
    });
  }

  async create(
    input: CreateOpenPlatformApplicationInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformApplication> {
    const mutation = mutationInput(input, options, "application-create");
    return this.client.request("/applications", {
      ...mutation.options,
      method: "POST",
      body: mutation.body,
    });
  }

  async publish(applicationId: string, options?: OpenPlatformCallOptions): Promise<OpenPlatformApplication> {
    return lifecycle(this.client, "applications", applicationId, "publish", options);
  }

  async enable(applicationId: string, options?: OpenPlatformCallOptions): Promise<OpenPlatformApplication> {
    return this.publish(applicationId, options);
  }

  async disable(applicationId: string, options?: OpenPlatformCallOptions): Promise<OpenPlatformApplication> {
    return lifecycle(this.client, "applications", applicationId, "disable", options);
  }

  async archive(applicationId: string, options?: OpenPlatformCallOptions): Promise<OpenPlatformApplication> {
    return lifecycle(this.client, "applications", applicationId, "archive", options);
  }

  async listEnvironments(
    applicationId: string,
    query: OpenPlatformListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformApplicationEnvironment>> {
    const split = splitListOptions(query, options);
    return requestPage(
      this.client,
      `/applications/${encodeURIComponent(safeIdentifier(applicationId, "applicationId"))}/environments`,
      split.query,
      split.options,
    );
  }

  async createEnvironment(
    applicationId: string,
    input: CreateOpenPlatformEnvironmentInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformApplicationEnvironment> {
    const mutation = mutationInput(input, options, "environment-create");
    return this.client.request(
      `/applications/${encodeURIComponent(safeIdentifier(applicationId, "applicationId"))}/environments`,
      {
        ...mutation.options,
        method: "POST",
        body: mutation.body,
      },
    );
  }

  async getEnvironment(
    applicationId: string,
    environmentId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformApplicationEnvironment> {
    return this.client.request(
      `/applications/${encodeURIComponent(safeIdentifier(applicationId, "applicationId"))}/environments/${encodeURIComponent(safeIdentifier(environmentId, "environmentId"))}`,
      { ...options, method: "GET" },
    );
  }

  async publishEnvironment(
    applicationId: string,
    environmentId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformApplicationEnvironment> {
    return environmentLifecycle(this.client, applicationId, environmentId, "publish", options);
  }

  async releaseEnvironment(
    applicationId: string,
    environmentId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformApplicationEnvironment> {
    return this.publishEnvironment(applicationId, environmentId, options);
  }

  async disableEnvironment(
    applicationId: string,
    environmentId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformApplicationEnvironment> {
    return environmentLifecycle(this.client, applicationId, environmentId, "disable", options);
  }

  async archiveEnvironment(
    applicationId: string,
    environmentId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformApplicationEnvironment> {
    return environmentLifecycle(this.client, applicationId, environmentId, "archive", options);
  }
}

export class OpenPlatformApiProductsResource {
  constructor(readonly client: OpenPlatformClient) {}

  async list(
    query: OpenPlatformApiProductListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformApiProduct>> {
    const split = splitListOptions(query, options);
    return requestPage(this.client, "/catalog/products", split.query, split.options);
  }

  async listAll(
    query: OpenPlatformApiProductListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions & { maxPages?: number },
  ): Promise<OpenPlatformApiProduct[]> {
    return listAll(this, query, options);
  }

  async get(productId: string, options?: OpenPlatformCallOptions): Promise<OpenPlatformApiProduct> {
    return this.client.request(`/catalog/products/${encodeURIComponent(safeIdentifier(productId, "productId"))}`, {
      ...options,
      method: "GET",
    });
  }

  async create(
    input: CreateOpenPlatformApiProductInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformApiProduct> {
    const mutation = mutationInput(input, options, "product-create");
    return this.client.request("/catalog/products", {
      ...mutation.options,
      method: "POST",
      body: mutation.body,
    });
  }

  async publish(productId: string, options?: OpenPlatformCallOptions): Promise<OpenPlatformApiProduct> {
    return lifecycle(this.client, "catalog/products", productId, "publish", options);
  }

  async disable(productId: string, options?: OpenPlatformCallOptions): Promise<OpenPlatformApiProduct> {
    return lifecycle(this.client, "catalog/products", productId, "disable", options);
  }

  async archive(productId: string, options?: OpenPlatformCallOptions): Promise<OpenPlatformApiProduct> {
    return lifecycle(this.client, "catalog/products", productId, "archive", options);
  }

  async listVersions(
    productId: string,
    query: OpenPlatformListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformApiVersion>> {
    const split = splitListOptions(query, options);
    return requestPage(
      this.client,
      `/catalog/products/${encodeURIComponent(safeIdentifier(productId, "productId"))}/versions`,
      split.query,
      split.options,
    );
  }

  async createVersion(
    productId: string,
    input: CreateOpenPlatformApiVersionInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformApiVersion> {
    const mutation = mutationInput(input, options, "version-create");
    return this.client.request(
      `/catalog/products/${encodeURIComponent(safeIdentifier(productId, "productId"))}/versions`,
      {
        ...mutation.options,
        method: "POST",
        body: mutation.body,
      },
    );
  }

  async getVersion(
    productId: string,
    versionId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformApiVersion> {
    return this.client.request(
      `/catalog/products/${encodeURIComponent(safeIdentifier(productId, "productId"))}/versions/${encodeURIComponent(safeIdentifier(versionId, "versionId"))}`,
      { ...options, method: "GET" },
    );
  }

  async publishVersion(
    productId: string,
    versionId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformApiVersion> {
    return versionLifecycle(this.client, productId, versionId, "publish", options);
  }

  async deprecateVersion(
    productId: string,
    versionId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformApiVersion> {
    return versionLifecycle(this.client, productId, versionId, "disable", options);
  }

  async disableVersion(
    productId: string,
    versionId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformApiVersion> {
    return versionLifecycle(this.client, productId, versionId, "disable", options);
  }

  async archiveVersion(
    productId: string,
    versionId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformApiVersion> {
    return versionLifecycle(this.client, productId, versionId, "archive", options);
  }
}

export class OpenPlatformCredentialsResource {
  constructor(readonly client: OpenPlatformClient) {}

  async list(
    query: OpenPlatformCredentialListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformCredential>> {
    const split = splitListOptions(query, options);
    return requestPage(this.client, "/credentials", split.query, { ...split.options, sensitive: true });
  }

  async listAll(
    query: OpenPlatformCredentialListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions & { maxPages?: number },
  ): Promise<OpenPlatformCredential[]> {
    return listAll(this, query, options);
  }

  async get(credentialId: string, options?: OpenPlatformCallOptions): Promise<OpenPlatformCredential> {
    return this.client.request(
      `/credentials/${encodeURIComponent(safeIdentifier(credentialId, "credentialId"))}`,
      { ...options, method: "GET", sensitive: true },
    );
  }

  async issue(
    input: IssueOpenPlatformCredentialInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformCredentialIssueResult> {
    const mutation = mutationInput(input, options, "credential-issue");
    return this.client.request("/credentials", {
      ...mutation.options,
      method: "POST",
      sensitive: true,
      body: mutation.body,
    });
  }

  async create(
    input: IssueOpenPlatformCredentialInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformCredentialIssueResult> {
    return this.issue(input, options);
  }

  async rotate(
    credentialId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformCredentialRotationResult> {
    return this.client.request(
      `/credentials/${encodeURIComponent(safeIdentifier(credentialId, "credentialId"))}/rotate`,
      {
        ...options,
        method: "POST",
        sensitive: true,
        body: {},
        idempotencyKey: options?.idempotencyKey ?? generateIdempotencyKey("credential-rotate"),
      },
    );
  }

  async revoke(
    credentialId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformCredential> {
    return this.client.request(
      `/credentials/${encodeURIComponent(safeIdentifier(credentialId, "credentialId"))}/revoke`,
      {
        ...options,
        method: "POST",
        sensitive: true,
        body: {},
        idempotencyKey: options?.idempotencyKey ?? generateIdempotencyKey("credential-revoke"),
      },
    );
  }
}

export class OpenPlatformUsageResource {
  constructor(readonly client: OpenPlatformClient) {}

  async list(
    query: OpenPlatformUsageListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformUsage>> {
    const split = splitListOptions(query, options);
    return requestPage(this.client, "/usage", split.query, split.options);
  }

  async listAll(
    query: OpenPlatformUsageListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions & { maxPages?: number },
  ): Promise<OpenPlatformUsage[]> {
    return listAll(this, query, options);
  }

  async record(
    input: RecordOpenPlatformUsageInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformUsage> {
    const mutation = mutationInput(input, options, "usage-record");
    return this.client.request("/usage", {
      ...mutation.options,
      method: "POST",
      body: mutation.body,
    });
  }

  async create(
    input: RecordOpenPlatformUsageInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformUsage> {
    return this.record(input, options);
  }
}

export class OpenPlatformSubscriptionsResource {
  constructor(readonly client: OpenPlatformClient) {}

  async list(
    query: OpenPlatformSubscriptionListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformSubscription>> {
    const split = splitListOptions(query, options);
    return requestPage(this.client, "/subscriptions", split.query, split.options);
  }

  async listAll(
    query: OpenPlatformSubscriptionListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions & { maxPages?: number },
  ): Promise<OpenPlatformSubscription[]> {
    return listAll(this, query, options);
  }

  async get(subscriptionId: string, options?: OpenPlatformCallOptions): Promise<OpenPlatformSubscription> {
    return this.client.request(
      `/subscriptions/${encodeURIComponent(safeIdentifier(subscriptionId, "subscriptionId"))}`,
      { ...options, method: "GET" },
    );
  }

  async create(
    input: CreateOpenPlatformSubscriptionInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformSubscription> {
    const mutation = mutationInput(input, options, "subscription-create");
    return this.client.request("/subscriptions", {
      ...mutation.options,
      method: "POST",
      body: mutation.body,
    });
  }

  async publish(subscriptionId: string, options?: OpenPlatformCallOptions): Promise<OpenPlatformSubscription> {
    return lifecycle(this.client, "subscriptions", subscriptionId, "publish", options);
  }

  async disable(subscriptionId: string, options?: OpenPlatformCallOptions): Promise<OpenPlatformSubscription> {
    return lifecycle(this.client, "subscriptions", subscriptionId, "disable", options);
  }

  async archive(subscriptionId: string, options?: OpenPlatformCallOptions): Promise<OpenPlatformSubscription> {
    return lifecycle(this.client, "subscriptions", subscriptionId, "archive", options);
  }
}

export class OpenPlatformWebhooksResource {
  constructor(readonly client: OpenPlatformClient) {}

  async list(
    query: OpenPlatformWebhookListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformWebhook>> {
    const split = splitListOptions(query, options);
    return requestPage(this.client, "/webhooks", split.query, { ...split.options, sensitive: true });
  }

  async listAll(
    query: OpenPlatformWebhookListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions & { maxPages?: number },
  ): Promise<OpenPlatformWebhook[]> {
    return listAll(this as unknown as { list: (query?: OpenPlatformListQuery & OpenPlatformCallOptions, options?: OpenPlatformCallOptions) => Promise<OpenPlatformPage<OpenPlatformWebhook>> }, query as OpenPlatformListQuery & OpenPlatformCallOptions, options);
  }

  async get(webhookId: string, options?: OpenPlatformCallOptions): Promise<OpenPlatformWebhook> {
    return this.client.request(
      `/webhooks/${encodeURIComponent(safeIdentifier(webhookId, "webhookId"))}`,
      { ...options, method: "GET", sensitive: true },
    );
  }

  async create(
    input: CreateOpenPlatformWebhookInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformWebhookSecretResult> {
    const mutation = mutationInput(input, options, "webhook-create");
    return this.client.request("/webhooks", {
      ...mutation.options,
      method: "POST",
      sensitive: true,
      body: mutation.body,
    });
  }

  async pause(webhookId: string, options?: OpenPlatformCallOptions): Promise<OpenPlatformWebhook> {
    return this.lifecycle(webhookId, "pause", options);
  }

  async disable(webhookId: string, options?: OpenPlatformCallOptions): Promise<OpenPlatformWebhook> {
    return this.lifecycle(webhookId, "disable", options);
  }

  async resume(webhookId: string, options?: OpenPlatformCallOptions): Promise<OpenPlatformWebhook> {
    return this.lifecycle(webhookId, "resume", options);
  }

  async rotateSecret(
    webhookId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformWebhookSecretResult> {
    return this.client.request(
      `/webhooks/${encodeURIComponent(safeIdentifier(webhookId, "webhookId"))}/rotate-secret`,
      {
        ...options,
        method: "POST",
        sensitive: true,
        body: {},
        idempotencyKey: options?.idempotencyKey ?? generateIdempotencyKey("webhook-rotate-secret"),
      },
    );
  }

  async test(
    webhookId: string,
    input: Record<string, unknown>,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformWebhookDispatchResult> {
    const mutation = mutationInput(input, options, "webhook-test");
    return this.client.request(
      `/webhooks/${encodeURIComponent(safeIdentifier(webhookId, "webhookId"))}/test`,
      {
        ...mutation.options,
        method: "POST",
        sensitive: true,
        body: mutation.body,
        idempotencyKey: options?.idempotencyKey ?? generateIdempotencyKey("webhook-test"),
      },
    );
  }

  async replayDelivery(
    webhookId: string,
    deliveryId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformWebhookDispatchResult> {
    return this.client.request(
      `/webhooks/${encodeURIComponent(safeIdentifier(webhookId, "webhookId"))}/deliveries/${encodeURIComponent(safeIdentifier(deliveryId, "deliveryId"))}/replay`,
      {
        ...options,
        method: "POST",
        sensitive: true,
        body: {},
        idempotencyKey: options?.idempotencyKey ?? generateIdempotencyKey("webhook-replay"),
      },
    );
  }

  async listDeliveries(
    webhookId: string,
    query: OpenPlatformWebhookDeliveryListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformWebhookDelivery>> {
    const split = splitListOptions(query, options);
    return requestPage(
      this.client,
      `/webhooks/${encodeURIComponent(safeIdentifier(webhookId, "webhookId"))}/deliveries`,
      split.query,
      { ...split.options, sensitive: true },
    );
  }

  private async lifecycle(
    webhookId: string,
    action: "pause" | "disable" | "resume",
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformWebhook> {
    return this.client.request(
      `/webhooks/${encodeURIComponent(safeIdentifier(webhookId, "webhookId"))}/${action}`,
      {
        ...options,
        method: "POST",
        sensitive: true,
        body: {},
        idempotencyKey: options?.idempotencyKey ?? generateIdempotencyKey(`webhook-${action}`),
      },
    );
  }
}

export class OpenPlatformAuditEventsResource {
  constructor(readonly client: OpenPlatformClient) {}

  async list(
    query: OpenPlatformAuditEventListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformAuditEvent>> {
    const split = splitListOptions(query, options);
    return requestPage(this.client, "/audit-events", split.query, { ...split.options, sensitive: true });
  }

  async listAll(
    query: OpenPlatformAuditEventListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions & { maxPages?: number },
  ): Promise<OpenPlatformAuditEvent[]> {
    return listAll(this as unknown as { list: (query?: OpenPlatformListQuery & OpenPlatformCallOptions, options?: OpenPlatformCallOptions) => Promise<OpenPlatformPage<OpenPlatformAuditEvent>> }, query as OpenPlatformListQuery & OpenPlatformCallOptions, options);
  }

  async get(auditEventId: string, options?: OpenPlatformCallOptions): Promise<OpenPlatformAuditEvent> {
    return this.client.request(
      `/audit-events/${encodeURIComponent(safeIdentifier(auditEventId, "auditEventId"))}`,
      { ...options, method: "GET", sensitive: true },
    );
  }
}

export class OpenPlatformMarketplaceListingsResource {
  constructor(readonly client: OpenPlatformClient) {}

  async list(
    query: OpenPlatformMarketplaceListingListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformMarketplaceListing>> {
    const split = splitListOptions(query, options);
    return requestPage(
      this.client,
      "/marketplace/listings",
      split.query,
      { ...split.options, sensitive: true },
    );
  }

  async listAll(
    query: OpenPlatformMarketplaceListingListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions & { maxPages?: number },
  ): Promise<OpenPlatformMarketplaceListing[]> {
    return listAll(this, query, options);
  }

  async get(
    listingId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformMarketplaceListing> {
    return this.client.request(
      `/marketplace/listings/${encodeURIComponent(safeIdentifier(listingId, "listingId"))}`,
      { ...options, method: "GET", sensitive: true },
    );
  }

  async create(
    input: CreateOpenPlatformMarketplaceListingInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformMarketplaceListing> {
    const mutation = mutationInput(input, options, "marketplace-listing-create");
    return this.client.request("/marketplace/listings", {
      ...mutation.options,
      method: "POST",
      sensitive: true,
      body: mutation.body,
    });
  }

  async submitReview(
    listingId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformMarketplaceListing> {
    return this.transition(listingId, "submit-review", options);
  }

  async submit(
    listingId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformMarketplaceListing> {
    return this.submitReview(listingId, options);
  }

  async publish(
    listingId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformMarketplaceListing> {
    return this.transition(listingId, "publish", options);
  }

  async suspend(
    listingId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformMarketplaceListing> {
    return this.transition(listingId, "suspend", options);
  }

  async remove(
    listingId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformMarketplaceListing> {
    return this.transition(listingId, "remove", options);
  }

  private async transition(
    listingId: string,
    action: "submit-review" | "publish" | "suspend" | "remove",
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformMarketplaceListing> {
    return this.client.request(
      `/marketplace/listings/${encodeURIComponent(safeIdentifier(listingId, "listingId"))}/${action}`,
      {
        ...options,
        method: "POST",
        sensitive: true,
        body: {},
        idempotencyKey: options?.idempotencyKey ?? generateIdempotencyKey(`marketplace-${action}`),
      },
    );
  }
}

export class OpenPlatformMarketplaceResource {
  readonly listings: OpenPlatformMarketplaceListingsResource;

  constructor(readonly client: OpenPlatformClient) {
    this.listings = new OpenPlatformMarketplaceListingsResource(client);
  }

  list(
    query: OpenPlatformMarketplaceListingListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformMarketplaceListing>> {
    return this.listings.list(query, options);
  }

  listAll(
    query: OpenPlatformMarketplaceListingListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions & { maxPages?: number },
  ): Promise<OpenPlatformMarketplaceListing[]> {
    return this.listings.listAll(query, options);
  }

  get(listingId: string, options?: OpenPlatformCallOptions): Promise<OpenPlatformMarketplaceListing> {
    return this.listings.get(listingId, options);
  }

  create(
    input: CreateOpenPlatformMarketplaceListingInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformMarketplaceListing> {
    return this.listings.create(input, options);
  }

  submitReview(
    listingId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformMarketplaceListing> {
    return this.listings.submitReview(listingId, options);
  }

  submit(
    listingId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformMarketplaceListing> {
    return this.listings.submitReview(listingId, options);
  }

  publish(
    listingId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformMarketplaceListing> {
    return this.listings.publish(listingId, options);
  }

  suspend(
    listingId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformMarketplaceListing> {
    return this.listings.suspend(listingId, options);
  }

  remove(
    listingId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformMarketplaceListing> {
    return this.listings.remove(listingId, options);
  }
}

export class OpenPlatformPartnersResource {
  constructor(readonly client: OpenPlatformClient) {}

  async list(
    query: OpenPlatformPartnerAccountListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformPartnerAccount>> {
    const split = splitListOptions(query, options);
    return requestPage(
      this.client,
      "/partners",
      split.query,
      { ...split.options, sensitive: true },
    );
  }

  async listAll(
    query: OpenPlatformPartnerAccountListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions & { maxPages?: number },
  ): Promise<OpenPlatformPartnerAccount[]> {
    return listAll(this, query, options);
  }

  async get(
    partnerId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPartnerAccount> {
    return this.client.request(
      `/partners/${encodeURIComponent(safeIdentifier(partnerId, "partnerId"))}`,
      { ...options, method: "GET", sensitive: true },
    );
  }
}

export class OpenPlatformCommissionRulesResource {
  constructor(readonly client: OpenPlatformClient) {}

  async list(
    query: OpenPlatformCommissionRuleListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformCommissionRule>> {
    const split = splitListOptions(query, options);
    return requestPage(
      this.client,
      "/commission-rules",
      split.query,
      { ...split.options, sensitive: true },
    );
  }

  async listAll(
    query: OpenPlatformCommissionRuleListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions & { maxPages?: number },
  ): Promise<OpenPlatformCommissionRule[]> {
    return listAll(this, query, options);
  }

  async get(
    commissionRuleId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformCommissionRule> {
    return this.client.request(
      `/commission-rules/${encodeURIComponent(safeIdentifier(commissionRuleId, "commissionRuleId"))}`,
      { ...options, method: "GET", sensitive: true },
    );
  }
}

export class OpenPlatformBillingAccountsResource {
  constructor(readonly client: OpenPlatformClient) {}

  async list(
    query: OpenPlatformBillingAccountListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformBillingAccount>> {
    const split = splitListOptions(query, options);
    return requestPage(
      this.client,
      "/billing/accounts",
      split.query,
      { ...split.options, sensitive: true },
    );
  }

  async listAll(
    query: OpenPlatformBillingAccountListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions & { maxPages?: number },
  ): Promise<OpenPlatformBillingAccount[]> {
    return listAll(this, query, options);
  }

  async get(
    accountId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformBillingAccount> {
    return this.client.request(
      `/billing/accounts/${encodeURIComponent(safeIdentifier(accountId, "accountId"))}`,
      { ...options, method: "GET", sensitive: true },
    );
  }
}

export class OpenPlatformInvoicesResource {
  constructor(readonly client: OpenPlatformClient) {}

  async list(
    query: OpenPlatformInvoiceListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformInvoice>> {
    const split = splitListOptions(query, options);
    return requestPage(
      this.client,
      "/billing/invoices",
      split.query,
      { ...split.options, sensitive: true },
    );
  }

  async listAll(
    query: OpenPlatformInvoiceListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions & { maxPages?: number },
  ): Promise<OpenPlatformInvoice[]> {
    return listAll(this, query, options);
  }

  async get(
    invoiceId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformInvoice> {
    return this.client.request(
      `/billing/invoices/${encodeURIComponent(safeIdentifier(invoiceId, "invoiceId"))}`,
      { ...options, method: "GET", sensitive: true },
    );
  }

  async dispute(
    invoiceId: string,
    input: OpenPlatformInvoiceDisputeInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformInvoiceDisputeResult> {
    const mutation = mutationInput(input, options, "invoice-dispute");
    return this.client.request(
      `/billing/invoices/${encodeURIComponent(safeIdentifier(invoiceId, "invoiceId"))}/disputes`,
      {
        ...mutation.options,
        method: "POST",
        sensitive: true,
        body: mutation.body,
      },
    );
  }

  async createDispute(
    invoiceId: string,
    input: OpenPlatformInvoiceDisputeInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformInvoiceDisputeResult> {
    return this.dispute(invoiceId, input, options);
  }

  async disputeInvoice(
    invoiceId: string,
    input: OpenPlatformInvoiceDisputeInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformInvoiceDisputeResult> {
    return this.dispute(invoiceId, input, options);
  }
}

export class OpenPlatformInvoiceDisputesResource {
  constructor(readonly client: OpenPlatformClient) {}

  async list(
    invoiceId: string,
    query: OpenPlatformInvoiceDisputeListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformInvoiceDispute>> {
    const split = splitListOptions(query, options);
    return requestPage(
      this.client,
      invoiceDisputePath(invoiceId, "invoiceId"),
      split.query,
      { ...split.options, sensitive: true },
    );
  }

  async listAll(
    invoiceId: string,
    query: OpenPlatformInvoiceDisputeListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions & { maxPages?: number },
  ): Promise<OpenPlatformInvoiceDispute[]> {
    return listAll(this.list.bind(this) as never, query, options);
  }

  async get(
    disputeId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformInvoiceDispute> {
    return this.client.request(
      `/billing/disputes/${encodeURIComponent(safeIdentifier(disputeId, "disputeId"))}`,
      { ...options, method: "GET", sensitive: true },
    );
  }

  async startReview(
    invoiceId: string,
    disputeId: string,
    input: OpenPlatformInvoiceDisputeActionInput = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformInvoiceDisputeDecisionResult> {
    return this.postAction("review", invoiceId, disputeId, input, options);
  }

  async review(
    invoiceId: string,
    disputeId: string,
    input: OpenPlatformInvoiceDisputeActionInput = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformInvoiceDisputeDecisionResult> {
    return this.startReview(invoiceId, disputeId, input, options);
  }

  async decide(
    invoiceId: string,
    disputeId: string,
    input: OpenPlatformInvoiceDisputeDecisionInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformInvoiceDisputeDecisionResult> {
    const mutation = mutationInput(input, options, "invoice-dispute-decide");
    return this.client.request(
      invoiceDisputePath(invoiceId, "invoiceId", disputeId, "disputeId", "decisions"),
      {
        ...mutation.options,
        method: "POST",
        sensitive: true,
        body: mutation.body,
      },
    );
  }

  async withdraw(
    invoiceId: string,
    disputeId: string,
    input: OpenPlatformInvoiceDisputeActionInput = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformInvoiceDisputeDecisionResult> {
    const mutation = mutationInput(input, options, "invoice-dispute-withdraw");
    return this.client.request(
      invoiceDisputePath(invoiceId, "invoiceId", disputeId, "disputeId", "withdrawal"),
      {
        ...mutation.options,
        method: "POST",
        sensitive: true,
        body: mutation.body,
      },
    );
  }

  private async postAction(
    action: "review",
    invoiceId: string,
    disputeId: string,
    input: OpenPlatformInvoiceDisputeActionInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformInvoiceDisputeDecisionResult> {
    const mutation = mutationInput(input, options, "invoice-dispute-review");
    return this.client.request(
      invoiceDisputePath(invoiceId, "invoiceId", disputeId, "disputeId", "review"),
      {
        ...mutation.options,
        method: "POST",
        sensitive: true,
        body: mutation.body,
      },
    );
  }
}

export class OpenPlatformBillingResource {
  readonly accounts: OpenPlatformBillingAccountsResource;
  readonly invoices: OpenPlatformInvoicesResource;
  readonly disputes: OpenPlatformInvoiceDisputesResource;

  constructor(readonly client: OpenPlatformClient) {
    this.accounts = new OpenPlatformBillingAccountsResource(client);
    this.invoices = new OpenPlatformInvoicesResource(client);
    this.disputes = new OpenPlatformInvoiceDisputesResource(client);
  }

  listAccounts(
    query: OpenPlatformBillingAccountListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformBillingAccount>> {
    return this.accounts.list(query, options);
  }

  getAccount(
    accountId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformBillingAccount> {
    return this.accounts.get(accountId, options);
  }

  listInvoices(
    query: OpenPlatformInvoiceListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformInvoice>> {
    return this.invoices.list(query, options);
  }

  getInvoice(
    invoiceId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformInvoice> {
    return this.invoices.get(invoiceId, options);
  }

  disputeInvoice(
    invoiceId: string,
    input: OpenPlatformInvoiceDisputeInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformInvoiceDisputeResult> {
    return this.invoices.dispute(invoiceId, input, options);
  }

  listDisputes(
    invoiceId: string,
    query: OpenPlatformInvoiceDisputeListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformInvoiceDispute>> {
    return this.disputes.list(invoiceId, query, options);
  }

  getDispute(
    disputeId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformInvoiceDispute> {
    return this.disputes.get(disputeId, options);
  }

  startDisputeReview(
    invoiceId: string,
    disputeId: string,
    input: OpenPlatformInvoiceDisputeActionInput = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformInvoiceDisputeDecisionResult> {
    return this.disputes.startReview(invoiceId, disputeId, input, options);
  }

  decideDispute(
    invoiceId: string,
    disputeId: string,
    input: OpenPlatformInvoiceDisputeDecisionInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformInvoiceDisputeDecisionResult> {
    return this.disputes.decide(invoiceId, disputeId, input, options);
  }

  withdrawDispute(
    invoiceId: string,
    disputeId: string,
    input: OpenPlatformInvoiceDisputeActionInput = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformInvoiceDisputeDecisionResult> {
    return this.disputes.withdraw(invoiceId, disputeId, input, options);
  }
}

export class OpenPlatformComplianceDataAssetsResource {
  constructor(readonly client: OpenPlatformClient) {}

  async list(
    query: OpenPlatformComplianceListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformComplianceDataAsset>> {
    const split = splitListOptions(query, options);
    return requestPage(this.client, "/compliance/data-assets", split.query, split.options);
  }

  async listAll(
    query: OpenPlatformComplianceListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions & { maxPages?: number },
  ): Promise<OpenPlatformComplianceDataAsset[]> {
    return listAll(this, query, options);
  }

  async get(
    dataAssetId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceDataAsset> {
    return this.client.request(compliancePath("data-assets", dataAssetId, "dataAssetId"), {
      ...options,
      method: "GET",
    });
  }

  async create(
    input: CreateOpenPlatformComplianceDataAssetInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceDataAsset> {
    const mutation = mutationInput(input, options, "data-asset-create");
    return this.client.request("/compliance/data-assets", {
      ...mutation.options,
      method: "POST",
      body: mutation.body,
    });
  }

  async update(
    dataAssetId: string,
    input: UpdateOpenPlatformComplianceDataAssetInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceDataAsset> {
    const mutation = mutationInput(input, options, "data-asset-update");
    return this.client.request(compliancePath("data-assets", dataAssetId, "dataAssetId"), {
      ...mutation.options,
      method: "PATCH",
      body: mutation.body,
    });
  }

  async transitionStatus(
    dataAssetId: string,
    input: TransitionOpenPlatformComplianceDataAssetInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceDataAsset> {
    const mutation = mutationInput(input, options, "data-asset-transition");
    return this.client.request(
      compliancePath("data-assets", dataAssetId, "dataAssetId", "status"),
      { ...mutation.options, method: "POST", body: mutation.body },
    );
  }
}

export class OpenPlatformComplianceConsentsResource {
  constructor(readonly client: OpenPlatformClient) {}

  async list(
    query: OpenPlatformComplianceListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformComplianceConsentRecord>> {
    const split = splitListOptions(query, options);
    return requestPage(this.client, "/compliance/consents", split.query, split.options);
  }

  async listAll(
    query: OpenPlatformComplianceListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions & { maxPages?: number },
  ): Promise<OpenPlatformComplianceConsentRecord[]> {
    return listAll(this, query, options);
  }

  async get(
    consentId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceConsentRecord> {
    return this.client.request(compliancePath("consents", consentId, "consentId"), {
      ...options,
      method: "GET",
    });
  }

  async create(
    input: CreateOpenPlatformComplianceConsentRecordInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceConsentRecord> {
    const mutation = mutationInput(input, options, "consent-create");
    return this.client.request("/compliance/consents", {
      ...mutation.options,
      method: "POST",
      body: mutation.body,
    });
  }

  async grant(
    consentId: string,
    input: GrantOpenPlatformComplianceConsentInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceConsentRecord> {
    return consentAction(this.client, consentId, "grant", input, "consent-grant", options);
  }

  async withdraw(
    consentId: string,
    input: WithdrawOpenPlatformComplianceConsentInput = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceConsentRecord> {
    return consentAction(this.client, consentId, "withdraw", input, "consent-withdraw", options);
  }

  async expire(
    consentId: string,
    input: ExpireOpenPlatformComplianceConsentInput = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceConsentRecord> {
    return consentAction(this.client, consentId, "expire", input, "consent-expire", options);
  }
}

export class OpenPlatformCompliancePrivacyRequestsResource {
  constructor(readonly client: OpenPlatformClient) {}

  async list(
    query: OpenPlatformComplianceListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformCompliancePrivacyRequest>> {
    const split = splitListOptions(query, options);
    return requestPage(this.client, "/compliance/privacy-requests", split.query, split.options);
  }

  async listAll(
    query: OpenPlatformComplianceListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions & { maxPages?: number },
  ): Promise<OpenPlatformCompliancePrivacyRequest[]> {
    return listAll(this, query, options);
  }

  async get(
    privacyRequestId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformCompliancePrivacyRequest> {
    return this.client.request(
      compliancePath("privacy-requests", privacyRequestId, "privacyRequestId"),
      { ...options, method: "GET" },
    );
  }

  async getSla(
    privacyRequestId: string,
    query: { readonly at?: string } & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformCompliancePrivacyRequestSla> {
    const split = splitListOptions(query, options);
    return this.client.request(
      compliancePath("privacy-requests", privacyRequestId, "privacyRequestId", "sla"),
      { ...split.options, method: "GET", query: split.query as OpenPlatformQuery },
    );
  }

  async create(
    input: CreateOpenPlatformCompliancePrivacyRequestInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformCompliancePrivacyRequest> {
    const mutation = mutationInput(input, options, "privacy-request-create");
    return this.client.request("/compliance/privacy-requests", {
      ...mutation.options,
      method: "POST",
      body: mutation.body,
    });
  }

  async recordIdentityVerification(
    privacyRequestId: string,
    input: RecordOpenPlatformComplianceIdentityVerificationInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformCompliancePrivacyRequest> {
    return privacyRequestAction(
      this.client,
      privacyRequestId,
      "identity-verification",
      input,
      "privacy-request-verify-identity",
      options,
    );
  }

  async decide(
    privacyRequestId: string,
    input: DecideOpenPlatformCompliancePrivacyRequestInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformCompliancePrivacyRequest> {
    return privacyRequestAction(
      this.client,
      privacyRequestId,
      "decision",
      input,
      "privacy-request-decide",
      options,
    );
  }

  async recordAction(
    privacyRequestId: string,
    input: RecordOpenPlatformCompliancePrivacyRequestActionInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformCompliancePrivacyRequest> {
    return privacyRequestAction(
      this.client,
      privacyRequestId,
      "actions",
      input,
      "privacy-request-record-action",
      options,
    );
  }

  async transitionStatus(
    privacyRequestId: string,
    input: TransitionOpenPlatformCompliancePrivacyRequestInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformCompliancePrivacyRequest> {
    return privacyRequestAction(
      this.client,
      privacyRequestId,
      "status",
      input,
      "privacy-request-transition",
      options,
    );
  }
}

export class OpenPlatformComplianceRetentionPoliciesResource {
  constructor(readonly client: OpenPlatformClient) {}

  async list(
    query: OpenPlatformComplianceListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformComplianceRetentionPolicy>> {
    const split = splitListOptions(query, options);
    return requestPage(this.client, "/compliance/retention-policies", split.query, split.options);
  }

  async listAll(
    query: OpenPlatformComplianceListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions & { maxPages?: number },
  ): Promise<OpenPlatformComplianceRetentionPolicy[]> {
    return listAll(this, query, options);
  }

  async get(
    retentionPolicyId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceRetentionPolicy> {
    return this.client.request(
      compliancePath("retention-policies", retentionPolicyId, "retentionPolicyId"),
      { ...options, method: "GET" },
    );
  }

  async create(
    input: CreateOpenPlatformComplianceRetentionPolicyInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceRetentionPolicy> {
    const mutation = mutationInput(input, options, "retention-policy-create");
    return this.client.request("/compliance/retention-policies", {
      ...mutation.options,
      method: "POST",
      body: mutation.body,
    });
  }

  async transitionStatus(
    retentionPolicyId: string,
    input: TransitionOpenPlatformComplianceRetentionPolicyInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceRetentionPolicy> {
    const mutation = mutationInput(input, options, "retention-policy-transition");
    return this.client.request(
      compliancePath("retention-policies", retentionPolicyId, "retentionPolicyId", "status"),
      { ...mutation.options, method: "POST", body: mutation.body },
    );
  }
}

export class OpenPlatformComplianceRetentionExecutionsResource {
  constructor(readonly client: OpenPlatformClient) {}

  async list(
    query: OpenPlatformComplianceListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformComplianceRetentionExecution>> {
    const split = splitListOptions(query, options);
    return requestPage(this.client, "/compliance/retention-executions", split.query, split.options);
  }

  async listAll(
    query: OpenPlatformComplianceListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions & { maxPages?: number },
  ): Promise<OpenPlatformComplianceRetentionExecution[]> {
    return listAll(this, query, options);
  }

  async record(
    input: RecordOpenPlatformComplianceRetentionExecutionInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceRetentionExecution> {
    const mutation = mutationInput(input, options, "retention-execution-record");
    return this.client.request("/compliance/retention-executions", {
      ...mutation.options,
      method: "POST",
      body: mutation.body,
    });
  }
}

export class OpenPlatformComplianceCrossBorderAssessmentsResource {
  constructor(readonly client: OpenPlatformClient) {}

  async list(
    query: OpenPlatformComplianceListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformComplianceCrossBorderAssessment>> {
    const split = splitListOptions(query, options);
    return requestPage(
      this.client,
      "/compliance/cross-border-assessments",
      split.query,
      split.options,
    );
  }

  async listAll(
    query: OpenPlatformComplianceListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions & { maxPages?: number },
  ): Promise<OpenPlatformComplianceCrossBorderAssessment[]> {
    return listAll(this, query, options);
  }

  async get(
    crossBorderAssessmentId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceCrossBorderAssessment> {
    return this.client.request(
      compliancePath(
        "cross-border-assessments",
        crossBorderAssessmentId,
        "crossBorderAssessmentId",
      ),
      { ...options, method: "GET" },
    );
  }

  async create(
    input: CreateOpenPlatformComplianceCrossBorderAssessmentInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceCrossBorderAssessment> {
    const mutation = mutationInput(input, options, "cross-border-assessment-create");
    return this.client.request("/compliance/cross-border-assessments", {
      ...mutation.options,
      method: "POST",
      body: mutation.body,
    });
  }

  async transitionStatus(
    crossBorderAssessmentId: string,
    input: TransitionOpenPlatformComplianceCrossBorderAssessmentInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceCrossBorderAssessment> {
    const mutation = mutationInput(input, options, "cross-border-assessment-transition");
    return this.client.request(
      compliancePath(
        "cross-border-assessments",
        crossBorderAssessmentId,
        "crossBorderAssessmentId",
        "status",
      ),
      { ...mutation.options, method: "POST", body: mutation.body },
    );
  }

  async decide(
    crossBorderAssessmentId: string,
    input: TransitionOpenPlatformComplianceCrossBorderAssessmentInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceCrossBorderAssessment> {
    const mutation = mutationInput(input, options, "cross-border-assessment-decide");
    return this.client.request(
      compliancePath(
        "cross-border-assessments",
        crossBorderAssessmentId,
        "crossBorderAssessmentId",
        "decision",
      ),
      { ...mutation.options, method: "POST", body: mutation.body },
    );
  }
}

export class OpenPlatformComplianceVendorsResource {
  constructor(readonly client: OpenPlatformClient) {}

  async list(
    query: OpenPlatformComplianceListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformComplianceVendor>> {
    const split = splitListOptions(query, options);
    return requestPage(this.client, "/compliance/vendors", split.query, split.options);
  }

  async listAll(
    query: OpenPlatformComplianceListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions & { maxPages?: number },
  ): Promise<OpenPlatformComplianceVendor[]> {
    return listAll(this, query, options);
  }

  async get(
    vendorId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceVendor> {
    return this.client.request(compliancePath("vendors", vendorId, "vendorId"), {
      ...options,
      method: "GET",
    });
  }

  async create(
    input: CreateOpenPlatformComplianceVendorInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceVendor> {
    const mutation = mutationInput(input, options, "vendor-create");
    return this.client.request("/compliance/vendors", {
      ...mutation.options,
      method: "POST",
      body: mutation.body,
    });
  }

  async transitionStatus(
    vendorId: string,
    input: TransitionOpenPlatformComplianceVendorInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceVendor> {
    const mutation = mutationInput(input, options, "vendor-transition");
    return this.client.request(compliancePath("vendors", vendorId, "vendorId", "status"), {
      ...mutation.options,
      method: "POST",
      body: mutation.body,
    });
  }

  async recordAssessment(
    vendorId: string,
    input: RecordOpenPlatformComplianceVendorAssessmentInput,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceVendor> {
    const mutation = mutationInput(input, options, "vendor-record-assessment");
    return this.client.request(compliancePath("vendors", vendorId, "vendorId", "assessments"), {
      ...mutation.options,
      method: "POST",
      body: mutation.body,
    });
  }
}

export class OpenPlatformComplianceReportResource {
  constructor(readonly client: OpenPlatformClient) {}

  async get(
    query: OpenPlatformComplianceReportQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceReportView> {
    const split = splitListOptions(query as OpenPlatformListQuery & OpenPlatformCallOptions, options);
    return this.client.request("/compliance/report", {
      ...split.options,
      method: "GET",
      query: split.query as OpenPlatformQuery,
    });
  }

  async generate(
    input: GenerateOpenPlatformComplianceReportInput = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceReportView> {
    const mutation = mutationInput(input, options, "compliance-report-generate");
    return this.client.request("/compliance/report", {
      ...mutation.options,
      method: "POST",
      body: mutation.body,
    });
  }
}

export class OpenPlatformComplianceResource {
  readonly dataAssets: OpenPlatformComplianceDataAssetsResource;
  readonly consents: OpenPlatformComplianceConsentsResource;
  readonly privacyRequests: OpenPlatformCompliancePrivacyRequestsResource;
  readonly retentionPolicies: OpenPlatformComplianceRetentionPoliciesResource;
  readonly retentionExecutions: OpenPlatformComplianceRetentionExecutionsResource;
  readonly crossBorderAssessments: OpenPlatformComplianceCrossBorderAssessmentsResource;
  readonly vendors: OpenPlatformComplianceVendorsResource;
  readonly report: OpenPlatformComplianceReportResource;

  constructor(readonly client: OpenPlatformClient) {
    this.dataAssets = new OpenPlatformComplianceDataAssetsResource(client);
    this.consents = new OpenPlatformComplianceConsentsResource(client);
    this.privacyRequests = new OpenPlatformCompliancePrivacyRequestsResource(client);
    this.retentionPolicies = new OpenPlatformComplianceRetentionPoliciesResource(client);
    this.retentionExecutions = new OpenPlatformComplianceRetentionExecutionsResource(client);
    this.crossBorderAssessments = new OpenPlatformComplianceCrossBorderAssessmentsResource(client);
    this.vendors = new OpenPlatformComplianceVendorsResource(client);
    this.report = new OpenPlatformComplianceReportResource(client);
  }

  listDataAssets(
    query: OpenPlatformComplianceListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformComplianceDataAsset>> {
    return this.dataAssets.list(query, options);
  }

  getDataAsset(
    dataAssetId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceDataAsset> {
    return this.dataAssets.get(dataAssetId, options);
  }

  listConsents(
    query: OpenPlatformComplianceListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformComplianceConsentRecord>> {
    return this.consents.list(query, options);
  }

  getConsentRecord(
    consentId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceConsentRecord> {
    return this.consents.get(consentId, options);
  }

  listPrivacyRequests(
    query: OpenPlatformComplianceListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformCompliancePrivacyRequest>> {
    return this.privacyRequests.list(query, options);
  }

  getPrivacyRequest(
    privacyRequestId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformCompliancePrivacyRequest> {
    return this.privacyRequests.get(privacyRequestId, options);
  }

  getPrivacyRequestSla(
    privacyRequestId: string,
    query: { readonly at?: string } & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformCompliancePrivacyRequestSla> {
    return this.privacyRequests.getSla(privacyRequestId, query, options);
  }

  listRetentionPolicies(
    query: OpenPlatformComplianceListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformComplianceRetentionPolicy>> {
    return this.retentionPolicies.list(query, options);
  }

  listRetentionExecutions(
    query: OpenPlatformComplianceListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformComplianceRetentionExecution>> {
    return this.retentionExecutions.list(query, options);
  }

  listCrossBorderAssessments(
    query: OpenPlatformComplianceListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformComplianceCrossBorderAssessment>> {
    return this.crossBorderAssessments.list(query, options);
  }

  listVendors(
    query: OpenPlatformComplianceListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformPage<OpenPlatformComplianceVendor>> {
    return this.vendors.list(query, options);
  }

  getVendor(
    vendorId: string,
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceVendor> {
    return this.vendors.get(vendorId, options);
  }

  getReport(
    query: OpenPlatformComplianceReportQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceReportView> {
    return this.report.get(query, options);
  }

  generateReport(
    input: GenerateOpenPlatformComplianceReportInput = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformComplianceReportView> {
    return this.report.generate(input, options);
  }
}

export class OpenPlatformDomainEventsResource {
  constructor(readonly client: OpenPlatformClient) {}

  async list(
    query: OpenPlatformDomainEventListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformDomainEventPage> {
    const split = splitListOptions(query, options);
    return this.client
      .request<unknown>("/domain-events", {
        ...split.options,
        method: "GET",
        query: split.query as OpenPlatformQuery,
      })
      .then((value) => normalizeOpenPlatformDomainEventPage(value));
  }

  async listAll(
    query: OpenPlatformDomainEventListQuery & OpenPlatformCallOptions = {},
    options?: OpenPlatformCallOptions & { maxPages?: number },
  ): Promise<OpenPlatformDomainEventSummary[]> {
    const split = splitListOptions(query, options);
    const maxPages = options?.maxPages;
    return collectOpenPlatformPages<OpenPlatformDomainEventSummary>(
      async (cursor) => {
        const nextQuery: Record<string, unknown> = { ...split.query };
        if (cursor === undefined) delete nextQuery.cursor;
        else nextQuery.cursor = cursor;
        delete nextQuery.sequence;
        const page = await this.list(nextQuery, split.options);
        return {
          items: [...page.items],
          hasMore: page.hasMore,
          ...(page.nextCursor === undefined ? {} : { nextCursor: page.nextCursor }),
        };
      },
      maxPages === undefined ? {} : { maxPages },
    );
  }

  async retry(
    input: RetryOpenPlatformDomainEventInput = {},
    options?: OpenPlatformCallOptions,
  ): Promise<OpenPlatformDomainEventRetryResultSummary> {
    const mutation = mutationInput(input, options, "domain-event-retry");
    return this.client
      .request<unknown>("/domain-events/retry", {
        ...mutation.options,
        method: "POST",
        body: mutation.body,
      })
      .then((value) => normalizeOpenPlatformDomainEventRetry(value));
  }
}

export const WebhookResource = OpenPlatformWebhooksResource;
export const AuditEventsResource = OpenPlatformAuditEventsResource;
export const MarketplaceResource = OpenPlatformMarketplaceResource;
export const Marketplace = OpenPlatformMarketplaceResource;
export const MarketplaceListingsResource = OpenPlatformMarketplaceListingsResource;
export const MarketplaceListings = OpenPlatformMarketplaceListingsResource;
export const PartnersResource = OpenPlatformPartnersResource;
export const Partners = OpenPlatformPartnersResource;
export const CommissionRulesResource = OpenPlatformCommissionRulesResource;
export const CommissionRules = OpenPlatformCommissionRulesResource;
export const BillingResource = OpenPlatformBillingResource;
export const Billing = OpenPlatformBillingResource;
export const BillingAccountsResource = OpenPlatformBillingAccountsResource;
export const BillingAccounts = OpenPlatformBillingAccountsResource;
export const InvoicesResource = OpenPlatformInvoicesResource;
export const Invoices = OpenPlatformInvoicesResource;
export const ComplianceResource = OpenPlatformComplianceResource;
export const Compliance = OpenPlatformComplianceResource;
export const ComplianceDataAssetsResource = OpenPlatformComplianceDataAssetsResource;
export const ComplianceDataAssets = OpenPlatformComplianceDataAssetsResource;
export const ComplianceConsentsResource = OpenPlatformComplianceConsentsResource;
export const ComplianceConsents = OpenPlatformComplianceConsentsResource;
export const CompliancePrivacyRequestsResource = OpenPlatformCompliancePrivacyRequestsResource;
export const CompliancePrivacyRequests = OpenPlatformCompliancePrivacyRequestsResource;
export const ComplianceRetentionPoliciesResource = OpenPlatformComplianceRetentionPoliciesResource;
export const ComplianceRetentionPolicies = OpenPlatformComplianceRetentionPoliciesResource;
export const ComplianceRetentionExecutionsResource = OpenPlatformComplianceRetentionExecutionsResource;
export const ComplianceRetentionExecutions = OpenPlatformComplianceRetentionExecutionsResource;
export const ComplianceCrossBorderAssessmentsResource = OpenPlatformComplianceCrossBorderAssessmentsResource;
export const ComplianceCrossBorderAssessments = OpenPlatformComplianceCrossBorderAssessmentsResource;
export const ComplianceVendorsResource = OpenPlatformComplianceVendorsResource;
export const ComplianceVendors = OpenPlatformComplianceVendorsResource;
export const ComplianceReportResource = OpenPlatformComplianceReportResource;
export const DomainEventsResource = OpenPlatformDomainEventsResource;
export const DomainEvents = OpenPlatformDomainEventsResource;

export function createOpenPlatformClient(options: OpenPlatformClientOptions): OpenPlatformClient {
  return new OpenPlatformClient(options);
}

export const createOpenPlatformSDKClient = createOpenPlatformClient;
export const createOpenPlatformSdkClient = createOpenPlatformClient;
export const createOpenPlatformSDK = createOpenPlatformClient;

export function resolveOpenPlatformBaseUrl(
  baseUrl: string | URL,
  apiPath?: string | false,
  allowInsecureHttp = false,
): { baseUrl: string; apiPath: string } {
  let parsed: URL;
  try {
    parsed = baseUrl instanceof URL ? new URL(baseUrl.toString()) : new URL(baseUrl);
  } catch {
    throw new OpenPlatformConfigurationError();
  }
  if (
    (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
    (!allowInsecureHttp && parsed.protocol === "http:" && !isLoopbackHost(parsed.hostname)) ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    parsed.hostname.length === 0 ||
    /[\u0000-\u001f\u007f\s]/u.test(parsed.pathname)
  ) {
    throw new OpenPlatformConfigurationError();
  }
  const suppliedPath = normalizeBasePath(parsed.pathname);
  let finalPath: string;
  if (apiPath === false) {
    finalPath = suppliedPath;
  } else if (apiPath === undefined) {
    finalPath = suppliedPath.length === 0 ? OPEN_PLATFORM_SDK_API_PATH : suppliedPath;
  } else {
    const requestedPath = normalizeBasePath(apiPath);
    finalPath = suppliedPath.endsWith(requestedPath) ? suppliedPath : joinBasePaths(suppliedPath, requestedPath);
  }
  parsed.pathname = finalPath.length === 0 ? "/" : finalPath;
  return {
    baseUrl: parsed.toString().replace(/\/$/u, ""),
    apiPath: finalPath,
  };
}

export const normalizeOpenPlatformBaseUrl = resolveOpenPlatformBaseUrl;

function requestPage<T>(
  client: OpenPlatformClient,
  path: string,
  query: Record<string, unknown>,
  options: OpenPlatformCallOptions,
): Promise<OpenPlatformPage<T>> {
  return client.request<unknown>(path, {
    ...options,
    method: "GET",
    query: query as OpenPlatformQuery,
  }).then((value) => normalizeOpenPlatformPage<T>(value));
}

async function listAll<T>(
  resource: { list: (query?: OpenPlatformListQuery & OpenPlatformCallOptions, options?: OpenPlatformCallOptions) => Promise<OpenPlatformPage<T>> },
  query: OpenPlatformListQuery & OpenPlatformCallOptions,
  options: (OpenPlatformCallOptions & { maxPages?: number }) | undefined,
): Promise<T[]> {
  const split = splitListOptions(query, options);
  const maxPages = options?.maxPages;
  return collectOpenPlatformPages(
    async (cursor) => {
      const nextQuery = { ...split.query, ...(cursor === undefined ? {} : { cursor }) };
      return resource.list(nextQuery, split.options);
    },
    maxPages === undefined ? {} : { maxPages },
  );
}

function splitListOptions(
  value: (OpenPlatformListQuery & OpenPlatformCallOptions) | undefined,
  explicit: OpenPlatformCallOptions | undefined,
): SplitListOptions {
  const source = isRecord(value) ? value : {};
  const query: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(source)) {
    if (CALL_OPTION_KEYS.has(key) || key === "tenantId" || key === "maxPages") continue;
    query[key] = item;
  }
  if (source.tenantId !== undefined) query.tenantId = undefined;
  const options = copyCallOptions(source);
  if (source.tenantId !== undefined && options.tenantId === undefined) {
    options.tenantId = safeIdentifier(source.tenantId, "tenantId");
  }
  return { query, options: { ...options, ...copyCallOptions(explicit) } };
}

function mutationInput(
  input: unknown,
  options: OpenPlatformCallOptions | undefined,
  operation: string,
): { body: Record<string, unknown>; options: OpenPlatformCallOptions } {
  if (!isRecord(input)) throw new OpenPlatformRequestError();
  const body: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input)) {
    if (key === "tenantId" || key === "idempotencyKey") continue;
    if (value !== undefined) body[key] = value;
  }
  const call = copyCallOptions(options);
  if (input.tenantId !== undefined && call.tenantId === undefined) {
    call.tenantId = safeIdentifier(input.tenantId, "tenantId");
  }
  if (input.idempotencyKey !== undefined && call.idempotencyKey === undefined) {
    call.idempotencyKey = assertIdempotencyKey(input.idempotencyKey);
  }
  if (call.idempotencyKey === undefined) call.idempotencyKey = generateIdempotencyKey(operation);
  return { body, options: call };
}

function lifecycle<T extends OpenPlatformResourceBase>(
  client: OpenPlatformClient,
  resource: string,
  id: string,
  action: string,
  options?: OpenPlatformCallOptions,
): Promise<T> {
  return client.request<T>(`/${resource}/${encodeURIComponent(safeIdentifier(id, "id"))}/${action}`, {
    ...options,
    method: "POST",
    body: {},
    idempotencyKey: options?.idempotencyKey ?? generateIdempotencyKey(`${resource}-${action}`),
  });
}

function invoiceDisputePath(
  invoiceId: string,
  invoiceField: string,
  disputeId?: string,
  disputeField = "disputeId",
  action?: string,
): string {
  const path = `/billing/invoices/${encodeURIComponent(safeIdentifier(invoiceId, invoiceField))}/disputes`;
  if (disputeId === undefined) return path;
  const scoped = `${path}/${encodeURIComponent(safeIdentifier(disputeId, disputeField))}`;
  return action === undefined ? scoped : `${scoped}/${action}`;
}

function compliancePath(
  resource: string,
  id: string,
  field: string,
  action?: string,
): string {
  const path = `/compliance/${resource}/${encodeURIComponent(safeIdentifier(id, field))}`;
  return action === undefined ? path : `${path}/${action}`;
}

function consentAction(
  client: OpenPlatformClient,
  consentId: string,
  action: "grant" | "withdraw" | "expire",
  input: unknown,
  operation: string,
  options?: OpenPlatformCallOptions,
): Promise<OpenPlatformComplianceConsentRecord> {
  const mutation = mutationInput(input, options, operation);
  return client.request(compliancePath("consents", consentId, "consentId", action), {
    ...mutation.options,
    method: "POST",
    body: mutation.body,
  });
}

function privacyRequestAction(
  client: OpenPlatformClient,
  privacyRequestId: string,
  action: "identity-verification" | "decision" | "actions" | "status",
  input: unknown,
  operation: string,
  options?: OpenPlatformCallOptions,
): Promise<OpenPlatformCompliancePrivacyRequest> {
  const mutation = mutationInput(input, options, operation);
  return client.request(
    compliancePath("privacy-requests", privacyRequestId, "privacyRequestId", action),
    { ...mutation.options, method: "POST", body: mutation.body },
  );
}

function environmentLifecycle(
  client: OpenPlatformClient,
  applicationId: string,
  environmentId: string,
  action: string,
  options?: OpenPlatformCallOptions,
): Promise<OpenPlatformApplicationEnvironment> {
  return client.request<OpenPlatformApplicationEnvironment>(
    `/applications/${encodeURIComponent(safeIdentifier(applicationId, "applicationId"))}/environments/${encodeURIComponent(safeIdentifier(environmentId, "environmentId"))}/${action}`,
    {
      ...options,
      method: "POST",
      body: {},
      idempotencyKey: options?.idempotencyKey ?? generateIdempotencyKey(`environment-${action}`),
    },
  );
}

function versionLifecycle(
  client: OpenPlatformClient,
  productId: string,
  versionId: string,
  action: string,
  options?: OpenPlatformCallOptions,
): Promise<OpenPlatformApiVersion> {
  return client.request<OpenPlatformApiVersion>(
    `/catalog/products/${encodeURIComponent(safeIdentifier(productId, "productId"))}/versions/${encodeURIComponent(safeIdentifier(versionId, "versionId"))}/${action}`,
    {
      ...options,
      method: "POST",
      body: {},
      idempotencyKey: options?.idempotencyKey ?? generateIdempotencyKey(`version-${action}`),
    },
  );
}

function copyCallOptions(value: unknown): OpenPlatformCallOptions {
  if (!isRecord(value)) return {};
  const output: Record<string, unknown> = {};
  for (const key of CALL_OPTION_KEYS) {
    if (Object.prototype.hasOwnProperty.call(value, key) && value[key] !== undefined) output[key] = value[key];
  }
  return output as OpenPlatformCallOptions;
}

function normalizeMethod(value: unknown): OpenPlatformHttpMethod {
  if (value === undefined) return "GET";
  if (typeof value !== "string") throw new OpenPlatformRequestError();
  const normalized = value.toUpperCase() as OpenPlatformHttpMethod;
  if (!["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].includes(normalized)) {
    throw new OpenPlatformRequestError();
  }
  return normalized;
}

function normalizeTimeout(value: unknown): number | undefined {
  if (value === undefined || value === 0) return undefined;
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > MAX_TIMEOUT_MS) {
    throw new OpenPlatformRequestError();
  }
  return value as number;
}

function normalizeRetryOptions(value: boolean | OpenPlatformRetryOptions | number | undefined): NormalizedRetryOptions {
  if (value === false) {
    return {
      maxRetries: 0,
      baseDelayMs: 0,
      maxDelayMs: 0,
      jitter: false,
      retryableStatuses: new Set(),
    };
  }
  const options = typeof value === "number"
    ? { maxRetries: value }
    : value === true
      ? {}
      : value ?? {};
  const maxRetries = options.maxRetries ??
    (options.maxAttempts === undefined ? DEFAULT_MAX_RETRIES : Math.max(options.maxAttempts - 1, 0));
  const baseDelayMs = options.baseDelayMs ?? DEFAULT_BASE_DELAY_MS;
  const maxDelayMs = options.maxDelayMs ?? DEFAULT_MAX_DELAY_MS;
  if (
    !Number.isSafeInteger(maxRetries) || maxRetries < 0 || maxRetries > 10 ||
    !Number.isSafeInteger(baseDelayMs) || baseDelayMs < 0 || baseDelayMs > 60_000 ||
    !Number.isSafeInteger(maxDelayMs) || maxDelayMs < 0 || maxDelayMs > 300_000 ||
    maxDelayMs < baseDelayMs ||
    (options.jitter !== undefined && typeof options.jitter !== "boolean" && !Number.isFinite(options.jitter))
  ) {
    throw new OpenPlatformConfigurationError();
  }
  const statuses = options.retryableStatuses ?? RETRYABLE_STATUSES;
  const retryableStatuses = new Set<number>();
  for (const status of statuses) {
    if (!Number.isSafeInteger(status) || status < 100 || status > 599) {
      throw new OpenPlatformConfigurationError();
    }
    retryableStatuses.add(status);
  }
  return {
    maxRetries,
    baseDelayMs,
    maxDelayMs,
    jitter: options.jitter ?? false,
    retryableStatuses,
    ...(options.shouldRetry === undefined ? {} : { shouldRetry: options.shouldRetry }),
  };
}

async function resolveToken(source: OpenPlatformTokenSource | undefined): Promise<ResolvedToken | undefined> {
  if (source === undefined) return undefined;
  try {
    let value: string | OpenPlatformToken | null | undefined;
    if (typeof source === "string") value = source;
    else if (typeof source === "function") value = await source();
    else if (typeof source === "object" && "getToken" in source && typeof source.getToken === "function") {
      value = await source.getToken();
    } else if (
      typeof source === "object" &&
      "getAccessToken" in source &&
      typeof source.getAccessToken === "function"
    ) {
      value = await source.getAccessToken();
    } else if (typeof source === "object" && "getAccessToken" in source && source.getAccessToken !== undefined) {
      value = await (typeof source.getAccessToken === "function" ? source.getAccessToken() : source.getAccessToken);
    } else if (typeof source === "object" && "accessToken" in source) {
      value = source as OpenPlatformToken;
    } else return undefined;
    if (value === null || value === undefined) return undefined;
    if (typeof value === "string") return { value: safeToken(value), type: "Bearer" };
    if (typeof value !== "object") return undefined;
    return {
      value: safeToken(value.accessToken),
      type: safeTokenType(value.tokenType ?? "Bearer"),
    };
  } catch {
    throw new OpenPlatformAuthenticationProviderError();
  }
}

function formatAuthorization(token: ResolvedToken): string {
  if (/^Bearer\s+\S+$/iu.test(token.value)) return token.value;
  return `${token.type} ${token.value}`;
}

function safeToken(value: unknown): string {
  if (typeof value !== "string") throw new OpenPlatformAuthenticationProviderError();
  const normalized = value.trim();
  if (normalized.length < 1 || normalized.length > 16_384 || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new OpenPlatformAuthenticationProviderError();
  }
  return normalized;
}

function safeTokenType(value: unknown): string {
  if (typeof value !== "string" || !/^[A-Za-z][A-Za-z0-9._-]{0,31}$/u.test(value)) {
    throw new OpenPlatformAuthenticationProviderError();
  }
  return value;
}

function safeIdentifier(value: unknown, field: string): string {
  if (typeof value !== "string") throw new OpenPlatformRequestError();
  const normalized = value.trim();
  if (
    normalized.length < 1 ||
    normalized.length > 512 ||
    /[\u0000-\u001f\u007f\s]/u.test(normalized) ||
    /(?:secret|password|private[-_]?key|authorization|cookie|vault:\/\/)/iu.test(normalized)
  ) {
    throw new OpenPlatformRequestError();
  }
  return normalized;
}

function serializeBody(value: unknown): string {
  if (typeof value === "string") return value;
  if (value instanceof URLSearchParams) return value.toString();
  try {
    const serialized = JSON.stringify(value);
    if (typeof serialized !== "string") throw new Error("invalid body");
    return serialized;
  } catch {
    throw new OpenPlatformRequestError();
  }
}

function assertNoPlaintextBody(value: unknown, depth = 0): void {
  if (depth > 8 || value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (const item of value) assertNoPlaintextBody(item, depth + 1);
    return;
  }
  for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
    if (isPlaintextSecretKey(key)) throw new OpenPlatformRequestError();
    assertNoPlaintextBody(nested, depth + 1);
  }
}

function isPlaintextSecretKey(key: string): boolean {
  const normalized = key.replace(/[-_]/gu, "").toLowerCase();
  if (normalized.endsWith("ref") || normalized.endsWith("reference") || normalized.endsWith("digest") || normalized.endsWith("fingerprint")) {
    return false;
  }
  return normalized.includes("secret") ||
    normalized === "plaintext" ||
    normalized === "password" ||
    normalized === "token" ||
    normalized.endsWith("token") ||
    normalized === "accesstoken" ||
    normalized === "refreshtoken" ||
    normalized === "idtoken" ||
    normalized === "privatekey" ||
    normalized === "authorization" ||
    normalized === "apikey";
}

function appendQuery(url: URL, query: OpenPlatformQuery): void {
  const params = new URLSearchParams();
  if (query instanceof URLSearchParams) {
    query.forEach((value, key) => appendQueryValue(params, key, value));
    return;
  }
  if (!isRecord(query)) throw new OpenPlatformRequestError();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null) continue;
    if (typeof value === "object" && !Array.isArray(value)) throw new OpenPlatformRequestError();
    if (Array.isArray(value)) {
      for (const item of value) appendQueryValue(params, key, item);
    } else appendQueryValue(params, key, value);
  }
  const serialized = params.toString();
  if (serialized.length > 0) url.search = serialized;
}

function appendQueryValue(params: URLSearchParams, key: string, value: unknown): void {
  if (isSensitiveQueryKey(key) || !isSafeQueryKey(key)) throw new OpenPlatformRequestError();
  if (value === undefined || value === null) return;
  let normalized: string;
  if (typeof value === "string") normalized = value;
  else if (typeof value === "number" && Number.isFinite(value)) normalized = String(value);
  else if (typeof value === "boolean") normalized = String(value);
  else throw new OpenPlatformRequestError();
  const normalizedKey = key.replace(/[-_]/gu, "").toLowerCase();
  if (normalizedKey === "limit" || normalizedKey === "pagesize") {
    if (!/^[1-9][0-9]{0,2}$/u.test(normalized) || Number(normalized) > 100) {
      throw new OpenPlatformRequestError();
    }
  }
  if (normalizedKey === "cursor" && (
    normalized.length === 0 ||
    normalized.length > 2048 ||
    /[\s\u0000-\u001f\u007f]/u.test(normalized)
  )) {
    throw new OpenPlatformRequestError();
  }
  params.append(key, normalized);
}

function isSafeQueryKey(key: string): boolean {
  return key.length > 0 && key.length <= 128 && !/[\u0000-\u001f\u007f\s]/u.test(key);
}

function isSensitiveQueryKey(key: string): boolean {
  const normalized = key.replace(/[-_]/gu, "").toLowerCase();
  return normalized.includes("secret") ||
    normalized.includes("password") ||
    normalized.includes("authorization") ||
    normalized.includes("privatekey") ||
    normalized === "token" ||
    normalized.endsWith("token") ||
    normalized === "apikey" ||
    normalized.endsWith("apikey");
}

function unwrapPayload(value: unknown): unknown {
  if (!isRecord(value)) return value;
  const wrapperKeys = new Set(["data", "requestId", "meta", "success", "ok"]);
  if (
    Object.prototype.hasOwnProperty.call(value, "data") &&
    Object.keys(value).every((key) => wrapperKeys.has(key))
  ) {
    return value.data;
  }
  return value;
}

function readResponseBody(response: Response): Promise<unknown> {
  const candidate = response as unknown as {
    text?: () => Promise<string>;
    json?: () => Promise<unknown>;
  };
  if (typeof candidate.text === "function") {
    return candidate.text().then((text) => {
      const normalized = text.replace(/^\uFEFF/u, "").trim();
      if (normalized.length === 0) return undefined;
      try {
        return JSON.parse(normalized) as unknown;
      } catch {
        return INVALID_RESPONSE;
      }
    });
  }
  if (typeof candidate.json === "function") return candidate.json().catch(() => INVALID_RESPONSE);
  return Promise.reject(new OpenPlatformProtocolError());
}

function waitForRetry(delayMs: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) return Promise.reject(new OpenPlatformAbortError());
  if (delayMs <= 0) return Promise.resolve();
  return new Promise<void>((resolve, reject) => {
    let settled = false;
    const onAbort = (): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new OpenPlatformAbortError());
    };
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, delayMs);
    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted) onAbort();
  });
}

function normalizeTransportError(error: unknown): OpenPlatformErrorLike {
  if (error instanceof OpenPlatformAbortError || error instanceof OpenPlatformTimeoutError) return error;
  return new OpenPlatformNetworkError();
}

function isAbortError(error: unknown): boolean {
  return isRecord(error) && error.name === "AbortError";
}

function authorizationSensitiveValues(headers: Record<string, string> | undefined): string[] {
  if (headers === undefined) return [];
  const values: string[] = [];
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== "authorization" || value.length === 0) continue;
    values.push(value);
    const separator = value.indexOf(" ");
    if (separator > 0 && separator < value.length - 1) values.push(value.slice(separator + 1));
  }
  return values;
}

function isCompliancePath(path: string): boolean {
  return /^\/compliance(?:\/|$)/u.test(path);
}

function isSensitivePath(path: string): boolean {
  return /(?:^|\/)(?:credentials|webhooks|audit-events|marketplace|partners|partner-accounts|commission-rules|billing|compliance|domain-events)(?:\/|$)/iu.test(path);
}

function isWithinBasePath(pathname: string, basePath: string): boolean {
  if (basePath.length === 0) return true;
  return pathname === basePath || pathname.startsWith(`${basePath}/`);
}

function normalizeBasePath(value: string): string {
  if (typeof value !== "string" || /[?#\u0000-\u001f\u007f\s]/u.test(value)) {
    throw new OpenPlatformConfigurationError();
  }
  const normalized = value.replace(/\/+$/u, "");
  if (normalized.length > 1 && !normalized.startsWith("/")) throw new OpenPlatformConfigurationError();
  return normalized === "/" ? "" : normalized;
}

function joinBasePaths(left: string, right: string): string {
  if (left.length === 0) return right;
  if (right.length === 0) return left;
  return `${left}/${right.replace(/^\/+/u, "")}`;
}

function isLoopbackHost(hostname: string): boolean {
  const normalized = hostname.toLowerCase();
  return normalized === "localhost" || normalized === "127.0.0.1" || normalized === "[::1]";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export { OpenPlatformClient as OpenPlatformSDKClient };
export { OpenPlatformClient as OpenPlatformSdkClient };
export { OpenPlatformClient as OpenPlatformFetchClient };
export { OpenPlatformClient as OpenPlatformHttpClient };
export { OpenPlatformClient as IdaasOpenPlatformClient };
export { OpenPlatformApplicationsResource as ApplicationsResource };
export { OpenPlatformApiProductsResource as ApiProductsResource };
export { OpenPlatformCredentialsResource as CredentialsResource };
export { OpenPlatformUsageResource as UsageResource };
export { OpenPlatformSubscriptionsResource as SubscriptionsResource };
export { OpenPlatformMarketplaceResource as OpenPlatformMarketplace };
export { OpenPlatformMarketplaceListingsResource as OpenPlatformMarketplaceListings };
export { OpenPlatformPartnersResource as OpenPlatformPartners };
export { OpenPlatformCommissionRulesResource as OpenPlatformCommissionRules };
export { OpenPlatformBillingResource as OpenPlatformBilling };
export { OpenPlatformBillingAccountsResource as OpenPlatformBillingAccounts };
export { OpenPlatformInvoicesResource as OpenPlatformInvoices };
export { OpenPlatformComplianceResource as OpenPlatformCompliance };
export { OpenPlatformDomainEventsResource as OpenPlatformDomainEvents };
