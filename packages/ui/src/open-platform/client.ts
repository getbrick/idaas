import type {
  OpenPlatformAuditEvent,
  OpenPlatformComplianceDataAsset,
  OpenPlatformComplianceListQuery,
  OpenPlatformCompliancePrivacyRequest,
  OpenPlatformCompliancePrivacyRequestSla,
  OpenPlatformComplianceReport,
  OpenPlatformComplianceReportQuery,
  OpenPlatformDomainEventListQuery,
  OpenPlatformDomainEventRetryInput,
  OpenPlatformDomainEventRetrySummary,
  OpenPlatformDomainEventSummary,
  OpenPlatformInvoice,
  OpenPlatformListQuery,
  OpenPlatformMarketplaceListing,
  OpenPlatformPage,
  OpenPlatformWebhookEndpoint,
} from "./types.js";

export type OpenPlatformMaybePromise<T> = T | Promise<T>;

export interface OpenPlatformToken {
  readonly accessToken?: string;
  readonly token?: string;
  readonly tokenType?: string;
}

export type OpenPlatformTokenResult = string | OpenPlatformToken | null | undefined;
export type OpenPlatformTokenSource =
  | string
  | OpenPlatformToken
  | (() => OpenPlatformMaybePromise<OpenPlatformTokenResult>)
  | { readonly getToken?: () => OpenPlatformMaybePromise<OpenPlatformTokenResult> }
  | { readonly getAccessToken?: () => OpenPlatformMaybePromise<OpenPlatformTokenResult> };

export type OpenPlatformFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export interface OpenPlatformClientOptions {
  baseURL?: string | URL;
  baseUrl?: string | URL;
  apiPath?: string | false;
  basePath?: string | false;
  allowInsecureHttp?: boolean;
  tenantId?: string;
  tenant?: string;
  tenant_id?: string;
  token?: OpenPlatformTokenSource;
  accessToken?: OpenPlatformTokenSource;
  tokenProvider?: OpenPlatformTokenSource;
  accessTokenProvider?: OpenPlatformTokenSource;
  fetch?: OpenPlatformFetch;
  fetcher?: OpenPlatformFetch;
  headers?: HeadersInit;
  defaultHeaders?: HeadersInit;
}

export interface OpenPlatformRequestOptions {
  method?: string;
  query?: Record<string, unknown> | URLSearchParams;
  headers?: HeadersInit;
  signal?: AbortSignal;
  tenantId?: string;
  tenant?: string;
  tenant_id?: string;
  token?: OpenPlatformTokenSource;
  authenticated?: boolean;
  body?: unknown;
  idempotencyKey?: string;
}

export type OpenPlatformClientErrorCode =
  | "configuration_error"
  | "request_error"
  | "network_error"
  | "timeout"
  | "aborted"
  | "invalid_response"
  | "unauthorized"
  | "forbidden"
  | "not_found"
  | "conflict"
  | "rate_limited"
  | "service_unavailable"
  | "internal_error"
  | "unknown";

export class OpenPlatformFetchError extends Error {
  readonly code: OpenPlatformClientErrorCode;
  readonly status: number;
  readonly requestId?: string;
  readonly retryable: boolean;

  constructor(
    code: OpenPlatformClientErrorCode,
    status = 0,
    requestId?: string,
    retryable = false,
  ) {
    super(messageForErrorCode(code, status));
    this.name = "OpenPlatformFetchError";
    this.code = code;
    this.status = Number.isInteger(status) && status >= 100 && status <= 599 ? status : 0;
    this.requestId = safeRequestId(requestId);
    this.retryable = retryable;
    Object.setPrototypeOf(this, new.target.prototype);
  }

  toJSON(): { code: OpenPlatformClientErrorCode; status: number; message: string; retryable: boolean; requestId?: string } {
    return {
      code: this.code,
      status: this.status,
      message: this.message,
      retryable: this.retryable,
      ...(this.requestId === undefined ? {} : { requestId: this.requestId }),
    };
  }
}

export class OpenPlatformNetworkError extends OpenPlatformFetchError {
  constructor(status = 0, requestId?: string) {
    super("network_error", status, requestId, true);
    this.name = "OpenPlatformNetworkError";
  }
}

export const OpenPlatformClientError = OpenPlatformFetchError;
export const OpenPlatformApiError = OpenPlatformFetchError;
export const OpenPlatformHttpError = OpenPlatformFetchError;

export class OpenPlatformClient {
  readonly baseURL: string;
  readonly baseUrl: string;
  readonly tenantId?: string;
  readonly fetchImpl: OpenPlatformFetch;

  private readonly tokenSource: OpenPlatformTokenSource | undefined;
  private readonly defaultHeaders: Headers;
  private readonly basePath: string;

  constructor(options: OpenPlatformClientOptions) {
    if (!options || typeof options !== "object") {
      throw new OpenPlatformFetchError("configuration_error");
    }
    const base = resolveOpenPlatformBaseUrl(
      options.baseURL ?? options.baseUrl,
      options.apiPath ?? options.basePath,
      options.allowInsecureHttp === true,
    );
    this.baseURL = base;
    this.baseUrl = base;
    this.basePath = new URL(base).pathname.replace(/\/$/u, "");
    this.tenantId = normalizeTenant(options.tenantId ?? options.tenant ?? options.tenant_id);
    this.tokenSource = options.tokenProvider ?? options.accessTokenProvider ?? options.token ?? options.accessToken;
    const selectedFetch = options.fetch ?? options.fetcher ?? globalThis.fetch;
    if (typeof selectedFetch !== "function") throw new OpenPlatformFetchError("configuration_error");
    this.fetchImpl = selectedFetch.bind(globalThis) as OpenPlatformFetch;
    try {
      this.defaultHeaders = new Headers(options.defaultHeaders ?? options.headers);
    } catch {
      throw new OpenPlatformFetchError("configuration_error");
    }
  }

  get auditEvents() {
    const resource = { list: (query?: OpenPlatformListQuery) => this.listAuditEvents(query) };
    return { ...resource, events: resource };
  }

  get audit() {
    return this.auditEvents;
  }

  get webhooks() {
    const resource = { list: (query?: OpenPlatformListQuery) => this.listWebhooks(query) };
    return { ...resource, endpoints: resource };
  }

  get webhook() {
    return this.webhooks;
  }

  get marketplaceListings() {
    const resource = { list: (query?: OpenPlatformListQuery) => this.listMarketplaceListings(query) };
    return { ...resource, listings: resource };
  }

  get marketplace() {
    return this.marketplaceListings;
  }

  get listings() {
    return this.marketplaceListings;
  }

  get invoices() {
    const resource = { list: (query?: OpenPlatformListQuery) => this.listInvoices(query) };
    return { ...resource, billing: resource };
  }

  get billingInvoices() {
    return this.invoices;
  }

  get billing() {
    const resource = this.invoices;
    return { ...resource, invoices: resource };
  }

  get compliance() {
    const dataAssets = {
      list: (query?: OpenPlatformComplianceListQuery) => this.listComplianceDataAssets(query),
      get: (id: string) => this.getComplianceDataAsset(id),
    };
    const privacyRequests = {
      list: (query?: OpenPlatformComplianceListQuery) => this.listCompliancePrivacyRequests(query),
      get: (id: string) => this.getCompliancePrivacyRequest(id),
      getSla: (id: string, query?: OpenPlatformComplianceListQuery) => this.getCompliancePrivacyRequestSla(id, query),
    };
    return {
      dataAssets: { ...dataAssets, dataAsset: dataAssets },
      privacyRequests: { ...privacyRequests, privacyRequest: privacyRequests },
      report: {
        get: (query?: OpenPlatformComplianceReportQuery) => this.getComplianceReport(query),
      },
    };
  }

  get domainEvents() {
    const resource = {
      list: (query?: OpenPlatformDomainEventListQuery) => this.listDomainEvents(query),
      outbox: (query?: OpenPlatformDomainEventListQuery) => this.listDomainEvents(query),
      retry: (input?: OpenPlatformDomainEventRetryInput) => this.retryDomainEvents(input),
    };
    return { ...resource, events: resource };
  }

  get events() {
    return this.domainEvents;
  }

  get outbox() {
    return this.domainEvents;
  }

  async request<T>(path: string, options: OpenPlatformRequestOptions = {}): Promise<T> {
    const url = this.resolveUrl(path, options.query);
    const authenticated = options.authenticated !== false;
    const token = authenticated ? await resolveToken(options.token ?? this.tokenSource) : undefined;
    const tenant = normalizeTenant(options.tenantId ?? options.tenant ?? options.tenant_id ?? this.tenantId);
    const headers = this.createHeaders(options.headers, token, tenant, authenticated);
    const method = (options.method ?? "GET").toUpperCase();
    const body = serializeRequestBody(options.body);
    if (options.idempotencyKey !== undefined) {
      headers.set(OPEN_PLATFORM_IDEMPOTENCY_HEADER, normalizeOpenPlatformIdempotencyKey(options.idempotencyKey));
    }
    if (body !== undefined) headers.set("content-type", "application/json");
    let response: Response;
    try {
      response = await this.fetchImpl(url.toString(), {
        method,
        headers,
        cache: "no-store",
        credentials: "omit",
        redirect: "error",
        ...(body === undefined ? {} : { body }),
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      });
    } catch (error) {
      if (isAbortError(error)) throw new OpenPlatformFetchError("aborted");
      if (options.signal?.aborted) throw new OpenPlatformFetchError("aborted");
      throw new OpenPlatformNetworkError();
    }
    const parsedBody = await readResponseBody(response);
    if (!response.ok) {
      const parsed = parseErrorResponse(parsedBody, response);
      throw new OpenPlatformFetchError(parsed.code, response.status, parsed.requestId, parsed.retryable);
    }
    if (parsedBody === INVALID_RESPONSE) throw new OpenPlatformFetchError("invalid_response", response.status);
    return parsedBody as T;
  }

  async get<T>(path: string, options: OpenPlatformRequestOptions = {}): Promise<T> {
    const value = await this.request<unknown>(path, { ...options, method: "GET" });
    return unwrapPayload(value) as T;
  }

  listAuditEvents(query: OpenPlatformListQuery = {}): Promise<OpenPlatformPage<OpenPlatformAuditEvent>> {
    return this.requestPage("/audit-events", query);
  }

  getAuditEvents(query: OpenPlatformListQuery = {}): Promise<OpenPlatformPage<OpenPlatformAuditEvent>> {
    return this.listAuditEvents(query);
  }

  getAuditEvent(id: string): Promise<OpenPlatformAuditEvent> {
    return this.get(`/audit-events/${encodePathSegment(id, "auditEventId")}`);
  }

  listWebhooks(query: OpenPlatformListQuery = {}): Promise<OpenPlatformPage<OpenPlatformWebhookEndpoint>> {
    return this.requestPage("/webhooks", query);
  }

  listWebhookEndpoints(query: OpenPlatformListQuery = {}): Promise<OpenPlatformPage<OpenPlatformWebhookEndpoint>> {
    return this.listWebhooks(query);
  }

  getWebhooks(query: OpenPlatformListQuery = {}): Promise<OpenPlatformPage<OpenPlatformWebhookEndpoint>> {
    return this.listWebhooks(query);
  }

  getWebhook(id: string): Promise<OpenPlatformWebhookEndpoint> {
    return this.get(`/webhooks/${encodePathSegment(id, "webhookId")}`);
  }

  listMarketplaceListings(query: OpenPlatformListQuery = {}): Promise<OpenPlatformPage<OpenPlatformMarketplaceListing>> {
    return this.requestPage("/marketplace/listings", query);
  }

  listMarketplaceListing(query: OpenPlatformListQuery = {}): Promise<OpenPlatformPage<OpenPlatformMarketplaceListing>> {
    return this.listMarketplaceListings(query);
  }

  listMarketplace(query: OpenPlatformListQuery = {}): Promise<OpenPlatformPage<OpenPlatformMarketplaceListing>> {
    return this.listMarketplaceListings(query);
  }

  getMarketplaceListings(query: OpenPlatformListQuery = {}): Promise<OpenPlatformPage<OpenPlatformMarketplaceListing>> {
    return this.listMarketplaceListings(query);
  }

  getMarketplaceListing(id: string): Promise<OpenPlatformMarketplaceListing> {
    return this.get(`/marketplace/listings/${encodePathSegment(id, "listingId")}`);
  }

  listInvoices(query: OpenPlatformListQuery = {}): Promise<OpenPlatformPage<OpenPlatformInvoice>> {
    return this.requestPage("/billing/invoices", query);
  }

  listBillingInvoices(query: OpenPlatformListQuery = {}): Promise<OpenPlatformPage<OpenPlatformInvoice>> {
    return this.listInvoices(query);
  }

  listBillingInvoice(query: OpenPlatformListQuery = {}): Promise<OpenPlatformPage<OpenPlatformInvoice>> {
    return this.listInvoices(query);
  }

  listBilling(query: OpenPlatformListQuery = {}): Promise<OpenPlatformPage<OpenPlatformInvoice>> {
    return this.listInvoices(query);
  }

  getInvoices(query: OpenPlatformListQuery = {}): Promise<OpenPlatformPage<OpenPlatformInvoice>> {
    return this.listInvoices(query);
  }

  getInvoice(id: string): Promise<OpenPlatformInvoice> {
    return this.get(`/billing/invoices/${encodePathSegment(id, "invoiceId")}`);
  }

  listComplianceDataAssets(query: OpenPlatformComplianceListQuery = {}): Promise<OpenPlatformPage<OpenPlatformComplianceDataAsset>> {
    return this.requestPage("/compliance/data-assets", query);
  }

  listDataAssets(query: OpenPlatformComplianceListQuery = {}): Promise<OpenPlatformPage<OpenPlatformComplianceDataAsset>> {
    return this.listComplianceDataAssets(query);
  }

  getComplianceDataAssets(query: OpenPlatformComplianceListQuery = {}): Promise<OpenPlatformPage<OpenPlatformComplianceDataAsset>> {
    return this.listComplianceDataAssets(query);
  }

  getComplianceDataAsset(id: string): Promise<OpenPlatformComplianceDataAsset> {
    return this.get(`/compliance/data-assets/${encodePathSegment(id, "dataAssetId")}`);
  }

  getDataAsset(id: string): Promise<OpenPlatformComplianceDataAsset> {
    return this.getComplianceDataAsset(id);
  }

  listCompliancePrivacyRequests(query: OpenPlatformComplianceListQuery = {}): Promise<OpenPlatformPage<OpenPlatformCompliancePrivacyRequest>> {
    return this.requestPage("/compliance/privacy-requests", query);
  }

  listPrivacyRequests(query: OpenPlatformComplianceListQuery = {}): Promise<OpenPlatformPage<OpenPlatformCompliancePrivacyRequest>> {
    return this.listCompliancePrivacyRequests(query);
  }

  getCompliancePrivacyRequests(query: OpenPlatformComplianceListQuery = {}): Promise<OpenPlatformPage<OpenPlatformCompliancePrivacyRequest>> {
    return this.listCompliancePrivacyRequests(query);
  }

  getCompliancePrivacyRequest(id: string): Promise<OpenPlatformCompliancePrivacyRequest> {
    return this.get(`/compliance/privacy-requests/${encodePathSegment(id, "privacyRequestId")}`);
  }

  getPrivacyRequest(id: string): Promise<OpenPlatformCompliancePrivacyRequest> {
    return this.getCompliancePrivacyRequest(id);
  }

  getCompliancePrivacyRequestSla(
    id: string,
    query: OpenPlatformComplianceListQuery = {},
  ): Promise<OpenPlatformCompliancePrivacyRequestSla> {
    const { at, ...rest } = query as OpenPlatformComplianceListQuery & { readonly at?: string };
    return this.get(
      `/compliance/privacy-requests/${encodePathSegment(id, "privacyRequestId")}/sla`,
      {
        query: {
          ...(at === undefined ? {} : { at }),
          ...normalizeListQuery(rest),
        },
      },
    );
  }

  getPrivacyRequestSla(id: string, query: OpenPlatformComplianceListQuery = {}): Promise<OpenPlatformCompliancePrivacyRequestSla> {
    return this.getCompliancePrivacyRequestSla(id, query);
  }

  getComplianceReport(query: OpenPlatformComplianceReportQuery = {}): Promise<OpenPlatformComplianceReport> {
    return this.get(OPEN_PLATFORM_COMPLIANCE_REPORT_PATH, { query: normalizeReportQuery(query) });
  }

  getReport(query: OpenPlatformComplianceReportQuery = {}): Promise<OpenPlatformComplianceReport> {
    return this.getComplianceReport(query);
  }

  listDomainEvents(query: OpenPlatformDomainEventListQuery = {}): Promise<OpenPlatformPage<OpenPlatformDomainEventSummary>> {
    return this.requestPage(OPEN_PLATFORM_DOMAIN_EVENTS_PATH, query);
  }

  getDomainEvents(query: OpenPlatformDomainEventListQuery = {}): Promise<OpenPlatformPage<OpenPlatformDomainEventSummary>> {
    return this.listDomainEvents(query);
  }

  listOutboxEvents(query: OpenPlatformDomainEventListQuery = {}): Promise<OpenPlatformPage<OpenPlatformDomainEventSummary>> {
    return this.listDomainEvents(query);
  }

  async retryDomainEvents(input: OpenPlatformDomainEventRetryInput = {}): Promise<OpenPlatformDomainEventRetrySummary> {
    const body = normalizeRetryInput(input);
    const value = await this.request<unknown>(OPEN_PLATFORM_DOMAIN_EVENTS_RETRY_PATH, {
      method: "POST",
      body,
      idempotencyKey: input.idempotencyKey ?? createOpenPlatformIdempotencyKey("domain-event-retry"),
    });
    return normalizeRetrySummary(value);
  }

  retryOutboxEvents(input: OpenPlatformDomainEventRetryInput = {}): Promise<OpenPlatformDomainEventRetrySummary> {
    return this.retryDomainEvents(input);
  }

  private async requestPage<T>(path: string, query: OpenPlatformListQuery): Promise<OpenPlatformPage<T>> {
    const value = await this.request<unknown>(path, { query: normalizeListQuery(query) });
    return normalizePage<T>(value);
  }

  private resolveUrl(path: string, query: OpenPlatformRequestOptions["query"]): URL {
    if (typeof path !== "string" || !path.startsWith("/") || /[?#\u0000-\u001f\u007f\s]/u.test(path)) {
      throw new OpenPlatformFetchError("request_error");
    }
    const base = new URL(`${this.baseURL}/`);
    const url = new URL(path.replace(/^\/+/u, ""), base);
    if (url.origin !== base.origin || !isWithinBasePath(url.pathname, this.basePath)) {
      throw new OpenPlatformFetchError("request_error");
    }
    if (query !== undefined) appendQuery(url, query);
    return url;
  }

  private createHeaders(
    supplied: HeadersInit | undefined,
    token: string | undefined,
    tenantId: string | undefined,
    authenticated: boolean,
  ): Headers {
    try {
      const headers = new Headers(this.defaultHeaders);
      if (supplied !== undefined) {
        const suppliedHeaders = new Headers(supplied);
        suppliedHeaders.forEach((value, key) => headers.set(key, value));
      }
      if (!headers.has("accept")) headers.set("accept", "application/json");
      headers.set("cache-control", "no-store");
      if (authenticated && token !== undefined) headers.set("authorization", token);
      if (!authenticated || (authenticated && this.tokenSource !== undefined && token === undefined)) headers.delete("authorization");
      if (tenantId !== undefined) headers.set("x-tenant-id", tenantId);
      return headers;
    } catch {
      throw new OpenPlatformFetchError("request_error");
    }
  }
}

export const OpenPlatformFetchClient = OpenPlatformClient;
export const OpenPlatformOperationsClient = OpenPlatformClient;
export const OpenPlatformUIClient = OpenPlatformClient;

export const OPEN_PLATFORM_IDEMPOTENCY_HEADER = "Idempotency-Key";
export const OPEN_PLATFORM_COMPLIANCE_REPORT_PATH = "/compliance/report";
export const OPEN_PLATFORM_DOMAIN_EVENTS_PATH = "/domain-events";
export const OPEN_PLATFORM_DOMAIN_EVENTS_RETRY_PATH = "/domain-events/retry";

const MAX_IDEMPOTENCY_KEY_LENGTH = 128;
const SAFE_IDEMPOTENCY_PREFIX = /^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/;
const RETRY_BODY_KEYS = ["tenantId", "eventType", "limit"] as const;
const REPORT_QUERY_KEYS = ["from", "to", "generatedAt"] as const;

export function createOpenPlatformIdempotencyKey(prefix = "op"): string {
  const normalizedPrefix = normalizeIdempotencyPrefix(prefix);
  const key = `${normalizedPrefix}-${randomIdempotencySuffix()}`;
  if (key.length > MAX_IDEMPOTENCY_KEY_LENGTH) throw new OpenPlatformFetchError("configuration_error");
  return key;
}

export const createOpenPlatformIdempotencyHeader = createOpenPlatformIdempotencyKey;
export const newOpenPlatformIdempotencyKey = createOpenPlatformIdempotencyKey;

export function normalizeOpenPlatformIdempotencyKey(value: unknown): string {
  if (typeof value !== "string") throw new OpenPlatformFetchError("request_error");
  const normalized = value.trim();
  if (
    normalized.length < 1 ||
    normalized.length > MAX_IDEMPOTENCY_KEY_LENGTH ||
    /[\u0000-\u001f\u007f]/u.test(normalized) ||
    /(?:secret|password|private[-_]?key|authorization|cookie|bearer|vault:\/\/)/iu.test(normalized)
  ) {
    throw new OpenPlatformFetchError("request_error");
  }
  return normalized;
}

export function assertOpenPlatformIdempotencyKey(value: unknown): string {
  return normalizeOpenPlatformIdempotencyKey(value);
}

export function normalizeOpenPlatformPage<T>(value: unknown): OpenPlatformPage<T> {
  return normalizePage<T>(value);
}

export function normalizeOpenPlatformPageQuery(query: OpenPlatformListQuery = {}): Record<string, string> {
  const normalized = normalizeListQuery(query);
  const output: Record<string, string> = {};
  for (const [key, item] of Object.entries(normalized)) {
    if (item === undefined || item === null) continue;
    output[key] = String(item);
  }
  return output;
}

export function createOpenPlatformClient(options: OpenPlatformClientOptions): OpenPlatformClient {
  return new OpenPlatformClient(options);
}

export const createOpenPlatformFetchClient = createOpenPlatformClient;
export const createOpenPlatformOperationsClient = createOpenPlatformClient;
export const createOpenPlatformOperationsFetchClient = createOpenPlatformClient;
export const createOpenPlatformBrowserClient = createOpenPlatformClient;
export const createOperationsClient = createOpenPlatformClient;
export const createOpenPlatformUIClient = createOpenPlatformClient;

export function resolveOpenPlatformBaseUrl(
  baseURL: string | URL | undefined,
  apiPath?: string | false,
  allowInsecureHttp = false,
): string {
  if (typeof baseURL !== "string" && !(baseURL instanceof URL)) throw new OpenPlatformFetchError("configuration_error");
  const normalized = (baseURL instanceof URL ? baseURL.toString() : baseURL).trim();
  if (normalized.length === 0 || /[\u0000-\u001f\u007f\s]/u.test(normalized)) {
    throw new OpenPlatformFetchError("configuration_error");
  }
  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    throw new OpenPlatformFetchError("configuration_error");
  }
  if (
    (parsed.protocol !== "http:" && parsed.protocol !== "https:") ||
    !parsed.hostname ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash ||
    (parsed.protocol === "http:" && !allowInsecureHttp && !isLoopbackBrowserHost(parsed.hostname))
  ) {
    throw new OpenPlatformFetchError("configuration_error");
  }
  const suppliedPath = normalizePath(parsed.pathname);
  let finalPath = suppliedPath;
  if (apiPath === false) {
    finalPath = suppliedPath;
  } else if (apiPath !== undefined) {
    const requestedPath = normalizePath(apiPath);
    finalPath = suppliedPath.endsWith(requestedPath) ? suppliedPath : joinPaths(suppliedPath, requestedPath);
  } else if (suppliedPath.length === 0) {
    finalPath = "/api/open/v1";
  }
  parsed.pathname = finalPath.length === 0 ? "/" : finalPath;
  return parsed.toString().replace(/\/$/u, "");
}

const INVALID_RESPONSE = Symbol("open-platform-invalid-response");

function normalizeListQuery(query: OpenPlatformListQuery): Record<string, unknown> {
  if (!query || typeof query !== "object") throw new OpenPlatformFetchError("request_error");
  const output: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === "") continue;
    if (key === "tenantId" || key === "tenant_id" || key === "pageSize" || key === "page_size") continue;
    if (!/^[A-Za-z][A-Za-z0-9_.-]{0,127}$/u.test(key) || isSensitiveQueryKey(key)) {
      throw new OpenPlatformFetchError("request_error");
    }
    output[key] = value;
  }
  const limit = query.limit ?? query.pageSize ?? query.page_size;
  if (limit !== undefined) {
    const normalized = typeof limit === "number" ? String(limit) : typeof limit === "string" ? limit.trim() : "";
    if (!/^[1-9][0-9]{0,2}$/u.test(normalized) || Number(normalized) > 100) {
      throw new OpenPlatformFetchError("request_error");
    }
    output.limit = normalized;
  }
  if (query.cursor !== undefined) output.cursor = safeCursor(query.cursor);
  if (query.sequence !== undefined) output.sequence = safeSequence(query.sequence);
  return output;
}

function normalizeReportQuery(query: OpenPlatformComplianceReportQuery): Record<string, unknown> {
  if (!query || typeof query !== "object") throw new OpenPlatformFetchError("request_error");
  for (const key of Object.keys(query)) {
    if (key === "tenantId" || key === "tenant_id") continue;
    if (!(REPORT_QUERY_KEYS as readonly string[]).includes(key)) {
      throw new OpenPlatformFetchError("request_error");
    }
  }
  const output: Record<string, unknown> = {};
  for (const key of REPORT_QUERY_KEYS) {
    const value = (query as Record<string, unknown>)[key];
    if (value === undefined || value === null || value === "") continue;
    const normalized = typeof value === "string" ? value.trim() : "";
    if (normalized.length === 0 || normalized.length > 64 || /[\u0000-\u001f\u007f\s]/u.test(normalized)) {
      throw new OpenPlatformFetchError("request_error");
    }
    output[key] = normalized;
  }
  return output;
}

function normalizeRetryInput(input: OpenPlatformDomainEventRetryInput): Record<string, unknown> {
  if (!input || typeof input !== "object") throw new OpenPlatformFetchError("request_error");
  for (const key of Object.keys(input)) {
    if (key === "idempotencyKey") continue;
    if (!(RETRY_BODY_KEYS as readonly string[]).includes(key)) throw new OpenPlatformFetchError("request_error");
  }
  const output: Record<string, unknown> = {};
  const eventType = input.eventType;
  if (eventType !== undefined && eventType !== null && eventType !== "") {
    const normalized = getSafeToken(eventType, "eventType");
    if (normalized === undefined || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(normalized)) {
      throw new OpenPlatformFetchError("request_error");
    }
    output.eventType = normalized;
  }
  const limit = input.limit;
  if (limit !== undefined && limit !== null) {
    if (typeof limit !== "number" || !Number.isInteger(limit) || limit < 1 || limit > 100) {
      throw new OpenPlatformFetchError("request_error");
    }
    output.limit = limit;
  }
  const tenantId = normalizeTenant(input.tenantId);
  if (tenantId !== undefined) output.tenantId = tenantId;
  return output;
}

function normalizeRetrySummary(value: unknown): OpenPlatformDomainEventRetrySummary {
  const source = isRecord(value) && isRecord(value.data) ? value.data : value;
  if (!isRecord(source)) throw new OpenPlatformFetchError("invalid_response");
  const rawResults = Array.isArray(source.results) ? source.results : [];
  return {
    flushed: safeCount(source.flushed ?? rawResults.length),
    replayed: source.replayed === true,
    results: rawResults.filter(isRecord).map((entry) => ({
      eventId: getSafeToken(entry.eventId, "eventId") ?? "unknown",
      delivered: safeCount(entry.delivered),
      deadLettered: entry.deadLettered === true,
    })),
  };
}

function serializeRequestBody(body: unknown): string | undefined {
  if (body === undefined) return undefined;
  if (typeof body === "string") return body;
  if (!isRecord(body)) throw new OpenPlatformFetchError("request_error");
  let serialized: string | undefined;
  try {
    serialized = JSON.stringify(body);
  } catch {
    throw new OpenPlatformFetchError("request_error");
  }
  if (serialized === undefined || serialized.length > 32_768) throw new OpenPlatformFetchError("request_error");
  return serialized;
}

function normalizeIdempotencyPrefix(value: unknown): string {
  if (typeof value !== "string") throw new OpenPlatformFetchError("configuration_error");
  const normalized = value.trim();
  if (!SAFE_IDEMPOTENCY_PREFIX.test(normalized)) throw new OpenPlatformFetchError("configuration_error");
  return normalized;
}

function randomIdempotencySuffix(): string {
  const cryptoRef = globalThis.crypto as Crypto | undefined;
  if (cryptoRef !== undefined && typeof cryptoRef.randomUUID === "function") return cryptoRef.randomUUID();
  if (cryptoRef !== undefined && typeof cryptoRef.getRandomValues === "function") {
    const bytes = cryptoRef.getRandomValues(new Uint8Array(16));
    return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  }
  return `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 14)}`;
}

function safeSequence(value: unknown): string {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return String(value);
  if (typeof value !== "string") throw new OpenPlatformFetchError("request_error");
  const normalized = value.trim();
  if (!/^(?:0|[1-9][0-9]*)$/u.test(normalized)) throw new OpenPlatformFetchError("request_error");
  return normalized;
}

function getSafeToken(value: unknown, field: string): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string" && typeof value !== "number") throw new OpenPlatformFetchError("request_error", 0);
  const normalized = String(value).trim();
  if (normalized.length === 0) return undefined;
  if (
    normalized.length > 512 ||
    /[\s\u0000-\u001f\u007f]/u.test(normalized) ||
    /(?:secret|password|private[-_]?key|authorization|cookie|bearer|vault:\/\/)/iu.test(normalized)
  ) {
    throw new OpenPlatformFetchError("request_error", 0);
  }
  return field.length > 0 ? normalized : undefined;
}

function safeCount(value: unknown): number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : 0;
}

function unwrapPayload(value: unknown): unknown {
  if (!isRecord(value) || !Object.prototype.hasOwnProperty.call(value, "data")) return value;
  const allowed = new Set(["data", "requestId", "meta", "success", "ok"]);
  return Object.keys(value).every((key) => allowed.has(key)) ? value.data : value;
}

function normalizePage<T>(value: unknown): OpenPlatformPage<T> {
  const source = pageSource(value);
  const rawItems = Array.isArray(source)
    ? source
    : isRecord(source) && Array.isArray(source.items)
      ? source.items
      : isRecord(source) && Array.isArray(source.data)
        ? source.data
        : isRecord(source) && isRecord(source.data) && Array.isArray(source.data.items)
          ? source.data.items
          : undefined;
  if (rawItems === undefined) throw new OpenPlatformFetchError("invalid_response");
  const record = isRecord(source) ? source : {};
  const nextSequence = safeResponseSequence(record.nextSequence ?? record.next_sequence);
  const previousSequence = safeResponseSequence(record.previousSequence ?? record.previous_sequence);
  const nextCursor = safeOptionalCursor(record.nextCursor ?? record.next_cursor) ??
    (nextSequence === undefined ? undefined : String(nextSequence));
  const previousCursor = safeOptionalCursor(record.previousCursor ?? record.previous_cursor) ??
    (previousSequence === undefined ? undefined : String(previousSequence));
  const hasMore = typeof record.hasMore === "boolean"
    ? record.hasMore
    : typeof record.has_more === "boolean"
      ? record.has_more
      : nextCursor !== undefined;
  const total = typeof record.total === "number" && Number.isFinite(record.total) && record.total >= 0
    ? record.total
    : undefined;
  return {
    items: [...rawItems] as T[],
    ...(nextCursor === undefined ? {} : { nextCursor }),
    ...(previousCursor === undefined ? {} : { previousCursor }),
    ...(nextSequence === undefined ? {} : { nextSequence }),
    ...(previousSequence === undefined ? {} : { previousSequence }),
    hasMore,
    ...(total === undefined ? {} : { total }),
  };
}

function pageSource(value: unknown): unknown {
  if (isRecord(value) && isRecord(value.data) && (Array.isArray(value.data.items) || Array.isArray(value.data.data))) return value.data;
  if (isRecord(value) && isRecord(value.result) && (Array.isArray(value.result.items) || Array.isArray(value.result.data))) return value.result;
  return value;
}

async function resolveToken(source: OpenPlatformTokenSource | undefined): Promise<string | undefined> {
  if (source === undefined) return undefined;
  try {
    let value: OpenPlatformTokenResult;
    if (typeof source === "string" || typeof source === "object" && source !== null && ("accessToken" in source || "token" in source)) {
      value = source as OpenPlatformTokenResult;
    } else if (typeof source === "function") {
      value = await source();
    } else if (typeof source === "object" && "getToken" in source && typeof source.getToken === "function") {
      value = await source.getToken();
    } else if (typeof source === "object" && "getAccessToken" in source && typeof source.getAccessToken === "function") {
      value = await source.getAccessToken();
    } else {
      return undefined;
    }
    if (value === undefined || value === null) return undefined;
    if (typeof value === "string") return formatToken(value, "Bearer");
    if (typeof value !== "object") return undefined;
    return formatToken(value.accessToken ?? value.token, value.tokenType ?? "Bearer");
  } catch {
    throw new OpenPlatformFetchError("request_error");
  }
}

function formatToken(value: unknown, type: string): string {
  if (typeof value !== "string") throw new OpenPlatformFetchError("request_error");
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 16_384 || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new OpenPlatformFetchError("request_error");
  }
  if (/^Bearer\s+\S+$/iu.test(normalized)) return normalized;
  if (!/^[A-Za-z][A-Za-z0-9._-]{0,31}$/u.test(type)) throw new OpenPlatformFetchError("request_error");
  return `${type} ${normalized}`;
}

function appendQuery(url: URL, query: Record<string, unknown> | URLSearchParams): void {
  const params = new URLSearchParams();
  if (query instanceof URLSearchParams) {
    query.forEach((value, key) => appendQueryValue(params, key, value));
  } else {
    for (const [key, value] of Object.entries(query)) appendQueryValue(params, key, value);
  }
  const serialized = params.toString();
  if (serialized.length > 0) url.search = serialized;
}

function appendQueryValue(params: URLSearchParams, key: string, value: unknown): void {
  if (!/^[A-Za-z][A-Za-z0-9_.-]{0,127}$/u.test(key) || isSensitiveQueryKey(key)) {
    throw new OpenPlatformFetchError("request_error");
  }
  if (value === undefined || value === null) return;
  if (Array.isArray(value)) {
    for (const item of value) appendQueryValue(params, key, item);
    return;
  }
  if (typeof value === "object") throw new OpenPlatformFetchError("request_error");
  const normalized = typeof value === "string" ? value : String(value);
  if (normalized.length > 2048 || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new OpenPlatformFetchError("request_error");
  }
  const normalizedKey = key.replace(/[-_]/gu, "").toLowerCase();
  if (normalizedKey === "limit" && (!/^[1-9][0-9]{0,2}$/u.test(normalized) || Number(normalized) > 100)) {
    throw new OpenPlatformFetchError("request_error");
  }
  if (normalizedKey === "cursor") safeCursor(normalized);
  params.append(key, normalized);
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

function readResponseBody(response: Response): Promise<unknown> {
  if (response.status === 204) return Promise.resolve(undefined);
  return response.text().then((text) => {
    const normalized = text.replace(/^\uFEFF/u, "").trim();
    if (normalized.length === 0) return undefined;
    try {
      return JSON.parse(normalized) as unknown;
    } catch {
      return INVALID_RESPONSE;
    }
  }).catch(() => INVALID_RESPONSE);
}

function parseErrorResponse(value: unknown, response: Response): {
  code: OpenPlatformClientErrorCode;
  requestId?: string;
  retryable: boolean;
} {
  const record = isRecord(value) ? value : {};
  const envelope = isRecord(record.error) ? record.error : {};
  const codeValue = envelope.code ?? record.code ?? record.errorCode;
  const status = response.status;
  const mapped = mapErrorCode(codeValue, status);
  const requestId = safeRequestId(record.requestId ?? envelope.requestId ?? response.headers.get("x-request-id"));
  const retryable = typeof envelope.retryable === "boolean"
    ? envelope.retryable
    : typeof record.retryable === "boolean"
      ? record.retryable
      : status === 408 || status === 425 || status === 429 || status >= 500;
  return { code: mapped, requestId, retryable };
}

function mapErrorCode(value: unknown, status: number): OpenPlatformClientErrorCode {
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase().replace(/[\s-]+/gu, "_");
    const known: Record<string, OpenPlatformClientErrorCode> = {
      invalid_argument: "request_error",
      invalid_status: "request_error",
      invalid_slug: "request_error",
      invalid_scope: "request_error",
      invalid_redirect_uri: "request_error",
      invalid_client_configuration: "request_error",
      invalid_state_transition: "conflict",
      tenant_mismatch: "forbidden",
      credential_exposed: "request_error",
      not_found: "not_found",
      conflict: "conflict",
      rate_limited: "rate_limited",
      temporarily_unavailable: "service_unavailable",
      service_unavailable: "service_unavailable",
      internal_error: "internal_error",
      unauthorized: "unauthorized",
      forbidden: "forbidden",
    };
    if (known[normalized]) return known[normalized];
  }
  if (status === 401) return "unauthorized";
  if (status === 403) return "forbidden";
  if (status === 404) return "not_found";
  if (status === 409) return "conflict";
  if (status === 429) return "rate_limited";
  if (status === 408) return "timeout";
  if (status >= 500) return "service_unavailable";
  if (status >= 400) return "request_error";
  return "unknown";
}

function messageForErrorCode(code: OpenPlatformClientErrorCode, status: number): string {
  switch (code) {
    case "unauthorized":
      return "Please sign in and try again.";
    case "forbidden":
      return "You do not have permission to view this.";
    case "not_found":
      return "The requested resource was not found.";
    case "conflict":
      return "The resource changed. Refresh and try again.";
    case "rate_limited":
      return "Too many requests. Please try again later.";
    case "network_error":
      return "Unable to reach the service. Check your connection and try again.";
    case "timeout":
      return "The request timed out. Please try again.";
    case "service_unavailable":
    case "internal_error":
      return "The service is temporarily unavailable.";
    case "configuration_error":
    case "request_error":
    case "invalid_response":
    case "aborted":
    case "unknown":
      return "Something went wrong.";
  }
}

function normalizeTenant(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 256 || /[\u0000-\u001f\u007f\s]/u.test(normalized)) {
    throw new OpenPlatformFetchError("configuration_error");
  }
  return normalized;
}

function normalizePath(value: string): string {
  if (typeof value !== "string" || /[?#\u0000-\u001f\u007f\s]/u.test(value)) {
    throw new OpenPlatformFetchError("configuration_error");
  }
  const normalized = value.replace(/\/+$/u, "");
  if (normalized.length > 1 && !normalized.startsWith("/")) throw new OpenPlatformFetchError("configuration_error");
  return normalized === "/" ? "" : normalized;
}

function joinPaths(left: string, right: string): string {
  if (left.length === 0) return right;
  if (right.length === 0) return left;
  return `${left}/${right.replace(/^\/+/u, "")}`;
}

function safeCursor(value: unknown): string {
  if (typeof value !== "string") throw new OpenPlatformFetchError("request_error");
  const normalized = value.trim();
  if (normalized.length < 1 || normalized.length > 2048 || /[\s\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new OpenPlatformFetchError("request_error");
  }
  return normalized;
}

function safeOptionalCursor(value: unknown): string | undefined {
  return value === undefined || value === null ? undefined : safeCursor(value);
}

function safeResponseSequence(value: unknown): number | undefined {
  if (typeof value === "number") {
    return Number.isSafeInteger(value) && value >= 0 ? value : undefined;
  }
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  return /^(?:0|[1-9][0-9]*)$/u.test(normalized) ? Number(normalized) : undefined;
}

function encodePathSegment(value: unknown, field: string): string {
  if (typeof value !== "string") throw new OpenPlatformFetchError("request_error", 0);
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 512 || /[\s\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new OpenPlatformFetchError("request_error", 0);
  }
  return encodeURIComponent(normalized);
}

function safeRequestId(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  if (
    normalized.length === 0 ||
    normalized.length > 128 ||
    /[\s\u0000-\u001f\u007f]/u.test(normalized) ||
    /(?:secret|token|password|private[-_]?key|credential|authorization|cookie|vault:\/\/)/iu.test(normalized)
  ) return undefined;
  return normalized;
}

function isLoopbackBrowserHost(hostname: string): boolean {
  const normalized = hostname.trim().toLowerCase().replace(/^\[|\]$/gu, "");
  return normalized === "localhost" ||
    normalized === "::1" ||
    /^127(?:\.[0-9]{1,3}){3}$/u.test(normalized);
}

function isWithinBasePath(pathname: string, basePath: string): boolean {
  return basePath.length === 0 || pathname === basePath || pathname.startsWith(`${basePath}/`);
}

function isAbortError(value: unknown): boolean {
  return isRecord(value) && value.name === "AbortError";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
