export interface OpenPlatformErrorOptions {
  code?: string;
  status?: number;
  retryable?: boolean;
  requestId?: string;
  field?: string;
  issues?: readonly OpenPlatformErrorIssue[];
  retryAfterMs?: number;
}

export interface OpenPlatformErrorIssue {
  readonly code: string;
  readonly field?: string;
}

export interface OpenPlatformApiErrorOptions extends OpenPlatformErrorOptions {
  code: string;
  status: number;
}

export class OpenPlatformError extends Error {
  readonly code: string;
  readonly status: number;
  readonly statusCode: number;
  readonly retryable: boolean;
  readonly requestId: string | undefined;
  readonly field: string | undefined;
  readonly issues: readonly OpenPlatformErrorIssue[] | undefined;
  readonly retryAfterMs: number | undefined;

  constructor(message: string, options: OpenPlatformErrorOptions = {}) {
    super(message);
    this.name = "OpenPlatformError";
    this.code = options.code ?? "OPEN_PLATFORM_ERROR";
    this.status = options.status ?? 0;
    this.statusCode = this.status;
    this.retryable = options.retryable ?? false;
    this.requestId = safeRequestId(options.requestId);
    this.field = safeField(options.field);
    this.issues = safeIssues(options.issues);
    this.retryAfterMs = safeRetryAfter(options.retryAfterMs);
    Object.setPrototypeOf(this, new.target.prototype);
  }

  toJSON(): {
    code: string;
    status: number;
    retryable: boolean;
    message: string;
    requestId?: string;
    field?: string;
    issues?: readonly OpenPlatformErrorIssue[];
  } {
    return {
      code: this.code,
      status: this.status,
      retryable: this.retryable,
      message: this.message,
      ...(this.requestId === undefined ? {} : { requestId: this.requestId }),
      ...(this.field === undefined ? {} : { field: this.field }),
      ...(this.issues === undefined ? {} : { issues: this.issues }),
    };
  }
}

export class OpenPlatformApiError extends OpenPlatformError {
  constructor(options: OpenPlatformApiErrorOptions) {
    super(safeHttpMessage(options.status, options.code), options);
    this.name = "OpenPlatformApiError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class OpenPlatformNetworkError extends OpenPlatformError {
  constructor() {
    super("Open platform network request failed", {
      code: "NETWORK_ERROR",
      status: 0,
      retryable: true,
    });
    this.name = "OpenPlatformNetworkError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class OpenPlatformTimeoutError extends OpenPlatformError {
  constructor() {
    super("Open platform request timed out", {
      code: "TIMEOUT",
      status: 0,
      retryable: true,
    });
    this.name = "OpenPlatformTimeoutError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class OpenPlatformAbortError extends OpenPlatformError {
  constructor() {
    super("Open platform request was aborted", {
      code: "ABORTED",
      status: 0,
      retryable: false,
    });
    this.name = "AbortError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class OpenPlatformProtocolError extends OpenPlatformError {
  constructor() {
    super("Open platform returned an invalid response", {
      code: "INVALID_RESPONSE",
      status: 0,
      retryable: false,
    });
    this.name = "OpenPlatformProtocolError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class OpenPlatformConfigurationError extends OpenPlatformError {
  constructor() {
    super("Open platform SDK configuration is invalid", {
      code: "CONFIGURATION_ERROR",
      status: 0,
      retryable: false,
    });
    this.name = "OpenPlatformConfigurationError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class OpenPlatformRequestError extends OpenPlatformError {
  constructor() {
    super("Open platform request is invalid", {
      code: "INVALID_REQUEST",
      status: 0,
      retryable: false,
    });
    this.name = "OpenPlatformRequestError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class OpenPlatformAuthenticationProviderError extends OpenPlatformError {
  constructor() {
    super("Open platform authentication provider failed", {
      code: "AUTHENTICATION_PROVIDER_ERROR",
      status: 0,
      retryable: false,
    });
    this.name = "OpenPlatformAuthenticationProviderError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export { OpenPlatformApiError as OpenPlatformHttpError };
export { OpenPlatformRequestError as OpenPlatformInvalidRequestError };
export { OpenPlatformAuthenticationProviderError as OpenPlatformAuthProviderError };

export function isOpenPlatformError(value: unknown): value is OpenPlatformError {
  return value instanceof OpenPlatformError;
}

export function isOpenPlatformApiError(value: unknown): value is OpenPlatformApiError {
  return value instanceof OpenPlatformApiError;
}

export function parseOpenPlatformErrorResponse(
  body: unknown,
  statusOrResponse: number | { readonly status?: unknown; readonly headers?: { get(name: string): string | null } },
  headers?: { get(name: string): string | null },
  retryAfterMs?: number,
  sensitiveValues: readonly string[] = [],
): OpenPlatformApiError {
  const responseRecord = isRecord(statusOrResponse) ? statusOrResponse : undefined;
  const status = normalizeStatus(
    typeof statusOrResponse === "number" ? statusOrResponse : responseRecord?.status,
  );
  const responseHeaders = headers ?? responseRecord?.headers;
  const root = isRecord(body) ? body : {};
  const nested = isRecord(root.error) ? root.error : root;
  const code = safeCode(nested.code, sensitiveValues) ??
    safeCode(root.code, sensitiveValues) ??
    safeCode(typeof root.error === "string" ? root.error : undefined, sensitiveValues) ??
    `HTTP_${status}`;
  const candidateRetryable = typeof nested.retryable === "boolean"
    ? nested.retryable
    : typeof root.retryable === "boolean"
      ? root.retryable
      : isRetryableStatus(status, code);
  const requestId = safeRequestId(root.requestId, sensitiveValues) ??
    safeRequestId(nested.requestId, sensitiveValues) ??
    safeRequestId(responseHeaders?.get("x-request-id"), sensitiveValues);
  const field = safeField(nested.field, sensitiveValues) ?? safeField(root.field, sensitiveValues);
  const issues = safeIssues(nested.issues, sensitiveValues) ?? safeIssues(root.issues, sensitiveValues);
  return new OpenPlatformApiError({
    code,
    status,
    retryable: candidateRetryable,
    requestId,
    field,
    issues,
    retryAfterMs: retryAfterMs ?? parseRetryAfter(responseHeaders?.get("retry-after")),
  });
}

export const parseOpenPlatformError = parseOpenPlatformErrorResponse;

export function safeHttpMessage(status: number, code: string): string {
  const normalizedCode = code.toUpperCase();
  if (
    normalizedCode.includes("AUTHENTICATION") ||
    normalizedCode === "UNAUTHENTICATED" ||
    status === 401
  ) {
    return "Authentication is required";
  }
  if (
    normalizedCode.includes("FORBIDDEN") ||
    normalizedCode.includes("TENANT_MISMATCH") ||
    status === 403
  ) {
    return "Access is forbidden";
  }
  if (normalizedCode.includes("NOT_FOUND") || status === 404) {
    return "The requested resource was not found";
  }
  if (normalizedCode.includes("RATE_LIMITED") || status === 429) {
    return "The request rate limit was exceeded";
  }
  if (normalizedCode.includes("CREDENTIAL_UNAVAILABLE") || status === 423) {
    return "Credential is unavailable";
  }
  if (status === 408 || normalizedCode.includes("TIMEOUT")) {
    return "The request timed out";
  }
  if (status >= 500) {
    return "The open platform service is temporarily unavailable";
  }
  if (status === 409 || normalizedCode.includes("CONFLICT")) {
    return "The request conflicts with the current resource state";
  }
  if (status >= 400) {
    return "The open platform request is invalid";
  }
  return "Open platform request failed";
}

export function isRetryableStatus(status: number, code?: string): boolean {
  if (status === 408 || status === 425 || status === 429) return true;
  if (status >= 500 && status <= 599) return true;
  if (code === undefined) return false;
  const normalized = code.toUpperCase();
  return normalized.includes("TEMPORARILY_UNAVAILABLE") ||
    normalized.includes("RATE_LIMITED") ||
    normalized.includes("INTERNAL_ERROR");
}

function normalizeStatus(value: unknown): number {
  return typeof value === "number" && Number.isInteger(value) && value >= 100 && value <= 599
    ? value
    : 500;
}

function safeCode(value: unknown, sensitiveValues: readonly string[] = []): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  if (containsSensitiveValue(normalized, sensitiveValues)) return undefined;
  if (/(?:^|[_-])(?:sk|pk|ghp|xox)[_-]/iu.test(normalized)) return undefined;
  return /^[A-Z][A-Z0-9_.:-]{0,127}$/u.test(normalized) ? normalized : undefined;
}

function safeRequestId(value: unknown, sensitiveValues: readonly string[] = []): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  if (
    normalized.length < 1 ||
    normalized.length > 128 ||
    /[\s\u0000-\u001f\u007f]/u.test(normalized) ||
    /(?:secret|password|private[-_]?key|authorization|cookie|bearer|vault:\/\/|(?:^|[_-])(?:sk|pk|ghp|xox)[_-])/iu.test(normalized) ||
    containsSensitiveValue(normalized, sensitiveValues)
  ) {
    return undefined;
  }
  return normalized;
}

function safeField(value: unknown, sensitiveValues: readonly string[] = []): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  if (
    normalized.length === 0 ||
    normalized.length > 256 ||
    !/^[A-Za-z0-9_.[\]-]+$/u.test(normalized) ||
    /(?:secret|token|password|authorization|private[-_]?key|bearer)/iu.test(normalized) ||
    containsSensitiveValue(normalized, sensitiveValues)
  ) {
    return undefined;
  }
  return normalized;
}

function safeIssues(
  value: unknown,
  sensitiveValues: readonly string[] = [],
): readonly OpenPlatformErrorIssue[] | undefined {
  if (!Array.isArray(value) || value.length === 0 || value.length > 20) return undefined;
  const issues: OpenPlatformErrorIssue[] = [];
  for (const item of value) {
    if (!isRecord(item)) continue;
    const code = safeCode(item.code, sensitiveValues);
    if (code === undefined) continue;
    const field = safeField(item.field, sensitiveValues);
    issues.push({ code, ...(field === undefined ? {} : { field }) });
  }
  return issues.length === 0 ? undefined : issues;
}

function safeRetryAfter(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) && value >= 0
    ? Math.min(Math.floor(value), 86_400_000)
    : undefined;
}

function parseRetryAfter(value: string | null | undefined): number | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  if (normalized.length === 0) return undefined;
  const seconds = Number(normalized);
  if (Number.isFinite(seconds) && seconds >= 0) return Math.min(Math.floor(seconds * 1000), 86_400_000);
  const timestamp = Date.parse(normalized);
  if (!Number.isFinite(timestamp)) return undefined;
  return Math.min(Math.max(timestamp - Date.now(), 0), 86_400_000);
}

function containsSensitiveValue(value: string, sensitiveValues: readonly string[]): boolean {
  return sensitiveValues.some((sensitiveValue) => {
    if (typeof sensitiveValue !== "string" || sensitiveValue.length === 0) return false;
    if (value === sensitiveValue) return true;
    return sensitiveValue.length >= 8 && value.includes(sensitiveValue);
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
