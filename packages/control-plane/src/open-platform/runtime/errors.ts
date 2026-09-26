import {
  OPEN_PLATFORM_ERROR_CODES as DOMAIN_ERROR_CODES,
  isOpenPlatformDomainError,
} from "../errors.js";
import type { OpenPlatformRuntimeMode } from "../types.js";
import type { OpenPlatformApiRequestContext } from "./types.js";

export const OPEN_PLATFORM_RUNTIME_ERROR_CODES = Object.freeze({
  INVALID_REQUEST: "invalid_request",
  CONFIGURATION_ERROR: "configuration_error",
  AUTHENTICATION_REQUIRED: "authentication_required",
  CREDENTIAL_INVALID: "credential_invalid",
  CREDENTIAL_EXPIRED: "credential_expired",
  CREDENTIAL_REVOKED: "credential_revoked",
  CREDENTIAL_INACTIVE: "credential_inactive",
  CREDENTIAL_VERSION_MISMATCH: "credential_version_mismatch",
  CREDENTIAL_VERIFIER_UNAVAILABLE: "credential_verifier_unavailable",
  TENANT_MISMATCH: "tenant_mismatch",
  APPLICATION_MISMATCH: "application_mismatch",
  CLIENT_NOT_ALLOWED: "client_not_allowed",
  PARENT_RESOURCE_DISABLED: "parent_resource_disabled",
  INVALID_AUDIENCE: "invalid_audience",
  INVALID_SCOPE: "invalid_scope",
  SCOPE_GRANT_INVALID: "scope_grant_invalid",
  ROUTE_NOT_ALLOWED: "route_not_allowed",
  POLICY_DENIED: "policy_denied",
  POLICY_UNAVAILABLE: "policy_unavailable",
  RATE_LIMIT_EXCEEDED: "rate_limit_exceeded",
  QUOTA_EXCEEDED: "quota_exceeded",
  RATE_LIMITER_UNAVAILABLE: "rate_limiter_unavailable",
  AUDIT_UNAVAILABLE: "audit_unavailable",
  SERVICE_UNAVAILABLE: "service_unavailable",
  INTERNAL_ERROR: "internal_error",
} as const);

export type OpenPlatformRuntimeErrorCode =
  (typeof OPEN_PLATFORM_RUNTIME_ERROR_CODES)[keyof typeof OPEN_PLATFORM_RUNTIME_ERROR_CODES];

export type OpenPlatformRuntimeErrorDetails = Readonly<
  Record<string, string | number | boolean>
>;

export interface OpenPlatformRuntimeErrorOptions {
  readonly requestId?: string;
  readonly retryAfterSeconds?: number;
  readonly details?: Readonly<Record<string, unknown>>;
}

export interface OpenPlatformRuntimeErrorBody {
  readonly error: {
    readonly code: OpenPlatformRuntimeErrorCode;
    readonly message: string;
    readonly retryable: boolean;
    readonly retryAfter?: number;
    readonly details?: OpenPlatformRuntimeErrorDetails;
  };
  readonly requestId?: string;
}

export interface OpenPlatformRuntimeContractError {
  readonly statusCode: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: OpenPlatformRuntimeErrorBody;
}

interface RuntimeErrorDefinition {
  readonly statusCode: number;
  readonly message: string;
  readonly retryable: boolean;
}

const DEFINITIONS = Object.freeze({
  invalid_request: {
    statusCode: 400,
    message: "The API request is invalid.",
    retryable: false,
  },
  configuration_error: {
    statusCode: 500,
    message: "The API runtime is not configured correctly.",
    retryable: false,
  },
  authentication_required: {
    statusCode: 401,
    message: "Authentication is required.",
    retryable: false,
  },
  credential_invalid: {
    statusCode: 401,
    message: "The API credential is invalid.",
    retryable: false,
  },
  credential_expired: {
    statusCode: 401,
    message: "The API credential has expired.",
    retryable: false,
  },
  credential_revoked: {
    statusCode: 401,
    message: "The API credential has been revoked.",
    retryable: false,
  },
  credential_inactive: {
    statusCode: 401,
    message: "The API credential is not active.",
    retryable: false,
  },
  credential_version_mismatch: {
    statusCode: 409,
    message: "The API credential version is stale.",
    retryable: false,
  },
  credential_verifier_unavailable: {
    statusCode: 503,
    message: "Credential verification is temporarily unavailable.",
    retryable: true,
  },
  tenant_mismatch: {
    statusCode: 403,
    message: "The request is outside the active tenant boundary.",
    retryable: false,
  },
  application_mismatch: {
    statusCode: 403,
    message: "The credential is not bound to this application.",
    retryable: false,
  },
  client_not_allowed: {
    statusCode: 403,
    message: "The client is not allowed to call this route.",
    retryable: false,
  },
  parent_resource_disabled: {
    statusCode: 403,
    message: "A parent API resource is not active.",
    retryable: false,
  },
  invalid_audience: {
    statusCode: 403,
    message: "The credential audience is not allowed.",
    retryable: false,
  },
  invalid_scope: {
    statusCode: 403,
    message: "The requested scope is not allowed.",
    retryable: false,
  },
  scope_grant_invalid: {
    statusCode: 403,
    message: "The active scope grant does not authorize this request.",
    retryable: false,
  },
  route_not_allowed: {
    statusCode: 404,
    message: "The API route is not available.",
    retryable: false,
  },
  policy_denied: {
    statusCode: 403,
    message: "The API policy denied this request.",
    retryable: false,
  },
  policy_unavailable: {
    statusCode: 503,
    message: "API policy evaluation is temporarily unavailable.",
    retryable: true,
  },
  rate_limit_exceeded: {
    statusCode: 429,
    message: "The API rate limit was exceeded.",
    retryable: true,
  },
  quota_exceeded: {
    statusCode: 429,
    message: "The API quota was exceeded.",
    retryable: true,
  },
  rate_limiter_unavailable: {
    statusCode: 503,
    message: "API rate limiting is temporarily unavailable.",
    retryable: true,
  },
  audit_unavailable: {
    statusCode: 503,
    message: "API audit recording is temporarily unavailable.",
    retryable: true,
  },
  service_unavailable: {
    statusCode: 503,
    message: "The API runtime is temporarily unavailable.",
    retryable: true,
  },
  internal_error: {
    statusCode: 500,
    message: "The API request could not be completed.",
    retryable: false,
  },
} satisfies Readonly<Record<OpenPlatformRuntimeErrorCode, RuntimeErrorDefinition>>);

export class OpenPlatformRuntimeError extends Error {
  readonly code: OpenPlatformRuntimeErrorCode;
  readonly statusCode: number;
  readonly retryable: boolean;
  readonly retryAfterSeconds: number | undefined;
  readonly details: OpenPlatformRuntimeErrorDetails | undefined;
  readonly requestId: string | undefined;

  constructor(
    code: OpenPlatformRuntimeErrorCode,
    options: OpenPlatformRuntimeErrorOptions = {},
  ) {
    const definition = DEFINITIONS[code];
    super(definition.message);
    this.name = "OpenPlatformRuntimeError";
    this.code = code;
    this.statusCode = definition.statusCode;
    this.retryable = definition.retryable;
    this.retryAfterSeconds = normalizeRetryAfter(options.retryAfterSeconds);
    this.details = sanitizeRuntimeErrorDetails(options.details);
    this.requestId = normalizeRequestId(options.requestId);
    Object.setPrototypeOf(this, new.target.prototype);
  }

  toJSON(requestId?: string): OpenPlatformRuntimeErrorBody {
    const safeRequestId = normalizeRequestId(requestId) ?? this.requestId;
    return {
      error: {
        code: this.code,
        message: DEFINITIONS[this.code].message,
        retryable: this.retryable,
        ...(this.retryAfterSeconds === undefined
          ? {}
          : { retryAfter: this.retryAfterSeconds }),
        ...(this.details === undefined ? {} : { details: this.details }),
      },
      ...(safeRequestId === undefined ? {} : { requestId: safeRequestId }),
    };
  }
}

export function runtimeError(
  code: OpenPlatformRuntimeErrorCode,
  options: OpenPlatformRuntimeErrorOptions = {},
): OpenPlatformRuntimeError {
  return new OpenPlatformRuntimeError(code, options);
}

export function isOpenPlatformRuntimeError(
  value: unknown,
): value is OpenPlatformRuntimeError {
  return value instanceof OpenPlatformRuntimeError;
}

export function toOpenPlatformRuntimeContractError(
  error: unknown,
  requestId?: string,
): OpenPlatformRuntimeContractError {
  const normalized = isOpenPlatformRuntimeError(error)
    ? error
    : mapDomainError(error);
  const body = normalized.toJSON(requestId);
  const headers: Record<string, string> = {};
  if (body.requestId !== undefined) headers["X-Request-Id"] = body.requestId;
  if (body.error.retryAfter !== undefined) {
    headers["Retry-After"] = String(body.error.retryAfter);
  }
  return {
    statusCode: normalized.statusCode,
    headers: Object.freeze(headers),
    body: Object.freeze(body),
  };
}

export function contextRequestId(
  context: OpenPlatformApiRequestContext,
): string {
  return context.requestId;
}

export function assertRuntimeMode(
  value: unknown,
): asserts value is OpenPlatformRuntimeMode {
  if (
    value !== "development" &&
    value !== "test" &&
    value !== "production"
  ) {
    throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.CONFIGURATION_ERROR);
  }
}

function mapDomainError(error: unknown): OpenPlatformRuntimeError {
  if (!isOpenPlatformDomainError(error)) {
    return runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.INTERNAL_ERROR);
  }
  switch (error.code) {
    case DOMAIN_ERROR_CODES.VALIDATION_ERROR:
    case DOMAIN_ERROR_CODES.INVALID_STATE_TRANSITION:
      return runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.INVALID_REQUEST);
    case DOMAIN_ERROR_CODES.AUTHENTICATION_REQUIRED:
      return runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.AUTHENTICATION_REQUIRED,
      );
    case DOMAIN_ERROR_CODES.TENANT_MISMATCH:
      return runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.TENANT_MISMATCH);
    case DOMAIN_ERROR_CODES.CREDENTIAL_UNAVAILABLE:
      return runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.CREDENTIAL_INVALID);
    case DOMAIN_ERROR_CODES.SCOPE_NOT_ALLOWED:
      return runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.INVALID_SCOPE);
    case DOMAIN_ERROR_CODES.SCOPE_GRANT_INVALID:
      return runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.SCOPE_GRANT_INVALID,
      );
    case DOMAIN_ERROR_CODES.RESOURCE_UNAVAILABLE:
      return runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.PARENT_RESOURCE_DISABLED,
      );
    case DOMAIN_ERROR_CODES.FORBIDDEN:
      return runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.POLICY_DENIED);
    case DOMAIN_ERROR_CODES.STORAGE_UNAVAILABLE:
      return runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.SERVICE_UNAVAILABLE,
      );
    case DOMAIN_ERROR_CODES.CONFIGURATION_ERROR:
      return runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.CONFIGURATION_ERROR);
    case DOMAIN_ERROR_CODES.RESOURCE_NOT_FOUND:
      return runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.CREDENTIAL_INVALID);
    default:
      return runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.INTERNAL_ERROR);
  }
}

function sanitizeRuntimeErrorDetails(
  value: Readonly<Record<string, unknown>> | undefined,
): OpenPlatformRuntimeErrorDetails | undefined {
  if (value === undefined) return undefined;
  const safe: Record<string, string | number | boolean> = {};
  for (const [key, nested] of Object.entries(value)) {
    if (isSensitiveKey(key)) continue;
    if (typeof nested === "string") {
      safe[key] = nested.length > 128 ? nested.slice(0, 128) : nested;
    } else if (
      typeof nested === "number" &&
      Number.isFinite(nested)
    ) {
      safe[key] = nested;
    } else if (typeof nested === "boolean") {
      safe[key] = nested;
    }
  }
  return Object.keys(safe).length === 0 ? undefined : Object.freeze(safe);
}

function isSensitiveKey(key: string): boolean {
  const normalized = key.replace(/[-_]/gu, "").toLowerCase();
  return normalized.includes("secret") ||
    normalized.includes("password") ||
    normalized.includes("token") ||
    normalized.includes("authorization") ||
    normalized.includes("cookie") ||
    normalized.includes("privatekey") ||
    normalized.includes("apikey");
}

function normalizeRetryAfter(value: unknown): number | undefined {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 1 ||
    value > 86_400
  ) {
    return undefined;
  }
  return value;
}

function normalizeRequestId(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  if (
    normalized.length < 1 ||
    normalized.length > 128 ||
    /[\s\u0000-\u001f\u007f]/u.test(normalized)
  ) {
    return undefined;
  }
  return normalized;
}
