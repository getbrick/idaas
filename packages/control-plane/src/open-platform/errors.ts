export const OPEN_PLATFORM_ERROR_CODES = {
  VALIDATION_ERROR: "OPEN_PLATFORM_VALIDATION_ERROR",
  RESOURCE_NOT_FOUND: "OPEN_PLATFORM_RESOURCE_NOT_FOUND",
  RESOURCE_CONFLICT: "OPEN_PLATFORM_RESOURCE_CONFLICT",
  RESOURCE_UNAVAILABLE: "OPEN_PLATFORM_RESOURCE_UNAVAILABLE",
  INVALID_STATE_TRANSITION: "OPEN_PLATFORM_INVALID_STATE_TRANSITION",
  INVALID_IDEMPOTENCY_KEY: "OPEN_PLATFORM_INVALID_IDEMPOTENCY_KEY",
  IDEMPOTENCY_KEY_REUSED: "OPEN_PLATFORM_IDEMPOTENCY_KEY_REUSED",
  IDEMPOTENCY_REQUEST_IN_PROGRESS: "OPEN_PLATFORM_IDEMPOTENCY_REQUEST_IN_PROGRESS",
  SCOPE_NOT_ALLOWED: "OPEN_PLATFORM_SCOPE_NOT_ALLOWED",
  CREDENTIAL_UNAVAILABLE: "OPEN_PLATFORM_CREDENTIAL_UNAVAILABLE",
  SECRET_ISSUANCE_FAILED: "OPEN_PLATFORM_SECRET_ISSUANCE_FAILED",
  USAGE_REJECTED: "OPEN_PLATFORM_USAGE_REJECTED",
  AUTHENTICATION_REQUIRED: "OPEN_PLATFORM_AUTHENTICATION_REQUIRED",
  FORBIDDEN: "OPEN_PLATFORM_FORBIDDEN",
  TENANT_MISMATCH: "OPEN_PLATFORM_TENANT_MISMATCH",
  SCOPE_GRANT_INVALID: "OPEN_PLATFORM_SCOPE_GRANT_INVALID",
  STORAGE_UNAVAILABLE: "OPEN_PLATFORM_STORAGE_UNAVAILABLE",
  CONFIGURATION_ERROR: "OPEN_PLATFORM_CONFIGURATION_ERROR",
  INTERNAL_ERROR: "OPEN_PLATFORM_INTERNAL_ERROR",
} as const;

export type OpenPlatformErrorCode =
  (typeof OPEN_PLATFORM_ERROR_CODES)[keyof typeof OPEN_PLATFORM_ERROR_CODES];

export interface OpenPlatformErrorOptions {
  details?: Readonly<Record<string, unknown>>;
  cause?: unknown;
}

export class OpenPlatformDomainError extends Error {
  readonly code: OpenPlatformErrorCode;
  readonly details: Readonly<Record<string, unknown>> | undefined;

  constructor(
    code: OpenPlatformErrorCode,
    message: string,
    options: OpenPlatformErrorOptions = {},
  ) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = "OpenPlatformDomainError";
    this.code = code;
    this.details = options.details === undefined
      ? undefined
      : sanitizeErrorDetails(options.details);
    Object.setPrototypeOf(this, new.target.prototype);
  }

  toJSON(): {
    code: OpenPlatformErrorCode;
    message: string;
  } {
    return {
      code: this.code,
      message: "Open platform request failed",
    };
  }
}

export function isOpenPlatformDomainError(
  value: unknown,
): value is OpenPlatformDomainError {
  return value instanceof OpenPlatformDomainError;
}

export function validationError(
  message: string,
  details?: Readonly<Record<string, unknown>>,
): OpenPlatformDomainError {
  return new OpenPlatformDomainError(
    OPEN_PLATFORM_ERROR_CODES.VALIDATION_ERROR,
    message,
    { details },
  );
}

export function resourceNotFound(
  kind?: string,
): OpenPlatformDomainError {
  return new OpenPlatformDomainError(
    OPEN_PLATFORM_ERROR_CODES.RESOURCE_NOT_FOUND,
    "Open platform resource was not found",
    { details: kind === undefined ? undefined : { kind } },
  );
}

export function resourceConflict(
  message = "Open platform resource conflicts with existing state",
  details?: Readonly<Record<string, unknown>>,
): OpenPlatformDomainError {
  return new OpenPlatformDomainError(
    OPEN_PLATFORM_ERROR_CODES.RESOURCE_CONFLICT,
    message,
    { details },
  );
}

export function resourceUnavailable(
  kind: string,
): OpenPlatformDomainError {
  return new OpenPlatformDomainError(
    OPEN_PLATFORM_ERROR_CODES.RESOURCE_UNAVAILABLE,
    "Open platform resource is unavailable in its current state",
    { details: { kind } },
  );
}

export function invalidStateTransition(
  from: string,
  to: string,
): OpenPlatformDomainError {
  return new OpenPlatformDomainError(
    OPEN_PLATFORM_ERROR_CODES.INVALID_STATE_TRANSITION,
    "Open platform state transition is not allowed",
    { details: { from, to } },
  );
}

export function invalidIdempotencyKey(): OpenPlatformDomainError {
  return new OpenPlatformDomainError(
    OPEN_PLATFORM_ERROR_CODES.INVALID_IDEMPOTENCY_KEY,
    "Idempotency key is invalid",
  );
}

export function idempotencyKeyReused(): OpenPlatformDomainError {
  return new OpenPlatformDomainError(
    OPEN_PLATFORM_ERROR_CODES.IDEMPOTENCY_KEY_REUSED,
    "Idempotency key was already used for a different request",
  );
}

export function idempotencyRequestInProgress(): OpenPlatformDomainError {
  return new OpenPlatformDomainError(
    OPEN_PLATFORM_ERROR_CODES.IDEMPOTENCY_REQUEST_IN_PROGRESS,
    "A request with the same idempotency key is still in progress",
  );
}

export function scopeNotAllowed(): OpenPlatformDomainError {
  return new OpenPlatformDomainError(
    OPEN_PLATFORM_ERROR_CODES.SCOPE_NOT_ALLOWED,
    "Requested scope is not allowed",
  );
}

export function credentialUnavailable(): OpenPlatformDomainError {
  return new OpenPlatformDomainError(
    OPEN_PLATFORM_ERROR_CODES.CREDENTIAL_UNAVAILABLE,
    "Credential is unavailable",
  );
}

export function secretIssuanceFailed(): OpenPlatformDomainError {
  return new OpenPlatformDomainError(
    OPEN_PLATFORM_ERROR_CODES.SECRET_ISSUANCE_FAILED,
    "Credential secret could not be issued",
  );
}

export function usageRejected(
  message = "Usage record is invalid",
): OpenPlatformDomainError {
  return new OpenPlatformDomainError(
    OPEN_PLATFORM_ERROR_CODES.USAGE_REJECTED,
    message,
  );
}

export function authenticationRequired(): OpenPlatformDomainError {
  return new OpenPlatformDomainError(
    OPEN_PLATFORM_ERROR_CODES.AUTHENTICATION_REQUIRED,
    "Open platform authentication is required",
  );
}

export function forbidden(): OpenPlatformDomainError {
  return new OpenPlatformDomainError(
    OPEN_PLATFORM_ERROR_CODES.FORBIDDEN,
    "Open platform access is forbidden",
  );
}

export function tenantMismatch(): OpenPlatformDomainError {
  return new OpenPlatformDomainError(
    OPEN_PLATFORM_ERROR_CODES.TENANT_MISMATCH,
    "Open platform tenant does not match the authenticated context",
  );
}

export function scopeGrantInvalid(): OpenPlatformDomainError {
  return new OpenPlatformDomainError(
    OPEN_PLATFORM_ERROR_CODES.SCOPE_GRANT_INVALID,
    "Open platform scope grant is invalid",
  );
}

export function storageUnavailable(): OpenPlatformDomainError {
  return new OpenPlatformDomainError(
    OPEN_PLATFORM_ERROR_CODES.STORAGE_UNAVAILABLE,
    "Open platform storage is unavailable",
  );
}

export function configurationError(
  message = "Open platform configuration is invalid",
): OpenPlatformDomainError {
  return new OpenPlatformDomainError(
    OPEN_PLATFORM_ERROR_CODES.CONFIGURATION_ERROR,
    message,
  );
}

export interface OpenPlatformContractError {
  statusCode: number;
  body: {
    code: OpenPlatformErrorCode;
    message: string;
    requestId?: string;
  };
}

export function toOpenPlatformContractError(
  error: unknown,
  requestId?: string,
): OpenPlatformContractError {
  const domainError = isOpenPlatformDomainError(error)
    ? error
    : new OpenPlatformDomainError(
      OPEN_PLATFORM_ERROR_CODES.INTERNAL_ERROR,
      "Open platform request failed",
    );
  const contract = publicErrorContract(domainError);
  const safeRequestId = normalizeRequestId(requestId);
  return {
    statusCode: contract.statusCode,
    body: {
      code: contract.code,
      message: contract.message,
      ...(safeRequestId === undefined ? {} : { requestId: safeRequestId }),
    },
  };
}

function publicErrorContract(error: OpenPlatformDomainError): {
  statusCode: number;
  code: OpenPlatformErrorCode;
  message: string;
} {
  switch (error.code) {
    case OPEN_PLATFORM_ERROR_CODES.VALIDATION_ERROR:
    case OPEN_PLATFORM_ERROR_CODES.INVALID_IDEMPOTENCY_KEY:
    case OPEN_PLATFORM_ERROR_CODES.INVALID_STATE_TRANSITION:
      return {
        statusCode: 400,
        code: error.code,
        message: "Open platform request is invalid",
      };
    case OPEN_PLATFORM_ERROR_CODES.AUTHENTICATION_REQUIRED:
      return {
        statusCode: 401,
        code: error.code,
        message: "Authentication is required",
      };
    case OPEN_PLATFORM_ERROR_CODES.FORBIDDEN:
    case OPEN_PLATFORM_ERROR_CODES.TENANT_MISMATCH:
      return {
        statusCode: 403,
        code: error.code,
        message: "Access is forbidden",
      };
    case OPEN_PLATFORM_ERROR_CODES.RESOURCE_NOT_FOUND:
      return {
        statusCode: 404,
        code: error.code,
        message: "Open platform resource was not found",
      };
    case OPEN_PLATFORM_ERROR_CODES.RESOURCE_CONFLICT:
    case OPEN_PLATFORM_ERROR_CODES.RESOURCE_UNAVAILABLE:
    case OPEN_PLATFORM_ERROR_CODES.IDEMPOTENCY_KEY_REUSED:
    case OPEN_PLATFORM_ERROR_CODES.IDEMPOTENCY_REQUEST_IN_PROGRESS:
    case OPEN_PLATFORM_ERROR_CODES.SCOPE_NOT_ALLOWED:
    case OPEN_PLATFORM_ERROR_CODES.SCOPE_GRANT_INVALID:
    case OPEN_PLATFORM_ERROR_CODES.USAGE_REJECTED:
      return {
        statusCode: 409,
        code: error.code,
        message: "Open platform request conflicts with current state",
      };
    case OPEN_PLATFORM_ERROR_CODES.CREDENTIAL_UNAVAILABLE:
      return {
        statusCode: 423,
        code: error.code,
        message: "Credential is unavailable",
      };
    case OPEN_PLATFORM_ERROR_CODES.SECRET_ISSUANCE_FAILED:
    case OPEN_PLATFORM_ERROR_CODES.STORAGE_UNAVAILABLE:
      return {
        statusCode: 503,
        code: error.code,
        message: "Open platform service is unavailable",
      };
    case OPEN_PLATFORM_ERROR_CODES.CONFIGURATION_ERROR:
    case OPEN_PLATFORM_ERROR_CODES.INTERNAL_ERROR:
      return {
        statusCode: 500,
        code: error.code,
        message: "Open platform request failed",
      };
  }
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

function sanitizeErrorDetails(
  details: Readonly<Record<string, unknown>>,
): Readonly<Record<string, unknown>> {
  const safe: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(details)) {
    if (isSensitiveKey(key)) continue;
    if (typeof value === "string") {
      safe[key] = value.length > 128 ? value.slice(0, 128) : value;
    } else if (
      typeof value === "number" &&
      Number.isFinite(value)
    ) {
      safe[key] = value;
    } else if (typeof value === "boolean") {
      safe[key] = value;
    }
  }
  return Object.freeze(safe);
}

function isSensitiveKey(key: string): boolean {
  const normalized = key.replace(/[-_]/gu, "").toLowerCase();
  return normalized.includes("secret") ||
    normalized.includes("password") ||
    normalized.includes("token") ||
    normalized.includes("credential") ||
    normalized.includes("authorization") ||
    normalized.includes("privatekey");
}
