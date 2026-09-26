export const OPEN_PLATFORM_COMMERCE_ERROR_CODES = Object.freeze({
  VALIDATION_ERROR: "OPEN_PLATFORM_COMMERCE_VALIDATION_ERROR",
  RESOURCE_NOT_FOUND: "OPEN_PLATFORM_COMMERCE_RESOURCE_NOT_FOUND",
  RESOURCE_CONFLICT: "OPEN_PLATFORM_COMMERCE_RESOURCE_CONFLICT",
  INVALID_STATE_TRANSITION: "OPEN_PLATFORM_COMMERCE_INVALID_STATE_TRANSITION",
  IDEMPOTENCY_KEY_REUSED: "OPEN_PLATFORM_COMMERCE_IDEMPOTENCY_KEY_REUSED",
  ENTITLEMENT_DENIED: "OPEN_PLATFORM_COMMERCE_ENTITLEMENT_DENIED",
  USAGE_REJECTED: "OPEN_PLATFORM_COMMERCE_USAGE_REJECTED",
  QUOTA_EXCEEDED: "OPEN_PLATFORM_COMMERCE_QUOTA_EXCEEDED",
  NEGATIVE_AMOUNT: "OPEN_PLATFORM_COMMERCE_NEGATIVE_AMOUNT",
  INVALID_TOTAL: "OPEN_PLATFORM_COMMERCE_INVALID_TOTAL",
  COMMISSION_INVALID: "OPEN_PLATFORM_COMMERCE_COMMISSION_INVALID",
  CALCULATION_ERROR: "OPEN_PLATFORM_COMMERCE_CALCULATION_ERROR",
  STORAGE_UNAVAILABLE: "OPEN_PLATFORM_COMMERCE_STORAGE_UNAVAILABLE",
} as const);

export type OpenPlatformCommerceErrorCode =
  (typeof OPEN_PLATFORM_COMMERCE_ERROR_CODES)[keyof typeof OPEN_PLATFORM_COMMERCE_ERROR_CODES];

export class OpenPlatformCommerceError extends Error {
  readonly code: OpenPlatformCommerceErrorCode;
  readonly details: Readonly<Record<string, string | number | boolean>>;

  constructor(
    code: OpenPlatformCommerceErrorCode,
    message: string,
    details?: Readonly<Record<string, string | number | boolean>>,
  ) {
    super(message);
    this.name = "OpenPlatformCommerceError";
    this.code = code;
    this.details = Object.freeze({ ...(details ?? {}) });
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export function isOpenPlatformCommerceError(
  value: unknown,
): value is OpenPlatformCommerceError {
  return value instanceof OpenPlatformCommerceError;
}

export function commerceValidationError(
  message: string,
  field?: string,
): OpenPlatformCommerceError {
  return new OpenPlatformCommerceError(
    OPEN_PLATFORM_COMMERCE_ERROR_CODES.VALIDATION_ERROR,
    message,
    field === undefined ? undefined : { field },
  );
}

export function commerceResourceNotFound(
  kind: string,
): OpenPlatformCommerceError {
  return new OpenPlatformCommerceError(
    OPEN_PLATFORM_COMMERCE_ERROR_CODES.RESOURCE_NOT_FOUND,
    "Open platform commerce resource was not found",
    { kind },
  );
}

export function commerceResourceConflict(
  message = "Open platform commerce resource conflicts with existing state",
): OpenPlatformCommerceError {
  return new OpenPlatformCommerceError(
    OPEN_PLATFORM_COMMERCE_ERROR_CODES.RESOURCE_CONFLICT,
    message,
  );
}

export function commerceInvalidStateTransition(
  from: string,
  to: string,
): OpenPlatformCommerceError {
  return new OpenPlatformCommerceError(
    OPEN_PLATFORM_COMMERCE_ERROR_CODES.INVALID_STATE_TRANSITION,
    "Open platform commerce state transition is not allowed",
    { from, to },
  );
}

export function commerceIdempotencyKeyReused(): OpenPlatformCommerceError {
  return new OpenPlatformCommerceError(
    OPEN_PLATFORM_COMMERCE_ERROR_CODES.IDEMPOTENCY_KEY_REUSED,
    "Idempotency key was already used for a different request",
  );
}

export function commerceEntitlementDenied(
  feature: string,
): OpenPlatformCommerceError {
  return new OpenPlatformCommerceError(
    OPEN_PLATFORM_COMMERCE_ERROR_CODES.ENTITLEMENT_DENIED,
    "Commerce entitlement is denied",
    { feature },
  );
}

export function commerceUsageRejected(
  message = "Usage event is invalid",
): OpenPlatformCommerceError {
  return new OpenPlatformCommerceError(
    OPEN_PLATFORM_COMMERCE_ERROR_CODES.USAGE_REJECTED,
    message,
  );
}

export function commerceQuotaExceeded(): OpenPlatformCommerceError {
  return new OpenPlatformCommerceError(
    OPEN_PLATFORM_COMMERCE_ERROR_CODES.QUOTA_EXCEEDED,
    "Commerce quota would be exceeded",
  );
}

export function commerceNegativeAmount(
  message = "Commerce amount cannot be negative",
): OpenPlatformCommerceError {
  return new OpenPlatformCommerceError(
    OPEN_PLATFORM_COMMERCE_ERROR_CODES.NEGATIVE_AMOUNT,
    message,
  );
}

export function commerceInvalidTotal(
  message = "Commerce total is invalid",
): OpenPlatformCommerceError {
  return new OpenPlatformCommerceError(
    OPEN_PLATFORM_COMMERCE_ERROR_CODES.INVALID_TOTAL,
    message,
  );
}

export function commerceCommissionInvalid(
  message = "Commission calculation is invalid",
): OpenPlatformCommerceError {
  return new OpenPlatformCommerceError(
    OPEN_PLATFORM_COMMERCE_ERROR_CODES.COMMISSION_INVALID,
    message,
  );
}

export function commerceCalculationError(): OpenPlatformCommerceError {
  return new OpenPlatformCommerceError(
    OPEN_PLATFORM_COMMERCE_ERROR_CODES.CALCULATION_ERROR,
    "Commerce calculation is unavailable",
  );
}

export function normalizeCommerceCalculationError(
  error: unknown,
): OpenPlatformCommerceError {
  return isOpenPlatformCommerceError(error)
    ? error
    : commerceCalculationError();
}

export function commerceStorageUnavailable(): OpenPlatformCommerceError {
  return new OpenPlatformCommerceError(
    OPEN_PLATFORM_COMMERCE_ERROR_CODES.STORAGE_UNAVAILABLE,
    "Open platform commerce storage is unavailable",
  );
}

export interface OpenPlatformCommerceContractError {
  readonly statusCode: number;
  readonly body: {
    readonly code: OpenPlatformCommerceErrorCode;
    readonly message: string;
  };
}

export function toOpenPlatformCommerceContractError(
  error: unknown,
): OpenPlatformCommerceContractError {
  const stableError = normalizeCommerceCalculationError(error);
  return {
    statusCode: commerceErrorStatus(stableError.code),
    body: {
      code: stableError.code,
      message: "Open platform commerce request failed",
    },
  };
}

function commerceErrorStatus(code: OpenPlatformCommerceErrorCode): number {
  switch (code) {
    case OPEN_PLATFORM_COMMERCE_ERROR_CODES.RESOURCE_NOT_FOUND:
      return 404;
    case OPEN_PLATFORM_COMMERCE_ERROR_CODES.STORAGE_UNAVAILABLE:
      return 503;
    case OPEN_PLATFORM_COMMERCE_ERROR_CODES.RESOURCE_CONFLICT:
    case OPEN_PLATFORM_COMMERCE_ERROR_CODES.INVALID_STATE_TRANSITION:
    case OPEN_PLATFORM_COMMERCE_ERROR_CODES.IDEMPOTENCY_KEY_REUSED:
    case OPEN_PLATFORM_COMMERCE_ERROR_CODES.ENTITLEMENT_DENIED:
    case OPEN_PLATFORM_COMMERCE_ERROR_CODES.USAGE_REJECTED:
    case OPEN_PLATFORM_COMMERCE_ERROR_CODES.QUOTA_EXCEEDED:
      return 409;
    case OPEN_PLATFORM_COMMERCE_ERROR_CODES.VALIDATION_ERROR:
    case OPEN_PLATFORM_COMMERCE_ERROR_CODES.NEGATIVE_AMOUNT:
    case OPEN_PLATFORM_COMMERCE_ERROR_CODES.INVALID_TOTAL:
    case OPEN_PLATFORM_COMMERCE_ERROR_CODES.COMMISSION_INVALID:
    case OPEN_PLATFORM_COMMERCE_ERROR_CODES.CALCULATION_ERROR:
      return 400;
  }
}
