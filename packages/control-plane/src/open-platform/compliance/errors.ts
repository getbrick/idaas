export const COMPLIANCE_ERROR_CODES = Object.freeze({
  VALIDATION_ERROR: "OPEN_PLATFORM_COMPLIANCE_VALIDATION_ERROR",
  RESOURCE_NOT_FOUND: "OPEN_PLATFORM_COMPLIANCE_RESOURCE_NOT_FOUND",
  RESOURCE_CONFLICT: "OPEN_PLATFORM_COMPLIANCE_RESOURCE_CONFLICT",
  INVALID_STATE_TRANSITION: "OPEN_PLATFORM_COMPLIANCE_INVALID_STATE_TRANSITION",
  IMMUTABLE_RECORD: "OPEN_PLATFORM_COMPLIANCE_IMMUTABLE_RECORD",
  TENANT_MISMATCH: "OPEN_PLATFORM_COMPLIANCE_TENANT_MISMATCH",
  IDENTITY_VERIFICATION_REQUIRED:
    "OPEN_PLATFORM_COMPLIANCE_IDENTITY_VERIFICATION_REQUIRED",
  LEGAL_BASIS_REQUIRED: "OPEN_PLATFORM_COMPLIANCE_LEGAL_BASIS_REQUIRED",
  CROSS_BORDER_MECHANISM_REQUIRED:
    "OPEN_PLATFORM_COMPLIANCE_CROSS_BORDER_MECHANISM_REQUIRED",
  REDACTION_FAILED: "OPEN_PLATFORM_COMPLIANCE_REDACTION_FAILED",
  STORAGE_UNAVAILABLE: "OPEN_PLATFORM_COMPLIANCE_STORAGE_UNAVAILABLE",
  INVALID_IDEMPOTENCY_KEY: "OPEN_PLATFORM_COMPLIANCE_INVALID_IDEMPOTENCY_KEY",
  IDEMPOTENCY_KEY_REUSED: "OPEN_PLATFORM_COMPLIANCE_IDEMPOTENCY_KEY_REUSED",
  IDEMPOTENCY_REQUEST_IN_PROGRESS:
    "OPEN_PLATFORM_COMPLIANCE_IDEMPOTENCY_REQUEST_IN_PROGRESS",
} as const satisfies Record<string, string>);

export type ComplianceErrorCode =
  (typeof COMPLIANCE_ERROR_CODES)[keyof typeof COMPLIANCE_ERROR_CODES];

export class OpenPlatformComplianceError extends Error {
  readonly code: ComplianceErrorCode;
  readonly details: Readonly<Record<string, string | number | boolean>>;

  constructor(
    code: ComplianceErrorCode,
    message: string,
    details?: Readonly<Record<string, string | number | boolean>>,
  ) {
    super(message);
    this.name = "OpenPlatformComplianceError";
    this.code = code;
    this.details = Object.freeze({ ...(details ?? {}) });
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export function isOpenPlatformComplianceError(
  value: unknown,
): value is OpenPlatformComplianceError {
  return value instanceof OpenPlatformComplianceError;
}

export function complianceValidationError(
  message: string,
  field?: string,
): OpenPlatformComplianceError {
  return new OpenPlatformComplianceError(
    COMPLIANCE_ERROR_CODES.VALIDATION_ERROR,
    message,
    field === undefined ? undefined : { field },
  );
}

export function complianceResourceNotFound(
  kind: string,
): OpenPlatformComplianceError {
  return new OpenPlatformComplianceError(
    COMPLIANCE_ERROR_CODES.RESOURCE_NOT_FOUND,
    "Open platform compliance resource was not found",
    { kind },
  );
}

export function complianceResourceConflict(
  message = "Open platform compliance resource conflicts with existing state",
): OpenPlatformComplianceError {
  return new OpenPlatformComplianceError(
    COMPLIANCE_ERROR_CODES.RESOURCE_CONFLICT,
    message,
  );
}

export function complianceInvalidStateTransition(
  entity: string,
  from: string,
  to: string,
): OpenPlatformComplianceError {
  return new OpenPlatformComplianceError(
    COMPLIANCE_ERROR_CODES.INVALID_STATE_TRANSITION,
    "Open platform compliance state transition is not allowed",
    { entity, from, to },
  );
}

export function complianceImmutableRecord(
  kind: string,
): OpenPlatformComplianceError {
  return new OpenPlatformComplianceError(
    COMPLIANCE_ERROR_CODES.IMMUTABLE_RECORD,
    "Open platform compliance record is append-only",
    { kind },
  );
}

export function complianceTenantMismatch(
  expectedTenantId: string,
): OpenPlatformComplianceError {
  return new OpenPlatformComplianceError(
    COMPLIANCE_ERROR_CODES.TENANT_MISMATCH,
    "Open platform compliance record belongs to another tenant",
    { expectedTenantId },
  );
}

export function complianceIdentityVerificationRequired(
  field = "identityVerification",
): OpenPlatformComplianceError {
  return new OpenPlatformComplianceError(
    COMPLIANCE_ERROR_CODES.IDENTITY_VERIFICATION_REQUIRED,
    "Open platform privacy request requires recorded identity verification",
    { field },
  );
}

export function complianceLegalBasisRequired(
  field = "legalBasis",
): OpenPlatformComplianceError {
  return new OpenPlatformComplianceError(
    COMPLIANCE_ERROR_CODES.LEGAL_BASIS_REQUIRED,
    "Open platform compliance record requires a declared legal basis",
    { field },
  );
}

export function complianceCrossBorderMechanismRequired(
  field = "mechanisms",
): OpenPlatformComplianceError {
  return new OpenPlatformComplianceError(
    COMPLIANCE_ERROR_CODES.CROSS_BORDER_MECHANISM_REQUIRED,
    "Open platform cross-border assessment requires a declared legal mechanism",
    { field },
  );
}

export function complianceRedactionFailed(
  field = "value",
): OpenPlatformComplianceError {
  return new OpenPlatformComplianceError(
    COMPLIANCE_ERROR_CODES.REDACTION_FAILED,
    "Open platform compliance redaction failed",
    { field },
  );
}

export function complianceStorageUnavailable(): OpenPlatformComplianceError {
  return new OpenPlatformComplianceError(
    COMPLIANCE_ERROR_CODES.STORAGE_UNAVAILABLE,
    "Open platform compliance storage is unavailable",
  );
}

export function complianceInvalidIdempotencyKey(
  field = "idempotencyKey",
): OpenPlatformComplianceError {
  return new OpenPlatformComplianceError(
    COMPLIANCE_ERROR_CODES.INVALID_IDEMPOTENCY_KEY,
    "Open platform compliance idempotency key is invalid",
    { field },
  );
}

export function complianceIdempotencyKeyReused(): OpenPlatformComplianceError {
  return new OpenPlatformComplianceError(
    COMPLIANCE_ERROR_CODES.IDEMPOTENCY_KEY_REUSED,
    "Open platform compliance idempotency key was reused for a different request",
  );
}

export function complianceIdempotencyRequestInProgress(): OpenPlatformComplianceError {
  return new OpenPlatformComplianceError(
    COMPLIANCE_ERROR_CODES.IDEMPOTENCY_REQUEST_IN_PROGRESS,
    "Open platform compliance request with the same idempotency key is in progress",
  );
}

export interface ComplianceContractError {
  readonly statusCode: number;
  readonly body: {
    readonly code: ComplianceErrorCode;
    readonly message: string;
  };
}

export function toOpenPlatformComplianceContractError(
  error: unknown,
): ComplianceContractError {
  const stable = isOpenPlatformComplianceError(error)
    ? error
    : complianceStorageUnavailable();
  return {
    statusCode: complianceErrorStatus(stable.code),
    body: {
      code: stable.code,
      message: "Open platform compliance request failed",
    },
  };
}

function complianceErrorStatus(code: ComplianceErrorCode): number {
  switch (code) {
    case COMPLIANCE_ERROR_CODES.RESOURCE_NOT_FOUND:
      return 404;
    case COMPLIANCE_ERROR_CODES.TENANT_MISMATCH:
      return 403;
    case COMPLIANCE_ERROR_CODES.STORAGE_UNAVAILABLE:
      return 503;
    case COMPLIANCE_ERROR_CODES.REDACTION_FAILED:
      return 500;
    case COMPLIANCE_ERROR_CODES.RESOURCE_CONFLICT:
    case COMPLIANCE_ERROR_CODES.INVALID_STATE_TRANSITION:
    case COMPLIANCE_ERROR_CODES.IMMUTABLE_RECORD:
    case COMPLIANCE_ERROR_CODES.IDENTITY_VERIFICATION_REQUIRED:
    case COMPLIANCE_ERROR_CODES.LEGAL_BASIS_REQUIRED:
    case COMPLIANCE_ERROR_CODES.CROSS_BORDER_MECHANISM_REQUIRED:
    case COMPLIANCE_ERROR_CODES.IDEMPOTENCY_KEY_REUSED:
    case COMPLIANCE_ERROR_CODES.IDEMPOTENCY_REQUEST_IN_PROGRESS:
      return 409;
    case COMPLIANCE_ERROR_CODES.VALIDATION_ERROR:
    case COMPLIANCE_ERROR_CODES.INVALID_IDEMPOTENCY_KEY:
      return 400;
  }
}
