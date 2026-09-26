export const CONTROL_PLANE_ERROR_CODES = {
  BAD_REQUEST: "BAD_REQUEST",
  INVALID_REQUEST: "INVALID_REQUEST",
  UNAUTHENTICATED: "UNAUTHENTICATED",
  UNAUTHORIZED: "UNAUTHORIZED",
  FORBIDDEN: "FORBIDDEN",
  NOT_FOUND: "NOT_FOUND",
  CONFLICT: "CONFLICT",
  VALIDATION_ERROR: "VALIDATION_ERROR",
  RATE_LIMITED: "RATE_LIMITED",
  DEPENDENCY_UNAVAILABLE: "DEPENDENCY_UNAVAILABLE",
  SERVICE_UNAVAILABLE: "SERVICE_UNAVAILABLE",
  INTERNAL_ERROR: "INTERNAL_ERROR",
} as const;

export type ControlPlaneErrorCode =
  (typeof CONTROL_PLANE_ERROR_CODES)[keyof typeof CONTROL_PLANE_ERROR_CODES];

export const ERROR_CODES = CONTROL_PLANE_ERROR_CODES;

const STABLE_ERROR_CODES = new Set<string>(Object.values(CONTROL_PLANE_ERROR_CODES));

export function isControlPlaneErrorCode(value: unknown): value is ControlPlaneErrorCode {
  return typeof value === "string" && STABLE_ERROR_CODES.has(value);
}

export interface ControlPlaneErrorBody {
  code: ControlPlaneErrorCode;
  message: string;
  details?: Record<string, unknown>;
}

export interface ControlPlaneErrorResponse {
  error: ControlPlaneErrorBody;
  requestId?: string;
}

export interface ControlPlaneErrorOptions {
  statusCode?: number;
  details?: Record<string, unknown>;
}

export class ControlPlaneError extends Error {
  readonly code: ControlPlaneErrorCode;
  readonly statusCode: number;
  readonly details?: Record<string, unknown>;

  constructor(
    code: ControlPlaneErrorCode,
    message: string,
    options: ControlPlaneErrorOptions = {},
  ) {
    super(message);
    this.name = "ControlPlaneError";
    this.code = code;
    this.statusCode = options.statusCode ?? statusForCode(code);
    this.details = options.details ? sanitizeDetails(options.details) : undefined;
    Object.setPrototypeOf(this, new.target.prototype);
  }

  toJSON(): ControlPlaneErrorResponse {
    const error: ControlPlaneErrorBody = {
      code: this.code,
      message: this.message,
    };
    if (this.details && Object.keys(this.details).length > 0) error.details = this.details;
    return { error };
  }
}

export class ControlPlaneSqlRollbackError extends ControlPlaneError {
  readonly originalError: unknown;
  readonly rollbackError: unknown;
  readonly originalErrorCode: string | undefined;
  readonly rollbackErrorCode: string | undefined;

  constructor(originalError: unknown, rollbackError: unknown) {
    super(CONTROL_PLANE_ERROR_CODES.INTERNAL_ERROR, "Internal server error", {
      details: { operation: "rollback" },
    });
    this.name = "ControlPlaneSqlRollbackError";
    this.originalError = originalError;
    this.rollbackError = rollbackError;
    this.originalErrorCode = errorCode(originalError);
    this.rollbackErrorCode = errorCode(rollbackError);
    Object.defineProperty(this, "cause", {
      configurable: true,
      enumerable: false,
      value: originalError,
      writable: false,
    });
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export function isControlPlaneSqlRollbackError(value: unknown): value is ControlPlaneSqlRollbackError {
  return value instanceof ControlPlaneSqlRollbackError;
}

export function invalidRequest(
  message = "Invalid request",
  details?: Record<string, unknown>,
): ControlPlaneError {
  return new ControlPlaneError(CONTROL_PLANE_ERROR_CODES.INVALID_REQUEST, message, { details });
}

export function validationError(
  message = "Request validation failed",
  details?: Record<string, unknown>,
): ControlPlaneError {
  return new ControlPlaneError(CONTROL_PLANE_ERROR_CODES.VALIDATION_ERROR, message, {
    statusCode: 400,
    details,
  });
}

export function unauthenticated(message = "Authentication required"): ControlPlaneError {
  return new ControlPlaneError(CONTROL_PLANE_ERROR_CODES.UNAUTHENTICATED, message, {
    statusCode: 401,
  });
}

export function forbidden(message = "Insufficient permission"): ControlPlaneError {
  return new ControlPlaneError(CONTROL_PLANE_ERROR_CODES.FORBIDDEN, message, {
    statusCode: 403,
  });
}

export function notFound(message = "Resource not found"): ControlPlaneError {
  return new ControlPlaneError(CONTROL_PLANE_ERROR_CODES.NOT_FOUND, message, {
    statusCode: 404,
  });
}

export function conflict(message = "Resource state conflict"): ControlPlaneError {
  return new ControlPlaneError(CONTROL_PLANE_ERROR_CODES.CONFLICT, message, {
    statusCode: 409,
  });
}

export function internalError(): ControlPlaneError {
  return new ControlPlaneError(CONTROL_PLANE_ERROR_CODES.INTERNAL_ERROR, "Internal server error", {
    statusCode: 500,
  });
}

function statusForCode(code: ControlPlaneErrorCode): number {
  switch (code) {
    case CONTROL_PLANE_ERROR_CODES.BAD_REQUEST:
    case CONTROL_PLANE_ERROR_CODES.INVALID_REQUEST:
    case CONTROL_PLANE_ERROR_CODES.VALIDATION_ERROR:
      return 400;
    case CONTROL_PLANE_ERROR_CODES.UNAUTHENTICATED:
    case CONTROL_PLANE_ERROR_CODES.UNAUTHORIZED:
      return 401;
    case CONTROL_PLANE_ERROR_CODES.FORBIDDEN:
      return 403;
    case CONTROL_PLANE_ERROR_CODES.NOT_FOUND:
      return 404;
    case CONTROL_PLANE_ERROR_CODES.RATE_LIMITED:
      return 429;
    case CONTROL_PLANE_ERROR_CODES.DEPENDENCY_UNAVAILABLE:
    case CONTROL_PLANE_ERROR_CODES.SERVICE_UNAVAILABLE:
      return 503;
    default:
      return 500;
  }
}

function sanitizeDetails(value: Record<string, unknown>): Record<string, unknown> {
  const output: Record<string, unknown> = {};
  for (const [key, nested] of Object.entries(value)) {
    if (isUnsafeKey(key) || isSensitiveKey(key)) continue;
    const safe = sanitizeDetailValue(nested, 0, new Set<object>());
    if (safe !== undefined) output[key] = safe;
  }
  return output;
}

function sanitizeDetailValue(value: unknown, depth: number, ancestors: Set<object>): unknown {
  if (depth > 4) return undefined;
  if (typeof value === "string") {
    if (isSensitiveText(value) || /[\u0000-\u001f\u007f]/u.test(value)) return undefined;
    return value.length > 256 ? value.slice(0, 256) : value;
  }
  if (typeof value === "number") return Number.isFinite(value) ? value : undefined;
  if (typeof value === "boolean" || value === null) return value;
  if (typeof value !== "object") return undefined;
  if (ancestors.has(value)) return undefined;
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return value.slice(0, 20).map((item) => sanitizeDetailValue(item, depth + 1, ancestors)).filter((item) => item !== undefined);
    }
    const record = value as Record<string, unknown>;
    const output: Record<string, unknown> = {};
    for (const [key, nested] of Object.entries(record)) {
      if (isUnsafeKey(key) || isSensitiveKey(key)) continue;
      const descriptor = Object.getOwnPropertyDescriptor(record, key);
      if (!descriptor || !("value" in descriptor)) continue;
      const safe = sanitizeDetailValue(descriptor.value, depth + 1, ancestors);
      if (safe !== undefined) output[key] = safe;
    }
    return output;
  } finally {
    ancestors.delete(value);
  }
}

function isUnsafeKey(key: string): boolean {
  return key === "__proto__" || key === "prototype" || key === "constructor";
}

function isSensitiveKey(key: string): boolean {
  const normalized = key.replace(/[-_]/g, "").toLowerCase();
  return normalized.includes("password") ||
    normalized.includes("passphrase") ||
    normalized.includes("secret") ||
    normalized.includes("token") ||
    normalized.includes("hash") ||
    normalized.includes("authorization") ||
    normalized.includes("cookie") ||
    normalized.includes("credential") ||
    normalized.includes("apikey") ||
    normalized.includes("privatekey") ||
    normalized.includes("database") ||
    normalized.includes("connectionstring") ||
    normalized.includes("bearer") ||
    normalized.includes("signature") ||
    normalized.includes("dsn");
}

function isSensitiveText(value: string): boolean {
  return /(?:secret|password|token|private[-_]?key|credential|authorization|cookie|vault:\/\/)/iu.test(value);
}

function errorCode(value: unknown): string | undefined {
  if (value instanceof ControlPlaneError) return value.code;
  if (typeof value !== "object" || value === null) return undefined;
  const record = value as { code?: unknown; cause?: unknown };
  if (typeof record.code === "string") return record.code;
  return record.cause === undefined ? undefined : errorCode(record.cause);
}
