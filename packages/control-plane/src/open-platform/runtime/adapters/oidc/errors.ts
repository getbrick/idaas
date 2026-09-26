export const OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES = Object.freeze({
  CONFIGURATION: "configuration",
  NOT_READY: "not_ready",
  VERIFIER_UNAVAILABLE: "verifier_unavailable",
  INVALID_TOKEN: "invalid_token",
  INVALID_ISSUER: "invalid_issuer",
  INVALID_AUDIENCE: "invalid_audience",
  EXPIRED: "expired",
  NOT_YET_VALID: "not_yet_valid",
  REVOKED: "revoked",
  TENANT_MISMATCH: "tenant_mismatch",
  CLIENT_MISMATCH: "client_mismatch",
  INVALID_SCOPE: "invalid_scope",
  IDENTITY_INVALID: "identity_invalid",
} as const);

export type OpenPlatformOidcAdapterErrorCode =
  (typeof OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES)[keyof typeof OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES];

export class OpenPlatformOidcAdapterError extends Error {
  readonly code: OpenPlatformOidcAdapterErrorCode;
  readonly retryable: boolean;

  constructor(
    code: OpenPlatformOidcAdapterErrorCode,
    retryable = false,
  ) {
    super(code);
    this.name = "OpenPlatformOidcAdapterError";
    this.code = code;
    this.retryable = retryable;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export function oidcAdapterError(
  code: OpenPlatformOidcAdapterErrorCode,
  retryable = false,
): OpenPlatformOidcAdapterError {
  return new OpenPlatformOidcAdapterError(code, retryable);
}

export function isOpenPlatformOidcAdapterError(
  value: unknown,
): value is OpenPlatformOidcAdapterError {
  return value instanceof OpenPlatformOidcAdapterError;
}
