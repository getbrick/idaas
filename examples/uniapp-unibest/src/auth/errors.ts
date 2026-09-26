export type KnownAuthErrorCode =
  | "invalid_auth_response"
  | "invalid_oidc_callback"
  | "invalid_oidc_transaction"
  | "invalid_session"
  | "oidc_callback_denied"
  | "oidc_configuration_missing"
  | "oidc_flow_mismatch"
  | "oidc_nonce_mismatch"
  | "oidc_origin_mismatch"
  | "oidc_state_mismatch"
  | "oidc_transaction_expired"
  | "session_expired"
  | "session_generation_mismatch"
  | "session_missing"
  | "cookie_session_unavailable"
  | "unsupported_platform"
  | "wechat_login_failed"
  | "network_error"
  | "unauthorized";

export type AuthErrorCode = KnownAuthErrorCode | (string & {});

export interface StructuredAuthError {
  readonly code: string;
  readonly status: number;
  readonly retryable: boolean;
}

export interface AuthErrorOptions {
  status?: number;
  retryable?: boolean;
}

export class AuthError extends Error implements StructuredAuthError {
  readonly code: string;
  readonly status: number;
  readonly retryable: boolean;

  constructor(code: AuthErrorCode, message: string, status?: number, retryable?: boolean);
  constructor(code: AuthErrorCode, message: string, options?: AuthErrorOptions);
  constructor(code: AuthErrorCode, message: string, statusOrOptions: number | AuthErrorOptions = 0, retryable?: boolean) {
    super(message);
    this.name = "AuthError";
    this.code = code;
    const options = typeof statusOrOptions === "number" ? { status: statusOrOptions, retryable } : statusOrOptions;
    this.status = normalizeStatus(options.status, code);
    this.retryable = typeof options.retryable === "boolean" ? options.retryable : defaultRetryable(this.status, code);
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export function toAuthError(error: unknown, code: AuthErrorCode, message: string): AuthError {
  if (error instanceof AuthError) return error;
  const value = isRecord(error) ? error : undefined;
  const candidate = value === undefined ? undefined : readString(value.code);
  const nested = value !== undefined && isRecord(value.error) ? value.error : undefined;
  const nestedCode = nested === undefined ? undefined : readString(nested.code);
  const resolvedCode = candidate ?? nestedCode ?? code;
  const resolvedStatus = readStatus(value?.status) ?? readStatus(nested?.status) ?? 0;
  const resolvedRetryable = readBoolean(value?.retryable) ?? readBoolean(nested?.retryable);
  return new AuthError(resolvedCode, message, { status: resolvedStatus, ...(resolvedRetryable === undefined ? {} : { retryable: resolvedRetryable }) });
}

export function defaultAuthErrorStatus(code: string): number {
  if (code === "network_error") return 0;
  if (code === "session_expired" || code === "session_missing" || code === "unauthorized") return 401;
  if (code === "oidc_transaction_expired") return 408;
  if (code === "session_generation_mismatch" || code === "oidc_flow_mismatch") return 409;
  if (code === "oidc_configuration_missing") return 500;
  if (code === "wechat_login_failed") return 502;
  if (code === "invalid_auth_response" || code === "invalid_oidc_callback" || code === "invalid_oidc_transaction" || code === "invalid_session" || code === "oidc_callback_denied" || code === "oidc_nonce_mismatch" || code === "oidc_origin_mismatch" || code === "oidc_state_mismatch" || code === "unsupported_platform") return 400;
  return 0;
}

function defaultRetryable(status: number, code: string): boolean {
  return code === "network_error" || status === 408 || status === 425 || status === 429 || status >= 500;
}

function normalizeStatus(value: number | undefined, code: string): number {
  return Number.isSafeInteger(value) && (value as number) >= 0 && (value as number) <= 599 ? value as number : defaultAuthErrorStatus(code);
}

function readStatus(value: unknown): number | undefined {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= 599 ? value : undefined;
}

function readBoolean(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function readString(value: unknown): string | undefined {
  return typeof value === "string" && /^[A-Za-z][A-Za-z0-9_.-]{0,127}$/u.test(value) ? value : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
