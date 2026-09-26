import { normalizeOrigin } from "../config";
import { AuthError } from "./errors";

export interface OidcCallbackInput {
  flowId?: unknown;
  flow_id?: unknown;
  nonce?: unknown;
  origin?: unknown;
  code?: unknown;
  state?: unknown;
  ticket?: unknown;
  ticketReference?: unknown;
  error?: unknown;
  errorDescription?: unknown;
  error_description?: unknown;
}

export interface OidcCallbackOptions {
  requireFlowId?: boolean;
  requireNonce?: boolean;
  requireOrigin?: boolean;
  requireState?: boolean;
  allowedOrigins?: readonly string[];
  expectedFlowId?: string;
  expectedNonce?: string;
  expectedOrigin?: string;
  sourceOrigin?: string;
  allowProviderError?: boolean;
}

export type NormalizedOidcCallback =
  | { code: string; state: string; flowId?: string; nonce?: string; origin?: string }
  | { ticketReference: string; state?: string; flowId?: string; nonce?: string; origin?: string }
  | { error: true; state?: string; flowId?: string; nonce?: string; origin?: string };

export interface WebViewCallbackError {
  error: true;
  state?: string;
  flowId?: string;
  nonce?: string;
  origin?: string;
}

export function normalizeOidcCallback(input: OidcCallbackInput, options: OidcCallbackOptions = {}): NormalizedOidcCallback {
  if (!isRecord(input)) throw new AuthError("invalid_oidc_callback", "OIDC callback is invalid", 400, false);
  if (input.error !== undefined && input.error !== null && input.error !== "") {
    if (options.allowProviderError === true) {
      const errorState = input.state === undefined ? undefined : readValue(input.state, "state", 512);
      if (options.requireState === true && errorState === undefined) throw new AuthError("invalid_oidc_callback", "OIDC callback state is required", 400, false);
      const errorFlowId = readFlowId(input.flowId ?? input.flow_id, false);
      const errorNonce = readOpaqueValue(input.nonce, "nonce", false);
      const errorOrigin = readOrigin(input.origin, false);
      validateExpected(errorFlowId, errorNonce, errorOrigin, options);
      return { error: true, state: errorState, ...(errorFlowId === undefined ? {} : { flowId: errorFlowId }), ...(errorNonce === undefined ? {} : { nonce: errorNonce }), ...(errorOrigin === undefined ? {} : { origin: errorOrigin }) };
    }
    throw new AuthError("oidc_callback_denied", "OIDC authorization was denied", 400, false);
  }
  const ticketValue = input.ticketReference ?? input.ticket;
  const hasCode = input.code !== undefined;
  if (ticketValue !== undefined && hasCode) throw new AuthError("invalid_oidc_callback", "OIDC callback is invalid", 400, false);
  const flowId = readFlowId(input.flowId ?? input.flow_id, options.requireFlowId === true);
  const nonce = readOpaqueValue(input.nonce, "nonce", options.requireNonce === true);
  const origin = readOrigin(input.origin, options.requireOrigin === true);
  validateExpected(flowId, nonce, origin, options);
  if (ticketValue !== undefined) {
    const ticketState = input.state === undefined ? undefined : readValue(input.state, "state", 512);
    if (options.requireState === true && ticketState === undefined) throw new AuthError("invalid_oidc_callback", "OIDC callback state is required", 400, false);
    return { ticketReference: readTicketReference(ticketValue), ...(ticketState === undefined ? {} : { state: ticketState }), ...(flowId === undefined ? {} : { flowId }), ...(nonce === undefined ? {} : { nonce }), ...(origin === undefined ? {} : { origin }) };
  }
  const code = readValue(input.code, "code", 4096);
  const state = readValue(input.state, "state", 512);
  if (!/^[A-Za-z0-9._~-]+$/u.test(state)) throw new AuthError("invalid_oidc_callback", "OIDC callback is invalid", 400, false);
  return { code, state, ...(flowId === undefined ? {} : { flowId }), ...(nonce === undefined ? {} : { nonce }), ...(origin === undefined ? {} : { origin }) };
}

export function assertWebViewMessageOrigin(value: unknown, expectedOrigin: string): string {
  const origin = readOrigin(value, true) as string;
  const expected = normalizeCallbackOrigin(expectedOrigin);
  if (origin !== expected) throw new AuthError("oidc_origin_mismatch", "OIDC message origin is not allowed", 403, false);
  return origin;
}

export function parseWebViewCallback(value: unknown, options: OidcCallbackOptions = {}): NormalizedOidcCallback | WebViewCallbackError {
  const sourceOrigin = options.sourceOrigin === undefined ? undefined : normalizeCallbackOrigin(options.sourceOrigin);
  if (sourceOrigin !== undefined && options.expectedOrigin !== undefined && sourceOrigin !== normalizeCallbackOrigin(options.expectedOrigin)) {
    throw new AuthError("oidc_origin_mismatch", "OIDC message origin is not allowed", 403, false);
  }
  const parseOptions = sourceOrigin === undefined ? options : { ...options, expectedOrigin: sourceOrigin, requireOrigin: true };
  const candidates = Array.isArray(value) ? value : [value];
  for (const candidate of candidates) {
    const parsed = parseCandidate(candidate, parseOptions);
    if (parsed !== undefined) return parsed;
  }
  throw new AuthError("invalid_oidc_callback", "OIDC callback is invalid", 400, false);
}

export function assertCallbackMatchesTransaction(
  callback: NormalizedOidcCallback,
  transaction: { flowId: string; state: string; nonce: string; origin: string },
  options: { requireNonce?: boolean; requireOrigin?: boolean } = {},
): void {
  if (callback.flowId !== undefined && callback.flowId !== transaction.flowId) {
    throw new AuthError("oidc_flow_mismatch", "OIDC flow does not match the login transaction", 409, false);
  }
  if ("state" in callback && callback.state !== transaction.state) {
    throw new AuthError("oidc_state_mismatch", "OIDC state does not match the login transaction", 400, false);
  }
  if (options.requireNonce === true || callback.nonce !== undefined) {
    if (callback.nonce !== transaction.nonce) throw new AuthError("oidc_nonce_mismatch", "OIDC nonce does not match the login transaction", 400, false);
  }
  if (options.requireOrigin === true || callback.origin !== undefined) {
    if (callback.origin !== transaction.origin) throw new AuthError("oidc_origin_mismatch", "OIDC origin does not match the login transaction", 400, false);
  }
}

function parseCandidate(value: unknown, options: OidcCallbackOptions): NormalizedOidcCallback | WebViewCallbackError | undefined {
  let record: Record<string, unknown> | undefined;
  if (typeof value === "string") {
    try {
      const parsed: unknown = JSON.parse(value);
      record = isRecord(parsed) ? parsed : undefined;
    } catch {
      record = undefined;
    }
  } else if (isRecord(value)) {
    record = value;
  }
  if (record === undefined) return undefined;
  if (isRecord(record.data) && record.code === undefined && record.state === undefined && record.ticket === undefined && record.ticketReference === undefined) {
    const nestedOrigin = record.origin ?? options.expectedOrigin;
    const nested = parseCandidate(record.data, {
      ...options,
      ...(nestedOrigin === undefined ? {} : { expectedOrigin: normalizeCallbackOrigin(nestedOrigin) }),
    });
    return nested;
  }
  const effectiveRecord = record.origin === undefined && options.expectedOrigin !== undefined
    ? { ...record, origin: options.expectedOrigin }
    : record;
  if (effectiveRecord.type !== undefined && effectiveRecord.type !== "getbrick-oidc-callback") return undefined;
  if (effectiveRecord.error !== undefined && effectiveRecord.error !== null && effectiveRecord.error !== "") {
    const flowId = readFlowId(effectiveRecord.flowId ?? effectiveRecord.flow_id, options.requireFlowId === true);
    const nonce = readOpaqueValue(effectiveRecord.nonce, "nonce", options.requireNonce === true);
     const origin = readOrigin(effectiveRecord.origin, options.requireOrigin === true);
     const state = effectiveRecord.state === undefined ? undefined : readValue(effectiveRecord.state, "state", 512);
     if (options.requireState === true && state === undefined) throw new AuthError("invalid_oidc_callback", "OIDC callback state is required", 400, false);
     validateExpected(flowId, nonce, origin, options);

    return { error: true, ...(state === undefined ? {} : { state }), ...(flowId === undefined ? {} : { flowId }), ...(nonce === undefined ? {} : { nonce }), ...(origin === undefined ? {} : { origin }) };
  }
  if (effectiveRecord.code === undefined && effectiveRecord.state === undefined && effectiveRecord.ticket === undefined && effectiveRecord.ticketReference === undefined && effectiveRecord.flowId === undefined && effectiveRecord.flow_id === undefined) return undefined;
  return normalizeOidcCallback(effectiveRecord, options);
}

function validateExpected(flowId: string | undefined, nonce: string | undefined, origin: string | undefined, options: OidcCallbackOptions): void {
  if (options.expectedFlowId !== undefined && flowId !== options.expectedFlowId) throw new AuthError("oidc_flow_mismatch", "OIDC flow does not match the login transaction", 409, false);
  if (options.expectedNonce !== undefined && nonce !== options.expectedNonce) throw new AuthError("oidc_nonce_mismatch", "OIDC nonce does not match the login transaction", 400, false);
  if (options.expectedOrigin !== undefined && origin !== undefined && origin !== normalizeCallbackOrigin(options.expectedOrigin)) throw new AuthError("oidc_origin_mismatch", "OIDC origin does not match the login transaction", 400, false);
  if (options.allowedOrigins !== undefined && origin !== undefined) {
    const allowed = options.allowedOrigins.map((value) => normalizeCallbackOrigin(value));
    if (!allowed.includes(origin)) throw new AuthError("oidc_origin_mismatch", "OIDC origin is not allowed", 403, false);
  }
}

function readFlowId(value: unknown, required: boolean): string | undefined {
  if (value === undefined || value === null || value === "") {
    if (required) throw new AuthError("invalid_oidc_callback", "OIDC callback flow ID is required", 400, false);
    return undefined;
  }
  if (typeof value !== "string" || value.length < 16 || value.length > 128 || !/^[A-Za-z0-9_-]+$/u.test(value) || /(?:token|secret|authorization|session[_-]?key|refresh|access|id[_-]?token|code)/iu.test(value)) {
    throw new AuthError("invalid_oidc_callback", "OIDC callback flow ID is invalid", 400, false);
  }
  return value;
}

function readOpaqueValue(value: unknown, field: string, required: boolean): string | undefined {
  if (value === undefined || value === null || value === "") {
    if (required) throw new AuthError("invalid_oidc_callback", `OIDC callback ${field} is required`, 400, false);
    return undefined;
  }
  if (typeof value !== "string" || value.length < 16 || value.length > 512 || /[\u0000-\u001f\u007f\s]/u.test(value) || !/^[A-Za-z0-9._~-]+$/u.test(value)) {
    throw new AuthError("invalid_oidc_callback", `OIDC callback ${field} is invalid`, 400, false);
  }
  return value;
}

function readOrigin(value: unknown, required: boolean): string | undefined {
  if (value === undefined || value === null || value === "") {
    if (required) throw new AuthError("invalid_oidc_callback", "OIDC callback origin is required", 400, false);
    return undefined;
  }
  if (typeof value !== "string") throw new AuthError("invalid_oidc_callback", "OIDC callback origin is invalid", 400, false);
  try {
    return normalizeCallbackOrigin(value);
  } catch {
    throw new AuthError("invalid_oidc_callback", "OIDC callback origin is invalid", 400, false);
  }
}

function normalizeCallbackOrigin(value: unknown): string {
  if (typeof value !== "string") throw new AuthError("invalid_oidc_callback", "OIDC callback origin is invalid", 400, false);
  try {
    return normalizeOrigin(value);
  } catch {
    throw new AuthError("invalid_oidc_callback", "OIDC callback origin is invalid", 400, false);
  }
}

function readValue(value: unknown, field: string, max: number): string {
  if (typeof value !== "string") throw new AuthError("invalid_oidc_callback", "OIDC callback is invalid", 400, false);
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > max || /[\u0000-\u001f\u007f\s]/u.test(normalized)) throw new AuthError("invalid_oidc_callback", "OIDC callback is invalid", 400, false);
  if (field === "code" && !/^[A-Za-z0-9._~-]+$/u.test(normalized)) throw new AuthError("invalid_oidc_callback", "OIDC callback is invalid", 400, false);
  return normalized;
}

function readTicketReference(value: unknown): string {
  if (typeof value !== "string" || value.length < 24 || value.length > 512 || !/^[A-Za-z0-9_-]+$/u.test(value) || /(?:token|secret|authorization|session[_-]?key|refresh|access|id[_-]?token|code|state)/iu.test(value)) {
    throw new AuthError("invalid_oidc_callback", "OIDC callback is invalid", 400, false);
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
