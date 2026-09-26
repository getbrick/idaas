import { isIP } from "node:net";
import { isOpenPlatformRequestContext } from "../authorization.js";
import {
  normalizeIdentifier,
  normalizeResourceId,
  normalizeTenantKey,
} from "../validation.js";
import {
  OPEN_PLATFORM_RUNTIME_ERROR_CODES,
  runtimeError,
  type OpenPlatformRuntimeErrorCode,
} from "./errors.js";
import {
  OPEN_PLATFORM_API_METHODS,
  type OpenPlatformApiMethod,
  type OpenPlatformApiRequestContext,
} from "./types.js";

export interface OpenPlatformApiRequestContextInput {
  readonly method: string;
  readonly path: string;
  readonly audience: string;
  readonly tenantId: string;
  readonly applicationId: string;
  readonly clientId: string;
  readonly ip: string;
  readonly requestId: string;
}

const trustedRequestContexts = new WeakSet<object>();

export function createOpenPlatformApiRequestContext(
  input: OpenPlatformApiRequestContextInput,
  trustedContext: unknown,
): OpenPlatformApiRequestContext {
  if (!isOpenPlatformRequestContext(trustedContext)) {
    throw runtimeError(
      OPEN_PLATFORM_RUNTIME_ERROR_CODES.AUTHENTICATION_REQUIRED,
    );
  }
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.INVALID_REQUEST);
  }
  const method = normalizeApiMethod(input.method);
  const path = normalizeApiPath(input.path);
  const audience = normalizeAudience(input.audience);
  const tenantId = normalizeTenantKey(input.tenantId);
  const applicationId = normalizeResourceId(
    input.applicationId,
    "application",
  );
  const clientId = normalizeIdentifier(input.clientId, "clientId");
  const ip = normalizeIpAddress(input.ip);
  const requestId = normalizeIdentifier(input.requestId, "requestId");
  if (
    trustedContext.tenantId !== tenantId ||
    trustedContext.requestId !== requestId
  ) {
    throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.INVALID_REQUEST);
  }
  const context = Object.freeze({
    method,
    path,
    audience,
    tenantId,
    applicationId,
    clientId,
    ip,
    requestId,
    trustedContext,
  });
  trustedRequestContexts.add(context);
  return context;
}

export function isOpenPlatformApiRequestContext(
  value: unknown,
): value is OpenPlatformApiRequestContext {
  if (
    value === null ||
    typeof value !== "object" ||
    !trustedRequestContexts.has(value) ||
    !Object.isFrozen(value)
  ) {
    return false;
  }
  const context = value as OpenPlatformApiRequestContext;
  try {
    return context.method === normalizeApiMethod(context.method) &&
      context.path === normalizeApiPath(context.path) &&
      context.audience === normalizeAudience(context.audience) &&
      context.tenantId === normalizeTenantKey(context.tenantId) &&
      context.applicationId === normalizeResourceId(
        context.applicationId,
        "application",
      ) &&
      context.clientId === normalizeIdentifier(context.clientId, "clientId") &&
      context.ip === normalizeIpAddress(context.ip) &&
      context.requestId === normalizeIdentifier(context.requestId, "requestId") &&
      isOpenPlatformRequestContext(context.trustedContext) &&
      context.trustedContext.tenantId === context.tenantId &&
      context.trustedContext.requestId === context.requestId;
  } catch {
    return false;
  }
}

export function normalizeApiMethod(value: unknown): OpenPlatformApiMethod {
  if (typeof value !== "string") {
    throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.INVALID_REQUEST);
  }
  const normalized = value.trim().toUpperCase();
  if (
    !(OPEN_PLATFORM_API_METHODS as readonly string[]).includes(normalized)
  ) {
    throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.INVALID_REQUEST);
  }
  return normalized as OpenPlatformApiMethod;
}

export function normalizeApiPath(value: unknown): string {
  if (typeof value !== "string") {
    throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.INVALID_REQUEST);
  }
  if (
    value.length < 1 ||
    value.length > 2048 ||
    !value.startsWith("/") ||
    value.includes("?") ||
    value.includes("#") ||
    value.includes("\\") ||
    /[\s\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.INVALID_REQUEST);
  }
  return value;
}

export function normalizeAudience(value: unknown): string {
  if (typeof value !== "string") {
    throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.INVALID_REQUEST);
  }
  const normalized = value.trim();
  if (
    normalized.length < 1 ||
    normalized.length > 2048 ||
    /[\s\u0000-\u001f\u007f\\]/u.test(normalized)
  ) {
    throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.INVALID_REQUEST);
  }
  return normalized;
}

export function normalizeIpAddress(value: unknown): string {
  if (typeof value !== "string" || isIP(value) === 0) {
    throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.INVALID_REQUEST);
  }
  return value;
}

export function normalizeCredentialVersion(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.INVALID_REQUEST);
  }
  return value as number;
}

export function normalizeRuntimeInstant(
  value: unknown,
  code: OpenPlatformRuntimeErrorCode = OPEN_PLATFORM_RUNTIME_ERROR_CODES.INVALID_REQUEST,
): string {
  if (typeof value !== "string") throw runtimeError(code);
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) throw runtimeError(code);
  return new Date(timestamp).toISOString();
}
