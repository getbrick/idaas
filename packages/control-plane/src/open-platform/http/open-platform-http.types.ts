import type { OpenPlatformErrorCode } from "../errors.js";
import type {
  OpenPlatformRequestContext,
  OpenPlatformRequestContextInput,
} from "../authorization.js";
import type { MaybePromise } from "../types.js";

export const OPEN_PLATFORM_HTTP_BASE_PATH = "/api/open/v1";
export const OPEN_PLATFORM_BASE_PATH = OPEN_PLATFORM_HTTP_BASE_PATH;
export const OPEN_PLATFORM_HTTP_PREFIX = OPEN_PLATFORM_HTTP_BASE_PATH;
export const OPEN_PLATFORM_HTTP_CONTEXT_RESOLVER =
  "OPEN_PLATFORM_HTTP_CONTEXT_RESOLVER";
export const OPEN_PLATFORM_HTTP_RESOLVER = OPEN_PLATFORM_HTTP_CONTEXT_RESOLVER;
export const OPEN_PLATFORM_REQUEST_CONTEXT_RESOLVER =
  OPEN_PLATFORM_HTTP_CONTEXT_RESOLVER;
export const OPEN_PLATFORM_HTTP_CONTEXT_ISSUER =
  "OPEN_PLATFORM_REQUEST_CONTEXT_ISSUER";
export const OPEN_PLATFORM_HTTP_MODE = "OPEN_PLATFORM_HTTP_MODE";
export const OPEN_PLATFORM_HTTP_CONTEXT = "openPlatformHttpContext";
export interface OpenPlatformHttpRequest {
  headers?: Record<string, unknown>;
  query?: unknown;
  body?: unknown;
  id?: unknown;
  ip?: unknown;
  ips?: unknown;
  getbrickSession?: unknown;
  [key: string]: unknown;
}

export type OpenPlatformHttpContextResolution =
  | OpenPlatformRequestContextInput
  | OpenPlatformRequestContext
  | { readonly context: OpenPlatformRequestContextInput | OpenPlatformRequestContext }
  | null
  | undefined;

export interface OpenPlatformHttpContextResolver {
  resolve(
    request: OpenPlatformHttpRequest,
  ): MaybePromise<OpenPlatformHttpContextResolution>;
}

export type OpenPlatformRequestContextResolver = OpenPlatformHttpContextResolver;
export type OpenPlatformAuthenticationContextResolver = OpenPlatformHttpContextResolver;

export type OpenPlatformHttpContextResolverFactory = (
  request: OpenPlatformHttpRequest,
) => MaybePromise<OpenPlatformHttpContextResolution>;

export interface OpenPlatformHttpContextResolverWithContext {
  resolveContext(
    request: OpenPlatformHttpRequest,
  ): MaybePromise<OpenPlatformHttpContextResolution>;
}

export type OpenPlatformHttpContextResolverLike =
  | OpenPlatformHttpContextResolver
  | OpenPlatformHttpContextResolverWithContext
  | OpenPlatformHttpContextResolverFactory;

export interface OpenPlatformHttpErrorBody {
  code: OpenPlatformErrorCode;
  message: string;
  requestId?: string;
}

export interface OpenPlatformHttpErrorResponse {
  statusCode: number;
  body: OpenPlatformHttpErrorBody;
}

export function isOpenPlatformHttpRecord(
  value: unknown,
): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
