import type { NestMiddleware } from "@nestjs/common";
import { Inject, Optional } from "@nestjs/common";
import {
  AUTH_BASE_PATH,
  GETBRICK_AUTH,
  GETBRICK_AUTH_BASE_PATH,
  GETBRICK_AUTH_BASE_URL,
  GETBRICK_TRUST_PROXY,
  type GetbrickAuthLike,
} from "./tokens.js";

const BODY_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const DEFAULT_DEVELOPMENT_ORIGIN = "http://localhost";
const FORWARDED_HOST_HEADER = "x-forwarded-host";
const FORWARDED_PROTO_HEADER = "x-forwarded-proto";

export interface GetbrickAdapterRequest {
  originalUrl?: string;
  url?: string;
  method: string;
  headers: Record<string, unknown>;
  body?: unknown;
}

export interface ToWebRequestOptions {
  baseURL?: string | URL;
  trustProxy?: boolean;
}

export class GetbrickAuthMiddleware implements NestMiddleware {
  private readonly baseURL?: string;
  private readonly trustProxy: boolean;

  constructor(
    @Inject(GETBRICK_AUTH) private readonly auth: GetbrickAuthLike,
    @Optional() @Inject(GETBRICK_AUTH_BASE_PATH) private readonly basePath = AUTH_BASE_PATH,
    @Optional() @Inject(GETBRICK_AUTH_BASE_URL) baseURL?: string,
    @Optional() @Inject(GETBRICK_TRUST_PROXY) trustProxy = false,
  ) {
    this.baseURL = normalizeCanonicalOrigin(
      baseURL !== undefined ? baseURL : auth.options?.baseURL,
    );
    this.trustProxy = normalizeTrustProxy(trustProxy);
  }

  async use(req: GetbrickAdapterRequest, res: any, next: () => void): Promise<void> {
    try {
      const url = req.originalUrl ?? req.url ?? "";
      if (!isAuthPath(url, this.basePath)) {
        next();
        return;
      }
      const webRequest = toWebRequest(req, {
        baseURL: this.baseURL,
        trustProxy: this.trustProxy,
      });
      const webResponse = await this.auth.handler(webRequest);
      await writeWebResponse(webResponse, res);
    } catch {
      if (res.headersSent) {
        res.end();
        return;
      }
      res.status(500).json({ message: "Internal Server Error" });
    }
  }
}

export function isAuthPath(url: string | undefined, basePath = AUTH_BASE_PATH): boolean {
  const pathname = getPathname(url ?? "");
  const normalizedBasePath = normalizeAuthBasePath(basePath);
  if (normalizedBasePath === "/") return pathname === "/";
  return pathname === normalizedBasePath || pathname.startsWith(`${normalizedBasePath}/`);
}

export function toWebRequest(req: GetbrickAdapterRequest, options?: ToWebRequestOptions): Request;
export function toWebRequest(req: GetbrickAdapterRequest, baseURL?: string | URL, trustProxy?: boolean): Request;
export function toWebRequest(
  req: GetbrickAdapterRequest,
  optionsOrBaseURL: ToWebRequestOptions | string | URL = {},
  trustProxy = false,
): Request {
  const options = isURLValue(optionsOrBaseURL)
    ? { baseURL: optionsOrBaseURL, trustProxy }
    : optionsOrBaseURL;
  const origin = resolveCanonicalOrigin(options.baseURL, req.headers ?? {}, options.trustProxy);
  const requestPath = req.originalUrl ?? req.url ?? "/";
  const url = buildRequestURL(requestPath, origin);
  const headers = buildRequestHeaders(req.headers ?? {}, origin, options.trustProxy);
  const hasBody = BODY_METHODS.has(req.method.toUpperCase()) && req.body !== undefined;
  const body = hasBody ? JSON.stringify(req.body) : undefined;
  if (!hasBody) headers.delete("content-type");
  return new Request(url, {
    method: req.method,
    headers,
    body: body ?? undefined,
  });
}

export function resolveCanonicalOrigin(
  baseURL: string | URL | undefined,
  headers: Record<string, unknown> = {},
  trustProxy = false,
): string {
  const shouldTrustProxy = normalizeTrustProxy(trustProxy);
  const forwardedOrigin = shouldTrustProxy ? getForwardedOrigin(headers) : undefined;
  const configuredOrigin = normalizeCanonicalOrigin(baseURL);
  if (configuredOrigin) return configuredOrigin;

  if (forwardedOrigin) {
    const origin = normalizeCanonicalOrigin(forwardedOrigin, "forwarded origin");
    if (origin) return origin;
  }

  if (isProductionEnvironment()) {
    throw configurationError("baseURL is required in production unless trusted forwarded headers are provided");
  }
  return DEFAULT_DEVELOPMENT_ORIGIN;
}

export function normalizeCanonicalOrigin(value: unknown, source = "baseURL"): string | undefined {
  if (value === undefined) return undefined;

  let raw: string;
  if (value instanceof URL) {
    raw = value.toString();
  } else if (typeof value === "string") {
    raw = value;
  } else {
    throw configurationError(`${source} must be a valid absolute HTTP(S) URL`);
  }

  if (raw.length === 0 || raw.trim() !== raw || /[\s\u0000-\u001f\u007f]/.test(raw)) {
    throw configurationError(`${source} must be a valid absolute HTTP(S) URL`);
  }

  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw configurationError(`${source} must be a valid absolute HTTP(S) URL`);
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw configurationError(`${source} must use the http or https protocol`);
  }
  if (!parsed.hostname) {
    throw configurationError(`${source} must include a host`);
  }
  if (parsed.username || parsed.password) {
    throw configurationError(`${source} must not include credentials`);
  }
  if (parsed.search || parsed.hash) {
    throw configurationError(`${source} must not include a query string or fragment`);
  }
  if (parsed.origin === "null") {
    throw configurationError(`${source} must have a valid origin`);
  }
  if (isProductionEnvironment() && parsed.protocol !== "https:") {
    throw configurationError(`${source} must use HTTPS in production`);
  }
  return parsed.origin;
}

export function normalizeTrustProxy(value: unknown): boolean {
  if (value === undefined) return false;
  if (typeof value !== "boolean") {
    throw configurationError("trustProxy must be a boolean");
  }
  return value;
}

export async function writeWebResponse(response: Response, res: any): Promise<void> {
  const cookies = typeof response.headers.getSetCookie === "function" ? response.headers.getSetCookie() : [];
  res.status(response.status);
  response.headers.forEach((value, key) => {
    if (key.toLowerCase() === "set-cookie") return;
    res.setHeader(key, value);
  });
  for (const cookie of cookies) {
    res.append("Set-Cookie", cookie);
  }
  const text = await response.text();
  res.send(text);
}

function buildRequestURL(requestPath: string, origin: string): string {
  if (typeof requestPath !== "string") {
    throw configurationError("request URL must be a string");
  }
  let parsed: URL;
  try {
    parsed = new URL(requestPath || "/", origin);
  } catch {
    throw configurationError("request URL is invalid");
  }
  if (parsed.origin !== new URL(origin).origin) {
    throw configurationError("request URL must use the canonical origin");
  }
  if (parsed.hash) {
    throw configurationError("request URL must not include a fragment");
  }
  return parsed.toString();
}

function buildRequestHeaders(
  incoming: Record<string, unknown>,
  origin: string,
  trustProxy: unknown,
): Headers {
  const headers = new Headers();
  for (const [key, value] of Object.entries(incoming)) {
    const normalizedKey = key.toLowerCase();
    if (normalizedKey === "content-length" || normalizedKey === "host" || normalizedKey === "forwarded" || normalizedKey.startsWith("x-forwarded-")) {
      continue;
    }
    appendHeader(headers, key, value);
  }

  const canonical = new URL(origin);
  headers.set("host", canonical.host);
  if (normalizeTrustProxy(trustProxy)) {
    if (hasHeader(incoming, FORWARDED_HOST_HEADER)) headers.set(FORWARDED_HOST_HEADER, canonical.host);
    if (hasHeader(incoming, FORWARDED_PROTO_HEADER)) headers.set(FORWARDED_PROTO_HEADER, canonical.protocol.slice(0, -1));
  }
  return headers;
}

function getForwardedOrigin(headers: Record<string, unknown>): string | undefined {
  const hostValue = getHeaderValue(headers, FORWARDED_HOST_HEADER);
  const protoValue = getHeaderValue(headers, FORWARDED_PROTO_HEADER);
  if (hostValue === undefined && protoValue === undefined) return undefined;

  const host = hostValue === undefined ? undefined : validateForwardedHost(hostValue);
  const protocol = protoValue === undefined ? undefined : validateForwardedProtocol(protoValue);
  if (!host || !protocol) return undefined;
  return `${protocol}://${host}`;
}

function validateForwardedHost(value: string): string {
  if (value.length === 0 || value.trim() !== value || /[\0\s/\\?#@,%]/.test(value) || value.includes(",")) {
    throw configurationError("X-Forwarded-Host must be a valid host");
  }
  let parsed: URL;
  try {
    parsed = new URL(`http://${value}`);
  } catch {
    throw configurationError("X-Forwarded-Host must be a valid host");
  }
  if (!parsed.hostname || parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash) {
    throw configurationError("X-Forwarded-Host must be a valid host");
  }
  return parsed.host;
}

function validateForwardedProtocol(value: string): string {
  const protocol = value.toLowerCase();
  if (value.trim() !== value || (protocol !== "http" && protocol !== "https")) {
    throw configurationError("X-Forwarded-Proto must be http or https");
  }
  return protocol;
}

function getHeaderValue(headers: Record<string, unknown>, name: string): string | undefined {
  let found = false;
  let result: string | undefined;
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== name) continue;
    if (found) throw configurationError(`${name} must contain one value`);
    found = true;
    if (value === undefined) continue;
    if (typeof value === "string") {
      result = value;
      continue;
    }
    if (Array.isArray(value) && value.length === 1 && typeof value[0] === "string") {
      result = value[0];
      continue;
    }
    throw configurationError(`${name} must contain one string value`);
  }
  return result;
}

function hasHeader(headers: Record<string, unknown>, name: string): boolean {
  return Object.keys(headers).some((key) => key.toLowerCase() === name);
}

function appendHeader(headers: Headers, key: string, value: unknown): void {
  if (typeof value === "string") {
    headers.set(key, value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      if (typeof item === "string") headers.append(key, item);
    }
  }
}

function isURLValue(value: ToWebRequestOptions | string | URL): value is string | URL {
  return typeof value === "string" || value instanceof URL;
}

function isProductionEnvironment(): boolean {
  return process.env.NODE_ENV === "production";
}

function configurationError(message: string): Error {
  return new Error(`[getbrick-idaas] ${message}`);
}

function getPathname(url: string): string {
  try {
    return new URL(url, "http://localhost").pathname;
  } catch {
    return url.split(/[?#]/)[0] ?? "";
  }
}

export function normalizeAuthBasePath(value: string): string {
  let path = value.trim();
  try {
    path = new URL(path, "http://localhost").pathname;
  } catch {
    if (!path.startsWith("/")) path = `/${path}`;
  }
  path = path.replace(/\/+$/, "");
  return path || "/";
}
