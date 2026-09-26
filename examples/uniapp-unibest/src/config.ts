export interface ClientConfig {
  apiBaseUrl: string;
  authBasePath: string;
  platformBasePath: string;
  applicationId: string;
  platformId: string;
  requestTimeoutMs: number;
  oidc: {
    clientId: string;
    scope: string;
    h5RedirectUri: string;
    appRedirectUri: string;
    webviewOrigin?: string;
    allowedOrigins?: readonly string[];
    webviewAllowedOrigins?: readonly string[];
    originAllowlist?: readonly string[];
    webviewOriginAllowlist?: readonly string[];
  };
}

export const H5_OIDC_CALLBACK_PATH = "/pages/auth/callback";
export const PLATFORM_WEBVIEW_START_ROUTE = "login/webview/start";
export const PLATFORM_WEBVIEW_CALLBACK_ROUTE = "login/webview/callback";
export const PLATFORM_WEBVIEW_EXCHANGE_ROUTE = "login/webview/exchange";
export const PLATFORM_WEBVIEW_TICKET_EXCHANGE_ROUTE = "webview/ticket/exchange";
export const PLATFORM_SESSION_REFRESH_ROUTE = "login/session/refresh";
export const PLATFORM_SESSION_LOGOUT_ROUTE = "login/session/logout";

const environment = readEnvironment();

export const clientConfig: ClientConfig = {
  apiBaseUrl: normalizeBaseUrl(environment.VITE_API_BASE_URL ?? "https://api.example.com"),
  authBasePath: normalizePath(environment.VITE_AUTH_BASE_PATH ?? "/api/idaas/v1/client/auth"),
  platformBasePath: normalizePath(environment.VITE_PLATFORM_BASE_PATH ?? "/api/idaas/v1"),
  applicationId: readText(environment.VITE_APPLICATION_ID),
  platformId: readText(environment.VITE_PLATFORM_ID),
  requestTimeoutMs: normalizeTimeout(environment.VITE_REQUEST_TIMEOUT_MS),
  oidc: {
    clientId: readText(environment.VITE_OIDC_CLIENT_ID),
    scope: readText(environment.VITE_OIDC_SCOPE) || "openid profile",
    h5RedirectUri: readText(environment.VITE_OIDC_H5_REDIRECT_URI),
    appRedirectUri: readText(environment.VITE_OIDC_APP_REDIRECT_URI),
    webviewOrigin: readText(environment.VITE_OIDC_WEBVIEW_ORIGIN),
    allowedOrigins: readOrigins(environment.VITE_OIDC_ALLOWED_ORIGINS),
    webviewAllowedOrigins: readOrigins(environment.VITE_OIDC_WEBVIEW_ALLOWED_ORIGINS),
    originAllowlist: readOrigins(environment.VITE_OIDC_ORIGIN_ALLOWLIST),
    webviewOriginAllowlist: readOrigins(environment.VITE_OIDC_WEBVIEW_ORIGIN_ALLOWLIST),
  },
};

export function getOidcRedirectUri(platform: "h5" | "app", config: ClientConfig = clientConfig): string {
  const configured = platform === "h5" ? config.oidc.h5RedirectUri : config.oidc.appRedirectUri;
  if (platform === "h5") {
    if (configured.length > 0) return assertH5CallbackRedirectUri(configured);
    const location = (globalThis as { location?: { origin?: string } }).location;
    if (location?.origin) return `${location.origin}${H5_OIDC_CALLBACK_PATH}`;
  }
  return getWebviewRedirectUri(config);
}

export function assertH5CallbackRedirectUri(value: string): string {
  return assertRedirectText(value);
}

export function getWebviewRedirectUri(config: ClientConfig = clientConfig): string {
  const configured = config.oidc.appRedirectUri;
  if (configured.length === 0) throw new Error("OIDC app bridge redirect is required");
  return assertWebviewBridgeRedirectUri(configured);
}

export function getWebviewBridgeOrigin(config: ClientConfig = clientConfig): string {
  const redirectUri = getWebviewRedirectUri(config);
  const parsed = new URL(redirectUri);
  return normalizeOrigin(parsed.origin);
}

export function getOidcCallbackRoute(platform: "h5" | "app", config: ClientConfig = clientConfig): string {
  const redirect = new URL(getOidcRedirectUri(platform, config));
  return `${redirect.pathname}${redirect.search}`;
}

export function getPlatformRoute(config: ClientConfig, route: string): string {
  if (typeof route !== "string" || route.length === 0 || route.startsWith("/") || /[\u0000-\u001f\u007f?#]/u.test(route)) {
    throw new Error("Platform route is invalid");
  }
  assertPathIdentifier(config.applicationId, "application");
  assertPathIdentifier(config.platformId, "platform");
  return `${config.platformBasePath}/applications/${encodeURIComponent(config.applicationId)}/platforms/${encodeURIComponent(config.platformId)}/${route}`;
}

export function getConfiguredOrigins(platform: "h5" | "app", config: ClientConfig = clientConfig): readonly string[] {
  const configured = platform === "app"
    ? config.oidc.webviewOriginAllowlist ?? config.oidc.webviewAllowedOrigins ?? config.oidc.originAllowlist ?? config.oidc.allowedOrigins ?? (config.oidc.webviewOrigin === undefined ? undefined : [config.oidc.webviewOrigin])
    : config.oidc.originAllowlist ?? config.oidc.allowedOrigins;
  return (configured ?? []).map((value) => normalizeOrigin(value));
}

export function assertOidcConfig(platform: "h5" | "app", config: ClientConfig = clientConfig): void {
  if (config.oidc.clientId.length === 0) {
    throw new Error("OIDC client configuration is incomplete");
  }
  getOidcRedirectUri(platform, config);
  if (platform === "app") {
    const bridgeOrigin = getWebviewBridgeOrigin(config);
    const allowedOrigins = getConfiguredOrigins("app", config);
    if (!allowedOrigins.includes(bridgeOrigin)) throw new Error("OIDC app bridge origin is not allowed");
    getPlatformRoute(config, PLATFORM_WEBVIEW_CALLBACK_ROUTE);
  }
}

export function assertApiBaseUrl(value: string): string {
  return normalizeBaseUrl(value);
}

export function normalizeOrigin(value: string): string {
  const normalized = readText(value);
  if (normalized.length === 0 || normalized.length > 512 || /[\u0000-\u001f\u007f\s\\]/u.test(normalized)) {
    throw new Error("OIDC origin is invalid");
  }
  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    throw new Error("OIDC origin is invalid");
  }
  if (
    (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
    (parsed.protocol !== "https:" && !isLoopbackHost(parsed.hostname)) ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.pathname !== "" && parsed.pathname !== "/" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    parsed.origin === "null" ||
    parsed.origin !== normalized
  ) {
    throw new Error("OIDC origin is invalid");
  }
  return parsed.origin;
}

function readEnvironment(): Record<string, string | undefined> {
  const meta = import.meta as unknown as { env?: Record<string, string | undefined> };
  return meta.env ?? {};
}

function readText(value: string | undefined): string {
  return typeof value === "string" ? value.trim() : "";
}

function readOrigins(value: string | undefined): string[] {
  if (typeof value !== "string") return [];
  return value.split(",").map((item) => item.trim()).filter((item) => item.length > 0);
}

function normalizeBaseUrl(value: string): string {
  const normalized = readText(value);
  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    throw new Error("API base URL is invalid");
  }
  if (
    (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
    (parsed.protocol !== "https:" && !isLoopbackHost(parsed.hostname)) ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.hash !== "" ||
    parsed.hostname.length === 0 ||
    /[\u0000-\u001f\u007f\s]/u.test(normalized)
  ) {
    throw new Error("API base URL is invalid");
  }
  return parsed.toString().replace(/\/$/u, "");
}

function normalizePath(value: string): string {
  const normalized = readText(value);
  if (!normalized.startsWith("/") || normalized.includes("?") || normalized.includes("#") || /[\u0000-\u001f\u007f\s]/u.test(normalized)) {
    throw new Error("Auth base path is invalid");
  }
  return normalized.replace(/\/$/u, "");
}

function normalizeTimeout(value: string | undefined): number {
  const parsed = Number.parseInt(value ?? "15000", 10);
  return Number.isSafeInteger(parsed) && parsed >= 1000 && parsed <= 120000 ? parsed : 15000;
}

function assertWebviewBridgeRedirectUri(value: string): string {
  const normalized = readText(value);
  if (normalized.length === 0 || normalized.length > 2048 || /[\u0000-\u001f\u007f\s\\#]/u.test(normalized)) {
    throw new Error("OIDC app bridge redirect is invalid");
  }
  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    throw new Error("OIDC app bridge redirect is invalid");
  }
  if (
    (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
    (parsed.protocol !== "https:" && !isLoopbackHost(parsed.hostname)) ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.hash !== "" ||
    parsed.origin === "null"
  ) {
    throw new Error("OIDC app bridge redirect is invalid");
  }
  return normalized;
}

function assertRedirectText(value: string): string {
  const normalized = readText(value);
  if (normalized.length === 0 || normalized.length > 2048 || /[\u0000-\u001f\u007f\s\\#]/u.test(normalized)) {
    throw new Error("OIDC redirect URI is invalid");
  }
  try {
    const parsed = new URL(normalized);
    if (parsed.hash !== "" || parsed.username !== "" || parsed.password !== "") throw new Error("invalid");
  } catch {
    throw new Error("OIDC redirect URI is invalid");
  }
  return normalized;
}

function assertPathIdentifier(value: string, field: string): void {
  if (typeof value !== "string" || value.length === 0 || value.length > 256 || /[\u0000-\u001f\u007f/]/u.test(value)) {
    throw new Error(`${field} identifier is invalid`);
  }
}

function isLoopbackHost(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}
