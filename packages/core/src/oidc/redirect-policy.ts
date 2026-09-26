export type OidcApplicationType = "web" | "native" | "webview";

export type OidcRedirectAuthMethod =
  | "none"
  | "client_secret_basic"
  | "client_secret_post"
  | "private_key_jwt";

export interface OidcRedirectClient {
  applicationType: OidcApplicationType;
  tokenEndpointAuthMethod: string;
  requirePkce: boolean;
  application_type?: OidcApplicationType;
  token_endpoint_auth_method?: string;
  require_pkce?: boolean;
}

export interface OidcRedirectPolicyOptions {
  allowInsecureHttp?: boolean;
}

export interface OidcRedirectUriSet extends OidcRedirectClient {
  redirectUris: readonly string[];
  postLogoutRedirectUris?: readonly string[];
}

const REVERSE_DOMAIN_SCHEME =
  /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/iu;
const BLOCKED_SCHEMES = new Set(["data:", "file:", "javascript:", "vbscript:"]);

export function parseOidcRedirectUri(value: unknown): URL | undefined {
  const raw = typeof value === "string" ? value : value instanceof URL ? value.href : undefined;
  if (raw === undefined || raw.length === 0 || raw.length > 2048) return undefined;
  if (hasUnsafeRedirectText(raw)) return undefined;
  try {
    const parsed = new URL(raw);
    const separator = raw.indexOf(":");
    if (
      (parsed.protocol === "http:" || parsed.protocol === "https:") &&
      (separator < 0 || !raw.slice(separator + 1).startsWith("//") || raw.slice(separator + 1).startsWith("///"))
    ) {
      return undefined;
    }
    if (
      parsed.username !== "" ||
      parsed.password !== "" ||
      parsed.hash !== "" ||
      ((parsed.protocol === "http:" || parsed.protocol === "https:") && parsed.hostname === "") ||
      (parsed.protocol !== "http:" && parsed.protocol !== "https:" && parsed.hostname !== "")
    ) {
      return undefined;
    }
    return parsed;
  } catch {
    return undefined;
  }
}

function hasUnsafeRedirectText(value: string): boolean {
  if (/%(?![0-9a-f]{2})/iu.test(value)) return true;
  let decoded = value;
  for (let depth = 0; depth <= value.length; depth += 1) {
    if (/[\u0000-\u001f\u007f]/u.test(decoded) || decoded.includes("\\")) return true;
    if (!/%[0-9a-f]{2}/iu.test(decoded)) return false;
    let next: string;
    try {
      next = decodeURIComponent(decoded);
    } catch {
      return true;
    }
    if (next === decoded) return false;
    decoded = next;
  }
  return true;
}

export function isRfc8252PrivateUseRedirectUri(value: string | URL): boolean {
  const raw = typeof value === "string" ? value : value.href;
  const parsed = typeof value === "string" ? parseOidcRedirectUri(value) : parseOidcRedirectUri(value.href);
  if (!parsed || parsed.protocol === "http:" || parsed.protocol === "https:") return false;
  if (raw.includes("#") || raw.includes("\\") || BLOCKED_SCHEMES.has(parsed.protocol)) return false;
  const separator = raw.indexOf(":");
  if (separator <= 0 || separator > 255) return false;
  const scheme = raw.slice(0, separator);
  if (!REVERSE_DOMAIN_SCHEME.test(scheme)) return false;
  const schemeSpecificPart = raw.slice(separator + 1);
  return (
    parsed.hostname === "" &&
    schemeSpecificPart.startsWith("/") &&
    !schemeSpecificPart.startsWith("//") &&
    parsed.pathname.startsWith("/")
  );
}

export function isSafeOidcRedirectUri(
  value: unknown,
  client: OidcRedirectClient,
  options: OidcRedirectPolicyOptions = {},
): boolean {
  const parsed = parseOidcRedirectUri(value);
  const metadata = client as OidcRedirectClient & {
    application_type?: OidcApplicationType;
    token_endpoint_auth_method?: string;
    require_pkce?: boolean;
  };
  if (
    (client.applicationType !== undefined && metadata.application_type !== undefined && client.applicationType !== metadata.application_type) ||
    (client.tokenEndpointAuthMethod !== undefined && metadata.token_endpoint_auth_method !== undefined && client.tokenEndpointAuthMethod !== metadata.token_endpoint_auth_method) ||
    (client.requirePkce !== undefined && metadata.require_pkce !== undefined && client.requirePkce !== metadata.require_pkce)
  ) return false;
  const applicationType = client.applicationType ?? metadata.application_type;
  const tokenEndpointAuthMethod = client.tokenEndpointAuthMethod ?? metadata.token_endpoint_auth_method;
  const requirePkce = client.requirePkce ?? metadata.require_pkce ?? true;
  if (!parsed || (applicationType !== "web" && applicationType !== "native" && applicationType !== "webview")) return false;
  if (applicationType === "web" || applicationType === "webview") {
    if (parsed.protocol === "https:") return true;
    return parsed.protocol === "http:" && options.allowInsecureHttp === true;
  }
  if (parsed.protocol === "https:") return !isLoopbackHost(parsed.hostname);
  if (parsed.protocol === "http:") {
    return isLoopbackHost(parsed.hostname) && options.allowInsecureHttp === true;
  }
  return (
    isRfc8252PrivateUseRedirectUri(value as string) &&
    tokenEndpointAuthMethod === "none" &&
    requirePkce
  );
}

export function assertOidcRedirectUri(
  value: unknown,
  client: OidcRedirectClient,
  options: OidcRedirectPolicyOptions = {},
): string {
  if (!isSafeOidcRedirectUri(value, client, options)) {
    throw new Error("[getbrick-idaas] OIDC redirect URI violates the redirect policy");
  }
  return value as string;
}

export function assertOidcClientRedirectPolicy(
  client: OidcRedirectUriSet,
  options: OidcRedirectPolicyOptions = {},
): void {
  if (client.redirectUris.length === 0) {
    throw new Error("[getbrick-idaas] OIDC client requires at least one redirect URI");
  }
  const seen = new Set<string>();
  for (const uri of client.redirectUris) {
    assertOidcRedirectUri(uri, client, options);
    if (seen.has(uri)) {
      throw new Error("[getbrick-idaas] OIDC client contains a duplicate redirect URI");
    }
    seen.add(uri);
  }
  const seenPostLogout = new Set<string>();
  for (const uri of client.postLogoutRedirectUris ?? []) {
    assertOidcRedirectUri(uri, client, options);
    if (seenPostLogout.has(uri)) {
      throw new Error("[getbrick-idaas] OIDC client contains a duplicate post-logout redirect URI");
    }
    seenPostLogout.add(uri);
  }
}

export function isExactOidcRedirectUri(expected: unknown, actual: unknown): boolean {
  if (typeof expected !== "string" || typeof actual !== "string") return false;
  return expected === actual && parseOidcRedirectUri(expected) !== undefined && parseOidcRedirectUri(actual) !== undefined;
}

export function assertExactOidcRedirectUri(expected: unknown, actual: unknown): string {
  if (!isExactOidcRedirectUri(expected, actual)) {
    throw new Error("[getbrick-idaas] OIDC redirect URI does not exactly match registration");
  }
  return actual as string;
}

export function isLoopbackHost(hostname: string): boolean {
  const normalized = hostname.toLowerCase();
  return normalized === "localhost" || normalized === "127.0.0.1" || normalized === "[::1]";
}
