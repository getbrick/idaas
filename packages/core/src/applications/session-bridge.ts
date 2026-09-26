import { ApplicationPlatformError } from "./platforms.js";
import {
  PLATFORM_PLACEHOLDER_EMAIL_DOMAIN,
  type PlatformIdentityLinker,
  type PlatformIdentityProjection,
  type PlatformPublicUser,
  type SafePlatformIdentity,
} from "./identity-linker.js";

export type PlatformSessionClient = "web" | "native" | "mp_weixin" | "webview";

export interface PlatformSessionIssueInput {
  tenantId?: string;
  applicationId: string;
  platformId: string;
  userId: string;
  user: PlatformPublicUser;
  identity: SafePlatformIdentity;
  projection: PlatformIdentityProjection;
  account?: PlatformIdentityProjection["betterAuthAccount"];
  client?: PlatformSessionClient;
  context?: unknown;
  created: boolean;
  linked: boolean;
}

export interface PlatformSessionIssueResult {
  response?: Response;
  user?: PlatformPublicUser;
  expiresAt?: string;
  sessionId?: string;
  sessionReference?: string;
  opaqueSessionReference?: string;
  clientKind?: PlatformSessionClient | "mini_program";
}

export interface PlatformSessionIssuerBridge {
  issue(input: PlatformSessionIssueInput): PlatformSessionIssueResult | Response | Promise<PlatformSessionIssueResult | Response>;
}

export type PlatformSessionIssuer = PlatformSessionIssuerBridge;

export interface BetterAuthPlatformHostAdapter extends PlatformIdentityLinker, PlatformSessionIssuerBridge {}

export type BetterAuthPlatformAdapter = BetterAuthPlatformHostAdapter;
export type BetterAuthSessionIssuer = PlatformSessionIssuerBridge;

export const BETTER_AUTH_PLATFORM_HOST_ADAPTER = "host-injected" as const;
export const BETTER_AUTH_PLATFORM_INTEGRATION_BOUNDARY = Object.freeze({
  placeholderEmailDomain: PLATFORM_PLACEHOLDER_EMAIL_DOMAIN,
  sessionCookieOwner: "host",
  directBetterAuthPlaceholderCalls: false,
});

/**
 * Better Auth 1.7.5 does not expose a safe public operation for creating a user with
 * a deterministic placeholder email and setting that user's session in one
 * request. The host must implement this bridge with its Better Auth integration
 * and return the response that owns the session cookie. This package does not
 * synthesize Better Auth cookies or call private Better Auth context APIs.
 * The internal placeholder is non-contact and must not receive email delivery or
 * appear in a public response.
 */
export function createPlatformSessionIssuerBridge(
  issuer: PlatformSessionIssuerBridge | ((input: PlatformSessionIssueInput) => PlatformSessionIssueResult | Response | Promise<PlatformSessionIssueResult | Response>),
): PlatformSessionIssuerBridge {
  if (typeof issuer === "function") {
    return {
      issue: async (input) => normalizeAndCheckPlatformSessionResult(await issuer(input), input.client),
    };
  }
  if (!issuer || typeof issuer.issue !== "function") {
    throw new ApplicationPlatformError("invalid_session_issuer", "Platform session issuer is invalid");
  }
  return {
    issue: async (input) => normalizeAndCheckPlatformSessionResult(await issuer.issue(input), input.client),
  };
}

export const createHostInjectedPlatformSessionIssuer = createPlatformSessionIssuerBridge;
export const createSessionIssuerBridge = createPlatformSessionIssuerBridge;
export const createBetterAuthPlatformSessionIssuerBridge = createPlatformSessionIssuerBridge;

async function normalizeAndCheckPlatformSessionResult(
  value: PlatformSessionIssueResult | Response,
  client?: PlatformSessionClient,
): Promise<PlatformSessionIssueResult> {
  const result = normalizePlatformSessionIssueResult(value);
  assertPlatformSessionResultForClient(result, client);
  if (result.response !== undefined) await assertPlatformSessionResponseSafe(result.response);
  return result;
}

export function normalizePlatformSessionIssueResult(
  value: PlatformSessionIssueResult | Response,
): PlatformSessionIssueResult {
  if (isResponse(value)) return { response: value };
  if (!isRecord(value)) {
    throw new ApplicationPlatformError("invalid_session_issuer_result", "Platform session issuer returned an invalid result");
  }
  assertNoProviderSecrets(value);
  const output: PlatformSessionIssueResult = {};
  if (value.response !== undefined) {
    if (!isResponse(value.response)) {
      throw new ApplicationPlatformError("invalid_session_issuer_result", "Platform session issuer returned an invalid response");
    }
    output.response = value.response;
  }
  if (value.user !== undefined) {
    output.user = normalizePublicUser(value.user);
  }
  if (value.expiresAt !== undefined) {
    output.expiresAt = normalizeExpiresAt(value.expiresAt);
  }
  if (value.clientKind !== undefined) {
    output.clientKind = normalizeSessionClientKind(value.clientKind);
  }
  const referenceValues = [value.opaqueSessionReference, value.sessionReference, value.sessionId];
  if (referenceValues.some((entry) => entry !== undefined && entry !== null && typeof entry !== "string")) {
    throw new ApplicationPlatformError("invalid_session_issuer_result", "Platform session issuer returned an invalid session reference");
  }
  const references = referenceValues.filter((entry): entry is string => typeof entry === "string");
  if (new Set(references).size > 1) {
    throw new ApplicationPlatformError("invalid_session_issuer_result", "Platform session issuer returned conflicting session references");
  }
  const sessionReference = references[0];
  if (sessionReference !== undefined) {
    if (typeof sessionReference !== "string") {
      throw new ApplicationPlatformError("invalid_session_issuer_result", "Platform session issuer returned an invalid session reference");
    }
    const normalized = sessionReference.trim();
    if (normalized.length < 8 || normalized.length > 512 || /[\u0000-\u001f\u007f\s]/u.test(normalized) || /(?:provider|access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?key|authorization[_-]?code|(?:^|[^a-z])code(?:$|[^a-z])|(?:^|[^a-z])state(?:$|[^a-z]))/iu.test(normalized)) {
      throw new ApplicationPlatformError("session_issuer_secret_exposed", "Platform session issuer returned a forbidden session reference");
    }
    output.sessionReference = normalized;
  }
  if (output.response === undefined && output.user === undefined && output.expiresAt === undefined && output.sessionReference === undefined) {
    throw new ApplicationPlatformError("invalid_session_issuer_result", "Platform session issuer returned an empty result");
  }
  return output;
}

export function isOpaquePlatformSessionClient(client: PlatformSessionClient | undefined): boolean {
  return client !== undefined && client !== "web";
}

export function assertPlatformSessionResultForClient(
  result: PlatformSessionIssueResult,
  client: PlatformSessionClient | undefined,
): void {
  if (client === undefined) return;
  if (result.clientKind !== undefined && result.clientKind !== client) {
    throw new ApplicationPlatformError("invalid_session_issuer_result", "Platform session client kind does not match the login channel");
  }
  if (client === "web") {
    if (result.response === undefined || result.sessionReference !== undefined) {
      throw new ApplicationPlatformError("invalid_session_issuer_result", "Web platform sessions must use a cookie response");
    }
    if (!hasSetCookie(result.response)) {
      throw new ApplicationPlatformError("invalid_session_issuer_result", "Web platform session response did not set a session cookie");
    }
    return;
  }
  if (result.response !== undefined || result.sessionReference === undefined) {
    throw new ApplicationPlatformError("invalid_session_issuer_result", "Client platform sessions must use an opaque session reference");
  }
}

export async function assertPlatformSessionResponseSafe(response: Response): Promise<void> {
  for (const [key, value] of response.headers) {
    if (key.toLowerCase() === "set-cookie") {
      if (/(?:access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?(?:key|token)|raw[_-]?(?:better[_-]?auth[_-]?)?(?:session[_-]?)?token|provider[_-]?token|authorization[_-]?code|(?:^|[?&; ])(?:code|state)=)/iu.test(value)) {
        throw new ApplicationPlatformError("session_issuer_secret_exposed", "Platform session issuer response contained forbidden data");
      }
      continue;
    }
    if (/(?:access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?(?:key|token)|raw[_-]?(?:better[_-]?auth[_-]?)?(?:session[_-]?)?token|provider[_-]?token|authorization[_-]?code)/iu.test(`${key} ${value}`) || /(?:provider|secret|token|code|state|authorization|proxy[_-]?authorization)/iu.test(key) || /(?:[?&](?:code|state|session[_-]?(?:key|token)|token|access[_-]?token|refresh[_-]?token|id[_-]?token)=)/iu.test(value)) {
      throw new ApplicationPlatformError("session_issuer_secret_exposed", "Platform session issuer response contained forbidden data");
    }
  }
  if (!response.body) return;
  let text: string;
  try {
    text = await response.clone().text();
  } catch {
    throw new ApplicationPlatformError("invalid_session_issuer_result", "Platform session issuer response could not be inspected");
  }
  if (
    text.length > 1_048_576 ||
    /(?:access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?(?:key|token)|raw[_-]?(?:better[_-]?auth[_-]?)?(?:session[_-]?)?token|client[_-]?secret|provider[_-]?token|authorization)/iu.test(text) ||
    /(?:^|["'?\s])(?:code|state|token|authorization[_-]?code|code[_-]?verifier)\s*(?:=|:)/iu.test(text) ||
    /@placeholder\.invalid/iu.test(text)
  ) {
    throw new ApplicationPlatformError("session_issuer_secret_exposed", "Platform session issuer response contained forbidden data");
  }
}

export function assertNoProviderSecrets(value: unknown, depth = 0): void {
  const seen = new Set<object>();
  const visit = (entry: unknown, level: number): void => {
    if (level > 6 || entry === null || entry === undefined || isResponse(entry)) return;
    if (typeof entry !== "object") return;
    if (seen.has(entry)) return;
    seen.add(entry);
    if (Array.isArray(entry)) {
      for (const item of entry) visit(item, level + 1);
      return;
    }
    if (!isRecord(entry)) return;
    for (const [key, nested] of Object.entries(entry)) {
      const normalizedKey = key.toLowerCase().replace(/[^a-z0-9]/gu, "");
      if (isForbiddenSecretKey(normalizedKey)) {
        throw new ApplicationPlatformError("session_issuer_secret_exposed", "Platform session issuer returned a forbidden secret");
      }
      visit(nested, level + 1);
    }
  };
  visit(value, depth);
}

function isForbiddenSecretKey(key: string): boolean {
  return new Set([
    "sessionkey",
    "sessiontoken",
    "rawsession",
    "rawsessiontoken",
    "bettersession",
    "bettersessiontoken",
    "betterauthtoken",
    "betterauthsessiontoken",
    "setcookie",
    "cookie",
    "accesstoken",
    "refreshtoken",
    "idtoken",
    "providertoken",
    "oauthtoken",
    "authorizationcode",
    "authorization",
    "proxyauthorization",
    "codeverifier",
    "providerresponse",
    "providercode",
    "session",
    "code",
    "state",
    "token",
    "tokens",
  ]).has(key) ||
    key.endsWith("accesstoken") ||
    key.endsWith("refreshtoken") ||
    key.endsWith("idtoken") ||
    key.endsWith("sessiontoken") ||
    (key.startsWith("raw") && key.endsWith("token")) ||
    (key.includes("session") && key.endsWith("token"));
}

function normalizePublicUser(value: unknown): PlatformPublicUser {
  if (!isRecord(value)) {
    throw new ApplicationPlatformError("invalid_session_issuer_result", "Platform session issuer returned an invalid user");
  }
  const name = value.name === null || value.name === undefined ? "Platform user" : safeText(value.name, "name");
  const email = value.email === null || value.email === undefined ? null : safeEmail(value.email);
  if (value.email !== undefined && value.email !== null && email === null) {
    throw new ApplicationPlatformError("invalid_session_issuer_result", "Platform session issuer returned an invalid user");
  }
  const image = value.image === null || value.image === undefined ? undefined : safeText(value.image, "image");
  return {
    ...(typeof value.id === "string" ? { id: safeText(value.id, "user") } : {}),
    name,
    email,
    emailVerified: email !== null && value.emailVerified === true,
    ...(image === undefined ? {} : { image }),
  };
}

function safeEmail(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const normalized = value.trim().toLowerCase();
  if (
    normalized.length === 0 ||
    normalized.length > 320 ||
    /[\u0000-\u001f\u007f\s]/u.test(normalized) ||
    !normalized.includes("@") ||
    normalized.endsWith(`@${PLATFORM_PLACEHOLDER_EMAIL_DOMAIN}`)
  ) {
    return null;
  }
  return normalized;
}

function safeText(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new ApplicationPlatformError("invalid_session_issuer_result", "Platform session issuer returned an invalid value");
  }
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 1024 || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new ApplicationPlatformError("invalid_session_issuer_result", `Platform session issuer returned an invalid ${field}`);
  }
  return normalized;
}

function normalizeExpiresAt(value: unknown): string {
  const date = value instanceof Date ? value : new Date(value as string | number);
  if (!Number.isFinite(date.getTime())) {
    throw new ApplicationPlatformError("invalid_session_issuer_result", "Platform session issuer returned an invalid expiry");
  }
  return date.toISOString();
}

function normalizeSessionClientKind(value: unknown): PlatformSessionClient {
  if (value === "web" || value === "native" || value === "mp_weixin" || value === "webview") return value;
  if (value === "mini_program") return "mp_weixin";
  throw new ApplicationPlatformError("invalid_session_issuer_result", "Platform session issuer returned an invalid client kind");
}

function hasSetCookie(response: Response): boolean {
  const getSetCookie = (response.headers as Headers & { getSetCookie?: () => string[] }).getSetCookie;
  if (typeof getSetCookie === "function") return getSetCookie.call(response.headers).length > 0;
  return response.headers.get("set-cookie") !== null;
}

function isResponse(value: unknown): value is Response {
  if (typeof Response !== "undefined" && value instanceof Response) return true;
  return Object.prototype.toString.call(value) === "[object Response]";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
