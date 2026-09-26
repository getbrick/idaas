import { AuthError } from "./errors";
import { createMemoryStorage, type KeyValueStorage } from "../types/runtime";

export type OpaqueClientKind = "mp_weixin" | "native" | "webview" | "web";

export interface PublicUser {
  id: string;
  name: string;
  email: string | null;
  emailVerified: boolean;
  avatarUrl?: string;
}

export interface OpaqueSession {
  sessionReference: string;
  expiresAt: string;
  clientKind?: OpaqueClientKind;
  user?: PublicUser;
}

export const OPAQUE_SESSION_STORAGE_KEY = "getbrick.client.opaque-session";

const CREDENTIAL_KEYS = new Set([
  "accesstoken",
  "authorization",
  "clientsecret",
  "codeverifier",
  "cookie",
  "hostsessiontoken",
  "idtoken",
  "oidcsecret",
  "proxyauthorization",
  "providerresponse",
  "refreshtoken",
  "sessionid",
  "sessionkey",
  "sessiontoken",
  "setcookie",
  "token",
  "tokens",
]);

export function normalizeOpaqueSession(value: unknown, now = Date.now()): OpaqueSession {
  const root = isRecord(value) && isRecord(value.data) ? value.data : value;
  const wrapped = isRecord(root) && isRecord(root.session);
  const candidate = wrapped ? root.session : root;
  if (!isRecord(candidate)) {
    throw new AuthError("invalid_session", "Client session is invalid");
  }
  assertNoCredentialFields(root);
  const sessionReference = candidate.sessionReference;
  const expiresValue = candidate.expiresAt ?? candidate.expires_at;
  if (typeof sessionReference !== "string" || !isSafeReference(sessionReference)) {
    throw new AuthError("invalid_session", "Client session is invalid");
  }
  const expiresAt = normalizeDate(expiresValue);
  if (expiresAt.getTime() <= now) {
    throw new AuthError("session_expired", "Client session has expired");
  }
  const userValue = candidate.user ?? (wrapped ? root.user : undefined) ?? (root !== value && isRecord(value) ? value.user : undefined);
  const user = userValue === undefined ? undefined : normalizePublicUser(userValue);
  const clientKind = normalizeClientKind(candidate.clientKind ?? (wrapped ? root.client : undefined));
  return {
    sessionReference,
    expiresAt: expiresAt.toISOString(),
    ...(clientKind === undefined ? {} : { clientKind }),
    ...(user === undefined ? {} : { user }),
  };
}

export function serializeOpaqueSession(session: OpaqueSession): string {
  return JSON.stringify({
    sessionReference: session.sessionReference,
    expiresAt: session.expiresAt,
    ...(session.clientKind === undefined ? {} : { clientKind: session.clientKind }),
    ...(session.user === undefined ? {} : { user: session.user }),
  });
}

export class OpaqueSessionStore {
  private readonly storage: KeyValueStorage;
  private readonly now: () => number;
  private readonly key: string;
  private cached: OpaqueSession | null | undefined;

  constructor(options: { storage?: KeyValueStorage; now?: () => number; key?: string } = {}) {
    this.storage = options.storage ?? createMemoryStorage();
    this.now = options.now ?? Date.now;
    this.key = options.key ?? OPAQUE_SESSION_STORAGE_KEY;
  }

  load(): OpaqueSession | null {
    if (this.cached !== undefined) return this.cached;
    const raw = this.storage.get(this.key);
    if (raw === undefined || raw.length === 0) {
      this.cached = null;
      return null;
    }
    try {
      this.cached = normalizeOpaqueSession(JSON.parse(raw) as unknown, this.now());
    } catch {
      this.clear();
    }
    return this.cached ?? null;
  }

  save(value: OpaqueSession): OpaqueSession {
    const session = normalizeOpaqueSession(value, this.now());
    this.storage.set(this.key, serializeOpaqueSession(session));
    this.cached = session;
    return session;
  }

  clear(): void {
    this.storage.remove(this.key);
    this.cached = null;
  }

  get(): OpaqueSession | null {
    return this.load();
  }
}

export function assertNoCredentialFields(value: unknown, depth = 0): void {
  if (depth > 6 || value === null || value === undefined) return;
  if (Array.isArray(value)) {
    for (const item of value) assertNoCredentialFields(item, depth + 1);
    return;
  }
  if (!isRecord(value)) return;
  for (const [key, nested] of Object.entries(value)) {
    const normalized = key.toLowerCase().replace(/[^a-z0-9]/gu, "");
    if (CREDENTIAL_KEYS.has(normalized) || normalized.endsWith("token") || normalized.includes("secret")) {
      throw new AuthError("invalid_auth_response", "Authentication response contained a forbidden credential");
    }
    assertNoCredentialFields(nested, depth + 1);
  }
}

export function normalizePublicUser(value: unknown): PublicUser {
  if (!isRecord(value)) {
    throw new AuthError("invalid_auth_response", "Authentication response contained an invalid user");
  }
  const id = readText(value.id, 256);
  const name = readText(value.name, 256) || "User";
  const email = value.email === null || value.email === undefined ? null : readEmail(value.email);
  const avatarUrl = value.avatarUrl ?? value.image;
  const normalizedAvatarUrl = avatarUrl === undefined || avatarUrl === null ? undefined : readText(avatarUrl, 2048);
  return {
    id,
    name,
    email,
    emailVerified: value.emailVerified === true,
    ...(normalizedAvatarUrl === undefined ? {} : { avatarUrl: normalizedAvatarUrl }),
  };
}

function normalizeClientKind(value: unknown): OpaqueClientKind | undefined {
  if (value === undefined || value === null) return undefined;
  if (value === "mini_program") return "mp_weixin";
  if (value === "mp_weixin" || value === "native" || value === "webview" || value === "web") return value;
  throw new AuthError("invalid_session", "Client session kind is invalid");
}

function readEmail(value: unknown): string {
  const email = readText(value, 320).toLowerCase();
  if (!email.includes("@") || email.startsWith("@") || email.endsWith("@") || /\s/u.test(email)) {
    throw new AuthError("invalid_auth_response", "Authentication response contained an invalid user");
  }
  return email;
}

function readText(value: unknown, maxLength: number): string {
  if (typeof value !== "string") {
    throw new AuthError("invalid_auth_response", "Authentication response contained an invalid value");
  }
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > maxLength || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new AuthError("invalid_auth_response", "Authentication response contained an invalid value");
  }
  return normalized;
}

function normalizeDate(value: unknown): Date {
  const date = typeof value === "number" ? new Date(value) : typeof value === "string" ? new Date(value) : new Date(Number.NaN);
  if (!Number.isFinite(date.getTime())) {
    throw new AuthError("invalid_session", "Client session is invalid");
  }
  return date;
}

function isSafeReference(value: string): boolean {
  return /^[A-Za-z0-9._~-]{24,512}$/u.test(value) && !/(?:token|secret|authorization|session[_-]?key|refresh|access|id[_-]?token|code|state)/iu.test(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export { OIDC_FLOW_FENCE_STORAGE_KEY, OIDC_TRANSACTION_STORAGE_KEY } from "./pkce";
export { SessionCoordinator } from "./session-coordinator";
export type { SessionCookieRefreshOperation, SessionFence, SessionLogoutOperation, SessionRefreshContext, SessionRefreshOperation } from "./session-coordinator";
