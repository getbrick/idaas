import type { GetbrickAuthLike } from "./tokens.js";

const SENSITIVE_KEYS = new Set([
  "token",
  "sessiontoken",
  "accesstoken",
  "refreshtoken",
  "idtoken",
  "csrftoken",
  "password",
  "secret",
  "clientsecret",
  "authorization",
  "cookie",
]);

type UnknownRecord = Record<string, unknown>;

export function headersFromRequest(req: { headers?: Record<string, unknown> }): Headers {
  const out = new Headers();
  const headers = req.headers ?? {};
  for (const [key, value] of Object.entries(headers)) {
    if (typeof value === "string") {
      out.set(key, value);
    } else if (Array.isArray(value)) {
      for (const v of value) out.append(key, v);
    }
  }
  return out;
}

export interface GetbrickSession {
  [key: string]: unknown;
  user?: UnknownRecord;
  session?: UnknownRecord;
  member?: UnknownRecord;
  organization?: UnknownRecord;
}

export function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function sanitizeGetbrickSession(value: unknown): GetbrickSession | null {
  if (!isRecord(value)) return null;

  const user = sanitizeRecord(value.user);
  const session = sanitizeRecord(value.session);
  const member = sanitizeRecord(value.member);
  const organization = sanitizeRecord(value.organization);

  return {
    ...(user ? { user } : {}),
    ...(session ? { session } : {}),
    ...(member ? { member } : {}),
    ...(organization ? { organization } : {}),
  };
}

export const sanitizeSession = sanitizeGetbrickSession;

export async function getSessionFromRequest(
  auth: GetbrickAuthLike,
  req: { headers?: Record<string, unknown> },
): Promise<GetbrickSession | null> {
  const result = await auth.api.getSession({ headers: headersFromRequest(req) });
  return sanitizeGetbrickSession(result);
}

function sanitizeRecord(value: unknown): UnknownRecord | undefined {
  if (!isRecord(value)) return undefined;
  const sanitized = sanitizeValue(value, new Set<object>());
  return isRecord(sanitized) ? sanitized : undefined;
}

function sanitizeValue(value: unknown, ancestors: Set<object>): unknown {
  if (Array.isArray(value)) {
    if (ancestors.has(value)) return undefined;
    ancestors.add(value);
    const result = value
      .map((item) => sanitizeValue(item, ancestors))
      .filter((item) => item !== undefined);
    ancestors.delete(value);
    return result;
  }
  if (value instanceof Date) return new Date(value.getTime());
  if (!isRecord(value)) return value;
  if (ancestors.has(value)) return undefined;

  ancestors.add(value);
  const result: UnknownRecord = {};
  for (const [key, nested] of Object.entries(value)) {
    if (isSensitiveKey(key)) continue;
    const sanitized = sanitizeValue(nested, ancestors);
    if (sanitized !== undefined || nested === null) result[key] = sanitized;
  }
  ancestors.delete(value);
  return result;
}

function isSensitiveKey(key: string): boolean {
  const normalized = key.replace(/[-_]/g, "").toLowerCase();
  return SENSITIVE_KEYS.has(normalized) || normalized.endsWith("token");
}
