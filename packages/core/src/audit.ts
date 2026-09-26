import type { AuditEvent, AuditSink } from "./config.js";

export type DatabaseHooks = {
  [model: string]: {
    create?: { before?: (data: any) => Promise<any>; after?: (data: any) => Promise<void> };
    update?: { before?: (data: any) => Promise<any>; after?: (data: any) => Promise<void> };
    delete?: { before?: (data: any) => Promise<any>; after?: (data: any) => Promise<void> };
  };
};

export const AUDIT_MAX_DEPTH = 8;
export const AUDIT_MAX_LENGTH = 1024;
export const AUDIT_MAX_ITEMS = 100;

export const SENSITIVE_FIELDS = new Set([
  "password",
  "passwordhash",
  "password_hash",
  "hash",
  "secret",
  "token",
  "accesstoken",
  "access_token",
  "refreshtoken",
  "refresh_token",
  "idtoken",
  "id_token",
  "sessiontoken",
  "session_token",
  "twofactorsecret",
  "two_factor_secret",
  "mfasecret",
  "mfa_secret",
  "clientsecret",
  "client_secret",
  "secretkey",
  "secret_key",
  "apikey",
  "api_key",
  "privatekey",
  "private_key",
  "authorization",
  "cookie",
  "setcookie",
  "set_cookie",
  "otp",
  "verificationcode",
  "verification_code",
  "recoverycode",
  "recovery_code",
  "recoverycodes",
  "recovery_codes",
  "mfabackupcodes",
  "mfa_backup_codes",
  "resettoken",
  "reset_token",
  "verificationtoken",
  "verification_token",
  "csrftoken",
  "csrf_token",
  "credential",
  "credentials",
]);

export const PERSONAL_FIELDS = new Set([
  "email",
  "emailaddress",
  "phone",
  "phonenumber",
  "telephone",
  "mobile",
  "ip",
  "ipaddress",
  "clientip",
  "remoteip",
  "requestip",
  "sourceip",
  "forwardedfor",
  "useragent",
  "useragentstring",
  "username",
  "userhandle",
  "name",
  "displayname",
  "fullname",
  "firstname",
  "lastname",
  "givenname",
  "familyname",
  "middlename",
  "nickname",
  "address",
  "streetaddress",
  "addressline1",
  "addressline2",
  "city",
  "state",
  "province",
  "postalcode",
  "zipcode",
  "country",
  "countrycode",
  "location",
  "latitude",
  "longitude",
  "deviceid",
  "devicefingerprint",
  "fingerprint",
  "avatar",
  "avatarurl",
]);

export interface SanitizeOptions {
  maxDepth?: number;
  maxLength?: number;
  maxStringLength?: number;
  maxItems?: number;
  redactPersonalData?: boolean;
}

export interface AuditHookOptions {
  redactPersonalData?: boolean;
}

type SanitizeLimits = {
  maxDepth: number;
  maxLength: number;
  maxItems: number;
  redactPersonalData: boolean;
};

const REDACTED = "[redacted]";
const CIRCULAR = "[circular]";
const MAX_DEPTH = "[max depth]";
const TRUNCATED = "...[truncated]";

export function sanitize(detail: unknown, options: SanitizeOptions = {}): Record<string, unknown> {
  const limits: SanitizeLimits = {
    maxDepth: normalizeLimit(options.maxDepth, AUDIT_MAX_DEPTH, 1),
    maxLength: normalizeLimit(options.maxLength ?? options.maxStringLength, AUDIT_MAX_LENGTH, 1),
    maxItems: normalizeLimit(options.maxItems ?? options.maxLength, AUDIT_MAX_ITEMS, 1),
    redactPersonalData: options.redactPersonalData === true,
  };
  return sanitizeValue(detail, 0, new WeakSet<object>(), limits) as Record<string, unknown>;
}

function sanitizeValue(
  value: unknown,
  depth: number,
  ancestors: WeakSet<object>,
  limits: SanitizeLimits,
): unknown {
  if (value === null) return null;
  if (typeof value === "string") return truncateString(value, limits.maxLength);
  if (typeof value === "number") return Number.isFinite(value) ? value : "[number]";
  if (typeof value === "boolean" || typeof value === "undefined") return value;
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "symbol") return value.toString();
  if (typeof value === "function") return "[function]";
  if (depth >= limits.maxDepth) return MAX_DEPTH;
  if (ancestors.has(value)) return CIRCULAR;
  ancestors.add(value);
  try {
    if (value instanceof Date) return Number.isNaN(value.getTime()) ? "[date]" : value.toISOString();
    if (value instanceof Error) return sanitizeError(value, depth, ancestors, limits);
    if (Array.isArray(value)) return sanitizeArray(value, depth, ancestors, limits);
    if (value instanceof URL) return truncateString(value.toString(), limits.maxLength);
    if (value instanceof RegExp) return truncateString(value.toString(), limits.maxLength);
    if (value instanceof Map) return sanitizeEntries([...value.entries()], depth, ancestors, limits);
    if (value instanceof Set) return sanitizeEntries([...value.values()], depth, ancestors, limits);
    if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) return "[binary]";
    return sanitizeObject(value, depth, ancestors, limits);
  } finally {
    ancestors.delete(value);
  }
}

function sanitizeError(
  error: Error,
  depth: number,
  ancestors: WeakSet<object>,
  limits: SanitizeLimits,
): Record<string, unknown> {
  const out: Record<string, unknown> = {
    name: error.name,
    message: error.message,
  };
  if (error.stack !== undefined) setEntry(out, "stack", error.stack);
  if ("cause" in error) setEntry(out, "cause", error.cause);
  let keys: string[] = [];
  try {
    keys = Object.keys(error);
  } catch {
    return out;
  }
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(out, key)) continue;
    setEntry(out, key, readProperty(error, key, depth, ancestors, limits));
  }
  return sanitizeObject(out, depth, ancestors, limits);
}

function sanitizeArray(
  value: unknown[],
  depth: number,
  ancestors: WeakSet<object>,
  limits: SanitizeLimits,
): unknown[] {
  const out: unknown[] = [];
  const count = Math.min(value.length, limits.maxItems);
  for (let index = 0; index < count; index++) {
    if (index === limits.maxItems - 1 && value.length > limits.maxItems) {
      out.push(TRUNCATED);
      break;
    }
    out.push(sanitizeValue(value[index], depth + 1, ancestors, limits));
  }
  return out;
}

function sanitizeEntries(
  value: unknown[],
  depth: number,
  ancestors: WeakSet<object>,
  limits: SanitizeLimits,
): unknown[] {
  return sanitizeArray(value, depth, ancestors, limits);
}

function sanitizeObject(
  value: object,
  depth: number,
  ancestors: WeakSet<object>,
  limits: SanitizeLimits,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  let keys: string[];
  try {
    keys = Object.keys(value);
  } catch {
    return { value: "[unavailable]" };
  }
  const count = Math.min(keys.length, limits.maxItems);
  for (let index = 0; index < count; index++) {
    if (index === limits.maxItems - 1 && keys.length > limits.maxItems) {
      setEntry(out, "[truncated]", TRUNCATED);
      break;
    }
    const key = keys[index];
    if (isSensitiveField(key) || (limits.redactPersonalData && isPersonalField(key))) {
      setEntry(out, key, REDACTED);
      continue;
    }
    setEntry(out, key, readProperty(value, key, depth, ancestors, limits));
  }
  return out;
}

function readProperty(
  value: object,
  key: string,
  depth: number,
  ancestors: WeakSet<object>,
  limits: SanitizeLimits,
): unknown {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor && !("value" in descriptor)) {
      return sanitizeValue(Reflect.get(value, key), depth + 1, ancestors, limits);
    }
    return sanitizeValue(descriptor?.value, depth + 1, ancestors, limits);
  } catch {
    return "[unavailable]";
  }
}

function setEntry(target: Record<string, unknown>, key: string, value: unknown): void {
  Object.defineProperty(target, key, {
    configurable: true,
    enumerable: true,
    value,
    writable: true,
  });
}

function isSensitiveField(key: string): boolean {
  const normalized = normalizeFieldName(key);
  if (SENSITIVE_FIELDS.has(normalized)) return true;
  for (const field of SENSITIVE_FIELDS) {
    if (normalizeFieldName(field) === normalized) return true;
  }
  return ["password", "secret", "token", "hash", "privatekey", "apikey", "credential"].some(
    (suffix) => normalized.endsWith(suffix),
  );
}

function isPersonalField(key: string): boolean {
  const normalized = normalizeFieldName(key);
  if (PERSONAL_FIELDS.has(normalized)) return true;
  return [
    "email",
    "emailaddress",
    "phone",
    "phonenumber",
    "ipaddress",
    "useragent",
    "username",
    "userhandle",
  ].some((suffix) => normalized.endsWith(suffix));
}

function normalizeFieldName(key: string): string {
  return key.trim().toLowerCase().replace(/[^a-z0-9]/g, "");
}

function truncateString(value: string, maxLength: number): string {
  if (value.length <= maxLength) return value;
  if (maxLength <= TRUNCATED.length) return value.slice(0, maxLength);
  return `${value.slice(0, maxLength - TRUNCATED.length)}${TRUNCATED}`;
}

function normalizeLimit(value: number | undefined, fallback: number, minimum: number): number {
  if (value === undefined || !Number.isFinite(value)) return fallback;
  return Math.max(minimum, Math.floor(value));
}

export function createMemoryAuditSink(): AuditSink & { events: AuditEvent[] } {
  const events: AuditEvent[] = [];
  const sink = (event: AuditEvent) => {
    events.push(event);
  };
  return Object.assign(sink, { events });
}

export function createAuditDatabaseHooks(
  sink: AuditSink,
  now?: () => Date,
  options?: AuditHookOptions,
): DatabaseHooks;
export function createAuditDatabaseHooks(
  sink: AuditSink,
  options?: AuditHookOptions,
  now?: () => Date,
): DatabaseHooks;
export function createAuditDatabaseHooks(
  sink: AuditSink,
  nowOrOptions: (() => Date) | AuditHookOptions = () => new Date(),
  optionsOrNow: AuditHookOptions | (() => Date) = {},
): DatabaseHooks {
  const now =
    typeof nowOrOptions === "function"
      ? nowOrOptions
      : typeof optionsOrNow === "function"
        ? optionsOrNow
        : () => new Date();
  const options =
    typeof nowOrOptions === "function"
      ? typeof optionsOrNow === "function"
        ? {}
        : optionsOrNow
      : nowOrOptions;
  const redactPersonalData = options.redactPersonalData ?? true;
  const emit = async (event: string, data: Record<string, unknown> | undefined) => {
    const rawUserId = data?.userId ?? data?.id;
    const userId = typeof rawUserId === "string" ? rawUserId : undefined;
    await sink({
      event,
      userId,
      detail: sanitize(
        data !== null && typeof data === "object" && !Array.isArray(data)
          ? data
          : { value: data },
        { redactPersonalData },
      ),
      occurredAt: now().toISOString(),
    });
  };
  return {
    user: {
      create: { after: (data) => emit("user.created", data) },
      update: { after: (data) => emit("user.updated", data) },
      delete: { after: (data) => emit("user.deleted", data) },
    },
    session: {
      create: { after: (data) => emit("session.created", data) },
      delete: { after: (data) => emit("session.revoked", data) },
    },
    account: {
      create: { after: (data) => emit("account.created", data) },
      update: { after: (data) => emit("account.updated", data) },
      delete: { after: (data) => emit("account.deleted", data) },
    },
  };
}
