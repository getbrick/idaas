import type {
  AdminApplicationReadiness,
  AdminApplicationReadinessCheck,
  AdminApplicationSecretStatus,
  AdminApplicationVersion,
  AdminListBaseProps,
} from "./contracts.js";
import { adminClassName, adminClassNames, resolveAdminClassNamespace } from "./theme.js";

export interface AdminListClassSet {
  root: string;
  header: string;
  heading: string;
  actions: string;
  table: string;
  caption: string;
  cell: string;
}

export function getAdminListClassSet(props: AdminListBaseProps, block: string): AdminListClassSet {
  const namespace = resolveAdminClassNamespace(props);
  return {
    root: adminClassNames(adminClassName(namespace, block), props.className) ?? adminClassName(namespace, block),
    header: adminClassName(namespace, block, "header"),
    heading: adminClassName(namespace, block, "heading"),
    actions: adminClassName(namespace, block, "actions"),
    table: adminClassName(namespace, block, "table"),
    caption: adminClassName(namespace, block, "caption"),
    cell: adminClassName(namespace, block, "cell"),
  };
}

export function getAdminListTitle(title: string | undefined, fallback: string): string {
  return title?.trim() || fallback;
}

export function getAdminLoading(props: Pick<AdminListBaseProps, "loading" | "isLoading">): boolean {
  return props.isLoading ?? props.loading ?? false;
}

export function getAdminDate(value: string | Date): { dateTime: string; label: string } {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    const label = getAdminMetadataText(String(value), 128) ?? "—";
    return { dateTime: label, label };
  }
  const label = date.toISOString();
  return { dateTime: label, label };
}

export function getAdminDisplayValue(value: unknown): string {
  if (typeof value === "number") return Number.isFinite(value) ? String(value) : "—";
  if (typeof value !== "string") return "—";
  return getAdminMetadataText(value) ?? "—";
}

export function getAdminPositiveInteger(value: number | undefined, fallback: number): number {
  if (value === undefined || !Number.isFinite(value)) return fallback;
  return Math.max(1, Math.floor(value));
}

export function getAdminNonNegativeInteger(value: number | undefined, fallback: number): number {
  if (value === undefined || !Number.isFinite(value)) return fallback;
  return Math.max(0, Math.floor(value));
}

export function getAdminLifecycleStatus(value: unknown, fallback: unknown): string {
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    const record = value as Record<string, unknown>;
    return getAdminStatusText(typeof record.lifecycleStatus === "string" ? record.lifecycleStatus : undefined, getAdminStatusText(fallback, "Unknown"));
  }
  return getAdminStatusText(typeof value === "string" ? value : undefined, getAdminStatusText(fallback, "Unknown"));
}

export function getAdminStatusText(value: unknown, fallback: string): string {
  return getAdminMetadataText(value, 64) ?? fallback;
}

export function getAdminReadinessStatus(readiness: AdminApplicationReadiness | null | undefined): string {
  const allowed = new Set(["ready", "not_ready", "unknown"]);
  if (typeof readiness === "string") {
    const status = getAdminMetadataText(readiness);
    return status && allowed.has(status) ? status : "unknown";
  }
  if (readiness && typeof readiness === "object") {
    const status = getAdminMetadataText(readiness.status);
    if (status && allowed.has(status)) return status;
    if (typeof readiness.ready === "boolean") return readiness.ready ? "ready" : "not_ready";
  }
  return "unknown";
}

export function getAdminReadinessChecks(
  readiness: AdminApplicationReadiness | null | undefined,
): readonly AdminApplicationReadinessCheck[] {
  if (!readiness || typeof readiness === "string" || !Array.isArray(readiness.checks)) return [];
  return readiness.checks.filter((check): check is AdminApplicationReadinessCheck => {
    if (!check || typeof check !== "object") return false;
    return typeof check.id === "string" || typeof check.name === "string" || typeof check.status === "string" || typeof check.ready === "boolean";
  });
}

export function getAdminSecretStatus(value: {
  secretStatus?: AdminApplicationSecretStatus | null;
  credentialConfigured?: boolean | null;
  hasSecret?: boolean | null;
  tokenEndpointAuthMethod?: string | null;
}): string {
  const explicit = getAdminMetadataText(value.secretStatus);
  const allowed = new Set([
    "configured",
    "not_configured",
    "missing",
    "rotating",
    "active",
    "retiring",
    "revoked",
    "not_required",
    "expired",
    "unknown",
  ]);
  if (explicit && allowed.has(explicit)) return explicit;
  if (value.tokenEndpointAuthMethod === "none" || value.tokenEndpointAuthMethod === "private_key_jwt") return "not_required";
  return value.credentialConfigured === true || value.hasSecret === true ? "configured" : "not_configured";
}

export function getAdminVersion(value: AdminApplicationVersion | null | undefined): string | number | undefined {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return value;
  if (typeof value === "string") return getAdminMetadataText(value);
  return undefined;
}

export function getAdminSafeUrl(value: string | null | undefined): string | undefined {
  const normalized = getAdminMetadataText(value, 2048);
  if (!normalized) return undefined;
  try {
    const parsed = new URL(normalized);
    if (
      (parsed.protocol !== "http:" && parsed.protocol !== "https:") ||
      !parsed.hostname ||
      parsed.username ||
      parsed.password ||
      parsed.search ||
      parsed.hash
    ) return undefined;
    return parsed.toString();
  } catch {
    return undefined;
  }
}

export function getAdminRedirectUri(value: unknown): string | undefined {
  const normalized = getAdminMetadataText(value, 2048);
  if (!normalized || /[\u0000-\u001f\u007f]/u.test(normalized) || /\\|\s/u.test(normalized)) return undefined;
  try {
    const parsed = new URL(normalized);
    const customScheme = !["https:", "http:"].includes(parsed.protocol) && /^[a-z][a-z\d+.-]*:/u.test(normalized) && !normalized.slice(normalized.indexOf(":") + 1).startsWith("//");
    if (
      ((parsed.protocol !== "https:" && parsed.protocol !== "http:") && !customScheme) ||
      (!customScheme && !parsed.hostname) ||
      parsed.username ||
      parsed.password
    ) return undefined;
    for (const [key, item] of parsed.searchParams) {
      if (/(?:secret|token|password|private[-_]?key|credential|authorization|cookie|hash|database|dsn|signature|bearer)/iu.test(`${key} ${item}`)) return undefined;
    }
    return parsed.toString();
  } catch {
    return undefined;
  }
}

export function getAdminAuditDetail(value: unknown): unknown {
  return sanitizeAdminValue(value, 0);
}

function sanitizeAdminValue(value: unknown, depth: number): unknown {
  if (depth > 4) return undefined;
  if (typeof value === "string") return getAdminMetadataText(value, 512);
  if (typeof value === "number") return Number.isFinite(value) ? value : undefined;
  if (typeof value === "boolean") return value;
  if (value === null) return null;
  if (Array.isArray(value)) return value.slice(0, 20).map((item) => sanitizeAdminValue(item, depth + 1)).filter((item) => item !== undefined);
  if (typeof value !== "object") return undefined;
  const output: Record<string, unknown> = {};
  for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
    if (/^(?:__proto__|prototype|constructor)$/u.test(key)) continue;
    if (/(?:secret|token|password|private[-_]?key|credential|authorization|cookie|hash|database|dsn|signature|bearer)/iu.test(key)) continue;
    const safe = sanitizeAdminValue(nested, depth + 1);
    if (safe !== undefined) output[key] = safe;
  }
  return output;
}

export function getAdminMetadataText(value: unknown, maxLength = 512): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  const safeProtocolValue = new Set([
    "authorization_code",
    "refresh_token",
    "client_secret_basic",
    "client_secret_post",
    "private_key_jwt",
    "token_endpoint_auth_method",
  ]).has(normalized);
  if (
    normalized.length === 0 ||
    normalized.length > maxLength ||
    /[\u0000-\u001f\u007f]/u.test(normalized) ||
    (!safeProtocolValue && /(?:secret|token|password|private[-_]?key|session[-_]?key|credential|authorization|cookie|hash|database|dsn|signature|bearer|vault:\/\/)/iu.test(normalized))
  ) return undefined;
  return normalized;
}
