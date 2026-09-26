import {
  CONTROL_PLANE_DEFAULT_LIMIT,
  CONTROL_PLANE_MAX_LIMIT,
  type ControlPlaneAuditEventDto,
  type ControlPlaneCapabilitiesDto,
  type ControlPlaneHealthDto,
  type ControlPlaneRoleDto,
  type ControlPlaneSessionDto,
  type ControlPlaneSystemInfoDto,
  type ControlPlaneUserDto,
} from "./types.js";
import { internalError } from "./errors.js";

export function toUserDto(value: unknown): ControlPlaneUserDto {
  const record = recordValue(value);
  const id = requiredId(record.id);
  const roles = [...stringArray(record.roles), ...stringArray(record.role)].filter(
    (role, index, values) => values.indexOf(role) === index,
  );
  const dto: ControlPlaneUserDto = { id, roles };
  assignString(dto, "username", record.username);
  assignString(dto, "name", record.name ?? record.displayName);
  assignString(dto, "displayName", record.displayName ?? record.name);
  assignString(dto, "email", record.email);
  assignString(dto, "phoneNumber", record.phoneNumber);
  assignString(dto, "avatarUrl", record.avatarUrl);
  assignString(dto, "status", record.status ?? "active");
  assignString(dto, "role", record.role);
  assignString(dto, "organizationId", record.organizationId);
  if (typeof record.emailVerified === "boolean") dto.emailVerified = record.emailVerified;
  assignDate(dto, "createdAt", record.createdAt);
  assignDate(dto, "updatedAt", record.updatedAt);
  assignDate(dto, "lastLoginAt", record.lastLoginAt);
  return dto;
}

export function toRoleDto(value: unknown): ControlPlaneRoleDto {
  const record = recordValue(value);
  const id = requiredId(record.id);
  const code = safeString(record.code) ?? safeString(record.name) ?? id;
  const name = safeString(record.name) ?? code;
  const dto: ControlPlaneRoleDto = {
    id,
    code,
    name,
    permissions: stringArray(record.permissions),
    inheritedRoles: stringArray(record.inheritedRoles ?? record.parents),
  };
  assignString(dto, "description", record.description);
  if (typeof record.memberCount === "number" && Number.isFinite(record.memberCount)) {
    dto.memberCount = record.memberCount;
  } else if (typeof record.memberCount === "string" && /^\d+$/u.test(record.memberCount)) {
    dto.memberCount = Number(record.memberCount);
  }
  assignDate(dto, "createdAt", record.createdAt);
  assignDate(dto, "updatedAt", record.updatedAt);
  return dto;
}

export function toSessionDto(value: unknown): ControlPlaneSessionDto {
  const record = recordValue(value);
  const dto: ControlPlaneSessionDto = { id: requiredId(record.id) };
  assignString(dto, "userId", record.userId);
  assignString(dto, "organizationId", record.organizationId);
  assignString(dto, "status", record.status);
  assignString(dto, "device", record.device);
  assignString(dto, "ipAddress", record.ipAddress);
  assignString(dto, "userAgent", record.userAgent);
  assignDate(dto, "createdAt", record.createdAt);
  assignDate(dto, "lastActiveAt", record.lastActiveAt);
  assignDate(dto, "expiresAt", record.expiresAt);
  assignDate(dto, "revokedAt", record.revokedAt);
  assignString(dto, "requestId", record.requestId);
  return dto;
}

export function toAuditEventDto(value: unknown): ControlPlaneAuditEventDto {
  const record = recordValue(value);
  const dto: ControlPlaneAuditEventDto = {
    id: requiredId(record.id),
    event: safeString(record.event) ?? "unknown",
  };
  assignString(dto, "action", record.action);
  assignString(dto, "userId", record.userId);
  assignString(dto, "actorId", record.actorId);
  assignString(dto, "targetId", record.targetId);
  assignString(dto, "organizationId", record.organizationId);
  assignString(dto, "requestId", record.requestId);
  assignString(dto, "outcome", record.outcome);
  assignString(dto, "ipAddress", record.ipAddress);
  assignString(dto, "userAgent", record.userAgent);
  assignDate(dto, "occurredAt", record.occurredAt ?? record.createdAt);
  assignDate(dto, "createdAt", record.createdAt ?? record.occurredAt);
  const detail = sanitizeAuditDetail(record.detail);
  if (detail !== undefined) dto.detail = detail;
  const actor = toActor(record.actor ?? record.actorId);
  if (actor !== undefined) dto.actor = actor;
  return dto;
}

export function toCapabilitiesDto(version: string): ControlPlaneCapabilitiesDto {
  const normalizedVersion = safeString(version, 128);
  if (normalizedVersion === undefined) throw internalError();
  return {
    version: normalizedVersion,
    singleTenant: true,
    features: {
      users: true,
      roles: true,
      sessions: true,
      auditEvents: true,
      health: true,
    },
    pagination: {
      cursor: true,
      defaultLimit: CONTROL_PLANE_DEFAULT_LIMIT,
      maxLimit: CONTROL_PLANE_MAX_LIMIT,
    },
    masking: true,
  };
}

export function toSystemInfoDto(
  version: string,
  requestId?: string,
): ControlPlaneSystemInfoDto {
  const capabilities = toCapabilitiesDto(version);
  const dto: ControlPlaneSystemInfoDto = {
    version: capabilities.version,
    capabilities,
  };
  const normalizedRequestId = safeString(requestId, 128);
  if (normalizedRequestId !== undefined) dto.requestId = normalizedRequestId;
  return dto;
}

export function toLiveHealthDto(version: string): ControlPlaneHealthDto {
  return { status: "ok", service: "idaas-control-plane", version };
}

export function toReadyHealthDto(version: string): ControlPlaneHealthDto {
  return { status: "ready", service: "idaas-control-plane", version };
}

export function sanitizeAuditDetail(value: unknown): Record<string, unknown> | undefined {
  if (value === undefined) return undefined;
  const sanitized = sanitizeValue(value, 0, new Set<object>());
  return isRecord(sanitized) ? sanitized : undefined;
}

function toActor(value: unknown): { id?: string; name?: string; email?: string } | undefined {
  if (typeof value === "string") {
    const id = safeString(value);
    return id === undefined ? undefined : { id };
  }
  if (!isRecord(value)) return undefined;
  const actor: { id?: string; name?: string; email?: string } = {};
  assignString(actor, "id", value.id);
  assignString(actor, "name", value.name ?? value.displayName);
  assignString(actor, "email", value.email);
  return Object.keys(actor).length > 0 ? actor : undefined;
}

function sanitizeValue(value: unknown, depth: number, ancestors: Set<object>): unknown {
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") return truncate(value);
  if (typeof value === "number") return Number.isFinite(value) ? value : undefined;
  if (typeof value === "bigint") return value.toString();
  if (typeof value !== "object") return undefined;
  if (depth >= 6) return undefined;
  if (ancestors.has(value)) return undefined;
  ancestors.add(value);
  try {
    if (value instanceof Date) return Number.isNaN(value.getTime()) ? undefined : value.toISOString();
    if (Array.isArray(value)) {
      return value.slice(0, 50).map((item) => sanitizeValue(item, depth + 1, ancestors)).filter((item) => item !== undefined);
    }
    if (!isRecord(value)) return undefined;
    const output: Record<string, unknown> = {};
    for (const key of Object.keys(value).slice(0, 50)) {
      if (isUnsafeKey(key) || isSensitiveKey(key)) continue;
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !("value" in descriptor)) continue;
      const item = sanitizeValue(descriptor.value, depth + 1, ancestors);
      if (item !== undefined) output[key] = item;
    }
    return output;
  } finally {
    ancestors.delete(value);
  }
}

function isUnsafeKey(key: string): boolean {
  return key === "__proto__" || key === "prototype" || key === "constructor";
}

function isSensitiveKey(key: string): boolean {
  const normalized = key.replace(/[-_]/g, "").toLowerCase();
  return normalized.includes("password") ||
    normalized.includes("passphrase") ||
    normalized.includes("secret") ||
    normalized.includes("token") ||
    normalized.includes("hash") ||
    normalized.includes("authorization") ||
    normalized.includes("cookie") ||
    normalized.includes("credential") ||
    normalized.includes("apikey") ||
    normalized.includes("privatekey") ||
    normalized.includes("database") ||
    normalized.includes("connectionstring") ||
    normalized.includes("bearer") ||
    normalized.includes("signature") ||
    normalized.includes("dsn");
}

function recordValue(value: unknown): Record<string, unknown> {
  if (!isRecord(value)) throw internalError();
  return value;
}

function requiredId(value: unknown): string {
  const id = safeString(value, 256);
  if (id === undefined) throw internalError();
  return id;
}

function safeString(value: unknown, maxLength = 512): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > maxLength || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    return undefined;
  }
  return normalized;
}

function stringArray(value: unknown): string[] {
  const source = Array.isArray(value) ? value : typeof value === "string" ? [value] : [];
  const output: string[] = [];
  for (const item of source) {
    const normalized = safeString(item, 256);
    if (normalized !== undefined && !output.includes(normalized)) output.push(normalized);
    if (output.length >= 64) break;
  }
  return output;
}

function assignString<T extends object, K extends keyof T>(
  target: T,
  key: K,
  value: unknown,
): void {
  const normalized = safeString(value);
  if (normalized !== undefined) (target as Record<string, unknown>)[key as string] = normalized;
}

function assignDate<T extends object, K extends keyof T>(
  target: T,
  key: K,
  value: unknown,
): void {
  if (value === undefined || value === null) return;
  if (!(value instanceof Date) && typeof value !== "string" && typeof value !== "number") return;
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isNaN(date.getTime())) (target as Record<string, unknown>)[key as string] = date.toISOString();
}

function truncate(value: string): string {
  return value.length > 512 ? `${value.slice(0, 495)}...[truncated]` : value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
