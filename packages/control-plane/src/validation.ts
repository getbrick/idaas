import {
  CONTROL_PLANE_DEFAULT_LIMIT,
  CONTROL_PLANE_MAX_LIMIT,
  type NormalizedAuditEventQuery,
  type NormalizedPageQuery,
  type NormalizedRoleQuery,
  type NormalizedSessionQuery,
  type NormalizedUserQuery,
} from "./types.js";
import { invalidRequest } from "./errors.js";

export interface PageValidationOptions {
  defaultLimit?: number;
  maxLimit?: number;
}

export function parsePageQuery(
  input: unknown,
  options: PageValidationOptions = {},
): NormalizedPageQuery {
  const record = queryRecord(input);
  const defaultLimit = options.defaultLimit ?? CONTROL_PLANE_DEFAULT_LIMIT;
  const maxLimit = options.maxLimit ?? CONTROL_PLANE_MAX_LIMIT;
  validateLimit(defaultLimit, maxLimit, "defaultLimit");
  validateLimit(maxLimit, maxLimit, "maxLimit");

  const limit = readLimit(record.limit ?? record.pageSize, defaultLimit, maxLimit);
  const cursor = readOptionalString(record.cursor, "cursor", 1024);
  const page = readOptionalInteger(record.page, "page", 1, 100000);
  const offsetValue = readOptionalInteger(record.offset, "offset", 0, 1000000);
  const offset = cursor === undefined
    ? offsetValue ?? (page === undefined ? undefined : (page - 1) * limit)
    : undefined;
  return {
    limit,
    ...(cursor === undefined ? {} : { cursor }),
    ...(offset === undefined ? {} : { offset }),
  };
}

export function parseUserQuery(
  input: unknown,
  options: PageValidationOptions = {},
): NormalizedUserQuery {
  const record = queryRecord(input);
  rejectTenant(record);
  return {
    ...parsePageQuery(record, options),
    ...optionalField(record, "search", 256, readOptionalString),
    ...optionalField(record, "q", 256, readOptionalString),
    ...optionalField(record, "email", 320, readOptionalString),
    ...optionalField(record, "status", 64, readOptionalString),
    ...optionalField(record, "role", 128, readOptionalString),
    ...optionalField(record, "id", 256, readOptionalString),
  };
}

export function parseRoleQuery(
  input: unknown,
  options: PageValidationOptions = {},
): NormalizedRoleQuery {
  const record = queryRecord(input);
  rejectTenant(record);
  return {
    ...parsePageQuery(record, options),
    ...optionalField(record, "search", 256, readOptionalString),
    ...optionalField(record, "q", 256, readOptionalString),
    ...optionalField(record, "code", 128, readOptionalString),
    ...optionalField(record, "permission", 256, readOptionalString),
  };
}

export function parseSessionQuery(
  input: unknown,
  options: PageValidationOptions = {},
): NormalizedSessionQuery {
  const record = queryRecord(input);
  rejectTenant(record);
  const from = readOptionalDate(record.from, "from", 64);
  const to = readOptionalDate(record.to, "to", 64);
  validateDateRange(from, to);
  return {
    ...parsePageQuery(record, options),
    ...optionalField(record, "userId", 256, readOptionalString),
    ...optionalField(record, "status", 64, readOptionalString),
    ...optionalField(record, "active", 16, readOptionalBoolean),
    ...(from === undefined ? {} : { from }),
    ...(to === undefined ? {} : { to }),
  };
}

export function parseAuditEventQuery(
  input: unknown,
  options: PageValidationOptions = {},
): NormalizedAuditEventQuery {
  const record = queryRecord(input);
  rejectTenant(record);
  const from = readOptionalDate(record.from, "from", 64);
  const to = readOptionalDate(record.to, "to", 64);
  validateDateRange(from, to);
  return {
    ...parsePageQuery(record, options),
    ...optionalField(record, "search", 256, readOptionalString),
    ...optionalField(record, "q", 256, readOptionalString),
    ...optionalField(record, "event", 256, readOptionalString),
    ...optionalField(record, "action", 256, readOptionalString),
    ...optionalField(record, "userId", 256, readOptionalString),
    ...optionalField(record, "actorId", 256, readOptionalString),
    ...optionalField(record, "targetId", 256, readOptionalString),
    ...optionalField(record, "outcome", 64, readOptionalString),
    ...(from === undefined ? {} : { from }),
    ...(to === undefined ? {} : { to }),
  };
}

export function parseIdentifier(input: unknown, field = "id"): string {
  if (typeof input !== "string") throw invalidRequest("Invalid identifier", { field });
  const value = input.trim();
  if (value.length === 0 || value.length > 256 || hasControlCharacter(value)) {
    throw invalidRequest("Invalid identifier", { field });
  }
  return value;
}

export function parseWriteBody(input: unknown): Record<string, never> {
  if (input === undefined || input === null) return {};
  if (!isRecord(input)) throw invalidRequest("Request body must be an object");
  if (Object.prototype.hasOwnProperty.call(input, "tenantId")) {
    throw invalidRequest("Tenant selection is not supported", { field: "tenantId" });
  }
  for (const key of Object.keys(input)) {
    const normalized = key.replace(/[-_]/g, "").toLowerCase();
    if (normalized === "tenantid" || normalized === "tenant") {
      throw invalidRequest("Tenant selection is not supported", { field: key });
    }
    if (["status", "role", "roles", "revokedat", "userid", "sessionid"].includes(normalized)) {
      throw invalidRequest("Request body is not supported", { field: key });
    }
  }
  return {};
}

export function queryRecord(input: unknown): Record<string, unknown> {
  if (input === undefined) return {};
  if (!isRecord(input)) throw invalidRequest("Request query must be an object");
  return input;
}

function optionalField<T>(
  record: Record<string, unknown>,
  field: string,
  maxLength: number,
  parser: (value: unknown, field: string, maxLength: number) => T | undefined,
): Record<string, T> {
  if (!(field in record)) return {};
  const value = parser(record[field], field, maxLength);
  return value === undefined ? {} : { [field]: value };
}

function readLimit(value: unknown, fallback: number, maxLimit: number): number {
  if (value === undefined || value === null || value === "") return fallback;
  const parsed = typeof value === "number" ? value : parseIntegerString(value, "limit");
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > maxLimit) {
    throw invalidRequest("Invalid page size", { field: "limit" });
  }
  return parsed;
}

function validateLimit(value: number, maxLimit: number, field: string): void {
  if (!Number.isSafeInteger(value) || value < 1 || value > maxLimit) {
    throw invalidRequest("Invalid page configuration", { field });
  }
}

function readOptionalInteger(
  value: unknown,
  field: string,
  minimum: number,
  maximum: number,
): number | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  const parsed = typeof value === "number" ? value : parseIntegerString(value, field);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw invalidRequest(`Invalid ${field}`, { field });
  }
  return parsed;
}

function parseIntegerString(value: unknown, field: string): number {
  if (typeof value !== "string" || !/^\d+$/u.test(value.trim())) {
    throw invalidRequest(`Invalid ${field}`, { field });
  }
  const parsed = Number(value.trim());
  if (!Number.isSafeInteger(parsed)) throw invalidRequest(`Invalid ${field}`, { field });
  return parsed;
}

function readOptionalString(
  value: unknown,
  field: string,
  maxLength: number,
): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string") throw invalidRequest(`Invalid ${field}`, { field });
  const normalized = value.trim();
  if (normalized.length === 0) return undefined;
  if (normalized.length > maxLength || hasControlCharacter(normalized)) {
    throw invalidRequest(`Invalid ${field}`, { field });
  }
  return normalized;
}

function readOptionalBoolean(value: unknown, field: string, _maxLength: number): boolean | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value === "boolean") return value;
  if (value === "true") return true;
  if (value === "false") return false;
  throw invalidRequest(`Invalid ${field}`, { field });
}

function readOptionalDate(value: unknown, field: string, maxLength: number): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value === "string" && value.length > maxLength) {
    throw invalidRequest(`Invalid ${field}`, { field });
  }
  if (typeof value !== "string" && typeof value !== "number" && !(value instanceof Date)) {
    throw invalidRequest(`Invalid ${field}`, { field });
  }
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) throw invalidRequest(`Invalid ${field}`, { field });
  return date.toISOString();
}

function validateDateRange(from: string | undefined, to: string | undefined): void {
  if (from !== undefined && to !== undefined && new Date(from).getTime() > new Date(to).getTime()) {
    throw invalidRequest("Invalid date range", { field: "to" });
  }
}

function rejectTenant(record: Record<string, unknown>): void {
  for (const key of Object.keys(record)) {
    const normalized = key.replace(/[-_]/g, "").toLowerCase();
    if (normalized === "tenantid" || normalized === "tenant") {
      throw invalidRequest("Tenant selection is not supported", { field: key });
    }
  }
}

function hasControlCharacter(value: string): boolean {
  return /[\u0000-\u001f\u007f]/u.test(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
