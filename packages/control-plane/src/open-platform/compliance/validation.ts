import { randomUUID } from "node:crypto";
import { complianceValidationError } from "./errors.js";
import { assertComplianceTextIsRedacted } from "./redaction.js";
import {
  COMPLIANCE_ENTITY_KINDS,
  COMPLIANCE_ENTITY_PREFIXES,
  COMPLIANCE_MAX_EVIDENCE_REFS,
  COMPLIANCE_MAX_PAGE_SIZE,
  COMPLIANCE_MAX_RESPONSE_DAYS,
  COMPLIANCE_MAX_RETENTION_DAYS,
  COMPLIANCE_MIN_RETENTION_DAYS,
  type ComplianceEntityKind,
  type ComplianceEvidence,
} from "./types.js";

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const REGION_PATTERN = /^[A-Za-z]{2}(?:-[A-Za-z0-9]{2,8}){0,2}$/u;
const SUBJECT_REF_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@+-]{2,127}$/u;
const CODE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u;
const SUBJECT_REF_PLACEHOLDERS = Object.freeze([
  "[redacted]",
  "redacted",
  "***",
  "n/a",
  "na",
  "none",
  "null",
  "undefined",
  "unknown",
]);

export function complianceEntityId(
  kind: ComplianceEntityKind,
  value: unknown = randomSuffix(),
  field = `${kind}Id`,
): string {
  if (typeof value !== "string") {
    throw complianceValidationError("Compliance identifier is invalid", field);
  }
  const normalized = value.trim();
  const prefix = COMPLIANCE_ENTITY_PREFIXES[kind];
  if (
    !normalized.startsWith(`${prefix}_`) ||
    !UUID_PATTERN.test(normalized.slice(prefix.length + 1))
  ) {
    throw complianceValidationError("Compliance identifier is invalid", field);
  }
  return normalized;
}

export function assertComplianceId(
  value: unknown,
  kind: ComplianceEntityKind,
  field = `${kind}Id`,
): string {
  return complianceEntityId(kind, value, field);
}

export function normalizeComplianceTenantId(value: unknown): string {
  if (typeof value !== "string") {
    throw complianceValidationError(
      "Compliance tenant identifier is invalid",
      "tenantId",
    );
  }
  const normalized = value.trim();
  if (
    !/^[a-z][a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(normalized) ||
    COMPLIANCE_ENTITY_KINDS.some((kind) =>
      normalized.startsWith(`${COMPLIANCE_ENTITY_PREFIXES[kind]}_`) ||
      normalized.startsWith(`${COMPLIANCE_ENTITY_PREFIXES[kind]}-`),
    )
  ) {
    throw complianceValidationError(
      "Compliance tenant identifier is invalid",
      "tenantId",
    );
  }
  return normalized;
}

export function requireComplianceText(
  value: unknown,
  field: string,
  maxLength = 256,
  options: { readonly allowEmpty?: boolean } = {},
): string {
  if (typeof value !== "string") {
    throw complianceValidationError("Compliance text is invalid", field);
  }
  const normalized = value.trim();
  const empty = normalized.length === 0;
  if (empty) {
    if (options.allowEmpty === true) return normalized;
    throw complianceValidationError("Compliance text is invalid", field);
  }
  if (normalized.length > maxLength || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw complianceValidationError("Compliance text is invalid", field);
  }
  assertComplianceTextIsRedacted(normalized, field);
  return normalized;
}

export function requireComplianceCode(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw complianceValidationError("Compliance code is invalid", field);
  }
  const normalized = value.trim();
  if (!CODE_PATTERN.test(normalized)) {
    throw complianceValidationError("Compliance code is invalid", field);
  }
  return normalized;
}

export function requireComplianceRegion(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw complianceValidationError("Compliance region is invalid", field);
  }
  const normalized = value.trim();
  if (!REGION_PATTERN.test(normalized)) {
    throw complianceValidationError("Compliance region is invalid", field);
  }
  return normalized;
}

export function requireComplianceRegionList(
  value: unknown,
  field: string,
  options: { readonly min?: number; readonly max?: number } = {},
): string[] {
  const list = requireStringList(value, field, options);
  const normalized = list.map((item, index) =>
    requireComplianceRegion(item, `${field}[${index}]`),
  );
  return sortUnique(normalized);
}

export function requireComplianceIdentifier(
  value: unknown,
  field: string,
  maxLength = 128,
): string {
  if (typeof value !== "string") {
    throw complianceValidationError("Compliance identifier is invalid", field);
  }
  const normalized = value.trim();
  if (
    normalized.length < 1 ||
    normalized.length > maxLength ||
    /[\s\u0000-\u001f\u007f]/u.test(normalized)
  ) {
    throw complianceValidationError("Compliance identifier is invalid", field);
  }
  return normalized;
}

export function requireComplianceSubjectRef(
  value: unknown,
  field = "subjectRef",
): string {
  const normalized = requireComplianceIdentifier(value, field, 128);
  if (
    !SUBJECT_REF_PATTERN.test(normalized) ||
    SUBJECT_REF_PLACEHOLDERS.includes(normalized.toLowerCase())
  ) {
    throw complianceValidationError(
      "Compliance subject reference must be an opaque subject key",
      field,
    );
  }
  return normalized;
}

export function requireComplianceEnum<T extends string>(
  value: unknown,
  allowed: readonly T[],
  field: string,
): T {
  if (typeof value !== "string" || !allowed.includes(value as T)) {
    throw complianceValidationError("Compliance value is not allowed", field);
  }
  return value as T;
}

export function requireComplianceBoolean(value: unknown, field: string): boolean {
  if (typeof value !== "boolean") {
    throw complianceValidationError("Compliance flag must be boolean", field);
  }
  return value;
}

export function requireComplianceInteger(
  value: unknown,
  field: string,
  options: { readonly min?: number; readonly max?: number } = {},
): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw complianceValidationError("Compliance integer is invalid", field);
  }
  const min = options.min ?? Number.MIN_SAFE_INTEGER;
  const max = options.max ?? Number.MAX_SAFE_INTEGER;
  if (value < min || value > max) {
    throw complianceValidationError("Compliance integer is invalid", field);
  }
  return value;
}

export function requireComplianceRetentionDays(
  value: unknown,
  field = "retentionDays",
): number {
  return requireComplianceInteger(value, field, {
    min: COMPLIANCE_MIN_RETENTION_DAYS,
    max: COMPLIANCE_MAX_RETENTION_DAYS,
  });
}

export function requireComplianceResponseDays(
  value: unknown,
  field = "responseDays",
): number {
  return requireComplianceInteger(value, field, { min: 1, max: COMPLIANCE_MAX_RESPONSE_DAYS });
}

export function normalizeComplianceTimestamp(
  value: unknown,
  field: string,
): string {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) {
    throw complianceValidationError("Compliance timestamp is invalid", field);
  }
  return new Date(Date.parse(value)).toISOString();
}

export function requireComplianceStringList(
  value: unknown,
  field: string,
  options: { readonly min?: number; readonly max?: number } = {},
): string[] {
  return sortUnique(requireStringList(value, field, options));
}

export function requireComplianceEnumList<T extends string>(
  value: unknown,
  allowed: readonly T[],
  field: string,
  options: { readonly min?: number; readonly max?: number } = {},
): T[] {
  const list = requireStringList(value, field, options);
  return sortUnique(
    list.map((item, index) =>
      requireComplianceEnum(item, allowed, `${field}[${index}]`),
    ),
  );
}

export function requireComplianceResourceIdList(
  value: unknown,
  kind: ComplianceEntityKind,
  field: string,
  options: { readonly min?: number; readonly max?: number; readonly allowEmpty?: boolean } = {},
): string[] {
  const list = requireStringList(value, field, {
    ...options,
    min: options.allowEmpty === true ? 0 : options.min,
  });
  return sortUnique(
    list.map((item, index) =>
      assertComplianceId(item, kind, `${field}[${index}]`),
    ),
  );
}

export function requireComplianceEvidenceList(
  value: unknown,
  field: string,
  kinds: ReadonlyArray<ComplianceEvidence["kind"]>,
  options: { readonly min?: number; readonly max?: number } = {},
): ComplianceEvidence[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    throw complianceValidationError("Compliance evidence list is invalid", field);
  }
  if (value.length > COMPLIANCE_MAX_EVIDENCE_REFS) {
    throw complianceValidationError("Compliance evidence list is too large", field);
  }
  const min = options.min ?? 0;
  if (value.length < min) {
    throw complianceValidationError(
      "Compliance evidence list is too small",
      field,
    );
  }
  const seen = new Set<string>();
  return value.map((item, index) => {
    if (item === null || typeof item !== "object" || Array.isArray(item)) {
      throw complianceValidationError(
        "Compliance evidence entry is invalid",
        `${field}[${index}]`,
      );
    }
    const entry = item as Record<string, unknown>;
    const reference = requireComplianceText(
      entry.reference,
      `${field}[${index}].reference`,
      512,
    );
    if (seen.has(reference)) {
      throw complianceValidationError(
        "Compliance evidence references must be unique",
        `${field}[${index}].reference`,
      );
    }
    seen.add(reference);
    const kind = requireComplianceEnum(
      entry.kind,
      kinds,
      `${field}[${index}].kind`,
    );
    const recordedAt =
      entry.recordedAt === undefined
        ? undefined
        : normalizeComplianceTimestamp(
          entry.recordedAt,
          `${field}[${index}].recordedAt`,
        );
    return {
      reference,
      kind,
      ...(recordedAt === undefined ? {} : { recordedAt }),
    };
  });
}

export function requireComplianceEvidenceOptionalList(
  value: unknown,
  field: string,
  kinds: ReadonlyArray<ComplianceEvidence["kind"]>,
  options: { readonly min?: number; readonly max?: number } = {},
): ComplianceEvidence[] {
  return requireComplianceEvidenceList(value, field, kinds, {
    min: 0,
    ...options,
  });
}

export function normalizeComplianceLimit(
  value: unknown,
  field = "limit",
): number {
  if (value === undefined) return 20;
  if (
    (typeof value !== "number" && typeof value !== "string") ||
    (typeof value === "number" && !Number.isSafeInteger(value)) ||
    (typeof value === "string" && !/^(?:0|[1-9][0-9]*)$/u.test(value))
  ) {
    throw complianceValidationError(
      "Compliance pagination limit is invalid",
      field,
    );
  }
  const normalized = typeof value === "number" ? value : Number(value);
  if (
    !Number.isSafeInteger(normalized) ||
    normalized < 1 ||
    normalized > COMPLIANCE_MAX_PAGE_SIZE
  ) {
    throw complianceValidationError(
      "Compliance pagination limit is invalid",
      field,
    );
  }
  return normalized;
}

export function requireCompliancePeriod(
  from: unknown,
  to: unknown,
): { readonly from: string; readonly to: string } {
  const start = normalizeComplianceTimestamp(from, "period.from");
  const end = normalizeComplianceTimestamp(to, "period.to");
  if (Date.parse(end) < Date.parse(start)) {
    throw complianceValidationError(
      "Compliance report period is invalid",
      "period.to",
    );
  }
  return { from: start, to: end };
}

export function cloneComplianceValue<T>(value: T): T {
  if (value === null || typeof value !== "object") return value;
  return structuredClone(value);
}

export function sortUnique<T extends string>(values: readonly T[]): T[] {
  return [...new Set<T>(values)].sort((left, right) =>
    left < right ? -1 : left > right ? 1 : 0,
  );
}

function requireStringList(
  value: unknown,
  field: string,
  options: { readonly min?: number; readonly max?: number } = {},
): string[] {
  if (!Array.isArray(value)) {
    throw complianceValidationError("Compliance list is invalid", field);
  }
  const min = options.min ?? 0;
  const max = options.max ?? 64;
  if (value.length < min || value.length > max) {
    throw complianceValidationError("Compliance list size is invalid", field);
  }
  return value.map((item, index) => {
    if (typeof item !== "string") {
      throw complianceValidationError("Compliance list is invalid", `${field}[${index}]`);
    }
    return item;
  });
}

function randomSuffix(): string {
  return randomUUID();
}
