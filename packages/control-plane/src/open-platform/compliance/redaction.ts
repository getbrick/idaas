import { maskOpenPlatformComplianceSubjectRef } from "@getbrick/idaas-contracts";
import { complianceRedactionFailed, complianceValidationError } from "./errors.js";
import { COMPLIANCE_MAX_AUDIT_METADATA_KEYS, COMPLIANCE_REDACTED } from "./types.js";

export { maskOpenPlatformComplianceSubjectRef };

const SENSITIVE_KEY_PATTERN =
  /(?:secret|password|passwd|token|authorization|auth|privatekey|credential|apikey|session|cookie|signature|plaintext|rawvalue)/iu;
const PERSONAL_DATA_KEY_PATTERN =
  /(?:email|mail|phone|mobile|telephone|idcard|idnumber|passport|ssn|bankcard|iban|accountnumber|subject)/iu;
const HEX_GUARD_BEFORE = "(?<![0-9a-f-])";
const HEX_GUARD_AFTER = "(?![0-9a-f-])";
const EMAIL_PATTERN = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/gu;
const MAINLAND_CHINA_ID_PATTERN = new RegExp(
  `${HEX_GUARD_BEFORE}[1-9][0-9]{5}(?:19|20)[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])[0-9]{3}[0-9x]${HEX_GUARD_AFTER}`,
  "giu",
);
const MAINLAND_CHINA_MOBILE_PATTERN = new RegExp(
  `${HEX_GUARD_BEFORE}1[3-9][0-9]{9}${HEX_GUARD_AFTER}`,
  "giu",
);
const MAINLAND_CHINA_LANDLINE_PATTERN = new RegExp(
  `${HEX_GUARD_BEFORE}0[1-9][0-9]{1,2}-?[0-9]{7,8}${HEX_GUARD_AFTER}`,
  "giu",
);
const BANK_CARD_PATTERN = new RegExp(
  `${HEX_GUARD_BEFORE}[0-9]{16,19}${HEX_GUARD_AFTER}`,
  "giu",
);
const IPV4_PATTERN =
  /(?<![0-9])(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}(?![0-9])/gu;

export const COMPLIANCE_REDACTION_MASK = "*";

export function isSensitiveComplianceField(name: string): boolean {
  if (typeof name !== "string" || name.length === 0) return true;
  return SENSITIVE_KEY_PATTERN.test(name.replace(/[-_]/gu, ""));
}

export function isPersonalDataComplianceField(name: string): boolean {
  if (typeof name !== "string" || name.length === 0) return true;
  return PERSONAL_DATA_KEY_PATTERN.test(name.replace(/[-_]/gu, ""));
}

export function maskComplianceEmail(value: string): string {
  const at = value.lastIndexOf("@");
  if (at <= 0) return COMPLIANCE_REDACTED;
  const local = value.slice(0, at);
  const domain = value.slice(at + 1);
  const visible = local.slice(0, Math.min(2, local.length));
  return `${visible}${COMPLIANCE_REDACTION_MASK.repeat(
    Math.max(1, local.length - visible.length),
  )}@${domain}`;
}

export function maskCompliancePhone(value: string): string {
  if (value.length < 4) return COMPLIANCE_REDACTED;
  return `${COMPLIANCE_REDACTION_MASK.repeat(value.length - 4)}${value.slice(-4)}`;
}

export function maskComplianceIdNumber(value: string): string {
  if (value.length < 4) return COMPLIANCE_REDACTED;
  return `${value.slice(0, 1)}${COMPLIANCE_REDACTION_MASK.repeat(
    value.length - 2,
  )}${value.slice(-1)}`;
}

export function redactComplianceText(value: string): string {
  if (typeof value !== "string" || value.length === 0) return value;
  return value
    .replace(MAINLAND_CHINA_ID_PATTERN, maskComplianceIdNumber)
    .replace(EMAIL_PATTERN, maskComplianceEmail)
    .replace(MAINLAND_CHINA_MOBILE_PATTERN, maskCompliancePhone)
    .replace(MAINLAND_CHINA_LANDLINE_PATTERN, maskCompliancePhone)
    .replace(IPV4_PATTERN, COMPLIANCE_REDACTED)
    .replace(BANK_CARD_PATTERN, maskCompliancePhone);
}

export function assertComplianceTextIsRedacted(value: string, field: string): void {
  if (typeof value !== "string") {
    throw complianceValidationError("Compliance text is invalid", field);
  }
  if (redactComplianceText(value) !== value) {
    throw complianceRedactionFailed(field);
  }
}

export function redactComplianceValue(
  value: unknown,
  options: { readonly field: string; readonly maxDepth?: number },
): unknown {
  return redactValue(
    value,
    options.field,
    options.maxDepth ?? 8,
    0,
    new Set<object>(),
  );
}

export function toComplianceAuditMetadata(
  value: Readonly<Record<string, unknown>> | undefined,
): Readonly<Record<string, string | number | boolean | null>> {
  if (value === undefined) return Object.freeze({});
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw complianceValidationError(
      "Compliance audit metadata is invalid",
      "metadata",
    );
  }
  const keys = Object.keys(value).sort();
  if (keys.length > COMPLIANCE_MAX_AUDIT_METADATA_KEYS) {
    throw complianceValidationError(
      "Compliance audit metadata is too large",
      "metadata",
    );
  }
  const safe: Record<string, string | number | boolean | null> = {};
  for (const key of keys) {
    if (isSensitiveComplianceField(key) || isPersonalDataComplianceField(key)) {
      continue;
    }
    const item = redactComplianceValue(value[key], { field: key, maxDepth: 4 });
    if (item === null || typeof item === "boolean") {
      safe[key] = item;
    } else if (typeof item === "number" && Number.isFinite(item)) {
      safe[key] = item;
    } else if (typeof item === "string" && isSafeComplianceMetadataString(item)) {
      safe[key] = item;
    }
  }
  return Object.freeze(safe);
}

export function assertComplianceReportIsRedacted(
  value: unknown,
  field = "report",
): void {
  inspectForLeak(value, field, 0, new Set<object>());
}

export function complianceReportContainsSensitiveValue(
  report: unknown,
  candidates: readonly string[],
): boolean {
  const serialized = safeStringify(report);
  return candidates.some(
    (candidate) =>
      typeof candidate === "string" &&
      candidate.trim().length >= 3 &&
      serialized.includes(candidate.trim()),
  );
}

function redactValue(
  value: unknown,
  field: string,
  maxDepth: number,
  depth: number,
  seen: Set<object>,
): unknown {
  if (value === undefined) return null;
  if (value === null) return null;
  if (depth > maxDepth) return COMPLIANCE_REDACTED;
  if (typeof value === "string") {
    if (isSensitiveComplianceField(field)) return COMPLIANCE_REDACTED;
    return redactComplianceText(value);
  }
  if (typeof value === "boolean") return value;
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (typeof value !== "object") return COMPLIANCE_REDACTED;
  if (seen.has(value)) return COMPLIANCE_REDACTED;
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      return value.map((item) => redactValue(item, field, maxDepth, depth + 1, seen));
    }
    const safe: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      if (isSensitiveComplianceField(key)) {
        safe[key] = COMPLIANCE_REDACTED;
        continue;
      }
      safe[key] = redactValue(
        (value as Record<string, unknown>)[key],
        key,
        maxDepth,
        depth + 1,
        seen,
      );
    }
    return safe;
  } finally {
    seen.delete(value);
  }
}

function inspectForLeak(
  value: unknown,
  field: string,
  depth: number,
  seen: Set<object>,
): void {
  if (depth > 32) {
    throw complianceRedactionFailed(field);
  }
  if (typeof value === "string") {
    if (isSensitiveComplianceField(field) || redactComplianceText(value) !== value) {
      throw complianceRedactionFailed(field);
    }
    return;
  }
  if (value === null || typeof value !== "object") return;
  if (seen.has(value)) {
    throw complianceRedactionFailed(field);
  }
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      for (const item of value) inspectForLeak(item, field, depth + 1, seen);
      return;
    }
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      if (isSensitiveComplianceField(key)) {
        throw complianceRedactionFailed(key);
      }
      inspectForLeak(item, key, depth + 1, seen);
    }
  } finally {
    seen.delete(value);
  }
}

function isSafeComplianceMetadataString(value: string): boolean {
  return (
    value.length <= 512 &&
    !/[\u0000-\u001f\u007f]/u.test(value) &&
    redactComplianceText(value) === value
  );
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value) ?? "";
  } catch {
    return "";
  }
}
