import type {
  OpenPlatformAuditEvent,
  OpenPlatformComplianceEvidenceReference,
  OpenPlatformCompliancePrivacyRequest,
  OpenPlatformErrorCode,
  OpenPlatformErrorValue,
  OpenPlatformInvoice,
  OpenPlatformInvoiceMetadata,
  OpenPlatformMoney,
  OpenPlatformPage,
} from "./types.js";

const SENSITIVE_ERROR_TEXT = /(?:secret|token|password|private[-_]?key|session[-_]?key|credential|authorization|cookie|vault:\/\/)/iu;
const INTERNAL_RESPONSE_TEXT = /(?:stack\s*trace|traceback|internal\s+(?:response|server|service|details)|raw\s+(?:response|error|body)|response\s+(?:body|payload)|database|postgres(?:ql)?|mysql|redis|sql\s*(?:error|query)|odbc|exception|10\.0\.0\.|127\.0\.0\.1|localhost)/iu;
const SENSITIVE_FIELD_NAME = /(?:secret|token|password|private[-_]?key|session[-_]?key|credential|authorization|cookie|signature|signing|digest|reference|account|address|phone|vault:\/\/)/iu;
const ERROR_MESSAGES: Record<OpenPlatformErrorCode, string> = {
  validation_error: "Some submitted information is invalid.",
  unauthorized: "Please sign in and try again.",
  forbidden: "You do not have permission to view this.",
  not_found: "The requested resource was not found.",
  conflict: "The resource changed. Refresh and try again.",
  rate_limited: "Too many requests. Please try again later.",
  network_error: "Unable to reach the service. Check your connection and try again.",
  timeout: "The request timed out. Please try again.",
  service_unavailable: "The service is temporarily unavailable.",
  internal_error: "Something went wrong.",
  configuration_error: "Something went wrong.",
  request_error: "Something went wrong.",
  invalid_response: "Something went wrong.",
  aborted: "The request was cancelled.",
  unknown: "Something went wrong.",
};
const ERROR_CODES = new Set<string>(Object.keys(ERROR_MESSAGES));

export const OPEN_PLATFORM_REDACTED_VALUE = "[redacted]";

export function getOpenPlatformText(value: unknown, maxLength = 512): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > maxLength || /[\u0000-\u001f\u007f]/u.test(normalized)) return undefined;
  return normalized;
}

export function getOpenPlatformSafeText(value: unknown, maxLength = 512): string | undefined {
  const text = getOpenPlatformText(value, maxLength);
  return text && !SENSITIVE_ERROR_TEXT.test(text) ? text : undefined;
}

export function getOpenPlatformPublicText(value: unknown, maxLength = 512): string | undefined {
  const text = getOpenPlatformSafeText(value, maxLength);
  return text && !INTERNAL_RESPONSE_TEXT.test(text) ? text : undefined;
}

export function getOpenPlatformErrorCode(error?: OpenPlatformErrorValue): OpenPlatformErrorCode {
  const directCode = stableErrorCode(error);
  if (directCode) return directCode;
  if (!error || typeof error !== "object") return "unknown";
  const record = error as Record<string, unknown>;
  const envelope = asRecord(record.error);
  const response = asRecord(record.response);
  const responseData = asRecord(response?.data);
  const responseBody = asRecord(response?.body);
  const bodyError = asRecord(responseBody?.error);
  return (
    stableErrorCode(record.code) ??
    stableErrorCode(record.errorCode) ??
    stableErrorCode(envelope?.code) ??
    stableErrorCode(responseData?.code) ??
    stableErrorCode(responseData?.errorCode) ??
    stableErrorCode(responseBody?.code) ??
    stableErrorCode(responseBody?.errorCode) ??
    stableErrorCode(bodyError?.code) ??
    stableErrorCode(bodyError?.errorCode) ??
    "unknown"
  );
}

export function getOpenPlatformErrorMessage(error?: OpenPlatformErrorValue): string {
  return ERROR_MESSAGES[getOpenPlatformErrorCode(error)];
}

export function getOpenPlatformStatusText(value: unknown, fallback = "Unknown"): string {
  return getOpenPlatformPublicText(value, 128) ?? fallback;
}

export function getOpenPlatformDate(value: string | Date | null | undefined): { dateTime: string; label: string } {
  if (value === undefined || value === null) return { dateTime: "", label: "—" };
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return { dateTime: "", label: "—" };
  return { dateTime: date.toISOString(), label: date.toISOString() };
}

export function getOpenPlatformDisplayValue(value: unknown): string {
  if (typeof value === "number") return Number.isFinite(value) ? String(value) : "—";
  if (typeof value === "string") return getOpenPlatformPublicText(value) ?? "—";
  return "—";
}

export function getOpenPlatformAmount(
  value: OpenPlatformMoney | number | string | null | undefined,
  fallbackCurrency?: string | null,
): string {
  if (value === undefined || value === null) return "—";
  if (typeof value === "number") {
    return Number.isFinite(value) ? `${safeCurrency(fallbackCurrency) ?? "—"} ${formatDecimal(value)}` : "—";
  }
  if (typeof value === "string") {
    const amount = getOpenPlatformPublicText(value, 128);
    return amount === undefined ? "—" : `${safeCurrency(fallbackCurrency) ?? "—"} ${amount}`;
  }
  const currency = safeCurrency(value.currency) ?? safeCurrency(fallbackCurrency);
  if (value.amountMinor !== undefined && value.amountMinor !== null && Number.isFinite(value.amountMinor)) {
    return `${currency ?? "—"} ${formatMinorAmount(value.amountMinor)}`;
  }
  const amount = value.amount;
  if (typeof amount === "number" && Number.isFinite(amount)) return `${currency ?? "—"} ${formatDecimal(amount)}`;
  if (typeof amount === "string") {
    const text = getOpenPlatformPublicText(amount, 128);
    return text === undefined ? "—" : `${currency ?? "—"} ${text}`;
  }
  return "—";
}

export function getOpenPlatformMoney(
  value: OpenPlatformMoney | number | string | null | undefined,
  fallbackCurrency?: string | null,
): string {
  return getOpenPlatformAmount(value, fallbackCurrency);
}

export function maskOpenPlatformBankAccount(value: unknown): string {
  return maskTail(value);
}

export function maskOpenPlatformPhone(value: unknown): string {
  return maskTail(value);
}

export function maskOpenPlatformAddress(value: unknown): string {
  return value === undefined || value === null || value === "" ? "—" : OPEN_PLATFORM_REDACTED_VALUE;
}

export function maskOpenPlatformSettlementReference(value: unknown): string {
  return value === undefined || value === null || value === "" ? "—" : OPEN_PLATFORM_REDACTED_VALUE;
}

export function maskOpenPlatformSecretReference(value: unknown): string {
  return value === undefined || value === null || value === "" ? "—" : OPEN_PLATFORM_REDACTED_VALUE;
}

export const maskOpenPlatformInvoiceBankAccount = maskOpenPlatformBankAccount;
export const maskOpenPlatformInvoiceAddress = maskOpenPlatformAddress;
export const maskOpenPlatformInvoicePhone = maskOpenPlatformPhone;
export const maskOpenPlatformSettlement = maskOpenPlatformSettlementReference;
export const maskOpenPlatformSecret = maskOpenPlatformSecretReference;
export const maskInvoiceBankAccount = maskOpenPlatformBankAccount;
export const maskInvoiceAddress = maskOpenPlatformAddress;
export const maskInvoicePhone = maskOpenPlatformPhone;
export const maskSettlementReference = maskOpenPlatformSettlementReference;
export const maskSecretReference = maskOpenPlatformSecretReference;
export const maskOpenPlatformEvidenceReference = maskOpenPlatformSecretReference;
export const maskOpenPlatformOperatorRef = maskOpenPlatformSecretReference;
export const maskOpenPlatformVerifiedByRef = maskOpenPlatformSecretReference;
export const maskOpenPlatformExecutionRef = maskOpenPlatformSecretReference;

export interface OpenPlatformComplianceEvidenceSummary {
  readonly kind: string;
  readonly reference: string;
  readonly recordedAt?: string;
}

export interface OpenPlatformComplianceCountEntry {
  readonly label: string;
  readonly count: number;
}

export interface OpenPlatformComplianceCountBreakdownSummary {
  readonly total: number;
  readonly entries: readonly OpenPlatformComplianceCountEntry[];
}

export function maskOpenPlatformSubjectRef(value: unknown): string {
  const text = typeof value === "number" && Number.isFinite(value)
    ? String(value)
    : getOpenPlatformText(value, 4096);
  if (text === undefined || text === OPEN_PLATFORM_REDACTED_VALUE) return OPEN_PLATFORM_REDACTED_VALUE;
  if (/^[*•]+$/u.test(text)) return text;
  const compact = text.replace(/\s+/gu, "");
  if (compact.length < 1) return OPEN_PLATFORM_REDACTED_VALUE;
  if (compact.length <= 4) return "*".repeat(compact.length);
  return `${"*".repeat(Math.min(12, compact.length - 4))}${compact.slice(-4)}`;
}

export function getOpenPlatformSafeSubjectRef(
  request: OpenPlatformCompliancePrivacyRequest | null | undefined,
): string {
  const source = request?.subjectRefMasked ?? request?.subjectRef;
  if (source === undefined || source === null || source === "") return "—";
  return maskOpenPlatformSubjectRef(source);
}

export function getOpenPlatformSafeEvidenceSummary(
  evidence: readonly (OpenPlatformComplianceEvidenceReference | null | undefined)[] | null | undefined,
  maxItems = 4,
): readonly OpenPlatformComplianceEvidenceSummary[] {
  if (!Array.isArray(evidence)) return [];
  const limit = Number.isFinite(maxItems) ? Math.max(0, Math.floor(maxItems)) : 4;
  const output: OpenPlatformComplianceEvidenceSummary[] = [];
  for (const item of evidence) {
    if (output.length >= limit) break;
    if (item === null || typeof item !== "object") continue;
    const kind = getOpenPlatformStatusText(item.kind, "evidence");
    const recordedAt = getOpenPlatformDate(item.recordedAt).dateTime;
    output.push({
      kind,
      reference: maskOpenPlatformEvidenceReference(item.reference),
      ...(recordedAt === "" ? {} : { recordedAt }),
    });
  }
  return output;
}

export function getOpenPlatformSafeTextList(value: unknown, maxItems = 8): readonly string[] {
  if (!Array.isArray(value)) return [];
  const limit = Number.isFinite(maxItems) ? Math.max(0, Math.floor(maxItems)) : 8;
  const output: string[] = [];
  for (const item of value) {
    if (output.length >= limit) break;
    const text = getOpenPlatformPublicText(item, 128);
    if (text !== undefined) output.push(text);
  }
  return output;
}

export function getOpenPlatformComplianceCount(value: unknown): number | undefined {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : undefined;
}

export function getOpenPlatformSafeCountBreakdown(
  value: unknown,
  maxEntries = 8,
): OpenPlatformComplianceCountBreakdownSummary | undefined {
  const record = asRecord(value);
  if (record === undefined) return undefined;
  const total = getOpenPlatformComplianceCount(record.total);
  const counts = asRecord(record.counts);
  if (total === undefined && counts === undefined) return undefined;
  const limit = Number.isFinite(maxEntries) ? Math.max(0, Math.floor(maxEntries)) : 8;
  const entries: OpenPlatformComplianceCountEntry[] = [];
  if (counts !== undefined) {
    for (const [key, nested] of Object.entries(counts)) {
      if (entries.length >= limit) break;
      const count = getOpenPlatformComplianceCount(nested);
      if (count === undefined) continue;
      const label = getOpenPlatformStatusText(key, "Unknown");
      entries.push({ label, count });
    }
  }
  return { total: total ?? entries.reduce((sum, entry) => sum + entry.count, 0), entries };
}

export function getOpenPlatformBooleanText(value: unknown, fallback = "—"): string {
  if (value === true) return "Yes";
  if (value === false) return "No";
  return fallback;
}

export function getOpenPlatformInvoiceMetadata(invoice: OpenPlatformInvoice | null | undefined): OpenPlatformInvoiceMetadata | undefined {
  if (!invoice) return undefined;
  const value = invoice.mainlandChina ?? invoice.mainland_china ?? invoice.invoiceMetadata ?? invoice.metadata;
  return value && typeof value === "object" ? value : undefined;
}

export function getOpenPlatformSafeInvoiceMetadata(
  invoice: OpenPlatformInvoice | null | undefined,
): Readonly<Record<string, string>> {
  const metadata = getOpenPlatformInvoiceMetadata(invoice) ?? {};
  const buyer = asRecord(invoice?.buyer) ?? {};
  const output: Record<string, string> = {};
  const values: Array<[string, unknown]> = [
    ["buyerName", metadata.buyerName ?? metadata.buyer_name ?? invoice?.buyerName ?? invoice?.buyer_name ?? invoice?.customerName ?? buyer.name ?? buyer.displayName],
    ["buyerAddress", metadata.buyerAddress ?? metadata.buyer_address ?? metadata.address ?? invoice?.buyerAddress ?? invoice?.buyer_address ?? invoice?.billingAddress ?? invoice?.address ?? buyer.address],
    ["buyerPhone", metadata.buyerPhone ?? metadata.buyer_phone ?? metadata.phone ?? invoice?.buyerPhone ?? invoice?.buyer_phone ?? invoice?.phone ?? buyer.phone],
    ["buyerBankAccount", metadata.buyerBankAccount ?? metadata.buyer_bank_account ?? metadata.bankAccount ?? metadata.bankAccountNumber ?? invoice?.buyerBankAccount ?? invoice?.buyer_bank_account ?? invoice?.bankAccount ?? invoice?.bankAccountNumber ?? buyer.bankAccount ?? buyer.bankAccountNumber],
    ["settlementReference", metadata.settlementReference ?? metadata.settlement_reference ?? metadata.settlementRef ?? invoice?.settlementReference ?? invoice?.settlement_reference ?? invoice?.settlementRef ?? buyer.settlementReference],
    ["secretReference", metadata.secretReference ?? metadata.secret_reference ?? invoice?.secretReference ?? invoice?.secret_reference ?? invoice?.secretRef ?? invoice?.secret_ref ?? buyer.secretReference],
  ];
  for (const [key, value] of values) {
    if (value === undefined || value === null || value === "") continue;
    if (key === "buyerAddress") output[key] = maskOpenPlatformAddress(value);
    else if (key === "buyerPhone") output[key] = maskOpenPlatformPhone(value);
    else if (key === "buyerBankAccount") output[key] = maskOpenPlatformBankAccount(value);
    else if (key === "settlementReference") output[key] = maskOpenPlatformSettlementReference(value);
    else if (key === "secretReference") output[key] = maskOpenPlatformSecretReference(value);
    else {
      const safe = getOpenPlatformPublicText(value, 256);
      if (safe) output[key] = safe;
    }
  }
  return output;
}

export function getOpenPlatformSafeAuditMetadata(event: OpenPlatformAuditEvent | null | undefined): string {
  const value = event?.metadata ?? (event?.detail !== undefined ? event.detail : undefined);
  if (typeof value === "string") return getOpenPlatformPublicText(value, 512) ?? "—";
  if (!value || typeof value !== "object" || Array.isArray(value)) return "—";
  const entries: string[] = [];
  for (const [key, nested] of Object.entries(value as Record<string, unknown>).slice(0, 8)) {
    if (SENSITIVE_FIELD_NAME.test(key)) continue;
    if (typeof nested === "string") {
      const safe = getOpenPlatformPublicText(nested, 128);
      if (safe) entries.push(`${key}: ${safe}`);
    } else if (typeof nested === "number" && Number.isFinite(nested)) {
      entries.push(`${key}: ${nested}`);
    } else if (typeof nested === "boolean") {
      entries.push(`${key}: ${nested ? "true" : "false"}`);
    }
  }
  return entries.length > 0 ? entries.join(", ") : "—";
}

export function getOpenPlatformListItems<T>(value: unknown): readonly T[] {
  if (Array.isArray(value)) return value as readonly T[];
  if (!value || typeof value !== "object") return [];
  const record = value as Record<string, unknown>;
  if (Array.isArray(record.items)) return record.items as readonly T[];
  if (Array.isArray(record.data)) return record.data as readonly T[];
  if (record.data && typeof record.data === "object" && Array.isArray((record.data as Record<string, unknown>).items)) {
    return (record.data as Record<string, unknown>).items as readonly T[];
  }
  return [];
}

export function getOpenPlatformPageItems<T>(page: OpenPlatformPage<T> | null | undefined): readonly T[] {
  return page?.items ?? [];
}

function stableErrorCode(value: unknown): OpenPlatformErrorCode | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim().toLowerCase().replace(/[\s-]+/gu, "_");
  return ERROR_CODES.has(normalized) ? normalized as OpenPlatformErrorCode : undefined;
}

function safeCurrency(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim().toUpperCase();
  return /^[A-Z]{3,8}$/u.test(normalized) ? normalized : undefined;
}

function formatMinorAmount(value: number): string {
  if (!Number.isSafeInteger(value)) return "—";
  const sign = value < 0 ? "-" : "";
  const absolute = Math.abs(value);
  return `${sign}${Math.floor(absolute / 100)}.${String(absolute % 100).padStart(2, "0")}`;
}

function formatDecimal(value: number): string {
  if (!Number.isFinite(value)) return "—";
  return Number.isInteger(value) ? String(value) : value.toFixed(2);
}

function maskTail(value: unknown): string {
  const text = typeof value === "number" && Number.isFinite(value)
    ? String(value)
    : getOpenPlatformText(value, 4096);
  if (text === undefined) return "—";
  if (text === OPEN_PLATFORM_REDACTED_VALUE || /^[*•]+$/u.test(text)) return OPEN_PLATFORM_REDACTED_VALUE;
  const compact = text.replace(/\s+/gu, "");
  if (compact.length <= 4) return "****";
  return `****${compact.slice(-4)}`;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}
