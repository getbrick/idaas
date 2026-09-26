import { createHash } from "node:crypto";
import {
  commerceValidationError,
} from "./errors.js";
import {
  assertDecimalString,
  assertMoney,
  normalizeDecimalString,
} from "./money.js";
import {
  COMMISSION_RULE_STATUSES,
  COMMERCE_DEFAULT_PAGE_SIZE,
  COMMERCE_DISPUTE_EVIDENCE_MAX_LENGTH,
  COMMERCE_DISPUTE_REASON_MAX_LENGTH,
  COMMERCE_DISPUTE_RESOLUTION_NOTE_MAX_LENGTH,
  COMMERCE_ENTITY_KINDS,
  COMMERCE_ENTITY_PREFIXES,
  COMMERCE_MAX_PAGE_SIZE,
  INVOICE_DISPUTE_STATUSES,
  INVOICE_STATUSES,
  MARKETPLACE_LISTING_STATUSES,
  PARTNER_ACCOUNT_STATUSES,
  type CommissionRuleQuery,
  type CommerceEntityKind,
  type DecimalString,
  type InvoiceDisputeQuery,
  type InvoiceQuery,
  type MainlandChinaInvoiceMetadata,
  type MarketplaceListingQuery,
  type Money,
  type PartnerAccountQuery,
} from "./types.js";

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const COMMERCE_SENSITIVE_DIGIT_RUN_PATTERN = /[0-9]{8,}/u;
const COMMERCE_SENSITIVE_CREDENTIAL_PATTERN =
  /(?:password|passwd|secret|token|api[-_ ]?key|authorization|bearer|private[-_ ]?key|credential|passphrase)\b/iu;
const COMMERCE_SENSITIVE_MARKER_PATTERN = /-----BEGIN|PKCS10/iu;
const COMMERCE_SENSITIVE_REFERENCE_PATTERN =
  /settlement:\/\/|private[-_]bank|bank[-_]account[-_]/iu;
const COMMERCE_SENSITIVE_TOKEN_PATTERN =
  /(?:sk|pk|rk|ghp|gho|ghs|ghu|github_pat|xox[baprs]?|AKIA|ASIA)[-_][A-Za-z0-9]{8,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/u;

export function assertCommerceHasNoSensitiveValue(
  value: string,
  field: string,
): void {
  if (
    COMMERCE_SENSITIVE_DIGIT_RUN_PATTERN.test(value) ||
    COMMERCE_SENSITIVE_CREDENTIAL_PATTERN.test(value) ||
    COMMERCE_SENSITIVE_MARKER_PATTERN.test(value) ||
    COMMERCE_SENSITIVE_REFERENCE_PATTERN.test(value) ||
    COMMERCE_SENSITIVE_TOKEN_PATTERN.test(value)
  ) {
    throw commerceValidationError(
      "Commerce text must not contain secrets, credentials, or bank account values",
      field,
    );
  }
}

export function requireCommerceDisputeReason(value: unknown): string {
  const reason = requireCommerceText(
    value,
    "reason",
    COMMERCE_DISPUTE_REASON_MAX_LENGTH,
  );
  assertCommerceHasNoSensitiveValue(reason, "reason");
  return reason;
}

export function requireCommerceDisputeResolutionNote(value: unknown): string {
  const note = requireCommerceText(
    value,
    "resolutionNote",
    COMMERCE_DISPUTE_RESOLUTION_NOTE_MAX_LENGTH,
  );
  assertCommerceHasNoSensitiveValue(note, "resolutionNote");
  return note;
}

export function requireCommerceEvidenceReference(value: unknown): string {
  const reference = requireCommerceIdentifier(value, "evidenceReference");
  if (reference.length > COMMERCE_DISPUTE_EVIDENCE_MAX_LENGTH) {
    throw commerceValidationError(
      "Commerce evidence reference is invalid",
      "evidenceReference",
    );
  }
  assertCommerceHasNoSensitiveValue(reference, "evidenceReference");
  return reference;
}

export function normalizeCommerceTenantId(value: unknown): string {
  if (typeof value !== "string") {
    throw commerceValidationError("Commerce tenant identifier is invalid", "tenantId");
  }
  const normalized = value.trim();
  if (
    !/^[a-z][a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(normalized) ||
    (COMMERCE_ENTITY_KINDS as readonly CommerceEntityKind[]).some((kind) =>
      normalized.startsWith(`${COMMERCE_ENTITY_PREFIXES[kind]}_`) ||
      normalized.startsWith(`${COMMERCE_ENTITY_PREFIXES[kind]}-`)
    )
  ) {
    throw commerceValidationError("Commerce tenant identifier is invalid", "tenantId");
  }
  return normalized;
}

export function assertCommerceId(
  value: unknown,
  kind: CommerceEntityKind | "invoice" | "invoiceLine" | "usageEvent" | "invoiceDispute",
  field = `${kind}Id`,
): string {
  if (typeof value !== "string") {
    throw commerceValidationError("Commerce resource identifier is invalid", field);
  }
  const normalized = value.trim();
  const prefix = COMMERCE_ENTITY_PREFIXES[kind];
  if (
    !normalized.startsWith(`${prefix}_`) ||
    !UUID_PATTERN.test(normalized.slice(prefix.length + 1))
  ) {
    throw commerceValidationError("Commerce resource identifier is invalid", field);
  }
  return normalized;
}

export function requireCommerceText(
  value: unknown,
  field: string,
  maxLength: number,
): string {
  if (typeof value !== "string") {
    throw commerceValidationError("Commerce text is invalid", field);
  }
  const normalized = value.trim();
  if (
    normalized.length < 1 ||
    normalized.length > maxLength ||
    /[\u0000-\u001f\u007f]/u.test(normalized)
  ) {
    throw commerceValidationError("Commerce text is invalid", field);
  }
  return normalized;
}

export function requireCommerceCode(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw commerceValidationError("Commerce code is invalid", field);
  }
  const normalized = value.trim();
  if (
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u.test(normalized)
  ) {
    throw commerceValidationError("Commerce code is invalid", field);
  }
  return normalized;
}

export function requireCommerceIdentifier(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw commerceValidationError("Commerce identifier is invalid", field);
  }
  const normalized = value.trim();
  if (
    normalized.length < 1 ||
    normalized.length > 128 ||
    /[\s\u0000-\u001f\u007f]/u.test(normalized)
  ) {
    throw commerceValidationError("Commerce identifier is invalid", field);
  }
  return normalized;
}

export function normalizeCommerceTimestamp(value: unknown, field: string): string {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) {
    throw commerceValidationError("Commerce timestamp is invalid", field);
  }
  return new Date(Date.parse(value)).toISOString();
}

export function normalizePeriod(
  periodStart: unknown,
  periodEnd: unknown,
): { readonly periodStart: string; readonly periodEnd: string } {
  const start = normalizeCommerceTimestamp(periodStart, "periodStart");
  const end = normalizeCommerceTimestamp(periodEnd, "periodEnd");
  if (Date.parse(end) <= Date.parse(start)) {
    throw commerceValidationError(
      "Commerce period end must be after period start",
      "periodEnd",
    );
  }
  return { periodStart: start, periodEnd: end };
}

export function isEffectiveAt(
  effectiveFrom: string,
  effectiveTo: string | undefined,
  at: string,
): boolean {
  const point = Date.parse(at);
  return (
    point >= Date.parse(effectiveFrom) &&
    (effectiveTo === undefined || point < Date.parse(effectiveTo))
  );
}

export function requireEffectiveRange(
  effectiveFrom: string,
  effectiveTo: string | undefined,
): void {
  if (
    effectiveTo !== undefined &&
    Date.parse(effectiveTo) <= Date.parse(effectiveFrom)
  ) {
    throw commerceValidationError(
      "Commerce effective end must be after effective start",
      "effectiveTo",
    );
  }
}

export function normalizeIdempotencyKey(value: unknown): string {
  return requireCommerceIdentifier(value, "idempotencyKey");
}

export function normalizeCommerceLimit(
  value: unknown,
  field = "limit",
): number {
  if (value === undefined) return COMMERCE_DEFAULT_PAGE_SIZE;
  if (
    (typeof value !== "number" && typeof value !== "string") ||
    (typeof value === "number" && !Number.isSafeInteger(value)) ||
    (typeof value === "string" && !/^(?:0|[1-9][0-9]*)$/u.test(value))
  ) {
    throw commerceValidationError("Commerce pagination limit is invalid", field);
  }
  const normalized = typeof value === "number" ? value : Number(value);
  if (
    !Number.isSafeInteger(normalized) ||
    normalized < 1 ||
    normalized > COMMERCE_MAX_PAGE_SIZE
  ) {
    throw commerceValidationError("Commerce pagination limit is invalid", field);
  }
  return normalized;
}

export function encodeCommerceCursor(payload: {
  readonly version: 1;
  readonly kind: string;
  readonly scope: string;
  readonly offset: number;
}): string {
  if (
    !Number.isSafeInteger(payload.offset) ||
    payload.offset < 0 ||
    typeof payload.kind !== "string" ||
    payload.kind.length < 1 ||
    payload.kind.length > 128 ||
    /[\u0000-\u001f\u007f]/u.test(payload.kind) ||
    typeof payload.scope !== "string" ||
    payload.scope.length > 4096 ||
    /[\u0000-\u001f\u007f]/u.test(payload.scope)
  ) {
    throw commerceValidationError("Commerce pagination cursor is invalid", "cursor");
  }
  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
}

export function decodeCommerceCursor(
  value: unknown,
  kind: string,
  scope: string,
): number {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 2048 ||
    !/^[A-Za-z0-9_-]+$/u.test(value) ||
    Buffer.from(value, "base64url").toString("base64url") !== value
  ) {
    throw commerceValidationError("Commerce pagination cursor is invalid", "cursor");
  }
  try {
    const parsed = JSON.parse(
      Buffer.from(value, "base64url").toString("utf8"),
    ) as Partial<{
      version: number;
      kind: string;
      scope: string;
      offset: number;
    }>;
    if (
      parsed === null ||
      typeof parsed !== "object" ||
      Array.isArray(parsed) ||
      parsed.version !== 1 ||
      parsed.kind !== kind ||
      parsed.scope !== scope ||
      !Number.isSafeInteger(parsed.offset) ||
      (parsed.offset ?? -1) < 0
    ) {
      throw new Error("invalid cursor");
    }
    return parsed.offset as number;
  } catch {
    throw commerceValidationError("Commerce pagination cursor is invalid", "cursor");
  }
}

export function normalizeCommercePageQuery(
  value: {
    readonly cursor?: unknown;
    readonly limit?: unknown;
    readonly pageSize?: unknown;
  },
): { readonly limit: number; readonly cursor?: string } {
  const input = value ?? {};
  if (
    input.limit !== undefined &&
    input.pageSize !== undefined
  ) {
    throw commerceValidationError(
      "Commerce pagination accepts only one limit",
      "limit",
    );
  }
  const limit = normalizeCommerceLimit(
    input.limit ?? input.pageSize,
    input.limit === undefined ? "pageSize" : "limit",
  );
  if (input.cursor === undefined) return { limit };
  if (
    typeof input.cursor !== "string" ||
    input.cursor.length < 1 ||
    input.cursor.length > 2048 ||
    /[\u0000-\u001f\u007f]/u.test(input.cursor)
  ) {
    throw commerceValidationError("Commerce pagination cursor is invalid", "cursor");
  }
  return { limit, cursor: input.cursor };
}

export function normalizeMarketplaceListingQuery(
  value: MarketplaceListingQuery,
): MarketplaceListingQuery {
  const input = value ?? ({} as MarketplaceListingQuery);
  assertCommerceQueryKeys(input, [
    "tenantId",
    "id",
    "status",
    "partnerAccountId",
    "productId",
    "search",
    "q",
    "cursor",
    "limit",
    "pageSize",
  ]);
  const page = normalizeCommercePageQuery(input);
  const search = normalizeCommerceSearch(input.search, input.q);
  return {
    tenantId: normalizeCommerceTenantId(input.tenantId),
    ...page,
    ...(input.id === undefined ? {} : { id: assertCommerceId(input.id, "marketplaceListing") }),
    ...(input.status === undefined
      ? {}
      : { status: normalizeCommerceStatus(input.status, MARKETPLACE_LISTING_STATUSES, "status") }),
    ...(input.partnerAccountId === undefined
      ? {}
      : { partnerAccountId: assertCommerceId(input.partnerAccountId, "partnerAccount", "partnerAccountId") }),
    ...(input.productId === undefined
      ? {}
      : { productId: requireCommerceExternalReference(input.productId, "product", "productId") }),
    ...(search === undefined ? {} : { search }),
  };
}

export function normalizePartnerAccountQuery(
  value: PartnerAccountQuery,
): PartnerAccountQuery {
  const input = value ?? ({} as PartnerAccountQuery);
  assertCommerceQueryKeys(input, [
    "tenantId",
    "id",
    "status",
    "partnerCode",
    "search",
    "q",
    "cursor",
    "limit",
    "pageSize",
  ]);
  const page = normalizeCommercePageQuery(input);
  const search = normalizeCommerceSearch(input.search, input.q);
  return {
    tenantId: normalizeCommerceTenantId(input.tenantId),
    ...page,
    ...(input.id === undefined ? {} : { id: assertCommerceId(input.id, "partnerAccount") }),
    ...(input.status === undefined
      ? {}
      : { status: normalizeCommerceStatus(input.status, PARTNER_ACCOUNT_STATUSES, "status") }),
    ...(input.partnerCode === undefined
      ? {}
      : { partnerCode: requireCommerceCode(input.partnerCode, "partnerCode") }),
    ...(search === undefined ? {} : { search }),
  };
}

export function normalizeCommissionRuleQuery(
  value: CommissionRuleQuery,
): CommissionRuleQuery {
  const input = value ?? ({} as CommissionRuleQuery);
  assertCommerceQueryKeys(input, [
    "tenantId",
    "id",
    "listingId",
    "partnerAccountId",
    "status",
    "cursor",
    "limit",
    "pageSize",
  ]);
  const page = normalizeCommercePageQuery(input);
  return {
    tenantId: normalizeCommerceTenantId(input.tenantId),
    ...page,
    ...(input.id === undefined ? {} : { id: assertCommerceId(input.id, "commissionRule") }),
    ...(input.listingId === undefined
      ? {}
      : { listingId: assertCommerceId(input.listingId, "marketplaceListing", "listingId") }),
    ...(input.partnerAccountId === undefined
      ? {}
      : { partnerAccountId: assertCommerceId(input.partnerAccountId, "partnerAccount", "partnerAccountId") }),
    ...(input.status === undefined
      ? {}
      : { status: normalizeCommerceStatus(input.status, COMMISSION_RULE_STATUSES, "status") }),
  };
}

export function normalizeInvoiceQuery(value: InvoiceQuery): InvoiceQuery {
  const input = value ?? ({} as InvoiceQuery);
  assertCommerceQueryKeys(input, [
    "tenantId",
    "id",
    "subscriptionId",
    "planId",
    "status",
    "periodStart",
    "periodEnd",
    "from",
    "to",
    "cursor",
    "limit",
    "pageSize",
  ]);
  const page = normalizeCommercePageQuery(input);
  const periodStart = input.periodStart === undefined
    ? undefined
    : normalizeCommerceTimestamp(input.periodStart, "periodStart");
  const periodEnd = input.periodEnd === undefined
    ? undefined
    : normalizeCommerceTimestamp(input.periodEnd, "periodEnd");
  if (periodStart !== undefined && periodEnd !== undefined) {
    normalizePeriod(periodStart, periodEnd);
  }
  const from = input.from === undefined
    ? undefined
    : normalizeCommerceTimestamp(input.from, "from");
  const to = input.to === undefined
    ? undefined
    : normalizeCommerceTimestamp(input.to, "to");
  if (from !== undefined && to !== undefined && Date.parse(from) > Date.parse(to)) {
    throw commerceValidationError("Commerce invoice date range is invalid", "to");
  }
  return {
    tenantId: normalizeCommerceTenantId(input.tenantId),
    ...page,
    ...(input.id === undefined ? {} : { id: assertCommerceId(input.id, "invoice") }),
    ...(input.subscriptionId === undefined
      ? {}
      : { subscriptionId: assertCommerceId(input.subscriptionId, "subscription", "subscriptionId") }),
    ...(input.planId === undefined
      ? {}
      : { planId: assertCommerceId(input.planId, "plan", "planId") }),
    ...(input.status === undefined
      ? {}
      : { status: normalizeCommerceStatus(input.status, INVOICE_STATUSES, "status") }),
    ...(periodStart === undefined ? {} : { periodStart }),
    ...(periodEnd === undefined ? {} : { periodEnd }),
    ...(from === undefined ? {} : { from }),
    ...(to === undefined ? {} : { to }),
  };
}

export function normalizeInvoiceDisputeQuery(
  value: InvoiceDisputeQuery,
): InvoiceDisputeQuery {
  const input = value ?? ({} as InvoiceDisputeQuery);
  assertCommerceQueryKeys(input, [
    "tenantId",
    "invoiceId",
    "actorId",
    "status",
    "from",
    "to",
    "cursor",
    "limit",
    "pageSize",
  ]);
  const page = normalizeCommercePageQuery(input);
  const from = input.from === undefined
    ? undefined
    : normalizeCommerceTimestamp(input.from, "from");
  const to = input.to === undefined
    ? undefined
    : normalizeCommerceTimestamp(input.to, "to");
  if (from !== undefined && to !== undefined && Date.parse(from) > Date.parse(to)) {
    throw commerceValidationError("Commerce invoice dispute date range is invalid", "to");
  }
  return {
    tenantId: normalizeCommerceTenantId(input.tenantId),
    ...page,
    ...(input.invoiceId === undefined
      ? {}
      : { invoiceId: assertCommerceId(input.invoiceId, "invoice", "invoiceId") }),
    ...(input.actorId === undefined
      ? {}
      : { actorId: requireCommerceIdentifier(input.actorId, "actorId") }),
    ...(input.status === undefined
      ? {}
      : {
          status: normalizeCommerceStatus(
            input.status,
            INVOICE_DISPUTE_STATUSES,
            "status",
          ),
        }),
    ...(from === undefined ? {} : { from }),
    ...(to === undefined ? {} : { to }),
  };
}

export function normalizeMainlandChinaInvoiceMetadata(
  value: unknown,
  taxRateBps: unknown,
): MainlandChinaInvoiceMetadata {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw commerceValidationError("Mainland China invoice metadata is invalid", "mainlandChina");
  }
  const record = value as Record<string, unknown>;
  const normalizedTaxRate = normalizeInteger(taxRateBps, "taxRateBps", 0, 10_000);
  if (
    record.invoiceType !== "vatSpecial" &&
    record.invoiceType !== "vatNormal" &&
    record.invoiceType !== "electronic"
  ) {
    throw commerceValidationError("Invoice type is invalid", "invoiceType");
  }
  if (record.issueMode !== "platform" && record.issueMode !== "selfIssued") {
    throw commerceValidationError("Invoice issue mode is invalid", "issueMode");
  }
  if (record.taxRateBps !== normalizedTaxRate) {
    throw commerceValidationError(
      "Invoice metadata tax rate must match the invoice tax rate",
      "taxRateBps",
    );
  }
  const unifiedSocialCreditCode = record.unifiedSocialCreditCode === undefined
    ? undefined
    : normalizeUnifiedSocialCreditCode(record.unifiedSocialCreditCode);
  const buyerPhone = record.buyerPhone === undefined
    ? undefined
    : normalizeMainlandPhone(record.buyerPhone);
  const buyerBankAccount = record.buyerBankAccount === undefined
    ? undefined
    : normalizeBankAccount(record.buyerBankAccount);
  const invoiceCode = record.invoiceCode === undefined
    ? undefined
    : normalizeInvoiceDigits(record.invoiceCode, "invoiceCode", 8, 12);
  const invoiceNumber = record.invoiceNumber === undefined
    ? undefined
    : normalizeInvoiceDigits(record.invoiceNumber, "invoiceNumber", 8, 8);
  return {
    invoiceType: record.invoiceType,
    buyerName: requireCommerceText(record.buyerName, "buyerName", 200),
    ...(unifiedSocialCreditCode === undefined ? {} : { unifiedSocialCreditCode }),
    ...(record.buyerAddress === undefined
      ? {}
      : { buyerAddress: requireCommerceText(record.buyerAddress, "buyerAddress", 500) }),
    ...(buyerPhone === undefined ? {} : { buyerPhone }),
    ...(record.buyerBankName === undefined
      ? {}
      : { buyerBankName: requireCommerceText(record.buyerBankName, "buyerBankName", 200) }),
    ...(buyerBankAccount === undefined ? {} : { buyerBankAccount }),
    taxRateBps: normalizedTaxRate,
    issueMode: record.issueMode,
    ...(invoiceCode === undefined ? {} : { invoiceCode }),
    ...(invoiceNumber === undefined ? {} : { invoiceNumber }),
  };
}

export function requireCommerceExternalReference(
  value: unknown,
  prefix: string,
  field: string,
): string {
  if (typeof value !== "string") {
    throw commerceValidationError("External commerce reference is invalid", field);
  }
  const normalized = value.trim();
  if (
    !normalized.startsWith(`${prefix}_`) ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
      normalized.slice(prefix.length + 1),
    )
  ) {
    throw commerceValidationError("External commerce reference is invalid", field);
  }
  return normalized;
}

function assertCommerceQueryKeys(
  value: object,
  allowed: readonly string[],
): void {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) {
      throw commerceValidationError("Commerce query parameter is invalid", key);
    }
  }
}

function normalizeCommerceSearch(
  search: unknown,
  q: unknown,
): string | undefined {
  if (search === undefined && q === undefined) return undefined;
  const normalizedSearch = requireCommerceText(search ?? q, "search", 200);
  if (q !== undefined && requireCommerceText(q, "q", 200) !== normalizedSearch) {
    throw commerceValidationError("Commerce search aliases do not match", "q");
  }
  return normalizedSearch;
}

function normalizeCommerceStatus(
  value: unknown,
  allowed: readonly string[],
  field: string,
): string {
  if (typeof value !== "string" || !allowed.includes(value)) {
    throw commerceValidationError("Commerce status filter is invalid", field);
  }
  return value;
}

function normalizeUnifiedSocialCreditCode(value: unknown): string {
  const normalized = requireCommerceCode(value, "unifiedSocialCreditCode").toUpperCase();
  if (!/^[0-9A-Z]{18}$/u.test(normalized)) {
    throw commerceValidationError("Unified social credit code is invalid", "unifiedSocialCreditCode");
  }
  return normalized;
}

function normalizeMainlandPhone(value: unknown): string {
  if (typeof value !== "string") {
    throw commerceValidationError("Mainland China invoice phone is invalid", "buyerPhone");
  }
  const normalized = value.trim();
  if (!/^\+?[0-9()-]{6,32}$/u.test(normalized)) {
    throw commerceValidationError("Mainland China invoice phone is invalid", "buyerPhone");
  }
  return normalized;
}

function normalizeBankAccount(value: unknown): string {
  if (typeof value !== "string") {
    throw commerceValidationError("Mainland China invoice bank account is invalid", "buyerBankAccount");
  }
  const normalized = value.trim();
  if (!/^[0-9]{8,32}$/u.test(normalized)) {
    throw commerceValidationError("Mainland China invoice bank account is invalid", "buyerBankAccount");
  }
  return normalized;
}

function normalizeInvoiceDigits(
  value: unknown,
  field: string,
  minimum: number,
  maximum: number,
): string {
  if (typeof value !== "string" || !new RegExp(`^[0-9]{${minimum},${maximum}}$`, "u").test(value.trim())) {
    throw commerceValidationError("Mainland China invoice number is invalid", field);
  }
  return value.trim();
}

export function normalizeDecimal(
  value: unknown,
  field: string,
  allowZero = true,
): DecimalString {
  return assertDecimalString(value, field, allowZero);
}

export function normalizeMoney(
  value: unknown,
  field: string,
  allowZero = true,
): Money {
  const normalized = assertMoney(value, field, allowZero);
  return { amountMinor: normalized.amountMinor, currency: normalized.currency };
}

export function normalizeDimensions(
  value: unknown,
  expectedKeys?: readonly string[],
): Readonly<Record<string, string>> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value)
  ) {
    throw commerceValidationError("Commerce dimensions are invalid", "dimensions");
  }
  const entries = Object.entries(value as Record<string, unknown>)
    .map(([key, entry]) => [
      requireCommerceIdentifier(key, "dimensions"),
      requireCommerceIdentifier(entry, `dimensions.${key}`),
    ] as const)
    .sort(([left], [right]) => left.localeCompare(right));
  const normalized = Object.fromEntries(entries);
  if (
    expectedKeys !== undefined &&
    !sameStringSet(Object.keys(normalized), expectedKeys)
  ) {
    throw commerceValidationError(
      "Commerce dimensions do not match the meter definition",
      "dimensions",
    );
  }
  return normalized;
}

export function sameStringSet(
  left: readonly string[],
  right: readonly string[],
): boolean {
  const normalizedLeft = [...new Set(left)].sort();
  const normalizedRight = [...new Set(right)].sort();
  return (
    normalizedLeft.length === normalizedRight.length &&
    normalizedLeft.every((value, index) => value === normalizedRight[index])
  );
}

export function normalizeInteger(
  value: unknown,
  field: string,
  minimum = 0,
  maximum = Number.MAX_SAFE_INTEGER,
): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    throw commerceValidationError("Commerce integer is invalid", field);
  }
  return value;
}

export function normalizeDecimalForHash(value: DecimalString): DecimalString {
  return normalizeDecimalString(assertDecimalString(value));
}

export function hashCommerceRequest(value: unknown): string {
  return createHash("sha256")
    .update(stableSerialize(value))
    .digest("hex");
}

export function cloneCommerceValue<T>(value: T): T {
  return structuredClone(value);
}

function stableSerialize(value: unknown): string {
  const ancestors = new Set<object>();
  const serialize = (current: unknown): string => {
    if (current === null) return "null";
    if (typeof current === "string") return JSON.stringify(current);
    if (typeof current === "boolean") return current ? "true" : "false";
    if (typeof current === "number") {
      if (!Number.isFinite(current)) {
        throw commerceValidationError("Commerce request is invalid");
      }
      return JSON.stringify(current);
    }
    if (current instanceof Date) return JSON.stringify(current.toISOString());
    if (typeof current !== "object") {
      throw commerceValidationError("Commerce request is invalid");
    }
    if (ancestors.has(current)) {
      throw commerceValidationError("Commerce request is invalid");
    }
    ancestors.add(current);
    try {
      if (Array.isArray(current)) {
        return `[${current.map((item) => serialize(item)).join(",")}]`;
      }
      const entries = Object.entries(current as Record<string, unknown>)
        .filter(([, item]) => item !== undefined)
        .sort(([left], [right]) => left.localeCompare(right));
      return `{${entries
        .map(([key, item]) => `${JSON.stringify(key)}:${serialize(item)}`)
        .join(",")}}`;
    } finally {
      ancestors.delete(current);
    }
  };
  return serialize(value);
}
