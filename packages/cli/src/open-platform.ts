import {
  OPEN_PLATFORM_DOMAIN_EVENT_TYPES,
  OPEN_PLATFORM_DOMAIN_EVENT_STATUSES,
  createOpenPlatformClient,
  type OpenPlatformClientOptions,
  type OpenPlatformFetch,
} from "@getbrick/idaas-open-platform-sdk";
import {
  EXIT_ENVIRONMENT,
  EXIT_FAILURE,
  EXIT_USAGE,
  type OperationIO,
} from "./ops.js";

export interface OpenPlatformIO {
  openPlatformClient?: unknown;
  openPlatformClientFactory?: (options: OpenPlatformClientOptions) => unknown;
  openPlatformFetch?: OpenPlatformFetch;
}

export type OpenPlatformCommand =
  | "app:list"
  | "app:get"
  | "app:publish"
  | "catalog:list"
  | "credential:list"
  | "credential:rotate"
  | "credential:revoke"
  | "usage:list"
  | "subscription:list"
  | "webhook:list"
  | "webhook:test"
  | "audit:list"
  | "marketplace:list"
  | "marketplace:get"
  | "billing:invoices"
  | "billing:invoice"
  | "billing:disputes:list"
  | "billing:disputes:get"
  | "billing:disputes:review"
  | "billing:disputes:decide"
  | "billing:disputes:withdraw"
  | "compliance:data-assets"
  | "compliance:privacy-requests"
  | "compliance:report"
  | "events:list"
  | "events:retry";

export type OpenPlatformParseResult<T> =
  | { ok: true; value: T }
  | { ok: false; error: string };

export interface OpenPlatformCommonArgs {
  baseUrl?: string;
  tenant?: string;
  json: boolean;
}

export interface OpenPlatformListArgs extends OpenPlatformCommonArgs {
  query: Record<string, string | number>;
}

export interface OpenPlatformIdArgs extends OpenPlatformCommonArgs {
  id: string;
}

export interface OpenPlatformWebhookTestArgs extends OpenPlatformCommonArgs {
  id: string;
  eventId: string;
  eventType: string;
}

export interface OpenPlatformComplianceRecordArgs extends OpenPlatformCommonArgs {
  id?: string;
  query: Record<string, string | number>;
}

export interface OpenPlatformPrivacyRequestArgs extends OpenPlatformCommonArgs {
  id?: string;
  sla: boolean;
  query: Record<string, string | number>;
}

export interface OpenPlatformComplianceReportArgs extends OpenPlatformCommonArgs {
  generate: boolean;
  idempotencyKey?: string;
  query: Record<string, string | number>;
}

export interface OpenPlatformDomainEventRetryArgs extends OpenPlatformCommonArgs {
  idempotencyKey?: string;
  query: Record<string, string | number>;
}

export interface OpenPlatformInvoiceDisputeArgs extends OpenPlatformCommonArgs {
  disputeId?: string;
  invoiceId?: string;
  outcome?: string;
  reference?: string;
  note?: string;
  idempotencyKey?: string;
  query: Record<string, string | number>;
}

export type OpenPlatformArgs =
  | OpenPlatformListArgs
  | OpenPlatformIdArgs
  | OpenPlatformInvoiceDisputeArgs
  | OpenPlatformWebhookTestArgs
  | OpenPlatformComplianceRecordArgs
  | OpenPlatformPrivacyRequestArgs
  | OpenPlatformComplianceReportArgs
  | OpenPlatformDomainEventRetryArgs;

const OPEN_PLATFORM_COMMANDS = new Set<OpenPlatformCommand>([
  "app:list",
  "app:get",
  "app:publish",
  "catalog:list",
  "credential:list",
  "credential:rotate",
  "credential:revoke",
  "usage:list",
  "subscription:list",
  "webhook:list",
  "webhook:test",
  "audit:list",
  "marketplace:list",
  "marketplace:get",
  "billing:invoices",
  "billing:invoice",
  "billing:disputes:list",
  "billing:disputes:get",
  "billing:disputes:review",
  "billing:disputes:decide",
  "billing:disputes:withdraw",
  "compliance:data-assets",
  "compliance:privacy-requests",
  "compliance:report",
  "events:list",
  "events:retry",
]);

const BASE_URL_ENV = [
  "OPEN_PLATFORM_BASE_URL",
  "OPEN_PLATFORM_API_URL",
  "OPEN_PLATFORM_API_BASE_URL",
  "IDAAS_OPEN_PLATFORM_BASE_URL",
  "IDAAS_OPEN_PLATFORM_URL",
  "GETBRICK_OPEN_PLATFORM_BASE_URL",
];

const TENANT_ENV = [
  "OPEN_PLATFORM_TENANT_ID",
  "OPEN_PLATFORM_TENANT",
  "IDAAS_OPEN_PLATFORM_TENANT_ID",
  "IDAAS_OPEN_PLATFORM_TENANT",
  "IDAAS_TENANT_ID",
  "GETBRICK_OPEN_PLATFORM_TENANT_ID",
];

const TOKEN_ENV = [
  "OPEN_PLATFORM_TOKEN",
  "OPEN_PLATFORM_ACCESS_TOKEN",
  "OPEN_PLATFORM_API_TOKEN",
  "OPEN_PLATFORM_BEARER_TOKEN",
  "IDAAS_OPEN_PLATFORM_TOKEN",
  "IDAAS_OPEN_PLATFORM_ACCESS_TOKEN",
  "IDAAS_OPEN_PLATFORM_API_TOKEN",
  "GETBRICK_OPEN_PLATFORM_TOKEN",
  "GETBRICK_OPEN_PLATFORM_ACCESS_TOKEN",
];

const OPTION_ALIASES = new Map<string, string>([
  ["base-url", "baseUrl"],
  ["baseurl", "baseUrl"],
  ["api-url", "baseUrl"],
  ["tenant", "tenant"],
  ["tenant-id", "tenant"],
  ["json", "json"],
  ["limit", "limit"],
  ["page-size", "pageSize"],
  ["cursor", "cursor"],
  ["search", "search"],
  ["status", "status"],
  ["sort", "sort"],
  ["id", "id"],
  ["organization-id", "organizationId"],
  ["application-id", "applicationId"],
  ["application", "applicationId"],
  ["app-id", "applicationId"],
  ["app", "applicationId"],
  ["environment-id", "environmentId"],
  ["subscription-id", "subscriptionId"],
  ["subscription", "subscriptionId"],
  ["credential-id", "credentialId"],
  ["credential", "credentialId"],
  ["from", "from"],
  ["to", "to"],
  ["product-id", "productId"],
  ["product", "productId"],
  ["api-product-id", "productId"],
  ["api-version-id", "apiVersionId"],
  ["api-version", "apiVersionId"],
  ["q", "search"],
  ["webhook-id", "webhookId"],
  ["webhook", "webhookId"],
  ["listing-id", "listingId"],
  ["listing", "listingId"],
  ["invoice-id", "invoiceId"],
  ["invoice", "invoiceId"],
  ["dispute-id", "disputeId"],
  ["dispute", "disputeId"],
  ["reference", "reference"],
  ["note", "note"],
  ["resolution-note", "note"],
  ["event-id", "eventId"],
  ["event-type", "eventType"],
  ["event", "eventType"],
  ["type", "eventType"],
  ["partner-account-id", "partnerAccountId"],
  ["partner", "partnerAccountId"],
  ["partner-code", "partnerCode"],
  ["plan-id", "planId"],
  ["period-start", "periodStart"],
  ["period-end", "periodEnd"],
  ["action", "action"],
  ["outcome", "outcome"],
  ["target-id", "targetId"],
  ["idempotency-key", "idempotencyKey"],
  ["resource-type", "resourceType"],
  ["resource-id", "resourceId"],
  ["sequence", "sequence"],
  ["generate", "generate"],
  ["sla", "sla"],
  ["at", "at"],
]);

const BOOLEAN_OPTIONS = new Set(["json", "generate", "sla"]);

const SAFE_DOMAIN_EVENT_TYPES = new Set<string>(OPEN_PLATFORM_DOMAIN_EVENT_TYPES);

const SAFE_DOMAIN_EVENT_STATUSES = new Set<string>(OPEN_PLATFORM_DOMAIN_EVENT_STATUSES);

const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;

const OPEN_PLATFORM_USAGE =
  "Usage: getbrick open-platform <app:list|app:get|app:publish|catalog:list|credential:list|credential:rotate|credential:revoke|usage:list|subscription:list|webhook:list|webhook:test|audit:list|marketplace:list|marketplace:get|billing:invoices|billing:invoice|billing:disputes:list|billing:disputes:get|billing:disputes:review|billing:disputes:decide|billing:disputes:withdraw|compliance:data-assets|compliance:privacy-requests|compliance:report|events:list|events:retry> [options]";

const OPEN_PLATFORM_COMMAND_USAGE: Record<OpenPlatformCommand, string> = {
  "app:list": "Usage: getbrick open-platform app:list [--base-url <url>] [--tenant <id>] [--json]",
  "app:get": "Usage: getbrick open-platform app:get <application-id> [--base-url <url>] [--tenant <id>] [--json]",
  "app:publish": "Usage: getbrick open-platform app:publish <application-id> [--base-url <url>] [--tenant <id>] [--json]",
  "catalog:list": "Usage: getbrick open-platform catalog:list [--base-url <url>] [--tenant <id>] [--json]",
  "credential:list": "Usage: getbrick open-platform credential:list [--base-url <url>] [--tenant <id>] [--json]",
  "credential:rotate": "Usage: getbrick open-platform credential:rotate <credential-id> [--base-url <url>] [--tenant <id>] [--json]",
  "credential:revoke": "Usage: getbrick open-platform credential:revoke <credential-id> [--base-url <url>] [--tenant <id>] [--json]",
  "usage:list": "Usage: getbrick open-platform usage:list [--base-url <url>] [--tenant <id>] [--json]",
  "subscription:list": "Usage: getbrick open-platform subscription:list [--base-url <url>] [--tenant <id>] [--json]",
  "webhook:list": "Usage: getbrick open-platform webhook:list [--base-url <url>] [--tenant <id>] [--json]",
  "webhook:test": "Usage: getbrick open-platform webhook:test <webhook-id> --event-id <event-id> --event-type <event-type> [--base-url <url>] [--tenant <id>] [--json]",
  "audit:list": "Usage: getbrick open-platform audit:list [--base-url <url>] [--tenant <id>] [--json]",
  "marketplace:list": "Usage: getbrick open-platform marketplace:list [--base-url <url>] [--tenant <id>] [--json]",
  "marketplace:get": "Usage: getbrick open-platform marketplace:get <listing-id> [--base-url <url>] [--tenant <id>] [--json]",
  "billing:invoices": "Usage: getbrick open-platform billing:invoices [--base-url <url>] [--tenant <id>] [--json]",
  "billing:invoice": "Usage: getbrick open-platform billing:invoice <invoice-id> [--base-url <url>] [--tenant <id>] [--json]",
  "billing:disputes:list": "Usage: getbrick open-platform billing:disputes:list <invoice-id> [--status <status>] [--limit <n>] [--cursor <cursor>] [--base-url <url>] [--tenant <id>] [--json]",
  "billing:disputes:get": "Usage: getbrick open-platform billing:disputes:get <dispute-id> [--base-url <url>] [--tenant <id>] [--json]",
  "billing:disputes:review": "Usage: getbrick open-platform billing:disputes:review <dispute-id> --invoice-id <invoice-id> [--idempotency-key <key>] [--base-url <url>] [--tenant <id>] [--json]",
  "billing:disputes:decide": "Usage: getbrick open-platform billing:disputes:decide <dispute-id> --invoice-id <invoice-id> --outcome <accepted|rejected|withdrawn> --reference <reference> [--note <note>] [--idempotency-key <key>] [--base-url <url>] [--tenant <id>] [--json]",
  "billing:disputes:withdraw": "Usage: getbrick open-platform billing:disputes:withdraw <dispute-id> --invoice-id <invoice-id> --reference <reference> [--note <note>] [--idempotency-key <key>] [--base-url <url>] [--tenant <id>] [--json]",
  "compliance:data-assets": "Usage: getbrick open-platform compliance:data-assets [--id <data-asset-id>] [--status <status>] [--limit <n>] [--cursor <cursor>] [--base-url <url>] [--tenant <id>] [--json]",
  "compliance:privacy-requests": "Usage: getbrick open-platform compliance:privacy-requests [--id <privacy-request-id>] [--sla] [--status <status>] [--limit <n>] [--cursor <cursor>] [--base-url <url>] [--tenant <id>] [--json]",
  "compliance:report": "Usage: getbrick open-platform compliance:report [--from <timestamp>] [--to <timestamp>] [--generate] [--idempotency-key <key>] [--base-url <url>] [--tenant <id>] [--json]",
  "events:list": "Usage: getbrick open-platform events:list [--event-type <event-type>] [--status <status>] [--resource-type <type>] [--resource-id <id>] [--sequence <n>] [--limit <n>] [--base-url <url>] [--tenant <id>] [--json]",
  "events:retry": "Usage: getbrick open-platform events:retry [--event-type <event-type>] [--limit <n>] [--idempotency-key <key>] [--base-url <url>] [--tenant <id>] [--json]",
};

const FALLBACK_METHODS: Record<string, string> = {
  "applications.list": "listApplications",
  "applications.get": "getApplication",
  "applications.publish": "publishApplication",
  "apiProducts.list": "listApiProducts",
  "credentials.list": "listCredentials",
  "credentials.rotate": "rotateCredential",
  "credentials.revoke": "revokeCredential",
  "usage.list": "listUsage",
  "subscriptions.list": "listSubscriptions",
  "webhooks.list": "listWebhooks",
  "webhooks.test": "testWebhook",
  "auditEvents.list": "listAuditEvents",
  "marketplace.list": "listMarketplaceListings",
  "marketplace.get": "getMarketplaceListing",
  "partners.list": "listPartners",
  "partners.get": "getPartner",
  "commissionRules.list": "listCommissionRules",
  "commissionRules.get": "getCommissionRule",
  "billing.accounts.list": "listBillingAccounts",
  "billing.accounts.get": "getBillingAccount",
  "billing.invoices.list": "listInvoices",
  "billing.invoices.get": "getInvoice",
  "billing.invoices.dispute": "disputeInvoice",
  "billing.disputes.list": "listInvoiceDisputes",
  "billing.disputes.get": "getInvoiceDispute",
  "billing.disputes.startReview": "startInvoiceDisputeReview",
  "billing.disputes.decide": "decideInvoiceDispute",
  "billing.disputes.withdraw": "withdrawInvoiceDispute",
  "compliance.dataAssets.list": "listDataAssets",
  "compliance.dataAssets.get": "getDataAsset",
  "compliance.consents.list": "listConsents",
  "compliance.consents.get": "getConsentRecord",
  "compliance.privacyRequests.list": "listPrivacyRequests",
  "compliance.privacyRequests.get": "getPrivacyRequest",
  "compliance.privacyRequests.getSla": "getPrivacyRequestSla",
  "compliance.retentionPolicies.list": "listRetentionPolicies",
  "compliance.retentionExecutions.list": "listRetentionExecutions",
  "compliance.crossBorderAssessments.list": "listCrossBorderAssessments",
  "compliance.vendors.list": "listVendors",
  "compliance.vendors.get": "getVendor",
  "compliance.report.get": "getComplianceReport",
  "compliance.report.generate": "generateComplianceReport",
  "domainEvents.list": "listDomainEvents",
  "domainEvents.retry": "retryDomainEvents",
};

const RESOURCE_ALIASES: Record<string, readonly string[]> = {
  apiProducts: ["products"],
  webhooks: ["webhook"],
  auditEvents: ["audit"],
  marketplace: ["marketplaceListings"],
  invoices: ["billing.invoices"],
  disputes: ["billing.disputes", "billing.invoiceDisputes"],
  domainEvents: ["events"],
  compliance: ["complianceCatalog"],
};

interface ResolvedConfig {
  baseUrl: string;
  tenant: string;
  token: string;
}

interface ConfigResult {
  ok: boolean;
  value?: ResolvedConfig;
  missing: string[];
}

interface ExtractedSecret {
  found: boolean;
  value?: string;
}

interface SafeError {
  code: string;
  status: number;
  retryable: boolean;
  message: string;
}

type UnknownFunction = (this: unknown, ...args: unknown[]) => unknown;

export function parseOpenPlatformArgs(
  args: string[],
  command?: string,
): OpenPlatformParseResult<OpenPlatformArgs>;
export function parseOpenPlatformArgs(
  command: string,
  args: string[],
): OpenPlatformParseResult<OpenPlatformArgs>;
export function parseOpenPlatformArgs(
  first: string[] | string,
  second: string | string[] | undefined,
): OpenPlatformParseResult<OpenPlatformArgs> {
  const args = Array.isArray(first) ? first : typeof second === "object" ? second : [];
  const command = Array.isArray(first) ? typeof second === "string" ? second : undefined : first;
  if (command === undefined) return { ok: false, error: "a command is required" };
  if (!OPEN_PLATFORM_COMMANDS.has(command as OpenPlatformCommand)) {
    return { ok: false, error: "unknown open-platform command" };
  }

  const typedCommand = command as OpenPlatformCommand;
  const allowed = allowedOptions(typedCommand);
  const values = new Map<string, string | boolean>();
  const positionals: string[] = [];
  let endOfOptions = false;

  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (!endOfOptions && argument === "--") {
      endOfOptions = true;
      continue;
    }

    if (!endOfOptions && argument.startsWith("-")) {
      const separator = argument.indexOf("=");
      const rawName = separator === -1 ? argument : argument.slice(0, separator);
      const canonical = OPTION_ALIASES.get(rawName.slice(2));
      if (canonical === undefined) return { ok: false, error: "unknown argument" };
      if (!allowed.has(canonical)) return { ok: false, error: "unknown argument" };
      if (values.has(canonical)) {
        return { ok: false, error: `${displayOption(canonical)} may only be specified once` };
      }

      if (BOOLEAN_OPTIONS.has(canonical)) {
        if (separator === -1) {
          values.set(canonical, true);
          continue;
        }
        const value = argument.slice(separator + 1);
        if (value === "true") {
          values.set(canonical, true);
          continue;
        }
        if (value === "false") {
          values.set(canonical, false);
          continue;
        }
        return { ok: false, error: `${displayOption(canonical)} requires true or false` };
      }

      let value: string;
      if (separator === -1) {
        const next = args[index + 1];
        if (next === undefined || next === "--" || next.startsWith("-")) {
          return { ok: false, error: `${displayOption(canonical)} requires a value` };
        }
        value = next;
        index += 1;
      } else {
        value = argument.slice(separator + 1);
      }
      if (value.length === 0 || /[\u0000-\u001f\u007f]/u.test(value)) {
        return { ok: false, error: `${displayOption(canonical)} requires a value` };
      }
      values.set(canonical, value);
      continue;
    }

    positionals.push(argument);
  }

  const common: OpenPlatformCommonArgs = {
    ...(typeof values.get("baseUrl") === "string" ? { baseUrl: String(values.get("baseUrl")) } : {}),
    ...(typeof values.get("tenant") === "string" ? { tenant: String(values.get("tenant")) } : {}),
    json: values.get("json") === true,
  };

  if (typedCommand === "webhook:test") {
    const optionId = singleOptionValue(values, ["id", "webhookId"]);
    const optionEventId = singleOptionValue(values, ["eventId"]);
    const optionEventType = singleOptionValue(values, ["eventType"]);
    if (positionals.length > (optionId === undefined ? 3 : 2)) return { ok: false, error: "unexpected argument" };
    const positionalId = optionId === undefined ? positionals[0] : undefined;
    const eventPositionals = optionId === undefined ? positionals.slice(1) : positionals;
    const second = eventPositionals[0];
    const third = eventPositionals[1];
    const positionalEventType = second !== undefined && SAFE_DOMAIN_EVENT_TYPES.has(second)
      ? second
      : third !== undefined && SAFE_DOMAIN_EVENT_TYPES.has(third)
        ? third
        : undefined;
    const positionalEventId = second !== undefined && second !== positionalEventType
      ? second
      : third !== undefined && third !== positionalEventType
        ? third
        : undefined;
    if (optionId !== undefined && positionalId !== undefined) return { ok: false, error: "use either a positional webhook id or --webhook-id, not both" };
    if (optionEventId !== undefined && positionalEventId !== undefined) return { ok: false, error: "use either a positional event id or --event-id, not both" };
    if (optionEventType !== undefined && positionalEventType !== undefined) return { ok: false, error: "use either a positional event type or --event-type, not both" };
    const id = optionId ?? positionalId;
    const eventId = optionEventId ?? positionalEventId;
    const eventType = optionEventType ?? positionalEventType;
    if (id === undefined || !isSafeIdentifier(id)) return { ok: false, error: "webhook id is required" };
    if (eventId === undefined || !isSafeWebhookEventId(eventId)) return { ok: false, error: "event id is required" };
    if (eventType === undefined || !SAFE_DOMAIN_EVENT_TYPES.has(eventType)) return { ok: false, error: "event type is invalid" };
    return { ok: true, value: { ...common, id, eventId, eventType } };
  }

  if (typedCommand === "compliance:data-assets" || typedCommand === "compliance:privacy-requests") {
    return parseComplianceRecordArgs(typedCommand, values, positionals, common);
  }

  if (typedCommand === "compliance:report") {
    return parseComplianceReportArgs(values, positionals, common);
  }

  if (typedCommand === "events:list") {
    return parseDomainEventListArgs(values, positionals, common);
  }

  if (typedCommand === "events:retry") {
    return parseDomainEventRetryArgs(values, positionals, common);
  }

  if (typedCommand.startsWith("billing:disputes:")) {
    return parseInvoiceDisputeArgs(typedCommand, values, positionals, common);
  }

  if (isIdCommand(typedCommand)) {
    const idValues = idOptionNames(typedCommand)
      .map((name) => values.get(name))
      .filter((value): value is string => typeof value === "string");
    if (idValues.length > 1) {
      return { ok: false, error: "id may only be specified once" };
    }
    if (idValues.length > 0 && positionals.length > 0) {
      return { ok: false, error: "use either a positional id or --id, not both" };
    }
    if (positionals.length > 1) return { ok: false, error: "unexpected argument" };
    const id = idValues[0] ?? positionals[0];
    if (id === undefined || !isSafeIdentifier(id)) {
      return { ok: false, error: `${idLabel(typedCommand)} is required` };
    }
    return { ok: true, value: { ...common, id } };
  }

  if (positionals.length > 0) return { ok: false, error: "unexpected argument" };
  if (values.has("limit") && values.has("pageSize")) {
    return { ok: false, error: "pagination limit may only be specified once" };
  }

  const query: Record<string, string | number> = {};
  for (const [key, rawValue] of values) {
    if (key === "baseUrl" || key === "tenant" || key === "json") continue;
    if (typeof rawValue !== "string") continue;
    const value = normalizeQueryValue(key, rawValue);
    if (value === undefined) return { ok: false, error: `${displayOption(key)} has an invalid value` };
    const queryKey = key === "listingId" || key === "invoiceId" || key === "webhookId" ? "id" : key;
    if (queryKey === "id" && query.id !== undefined) return { ok: false, error: "id may only be specified once" };
    query[queryKey] = value;
  }
  return { ok: true, value: { ...common, query } };
}

export function parseOpenPlatformCommandArgs(
  command: string,
  args: string[],
): OpenPlatformParseResult<OpenPlatformArgs> {
  return parseOpenPlatformArgs(args, command);
}

function parseComplianceRecordArgs(
  command: "compliance:data-assets" | "compliance:privacy-requests",
  values: Map<string, string | boolean>,
  positionals: readonly string[],
  common: OpenPlatformCommonArgs,
): OpenPlatformParseResult<OpenPlatformArgs> {
  if (positionals.length > 1) return { ok: false, error: "unexpected argument" };
  const optionId = singleOptionValue(values, ["id"]);
  if (optionId !== undefined && positionals.length > 0) {
    return { ok: false, error: "use either a positional id or --id, not both" };
  }
  const id = optionId ?? positionals[0];
  if (id !== undefined && !isSafeIdentifier(id)) {
    return { ok: false, error: `${idLabel(command)} is invalid` };
  }
  if (values.has("limit") && values.has("pageSize")) {
    return { ok: false, error: "pagination limit may only be specified once" };
  }
  const sla = values.get("sla") === true;
  if (id !== undefined) {
    for (const key of ["status", "cursor", "limit", "pageSize"] as const) {
      if (values.has(key)) {
        return { ok: false, error: `${displayOption(key)} is not valid with --id` };
      }
    }
    if (sla && command !== "compliance:privacy-requests") {
      return { ok: false, error: "--sla is only valid for compliance:privacy-requests" };
    }
    if (values.has("at") && !sla) {
      return { ok: false, error: "--at requires --sla" };
    }
    const at = values.get("at");
    if (sla && typeof at === "string") {
      const value = normalizeQueryValue("at", at);
      if (value === undefined) return { ok: false, error: "--at has an invalid value" };
      return {
        ok: true,
        value: { ...common, id, sla: true, query: { at: value } },
      };
    }
    return {
      ok: true,
      value: {
        ...common,
        id,
        ...(sla ? { sla: true } : {}),
        query: {},
      },
    };
  }
  if (sla) return { ok: false, error: "--sla requires a privacy request id" };
  if (values.has("at")) return { ok: false, error: "--at requires --sla" };
  const allowed = allowedOptions(command);
  const query: Record<string, string | number> = {};
  for (const key of ["status", "cursor", "limit", "pageSize"] as const) {
    if (!allowed.has(key) || !values.has(key)) continue;
    const raw = values.get(key);
    if (typeof raw !== "string") continue;
    const value = normalizeQueryValue(key, raw);
    if (value === undefined) return { ok: false, error: `${displayOption(key)} has an invalid value` };
    query[key === "pageSize" ? "limit" : key] = value;
  }
  return { ok: true, value: { ...common, query } };
}

function parseComplianceReportArgs(
  values: Map<string, string | boolean>,
  positionals: readonly string[],
  common: OpenPlatformCommonArgs,
): OpenPlatformParseResult<OpenPlatformArgs> {
  if (positionals.length > 0) return { ok: false, error: "unexpected argument" };
  const idempotencyKey = parseIdempotencyKeyOption(values);
  if (idempotencyKey.error !== undefined) return { ok: false, error: idempotencyKey.error };
  const query: Record<string, string | number> = {};
  for (const key of ["from", "to"] as const) {
    const raw = values.get(key);
    if (typeof raw !== "string") continue;
    const value = normalizeQueryValue(key, raw);
    if (value === undefined) return { ok: false, error: `${displayOption(key)} has an invalid value` };
    query[key] = value;
  }
  const generate = values.get("generate") === true;
  if (idempotencyKey.value !== undefined && !generate) {
    return { ok: false, error: "--idempotency-key is only valid with --generate" };
  }
  return {
    ok: true,
    value: {
      ...common,
      generate,
      ...(idempotencyKey.value === undefined ? {} : { idempotencyKey: idempotencyKey.value }),
      query,
    },
  };
}

function parseDomainEventListArgs(
  values: Map<string, string | boolean>,
  positionals: readonly string[],
  common: OpenPlatformCommonArgs,
): OpenPlatformParseResult<OpenPlatformArgs> {
  if (positionals.length > 0) return { ok: false, error: "unexpected argument" };
  if (values.has("limit") && values.has("pageSize")) {
    return { ok: false, error: "pagination limit may only be specified once" };
  }
  const eventType = values.get("eventType");
  if (typeof eventType === "string" && !SAFE_DOMAIN_EVENT_TYPES.has(eventType)) {
    return { ok: false, error: "event type is invalid" };
  }
  const status = values.get("status");
  if (typeof status === "string" && !SAFE_DOMAIN_EVENT_STATUSES.has(status)) {
    return { ok: false, error: "domain event status is invalid" };
  }
  const query: Record<string, string | number> = {};
  for (const key of [
    "eventType",
    "status",
    "resourceType",
    "resourceId",
    "sequence",
    "cursor",
    "limit",
    "pageSize",
  ] as const) {
    const raw = values.get(key);
    if (typeof raw !== "string") continue;
    const value = normalizeQueryValue(key, raw);
    if (value === undefined) return { ok: false, error: `${displayOption(key)} has an invalid value` };
    query[key === "pageSize" ? "limit" : key] = value;
  }
  if (query.cursor !== undefined && query.sequence !== undefined) {
    return { ok: false, error: "use either --cursor or --sequence, not both" };
  }
  return { ok: true, value: { ...common, query } };
}

function parseDomainEventRetryArgs(
  values: Map<string, string | boolean>,
  positionals: readonly string[],
  common: OpenPlatformCommonArgs,
): OpenPlatformParseResult<OpenPlatformArgs> {
  if (positionals.length > 0) return { ok: false, error: "unexpected argument" };
  const idempotencyKey = parseIdempotencyKeyOption(values);
  if (idempotencyKey.error !== undefined) return { ok: false, error: idempotencyKey.error };
  const eventType = values.get("eventType");
  if (typeof eventType === "string" && !SAFE_DOMAIN_EVENT_TYPES.has(eventType)) {
    return { ok: false, error: "event type is invalid" };
  }
  const query: Record<string, string | number> = {};
  const limit = values.get("limit");
  if (typeof limit === "string") {
    const value = normalizeQueryValue("limit", limit);
    if (value === undefined) return { ok: false, error: "--limit has an invalid value" };
    query.limit = value;
  }
  return {
    ok: true,
    value: {
      ...common,
      ...(typeof eventType === "string" ? { query: { eventType, ...query } } : { query }),
      ...(idempotencyKey.value === undefined ? {} : { idempotencyKey: idempotencyKey.value }),
    },
  };
}

const INVOICE_DISPUTE_OUTCOMES = new Set(["accepted", "rejected", "withdrawn"]);

const INVOICE_DISPUTE_STATUSES = new Set([
  "open",
  "underReview",
  "accepted",
  "rejected",
  "withdrawn",
]);

function parseInvoiceDisputeArgs(
  command: OpenPlatformCommand,
  values: Map<string, string | boolean>,
  positionals: readonly string[],
  common: OpenPlatformCommonArgs,
): OpenPlatformParseResult<OpenPlatformArgs> {
  if (positionals.length > 1) return { ok: false, error: "unexpected argument" };
  const idempotencyKey = parseIdempotencyKeyOption(values);
  if (idempotencyKey.error !== undefined) return { ok: false, error: idempotencyKey.error };
  const optionDisputeId = singleOptionValue(values, ["id", "disputeId"]);
  const optionInvoiceId = singleOptionValue(values, ["invoiceId"]);
  if (optionDisputeId !== undefined && positionals.length > 0) {
    return { ok: false, error: "use either a positional id or --id, not both" };
  }
  const positionalId = positionals[0];
  if (positionalId !== undefined && !isSafeIdentifier(positionalId)) {
    return { ok: false, error: "invoice dispute id is invalid" };
  }
  if (optionInvoiceId !== undefined && !isSafeIdentifier(optionInvoiceId)) {
    return { ok: false, error: "--invoice-id is invalid" };
  }
  if (command === "billing:disputes:list") {
    if (values.has("limit") && values.has("pageSize")) {
      return { ok: false, error: "pagination limit may only be specified once" };
    }
    if (optionDisputeId !== undefined) {
      return { ok: false, error: "--dispute-id is not valid for a dispute list" };
    }
    if (optionInvoiceId !== undefined && positionalId !== undefined) {
      return { ok: false, error: "use either a positional invoice id or --invoice-id, not both" };
    }
    const invoiceId = optionInvoiceId ?? positionalId;
    if (invoiceId === undefined) {
      return { ok: false, error: "invoice id is required" };
    }
    const status = values.get("status");
    if (typeof status === "string" && !INVOICE_DISPUTE_STATUSES.has(status)) {
      return { ok: false, error: "--status has an invalid value" };
    }
    const query: Record<string, string | number> = {};
    for (const key of ["status", "from", "to", "cursor", "limit", "pageSize"] as const) {
      const raw = values.get(key);
      if (typeof raw !== "string") continue;
      const value = normalizeQueryValue(key, raw);
      if (value === undefined) {
        return { ok: false, error: `${displayOption(key)} has an invalid value` };
      }
      query[key === "pageSize" ? "limit" : key] = value;
    }
    return { ok: true, value: { ...common, invoiceId, query } };
  }
  const disputeId = optionDisputeId ?? positionalId;
  if (disputeId === undefined) {
    return { ok: false, error: "invoice dispute id is required" };
  }
  if (command === "billing:disputes:get") {
    if (optionInvoiceId !== undefined) {
      return { ok: false, error: "--invoice-id is not valid for a dispute read" };
    }
    return { ok: true, value: { ...common, disputeId, query: {} } };
  }
  if (optionInvoiceId === undefined) {
    return { ok: false, error: "invoice id is required" };
  }
  const outcome = values.get("outcome");
  if (command === "billing:disputes:decide") {
    if (typeof outcome !== "string" || !INVOICE_DISPUTE_OUTCOMES.has(outcome)) {
      return { ok: false, error: "--outcome is invalid" };
    }
  } else if (outcome !== undefined) {
    return { ok: false, error: "--outcome is only valid for a dispute decision" };
  }
  const rawReference = values.get("reference");
  if (command === "billing:disputes:review") {
    if (rawReference !== undefined) {
      return { ok: false, error: "--reference is only valid for a dispute decision or withdrawal" };
    }
  } else if (typeof rawReference !== "string") {
    return { ok: false, error: "--reference is required" };
  } else if (normalizeQueryValue("reference", rawReference) === undefined) {
    return { ok: false, error: "--reference has an invalid value" };
  }
  const reference = typeof rawReference === "string" ? rawReference : undefined;
  const rawNote = values.get("note");
  const note = typeof rawNote === "string"
    ? normalizeQueryValue("note", rawNote)
    : undefined;
  if (rawNote !== undefined && note === undefined) {
    return { ok: false, error: "--note has an invalid value" };
  }
  return {
    ok: true,
    value: {
      ...common,
      disputeId,
      invoiceId: optionInvoiceId,
      ...(typeof outcome === "string" ? { outcome } : {}),
      ...(typeof reference === "string" ? { reference } : {}),
      ...(typeof note === "string" ? { note } : {}),
      ...(idempotencyKey.value === undefined
        ? {}
        : { idempotencyKey: idempotencyKey.value }),
      query: {},
    },
  };
}

function omitInvoiceDisputeRouteFields(
  input: Record<string, unknown>,
): Record<string, unknown> {
  const { invoiceId: _invoiceId, ...rest } = input;
  return Object.fromEntries(
    Object.entries(rest).filter(([, value]) => value !== undefined),
  );
}

function parseIdempotencyKeyOption(
  values: Map<string, string | boolean>,
): { value?: string; error?: string } {
  const raw = values.get("idempotencyKey");
  if (typeof raw !== "string") return {};
  if (!IDEMPOTENCY_KEY_PATTERN.test(raw) || /(?:secret|password|authorization|cookie|bearer)/iu.test(raw)) {
    return { error: "--idempotency-key has an invalid value" };
  }
  return { value: raw };
}

export async function runOpenPlatform(
  command: string | undefined,
  args: string[],
  io: OperationIO & OpenPlatformIO,
): Promise<number> {
  const routed = routeOpenPlatformArgs(command, args);
  const actualCommand = routed.command;
  const actualArgs = routed.args;
  const parsed = parseOpenPlatformArgs(actualArgs, actualCommand);
  if (!parsed.ok) {
    const json = wantsJson(actualArgs, actualCommand);
    emitUsageError(io, actualCommand, parsed.error, json);
    return actualCommand !== undefined && OPEN_PLATFORM_COMMANDS.has(actualCommand as OpenPlatformCommand)
      ? EXIT_USAGE
      : EXIT_FAILURE;
  }

  const config = resolveConfig(parsed.value, io);
  if (!config.ok || config.value === undefined) {
    emitEnvironmentError(io, config.missing, wantsJson(actualArgs, actualCommand));
    return EXIT_ENVIRONMENT;
  }

  let client: unknown;
  try {
    client = await resolveClient(config.value, io);
    const result = await dispatchOpenPlatformCommand(actualCommand as OpenPlatformCommand, client, parsed.value);
    emitSuccess(io, result, parsed.value.json, actualCommand === "credential:rotate", config.value.token);
    return 0;
  } catch (error) {
    emitOpenPlatformError(io, error, parsed.value.json);
    return EXIT_FAILURE;
  }
}

function routeOpenPlatformArgs(
  command: string | undefined,
  args: string[],
): { command: string | undefined; args: string[] } {
  if (command !== undefined && !command.startsWith("-")) {
    return { command, args };
  }
  const tokens = command === undefined ? args : [command, ...args];
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (OPEN_PLATFORM_COMMANDS.has(token as OpenPlatformCommand)) {
      return {
        command: token,
        args: [...tokens.slice(0, index), ...tokens.slice(index + 1)],
      };
    }
    if (token === "--") break;
    if (!token.startsWith("--")) continue;
    const separator = token.indexOf("=");
    const canonical = OPTION_ALIASES.get((separator === -1 ? token : token.slice(0, separator)).slice(2));
    if (canonical !== undefined && !BOOLEAN_OPTIONS.has(canonical) && separator === -1) index += 1;
  }
  return { command, args };
}

function allowedOptions(command: OpenPlatformCommand): ReadonlySet<string> {
  const common = ["baseUrl", "tenant", "json"];
  const list = ["limit", "pageSize", "cursor", "search", "status", "sort", "id"];
  const page = ["limit", "pageSize", "cursor"];
  if (command === "app:list") return new Set([...common, ...list, "organizationId"]);
  if (command === "catalog:list") return new Set([...common, ...list, "applicationId"]);
  if (command === "credential:list") return new Set([...common, ...list, "applicationId", "environmentId"]);
  if (command === "usage:list") return new Set([...common, ...list, "subscriptionId", "credentialId", "from", "to"]);
  if (command === "subscription:list") return new Set([...common, ...list, "applicationId", "productId", "apiVersionId"]);
  if (command === "webhook:list") return new Set([...common, ...page, "id", "webhookId", "status", "applicationId", "environmentId"]);
  if (command === "audit:list") return new Set([...common, ...page, "action", "outcome", "targetId"]);
  if (command === "marketplace:list") return new Set([...common, ...page, "id", "listingId", "status", "search", "partnerAccountId", "productId"]);
  if (command === "billing:invoices") return new Set([...common, ...page, "id", "invoiceId", "subscriptionId", "planId", "status", "periodStart", "periodEnd", "from", "to"]);
  if (command === "app:get" || command === "app:publish") {
    return new Set([...common, "id", "applicationId"]);
  }
  if (command === "marketplace:get") return new Set([...common, "id", "listingId"]);
  if (command === "billing:invoice") return new Set([...common, "id", "invoiceId"]);
  if (command === "billing:disputes:list") {
    return new Set([...common, ...page, "status", "invoiceId", "disputeId"]);
  }
  if (command === "billing:disputes:get") {
    return new Set([...common, "id", "disputeId", "invoiceId"]);
  }
  if (command === "billing:disputes:review") {
    return new Set([...common, "id", "disputeId", "invoiceId", "idempotencyKey"]);
  }
  if (command === "billing:disputes:decide" || command === "billing:disputes:withdraw") {
    return new Set([
      ...common,
      "id",
      "disputeId",
      "invoiceId",
      "outcome",
      "reference",
      "note",
      "idempotencyKey",
    ]);
  }
  if (command === "webhook:test") return new Set([...common, "id", "webhookId", "eventId", "eventType"]);
  if (command === "compliance:data-assets") return new Set([...common, ...page, "id", "status"]);
  if (command === "compliance:privacy-requests") return new Set([...common, ...page, "id", "status", "sla", "at"]);
  if (command === "compliance:report") return new Set([...common, "from", "to", "generate", "idempotencyKey"]);
  if (command === "events:list") {
    return new Set([...common, ...page, "eventType", "status", "resourceType", "resourceId", "sequence"]);
  }
  if (command === "events:retry") {
    return new Set([...common, "eventType", "limit", "idempotencyKey"]);
  }
  return new Set([...common, "id", "credentialId"]);
}

function idOptionNames(command: OpenPlatformCommand): string[] {
  if (command === "app:get" || command === "app:publish") return ["id", "applicationId"];
  if (command === "credential:rotate" || command === "credential:revoke") return ["id", "credentialId"];
  if (command === "marketplace:get") return ["id", "listingId"];
  if (command === "billing:invoice") return ["id", "invoiceId"];
  if (command === "webhook:test") return ["id", "webhookId"];
  return ["id"];
}

function isIdCommand(command: OpenPlatformCommand): boolean {
  return command === "app:get" ||
    command === "app:publish" ||
    command === "credential:rotate" ||
    command === "credential:revoke" ||
    command === "marketplace:get" ||
    command === "billing:invoice" ||
    command === "webhook:test";
}

function idLabel(command: OpenPlatformCommand): string {
  if (command === "app:get" || command === "app:publish") return "application id";
  if (command === "credential:rotate" || command === "credential:revoke") return "credential id";
  if (command === "marketplace:get") return "listing id";
  if (command === "billing:invoice") return "invoice id";
  if (command === "webhook:test") return "webhook id";
  if (command === "compliance:data-assets") return "data asset id";
  if (command === "compliance:privacy-requests") return "privacy request id";
  return "id";
}

function displayOption(option: string): string {
  const names: Record<string, string> = {
    baseUrl: "--base-url",
    tenant: "--tenant",
    json: "--json",
    limit: "--limit",
    pageSize: "--page-size",
    cursor: "--cursor",
    search: "--search",
    status: "--status",
    sort: "--sort",
    id: "--id",
    organizationId: "--organization-id",
    applicationId: "--application-id",
    environmentId: "--environment-id",
    subscriptionId: "--subscription-id",
    credentialId: "--credential-id",
    from: "--from",
    to: "--to",
    productId: "--product-id",
    apiVersionId: "--api-version-id",
    webhookId: "--webhook-id",
    listingId: "--listing-id",
    invoiceId: "--invoice-id",
    disputeId: "--dispute-id",
    reference: "--reference",
    note: "--note",
    eventId: "--event-id",
    eventType: "--event-type",
    partnerAccountId: "--partner-account-id",
    partnerCode: "--partner-code",
    planId: "--plan-id",
    periodStart: "--period-start",
    periodEnd: "--period-end",
    action: "--action",
    outcome: "--outcome",
    targetId: "--target-id",
    idempotencyKey: "--idempotency-key",
    resourceType: "--resource-type",
    resourceId: "--resource-id",
    sequence: "--sequence",
    generate: "--generate",
    sla: "--sla",
    at: "--at",
  };
  return names[option] ?? `--${option}`;
}

function normalizeQueryValue(key: string, value: string): string | number | undefined {
  if (key === "limit" || key === "pageSize") {
    if (!/^[1-9][0-9]{0,2}$/u.test(value) || Number(value) > 100) return undefined;
    return Number(value);
  }
  if (key === "cursor") {
    return value.length > 0 && value.length <= 2048 && !/[\s\u0000-\u001f\u007f]/u.test(value)
      ? value
      : undefined;
  }
  if (key === "sequence") {
    return /^(?:0|[1-9][0-9]*)$/u.test(value) && Number(value) <= Number.MAX_SAFE_INTEGER
      ? Number(value)
      : undefined;
  }
  if (
    key === "id" ||
    key === "organizationId" ||
    key === "applicationId" ||
    key === "environmentId" ||
    key === "subscriptionId" ||
    key === "credentialId" ||
    key === "productId" ||
    key === "apiVersionId" ||
    key === "listingId" ||
    key === "invoiceId" ||
    key === "disputeId" ||
    key === "reference" ||
    key === "webhookId" ||
    key === "eventId" ||
    key === "partnerAccountId" ||
    key === "partnerCode" ||
    key === "planId" ||
    key === "action" ||
    key === "outcome" ||
    key === "targetId" ||
    key === "resourceId" ||
    key === "resourceType"
  ) {
    return isSafeIdentifier(value) ? value : undefined;
  }
  if (key === "eventType") {
    return SAFE_DOMAIN_EVENT_TYPES.has(value) ? value : undefined;
  }
  if (key === "note") {
    return value.length <= 500 && !/[\u0000-\u001f\u007f]/u.test(value)
      ? value
      : undefined;
  }
  if (/[\u0000-\u001f\u007f]/u.test(value)) return undefined;
  return value;
}

function isSafeIdentifier(value: string): boolean {
  return value.length > 0 &&
    value.length <= 512 &&
    !/[\s\u0000-\u001f\u007f]/u.test(value) &&
    !/(?:secret|password|private[-_]?key|authorization|cookie|bearer|vault:\/\/)/iu.test(value);
}

function isSafeWebhookEventId(value: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value) &&
    !/(?:secret|password|private[-_]?key|authorization|cookie|bearer|vault:\/\/)/iu.test(value);
}

function singleOptionValue(
  values: Map<string, string | boolean>,
  names: readonly string[],
): string | undefined {
  const found = names
    .map((name) => values.get(name))
    .filter((value): value is string => typeof value === "string");
  return found.length === 1 ? found[0] : undefined;
}

function resolveConfig(parsed: OpenPlatformArgs, io: OperationIO): ConfigResult {
  const env = io.env ?? process.env;
  const baseUrl = parsed.baseUrl ?? readEnvironment(env, BASE_URL_ENV);
  const tenant = parsed.tenant ?? readEnvironment(env, TENANT_ENV);
  const token = readEnvironment(env, TOKEN_ENV);
  const missing: string[] = [];
  if (baseUrl === undefined) missing.push("OPEN_PLATFORM_BASE_URL");
  if (tenant === undefined) missing.push("OPEN_PLATFORM_TENANT_ID");
  if (token === undefined) missing.push("OPEN_PLATFORM_TOKEN");
  if (missing.length > 0 || baseUrl === undefined || tenant === undefined || token === undefined) {
    return { ok: false, missing };
  }
  return { ok: true, value: { baseUrl, tenant, token }, missing: [] };
}

function readEnvironment(env: NodeJS.ProcessEnv, names: readonly string[]): string | undefined {
  for (const name of names) {
    const value = env[name];
    if (typeof value === "string" && value.trim().length > 0) return value.trim();
  }
  return undefined;
}

async function resolveClient(config: ResolvedConfig, io: OpenPlatformIO): Promise<unknown> {
  const options: OpenPlatformClientOptions = {
    baseUrl: config.baseUrl,
    tenantId: config.tenant,
    tokenProvider: config.token,
    retry: false,
    ...(io.openPlatformFetch === undefined ? {} : { fetch: io.openPlatformFetch }),
  };
  if (io.openPlatformClientFactory !== undefined) return io.openPlatformClientFactory(options);
  if (typeof io.openPlatformClient === "function") {
    const factory = io.openPlatformClient as (value: OpenPlatformClientOptions) => unknown;
    return factory(options);
  }
  if (io.openPlatformClient !== undefined) return io.openPlatformClient;
  return createOpenPlatformClient(options);
}

async function dispatchOpenPlatformCommand(
  command: OpenPlatformCommand,
  client: unknown,
  parsed: OpenPlatformArgs,
): Promise<unknown> {
  if (command === "app:list") return invokeResource(client, "applications.list", [queryOf(parsed)]);
  if (command === "app:get") return invokeResource(client, "applications.get", [idOf(parsed)]);
  if (command === "app:publish") return invokeResource(client, "applications.publish", [idOf(parsed)]);
  if (command === "catalog:list") return invokeResource(client, "apiProducts.list", [queryOf(parsed)]);
  if (command === "credential:list") return invokeResource(client, "credentials.list", [queryOf(parsed)]);
  if (command === "credential:rotate") return invokeResource(client, "credentials.rotate", [idOf(parsed)]);
  if (command === "credential:revoke") return invokeResource(client, "credentials.revoke", [idOf(parsed)]);
  if (command === "usage:list") return invokeResource(client, "usage.list", [queryOf(parsed)]);
  if (command === "subscription:list") return invokeResource(client, "subscriptions.list", [queryOf(parsed)]);
  if (command === "webhook:list") return invokeResource(client, "webhooks.list", [queryOf(parsed)]);
  if (command === "webhook:test") {
    if (!("eventId" in parsed) || !("eventType" in parsed)) throw new Error("open platform webhook test arguments are invalid");
    return invokeResource(client, "webhooks.test", [parsed.id, { eventId: parsed.eventId, eventType: parsed.eventType }]);
  }
  if (command === "audit:list") return invokeResource(client, "auditEvents.list", [queryOf(parsed)]);
  if (command === "marketplace:list") return invokeResource(client, "marketplace.list", [queryOf(parsed)]);
  if (command === "marketplace:get") return invokeResource(client, "marketplace.get", [idOf(parsed)]);
  if (command === "billing:invoices") return invokeResource(client, "invoices.list", [queryOf(parsed)]);
  if (command === "billing:invoice") return invokeResource(client, "invoices.get", [idOf(parsed)]);
  if (command === "billing:disputes:list") {
    if (!("invoiceId" in parsed) || parsed.invoiceId === undefined) {
      throw new Error("open platform invoice dispute arguments are invalid");
    }
    return invokeResource(client, "billing.disputes.list", [
      parsed.invoiceId,
      queryOf(parsed),
    ]);
  }
  if (command === "billing:disputes:get") {
    if (!("disputeId" in parsed) || parsed.disputeId === undefined) {
      throw new Error("open platform invoice dispute arguments are invalid");
    }
    return invokeResource(client, "billing.disputes.get", [parsed.disputeId]);
  }
  if (
    command === "billing:disputes:review" ||
    command === "billing:disputes:decide" ||
    command === "billing:disputes:withdraw"
  ) {
    if (!("disputeId" in parsed) || !("invoiceId" in parsed)) {
      throw new Error("open platform invoice dispute arguments are invalid");
    }
    if (parsed.disputeId === undefined || parsed.invoiceId === undefined) {
      throw new Error("open platform invoice dispute arguments are invalid");
    }
    const input = {
      invoiceId: parsed.invoiceId,
      ...(command === "billing:disputes:decide"
        ? { outcome: "outcome" in parsed ? parsed.outcome : undefined }
        : {}),
      ...("reference" in parsed ? { reference: parsed.reference } : {}),
      ...("note" in parsed ? { resolutionNote: parsed.note } : {}),
      ...("idempotencyKey" in parsed
        ? { idempotencyKey: parsed.idempotencyKey }
        : {}),
    };
    if (command === "billing:disputes:review") {
      return invokeResource(client, "billing.disputes.startReview", [
        input.invoiceId,
        parsed.disputeId,
        omitInvoiceDisputeRouteFields(input),
      ]);
    }
    if (command === "billing:disputes:decide") {
      return invokeResource(client, "billing.disputes.decide", [
        input.invoiceId,
        parsed.disputeId,
        omitInvoiceDisputeRouteFields(input),
      ]);
    }
    return invokeResource(client, "billing.disputes.withdraw", [
      input.invoiceId,
      parsed.disputeId,
      omitInvoiceDisputeRouteFields(input),
    ]);
  }
  if (command === "compliance:data-assets") {
    if (idOf(parsed) === "") return invokeResource(client, "compliance.dataAssets.list", [queryOf(parsed)]);
    return invokeResource(client, "compliance.dataAssets.get", [idOf(parsed)]);
  }
  if (command === "compliance:privacy-requests") {
    if (idOf(parsed) === "") return invokeResource(client, "compliance.privacyRequests.list", [queryOf(parsed)]);
    if ("sla" in parsed && parsed.sla) {
      return invokeResource(client, "compliance.privacyRequests.getSla", [idOf(parsed), queryOf(parsed)]);
    }
    return invokeResource(client, "compliance.privacyRequests.get", [idOf(parsed)]);
  }
  if (command === "compliance:report") {
    if ("generate" in parsed && parsed.generate) {
      const input = { ...queryOf(parsed), ...("idempotencyKey" in parsed && parsed.idempotencyKey !== undefined ? { idempotencyKey: parsed.idempotencyKey } : {}) };
      return invokeResource(client, "compliance.report.generate", [input]);
    }
    return invokeResource(client, "compliance.report.get", [queryOf(parsed)]);
  }
  if (command === "events:list") return invokeResource(client, "domainEvents.list", [queryOf(parsed)]);
  if (command === "events:retry") {
    const input = {
      ...queryOf(parsed),
      ...("idempotencyKey" in parsed && parsed.idempotencyKey !== undefined ? { idempotencyKey: parsed.idempotencyKey } : {}),
    };
    return invokeResource(client, "domainEvents.retry", [input]);
  }
  return invokeResource(client, "invoices.get", [idOf(parsed)]);
}

function queryOf(parsed: OpenPlatformArgs): Record<string, string | number> {
  return "query" in parsed ? parsed.query : {};
}

function idOf(parsed: OpenPlatformArgs): string {
  return "id" in parsed && typeof parsed.id === "string" ? parsed.id : "";
}

async function invokeResource(client: unknown, resourcePath: string, args: unknown[]): Promise<unknown> {
  if (!isRecord(client)) throw new Error("open platform client is invalid");
  const segments = resourcePath.split(".");
  const methodName = segments[segments.length - 1];
  for (const candidate of resolveResourceCandidates(client, segments)) {
    if (isRecord(candidate) && typeof candidate[methodName] === "function") {
      const method = candidate[methodName] as UnknownFunction;
      return method.apply(candidate, args);
    }
  }
  const fallbackName = FALLBACK_METHODS[resourcePath];
  if (fallbackName !== undefined && typeof client[fallbackName] === "function") {
    const method = client[fallbackName] as UnknownFunction;
    return method.apply(client, args);
  }
  throw new Error("open platform client method is unavailable");
}

function resolveResourceCandidates(
  client: Record<string, unknown>,
  segments: readonly string[],
): unknown[] {
  let current = resolveResourceRoots(client, segments[0]);
  for (const segment of segments.slice(1, -1)) {
    const next: unknown[] = [];
    for (const value of current) {
      if (!isRecord(value)) continue;
      const resolved = value[segment];
      if (resolved === undefined || next.includes(resolved)) continue;
      next.push(resolved);
    }
    current = next;
  }
  return current;
}

function resolveResourceRoots(
  client: Record<string, unknown>,
  head: string,
): unknown[] {
  const roots: unknown[] = [];
  for (const name of [head, ...(RESOURCE_ALIASES[head] ?? [])]) {
    let current: unknown = client;
    for (const path of name.split(".")) {
      current = isRecord(current) ? current[path] : undefined;
      if (current === undefined) break;
    }
    if (current !== undefined && !roots.includes(current)) roots.push(current);
  }
  return roots;
}

function wantsJson(args: string[], command?: string): boolean {
  return command === "--json" || command === "--json=true" || args.some((argument) => argument === "--json" || argument === "--json=true");
}

function emitUsageError(
  io: OperationIO,
  command: string | undefined,
  message: string,
  json: boolean,
): void {
  if (json) {
    io.log(jsonString({ error: { code: "USAGE", message } }));
    return;
  }
  const knownCommand = command !== undefined && OPEN_PLATFORM_COMMANDS.has(command as OpenPlatformCommand);
  io.log(`✗ open-platform${knownCommand ? ` ${command}` : ""}: ${message}`);
  io.log(command !== undefined && OPEN_PLATFORM_COMMANDS.has(command as OpenPlatformCommand)
    ? OPEN_PLATFORM_COMMAND_USAGE[command as OpenPlatformCommand]
    : OPEN_PLATFORM_USAGE);
}

function emitEnvironmentError(io: OperationIO, missing: string[], json: boolean): void {
  const message = `missing environment: ${missing.join(", ")}`;
  if (json) {
    io.log(jsonString({ error: { code: "ENVIRONMENT_ERROR", message } }));
    return;
  }
  io.log(`✗ open-platform: ${message}`);
}

function emitOpenPlatformError(io: OperationIO, error: unknown, json: boolean): void {
  const safe = safeError(error);
  if (json) {
    io.log(jsonString({ error: safe }));
    return;
  }
  io.log(`✗ open-platform: ${safe.message} (${safe.code})`);
}

function emitSuccess(
  io: OperationIO,
  value: unknown,
  json: boolean,
  revealCredential: boolean,
  token: string,
): void {
  const extracted = revealCredential ? extractSecret(value) : { found: false };
  const sensitiveValues = [token];
  if (extracted.found && extracted.value !== undefined) sensitiveValues.push(extracted.value);
  const safeValue = sanitizeOutput(value, sensitiveValues);
  const output = revealCredential && extracted.found && extracted.value !== undefined
    ? addSecret(safeValue, extracted.value)
    : safeValue;
  io.log(json ? jsonString(output) : humanOutput(output));
}

function safeError(error: unknown): SafeError {
  const record = isRecord(error) ? error : {};
  const rawCode = typeof record.code === "string" ? record.code : "";
  const code = safeCode(rawCode) ?? (typeof record.status === "number" ? `HTTP_${record.status}` : "OPEN_PLATFORM_ERROR");
  const status = typeof record.status === "number" && Number.isInteger(record.status) && record.status >= 100 && record.status <= 599
    ? record.status
    : 0;
  const retryable = record.retryable === true;
  return { code, status, retryable, message: safeErrorMessage(code, status) };
}

function safeCode(value: string): string | undefined {
  const normalized = value.trim().toUpperCase();
  if (!/^[A-Z][A-Z0-9_.:-]{0,127}$/u.test(normalized)) return undefined;
  if (/(?:SECRET|PASSWORD|AUTHORIZATION|COOKIE|PRIVATE|BEARER|TOKEN)/u.test(normalized)) return undefined;
  return normalized;
}

function safeErrorMessage(code: string, status: number): string {
  if (code === "NETWORK_ERROR") return "open platform network request failed";
  if (code === "TIMEOUT") return "open platform request timed out";
  if (code === "ABORTED" || code === "INVALID_RESPONSE") return "open platform request failed";
  if (status === 401 || code.includes("AUTH")) return "open platform authentication failed";
  if (status === 403 || code.includes("FORBIDDEN") || code.includes("TENANT_MISMATCH")) return "open platform access was denied";
  if (status === 404 || code.includes("NOT_FOUND")) return "open platform resource was not found";
  if (status === 429 || code.includes("RATE_LIMIT")) return "open platform request was rate limited";
  if (status >= 500) return "open platform service is temporarily unavailable";
  return "open platform request failed";
}

function extractSecret(value: unknown): ExtractedSecret {
  if (!isRecord(value)) return { found: false };
  if (!Object.prototype.hasOwnProperty.call(value, "secret")) return { found: false };
  const secret = value.secret;
  if (typeof secret === "string") return { found: true, value: secret };
  if (isRecord(secret) && typeof secret.value === "string") return { found: true, value: secret.value };
  return { found: true };
}

function addSecret(value: unknown, secret: string): unknown {
  if (isRecord(value)) return { ...value, secret };
  return { value, secret };
}

function sanitizeOutput(value: unknown, sensitiveValues: string[]): unknown {
  const values = [...new Set(sensitiveValues.filter((item) => typeof item === "string" && item.length > 0))];
  collectSensitiveValues(value, values);
  const seen = new WeakSet<object>();
  const visit = (current: unknown, key?: string): unknown => {
    if (key !== undefined && isSensitiveKey(key)) return undefined;
    if (typeof current === "string") return scrubString(current, values);
    if (current === null || typeof current !== "object") return current;
    if (seen.has(current)) return "[circular]";
    seen.add(current);
    if (Array.isArray(current)) return current.map((item) => visit(item));
    const output: Record<string, unknown> = {};
    for (const [entryKey, entryValue] of Object.entries(current)) {
      const sanitized = visit(entryValue, entryKey);
      if (sanitized !== undefined) output[entryKey] = sanitized;
    }
    return output;
  };
  return visit(value);
}

function collectSensitiveValues(value: unknown, values: string[], seen = new WeakSet<object>()): void {
  if (value === null || typeof value !== "object" || seen.has(value)) return;
  seen.add(value);
  if (Array.isArray(value)) {
    for (const item of value) collectSensitiveValues(item, values, seen);
    return;
  }
  for (const [key, entry] of Object.entries(value)) {
    if (isSensitiveKey(key) && typeof entry === "string" && entry.length > 0) values.push(entry);
    collectSensitiveValues(entry, values, seen);
  }
}

function isSensitiveKey(key: string): boolean {
  const normalized = key.replace(/[-_]/gu, "").toLowerCase();
  if (normalized === "auth" || normalized === "authorization" || normalized === "bearer" || normalized === "cookie" || normalized === "password" || normalized === "plaintext" || normalized === "privatekey" || normalized === "apikey" || normalized === "idempotencykey") return true;
  if (normalized.includes("authorization") || normalized.includes("idempotency") || normalized.includes("token") || normalized.includes("bearer") || normalized.includes("password") || normalized.includes("plaintext") || normalized.includes("privatekey")) return true;
  return normalized.includes("secret");
}

function scrubString(value: string, sensitiveValues: string[]): string {
  let result = value;
  for (const sensitive of sensitiveValues) {
    if (sensitive.length > 0) result = result.split(sensitive).join("[redacted]");
  }
  return result;
}

function humanOutput(value: unknown): string {
  const lines: string[] = [];
  appendHumanLines(value, "", lines, new WeakSet<object>());
  return lines.length === 0 ? "No output." : lines.join("\n");
}

function appendHumanLines(value: unknown, indent: string, lines: string[], seen: WeakSet<object>): void {
  if (value === null || typeof value !== "object") {
    lines.push(`${indent}${formatScalar(value)}`);
    return;
  }
  if (seen.has(value)) {
    lines.push(`${indent}[circular]`);
    return;
  }
  seen.add(value);
  if (Array.isArray(value)) {
    if (value.length === 0) {
      lines.push(`${indent}[]`);
      return;
    }
    for (const item of value) {
      if (item !== null && typeof item === "object") {
        lines.push(`${indent}-`);
        appendHumanLines(item, `${indent}  `, lines, seen);
      } else {
        lines.push(`${indent}- ${formatScalar(item)}`);
      }
    }
    return;
  }
  const entries = Object.entries(value);
  if (entries.length === 0) {
    lines.push(`${indent}{}`);
    return;
  }
  for (const [key, entry] of entries) {
    if (entry !== null && typeof entry === "object") {
      lines.push(`${indent}${key}:`);
      appendHumanLines(entry, `${indent}  `, lines, seen);
    } else {
      lines.push(`${indent}${key}: ${formatScalar(entry)}`);
    }
  }
}

function formatScalar(value: unknown): string {
  if (typeof value === "string") return value.replace(/[\u0000-\u001f\u007f]/gu, " ");
  if (value === undefined) return "";
  if (value === null) return "null";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function jsonString(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2) ?? "null";
  } catch {
    return "null";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
