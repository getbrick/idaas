import {
  OPEN_PLATFORM_DOMAIN_EVENTS,
  isOpenPlatformDomainEventName,
} from "@getbrick/idaas-contracts";
import { OpenPlatformProtocolError } from "./errors.js";
import type { OpenPlatformPage } from "./types.js";

export {
  OPEN_PLATFORM_DOMAIN_EVENT_CATALOG,
  OPEN_PLATFORM_DOMAIN_EVENT_RESOURCES,
  OPEN_PLATFORM_DOMAIN_EVENT_SCHEMA_VERSION,
  OPEN_PLATFORM_DOMAIN_EVENTS,
  OPEN_PLATFORM_WEBHOOK_EVENTS,
  isOpenPlatformDomainEventName,
  openPlatformDomainEventNameParts,
} from "@getbrick/idaas-contracts";
export type {
  OpenPlatformDomainEvent,
  OpenPlatformDomainEventAction,
  OpenPlatformDomainEventNameParts,
  OpenPlatformDomainEventResource,
} from "@getbrick/idaas-contracts";

export const OPEN_PLATFORM_DOMAIN_EVENTS_BASE_PATH = "/domain-events" as const;

export const OPEN_PLATFORM_DOMAIN_EVENT_TYPES = OPEN_PLATFORM_DOMAIN_EVENTS;

export type OpenPlatformDomainEventType = (typeof OPEN_PLATFORM_DOMAIN_EVENT_TYPES)[number];

export const OPEN_PLATFORM_SAFE_DOMAIN_EVENT_TYPES: readonly string[] =
  OPEN_PLATFORM_DOMAIN_EVENTS;

export const OPEN_PLATFORM_DOMAIN_EVENT_STATUSES = [
  "pending",
  "delivering",
  "published",
  "failed",
  "dead_lettered",
] as const;
export type OpenPlatformDomainEventStatus =
  (typeof OPEN_PLATFORM_DOMAIN_EVENT_STATUSES)[number];

export const OPEN_PLATFORM_DOMAIN_EVENTS_MAX_PAGE_SIZE = 100 as const;

export interface OpenPlatformDomainEventResourceSummary {
  readonly type: string;
  readonly id: string;
}

export interface OpenPlatformDomainEventSummary {
  readonly eventId: string;
  readonly tenantId: string;
  readonly type: string;
  readonly resource: OpenPlatformDomainEventResourceSummary;
  readonly status: string;
  readonly attempt: number;
  readonly occurredAt: string;
  readonly errorCode?: string;
  readonly nextAttemptAt?: string;
}

export interface OpenPlatformDomainEventPage extends OpenPlatformPage<OpenPlatformDomainEventSummary> {
  readonly tenantId: string;
  readonly nextSequence?: number;
}

export interface OpenPlatformDomainEventRetryResult {
  readonly eventId: string;
  readonly delivered: number;
  readonly deadLettered: boolean;
}

export interface OpenPlatformDomainEventRetryResultSummary {
  readonly tenantId: string;
  readonly flushed: number;
  readonly results: readonly OpenPlatformDomainEventRetryResult[];
  readonly replayed: boolean;
}

export interface OpenPlatformDomainEventListQuery {
  readonly cursor?: string;
  readonly limit?: number | string;
  readonly status?: OpenPlatformDomainEventStatus | string;
  readonly eventType?: OpenPlatformDomainEventType | string;
  readonly resourceType?: string;
  readonly resourceId?: string;
  readonly sequence?: number | string;
  readonly tenantId?: string;
}

export interface RetryOpenPlatformDomainEventInput {
  readonly eventType?: OpenPlatformDomainEventType | string;
  readonly limit?: number;
  readonly tenantId?: string;
  readonly idempotencyKey?: string;
}

export function isOpenPlatformDomainEventType(
  value: unknown,
): value is OpenPlatformDomainEventType {
  return isOpenPlatformDomainEventName(value);
}

export function isSafeOpenPlatformDomainEventType(value: unknown): boolean {
  return (
    typeof value === "string" &&
    (OPEN_PLATFORM_SAFE_DOMAIN_EVENT_TYPES as readonly string[]).includes(value)
  );
}

export function isOpenPlatformDomainEventStatusValue(
  value: unknown,
): value is OpenPlatformDomainEventStatus {
  return (
    typeof value === "string" &&
    (OPEN_PLATFORM_DOMAIN_EVENT_STATUSES as readonly string[]).includes(value)
  );
}

export function toOpenPlatformDomainEventSummary(
  value: unknown,
): OpenPlatformDomainEventSummary {
  if (!isRecord(value)) throw new OpenPlatformProtocolError();
  const resource = isRecord(value.resource) ? value.resource : {};
  const errorCode = optionalText(value.errorCode);
  const nextAttemptAt = optionalText(value.nextAttemptAt);
  return {
    eventId: safeText(value.eventId),
    tenantId: safeText(value.tenantId),
    type: safeText(value.type ?? value.eventType),
    resource: {
      type: safeText(resource.type),
      id: safeText(resource.id),
    },
    status: safeText(value.status),
    attempt: safeCount(value.attempt),
    occurredAt: safeText(value.occurredAt),
    ...(errorCode === undefined ? {} : { errorCode }),
    ...(nextAttemptAt === undefined ? {} : { nextAttemptAt }),
  };
}

export function normalizeOpenPlatformDomainEventPage(
  value: unknown,
): OpenPlatformDomainEventPage {
  const source = isRecord(value) && isRecord(value.data) && !Array.isArray(value.data)
    ? value.data
    : value;
  if (!isRecord(source) || !Array.isArray(source.items)) {
    throw new OpenPlatformProtocolError();
  }
  const nextSequence = safeSequence(source.nextSequence);
  const nextCursor = nextSequence === undefined ? undefined : String(nextSequence);
  return {
    tenantId: safeText(source.tenantId),
    items: source.items.map(toOpenPlatformDomainEventSummary),
    ...(nextCursor === undefined ? {} : { nextCursor }),
    ...(nextSequence === undefined ? {} : { nextSequence }),
    hasMore: source.hasMore === true || nextSequence !== undefined,
  };
}

export function normalizeOpenPlatformDomainEventRetry(
  value: unknown,
): OpenPlatformDomainEventRetryResultSummary {
  if (!isRecord(value)) throw new OpenPlatformProtocolError();
  const results = Array.isArray(value.results) ? value.results : [];
  return {
    tenantId: safeText(value.tenantId),
    flushed: safeCount(value.flushed ?? results.length),
    results: results.map(toOpenPlatformDomainEventRetryResult),
    replayed: value.replayed === true,
  };
}

export function toOpenPlatformDomainEventRetryResult(
  value: unknown,
): OpenPlatformDomainEventRetryResult {
  if (!isRecord(value)) throw new OpenPlatformProtocolError();
  return {
    eventId: safeText(value.eventId),
    delivered: safeCount(value.delivered),
    deadLettered: value.deadLettered === true,
  };
}

export type DomainEventType = OpenPlatformDomainEventType;
export type DomainEventStatus = OpenPlatformDomainEventStatus;
export type DomainEventSummary = OpenPlatformDomainEventSummary;
export type DomainEventPage = OpenPlatformDomainEventPage;
export type DomainEventListQuery = OpenPlatformDomainEventListQuery;
export type DomainEventRetryInput = RetryOpenPlatformDomainEventInput;
export type DomainEventRetryResult = OpenPlatformDomainEventRetryResult;
export type DomainEventRetryResultSummary = OpenPlatformDomainEventRetryResultSummary;

function safeText(value: unknown): string {
  const text = optionalText(value);
  return text ?? "unknown";
}

function optionalText(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  if (normalized.length < 1) return undefined;
  if (/[\u0000-\u001f\u007f]/u.test(normalized)) return undefined;
  return normalized.length > 128 ? normalized.slice(0, 128) : normalized;
}

function safeCount(value: unknown): number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0
    ? value
    : 0;
}

function safeSequence(value: unknown): number | undefined {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    return undefined;
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
