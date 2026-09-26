import { randomUUID } from "node:crypto";
import {
  OPEN_PLATFORM_DOMAIN_EVENT_CATALOG as OPEN_PLATFORM_CONTRACT_EVENT_CATALOG,
  OPEN_PLATFORM_DOMAIN_EVENT_RESOURCES as OPEN_PLATFORM_CONTRACT_EVENT_RESOURCES,
  OPEN_PLATFORM_DOMAIN_EVENT_SCHEMA_VERSION as OPEN_PLATFORM_CONTRACT_DOMAIN_EVENT_SCHEMA_VERSION,
  OPEN_PLATFORM_WEBHOOK_EVENTS,
  isOpenPlatformDomainEventName,
  openPlatformDomainEventNameParts,
  type OpenPlatformDomainEventResource as ContractDomainEventResource,
} from "@getbrick/idaas-contracts";
import {
  configurationError,
  isOpenPlatformDomainError,
  resourceNotFound,
  storageUnavailable,
  validationError,
} from "./errors.js";
import { OPEN_PLATFORM_LIFECYCLE_RESOURCE_KINDS } from "./types.js";
import { normalizeIdentifier, normalizeTenantKey } from "./validation.js";
import type {
  MaybePromise,
  OpenPlatformDependencyReadiness,
  OpenPlatformEntityKind,
  OpenPlatformLifecycleResourceKind,
  OpenPlatformLifecycleStatus,
} from "./types.js";

export const OPEN_PLATFORM_DOMAIN_EVENT_TYPES = OPEN_PLATFORM_WEBHOOK_EVENTS;

export type OpenPlatformDomainEventType =
  (typeof OPEN_PLATFORM_DOMAIN_EVENT_TYPES)[number];

export const OPEN_PLATFORM_DOMAIN_EVENT_CATALOG = OPEN_PLATFORM_CONTRACT_EVENT_CATALOG;

export const OPEN_PLATFORM_DOMAIN_EVENT_RESOURCES = OPEN_PLATFORM_CONTRACT_EVENT_RESOURCES;

export type OpenPlatformDomainEventResource = ContractDomainEventResource;

export const OPEN_PLATFORM_DOMAIN_EVENT_RESOURCE_KINDS: Readonly<
  Partial<Record<OpenPlatformDomainEventResource, OpenPlatformEntityKind>>
> = Object.freeze({
  tenant: "tenant",
  developer_organization: "developerOrganization",
  application: "application",
  client: "applicationEnvironment",
  credential: "credential",
  api_product: "apiProduct",
  api_version: "apiVersion",
  subscription: "subscription",
  scope_grant: "scopeGrant",
  usage: "usage",
});

export const OPEN_PLATFORM_DOMAIN_EVENT_SCHEMA_VERSION =
  OPEN_PLATFORM_CONTRACT_DOMAIN_EVENT_SCHEMA_VERSION;

export const OPEN_PLATFORM_DOMAIN_EVENT_OUTBOX_STATUSES = [
  "pending",
  "delivering",
  "published",
  "failed",
  "dead_lettered",
] as const;

export type OpenPlatformDomainEventStatus =
  (typeof OPEN_PLATFORM_DOMAIN_EVENT_OUTBOX_STATUSES)[number];

export const OPEN_PLATFORM_DOMAIN_EVENT_SYSTEM_ACTOR_ID =
  "open-platform-events" as const;

export const OPEN_PLATFORM_DOMAIN_EVENT_MAX_ATTEMPTS = 5;

export type OpenPlatformDomainEventValue =
  | string
  | number
  | boolean
  | null
  | readonly (string | number | boolean | null)[];

export type OpenPlatformDomainEventData = Readonly<
  Record<string, OpenPlatformDomainEventValue>
>;

export type OpenPlatformDomainEventAction =
  | "created"
  | "issued"
  | "rotated"
  | "revoked"
  | "published"
  | "disabled"
  | "archived"
  | "reviewed"
  | "threshold_reached";

export type OpenPlatformCrossDomainEntityKind =
  | "marketplaceListing"
  | "partnerAccount"
  | "commissionRule"
  | "invoice"
  | "invoiceDispute"
  | "dataAsset"
  | "consentRecord"
  | "privacyRequest"
  | "retentionPolicy"
  | "crossBorderAssessment"
  | "vendor";

export type OpenPlatformDomainEventResourceType =
  | OpenPlatformEntityKind
  | OpenPlatformCrossDomainEntityKind;

export const OPEN_PLATFORM_CROSS_DOMAIN_EVENT_RESOURCE_BINDINGS: Readonly<
  Partial<Record<OpenPlatformDomainEventResource, OpenPlatformCrossDomainEntityKind>>
> = Object.freeze({
  commerce_listing: "marketplaceListing",
  commerce_partner: "partnerAccount",
  commerce_commission: "commissionRule",
  commerce_account: "partnerAccount",
  commerce_invoice: "invoice",
  commerce_dispute: "invoiceDispute",
  compliance_data_asset: "dataAsset",
  compliance_consent_record: "consentRecord",
  compliance_privacy_request: "privacyRequest",
  compliance_retention_policy: "retentionPolicy",
  compliance_cross_border_assessment: "crossBorderAssessment",
  compliance_vendor: "vendor",
});

export interface OpenPlatformDomainEvent {
  readonly eventId: string;
  readonly tenantId: string;
  readonly eventType: OpenPlatformDomainEventType;
  readonly resourceType: OpenPlatformDomainEventResourceType;
  readonly resourceId: string;
  readonly resourceVersion?: number;
  readonly resourceStatus?: string;
  readonly actorId?: string;
  readonly requestId?: string;
  readonly occurredAt: string;
  readonly schemaVersion: string;
  readonly data: OpenPlatformDomainEventData;
}

export interface OpenPlatformOutboxRecord extends OpenPlatformDomainEvent {
  readonly status: OpenPlatformDomainEventStatus;
  readonly sequence: number;
  readonly attempt: number;
  readonly maxAttempts: number;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly nextAttemptAt?: string;
  readonly publishedAt?: string;
  readonly errorCode?: string;
  readonly leaseId?: string;
  readonly leaseExpiresAt?: string;
}

export type OpenPlatformDomainEventRecord = OpenPlatformOutboxRecord;

export interface OpenPlatformDomainEventInput {
  readonly eventId?: string;
  readonly tenantId: string;
  readonly eventType: OpenPlatformDomainEventType | string;
  readonly resourceType: OpenPlatformDomainEventResourceType;
  readonly resourceId: string;
  readonly resourceVersion?: number;
  readonly resourceStatus?: string;
  readonly actorId?: string;
  readonly requestId?: string;
  readonly occurredAt: string;
  readonly schemaVersion?: string;
  readonly data?: Readonly<Record<string, unknown>>;
}

export interface OpenPlatformOutboxQuery {
  readonly tenantId: string;
  readonly status?: OpenPlatformDomainEventStatus;
  readonly eventType?: OpenPlatformDomainEventType | string;
  readonly resourceType?: OpenPlatformDomainEventResourceType;
  readonly resourceId?: string;
  readonly fromSequence?: number;
  readonly limit?: number;
}

export interface OpenPlatformOutboxPage {
  readonly items: readonly OpenPlatformOutboxRecord[];
  readonly nextSequence?: number;
  readonly hasMore: boolean;
}

export interface OpenPlatformOutboxClaimRequest {
  readonly tenantId: string;
  readonly eventId: string;
  readonly attempt: number;
  readonly leaseId: string;
  readonly now: string;
  readonly leaseExpiresAt: string;
}

export interface OpenPlatformOutboxClaimResult {
  readonly claimed: boolean;
  readonly record?: OpenPlatformOutboxRecord;
}

export interface OpenPlatformOutboxCompleteRequest {
  readonly tenantId: string;
  readonly eventId: string;
  readonly now: string;
  readonly leaseId?: string;
}

export interface OpenPlatformOutboxFailRequest
  extends OpenPlatformOutboxCompleteRequest {
  readonly errorCode: string;
  readonly nextAttemptAt?: string;
  readonly deadLetter?: boolean;
}

export interface OpenPlatformOutboxPort {
  readonly productionReady?: boolean;
  readonly readiness?: OpenPlatformDependencyReadiness;
  isReady?(): MaybePromise<boolean>;
  append(event: OpenPlatformDomainEventInput): Promise<OpenPlatformOutboxRecord>;
  get(
    tenantId: string,
    eventId: string,
  ): Promise<OpenPlatformOutboxRecord | undefined>;
  list(query: OpenPlatformOutboxQuery): Promise<OpenPlatformOutboxPage>;
  claim?(
    request: OpenPlatformOutboxClaimRequest,
  ): Promise<OpenPlatformOutboxClaimResult>;
  complete?(
    request: OpenPlatformOutboxCompleteRequest,
  ): Promise<OpenPlatformOutboxRecord>;
  fail?(request: OpenPlatformOutboxFailRequest): Promise<OpenPlatformOutboxRecord>;
}

export const OPEN_PLATFORM_OUTBOX_TENANT_PAGE_LIMIT = 500;

export const OPEN_PLATFORM_OUTBOX_TENANT_CURSOR_LIMIT = 256;

export interface OpenPlatformOutboxTenantQuery {
  readonly limit: number;
  readonly cursor?: string;
  readonly signal?: AbortSignal;
}

export interface OpenPlatformOutboxTenantPage {
  readonly tenantIds: readonly string[];
  readonly cursor?: string;
  readonly hasMore?: boolean;
}

export interface OpenPlatformOutboxTenantResolver {
  listTenants(
    query: OpenPlatformOutboxTenantQuery,
  ): Promise<OpenPlatformOutboxTenantPage>;
}

export interface OpenPlatformOutboxTenantBatch {
  readonly tenantIds: readonly string[];
  readonly cursor?: string;
  readonly hasMore: boolean;
  readonly rejected: number;
}

export interface OpenPlatformEventSinkResult {
  readonly delivered: number;
  readonly deadLettered?: number;
}

export interface OpenPlatformEventSink {
  deliver(
    event: OpenPlatformOutboxRecord,
  ): MaybePromise<OpenPlatformEventSinkResult>;
}

export interface OpenPlatformEventPublishResult {
  readonly eventId: string;
  readonly delivered: number;
  readonly deadLettered: boolean;
}

export interface OpenPlatformEventPublisherPort {
  readonly productionReady?: boolean;
  readonly readiness?: OpenPlatformDependencyReadiness;
  isReady?(): MaybePromise<boolean>;
  record(
    event: OpenPlatformDomainEventInput,
  ): Promise<OpenPlatformOutboxRecord>;
  publish(
    event: OpenPlatformOutboxRecord,
  ): Promise<OpenPlatformEventPublishResult>;
  flush?(query: {
    readonly tenantId: string;
    readonly eventType?: string;
    readonly limit?: number;
  }): Promise<OpenPlatformEventPublishResult[]>;
}

export interface OpenPlatformEventPublisherOptions {
  readonly outbox: OpenPlatformOutboxPort;
  readonly sink?: OpenPlatformEventSink;
  readonly clock?: () => Date;
  readonly idGenerator?: () => string;
  readonly maxAttempts?: number;
  readonly leaseMs?: number;
}

export type OpenPlatformEventFlushStatus =
  | "published"
  | "failed"
  | "dead_lettered"
  | "skipped";

export interface OpenPlatformEventFlushOutcome {
  readonly eventId: string;
  readonly tenantId: string;
  readonly status: OpenPlatformEventFlushStatus;
  readonly delivered: number;
  readonly attempt: number;
  readonly maxAttempts: number;
  readonly retryScheduled: boolean;
  readonly errorCode?: string;
}

export interface OpenPlatformEventFlushResult {
  readonly tenantId: string;
  readonly outcomes: readonly OpenPlatformEventFlushOutcome[];
  readonly scanned: number;
  readonly deferred: number;
  readonly truncated: boolean;
}

export interface OpenPlatformEventFlushRequest {
  readonly publisher: OpenPlatformEventPublisherPort;
  readonly outbox: OpenPlatformOutboxPort;
  readonly tenantId: string;
  readonly limit?: number;
  readonly clock?: () => Date;
  readonly signal?: AbortSignal;
}

export interface OpenPlatformEventFlushFailure {
  readonly tenantId: string;
  readonly code: string;
  readonly message: string;
  readonly cause: unknown;
}

export interface OpenPlatformEventFlushTenantsResult {
  readonly tenants: readonly OpenPlatformEventFlushResult[];
  readonly failures: readonly OpenPlatformEventFlushFailure[];
  readonly rejected: number;
}

export interface OpenPlatformEventFlushTenantsRequest {
  readonly publisher: OpenPlatformEventPublisherPort;
  readonly outbox: OpenPlatformOutboxPort;
  readonly tenants?: OpenPlatformOutboxTenantBatch;
  readonly tenantIds?: readonly string[];
  readonly limit?: number;
  readonly clock?: () => Date;
  readonly signal?: AbortSignal;
}

export interface InMemoryOpenPlatformOutboxOptions {
  readonly clock?: () => Date;
  readonly idGenerator?: () => string;
  readonly production?: boolean;
  readonly maxAttempts?: number;
  readonly leaseMs?: number;
  readonly maxEventsPerTenant?: number;
  readonly retentionMs?: number;
}

export interface OpenPlatformDomainEventDescriptor {
  readonly eventType: OpenPlatformDomainEventType;
  readonly resourceType: OpenPlatformDomainEventResourceType;
  readonly resourceId: string;
  readonly resourceVersion?: number;
  readonly resourceStatus?: string;
  readonly data?: Readonly<Record<string, unknown>>;
}

export type OpenPlatformDomainEventFactory<T> = (
  result: T,
) => OpenPlatformDomainEventDescriptor | undefined;

const trustedEvents = new WeakSet<object>();

const DOMAIN_EVENT_RESOURCE_TYPES: readonly OpenPlatformDomainEventResourceType[] =
  Object.freeze([
    ...new Set<OpenPlatformDomainEventResourceType>([
      ...Object.values(OPEN_PLATFORM_DOMAIN_EVENT_RESOURCE_KINDS),
      ...Object.values(OPEN_PLATFORM_CROSS_DOMAIN_EVENT_RESOURCE_BINDINGS),
    ]),
    "webhook",
    "auditEvent",
  ]);

const FLUSH_SCAN_FACTOR = 4;

const SENSITIVE_EVENT_DATA_PATTERNS = [
  "secret",
  "password",
  "passwd",
  "token",
  "authorization",
  "privatekey",
  "apikey",
  "signature",
  "digest",
  "fingerprint",
  "cookie",
  "session",
  "credential",
  "email",
  "phone",
  "idcard",
  "passport",
  "address",
  "ssn",
  "iban",
  "cardnumber",
];

export function isOpenPlatformDomainEventRecord(
  value: unknown,
): value is OpenPlatformOutboxRecord {
  return value !== null && typeof value === "object" && trustedEvents.has(value);
}

export function brandOpenPlatformDomainEventRecord<
  T extends OpenPlatformOutboxRecord,
>(record: T): T {
  trustedEvents.add(record);
  return record;
}

export function isOpenPlatformDomainEventType(
  value: unknown,
): value is OpenPlatformDomainEventType {
  return isOpenPlatformDomainEventName(value);
}

export function toOpenPlatformDomainEventType(
  value: unknown,
): OpenPlatformDomainEventType {
  if (!isOpenPlatformDomainEventType(value)) {
    throw validationError("Open platform domain event type is invalid", {
      field: "eventType",
    });
  }
  return value;
}

export function isOpenPlatformDomainEventStatus(
  value: unknown,
): value is OpenPlatformDomainEventStatus {
  return (
    typeof value === "string" &&
    (OPEN_PLATFORM_DOMAIN_EVENT_OUTBOX_STATUSES as readonly string[]).includes(
      value,
    )
  );
}

export const OPEN_PLATFORM_LIFECYCLE_PUBLISHED_EVENT_TYPES: Readonly<
  Record<OpenPlatformLifecycleResourceKind, OpenPlatformDomainEventType>
> = Object.freeze({
  tenant: "tenant.status_changed",
  developerOrganization: "developer_organization.status_changed",
  application: "application.status_changed",
  applicationEnvironment: "client.status_changed",
  apiProduct: "api_product.published",
  apiVersion: "api_version.published",
  subscription: "subscription.status_changed",
});

export const OPEN_PLATFORM_LIFECYCLE_DEPRECATED_EVENT_TYPES: Readonly<
  Record<OpenPlatformLifecycleResourceKind, OpenPlatformDomainEventType>
> = Object.freeze({
  tenant: "tenant.status_changed",
  developerOrganization: "developer_organization.status_changed",
  application: "application.status_changed",
  applicationEnvironment: "client.status_changed",
  apiProduct: "api_product.deprecated",
  apiVersion: "api_version.deprecated",
  subscription: "subscription.status_changed",
});

export const OPEN_PLATFORM_LIFECYCLE_STATUS_EVENT_TYPES: Readonly<
  Record<OpenPlatformLifecycleResourceKind, OpenPlatformDomainEventType>
> = Object.freeze({
  tenant: "tenant.status_changed",
  developerOrganization: "developer_organization.status_changed",
  application: "application.status_changed",
  applicationEnvironment: "client.status_changed",
  apiProduct: "api_product.status_changed",
  apiVersion: "api_version.status_changed",
  subscription: "subscription.status_changed",
});

export function openPlatformDomainEventTypeForLifecycle(
  resource: OpenPlatformEntityKind,
  targetStatus: OpenPlatformLifecycleStatus | string,
): OpenPlatformDomainEventType | undefined {
  if (!isOpenPlatformLifecycleResourceKind(resource)) return undefined;
  if (targetStatus === "published") {
    return OPEN_PLATFORM_LIFECYCLE_PUBLISHED_EVENT_TYPES[resource];
  }
  if (targetStatus === "disabled") {
    return OPEN_PLATFORM_LIFECYCLE_DEPRECATED_EVENT_TYPES[resource];
  }
  if (targetStatus === "archived") {
    return OPEN_PLATFORM_LIFECYCLE_STATUS_EVENT_TYPES[resource];
  }
  return undefined;
}

export function isOpenPlatformLifecycleResourceKind(
  value: unknown,
): value is OpenPlatformLifecycleResourceKind {
  return (
    typeof value === "string" &&
    (OPEN_PLATFORM_LIFECYCLE_RESOURCE_KINDS as readonly string[]).includes(value)
  );
}

export function openPlatformDomainEventResourceKind(
  eventType: OpenPlatformDomainEventType,
): OpenPlatformEntityKind {
  const kind = OPEN_PLATFORM_DOMAIN_EVENT_RESOURCE_KINDS[
    openPlatformDomainEventNameParts(eventType).resource
  ];
  if (kind === undefined) {
    throw validationError("Open platform domain event resource kind is unavailable", {
      field: "eventType",
    });
  }
  return kind;
}

export function openPlatformDomainEventActionForStatus(
  targetStatus: OpenPlatformLifecycleStatus | string,
): OpenPlatformDomainEventAction {
  if (targetStatus === "published") return "published";
  if (targetStatus === "disabled") return "disabled";
  if (targetStatus === "archived") return "archived";
  return "reviewed";
}

export function createdDomainEvent(
  eventType: OpenPlatformDomainEventType,
  record: {
    readonly id: string;
    readonly version: number;
    readonly status?: string;
  },
  data: Readonly<Record<string, OpenPlatformDomainEventValue>> = {},
): OpenPlatformDomainEventDescriptor {
  return {
    eventType,
    resourceType: openPlatformDomainEventResourceKind(eventType),
    resourceId: record.id,
    resourceVersion: record.version,
    ...(record.status === undefined ? {} : { resourceStatus: record.status }),
    data: { ...data },
  };
}

export function sanitizeOpenPlatformDomainEventData(
  value: Readonly<Record<string, unknown>> | undefined,
): OpenPlatformDomainEventData {
  if (value === undefined || value === null) return Object.freeze({});
  const source = value as Record<string, unknown>;
  const output: Record<string, OpenPlatformDomainEventValue> = {};
  let included = 0;
  for (const key of Object.keys(source).sort(compareStrings)) {
    if (included >= 32) break;
    if (isSensitiveEventDataKey(key)) continue;
    const sanitized = sanitizeEventDataValue(source[key]);
    if (sanitized === undefined) continue;
    output[key] = sanitized;
    included += 1;
  }
  return Object.freeze(output);
}

export function containsOpenPlatformSensitiveEventData(
  value: Readonly<Record<string, unknown>> | undefined,
): boolean {
  if (value === undefined || value === null) return false;
  return Object.keys(value).some((key) => isSensitiveEventDataKey(key));
}

export class InMemoryOpenPlatformOutbox implements OpenPlatformOutboxPort {
  readonly productionReady = false;
  readonly readiness: OpenPlatformDependencyReadiness;
  private readonly records = new Map<string, OpenPlatformOutboxRecord>();
  private readonly sequences = new Map<string, number>();
  private readonly clock: () => Date;
  private readonly idGenerator: () => string;
  private readonly maxAttempts: number;
  private readonly leaseMs: number;
  private readonly maxEventsPerTenant: number;
  private readonly retentionMs: number;

  constructor(options: InMemoryOpenPlatformOutboxOptions = {}) {
    this.clock = options.clock ?? (() => new Date());
    this.idGenerator =
      options.idGenerator ?? (() => `open_platform_event_${randomUUID()}`);
    this.maxAttempts = normalizeMaxAttempts(options.maxAttempts);
    this.leaseMs = normalizeLeaseMs(options.leaseMs);
    this.maxEventsPerTenant = normalizeMaxEvents(options.maxEventsPerTenant);
    this.retentionMs = normalizeRetentionMs(options.retentionMs);
    this.readiness = Object.freeze({
      storage: "memory" as const,
      distributed: false,
      ready: () => options.production !== true,
    });
  }

  async isReady(): Promise<boolean> {
    return this.readiness.ready();
  }

  async append(
    event: OpenPlatformDomainEventInput,
  ): Promise<OpenPlatformOutboxRecord> {
    const normalized = normalizeDomainEventInput(event, {
      id: this.idGenerator(),
      maxAttempts: this.maxAttempts,
    });
    const key = outboxKey(normalized.tenantId, normalized.eventId);
    const existing = this.records.get(key);
    if (existing !== undefined) return cloneEvent(existing);
    const record = brandOpenPlatformDomainEventRecord(
      Object.freeze({
        ...normalized,
        status: "pending" as const,
        sequence: (this.sequences.get(normalized.tenantId) ?? 0) + 1,
        attempt: 0,
        maxAttempts: normalized.maxAttempts,
        createdAt: normalized.occurredAt,
        updatedAt: normalized.occurredAt,
        nextAttemptAt: normalized.occurredAt,
      }),
    );
    this.records.set(key, record);
    this.sequences.set(normalized.tenantId, record.sequence);
    this.prune(normalized.tenantId, this.timestamp());
    return cloneEvent(record);
  }

  async get(
    tenantId: string,
    eventId: string,
  ): Promise<OpenPlatformOutboxRecord | undefined> {
    const record = this.records.get(
      outboxKey(
        normalizeTenantKey(tenantId),
        normalizeIdentifier(eventId, "eventId"),
      ),
    );
    return record === undefined ? undefined : cloneEvent(record);
  }

  async list(query: OpenPlatformOutboxQuery): Promise<OpenPlatformOutboxPage> {
    const tenantId = normalizeTenantKey(query.tenantId);
    const limit = normalizeLimit(query.limit);
    const fromSequence = query.fromSequence ?? 0;
    if (!Number.isSafeInteger(fromSequence) || fromSequence < 0) {
      throw validationError("Open platform outbox cursor is invalid", {
        field: "fromSequence",
      });
    }
    const all = [...this.records.values()]
      .filter(
        (record) =>
          record.tenantId === tenantId &&
          record.sequence > fromSequence &&
          (query.status === undefined || record.status === query.status) &&
          (query.eventType === undefined || record.eventType === query.eventType) &&
          (query.resourceType === undefined ||
            record.resourceType === query.resourceType) &&
          (query.resourceId === undefined ||
            record.resourceId === query.resourceId),
      )
      .sort((left, right) => left.sequence - right.sequence);
    const items = all.slice(0, limit).map((record) => cloneEvent(record));
    const last = items.at(-1);
    return {
      items,
      ...(last === undefined ? {} : { nextSequence: last.sequence }),
      hasMore: all.length > items.length,
    };
  }

  async claim(
    request: OpenPlatformOutboxClaimRequest,
  ): Promise<OpenPlatformOutboxClaimResult> {
    const normalized = normalizeClaimRequest(request);
    const key = outboxKey(normalized.tenantId, normalized.eventId);
    const current = this.records.get(key);
    if (current === undefined || current.tenantId !== normalized.tenantId) {
      return { claimed: false };
    }
    const now = Date.parse(normalized.now);
    if (
      current.status === "published" ||
      current.status === "dead_lettered" ||
      current.attempt >= current.maxAttempts ||
      (current.status === "delivering" &&
        !isExpiredLease(current.leaseExpiresAt, now)) ||
      (current.nextAttemptAt !== undefined &&
        Date.parse(current.nextAttemptAt) > now)
    ) {
      return { claimed: false };
    }
    const claimed = brandOpenPlatformDomainEventRecord(
      Object.freeze({
        ...current,
        status: "delivering" as const,
        attempt: Math.max(current.attempt, normalized.attempt),
        leaseId: normalized.leaseId,
        leaseExpiresAt: normalized.leaseExpiresAt,
        updatedAt: normalized.now,
      }),
    );
    this.records.set(key, claimed);
    return { claimed: true, record: cloneEvent(claimed) };
  }

  async complete(
    request: OpenPlatformOutboxCompleteRequest,
  ): Promise<OpenPlatformOutboxRecord> {
    const normalized = normalizeCompleteRequest(request);
    const current = this.requireCurrent(normalized.tenantId, normalized.eventId);
    if (current.status === "published") return cloneEvent(current);
    const published = brandOpenPlatformDomainEventRecord(
      Object.freeze({
        ...current,
        status: "published" as const,
        publishedAt: normalized.now,
        updatedAt: normalized.now,
        nextAttemptAt: undefined,
        errorCode: undefined,
        leaseId: undefined,
        leaseExpiresAt: undefined,
      }),
    );
    this.records.set(outboxKey(current.tenantId, current.eventId), published);
    return cloneEvent(published);
  }

  async fail(
    request: OpenPlatformOutboxFailRequest,
  ): Promise<OpenPlatformOutboxRecord> {
    const normalized = normalizeFailRequest(request);
    const current = this.requireCurrent(normalized.tenantId, normalized.eventId);
    if (current.status === "published") return cloneEvent(current);
    const deadLettered =
      normalized.deadLetter === true || current.attempt >= current.maxAttempts;
    const failed = brandOpenPlatformDomainEventRecord(
      Object.freeze({
        ...current,
        status: deadLettered ? ("dead_lettered" as const) : ("failed" as const),
        nextAttemptAt:
          normalized.nextAttemptAt === undefined || deadLettered
            ? undefined
            : normalized.nextAttemptAt,
        errorCode: normalized.errorCode,
        leaseId: undefined,
        leaseExpiresAt: undefined,
        updatedAt: normalized.now,
      }),
    );
    this.records.set(outboxKey(current.tenantId, current.eventId), failed);
    return cloneEvent(failed);
  }

  snapshot(tenantId: string): OpenPlatformOutboxRecord[] {
    const normalized = normalizeTenantKey(tenantId);
    return [...this.records.values()]
      .filter((record) => record.tenantId === normalized)
      .sort((left, right) => left.sequence - right.sequence)
      .map((record) => cloneEvent(record));
  }

  size(): number {
    return this.records.size;
  }

  private requireCurrent(
    tenantId: string,
    eventId: string,
  ): OpenPlatformOutboxRecord {
    const record = this.records.get(outboxKey(tenantId, eventId));
    if (record === undefined) throw resourceNotFound("outboxEvent");
    return record;
  }

  private prune(tenantId: string, now: string): void {
    const settled = [...this.records.values()]
      .filter(
        (record) =>
          record.tenantId === tenantId &&
          (record.status === "published" || record.status === "dead_lettered") &&
          (record.sequence <=
            (this.sequences.get(tenantId) ?? 0) - this.maxEventsPerTenant ||
            Date.parse(record.updatedAt) <= Date.parse(now) - this.retentionMs),
      )
      .sort((left, right) => left.sequence - right.sequence);
    for (const record of settled) {
      this.records.delete(outboxKey(tenantId, record.eventId));
    }
  }

  private timestamp(): string {
    const value = this.clock();
    if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
      throw configurationError("Open platform outbox clock is invalid");
    }
    return value.toISOString();
  }
}

export const InMemoryOpenPlatformOutboxRepository = InMemoryOpenPlatformOutbox;
export const InMemoryOpenPlatformEventOutbox = InMemoryOpenPlatformOutbox;

export function createInMemoryOpenPlatformOutbox(
  options: InMemoryOpenPlatformOutboxOptions = {},
): InMemoryOpenPlatformOutbox {
  return new InMemoryOpenPlatformOutbox(options);
}

export class OpenPlatformEventPublisher implements OpenPlatformEventPublisherPort {
  readonly productionReady: boolean;
  readonly readiness: OpenPlatformDependencyReadiness;
  private readonly outbox: OpenPlatformOutboxPort;
  private readonly sink: OpenPlatformEventSink | undefined;
  private readonly clock: () => Date;
  private readonly maxAttempts: number;
  private readonly leaseMs: number;

  constructor(options: OpenPlatformEventPublisherOptions) {
    if (
      options === null ||
      typeof options !== "object" ||
      options.outbox === null ||
      typeof options.outbox !== "object" ||
      typeof options.outbox.append !== "function" ||
      typeof options.outbox.get !== "function" ||
      typeof options.outbox.list !== "function"
    ) {
      throw configurationError("Open platform event outbox is required");
    }
    if (
      options.sink !== undefined &&
      (options.sink === null ||
        typeof options.sink !== "object" ||
        typeof options.sink.deliver !== "function")
    ) {
      throw configurationError("Open platform event sink is invalid");
    }
    this.outbox = options.outbox;
    this.sink = options.sink;
    this.clock = options.clock ?? (() => new Date());
    this.maxAttempts = normalizeMaxAttempts(options.maxAttempts);
    this.leaseMs = normalizeLeaseMs(options.leaseMs);
    this.productionReady = this.outbox.productionReady === true;
    this.readiness = Object.freeze({
      storage: this.outbox.readiness?.storage ?? "memory",
      distributed: this.outbox.readiness?.distributed ?? false,
      ready: () => this.resolveOutboxReady(),
    });
  }

  async isReady(): Promise<boolean> {
    return this.readiness.ready();
  }

  async record(
    event: OpenPlatformDomainEventInput,
  ): Promise<OpenPlatformOutboxRecord> {
    if (!(await this.isReady())) throw storageUnavailable();
    return this.outbox.append(event);
  }

  async publish(
    event: OpenPlatformOutboxRecord,
  ): Promise<OpenPlatformEventPublishResult> {
    if (event.status === "published" || event.status === "dead_lettered") {
      return { eventId: event.eventId, delivered: 0, deadLettered: event.status === "dead_lettered" };
    }
    const claimed = await this.claim(event);
    if (claimed === undefined) {
      return { eventId: event.eventId, delivered: 0, deadLettered: false };
    }
    if (this.sink === undefined) {
      const published = await this.complete(claimed);
      return { eventId: published.eventId, delivered: 0, deadLettered: false };
    }
    let delivered = 0;
    let deadLettered = 0;
    try {
      const result = await this.sink.deliver(claimed);
      delivered = normalizeCount(result?.delivered);
      deadLettered = normalizeCount(result?.deadLettered);
    } catch {
      const failed = await this.fail(claimed, "EVENT_SINK_ERROR");
      return {
        eventId: failed.eventId,
        delivered: 0,
        deadLettered: failed.status === "dead_lettered",
      };
    }
    if (deadLettered > 0) {
      const failed = await this.fail(claimed, "EVENT_DELIVERY_DEAD_LETTERED", true);
      return {
        eventId: failed.eventId,
        delivered,
        deadLettered: failed.status === "dead_lettered",
      };
    }
    const published = await this.complete(claimed);
    return { eventId: published.eventId, delivered, deadLettered: false };
  }

  async flush(query: {
    readonly tenantId: string;
    readonly eventType?: string;
    readonly limit?: number;
  }): Promise<OpenPlatformEventPublishResult[]> {
    const page = await this.outbox.list({
      tenantId: query.tenantId,
      ...(query.eventType === undefined ? {} : { eventType: query.eventType }),
      ...(query.limit === undefined ? {} : { limit: query.limit }),
    });
    const results: OpenPlatformEventPublishResult[] = [];
    for (const record of page.items) {
      if (record.status === "published" || record.status === "dead_lettered") {
        continue;
      }
      results.push(await this.publish(record));
    }
    return results;
  }

  private async resolveOutboxReady(): Promise<boolean> {
    if (this.outbox.readiness !== undefined) {
      return safeReady(this.outbox.readiness);
    }
    if (typeof this.outbox.isReady === "function") {
      try {
        return (await this.outbox.isReady()) === true;
      } catch {
        return false;
      }
    }
    return this.outbox.productionReady === true;
  }

  private async claim(
    event: OpenPlatformOutboxRecord,
  ): Promise<OpenPlatformOutboxRecord | undefined> {
    const now = this.timestamp();
    const attempt = Math.max(event.attempt + 1, 1);
    const leaseId = `event_lease_${randomUUID()}`;
    const leaseExpiresAt = new Date(Date.parse(now) + this.leaseMs).toISOString();
    if (this.outbox.claim === undefined) {
      return brandOpenPlatformDomainEventRecord(
        Object.freeze({
          ...event,
          status: "delivering" as const,
          attempt: Math.min(attempt, Math.max(event.maxAttempts, 1)),
          leaseId,
          leaseExpiresAt,
          updatedAt: now,
        }),
      );
    }
    const result = await this.outbox.claim({
      tenantId: event.tenantId,
      eventId: event.eventId,
      attempt: Math.min(attempt, Math.max(event.maxAttempts, 1)),
      leaseId,
      now,
      leaseExpiresAt,
    });
    return result.claimed === true && result.record !== undefined
      ? result.record
      : undefined;
  }

  private async complete(
    event: OpenPlatformOutboxRecord,
  ): Promise<OpenPlatformOutboxRecord> {
    if (this.outbox.complete === undefined) return event;
    return this.outbox.complete({
      tenantId: event.tenantId,
      eventId: event.eventId,
      now: this.timestamp(),
      ...(event.leaseId === undefined ? {} : { leaseId: event.leaseId }),
    });
  }

  private async fail(
    event: OpenPlatformOutboxRecord,
    errorCode: string,
    deadLetter = false,
  ): Promise<OpenPlatformOutboxRecord> {
    if (this.outbox.fail === undefined) return event;
    const now = this.timestamp();
    return this.outbox.fail({
      tenantId: event.tenantId,
      eventId: event.eventId,
      now,
      ...(event.leaseId === undefined ? {} : { leaseId: event.leaseId }),
      errorCode,
      nextAttemptAt: new Date(
        Date.parse(now) + this.backoffMs(event.attempt),
      ).toISOString(),
      deadLetter,
    });
  }

  private backoffMs(attempt: number): number {
    return Math.min(300_000, 1_000 * 2 ** Math.max(attempt - 1, 0));
  }

  private timestamp(): string {
    const value = this.clock();
    if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
      throw configurationError("Open platform event publisher clock is invalid");
    }
    return value.toISOString();
  }
}

export function createOpenPlatformEventPublisher(
  options: OpenPlatformEventPublisherOptions,
): OpenPlatformEventPublisher {
  return new OpenPlatformEventPublisher(options);
}

export function isOpenPlatformOutboxTenantResolver(
  value: unknown,
): value is OpenPlatformOutboxTenantResolver {
  return (
    value !== null &&
    typeof value === "object" &&
    typeof (value as OpenPlatformOutboxTenantResolver).listTenants === "function"
  );
}

export function createOpenPlatformOutboxTenantResolver(
  tenantIds: readonly string[],
): OpenPlatformOutboxTenantResolver {
  if (!Array.isArray(tenantIds)) {
    throw configurationError("Open platform outbox tenant identifiers are required");
  }
  if (tenantIds.length === 0) {
    throw configurationError("Open platform outbox tenant identifiers are required");
  }
  const normalized: string[] = [];
  const seen = new Set<string>();
  for (const candidate of tenantIds) {
    const tenantId = normalizeTenantResolverKey(candidate);
    if (seen.has(tenantId)) continue;
    seen.add(tenantId);
    normalized.push(tenantId);
  }
  const tenants = Object.freeze(normalized);
  return {
    listTenants(query: OpenPlatformOutboxTenantQuery) {
      const limit = normalizeTenantPageLimit(query?.limit);
      const offset = tenantCursorOffset(query?.cursor, tenants.length);
      const items = tenants.slice(offset, offset + limit);
      const next = offset + items.length;
      return Promise.resolve(
        Object.freeze({
          tenantIds: Object.freeze([...items]),
          ...(next < tenants.length ? { cursor: String(next) } : {}),
          hasMore: next < tenants.length,
        }),
      );
    },
  };
}

export async function listOpenPlatformOutboxTenants(
  resolver: OpenPlatformOutboxTenantResolver,
  query: {
    readonly cursor?: string;
    readonly limit?: number;
    readonly signal?: AbortSignal;
  } = {},
): Promise<OpenPlatformOutboxTenantBatch> {
  if (!isOpenPlatformOutboxTenantResolver(resolver)) {
    throw configurationError("Open platform outbox tenant resolver is invalid");
  }
  const limit = normalizeTenantPageLimit(query.limit);
  const cursor =
    query.cursor === undefined ? undefined : normalizeTenantCursor(query.cursor);
  const page = await resolver.listTenants({
    limit,
    ...(cursor === undefined ? {} : { cursor }),
    ...(query.signal === undefined ? {} : { signal: query.signal }),
  });
  if (
    page === null ||
    typeof page !== "object" ||
    !Array.isArray(page.tenantIds)
  ) {
    throw validationError("Open platform outbox tenant page is invalid", {
      field: "tenantIds",
    });
  }
  const tenantIds: string[] = [];
  const seen = new Set<string>();
  let rejected = 0;
  for (const candidate of page.tenantIds) {
    if (tenantIds.length >= limit) {
      rejected += 1;
      continue;
    }
    let tenantId: string;
    try {
      tenantId = normalizeTenantKey(candidate);
    } catch {
      rejected += 1;
      continue;
    }
    if (seen.has(tenantId)) continue;
    seen.add(tenantId);
    tenantIds.push(tenantId);
  }
  const hasMore = page.hasMore === true;
  const pageCursor =
    page.cursor === undefined ? undefined : normalizeTenantCursor(page.cursor);
  const nextCursor = hasMore
    ? pageCursor ?? cursor
    : undefined;
  return Object.freeze({
    tenantIds: Object.freeze(tenantIds),
    ...(nextCursor === undefined ? {} : { cursor: nextCursor }),
    hasMore,
    rejected,
  });
}

export async function flushOpenPlatformOutboxTenant(
  request: OpenPlatformEventFlushRequest,
): Promise<OpenPlatformEventFlushResult> {
  if (request === null || typeof request !== "object") {
    throw configurationError("Open platform outbox flush request is required");
  }
  const publisher = request.publisher;
  if (
    publisher === null ||
    typeof publisher !== "object" ||
    typeof publisher.publish !== "function"
  ) {
    throw configurationError("Open platform event publisher is invalid");
  }
  const outbox = request.outbox;
  if (
    outbox === null ||
    typeof outbox !== "object" ||
    typeof outbox.list !== "function" ||
    typeof outbox.get !== "function"
  ) {
    throw configurationError("Open platform event outbox is invalid");
  }
  const tenantId = normalizeTenantKey(request.tenantId);
  const limit = normalizeLimit(request.limit);
  const now = flushNow(request.clock?.() ?? new Date());
  const candidates = await collectFlushCandidates(
    outbox,
    tenantId,
    limit,
    now,
    request.signal,
  );
  const outcomes: OpenPlatformEventFlushOutcome[] = [];
  for (const record of candidates.selected) {
    outcomes.push(await flushCandidate(publisher, outbox, record));
  }
  return Object.freeze({
    tenantId,
    outcomes: Object.freeze(outcomes),
    scanned: candidates.scanned,
    deferred: candidates.deferred,
    truncated: candidates.truncated,
  });
}

export async function flushOpenPlatformOutboxTenants(
  request: OpenPlatformEventFlushTenantsRequest,
): Promise<OpenPlatformEventFlushTenantsResult> {
  if (request === null || typeof request !== "object") {
    throw configurationError("Open platform outbox flush request is required");
  }
  if (request.publisher === undefined || request.outbox === undefined) {
    throw configurationError("Open platform outbox flush requires a publisher and outbox");
  }
  const batch = request.tenants;
  const supplied = request.tenantIds;
  if (batch !== undefined && supplied !== undefined) {
    throw configurationError("Open platform outbox flush tenant options conflict");
  }
  const tenantIds: string[] = [];
  const seen = new Set<string>();
  let rejected = batch?.rejected ?? 0;
  const candidates = batch?.tenantIds ?? supplied ?? [];
  if (!Array.isArray(candidates)) {
    throw validationError("Open platform outbox tenant batch is invalid", {
      field: "tenantIds",
    });
  }
  for (const candidate of candidates) {
    let tenantId: string;
    try {
      tenantId = normalizeTenantKey(candidate);
    } catch {
      rejected += 1;
      continue;
    }
    if (seen.has(tenantId)) continue;
    seen.add(tenantId);
    tenantIds.push(tenantId);
  }
  const limit = normalizeLimit(request.limit);
  const clock = request.clock;
  const results: OpenPlatformEventFlushResult[] = [];
  const failures: OpenPlatformEventFlushFailure[] = [];
  for (const tenantId of tenantIds) {
    if (request.signal?.aborted === true) break;
    try {
      results.push(
        await flushOpenPlatformOutboxTenant({
          publisher: request.publisher,
          outbox: request.outbox,
          tenantId,
          limit,
          ...(clock === undefined ? {} : { clock }),
          ...(request.signal === undefined ? {} : { signal: request.signal }),
        }),
      );
    } catch (error) {
      failures.push(
        Object.freeze({
          tenantId,
          code: flushErrorCode(error),
          message: flushErrorMessage(error),
          cause: error,
        }),
      );
    }
  }
  return Object.freeze({
    tenants: Object.freeze(results),
    failures: Object.freeze(failures),
    rejected,
  });
}

interface FlushCandidates {
  readonly selected: readonly OpenPlatformOutboxRecord[];
  readonly scanned: number;
  readonly deferred: number;
  readonly truncated: boolean;
}

async function collectFlushCandidates(
  outbox: OpenPlatformOutboxPort,
  tenantId: string,
  limit: number,
  now: number,
  signal: AbortSignal | undefined,
): Promise<FlushCandidates> {
  const selected: OpenPlatformOutboxRecord[] = [];
  const scanLimit = limit * FLUSH_SCAN_FACTOR;
  let cursor = 0;
  let scanned = 0;
  let deferred = 0;
  let hasMore = true;
  while (hasMore && scanned < scanLimit && selected.length < limit) {
    if (signal?.aborted === true) break;
    const page = await outbox.list({
      tenantId,
      fromSequence: cursor,
      limit,
    });
    if (page === null || typeof page !== "object" || !Array.isArray(page.items)) {
      throw validationError("Open platform outbox page is invalid", {
        field: "items",
      });
    }
    scanned += page.items.length;
    hasMore = page.hasMore === true && page.items.length > 0;
    if (page.items.length === 0) break;
    for (const record of page.items) {
      if (record === null || typeof record !== "object") {
        throw validationError("Open platform outbox record is invalid", {
          field: "items",
        });
      }
      if (record.tenantId !== tenantId) {
        throw validationError("Open platform outbox page crossed tenant boundaries", {
          field: "tenantId",
        });
      }
      if (isSettledOutboxRecord(record)) continue;
      if (!isClaimableOutboxRecord(record, now)) {
        deferred += 1;
        continue;
      }
      selected.push(record);
      if (selected.length >= limit) break;
    }
    cursor = page.nextSequence ?? cursor + page.items.length;
  }
  return Object.freeze({
    selected: Object.freeze(selected),
    scanned,
    deferred,
    truncated: selected.length >= limit && hasMore,
  });
}

async function flushCandidate(
  publisher: OpenPlatformEventPublisherPort,
  outbox: OpenPlatformOutboxPort,
  record: OpenPlatformOutboxRecord,
): Promise<OpenPlatformEventFlushOutcome> {
  let result: OpenPlatformEventPublishResult;
  try {
    result = await publisher.publish(record);
  } catch (error) {
    const settled = await readFlushedRecord(outbox, record);
    if (settled !== undefined) {
      return flushOutcome(record, settled, 0, errorCode(error));
    }
    return Object.freeze({
      eventId: record.eventId,
      tenantId: record.tenantId,
      status: "failed" as const,
      delivered: 0,
      attempt: record.attempt,
      maxAttempts: record.maxAttempts,
      retryScheduled: true,
      errorCode: errorCode(error),
    });
  }
  if (
    result === null ||
    typeof result !== "object" ||
    result.eventId !== record.eventId
  ) {
    throw validationError("Open platform event publisher result is invalid", {
      field: "eventId",
    });
  }
  const settled = await readFlushedRecord(outbox, record);
  if (settled === undefined) {
    return Object.freeze({
      eventId: record.eventId,
      tenantId: record.tenantId,
      status: result.deadLettered === true
        ? ("dead_lettered" as const)
        : ("published" as const),
      delivered: normalizeCount(result.delivered),
      attempt: record.attempt,
      maxAttempts: record.maxAttempts,
      retryScheduled: false,
    });
  }
  return flushOutcome(record, settled, result.delivered, undefined);
}

function flushOutcome(
  record: OpenPlatformOutboxRecord,
  settled: OpenPlatformOutboxRecord,
  delivered: unknown,
  code: string | undefined,
): OpenPlatformEventFlushOutcome {
  const status: OpenPlatformEventFlushStatus =
    settled.status === "published"
      ? "published"
      : settled.status === "dead_lettered"
        ? "dead_lettered"
        : settled.status === "failed"
          ? "failed"
          : "skipped";
  const retryScheduled =
    status === "failed" &&
    settled.nextAttemptAt !== undefined &&
    settled.attempt < settled.maxAttempts;
  return Object.freeze({
    eventId: record.eventId,
    tenantId: record.tenantId,
    status,
    delivered: normalizeCount(delivered),
    attempt: record.attempt,
    maxAttempts: record.maxAttempts,
    retryScheduled,
    ...(code === undefined ? {} : { errorCode: code }),
  });
}

async function readFlushedRecord(
  outbox: OpenPlatformOutboxPort,
  record: OpenPlatformOutboxRecord,
): Promise<OpenPlatformOutboxRecord | undefined> {
  let settled: OpenPlatformOutboxRecord | undefined;
  try {
    settled = await outbox.get(record.tenantId, record.eventId);
  } catch {
    return undefined;
  }
  if (settled === undefined) return undefined;
  if (settled.tenantId !== record.tenantId || settled.eventId !== record.eventId) {
    throw validationError("Open platform outbox record does not match the flushed event", {
      field: "eventId",
    });
  }
  return settled;
}

function isSettledOutboxRecord(record: OpenPlatformOutboxRecord): boolean {
  return record.status === "published" || record.status === "dead_lettered";
}

function isClaimableOutboxRecord(
  record: OpenPlatformOutboxRecord,
  now: number,
): boolean {
  if (record.status === "delivering") {
    return isExpiredLease(record.leaseExpiresAt, now);
  }
  if (record.nextAttemptAt !== undefined && Date.parse(record.nextAttemptAt) > now) {
    return false;
  }
  return true;
}

function flushNow(value: Date): number {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    throw configurationError("Open platform outbox flush clock is invalid");
  }
  return value.getTime();
}

function flushErrorCode(error: unknown): string {
  return isOpenPlatformDomainError(error) ? error.code : "EVENT_FLUSH_FAILED";
}

function flushErrorMessage(error: unknown): string {
  if (isOpenPlatformDomainError(error)) return error.message;
  if (error instanceof Error) return sanitizeRelayText(error.message);
  return "Open platform outbox flush failed";
}

function sanitizeRelayText(value: string): string {
  return value.replace(/[\u0000-\u001f\u007f]/gu, " ").trim().slice(0, 256);
}

function errorCode(error: unknown): string {
  return isOpenPlatformDomainError(error) ? error.code : "EVENT_PUBLISH_FAILED";
}

function normalizeTenantResolverKey(value: unknown): string {
  try {
    return normalizeTenantKey(value);
  } catch {
    throw configurationError("Open platform outbox tenant identifier is invalid");
  }
}

function normalizeTenantPageLimit(value: unknown): number {
  if (value === undefined) return 100;
  if (
    !Number.isSafeInteger(value) ||
    (value as number) < 1 ||
    (value as number) > OPEN_PLATFORM_OUTBOX_TENANT_PAGE_LIMIT
  ) {
    throw configurationError("Open platform outbox tenant page limit is invalid");
  }
  return value as number;
}

function normalizeTenantCursor(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > OPEN_PLATFORM_OUTBOX_TENANT_CURSOR_LIMIT ||
    /[\s\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw validationError("Open platform outbox tenant cursor is invalid", {
      field: "cursor",
    });
  }
  return value;
}

function tenantCursorOffset(cursor: string | undefined, size: number): number {
  if (cursor === undefined) return 0;
  if (!/^(?:0|[1-9][0-9]*)$/u.test(cursor)) {
    throw validationError("Open platform outbox tenant cursor is invalid", {
      field: "cursor",
    });
  }
  const offset = Number(cursor);
  if (!Number.isSafeInteger(offset) || offset > size) {
    throw validationError("Open platform outbox tenant cursor is invalid", {
      field: "cursor",
    });
  }
  return offset;
}

interface NormalizedDomainEventInput extends OpenPlatformDomainEvent {
  readonly maxAttempts: number;
}

function normalizeDomainEventInput(
  event: OpenPlatformDomainEventInput,
  defaults: { readonly id: string; readonly maxAttempts: number },
): NormalizedDomainEventInput {
  if (event === null || typeof event !== "object") {
    throw validationError("Open platform domain event is invalid", {
      field: "event",
    });
  }
  return {
    eventId: normalizeIdentifier(event.eventId ?? defaults.id, "eventId"),
    tenantId: normalizeTenantKey(event.tenantId),
    eventType: toOpenPlatformDomainEventType(event.eventType),
    resourceType: normalizeResourceType(event.resourceType),
    resourceId: normalizeIdentifier(event.resourceId, "resourceId"),
    ...(event.resourceVersion === undefined
      ? {}
      : { resourceVersion: normalizePositiveInteger(event.resourceVersion, "resourceVersion") }),
    ...(event.resourceStatus === undefined
      ? {}
      : { resourceStatus: normalizeIdentifier(event.resourceStatus, "resourceStatus") }),
    ...(event.actorId === undefined
      ? {}
      : { actorId: normalizeIdentifier(event.actorId, "actorId") }),
    ...(event.requestId === undefined
      ? {}
      : { requestId: normalizeIdentifier(event.requestId, "requestId") }),
    occurredAt: normalizeInstant(event.occurredAt, "occurredAt"),
    schemaVersion: normalizeIdentifier(
      event.schemaVersion ?? OPEN_PLATFORM_DOMAIN_EVENT_SCHEMA_VERSION,
      "schemaVersion",
    ),
    data: sanitizeOpenPlatformDomainEventData(event.data),
    maxAttempts: defaults.maxAttempts,
  };
}

function normalizeResourceType(
  value: unknown,
): OpenPlatformDomainEventResourceType {
  if (
    typeof value !== "string" ||
    !(DOMAIN_EVENT_RESOURCE_TYPES as readonly string[]).includes(value)
  ) {
    throw validationError("Open platform domain event resource type is invalid", {
      field: "resourceType",
    });
  }
  return value as OpenPlatformEntityKind;
}

function normalizeClaimRequest(
  request: OpenPlatformOutboxClaimRequest,
): OpenPlatformOutboxClaimRequest {
  if (request === null || typeof request !== "object") {
    throw validationError("Open platform outbox claim is invalid", {
      field: "claim",
    });
  }
  if (!Number.isSafeInteger(request.attempt) || request.attempt < 1) {
    throw validationError("Open platform outbox claim attempt is invalid", {
      field: "attempt",
    });
  }
  const now = normalizeInstant(request.now, "now");
  const leaseExpiresAt = normalizeInstant(request.leaseExpiresAt, "leaseExpiresAt");
  if (Date.parse(leaseExpiresAt) <= Date.parse(now)) {
    throw validationError("Open platform outbox claim lease is invalid", {
      field: "leaseExpiresAt",
    });
  }
  return {
    tenantId: normalizeTenantKey(request.tenantId),
    eventId: normalizeIdentifier(request.eventId, "eventId"),
    attempt: request.attempt,
    leaseId: normalizeIdentifier(request.leaseId, "leaseId"),
    now,
    leaseExpiresAt,
  };
}

function normalizeCompleteRequest(
  request: OpenPlatformOutboxCompleteRequest,
): OpenPlatformOutboxCompleteRequest {
  if (request === null || typeof request !== "object") {
    throw validationError("Open platform outbox completion is invalid", {
      field: "complete",
    });
  }
  return {
    tenantId: normalizeTenantKey(request.tenantId),
    eventId: normalizeIdentifier(request.eventId, "eventId"),
    now: normalizeInstant(request.now, "now"),
    ...(request.leaseId === undefined
      ? {}
      : { leaseId: normalizeIdentifier(request.leaseId, "leaseId") }),
  };
}

function normalizeFailRequest(
  request: OpenPlatformOutboxFailRequest,
): Required<OpenPlatformOutboxFailRequest> {
  const base = normalizeCompleteRequest(request);
  return {
    ...base,
    errorCode: normalizeIdentifier(request.errorCode, "errorCode"),
    ...(request.nextAttemptAt === undefined
      ? {}
      : {
          nextAttemptAt: normalizeInstant(
            request.nextAttemptAt,
            "nextAttemptAt",
          ),
        }),
    ...(request.deadLetter === true ? { deadLetter: true } : {}),
  } as Required<OpenPlatformOutboxFailRequest>;
}

function sanitizeEventDataValue(
  value: unknown,
): OpenPlatformDomainEventValue | undefined {
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "number") {
    return Number.isFinite(value) ? value : undefined;
  }
  if (typeof value === "string") {
    return isSafeEventDataString(value) ? value : undefined;
  }
  if (Array.isArray(value)) {
    if (value.length === 0 || value.length > 64) return undefined;
    const values: (string | number | boolean | null)[] = [];
    for (const entry of value) {
      const sanitized = sanitizeEventDataScalar(entry);
      if (sanitized === undefined) return undefined;
      values.push(sanitized);
    }
    return Object.freeze(values);
  }
  return undefined;
}

function sanitizeEventDataScalar(
  value: unknown,
): string | number | boolean | null | undefined {
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "number") {
    return Number.isFinite(value) ? value : undefined;
  }
  if (typeof value === "string") {
    return isSafeEventDataString(value) ? value : undefined;
  }
  return undefined;
}

function normalizeInstant(value: unknown, field: string): string {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) {
    throw validationError("Open platform outbox timestamp is invalid", { field });
  }
  return new Date(Date.parse(value)).toISOString();
}

function normalizePositiveInteger(value: unknown, field: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    throw validationError("Open platform outbox number is invalid", { field });
  }
  return value as number;
}

function normalizeMaxAttempts(value: unknown): number {
  if (value === undefined) return OPEN_PLATFORM_DOMAIN_EVENT_MAX_ATTEMPTS;
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > 20) {
    throw configurationError("Open platform event maximum attempts is invalid");
  }
  return value as number;
}

function normalizeLeaseMs(value: unknown): number {
  if (value === undefined) return 30_000;
  if (
    !Number.isSafeInteger(value) ||
    (value as number) < 1_000 ||
    (value as number) > 3_600_000
  ) {
    throw configurationError("Open platform event lease is invalid");
  }
  return value as number;
}

function normalizeRetentionMs(value: unknown): number {
  if (value === undefined) return 604_800_000;
  if (
    !Number.isSafeInteger(value) ||
    (value as number) < 60_000 ||
    (value as number) > 31_536_000_000
  ) {
    throw configurationError("Open platform outbox retention is invalid");
  }
  return value as number;
}

function normalizeMaxEvents(value: unknown): number {
  if (value === undefined) return 10_000;
  if (
    !Number.isSafeInteger(value) ||
    (value as number) < 1 ||
    (value as number) > 1_000_000
  ) {
    throw configurationError("Open platform outbox capacity is invalid");
  }
  return value as number;
}

function normalizeLimit(value: unknown): number {
  if (value === undefined) return 50;
  if (
    !Number.isSafeInteger(value) ||
    (value as number) < 1 ||
    (value as number) > 500
  ) {
    throw validationError("Open platform outbox page limit is invalid", {
      field: "limit",
    });
  }
  return value as number;
}

function normalizeCount(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) return 0;
  return value as number;
}

function cloneEvent(record: OpenPlatformOutboxRecord): OpenPlatformOutboxRecord {
  return brandOpenPlatformDomainEventRecord(Object.freeze(structuredClone(record)));
}

function isSensitiveEventDataKey(key: string): boolean {
  const normalized = key.replace(/[-_]/gu, "").toLowerCase();
  return SENSITIVE_EVENT_DATA_PATTERNS.some((pattern) =>
    normalized.includes(pattern)
  );
}

function isSafeEventDataString(value: string): boolean {
  return (
    value.length <= 256 &&
    !/[\u0000-\u001f\u007f]/u.test(value) &&
    !/(?:secret|password|passwd|token|authorization|private[-_ ]?key|vault:\/\/)/iu.test(
      value,
    )
  );
}

function outboxKey(tenantId: string, eventId: string): string {
  return `${tenantId}\u0000${eventId}`;
}

function isExpiredLease(
  leaseExpiresAt: string | undefined,
  now: number,
): boolean {
  if (leaseExpiresAt === undefined) return true;
  const expires = Date.parse(leaseExpiresAt);
  return !Number.isFinite(expires) || expires <= now;
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

async function safeReady(
  readiness: OpenPlatformDependencyReadiness,
): Promise<boolean> {
  try {
    return (await readiness.ready()) === true;
  } catch {
    return false;
  }
}
