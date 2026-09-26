import {
  createHmac,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import {
  isDevelopmentOpenPlatformAuthorization,
  isOpenPlatformRequestContext,
  type OpenPlatformAuthorizationPort,
  type OpenPlatformRequestContext,
} from "./authorization.js";
import {
  configurationError,
  forbidden,
  idempotencyKeyReused,
  isOpenPlatformDomainError,
  resourceConflict,
  resourceNotFound,
  validationError,
} from "./errors.js";
import {
  InMemoryOpenPlatformAuditEventStore,
  type OpenPlatformAuditPort,
  type OpenPlatformAuditResourceType,
} from "./audit.js";
import {
  OPEN_PLATFORM_DOMAIN_EVENT_SYSTEM_ACTOR_ID,
  OPEN_PLATFORM_DOMAIN_EVENT_TYPES,
  isOpenPlatformDomainEventRecord,
  type OpenPlatformOutboxRecord,
} from "./events.js";
import { normalizeIdentifier, normalizeTenantKey } from "./validation.js";
import { hashOpenPlatformIdempotencyRequest } from "./idempotency.js";
import type {
  MaybePromise,
  OpenPlatformDependencyReadiness,
  OpenPlatformEntityKind,
  OpenPlatformRecord,
  OpenPlatformRecordBase,
  OpenPlatformRuntimeMode,
  TenantScopedRepository,
} from "./types.js";

export const OPEN_PLATFORM_WEBHOOK_STATUSES = ["active", "paused", "failing", "disabled"] as const;
export type OpenPlatformWebhookStatus = (typeof OPEN_PLATFORM_WEBHOOK_STATUSES)[number];

export const OPEN_PLATFORM_WEBHOOK_TRANSITIONS = Object.freeze({
  active: Object.freeze(["paused", "failing", "disabled"]),
  paused: Object.freeze(["active", "failing", "disabled"]),
  failing: Object.freeze(["active", "paused", "disabled"]),
  disabled: Object.freeze(["active"]),
} satisfies Readonly<Record<OpenPlatformWebhookStatus, readonly OpenPlatformWebhookStatus[]>>);

export function canTransitionOpenPlatformWebhook(
  from: OpenPlatformWebhookStatus,
  to: OpenPlatformWebhookStatus,
): boolean {
  return (OPEN_PLATFORM_WEBHOOK_TRANSITIONS[from] as readonly OpenPlatformWebhookStatus[]).includes(to);
}

export function transitionOpenPlatformWebhook(
  from: OpenPlatformWebhookStatus,
  to: OpenPlatformWebhookStatus,
): OpenPlatformWebhookStatus {
  if (!canTransitionOpenPlatformWebhook(from, to)) {
    throw resourceConflict("Webhook state transition is not allowed");
  }
  return to;
}

export const OPEN_PLATFORM_WEBHOOK_EVENT_TYPES = OPEN_PLATFORM_DOMAIN_EVENT_TYPES;
export type OpenPlatformWebhookEventType = (typeof OPEN_PLATFORM_WEBHOOK_EVENT_TYPES)[number];

export const OPEN_PLATFORM_WEBHOOK_DELIVERY_STATUSES = [
  "pending",
  "delivering",
  "succeeded",
  "failed",
  "dead_lettered",
] as const;
export type OpenPlatformWebhookDeliveryStatus =
  (typeof OPEN_PLATFORM_WEBHOOK_DELIVERY_STATUSES)[number];

export const OPEN_PLATFORM_WEBHOOK_SIGNATURE_ALGORITHM = "hmac-sha256" as const;
export const OPEN_PLATFORM_WEBHOOK_SIGNATURE_VERSION = "v1" as const;
export const OPEN_PLATFORM_WEBHOOK_EVENT_SCHEMA_VERSION = "open-platform.webhook-event.v1" as const;
export const OPEN_PLATFORM_WEBHOOK_SIGNATURE_HEADER = "X-Webhook-Signature" as const;
export const OPEN_PLATFORM_WEBHOOK_TIMESTAMP_HEADER = "X-Webhook-Timestamp" as const;
export const OPEN_PLATFORM_WEBHOOK_SECRET_VERSION_HEADER = "X-Webhook-Secret-Version" as const;
export const OPEN_PLATFORM_WEBHOOK_EVENT_ID_HEADER = "X-Webhook-Event-Id" as const;
export const OPEN_PLATFORM_WEBHOOK_EVENT_TYPE_HEADER = "X-Webhook-Event-Type" as const;
export const OPEN_PLATFORM_WEBHOOK_IDEMPOTENCY_HEADER = "Idempotency-Key" as const;
export const OPEN_PLATFORM_WEBHOOK_SIGNATURE_HEADER_NAME = OPEN_PLATFORM_WEBHOOK_SIGNATURE_HEADER;
export const OPEN_PLATFORM_WEBHOOK_TIMESTAMP_HEADER_NAME = OPEN_PLATFORM_WEBHOOK_TIMESTAMP_HEADER;
export const OPEN_PLATFORM_WEBHOOK_SECRET_VERSION_HEADER_NAME = OPEN_PLATFORM_WEBHOOK_SECRET_VERSION_HEADER;
export const OPEN_PLATFORM_WEBHOOK_OPEN_PLATFORM_SIGNATURE_HEADER = "X-OpenPlatform-Signature" as const;
export const OPEN_PLATFORM_WEBHOOK_OPEN_PLATFORM_TIMESTAMP_HEADER = "X-OpenPlatform-Timestamp" as const;
export const OPEN_PLATFORM_WEBHOOK_OPEN_PLATFORM_SECRET_VERSION_HEADER = "X-OpenPlatform-Secret-Version" as const;

export interface OpenPlatformWebhook extends OpenPlatformRecordBase {
  readonly kind: "webhook";
  readonly developerOrganizationId: string;
  readonly applicationId: string;
  readonly environmentId: string;
  readonly name: string;
  readonly endpointUrl: string;
  readonly status: OpenPlatformWebhookStatus;
  readonly events: readonly string[];
  readonly signingAlgorithm: typeof OPEN_PLATFORM_WEBHOOK_SIGNATURE_ALGORITHM;
  readonly signingSecretReference: string;
  readonly secretVersion: number;
  readonly failureCount: number;
  readonly nextDeliveryAt?: string;
  readonly lastDeliveryAt?: string;
}

export type OpenPlatformWebhookRecord = OpenPlatformWebhook;
export type OpenPlatformWebhookSubscription = OpenPlatformWebhook;
export type OpenPlatformWebhookEventPayload = OpenPlatformWebhookEventEnvelope;

export interface OpenPlatformWebhookEventResource {
  readonly type: string;
  readonly id: string;
  readonly version?: number;
  readonly status?: string;
}

export interface OpenPlatformWebhookEventEnvelope {
  readonly eventId?: string;
  readonly eventType?: OpenPlatformWebhookEventType | string;
  readonly type?: OpenPlatformWebhookEventType | string;
  readonly occurredAt?: string;
  readonly tenantId: string;
  readonly actor?: {
    readonly type: "user" | "service" | "system";
    readonly id: string;
  };
  readonly resource?: OpenPlatformWebhookEventResource;
  readonly data?: Readonly<Record<string, unknown>>;
  readonly schemaVersion?: string;
  readonly requestId?: string;
  readonly traceId?: string;
}

export interface OpenPlatformWebhookDelivery {
  readonly id: string;
  readonly tenantId: string;
  readonly webhookId: string;
  readonly eventId: string;
  readonly event: OpenPlatformWebhookEventType | string;
  readonly eventType?: OpenPlatformWebhookEventType | string;
  readonly status: OpenPlatformWebhookDeliveryStatus;
  readonly attempt: number;
  readonly maxAttempts: number;
  readonly idempotencyKey: string;
  readonly payload: string;
  readonly body?: string;
  readonly secretVersion: number;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly nextAttemptAt?: string;
  readonly deliveredAt?: string;
  readonly responseStatusCode?: number;
  readonly responseBodyExcerpt?: string;
  readonly errorCode?: string;
  readonly leaseId?: string;
  readonly leaseExpiresAt?: string;
}

export type OpenPlatformWebhookDeliveryRecord = OpenPlatformWebhookDelivery;
export type OpenPlatformWebhookDeliveryAttempt = OpenPlatformWebhookDelivery;

export interface OpenPlatformWebhookQuery {
  readonly tenantId: string;
  readonly id?: string;
  readonly status?: OpenPlatformWebhookStatus | string;
  readonly applicationId?: string;
  readonly environmentId?: string;
  readonly cursor?: string;
  readonly limit?: number;
}

export interface OpenPlatformWebhookPage {
  readonly items: readonly OpenPlatformWebhook[];
  readonly nextCursor?: string;
  readonly previousCursor?: string;
  readonly hasMore: boolean;
  readonly total?: number;
}

export interface OpenPlatformWebhookDeliveryQuery {
  readonly tenantId: string;
  readonly webhookId?: string;
  readonly eventId?: string;
  readonly status?: OpenPlatformWebhookDeliveryStatus | string;
  readonly cursor?: string;
  readonly limit?: number;
}

export interface OpenPlatformWebhookDeliveryPage {
  readonly items: readonly OpenPlatformWebhookDelivery[];
  readonly nextCursor?: string;
  readonly previousCursor?: string;
  readonly hasMore: boolean;
  readonly total?: number;
}

export interface OpenPlatformWebhookSecretMaterial {
  readonly secret?: string;
  readonly value?: string;
  readonly reference?: string;
  readonly secretReference?: string;
  readonly version?: number;
}

export interface OpenPlatformWebhookSecretResult {
  readonly webhook: OpenPlatformWebhook;
  readonly secret: string;
  readonly secretVersion: number;
  readonly replayed?: boolean;
}

export interface OpenPlatformWebhookSecretPort {
  readonly productionReady?: boolean;
  readonly readiness?: OpenPlatformDependencyReadiness;
  issue?(input: {
    readonly tenantId: string;
    readonly webhookId: string;
    readonly version: number;
    readonly reason: "create" | "rotate";
  }): MaybePromise<OpenPlatformWebhookSecretMaterial>;
  create?(input: {
    readonly tenantId: string;
    readonly webhookId: string;
    readonly version: number;
    readonly reason: "create" | "rotate";
  }): MaybePromise<OpenPlatformWebhookSecretMaterial>;
  rotate?(input: {
    readonly tenantId: string;
    readonly webhookId: string;
    readonly version: number;
    readonly previousVersion: number;
  }): MaybePromise<OpenPlatformWebhookSecretMaterial>;
  resolve?(input: {
    readonly tenantId: string;
    readonly webhookId: string;
    readonly version: number;
  }): MaybePromise<string | undefined>;
  get?(input: {
    readonly tenantId: string;
    readonly webhookId: string;
    readonly version: number;
  }): MaybePromise<string | undefined>;
  revoke?(input: {
    readonly tenantId: string;
    readonly webhookId: string;
    readonly version: number;
  }): MaybePromise<void>;
}

export interface OpenPlatformWebhookEndpointAddresses {
  readonly addresses: readonly string[];
}

export interface OpenPlatformWebhookEndpointResolver {
  resolve(
    hostname: string,
  ): MaybePromise<readonly string[] | OpenPlatformWebhookEndpointAddresses>;
}

export type OpenPlatformWebhookEndpointResolverFunction = (
  hostname: string,
) => MaybePromise<readonly string[] | OpenPlatformWebhookEndpointAddresses>;

export interface OpenPlatformWebhookEndpointPolicy {
  readonly requireHttps?: boolean;
  readonly allowLoopbackHttp?: boolean;
  readonly allowPrivateNetwork?: boolean;
  readonly allowHosts?: readonly string[];
  readonly allowedPorts?: readonly number[];
  readonly allowedCidrs?: readonly string[];
  readonly blockedCidrs?: readonly string[];
  readonly blockedHosts?: readonly string[];
  readonly requireResolution?: boolean;
  readonly resolver?:
    | OpenPlatformWebhookEndpointResolver
    | OpenPlatformWebhookEndpointResolverFunction;
  readonly resolutionTimeoutMs?: number;
}

export interface OpenPlatformWebhookEndpointTarget {
  readonly endpointUrl: string;
  readonly resolvedAddresses?: readonly string[];
}

export interface OpenPlatformWebhookEndpointContext {
  readonly production: boolean;
  readonly policy?: OpenPlatformWebhookEndpointPolicy;
}

export class OpenPlatformWebhookEndpointRejectedError extends Error {
  readonly reason: string;

  constructor(reason: string) {
    super("Webhook endpoint URL is not allowed");
    this.name = "OpenPlatformWebhookEndpointRejectedError";
    this.reason = reason;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class OpenPlatformWebhookEndpointUnresolvedError extends Error {
  readonly hostname: string;

  constructor(hostname: string) {
    super("Webhook endpoint host could not be resolved");
    this.name = "OpenPlatformWebhookEndpointUnresolvedError";
    this.hostname = hostname;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export interface OpenPlatformWebhookTransportRequest {
  readonly url: string;
  readonly endpointUrl?: string;
  readonly method: "POST";
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
  readonly payload?: string;
  readonly signal?: AbortSignal;
  readonly resolvedAddresses?: readonly string[];
}

export interface OpenPlatformWebhookTransportResponse {
  readonly statusCode?: number;
  readonly status?: number;
  readonly body?: string;
  readonly headers?: Readonly<Record<string, string>>;
}

export interface OpenPlatformWebhookTransport {
  readonly productionReady?: boolean;
  send?(request: OpenPlatformWebhookTransportRequest): MaybePromise<OpenPlatformWebhookTransportResponse>;
  deliver?(request: OpenPlatformWebhookTransportRequest): MaybePromise<OpenPlatformWebhookTransportResponse>;
  request?(request: OpenPlatformWebhookTransportRequest): MaybePromise<OpenPlatformWebhookTransportResponse>;
}

export type OpenPlatformWebhookTransportFunction = (
  request: OpenPlatformWebhookTransportRequest,
) => MaybePromise<OpenPlatformWebhookTransportResponse>;

export interface OpenPlatformWebhookRepository extends TenantScopedRepository<OpenPlatformWebhook> {}

export interface OpenPlatformWebhookPort extends OpenPlatformWebhookRepository {
  readonly productionReady?: boolean;
  readonly readiness?: OpenPlatformDependencyReadiness;
  isReady?(): MaybePromise<boolean>;
  rotateSecret?(record: OpenPlatformWebhook): Promise<OpenPlatformWebhook>;
}

export interface OpenPlatformWebhookDeliveryClaimRequest {
  readonly tenantId: string;
  readonly id: string;
  readonly attempt: number;
  readonly leaseId: string;
  readonly now: string;
  readonly leaseExpiresAt: string;
}

export interface OpenPlatformWebhookDeliveryClaimResult {
  readonly claimed: boolean;
  readonly delivery?: OpenPlatformWebhookDelivery;
}

export interface OpenPlatformWebhookDeliveryPort {
  readonly productionReady?: boolean;
  readonly readiness?: OpenPlatformDependencyReadiness;
  isReady?(): MaybePromise<boolean>;
  append(record: OpenPlatformWebhookDelivery): Promise<OpenPlatformWebhookDelivery>;
  get(tenantId: string, id: string): Promise<OpenPlatformWebhookDelivery | undefined>;
  list(query: OpenPlatformWebhookDeliveryQuery): Promise<OpenPlatformWebhookDeliveryPage>;
  update?(tenantId: string, id: string, patch: Partial<OpenPlatformWebhookDelivery>): Promise<OpenPlatformWebhookDelivery>;
  findByEvent?(tenantId: string, webhookId: string, eventId: string): Promise<OpenPlatformWebhookDelivery | undefined>;
  claim?(
    request: OpenPlatformWebhookDeliveryClaimRequest,
  ): Promise<OpenPlatformWebhookDeliveryClaimResult>;
}

export interface OpenPlatformWebhookDispatchResult {
  readonly delivery: OpenPlatformWebhookDelivery;
  readonly deliveries: readonly OpenPlatformWebhookDelivery[];
  readonly attempts: number;
  readonly duplicate: boolean;
  readonly deadLettered: boolean;
}

export interface OpenPlatformWebhookEventDispatchResult {
  readonly eventId: string;
  readonly eventType: string;
  readonly tenantId: string;
  readonly deliveries: readonly OpenPlatformWebhookDelivery[];
  readonly webhooks: number;
  readonly deadLettered: number;
}

export interface OpenPlatformWebhookAuditSubject {
  readonly tenantId: string;
  readonly actorId: string;
  readonly requestId: string;
}

export type NormalizedOpenPlatformWebhookEventEnvelope =
  Required<
    Pick<
      OpenPlatformWebhookEventEnvelope,
      "eventId" | "eventType" | "occurredAt" | "tenantId" | "schemaVersion"
    >
  > &
  Omit<
    OpenPlatformWebhookEventEnvelope,
    "eventId" | "eventType" | "type" | "occurredAt" | "tenantId" | "schemaVersion"
  >;

export interface OpenPlatformWebhookServiceOptions {
  readonly mode?: OpenPlatformRuntimeMode;
  readonly authorization: OpenPlatformAuthorizationPort;
  readonly webhooks: OpenPlatformWebhookPort;
  readonly deliveries: OpenPlatformWebhookDeliveryPort;
  readonly secretProvider: OpenPlatformWebhookSecretPort;
  readonly transport?: OpenPlatformWebhookTransport | OpenPlatformWebhookTransportFunction;
  readonly audit?: OpenPlatformAuditPort;
  readonly auditEnabled?: boolean;
  readonly auditDeniedEnabled?: boolean;
  readonly clock?: () => Date;
  readonly idGenerator?: (kind: OpenPlatformEntityKind) => string;
  readonly sleep?: (milliseconds: number) => Promise<void>;
  readonly maxAttempts?: number;
  readonly maxRetries?: number;
  readonly baseDelayMs?: number;
  readonly maxDelayMs?: number;
  readonly timestampToleranceSeconds?: number;
  readonly endpointPolicy?: OpenPlatformWebhookEndpointPolicy;
  readonly deliveryLeaseMs?: number;
}

export interface InMemoryOpenPlatformWebhookSecretProviderOptions {
  readonly clock?: () => Date;
  readonly production?: boolean;
}

export class InMemoryOpenPlatformWebhookRepository implements OpenPlatformWebhookPort {
  readonly productionReady = false;
  readonly readiness: OpenPlatformDependencyReadiness = Object.freeze({
    storage: "memory" as const,
    distributed: false,
    ready: () => true,
  });
  private readonly records = new Map<string, OpenPlatformWebhook>();

  async isReady(): Promise<boolean> {
    return true;
  }

  async create(record: OpenPlatformWebhook): Promise<OpenPlatformWebhook> {
    const normalized = normalizeWebhookRecord(record);
    if (this.records.has(normalized.id)) throw resourceConflict("Webhook already exists");
    this.records.set(normalized.id, structuredClone(normalized));
    return structuredClone(normalized);
  }

  async get(tenantId: string, id: string): Promise<OpenPlatformWebhook | undefined> {
    const record = this.records.get(requireId(id, "webhookId"));
    return record === undefined || record.tenantId !== normalizeTenantKey(tenantId)
      ? undefined
      : structuredClone(record);
  }

  async list(tenantId: string): Promise<OpenPlatformWebhook[]> {
    const normalizedTenantId = normalizeTenantKey(tenantId);
    return [...this.records.values()]
      .filter((record) => record.tenantId === normalizedTenantId)
      .sort(compareWebhooks)
      .map((record) => structuredClone(record));
  }

  async save(record: OpenPlatformWebhook): Promise<OpenPlatformWebhook> {
    const normalized = normalizeWebhookRecord(record);
    const current = this.records.get(normalized.id);
    if (current === undefined || current.tenantId !== normalized.tenantId) throw resourceNotFound("webhook");
    if (normalized.version !== current.version + 1) throw resourceConflict("Webhook version is stale");
    if (normalized.kind !== current.kind || normalized.createdAt !== current.createdAt) {
      throw resourceConflict("Webhook identity is immutable");
    }
    this.records.set(normalized.id, structuredClone(normalized));
    return structuredClone(normalized);
  }

  async snapshot(tenantId: string): Promise<OpenPlatformWebhook[]> {
    return this.list(tenantId);
  }
}

export class InMemoryOpenPlatformWebhookDeliveryRepository implements OpenPlatformWebhookDeliveryPort {
  readonly productionReady = false;
  readonly readiness: OpenPlatformDependencyReadiness = Object.freeze({
    storage: "memory" as const,
    distributed: false,
    ready: () => true,
  });
  private readonly records = new Map<string, OpenPlatformWebhookDelivery>();

  async isReady(): Promise<boolean> {
    return true;
  }

  async append(record: OpenPlatformWebhookDelivery): Promise<OpenPlatformWebhookDelivery> {
    const normalized = normalizeDeliveryRecord(record);
    if ([...this.records.values()].some((candidate) =>
      candidate.tenantId === normalized.tenantId &&
      candidate.webhookId === normalized.webhookId &&
      candidate.eventId === normalized.eventId
    )) {
      throw resourceConflict("Webhook event has already been recorded");
    }
    this.records.set(normalized.id, structuredClone(normalized));
    return structuredClone(normalized);
  }

  async get(tenantId: string, id: string): Promise<OpenPlatformWebhookDelivery | undefined> {
    const record = this.records.get(requireId(id, "deliveryId"));
    return record === undefined || record.tenantId !== normalizeTenantKey(tenantId)
      ? undefined
      : structuredClone(record);
  }

  async list(query: OpenPlatformWebhookDeliveryQuery): Promise<OpenPlatformWebhookDeliveryPage> {
    const tenantId = normalizeTenantKey(query.tenantId);
    const limit = normalizeLimit(query.limit);
    const all = [...this.records.values()]
      .filter((record) =>
        record.tenantId === tenantId &&
        (query.webhookId === undefined || record.webhookId === query.webhookId) &&
        (query.eventId === undefined || record.eventId === query.eventId) &&
        (query.status === undefined || record.status === query.status)
      )
      .sort((left, right) => compareStrings(left.createdAt, right.createdAt) || compareStrings(left.id, right.id));
    const start = query.cursor === undefined ? 0 : decodeDeliveryCursor(query.cursor, tenantId);
    const filtered = all.slice(start);
    const items = filtered.slice(0, limit).map((record) => structuredClone(record));
    const hasMore = filtered.length > limit;
    const last = items.at(-1);
    const nextCursor = hasMore && last !== undefined
      ? encodeDeliveryCursor(tenantId, all.indexOf(last) + 1)
      : undefined;
    return {
      items,
      ...(nextCursor === undefined ? {} : { nextCursor }),
      hasMore,
    };
  }

  async update(
    tenantId: string,
    id: string,
    patch: Partial<OpenPlatformWebhookDelivery>,
  ): Promise<OpenPlatformWebhookDelivery> {
    const normalizedTenantId = normalizeTenantKey(tenantId);
    const current = this.records.get(requireId(id, "deliveryId"));
    if (current === undefined || current.tenantId !== normalizedTenantId) throw resourceNotFound("webhookDelivery");
    const next = normalizeDeliveryRecord({ ...current, ...patch, tenantId: current.tenantId, id: current.id, webhookId: current.webhookId, eventId: current.eventId, createdAt: current.createdAt });
    this.records.set(next.id, structuredClone(next));
    return structuredClone(next);
  }

  async findByEvent(tenantId: string, webhookId: string, eventId: string): Promise<OpenPlatformWebhookDelivery | undefined> {
    const normalizedTenantId = normalizeTenantKey(tenantId);
    const record = [...this.records.values()].find((candidate) =>
      candidate.tenantId === normalizedTenantId &&
      candidate.webhookId === webhookId &&
      candidate.eventId === eventId
    );
    return record === undefined ? undefined : structuredClone(record);
  }

  async claim(
    request: OpenPlatformWebhookDeliveryClaimRequest,
  ): Promise<OpenPlatformWebhookDeliveryClaimResult> {
    const normalized = normalizeDeliveryClaim(request);
    const current = this.records.get(normalized.id);
    if (current === undefined || current.tenantId !== normalized.tenantId) {
      return { claimed: false };
    }
    const now = Date.parse(normalized.now);
    if (
      current.status === "succeeded" ||
      current.status === "dead_lettered" ||
      current.status === "delivering" && !isExpiredLease(current.leaseExpiresAt, now)
    ) {
      return { claimed: false };
    }
    const claimed = normalizeDeliveryRecord({
      ...current,
      status: "delivering",
      attempt: Math.max(current.attempt, normalized.attempt),
      leaseId: normalized.leaseId,
      leaseExpiresAt: normalized.leaseExpiresAt,
      updatedAt: normalized.now,
    });
    this.records.set(claimed.id, structuredClone(claimed));
    return { claimed: true, delivery: structuredClone(claimed) };
  }

  snapshot(tenantId: string): OpenPlatformWebhookDelivery[] {
    return [...this.records.values()]
      .filter((record) => record.tenantId === normalizeTenantKey(tenantId))
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt) || left.id.localeCompare(right.id))
      .map((record) => structuredClone(record));
  }
}

export class InMemoryOpenPlatformWebhookSecretProvider implements OpenPlatformWebhookSecretPort {
  readonly productionReady = false;
  readonly readiness: OpenPlatformDependencyReadiness;
  private readonly secrets = new Map<string, string>();

  constructor(options: InMemoryOpenPlatformWebhookSecretProviderOptions = {}) {
    this.readiness = Object.freeze({
      storage: "memory" as const,
      distributed: false,
      ready: () => options.production !== true,
    });
  }

  async issue(input: {
    readonly tenantId: string;
    readonly webhookId: string;
    readonly version: number;
    readonly reason: "create" | "rotate";
  }): Promise<OpenPlatformWebhookSecretMaterial> {
    const secret = randomBytes(32).toString("base64url");
    this.secrets.set(secretKey(input.tenantId, input.webhookId, input.version), secret);
    return {
      secret,
      reference: `vault://open-platform/webhook/${input.webhookId}/${input.version}`,
      version: input.version,
    };
  }

  async rotate(input: {
    readonly tenantId: string;
    readonly webhookId: string;
    readonly version: number;
    readonly previousVersion: number;
  }): Promise<OpenPlatformWebhookSecretMaterial> {
    return this.issue({ ...input, reason: "rotate" });
  }

  async resolve(input: {
    readonly tenantId: string;
    readonly webhookId: string;
    readonly version: number;
  }): Promise<string | undefined> {
    return this.secrets.get(secretKey(input.tenantId, input.webhookId, input.version));
  }
}

export const InMemoryOpenPlatformWebhookSecretStore = InMemoryOpenPlatformWebhookSecretProvider;
export const InMemoryOpenPlatformWebhookRepositoryStore = InMemoryOpenPlatformWebhookRepository;
export const InMemoryOpenPlatformWebhookDeliveryStore = InMemoryOpenPlatformWebhookDeliveryRepository;

export function createInMemoryOpenPlatformWebhookRepository(): InMemoryOpenPlatformWebhookRepository {
  return new InMemoryOpenPlatformWebhookRepository();
}

export function createInMemoryOpenPlatformWebhookDeliveryRepository(): InMemoryOpenPlatformWebhookDeliveryRepository {
  return new InMemoryOpenPlatformWebhookDeliveryRepository();
}

export function createInMemoryOpenPlatformWebhookSecretProvider(): InMemoryOpenPlatformWebhookSecretProvider {
  return new InMemoryOpenPlatformWebhookSecretProvider();
}

export class OpenPlatformWebhookService {
  readonly mode: OpenPlatformRuntimeMode;
  private readonly authorization: OpenPlatformAuthorizationPort;
  private readonly webhooks: OpenPlatformWebhookPort;
  private readonly deliveries: OpenPlatformWebhookDeliveryPort;
  private readonly secretProvider: OpenPlatformWebhookSecretPort;
  private readonly transport: OpenPlatformWebhookTransport | OpenPlatformWebhookTransportFunction | undefined;
  private readonly audit: OpenPlatformAuditPort;
  private readonly auditEnabled: boolean;
  private readonly auditDeniedEnabled: boolean;
  private readonly clock: () => Date;
  private readonly idGenerator: (kind: OpenPlatformEntityKind) => string;
  private readonly sleep: (milliseconds: number) => Promise<void>;
  private readonly maxAttempts: number;
  private readonly baseDelayMs: number;
  private readonly maxDelayMs: number;
  private readonly timestampToleranceSeconds: number;
  private readonly endpoint: ResolvedOpenPlatformWebhookEndpointContext;
  private readonly deliveryLeaseMs: number;
  private readonly localSecrets = new Map<string, string>();
  private readonly commandCache = new Map<string, { hash: string; value: unknown }>();

  constructor(options: OpenPlatformWebhookServiceOptions) {
    if (options === null || typeof options !== "object") throw configurationError("Webhook service configuration is required");
    if (options.authorization === null || typeof options.authorization.authorize !== "function") {
      throw configurationError("Webhook authorization is required");
    }
    if (options.webhooks === null || typeof options.webhooks !== "object" || typeof options.webhooks.create !== "function") {
      throw configurationError("Webhook repository is required");
    }
    if (options.deliveries === null || typeof options.deliveries !== "object" || typeof options.deliveries.append !== "function") {
      throw configurationError("Webhook delivery repository is required");
    }
    if (options.secretProvider === null || typeof options.secretProvider !== "object" ||
      (typeof options.secretProvider.issue !== "function" && typeof options.secretProvider.create !== "function")) {
      throw configurationError("Webhook secret provider is required");
    }
    this.mode = options.mode ?? "test";
    if (this.mode !== "development" && this.mode !== "test" && this.mode !== "production") {
      throw configurationError("Webhook runtime mode is invalid");
    }
    if (this.mode === "production" && (!options.authorization.productionReady || isDevelopmentOpenPlatformAuthorization(options.authorization))) {
      throw configurationError("Production webhook authorization is invalid");
    }
    if (options.transport !== undefined && options.transport !== null && typeof options.transport !== "function") {
      const transport = options.transport as OpenPlatformWebhookTransport;
      if (typeof transport.send !== "function" && typeof transport.deliver !== "function" && typeof transport.request !== "function") {
        throw configurationError("Webhook transport is invalid");
      }
    }
    this.authorization = options.authorization;
    this.webhooks = options.webhooks;
    this.deliveries = options.deliveries;
    this.secretProvider = options.secretProvider;
    this.transport = options.transport;
    this.audit = options.audit ?? new InMemoryOpenPlatformAuditEventStore({ clock: options.clock, production: options.mode === "production" });
    this.auditEnabled = options.auditEnabled !== false;
    this.auditDeniedEnabled = options.auditDeniedEnabled !== false;
    this.clock = options.clock ?? (() => new Date());
    this.idGenerator = options.idGenerator ?? ((kind) => `${kind}_${randomUUID()}`);
    this.sleep = options.sleep ?? ((milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)));
    this.maxAttempts = normalizeMaxAttempts(options.maxAttempts ?? (options.maxRetries === undefined ? undefined : options.maxRetries + 1));
    this.baseDelayMs = normalizeDelay(options.baseDelayMs ?? 1000, "baseDelayMs");
    this.maxDelayMs = normalizeDelay(options.maxDelayMs ?? 60_000, "maxDelayMs");
    if (this.maxDelayMs < this.baseDelayMs) throw configurationError("Webhook retry delay is invalid");
    this.timestampToleranceSeconds = normalizeTolerance(options.timestampToleranceSeconds ?? 300);
    this.endpoint = normalizeEndpointContext({
      production: this.mode === "production",
      ...(options.endpointPolicy === undefined ? {} : { policy: options.endpointPolicy }),
    });
    this.deliveryLeaseMs = normalizeLeaseDuration(options.deliveryLeaseMs ?? 30_000);
  }

  async isReady(): Promise<boolean> {
    const auditReady = this.audit.readiness === undefined || await safeReady(this.audit.readiness);
    const secretReady = this.secretProvider.readiness === undefined || await safeReady(this.secretProvider.readiness);
    const secretResolverReady = this.mode !== "production" || this.canResolveSecrets();
    const transportReady = this.mode !== "production" || this.isProductionTransportReady();
    const webhookRepositoryReady = this.mode !== "production" || await isRepositoryReady(this.webhooks);
    const deliveryRepositoryReady = this.mode !== "production" || await isRepositoryReady(this.deliveries);
    const deliveryClaimReady = this.mode !== "production" || typeof this.deliveries.claim === "function";
    const productionShape = this.mode !== "production" ||
      (this.authorization.productionReady === true && this.audit.productionReady === true && this.secretProvider.productionReady === true);
    return auditReady &&
      secretReady &&
      secretResolverReady &&
      transportReady &&
      webhookRepositoryReady &&
      deliveryRepositoryReady &&
      deliveryClaimReady &&
      productionShape;
  }

  private canResolveSecrets(): boolean {
    return typeof this.secretProvider.resolve === "function" || typeof this.secretProvider.get === "function";
  }

  private isProductionTransportReady(): boolean {
    if (this.transport === undefined || this.transport === null) return false;
    if (typeof this.transport === "function") return false;
    return this.transport.productionReady === true;
  }

  async listWebhooks(
    context: OpenPlatformRequestContext,
    query: OpenPlatformWebhookQuery,
  ): Promise<OpenPlatformWebhookPage> {
    const actor = await this.authorize(context, query.tenantId, "read", "webhook", query.id);
    const limit = normalizeLimit(query.limit);
    const records = (await this.webhooks.list(actor.tenantId)).filter((record) =>
      (query.id === undefined || record.id === query.id) &&
      (query.status === undefined || record.status === query.status) &&
      (query.applicationId === undefined || record.applicationId === query.applicationId) &&
      (query.environmentId === undefined || record.environmentId === query.environmentId)
    );
    const start = query.cursor === undefined ? 0 : decodeCursor(query.cursor, actor.tenantId);
    const items = records.slice(start, start + limit);
    const hasMore = records.length > start + limit;
    const last = items.at(-1);
    const nextCursor = hasMore && last !== undefined
      ? encodeCursor(actor.tenantId, start + limit)
      : undefined;
    return {
      items: items.map((record) => structuredClone(record)),
      ...(nextCursor === undefined ? {} : { nextCursor }),
      hasMore,
    };
  }

  async getWebhook(
    context: OpenPlatformRequestContext,
    query: OpenPlatformWebhookQuery & { id: string },
  ): Promise<OpenPlatformWebhook> {
    const actor = await this.authorize(context, query.tenantId, "read", "webhook", query.id);
    return this.requireWebhook(actor.tenantId, query.id);
  }

  async createWebhook(
    context: OpenPlatformRequestContext,
    command: {
      readonly tenantId: string;
      readonly developerOrganizationId?: string;
      readonly applicationId: string;
      readonly environmentId: string;
      readonly name: string;
      readonly endpointUrl: string;
      readonly events: readonly string[];
      readonly idempotencyKey: string;
    },
  ): Promise<OpenPlatformWebhookSecretResult> {
    const normalized = normalizeCreateCommand(command, this.endpoint);
    const actor = await this.authorize(context, normalized.tenantId, "create", "webhook");
    const cached = this.commandReplay<OpenPlatformWebhookSecretResult>(actor, "webhook.create", normalized.idempotencyKey, normalized);
    if (cached !== undefined) return { ...cached, secret: "", replayed: true };
    const endpointUrl = await this.resolveEndpoint(normalized.endpointUrl);
    const id = this.newId();
    const version = 1;
    let material: OpenPlatformWebhookSecretMaterial;
    try {
      material = await this.issueSecret({ tenantId: actor.tenantId, webhookId: id, version, reason: "create" });
    } catch {
      throw configurationError("Webhook secret could not be issued");
    }
    const secret = requireSecret(material.secret ?? material.value);
    this.localSecrets.set(secretKey(actor.tenantId, id, version), secret);
    const timestamp = this.timestamp();
    const record: OpenPlatformWebhook = {
      id,
      tenantId: actor.tenantId,
      kind: "webhook",
      developerOrganizationId: normalized.developerOrganizationId ?? "organization-unassigned",
      applicationId: normalized.applicationId,
      environmentId: normalized.environmentId,
      name: normalized.name,
      endpointUrl,
      status: "active",
      events: normalized.events,
      signingAlgorithm: OPEN_PLATFORM_WEBHOOK_SIGNATURE_ALGORITHM,
      signingSecretReference: normalizeSecretReference(
        material.reference ?? material.secretReference ?? `vault://open-platform/webhook/${id}/${version}`,
        secret,
      ),
      secretVersion: version,
      failureCount: 0,
      version: 1,
      createdAt: timestamp,
      updatedAt: timestamp,
    };
    const webhook = await this.webhooks.create(record);
    await this.auditSuccess(actor, "webhook.create", webhook, { version });
    const result = { webhook: structuredClone(webhook), secret, secretVersion: version, replayed: false };
    this.rememberCommand(actor, "webhook.create", normalized.idempotencyKey, normalized, {
      ...result,
      webhook: projectWebhookRecord(result.webhook),
      secret: "",
    });
    return result;
  }

  async pauseWebhook(context: OpenPlatformRequestContext, command: { tenantId: string; webhookId: string; idempotencyKey: string }): Promise<OpenPlatformWebhook> {
    return this.transition(context, command, "paused", "webhook.pause");
  }

  async disableWebhook(context: OpenPlatformRequestContext, command: { tenantId: string; webhookId: string; idempotencyKey: string }): Promise<OpenPlatformWebhook> {
    return this.transition(context, command, "disabled", "webhook.disable");
  }

  async resumeWebhook(context: OpenPlatformRequestContext, command: { tenantId: string; webhookId: string; idempotencyKey: string }): Promise<OpenPlatformWebhook> {
    return this.transition(context, command, "active", "webhook.resume");
  }

  async rotateWebhookSecret(
    context: OpenPlatformRequestContext,
    command: { tenantId: string; webhookId: string; idempotencyKey: string },
  ): Promise<OpenPlatformWebhookSecretResult> {
    const tenantId = normalizeTenant(command.tenantId);
    const webhookId = requireId(command.webhookId, "webhookId");
    requireId(command.idempotencyKey, "idempotencyKey");
    const actor = await this.authorize(context, tenantId, "rotate", "webhook", webhookId);
    const cached = this.commandReplay<OpenPlatformWebhookSecretResult>(actor, "webhook.rotate_secret", command.idempotencyKey, command);
    if (cached !== undefined) return { ...cached, secret: "", replayed: true };
    const current = await this.requireWebhook(actor.tenantId, webhookId);
    const version = current.secretVersion + 1;
    let material: OpenPlatformWebhookSecretMaterial;
    try {
      material = this.secretProvider.rotate === undefined
        ? await this.issueSecret({ tenantId: actor.tenantId, webhookId, version, reason: "rotate" })
        : await this.secretProvider.rotate({ tenantId: actor.tenantId, webhookId, version, previousVersion: current.secretVersion });
    } catch {
      throw configurationError("Webhook secret could not be rotated");
    }
    const secret = requireSecret(material.secret ?? material.value);
    this.localSecrets.set(secretKey(actor.tenantId, webhookId, version), secret);
    const updated = await this.webhooks.save({
      ...current,
      signingSecretReference: normalizeSecretReference(
        material.reference ?? material.secretReference ?? `vault://open-platform/webhook/${webhookId}/${version}`,
        secret,
      ),
      secretVersion: version,
      version: current.version + 1,
      updatedAt: this.timestamp(),
    });
    await this.auditSuccess(actor, "webhook.rotate_secret", updated, { version });
    const result = { webhook: structuredClone(updated), secret, secretVersion: version, replayed: false };
    this.rememberCommand(actor, "webhook.rotate_secret", command.idempotencyKey, command, {
      ...result,
      webhook: projectWebhookRecord(result.webhook),
      secret: "",
    });
    return result;
  }

  async dispatchWebhookEvent(
    context: OpenPlatformRequestContext,
    command: {
      readonly tenantId: string;
      readonly webhookId: string;
      readonly event: OpenPlatformWebhookEventEnvelope;
      readonly idempotencyKey: string;
      readonly replay?: boolean;
    },
  ): Promise<OpenPlatformWebhookDispatchResult> {
    const tenantId = normalizeTenant(command.tenantId);
    const webhookId = requireId(command.webhookId, "webhookId");
    const event = normalizeEvent(command.event, tenantId, this.timestamp());
    requireId(command.idempotencyKey, "idempotencyKey");
    const actor = await this.authorize(context, tenantId, "record", "webhook", webhookId);
    const webhook = await this.requireWebhook(actor.tenantId, webhookId);
    const auditAction = command.replay === true ? "webhook.replay" : "webhook.dispatch";
    if (!webhook.events.includes(event.eventType)) {
      throw validationError("Webhook does not subscribe to this event", { field: "events" });
    }
    if (webhook.status !== "active") {
      throw resourceConflict("Webhook is not active");
    }
    const existing = this.deliveries.findByEvent === undefined
      ? (await this.deliveries.list({ tenantId: actor.tenantId, webhookId, eventId: event.eventId, limit: 1 })).items[0]
      : await this.deliveries.findByEvent(actor.tenantId, webhookId, event.eventId);
    return this.deliverEventToWebhook(webhook, event, {
      replay: command.replay === true,
      auditAction,
      subject: auditSubject(actor),
      ...(existing === undefined ? {} : { existing }),
    });
  }

  async dispatchDomainEvent(
    event: OpenPlatformOutboxRecord,
    options: { readonly replay?: boolean } = {},
  ): Promise<OpenPlatformWebhookEventDispatchResult> {
    if (!isOpenPlatformDomainEventRecord(event)) throw forbidden();
    const tenantId = normalizeTenant(event.tenantId);
    const envelope = toWebhookEventEnvelope(event);
    const webhooks = (await this.webhooks.list(tenantId)).filter((record) =>
      record.status === "active" && record.events.includes(event.eventType)
    );
    const subject: OpenPlatformWebhookAuditSubject = {
      tenantId,
      actorId: event.actorId ?? OPEN_PLATFORM_DOMAIN_EVENT_SYSTEM_ACTOR_ID,
      requestId: event.requestId ?? event.eventId,
    };
    const deliveries: OpenPlatformWebhookDelivery[] = [];
    let deadLettered = 0;
    for (const webhook of webhooks) {
      const result = await this.deliverEventToWebhook(webhook, envelope, {
        replay: options.replay === true,
        auditAction: "webhook.domain_event",
        subject,
      });
      deliveries.push(result.delivery);
      if (result.deadLettered) deadLettered += 1;
    }
    return {
      eventId: event.eventId,
      eventType: event.eventType,
      tenantId,
      deliveries,
      webhooks: webhooks.length,
      deadLettered,
    };
  }

  private async deliverEventToWebhook(
    webhook: OpenPlatformWebhook,
    event: NormalizedOpenPlatformWebhookEventEnvelope,
    options: {
      readonly replay: boolean;
      readonly auditAction: string;
      readonly subject: OpenPlatformWebhookAuditSubject;
      readonly existing?: OpenPlatformWebhookDelivery;
    },
  ): Promise<OpenPlatformWebhookDispatchResult> {
    const replay = options.replay;
    const existing = options.existing;
    const auditAction = options.auditAction;
    const subject = options.subject;
    const tenantId = subject.tenantId;
    if (webhook.tenantId !== tenantId) throw forbidden();
    if (existing !== undefined && !replay) {
      await this.auditSuccess(subject, auditAction, webhook, {
        eventId: event.eventId,
        attempts: existing.attempt,
        duplicate: true,
      });
      return {
        delivery: structuredClone(existing),
        deliveries: [structuredClone(existing)],
        attempts: existing.attempt,
        duplicate: true,
        deadLettered: existing.status === "dead_lettered",
      };
    }
    const payload = serializeWebhookEvent(event);
    const now = this.timestamp();
    let delivery: OpenPlatformWebhookDelivery;
    if (existing !== undefined && replay) {
      delivery = await this.updateDelivery(existing, {
        status: "pending",
        attempt: 0,
        maxAttempts: this.maxAttempts,
        payload,
        body: payload,
        secretVersion: webhook.secretVersion,
        nextAttemptAt: now,
        deliveredAt: undefined,
        responseStatusCode: undefined,
        responseBodyExcerpt: undefined,
        errorCode: undefined,
        updatedAt: now,
      });
    } else {
      try {
        delivery = await this.deliveries.append({
          id: this.newDeliveryId(),
          tenantId,
          webhookId: webhook.id,
          eventId: event.eventId,
          event: event.eventType,
          eventType: event.eventType,
          status: "pending",
          attempt: 0,
          maxAttempts: this.maxAttempts,
          idempotencyKey: event.eventId,
          payload,
          body: payload,
          secretVersion: webhook.secretVersion,
          createdAt: now,
          updatedAt: now,
          nextAttemptAt: now,
        });
      } catch (error) {
        if (!isOpenPlatformDomainError(error) || error.code !== "OPEN_PLATFORM_RESOURCE_CONFLICT") throw error;
        const raced = this.deliveries.findByEvent === undefined
          ? (await this.deliveries.list({ tenantId, webhookId: webhook.id, eventId: event.eventId, limit: 1 })).items[0]
          : await this.deliveries.findByEvent(tenantId, webhook.id, event.eventId);
        if (raced === undefined) throw error;
        return {
          delivery: structuredClone(raced),
          deliveries: [structuredClone(raced)],
          attempts: raced.attempt,
          duplicate: true,
          deadLettered: raced.status === "dead_lettered",
        };
      }
    }
    if (this.transport === undefined) throw configurationError("Webhook transport is required");
    let current = delivery;
    for (let attempt = 1; attempt <= this.maxAttempts; attempt += 1) {
      try {
        current = await this.deliverOnce(current, undefined, event, attempt);
      } catch (error) {
        if (!isDeliveryClaimConflict(error)) throw error;
        return {
          delivery: structuredClone(current),
          deliveries: [structuredClone(current)],
          attempts: current.attempt,
          duplicate: true,
          deadLettered: current.status === "dead_lettered",
        };
      }
      if (current.status === "succeeded") {
        await this.updateWebhookDeliveryState(webhook, 0, current.deliveredAt);
        await this.auditSuccess(subject, auditAction, webhook, {
          eventId: event.eventId,
          attempts: attempt,
          duplicate: false,
        });
        return { delivery: structuredClone(current), deliveries: [structuredClone(current)], attempts: attempt, duplicate: false, deadLettered: false };
      }
      if (current.status !== "failed" || attempt >= this.maxAttempts) break;
      await this.sleep(retryDelay(attempt, this.baseDelayMs, this.maxDelayMs));
    }
    const deadLettered = current.status === "dead_lettered" || current.attempt >= this.maxAttempts;
    if (deadLettered) await this.updateWebhookDeliveryState(webhook, current.attempt, undefined, "failing", current.nextAttemptAt);
    await this.auditSuccess(subject, auditAction, webhook, {
      eventId: event.eventId,
      attempts: current.attempt,
      deadLettered,
    });
    return { delivery: structuredClone(current), deliveries: [structuredClone(current)], attempts: current.attempt, duplicate: false, deadLettered };
  }

  async deliverOnce(
    deliveryOrId: OpenPlatformWebhookDelivery | string,
    context?: OpenPlatformRequestContext,
    event?: OpenPlatformWebhookEventEnvelope,
    attempt?: number,
  ): Promise<OpenPlatformWebhookDelivery> {
    const delivery = typeof deliveryOrId === "string"
      ? await this.deliveries.get(normalizeTenant(context?.tenantId ?? ""), deliveryOrId)
      : deliveryOrId;
    if (delivery === undefined) throw resourceNotFound("webhookDelivery");
    if (context !== undefined && (!isOpenPlatformRequestContext(context) || context.tenantId !== delivery.tenantId)) {
      throw forbidden();
    }
    if (delivery.status === "succeeded" || delivery.status === "dead_lettered") return structuredClone(delivery);
    if (this.transport === undefined) throw configurationError("Webhook transport is required");
    const webhook = await this.requireWebhook(delivery.tenantId, delivery.webhookId);
    if (webhook.status !== "active") throw resourceConflict("Webhook is not active");
    const normalizedEvent = normalizeEvent(event ?? JSON.parse(delivery.payload) as OpenPlatformWebhookEventEnvelope, delivery.tenantId);
    const claim = await this.claimDelivery(delivery, attempt);
    if (!claim.claimed) {
      throw resourceConflict("Webhook delivery is already claimed by another worker", { deliveryId: delivery.id });
    }
    const current = claim.delivery;
    let response: OpenPlatformWebhookTransportResponse;
    try {
      response = await this.send(webhook, current, normalizedEvent);
    } catch (error) {
      return this.finishAttempt(current, webhook, undefined, undefined, error);
    }
    const status = responseStatus(response);
    const body = responseBody(response);
    if (status !== undefined && status >= 200 && status < 300) {
      return this.finishAttempt(current, webhook, status, body);
    }
    return this.finishAttempt(current, webhook, status, body, status === undefined ? "TRANSPORT_ERROR" : `HTTP_${status}`);
  }

  async processDueDeliveries(
    context: OpenPlatformRequestContext,
    query: OpenPlatformWebhookDeliveryQuery,
  ): Promise<OpenPlatformWebhookDelivery[]> {
    const actor = await this.authorize(context, query.tenantId, "record", "webhook", query.webhookId);
    const page = await this.deliveries.list({ ...query, tenantId: actor.tenantId, limit: 100 });
    const now = Date.parse(this.timestamp());
    const due = page.items.filter((item) =>
      item.status === "pending" ||
      item.status === "failed" ||
      item.status === "delivering" && isExpiredLease(item.leaseExpiresAt, now)
    );
    const results: OpenPlatformWebhookDelivery[] = [];
    for (const item of due) {
      if (item.nextAttemptAt !== undefined && Date.parse(item.nextAttemptAt) > now) continue;
      const webhook = await this.requireWebhook(actor.tenantId, item.webhookId);
      if (webhook.status !== "active") continue;
      const event = JSON.parse(item.payload) as OpenPlatformWebhookEventEnvelope;
      let delivered: OpenPlatformWebhookDelivery;
      try {
        delivered = await this.deliverOnce(item, context, event);
      } catch (error) {
        if (isDeliveryClaimConflict(error)) continue;
        throw error;
      }
      if (delivered.status === "succeeded") {
        await this.updateWebhookDeliveryState(webhook, 0, delivered.deliveredAt);
      } else if (delivered.status === "dead_lettered") {
        await this.updateWebhookDeliveryState(webhook, delivered.attempt, undefined, "failing");
      }
      await this.auditSuccess(actor, "webhook.retry", webhook, {
        eventId: delivered.eventId,
        attempts: delivered.attempt,
        status: delivered.status,
      });
      results.push(delivered);
    }
    return results;
  }

  async replayDelivery(
    context: OpenPlatformRequestContext,
    command: { tenantId: string; webhookId: string; deliveryId: string; idempotencyKey: string },
  ): Promise<OpenPlatformWebhookDispatchResult> {
    const tenantId = normalizeTenant(command.tenantId);
    const webhookId = requireId(command.webhookId, "webhookId");
    const deliveryId = requireId(command.deliveryId, "deliveryId");
    requireId(command.idempotencyKey, "idempotencyKey");
    const actor = await this.authorize(context, tenantId, "record", "webhook", webhookId);
    const delivery = await this.deliveries.get(actor.tenantId, deliveryId);
    if (delivery === undefined || delivery.webhookId !== webhookId) throw resourceNotFound("webhookDelivery");
    const event = JSON.parse(delivery.payload) as OpenPlatformWebhookEventEnvelope;
    return this.dispatchWebhookEvent(actor, {
      tenantId: actor.tenantId,
      webhookId,
      event,
      idempotencyKey: command.idempotencyKey,
      replay: true,
    });
  }

  async listWebhookDeliveries(
    context: OpenPlatformRequestContext,
    query: OpenPlatformWebhookDeliveryQuery,
  ): Promise<OpenPlatformWebhookDeliveryPage> {
    const actor = await this.authorize(context, query.tenantId, "read", "webhook", query.webhookId);
    return this.deliveries.list({ ...query, tenantId: actor.tenantId });
  }

  async verifyWebhookSignature(input: {
    readonly body: string | Uint8Array;
    readonly signature: string;
    readonly timestamp: string | number;
    readonly secretVersion: number | string;
    readonly secret: string;
    readonly toleranceSeconds?: number;
    readonly now?: Date;
  }): Promise<boolean> {
    return verifyOpenPlatformWebhookSignature({
      ...input,
      toleranceSeconds: input.toleranceSeconds ?? this.timestampToleranceSeconds,
    });
  }

  async pause(context: OpenPlatformRequestContext, command: { tenantId: string; webhookId: string; idempotencyKey: string }): Promise<OpenPlatformWebhook> {
    return this.pauseWebhook(context, command);
  }

  async disable(context: OpenPlatformRequestContext, command: { tenantId: string; webhookId: string; idempotencyKey: string }): Promise<OpenPlatformWebhook> {
    return this.disableWebhook(context, command);
  }

  async resume(context: OpenPlatformRequestContext, command: { tenantId: string; webhookId: string; idempotencyKey: string }): Promise<OpenPlatformWebhook> {
    return this.resumeWebhook(context, command);
  }

  async rotateSecret(context: OpenPlatformRequestContext, command: { tenantId: string; webhookId: string; idempotencyKey: string }): Promise<OpenPlatformWebhookSecretResult> {
    return this.rotateWebhookSecret(context, command);
  }

  async deliver(context: OpenPlatformRequestContext, command: { tenantId: string; webhookId: string; event: OpenPlatformWebhookEventEnvelope; idempotencyKey: string; replay?: boolean }): Promise<OpenPlatformWebhookDispatchResult> {
    return this.dispatchWebhookEvent(context, command);
  }

  async enqueue(context: OpenPlatformRequestContext, command: { tenantId: string; webhookId: string; event: OpenPlatformWebhookEventEnvelope; idempotencyKey: string; replay?: boolean }): Promise<OpenPlatformWebhookDispatchResult> {
    return this.dispatchWebhookEvent(context, command);
  }

  async getDeliveries(context: OpenPlatformRequestContext, query: OpenPlatformWebhookDeliveryQuery): Promise<OpenPlatformWebhookDeliveryPage> {
    return this.listWebhookDeliveries(context, query);
  }

  private async transition(
    context: OpenPlatformRequestContext,
    command: { tenantId: string; webhookId: string; idempotencyKey: string },
    target: OpenPlatformWebhookStatus,
    action: string,
  ): Promise<OpenPlatformWebhook> {
    const tenantId = normalizeTenant(command.tenantId);
    const webhookId = requireId(command.webhookId, "webhookId");
    requireId(command.idempotencyKey, "idempotencyKey");
    const actor = await this.authorize(context, tenantId, "update", "webhook", webhookId);
    const cached = this.commandReplay<OpenPlatformWebhook>(actor, action, command.idempotencyKey, command);
    if (cached !== undefined) return structuredClone(cached);
    const current = await this.requireWebhook(actor.tenantId, webhookId);
    if (current.status === target) {
      this.rememberCommand(actor, action, command.idempotencyKey, command, current);
      return structuredClone(current);
    }
    const allowed = target === "paused"
      ? current.status === "active" || current.status === "failing"
      : target === "disabled"
        ? current.status === "active" || current.status === "paused" || current.status === "failing"
        : current.status === "paused" || current.status === "failing" || current.status === "disabled";
    if (!allowed) throw resourceConflict("Webhook state transition is not allowed");
    const updated = await this.webhooks.save({
      ...current,
      status: target,
      version: current.version + 1,
      updatedAt: this.timestamp(),
      ...(target === "active" ? { failureCount: 0, nextDeliveryAt: undefined } : {}),
    });
    await this.auditSuccess(actor, action, updated, { status: target });
    this.rememberCommand(actor, action, command.idempotencyKey, command, updated);
    return structuredClone(updated);
  }

  private commandReplay<T>(
    context: OpenPlatformRequestContext,
    operation: string,
    key: string,
    request: unknown,
  ): T | undefined {
    const cacheKey = [context.tenantId, context.actorId, operation, key].join("\u0000");
    const cached = this.commandCache.get(cacheKey);
    if (cached === undefined) return undefined;
    const hash = hashOpenPlatformIdempotencyRequest(request);
    if (cached.hash !== hash) throw idempotencyKeyReused();
    return structuredClone(cached.value) as T;
  }

  private rememberCommand(
    context: OpenPlatformRequestContext,
    operation: string,
    key: string,
    request: unknown,
    value: unknown,
  ): void {
    const cacheKey = [context.tenantId, context.actorId, operation, key].join("\u0000");
    this.commandCache.set(cacheKey, {
      hash: hashOpenPlatformIdempotencyRequest(request),
      value: structuredClone(value),
    });
  }

  private async authorize(
    contextValue: unknown,
    requestedTenantId: string,
    action: "create" | "read" | "update" | "rotate" | "record",
    resource: OpenPlatformEntityKind,
    resourceId?: string,
  ): Promise<OpenPlatformRequestContext> {
    if (!isOpenPlatformRequestContext(contextValue)) {
      throw forbidden();
    }
    const context = contextValue;
    if (context.tenantId !== requestedTenantId) {
      if (action !== "read") await this.auditDenied(context, `${resource}.${action}`, "unknown");
      throw forbidden();
    }
    let allowed = false;
    try {
      allowed = await this.authorization.authorize({ context, tenantId: context.tenantId, action, resource, ...(resourceId === undefined ? {} : { resourceId }) });
    } catch {
      allowed = false;
    }
    if (allowed !== true) {
      await this.auditDenied(context, `${resource}.${action}`, resourceId ?? "unknown");
      throw forbidden();
    }
    return context;
  }

  private async requireWebhook(tenantId: string, id: string): Promise<OpenPlatformWebhook> {
    const record = await this.webhooks.get(normalizeTenant(tenantId), requireId(id, "webhookId"));
    if (record === undefined) throw resourceNotFound("webhook");
    return record;
  }

  private async send(
    webhook: OpenPlatformWebhook,
    delivery: OpenPlatformWebhookDelivery,
    event: OpenPlatformWebhookEventEnvelope,
  ): Promise<OpenPlatformWebhookTransportResponse> {
    const target = await resolveResolvedEndpointTarget(webhook.endpointUrl, this.endpoint);
    const endpointUrl = target.endpointUrl;
    const secret = await this.resolveSecret(webhook, delivery.secretVersion);
    if (secret === undefined) throw new Error("Webhook secret version is unavailable");
    const timestamp = this.timestamp();
    const signature = signOpenPlatformWebhookPayload({
      timestamp,
      body: delivery.payload,
      secret,
      secretVersion: delivery.secretVersion,
    });
    const headers: Record<string, string> = {
      "content-type": "application/json",
      "user-agent": "getbrick-open-platform-webhook/1",
      [OPEN_PLATFORM_WEBHOOK_SIGNATURE_HEADER]: signature,
      [OPEN_PLATFORM_WEBHOOK_TIMESTAMP_HEADER]: timestamp,
      [OPEN_PLATFORM_WEBHOOK_SECRET_VERSION_HEADER]: String(delivery.secretVersion),
      [OPEN_PLATFORM_WEBHOOK_EVENT_ID_HEADER]: event.eventId!,
      [OPEN_PLATFORM_WEBHOOK_EVENT_TYPE_HEADER]: event.eventType!,
      [OPEN_PLATFORM_WEBHOOK_IDEMPOTENCY_HEADER]: event.eventId!,
      [OPEN_PLATFORM_WEBHOOK_OPEN_PLATFORM_SIGNATURE_HEADER]: signature,
      [OPEN_PLATFORM_WEBHOOK_OPEN_PLATFORM_TIMESTAMP_HEADER]: timestamp,
      [OPEN_PLATFORM_WEBHOOK_OPEN_PLATFORM_SECRET_VERSION_HEADER]: String(delivery.secretVersion),
    };
    const request: OpenPlatformWebhookTransportRequest = {
      url: endpointUrl,
      endpointUrl,
      method: "POST",
      headers,
      body: delivery.payload,
      payload: delivery.payload,
      ...(target.resolvedAddresses === undefined ? {} : { resolvedAddresses: target.resolvedAddresses }),
    };
    if (typeof this.transport === "function") return this.transport(request);
    if (this.transport?.send !== undefined) return this.transport.send(request);
    if (this.transport?.deliver !== undefined) return this.transport.deliver(request);
    if (this.transport?.request !== undefined) return this.transport.request(request);
    throw configurationError("Webhook transport is required");
  }

  private async issueSecret(input: {
    readonly tenantId: string;
    readonly webhookId: string;
    readonly version: number;
    readonly reason: "create" | "rotate";
  }): Promise<OpenPlatformWebhookSecretMaterial> {
    if (this.secretProvider.issue !== undefined) return this.secretProvider.issue(input);
    if (this.secretProvider.create !== undefined) return this.secretProvider.create(input);
    throw configurationError("Webhook secret provider cannot issue secrets");
  }

  private async resolveSecret(webhook: OpenPlatformWebhook, version: number): Promise<string | undefined> {
    const input = { tenantId: webhook.tenantId, webhookId: webhook.id, version };
    if (this.secretProvider.resolve !== undefined) return this.secretProvider.resolve(input);
    if (this.secretProvider.get !== undefined) return this.secretProvider.get(input);
    return this.localSecrets.get(secretKey(webhook.tenantId, webhook.id, version));
  }

  private async claimDelivery(
    delivery: OpenPlatformWebhookDelivery,
    attempt: number | undefined,
  ): Promise<{ claimed: boolean; delivery: OpenPlatformWebhookDelivery }> {
    const now = this.timestamp();
    const requested = attempt ?? (delivery.status === "delivering" ? delivery.attempt : delivery.attempt + 1);
    const normalizedAttempt = Math.min(Math.max(requested, delivery.attempt, 1), Math.max(delivery.maxAttempts, 1));
    if (this.deliveries.claim === undefined) {
      if (delivery.status === "delivering" && !isExpiredLease(delivery.leaseExpiresAt, Date.parse(now))) {
        return { claimed: false, delivery };
      }
      const current = await this.updateDelivery(delivery, {
        status: "delivering",
        attempt: normalizedAttempt,
        leaseId: `lease_${randomUUID()}`,
        leaseExpiresAt: leaseExpiry(now, this.deliveryLeaseMs),
        updatedAt: now,
      });
      return { claimed: true, delivery: current };
    }
    const result = await this.deliveries.claim({
      tenantId: delivery.tenantId,
      id: delivery.id,
      attempt: normalizedAttempt,
      leaseId: `lease_${randomUUID()}`,
      now,
      leaseExpiresAt: leaseExpiry(now, this.deliveryLeaseMs),
    });
    if (result.claimed !== true || result.delivery === undefined) {
      return { claimed: false, delivery: await this.deliveries.get(delivery.tenantId, delivery.id) ?? delivery };
    }
    return { claimed: true, delivery: result.delivery };
  }

  private async resolveEndpoint(value: unknown): Promise<string> {
    try {
      return await resolveResolvedEndpointTarget(value, this.endpoint).then((target) => target.endpointUrl);
    } catch (error) {
      if (error instanceof OpenPlatformWebhookEndpointRejectedError) {
        throw validationError("Webhook endpoint URL is not allowed", { field: "endpointUrl", reason: error.reason });
      }
      if (error instanceof OpenPlatformWebhookEndpointUnresolvedError) {
        throw validationError("Webhook endpoint URL could not be verified", { field: "endpointUrl" });
      }
      throw error;
    }
  }

  private async finishAttempt(
    current: OpenPlatformWebhookDelivery,
    webhook: OpenPlatformWebhook,
    responseStatusCode: number | undefined,
    responseBodyExcerpt: string | undefined,
    error?: unknown,
  ): Promise<OpenPlatformWebhookDelivery> {
    const code = typeof error === "string" ? error : error === undefined ? undefined : errorCode(error);
    const rejected = error instanceof OpenPlatformWebhookEndpointRejectedError;
    const succeeded = responseStatusCode !== undefined && responseStatusCode >= 200 && responseStatusCode < 300;
    const retryable = !rejected && (responseStatusCode === undefined || isRetryableWebhookStatus(responseStatusCode));
    const nextAttemptAt = succeeded
      ? undefined
      : new Date(Date.parse(this.timestamp()) + retryDelay(current.attempt, this.baseDelayMs, this.maxDelayMs)).toISOString();
    const status: OpenPlatformWebhookDeliveryStatus = succeeded
      ? "succeeded"
      : current.attempt >= this.maxAttempts || !retryable
        ? "dead_lettered"
        : "failed";
    return this.updateDelivery(current, {
      status,
      nextAttemptAt: status === "failed" ? nextAttemptAt : undefined,
      ...(succeeded ? { deliveredAt: this.timestamp() } : {}),
      ...(responseStatusCode === undefined ? {} : { responseStatusCode }),
      ...(responseBodyExcerpt === undefined ? {} : { responseBodyExcerpt: safeResponseExcerpt(responseBodyExcerpt) }),
      ...(succeeded || code === undefined ? { errorCode: undefined } : { errorCode: code }),
      leaseId: undefined,
      leaseExpiresAt: undefined,
      updatedAt: this.timestamp(),
    });
  }

  private async updateDelivery(
    delivery: OpenPlatformWebhookDelivery,
    patch: Partial<OpenPlatformWebhookDelivery>,
  ): Promise<OpenPlatformWebhookDelivery> {
    if (this.deliveries.update === undefined) {
      if (Object.keys(patch).length === 0) return structuredClone(delivery);
      throw configurationError("Webhook delivery repository is not mutable");
    }
    return this.deliveries.update(delivery.tenantId, delivery.id, patch);
  }

  private async updateWebhookDeliveryState(
    webhook: OpenPlatformWebhook,
    failureCount: number,
    deliveredAt?: string,
    status?: OpenPlatformWebhookStatus,
    nextDeliveryAt?: string,
  ): Promise<void> {
    await this.webhooks.save({
      ...webhook,
      ...(status === undefined ? {} : { status }),
      failureCount,
      ...(deliveredAt === undefined ? {} : { lastDeliveryAt: deliveredAt, nextDeliveryAt: undefined }),
      ...(nextDeliveryAt === undefined ? {} : { nextDeliveryAt }),
      version: webhook.version + 1,
      updatedAt: this.timestamp(),
    });
  }

  private async auditSuccess(
    subject: OpenPlatformWebhookAuditSubject,
    action: string,
    webhook: OpenPlatformWebhook,
    metadata: Readonly<Record<string, string | number | boolean | null>>,
  ): Promise<void> {
    if (!this.auditEnabled) return;
    await this.audit.append({
      tenantId: subject.tenantId,
      action,
      outcome: "success",
      actor: { type: "user", id: subject.actorId },
      target: { type: "webhook", id: webhook.id },
      requestId: subject.requestId,
      metadata,
      source: "open-platform",
    });
  }

  private async auditDenied(
    subject: OpenPlatformWebhookAuditSubject,
    action: string,
    targetId: string,
  ): Promise<void> {
    if (!this.auditDeniedEnabled || action.endsWith(".read")) return;
    try {
      await this.audit.append({
        tenantId: subject.tenantId,
        action,
        outcome: "denied",
        actor: { type: "user", id: subject.actorId },
        target: { type: "webhook", id: targetId },
        requestId: subject.requestId,
        metadata: { source: "authorization" },
        source: "open-platform",
      });
    } catch {
      return;
    }
  }

  private newId(): string {
    return normalizeGeneratedId(this.idGenerator("webhook"), "webhook");
  }

  private newDeliveryId(): string {
    return `delivery_${randomUUID()}`;
  }

  private timestamp(): string {
    const value = this.clock();
    if (!(value instanceof Date) || !Number.isFinite(value.getTime())) throw configurationError("Webhook clock is invalid");
    return value.toISOString();
  }
}

export function createOpenPlatformWebhookService(options: OpenPlatformWebhookServiceOptions): OpenPlatformWebhookService {
  return new OpenPlatformWebhookService(options);
}

export const createOpenPlatformWebhookSubscription = createOpenPlatformWebhookService;

export function toOpenPlatformWebhookDto(webhook: OpenPlatformWebhook): Omit<OpenPlatformWebhook, "signingSecretReference"> {
  const { signingSecretReference: _signingSecretReference, ...dto } = webhook;
  return { ...dto, events: [...dto.events] };
}

export function signOpenPlatformWebhookPayload(input: {
  readonly timestamp: string | number;
  readonly body: string | Uint8Array;
  readonly secret: string;
  readonly secretVersion: number | string;
}): string {
  const timestamp = normalizeSignatureTimestamp(input.timestamp);
  const body = typeof input.body === "string" ? input.body : Buffer.from(input.body).toString("utf8");
  const version = normalizeSecretVersion(input.secretVersion);
  const secret = requireSecret(input.secret);
  const digest = createHmac("sha256", secret)
    .update(createOpenPlatformWebhookSigningPayload({ timestamp, body, secretVersion: version }), "utf8")
    .digest("hex");
  return `${OPEN_PLATFORM_WEBHOOK_SIGNATURE_VERSION}=${digest}`;
}

export const createOpenPlatformWebhookSignature = signOpenPlatformWebhookPayload;
export const createWebhookSignature = signOpenPlatformWebhookPayload;

export function createOpenPlatformWebhookSigningPayload(input: {
  readonly timestamp: string | number;
  readonly body: string | Uint8Array;
  readonly secretVersion: number | string;
}): string {
  const timestamp = normalizeSignatureTimestamp(input.timestamp);
  const body = typeof input.body === "string" ? input.body : Buffer.from(input.body).toString("utf8");
  return `${timestamp}.${normalizeSecretVersion(input.secretVersion)}.${body}`;
}

export function verifyOpenPlatformWebhookSignature(input: {
  readonly body: string | Uint8Array;
  readonly signature: string;
  readonly timestamp: string | number;
  readonly secretVersion: number | string;
  readonly secret: string;
  readonly toleranceSeconds?: number;
  readonly now?: Date;
}): boolean {
  try {
    const timestamp = normalizeSignatureTimestamp(input.timestamp);
    const tolerance = normalizeTolerance(input.toleranceSeconds ?? 300);
    const now = input.now ?? new Date();
    if (!(now instanceof Date) || !Number.isFinite(now.getTime())) return false;
    if (Math.abs(now.getTime() - Date.parse(timestamp)) > tolerance * 1000) return false;
    const expected = signOpenPlatformWebhookPayload({
      timestamp,
      body: input.body,
      secret: input.secret,
      secretVersion: input.secretVersion,
    });
    const candidates = parseSignatureCandidates(input.signature);
    if (candidates.length === 0) return false;
    const expectedBytes = Buffer.from(expected, "utf8");
    let valid = false;
    for (const candidate of candidates) {
      const candidateBytes = Buffer.from(candidate, "utf8");
      valid = (expectedBytes.length === candidateBytes.length && timingSafeEqual(expectedBytes, candidateBytes)) || valid;
    }
    return valid;
  } catch {
    return false;
  }
}

export function verifyOpenPlatformWebhookHeaders(input: {
  readonly headers: Headers | Record<string, string | string[] | undefined>;
  readonly body: string | Uint8Array;
  readonly secret: string;
  readonly toleranceSeconds?: number;
  readonly now?: Date;
}): boolean {
  const signature = webhookHeader(input.headers, OPEN_PLATFORM_WEBHOOK_SIGNATURE_HEADER);
  const timestamp = webhookHeader(input.headers, OPEN_PLATFORM_WEBHOOK_TIMESTAMP_HEADER);
  const secretVersion = webhookHeader(input.headers, OPEN_PLATFORM_WEBHOOK_SECRET_VERSION_HEADER);
  if (signature === undefined || timestamp === undefined || secretVersion === undefined) return false;
  return verifyOpenPlatformWebhookSignature({
    body: input.body,
    signature,
    timestamp,
    secretVersion,
    secret: input.secret,
    ...(input.toleranceSeconds === undefined ? {} : { toleranceSeconds: input.toleranceSeconds }),
    ...(input.now === undefined ? {} : { now: input.now }),
  });
}

export const verifyWebhookSignature = verifyOpenPlatformWebhookSignature;
export const OpenPlatformWebhookDispatcher = OpenPlatformWebhookService;
export const OpenPlatformWebhookDeliveryService = OpenPlatformWebhookService;
export const createOpenPlatformWebhookDispatcher = createOpenPlatformWebhookService;
export const createOpenPlatformWebhookDeliveryService = createOpenPlatformWebhookService;
export type OpenPlatformWebhookSubscriptionRepository = OpenPlatformWebhookRepository;
export type OpenPlatformWebhookDeliveryRepository = OpenPlatformWebhookDeliveryPort;
export type OpenPlatformWebhookSecretResolver = OpenPlatformWebhookSecretPort;
export type OpenPlatformWebhookTransportPort = OpenPlatformWebhookTransport;
export type OpenPlatformWebhookTransportFunctionPort = OpenPlatformWebhookTransportFunction;
export type OpenPlatformWebhookSubscriptionService = OpenPlatformWebhookService;
export type OpenPlatformWebhookDeliveryStore = OpenPlatformWebhookDeliveryPort;
export const createOpenPlatformWebhookSubscriptionService = createOpenPlatformWebhookService;

export function serializeWebhookEvent(event: OpenPlatformWebhookEventEnvelope): string {
  const normalized = normalizeEvent(event, event.tenantId);
  return JSON.stringify({
    event_id: normalized.eventId,
    event_type: normalized.eventType,
    occurred_at: normalized.occurredAt,
    tenant_id: normalized.tenantId,
    ...(normalized.actor === undefined ? {} : { actor: normalized.actor }),
    ...(normalized.resource === undefined ? {} : { resource: normalized.resource }),
    data: sanitizeWebhookData(normalized.data),
    schema_version: normalized.schemaVersion,
    ...(normalized.requestId === undefined ? {} : { request_id: normalized.requestId }),
    ...(normalized.traceId === undefined ? {} : { trace_id: normalized.traceId }),
  });
}

export function toWebhookEventEnvelope(
  event: OpenPlatformOutboxRecord,
): NormalizedOpenPlatformWebhookEventEnvelope {
  if (!isOpenPlatformDomainEventRecord(event)) throw forbidden();
  return normalizeEvent(
    {
      eventId: event.eventId,
      eventType: event.eventType,
      occurredAt: event.occurredAt,
      tenantId: event.tenantId,
      actor: {
        type: event.actorId === undefined ? "system" : "user",
        id: event.actorId ?? OPEN_PLATFORM_DOMAIN_EVENT_SYSTEM_ACTOR_ID,
      },
      resource: {
        type: event.resourceType,
        id: event.resourceId,
        ...(event.resourceVersion === undefined ? {} : { version: event.resourceVersion }),
        ...(event.resourceStatus === undefined ? {} : { status: event.resourceStatus }),
      },
      data: { ...event.data },
      schemaVersion: OPEN_PLATFORM_WEBHOOK_EVENT_SCHEMA_VERSION,
      ...(event.requestId === undefined ? {} : { requestId: event.requestId }),
    },
    event.tenantId,
    event.occurredAt,
  );
}

function auditSubject(
  context: OpenPlatformRequestContext,
): OpenPlatformWebhookAuditSubject {
  return {
    tenantId: context.tenantId,
    actorId: context.actorId,
    requestId: context.requestId,
  };
}

function normalizeCreateCommand(command: {
  readonly tenantId: string;
  readonly developerOrganizationId?: string;
  readonly applicationId: string;
  readonly environmentId: string;
  readonly name: string;
  readonly endpointUrl: string;
  readonly events: readonly string[];
  readonly idempotencyKey: string;
}, context: ResolvedOpenPlatformWebhookEndpointContext = normalizeEndpointContext({ production: false })): {
  tenantId: string;
  developerOrganizationId?: string;
  applicationId: string;
  environmentId: string;
  name: string;
  endpointUrl: string;
  events: string[];
  idempotencyKey: string;
} {
  if (command === null || typeof command !== "object") throw validationError("Webhook request is invalid");
  const events = normalizeEvents(command.events);
  return {
    tenantId: normalizeTenant(command.tenantId),
    ...(command.developerOrganizationId === undefined ? {} : { developerOrganizationId: requireId(command.developerOrganizationId, "developerOrganizationId") }),
    applicationId: requireId(command.applicationId, "applicationId"),
    environmentId: requireId(command.environmentId, "environmentId"),
    name: requireText(command.name, "name"),
    endpointUrl: requireEndpoint(command.endpointUrl, context),
    events,
    idempotencyKey: requireId(command.idempotencyKey, "idempotencyKey"),
  };
}

function normalizeWebhookRecord(record: OpenPlatformWebhook): OpenPlatformWebhook {
  if (record === null || typeof record !== "object" || record.kind !== "webhook") throw validationError("Webhook record is invalid");
  if (!Number.isSafeInteger(record.version) || record.version < 1) throw validationError("Webhook record version is invalid");
  if (!Number.isSafeInteger(record.secretVersion) || record.secretVersion < 1) throw validationError("Webhook secret version is invalid");
  if (!Number.isSafeInteger(record.failureCount) || record.failureCount < 0) throw validationError("Webhook failure count is invalid");
  if (!isWebhookStatus(record.status)) throw validationError("Webhook status is invalid");
  return {
    ...record,
    tenantId: normalizeTenant(record.tenantId),
    developerOrganizationId: requireId(record.developerOrganizationId, "developerOrganizationId"),
    applicationId: requireId(record.applicationId, "applicationId"),
    environmentId: requireId(record.environmentId, "environmentId"),
    name: requireText(record.name, "name"),
    endpointUrl: requireEndpoint(record.endpointUrl),
    events: normalizeEvents(record.events),
    signingSecretReference: normalizeReference(record.signingSecretReference),
    createdAt: normalizeInstant(record.createdAt, "createdAt"),
    updatedAt: normalizeInstant(record.updatedAt, "updatedAt"),
  };
}

function normalizeDeliveryRecord(record: OpenPlatformWebhookDelivery): OpenPlatformWebhookDelivery {
  if (record === null || typeof record !== "object") throw validationError("Webhook delivery is invalid");
  if (!Number.isSafeInteger(record.attempt) || record.attempt < 0) throw validationError("Webhook delivery attempt is invalid");
  if (!Number.isSafeInteger(record.maxAttempts) || record.maxAttempts < 1) throw validationError("Webhook delivery maximum attempts is invalid");
  if (!isDeliveryStatus(record.status)) throw validationError("Webhook delivery status is invalid");
  if (!Number.isSafeInteger(record.secretVersion) || record.secretVersion < 1) throw validationError("Webhook delivery secret version is invalid", { field: "secretVersion" });
  if (record.responseStatusCode !== undefined && (!Number.isInteger(record.responseStatusCode) || record.responseStatusCode < 100 || record.responseStatusCode > 599)) {
    throw validationError("Webhook delivery response status is invalid", { field: "responseStatusCode" });
  }
  const eventType = requireId(record.event, "event");
  if (!(OPEN_PLATFORM_WEBHOOK_EVENT_TYPES as readonly string[]).includes(eventType)) {
    throw validationError("Webhook delivery event type is invalid", { field: "event" });
  }
  return {
    ...record,
    tenantId: normalizeTenant(record.tenantId),
    webhookId: requireId(record.webhookId, "webhookId"),
    eventId: requireId(record.eventId, "eventId"),
    event: eventType,
    idempotencyKey: requireId(record.idempotencyKey, "idempotencyKey"),
    secretVersion: normalizeSecretVersion(record.secretVersion),
    ...(record.leaseId === undefined ? {} : { leaseId: requireId(record.leaseId, "leaseId") }),
    ...(record.leaseExpiresAt === undefined ? {} : { leaseExpiresAt: normalizeInstant(record.leaseExpiresAt, "leaseExpiresAt") }),
    createdAt: normalizeInstant(record.createdAt, "createdAt"),
    updatedAt: normalizeInstant(record.updatedAt, "updatedAt"),
  };
}

function normalizeDeliveryClaim(
  request: OpenPlatformWebhookDeliveryClaimRequest,
): Required<OpenPlatformWebhookDeliveryClaimRequest> {
  if (request === null || typeof request !== "object") throw validationError("Webhook delivery claim is invalid");
  const now = normalizeInstant(request.now, "now");
  const leaseExpiresAt = normalizeInstant(request.leaseExpiresAt, "leaseExpiresAt");
  if (Date.parse(leaseExpiresAt) <= Date.parse(now)) throw validationError("Webhook delivery claim lease is invalid");
  return {
    tenantId: normalizeTenant(request.tenantId),
    id: requireId(request.id, "deliveryId"),
    attempt: normalizeClaimAttempt(request.attempt),
    leaseId: requireId(request.leaseId, "leaseId"),
    now,
    leaseExpiresAt,
  };
}

function normalizeClaimAttempt(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) throw validationError("Webhook delivery claim attempt is invalid");
  return value as number;
}

function normalizeEvent(event: OpenPlatformWebhookEventEnvelope, tenantId: string, defaultOccurredAt?: string): NormalizedOpenPlatformWebhookEventEnvelope {
  if (event === null || typeof event !== "object") throw validationError("Webhook event is invalid");
  const raw = event as unknown as Record<string, unknown>;
  const eventType = requireId(event.eventType ?? event.type ?? raw.event_type, "eventType");
  if (!(OPEN_PLATFORM_WEBHOOK_EVENT_TYPES as readonly string[]).includes(eventType)) {
    throw validationError("Webhook event type is invalid", { field: "eventType" });
  }
  const eventTenantId = normalizeTenant(event.tenantId ?? raw.tenant_id ?? tenantId);
  if (eventTenantId !== normalizeTenant(tenantId)) throw validationError("Webhook event tenant is invalid", { field: "tenantId" });
  const actor = event.actor === undefined ? undefined : normalizeWebhookActor(event.actor);
  const resource = event.resource === undefined ? undefined : normalizeWebhookResource(event.resource);
  if (event.data !== undefined && (event.data === null || typeof event.data !== "object" || Array.isArray(event.data))) {
    throw validationError("Webhook event data is invalid", { field: "data" });
  }
  const requestId = event.requestId ?? raw.request_id;
  const traceId = event.traceId ?? raw.trace_id;
  return {
    eventId: requireId(event.eventId ?? raw.event_id ?? `event_${randomUUID()}`, "eventId"),
    eventType,
    occurredAt: normalizeInstant(event.occurredAt ?? raw.occurred_at ?? defaultOccurredAt ?? new Date().toISOString(), "occurredAt"),
    tenantId: eventTenantId,
    schemaVersion: requireId(event.schemaVersion ?? raw.schema_version ?? OPEN_PLATFORM_WEBHOOK_EVENT_SCHEMA_VERSION, "schemaVersion"),
    ...(actor === undefined ? {} : { actor }),
    ...(resource === undefined ? {} : { resource }),
    ...(event.data === undefined ? {} : { data: event.data }),
    ...(requestId === undefined ? {} : { requestId: requireId(requestId, "requestId") }),
    ...(traceId === undefined ? {} : { traceId: requireId(traceId, "traceId") }),
  };
}

function normalizeWebhookActor(value: unknown): { readonly type: "user" | "service" | "system"; readonly id: string } {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw validationError("Webhook event actor is invalid");
  const actor = value as Record<string, unknown>;
  if (actor.type !== "user" && actor.type !== "service" && actor.type !== "system") throw validationError("Webhook event actor is invalid");
  return { type: actor.type, id: requireId(actor.id, "actor.id") };
}

function normalizeWebhookResource(value: unknown): { readonly type: string; readonly id: string; readonly version?: number; readonly status?: string } {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw validationError("Webhook event resource is invalid");
  const resource = value as Record<string, unknown>;
  if (resource.version !== undefined && (!Number.isSafeInteger(resource.version) || (resource.version as number) < 1)) throw validationError("Webhook event resource version is invalid");
  return {
    type: requireId(resource.type, "resource.type"),
    id: requireId(resource.id, "resource.id"),
    ...(resource.version === undefined ? {} : { version: resource.version as number }),
    ...(resource.status === undefined ? {} : { status: requireId(resource.status, "resource.status") }),
  };
}

function isSafeWebhookString(value: string): boolean {
  return value.length <= 2048 && !/[\u0000-\u001f\u007f]/u.test(value) && !/(?:secret|password|token|authorization|private[-_]?key|vault:\/\/)/iu.test(value);
}

function sanitizeWebhookData(value: Readonly<Record<string, unknown>> | undefined): Record<string, unknown> {
  if (value === undefined) return {};
  const output: Record<string, unknown> = {};
  for (const key of Object.keys(value).sort(compareStrings)) {
    if (isSensitiveKey(key)) continue;
    const item = value[key];
    if (item === null || typeof item === "boolean" || (typeof item === "number" && Number.isFinite(item))) {
      output[key] = item;
    } else if (typeof item === "string" && isSafeWebhookString(item)) {
      output[key] = item;
    } else if (Array.isArray(item) && item.length <= 100) {
      const values = item.filter((entry) => entry === null || typeof entry === "boolean" || (typeof entry === "number" && Number.isFinite(entry)) || (typeof entry === "string" && isSafeWebhookString(entry)));
      if (values.length === item.length) output[key] = values;
    }
  }
  return output;
}

function projectWebhookRecord(record: OpenPlatformWebhook): OpenPlatformWebhook {
  return {
    ...structuredClone(record),
    signingSecretReference: "",
  };
}

function isSensitiveKey(key: string): boolean {
  const normalized = key.replace(/[-_]/gu, "").toLowerCase();
  return normalized.includes("secret") ||
    normalized.includes("password") ||
    normalized.includes("token") ||
    normalized.includes("authorization") ||
    normalized.includes("privatekey") ||
    normalized.includes("credential");
}

function normalizeEvents(value: unknown): string[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > 100) throw validationError("Webhook events are invalid", { field: "events" });
  const events = value.map((event) => {
    const normalized = requireId(event, "events");
    if (!(OPEN_PLATFORM_WEBHOOK_EVENT_TYPES as readonly string[]).includes(normalized)) {
      throw validationError("Webhook event type is invalid", { field: "events" });
    }
    return normalized;
  });
  return [...new Set(events)].sort(compareStrings);
}

const WEBHOOK_ENDPOINT_MAX_LENGTH = 2048;
const WEBHOOK_ENDPOINT_MAX_ADDRESSES = 16;
const WEBHOOK_ENDPOINT_DEFAULT_TIMEOUT_MS = 5_000;
const WEBHOOK_ENDPOINT_MAX_TIMEOUT_MS = 30_000;
const WEBHOOK_ENDPOINT_MAX_CIDR_RANGES = 256;
const WEBHOOK_ENDPOINT_MAX_HOST_PATTERNS = 256;
const WEBHOOK_ENDPOINT_MAX_CIDR_LENGTH = 64;

const WEBHOOK_ENDPOINT_HARD_BLOCKED_CIDR_TEXT: readonly string[] = Object.freeze([
  "0.0.0.0/8",
  "169.254.0.0/16",
  "100.100.100.200/32",
  "168.63.129.16/32",
  "224.0.0.0/4",
  "240.0.0.0/4",
  "::/128",
  "fe80::/10",
  "ff00::/8",
  "fd00:ec2::254/128",
]);

export const OPEN_PLATFORM_WEBHOOK_EGRESS_HARD_BLOCKED_CIDRS = WEBHOOK_ENDPOINT_HARD_BLOCKED_CIDR_TEXT;

const WEBHOOK_BLOCKED_HOSTS = new Set([
  "localhost",
  "localhost.localdomain",
  "ip6-localhost",
  "ip6-loopback",
  "metadata",
  "metadata.google.internal",
  "metadata.goog",
  "instance-data",
  "instance-data.ec2.internal",
]);

const WEBHOOK_BLOCKED_HOST_SUFFIXES = [
  ".localhost",
  ".local",
  ".localdomain",
  ".internal",
  ".intranet",
  ".home.arpa",
  ".lan",
];

const WEBHOOK_BLOCKED_IPV4 = new Set([
  "127.0.0.1",
  "169.254.169.254",
  "169.254.170.2",
  "100.100.100.200",
  "168.63.129.16",
  "192.0.0.192",
  "192.0.0.1",
  "0.0.0.0",
  "255.255.255.255",
]);

const WEBHOOK_BLOCKED_IPV6 = new Set([
  "::1",
  "::",
  "fd00:ec2::254",
  "fe80::a9fe:a9fe",
  "::ffff:127.0.0.1",
]);

interface WebhookEndpointCidrRange {
  readonly family: 4 | 6;
  readonly prefix: number;
  readonly address: readonly number[];
}

interface WebhookEndpointAddress {
  readonly family: 4 | 6;
  readonly value: readonly number[];
}

const WEBHOOK_ENDPOINT_HARD_BLOCKED_RANGES: readonly WebhookEndpointCidrRange[] = Object.freeze(
  WEBHOOK_ENDPOINT_HARD_BLOCKED_CIDR_TEXT.map((entry) => parseEndpointCidr(entry) as WebhookEndpointCidrRange),
);

function parseEndpointCidr(value: string): WebhookEndpointCidrRange | undefined {
  if (typeof value !== "string" || value.length < 4 || value.length > WEBHOOK_ENDPOINT_MAX_CIDR_LENGTH) {
    return undefined;
  }
  const separator = value.indexOf("/");
  if (separator < 1 || separator === value.length - 1) return undefined;
  const prefixText = value.slice(separator + 1);
  if (!/^(?:0|[1-9][0-9]{0,2})$/u.test(prefixText)) return undefined;
  const prefix = Number(prefixText);
  const address = value.slice(0, separator);
  const ipv4 = parseIpv4(address);
  if (ipv4 !== undefined) {
    return prefix <= 32 ? { family: 4, prefix, address: ipv4 } : undefined;
  }
  const ipv6 = parseIpv6(address);
  if (ipv6 === undefined || prefix > 128) return undefined;
  return { family: 6, prefix, address: ipv6 };
}

function parseEndpointAddress(value: string): WebhookEndpointAddress | undefined {
  const host = normalizeEndpointHost(value);
  const ipv4 = parseIpv4(host);
  if (ipv4 !== undefined) return { family: 4, value: ipv4 };
  const ipv6 = parseIpv6(host);
  if (ipv6 === undefined) return undefined;
  return { family: 6, value: ipv6 };
}

function matchesEndpointCidrRange(
  address: WebhookEndpointAddress,
  range: WebhookEndpointCidrRange,
): boolean {
  if (range.family !== address.family) return false;
  if (range.prefix === 0) return true;
  const wholeBytes = Math.floor(range.prefix / 8);
  for (let index = 0; index < wholeBytes; index += 1) {
    if (address.value[index] !== range.address[index]) return false;
  }
  const remainder = range.prefix % 8;
  if (remainder === 0) return true;
  const mask = (0xff << (8 - remainder)) & 0xff;
  return ((address.value[wholeBytes] ?? 0) & mask) === ((range.address[wholeBytes] ?? 0) & mask);
}

function matchesEndpointAddressCidrs(
  address: WebhookEndpointAddress,
  ranges: readonly WebhookEndpointCidrRange[],
): boolean {
  for (const range of ranges) {
    if (matchesEndpointCidrRange(address, range)) return true;
  }
  if (address.family !== 6) return false;
  const embedded = embeddedIpv4FromIpv6(address.value);
  if (embedded === undefined) return false;
  const mapped: WebhookEndpointAddress = { family: 4, value: embedded };
  return ranges.some((range) => matchesEndpointCidrRange(mapped, range));
}

function endpointAddressRejectionReason(
  addresses: readonly string[],
  policy: ResolvedOpenPlatformWebhookEndpointPolicy,
  loopbackAllowed: boolean,
): string | undefined {
  for (const value of addresses) {
    const address = parseEndpointAddress(value);
    if (address === undefined) return "private-address";
    if (matchesEndpointAddressCidrs(address, WEBHOOK_ENDPOINT_HARD_BLOCKED_RANGES)) {
      return "hard-blocked-address";
    }
    if (policy.blockedCidrs !== undefined && matchesEndpointAddressCidrs(address, policy.blockedCidrs)) {
      return "blocked-address";
    }
    if (policy.allowPrivateNetwork === true || loopbackAllowed) continue;
    if (policy.allowedCidrs !== undefined && matchesEndpointAddressCidrs(address, policy.allowedCidrs)) continue;
    if (isBlockedEndpointAddress(value)) return "private-address";
  }
  return undefined;
}

export function assertOpenPlatformWebhookEndpointSync(
  value: unknown,
  context: OpenPlatformWebhookEndpointContext = { production: false },
): string {
  return assertResolvedEndpointSync(value, normalizeEndpointContext(context));
}

function assertResolvedEndpointSync(
  value: unknown,
  context: ResolvedOpenPlatformWebhookEndpointContext,
): string {
  const policy = context.policy;
  if (typeof value !== "string" || value.length > WEBHOOK_ENDPOINT_MAX_LENGTH || value !== value.trim() || /[\u0000-\u0020\u007f]/u.test(value)) {
    throw endpointRejectedError("malformed");
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw endpointRejectedError("malformed");
  }
  if (url.username !== "" || url.password !== "") throw endpointRejectedError("userinfo");
  if (url.hash !== "") throw endpointRejectedError("fragment");
  if (url.hostname.length === 0) throw endpointRejectedError("host");
  if (url.hostname.includes("%")) throw endpointRejectedError("zone");
  const host = normalizeEndpointHost(url.hostname);
  if (host.length === 0 || host.length > 253) throw endpointRejectedError("host");
  if (!isValidEndpointPort(url.port, policy)) throw endpointRejectedError("port");
  const loopbackAllowed = isLoopbackEndpointAllowed(policy, host);
  if (url.protocol !== "https:") {
    if (!(url.protocol === "http:" && loopbackAllowed)) {
      throw endpointRejectedError(url.protocol === "http:" ? "insecure-transport" : "protocol");
    }
  }
  if (policy.blockedHosts !== undefined && matchesEndpointHostPattern(host, policy.blockedHosts)) {
    throw endpointRejectedError("blocked-host");
  }
  if (policy.allowHosts !== undefined && !matchesEndpointHostPattern(host, policy.allowHosts)) {
    throw endpointRejectedError("host-not-allowed");
  }
  if (matchesEndpointHostPattern(host, WEBHOOK_BLOCKED_HOSTS) || hasBlockedEndpointSuffix(host)) {
    throw endpointRejectedError("host");
  }
  const literal = literalEndpointAddresses(host);
  const reason = endpointAddressRejectionReason(literal, policy, loopbackAllowed);
  if (reason !== undefined) throw endpointRejectedError(reason);
  if (literal.length === 0 && /^[0-9.]+$/u.test(host) && policy.allowPrivateNetwork !== true && !loopbackAllowed) {
    throw endpointRejectedError("ambiguous-address");
  }
  return value;
}

export async function assertOpenPlatformWebhookEndpoint(
  value: unknown,
  context: OpenPlatformWebhookEndpointContext = { production: false },
): Promise<string> {
  return (await resolveOpenPlatformWebhookEndpointTarget(value, context)).endpointUrl;
}

export async function resolveOpenPlatformWebhookEndpointTarget(
  value: unknown,
  context: OpenPlatformWebhookEndpointContext = { production: false },
): Promise<OpenPlatformWebhookEndpointTarget> {
  return resolveResolvedEndpointTarget(value, normalizeEndpointContext(context));
}

function resolveResolvedEndpointTarget(
  value: unknown,
  context: ResolvedOpenPlatformWebhookEndpointContext,
): Promise<OpenPlatformWebhookEndpointTarget> {
  const endpoint = assertResolvedEndpointSync(value, context);
  const policy = context.policy;
  const host = normalizeEndpointHost(new URL(endpoint).hostname);
  if (literalEndpointAddresses(host).length > 0) return Promise.resolve({ endpointUrl: endpoint });
  if (policy.requireResolution !== true) return Promise.resolve({ endpointUrl: endpoint });
  return resolveTargetAddresses(host, policy, endpoint);
}

async function resolveTargetAddresses(
  host: string,
  policy: ResolvedOpenPlatformWebhookEndpointPolicy,
  endpointUrl: string,
): Promise<OpenPlatformWebhookEndpointTarget> {
  const addresses = await resolveEndpointAddresses(host, policy);
  if (addresses.length === 0) throw new OpenPlatformWebhookEndpointUnresolvedError(host);
  const loopbackAllowed = isLoopbackEndpointAllowed(policy, host);
  for (const address of addresses) {
    const reason = endpointAddressRejectionReason([address], policy, loopbackAllowed);
    if (reason !== undefined) throw endpointRejectedError(reason);
  }
  return { endpointUrl, resolvedAddresses: Object.freeze([...addresses]) };
}

function isLoopbackEndpointAllowed(
  policy: ResolvedOpenPlatformWebhookEndpointPolicy,
  host: string,
): boolean {
  return !policy.requireHttps && policy.allowLoopbackHttp && isLoopbackHost(host);
}

export function isBlockedWebhookEndpointAddress(value: unknown): boolean {
  return typeof value === "string" && isBlockedEndpointAddress(value);
}

export function isHardBlockedOpenPlatformWebhookEndpointAddress(value: unknown): boolean {
  if (typeof value !== "string") return false;
  const parsed = parseEndpointAddress(value);
  return parsed !== undefined && matchesEndpointAddressCidrs(parsed, WEBHOOK_ENDPOINT_HARD_BLOCKED_RANGES);
}

export function assertOpenPlatformWebhookEndpointPolicy(
  policy: OpenPlatformWebhookEndpointPolicy | undefined,
  context: { readonly production?: boolean } = {},
): void {
  resolveEndpointPolicy({
    production: context.production === true,
    ...(policy === undefined ? {} : { policy }),
  });
}

function requireEndpoint(
  value: unknown,
  context: ResolvedOpenPlatformWebhookEndpointContext = normalizeEndpointContext({ production: false }),
): string {
  try {
    return assertResolvedEndpointSync(value, context);
  } catch (error) {
    if (error instanceof OpenPlatformWebhookEndpointRejectedError) {
      throw validationError("Webhook endpoint URL is invalid", { field: "endpointUrl", reason: error.reason });
    }
    throw error;
  }
}

type ResolvedOpenPlatformWebhookEndpointPolicy = {
  readonly requireHttps: boolean;
  readonly allowLoopbackHttp: boolean;
  readonly allowPrivateNetwork: boolean;
  readonly requireResolution: boolean;
  readonly allowHosts?: readonly string[];
  readonly allowedPorts?: readonly number[];
  readonly allowedCidrs?: readonly WebhookEndpointCidrRange[];
  readonly blockedCidrs?: readonly WebhookEndpointCidrRange[];
  readonly blockedHosts?: readonly string[];
  readonly resolutionTimeoutMs: number;
  readonly resolver?: OpenPlatformWebhookEndpointResolver | OpenPlatformWebhookEndpointResolverFunction;
};

interface ResolvedOpenPlatformWebhookEndpointContext {
  readonly production: boolean;
  readonly policy: ResolvedOpenPlatformWebhookEndpointPolicy;
}

function resolveEndpointPolicy(context: OpenPlatformWebhookEndpointContext): ResolvedOpenPlatformWebhookEndpointPolicy {
  const production = context.production === true;
  const policy = context.policy ?? {};
  if (policy.allowHosts !== undefined && !isValidHostPatternList(policy.allowHosts)) {
    throw configurationError("Webhook endpoint allowlist is invalid");
  }
  if (policy.blockedHosts !== undefined && !isValidHostPatternList(policy.blockedHosts)) {
    throw configurationError("Webhook endpoint host blocklist is invalid");
  }
  if (policy.allowedPorts !== undefined && (!Array.isArray(policy.allowedPorts) || policy.allowedPorts.length === 0 ||
    policy.allowedPorts.length > 64 || policy.allowedPorts.some((port) => !Number.isSafeInteger(port) || (port as number) < 1 || (port as number) > 65_535))) {
    throw configurationError("Webhook endpoint port allowlist is invalid");
  }
  const allowedCidrs = normalizePolicyCidrs(policy.allowedCidrs, "allowed");
  const blockedCidrs = normalizePolicyCidrs(policy.blockedCidrs, "blocked");
  const timeout = policy.resolutionTimeoutMs ?? WEBHOOK_ENDPOINT_DEFAULT_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeout) || timeout < 1 || timeout > WEBHOOK_ENDPOINT_MAX_TIMEOUT_MS) {
    throw configurationError("Webhook endpoint resolution timeout is invalid");
  }
  if (policy.resolver !== undefined && typeof policy.resolver !== "function" &&
    (typeof policy.resolver !== "object" || policy.resolver === null || typeof policy.resolver.resolve !== "function")) {
    throw configurationError("Webhook endpoint resolver is invalid");
  }
  return {
    requireHttps: policy.requireHttps ?? production,
    allowLoopbackHttp: policy.allowLoopbackHttp ?? !production,
    allowPrivateNetwork: policy.allowPrivateNetwork === true,
    requireResolution: policy.requireResolution ?? production,
    ...(policy.allowHosts === undefined ? {} : { allowHosts: normalizeHostPatterns(policy.allowHosts) }),
    ...(policy.allowedPorts === undefined ? {} : { allowedPorts: [...policy.allowedPorts] }),
    ...(allowedCidrs === undefined ? {} : { allowedCidrs }),
    ...(blockedCidrs === undefined ? {} : { blockedCidrs }),
    ...(policy.blockedHosts === undefined ? {} : { blockedHosts: normalizeHostPatterns(policy.blockedHosts) }),
    resolutionTimeoutMs: timeout,
    ...(policy.resolver === undefined ? {} : { resolver: policy.resolver }),
  };
}

function isValidHostPatternList(value: readonly string[]): boolean {
  return Array.isArray(value) && value.length > 0 && value.length <= WEBHOOK_ENDPOINT_MAX_HOST_PATTERNS &&
    value.every((entry) => typeof entry === "string" && normalizeHostPattern(entry) !== undefined);
}

function normalizeHostPatterns(values: readonly string[]): readonly string[] {
  return Object.freeze(values.map((entry) => normalizeHostPattern(entry) as string));
}

function normalizeHostPattern(value: string): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim().toLowerCase();
  if (trimmed.length === 0 || trimmed.length > 253) return undefined;
  const wildcard = trimmed.startsWith("*.") || trimmed.startsWith(".");
  const host = normalizeEndpointHost(wildcard ? trimmed.slice(2) : trimmed);
  if (host.length === 0 || host.length > 253) return undefined;
  if (literalEndpointAddresses(host).length > 0) return wildcard ? undefined : host;
  for (const label of host.split(".")) {
    if (label.length === 0 || label.length > 63) return undefined;
    if (!/^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?$/u.test(label)) return undefined;
  }
  return wildcard ? `.${host}` : host;
}

function normalizePolicyCidrs(
  values: readonly string[] | undefined,
  kind: "allowed" | "blocked",
): readonly WebhookEndpointCidrRange[] | undefined {
  if (values === undefined) return undefined;
  if (!Array.isArray(values) || values.length === 0 || values.length > WEBHOOK_ENDPOINT_MAX_CIDR_RANGES ||
    values.some((entry) => typeof entry !== "string" || parseEndpointCidr(entry) === undefined)) {
    throw configurationError(
      kind === "allowed"
        ? "Webhook endpoint allowed CIDR list is invalid"
        : "Webhook endpoint blocked CIDR list is invalid",
    );
  }
  return Object.freeze(values.map((entry) => parseEndpointCidr(entry) as WebhookEndpointCidrRange));
}

function normalizeEndpointContext(value: OpenPlatformWebhookEndpointContext): ResolvedOpenPlatformWebhookEndpointContext {
  return { production: value.production === true, policy: resolveEndpointPolicy(value) };
}

function endpointRejectedError(reason: string): OpenPlatformWebhookEndpointRejectedError {
  return new OpenPlatformWebhookEndpointRejectedError(reason);
}

function normalizeEndpointHost(hostname: string): string {
  const normalized = hostname.trim().toLowerCase();
  const unbracketed = normalized.startsWith("[") && normalized.endsWith("]")
    ? normalized.slice(1, -1)
    : normalized;
  return unbracketed.endsWith(".") && unbracketed.length > 1 ? unbracketed.slice(0, -1) : unbracketed;
}

function isValidEndpointPort(port: string, policy: ReturnType<typeof resolveEndpointPolicy>): boolean {
  if (port === "") return policy.allowedPorts === undefined || policy.allowedPorts.includes(443);
  if (!/^(?:[1-9][0-9]{0,4})$/u.test(port)) return false;
  const value = Number(port);
  if (value < 1 || value > 65_535) return false;
  return policy.allowedPorts === undefined || policy.allowedPorts.includes(value);
}

function matchesEndpointHostPattern(host: string, patterns: ReadonlySet<string> | readonly string[]): boolean {
  const entries = patterns instanceof Set ? patterns : new Set(patterns);
  for (const entry of entries) {
    if (entry === host) return true;
    if (entry.startsWith("*.") && host.endsWith(entry.slice(1)) && host.length > entry.length - 1) return true;
    if (entry.startsWith(".") && host.endsWith(entry) && host.length > entry.length) return true;
  }
  return false;
}

function hasBlockedEndpointSuffix(host: string): boolean {
  return WEBHOOK_BLOCKED_HOST_SUFFIXES.some((suffix) => host.endsWith(suffix) && host.length > suffix.length);
}

function isLoopbackHost(host: string): boolean {
  return host === "localhost" || host === "::1" || /^127(?:\.[0-9]{1,3}){3}$/u.test(host);
}

function literalEndpointAddresses(host: string): readonly string[] {
  const ipv4 = parseIpv4(host);
  if (ipv4 !== undefined) return [formatIpv4(ipv4)];
  const ipv6 = parseIpv6(host);
  return ipv6 === undefined ? [] : [formatIpv6(ipv6)];
}

function isBlockedEndpointAddress(value: string): boolean {
  const host = normalizeEndpointHost(value);
  if (WEBHOOK_BLOCKED_IPV4.has(host) || WEBHOOK_BLOCKED_IPV6.has(host)) return true;
  const ipv4 = parseIpv4(host);
  if (ipv4 !== undefined) return isBlockedIpv4(ipv4);
  const ipv6 = parseIpv6(host);
  if (ipv6 === undefined) return true;
  return isBlockedIpv6(ipv6);
}

function isBlockedIpv4(octets: readonly number[]): boolean {
  const [a, b, c] = octets;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return true;
  if (a === 192 && b === 88 && c === 99) return true;
  if (a === 192 && b === 168) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  if (a === 198 && b === 51 && c === 100) return true;
  if (a === 203 && b === 0 && c === 113) return true;
  return a >= 224;
}

function isBlockedIpv6(groups: readonly number[]): boolean {
  if (groups.every((group) => group === 0)) return true;
  if (groups.slice(0, 7).every((group) => group === 0) && groups[7] === 1) return true;
  const embedded = embeddedIpv4FromIpv6(groups);
  if (embedded !== undefined) return isBlockedIpv4(embedded);
  if ((groups[0] & 0xfe00) === 0xfc00) return true;
  if ((groups[0] & 0xffc0) === 0xfe80) return true;
  if ((groups[0] & 0xffc0) === 0xfec0) return true;
  if ((groups[0] & 0xff00) === 0xff00) return true;
  if (groups[0] === 0x0100 && groups[1] === 0 && groups[2] === 0 && groups[3] === 0) return true;
  if (groups[0] === 0x2001 && groups[1] === 0x0db8) return true;
  return false;
}

function embeddedIpv4FromIpv6(groups: readonly number[]): readonly number[] | undefined {
  if (groups.length !== 8) return undefined;
  const leadingZeros = groups.slice(0, 5).every((group) => group === 0);
  if (leadingZeros && (groups[5] === 0xffff || groups[5] === 0)) {
    return [groups[6] >> 8, groups[6] & 0xff, groups[7] >> 8, groups[7] & 0xff];
  }
  if (groups[0] === 0x0064 && groups[1] === 0xff9b && groups.slice(2, 6).every((group) => group === 0)) {
    return [groups[6] >> 8, groups[6] & 0xff, groups[7] >> 8, groups[7] & 0xff];
  }
  if (groups[0] === 0x2002) {
    return [groups[1] >> 8, groups[1] & 0xff, groups[2] >> 8, groups[2] & 0xff];
  }
  return undefined;
}

function parseIpv4(value: string): readonly number[] | undefined {
  const parts = value.split(".");
  if (parts.length !== 4) return undefined;
  const octets: number[] = [];
  for (const part of parts) {
    if (!/^(?:0|[1-9][0-9]{0,2})$/u.test(part)) return undefined;
    const octet = Number(part);
    if (octet > 255) return undefined;
    octets.push(octet);
  }
  return octets;
}

function formatIpv4(octets: readonly number[]): string {
  return octets.join(".");
}

function parseIpv6(value: string): readonly number[] | undefined {
  if (!/^[0-9a-f:.]+$/u.test(value)) return undefined;
  const doubleColon = value.indexOf("::");
  if (doubleColon !== -1 && value.indexOf("::", doubleColon + 1) !== -1) return undefined;
  const [headText, tailText] = doubleColon === -1 ? [value, ""] : [value.slice(0, doubleColon), value.slice(doubleColon + 2)];
  const head = parseIpv6Groups(headText);
  const tail = parseIpv6Groups(tailText);
  if (head === undefined || tail === undefined) return undefined;
  if (doubleColon === -1) return head.length === 8 ? head : undefined;
  if (head.length + tail.length > 7) return undefined;
  return [...head, ...new Array<number>(8 - head.length - tail.length).fill(0), ...tail];
}

function parseIpv6Groups(value: string): number[] | undefined {
  if (value === "") return [];
  const groups: number[] = [];
  for (const part of value.split(":")) {
    if (part === "") return undefined;
    if (part.includes(".")) {
      const embedded = parseIpv4(part);
      if (embedded === undefined) return undefined;
      groups.push((embedded[0] << 8) | embedded[1], (embedded[2] << 8) | embedded[3]);
      continue;
    }
    if (!/^[0-9a-f]{1,4}$/u.test(part)) return undefined;
    groups.push(Number.parseInt(part, 16));
  }
  return groups;
}

function formatIpv6(groups: readonly number[]): string {
  return groups.map((group) => group.toString(16)).join(":");
}

async function resolveEndpointAddresses(
  host: string,
  policy: ReturnType<typeof resolveEndpointPolicy>,
): Promise<readonly string[]> {
  let resolved: readonly string[] | OpenPlatformWebhookEndpointAddresses;
  try {
    const pending = policy.resolver === undefined
      ? defaultWebhookEndpointResolver(host)
      : typeof policy.resolver === "function"
        ? Promise.resolve(policy.resolver(host))
        : Promise.resolve(policy.resolver.resolve(host));
    resolved = await withEndpointResolutionTimeout(pending, policy.resolutionTimeoutMs);
  } catch {
    throw new OpenPlatformWebhookEndpointUnresolvedError(host);
  }
  const addresses = Array.isArray(resolved)
    ? resolved
    : (resolved as OpenPlatformWebhookEndpointAddresses | undefined)?.addresses ?? [];
  const normalized: string[] = [];
  for (const entry of addresses) {
    if (typeof entry !== "string") throw new OpenPlatformWebhookEndpointUnresolvedError(host);
    const address = normalizeEndpointHost(entry);
    if (address.length === 0 || literalEndpointAddresses(address).length === 0) {
      throw new OpenPlatformWebhookEndpointUnresolvedError(host);
    }
    normalized.push(address);
    if (normalized.length >= WEBHOOK_ENDPOINT_MAX_ADDRESSES) break;
  }
  return normalized;
}

async function defaultWebhookEndpointResolver(
  host: string,
): Promise<readonly string[]> {
  const dns = await import("node:dns/promises");
  const results = await dns.lookup(host, { all: true, verbatim: true });
  return results.map((entry) => entry.address);
}

async function withEndpointResolutionTimeout<T>(
  pending: Promise<T>,
  timeoutMs: number,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      pending,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error("Webhook endpoint resolution timed out")), timeoutMs);
        timer.unref?.();
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function requireSecret(value: unknown): string {
  if (typeof value !== "string" || value.length < 16 || value.length > 4096 || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw configurationError("Webhook secret is invalid");
  }
  return value;
}

function normalizeReference(value: unknown): string {
  if (typeof value !== "string" || value.length < 8 || value.length > 2048 || /\s/u.test(value)) {
    throw configurationError("Webhook secret reference is invalid");
  }
  return value;
}

function normalizeSecretReference(value: unknown, secret: string): string {
  const reference = normalizeReference(value);
  if (reference === secret || reference.includes(secret)) {
    throw configurationError("Webhook secret reference is invalid");
  }
  return reference;
}

function requireId(value: unknown, field: string): string {
  if (typeof value !== "string") throw validationError("Webhook identifier is invalid", { field });
  const normalized = value.trim();
  if (normalized.length < 1 || normalized.length > 256 || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw validationError("Webhook identifier is invalid", { field });
  }
  return normalized;
}

function normalizeGeneratedId(value: unknown, kind: string): string {
  if (typeof value !== "string" || !new RegExp(`^${kind}_[A-Za-z0-9._:-]+$`, "u").test(value)) {
    throw configurationError("Generated webhook identifier is invalid");
  }
  return value;
}

function requireText(value: unknown, field: string): string {
  if (typeof value !== "string") throw validationError("Webhook text is invalid", { field });
  const normalized = value.trim();
  if (normalized.length < 1 || normalized.length > 200 || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw validationError("Webhook text is invalid", { field });
  }
  return normalized;
}

function normalizeTenant(value: unknown): string {
  return normalizeTenantKey(value);
}

function normalizeInstant(value: unknown, field: string): string {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) throw validationError("Webhook timestamp is invalid", { field });
  return new Date(Date.parse(value)).toISOString();
}

function normalizeLimit(value: unknown): number {
  if (value === undefined) return 20;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1 || value > 100) throw validationError("Webhook page limit is invalid", { field: "limit" });
  return value;
}

function normalizeMaxAttempts(value: unknown): number {
  if (value === undefined) return 5;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1 || value > 20) throw configurationError("Webhook maximum attempts is invalid");
  return value;
}

function normalizeDelay(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > 86_400_000) throw configurationError(`Webhook ${field} is invalid`);
  return value;
}

function normalizeTolerance(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) > 86_400) throw configurationError("Webhook timestamp tolerance is invalid");
  return value as number;
}

function normalizeLeaseDuration(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1_000 || (value as number) > 3_600_000) {
    throw configurationError("Webhook delivery lease is invalid");
  }
  return value as number;
}

function leaseExpiry(now: string, leaseMs: number): string {
  return new Date(Date.parse(now) + leaseMs).toISOString();
}

function isExpiredLease(leaseExpiresAt: string | undefined, now: number): boolean {
  if (leaseExpiresAt === undefined) return true;
  const expires = Date.parse(leaseExpiresAt);
  return !Number.isFinite(expires) || expires <= now;
}

function isDeliveryClaimConflict(error: unknown): boolean {
  return isOpenPlatformDomainError(error) &&
    error.code === "OPEN_PLATFORM_RESOURCE_CONFLICT" &&
    (error.details?.deliveryId !== undefined || /already claimed/u.test(error.message));
}

async function isRepositoryReady(
  port: OpenPlatformWebhookPort | OpenPlatformWebhookDeliveryPort,
): Promise<boolean> {
  if (port.productionReady !== true) return false;
  if (port.readiness !== undefined) {
    return port.readiness.storage === "persistent" &&
      port.readiness.distributed &&
      await safeReady(port.readiness);
  }
  if (typeof port.isReady === "function") {
    try {
      return await port.isReady() === true;
    } catch {
      return false;
    }
  }
  return false;
}

function webhookHeader(
  headers: Headers | Record<string, string | string[] | undefined>,
  name: string,
): string | undefined {
  if (typeof Headers !== "undefined" && headers instanceof Headers) return headers.get(name) ?? undefined;
  const entry = Object.entries(headers as Record<string, string | string[] | undefined>)
    .find(([key]) => key.toLowerCase() === name.toLowerCase());
  const value = entry?.[1];
  return Array.isArray(value) ? value[0] : value;
}

function normalizeSecretVersion(value: unknown): number {
  const normalized = typeof value === "number" ? value : typeof value === "string" && /^[1-9][0-9]{0,8}$/u.test(value.trim()) ? Number(value.trim()) : Number.NaN;
  if (!Number.isSafeInteger(normalized) || normalized < 1) throw validationError("Webhook secret version is invalid", { field: "secretVersion" });
  return normalized;
}

function normalizeSignatureTimestamp(value: unknown): string {
  if (typeof value === "number" && Number.isFinite(value)) return new Date(value).toISOString();
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) throw validationError("Webhook signature timestamp is invalid");
  return new Date(Date.parse(value)).toISOString();
}

function parseSignatureCandidates(value: unknown): string[] {
  if (typeof value !== "string" || value.length < 16 || value.length > 512 || /[\u0000-\u001f\u007f]/u.test(value)) return [];
  const candidates: string[] = [];
  for (const part of value.split(",")) {
    const trimmed = part.trim();
    const separator = trimmed.indexOf("=");
    if (separator >= 0 && trimmed.slice(0, separator).trim().toLowerCase() !== OPEN_PLATFORM_WEBHOOK_SIGNATURE_VERSION) continue;
    const raw = separator < 0 ? trimmed : trimmed.slice(separator + 1);
    if (/^[a-f0-9]{64}$/u.test(raw)) candidates.push(`${OPEN_PLATFORM_WEBHOOK_SIGNATURE_VERSION}=${raw}`);
    if (/^[A-Za-z0-9_-]{43,44}$/u.test(raw)) {
      const decoded = Buffer.from(raw, "base64url").toString("hex");
      if (/^[a-f0-9]{64}$/u.test(decoded)) candidates.push(`${OPEN_PLATFORM_WEBHOOK_SIGNATURE_VERSION}=${decoded}`);
    }
  }
  return [...new Set(candidates)];
}

function isRetryableWebhookStatus(status: number): boolean {
  return status === 408 || status === 425 || status === 429 || status >= 500 && status <= 599;
}

function responseStatus(value: unknown): number | undefined {
  if (value === null || typeof value !== "object") return undefined;
  const response = value as Record<string, unknown>;
  const status = response.statusCode ?? response.status;
  return typeof status === "number" && Number.isInteger(status) && status >= 100 && status <= 599 ? status : undefined;
}

function responseBody(value: unknown): string | undefined {
  if (value === null || typeof value !== "object") return undefined;
  const response = value as Record<string, unknown>;
  return typeof response.body === "string" ? response.body : undefined;
}

function safeResponseExcerpt(value: string): string {
  const normalized = value
    .replace(/(?:secret|password|token|authorization|private[-_]?key|vault:\/\/)[^\s,;]*/giu, "[redacted]")
    .slice(0, 1024);
  return normalized;
}

function errorCode(value: unknown): string {
  if (value instanceof OpenPlatformWebhookEndpointUnresolvedError) return "WEBHOOK_ENDPOINT_UNRESOLVED";
  if (value instanceof OpenPlatformWebhookEndpointRejectedError) return "WEBHOOK_ENDPOINT_BLOCKED";
  return "TRANSPORT_ERROR";
}

function retryDelay(attempt: number, baseDelayMs: number, maxDelayMs: number): number {
  return Math.min(maxDelayMs, baseDelayMs * (2 ** Math.max(attempt - 1, 0)));
}

function secretKey(tenantId: string, webhookId: string, version: number): string {
  return `${tenantId}\u0000${webhookId}\u0000${version}`;
}

function compareWebhooks(left: OpenPlatformWebhook, right: OpenPlatformWebhook): number {
  const created = compareStrings(left.createdAt, right.createdAt);
  return created === 0 ? compareStrings(left.id, right.id) : created;
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isWebhookStatus(value: unknown): value is OpenPlatformWebhookStatus {
  return value === "active" || value === "paused" || value === "failing" || value === "disabled";
}

function isDeliveryStatus(value: unknown): value is OpenPlatformWebhookDeliveryStatus {
  return value === "pending" || value === "delivering" || value === "succeeded" || value === "failed" || value === "dead_lettered";
}

function encodeCursor(tenantId: string, offset: number): string {
  return `webhook_${Buffer.from(JSON.stringify({ tenantId, offset }), "utf8").toString("base64url")}`;
}

function decodeCursor(value: unknown, tenantId: string): number {
  if (typeof value !== "string" || !/^webhook_[A-Za-z0-9_-]+$/u.test(value)) throw validationError("Webhook cursor is invalid", { field: "cursor" });
  try {
    const parsed = JSON.parse(Buffer.from(value.slice(8), "base64url").toString("utf8")) as Record<string, unknown>;
    if (parsed.tenantId !== tenantId || !Number.isSafeInteger(parsed.offset) || (parsed.offset as number) < 0) throw new Error("invalid");
    return parsed.offset as number;
  } catch {
    throw validationError("Webhook cursor is invalid", { field: "cursor" });
  }
}

function encodeDeliveryCursor(tenantId: string, offset: number): string {
  return encodeCursor(tenantId, offset).replace(/^webhook_/u, "delivery_");
}

function decodeDeliveryCursor(value: unknown, tenantId: string): number {
  if (typeof value !== "string" || !/^delivery_[A-Za-z0-9_-]+$/u.test(value)) throw validationError("Webhook delivery cursor is invalid", { field: "cursor" });
  try {
    const parsed = JSON.parse(Buffer.from(value.slice(9), "base64url").toString("utf8")) as Record<string, unknown>;
    if (parsed.tenantId !== tenantId || !Number.isSafeInteger(parsed.offset) || (parsed.offset as number) < 0) throw new Error("invalid");
    return parsed.offset as number;
  } catch {
    throw validationError("Webhook delivery cursor is invalid", { field: "cursor" });
  }
}

async function safeReady(readiness: OpenPlatformDependencyReadiness): Promise<boolean> {
  try {
    return (await readiness.ready()) === true;
  } catch {
    return false;
  }
}
