import { randomUUID } from "node:crypto";
import {
  sanitizeOpenPlatformAuditMetadata,
  type OpenPlatformAuditActor,
  type OpenPlatformAuditEventInput,
  type OpenPlatformAuditMetadata,
  type OpenPlatformAuditOutcome,
  type OpenPlatformAuditPort,
  type OpenPlatformAuditResourceType,
} from "../audit.js";
import { validationError } from "../errors.js";
import {
  COMMERCE_AUTHORIZATION_RESOURCES,
  type CommerceAuthorizationResource,
} from "./authorization.js";
import type { CommerceDependencyReadiness } from "./types.js";

export const COMMERCE_AUDIT_OUTCOMES = Object.freeze([
  "success",
  "failure",
  "denied",
] as const);

export type CommerceAuditOutcome = (typeof COMMERCE_AUDIT_OUTCOMES)[number];

export const COMMERCE_AUDIT_RESOURCE_TYPES = COMMERCE_AUTHORIZATION_RESOURCES;

export type CommerceAuditResourceType = CommerceAuthorizationResource;

export const COMMERCE_AUDIT_SOURCE = "open-platform-commerce";

export const COMMERCE_AUDIT_PLATFORM_RESOURCE_TYPES: Readonly<
  Record<CommerceAuditResourceType, OpenPlatformAuditResourceType>
> = Object.freeze({
  marketplaceListing: "api_product",
  partnerAccount: "tenant",
  commissionRule: "api_product",
  invoice: "subscription",
});

export interface CommerceAuditTarget {
  readonly type: CommerceAuditResourceType;
  readonly id: string;
  readonly displayName?: string;
}

export interface CommerceAuditEventInput {
  readonly tenantId: string;
  readonly action: string;
  readonly outcome: CommerceAuditOutcome;
  readonly actor: OpenPlatformAuditActor;
  readonly target: CommerceAuditTarget;
  readonly requestId?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
  readonly occurredAt?: string;
  readonly source?: string;
}

export interface CommerceAuditRecord {
  readonly id: string;
  readonly tenantId: string;
  readonly action: string;
  readonly outcome: CommerceAuditOutcome;
  readonly actor: OpenPlatformAuditActor;
  readonly target: CommerceAuditTarget;
  readonly requestId?: string;
  readonly metadata: OpenPlatformAuditMetadata;
  readonly occurredAt: string;
  readonly source: string;
}

export interface CommerceAuditPort {
  readonly productionReady?: boolean;
  readonly readiness?: CommerceDependencyReadiness;
  append(event: CommerceAuditEventInput): Promise<CommerceAuditRecord>;
}

export interface InMemoryCommerceAuditStoreOptions {
  readonly clock?: () => Date;
  readonly idGenerator?: () => string;
  readonly production?: boolean;
  readonly maxEvents?: number;
  readonly retentionMs?: number;
}

export class InMemoryCommerceAuditEventStore implements CommerceAuditPort {
  readonly productionReady = false;
  readonly readiness: CommerceDependencyReadiness;
  private readonly events = new Map<string, CommerceAuditRecord[]>();
  private readonly clock: () => Date;
  private readonly idGenerator: () => string;
  private readonly maxEvents: number;
  private readonly retentionMs: number;

  constructor(options: InMemoryCommerceAuditStoreOptions = {}) {
    this.clock = options.clock ?? (() => new Date());
    this.idGenerator = options.idGenerator ?? (() => `commerce_audit_${randomUUID()}`);
    const maxEvents = options.maxEvents ?? 10_000;
    const retentionMs = options.retentionMs ?? 604_800_000;
    if (!Number.isSafeInteger(maxEvents) || maxEvents < 1 || maxEvents > 1_000_000) {
      throw validationError("Commerce audit capacity is invalid");
    }
    if (!Number.isSafeInteger(retentionMs) || retentionMs < 60_000 || retentionMs > 2_592_000_000) {
      throw validationError("Commerce audit retention is invalid");
    }
    this.maxEvents = maxEvents;
    this.retentionMs = retentionMs;
    this.readiness = Object.freeze({
      storage: "memory" as const,
      distributed: false,
      ready: () => options.production !== true,
    });
  }

  async append(event: CommerceAuditEventInput): Promise<CommerceAuditRecord> {
    const record = normalizeCommerceAuditEvent(event, {
      id: this.idGenerator(),
      occurredAt: this.timestamp(),
    });
    const records = this.events.get(record.tenantId) ?? [];
    this.prune(records, record.occurredAt);
    records.push(record);
    if (records.length > this.maxEvents) records.splice(0, records.length - this.maxEvents);
    this.events.set(record.tenantId, records);
    return structuredClone(record);
  }

  list(tenantId: string): CommerceAuditRecord[] {
    return (this.events.get(normalizeCommerceAuditTenantId(tenantId)) ?? [])
      .map((record) => structuredClone(record));
  }

  size(): number {
    let total = 0;
    for (const records of this.events.values()) total += records.length;
    return total;
  }

  private prune(records: CommerceAuditRecord[], now: string): void {
    const threshold = Date.parse(now) - this.retentionMs;
    let index = 0;
    while (index < records.length && Date.parse(records[index]?.occurredAt ?? "") <= threshold) {
      index += 1;
    }
    if (index > 0) records.splice(0, index);
  }

  private timestamp(): string {
    const value = this.clock();
    if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
      throw validationError("Commerce audit clock is invalid");
    }
    return value.toISOString();
  }
}

export const InMemoryCommerceAuditStore = InMemoryCommerceAuditEventStore;
export const InMemoryCommerceAuditRepository = InMemoryCommerceAuditEventStore;

export function createInMemoryCommerceAuditEventStore(
  options: InMemoryCommerceAuditStoreOptions = {},
): InMemoryCommerceAuditEventStore {
  return new InMemoryCommerceAuditEventStore(options);
}

export const createInMemoryCommerceAuditStore = createInMemoryCommerceAuditEventStore;

export interface CommerceAuditAdapterOptions {
  readonly resourceTypes?: Partial<
    Record<CommerceAuditResourceType, OpenPlatformAuditResourceType>
  >;
  readonly actionPrefix?: string;
}

export function createCommerceAuditAdapter(
  audit: OpenPlatformAuditPort,
  options: CommerceAuditAdapterOptions = {},
): CommerceAuditPort {
  if (
    audit === null ||
    typeof audit !== "object" ||
    typeof audit.append !== "function"
  ) {
    throw validationError("Commerce audit port is invalid");
  }
  const resourceTypes: Readonly<Record<CommerceAuditResourceType, OpenPlatformAuditResourceType>> =
    Object.freeze({ ...COMMERCE_AUDIT_PLATFORM_RESOURCE_TYPES, ...(options.resourceTypes ?? {}) });
  const actionPrefix = options.actionPrefix ?? "commerce.";
  return Object.freeze({
    productionReady: audit.productionReady === true,
    ...(audit.readiness === undefined ? {} : { readiness: audit.readiness }),
    async append(event: CommerceAuditEventInput): Promise<CommerceAuditRecord> {
      const normalized = normalizeCommerceAuditEvent(event, {
        id: `commerce_audit_${randomUUID()}`,
        occurredAt: normalizeOccurredAt(event.occurredAt),
      });
      const forwarded: OpenPlatformAuditEventInput = {
        tenantId: normalized.tenantId,
        action: `${actionPrefix}${normalized.action}`,
        outcome: normalized.outcome,
        actor: normalized.actor,
        target: {
          type: resourceTypes[normalized.target.type],
          id: normalized.target.id,
          ...(normalized.target.displayName === undefined
            ? {}
            : { displayName: normalized.target.displayName }),
        },
        ...(normalized.requestId === undefined ? {} : { requestId: normalized.requestId }),
        metadata: {
          ...normalized.metadata,
          commerceResource: normalized.target.type,
        },
        occurredAt: normalized.occurredAt,
        source: normalized.source,
      };
      const appended = await audit.append(forwarded);
      return {
        id: appended.id,
        tenantId: appended.tenantId,
        action: normalized.action,
        outcome: appended.outcome,
        actor: appended.actor,
        target: normalized.target,
        ...(appended.requestId === undefined ? {} : { requestId: appended.requestId }),
        metadata: appended.metadata,
        occurredAt: appended.occurredAt,
        source: appended.source,
      };
    },
  });
}

export function sanitizeCommerceAuditMetadata(
  value: Readonly<Record<string, unknown>> | undefined,
): OpenPlatformAuditMetadata {
  return sanitizeOpenPlatformAuditMetadata(value);
}

function normalizeCommerceAuditEvent(
  event: CommerceAuditEventInput,
  defaults: { readonly id: string; readonly occurredAt: string },
): CommerceAuditRecord {
  if (event === null || typeof event !== "object") {
    throw validationError("Commerce audit event is invalid");
  }
  const tenantId = normalizeCommerceAuditTenantId(event.tenantId);
  if (!isCommerceAuditOutcome(event.outcome)) {
    throw validationError("Commerce audit outcome is invalid");
  }
  const target = normalizeCommerceAuditTarget(event.target);
  const actor = normalizeCommerceAuditActor(event.actor);
  const record: CommerceAuditRecord = {
    id: requireCommerceAuditPart(defaults.id, "id"),
    tenantId,
    action: requireCommerceAuditPart(event.action, "action"),
    outcome: event.outcome,
    actor,
    target,
    ...(event.requestId === undefined
      ? {}
      : { requestId: requireCommerceAuditPart(event.requestId, "requestId") }),
    metadata: sanitizeOpenPlatformAuditMetadata(event.metadata),
    occurredAt: normalizeOccurredAt(event.occurredAt ?? defaults.occurredAt),
    source: event.source === undefined
      ? COMMERCE_AUDIT_SOURCE
      : requireCommerceAuditPart(event.source, "source"),
  };
  return Object.freeze(record);
}

function normalizeCommerceAuditTarget(
  value: CommerceAuditTarget,
): CommerceAuditTarget {
  if (
    value === null ||
    typeof value !== "object" ||
    !isCommerceAuditResourceType(value.type)
  ) {
    throw validationError("Commerce audit target is invalid");
  }
  return Object.freeze({
    type: value.type,
    id: requireCommerceAuditPart(value.id, "target.id"),
    ...(value.displayName === undefined
      ? {}
      : { displayName: requireCommerceAuditPart(value.displayName, "target.displayName") }),
  });
}

function normalizeCommerceAuditActor(
  value: OpenPlatformAuditActor,
): OpenPlatformAuditActor {
  if (value === null || typeof value !== "object") {
    throw validationError("Commerce audit actor is invalid");
  }
  if (value.type !== "user" && value.type !== "service" && value.type !== "system") {
    throw validationError("Commerce audit actor is invalid");
  }
  return Object.freeze({
    type: value.type,
    id: requireCommerceAuditPart(value.id, "actor.id"),
  });
}

function normalizeCommerceAuditTenantId(value: unknown): string {
  return requireCommerceAuditPart(value, "tenantId");
}

function normalizeOccurredAt(value: unknown): string {
  if (value === undefined) {
    const now = new Date();
    if (!Number.isFinite(now.getTime())) {
      throw validationError("Commerce audit timestamp is invalid");
    }
    return now.toISOString();
  }
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) {
    throw validationError("Commerce audit timestamp is invalid");
  }
  return new Date(Date.parse(value)).toISOString();
}

function isCommerceAuditOutcome(value: unknown): value is CommerceAuditOutcome {
  return value === "success" || value === "failure" || value === "denied";
}

function isCommerceAuditResourceType(
  value: unknown,
): value is CommerceAuditResourceType {
  return typeof value === "string" &&
    (COMMERCE_AUDIT_RESOURCE_TYPES as readonly string[]).includes(value);
}

function requireCommerceAuditPart(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw validationError("Commerce audit field is invalid", { field });
  }
  const normalized = value.trim();
  if (
    normalized.length < 1 ||
    normalized.length > 256 ||
    /[\s\u0000-\u001f\u007f]/su.test(normalized)
  ) {
    throw validationError("Commerce audit field is invalid", { field });
  }
  return normalized;
}
