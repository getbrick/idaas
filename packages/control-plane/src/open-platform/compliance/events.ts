import { createHash, randomUUID } from "node:crypto";
import {
  sanitizeOpenPlatformAuditMetadata,
  type OpenPlatformAuditActor,
  type OpenPlatformAuditMetadata,
  type OpenPlatformAuditPort,
} from "../audit.js";
import { complianceValidationError } from "./errors.js";
import { toComplianceAuditMetadata } from "./redaction.js";
import {
  complianceTransitionsFor,
  isComplianceTerminalStatus,
  type ComplianceStatefulEntityKind,
} from "./state-machine.js";
import type {
  ComplianceDependencyReadiness,
  ComplianceEntityKind,
} from "./types.js";

export const COMPLIANCE_AUDIT_SOURCE = "open-platform-compliance";
export const COMPLIANCE_EVENT_CHAIN_ALGORITHM = "sha256" as const;

export const COMPLIANCE_AUDIT_OUTCOMES = Object.freeze([
  "success",
  "failure",
  "denied",
] as const);
export type ComplianceAuditOutcome = (typeof COMPLIANCE_AUDIT_OUTCOMES)[number];

export const COMPLIANCE_AUDIT_ACTIONS = Object.freeze([
  "dataAsset.create",
  "dataAsset.transition",
  "consentRecord.create",
  "consentRecord.grant",
  "consentRecord.withdraw",
  "privacyRequest.create",
  "privacyRequest.transition",
  "privacyRequest.verifyIdentity",
  "privacyRequest.decide",
  "privacyRequest.recordAction",
  "retentionPolicy.create",
  "retentionPolicy.transition",
  "retentionExecution.record",
  "crossBorderAssessment.create",
  "crossBorderAssessment.transition",
  "crossBorderAssessment.decide",
  "vendor.create",
  "vendor.transition",
  "vendor.recordAssessment",
  "report.generate",
] as const);
export type ComplianceAuditAction = (typeof COMPLIANCE_AUDIT_ACTIONS)[number];

export const COMPLIANCE_AUDIT_RESOURCE_TYPES = Object.freeze([
  "dataAsset",
  "consentRecord",
  "privacyRequest",
  "retentionPolicy",
  "retentionExecution",
  "crossBorderAssessment",
  "vendor",
  "report",
] as const);
export type ComplianceAuditResourceType =
  (typeof COMPLIANCE_AUDIT_RESOURCE_TYPES)[number];

export const COMPLIANCE_AUDIT_ACTOR_TYPES = Object.freeze([
  "user",
  "service",
  "system",
] as const);
export type ComplianceAuditActorType =
  (typeof COMPLIANCE_AUDIT_ACTOR_TYPES)[number];

export interface ComplianceAuditActor {
  readonly type: ComplianceAuditActorType;
  readonly id: string;
  readonly displayName?: string;
}

export interface ComplianceAuditTarget {
  readonly type: ComplianceAuditResourceType;
  readonly id: string;
  readonly displayName?: string;
}

export interface ComplianceAuditEventInput {
  readonly tenantId: string;
  readonly action: ComplianceAuditAction | string;
  readonly outcome: ComplianceAuditOutcome;
  readonly actor: ComplianceAuditActor;
  readonly target: ComplianceAuditTarget;
  readonly requestId?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
  readonly occurredAt?: string;
  readonly source?: string;
}

export interface ComplianceAuditRecord {
  readonly id: string;
  readonly tenantId: string;
  readonly action: string;
  readonly outcome: ComplianceAuditOutcome;
  readonly actor: ComplianceAuditActor;
  readonly target: ComplianceAuditTarget;
  readonly requestId?: string;
  readonly metadata: Readonly<Record<string, string | number | boolean | null>>;
  readonly occurredAt: string;
  readonly source: string;
}

export interface ComplianceAuditPort {
  readonly productionReady?: boolean;
  readonly readiness?: ComplianceDependencyReadiness;
  append(event: ComplianceAuditEventInput): Promise<ComplianceAuditRecord>;
}

export interface InMemoryComplianceAuditStoreOptions {
  readonly clock?: () => Date;
  readonly idGenerator?: () => string;
  readonly production?: boolean;
  readonly maxEvents?: number;
  readonly retentionMs?: number;
}

export class InMemoryComplianceAuditStore implements ComplianceAuditPort {
  readonly productionReady = false;
  readonly readiness: ComplianceDependencyReadiness;
  private readonly events = new Map<string, ComplianceAuditRecord[]>();
  private readonly clock: () => Date;
  private readonly idGenerator: () => string;
  private readonly maxEvents: number;
  private readonly retentionMs: number;

  constructor(options: InMemoryComplianceAuditStoreOptions = {}) {
    this.clock = options.clock ?? (() => new Date());
    this.idGenerator =
      options.idGenerator ?? (() => `compliance_audit_${randomUUID()}`);
    const maxEvents = options.maxEvents ?? 10_000;
    const retentionMs = options.retentionMs ?? 2_592_000_000;
    if (!Number.isSafeInteger(maxEvents) || maxEvents < 1 || maxEvents > 1_000_000) {
      throw complianceValidationError("Compliance audit capacity is invalid");
    }
    if (
      !Number.isSafeInteger(retentionMs) ||
      retentionMs < 60_000 ||
      retentionMs > 7_776_000_000
    ) {
      throw complianceValidationError("Compliance audit retention is invalid");
    }
    this.maxEvents = maxEvents;
    this.retentionMs = retentionMs;
    this.readiness = Object.freeze({
      storage: "memory" as const,
      distributed: false,
      ready: () => options.production !== true,
    });
  }

  async append(event: ComplianceAuditEventInput): Promise<ComplianceAuditRecord> {
    const record = normalizeComplianceAuditEvent(event, {
      id: this.idGenerator(),
      occurredAt: this.timestamp(),
    });
    const records = this.events.get(record.tenantId) ?? [];
    this.prune(records, record.occurredAt);
    records.push(record);
    if (records.length > this.maxEvents) {
      records.splice(0, records.length - this.maxEvents);
    }
    this.events.set(record.tenantId, records);
    return cloneAuditRecord(record);
  }

  list(tenantId: string): ComplianceAuditRecord[] {
    const normalized = requireAuditPart(tenantId, "tenantId");
    return (this.events.get(normalized) ?? []).map(cloneAuditRecord);
  }

  size(): number {
    let total = 0;
    for (const records of this.events.values()) total += records.length;
    return total;
  }

  private prune(records: ComplianceAuditRecord[], now: string): void {
    const threshold = Date.parse(now) - this.retentionMs;
    let index = 0;
    while (
      index < records.length &&
      Date.parse(records[index]?.occurredAt ?? "") <= threshold
    ) {
      index += 1;
    }
    if (index > 0) records.splice(0, index);
  }

  private timestamp(): string {
    const value = this.clock();
    if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
      throw complianceValidationError("Compliance audit clock is invalid");
    }
    return value.toISOString();
  }
}

export const InMemoryComplianceAuditEventStore = InMemoryComplianceAuditStore;
export const InMemoryComplianceAuditRepository = InMemoryComplianceAuditStore;

export function createInMemoryComplianceAuditStore(
  options: InMemoryComplianceAuditStoreOptions = {},
): InMemoryComplianceAuditStore {
  return new InMemoryComplianceAuditStore(options);
}

export interface ComplianceEventInput {
  readonly tenantId: string;
  readonly kind: ComplianceEntityKind;
  readonly recordId: string;
  readonly eventType: string;
  readonly fromStatus?: string;
  readonly toStatus?: string;
  readonly actorRef: string;
  readonly occurredAt: string;
  readonly dataAssetIds?: readonly string[];
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface ComplianceEventRecord extends ComplianceEventInput {
  readonly id: string;
  readonly sequence: number;
  readonly previousHash?: string;
  readonly eventHash: string;
  readonly metadata: Readonly<Record<string, string | number | boolean | null>>;
}

export interface ComplianceEventQuery {
  readonly tenantId: string;
  readonly kind?: ComplianceEntityKind;
  readonly recordId?: string;
  readonly eventType?: string;
  readonly fromSequence?: number;
  readonly limit?: number;
}

export interface ComplianceEventPage {
  readonly items: readonly ComplianceEventRecord[];
  readonly nextSequence?: number;
  readonly hasMore: boolean;
  readonly total: number;
}

export interface ComplianceEventPort {
  readonly productionReady?: boolean;
  readonly readiness?: ComplianceDependencyReadiness;
  append(event: ComplianceEventInput): Promise<ComplianceEventRecord>;
  list(query: ComplianceEventQuery): Promise<ComplianceEventPage>;
  verifyChain(tenantId: string): Promise<boolean>;
}

export class InMemoryComplianceEventStore implements ComplianceEventPort {
  readonly productionReady = false;
  readonly readiness: ComplianceDependencyReadiness;
  private readonly events = new Map<string, ComplianceEventRecord[]>();
  private readonly locks = new Map<string, Promise<void>>();

  constructor(options: { readonly production?: boolean } = {}) {
    this.readiness = Object.freeze({
      storage: "memory" as const,
      distributed: false,
      ready: () => options.production !== true,
    });
  }

  async append(event: ComplianceEventInput): Promise<ComplianceEventRecord> {
    const tenantId = requireAuditPart(event?.tenantId, "tenantId");
    const previousLock = this.locks.get(tenantId) ?? Promise.resolve();
    let release!: () => void;
    const currentLock = new Promise<void>((resolve) => {
      release = resolve;
    });
    const lock = previousLock.then(() => currentLock);
    this.locks.set(tenantId, lock);
    await previousLock;
    try {
      const records = this.events.get(tenantId) ?? [];
      const previous = records.at(-1);
      const normalized = normalizeComplianceEvent(event, {
        id: `compliance_event_${randomUUID()}`,
        sequence: (previous?.sequence ?? 0) + 1,
        previousHash: previous?.eventHash,
      });
      if (records.some((record) => record.id === normalized.id)) {
        throw complianceValidationError(
          "Compliance event identifier already exists",
          "id",
        );
      }
      records.push(normalized);
      this.events.set(tenantId, records);
      return cloneEventRecord(normalized);
    } finally {
      release();
      if (this.locks.get(tenantId) === lock) this.locks.delete(tenantId);
    }
  }

  async list(query: ComplianceEventQuery): Promise<ComplianceEventPage> {
    const tenantId = requireAuditPart(query?.tenantId, "tenantId");
    const limit = normalizeEventLimit(query?.limit);
    const fromSequence = query?.fromSequence ?? 0;
    if (!Number.isSafeInteger(fromSequence) || fromSequence < 0) {
      throw complianceValidationError("Compliance event cursor is invalid", "fromSequence");
    }
    const recordId =
      query?.recordId === undefined
        ? undefined
        : requireAuditPart(query.recordId, "recordId");
    const eventType =
      query?.eventType === undefined
        ? undefined
        : requireAuditPart(query.eventType, "eventType");
    const all = (this.events.get(tenantId) ?? []).filter(
      (event) =>
        (query.kind === undefined || event.kind === query.kind) &&
        (recordId === undefined || event.recordId === recordId) &&
        (eventType === undefined || event.eventType === eventType) &&
        event.sequence > fromSequence,
    );
    const items = all.slice(0, limit).map(cloneEventRecord);
    const last = items.at(-1);
    return {
      items,
      ...(last === undefined ? {} : { nextSequence: last.sequence }),
      hasMore: all.length > items.length,
      total: all.length,
    };
  }

  async verifyChain(tenantId: string): Promise<boolean> {
    const records = this.events.get(
      requireAuditPart(tenantId, "tenantId"),
    ) ?? [];
    let previousHash: string | undefined;
    for (const [index, event] of records.entries()) {
      if (event.sequence !== index + 1 || event.previousHash !== previousHash) {
        return false;
      }
      if (createComplianceEventHash(event) !== event.eventHash) return false;
      previousHash = event.eventHash;
    }
    return true;
  }

  snapshot(tenantId: string): ComplianceEventRecord[] {
    return (this.events.get(requireAuditPart(tenantId, "tenantId")) ?? []).map(
      cloneEventRecord,
    );
  }
}

export const InMemoryComplianceEventRepository = InMemoryComplianceEventStore;

export function createInMemoryComplianceEventStore(options: {
  readonly production?: boolean;
} = {}): InMemoryComplianceEventStore {
  return new InMemoryComplianceEventStore(options);
}

export function createComplianceEventHash(
  event: ComplianceEventInput & {
    readonly sequence: number;
    readonly previousHash?: string;
  },
): string {
  const canonical = stableSerialize({
    actorRef: event.actorRef,
    dataAssetIds: [...(event.dataAssetIds ?? [])].sort(),
    eventType: event.eventType,
    fromStatus: event.fromStatus ?? null,
    kind: event.kind,
    metadata: toComplianceAuditMetadata(event.metadata),
    occurredAt: event.occurredAt,
    previousHash: event.previousHash ?? null,
    recordId: event.recordId,
    sequence: event.sequence,
    tenantId: event.tenantId,
    toStatus: event.toStatus ?? null,
  });
  return createHash(COMPLIANCE_EVENT_CHAIN_ALGORITHM)
    .update(canonical, "utf8")
    .digest("hex");
}

export interface ComplianceOpenPlatformAuditBridgeOptions {
  readonly actionPrefix?: string;
}

export function createComplianceAuditBridge(
  audit: OpenPlatformAuditPort,
  options: ComplianceOpenPlatformAuditBridgeOptions = {},
): ComplianceAuditPort {
  if (
    audit === null ||
    typeof audit !== "object" ||
    typeof audit.append !== "function"
  ) {
    throw complianceValidationError("Compliance audit port is invalid", "audit");
  }
  const actionPrefix = options.actionPrefix ?? "compliance.";
  return Object.freeze({
    productionReady: audit.productionReady === true,
    async append(event: ComplianceAuditEventInput): Promise<ComplianceAuditRecord> {
      const metadata: OpenPlatformAuditMetadata =
        sanitizeOpenPlatformAuditMetadata(toComplianceAuditMetadata(event.metadata));
      const appended = await audit.append({
        tenantId: requireAuditPart(event.tenantId, "tenantId"),
        action: `${actionPrefix}${requireAuditPart(event.action, "action")}`,
        outcome: event.outcome,
        actor: toOpenPlatformActor(event.actor),
        target: {
          type: "audit_event",
          id: requireAuditPart(event.target.id, "target.id"),
          ...(event.target.displayName === undefined
            ? {}
            : {
              displayName: requireAuditPart(
                event.target.displayName,
                "target.displayName",
              ),
            }),
        },
        ...(event.requestId === undefined
          ? {}
          : { requestId: requireAuditPart(event.requestId, "requestId") }),
        metadata,
        ...(event.occurredAt === undefined ? {} : { occurredAt: event.occurredAt }),
        source: COMPLIANCE_AUDIT_SOURCE,
      });
      return {
        id: appended.id,
        tenantId: appended.tenantId,
        action: requireAuditPart(event.action, "action"),
        outcome: event.outcome,
        actor: event.actor,
        target: event.target,
        ...(appended.requestId === undefined ? {} : { requestId: appended.requestId }),
        metadata: appended.metadata,
        occurredAt: appended.occurredAt,
        source: COMPLIANCE_AUDIT_SOURCE,
      };
    },
  });
}

export function complianceStatusTransitionEventType(
  entity: ComplianceStatefulEntityKind,
  toStatus: string,
): string {
  if (isComplianceTerminalStatus(entity, toStatus)) {
    return `${entity}.${toStatus}`;
  }
  const from = Object.keys(complianceTransitionsFor(entity)).find((status) =>
    (complianceTransitionsFor(entity)[status] ?? []).includes(toStatus),
  );
  return from === undefined ? `${entity}.${toStatus}` : `${entity}.${from}->${toStatus}`;
}

function normalizeComplianceEvent(
  event: ComplianceEventInput,
  chain: {
    readonly id: string;
    readonly sequence: number;
    readonly previousHash?: string;
  },
): ComplianceEventRecord {
  if (event === null || typeof event !== "object") {
    throw complianceValidationError("Compliance event is invalid", "event");
  }
  if (!Number.isSafeInteger(chain.sequence) || chain.sequence < 1) {
    throw complianceValidationError("Compliance event sequence is invalid", "sequence");
  }
  const metadata = toComplianceAuditMetadata(event.metadata);
  const base = {
    tenantId: requireAuditPart(event.tenantId, "tenantId"),
    kind: event.kind,
    recordId: requireAuditPart(event.recordId, "recordId"),
    eventType: requireAuditPart(event.eventType, "eventType"),
    ...(event.fromStatus === undefined
      ? {}
      : { fromStatus: requireAuditPart(event.fromStatus, "fromStatus") }),
    ...(event.toStatus === undefined
      ? {}
      : { toStatus: requireAuditPart(event.toStatus, "toStatus") }),
    actorRef: requireAuditPart(event.actorRef, "actorRef"),
    occurredAt: normalizeOccurredAt(event.occurredAt),
    ...(event.dataAssetIds === undefined
      ? {}
      : { dataAssetIds: normalizeDataAssetIds(event.dataAssetIds) }),
    metadata,
  };
  const withChain: Omit<ComplianceEventRecord, "eventHash"> = {
    ...base,
    id: chain.id,
    sequence: chain.sequence,
    ...(chain.previousHash === undefined
      ? {}
      : { previousHash: chain.previousHash }),
    metadata,
  };
  return Object.freeze({
    ...withChain,
    eventHash: createComplianceEventHash(withChain),
  });
}

function normalizeComplianceAuditEvent(
  event: ComplianceAuditEventInput,
  defaults: { readonly id: string; readonly occurredAt: string },
): ComplianceAuditRecord {
  if (event === null || typeof event !== "object") {
    throw complianceValidationError("Compliance audit event is invalid", "event");
  }
  return Object.freeze({
    id: requireAuditPart(defaults.id, "id"),
    tenantId: requireAuditPart(event.tenantId, "tenantId"),
    action: requireAuditPart(event.action, "action"),
    outcome: normalizeAuditOutcome(event.outcome),
    actor: normalizeAuditActor(event.actor),
    target: normalizeAuditTarget(event.target),
    ...(event.requestId === undefined
      ? {}
      : { requestId: requireAuditPart(event.requestId, "requestId") }),
    metadata: toComplianceAuditMetadata(event.metadata),
    occurredAt: normalizeOccurredAt(event.occurredAt ?? defaults.occurredAt),
    source:
      event.source === undefined
        ? COMPLIANCE_AUDIT_SOURCE
        : requireAuditPart(event.source, "source"),
  });
}

function normalizeAuditOutcome(value: unknown): ComplianceAuditOutcome {
  if (
    value !== "success" &&
    value !== "failure" &&
    value !== "denied"
  ) {
    throw complianceValidationError("Compliance audit outcome is invalid", "outcome");
  }
  return value;
}

function normalizeAuditActor(value: ComplianceAuditActor): ComplianceAuditActor {
  if (value === null || typeof value !== "object") {
    throw complianceValidationError("Compliance audit actor is invalid", "actor");
  }
  if (
    value.type !== "user" &&
    value.type !== "service" &&
    value.type !== "system"
  ) {
    throw complianceValidationError("Compliance audit actor is invalid", "actor.type");
  }
  return Object.freeze({
    type: value.type,
    id: requireAuditPart(value.id, "actor.id"),
    ...(value.displayName === undefined
      ? {}
      : { displayName: requireAuditPart(value.displayName, "actor.displayName") }),
  });
}

function normalizeAuditTarget(value: ComplianceAuditTarget): ComplianceAuditTarget {
  if (
    value === null ||
    typeof value !== "object" ||
    typeof value.type !== "string" ||
    !(COMPLIANCE_AUDIT_RESOURCE_TYPES as readonly string[]).includes(value.type)
  ) {
    throw complianceValidationError("Compliance audit target is invalid", "target");
  }
  return Object.freeze({
    type: value.type,
    id: requireAuditPart(value.id, "target.id"),
    ...(value.displayName === undefined
      ? {}
      : { displayName: requireAuditPart(value.displayName, "target.displayName") }),
  });
}

function normalizeDataAssetIds(value: readonly string[]): string[] {
  if (!Array.isArray(value)) {
    throw complianceValidationError("Compliance data asset scope is invalid", "dataAssetIds");
  }
  return [...new Set(value.map((item) => requireAuditPart(item, "dataAssetIds")))].sort(
    (left, right) => (left < right ? -1 : left > right ? 1 : 0),
  );
}

function normalizeEventLimit(value: unknown): number {
  if (value === undefined) return 50;
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > 500) {
    throw complianceValidationError("Compliance event limit is invalid", "limit");
  }
  return value as number;
}

function normalizeOccurredAt(value: unknown): string {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) {
    throw complianceValidationError("Compliance timestamp is invalid", "occurredAt");
  }
  return new Date(Date.parse(value)).toISOString();
}

function toOpenPlatformActor(actor: ComplianceAuditActor): OpenPlatformAuditActor {
  return {
    type: actor.type,
    id: actor.id,
    ...(actor.displayName === undefined ? {} : { displayName: actor.displayName }),
  };
}

function requireAuditPart(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw complianceValidationError("Compliance audit field is invalid", field);
  }
  const normalized = value.trim();
  if (
    normalized.length < 1 ||
    normalized.length > 256 ||
    /[\s\u0000-\u001f\u007f]/su.test(normalized)
  ) {
    throw complianceValidationError("Compliance audit field is invalid", field);
  }
  return normalized;
}

function cloneAuditRecord(record: ComplianceAuditRecord): ComplianceAuditRecord {
  return structuredClone(record);
}

function cloneEventRecord(record: ComplianceEventRecord): ComplianceEventRecord {
  return structuredClone(record);
}

function stableSerialize(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw complianceValidationError("Compliance hash input is invalid", "metadata");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableSerialize(item)).join(",")}]`;
  }
  if (typeof value !== "object") {
    throw complianceValidationError("Compliance hash input is invalid", "metadata");
  }
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, item]) => item !== undefined)
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));
  return `{${entries
    .map(([key, item]) => `${JSON.stringify(key)}:${stableSerialize(item)}`)
    .join(",")}}`;
}
