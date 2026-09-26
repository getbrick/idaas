import { createHash, randomUUID } from "node:crypto";
import { validationError } from "./errors.js";
import type { OpenPlatformDependencyReadiness } from "./types.js";

export const OPEN_PLATFORM_AUDIT_HASH_ALGORITHM = "sha256" as const;
export const OPEN_PLATFORM_AUDIT_OUTCOMES = ["success", "failure", "denied"] as const;
export type OpenPlatformAuditOutcome = (typeof OPEN_PLATFORM_AUDIT_OUTCOMES)[number];

export const OPEN_PLATFORM_AUDIT_ACTOR_TYPES = ["user", "service", "system"] as const;
export type OpenPlatformAuditActorType = (typeof OPEN_PLATFORM_AUDIT_ACTOR_TYPES)[number];

export type OpenPlatformAuditResourceType =
  | "tenant"
  | "developer_organization"
  | "application"
  | "application_environment"
  | "api_product"
  | "api_version"
  | "credential"
  | "subscription"
  | "scope_grant"
  | "usage"
  | "webhook"
  | "audit_event";

export type OpenPlatformAuditMetadata = Readonly<
  Record<string, string | number | boolean | null>
>;

export interface OpenPlatformAuditActor {
  readonly type: OpenPlatformAuditActorType;
  readonly id: string;
  readonly displayName?: string;
  readonly ipAddress?: string;
  readonly userAgent?: string;
}

export interface OpenPlatformAuditTarget {
  readonly type: OpenPlatformAuditResourceType;
  readonly id: string;
  readonly displayName?: string;
}

export interface OpenPlatformAuditEventInput {
  readonly id?: string;
  readonly tenantId: string;
  readonly action: string;
  readonly outcome: OpenPlatformAuditOutcome;
  readonly actor: OpenPlatformAuditActor;
  readonly target: OpenPlatformAuditTarget;
  readonly requestId?: string;
  readonly metadata?: OpenPlatformAuditMetadata;
  readonly occurredAt?: string;
  readonly source?: string;
}

export interface OpenPlatformAuditEventRecord extends OpenPlatformAuditEventInput {
  readonly contractVersion: 1;
  readonly id: string;
  readonly sequence: number;
  readonly previousHash?: string;
  readonly eventHash: string;
  readonly occurredAt: string;
  readonly metadata: OpenPlatformAuditMetadata;
  readonly source: string;
}

export interface OpenPlatformAuditQuery {
  readonly tenantId: string;
  readonly cursor?: string;
  readonly limit?: number;
  readonly action?: string;
  readonly outcome?: OpenPlatformAuditOutcome;
  readonly targetId?: string;
}

export type OpenPlatformAuditEvent = OpenPlatformAuditEventRecord;
export type OpenPlatformAuditEventInputRecord = OpenPlatformAuditEventInput;

export interface OpenPlatformAuditPage {
  readonly items: readonly OpenPlatformAuditEventRecord[];
  readonly nextCursor?: string;
  readonly previousCursor?: string;
  readonly hasMore: boolean;
  readonly total?: number;
}

export interface OpenPlatformAuditAppendPort {
  readonly productionReady?: boolean;
  readonly readiness?: OpenPlatformDependencyReadiness;
  append(event: OpenPlatformAuditEventInput): Promise<OpenPlatformAuditEventRecord>;
}

export interface OpenPlatformAuditReadPort {
  list(query: OpenPlatformAuditQuery): Promise<OpenPlatformAuditPage>;
  get?(tenantId: string, id: string): Promise<OpenPlatformAuditEventRecord | undefined>;
}

export interface OpenPlatformAuditPort extends OpenPlatformAuditAppendPort {
  list?(query: OpenPlatformAuditQuery): Promise<OpenPlatformAuditPage>;
  get?(tenantId: string, id: string): Promise<OpenPlatformAuditEventRecord | undefined>;
  verifyChain?(tenantId: string): Promise<boolean>;
}

export interface OpenPlatformAuditChainVerification {
  readonly valid: boolean;
  readonly reason?: string;
}

export interface InMemoryOpenPlatformAuditStoreOptions {
  readonly clock?: () => Date;
  readonly idGenerator?: () => string;
  readonly production?: boolean;
}

export class InMemoryOpenPlatformAuditEventStore implements OpenPlatformAuditPort {
  readonly productionReady = false;
  readonly readiness: OpenPlatformDependencyReadiness;
  private readonly events = new Map<string, OpenPlatformAuditEventRecord[]>();
  private readonly locks = new Map<string, Promise<void>>();
  private readonly clock: () => Date;
  private readonly idGenerator: () => string;

  private timestamp(): string {
    const value = this.clock();
    if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
      throw validationError("Audit clock is invalid", { field: "clock" });
    }
    return value.toISOString();
  }

  constructor(options: InMemoryOpenPlatformAuditStoreOptions = {}) {
    this.clock = options.clock ?? (() => new Date());
    this.idGenerator = options.idGenerator ?? (() => `audit_${randomUUID()}`);
    this.readiness = Object.freeze({
      storage: "memory" as const,
      distributed: false,
      ready: () => options.production !== true,
    });
  }

  async append(event: OpenPlatformAuditEventInput): Promise<OpenPlatformAuditEventRecord> {
    const tenantId = normalizeTenantId(event?.tenantId);
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
      const sequence = (previous?.sequence ?? 0) + 1;
       const normalized = normalizeAuditEvent(event, {
         id: event.id ?? this.idGenerator(),
         sequence,
         previousHash: previous?.eventHash,
         defaultOccurredAt: event.occurredAt === undefined ? this.timestamp() : undefined,
       });
       if (records.some((record) => record.id === normalized.id)) {
         throw validationError("Audit event identifier already exists");
       }
       records.push(normalized);
      this.events.set(tenantId, records);
      return structuredClone(normalized);
    } finally {
      release();
      if (this.locks.get(tenantId) === lock) this.locks.delete(tenantId);
    }
  }

  async list(query: OpenPlatformAuditQuery): Promise<OpenPlatformAuditPage> {
    const tenantId = normalizeTenantId(query?.tenantId);
    const limit = normalizeLimit(query?.limit);
    const after = query?.cursor === undefined ? undefined : decodeAuditCursor(query.cursor, tenantId);
    const action = query?.action === undefined ? undefined : requirePart(query.action, "action");
    const outcome = query?.outcome;
    if (outcome !== undefined && !isAuditOutcome(outcome)) {
      throw validationError("Audit outcome is invalid", { field: "outcome" });
    }
    const targetId = query?.targetId === undefined ? undefined : requirePart(query.targetId, "targetId");
    const all = (this.events.get(tenantId) ?? []).filter((event) =>
      (after === undefined || event.sequence > after) &&
      (action === undefined || event.action === action) &&
      (outcome === undefined || event.outcome === outcome) &&
      (targetId === undefined || event.target.id === targetId)
    );
    const items = all.slice(0, limit).map((event) => structuredClone(event));
    const hasMore = all.length > limit;
    const last = items.at(-1);
    const nextCursor = hasMore && last !== undefined
      ? encodeAuditCursor(tenantId, last.sequence)
      : undefined;
    return {
      items,
      ...(nextCursor === undefined ? {} : { nextCursor }),
      hasMore,
    };
  }

  async get(tenantId: string, id: string): Promise<OpenPlatformAuditEventRecord | undefined> {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const normalizedId = requirePart(id, "id");
    const event = (this.events.get(normalizedTenantId) ?? []).find((candidate) => candidate.id === normalizedId);
    return event === undefined ? undefined : structuredClone(event);
  }

  async verifyChain(tenantId: string): Promise<boolean> {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const records = this.events.get(normalizedTenantId) ?? [];
    let previousHash: string | undefined;
    for (const [index, event] of records.entries()) {
      if (event.sequence !== index + 1 || event.previousHash !== previousHash) return false;
      const expected = createOpenPlatformAuditEventHash(event);
      if (expected !== event.eventHash) return false;
      previousHash = event.eventHash;
    }
    return true;
  }

  snapshot(tenantId: string): OpenPlatformAuditEventRecord[] {
    return (this.events.get(normalizeTenantId(tenantId)) ?? []).map((event) => structuredClone(event));
  }
}

export const InMemoryOpenPlatformAuditStore = InMemoryOpenPlatformAuditEventStore;
export const InMemoryOpenPlatformAuditRepository = InMemoryOpenPlatformAuditEventStore;
export const InMemoryOpenPlatformAuditEventRepository = InMemoryOpenPlatformAuditEventStore;

export function createInMemoryOpenPlatformAuditEventStore(
  options: InMemoryOpenPlatformAuditStoreOptions = {},
): InMemoryOpenPlatformAuditEventStore {
  return new InMemoryOpenPlatformAuditEventStore(options);
}

export const createInMemoryOpenPlatformAuditStore = createInMemoryOpenPlatformAuditEventStore;
export const createInMemoryOpenPlatformAuditRepository = createInMemoryOpenPlatformAuditEventStore;
export const OpenPlatformAuditEventStore = InMemoryOpenPlatformAuditEventStore;
export const OpenPlatformManagementAuditStore = InMemoryOpenPlatformAuditEventStore;
export type OpenPlatformAuditRepository = OpenPlatformAuditPort;
export type OpenPlatformAuditEventRepository = OpenPlatformAuditPort;
export const createOpenPlatformAuditRepository = createInMemoryOpenPlatformAuditEventStore;
export async function appendOpenPlatformAuditEvent(
  port: OpenPlatformAuditAppendPort,
  event: OpenPlatformAuditEventInput,
): Promise<OpenPlatformAuditEventRecord> {
  return port.append(event);
}
export async function listOpenPlatformAuditEvents(
  port: OpenPlatformAuditReadPort,
  query: OpenPlatformAuditQuery,
): Promise<OpenPlatformAuditPage> {
  return port.list(query);
}
export type OpenPlatformAuditEventAppendPort = OpenPlatformAuditAppendPort;
export type OpenPlatformManagementAuditPort = OpenPlatformAuditPort;
export type OpenPlatformAuditAppender = OpenPlatformAuditAppendPort;
export type OpenPlatformAuditStore = OpenPlatformAuditPort;
export const createOpenPlatformManagementAuditStore = createInMemoryOpenPlatformAuditEventStore;
export const createOpenPlatformAuditStore = createInMemoryOpenPlatformAuditEventStore;

export function createOpenPlatformAuditEventHash(
  event: OpenPlatformAuditEventInput & {
    readonly sequence: number;
    readonly previousHash?: string;
  },
): string {
  const canonical = stableSerialize({
    contractVersion: 1,
    action: event.action,
    actor: event.actor,
    metadata: sanitizeOpenPlatformAuditMetadata(event.metadata),
    occurredAt: event.occurredAt,
    outcome: event.outcome,
    previousHash: event.previousHash ?? null,
    requestId: event.requestId ?? null,
    sequence: event.sequence,
    source: event.source ?? "open-platform",
    target: event.target,
    tenantId: event.tenantId,
  });
  return createHash(OPEN_PLATFORM_AUDIT_HASH_ALGORITHM).update(canonical, "utf8").digest("hex");
}

export const hashOpenPlatformAuditEvent = createOpenPlatformAuditEventHash;

export function sanitizeOpenPlatformAuditMetadata(
  value: Readonly<Record<string, unknown>> | undefined,
): OpenPlatformAuditMetadata {
  if (value === undefined) return Object.freeze({});
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw validationError("Audit metadata is invalid", { field: "metadata" });
  }
  const safe: Record<string, string | number | boolean | null> = {};
  for (const key of Object.keys(value).sort()) {
    if (isSensitiveKey(key)) continue;
    const item = value[key];
    if (item === null || typeof item === "boolean") {
      safe[key] = item;
    } else if (typeof item === "number" && Number.isFinite(item)) {
      safe[key] = item;
    } else if (typeof item === "string" && isSafeAuditString(item)) {
      safe[key] = item;
    }
  }
  return Object.freeze(safe);
}

export function encodeOpenPlatformAuditCursor(tenantId: string, sequence: number): string {
  const normalizedTenantId = normalizeTenantId(tenantId);
  if (!Number.isSafeInteger(sequence) || sequence < 0) throw validationError("Audit cursor is invalid");
  return `audit_${Buffer.from(JSON.stringify({ tenantId: normalizedTenantId, sequence }), "utf8").toString("base64url")}`;
}

export const createOpenPlatformAuditCursor = encodeOpenPlatformAuditCursor;

export function decodeOpenPlatformAuditCursor(cursor: string, tenantId: string): number {
  return decodeAuditCursor(cursor, normalizeTenantId(tenantId));
}

function normalizeAuditEvent(
  event: OpenPlatformAuditEventInput,
  chain: { id: string; sequence: number; previousHash?: string; defaultOccurredAt?: string },
): OpenPlatformAuditEventRecord {
  if (event === null || typeof event !== "object") {
    throw validationError("Audit event is invalid");
  }
  const tenantId = normalizeTenantId(event.tenantId);
  if (!isAuditOutcome(event.outcome)) throw validationError("Audit outcome is invalid", { field: "outcome" });
  const actor = normalizeActor(event.actor);
  const target = normalizeTarget(event.target);
  const occurredAt = normalizeTimestamp(event.occurredAt ?? chain.defaultOccurredAt ?? new Date().toISOString(), "occurredAt");
  const normalized: OpenPlatformAuditEventRecord = {
    contractVersion: 1,
    id: requirePart(chain.id, "id"),
    tenantId,
    action: requirePart(event.action, "action"),
    outcome: event.outcome,
    actor,
    target,
    ...(event.requestId === undefined ? {} : { requestId: requirePart(event.requestId, "requestId") }),
    metadata: sanitizeOpenPlatformAuditMetadata(event.metadata),
    occurredAt,
    sequence: chain.sequence,
    source: event.source === undefined ? "open-platform" : requirePart(event.source, "source"),
    ...(chain.previousHash === undefined ? {} : { previousHash: chain.previousHash }),
    eventHash: "",
  };
  return Object.freeze({
    ...normalized,
    eventHash: createOpenPlatformAuditEventHash(normalized),
  });
}

function normalizeActor(value: OpenPlatformAuditActor): OpenPlatformAuditActor {
  if (value === null || typeof value !== "object" || !isAuditActorType(value.type)) {
    throw validationError("Audit actor is invalid", { field: "actor" });
  }
  return Object.freeze({
    type: value.type,
    id: requirePart(value.id, "actor.id"),
    ...(value.displayName === undefined ? {} : { displayName: optionalAuditText(value.displayName, "actor.displayName") }),
    ...(value.ipAddress === undefined ? {} : { ipAddress: optionalAuditText(value.ipAddress, "actor.ipAddress") }),
    ...(value.userAgent === undefined ? {} : { userAgent: optionalAuditText(value.userAgent, "actor.userAgent") }),
  });
}

function normalizeTarget(value: OpenPlatformAuditTarget): OpenPlatformAuditTarget {
  if (value === null || typeof value !== "object" || !isAuditResourceType(value.type)) {
    throw validationError("Audit target is invalid", { field: "target" });
  }
  return Object.freeze({
    type: value.type,
    id: requirePart(value.id, "target.id"),
    ...(value.displayName === undefined ? {} : { displayName: optionalAuditText(value.displayName, "target.displayName") }),
  });
}

function normalizeTimestamp(value: unknown, field: string): string {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) {
    throw validationError("Audit timestamp is invalid", { field });
  }
  return new Date(Date.parse(value)).toISOString();
}

function normalizeTenantId(value: unknown): string {
  return requirePart(value, "tenantId");
}

function requirePart(value: unknown, field: string): string {
  if (typeof value !== "string") throw validationError("Audit field is invalid", { field });
  const normalized = value.trim();
  if (normalized.length < 1 || normalized.length > 256 || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw validationError("Audit field is invalid", { field });
  }
  return normalized;
}

function optionalText(value: unknown, field: string): string {
  if (typeof value !== "string") throw validationError("Audit text is invalid", { field });
  const normalized = value.trim();
  if (normalized.length < 1 || normalized.length > 256 || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw validationError("Audit text is invalid", { field });
  }
  return normalized;
}

function optionalAuditText(value: unknown, field: string): string {
  const normalized = optionalText(value, field);
  if (!isSafeAuditString(normalized)) throw validationError("Audit text is invalid", { field });
  return normalized;
}

function isSafeAuditString(value: string): boolean {
  return value.length <= 2048 && !/[\u0000-\u001f\u007f]/u.test(value) && !/(?:secret|password|token|authorization|private[-_]?key|vault:\/\/)/iu.test(value);
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

function isAuditOutcome(value: unknown): value is OpenPlatformAuditOutcome {
  return value === "success" || value === "failure" || value === "denied";
}

function isAuditActorType(value: unknown): value is OpenPlatformAuditActorType {
  return value === "user" || value === "service" || value === "system";
}

function isAuditResourceType(value: unknown): value is OpenPlatformAuditResourceType {
  return value === "tenant" ||
    value === "developer_organization" ||
    value === "application" ||
    value === "application_environment" ||
    value === "api_product" ||
    value === "api_version" ||
    value === "credential" ||
    value === "subscription" ||
    value === "scope_grant" ||
    value === "usage" ||
    value === "webhook" ||
    value === "audit_event";
}

function normalizeLimit(value: unknown): number {
  if (value === undefined) return 20;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1 || value > 100) {
    throw validationError("Audit page limit is invalid", { field: "limit" });
  }
  return value;
}

function encodeAuditCursor(tenantId: string, sequence: number): string {
  return encodeOpenPlatformAuditCursor(tenantId, sequence);
}

function decodeAuditCursor(value: unknown, tenantId: string): number {
  if (typeof value !== "string" || !/^audit_[A-Za-z0-9_-]+$/u.test(value)) {
    throw validationError("Audit cursor is invalid", { field: "cursor" });
  }
  try {
    const parsed = JSON.parse(Buffer.from(value.slice(6), "base64url").toString("utf8")) as Record<string, unknown>;
    if (parsed.tenantId !== tenantId || typeof parsed.sequence !== "number" || !Number.isSafeInteger(parsed.sequence) || parsed.sequence < 0) {
      throw new Error("invalid cursor scope");
    }
    return parsed.sequence;
  } catch {
    throw validationError("Audit cursor is invalid", { field: "cursor" });
  }
}

function stableSerialize(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw validationError("Audit hash input is invalid");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((item) => stableSerialize(item)).join(",")}]`;
  if (typeof value !== "object") throw validationError("Audit hash input is invalid");
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, item]) => item !== undefined)
    .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0);
  return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${stableSerialize(item)}`).join(",")}}`;
}
