import { randomUUID } from "node:crypto";
import {
  resourceConflict,
  resourceNotFound,
  validationError,
} from "../errors.js";
import {
  OPEN_PLATFORM_DOMAIN_EVENT_MAX_ATTEMPTS,
  OPEN_PLATFORM_DOMAIN_EVENT_OUTBOX_STATUSES,
  brandOpenPlatformDomainEventRecord,
  isOpenPlatformDomainEventType,
  sanitizeOpenPlatformDomainEventData,
  type OpenPlatformDomainEventData,
  type OpenPlatformDomainEventInput,
  type OpenPlatformDomainEventType,
  type OpenPlatformDomainEventStatus,
  type OpenPlatformOutboxClaimRequest,
  type OpenPlatformOutboxClaimResult,
  type OpenPlatformOutboxCompleteRequest,
  type OpenPlatformOutboxFailRequest,
  type OpenPlatformOutboxPage,
  type OpenPlatformOutboxPort,
  type OpenPlatformOutboxQuery,
  type OpenPlatformOutboxRecord,
} from "../events.js";
import { normalizeIdentifier, normalizeTenantKey } from "../validation.js";
import {
  normalizeOpenPlatformRelayLeaseRequest,
  type OpenPlatformRelayLeasePort,
  type OpenPlatformRelayLeaseRequest,
  type OpenPlatformRelayLeaseState,
} from "../events-relay.js";
import type { OpenPlatformDependencyReadiness, OpenPlatformEntityKind } from "../types.js";
import {
  OpenPlatformSqlRuntime,
  createOpenPlatformSqlRuntime,
  readBoolean,
  readDate,
  readNumber,
  readText,
  rowValue,
  type DatabaseAdapter,
  type OpenPlatformSqlRepositoryInput,
  type OpenPlatformSqlRepositorySecondOptions,
} from "./adapter.js";

const DOMAIN_EVENT_DATA_LIMIT = 32;

export interface SqlOpenPlatformOutboxRepositoryOptions
  extends OpenPlatformSqlRepositorySecondOptions {
  readonly maxAttempts?: number;
}

export class SqlDomainEventOutboxRepository implements OpenPlatformOutboxPort {
  readonly productionReady = true;
  readonly readiness: OpenPlatformDependencyReadiness;
  private readonly runtime: OpenPlatformSqlRuntime;
  private readonly maxAttempts: number;

  constructor(
    input: OpenPlatformSqlRepositoryInput,
    options?: SqlOpenPlatformOutboxRepositoryOptions,
  ) {
    this.runtime = createOpenPlatformSqlRuntime(input, options);
    this.maxAttempts = normalizeMaxAttempts(options?.maxAttempts);
    this.readiness = Object.freeze({
      storage: "persistent" as const,
      distributed: this.runtime.distributed,
      ready: () => this.isReady(),
    });
  }

  async isReady(): Promise<boolean> {
    return this.runtime.isReady(["domainEvents"]);
  }

  async append(
    event: OpenPlatformDomainEventInput,
  ): Promise<OpenPlatformOutboxRecord> {
    const normalized = normalizeEventInput(event, {
      tenantId: this.runtime.tenantId,
      maxAttempts: this.maxAttempts,
    });
    return this.runtime.withTransaction(async (executor) => {
      const existing = await this.findByEventId(
        normalized.tenantId,
        normalized.eventId,
        executor,
      );
      if (existing !== undefined) return existing;
      const sequence = await this.nextSequence(normalized.tenantId, executor);
      const values = [
        normalized.eventId,
        normalized.tenantId,
        normalized.eventType,
        normalized.resourceType,
        normalized.resourceId,
        normalized.resourceVersion ?? null,
        normalized.resourceStatus ?? null,
        normalized.actorId ?? null,
        normalized.requestId ?? null,
        normalized.occurredAt,
        normalized.schemaVersion,
        JSON.stringify(normalized.data),
        "pending",
        sequence,
        0,
        normalized.maxAttempts,
        normalized.occurredAt,
        normalized.occurredAt,
        normalized.occurredAt,
      ];
      let result;
      try {
        result = await this.runtime.executeMutation(
          `INSERT INTO ${this.runtime.table("domainEvents")} (${domainEventFields().map((field) => this.column(field)).join(", ")}) VALUES (${values.map((_value, index) => `$${index + 1}`).join(", ")}) RETURNING ${this.select()}`,
          values,
          executor,
        );
      } catch (error) {
        if (!isConflictError(error)) throw error;
        const raced = await this.findByEventId(
          normalized.tenantId,
          normalized.eventId,
          executor,
        );
        if (raced === undefined) throw error;
        return raced;
      }
      if (result.affected !== 1 || result.rows[0] === undefined) {
        throw resourceConflict("Open platform domain event already exists");
      }
      return this.mapRecord(result.rows[0]);
    });
  }

  async get(
    tenantId: string,
    eventId: string,
  ): Promise<OpenPlatformOutboxRecord | undefined> {
    return this.findByEventId(
      requiredTenant(tenantId),
      requiredText(eventId, "domainEvent"),
    );
  }

  async list(query: OpenPlatformOutboxQuery): Promise<OpenPlatformOutboxPage> {
    const tenantId = requiredTenant(query?.tenantId);
    if (tenantId !== this.runtime.tenantId) return { items: [], hasMore: false };
    const limit = normalizeLimit(query.limit);
    const fromSequence = query.fromSequence ?? 0;
    if (!Number.isSafeInteger(fromSequence) || fromSequence < 0) {
      throw validationError("Open platform outbox cursor is invalid", {
        field: "fromSequence",
      });
    }
    const values: unknown[] = [tenantId, fromSequence];
    const clauses = [
      `${this.column("tenantId")} = $1`,
      `${this.column("sequence")} > $2`,
    ];
    for (const [field, value] of [
      ["status", query.status],
      ["eventType", query.eventType],
      ["resourceType", query.resourceType],
      ["resourceId", query.resourceId],
    ] as const) {
      if (value === undefined) continue;
      values.push(value);
      clauses.push(`${this.column(field)} = $${values.length}`);
    }
    values.push(limit + 1);
    const rows = await this.runtime.queryRows(
      `SELECT ${this.select()} FROM ${this.runtime.table("domainEvents")} WHERE ${clauses.join(" AND ")} ORDER BY ${this.column("sequence")} ASC LIMIT $${values.length}`,
      values,
    );
    const hasMore = rows.length > limit;
    const items = rows.slice(0, limit).map((row) => this.mapRecord(row));
    const last = items.at(-1);
    return {
      items,
      ...(last === undefined ? {} : { nextSequence: last.sequence }),
      hasMore,
    };
  }

  async claim(
    request: OpenPlatformOutboxClaimRequest,
  ): Promise<OpenPlatformOutboxClaimResult> {
    const normalized = normalizeClaim(request);
    if (normalized.tenantId !== this.runtime.tenantId) return { claimed: false };
    const result = await this.runtime.executeMutation(
      `UPDATE ${this.runtime.table("domainEvents")} SET ${[
        `${this.column("status")} = 'delivering'`,
        `${this.column("attempt")} = GREATEST(${this.column("attempt")}, $3::integer)`,
        `${this.column("leaseId")} = $4`,
        `${this.column("leaseExpiresAt")} = $5::timestamptz`,
        `${this.column("updatedAt")} = $6::timestamptz`,
      ].join(", ")} WHERE ${this.column("tenantId")} = $1 AND ${this.column("id")} = $2 AND ${this.column("attempt")} < ${this.column("maxAttempts")} AND (${[
        `${this.column("status")} IN ('pending', 'failed')`,
        `(${this.column("status")} = 'delivering' AND COALESCE(${this.column("leaseExpiresAt")}, TIMESTAMP 'epoch' AT TIME ZONE 'UTC') <= $6::timestamptz)`,
      ].join(" OR ")}) AND (${this.column("nextAttemptAt")} IS NULL OR ${this.column("nextAttemptAt")} <= $6::timestamptz) RETURNING ${this.select()}`,
      [
        normalized.tenantId,
        normalized.eventId,
        normalized.attempt,
        normalized.leaseId,
        normalized.leaseExpiresAt,
        normalized.now,
      ],
    );
    if (result.affected !== 1 || result.rows[0] === undefined) {
      return { claimed: false };
    }
    return { claimed: true, record: this.mapRecord(result.rows[0]) };
  }

  async complete(
    request: OpenPlatformOutboxCompleteRequest,
  ): Promise<OpenPlatformOutboxRecord> {
    const normalized = normalizeComplete(request);
    if (normalized.tenantId !== this.runtime.tenantId) {
      throw resourceNotFound("outboxEvent");
    }
    const assignments = [
      `${this.column("status")} = 'published'`,
      `${this.column("publishedAt")} = $3::timestamptz`,
      `${this.column("updatedAt")} = $3::timestamptz`,
      `${this.column("nextAttemptAt")} = NULL`,
      `${this.column("errorCode")} = NULL`,
      `${this.column("leaseId")} = NULL`,
      `${this.column("leaseExpiresAt")} = NULL`,
    ];
    const result = await this.runtime.executeMutation(
      `UPDATE ${this.runtime.table("domainEvents")} SET ${assignments.join(", ")} WHERE ${this.column("tenantId")} = $1 AND ${this.column("id")} = $2 AND ${this.column("status")} <> 'published' RETURNING ${this.select()}`,
      [normalized.tenantId, normalized.eventId, normalized.now],
    );
    if (result.affected === 1 && result.rows[0] !== undefined) {
      return this.mapRecord(result.rows[0]);
    }
    const current = await this.findByEventId(normalized.tenantId, normalized.eventId);
    if (current === undefined) throw resourceNotFound("outboxEvent");
    return current;
  }

  async fail(
    request: OpenPlatformOutboxFailRequest,
  ): Promise<OpenPlatformOutboxRecord> {
    const normalized = normalizeFail(request);
    if (normalized.tenantId !== this.runtime.tenantId) {
      throw resourceNotFound("outboxEvent");
    }
    const current = await this.requireRecord(normalized.tenantId, normalized.eventId);
    if (current.status === "published") return current;
    const deadLettered = normalized.deadLetter === true ||
      current.attempt >= current.maxAttempts;
    const status: OpenPlatformDomainEventStatus = deadLettered
      ? "dead_lettered"
      : "failed";
    const assignments = [
      `${this.column("status")} = $3`,
      `${this.column("nextAttemptAt")} = ${deadLettered || normalized.nextAttemptAt === undefined ? "NULL" : "$4::timestamptz"}`,
      `${this.column("errorCode")} = $5`,
      `${this.column("leaseId")} = NULL`,
      `${this.column("leaseExpiresAt")} = NULL`,
      `${this.column("updatedAt")} = $6::timestamptz`,
    ];
    const result = await this.runtime.executeMutation(
      `UPDATE ${this.runtime.table("domainEvents")} SET ${assignments.join(", ")} WHERE ${this.column("tenantId")} = $1 AND ${this.column("id")} = $2 AND ${this.column("status")} <> 'published' RETURNING ${this.select()}`,
      [
        normalized.tenantId,
        normalized.eventId,
        status,
        normalized.nextAttemptAt ?? null,
        normalized.errorCode,
        normalized.now,
      ],
    );
    if (result.affected === 1 && result.rows[0] !== undefined) {
      return this.mapRecord(result.rows[0]);
    }
    return this.requireRecord(normalized.tenantId, normalized.eventId);
  }

  private async nextSequence(
    tenantId: string,
    executor: DatabaseAdapter,
  ): Promise<number> {
    await this.runtime.queryRows(
      `SELECT ${this.runtime.column("tenants", "tenantId")} FROM ${this.runtime.table("tenants")} WHERE ${this.runtime.column("tenants", "tenantId")} = $1 FOR UPDATE`,
      [tenantId],
      executor,
    );
    const rows = await this.runtime.queryRows(
      `SELECT COALESCE(MAX(${this.column("sequence")}), 0) AS ${quoteAlias("maxSequence")} FROM ${this.runtime.table("domainEvents")} WHERE ${this.column("tenantId")} = $1`,
      [tenantId],
      executor,
    );
    const current = readNumber(rows[0] === undefined ? undefined : rows[0].maxSequence);
    return (current ?? 0) + 1;
  }

  private async findByEventId(
    tenantId: string,
    eventId: string,
    executor?: DatabaseAdapter,
  ): Promise<OpenPlatformOutboxRecord | undefined> {
    if (tenantId !== this.runtime.tenantId) return undefined;
    const rows = await this.runtime.queryRows(
      `SELECT ${this.select()} FROM ${this.runtime.table("domainEvents")} WHERE ${this.column("tenantId")} = $1 AND ${this.column("id")} = $2 LIMIT 1`,
      [tenantId, eventId],
      executor,
    );
    return rows[0] === undefined ? undefined : this.mapRecord(rows[0]);
  }

  private async requireRecord(
    tenantId: string,
    eventId: string,
  ): Promise<OpenPlatformOutboxRecord> {
    const record = await this.findByEventId(tenantId, eventId);
    if (record === undefined) throw resourceNotFound("outboxEvent");
    return record;
  }

  private column(field: string): string {
    return this.runtime.column("domainEvents", field);
  }

  private select(): string {
    return domainEventFields()
      .map((field) => `${this.column(field)} AS ${quoteAlias(field)}`)
      .join(", ");
  }

  private mapRecord(row: Record<string, unknown>): OpenPlatformOutboxRecord {
    const eventType = requiredText(rowValue(row, "eventType"), "domainEvent");
    if (!isOpenPlatformDomainEventType(eventType)) {
      throw new Error("Invalid domain event type SQL row");
    }
    const status = requiredText(rowValue(row, "status"), "domainEvent");
    if (!(OPEN_PLATFORM_DOMAIN_EVENT_OUTBOX_STATUSES as readonly string[]).includes(status)) {
      throw new Error("Invalid domain event status SQL row");
    }
    const attempt = requiredNumber(rowValue(row, "attempt"), "domainEvent", true);
    const maxAttempts = requiredNumber(rowValue(row, "maxAttempts"), "domainEvent");
    if (attempt > maxAttempts) throw new Error("Invalid domain event attempt SQL row");
    return brandOpenPlatformDomainEventRecord(
      Object.freeze({
        eventId: requiredText(rowValue(row, "id"), "domainEvent"),
        tenantId: requiredText(rowValue(row, "tenantId"), "domainEvent"),
        eventType,
        resourceType: requiredText(rowValue(row, "resourceType"), "domainEvent") as OpenPlatformEntityKind,
        resourceId: requiredText(rowValue(row, "resourceId"), "domainEvent"),
        ...optionalNumber(rowValue(row, "resourceVersion"), "resourceVersion"),
        ...optionalText(rowValue(row, "resourceStatus"), "resourceStatus"),
        ...optionalText(rowValue(row, "actorId"), "actorId"),
        ...optionalText(rowValue(row, "requestId"), "requestId"),
        occurredAt: requiredDate(rowValue(row, "occurredAt"), "domainEvent"),
        schemaVersion: requiredText(rowValue(row, "schemaVersion"), "domainEvent"),
        data: readEventData(rowValue(row, "data")),
        status: status as OpenPlatformDomainEventStatus,
        sequence: requiredNumber(rowValue(row, "sequence"), "domainEvent"),
        attempt,
        maxAttempts,
        createdAt: requiredDate(rowValue(row, "createdAt"), "domainEvent"),
        updatedAt: requiredDate(rowValue(row, "updatedAt"), "domainEvent"),
        ...optionalDate(rowValue(row, "nextAttemptAt"), "nextAttemptAt"),
        ...optionalDate(rowValue(row, "publishedAt"), "publishedAt"),
        ...optionalText(rowValue(row, "errorCode"), "errorCode"),
        ...optionalText(rowValue(row, "leaseId"), "leaseId"),
        ...optionalDate(rowValue(row, "leaseExpiresAt"), "leaseExpiresAt"),
      }),
    );
  }
}

export const SqlOpenPlatformOutboxRepository = SqlDomainEventOutboxRepository;
export const SqlDomainEventRepository = SqlDomainEventOutboxRepository;
export const PostgresDomainEventOutboxRepository = SqlDomainEventOutboxRepository;
export const PostgreSqlDomainEventOutboxRepository = SqlDomainEventOutboxRepository;

export class SqlOpenPlatformRelayLease implements OpenPlatformRelayLeasePort {
  readonly productionReady = true;
  readonly readiness: OpenPlatformDependencyReadiness;
  private readonly runtime: OpenPlatformSqlRuntime;

  constructor(
    input: OpenPlatformSqlRepositoryInput,
    options?: OpenPlatformSqlRepositorySecondOptions,
  ) {
    this.runtime = createOpenPlatformSqlRuntime(input, options);
    this.readiness = Object.freeze({
      storage: "persistent" as const,
      distributed: this.runtime.distributed,
      ready: () => this.isReady(),
    });
  }

  async isReady(): Promise<boolean> {
    return this.runtime.isReady(["domainEvents"]);
  }

  async acquire(
    request: OpenPlatformRelayLeaseRequest,
  ): Promise<OpenPlatformRelayLeaseState> {
    const normalized = normalizeOpenPlatformRelayLeaseRequest(request);
    const rows = await this.runtime.queryRows(
      `SELECT pg_try_advisory_lock(hashtextextended($1, 0)) AS ${quoteAlias("acquired")}`,
      [normalized.key],
    );
    return advisoryLeaseState(normalized, readBoolean(rowValue(rows[0] ?? {}, "acquired")));
  }

  async renew(
    request: OpenPlatformRelayLeaseRequest,
  ): Promise<OpenPlatformRelayLeaseState> {
    return this.acquire(request);
  }

  async release(request: OpenPlatformRelayLeaseRequest): Promise<boolean> {
    const normalized = normalizeOpenPlatformRelayLeaseRequest(request);
    const rows = await this.runtime.queryRows(
      `SELECT pg_advisory_unlock(hashtextextended($1, 0)) AS ${quoteAlias("released")}`,
      [normalized.key],
    );
    return readBoolean(rowValue(rows[0] ?? {}, "released"));
  }
}

export const SqlDomainEventRelayLease = SqlOpenPlatformRelayLease;
export const PostgresOpenPlatformRelayLease = SqlOpenPlatformRelayLease;
export const PostgreSqlOpenPlatformRelayLease = SqlOpenPlatformRelayLease;

function advisoryLeaseState(
  request: OpenPlatformRelayLeaseRequest,
  held: boolean,
): OpenPlatformRelayLeaseState {
  return Object.freeze({
    key: request.key,
    ownerId: request.ownerId,
    held,
    ...(held
      ? {
          expiresAt: new Date(
            Date.parse(request.now) + request.ttlMs,
          ).toISOString(),
        }
      : {}),
  });
}

function domainEventFields(): string[] {
  return [
    "id",
    "tenantId",
    "eventType",
    "resourceType",
    "resourceId",
    "resourceVersion",
    "resourceStatus",
    "actorId",
    "requestId",
    "occurredAt",
    "schemaVersion",
    "data",
    "status",
    "sequence",
    "attempt",
    "maxAttempts",
    "nextAttemptAt",
    "publishedAt",
    "errorCode",
    "leaseId",
    "leaseExpiresAt",
    "createdAt",
    "updatedAt",
  ];
}

interface NormalizedDomainEvent extends OpenPlatformDomainEventInput {
  readonly eventId: string;
  readonly tenantId: string;
  readonly eventType: OpenPlatformDomainEventType;
  readonly occurredAt: string;
  readonly schemaVersion: string;
  readonly data: OpenPlatformDomainEventData;
  readonly maxAttempts: number;
}

function normalizeEventInput(
  event: OpenPlatformDomainEventInput,
  defaults: { readonly tenantId: string; readonly maxAttempts: number },
): NormalizedDomainEvent {
  if (event === null || typeof event !== "object") {
    throw validationError("Open platform domain event is invalid", { field: "event" });
  }
  if (!isOpenPlatformDomainEventType(event.eventType)) {
    throw validationError("Open platform domain event type is invalid", {
      field: "eventType",
    });
  }
  const tenantId = normalizeTenantKey(event.tenantId);
  if (tenantId !== defaults.tenantId) {
    throw validationError("Open platform domain event tenant is invalid", {
      field: "tenantId",
    });
  }
  if (event.resourceVersion !== undefined &&
    (!Number.isSafeInteger(event.resourceVersion) || event.resourceVersion < 1)) {
    throw validationError("Open platform domain event version is invalid", {
      field: "resourceVersion",
    });
  }
  const data = sanitizeOpenPlatformDomainEventData(event.data);
  if (Object.keys(data).length > DOMAIN_EVENT_DATA_LIMIT) {
    throw validationError("Open platform domain event data is too large", {
      field: "data",
    });
  }
  return {
    eventId: normalizeIdentifier(
      event.eventId ?? `open_platform_event_${randomEventId()}`,
      "eventId",
    ),
    tenantId,
    eventType: event.eventType,
    resourceType: event.resourceType,
    resourceId: normalizeIdentifier(event.resourceId, "resourceId"),
    ...(event.resourceVersion === undefined
      ? {}
      : { resourceVersion: event.resourceVersion }),
    ...(event.resourceStatus === undefined
      ? {}
      : { resourceStatus: normalizeIdentifier(event.resourceStatus, "resourceStatus") }),
    ...(event.actorId === undefined
      ? {}
      : { actorId: normalizeIdentifier(event.actorId, "actorId") }),
    ...(event.requestId === undefined
      ? {}
      : { requestId: normalizeIdentifier(event.requestId, "requestId") }),
    occurredAt: requiredDate(event.occurredAt, "occurredAt"),
    schemaVersion: normalizeIdentifier(
      event.schemaVersion ?? "open-platform.domain-event.v1",
      "schemaVersion",
    ),
    data,
    maxAttempts: defaults.maxAttempts,
  };
}

function normalizeClaim(
  request: OpenPlatformOutboxClaimRequest,
): OpenPlatformOutboxClaimRequest {
  if (request === null || typeof request !== "object") {
    throw validationError("Open platform outbox claim is invalid", { field: "claim" });
  }
  if (!Number.isSafeInteger(request.attempt) || request.attempt < 1) {
    throw validationError("Open platform outbox claim attempt is invalid", {
      field: "attempt",
    });
  }
  const now = requiredDate(request.now, "now");
  const leaseExpiresAt = requiredDate(request.leaseExpiresAt, "leaseExpiresAt");
  if (Date.parse(leaseExpiresAt) <= Date.parse(now)) {
    throw validationError("Open platform outbox claim lease is invalid", {
      field: "leaseExpiresAt",
    });
  }
  return {
    tenantId: requiredTenant(request.tenantId),
    eventId: requiredText(request.eventId, "domainEvent"),
    attempt: request.attempt,
    leaseId: requiredText(request.leaseId, "domainEvent"),
    now,
    leaseExpiresAt,
  };
}

function normalizeComplete(
  request: OpenPlatformOutboxCompleteRequest,
): OpenPlatformOutboxCompleteRequest {
  if (request === null || typeof request !== "object") {
    throw validationError("Open platform outbox completion is invalid", {
      field: "complete",
    });
  }
  return {
    tenantId: requiredTenant(request.tenantId),
    eventId: requiredText(request.eventId, "domainEvent"),
    now: requiredDate(request.now, "now"),
  };
}

function normalizeFail(
  request: OpenPlatformOutboxFailRequest,
): OpenPlatformOutboxFailRequest & { readonly errorCode: string } {
  const base = normalizeComplete(request);
  return {
    ...base,
    errorCode: requiredText(request.errorCode, "errorCode"),
    ...(request.nextAttemptAt === undefined
      ? {}
      : { nextAttemptAt: requiredDate(request.nextAttemptAt, "nextAttemptAt") }),
    ...(request.deadLetter === true ? { deadLetter: true } : {}),
  };
}

function isConflictError(error: unknown): boolean {
  return (
    error !== null &&
    typeof error === "object" &&
    (error as { code?: unknown }).code === "OPEN_PLATFORM_RESOURCE_CONFLICT"
  );
}

function readEventData(value: unknown): OpenPlatformDomainEventData {
  if (value === null || value === undefined) return Object.freeze({});
  if (typeof value === "string") {
    try {
      return sanitizeOpenPlatformDomainEventData(
        JSON.parse(value) as Record<string, unknown>,
      );
    } catch {
      throw new Error("Invalid domain event data SQL row");
    }
  }
  if (typeof value === "object") {
    return sanitizeOpenPlatformDomainEventData(
      value as Record<string, unknown>,
    );
  }
  throw new Error("Invalid domain event data SQL row");
}

function randomEventId(): string {
  return randomUUID();
}

function requiredTenant(value: unknown): string {
  return normalizeTenantKey(value);
}

function requiredText(value: unknown, field: string): string {
  const text = readText(value);
  if (text === undefined || text.length === 0) {
    throw new Error(`Invalid ${field} SQL row`);
  }
  return text;
}

function requiredDate(value: unknown, field: string): string {
  const date = readDate(value);
  if (date === undefined) throw new Error(`Invalid ${field} SQL row`);
  return date;
}

function requiredNumber(value: unknown, field: string, allowZero = false): number {
  const number = readNumber(value);
  if (number === undefined || number < (allowZero ? 0 : 1)) {
    throw new Error(`Invalid ${field} SQL row`);
  }
  return number;
}

function optionalDate(value: unknown, field: string): Record<string, string> {
  const date = readDate(value);
  return date === undefined ? {} : { [field]: date };
}

function optionalNumber(value: unknown, field: string): Record<string, number> {
  const number = readNumber(value);
  return number === undefined ? {} : { [field]: number };
}

function optionalText(value: unknown, field: string): Record<string, string> {
  const text = readText(value);
  return text === undefined ? {} : { [field]: text };
}

function normalizeMaxAttempts(value: unknown): number {
  if (value === undefined) return OPEN_PLATFORM_DOMAIN_EVENT_MAX_ATTEMPTS;
  if (
    !Number.isSafeInteger(value) ||
    (value as number) < 1 ||
    (value as number) > 20
  ) {
    throw validationError("Open platform event maximum attempts is invalid");
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

function quoteAlias(value: string): string {
  return `"${value.replace(/"/gu, '""')}"`;
}
