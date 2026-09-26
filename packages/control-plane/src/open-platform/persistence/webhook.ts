import {
  resourceConflict,
  resourceNotFound,
  validationError,
} from "../errors.js";
import {
  OPEN_PLATFORM_WEBHOOK_DELIVERY_STATUSES,
  OPEN_PLATFORM_WEBHOOK_EVENT_TYPES,
  OPEN_PLATFORM_WEBHOOK_STATUSES,
} from "../webhook.js";
import type {
  OpenPlatformWebhook,
  OpenPlatformWebhookDelivery,
  OpenPlatformWebhookDeliveryClaimRequest,
  OpenPlatformWebhookDeliveryClaimResult,
  OpenPlatformWebhookDeliveryPage,
  OpenPlatformWebhookDeliveryPort,
  OpenPlatformWebhookDeliveryQuery,
  OpenPlatformWebhookPage,
  OpenPlatformWebhookPort,
  OpenPlatformWebhookQuery,
} from "../webhook.js";
import type { OpenPlatformDependencyReadiness } from "../types.js";
import {
  OpenPlatformSqlRuntime,
  createOpenPlatformSqlRuntime,
  readDate,
  readNumber,
  readStringArray,
  readText,
  isUniqueViolation,
  rowValue,
  type OpenPlatformMutationResult,
  type OpenPlatformSqlRepositoryInput,
  type OpenPlatformSqlRepositorySecondOptions,
} from "./adapter.js";

const DELIVERY_LEASE_ID_COLUMN = "lease_id";
const DELIVERY_LEASE_EXPIRES_AT_COLUMN = "lease_expires_at";

export class SqlWebhookRepository implements OpenPlatformWebhookPort {
  readonly productionReady = true;
  readonly readiness: OpenPlatformDependencyReadiness;
  protected readonly runtime: OpenPlatformSqlRuntime;

  constructor(input: OpenPlatformSqlRepositoryInput, options?: OpenPlatformSqlRepositorySecondOptions) {
    this.runtime = createOpenPlatformSqlRuntime(input, options);
    this.readiness = Object.freeze({
      storage: "persistent" as const,
      distributed: this.runtime.distributed,
      ready: () => this.isReady(),
    });
  }

  async create(record: OpenPlatformWebhook): Promise<OpenPlatformWebhook> {
    const normalized = normalizeWebhook(record, this.runtime.tenantId);
    return this.runtime.withTransaction(async (executor) => {
      const fields = webhookFields();
      let result: OpenPlatformMutationResult;
      try {
        result = await this.runtime.executeMutation(
          `INSERT INTO ${this.runtime.table("webhooks")} (${fields.map((field) => this.runtime.column("webhooks", field)).join(", ")}) VALUES (${fields.map((_field, index) => `$${index + 1}`).join(", ")}) RETURNING ${this.select("webhooks", fields)}`,
          webhookValues(normalized),
          executor,
        );
      } catch (error) {
        if (isUniqueViolation(error)) throw resourceConflict("Webhook already exists");
        throw error;
      }
      if (result.affected !== 1) throw resourceConflict("Webhook already exists");
      return result.rows[0] === undefined ? normalized : this.mapWebhook(result.rows[0]);
    });
  }

  async get(tenantId: string, id: string): Promise<OpenPlatformWebhook | undefined> {
    const normalizedTenantId = requiredText(tenantId, "webhook");
    if (normalizedTenantId !== this.runtime.tenantId) return undefined;
    const values = [normalizedTenantId, id];
    const rows = await this.runtime.queryRows(
      `SELECT ${this.select("webhooks", webhookFields())} FROM ${this.runtime.table("webhooks")} WHERE ${this.runtime.column("webhooks", "tenantId")} = $1 AND ${this.runtime.column("webhooks", "id")} = $2 LIMIT 1`,
      values,
    );
    return rows[0] === undefined ? undefined : this.mapWebhook(rows[0]);
  }

  async list(tenantId: string): Promise<OpenPlatformWebhook[]> {
    if (requiredText(tenantId, "webhook") !== this.runtime.tenantId) return [];
    const rows = await this.runtime.queryRows(
      `SELECT ${this.select("webhooks", webhookFields())} FROM ${this.runtime.table("webhooks")} WHERE ${this.runtime.column("webhooks", "tenantId")} = $1 ORDER BY ${this.runtime.column("webhooks", "createdAt")} ASC, ${this.runtime.column("webhooks", "id")} ASC`,
      [tenantId],
    );
    return rows.map((row) => this.mapWebhook(row));
  }

  async save(record: OpenPlatformWebhook): Promise<OpenPlatformWebhook> {
    const normalized = normalizeWebhook(record, this.runtime.tenantId);
    return this.runtime.withTransaction(async (executor) => {
      const currentRows = await this.runtime.queryRows(
        `SELECT ${this.select("webhooks", webhookFields())} FROM ${this.runtime.table("webhooks")} WHERE ${this.runtime.column("webhooks", "tenantId")} = $1 AND ${this.runtime.column("webhooks", "id")} = $2 LIMIT 1 FOR UPDATE`,
        [normalized.tenantId, normalized.id],
        executor,
      );
      const current = currentRows[0] === undefined ? undefined : this.mapWebhook(currentRows[0]);
      if (current === undefined) throw resourceNotFound("webhook");
      if (current.version + 1 !== normalized.version) throw resourceConflict("Webhook version is stale");
      const fields = webhookFields().filter((field) => !["id", "tenantId", "kind", "createdAt"].includes(field));
      const values = [normalized.tenantId, normalized.id, current.version, ...fields.map((field) => webhookStorageValue(field, normalized))];
      const assignments = fields.map((field, index) => `${this.runtime.column("webhooks", field)} = $${index + 4}`);
      const result = await this.runtime.executeMutation(
        `UPDATE ${this.runtime.table("webhooks")} SET ${assignments.join(", ")} WHERE ${this.runtime.column("webhooks", "tenantId")} = $1 AND ${this.runtime.column("webhooks", "id")} = $2 AND ${this.runtime.column("webhooks", "version")} = $3 RETURNING ${this.select("webhooks", webhookFields())}`,
        values,
        executor,
      );
      if (result.affected !== 1) throw resourceConflict("Webhook version is stale");
      return result.rows[0] === undefined ? normalized : this.mapWebhook(result.rows[0]);
    });
  }

  async isReady(): Promise<boolean> {
    return this.runtime.isReady(["webhooks"]);
  }

  protected mapWebhook(row: Record<string, unknown>): OpenPlatformWebhook {
    const status = requiredText(rowValue(row, "status"), "webhook");
    if (!(OPEN_PLATFORM_WEBHOOK_STATUSES as readonly string[]).includes(status)) throw new Error("Invalid webhook status SQL row");
    const events = readStringArray(rowValue(row, "events"));
    if (events.length < 1 || events.some((event) => !(OPEN_PLATFORM_WEBHOOK_EVENT_TYPES as readonly string[]).includes(event))) throw new Error("Invalid webhook events SQL row");
    return {
      id: requiredText(rowValue(row, "id"), "webhook"),
      tenantId: requiredText(rowValue(row, "tenantId"), "webhook"),
      kind: "webhook",
      developerOrganizationId: requiredText(rowValue(row, "developerOrganizationId"), "webhook"),
      applicationId: requiredText(rowValue(row, "applicationId"), "webhook"),
      environmentId: requiredText(rowValue(row, "environmentId"), "webhook"),
      name: requiredText(rowValue(row, "name"), "webhook"),
      endpointUrl: requiredText(rowValue(row, "endpointUrl"), "webhook"),
      status: status as OpenPlatformWebhook["status"],
      events,
      signingAlgorithm: "hmac-sha256",
      signingSecretReference: requiredText(rowValue(row, "signingSecretReference"), "webhook"),
      secretVersion: requiredNumber(rowValue(row, "secretVersion"), "webhook"),
      failureCount: requiredNumber(rowValue(row, "failureCount"), "webhook", true),
      ...optionalDate(rowValue(row, "nextDeliveryAt"), "nextDeliveryAt"),
      ...optionalDate(rowValue(row, "lastDeliveryAt"), "lastDeliveryAt"),
      version: requiredNumber(rowValue(row, "version"), "webhook"),
      createdAt: requiredDate(rowValue(row, "createdAt"), "webhook"),
      updatedAt: requiredDate(rowValue(row, "updatedAt"), "webhook"),
    };
  }

  protected select(table: "webhooks", fields: readonly string[]): string {
    return fields.map((field) => `${this.runtime.column(table, field)} AS ${quoteAlias(field)}`).join(", ");
  }
}

export class SqlWebhookDeliveryRepository implements OpenPlatformWebhookDeliveryPort {
  readonly productionReady = true;
  readonly readiness: OpenPlatformDependencyReadiness;
  private readonly runtime: OpenPlatformSqlRuntime;

  constructor(input: OpenPlatformSqlRepositoryInput, options?: OpenPlatformSqlRepositorySecondOptions) {
    this.runtime = createOpenPlatformSqlRuntime(input, options);
    this.readiness = Object.freeze({
      storage: "persistent" as const,
      distributed: this.runtime.distributed,
      ready: () => this.isReady(),
    });
  }

  async append(record: OpenPlatformWebhookDelivery): Promise<OpenPlatformWebhookDelivery> {
    const normalized = normalizeDelivery(record, this.runtime.tenantId);
    const fields = deliveryFields();
    return this.runtime.withTransaction(async (executor) => {
      let result: OpenPlatformMutationResult;
      try {
        result = await this.runtime.executeMutation(
          `INSERT INTO ${this.runtime.table("webhookDeliveries")} (${fields.map((field) => this.deliveryColumn(field)).join(", ")}) VALUES (${fields.map((_field, index) => `$${index + 1}`).join(", ")}) RETURNING ${this.select(fields)}`,
          deliveryValues(normalized),
          executor,
        );
      } catch (error) {
        if (isUniqueViolation(error)) throw resourceConflict("Webhook event has already been recorded");
        throw error;
      }
      if (result.affected !== 1) throw resourceConflict("Webhook event has already been recorded");
      return result.rows[0] === undefined ? normalized : this.mapDelivery(result.rows[0]);
    });
  }

  async get(tenantId: string, id: string): Promise<OpenPlatformWebhookDelivery | undefined> {
    const normalizedTenantId = requiredText(tenantId, "webhookDelivery");
    if (normalizedTenantId !== this.runtime.tenantId) return undefined;
    const rows = await this.runtime.queryRows(
      `SELECT ${this.select(deliveryFields())} FROM ${this.runtime.table("webhookDeliveries")} WHERE ${this.runtime.column("webhookDeliveries", "tenantId")} = $1 AND ${this.runtime.column("webhookDeliveries", "id")} = $2 LIMIT 1`,
      [tenantId, id],
    );
    return rows[0] === undefined ? undefined : this.mapDelivery(rows[0]);
  }

  async list(query: OpenPlatformWebhookDeliveryQuery): Promise<OpenPlatformWebhookDeliveryPage> {
    const tenantId = requiredText(query.tenantId, "webhookDelivery");
    if (tenantId !== this.runtime.tenantId) return { items: [], hasMore: false };
    const limit = normalizeLimit(query.limit);
    const values: unknown[] = [tenantId];
    const clauses = [`${this.runtime.column("webhookDeliveries", "tenantId")} = $1`];
    for (const [field, value] of [["webhookId", query.webhookId], ["eventId", query.eventId], ["status", query.status]] as const) {
      if (value !== undefined) {
        values.push(value);
        clauses.push(`${this.runtime.column("webhookDeliveries", field)} = $${values.length}`);
      }
    }
    const offset = query.cursor === undefined ? 0 : decodeCursor(query.cursor, tenantId);
    values.push(limit + 1, offset);
    const rows = await this.runtime.queryRows(
      `SELECT ${this.select(deliveryFields())} FROM ${this.runtime.table("webhookDeliveries")} WHERE ${clauses.join(" AND ")} ORDER BY ${this.runtime.column("webhookDeliveries", "createdAt")} ASC, ${this.runtime.column("webhookDeliveries", "id")} ASC LIMIT $${values.length - 1} OFFSET $${values.length}`,
      values,
    );
    const hasMore = rows.length > limit;
    const items = rows.slice(0, limit).map((row) => this.mapDelivery(row));
    return {
      items,
      ...(hasMore ? { nextCursor: encodeCursor(tenantId, offset + limit) } : {}),
      hasMore,
    };
  }

  async update(tenantId: string, id: string, patch: Partial<OpenPlatformWebhookDelivery>): Promise<OpenPlatformWebhookDelivery> {
    const current = await this.get(tenantId, id);
    if (current === undefined) throw resourceNotFound("webhookDelivery");
    const next = normalizeDelivery({ ...current, ...patch, tenantId: current.tenantId, id: current.id, webhookId: current.webhookId, eventId: current.eventId, createdAt: current.createdAt }, this.runtime.tenantId);
    const fields = deliveryFields().filter((field) => !["id", "tenantId", "webhookId", "eventId", "createdAt"].includes(field));
    const values = [next.tenantId, next.id, ...fields.map((field) => deliveryStorageValue(field, next))];
    const assignments = fields.map((field, index) => `${this.deliveryColumn(field)} = $${index + 3}`);
    const result = await this.runtime.executeMutation(
      `UPDATE ${this.runtime.table("webhookDeliveries")} SET ${assignments.join(", ")} WHERE ${this.runtime.column("webhookDeliveries", "tenantId")} = $1 AND ${this.runtime.column("webhookDeliveries", "id")} = $2 RETURNING ${this.select(deliveryFields())}`,
      values,
    );
    if (result.affected !== 1) throw resourceNotFound("webhookDelivery");
    return result.rows[0] === undefined ? next : this.mapDelivery(result.rows[0]);
  }

  async claim(
    request: OpenPlatformWebhookDeliveryClaimRequest,
  ): Promise<OpenPlatformWebhookDeliveryClaimResult> {
    const normalized = normalizeClaim(request);
    if (normalized.tenantId !== this.runtime.tenantId) return { claimed: false };
    const result = await this.runtime.executeMutation(
      `UPDATE ${this.runtime.table("webhookDeliveries")} SET ${[
        `${this.runtime.column("webhookDeliveries", "status")} = 'delivering'`,
        `${this.runtime.column("webhookDeliveries", "attempt")} = GREATEST(${this.runtime.column("webhookDeliveries", "attempt")}, $3::integer)`,
        `${this.runtime.quote(DELIVERY_LEASE_ID_COLUMN)} = $4`,
        `${this.runtime.quote(DELIVERY_LEASE_EXPIRES_AT_COLUMN)} = $5::timestamptz`,
        `${this.runtime.column("webhookDeliveries", "updatedAt")} = $6::timestamptz`,
      ].join(", ")} WHERE ${this.runtime.column("webhookDeliveries", "tenantId")} = $1 AND ${this.runtime.column("webhookDeliveries", "id")} = $2 AND (${[
        `${this.runtime.column("webhookDeliveries", "status")} IN ('pending', 'failed')`,
        `(${this.runtime.column("webhookDeliveries", "status")} = 'delivering' AND COALESCE(${this.runtime.quote(DELIVERY_LEASE_EXPIRES_AT_COLUMN)}, TIMESTAMP 'epoch' AT TIME ZONE 'UTC') <= $6::timestamptz)`,
      ].join(" OR ")}) RETURNING ${this.select(deliveryFields())}`,
      [
        normalized.tenantId,
        normalized.id,
        normalized.attempt,
        normalized.leaseId,
        normalized.leaseExpiresAt,
        normalized.now,
      ],
    );
    if (result.affected !== 1) return { claimed: false };
    return { claimed: true, delivery: this.mapDelivery(result.rows[0]) };
  }

  async findByEvent(tenantId: string, webhookId: string, eventId: string): Promise<OpenPlatformWebhookDelivery | undefined> {
    const normalizedTenantId = requiredText(tenantId, "webhookDelivery");
    if (normalizedTenantId !== this.runtime.tenantId) return undefined;
    const rows = await this.runtime.queryRows(
      `SELECT ${this.select(deliveryFields())} FROM ${this.runtime.table("webhookDeliveries")} WHERE ${this.runtime.column("webhookDeliveries", "tenantId")} = $1 AND ${this.runtime.column("webhookDeliveries", "webhookId")} = $2 AND ${this.runtime.column("webhookDeliveries", "eventId")} = $3 LIMIT 1`,
      [normalizedTenantId, webhookId, eventId],
    );
    return rows[0] === undefined ? undefined : this.mapDelivery(rows[0]);
  }

  async isReady(): Promise<boolean> {
    return this.runtime.isReady(["webhookDeliveries"]);
  }

  private select(fields: readonly string[]): string {
    return fields.map((field) => `${this.deliveryColumn(field)} AS ${quoteAlias(field)}`).join(", ");
  }

  private deliveryColumn(field: string): string {
    if (field === "leaseId") return this.runtime.quote(DELIVERY_LEASE_ID_COLUMN);
    if (field === "leaseExpiresAt") return this.runtime.quote(DELIVERY_LEASE_EXPIRES_AT_COLUMN);
    return this.runtime.column("webhookDeliveries", field === "event" ? "event" : field);
  }

  private mapDelivery(row: Record<string, unknown>): OpenPlatformWebhookDelivery {
    const event = requiredText(rowValue(row, "event"), "webhookDelivery");
    if (!(OPEN_PLATFORM_WEBHOOK_EVENT_TYPES as readonly string[]).includes(event)) throw new Error("Invalid webhook delivery event SQL row");
    const status = requiredText(rowValue(row, "status"), "webhookDelivery");
    if (!(OPEN_PLATFORM_WEBHOOK_DELIVERY_STATUSES as readonly string[]).includes(status)) throw new Error("Invalid webhook delivery status SQL row");
    const attempt = requiredNumber(rowValue(row, "attempt"), "webhookDelivery", true);
    const maxAttempts = requiredNumber(rowValue(row, "maxAttempts"), "webhookDelivery");
    if (attempt > maxAttempts) throw new Error("Invalid webhook delivery attempt SQL row");
    const responseStatusCode = optionalNumber(rowValue(row, "responseStatusCode"), "responseStatusCode");
    if (responseStatusCode.responseStatusCode !== undefined && (responseStatusCode.responseStatusCode < 100 || responseStatusCode.responseStatusCode > 599)) throw new Error("Invalid webhook delivery response SQL row");
    return {
      id: requiredText(rowValue(row, "id"), "webhookDelivery"),
      tenantId: requiredText(rowValue(row, "tenantId"), "webhookDelivery"),
      webhookId: requiredText(rowValue(row, "webhookId"), "webhookDelivery"),
      eventId: requiredText(rowValue(row, "eventId"), "webhookDelivery"),
      event,
      eventType: event,
      status: status as OpenPlatformWebhookDelivery["status"],
      attempt,
      maxAttempts,
      idempotencyKey: requiredText(rowValue(row, "idempotencyKey"), "webhookDelivery"),
      payload: requiredText(rowValue(row, "payload"), "webhookDelivery"),
      body: requiredText(rowValue(row, "body"), "webhookDelivery"),
      secretVersion: requiredNumber(rowValue(row, "secretVersion"), "webhookDelivery"),
      createdAt: requiredDate(rowValue(row, "createdAt"), "webhookDelivery"),
      updatedAt: requiredDate(rowValue(row, "updatedAt"), "webhookDelivery"),
      ...optionalDate(rowValue(row, "nextAttemptAt"), "nextAttemptAt"),
      ...optionalDate(rowValue(row, "deliveredAt"), "deliveredAt"),
      ...optionalNumber(rowValue(row, "responseStatusCode"), "responseStatusCode"),
      ...optionalText(rowValue(row, "responseBodyExcerpt"), "responseBodyExcerpt"),
      ...optionalText(rowValue(row, "errorCode"), "errorCode"),
      ...optionalText(rowValue(row, "leaseId"), "leaseId"),
      ...optionalDate(rowValue(row, "leaseExpiresAt"), "leaseExpiresAt"),
    };
  }
}

function webhookFields(): string[] {
  return [
    "id",
    "tenantId",
    "kind",
    "developerOrganizationId",
    "applicationId",
    "environmentId",
    "name",
    "endpointUrl",
    "status",
    "events",
    "signingAlgorithm",
    "signingSecretReference",
    "secretVersion",
    "failureCount",
    "nextDeliveryAt",
    "lastDeliveryAt",
    "version",
    "createdAt",
    "updatedAt",
  ];
}

function deliveryFields(): string[] {
  return [
    "id",
    "tenantId",
    "webhookId",
    "eventId",
    "event",
    "status",
    "attempt",
    "maxAttempts",
    "idempotencyKey",
    "payload",
    "body",
    "secretVersion",
    "nextAttemptAt",
    "deliveredAt",
    "responseStatusCode",
    "responseBodyExcerpt",
    "errorCode",
    "leaseId",
    "leaseExpiresAt",
    "createdAt",
    "updatedAt",
  ];
}

function webhookValues(record: OpenPlatformWebhook): unknown[] {
  return [
    record.id,
    record.tenantId,
    record.kind,
    record.developerOrganizationId,
    record.applicationId,
    record.environmentId,
    record.name,
    record.endpointUrl,
    record.status,
    JSON.stringify(record.events),
    record.signingAlgorithm,
    record.signingSecretReference,
    record.secretVersion,
    record.failureCount,
    record.nextDeliveryAt,
    record.lastDeliveryAt,
    record.version,
    record.createdAt,
    record.updatedAt,
  ];
}

function deliveryValues(record: OpenPlatformWebhookDelivery): unknown[] {
  return [
    record.id,
    record.tenantId,
    record.webhookId,
    record.eventId,
    record.event,
    record.status,
    record.attempt,
    record.maxAttempts,
    record.idempotencyKey,
    record.payload,
    record.body ?? record.payload,
    record.secretVersion,
    record.nextAttemptAt,
    record.deliveredAt,
    record.responseStatusCode,
    record.responseBodyExcerpt,
    record.errorCode,
    record.leaseId,
    record.leaseExpiresAt,
    record.createdAt,
    record.updatedAt,
  ];
}

function webhookStorageValue(field: string, record: OpenPlatformWebhook): unknown {
  if (field === "events") return JSON.stringify(record.events);
  if (["nextDeliveryAt", "lastDeliveryAt"].includes(field)) return record[field as "nextDeliveryAt" | "lastDeliveryAt"];
  return (record as unknown as Record<string, unknown>)[field];
}

function deliveryStorageValue(field: string, record: OpenPlatformWebhookDelivery): unknown {
  if (field === "event") return record.event;
  if (["nextAttemptAt", "deliveredAt", "responseStatusCode", "responseBodyExcerpt", "errorCode"].includes(field)) {
    return (record as unknown as Record<string, unknown>)[field];
  }
  return (record as unknown as Record<string, unknown>)[field];
}

function normalizeWebhook(record: OpenPlatformWebhook, tenantId: string): OpenPlatformWebhook {
  if (record === null || typeof record !== "object" || record.kind !== "webhook" || record.tenantId !== tenantId) throw validationError("Webhook record is invalid");
  if (record.version < 1 || record.secretVersion < 1 || record.failureCount < 0) throw validationError("Webhook record is invalid");
  if (!(OPEN_PLATFORM_WEBHOOK_STATUSES as readonly string[]).includes(record.status)) throw validationError("Webhook status is invalid");
  if (!Array.isArray(record.events) || record.events.length < 1 || record.events.some((event) => !(OPEN_PLATFORM_WEBHOOK_EVENT_TYPES as readonly string[]).includes(event))) throw validationError("Webhook events are invalid");
  return {
    ...record,
    id: requiredText(record.id, "webhook"),
    tenantId,
    developerOrganizationId: requiredText(record.developerOrganizationId, "webhook"),
    applicationId: requiredText(record.applicationId, "webhook"),
    environmentId: requiredText(record.environmentId, "webhook"),
    name: requiredText(record.name, "webhook"),
    endpointUrl: requiredText(record.endpointUrl, "webhook"),
    events: [...record.events],
    signingSecretReference: requiredText(record.signingSecretReference, "webhook"),
    createdAt: requiredDate(record.createdAt, "webhook"),
    updatedAt: requiredDate(record.updatedAt, "webhook"),
  };
}

function normalizeDelivery(record: OpenPlatformWebhookDelivery, tenantId: string): OpenPlatformWebhookDelivery {
  if (record === null || typeof record !== "object" || record.tenantId !== tenantId) throw validationError("Webhook delivery is invalid");
  if (!Number.isSafeInteger(record.attempt) || record.attempt < 0 || !Number.isSafeInteger(record.maxAttempts) || record.maxAttempts < 1 || !(OPEN_PLATFORM_WEBHOOK_DELIVERY_STATUSES as readonly string[]).includes(record.status)) {
    throw validationError("Webhook delivery state is invalid");
  }
  if (!Number.isSafeInteger(record.secretVersion) || record.secretVersion < 1) throw validationError("Webhook delivery secret version is invalid");
  if (record.responseStatusCode !== undefined && (!Number.isInteger(record.responseStatusCode) || record.responseStatusCode < 100 || record.responseStatusCode > 599)) {
    throw validationError("Webhook delivery response status is invalid");
  }
  if (!(OPEN_PLATFORM_WEBHOOK_EVENT_TYPES as readonly string[]).includes(record.event)) throw validationError("Webhook delivery event is invalid");
  return {
    ...record,
    id: requiredText(record.id, "webhookDelivery"),
    tenantId,
    webhookId: requiredText(record.webhookId, "webhookDelivery"),
    eventId: requiredText(record.eventId, "webhookDelivery"),
    event: requiredText(record.event, "webhookDelivery"),
    idempotencyKey: requiredText(record.idempotencyKey, "webhookDelivery"),
    payload: requiredText(record.payload, "webhookDelivery"),
    body: requiredText(record.body ?? record.payload, "webhookDelivery"),
    ...(record.leaseId === undefined ? {} : { leaseId: requiredText(record.leaseId, "webhookDelivery") }),
    ...(record.leaseExpiresAt === undefined ? {} : { leaseExpiresAt: requiredDate(record.leaseExpiresAt, "webhookDelivery") }),
    createdAt: requiredDate(record.createdAt, "webhookDelivery"),
    updatedAt: requiredDate(record.updatedAt, "webhookDelivery"),
  };
}

function normalizeClaim(
  request: OpenPlatformWebhookDeliveryClaimRequest,
): Required<OpenPlatformWebhookDeliveryClaimRequest> {
  if (request === null || typeof request !== "object" || typeof request.tenantId !== "string" || request.tenantId.length === 0) {
    throw validationError("Webhook delivery claim is invalid");
  }
  const tenantId = requiredText(request.tenantId, "webhookDelivery");
  if (!Number.isSafeInteger(request.attempt) || request.attempt < 1) {
    throw validationError("Webhook delivery claim is invalid");
  }
  const now = requiredDate(request.now, "webhookDelivery");
  const leaseExpiresAt = requiredDate(request.leaseExpiresAt, "webhookDelivery");
  if (Date.parse(leaseExpiresAt) <= Date.parse(now)) throw validationError("Webhook delivery claim lease is invalid");
  return {
    tenantId,
    id: requiredText(request.id, "webhookDelivery"),
    attempt: request.attempt,
    leaseId: requiredText(request.leaseId, "webhookDelivery"),
    now,
    leaseExpiresAt,
  };
}

function requiredText(value: unknown, field: string): string {
  const text = readText(value);
  if (text === undefined) throw new Error(`Invalid ${field} SQL row`);
  return text;
}

function requiredDate(value: unknown, field: string): string {
  const date = readDate(value);
  if (date === undefined) throw new Error(`Invalid ${field} SQL row`);
  return date;
}

function requiredNumber(value: unknown, field: string, allowZero = false): number {
  const number = readNumber(value);
  if (number === undefined || number < (allowZero ? 0 : 1)) throw new Error(`Invalid ${field} SQL row`);
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

function normalizeLimit(value: unknown): number {
  if (value === undefined) return 20;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1 || value > 100) throw validationError("Webhook page limit is invalid");
  return value;
}

function encodeCursor(tenantId: string, offset: number): string {
  return `sql_delivery_${Buffer.from(JSON.stringify({ tenantId, offset }), "utf8").toString("base64url")}`;
}

function decodeCursor(value: unknown, tenantId: string): number {
  if (typeof value !== "string" || !/^sql_delivery_[A-Za-z0-9_-]+$/u.test(value)) throw validationError("Webhook delivery cursor is invalid");
  try {
    const parsed = JSON.parse(Buffer.from(value.slice(13), "base64url").toString("utf8")) as Record<string, unknown>;
    if (parsed.tenantId !== tenantId || typeof parsed.offset !== "number" || parsed.offset < 0) throw new Error("invalid");
    return parsed.offset;
  } catch {
    throw validationError("Webhook delivery cursor is invalid");
  }
}

function quoteAlias(value: string): string {
  return `"${value.replace(/"/gu, '""')}"`;
}

export const SqlWebhookSubscriptionRepository = SqlWebhookRepository;
export const PostgresWebhookSubscriptionRepository = SqlWebhookRepository;
export const PostgreSqlWebhookSubscriptionRepository = SqlWebhookRepository;
export const PostgresWebhookRepository = SqlWebhookRepository;
export const PostgreSqlWebhookRepository = SqlWebhookRepository;
export const PostgresWebhookDeliveryRepository = SqlWebhookDeliveryRepository;
export const PostgreSqlWebhookDeliveryRepository = SqlWebhookDeliveryRepository;
