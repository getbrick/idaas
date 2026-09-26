import { randomUUID } from "node:crypto";
import {
  createOpenPlatformAuditEventHash,
  decodeOpenPlatformAuditCursor,
  encodeOpenPlatformAuditCursor,
  sanitizeOpenPlatformAuditMetadata,
  type OpenPlatformAuditEventInput,
  type OpenPlatformAuditEventRecord,
  type OpenPlatformAuditPage,
  type OpenPlatformAuditPort,
  type OpenPlatformAuditQuery,
} from "../audit.js";
import { resourceConflict, resourceNotFound, validationError } from "../errors.js";
import type { OpenPlatformDependencyReadiness } from "../types.js";
import {
  OpenPlatformSqlRuntime,
  createOpenPlatformSqlRuntime,
  readDate,
  readJson,
  readNumber,
  readText,
  isUniqueViolation,
  rowValue,
  storageValue,
  type DatabaseAdapter,
  type OpenPlatformMutationResult,
  type OpenPlatformSqlRepositoryInput,
  type OpenPlatformSqlRepositorySecondOptions,
} from "./adapter.js";

export class SqlAuditEventRepository implements OpenPlatformAuditPort {
  readonly productionReady = true;
  readonly readiness: OpenPlatformDependencyReadiness;
  private readonly runtime: OpenPlatformSqlRuntime;

  constructor(input: OpenPlatformSqlRepositoryInput, options?: OpenPlatformSqlRepositorySecondOptions) {
    this.runtime = createOpenPlatformSqlRuntime(input, options);
    this.readiness = Object.freeze({
      storage: "persistent" as const,
      distributed: this.runtime.distributed,
      ready: async () => this.runtime.isReady(["auditEvents"]),
    });
  }

  async append(event: OpenPlatformAuditEventInput): Promise<OpenPlatformAuditEventRecord> {
    const normalized = normalizeAuditInput(event);
    if (normalized.tenantId !== this.runtime.tenantId) throw resourceNotFound("auditEvent");
    return this.runtime.withTransaction(async (executor) => {
      await executor.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [normalized.tenantId]);
      const previous = await this.previous(normalized.tenantId, executor);
      const record = {
        contractVersion: 1 as const,
        ...normalized,
        sequence: (previous?.sequence ?? 0) + 1,
        ...(previous === undefined ? {} : { previousHash: previous.eventHash }),
        eventHash: "",
      };
      const withHash = {
        ...record,
        eventHash: createOpenPlatformAuditEventHash(record),
      };
      const fields = [
        "id",
        "tenantId",
        "action",
        "outcome",
        "actorType",
        "actorId",
        "actorDisplayName",
        "actorIpAddress",
        "actorUserAgent",
        "targetType",
        "targetId",
        "targetDisplayName",
        "requestId",
        "metadata",
        "occurredAt",
        "sequence",
        "source",
        "previousHash",
        "eventHash",
        "createdAt",
      ];
      const values = [
        withHash.id,
        withHash.tenantId,
        withHash.action,
        withHash.outcome,
        withHash.actor.type,
        withHash.actor.id,
        withHash.actor.displayName,
        withHash.actor.ipAddress,
        withHash.actor.userAgent,
        withHash.target.type,
        withHash.target.id,
        withHash.target.displayName,
        withHash.requestId,
        JSON.stringify(withHash.metadata),
        withHash.occurredAt,
        withHash.sequence,
        withHash.source,
        withHash.previousHash,
        withHash.eventHash,
        withHash.occurredAt,
      ];
      let result: OpenPlatformMutationResult;
      try {
        result = await this.runtime.executeMutation(
          `INSERT INTO ${this.runtime.table("auditEvents")} (${fields.map((field) => this.runtime.column("auditEvents", field)).join(", ")}) VALUES (${fields.map((_field, index) => `$${index + 1}`).join(", ")}) RETURNING ${this.select("auditEvents", fields)}`,
          values,
          executor,
        );
      } catch (error) {
        if (isUniqueViolation(error)) throw resourceConflict("Audit event already exists");
        throw error;
      }
      if (result.affected !== 1) throw resourceConflict("Audit event already exists");
      return result.rows[0] === undefined ? withHash : this.mapRow(result.rows[0]);
    });
  }

  async list(query: OpenPlatformAuditQuery): Promise<OpenPlatformAuditPage> {
    const tenantId = requiredText(query.tenantId, "tenantId");
    if (tenantId !== this.runtime.tenantId) return { items: [], hasMore: false };
    const limit = normalizeLimit(query.limit);
    const after = query.cursor === undefined ? undefined : decodeOpenPlatformAuditCursor(query.cursor, tenantId);
    if (query.outcome !== undefined && query.outcome !== "success" && query.outcome !== "failure" && query.outcome !== "denied") {
      throw validationError("Audit outcome is invalid", { field: "outcome" });
    }
    const values: unknown[] = [tenantId];
    const clauses = [`${this.runtime.column("auditEvents", "tenantId")} = $1`];
    if (after !== undefined) {
      values.push(after);
      clauses.push(`${this.runtime.column("auditEvents", "sequence")} > $${values.length}`);
    }
    if (query.action !== undefined) {
      values.push(requiredText(query.action, "action"));
      clauses.push(`${this.runtime.column("auditEvents", "action")} = $${values.length}`);
    }
    if (query.outcome !== undefined) {
      values.push(query.outcome);
      clauses.push(`${this.runtime.column("auditEvents", "outcome")} = $${values.length}`);
    }
    if (query.targetId !== undefined) {
      values.push(requiredText(query.targetId, "targetId"));
      clauses.push(`${this.runtime.column("auditEvents", "targetId")} = $${values.length}`);
    }
    values.push(limit + 1);
    const fields = this.fields();
    const rows = await this.runtime.queryRows(
      `SELECT ${this.select("auditEvents", fields)} FROM ${this.runtime.table("auditEvents")} WHERE ${clauses.join(" AND ")} ORDER BY ${this.runtime.column("auditEvents", "sequence")} ASC LIMIT $${values.length}`,
      values,
    );
    const hasMore = rows.length > limit;
    const items = rows.slice(0, limit).map((row) => this.mapRow(row));
    const last = items.at(-1);
    return {
      items,
      ...(hasMore && last !== undefined ? { nextCursor: encodeOpenPlatformAuditCursor(tenantId, last.sequence) } : {}),
      hasMore,
    };
  }

  async get(tenantId: string, id: string): Promise<OpenPlatformAuditEventRecord | undefined> {
    const normalizedTenantId = requiredText(tenantId, "tenantId");
    if (normalizedTenantId !== this.runtime.tenantId) return undefined;
    const values: unknown[] = [normalizedTenantId, requiredText(id, "id")];
    const rows = await this.runtime.queryRows(
      `SELECT ${this.select("auditEvents", this.fields())} FROM ${this.runtime.table("auditEvents")} WHERE ${this.runtime.column("auditEvents", "tenantId")} = $1 AND ${this.runtime.column("auditEvents", "id")} = $2 LIMIT 1`,
      values,
    );
    return rows[0] === undefined ? undefined : this.mapRow(rows[0]);
  }

  async verifyChain(tenantId: string): Promise<boolean> {
    if (requiredText(tenantId, "tenantId") !== this.runtime.tenantId) return false;
    let cursor: string | undefined;
    let expectedSequence = 1;
    let previous: string | undefined;
    do {
      const page = await this.list({ tenantId, limit: 100, ...(cursor === undefined ? {} : { cursor }) });
      for (const event of page.items) {
        if (event.sequence !== expectedSequence || event.previousHash !== previous) return false;
        if (createOpenPlatformAuditEventHash(event) !== event.eventHash) return false;
        previous = event.eventHash;
        expectedSequence += 1;
      }
      cursor = page.hasMore ? page.nextCursor : undefined;
    } while (cursor !== undefined);
    return true;
  }

  async isReady(): Promise<boolean> {
    return this.runtime.isReady(["auditEvents"]);
  }

  private async previous(tenantId: string, executor: DatabaseAdapter): Promise<OpenPlatformAuditEventRecord | undefined> {
    const fields = this.fields();
    const rows = await this.runtime.queryRows(
      `SELECT ${this.select("auditEvents", fields)} FROM ${this.runtime.table("auditEvents")} WHERE ${this.runtime.column("auditEvents", "tenantId")} = $1 ORDER BY ${this.runtime.column("auditEvents", "sequence")} DESC LIMIT 1 FOR UPDATE`,
      [tenantId],
      executor,
    );
    return rows[0] === undefined ? undefined : this.mapRow(rows[0]);
  }

  private fields(): string[] {
    return [
      "id",
      "tenantId",
      "action",
      "outcome",
      "actorType",
      "actorId",
      "actorDisplayName",
      "actorIpAddress",
      "actorUserAgent",
      "targetType",
      "targetId",
      "targetDisplayName",
      "requestId",
      "metadata",
      "occurredAt",
      "sequence",
      "source",
      "previousHash",
      "eventHash",
      "createdAt",
    ];
  }

  private select(table: "auditEvents", fields: readonly string[]): string {
    return fields.map((field) => `${this.runtime.column(table, field)} AS ${quoteAlias(field)}`).join(", ");
  }

  private mapRow(row: Record<string, unknown>): OpenPlatformAuditEventRecord {
    const actorType = requiredText(rowValue(row, "actorType"), "actorType");
    const targetType = requiredText(rowValue(row, "targetType"), "targetType");
    const outcome = requiredText(rowValue(row, "outcome"), "outcome");
    if (actorType !== "user" && actorType !== "service" && actorType !== "system") throw new Error("Invalid audit actor type");
    if (outcome !== "success" && outcome !== "failure" && outcome !== "denied") throw new Error("Invalid audit outcome");
    if (!isAuditResourceType(targetType)) throw new Error("Invalid audit target type");
    const event: OpenPlatformAuditEventRecord = {
      contractVersion: 1,
      id: requiredText(rowValue(row, "id"), "id"),
      tenantId: requiredText(rowValue(row, "tenantId"), "tenantId"),
      action: requiredText(rowValue(row, "action"), "action"),
      outcome,
      actor: {
        type: actorType,
        id: requiredText(rowValue(row, "actorId"), "actorId"),
        ...optionalField(rowValue(row, "actorDisplayName"), "actorDisplayName"),
        ...optionalField(rowValue(row, "actorIpAddress"), "actorIpAddress"),
        ...optionalField(rowValue(row, "actorUserAgent"), "actorUserAgent"),
      },
      target: {
        type: targetType as OpenPlatformAuditEventRecord["target"]["type"],
        id: requiredText(rowValue(row, "targetId"), "targetId"),
        ...optionalField(rowValue(row, "targetDisplayName"), "targetDisplayName"),
      },
      ...optionalField(rowValue(row, "requestId"), "requestId"),
      metadata: sanitizeOpenPlatformAuditMetadata(readJson(rowValue(row, "metadata")) as Record<string, unknown>),
      occurredAt: requiredDate(rowValue(row, "occurredAt"), "occurredAt"),
      sequence: requiredNumber(rowValue(row, "sequence"), "sequence"),
      source: requiredText(rowValue(row, "source"), "source"),
      ...optionalField(rowValue(row, "previousHash"), "previousHash"),
      eventHash: requiredText(rowValue(row, "eventHash"), "eventHash"),
    };
    return event;
  }
}

function normalizeAuditInput(event: OpenPlatformAuditEventInput): OpenPlatformAuditEventInput & { id: string; occurredAt: string; source: string; metadata: Record<string, string | number | boolean | null> } {
  if (event === null || typeof event !== "object") throw validationError("Audit event is invalid");
  if (event.outcome !== "success" && event.outcome !== "failure" && event.outcome !== "denied") throw validationError("Audit outcome is invalid");
  if (event.actor === null || typeof event.actor !== "object" || !["user", "service", "system"].includes(event.actor.type)) throw validationError("Audit actor is invalid");
  if (event.target === null || typeof event.target !== "object" || !isAuditResourceType(event.target.type)) throw validationError("Audit target is invalid");
  return {
    id: requiredText(event.id ?? `audit_${randomUUID()}`, "id"),
    tenantId: requiredText(event.tenantId, "tenantId"),
    action: requiredText(event.action, "action"),
    outcome: event.outcome,
    actor: {
      type: event.actor.type,
      id: requiredText(event.actor.id, "actorId"),
      ...(event.actor.displayName === undefined ? {} : { displayName: requiredText(event.actor.displayName, "actorDisplayName") }),
      ...(event.actor.ipAddress === undefined ? {} : { ipAddress: requiredText(event.actor.ipAddress, "actorIpAddress") }),
      ...(event.actor.userAgent === undefined ? {} : { userAgent: requiredText(event.actor.userAgent, "actorUserAgent") }),
    },
    target: {
      type: event.target.type,
      id: requiredText(event.target.id, "targetId"),
      ...(event.target.displayName === undefined ? {} : { displayName: requiredText(event.target.displayName, "targetDisplayName") }),
    },
    ...(event.requestId === undefined ? {} : { requestId: requiredText(event.requestId, "requestId") }),
    metadata: { ...sanitizeOpenPlatformAuditMetadata(event.metadata) },
    occurredAt: requiredDate(event.occurredAt ?? new Date().toISOString(), "occurredAt"),
    source: requiredText(event.source ?? "open-platform", "source"),
  };
}

function requiredText(value: unknown, field: string): string {
  const text = readText(value);
  if (text === undefined) throw new Error(`Invalid audit ${field}`);
  return text;
}

function requiredDate(value: unknown, field: string): string {
  const date = readDate(value);
  if (date === undefined) throw new Error(`Invalid audit ${field}`);
  return date;
}

function requiredNumber(value: unknown, field: string): number {
  const number = readNumber(value);
  if (number === undefined || number < 1) throw new Error(`Invalid audit ${field}`);
  return number;
}

function optionalField(value: unknown, field: string): Record<string, string> {
  const text = readText(value);
  return text === undefined ? {} : { [field]: text };
}

function isAuditResourceType(value: string): value is OpenPlatformAuditEventRecord["target"]["type"] {
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
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1 || value > 100) throw validationError("Audit page limit is invalid", { field: "limit" });
  return value;
}

function quoteAlias(value: string): string {
  return `"${value.replace(/"/gu, '""')}"`;
}

export const SqlAuditRepository = SqlAuditEventRepository;
export const PostgresAuditRepository = SqlAuditEventRepository;
export const PostgreSqlAuditRepository = SqlAuditEventRepository;
export const PostgresAuditEventRepository = SqlAuditEventRepository;
export const PostgreSqlAuditEventRepository = SqlAuditEventRepository;
export const SqlOpenPlatformAuditEventRepository = SqlAuditEventRepository;
