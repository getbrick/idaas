import { describe, expect, it } from "vitest";
import {
  applyVersionedOpenPlatformMigration,
  createOpenPlatformManagementMigrationSql,
  createOpenPlatformMigrationSql,
  createOpenPlatformDeliveryLeaseMigrationSql,
  createOpenPlatformDomainEventMigrationSql,
  getOpenPlatformDeliveryLeaseMigrationDefinition,
  getOpenPlatformDomainEventMigrationDefinition,
  getOpenPlatformManagementMigrationDefinition,
  getOpenPlatformMigrationDefinition,
  getOpenPlatformMigrations,
  OpenPlatformSqlRuntime,
  SqlApplicationRepository,
  SqlAuditEventRepository,
  SqlIdempotencyStore,
  SqlUsageRepository,
  SqlWebhookDeliveryRepository,
  SqlWebhookRepository,
  createSqlOpenPlatformRepositories,
  type DatabaseAdapter,
} from "../src/open-platform/persistence/index.js";
import { InMemoryUsageRepository } from "../src/open-platform/repositories.js";
import type { Application, UsageRecord } from "../src/open-platform/types.js";

type QueryResult = { rows?: unknown[]; rowCount?: number };
type Responder = (text: string, values: unknown[]) => unknown | Promise<unknown>;
type TestAdapter = DatabaseAdapter & { calls: { text: string; values: unknown[] }[] };

const timestamp = "2030-01-01T00:00:00.000Z";

function adapter(responder: Responder): TestAdapter {
  const calls: { text: string; values: unknown[] }[] = [];
  const query = async (text: string, values: unknown[] = []): Promise<unknown> => {
    calls.push({ text, values });
    return responder(text, values);
  };
  return {
    calls,
    query,
    transaction: async <T>(callback: (executor: DatabaseAdapter) => Promise<T>): Promise<T> =>
      callback({ query }),
  };
}

function application(overrides: Partial<Application> = {}): Application {
  return {
    id: "app-1",
    tenantId: "tenant-a",
    kind: "application",
    organizationId: "org-1",
    name: "Orders",
    status: "draft",
    version: 1,
    createdAt: timestamp,
    updatedAt: timestamp,
    ...overrides,
  };
}

function applicationRow(tenantId = "tenant-a", version = 1): Record<string, unknown> {
  return {
    id: "app-1",
    tenantId,
    kind: "application",
    organizationId: "org-1",
    name: "Orders",
    description: null,
    status: "draft",
    version,
    etag: `application:app-1:${version}`,
    createdAt: timestamp,
    updatedAt: timestamp,
    archivedAt: null,
  };
}

function usage(overrides: Partial<UsageRecord> = {}): UsageRecord {
  return {
    id: "usage-1",
    tenantId: "tenant-a",
    kind: "usage",
    subscriptionId: "subscription-1",
    productId: "product-1",
    metric: "requests",
    quantity: 1,
    occurredAt: timestamp,
    idempotencyKey: "usage-key-1",
    version: 1,
    createdAt: timestamp,
    updatedAt: timestamp,
    ...overrides,
  };
}

function usageRow(quantity: unknown = 1): Record<string, unknown> {
  return {
    id: "usage-1",
    tenantId: "tenant-a",
    kind: "usage",
    subscriptionId: "subscription-1",
    credentialId: null,
    productId: "product-1",
    apiVersionId: null,
    metric: "requests",
    quantity,
    occurredAt: timestamp,
    idempotencyKey: "usage-key-1",
    version: 1,
    etag: "usage:usage-1:1",
    createdAt: timestamp,
    updatedAt: timestamp,
  };
}

describe("open platform SQL persistence", () => {
  it("uses independent versioned schema, RLS, immutable usage, and no existing IDaaS tables", () => {
    const sql = createOpenPlatformMigrationSql({ mode: "shared", tenantId: "tenant-a" });
    expect(sql).toContain('"gb_open_tenant"');
    expect(sql).toContain('"gb_open_credential"');
    expect(sql).toContain('"gb_open_usage"');
    expect(sql).toContain('"gb_open_idempotency"');
    expect(sql).toContain("FORCE ROW LEVEL SECURITY");
    expect(sql).toContain("current_setting('app.tenant_id', true)");
    expect(sql).toContain('CREATE OR REPLACE FUNCTION "gb_open_reject_usage_mutation"');
    expect(sql).toContain('BEFORE UPDATE OR DELETE ON "gb_open_usage"');
    expect(sql).toContain('PRIMARY KEY ("tenant_id", "actor_id", "operation", "idempotency_key")');
    expect(sql).toContain('FOREIGN KEY ("tenant_id") REFERENCES "gb_open_tenant" ("tenant_id")');
    expect(sql.match(/FOREIGN KEY \("tenant_id"\) REFERENCES "gb_open_tenant" \("tenant_id"\)/gu)).toHaveLength(10);
    expect(sql).not.toContain('REFERENCES "gb_open_tenant" ("tenant_id", "id")');
    expect(sql).toContain('COALESCE("credential_id", \'\')');
    expect(sql).not.toContain('("tenant_id", "idempotency_key")');
    expect(sql).toContain('CHECK ("lease_expires_at" >= "created_at")');
    expect(sql).toContain('"secret_digest"');
    expect(sql).not.toContain('"secret" TEXT');
    expect(sql).not.toContain("gb_idaas_");
    const definition = getOpenPlatformMigrationDefinition({ tenantId: "tenant-a" });
    expect(definition.version).toBe(1);
    expect(definition.checksum).toHaveLength(64);
    const customSchemaSql = createOpenPlatformMigrationSql({ schema: "open", tenantId: "tenant-a" });
    expect(customSchemaSql).toContain('FOREIGN KEY ("tenant_id") REFERENCES "open"."gb_open_tenant" ("tenant_id")');
  });

  it("adds webhook and audit tables only in the additive migration", () => {
    const foundation = createOpenPlatformMigrationSql({ mode: "shared", tenantId: "tenant-a" });
    const additive = createOpenPlatformManagementMigrationSql({ mode: "shared", tenantId: "tenant-a" });
    expect(foundation).not.toContain('"gb_open_webhook"');
    expect(foundation).not.toContain('"gb_open_audit_event"');
    expect(additive).toContain('"gb_open_webhook"');
    expect(additive).toContain('"gb_open_webhook_delivery"');
    expect(additive).toContain('"gb_open_audit_event"');
    expect(additive).toContain("FORCE ROW LEVEL SECURITY");
    expect(additive).toContain("gb_open_audit_event");
    expect(additive).toContain("gb_open_audit_immutable");
    expect(additive).toContain("event_hash");
    expect(additive).toContain("previous_hash");
    expect(additive).toContain("event_id");
    expect(getOpenPlatformMigrations({ tenantId: "tenant-a" }).map((migration) => migration.version)).toEqual([1, 2, 3, 4, 5]);
    expect(getOpenPlatformManagementMigrationDefinition({ tenantId: "tenant-a" }).version).toBe(2);
  });

  it("adds the delivery lease columns only in the additive v3 migration", () => {
    const foundation = createOpenPlatformMigrationSql({ mode: "shared", tenantId: "tenant-a" });
    const additive = createOpenPlatformManagementMigrationSql({ mode: "shared", tenantId: "tenant-a" });
    const lease = createOpenPlatformDeliveryLeaseMigrationSql({ mode: "shared", tenantId: "tenant-a" });
    const deliveryTable = (additive.split(";\n").find((line) => line.includes('CREATE TABLE IF NOT EXISTS "gb_open_webhook_delivery"')) ?? "")
      .replace(/\s+/gu, " ");
    expect(foundation).not.toContain('ADD COLUMN IF NOT EXISTS "lease_id"');
    expect(additive).not.toContain('ALTER TABLE "gb_open_webhook_delivery" ADD COLUMN');
    expect(additive).not.toContain('"gb_open_webhook_delivery_lease_idx"');
    expect(deliveryTable).not.toContain("lease_id");
    expect(deliveryTable).not.toContain("lease_expires_at");
    expect(lease).toContain('ALTER TABLE "gb_open_webhook_delivery" ADD COLUMN IF NOT EXISTS "lease_id" TEXT');
    expect(lease).toContain('ALTER TABLE "gb_open_webhook_delivery" ADD COLUMN IF NOT EXISTS "lease_expires_at" TIMESTAMPTZ');
    expect(lease).toContain('CREATE INDEX IF NOT EXISTS "gb_open_webhook_delivery_lease_idx"');
    expect(lease).toContain('("tenant_id", "status", "lease_expires_at", "next_attempt_at")');
    const definition = getOpenPlatformDeliveryLeaseMigrationDefinition({ tenantId: "tenant-a" });
    expect(definition.version).toBe(3);
    expect(definition.checksum).toHaveLength(64);
    expect(definition.additive).toBe(true);
    expect(definition.requires).toEqual([2]);
    expect(getOpenPlatformMigrations({ tenantId: "tenant-a", includeManagementMigration: false }).map((migration) => migration.version)).toEqual([1, 4, 5]);
    expect(getOpenPlatformMigrations({ tenantId: "tenant-a", includeDeliveryLeaseMigration: false }).map((migration) => migration.version)).toEqual([1, 2, 4, 5]);
    expect(getOpenPlatformMigrations({ tenantId: "tenant-a", includeDomainEventMigration: false }).map((migration) => migration.version)).toEqual([1, 2, 3, 5]);
  });

  it("adds the append-only domain event outbox only in the additive v4 migration", () => {
    const foundation = createOpenPlatformMigrationSql({ mode: "shared", tenantId: "tenant-a" });
    const management = createOpenPlatformManagementMigrationSql({ mode: "shared", tenantId: "tenant-a" });
    const lease = createOpenPlatformDeliveryLeaseMigrationSql({ mode: "shared", tenantId: "tenant-a" });
    const outbox = createOpenPlatformDomainEventMigrationSql({ mode: "shared", tenantId: "tenant-a" });
    for (const published of [foundation, management, lease]) {
      expect(published).not.toContain('"gb_open_domain_event"');
    }
    expect(outbox).toContain('CREATE TABLE IF NOT EXISTS "gb_open_domain_event"');
    expect(outbox).toContain('PRIMARY KEY ("tenant_id", "event_id")');
    expect(outbox).toContain('UNIQUE ("tenant_id", "sequence")');
    expect(outbox).toContain('"lease_id" TEXT');
    expect(outbox).toContain('"lease_expires_at" TIMESTAMPTZ');
    expect(outbox).toContain('CHECK ("status" IN (\'pending\', \'delivering\', \'published\', \'failed\', \'dead_lettered\'))');
    expect(outbox).toContain('"gb_open_domain_event_pending_idx"');
    expect(outbox).toContain('"gb_open_domain_event_lease_idx"');
    expect(outbox).toContain("gb_open_domain_event_immutable");
    expect(outbox).toContain("gb_open_domain_event_payload_guard");
    expect(outbox).toContain("BEFORE DELETE ON");
    expect(outbox).toContain("BEFORE UPDATE ON");
    expect(outbox).toContain("FORCE ROW LEVEL SECURITY");
    expect(outbox).toContain("current_setting('app.tenant_id', true)");
    expect(outbox).not.toContain("gb_idaas_");
    const definition = getOpenPlatformDomainEventMigrationDefinition({ tenantId: "tenant-a" });
    expect(definition.version).toBe(4);
    expect(definition.checksum).toHaveLength(64);
    expect(definition.additive).toBe(true);
    expect(definition.requires).toEqual([3]);
  });

  it("claims a webhook delivery atomically and only reclaims an expired lease", async () => {
    const row: Record<string, unknown> = {
      id: "delivery-1",
      tenantId: "tenant-a",
      webhookId: "webhook-a",
      eventId: "event-1",
      event: "application.status_changed",
      status: "pending",
      attempt: 0,
      maxAttempts: 5,
      idempotencyKey: "event-1",
      payload: "{}",
      body: "{}",
      secretVersion: 1,
      nextAttemptAt: null,
      deliveredAt: null,
      responseStatusCode: null,
      responseBodyExcerpt: null,
      errorCode: null,
      leaseId: null,
      leaseExpiresAt: null,
      createdAt: timestamp,
      updatedAt: timestamp,
    };
    const executor = adapter((text, values) => {
      if (!text.startsWith('UPDATE "gb_open_webhook_delivery"')) return { rows: [] };
      const claimable = row.status === "pending" || row.status === "failed" ||
        (row.status === "delivering" && String(row.leaseExpiresAt) <= String(values[5]));
      if (row.tenantId !== values[0] || row.id !== values[1] || !claimable) return { rowCount: 0, rows: [] };
      Object.assign(row, {
        status: "delivering",
        attempt: Math.max(Number(row.attempt), Number(values[2])),
        leaseId: values[3],
        leaseExpiresAt: values[4],
        updatedAt: values[5],
      });
      return { rowCount: 1, rows: [row] };
    });
    const deliveries = new SqlWebhookDeliveryRepository(
      new OpenPlatformSqlRuntime({ adapter: executor, tenantId: "tenant-a" }),
    );
    const first = await deliveries.claim({
      tenantId: "tenant-a",
      id: "delivery-1",
      attempt: 1,
      leaseId: "lease-first",
      now: "2030-01-01T00:00:00.000Z",
      leaseExpiresAt: "2030-01-01T00:00:30.000Z",
    });
    expect(first.claimed).toBe(true);
    expect(first.delivery).toMatchObject({ status: "delivering", attempt: 1, leaseId: "lease-first" });
    const statement = executor.calls.at(-1);
    expect(statement?.text).toContain('"status" IN (\'pending\', \'failed\')');
    expect(statement?.text).toContain('"status" = \'delivering\' AND COALESCE("lease_expires_at"');
    expect(statement?.text).toContain('"attempt" = GREATEST("attempt", $3::integer)');
    expect(statement?.values).toEqual(["tenant-a", "delivery-1", 1, "lease-first", "2030-01-01T00:00:30.000Z", "2030-01-01T00:00:00.000Z"]);

    const contested = await deliveries.claim({
      tenantId: "tenant-a",
      id: "delivery-1",
      attempt: 1,
      leaseId: "lease-second",
      now: "2030-01-01T00:00:05.000Z",
      leaseExpiresAt: "2030-01-01T00:00:35.000Z",
    });
    expect(contested.claimed).toBe(false);
    expect(contested.delivery).toBeUndefined();
    expect(row.leaseId).toBe("lease-first");

    const recovered = await deliveries.claim({
      tenantId: "tenant-a",
      id: "delivery-1",
      attempt: 2,
      leaseId: "lease-third",
      now: "2030-01-01T00:01:00.000Z",
      leaseExpiresAt: "2030-01-01T00:01:30.000Z",
    });
    expect(recovered.claimed).toBe(true);
    expect(recovered.delivery).toMatchObject({ status: "delivering", attempt: 2, leaseId: "lease-third" });

    const otherTenant = await deliveries.claim({
      tenantId: "tenant-b",
      id: "delivery-1",
      attempt: 1,
      leaseId: "lease-other",
      now: "2030-01-01T00:02:00.000Z",
      leaseExpiresAt: "2030-01-01T00:02:30.000Z",
    });
    expect(otherTenant.claimed).toBe(false);
    expect(executor.calls.at(-1)?.values[0]).toBe("tenant-a");
    expect(executor.calls.every((call) => !call.values.includes("lease-other"))).toBe(true);
    await expect(deliveries.claim({
      tenantId: "tenant-a",
      id: "delivery-1",
      attempt: 1,
      leaseId: "lease-stale",
      now: "2030-01-01T00:03:00.000Z",
      leaseExpiresAt: "2030-01-01T00:02:59.000Z",
    })).rejects.toMatchObject({ code: "OPEN_PLATFORM_VALIDATION_ERROR" });
  });

  it("executes the versioned migration through the SQL adapter harness", async () => {
    const definition = getOpenPlatformMigrationDefinition({ tenantId: "tenant-a" });
    const calls: { text: string; values: unknown[] }[] = [];
    const executor = adapter((text, values) => {
      calls.push({ text, values });
      if (text.startsWith("SELECT") && text.includes('FROM "gb_open_schema_migration"')) return { rows: [] };
      return { rows: [] };
    });
    const result = await applyVersionedOpenPlatformMigration(executor, { tenantId: "tenant-a" });
    expect(result.atomic).toBe(true);
    expect(calls.some((call) => call.text.trim() === definition.sql.trim())).toBe(true);
    expect(calls.some((call) => call.text.includes("pg_advisory_xact_lock"))).toBe(true);
  });

  it("persists chained audit events and webhook delivery metadata through tenant-scoped SQL", async () => {
    const auditExecutor = adapter((text, values) => {
      if (text.startsWith("SELECT pg_advisory")) return { rows: [] };
      if (text.includes('ORDER BY "sequence" DESC')) return { rows: [] };
      if (text.startsWith('INSERT INTO "gb_open_audit_event"')) {
        return {
          rowCount: 1,
          rows: [{
            id: values[0],
            tenantId: values[1],
            action: values[2],
            outcome: values[3],
            actorType: values[4],
            actorId: values[5],
            actorDisplayName: null,
            actorIpAddress: null,
            actorUserAgent: null,
            targetType: values[9],
            targetId: values[10],
            targetDisplayName: null,
            requestId: values[12],
            metadata: values[13],
            occurredAt: values[14],
            sequence: values[15],
            source: values[16],
            previousHash: null,
            eventHash: values[18],
            createdAt: values[19],
          }],
        };
      }
      return { rows: [] };
    });
    const audit = new SqlAuditEventRepository(new OpenPlatformSqlRuntime({ adapter: auditExecutor, tenantId: "tenant-a" }));
    await expect(audit.append({
      tenantId: "tenant-a",
      action: "webhook.create",
      outcome: "success",
      actor: { type: "user", id: "actor-a" },
      target: { type: "webhook", id: "webhook-a" },
      requestId: "request-a",
    })).resolves.toMatchObject({ sequence: 1, tenantId: "tenant-a" });
    expect(auditExecutor.calls.some((call) => call.values.includes("tenant-a"))).toBe(true);

    const webhookExecutor = adapter((text, values) => {
      if (text.startsWith('INSERT INTO "gb_open_webhook"')) {
        return {
          rowCount: 1,
          rows: [{
            id: values[0],
            tenantId: values[1],
            kind: "webhook",
            developerOrganizationId: values[3],
            applicationId: values[4],
            environmentId: values[5],
            name: values[6],
            endpointUrl: values[7],
            status: values[8],
            events: values[9],
            signingAlgorithm: values[10],
            signingSecretReference: values[11],
            secretVersion: values[12],
            failureCount: values[13],
            nextDeliveryAt: null,
            lastDeliveryAt: null,
            version: values[16],
            createdAt: values[17],
            updatedAt: values[18],
          }],
        };
      }
      return { rows: [] };
    });
    const webhooks = new SqlWebhookRepository(new OpenPlatformSqlRuntime({ adapter: webhookExecutor, tenantId: "tenant-a" }));
    await expect(webhooks.create({
      id: "webhook-a",
      tenantId: "tenant-a",
      kind: "webhook",
      developerOrganizationId: "org-a",
      applicationId: "app-a",
      environmentId: "env-a",
      name: "Events",
      endpointUrl: "https://client.example.test/webhook",
      status: "active",
      events: ["application.status_changed"],
      signingAlgorithm: "hmac-sha256",
      signingSecretReference: "vault://webhook-a",
      secretVersion: 1,
      failureCount: 0,
      version: 1,
      createdAt: timestamp,
      updatedAt: timestamp,
    })).resolves.toMatchObject({ id: "webhook-a", secretVersion: 1 });
  });

  it("keeps repository readiness persistent and distributed", async () => {
    const executor = adapter((text) => {
      if (text.includes("pg_roles")) return { rows: [{ superuser: false, bypassRls: false }] };
      if (text.includes("pg_class")) return { rows: [{ rls: true, forceRls: true, policy: true }] };
      return { rows: [] };
    });
    const repositories = createSqlOpenPlatformRepositories({
      adapter: executor,
      mode: "shared",
      tenantId: "tenant-a",
    });
    expect(repositories.readiness.storage).toBe("persistent");
    expect(repositories.readiness.distributed).toBe(true);
    await expect(repositories.isReady()).resolves.toBe(true);
    expect(executor.calls.some((call) => call.text.includes("set_config('app.tenant_id'"))).toBe(true);
    const missingCalls: { text: string; values: unknown[] }[] = [];
    const missing = new SqlApplicationRepository({
      adapter: adapter((text, values) => {
        missingCalls.push({ text, values });
        return { rows: [] };
      }),
      tenantId: "tenant-a",
      columns: { applications: { version: null } },
    });
    await expect(missing.isReady()).resolves.toBe(false);
    expect(missingCalls).toHaveLength(0);
  });

  it("enforces tenant predicates and rejects rows outside repository scope", async () => {
    const executor = adapter((text) => text.includes('FROM "gb_open_application"')
      ? { rows: [applicationRow("tenant-b")] }
      : { rows: [] });
    const runtime = new OpenPlatformSqlRuntime({ adapter: executor, tenantId: "tenant-a" });
    const repository = new SqlApplicationRepository(runtime);
    await expect(repository.get("tenant-a", "app-1")).resolves.toBeUndefined();
    const call = executor.calls.at(-1);
    expect(call?.text).toContain('"tenant_id" = $1');
    expect(call?.values[0]).toBe("tenant-a");
    await expect(repository.get("tenant-b", "app-1")).resolves.toBeUndefined();
  });

  it("uses version and status predicates for optimistic updates", async () => {
    const executor = adapter((text) => {
      if (text.startsWith('UPDATE "gb_open_application"')) return { rowCount: 0, rows: [] };
      if (text.includes('FROM "gb_open_application"')) return { rows: [applicationRow()] };
      return { rows: [] };
    });
    const repository = new SqlApplicationRepository(
      new OpenPlatformSqlRuntime({ adapter: executor, tenantId: "tenant-a" }),
    );
    await expect(repository.save(application({ status: "published", version: 2, updatedAt: timestamp }))).rejects.toMatchObject({
      code: "OPEN_PLATFORM_RESOURCE_CONFLICT",
    });
    const update = executor.calls.find((call) => call.text.startsWith('UPDATE "gb_open_application"'));
    expect(update?.text).toContain('"version" = $3');
    expect(update?.text).toContain('"status" = $4');
    expect(update?.values).toContain(1);
    expect(update?.values).toContain("draft");
  });

  it("maps database uniqueness violations to resource conflicts", async () => {
    const executor = adapter((text) => {
      if (text.startsWith('INSERT INTO "gb_open_application"')) {
        throw Object.assign(new Error("duplicate key"), { code: "23505" });
      }
      return { rows: [] };
    });
    const repository = new SqlApplicationRepository(
      new OpenPlatformSqlRuntime({ adapter: executor, tenantId: "tenant-a" }),
    );
    await expect(repository.create(application())).rejects.toMatchObject({
      code: "OPEN_PLATFORM_RESOURCE_CONFLICT",
    });
  });

  it("keeps usage append-only at the repository boundary", async () => {
    const executor = adapter((text) => text.startsWith('INSERT INTO "gb_open_usage"')
      ? { rowCount: 1, rows: [usageRow()] }
      : { rows: [] });
    const repository = new SqlUsageRepository(
      new OpenPlatformSqlRuntime({ adapter: executor, tenantId: "tenant-a" }),
    );
    await expect(repository.append(usage())).resolves.toMatchObject({ id: "usage-1", version: 1 });
    expect("update" in repository).toBe(false);
    expect("delete" in repository).toBe(false);
    expect(executor.calls.some((call) => /UPDATE "gb_open_usage"|DELETE FROM "gb_open_usage"/u.test(call.text))).toBe(false);
  });

  it("round-trips finite decimal usage quantities consistently", async () => {
    const executor = adapter((text) => {
      if (text.startsWith('INSERT INTO "gb_open_usage"')) return { rowCount: 1, rows: [usageRow("0.25")] };
      if (text.includes('FROM "gb_open_usage"')) return { rows: [usageRow("12.50")] };
      return { rows: [] };
    });
    const repository = new SqlUsageRepository(
      new OpenPlatformSqlRuntime({ adapter: executor, tenantId: "tenant-a" }),
    );
    const appended = await repository.append(usage({ quantity: 0.25 }));
    expect(appended.quantity).toBe(0.25);
    const insert = executor.calls.find((call) => call.text.startsWith('INSERT INTO "gb_open_usage"'));
    expect(insert?.values[8]).toBe(0.25);
    const loaded = await repository.get("tenant-a", "usage-1");
    expect(loaded?.quantity).toBe(12.5);
    const memory = new InMemoryUsageRepository();
    const memoryRecord = usage({
      id: "usage_00000000-0000-4000-8000-000000000001",
      quantity: 0.25,
    });
    await expect(memory.append(memoryRecord)).resolves.toMatchObject({ quantity: 0.25 });
  });

  it("supports idempotency lease takeover and replay", async () => {
    const rows = new Map<string, Record<string, unknown>>();
    const keyOf = (values: unknown[]): string => values.slice(0, 4).map(String).join("\u0000");
    const executor = adapter((text, values) => {
      if (text.startsWith('INSERT INTO "gb_open_idempotency"')) {
        const key = keyOf(values);
        if (rows.has(key)) return { rowCount: 0, rows: [] };
        const row = {
          tenantId: values[0],
          actorId: values[1],
          operation: values[2],
          key: values[3],
          requestHash: values[4],
          state: values[5],
          leaseToken: values[6],
          leaseExpiresAt: values[7],
          expiresAt: values[8],
          createdAt: values[9],
          updatedAt: values[9],
          completedAt: null,
          response: null,
        };
        rows.set(key, row);
        return { rowCount: 1, rows: [row] };
      }
      if (text.includes('FROM "gb_open_idempotency"')) {
        const row = rows.get(keyOf(values));
        return { rows: row === undefined ? [] : [row] };
      }
      if (text.startsWith('UPDATE "gb_open_idempotency"') && text.includes('SET "request_hash"')) {
        const row = rows.get(keyOf(values));
        if (row === undefined || row.requestHash !== values[4] || String(row.leaseExpiresAt) > String(values[8])) return { rowCount: 0, rows: [] };
        Object.assign(row, {
          requestHash: values[4],
          state: "inProgress",
          leaseToken: values[5],
          leaseExpiresAt: values[6],
          expiresAt: values[7],
          updatedAt: values[8],
          completedAt: null,
          response: null,
        });
        return { rowCount: 1, rows: [row] };
      }
      if (text.startsWith('UPDATE "gb_open_idempotency"')) {
        const row = rows.get(keyOf(values));
        if (row === undefined || row.requestHash !== values[7] || row.leaseToken !== values[8] || String(row.leaseExpiresAt) <= String(values[5])) return { rowCount: 0, rows: [] };
        Object.assign(row, {
          state: "completed",
          response: JSON.parse(String(values[4])),
          completedAt: values[5],
          updatedAt: values[5],
          expiresAt: values[6],
          leaseToken: null,
          leaseExpiresAt: values[5],
        });
        return { rowCount: 1, rows: [row] };
      }
      if (text.startsWith('DELETE FROM "gb_open_idempotency"')) {
        return { rowCount: rows.delete(keyOf(values)) ? 1 : 0, rows: [] };
      }
      return { rows: [] };
    });
    const store = new SqlIdempotencyStore(
      new OpenPlatformSqlRuntime({ adapter: executor, tenantId: "tenant-a" }),
    );
    const requestHash = "a".repeat(64);
    const scope = { tenantId: "tenant-a", actorId: "actor-1", operation: "usage.record", key: "key-1" };
    const firstNow = "2030-01-01T00:00:00.000Z";
    const lease = "2030-01-01T00:00:01.000Z";
    const expiry = "2030-01-01T00:01:00.000Z";
    const firstToken = "a".repeat(32);
    const secondToken = "b".repeat(32);
    await expect(store.acquire({ scope, requestHash, leaseToken: firstToken, now: firstNow, leaseExpiresAt: lease, expiresAt: expiry })).resolves.toEqual({ state: "acquired" });
    await expect(store.acquire({ scope, requestHash, leaseToken: secondToken, now: firstNow, leaseExpiresAt: lease, expiresAt: expiry })).resolves.toEqual({ state: "inProgress" });
    await expect(store.acquire({ scope, requestHash: "c".repeat(64), leaseToken: secondToken, now: firstNow, leaseExpiresAt: lease, expiresAt: expiry })).resolves.toEqual({ state: "conflict" });
    const takeoverNow = "2030-01-01T00:00:02.000Z";
    await expect(store.acquire({ scope, requestHash, leaseToken: secondToken, now: takeoverNow, leaseExpiresAt: "2030-01-01T00:00:03.000Z", expiresAt: "2030-01-01T00:01:00.000Z" })).resolves.toEqual({ state: "acquired" });
    await expect(store.complete({ scope, requestHash, leaseToken: firstToken, now: takeoverNow, expiresAt: expiry, response: { ok: true } })).resolves.toBe(false);
    await expect(store.complete({ scope, requestHash, leaseToken: secondToken, now: takeoverNow, expiresAt: expiry, response: { ok: true, secret: undefined } })).resolves.toBe(true);
    await expect(store.acquire({ scope, requestHash, leaseToken: firstToken, now: takeoverNow, leaseExpiresAt: "2030-01-01T00:00:03.000Z", expiresAt: expiry })).resolves.toEqual({ state: "replay", response: { ok: true } });
    const sameMillisecondScope = { ...scope, key: "same-millisecond" };
    const sameMillisecondNow = "2030-01-01T00:00:04.000Z";
    const sameMillisecondToken = "c".repeat(32);
    await expect(store.acquire({ scope: sameMillisecondScope, requestHash, leaseToken: sameMillisecondToken, now: sameMillisecondNow, leaseExpiresAt: "2030-01-01T00:00:05.000Z", expiresAt: "2030-01-01T00:01:00.000Z" })).resolves.toEqual({ state: "acquired" });
    await expect(store.complete({ scope: sameMillisecondScope, requestHash, leaseToken: sameMillisecondToken, now: sameMillisecondNow, expiresAt: expiry, response: { ok: true } })).resolves.toBe(true);
    const sameMillisecondComplete = executor.calls.filter((call) => call.text.startsWith('UPDATE "gb_open_idempotency"')).at(-1);
    expect(sameMillisecondComplete?.values[5]).toBe(sameMillisecondNow);
  });
});
