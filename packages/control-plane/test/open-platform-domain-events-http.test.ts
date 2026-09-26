import "reflect-metadata";
import { Test } from "@nestjs/testing";
import request from "supertest";
import { describe, expect, it } from "vitest";
import {
  createDevelopmentOpenPlatformAuthorization,
  createOpenPlatformRequestContextIssuer,
  createOpenPlatformService,
  InMemoryOpenPlatformOutbox,
  InMemoryOpenPlatformRepositories,
  OPEN_PLATFORM_DOMAIN_EVENTS_BASE_PATH,
  OpenPlatformHttpModule,
  type OpenPlatformAuthorizationPort,
  type OpenPlatformEventPublisherPort,
  type OpenPlatformHttpRequest,
  type OpenPlatformOutboxPort,
  type OpenPlatformOutboxRecord,
  type OpenPlatformService,
} from "../src/open-platform/index.js";

const now = new Date("2030-05-01T00:00:00.000Z");
const timestamp = now.toISOString();
const tenantId = "tenant-domain-events-http";
const otherTenantId = "tenant-domain-events-other";
const actorId = "actor-domain-events-http";
const secretDataValue = "sensitive-note-value";

interface FlushCall {
  readonly tenantId: string;
  readonly eventType?: string;
  readonly limit?: number;
}

interface Harness {
  readonly service: OpenPlatformService;
  readonly outbox: InMemoryOpenPlatformOutbox;
  readonly flushCalls: FlushCall[];
}

function createHarness(
  options: { readonly authorization?: OpenPlatformAuthorizationPort } = {},
): Harness {
  const outbox = new InMemoryOpenPlatformOutbox({ clock: () => now });
  const flushCalls: FlushCall[] = [];
  const eventPublisher: OpenPlatformEventPublisherPort = {
    readiness: { storage: "memory", distributed: false, ready: () => true },
    record: (event) => outbox.append(event),
    publish: async (event) => ({
      eventId: event.eventId,
      delivered: 0,
      deadLettered: false,
    }),
    flush: async (query) => {
      flushCalls.push({
        tenantId: query.tenantId,
        ...(query.eventType === undefined ? {} : { eventType: query.eventType }),
        ...(query.limit === undefined ? {} : { limit: query.limit }),
      });
      return [
        { eventId: "open_platform_event_1", delivered: 2, deadLettered: false },
        { eventId: "open_platform_event_2", delivered: 0, deadLettered: true },
      ];
    },
  };
  const service = createOpenPlatformService({
    mode: "test",
    authorization:
      options.authorization ?? createDevelopmentOpenPlatformAuthorization("all"),
    repositories: new InMemoryOpenPlatformRepositories({ clock: () => now }),
    outbox,
    eventPublisher,
    webhookService: { sleep: async () => undefined, baseDelayMs: 0, maxDelayMs: 0 },
    clock: () => now,
  });
  return { service, outbox, flushCalls };
}

function issuer() {
  return createOpenPlatformRequestContextIssuer({
    issuerId: "open-platform-domain-events-http",
    attestation: Object.freeze({ test: true }),
    clock: () => now,
  });
}

function resolverFor(targetTenantId: string) {
  return (httpRequest: OpenPlatformHttpRequest) => {
    const headers = httpRequest.headers ?? {};
    const authenticated = Object.entries(headers).some(
      ([key, value]) => key.toLowerCase() === "x-events-auth" && value === "valid",
    );
    if (!authenticated) return undefined;
    const scoped = Object.entries(headers).some(
      ([key, value]) => key.toLowerCase() === "x-events-tenant" && typeof value === "string",
    )
      ? (headers["x-events-tenant"] as string)
      : targetTenantId;
    return { tenantId: scoped, actorId, requestId: "domain-events-request" };
  };
}

async function createApp(
  harness: Harness,
  options: { readonly targetTenantId?: string } = {},
) {
  const moduleRef = await Test.createTestingModule({
    imports: [
      OpenPlatformHttpModule.forRoot({
        service: harness.service,
        contextIssuer: issuer(),
        mode: "test",
        resolver: resolverFor(options.targetTenantId ?? tenantId),
      }),
    ],
  }).compile();
  const app = moduleRef.createNestApplication();
  await app.init();
  return app;
}

function auth<T extends { set: (name: string, value: string) => T }>(value: T): T {
  return value.set("x-events-auth", "valid");
}

function scoped<T extends { set: (name: string, value: string) => T }>(
  value: T,
  target: string,
): T {
  return value.set("x-events-tenant", target);
}

function idempotent<T extends { set: (name: string, value: string) => T }>(
  value: T,
  key: string,
): T {
  return value.set("Idempotency-Key", key);
}

async function seedEvent(
  outbox: OpenPlatformOutboxPort,
  target: string,
  input: {
    readonly eventId: string;
    readonly eventType?: string;
    readonly resourceType?: string;
    readonly resourceId?: string;
    readonly data?: Record<string, unknown>;
  },
): Promise<OpenPlatformOutboxRecord> {
  return outbox.append({
    eventId: input.eventId,
    tenantId: target,
    eventType: input.eventType ?? "application.status_changed",
    resourceType: (input.resourceType ?? "application") as never,
    resourceId: input.resourceId ?? "app-1",
    occurredAt: timestamp,
    ...(input.data === undefined ? {} : { data: input.data }),
  });
}

async function seedTenantEvents(harness: Harness): Promise<void> {
  await seedEvent(harness.outbox, tenantId, {
    eventId: "open_platform_event_1",
    data: { owner: "platform-ops", rotationNote: secretDataValue },
  });
  await seedEvent(harness.outbox, tenantId, {
    eventId: "open_platform_event_2",
    eventType: "application.created",
    resourceId: "app-2",
  });
  await seedEvent(harness.outbox, tenantId, {
    eventId: "open_platform_event_3",
    eventType: "credential.created",
    resourceType: "credential",
    resourceId: "cred-1",
  });
  await seedEvent(harness.outbox, otherTenantId, {
    eventId: "open_platform_event_other",
    resourceId: "app-other",
  });
}

function denyingAuthorization(): OpenPlatformAuthorizationPort {
  return Object.freeze({
    productionReady: false,
    authorize: () => false,
  });
}

describe("open platform domain event HTTP", () => {
  it("returns a tenant scoped safe summary without event data", async () => {
    const harness = createHarness();
    await seedTenantEvents(harness);
    const app = await createApp(harness);
    const server = app.getHttpServer();

    const response = await auth(
      request(server).get(OPEN_PLATFORM_DOMAIN_EVENTS_BASE_PATH),
    );
    expect(response.status).toBe(200);
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(response.body.tenantId).toBe(tenantId);
    expect(response.body.hasMore).toBe(false);
    expect(response.body.items).toHaveLength(3);
    expect(response.body.items[0]).toEqual({
      eventId: "open_platform_event_1",
      tenantId,
      type: "application.status_changed",
      resource: { type: "application", id: "app-1" },
      status: "pending",
      attempt: 0,
      occurredAt: timestamp,
      nextAttemptAt: timestamp,
    });
    expect(Object.keys(response.body.items[0]).sort()).toEqual([
      "attempt",
      "eventId",
      "nextAttemptAt",
      "occurredAt",
      "resource",
      "status",
      "tenantId",
      "type",
    ]);
    const serialized = JSON.stringify(response.body);
    expect(serialized).not.toContain(secretDataValue);
    expect(serialized).not.toContain("rotationNote");
    expect(serialized).not.toContain("data");
    expect(serialized).not.toContain("payload");
    expect(serialized).not.toContain("secret");
    expect(serialized).not.toContain("leaseId");
    expect(serialized).not.toContain(otherTenantId);
    expect(serialized).not.toContain("open_platform_event_other");

    const credential = await auth(
      request(server).get(
        `${OPEN_PLATFORM_DOMAIN_EVENTS_BASE_PATH}?eventType=credential.created&resourceType=credential&resourceId=cred-1`,
      ),
    );
    expect(credential.status).toBe(200);
    expect(credential.body.items).toHaveLength(1);
    expect(credential.body.items[0].resource).toEqual({
      type: "credential",
      id: "cred-1",
    });

    const published = await auth(
      request(server).get(`${OPEN_PLATFORM_DOMAIN_EVENTS_BASE_PATH}?status=published`),
    );
    expect(published.status).toBe(200);
    expect(published.body.items).toHaveLength(0);

    await app.close();
  });

  it("pages the tenant outbox with a sequence cursor", async () => {
    const harness = createHarness();
    await seedTenantEvents(harness);
    const app = await createApp(harness);
    const server = app.getHttpServer();

    const first = await auth(
      request(server).get(`${OPEN_PLATFORM_DOMAIN_EVENTS_BASE_PATH}?limit=2`),
    );
    expect(first.status).toBe(200);
    expect(first.body.items).toHaveLength(2);
    expect(first.body.items[0].eventId).toBe("open_platform_event_1");
    expect(first.body.items[1].eventId).toBe("open_platform_event_2");
    expect(first.body.hasMore).toBe(true);
    expect(first.body.nextSequence).toBe(2);

    const second = await auth(
      request(server).get(
        `${OPEN_PLATFORM_DOMAIN_EVENTS_BASE_PATH}?limit=2&sequence=${first.body.nextSequence}`,
      ),
    );
    expect(second.status).toBe(200);
    expect(second.body.items).toHaveLength(1);
    expect(second.body.items[0].eventId).toBe("open_platform_event_3");
    expect(second.body.hasMore).toBe(false);

    const cursorAlias = await auth(
      request(server).get(`${OPEN_PLATFORM_DOMAIN_EVENTS_BASE_PATH}?cursor=2`),
    );
    expect(cursorAlias.status).toBe(200);
    expect(cursorAlias.body.items).toHaveLength(1);

    const exhausted = await auth(
      request(server).get(`${OPEN_PLATFORM_DOMAIN_EVENTS_BASE_PATH}?sequence=99`),
    );
    expect(exhausted.status).toBe(200);
    expect(exhausted.body.items).toHaveLength(0);
    expect(exhausted.body.hasMore).toBe(false);

    await app.close();
  });

  it("keeps every other tenant out of the listing and the retry", async () => {
    const harness = createHarness();
    await seedTenantEvents(harness);
    const app = await createApp(harness);
    const server = app.getHttpServer();

    const queryMismatch = await auth(
      request(server).get(
        `${OPEN_PLATFORM_DOMAIN_EVENTS_BASE_PATH}?tenantId=${otherTenantId}`,
      ),
    );
    expect(queryMismatch.status).toBe(403);
    expect(queryMismatch.body.code).toBe("OPEN_PLATFORM_TENANT_MISMATCH");
    expect(queryMismatch.headers["cache-control"]).toBe("no-store");

    const bodyMismatch = await idempotent(
      auth(request(server).post(`${OPEN_PLATFORM_DOMAIN_EVENTS_BASE_PATH}/retry`)),
      "cross-tenant-retry-0001",
    ).send({ tenantId: otherTenantId });
    expect(bodyMismatch.status).toBe(403);
    expect(bodyMismatch.body.code).toBe("OPEN_PLATFORM_TENANT_MISMATCH");
    expect(JSON.stringify(bodyMismatch.body)).not.toContain(otherTenantId);
    expect(harness.flushCalls).toHaveLength(0);

    const otherTenant = await scoped(
      auth(request(server).get(OPEN_PLATFORM_DOMAIN_EVENTS_BASE_PATH)),
      otherTenantId,
    );
    expect(otherTenant.status).toBe(200);
    expect(otherTenant.body.tenantId).toBe(otherTenantId);
    expect(otherTenant.body.items).toHaveLength(1);
    expect(otherTenant.body.items[0].eventId).toBe("open_platform_event_other");
    expect(JSON.stringify(otherTenant.body)).not.toContain("app-1");

    await app.close();
  });

  it("requires an idempotency key and replays the retry result", async () => {
    const harness = createHarness();
    await seedTenantEvents(harness);
    const app = await createApp(harness);
    const server = app.getHttpServer();

    const missingKey = await auth(
      request(server).post(`${OPEN_PLATFORM_DOMAIN_EVENTS_BASE_PATH}/retry`),
    ).send({});
    expect(missingKey.status).toBe(400);
    expect(missingKey.body.code).toBe("OPEN_PLATFORM_VALIDATION_ERROR");
    expect(missingKey.headers["cache-control"]).toBe("no-store");
    expect(harness.flushCalls).toHaveLength(0);

    const invalidKey = await idempotent(
      auth(request(server).post(`${OPEN_PLATFORM_DOMAIN_EVENTS_BASE_PATH}/retry`)),
      "invalid key with spaces",
    ).send({});
    expect(invalidKey.status).toBe(400);
    expect(invalidKey.body.code).toBe("OPEN_PLATFORM_INVALID_IDEMPOTENCY_KEY");
    expect(harness.flushCalls).toHaveLength(0);

    const first = await idempotent(
      auth(request(server).post(`${OPEN_PLATFORM_DOMAIN_EVENTS_BASE_PATH}/retry`)),
      "domain-events-retry-0001",
    ).send({ eventType: "application.status_changed", limit: 25 });
    expect(first.status).toBe(200);
    expect(first.headers["idempotency-replayed"]).toBeUndefined();
    expect(first.body).toEqual({
      tenantId,
      replayed: false,
      flushed: 2,
      results: [
        { eventId: "open_platform_event_1", delivered: 2, deadLettered: false },
        { eventId: "open_platform_event_2", delivered: 0, deadLettered: true },
      ],
    });
    expect(harness.flushCalls).toEqual([
      { tenantId, eventType: "application.status_changed", limit: 25 },
    ]);

    const replay = await idempotent(
      auth(request(server).post(`${OPEN_PLATFORM_DOMAIN_EVENTS_BASE_PATH}/retry`)),
      "domain-events-retry-0001",
    ).send({ eventType: "application.status_changed", limit: 25 });
    expect(replay.status).toBe(200);
    expect(replay.headers["idempotency-replayed"]).toBe("true");
    expect(replay.body).toEqual({ ...first.body, replayed: true });
    expect(harness.flushCalls).toHaveLength(1);

    const reused = await idempotent(
      auth(request(server).post(`${OPEN_PLATFORM_DOMAIN_EVENTS_BASE_PATH}/retry`)),
      "domain-events-retry-0001",
    ).send({ eventType: "credential.created" });
    expect(reused.status).toBe(409);
    expect(reused.body.code).toBe("OPEN_PLATFORM_IDEMPOTENCY_KEY_REUSED");
    expect(harness.flushCalls).toHaveLength(1);

    const perActor = await idempotent(
      scoped(
        auth(
          request(server).post(`${OPEN_PLATFORM_DOMAIN_EVENTS_BASE_PATH}/retry`),
        ),
        otherTenantId,
      ),
      "domain-events-retry-0001",
    ).send({ eventType: "application.status_changed", limit: 25 });
    expect(perActor.status).toBe(200);
    expect(perActor.body.tenantId).toBe(otherTenantId);
    expect(harness.flushCalls).toHaveLength(2);
    expect(harness.flushCalls[1]).toEqual({
      tenantId: otherTenantId,
      eventType: "application.status_changed",
      limit: 25,
    });

    await app.close();
  });

  it("denies the listing and the retry without a webhook permission", async () => {
    const harness = createHarness({ authorization: denyingAuthorization() });
    await seedTenantEvents(harness);
    const app = await createApp(harness);
    const server = app.getHttpServer();

    const read = await auth(
      request(server).get(OPEN_PLATFORM_DOMAIN_EVENTS_BASE_PATH),
    );
    expect(read.status).toBe(403);
    expect(read.body.code).toBe("OPEN_PLATFORM_FORBIDDEN");
    expect(read.headers["cache-control"]).toBe("no-store");
    expect(JSON.stringify(read.body)).not.toContain(tenantId);

    const retry = await idempotent(
      auth(request(server).post(`${OPEN_PLATFORM_DOMAIN_EVENTS_BASE_PATH}/retry`)),
      "denied-retry-0001",
    ).send({});
    expect(retry.status).toBe(403);
    expect(retry.body.code).toBe("OPEN_PLATFORM_FORBIDDEN");
    expect(harness.flushCalls).toHaveLength(0);

    await app.close();
  });

  it("requires an authenticated context before touching the outbox", async () => {
    const harness = createHarness();
    await seedTenantEvents(harness);
    const app = await createApp(harness);
    const server = app.getHttpServer();

    const anonymous = await request(server).get(OPEN_PLATFORM_DOMAIN_EVENTS_BASE_PATH);
    expect(anonymous.status).toBe(401);
    expect(anonymous.body.code).toBe("OPEN_PLATFORM_AUTHENTICATION_REQUIRED");
    expect(anonymous.headers["cache-control"]).toBe("no-store");
    expect(JSON.stringify(anonymous.body)).not.toContain(tenantId);

    const anonymousRetry = await idempotent(
      request(server).post(`${OPEN_PLATFORM_DOMAIN_EVENTS_BASE_PATH}/retry`),
      "anonymous-retry-0001",
    ).send({});
    expect(anonymousRetry.status).toBe(401);
    expect(harness.flushCalls).toHaveLength(0);

    await app.close();
  });

  it("rejects unknown filters, arbitrary statements, and out of range cursors", async () => {
    const harness = createHarness();
    await seedTenantEvents(harness);
    const app = await createApp(harness);
    const server = app.getHttpServer();

    const cases: readonly string[] = [
      "?sql=SELECT%20*%20FROM%20gb_open_domain_event",
      "?where=1%3D1",
      "?status=bogus",
      "?eventType=application.exploded",
      "?resourceType=not_a_resource",
      "?sequence=-1",
      "?sequence=1.5",
      "?limit=0",
      "?limit=101",
      "?eventType=application.created&event_type=credential.created",
    ];
    for (const suffix of cases) {
      const response = await auth(
        request(server).get(`${OPEN_PLATFORM_DOMAIN_EVENTS_BASE_PATH}${suffix}`),
      );
      expect(response.status).toBe(400);
      expect(response.body.code).toBe("OPEN_PLATFORM_VALIDATION_ERROR");
      expect(response.headers["cache-control"]).toBe("no-store");
      expect(JSON.stringify(response.body)).not.toContain("gb_open_domain_event");
    }

    const bodies: readonly Readonly<Record<string, unknown>>[] = [
      { sql: "DELETE FROM gb_open_domain_event" },
      { endpointUrl: "https://attacker.example.test/hook" },
      { sql: "SELECT 1" },
      { eventType: "application.exploded" },
      { limit: 0 },
    ];
    for (const payload of bodies) {
      const response = await idempotent(
        auth(request(server).post(`${OPEN_PLATFORM_DOMAIN_EVENTS_BASE_PATH}/retry`)),
        `rejected-body-${Math.abs(JSON.stringify(payload).length)}`,
      ).send(payload);
      expect(response.status).toBe(400);
      expect(response.body.code).toBe("OPEN_PLATFORM_VALIDATION_ERROR");
      expect(JSON.stringify(response.body)).not.toContain("attacker.example.test");
      expect(JSON.stringify(response.body)).not.toContain("gb_open_domain_event");
    }
    expect(harness.flushCalls).toHaveLength(0);

    await app.close();
  });

  it("hides outbox storage failures behind a retryable contract error", async () => {
    const connectionString =
      "postgres://open_platform:hunter2@db.internal:5432/idaas?sslmode=require";
    const outbox: OpenPlatformOutboxPort = {
      readiness: { storage: "memory", distributed: false, ready: () => true },
      append: async () => {
        throw new Error("unreachable");
      },
      get: async () => undefined,
      list: async () => {
        throw new Error(`connection failed: ${connectionString}`);
      },
    };
    const service = createOpenPlatformService({
      mode: "test",
      authorization: createDevelopmentOpenPlatformAuthorization("all"),
      repositories: new InMemoryOpenPlatformRepositories({ clock: () => now }),
      outbox,
      eventPublisher: {
        readiness: { storage: "memory", distributed: false, ready: () => true },
        record: async () => {
          throw new Error("unreachable");
        },
        publish: async () => ({ eventId: "unused", delivered: 0, deadLettered: false }),
        flush: async () => {
          throw new Error(`flush failed: ${connectionString}`);
        },
      },
      clock: () => now,
    });
    const app = await createApp({ service, outbox: new InMemoryOpenPlatformOutbox(), flushCalls: [] });
    const server = app.getHttpServer();

    const read = await auth(
      request(server).get(OPEN_PLATFORM_DOMAIN_EVENTS_BASE_PATH),
    );
    expect(read.status).toBe(503);
    expect(read.body).toEqual({
      code: "OPEN_PLATFORM_STORAGE_UNAVAILABLE",
      message: "Open platform service is unavailable",
      requestId: "domain-events-request",
    });
    expect(read.headers["retry-after"]).toBe("1");
    expect(read.headers["cache-control"]).toBe("no-store");
    expect(JSON.stringify(read.body)).not.toContain(connectionString);
    expect(JSON.stringify(read.body)).not.toContain("hunter2");

    const retry = await idempotent(
      auth(request(server).post(`${OPEN_PLATFORM_DOMAIN_EVENTS_BASE_PATH}/retry`)),
      "storage-failure-retry-0001",
    ).send({});
    expect(retry.status).toBe(503);
    expect(retry.body.code).toBe("OPEN_PLATFORM_STORAGE_UNAVAILABLE");
    expect(JSON.stringify(retry.body)).not.toContain(connectionString);

    await app.close();
  });
});
