import { describe, expect, it } from "vitest";
import { COMMERCE_ENTITY_KINDS } from "../src/open-platform/commerce/types.js";
import { COMPLIANCE_ENTITY_KINDS } from "../src/open-platform/compliance/types.js";
import {
  InMemoryOpenPlatformOutbox,
  InMemoryOpenPlatformRepositories,
  OPEN_PLATFORM_AUTHORIZATION,
  OPEN_PLATFORM_CROSS_DOMAIN_EVENT_RESOURCE_BINDINGS,
  OPEN_PLATFORM_DOMAIN_EVENT_CATALOG,
  OPEN_PLATFORM_DOMAIN_EVENT_RESOURCE_KINDS,
  OPEN_PLATFORM_DOMAIN_EVENT_TYPES,
  OPEN_PLATFORM_ERROR_CODES,
  OPEN_PLATFORM_EVENT_PUBLISHER,
  OPEN_PLATFORM_LIFECYCLE_DEPRECATED_EVENT_TYPES,
  OPEN_PLATFORM_LIFECYCLE_PUBLISHED_EVENT_TYPES,
  OPEN_PLATFORM_LIFECYCLE_RESOURCE_KINDS,
  OPEN_PLATFORM_LIFECYCLE_STATUS_EVENT_TYPES,
  OPEN_PLATFORM_OUTBOX,
  OPEN_PLATFORM_SERVICE,
  OpenPlatformEventPublisher,
  OpenPlatformProviderModule,
  OpenPlatformService,
  OPEN_PLATFORM_WEBHOOK_SIGNATURE_HEADER,
  OPEN_PLATFORM_WEBHOOK_TIMESTAMP_HEADER,
  containsOpenPlatformSensitiveEventData,
  createDevelopmentOpenPlatformAuthorization,
  createInMemoryOpenPlatformOutbox,
  createOpenPlatformId,
  createOpenPlatformRequestContextIssuer,
  createOpenPlatformService,
  isOpenPlatformDomainEventType,
  openPlatformDomainEventResourceKind,
  openPlatformDomainEventTypeForLifecycle,
  sanitizeOpenPlatformDomainEventData,
  verifyOpenPlatformWebhookSignature,
  createDevelopmentOpenPlatformRequestContext,
  type OpenPlatformDependencyReadiness,
  type OpenPlatformEventPublisherPort,
  type OpenPlatformOutboxPort,
  type OpenPlatformOutboxRecord,
  type OpenPlatformRequestContext,
  type OpenPlatformServiceOptions,
  type OpenPlatformWebhookTransportRequest,
  type OpenPlatformWebhookTransportResponse,
} from "../src/open-platform/index.js";
import {
  OPEN_PLATFORM_DOMAIN_EVENT_CATALOG as OPEN_PLATFORM_CONTRACT_EVENT_CATALOG,
  OPEN_PLATFORM_DOMAIN_EVENT_RESOURCES,
  OPEN_PLATFORM_WEBHOOK_EVENTS,
} from "@getbrick/idaas-contracts";
import {
  OPEN_PLATFORM_SQL_TABLES,
  OpenPlatformSqlRuntime,
  SqlDomainEventOutboxRepository,
  createOpenPlatformDomainEventMigrationSql,
  getOpenPlatformDomainEventMigrationDefinition,
  type DatabaseAdapter,
} from "../src/open-platform/persistence/index.js";

const now = new Date("2030-01-01T00:00:00.000Z");
const timestamp = now.toISOString();

interface RecordedRequest extends OpenPlatformWebhookTransportRequest {
  index: number;
}

function createRecordingTransport(
  respond: (request: OpenPlatformWebhookTransportRequest, index: number) => OpenPlatformWebhookTransportResponse = () => ({ statusCode: 200, body: "ok" }),
): { requests: RecordedRequest[]; transport: (request: OpenPlatformWebhookTransportRequest) => OpenPlatformWebhookTransportResponse } {
  const requests: RecordedRequest[] = [];
  return {
    requests,
    transport(request) {
      const index = requests.length;
      requests.push({ ...request, index });
      return respond(request, index);
    },
  };
}

function header(request: OpenPlatformWebhookTransportRequest, name: string): string | undefined {
  const entry = Object.entries(request.headers).find(
    ([key]) => key.toLowerCase() === name.toLowerCase(),
  );
  return entry?.[1];
}

function createContextIssuer(): { context(tenantId: string, actorId?: string): OpenPlatformRequestContext } {
  const issuer = createOpenPlatformRequestContextIssuer({
    issuerId: "open-platform-domain-events",
    attestation: Object.freeze({ test: true }),
    clock: () => now,
  });
  let sequence = 0;
  return {
    context(tenantId, actorId = "actor-events") {
      sequence += 1;
      return issuer.issueDevelopment({
        tenantId,
        actorId,
        requestId: `request-${sequence}`,
      });
    },
  };
}

interface Harness {
  service: OpenPlatformService;
  outbox: OpenPlatformOutboxPort;
  requests: RecordedRequest[];
  context(tenantId: string, actorId?: string): OpenPlatformRequestContext;
}

async function createHarness(
  options: {
    transport?: (request: OpenPlatformWebhookTransportRequest) => OpenPlatformWebhookTransportResponse;
    respond?: (request: OpenPlatformWebhookTransportRequest, index: number) => OpenPlatformWebhookTransportResponse;
    mode?: OpenPlatformServiceOptions["mode"];
    outbox?: OpenPlatformOutboxPort;
    eventPublisher?: OpenPlatformServiceOptions["eventPublisher"];
    usageEventThresholds?: OpenPlatformServiceOptions["usageEventThresholds"];
    repositories?: InMemoryOpenPlatformRepositories;
    clock?: () => Date;
  } = {},
): Promise<Harness> {
  const recorded = createRecordingTransport(options.respond);
  const transport = options.transport ?? recorded.transport;
  const outbox = options.outbox ?? new InMemoryOpenPlatformOutbox({
    clock: options.clock ?? (() => now),
  });
  const service = createOpenPlatformService({
    mode: options.mode ?? "test",
    authorization: createDevelopmentOpenPlatformAuthorization("all"),
    repositories: options.repositories ?? new InMemoryOpenPlatformRepositories({
      clock: options.clock ?? (() => now),
    }),
    outbox,
    ...(options.eventPublisher === undefined
      ? {}
      : { eventPublisher: options.eventPublisher }),
    ...(options.usageEventThresholds === undefined
      ? {}
      : { usageEventThresholds: options.usageEventThresholds }),
    webhookTransport: transport,
    webhookService: { sleep: async () => undefined, baseDelayMs: 0, maxDelayMs: 0 },
    clock: options.clock ?? (() => now),
  });
  const contexts = createContextIssuer();
  return {
    service,
    outbox,
    requests: recorded.requests,
    context: contexts.context,
  };
}

async function seedPublishedApplication(
  harness: Harness,
  tenantId: string,
): Promise<{ applicationId: string; environmentId: string }> {
  const context = harness.context(tenantId);
  const tenant = await harness.service.createTenant(context, {
    tenantId,
    name: "Events tenant",
    idempotencyKey: `${tenantId}-tenant`,
  });
  await harness.service.publish(context, {
    resource: "tenant",
    tenantId,
    id: tenant.id,
    idempotencyKey: `${tenantId}-tenant-publish`,
  });
  const organization = await harness.service.createDeveloperOrganization(context, {
    tenantId,
    name: "Events organization",
    idempotencyKey: `${tenantId}-organization`,
  });
  await harness.service.publish(context, {
    resource: "developerOrganization",
    tenantId,
    id: organization.id,
    idempotencyKey: `${tenantId}-organization-publish`,
  });
  const application = await harness.service.createApplication(context, {
    tenantId,
    organizationId: organization.id,
    name: "Events application",
    idempotencyKey: `${tenantId}-application`,
  });
  await harness.service.publish(context, {
    resource: "application",
    tenantId,
    id: application.id,
    idempotencyKey: `${tenantId}-application-publish`,
  });
  const environment = await harness.service.createApplicationEnvironment(context, {
    tenantId,
    applicationId: application.id,
    name: "Production",
    idempotencyKey: `${tenantId}-environment`,
  });
  await harness.service.publish(context, {
    resource: "applicationEnvironment",
    tenantId,
    id: environment.id,
    idempotencyKey: `${tenantId}-environment-publish`,
  });
  return { applicationId: application.id, environmentId: environment.id };
}

async function createWebhook(
  harness: Harness,
  input: {
    tenantId: string;
    applicationId: string;
    environmentId: string;
    events: readonly string[];
    key: string;
  },
): Promise<{ id: string; secret: string }> {
  const result = await harness.service.createWebhook(harness.context(input.tenantId), {
    tenantId: input.tenantId,
    applicationId: input.applicationId,
    environmentId: input.environmentId,
    name: "Events webhook",
    endpointUrl: "https://client.example.test/hooks/events",
    events: input.events,
    idempotencyKey: input.key,
  });
  return { id: result.webhook.id, secret: result.secret };
}

describe("open platform domain event outbox", () => {
  it("isolates tenants, numbers sequences, and is idempotent per event id", async () => {
    const outbox = createInMemoryOpenPlatformOutbox({ clock: () => now });
    const first = await outbox.append({
      eventId: "open_platform_event_1",
      tenantId: "tenant-outbox-a",
      eventType: "application.created",
      resourceType: "application",
      resourceId: "app-1",
      resourceVersion: 1,
      resourceStatus: "draft",
      actorId: "actor-a",
      requestId: "request-a",
      occurredAt: timestamp,
    });
    const repeated = await outbox.append({
      eventId: "open_platform_event_1",
      tenantId: "tenant-outbox-a",
      eventType: "application.created",
      resourceType: "application",
      resourceId: "app-1",
      resourceVersion: 1,
      resourceStatus: "draft",
      occurredAt: timestamp,
    });
    const second = await outbox.append({
      eventId: "open_platform_event_2",
      tenantId: "tenant-outbox-a",
      eventType: "client.created",
      resourceType: "applicationEnvironment",
      resourceId: "env-1",
      occurredAt: timestamp,
    });
    const other = await outbox.append({
      eventId: "open_platform_event_3",
      tenantId: "tenant-outbox-b",
      eventType: "application.created",
      resourceType: "application",
      resourceId: "app-1",
      occurredAt: timestamp,
    });

    expect(repeated).toEqual(first);
    expect(second.sequence).toBe(2);
    expect(other.sequence).toBe(1);
    expect(first.status).toBe("pending");
    expect(first.schemaVersion).toBe("open-platform.domain-event.v1");
    expect(Object.isFrozen(first)).toBe(true);
    expect(outbox.size()).toBe(3);
    expect((await outbox.list({ tenantId: "tenant-outbox-a" })).items).toHaveLength(2);
    expect((await outbox.list({ tenantId: "tenant-outbox-b" })).items).toHaveLength(1);
    expect(await outbox.get("tenant-outbox-b", first.eventId)).toBeUndefined();
    expect(await outbox.get("tenant-outbox-a", "open_platform_event_missing")).toBeUndefined();
    const page = await outbox.list({ tenantId: "tenant-outbox-a", limit: 1 });
    expect(page.hasMore).toBe(true);
    expect(page.nextSequence).toBe(1);
    expect(await outbox.isReady()).toBe(true);
    expect(
      new InMemoryOpenPlatformOutbox({ production: true }).readiness.ready(),
    ).toBe(false);
    await expect(
      outbox.list({ tenantId: "tenant-outbox-a", status: "published" as "pending" }),
    ).resolves.toMatchObject({ items: [] });
    await expect(
      outbox.append({
        tenantId: "tenant-outbox-a",
        eventType: "application.deleted" as "application.created",
        resourceType: "application",
        resourceId: "app-1",
        occurredAt: timestamp,
      }),
    ).rejects.toMatchObject({ code: OPEN_PLATFORM_ERROR_CODES.VALIDATION_ERROR });
  });

  it("allows a single claim winner and only reclaims an expired lease", async () => {
    const outbox = createInMemoryOpenPlatformOutbox({ clock: () => now });
    await outbox.append({
      eventId: "open_platform_event_claim",
      tenantId: "tenant-claim",
      eventType: "application.status_changed",
      resourceType: "application",
      resourceId: "app-1",
      occurredAt: timestamp,
    });
    const first = await outbox.claim({
      tenantId: "tenant-claim",
      eventId: "open_platform_event_claim",
      attempt: 1,
      leaseId: "lease-first",
      now: timestamp,
      leaseExpiresAt: "2030-01-01T00:00:30.000Z",
    });
    expect(first.claimed).toBe(true);
    expect(first.record).toMatchObject({ status: "delivering", attempt: 1, leaseId: "lease-first" });

    const contested = await outbox.claim({
      tenantId: "tenant-claim",
      eventId: "open_platform_event_claim",
      attempt: 1,
      leaseId: "lease-second",
      now: "2030-01-01T00:00:05.000Z",
      leaseExpiresAt: "2030-01-01T00:00:35.000Z",
    });
    expect(contested.claimed).toBe(false);

    const crossTenant = await outbox.claim({
      tenantId: "tenant-other",
      eventId: "open_platform_event_claim",
      attempt: 1,
      leaseId: "lease-third",
      now: timestamp,
      leaseExpiresAt: "2030-01-01T00:00:30.000Z",
    });
    expect(crossTenant.claimed).toBe(false);

    const recovered = await outbox.claim({
      tenantId: "tenant-claim",
      eventId: "open_platform_event_claim",
      attempt: 2,
      leaseId: "lease-fourth",
      now: "2030-01-01T00:01:00.000Z",
      leaseExpiresAt: "2030-01-01T00:01:30.000Z",
    });
    expect(recovered.claimed).toBe(true);
    expect(recovered.record).toMatchObject({ status: "delivering", attempt: 2, leaseId: "lease-fourth" });

    const published = await outbox.complete({
      tenantId: "tenant-claim",
      eventId: "open_platform_event_claim",
      now: "2030-01-01T00:01:31.000Z",
    });
    expect(published).toMatchObject({
      status: "published",
      publishedAt: "2030-01-01T00:01:31.000Z",
    });
    expect(
      await outbox.claim({
        tenantId: "tenant-claim",
        eventId: "open_platform_event_claim",
        attempt: 3,
        leaseId: "lease-fifth",
        now: "2030-01-01T00:02:00.000Z",
        leaseExpiresAt: "2030-01-01T00:02:30.000Z",
      }),
    ).toMatchObject({ claimed: false });
  });

  it("retries a failing sink, backs off, and dead letters after the attempt budget", async () => {
    let currentTime = Date.parse(timestamp);
    const clock = (): Date => new Date(currentTime);
    const outbox = createInMemoryOpenPlatformOutbox({ clock, maxAttempts: 2 });
    const attempts: number[] = [];
    const publisher = new OpenPlatformEventPublisher({
      outbox,
      clock,
      sink: {
        deliver: (event) => {
          attempts.push(event.attempt);
          if (event.attempt < 2) throw new Error("sink unavailable");
          return { delivered: 0, deadLettered: 1 };
        },
      },
    });
    const record = await outbox.append({
      eventId: "open_platform_event_retry",
      tenantId: "tenant-retry",
      eventType: "api_version.published",
      resourceType: "apiVersion",
      resourceId: "apiver-1",
      occurredAt: timestamp,
    });
    const first = await publisher.publish(record);
    expect(first).toMatchObject({ delivered: 0, deadLettered: false });
    expect(attempts).toEqual([1]);
    const failed = await outbox.get("tenant-retry", record.eventId);
    expect(failed).toMatchObject({ status: "failed", attempt: 1, errorCode: "EVENT_SINK_ERROR" });
    expect(failed?.nextAttemptAt).toBe(new Date(currentTime + 1_000).toISOString());

    const early = await publisher.publish(failed as OpenPlatformOutboxRecord);
    expect(early).toMatchObject({ delivered: 0, deadLettered: false });
    expect(attempts).toEqual([1]);

    currentTime += 60_000;
    const due = (await outbox.get("tenant-retry", record.eventId)) as OpenPlatformOutboxRecord;
    const second = await publisher.publish(due);
    expect(second).toMatchObject({ delivered: 0, deadLettered: true });
    expect(attempts).toEqual([1, 2]);
    const dead = await outbox.get("tenant-retry", record.eventId);
    expect(dead?.status).toBe("dead_lettered");
    expect(dead?.nextAttemptAt).toBeUndefined();
    expect(
      await publisher.publish(dead as OpenPlatformOutboxRecord),
    ).toMatchObject({ deadLettered: true });
    expect(attempts).toEqual([1, 2]);
    expect(
      (await publisher.flush({ tenantId: "tenant-retry" })).length,
    ).toBe(0);
  });

  it("strips secrets, tokens, and personal data from event payloads", () => {
    expect(
      sanitizeOpenPlatformDomainEventData({
        status: "published",
        version: 2,
        scopes: ["orders:read"],
        clientSecret: "super-secret-value",
        accessToken: "token-value",
        password: "hunter2",
        secretDigest: "sha256:abc",
        sessionKey: "session",
        fingerprint: "abcdef",
        userEmail: "person@example.test",
        phone: "+1-555-0100",
        nested: { secret: "nope" },
        long: "x".repeat(300),
        notSerializable: () => undefined,
      }),
    ).toEqual({ scopes: ["orders:read"], status: "published", version: 2 });
  });
});

describe("open platform domain event catalog", () => {
  it("reuses the contract catalog as the single source of truth", () => {
    expect(OPEN_PLATFORM_DOMAIN_EVENT_TYPES).toBe(OPEN_PLATFORM_WEBHOOK_EVENTS);
    expect(OPEN_PLATFORM_DOMAIN_EVENT_CATALOG).toBe(OPEN_PLATFORM_CONTRACT_EVENT_CATALOG);
    expect(OPEN_PLATFORM_DOMAIN_EVENT_RESOURCES).toEqual([
      "tenant",
      "developer_organization",
      "application",
      "client",
      "credential",
      "api_product",
      "api_version",
      "subscription",
      "scope_grant",
      "usage",
      "commerce_listing",
      "commerce_partner",
      "commerce_commission",
      "commerce_account",
      "commerce_invoice",
      "commerce_dispute",
      "compliance_data_asset",
      "compliance_consent_record",
      "compliance_privacy_request",
      "compliance_retention_policy",
      "compliance_cross_border_assessment",
      "compliance_vendor",
    ]);
    expect(OPEN_PLATFORM_DOMAIN_EVENT_TYPES).toHaveLength(72);
    expect(new Set(OPEN_PLATFORM_DOMAIN_EVENT_TYPES).size).toBe(
      OPEN_PLATFORM_DOMAIN_EVENT_TYPES.length,
    );
    for (const eventType of OPEN_PLATFORM_DOMAIN_EVENT_TYPES) {
      expect(eventType).toMatch(/^[a-z][a-z0-9]*(?:_[a-z0-9]+)*\.[a-z][a-z0-9]*(?:_[a-z0-9]+)*$/u);
      const [resource, action] = eventType.split(".");
      expect(
        (OPEN_PLATFORM_DOMAIN_EVENT_CATALOG[resource as keyof typeof OPEN_PLATFORM_DOMAIN_EVENT_CATALOG] as readonly string[]).includes(action as string),
      ).toBe(true);
      expect(isOpenPlatformDomainEventType(eventType)).toBe(true);
    }
  });

  it("maps every persisted catalog resource onto an open platform entity kind", () => {
    expect(Object.keys(OPEN_PLATFORM_DOMAIN_EVENT_RESOURCE_KINDS).sort()).toEqual(
      [
        "tenant",
        "developer_organization",
        "application",
        "client",
        "credential",
        "api_product",
        "api_version",
        "subscription",
        "scope_grant",
        "usage",
      ].sort(),
    );
    const kinds = new Set<string>();
    for (const [resource, kind] of Object.entries(OPEN_PLATFORM_DOMAIN_EVENT_RESOURCE_KINDS)) {
      expect(OPEN_PLATFORM_CONTRACT_EVENT_CATALOG).toHaveProperty(resource);
      expect(createOpenPlatformId(kind)).toMatch(/^[a-z]+_[0-9a-f-]{36}$/u);
      kinds.add(kind);
    }
    for (const eventType of OPEN_PLATFORM_DOMAIN_EVENT_TYPES) {
      const resource = eventType.slice(0, eventType.indexOf("."));
      if (!Object.hasOwn(OPEN_PLATFORM_DOMAIN_EVENT_RESOURCE_KINDS, resource)) {
        expect(() => openPlatformDomainEventResourceKind(eventType)).toThrowError(
          /resource kind is unavailable/u,
        );
        continue;
      }
      const kind = openPlatformDomainEventResourceKind(eventType);
      expect(kinds.has(kind)).toBe(true);
    }
  });

  it("rejects domain events without a persisted open platform entity kind", () => {
    let failure: unknown;
    try {
      openPlatformDomainEventResourceKind("commerce_invoice.created");
    } catch (error) {
      failure = error;
    }
    expect(failure).toMatchObject({ code: OPEN_PLATFORM_ERROR_CODES.VALIDATION_ERROR });
  });

  it("binds every cross-domain catalog resource onto a registrable entity kind", () => {
    expect(Object.keys(OPEN_PLATFORM_CROSS_DOMAIN_EVENT_RESOURCE_BINDINGS).sort()).toEqual(
      [
        "commerce_listing",
        "commerce_partner",
        "commerce_commission",
        "commerce_account",
        "commerce_invoice",
        "commerce_dispute",
        "compliance_data_asset",
        "compliance_consent_record",
        "compliance_privacy_request",
        "compliance_retention_policy",
        "compliance_cross_border_assessment",
        "compliance_vendor",
      ].sort(),
    );
    const commerceKinds = new Set<string>([...COMMERCE_ENTITY_KINDS, "invoice", "invoiceDispute"]);
    for (const [resource, kind] of Object.entries(
      OPEN_PLATFORM_CROSS_DOMAIN_EVENT_RESOURCE_BINDINGS,
    )) {
      expect(OPEN_PLATFORM_CONTRACT_EVENT_CATALOG).toHaveProperty(resource);
      if (resource.startsWith("commerce_")) {
        expect(commerceKinds.has(kind)).toBe(true);
        continue;
      }
      expect(COMPLIANCE_ENTITY_KINDS).toContain(kind);
    }
    const covered = new Set([
      ...Object.keys(OPEN_PLATFORM_DOMAIN_EVENT_RESOURCE_KINDS),
      ...Object.keys(OPEN_PLATFORM_CROSS_DOMAIN_EVENT_RESOURCE_BINDINGS),
    ]);
    for (const resource of OPEN_PLATFORM_DOMAIN_EVENT_RESOURCES) {
      expect(covered.has(resource)).toBe(true);
    }
  });

  it("accepts cross-domain entity kinds as outbox resource types", async () => {
    for (const eventType of [
      "commerce_invoice.status_changed",
      "commerce_dispute.decided",
      "compliance_privacy_request.decided",
      "compliance_retention_policy.executed",
    ]) {
      expect(isOpenPlatformDomainEventType(eventType)).toBe(true);
    }
    const outbox = new InMemoryOpenPlatformOutbox();
    await expect(
      outbox.append({
        eventId: "evt_commerce_invoice_1",
        tenantId: "tenant-events",
        eventType: "commerce_invoice.status_changed",
        resourceType: "invoice",
        resourceId: "inv_1",
        resourceStatus: "paid",
        occurredAt: "2026-01-01T00:00:00.000Z",
        data: { invoiceId: "inv_1" },
      }),
    ).resolves.toMatchObject({
      resourceType: "invoice",
      eventType: "commerce_invoice.status_changed",
      status: "pending",
    });
    await expect(
      outbox.append({
        eventId: "evt_compliance_privacy_1",
        tenantId: "tenant-events",
        eventType: "compliance_privacy_request.decided",
        resourceType: "privacyRequest",
        resourceId: "pr_1",
        resourceStatus: "completed",
        occurredAt: "2026-01-01T00:00:00.000Z",
      }),
    ).resolves.toMatchObject({ resourceType: "privacyRequest" });
    await expect(
      outbox.append({
        eventId: "evt_unknown_kind_1",
        tenantId: "tenant-events",
        eventType: "compliance_privacy_request.decided",
        resourceType: "not_a_registered_kind" as never,
        resourceId: "pr_2",
        occurredAt: "2026-01-01T00:00:00.000Z",
      }),
    ).rejects.toThrowError(/resource type is invalid/u);
  });

  it("keeps every previously published event name accepted", () => {
    for (const eventType of [
      "application.created",
      "application.updated",
      "application.status_changed",
      "client.created",
      "client.updated",
      "client.status_changed",
      "credential.status_changed",
      "api_product.published",
      "api_version.published",
      "api_version.deprecated",
      "subscription.status_changed",
      "usage.threshold_reached",
    ]) {
      expect(isOpenPlatformDomainEventType(eventType)).toBe(true);
    }
  });

  it("rejects unknown event names everywhere a subscription is validated", () => {
    for (const rejected of [
      "application.deleted",
      "usage.recorded",
      "webhook.delivered",
      "application",
      "application.created ",
      "APPLICATION.CREATED",
      "",
    ]) {
      expect(isOpenPlatformDomainEventType(rejected)).toBe(false);
    }
    const outbox = createInMemoryOpenPlatformOutbox({ clock: () => now });
    return expect(
      outbox.append({
        tenantId: "tenant-catalog",
        eventType: "application.deleted",
        resourceType: "application",
        resourceId: "app-1",
        occurredAt: timestamp,
      }),
    ).rejects.toMatchObject({ code: OPEN_PLATFORM_ERROR_CODES.VALIDATION_ERROR });
  });

  it("derives one lifecycle event per granular target status", () => {
    expect(OPEN_PLATFORM_LIFECYCLE_RESOURCE_KINDS).toHaveLength(7);
    expect(OPEN_PLATFORM_LIFECYCLE_PUBLISHED_EVENT_TYPES).toEqual({
      tenant: "tenant.status_changed",
      developerOrganization: "developer_organization.status_changed",
      application: "application.status_changed",
      applicationEnvironment: "client.status_changed",
      apiProduct: "api_product.published",
      apiVersion: "api_version.published",
      subscription: "subscription.status_changed",
    });
    expect(OPEN_PLATFORM_LIFECYCLE_DEPRECATED_EVENT_TYPES).toMatchObject({
      apiProduct: "api_product.deprecated",
      apiVersion: "api_version.deprecated",
      application: "application.status_changed",
    });
    expect(OPEN_PLATFORM_LIFECYCLE_STATUS_EVENT_TYPES).toMatchObject({
      apiProduct: "api_product.status_changed",
      apiVersion: "api_version.status_changed",
    });
    for (const resource of OPEN_PLATFORM_LIFECYCLE_RESOURCE_KINDS) {
      for (const [targetStatus, expected] of [
        ["published", OPEN_PLATFORM_LIFECYCLE_PUBLISHED_EVENT_TYPES],
        ["disabled", OPEN_PLATFORM_LIFECYCLE_DEPRECATED_EVENT_TYPES],
        ["archived", OPEN_PLATFORM_LIFECYCLE_STATUS_EVENT_TYPES],
      ] as const) {
        const eventType = openPlatformDomainEventTypeForLifecycle(resource, targetStatus);
        expect(eventType).toBe(expected[resource]);
        expect(isOpenPlatformDomainEventType(eventType)).toBe(true);
      }
      expect(
        openPlatformDomainEventTypeForLifecycle(resource, "draft"),
      ).toBeUndefined();
    }
    expect(openPlatformDomainEventTypeForLifecycle("credential", "published")).toBeUndefined();
    expect(openPlatformDomainEventTypeForLifecycle("webhook", "archived")).toBeUndefined();
  });
});

describe("open platform automatic webhook delivery", () => {
  it("delivers a signed domain event after the core write that produced it", async () => {
    const harness = await createHarness();
    const tenantId = "tenant-events-delivery";
    const { applicationId, environmentId } = await seedPublishedApplication(
      harness,
      tenantId,
    );
    const webhook = await createWebhook(harness, {
      tenantId,
      applicationId,
      environmentId,
      events: ["application.status_changed"],
      key: "events-delivery-webhook",
    });
    const context = harness.context(tenantId);
    await harness.service.deactivate(context, {
      resource: "application",
      tenantId,
      id: applicationId,
      idempotencyKey: "events-delivery-deactivate",
    });

    expect(harness.requests).toHaveLength(1);
    const request = harness.requests[0];
    expect(request.url).toBe("https://client.example.test/hooks/events");
    expect(request.method).toBe("POST");
    expect(
      verifyOpenPlatformWebhookSignature({
        body: request.body,
        signature: header(request, OPEN_PLATFORM_WEBHOOK_SIGNATURE_HEADER) ?? "",
        timestamp: header(request, OPEN_PLATFORM_WEBHOOK_TIMESTAMP_HEADER) ?? "",
        secretVersion: "1",
        secret: webhook.secret,
        now,
      }),
    ).toBe(true);
    const payload = JSON.parse(request.body) as Record<string, unknown>;
    expect(payload).toMatchObject({
      event_type: "application.status_changed",
      tenant_id: tenantId,
      schema_version: "open-platform.webhook-event.v1",
      resource: { type: "application", id: applicationId, status: "disabled" },
      actor: { type: "user", id: "actor-events" },
    });
    expect((payload.data as Record<string, unknown>).action).toBe("disabled");
    expect((payload.data as Record<string, unknown>).trigger).toBe("disable");
    expect((payload.data as Record<string, unknown>).fromStatus).toBe("published");
    expect(Object.keys(payload.data as Record<string, unknown>).sort()).toEqual([
      "action",
      "fromStatus",
      "toStatus",
      "trigger",
    ]);
    expect(request.body).not.toMatch(/secret|password|token|authorization/iu);
    expect(header(request, "idempotency-key")).toBe(payload.event_id);
    expect(header(request, "x-webhook-event-type")).toBe("application.status_changed");

    const stored = (await harness.outbox.list({ tenantId, limit: 50 })).items.filter(
      (item) =>
        item.eventType === "application.status_changed" &&
        item.resourceStatus === "disabled",
    );
    expect(stored).toHaveLength(1);
    expect(stored[0]).toMatchObject({
      eventType: "application.status_changed",
      resourceType: "application",
      resourceId: applicationId,
      resourceStatus: "disabled",
      status: "published",
      attempt: 1,
      tenantId,
    });
    expect(
      (await harness.outbox.list({ tenantId, eventType: "client.created" })).items,
    ).toHaveLength(1);
    const deliveries = await harness.service.listWebhookDeliveries(context, {
      tenantId,
      limit: 10,
    });
    expect(deliveries.items).toHaveLength(1);
    expect(deliveries.items[0]).toMatchObject({
      status: "succeeded",
      event: "application.status_changed",
      attempt: 1,
    });
  });

  it("emits typed events for the remaining lifecycle, credential, and usage writes", async () => {
    const harness = await createHarness({ usageEventThresholds: { "orders:read": 10 } });
    const tenantId = "tenant-events-mapping";
    const { applicationId, environmentId } = await seedPublishedApplication(
      harness,
      tenantId,
    );
    const seededEventCount = (await harness.outbox.list({ tenantId, limit: 100 })).items
      .length;
    await createWebhook(harness, {
      tenantId,
      applicationId,
      environmentId,
      events: [...OPEN_PLATFORM_DOMAIN_EVENT_TYPES],
      key: "events-mapping-webhook",
    });
    const context = harness.context(tenantId);
    const environment = await harness.service.createApplicationEnvironment(context, {
      tenantId,
      applicationId,
      name: "Staging",
      idempotencyKey: "events-mapping-environment",
    });
    await harness.service.publish(context, {
      resource: "applicationEnvironment",
      tenantId,
      id: environment.id,
      idempotencyKey: "events-mapping-environment-publish",
    });
    const product = await harness.service.createApiProduct(context, {
      tenantId,
      name: "Orders API",
      scopes: ["orders:read"],
      idempotencyKey: "events-mapping-product",
    });
    await harness.service.publish(context, {
      resource: "apiProduct",
      tenantId,
      id: product.id,
      idempotencyKey: "events-mapping-product-publish",
    });
    const version = await harness.service.createApiVersion(context, {
      tenantId,
      productId: product.id,
      apiVersion: "1.0.0",
      scopes: ["orders:read"],
      idempotencyKey: "events-mapping-version",
    });
    await harness.service.publish(context, {
      resource: "apiVersion",
      tenantId,
      id: version.id,
      idempotencyKey: "events-mapping-version-publish",
    });
    const issued = await harness.service.issueCredential(context, {
      tenantId,
      applicationId,
      environmentId,
      name: "Orders credential",
      scopes: ["orders:read"],
      idempotencyKey: "events-mapping-credential",
    });
    const rotated = await harness.service.rotateCredential(context, {
      tenantId,
      credentialId: issued.credential.id,
      idempotencyKey: "events-mapping-credential-rotate",
    });
    await harness.service.revokeCredential(context, {
      tenantId,
      credentialId: rotated.credential.id,
      idempotencyKey: "events-mapping-credential-revoke",
    });
    await harness.service.revokeCredential(harness.context(tenantId), {
      tenantId,
      credentialId: issued.credential.id,
      idempotencyKey: "events-mapping-credential-revoke-settled",
    });
    const subscription = await harness.service.createSubscription(context, {
      tenantId,
      applicationId,
      productId: product.id,
      name: "Orders subscription",
      scopes: ["orders:read"],
      idempotencyKey: "events-mapping-subscription",
    });
    await harness.service.publish(context, {
      resource: "subscription",
      tenantId,
      id: subscription.id,
      idempotencyKey: "events-mapping-subscription-publish",
    });
    await harness.service.deactivate(context, {
      resource: "apiVersion",
      tenantId,
      id: version.id,
      idempotencyKey: "events-mapping-version-deactivate",
    });
    await harness.service.deactivate(context, {
      resource: "applicationEnvironment",
      tenantId,
      id: environment.id,
      idempotencyKey: "events-mapping-environment-deactivate",
    });
    const belowThreshold = await harness.service.recordUsage(context, {
      tenantId,
      subscriptionId: subscription.id,
      metric: "orders:read",
      quantity: 1,
      idempotencyKey: "events-mapping-usage-low",
    });
    expect(belowThreshold.quantity).toBe(1);
    await harness.service.recordUsage(context, {
      tenantId,
      subscriptionId: subscription.id,
      metric: "orders:read",
      quantity: 25,
      idempotencyKey: "events-mapping-usage-high",
    });

    const eventTypes = (await harness.outbox.list({ tenantId, limit: 100 })).items
      .map((item) => item.eventType);
    expect(eventTypes).toEqual([
      "tenant.created",
      "tenant.status_changed",
      "developer_organization.created",
      "developer_organization.status_changed",
      "application.created",
      "application.status_changed",
      "client.created",
      "client.status_changed",
      "client.created",
      "client.status_changed",
      "api_product.created",
      "api_product.published",
      "api_version.created",
      "api_version.published",
      "credential.created",
      "credential.status_changed",
      "credential.status_changed",
      "subscription.created",
      "subscription.status_changed",
      "api_version.deprecated",
      "client.status_changed",
      "usage.threshold_reached",
    ]);
    expect(
      (await harness.outbox.list({ tenantId, limit: 100 })).items
        .filter((item) => item.eventType === "credential.status_changed")
        .map((item) => (item.data as Record<string, unknown>).action),
    ).toEqual(["rotated", "revoked"]);
    const rotationEvent = (await harness.outbox.list({
      tenantId,
      eventType: "credential.status_changed",
    })).items[0];
    expect(rotationEvent.data).toMatchObject({
      action: "rotated",
      previousId: issued.credential.id,
    });
    const issuedEvent = (await harness.outbox.list({
      tenantId,
      eventType: "credential.created",
    })).items[0];
    expect(issuedEvent).toMatchObject({
      resourceType: "credential",
      resourceStatus: "active",
      resourceVersion: 1,
    });
    const usage = (await harness.outbox.list({
      tenantId,
      eventType: "usage.threshold_reached",
    })).items[0];
    expect(usage.data).toMatchObject({
      metric: "orders:read",
      quantity: 25,
      threshold: 10,
    });
    expect(usage.resourceType).toBe("subscription");
    expect(
      usage.data as unknown as Record<string, unknown>,
    ).not.toHaveProperty("idempotencyKey");
    expect(harness.requests).toHaveLength(eventTypes.length - seededEventCount);
  });

  it("emits the catalog event for every core write and lifecycle action", async () => {
    const harness = await createHarness({ usageEventThresholds: { "orders:read": 5 } });
    const tenantId = "tenant-events-core-writes";
    const { applicationId, environmentId } = await seedPublishedApplication(
      harness,
      tenantId,
    );
    const context = harness.context(tenantId);
    const product = await harness.service.createApiProduct(context, {
      tenantId,
      name: "Core writes API",
      scopes: ["orders:read"],
      idempotencyKey: "core-writes-product",
    });
    await harness.service.publish(context, {
      resource: "apiProduct",
      tenantId,
      id: product.id,
      idempotencyKey: "core-writes-product-publish",
    });
    const version = await harness.service.createApiVersion(context, {
      tenantId,
      productId: product.id,
      apiVersion: "2.0.0",
      scopes: ["orders:read"],
      idempotencyKey: "core-writes-version",
    });
    await harness.service.publish(context, {
      resource: "apiVersion",
      tenantId,
      id: version.id,
      idempotencyKey: "core-writes-version-publish",
    });
    const subscription = await harness.service.createSubscription(context, {
      tenantId,
      applicationId,
      productId: product.id,
      apiVersionId: version.id,
      name: "Core writes subscription",
      scopes: ["orders:read"],
      idempotencyKey: "core-writes-subscription",
    });
    await harness.service.publish(context, {
      resource: "subscription",
      tenantId,
      id: subscription.id,
      idempotencyKey: "core-writes-subscription-publish",
    });
    const issued = await harness.service.issueCredential(context, {
      tenantId,
      applicationId,
      environmentId,
      name: "Core writes credential",
      scopes: ["orders:read"],
      idempotencyKey: "core-writes-credential",
    });
    const grant = await harness.service.grantScopes(context, {
      tenantId,
      credentialId: issued.credential.id,
      productId: product.id,
      apiVersionId: version.id,
      scopes: ["orders:read"],
      idempotencyKey: "core-writes-grant",
    });
    await harness.service.revokeScopeGrant(context, {
      tenantId,
      scopeGrantId: grant.id,
      idempotencyKey: "core-writes-grant-revoke",
    });
    await harness.service.recordUsage(context, {
      tenantId,
      subscriptionId: subscription.id,
      metric: "orders:read",
      quantity: 9,
      idempotencyKey: "core-writes-usage",
    });
    await harness.service.deactivate(context, {
      resource: "apiVersion",
      tenantId,
      id: version.id,
      idempotencyKey: "core-writes-version-deactivate",
    });
    await harness.service.archive(context, {
      resource: "apiVersion",
      tenantId,
      id: version.id,
      idempotencyKey: "core-writes-version-archive",
    });
    await harness.service.deactivate(context, {
      resource: "apiProduct",
      tenantId,
      id: product.id,
      idempotencyKey: "core-writes-product-deactivate",
    });
    await harness.service.archive(context, {
      resource: "apiProduct",
      tenantId,
      id: product.id,
      idempotencyKey: "core-writes-product-archive",
    });

    const items = (await harness.outbox.list({ tenantId, limit: 100 })).items;
    expect(items.map((item) => item.eventType)).toEqual([
      "tenant.created",
      "tenant.status_changed",
      "developer_organization.created",
      "developer_organization.status_changed",
      "application.created",
      "application.status_changed",
      "client.created",
      "client.status_changed",
      "api_product.created",
      "api_product.published",
      "api_version.created",
      "api_version.published",
      "subscription.created",
      "subscription.status_changed",
      "credential.created",
      "scope_grant.created",
      "scope_grant.status_changed",
      "usage.threshold_reached",
      "api_version.deprecated",
      "api_version.status_changed",
      "api_product.deprecated",
      "api_product.status_changed",
    ]);
    const byType = new Map(items.map((item) => [item.eventType, item]));
    expect(byType.get("api_product.created")).toMatchObject({
      resourceType: "apiProduct",
      resourceId: product.id,
      resourceStatus: "draft",
      resourceVersion: 1,
    });
    expect(byType.get("api_product.published")).toMatchObject({
      resourceType: "apiProduct",
      resourceStatus: "published",
    });
    expect(byType.get("api_version.deprecated")).toMatchObject({
      resourceType: "apiVersion",
      resourceStatus: "disabled",
      data: { action: "disabled", trigger: "disable", fromStatus: "published" },
    });
    expect(byType.get("api_version.status_changed")).toMatchObject({
      resourceType: "apiVersion",
      resourceStatus: "archived",
      data: { action: "archived", trigger: "archive" },
    });
    expect(byType.get("scope_grant.created")).toMatchObject({
      resourceType: "scopeGrant",
      resourceStatus: "active",
      data: { productId: product.id, apiVersionId: version.id },
    });
    expect(byType.get("scope_grant.status_changed")).toMatchObject({
      resourceType: "scopeGrant",
      resourceStatus: "revoked",
      data: { action: "revoked" },
    });
    expect(byType.get("subscription.created")).toMatchObject({
      resourceType: "subscription",
      resourceStatus: "draft",
      data: { productId: product.id, apiVersionId: version.id },
    });
  });

  it("does not emit events for reads, settled writes, or non core operations", async () => {
    const harness = await createHarness();
    const tenantId = "tenant-events-non-core";
    const { applicationId, environmentId } = await seedPublishedApplication(
      harness,
      tenantId,
    );
    await createWebhook(harness, {
      tenantId,
      applicationId,
      environmentId,
      events: [...OPEN_PLATFORM_DOMAIN_EVENT_TYPES],
      key: "non-core-webhook",
    });
    const context = harness.context(tenantId);
    const settled = (await harness.outbox.list({ tenantId, limit: 100 })).items.length;
    const product = await harness.service.createApiProduct(context, {
      tenantId,
      name: "Non core API",
      scopes: ["orders:read"],
      idempotencyKey: "non-core-product",
    });
    await harness.service.getApiProduct(context, { tenantId, id: product.id });
    await harness.service.listApiProducts(context, { tenantId });
    await harness.service.getApplication(context, { tenantId, id: applicationId });
    await harness.service.listSubscriptions(context, { tenantId });
    const issued = await harness.service.issueCredential(context, {
      tenantId,
      applicationId,
      environmentId,
      name: "Non core credential",
      scopes: ["orders:read"],
      idempotencyKey: "non-core-credential",
    });
    await expect(
      harness.service.verifyCredentialSecret(context, {
        tenantId,
        credentialId: issued.credential.id,
        secret: "invalid-secret-value",
      }),
    ).resolves.toBe(false);
    await harness.service.publish(context, {
      resource: "apiProduct",
      tenantId,
      id: product.id,
      idempotencyKey: "non-core-product-publish",
    });
    const grant = await harness.service.grantScopes(context, {
      tenantId,
      credentialId: issued.credential.id,
      productId: product.id,
      scopes: ["orders:read"],
      idempotencyKey: "non-core-grant",
    });
    await harness.service.grantScopes(harness.context(tenantId), {
      tenantId,
      credentialId: issued.credential.id,
      productId: product.id,
      scopes: ["orders:read"],
      idempotencyKey: "non-core-grant-repeat",
    });
    await expect(
      harness.service.authorizeScopes(context, {
        tenantId,
        credentialId: issued.credential.id,
        productId: product.id,
        scopes: ["orders:read"],
      }),
    ).resolves.toMatchObject({ valid: true, scopeGrantId: grant.id });
    await expect(
      harness.service.recordUsage(context, {
        tenantId,
        subscriptionId: "subscription_00000000-0000-4000-8000-000000000000",
        metric: "orders:read",
        quantity: 100,
        idempotencyKey: "non-core-usage",
      }),
    ).rejects.toMatchObject({ code: OPEN_PLATFORM_ERROR_CODES.RESOURCE_NOT_FOUND });
    const subscription = await harness.service.createSubscription(context, {
      tenantId,
      applicationId,
      productId: product.id,
      name: "Non core subscription",
      scopes: ["orders:read"],
      idempotencyKey: "non-core-subscription",
    });
    await harness.service.publish(context, {
      resource: "subscription",
      tenantId,
      id: subscription.id,
      idempotencyKey: "non-core-subscription-publish",
    });
    await harness.service.recordUsage(context, {
      tenantId,
      subscriptionId: subscription.id,
      metric: "orders:read",
      quantity: 1,
      idempotencyKey: "non-core-usage-low",
    });
    const emitted = (await harness.outbox.list({ tenantId, limit: 100 })).items
      .slice(settled)
      .map((item) => item.eventType);
    expect(emitted).toEqual([
      "api_product.created",
      "credential.created",
      "api_product.published",
      "scope_grant.created",
      "subscription.created",
      "subscription.status_changed",
    ]);
    expect(harness.requests).toHaveLength(emitted.length);
  });

  it("keeps credential and grant secrets out of event data and webhook bodies", async () => {
    const harness = await createHarness();
    const tenantId = "tenant-events-sensitive";
    const { applicationId, environmentId } = await seedPublishedApplication(
      harness,
      tenantId,
    );
    await createWebhook(harness, {
      tenantId,
      applicationId,
      environmentId,
      events: [...OPEN_PLATFORM_DOMAIN_EVENT_TYPES],
      key: "events-sensitive-webhook",
    });
    const context = harness.context(tenantId);
    const product = await harness.service.createApiProduct(context, {
      tenantId,
      name: "Sensitive API",
      scopes: ["orders:read"],
      idempotencyKey: "sensitive-product",
    });
    await harness.service.publish(context, {
      resource: "apiProduct",
      tenantId,
      id: product.id,
      idempotencyKey: "sensitive-product-publish",
    });
    const issued = await harness.service.issueCredential(context, {
      tenantId,
      applicationId,
      environmentId,
      name: "Sensitive credential",
      scopes: ["orders:read"],
      idempotencyKey: "sensitive-credential",
    });
    const secret = issued.secret;
    expect(typeof secret).toBe("string");
    const rotated = await harness.service.rotateCredential(context, {
      tenantId,
      credentialId: issued.credential.id,
      idempotencyKey: "sensitive-credential-rotate",
    });
    await harness.service.grantScopes(context, {
      tenantId,
      credentialId: rotated.credential.id,
      productId: product.id,
      scopes: ["orders:read"],
      idempotencyKey: "sensitive-grant",
    });
    await harness.service.revokeCredential(context, {
      tenantId,
      credentialId: rotated.credential.id,
      idempotencyKey: "sensitive-credential-revoke",
    });

    const allowed = new Set([
      "action",
      "trigger",
      "fromStatus",
      "toStatus",
      "applicationId",
      "environmentId",
      "productId",
      "apiVersionId",
      "organizationId",
      "previousId",
      "metric",
      "quantity",
      "threshold",
    ]);
    const items = (await harness.outbox.list({ tenantId, limit: 100 })).items;
    expect(items.length).toBeGreaterThan(8);
    for (const item of items) {
      expect(containsOpenPlatformSensitiveEventData(item.data)).toBe(false);
      for (const key of Object.keys(item.data)) {
        expect(allowed.has(key)).toBe(true);
      }
      expect(JSON.stringify(item)).not.toMatch(
        /secret|password|passwd|token|authorization|private[-_ ]?key|email|digest|fingerprint/iu,
      );
    }
    const subscription = await harness.service.createSubscription(context, {
      tenantId,
      applicationId,
      productId: product.id,
      name: "Sensitive subscription",
      scopes: ["orders:read"],
      idempotencyKey: "sensitive-subscription",
    });
    await harness.service.publish(context, {
      resource: "subscription",
      tenantId,
      id: subscription.id,
      idempotencyKey: "sensitive-subscription-publish",
    });
    expect(harness.requests.length).toBeGreaterThan(0);
    for (const request of harness.requests) {
      expect(request.body).not.toContain(secret);
      expect(request.body).not.toMatch(
        /secret|password|passwd|token|authorization|private[-_ ]?key/iu,
      );
    }
  });

  it("refuses a webhook subscription and a dispatch for an unknown event", async () => {
    const harness = await createHarness();
    const tenantId = "tenant-events-unknown";
    const { applicationId, environmentId } = await seedPublishedApplication(
      harness,
      tenantId,
    );
    await expect(
      harness.service.createWebhook(harness.context(tenantId), {
        tenantId,
        applicationId,
        environmentId,
        name: "Unknown event webhook",
        endpointUrl: "https://client.example.test/hooks/unknown",
        events: ["application.deleted" as "application.status_changed"],
        idempotencyKey: "unknown-event-webhook",
      }),
    ).rejects.toMatchObject({ code: OPEN_PLATFORM_ERROR_CODES.VALIDATION_ERROR });
    const webhook = await createWebhook(harness, {
      tenantId,
      applicationId,
      environmentId,
      events: ["application.status_changed"],
      key: "unknown-event-webhook-valid",
    });
    await expect(
      harness.service.dispatchWebhookEvent(harness.context(tenantId), {
        tenantId,
        webhookId: webhook.id,
        idempotencyKey: "unknown-event-dispatch",
        event: {
          tenantId,
          eventType: "application.deleted" as "application.status_changed",
        },
      }),
    ).rejects.toMatchObject({ code: OPEN_PLATFORM_ERROR_CODES.VALIDATION_ERROR });
    expect(harness.requests).toHaveLength(0);
  });

  it("does not duplicate outbox records when a core write is replayed", async () => {
    const harness = await createHarness();
    const tenantId = "tenant-events-idempotent";
    const { applicationId, environmentId } = await seedPublishedApplication(
      harness,
      tenantId,
    );
    await createWebhook(harness, {
      tenantId,
      applicationId,
      environmentId,
      events: [...OPEN_PLATFORM_DOMAIN_EVENT_TYPES],
      key: "idempotent-webhook",
    });
    const context = harness.context(tenantId);
    const before = (await harness.outbox.list({ tenantId, limit: 100 })).items.length;
    const created = await harness.service.createApiProduct(context, {
      tenantId,
      name: "Idempotent API",
      scopes: ["orders:read"],
      idempotencyKey: "idempotent-product",
    });
    const afterCreate = (await harness.outbox.list({ tenantId, limit: 100 })).items;
    expect(afterCreate).toHaveLength(before + 1);
    const issued = await harness.service.issueCredential(context, {
      tenantId,
      applicationId,
      environmentId,
      name: "Idempotent credential",
      scopes: ["orders:read"],
      idempotencyKey: "idempotent-credential",
    });
    await harness.service.publish(context, {
      resource: "apiProduct",
      tenantId,
      id: created.id,
      idempotencyKey: "idempotent-product-publish",
    });
    const grant = await harness.service.grantScopes(context, {
      tenantId,
      credentialId: issued.credential.id,
      productId: created.id,
      scopes: ["orders:read"],
      idempotencyKey: "idempotent-grant",
    });
    const afterWrites = (await harness.outbox.list({ tenantId, limit: 100 })).items;
    const delivered = harness.requests.length;

    const replayProduct = await harness.service.createApiProduct(context, {
      tenantId,
      name: "Idempotent API",
      scopes: ["orders:read"],
      idempotencyKey: "idempotent-product",
    });
    const replayCredential = await harness.service.issueCredential(context, {
      tenantId,
      applicationId,
      environmentId,
      name: "Idempotent credential",
      scopes: ["orders:read"],
      idempotencyKey: "idempotent-credential",
    });
    const replayGrant = await harness.service.grantScopes(context, {
      tenantId,
      credentialId: issued.credential.id,
      productId: created.id,
      scopes: ["orders:read"],
      idempotencyKey: "idempotent-grant",
    });
    expect(replayProduct.id).toBe(created.id);
    expect(replayCredential.replayed).toBe(true);
    expect(replayGrant.id).toBe(grant.id);
    const afterReplay = (await harness.outbox.list({ tenantId, limit: 100 })).items;
    expect(afterReplay).toHaveLength(afterWrites.length);
    expect(afterReplay.map((item) => item.eventId)).toEqual(
      afterWrites.map((item) => item.eventId),
    );
    expect(harness.requests).toHaveLength(delivered);
  });

  it("does not deliver to other tenants or to webhooks that do not subscribe", async () => {
    const harness = await createHarness();
    const tenantId = "tenant-events-isolation-a";
    const otherTenantId = "tenant-events-isolation-b";
    const { applicationId, environmentId } = await seedPublishedApplication(
      harness,
      tenantId,
    );
    const other = await seedPublishedApplication(harness, otherTenantId);
    await createWebhook(harness, {
      tenantId,
      applicationId,
      environmentId,
      events: ["api_product.published"],
      key: "events-isolation-unsubscribed",
    });
    const foreign = await createWebhook(harness, {
      tenantId: otherTenantId,
      applicationId: other.applicationId,
      environmentId: other.environmentId,
      events: ["application.status_changed"],
      key: "events-isolation-foreign",
    });
    expect(foreign.id).not.toBe("");

    await harness.service.deactivate(harness.context(tenantId), {
      resource: "application",
      tenantId,
      id: applicationId,
      idempotencyKey: "events-isolation-deactivate",
    });

    expect(harness.requests).toHaveLength(0);
    for (const tenant of [tenantId, otherTenantId]) {
      const page = await harness.service.listWebhookDeliveries(
        harness.context(tenant),
        { tenantId: tenant, limit: 10 },
      );
      expect(page.items).toHaveLength(0);
    }
    const own = (await harness.outbox.list({ tenantId })).items;
    expect(own.map((item) => item.eventType)).toEqual([
      "tenant.created",
      "tenant.status_changed",
      "developer_organization.created",
      "developer_organization.status_changed",
      "application.created",
      "application.status_changed",
      "client.created",
      "client.status_changed",
      "application.status_changed",
    ]);
    expect(own.every((item) => item.status === "published")).toBe(true);
    const otherEvents = (await harness.outbox.list({ tenantId: otherTenantId })).items;
    expect(otherEvents).toHaveLength(8);
    expect(otherEvents.every((item) => item.tenantId === otherTenantId)).toBe(true);
  });

  it("rejects forged domain events at the webhook dispatch boundary", async () => {
    const harness = await createHarness();
    const context = harness.context("tenant-events-forged");
    await expect(
      harness.service.webhooks.dispatchDomainEvent({
        eventId: "open_platform_event_forged",
        tenantId: "tenant-events-forged",
        eventType: "application.status_changed",
        resourceType: "application",
        resourceId: "app-forged",
        occurredAt: timestamp,
        schemaVersion: "open-platform.domain-event.v1",
        data: {},
        status: "pending",
        sequence: 1,
        attempt: 0,
        maxAttempts: 5,
        createdAt: timestamp,
        updatedAt: timestamp,
      } as unknown as OpenPlatformOutboxRecord),
    ).rejects.toMatchObject({ code: OPEN_PLATFORM_ERROR_CODES.FORBIDDEN });
    void context;
  });

  it("does not re-deliver on idempotent replay or a repeated publish", async () => {
    const harness = await createHarness();
    const tenantId = "tenant-events-replay";
    const { applicationId, environmentId } = await seedPublishedApplication(
      harness,
      tenantId,
    );
    const webhook = await createWebhook(harness, {
      tenantId,
      applicationId,
      environmentId,
      events: ["application.status_changed"],
      key: "events-replay-webhook",
    });
    const context = harness.context(tenantId);
    const command = {
      resource: "application" as const,
      tenantId,
      id: applicationId,
      idempotencyKey: "events-replay-deactivate",
    };
    await harness.service.deactivate(context, command);
    expect(harness.requests).toHaveLength(1);
    const firstDeliveries = await harness.service.listWebhookDeliveries(context, {
      tenantId,
      limit: 10,
    });
    expect(firstDeliveries.items).toHaveLength(1);

    const replay = await harness.service.deactivate(context, command);
    expect(replay.status).toBe("disabled");
    expect(harness.requests).toHaveLength(1);
    expect(
      (await harness.outbox.list({
        tenantId,
        eventType: "application.status_changed",
        limit: 50,
      })).items.map((item) => item.resourceStatus),
    ).toEqual(["published", "disabled"]);

    await expect(
      harness.service.publish(harness.context(tenantId), {
        resource: "application",
        tenantId,
        id: applicationId,
        idempotencyKey: "events-republish",
      }),
    ).resolves.toMatchObject({ status: "published" });
    expect(harness.requests).toHaveLength(2);
    expect(
      (await harness.outbox.list({
        tenantId,
        eventType: "application.status_changed",
        limit: 50,
      })).items,
    ).toHaveLength(3);

    const deliveries = await harness.service.listWebhookDeliveries(context, {
      tenantId,
      limit: 10,
    });
    const replayed = await harness.service.replayWebhookDelivery(
      harness.context(tenantId),
      {
        tenantId,
        webhookId: webhook.id,
        deliveryId: deliveries.items.at(-1)?.id ?? "",
        idempotencyKey: "events-replay-delivery",
      },
    );
    expect(replayed.duplicate).toBe(false);
    expect(harness.requests).toHaveLength(3);
    expect(
      (await harness.outbox.list({
        tenantId,
        eventType: "application.status_changed",
        limit: 50,
      })).items,
    ).toHaveLength(3);
  });

  it("recovers a lost outbox append on the next idempotent replay without duplicating", async () => {
    const backing = new InMemoryOpenPlatformOutbox({ clock: () => now });
    let failures = 1;
    const flaky: OpenPlatformOutboxPort = {
      readiness: backing.readiness,
      append: async (event) => {
        if (failures > 0 && (event.data as Record<string, unknown>)?.trigger === "disable") {
          failures -= 1;
          throw new Error("outbox unavailable");
        }
        return backing.append(event);
      },
      get: (tenantId, eventId) => backing.get(tenantId, eventId),
      list: (query) => backing.list(query),
      claim: (request) => backing.claim?.(request) ?? Promise.resolve({ claimed: false }),
      complete: (request) => backing.complete?.(request) ?? Promise.reject(new Error("unreachable")),
      fail: (request) => backing.fail?.(request) ?? Promise.reject(new Error("unreachable")),
    };
    const harness = await createHarness({ outbox: flaky });
    const tenantId = "tenant-events-outbox-recovery";
    const { applicationId, environmentId } = await seedPublishedApplication(
      harness,
      tenantId,
    );
    await createWebhook(harness, {
      tenantId,
      applicationId,
      environmentId,
      events: ["application.status_changed"],
      key: "events-outbox-recovery-webhook",
    });
    const context = harness.context(tenantId);
    const command = {
      resource: "application" as const,
      tenantId,
      id: applicationId,
      idempotencyKey: "events-outbox-recovery-deactivate",
    };
    await harness.service.deactivate(context, command);
    const lost = (await backing.list({ tenantId, limit: 50 })).items.filter(
      (item) => item.resourceStatus === "disabled",
    );
    expect(lost).toHaveLength(0);
    expect(harness.requests).toHaveLength(0);

    await harness.service.deactivate(context, command);
    const recovered = (await backing.list({ tenantId, limit: 50 })).items.filter(
      (item) => item.resourceStatus === "disabled",
    );
    expect(recovered).toHaveLength(1);
    expect(recovered[0]).toMatchObject({ status: "published", attempt: 1 });
    expect(harness.requests).toHaveLength(1);

    await harness.service.deactivate(context, command);
    expect(
      (await backing.list({ tenantId, limit: 50 })).items.filter(
        (item) => item.resourceStatus === "disabled",
      ),
    ).toHaveLength(1);
    expect(harness.requests).toHaveLength(1);
  });

  it("dead letters a failing endpoint and keeps the domain write successful", async () => {
    let calls = 0;
    const harness = await createHarness({
      respond: () => {
        calls += 1;
        return { statusCode: 500, body: "server error secret=abc" };
      },
    });
    const tenantId = "tenant-events-failure";
    const { applicationId, environmentId } = await seedPublishedApplication(
      harness,
      tenantId,
    );
    await createWebhook(harness, {
      tenantId,
      applicationId,
      environmentId,
      events: ["application.status_changed"],
      key: "events-failure-webhook",
    });
    const deactivated = await harness.service.deactivate(
      harness.context(tenantId),
      {
        resource: "application",
        tenantId,
        id: applicationId,
        idempotencyKey: "events-failure-deactivate",
      },
    );
    expect(deactivated.status).toBe("disabled");
    expect(calls).toBe(5);
    const stored = (await harness.outbox.list({ tenantId, limit: 50 })).items.at(-1);
    expect(stored?.eventType).toBe("application.status_changed");
    expect(stored?.status).toBe("dead_lettered");
    expect(stored?.errorCode).toBe("EVENT_DELIVERY_DEAD_LETTERED");
    const deliveries = await harness.service.listWebhookDeliveries(
      harness.context(tenantId),
      { tenantId, limit: 10 },
    );
    expect(deliveries.items[0]).toMatchObject({
      status: "dead_lettered",
      attempt: 5,
    });
    expect(deliveries.items[0]?.errorCode).toBe("HTTP_500");
  });

  it("retries pending outbox events through the tenant scoped retry entry point", async () => {
    const flushed: { tenantId: string }[] = [];
    const outbox = new InMemoryOpenPlatformOutbox({ clock: () => now });
    const publisher: OpenPlatformEventPublisherPort = {
      readiness: { storage: "memory", distributed: false, ready: () => true },
      record: (event) => outbox.append(event),
      publish: async () => ({ eventId: "skipped", delivered: 0, deadLettered: false }),
      flush: async (query) => {
        flushed.push({ tenantId: query.tenantId });
        return [];
      },
    };
    const harness = await createHarness({ outbox, eventPublisher: publisher });
    const tenantId = "tenant-events-retry-entry";
    const { applicationId, environmentId } = await seedPublishedApplication(
      harness,
      tenantId,
    );
    await createWebhook(harness, {
      tenantId,
      applicationId,
      environmentId,
      events: ["application.status_changed"],
      key: "events-retry-entry-webhook",
    });
    await harness.service.deactivate(harness.context(tenantId), {
      resource: "application",
      tenantId,
      id: applicationId,
      idempotencyKey: "events-retry-entry-deactivate",
    });
    expect(harness.requests).toHaveLength(0);
    const pending = (await harness.outbox.list({ tenantId, limit: 50 })).items;
    expect(pending.every((item) => item.status === "pending")).toBe(true);

    expect(
      await harness.service.retryDomainEvents(harness.context(tenantId), {
        tenantId,
        eventType: "application.status_changed",
      }),
    ).toEqual([]);
    expect(flushed).toEqual([{ tenantId }]);

    await expect(
      harness.service.retryDomainEvents(
        createDevelopmentOpenPlatformRequestContext({
          tenantId: "tenant-events-retry-other",
          actorId: "actor-events",
          requestId: "request-other",
        }),
        { tenantId: "tenant-events-other" },
      ),
    ).rejects.toMatchObject({ code: OPEN_PLATFORM_ERROR_CODES.TENANT_MISMATCH });
  });
});

describe("open platform domain event fail closed wiring", () => {
  const productionAuthorization = {
    productionReady: true,
    authorize: () => true,
  };

  const persistentReady: OpenPlatformDependencyReadiness = Object.freeze({
    storage: "persistent" as const,
    distributed: true,
    ready: () => true,
  });

  const memoryReadiness: OpenPlatformDependencyReadiness = Object.freeze({
    storage: "memory" as const,
    distributed: false,
    ready: () => true,
  });

  function productionRepositories(): InMemoryOpenPlatformRepositories {
    return new InMemoryOpenPlatformRepositories();
  }

  it("refuses to construct a production service without a domain event outbox", () => {
    const repositories = productionRepositories();
    Object.defineProperty(repositories, "readiness", {
      value: persistentReady,
    });
    Object.defineProperty(repositories, "idempotency", {
      value: { readiness: persistentReady },
    });
    expect(() =>
      createOpenPlatformService({
        mode: "production",
        authorization: productionAuthorization,
        repositories,
        secretProvider: {
          readiness: persistentReady,
          issue: () => ({ secret: "s".repeat(40) }),
          revoke: () => undefined,
          compensate: () => undefined,
        },
        clock: () => now,
      }),
    ).toThrow(/domain event outbox/u);
  });

  it("refuses to construct a production service without a persistent publisher outbox", () => {
    const repositories = productionRepositories();
    Object.defineProperty(repositories, "readiness", { value: persistentReady });
    Object.defineProperty(repositories, "idempotency", {
      value: { readiness: persistentReady },
    });
    expect(() =>
      createOpenPlatformService({
        mode: "production",
        authorization: productionAuthorization,
        repositories,
        outbox: {
          readiness: memoryReadiness,
          append: async () => {
            throw new Error("unreachable");
          },
          get: async () => undefined,
          list: async () => ({ items: [], hasMore: false }),
        },
        secretProvider: {
          readiness: persistentReady,
          issue: () => ({ secret: "s".repeat(40) }),
          revoke: () => undefined,
          compensate: () => undefined,
        },
        clock: () => now,
      }),
    ).toThrow(/distributed domain event outbox/u);
  });

  it("fails production writes closed when the outbox readiness is not ready", async () => {
    const service = createOpenPlatformService({
      mode: "production",
      authorization: productionAuthorization,
      repositories: productionRepositories(),
      outbox: {
        readiness: { ...persistentReady, ready: () => false },
        append: async () => {
          throw new Error("append must not be reached");
        },
        get: async () => undefined,
        list: async () => ({ items: [], hasMore: false }),
      },
      eventPublisher: {
        readiness: persistentReady,
        record: async () => {
          throw new Error("record must not be reached");
        },
        publish: async () => ({ eventId: "unused", delivered: 0, deadLettered: false }),
      },
      secretProvider: {
        readiness: persistentReady,
        issue: () => ({ secret: "s".repeat(40) }),
        revoke: () => undefined,
        compensate: () => undefined,
      },
      allowInMemoryInProduction: true,
      clock: () => now,
    });
    const readiness = await service.isReady();
    expect(readiness.events).toBe(false);
    expect(readiness.ready).toBe(false);
    await expect(
      service.createTenant(
        createDevelopmentOpenPlatformRequestContextForProduction(),
        { tenantId: "tenant-fail-closed", name: "Tenant", idempotencyKey: "k1" },
      ),
    ).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.STORAGE_UNAVAILABLE,
    });
  });

  it("keeps the default in-memory outbox usable outside production", async () => {
    const service = createOpenPlatformService({
      mode: "development",
      authorization: createDevelopmentOpenPlatformAuthorization("all"),
      clock: () => now,
    });
    expect(service.outbox).toBeInstanceOf(InMemoryOpenPlatformOutbox);
    const readiness = await service.isReady();
    expect(readiness.events).toBe(true);
    expect(readiness.ready).toBe(true);
  });

  it("injects the outbox and publisher through the provider module", () => {
    const issuer = createOpenPlatformRequestContextIssuer({
      issuerId: "open-platform-domain-events-module",
      attestation: Object.freeze({ test: true }),
      clock: () => now,
    });
    const outbox = new InMemoryOpenPlatformOutbox({ clock: () => now });
    const publisher = new OpenPlatformEventPublisher({ outbox, clock: () => now });
    const dynamicModule = OpenPlatformProviderModule.forRoot({
      mode: "test",
      authorization: createDevelopmentOpenPlatformAuthorization("all"),
      contextIssuer: issuer,
      outbox,
      eventPublisher: publisher,
      clock: () => now,
    });
    const provided = new Map<unknown, unknown>();
    for (const provider of dynamicModule.providers ?? []) {
      if (typeof provider !== "object" || provider === null) continue;
      const candidate = provider as { provide?: unknown; useValue?: unknown };
      if (candidate.provide === undefined) continue;
      provided.set(candidate.provide, candidate.useValue);
    }
    expect(provided.get(OPEN_PLATFORM_OUTBOX)).toBe(outbox);
    expect(provided.get(OPEN_PLATFORM_EVENT_PUBLISHER)).toBe(publisher);
    expect(provided.get(OPEN_PLATFORM_SERVICE)).toBeInstanceOf(OpenPlatformService);
    expect(provided.get(OPEN_PLATFORM_AUTHORIZATION)).toBeDefined();
  });

  it("fails module startup when the domain event outbox is not ready", async () => {
    const { Test } = await import("@nestjs/testing");
    const issuer = createOpenPlatformRequestContextIssuer({
      issuerId: "open-platform-domain-events-readiness",
      attestation: Object.freeze({ test: true }),
      clock: () => now,
    });
    const moduleRef = await Test.createTestingModule({
      imports: [
        OpenPlatformProviderModule.forRoot({
          mode: "test",
          authorization: createDevelopmentOpenPlatformAuthorization("all"),
          contextIssuer: issuer,
          outbox: {
            readiness: { ...memoryReadiness, ready: () => false },
            append: async () => {
              throw new Error("append must not be reached");
            },
            get: async () => undefined,
            list: async () => ({ items: [], hasMore: false }),
          },
          clock: () => now,
        }),
      ],
    }).compile();
    let failure: unknown;
    try {
      await moduleRef.init();
    } catch (error) {
      failure = error;
    }
    expect((failure as Error).message).toMatch(/domain event outbox is not ready/u);
  });
});

function createDevelopmentOpenPlatformRequestContextForProduction(): OpenPlatformRequestContext {
  const issuer = createOpenPlatformRequestContextIssuer({
    issuerId: "open-platform-domain-events-production",
    attestation: Object.freeze({ test: true }),
    clock: () => now,
  });
  return issuer.issueAuthenticated({
    tenantId: "tenant-fail-closed",
    actorId: "actor-production",
    requestId: "request-production",
  });
}

describe("open platform SQL domain event outbox", () => {
  type QueryResult = { rows?: unknown[]; rowCount?: number };
  type Responder = (text: string, values: unknown[]) => unknown | Promise<unknown>;
  type TestAdapter = DatabaseAdapter & { calls: { text: string; values: unknown[] }[] };

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

  function outboxRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      id: "open_platform_event_1",
      tenantId: "tenant-a",
      eventType: "application.status_changed",
      resourceType: "application",
      resourceId: "app-1",
      resourceVersion: 2,
      resourceStatus: "disabled",
      actorId: "actor-a",
      requestId: "request-a",
      occurredAt: timestamp,
      schemaVersion: "open-platform.domain-event.v1",
      data: { action: "disabled" },
      status: "pending",
      sequence: 1,
      attempt: 0,
      maxAttempts: 5,
      nextAttemptAt: timestamp,
      publishedAt: null,
      errorCode: null,
      leaseId: null,
      leaseExpiresAt: null,
      createdAt: timestamp,
      updatedAt: timestamp,
      ...overrides,
    };
  }

  it("migrates an append-only outbox with tenant isolation and a claim lease", () => {
    const sql = createOpenPlatformDomainEventMigrationSql({ mode: "shared", tenantId: "tenant-a" });
    expect(sql).toContain(`CREATE TABLE IF NOT EXISTS "${OPEN_PLATFORM_SQL_TABLES.domainEvents}"`);
    expect(sql).toContain("FORCE ROW LEVEL SECURITY");
    expect(sql).toContain("gb_open_domain_event_immutable");
    expect(sql).toContain("gb_open_domain_event_payload_guard");
    expect(getOpenPlatformDomainEventMigrationDefinition({ tenantId: "tenant-a" }).version).toBe(4);
  });

  it("claims atomically and refuses tenants outside the repository scope", async () => {
    const row = outboxRow();
    const executor = adapter((text, values) => {
      if (text.startsWith(`UPDATE "${OPEN_PLATFORM_SQL_TABLES.domainEvents}"`)) {
        const claimable = row.status === "pending" || row.status === "failed" ||
          (row.status === "delivering" && String(row.leaseExpiresAt) <= String(values[5]));
        if (row.tenantId !== values[0] || row.id !== values[1] || !claimable) {
          return { rowCount: 0, rows: [] };
        }
        Object.assign(row, {
          status: "delivering",
          attempt: Math.max(Number(row.attempt), Number(values[2])),
          leaseId: values[3],
          leaseExpiresAt: values[4],
          updatedAt: values[5],
        });
        return { rowCount: 1, rows: [row] };
      }
      return { rows: [] };
    });
    const repository = new SqlDomainEventOutboxRepository(
      new OpenPlatformSqlRuntime({ adapter: executor, tenantId: "tenant-a" }),
    );
    expect(await repository.isReady()).toBe(true);
    expect(repository.readiness).toMatchObject({
      storage: "persistent",
      distributed: true,
    });
    const claimed = await repository.claim({
      tenantId: "tenant-a",
      eventId: "open_platform_event_1",
      attempt: 1,
      leaseId: "lease-first",
      now: timestamp,
      leaseExpiresAt: "2030-01-01T00:00:30.000Z",
    });
    expect(claimed.claimed).toBe(true);
    expect(claimed.record).toMatchObject({
      eventId: "open_platform_event_1",
      status: "delivering",
      attempt: 1,
      leaseId: "lease-first",
      data: { action: "disabled" },
    });
    const statement = executor.calls.at(-1);
    expect(statement?.text).toContain(`"tenant_id" = $1 AND "event_id" = $2`);
    expect(statement?.text).toContain(`"attempt" < "max_attempts"`);
    expect(statement?.values).toEqual([
      "tenant-a",
      "open_platform_event_1",
      1,
      "lease-first",
      "2030-01-01T00:00:30.000Z",
      timestamp,
    ]);
    const contested = await repository.claim({
      tenantId: "tenant-a",
      eventId: "open_platform_event_1",
      attempt: 1,
      leaseId: "lease-second",
      now: "2030-01-01T00:00:05.000Z",
      leaseExpiresAt: "2030-01-01T00:00:35.000Z",
    });
    expect(contested.claimed).toBe(false);
    const otherTenant = await repository.claim({
      tenantId: "tenant-b",
      eventId: "open_platform_event_1",
      attempt: 1,
      leaseId: "lease-third",
      now: timestamp,
      leaseExpiresAt: "2030-01-01T00:00:30.000Z",
    });
    expect(otherTenant.claimed).toBe(false);
    expect(await repository.get("tenant-b", "open_platform_event_1")).toBeUndefined();
    expect((await repository.list({ tenantId: "tenant-b" })).items).toEqual([]);
  });
});
