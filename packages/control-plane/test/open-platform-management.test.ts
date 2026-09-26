import { describe, expect, it } from "vitest";
import {
  InMemoryOpenPlatformAuditEventStore,
  InMemoryOpenPlatformWebhookDeliveryRepository,
  InMemoryOpenPlatformWebhookRepository,
  InMemoryOpenPlatformWebhookSecretProvider,
  OpenPlatformService,
  OpenPlatformWebhookService,
  OpenPlatformWebhookEndpointRejectedError,
  assertOpenPlatformWebhookEndpointSync,
  createDevelopmentOpenPlatformAuthorization,
  createDevelopmentOpenPlatformRequestContext,
  createOpenPlatformRequestContextIssuer,
  signOpenPlatformWebhookPayload,
  verifyOpenPlatformWebhookSignature,
  type OpenPlatformRequestContext,
} from "../src/open-platform/index.js";

const now = new Date("2030-01-01T00:00:00.000Z");

function context(tenantId: string, actorId = "actor-management"): OpenPlatformRequestContext {
  return createDevelopmentOpenPlatformRequestContext({
    tenantId,
    actorId,
    requestId: `request-${tenantId}-${actorId}`,
  });
}

function event(eventId: string, eventType = "application.status_changed") {
  return {
    eventId,
    eventType,
    tenantId: "tenant-webhook",
    occurredAt: now.toISOString(),
    resource: { type: "application", id: "app-1", version: 2, status: "published" },
    data: { status: "published" },
  };
}

describe("open platform management audit", () => {
  it("keeps a stable tenant-local hash chain and cursor pages", async () => {
    const store = new InMemoryOpenPlatformAuditEventStore({ clock: () => now });
    const first = await store.append({
      tenantId: "tenant-audit-a",
      action: "application.create",
      outcome: "success",
      actor: { type: "user", id: "actor-a" },
      target: { type: "application", id: "app-a" },
      requestId: "request-a",
      metadata: { z: 1, a: "value" },
    });
    const second = await store.append({
      tenantId: "tenant-audit-a",
      action: "application.update",
      outcome: "denied",
      actor: { type: "user", id: "actor-a" },
      target: { type: "application", id: "app-a" },
      requestId: "request-b",
    });
    const other = await store.append({
      tenantId: "tenant-audit-b",
      action: "application.create",
      outcome: "success",
      actor: { type: "user", id: "actor-b" },
      target: { type: "application", id: "app-b" },
    });

    expect(first.sequence).toBe(1);
    expect(first.occurredAt).toBe(now.toISOString());
    expect(first.previousHash).toBeUndefined();
    expect(first.eventHash).toMatch(/^[a-f0-9]{64}$/u);
    expect(second.sequence).toBe(2);
    expect(second.previousHash).toBe(first.eventHash);
    expect(other.sequence).toBe(1);
    expect(await store.verifyChain("tenant-audit-a")).toBe(true);
    expect(await store.verifyChain("tenant-audit-b")).toBe(true);

    const firstPage = await store.list({ tenantId: "tenant-audit-a", limit: 1 });
    expect(firstPage.items).toHaveLength(1);
    expect(firstPage.hasMore).toBe(true);
    const secondPage = await store.list({ tenantId: "tenant-audit-a", cursor: firstPage.nextCursor });
    expect(secondPage.items.map((item) => item.id)).toEqual([second.id]);
    await expect(store.list({ tenantId: "tenant-audit-a", cursor: firstPage.nextCursor, targetId: "missing" })).resolves.toMatchObject({ items: [] });
  });

  it("audits denied webhook management writes through the outer service", async () => {
    const audit = new InMemoryOpenPlatformAuditEventStore({ clock: () => now });
    const service = new OpenPlatformService({
      mode: "test",
      authorization: {
        productionReady: false,
        authorize: ({ context: authorizedContext }) => authorizedContext.actorId !== "denied-webhook-actor",
      },
      audit,
      clock: () => now,
    });
    await expect(service.createWebhook(context("tenant-webhook-denied", "denied-webhook-actor"), {
      tenantId: "tenant-webhook-denied",
      applicationId: "app-1",
      environmentId: "env-1",
      name: "Denied",
      endpointUrl: "https://client.example.test/denied",
      events: ["application.status_changed"],
      idempotencyKey: "denied-webhook",
    })).rejects.toMatchObject({ code: "OPEN_PLATFORM_FORBIDDEN" });
    expect(audit.snapshot("tenant-webhook-denied")).toMatchObject([{ outcome: "denied" }]);
  });

  it("records successful and denied management writes through the service port", async () => {
    const store = new InMemoryOpenPlatformAuditEventStore({ clock: () => now });
    const service = new OpenPlatformService({
      mode: "test",
      authorization: {
        productionReady: false,
        authorize: ({ context: authorizedContext }) => authorizedContext.actorId !== "denied-actor",
      },
      audit: store,
      clock: () => now,
    });
    await service.createTenant(context("tenant-audit-service"), {
      tenantId: "tenant-audit-service",
      name: "Audit tenant",
      idempotencyKey: "audit-create",
    });
    await expect(service.createTenant(context("tenant-audit-service", "denied-actor"), {
      tenantId: "tenant-audit-service",
      name: "Denied tenant",
      idempotencyKey: "audit-denied",
    })).rejects.toMatchObject({ code: "OPEN_PLATFORM_FORBIDDEN" });
    const events = store.snapshot("tenant-audit-service");
    expect(events.some((event) => event.outcome === "success")).toBe(true);
    expect(events.length).toBeGreaterThanOrEqual(1);
  });
});

describe("open platform webhook delivery", () => {
  it("signs timestamp, body, and secret version and rejects tampering", () => {
    const secret = "webhook-secret-01234567890123456789";
    const timestamp = now.toISOString();
    const body = JSON.stringify({ event_id: "event-1" });
    const signature = signOpenPlatformWebhookPayload({
      timestamp,
      body,
      secret,
      secretVersion: 2,
    });
    expect(signature).toMatch(/^v1=[a-f0-9]{64}$/u);
    expect(verifyOpenPlatformWebhookSignature({
      timestamp,
      body,
      secret,
      secretVersion: 2,
      signature,
      now,
    })).toBe(true);
    expect(verifyOpenPlatformWebhookSignature({
      timestamp,
      body: `${body} `,
      secret,
      secretVersion: 2,
      signature,
      now,
    })).toBe(false);
    expect(verifyOpenPlatformWebhookSignature({
      timestamp,
      body,
      secret,
      secretVersion: 1,
      signature,
      now,
    })).toBe(false);
    expect(verifyOpenPlatformWebhookSignature({
      timestamp: new Date(now.getTime() + 1000).toISOString(),
      body,
      secret,
      secretVersion: 2,
      signature,
      now,
      toleranceSeconds: 0,
    })).toBe(false);
  });

  it("supports lifecycle, rotation, retries, dead letters, and event idempotency", async () => {
    const requests: Array<{ body: string; headers: Record<string, string>; url: string }> = [];
    let calls = 0;
    const service = new OpenPlatformWebhookService({
      authorization: createDevelopmentOpenPlatformAuthorization("all"),
      webhooks: new InMemoryOpenPlatformWebhookRepository(),
      deliveries: new InMemoryOpenPlatformWebhookDeliveryRepository(),
      secretProvider: new InMemoryOpenPlatformWebhookSecretProvider(),
      maxAttempts: 3,
      baseDelayMs: 0,
      maxDelayMs: 0,
      sleep: async () => undefined,
      clock: () => now,
      transport: {
        send: async (request) => {
          calls += 1;
          requests.push({ body: request.body, headers: { ...request.headers }, url: request.url });
          return { statusCode: calls < 3 ? 500 : 204 };
        },
      },
    });
    const tenantContext = context("tenant-webhook");
    const created = await service.createWebhook(tenantContext, {
      tenantId: "tenant-webhook",
      applicationId: "app-1",
      environmentId: "env-1",
      name: "Events",
      endpointUrl: "https://client.example.test/webhook",
      events: ["application.status_changed"],
      idempotencyKey: "webhook-create",
    });
    expect(created.secretVersion).toBe(1);
    const rotated = await service.rotateWebhookSecret(tenantContext, {
      tenantId: "tenant-webhook",
      webhookId: created.webhook.id,
      idempotencyKey: "webhook-rotate",
    });
    expect(rotated.secretVersion).toBe(2);
    const delivered = await service.dispatchWebhookEvent(tenantContext, {
      tenantId: "tenant-webhook",
      webhookId: created.webhook.id,
      event: event("event-1"),
      idempotencyKey: "event-1",
    });
    expect(delivered.attempts).toBe(3);
    expect(delivered.delivery.status).toBe("succeeded");
    expect(calls).toBe(3);
    expect(requests[0].headers["X-Webhook-Secret-Version"]).toBe("2");
    expect(verifyOpenPlatformWebhookSignature({
      body: requests[0].body,
      signature: requests[0].headers["X-Webhook-Signature"],
      timestamp: requests[0].headers["X-Webhook-Timestamp"],
      secretVersion: requests[0].headers["X-Webhook-Secret-Version"],
      secret: rotated.secret,
      now,
    })).toBe(true);
    const duplicate = await service.dispatchWebhookEvent(tenantContext, {
      tenantId: "tenant-webhook",
      webhookId: created.webhook.id,
      event: event("event-1"),
      idempotencyKey: "event-1",
    });
    expect(duplicate.duplicate).toBe(true);
    expect(calls).toBe(3);

    await service.pauseWebhook(tenantContext, {
      tenantId: "tenant-webhook",
      webhookId: created.webhook.id,
      idempotencyKey: "webhook-pause",
    });
    const resumed = await service.resumeWebhook(tenantContext, {
      tenantId: "tenant-webhook",
      webhookId: created.webhook.id,
      idempotencyKey: "webhook-resume",
    });
    expect(resumed.status).toBe("active");
    await service.disableWebhook(tenantContext, {
      tenantId: "tenant-webhook",
      webhookId: created.webhook.id,
      idempotencyKey: "webhook-disable",
    });
    await expect(service.dispatchWebhookEvent(tenantContext, {
      tenantId: "tenant-webhook",
      webhookId: created.webhook.id,
      event: event("event-2"),
      idempotencyKey: "event-2",
    })).rejects.toMatchObject({ code: "OPEN_PLATFORM_RESOURCE_CONFLICT" });

    const deadService = new OpenPlatformWebhookService({
      authorization: createDevelopmentOpenPlatformAuthorization("all"),
      webhooks: new InMemoryOpenPlatformWebhookRepository(),
      deliveries: new InMemoryOpenPlatformWebhookDeliveryRepository(),
      secretProvider: new InMemoryOpenPlatformWebhookSecretProvider(),
      maxAttempts: 2,
      baseDelayMs: 0,
      maxDelayMs: 0,
      sleep: async () => undefined,
      clock: () => now,
      transport: { send: async () => ({ statusCode: 503 }) },
    });
    const deadWebhook = await deadService.createWebhook(tenantContext, {
      tenantId: "tenant-webhook",
      applicationId: "app-1",
      environmentId: "env-1",
      name: "Dead events",
      endpointUrl: "https://client.example.test/dead",
      events: ["application.status_changed"],
      idempotencyKey: "dead-create",
    });
    const dead = await deadService.dispatchWebhookEvent(tenantContext, {
      tenantId: "tenant-webhook",
      webhookId: deadWebhook.webhook.id,
      event: event("event-dead"),
      idempotencyKey: "event-dead",
    });
    expect(dead.deadLettered).toBe(true);
    expect(dead.delivery.status).toBe("dead_lettered");
    expect(dead.delivery.attempt).toBe(2);
  });

  it("does not expose another tenant's webhook", async () => {
    const service = new OpenPlatformWebhookService({
      authorization: createDevelopmentOpenPlatformAuthorization("all"),
      webhooks: new InMemoryOpenPlatformWebhookRepository(),
      deliveries: new InMemoryOpenPlatformWebhookDeliveryRepository(),
      secretProvider: new InMemoryOpenPlatformWebhookSecretProvider(),
      clock: () => now,
    });
    const created = await service.createWebhook(context("tenant-webhook-a"), {
      tenantId: "tenant-webhook-a",
      applicationId: "app-1",
      environmentId: "env-1",
      name: "A",
      endpointUrl: "https://a.example.test/webhook",
      events: ["application.status_changed"],
      idempotencyKey: "a-create",
    });
    await expect(service.getWebhook(context("tenant-webhook-b"), {
      tenantId: "tenant-webhook-b",
      id: created.webhook.id,
    })).rejects.toMatchObject({ code: "OPEN_PLATFORM_RESOURCE_NOT_FOUND" });
  });
});

const productionReadiness = Object.freeze({
  storage: "persistent" as const,
  distributed: true,
  ready: () => true,
});

function webhookServiceHarness(overrides: Record<string, unknown> = {}) {
  const requests: Array<{ url: string; body: string; headers: Record<string, string> }> = [];
  const state = { calls: 0, resolve: async (): Promise<readonly string[]> => ["93.184.216.34"] };
  const secrets = new Map<string, string>();
  const secretProvider = {
    productionReady: true,
    readiness: productionReadiness,
    issue: (input: { tenantId: string; webhookId: string; version: number }) => {
      const secret = "webhook-secret-01234567890123456789";
      secrets.set(`${input.tenantId}:${input.webhookId}:${input.version}`, secret);
      return {
        secret,
        reference: `vault://open-platform/webhook/${input.webhookId}/${input.version}`,
        version: input.version,
      };
    },
    rotate: (input: { tenantId: string; webhookId: string; version: number; previousVersion: number }) => ({
      secret: "webhook-secret-98765432109876543210",
      reference: `vault://open-platform/webhook/${input.webhookId}/${input.version}`,
      version: input.version,
    }),
    resolve: (input: { tenantId: string; webhookId: string; version: number }) =>
      secrets.get(`${input.tenantId}:${input.webhookId}:${input.version}`) ?? "webhook-secret-01234567890123456789",
  };
  const audit = new InMemoryOpenPlatformAuditEventStore({ clock: () => now });
  const webhooks = new InMemoryOpenPlatformWebhookRepository();
  const deliveries = new InMemoryOpenPlatformWebhookDeliveryRepository();
  const service = new OpenPlatformWebhookService({
    mode: "production",
    authorization: { productionReady: true, authorize: () => true },
    webhooks: {
      productionReady: true,
      readiness: productionReadiness,
      create: (record) => webhooks.create(record),
      get: (tenantId, id) => webhooks.get(tenantId, id),
      list: (tenantId) => webhooks.list(tenantId),
      save: (record) => webhooks.save(record),
    },
    deliveries: {
      productionReady: true,
      readiness: productionReadiness,
      append: (record) => deliveries.append(record),
      get: (tenantId, id) => deliveries.get(tenantId, id),
      list: (query) => deliveries.list(query),
      update: (tenantId, id, patch) => deliveries.update(tenantId, id, patch),
      findByEvent: (tenantId, webhookId, eventId) => deliveries.findByEvent(tenantId, webhookId, eventId),
      claim: (claim) => deliveries.claim(claim),
    },
    secretProvider,
    transport: {
      productionReady: true,
      send: async (request) => {
        state.calls += 1;
        requests.push({ url: request.url, body: request.body, headers: { ...request.headers } });
        return { statusCode: 204 };
      },
    },
    audit: {
      productionReady: true,
      readiness: productionReadiness,
      append: (event) => audit.append(event),
      list: (query) => audit.list(query),
    },
    clock: () => now,
    sleep: async () => undefined,
    baseDelayMs: 0,
    maxDelayMs: 0,
    endpointPolicy: { resolver: () => state.resolve() },
    ...overrides,
  });
  return { service, requests, state, webhooks, deliveries };
}

const productionContextIssuer = createOpenPlatformRequestContextIssuer({
  issuerId: "open-platform-webhook-production-tests",
  attestation: Object.freeze({ production: true }),
  clock: () => now,
});

function productionContext(tenantId: string): OpenPlatformRequestContext {
  return productionContextIssuer.issueAuthenticated({
    tenantId,
    actorId: "actor-production",
    requestId: `request-${tenantId}`,
  });
}

describe("open platform webhook endpoint security", () => {
  it("blocks obfuscated, mapped, and non-standard endpoint forms", () => {
    const strict = { production: true, policy: { requireResolution: false } } as const;
    for (const endpoint of [
      "https://[::ffff:169.254.169.254]/x",
      "https://[::ffff:a9fe:a9fe]/x",
      "https://[64:ff9b::7f00:1]/x",
      "https://[2002:a9fe:a9fe::]/x",
      "https://0/x",
      "https://0.0.0.0/x",
      "https://[::]/x",
      "https://0177.0.0.1/x",
      "https://2130706433/x",
      "https://[fc00::1]/x",
      "https://[fe80::1]/x",
      "https://[::1]:8443/x",
      "https://client.example.test:70000/x",
    ]) {
      expect(() => assertOpenPlatformWebhookEndpointSync(endpoint, strict))
        .toThrowError(OpenPlatformWebhookEndpointRejectedError);
    }
    for (const endpoint of [
      "https://93.184.216.34/x",
      "https://8.8.8.8:8443/x",
      "https://[::ffff:8.8.8.8]/x",
      "https://[2606:4700::1111]/x",
      "https://hooks.example.test/x",
      "https://hooks.example.test.:8443/x",
    ]) {
      expect(assertOpenPlatformWebhookEndpointSync(endpoint, strict)).toBe(endpoint);
    }
  });

  it("rejects insecure, private, mapped, metadata, and malformed endpoints", async () => {
    const { service } = webhookServiceHarness();
    const tenantId = "tenant-webhook-ssrf";
    const rejected = [
      "http://client.example.test/webhook",
      "https://localhost/webhook",
      "https://127.0.0.1/webhook",
      "https://127.5.5.5/webhook",
      "https://[::1]/webhook",
      "https://[::ffff:127.0.0.1]/webhook",
      "https://10.1.2.3/webhook",
      "https://172.16.9.9/webhook",
      "https://192.168.1.10/webhook",
      "https://169.254.169.254/latest/meta-data/",
      "https://metadata.google.internal/computeMetadata/v1/",
      "https://100.100.100.200/latest/meta-data/",
      "https://[fd00:ec2::254]/latest",
      "https://[fe80::1]/webhook",
      "https://node.internal/webhook",
      "https://service.local/webhook",
      "https://user:secret@client.example.test/webhook",
      "https://client.example.test:0/webhook",
      "https://client.example.test:8443#fragment",
      "ftp://client.example.test/webhook",
      "not-a-url",
    ];
    for (const endpointUrl of rejected) {
      await expect(service.createWebhook(productionContext(tenantId), {
        tenantId,
        applicationId: "app-1",
        environmentId: "env-1",
        name: "Blocked",
        endpointUrl,
        events: ["application.status_changed"],
        idempotencyKey: `blocked-${endpointUrl}`,
      })).rejects.toMatchObject({ code: "OPEN_PLATFORM_VALIDATION_ERROR" });
    }
    expect(await service.listWebhooks(productionContext(tenantId), { tenantId })).toMatchObject({ items: [] });
  });

  it("rejects hosts that resolve to private, loopback, or metadata addresses", async () => {
    const { service, state } = webhookServiceHarness();
    const tenantId = "tenant-webhook-dns";
    const privateAnswers = [
      ["127.0.0.1"],
      ["10.0.0.5"],
      ["169.254.169.254"],
      ["192.168.1.1"],
      ["[::ffff:10.0.0.5]"],
      ["fd00::1"],
      ["203.0.113.10", "172.20.5.5"],
    ];
    for (const [index, addresses] of privateAnswers.entries()) {
      state.resolve = async () => addresses;
      await expect(service.createWebhook(productionContext(tenantId), {
        tenantId,
        applicationId: "app-1",
        environmentId: "env-1",
        name: "Rebind",
        endpointUrl: "https://hooks.example.test/webhook",
        events: ["application.status_changed"],
        idempotencyKey: `rebind-${index}`,
      })).rejects.toMatchObject({ code: "OPEN_PLATFORM_VALIDATION_ERROR" });
    }
    state.resolve = async () => { throw new Error("dns failure"); };
    await expect(service.createWebhook(productionContext(tenantId), {
      tenantId,
      applicationId: "app-1",
      environmentId: "env-1",
      name: "Unresolvable",
      endpointUrl: "https://unresolvable.example.test/webhook",
      events: ["application.status_changed"],
      idempotencyKey: "unresolvable",
    })).rejects.toMatchObject({ code: "OPEN_PLATFORM_VALIDATION_ERROR" });
    state.resolve = async () => [];
    await expect(service.createWebhook(productionContext(tenantId), {
      tenantId,
      applicationId: "app-1",
      environmentId: "env-1",
      name: "Empty",
      endpointUrl: "https://empty.example.test/webhook",
      events: ["application.status_changed"],
      idempotencyKey: "empty",
    })).rejects.toMatchObject({ code: "OPEN_PLATFORM_VALIDATION_ERROR" });
  });

  it("keeps delivery blocked for endpoints that fail the policy at send time", async () => {
    const { service, state, requests, deliveries } = webhookServiceHarness();
    const tenantId = "tenant-webhook-send-policy";
    state.resolve = async () => ["93.184.216.34"];
    const created = await service.createWebhook(productionContext(tenantId), {
      tenantId,
      applicationId: "app-1",
      environmentId: "env-1",
      name: "Send policy",
      endpointUrl: "https://hooks.example.test/webhook",
      events: ["application.status_changed"],
      idempotencyKey: "send-policy-create",
    });
    state.resolve = async () => ["169.254.169.254"];
    const blocked = await service.dispatchWebhookEvent(productionContext(tenantId), {
      tenantId,
      webhookId: created.webhook.id,
      event: { ...event("event-blocked"), tenantId },
      idempotencyKey: "event-blocked",
    });
    expect(blocked.delivery.status).toBe("dead_lettered");
    expect(blocked.delivery.errorCode).toBe("WEBHOOK_ENDPOINT_BLOCKED");
    expect(requests).toHaveLength(0);

    state.resolve = async () => ["93.184.216.34"];
    const second = await service.createWebhook(productionContext(tenantId), {
      tenantId,
      applicationId: "app-1",
      environmentId: "env-1",
      name: "Unresolvable send",
      endpointUrl: "https://second.example.test/webhook",
      events: ["application.status_changed"],
      idempotencyKey: "send-policy-second",
    });
    const payload = JSON.stringify({
      event_id: "event-unresolved",
      event_type: "application.status_changed",
      tenant_id: tenantId,
      schema_version: "open-platform.webhook-event.v1",
      occurred_at: now.toISOString(),
    });
    await deliveries.append({
      id: "delivery-unresolved-1",
      tenantId,
      webhookId: second.webhook.id,
      eventId: "event-unresolved",
      event: "application.status_changed",
      eventType: "application.status_changed",
      status: "pending",
      attempt: 0,
      maxAttempts: 3,
      idempotencyKey: "event-unresolved",
      payload,
      body: payload,
      secretVersion: 1,
      createdAt: now.toISOString(),
      updatedAt: now.toISOString(),
      nextAttemptAt: now.toISOString(),
    });
    state.resolve = async () => { throw new Error("dns failure"); };
    const retried = await service.processDueDeliveries(productionContext(tenantId), {
      tenantId,
      webhookId: second.webhook.id,
    });
    expect(retried).toHaveLength(1);
    expect(retried[0]).toMatchObject({ status: "failed", attempt: 1, errorCode: "WEBHOOK_ENDPOINT_UNRESOLVED" });
    expect(retried[0].nextAttemptAt).toBeDefined();
    expect(requests).toHaveLength(0);
  });

  it("accepts allowlisted hosts and public addresses and blocks other hosts", async () => {
    const { service } = webhookServiceHarness({
      endpointPolicy: {
        allowHosts: ["hooks.example.test", "*.trusted.example.test"],
        allowedPorts: [443, 8443],
        resolver: () => ["93.184.216.34"],
      },
    });
    const tenantId = "tenant-webhook-allowlist";
    const allowed = await service.createWebhook(productionContext(tenantId), {
      tenantId,
      applicationId: "app-1",
      environmentId: "env-1",
      name: "Allowlisted",
      endpointUrl: "https://sub.trusted.example.test:8443/webhook",
      events: ["application.status_changed"],
      idempotencyKey: "allowlisted",
    });
    expect(allowed.webhook.endpointUrl).toBe("https://sub.trusted.example.test:8443/webhook");
    for (const endpointUrl of [
      "https://other.example.test/webhook",
      "https://hooks.example.test:9443/webhook",
    ]) {
      await expect(service.createWebhook(productionContext(tenantId), {
        tenantId,
        applicationId: "app-1",
        environmentId: "env-1",
        name: "Not allowlisted",
        endpointUrl,
        events: ["application.status_changed"],
        idempotencyKey: `denied-${endpointUrl}`,
      })).rejects.toMatchObject({ code: "OPEN_PLATFORM_VALIDATION_ERROR" });
    }
  });

  it("keeps development fixtures on loopback HTTP and off DNS resolution", async () => {
    const requests: string[] = [];
    const service = new OpenPlatformWebhookService({
      mode: "development",
      authorization: createDevelopmentOpenPlatformAuthorization("all"),
      webhooks: new InMemoryOpenPlatformWebhookRepository(),
      deliveries: new InMemoryOpenPlatformWebhookDeliveryRepository(),
      secretProvider: new InMemoryOpenPlatformWebhookSecretProvider(),
      clock: () => now,
      transport: {
        send: async (request) => {
          requests.push(request.url);
          return { statusCode: 204 };
        },
      },
    });
    const created = await service.createWebhook(context("tenant-webhook-dev"), {
      tenantId: "tenant-webhook-dev",
      applicationId: "app-1",
      environmentId: "env-1",
      name: "Local",
      endpointUrl: "http://127.0.0.1:4010/webhook",
      events: ["application.status_changed"],
      idempotencyKey: "local-create",
    });
    const delivered = await service.dispatchWebhookEvent(context("tenant-webhook-dev"), {
      tenantId: "tenant-webhook-dev",
      webhookId: created.webhook.id,
      event: { ...event("event-dev"), tenantId: "tenant-webhook-dev" },
      idempotencyKey: "event-dev",
    });
    expect(delivered.delivery.status).toBe("succeeded");
    expect(requests).toEqual(["http://127.0.0.1:4010/webhook"]);
    await expect(service.createWebhook(context("tenant-webhook-dev"), {
      tenantId: "tenant-webhook-dev",
      applicationId: "app-1",
      environmentId: "env-1",
      name: "Private",
      endpointUrl: "https://10.0.0.9/webhook",
      events: ["application.status_changed"],
      idempotencyKey: "private-create",
    })).rejects.toMatchObject({ code: "OPEN_PLATFORM_VALIDATION_ERROR" });
    for (const endpointUrl of ["https://localhost/webhook", "http://localhost:4010/webhook"]) {
      await expect(service.createWebhook(context("tenant-webhook-dev"), {
        tenantId: "tenant-webhook-dev",
        applicationId: "app-1",
        environmentId: "env-1",
        name: "Localhost",
        endpointUrl,
        events: ["application.status_changed"],
        idempotencyKey: `localhost-${endpointUrl}`,
      })).rejects.toMatchObject({ code: "OPEN_PLATFORM_VALIDATION_ERROR" });
    }
  });
});

describe("open platform webhook production readiness", () => {
  it("fails closed when the transport, secret resolver, or repositories are not production ready", async () => {
    const { service: ready } = webhookServiceHarness();
    await expect(ready.isReady()).resolves.toBe(true);

    const withoutTransport = webhookServiceHarness({ transport: undefined }).service;
    await expect(withoutTransport.isReady()).resolves.toBe(false);

    const withFunctionTransport = webhookServiceHarness({ transport: () => ({ statusCode: 204 }) }).service;
    await expect(withFunctionTransport.isReady()).resolves.toBe(false);

    const withDevelopmentTransport = webhookServiceHarness({ transport: { send: async () => ({ statusCode: 204 }) } }).service;
    await expect(withDevelopmentTransport.isReady()).resolves.toBe(false);

    const withoutSecretResolver = webhookServiceHarness({
      secretProvider: {
        productionReady: true,
        readiness: { storage: "persistent", distributed: true, ready: () => true },
        issue: () => ({ secret: "webhook-secret-01234567890123456789" }),
      },
    }).service;
    await expect(withoutSecretResolver.isReady()).resolves.toBe(false);

    const withInMemorySecret = webhookServiceHarness({
      secretProvider: new InMemoryOpenPlatformWebhookSecretProvider(),
    }).service;
    await expect(withInMemorySecret.isReady()).resolves.toBe(false);

    const withUnavailableRepository = webhookServiceHarness({
      webhooks: {
        productionReady: true,
        readiness: { storage: "persistent", distributed: true, ready: () => false },
        create: async () => { throw new Error("unavailable"); },
        get: async () => undefined,
        list: async () => [],
        save: async () => { throw new Error("unavailable"); },
      },
    }).service;
    await expect(withUnavailableRepository.isReady()).resolves.toBe(false);

    const withUnavailableDeliveries = webhookServiceHarness({
      deliveries: {
        productionReady: true,
        readiness: { storage: "memory", distributed: false, ready: () => true },
        append: async () => { throw new Error("unavailable"); },
        get: async () => undefined,
        list: async () => ({ items: [], hasMore: false }),
      },
    }).service;
    await expect(withUnavailableDeliveries.isReady()).resolves.toBe(false);

    const withoutClaim = webhookServiceHarness({
      deliveries: {
        productionReady: true,
        readiness: productionReadiness,
        append: async () => { throw new Error("unavailable"); },
        get: async () => undefined,
        list: async () => ({ items: [], hasMore: false }),
      },
    }).service;
    await expect(withoutClaim.isReady()).resolves.toBe(false);

    const testMode = new OpenPlatformWebhookService({
      mode: "test",
      authorization: createDevelopmentOpenPlatformAuthorization("all"),
      webhooks: new InMemoryOpenPlatformWebhookRepository(),
      deliveries: new InMemoryOpenPlatformWebhookDeliveryRepository(),
      secretProvider: new InMemoryOpenPlatformWebhookSecretProvider(),
      clock: () => now,
    });
    await expect(testMode.isReady()).resolves.toBe(true);
  });
});

describe("open platform webhook delivery concurrency", () => {
  it("lets only one worker claim and send a queued delivery", async () => {
    const clock = { value: now };
    const deliveries = new InMemoryOpenPlatformWebhookDeliveryRepository();
    const requests: string[] = [];
    const service = new OpenPlatformWebhookService({
      authorization: createDevelopmentOpenPlatformAuthorization("all"),
      webhooks: new InMemoryOpenPlatformWebhookRepository(),
      deliveries,
      secretProvider: new InMemoryOpenPlatformWebhookSecretProvider(),
      clock: () => clock.value,
      sleep: async () => undefined,
      baseDelayMs: 0,
      maxDelayMs: 0,
      transport: {
        send: async (request) => {
          requests.push(request.url);
          await new Promise((resolve) => setTimeout(resolve, 5));
          return { statusCode: 204 };
        },
      },
    });
    const tenantId = "tenant-webhook-claim";
    const tenantContext = context(tenantId);
    const created = await service.createWebhook(tenantContext, {
      tenantId,
      applicationId: "app-1",
      environmentId: "env-1",
      name: "Claim",
      endpointUrl: "https://client.example.test/webhook",
      events: ["application.status_changed"],
      idempotencyKey: "claim-create",
    });
    const delivery = await deliveries.append({
      id: "delivery-claim-1",
      tenantId,
      webhookId: created.webhook.id,
      eventId: "event-claim-1",
      event: "application.status_changed",
      eventType: "application.status_changed",
      status: "pending",
      attempt: 0,
      maxAttempts: 3,
      idempotencyKey: "event-claim-1",
      payload: JSON.stringify({ event_id: "event-claim-1", event_type: "application.status_changed", tenant_id: tenantId, schema_version: "open-platform.webhook-event.v1", occurred_at: now.toISOString() }),
      body: JSON.stringify({ event_id: "event-claim-1" }),
      secretVersion: 1,
      createdAt: now.toISOString(),
      updatedAt: now.toISOString(),
      nextAttemptAt: now.toISOString(),
    });
    const settled = await Promise.all([
      service.processDueDeliveries(tenantContext, { tenantId, webhookId: created.webhook.id }),
      service.processDueDeliveries(tenantContext, { tenantId, webhookId: created.webhook.id }),
    ]);
    expect(requests).toHaveLength(1);
    expect(settled.flat()).toHaveLength(1);
    expect(settled.flat()[0]).toMatchObject({ id: delivery.id, status: "succeeded", attempt: 1 });
    expect(settled.flat()[0].leaseId).toBeUndefined();
    expect(settled.flat()[0].leaseExpiresAt).toBeUndefined();
  });

  it("recovers a delivery abandoned in the delivering state and refuses a live lease", async () => {
    const clock = { value: now };
    const deliveries = new InMemoryOpenPlatformWebhookDeliveryRepository();
    const webhooks = new InMemoryOpenPlatformWebhookRepository();
    const secretProvider = new InMemoryOpenPlatformWebhookSecretProvider();
    const requests: string[] = [];
    const service = new OpenPlatformWebhookService({
      authorization: createDevelopmentOpenPlatformAuthorization("all"),
      webhooks,
      deliveries,
      secretProvider,
      clock: () => clock.value,
      sleep: async () => undefined,
      baseDelayMs: 0,
      maxDelayMs: 0,
      deliveryLeaseMs: 30_000,
      transport: {
        send: async (request) => {
          requests.push(request.url);
          return { statusCode: 204 };
        },
      },
    });
    const tenantId = "tenant-webhook-stale";
    const tenantContext = context(tenantId);
    const created = await service.createWebhook(tenantContext, {
      tenantId,
      applicationId: "app-1",
      environmentId: "env-1",
      name: "Stale",
      endpointUrl: "https://client.example.test/webhook",
      events: ["application.status_changed"],
      idempotencyKey: "stale-create",
    });
    const payload = JSON.stringify({
      event_id: "event-stale-1",
      event_type: "application.status_changed",
      tenant_id: tenantId,
      schema_version: "open-platform.webhook-event.v1",
      occurred_at: now.toISOString(),
    });
    await deliveries.append({
      id: "delivery-stale-1",
      tenantId,
      webhookId: created.webhook.id,
      eventId: "event-stale-1",
      event: "application.status_changed",
      eventType: "application.status_changed",
      status: "pending",
      attempt: 0,
      maxAttempts: 3,
      idempotencyKey: "event-stale-1",
      payload,
      body: payload,
      secretVersion: 1,
      createdAt: now.toISOString(),
      updatedAt: now.toISOString(),
      nextAttemptAt: now.toISOString(),
    });
    const claim = {
      tenantId,
      id: "delivery-stale-1",
      attempt: 1,
      leaseId: "lease-crashed-worker",
      now: now.toISOString(),
      leaseExpiresAt: new Date(now.getTime() + 30_000).toISOString(),
    };
    expect(await deliveries.claim(claim)).toMatchObject({ claimed: true });
    expect(await deliveries.claim({ ...claim, leaseId: "lease-second-worker" })).toMatchObject({ claimed: false });
    await expect(service.processDueDeliveries(tenantContext, { tenantId, webhookId: created.webhook.id })).resolves.toEqual([]);
    expect(requests).toHaveLength(0);

    clock.value = new Date(now.getTime() + 30_001);
    const recovered = await service.processDueDeliveries(tenantContext, { tenantId, webhookId: created.webhook.id });
    expect(requests).toHaveLength(1);
    expect(recovered[0]).toMatchObject({ status: "succeeded", attempt: 1 });
    expect(recovered[0].leaseId).toBeUndefined();
  });
});
