import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, it } from "node:test";
import {
  OPEN_PLATFORM_DOMAIN_EVENTS,
  OPEN_PLATFORM_DOMAIN_EVENT_TYPES,
  OPEN_PLATFORM_SAFE_DOMAIN_EVENT_TYPES,
  OpenPlatformApiError,
  OpenPlatformClient,
  OpenPlatformTimeoutError,
  generateIdempotencyKey,
  isOpenPlatformDomainEventType,
  isSafeOpenPlatformDomainEventType,
  openPlatformDomainEventNameParts,
  signOpenPlatformWebhook,
  verifyOpenPlatformWebhookHeaders,
  OPEN_PLATFORM_WEBHOOK_SECRET_VERSION_HEADER,
  OPEN_PLATFORM_WEBHOOK_SIGNATURE_HEADER,
  OPEN_PLATFORM_WEBHOOK_TIMESTAMP_HEADER,
  generatePkcePair,
  parseOpenPlatformErrorResponse,
} from "../src/index.js";

interface CapturedRequest {
  readonly url: string;
  readonly init: RequestInit;
}

function response(value: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(value === undefined ? null : JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

function clientWith(
  handler: (request: CapturedRequest) => Promise<Response>,
  options: Partial<ConstructorParameters<typeof OpenPlatformClient>[0]> = {},
): { client: OpenPlatformClient; calls: CapturedRequest[] } {
  const calls: CapturedRequest[] = [];
  const client = new OpenPlatformClient({
    baseUrl: "https://api.example.test/api/open/v1",
    tenantId: "tenant-a",
    tokenProvider: async () => "access-token",
    retry: false,
    fetch: async (input, init) => {
      const captured = { url: String(input), init: init ?? {} };
      calls.push(captured);
      return handler(captured);
    },
    ...options,
  });
  return { client, calls };
}

describe("open platform SDK", () => {
  it("adds authentication and tenant/request headers without putting credentials in URLs", async () => {
    const { client, calls } = clientWith(async () => response([{ id: "app-1", name: "Orders" }]));
    const page = await client.applications.list({ limit: 2 });

    assert.equal(page.items.length, 1);
    assert.equal(page.hasMore, false);
    assert.equal(calls.length, 1);
    const url = new URL(calls[0].url);
    const headers = new Headers(calls[0].init.headers);
    assert.equal(url.pathname, "/api/open/v1/applications");
    assert.equal(url.searchParams.get("limit"), "2");
    assert.equal(headers.get("authorization"), "Bearer access-token");
    assert.equal(headers.get("x-tenant-id"), "tenant-a");
    assert.ok(headers.get("x-request-id"));
    assert.equal(url.toString().includes("access-token"), false);
  });

  it("uses a top-level string token source as a Bearer header", async () => {
    const token = "string-token-secret";
    const { client, calls } = clientWith(async () => response({ ok: true }), {
      tokenProvider: token,
    });
    await client.request("/health");
    const headers = new Headers(calls[0].init.headers);
    assert.equal(headers.get("authorization"), `Bearer ${token}`);
    assert.equal(calls[0].url.includes(token), false);
  });

  it("refreshes a dynamic token once after a 401 and keeps credentials out of errors", async () => {
    let tokenCalls = 0;
    const tokens = ["first-token-secret", "second-token-secret"];
    const { client, calls } = clientWith(async (request) => {
      const authorization = new Headers(request.init.headers).get("authorization");
      if (authorization === `Bearer ${tokens[0]}`) {
        return response({ error: { code: "UNAUTHENTICATED", message: `Bearer ${tokens[0]}` } }, 401);
      }
      return response({ ok: true });
    }, {
      tokenProvider: async () => {
        tokenCalls += 1;
        return tokens[Math.min(tokenCalls - 1, tokens.length - 1)];
      },
      retryOnUnauthorized: true,
      retry: false,
    });

    const result = await client.request<{ ok: boolean }>("/health");
    assert.deepEqual(result, { ok: true });
    assert.equal(tokenCalls, 2);
    assert.equal(calls.length, 2);
    assert.equal(new Headers(calls[0].init.headers).get("authorization"), `Bearer ${tokens[0]}`);
    assert.equal(new Headers(calls[1].init.headers).get("authorization"), `Bearer ${tokens[1]}`);
    assert.equal(calls.some((call) => call.url.includes(tokens[0]) || call.url.includes(tokens[1])), false);
  });

  it("uses idempotency headers and no-store for credential responses", async () => {
    const { client, calls } = clientWith(async (request) => {
      if (request.init.method === "POST" && new URL(request.url).pathname.endsWith("/credentials")) {
        return response({
          credential: { id: "credential-1", name: "Orders" },
          secret: "one-time-secret",
        }, 201);
      }
      return response({
        credential: { id: "credential-2", name: "Orders" },
        previousCredential: { id: "credential-1", name: "Orders" },
        secret: "rotated-secret",
      });
    });

    const issued = await client.credentials.issue({
      applicationId: "app-1",
      name: "Orders",
      scopes: ["orders:read"],
    });
    assert.equal(issued.secret, "one-time-secret");
    assert.equal(calls[0].init.cache, "no-store");
    assert.equal((calls[0].init.headers as Record<string, string>)["cache-control"], "no-store");
    assert.ok(new Headers(calls[0].init.headers).get("idempotency-key"));
    assert.equal(calls[0].url.includes("one-time-secret"), false);
    assert.equal(String(calls[0].init.body).includes("one-time-secret"), false);

    const rotated = await client.credentials.rotate("credential-1");
    assert.equal(rotated.previousCredential.id, "credential-1");
    assert.equal(calls[1].init.cache, "no-store");
    assert.equal((calls[1].init.headers as Record<string, string>)["cache-control"], "no-store");
    assert.ok(new Headers(calls[1].init.headers).get("idempotency-key"));
  });

  it("parses errors safely and retries retryable responses", async () => {
    let attempts = 0;
    const { client } = clientWith(async () => {
      attempts += 1;
      if (attempts === 1) return response({ error: { code: "TEMPORARILY_UNAVAILABLE", message: "token=hidden" } }, 503);
      return response({ ok: true });
    }, { retry: { maxRetries: 1, baseDelayMs: 0, maxDelayMs: 0 } });

    const result = await client.request<{ ok: boolean }>("/health");
    assert.deepEqual(result, { ok: true });
    assert.equal(attempts, 2);

    const error = parseOpenPlatformErrorResponse({
      error: { code: "INVALID_ARGUMENT", message: "secret=do-not-leak" },
      requestId: "request-1",
    }, 400);
    assert.ok(error instanceof OpenPlatformApiError);
    assert.equal(error.requestId, "request-1");
    assert.equal(JSON.stringify(error).includes("do-not-leak"), false);
    const secretCodeError = parseOpenPlatformErrorResponse({
      error: { code: "sk_live_do-not-leak", message: "ignored" },
    }, 400);
    assert.equal(JSON.stringify(secretCodeError).includes("do-not-leak"), false);
  });

  it("does not expose an authentication token through API errors", async () => {
    const token = "error-token-secret";
    const client = new OpenPlatformClient({
      baseUrl: "https://api.example.test/api/open/v1",
      tokenProvider: token,
      retry: false,
      fetch: async (input) => {
        assert.equal(String(input).includes(token), false);
        return response({
          error: {
            code: "UNAUTHENTICATED",
            message: `Bearer ${token}`,
            requestId: token,
            field: token,
          },
        }, 401);
      },
    });
    await assert.rejects(
      client.request("/health"),
      (error: unknown) => {
        assert.ok(error instanceof OpenPlatformApiError);
        assert.equal(error.message.includes(token), false);
        assert.equal(JSON.stringify(error).includes(token), false);
        return true;
      },
    );
  });

  it("normalizes array and cursor page responses", async () => {
    const calls: string[] = [];
    const client = new OpenPlatformClient({
      baseUrl: "https://api.example.test/api/open/v1",
      fetch: async (input) => {
        const url = new URL(String(input));
        calls.push(url.toString());
        if (url.searchParams.get("cursor") === "next-1") return response([{ id: "app-2" }]);
        return response({ items: [{ id: "app-1" }], nextCursor: "next-1", hasMore: true });
      },
      retry: false,
    });

    const applications = await client.applications.listAll();
    assert.deepEqual(applications.map((item) => item.id), ["app-1", "app-2"]);
    assert.equal(calls.length, 2);
    assert.equal(new URL(calls[1]).searchParams.get("cursor"), "next-1");
  });

  it("exposes typed API product, usage, and subscription routes", async () => {
    const { client, calls } = clientWith(async (request) => {
      const method = request.init.method ?? "GET";
      if (method === "GET") return response([]);
      return response({ id: "resource-1" });
    });

    await client.apiProducts.create({ name: "Orders API", scopes: ["orders:read"] });
    await client.usage.record({ subscriptionId: "subscription-1", metric: "requests", quantity: 1 });
    await client.subscriptions.create({
      applicationId: "application-1",
      productId: "product-1",
      name: "Orders",
      scopes: ["orders:read"],
    });

    assert.deepEqual(calls.map((call) => new URL(call.url).pathname), [
      "/api/open/v1/catalog/products",
      "/api/open/v1/usage",
      "/api/open/v1/subscriptions",
    ]);
    assert.deepEqual(calls.map((call) => call.init.method), ["POST", "POST", "POST"]);
    assert.equal(calls.every((call) => new Headers(call.init.headers).has("idempotency-key")), true);
  });

  it("aborts an in-flight request without retrying or leaking the token", async () => {
    const token = "abort-token-secret";
    const controller = new AbortController();
    let calls = 0;
    let markFetchStarted: (() => void) | undefined;
    const fetchStarted = new Promise<void>((resolve) => {
      markFetchStarted = resolve;
    });
    const client = new OpenPlatformClient({
      baseUrl: "https://api.example.test/api/open/v1",
      tokenProvider: token,
      retry: { maxRetries: 3, baseDelayMs: 0, maxDelayMs: 0 },
      fetch: async (_input, init) => {
        calls += 1;
        markFetchStarted?.();
        return new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            reject(new DOMException("aborted", "AbortError"));
          }, { once: true });
        });
      },
    });
    const request = client.request("/health", { signal: controller.signal });
    await fetchStarted;
    controller.abort();
    await assert.rejects(
      request,
      (error: unknown) => error instanceof Error && error.name === "AbortError" && !JSON.stringify(error).includes(token),
    );
    assert.equal(calls, 1);
  });

  it("honors timeout and AbortSignal", async () => {
    const timeoutClient = new OpenPlatformClient({
      baseUrl: "https://api.example.test/api/open/v1",
      timeoutMs: 5,
      retry: false,
      fetch: async (_input, init) => new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")), { once: true });
      }),
    });
    await assert.rejects(
      timeoutClient.request("/applications"),
      (error: unknown) => error instanceof OpenPlatformTimeoutError,
    );

    const controller = new AbortController();
    controller.abort();
    const abortClient = new OpenPlatformClient({
      baseUrl: "https://api.example.test/api/open/v1",
      retry: false,
      fetch: async () => response({}),
    });
    await assert.rejects(
      abortClient.request("/applications", { signal: controller.signal }),
      (error: unknown) => error instanceof Error && error.name === "AbortError",
    );
  });

  it("calls webhook and audit routes and verifies signed webhook headers", async () => {
    const secret = "sdk-webhook-secret-01234567890123456789";
    const body = JSON.stringify({ event_id: "event-sdk" });
    const timestamp = new Date("2030-01-01T00:00:00.000Z").toISOString();
    const signature = signOpenPlatformWebhook({ body, secret, secretVersion: 3, timestamp });
    const { client, calls } = clientWith(async (request) => {
      const url = new URL(request.url);
      if (url.pathname.endsWith("/audit-events")) return response({ items: [], hasMore: false });
      if (url.pathname.endsWith("/deliveries")) return response({ items: [], hasMore: false });
      if (request.init.method === "GET" && url.pathname.endsWith("/webhooks")) return response({ items: [], hasMore: false });
      if (request.init.method === "POST" && url.pathname.endsWith("/rotate-secret")) {
        return response({ webhook: { id: "webhook-1" }, secret: "rotated-secret-01234567890123456789", secretVersion: 4 });
      }
      if (request.init.method === "POST" && url.pathname.endsWith("/test")) {
        return response({ delivery: { id: "delivery-1", status: "succeeded" }, deliveries: [], attempts: 1, duplicate: false, deadLettered: false });
      }
      if (request.init.method === "POST" && url.pathname.endsWith("/replay")) {
        return response({ delivery: { id: "delivery-2", status: "succeeded" }, deliveries: [], attempts: 1, duplicate: false, deadLettered: false });
      }
      if (request.init.method === "POST") return response({ webhook: { id: "webhook-1" }, secret: "created-secret-01234567890123456789", secretVersion: 1 });
      return response({ id: "webhook-1", status: "active" });
    });
    const created = await client.createWebhook({
      applicationId: "app-1",
      environmentId: "env-1",
      name: "Events",
      endpointUrl: "https://client.example.test/webhook",
      events: ["application.status_changed"],
    });
    assert.equal(created.secretVersion, 1);
    await client.listWebhooks({ limit: 10 });
    await client.listWebhookDeliveries("webhook-1");
    await client.pauseWebhook("webhook-1");
    await client.resumeWebhook("webhook-1");
    await client.disableWebhook("webhook-1");
    await client.rotateWebhookSecret("webhook-1");
    await client.testWebhook("webhook-1", { eventId: "event-sdk", eventType: "application.status_changed" });
    await client.replayWebhookDelivery("webhook-1", "delivery-1");
    await client.listAuditEvents({ limit: 10 });
    assert.equal(calls.length, 10);
    assert.ok(calls.filter((call) => call.init.method === "POST").every((call) => new Headers(call.init.headers).has("idempotency-key")));
    assert.equal(verifyOpenPlatformWebhookHeaders({
      body,
      secret,
      now: new Date(timestamp),
      headers: {
        [OPEN_PLATFORM_WEBHOOK_SIGNATURE_HEADER]: signature,
        [OPEN_PLATFORM_WEBHOOK_TIMESTAMP_HEADER]: timestamp,
        [OPEN_PLATFORM_WEBHOOK_SECRET_VERSION_HEADER]: "3",
      },
    }), true);
  });

  it("exposes commerce routes, aliases, pagination, idempotency, and safe errors", async () => {
    const token = "commerce-error-token-secret";
    const { client, calls } = clientWith(async (request) => {
      const url = new URL(request.url);
      const path = url.pathname;
      const method = request.init.method ?? "GET";
      if (path.endsWith("/marketplace/listings") && method === "GET") {
        return url.searchParams.get("cursor") === "listing-next"
          ? response({ items: [{ id: "listing-2", status: "published" }], hasMore: false, total: 2 })
          : response({ items: [{ id: "listing-1", status: "draft" }], nextCursor: "listing-next", hasMore: true, total: 2 });
      }
      if (path.endsWith("/marketplace/listings") && method === "POST") return response({ id: "listing-1", status: "draft" }, 201);
      if (path.includes("/marketplace/listings/") && method === "POST") return response({ id: "listing-1", status: "published" });
      if (path.endsWith("/partners") && method === "GET") return response({ items: [{ id: "partner-1" }], hasMore: false });
      if (path.includes("/partners/") && method === "GET") {
        if (path.endsWith("/partner-error")) return response({ error: { code: "INVALID_ARGUMENT", message: `Bearer ${token}` } }, 400);
        return response({ id: "partner-1", status: "active" });
      }
      if (path.endsWith("/commission-rules") && method === "GET") return response({ items: [{ id: "rule-1" }], hasMore: false });
      if (path.endsWith("/billing/accounts") && method === "GET") return response({ items: [{ id: "account-1" }], hasMore: false });
      if (path.endsWith("/billing/invoices") && method === "GET") return response({ items: [{ id: "invoice-1", total: { amountMinor: "100", currency: "CNY" } }], hasMore: false });
      if (path.endsWith("/disputes") && method === "POST") return response({ invoice: { id: "invoice-1" }, replayed: false });
      if (path.includes("/billing/invoices/") && method === "GET") return response({ id: "invoice-1", total: { amountMinor: "100", currency: "CNY" } });
      return response({});
    });

    const listings = await client.marketplace.listAll({ limit: 1 });
    assert.deepEqual(listings.map((item) => item.id), ["listing-1", "listing-2"]);
    await client.marketplace.get("listing-1");
    await client.marketplace.create({
      partnerAccountId: "partner-1",
      productId: "product-1",
      title: "Orders",
      description: "Orders API",
    });
    await client.marketplace.submitReview("listing-1");
    await client.marketplace.publish("listing-1");
    await client.marketplace.suspend("listing-1");
    await client.marketplace.remove("listing-1");
    await client.partners.list({ limit: 10 });
    await client.partners.get("partner-1");
    await client.commissionRules.list({ limit: 10 });
    await client.billing.accounts.list({ limit: 10 });
    await client.invoices.list({ limit: 10 });
    await client.invoices.get("invoice-1");
    const dispute = await client.invoices.dispute("invoice-1", { reason: "incorrect total" });
    assert.equal(dispute.invoice.id, "invoice-1");
    await client.listMarketplaceListings({ limit: 10 });

    assert.equal(calls.length, 16);
    assert.equal(calls.filter((call) => call.init.method === "POST").every((call) =>
      new Headers(call.init.headers).has("idempotency-key")), true);
    assert.equal(calls.every((call) => call.init.cache === "no-store"), true);
    assert.equal(calls.some((call) => String(call.init.body).includes("incorrect total")), true);
    assert.equal(calls.every((call) => !call.url.includes(token)), true);

    await assert.rejects(
      client.partners.get("partner-error"),
      (error: unknown) => {
        assert.ok(error instanceof OpenPlatformApiError);
        assert.equal(JSON.stringify(error).includes(token), false);
        assert.equal(error.message.includes(token), false);
        return true;
      },
    );
  });

  it("generates valid idempotency keys and PKCE pairs", () => {
    const key = generateIdempotencyKey("test");
    assert.match(key, /^test-[0-9a-f-]{36}$/u);
    const pair = generatePkcePair();
    assert.equal(pair.codeChallengeMethod, "S256");
    assert.equal(pair.codeChallenge, createHash("sha256").update(pair.codeVerifier).digest("base64url"));
    assert.ok(pair.codeVerifier.length >= 43);
    assert.ok(pair.codeVerifier.length <= 128);
  });

  it("keeps the domain event catalog in sync with the contract catalog", () => {
    assert.equal(OPEN_PLATFORM_DOMAIN_EVENT_TYPES.length, 72);
    assert.deepEqual(
      [...OPEN_PLATFORM_DOMAIN_EVENT_TYPES],
      [...OPEN_PLATFORM_SAFE_DOMAIN_EVENT_TYPES],
    );
    assert.equal(OPEN_PLATFORM_DOMAIN_EVENTS.length, 72);
    assert.equal(new Set(OPEN_PLATFORM_DOMAIN_EVENT_TYPES).size, 72);
    for (const eventType of OPEN_PLATFORM_DOMAIN_EVENT_TYPES) {
      assert.equal(isOpenPlatformDomainEventType(eventType), true);
    }
    assert.equal(isOpenPlatformDomainEventType("secret.payload"), false);
    assert.equal(isSafeOpenPlatformDomainEventType("tenant.created"), true);
    assert.equal(isSafeOpenPlatformDomainEventType("api_product.published"), true);
    assert.equal(isSafeOpenPlatformDomainEventType("commerce_invoice.status_changed"), true);
    assert.equal(isSafeOpenPlatformDomainEventType("compliance_privacy_request.decided"), true);
    assert.equal(isSafeOpenPlatformDomainEventType("credential.rotated"), false);
    const parts = openPlatformDomainEventNameParts("api_version.deprecated");
    assert.equal(parts.resource, "api_version");
    assert.equal(parts.action, "deprecated");
    const commerceParts = openPlatformDomainEventNameParts("compliance_retention_policy.executed");
    assert.equal(commerceParts.resource, "compliance_retention_policy");
    assert.equal(commerceParts.action, "executed");
  });

  it("routes invoice dispute review, decision, and withdrawal with aliases", async () => {
    const decision = {
      dispute: {
        id: "invoice-dispute_1",
        invoiceId: "invoice-1",
        status: "accepted",
        version: 3,
        resolution: {
          outcome: "accepted",
          actorId: "actor-1",
          reference: "resolution://case-1",
          resolvedAt: "2030-01-02T00:00:00.000Z",
        },
      },
      fromStatus: "underReview",
      replayed: false,
    };
    const { client, calls } = clientWith(async (request) => {
      const path = new URL(request.url).pathname;
      const method = request.init.method ?? "GET";
      if (path === "/api/open/v1/billing/invoices/invoice-1/disputes" && method === "GET") {
        return response({ items: [{ id: "invoice-dispute_1", status: "open" }], hasMore: false });
      }
      if (path === "/api/open/v1/billing/disputes/invoice-dispute_1" && method === "GET") {
        return response({ id: "invoice-dispute_1", status: "open" });
      }
      if (path.endsWith("/review")) return response({ ...decision, dispute: { ...decision.dispute, status: "underReview" } });
      if (path.endsWith("/decisions")) return response(decision);
      if (path.endsWith("/withdrawal")) {
        return response({ ...decision, dispute: { ...decision.dispute, status: "withdrawn" } });
      }
      return response({ error: { code: "NOT_FOUND", message: "unknown route" } }, 404);
    });

    const page = await client.billing.disputes.list("invoice-1", { status: "open", limit: 5 });
    assert.deepEqual(page.items.map((item) => item.id), ["invoice-dispute_1"]);
    assert.equal(new URL(calls[0].url).searchParams.get("status"), "open");
    assert.equal(new URL(calls[0].url).searchParams.get("limit"), "5");
    assert.equal(calls[0].init.cache, "no-store");
    const single = await client.billing.disputes.get("invoice-dispute_1");
    assert.equal(single.id, "invoice-dispute_1");
    assert.equal(new URL(calls[1].url).pathname, "/api/open/v1/billing/disputes/invoice-dispute_1");

    const reviewed = await client.billing.disputes.startReview("invoice-1", "invoice-dispute_1");
    assert.equal(reviewed.dispute.status, "underReview");
    assert.equal(reviewed.fromStatus, "underReview");
    assert.equal(calls[2].init.method, "POST");
    assert.equal(
      new URL(calls[2].url).pathname,
      "/api/open/v1/billing/invoices/invoice-1/disputes/invoice-dispute_1/review",
    );
    assert.ok(new Headers(calls[2].init.headers).get("idempotency-key"));
    await client.reviewInvoiceDispute("invoice-1", "invoice-dispute_1", {
      idempotencyKey: "review-1",
    });
    assert.equal(new Headers(calls[3].init.headers).get("idempotency-key"), "review-1");

    const decided = await client.billing.disputes.decide("invoice-1", "invoice-dispute_1", {
      outcome: "accepted",
      reference: "resolution://case-1",
      resolutionNote: "Credit note issued",
    });
    assert.equal(decided.dispute.resolution?.outcome, "accepted");
    assert.equal(
      new URL(calls[4].url).pathname,
      "/api/open/v1/billing/invoices/invoice-1/disputes/invoice-dispute_1/decisions",
    );
    assert.deepEqual(JSON.parse(String(calls[4].init.body)), {
      outcome: "accepted",
      reference: "resolution://case-1",
      resolutionNote: "Credit note issued",
    });
    const aliasDecision = await client.decideInvoiceDispute("invoice-1", "invoice-dispute_1", {
      outcome: "rejected",
      reference: "resolution://case-2",
    });
    assert.equal(aliasDecision.replayed, false);
    assert.equal(JSON.parse(String(calls[5].init.body)).outcome, "rejected");

    const withdrawn = await client.billing.disputes.withdraw("invoice-1", "invoice-dispute_1", {
      reference: "withdrawal://case-1",
    });
    assert.equal(withdrawn.dispute.status, "withdrawn");
    assert.equal(
      new URL(calls[6].url).pathname,
      "/api/open/v1/billing/invoices/invoice-1/disputes/invoice-dispute_1/withdrawal",
    );
    assert.deepEqual(JSON.parse(String(calls[6].init.body)), {
      reference: "withdrawal://case-1",
    });
    await client.withdrawInvoiceDispute("invoice-1", "invoice-dispute_1");
    await client.startInvoiceDisputeReview("invoice-1", "invoice-dispute_1");
    await client.getInvoiceDispute("invoice-dispute_1");
    await client.listInvoiceDisputes("invoice-1", { status: "underReview" });
    assert.equal(calls.length, 11);
    assert.equal(calls.every((call) => call.init.cache === "no-store"), true);

    await assert.rejects(
      client.billing.disputes.get("invoice-dispute 1"),
      (error: unknown) => error instanceof Error,
    );
    await assert.rejects(
      client.billing.disputes.decide("invoice-1", "invoice-dispute_1/secrets", {
        outcome: "accepted",
        reference: "resolution://case-3",
      }),
      (error: unknown) => error instanceof Error,
    );
    await assert.rejects(
      client.billing.disputes.get("invoice-dispute_2"),
      (error: unknown) => {
        assert.ok(error instanceof OpenPlatformApiError);
        assert.equal(error.status, 404);
        assert.equal(error.code, "NOT_FOUND");
        return true;
      },
    );
    assert.equal(calls.length, 12);
  });

  it("exposes compliance list, read, and write routes with idempotency keys", async () => {
    const { client, calls } = clientWith(async (request) => {
      const url = new URL(request.url);
      const path = url.pathname;
      const method = request.init.method ?? "GET";
      if (path.endsWith("/compliance/data-assets") && method === "GET") {
        return url.searchParams.get("cursor") === "asset-next"
          ? response({ items: [{ id: "data-asset-2", code: "orders", status: "active" }], hasMore: false, total: 2 })
          : response({
            items: [{ id: "data-asset-1", code: "orders", status: "draft", subjectRef: "raw-secret" }],
            nextCursor: "asset-next",
            hasMore: true,
            total: 2,
          });
      }
      if (path.endsWith("/compliance/data-assets") && method === "POST") {
        return response({ id: "data-asset-1", code: "orders", status: "draft" }, 201);
      }
      if (path.endsWith("/compliance/data-assets/data-asset-1") && method === "GET") {
        return response({ id: "data-asset-1", code: "orders", status: "active" });
      }
      if (path.endsWith("/compliance/data-assets/data-asset-1") && method === "PATCH") {
        return response({ id: "data-asset-1", code: "orders", status: "active" });
      }
      if (path.endsWith("/compliance/data-assets/data-asset-1/status")) {
        return response({ id: "data-asset-1", code: "orders", status: "registered" }, 201);
      }
      if (path.endsWith("/compliance/consents") && method === "GET") {
        return response({ items: [{ id: "consent-1", subjectRefMasked: "****1234" }], hasMore: false, total: 1 });
      }
      if (path.endsWith("/compliance/consents/consent-1/withdraw")) {
        return response({ id: "consent-1", status: "withdrawn", subjectRefMasked: "****1234" }, 201);
      }
      if (path.endsWith("/compliance/privacy-requests") && method === "GET") {
        return response({ items: [{ id: "privacy-request-1", status: "verified" }], hasMore: false, total: 1 });
      }
      if (path.endsWith("/compliance/privacy-requests/privacy-request-1")) {
        return response({ id: "privacy-request-1", status: "verified", subjectRefMasked: "****1234" });
      }
      if (path.endsWith("/compliance/privacy-requests/privacy-request-1/sla")) {
        return response({ id: "privacy-request-1_sla", requestId: "privacy-request-1", state: "withinSla", millisecondsRemaining: 1000 });
      }
      if (path.endsWith("/compliance/privacy-requests/privacy-request-1/identity-verification")) {
        return response({ id: "privacy-request-1", status: "verified" }, 201);
      }
      if (path.endsWith("/compliance/privacy-requests/privacy-request-1/decision")) {
        return response({ id: "privacy-request-1", status: "fulfilled" }, 201);
      }
      if (path.endsWith("/compliance/privacy-requests/privacy-request-1/actions")) {
        return response({ id: "privacy-request-1", status: "fulfilled" }, 201);
      }
      if (path.endsWith("/compliance/privacy-requests/privacy-request-1/status")) {
        return response({ id: "privacy-request-1", status: "inProgress" }, 201);
      }
      if (path.endsWith("/compliance/retention-policies") && method === "GET") {
        return response({ items: [{ id: "retention-policy-1", code: "orders-90d" }], hasMore: false, total: 1 });
      }
      if (path.endsWith("/compliance/retention-policies/retention-policy-1/status")) {
        return response({ id: "retention-policy-1", status: "active" }, 201);
      }
      if (path.endsWith("/compliance/retention-executions") && method === "GET") {
        return response({ items: [{ id: "retention-execution-1", recordsDeleted: 3 }], hasMore: false, total: 1 });
      }
      if (path.endsWith("/compliance/retention-executions") && method === "POST") {
        return response({ id: "retention-execution-1", status: "completed" }, 201);
      }
      if (path.endsWith("/compliance/cross-border-assessments") && method === "GET") {
        return response({ items: [{ id: "cross-border-1", code: "eu-cn" }], hasMore: false, total: 1 });
      }
      if (path.endsWith("/compliance/cross-border-assessments/cross-border-1")) {
        return response({ id: "cross-border-1", code: "eu-cn", status: "approved" });
      }
      if (path.endsWith("/compliance/cross-border-assessments/cross-border-1/decision")) {
        return response({ id: "cross-border-1", status: "approved" }, 201);
      }
      if (path.endsWith("/compliance/vendors") && method === "GET") {
        return response({ items: [{ id: "vendor-1", code: "host" }], hasMore: false, total: 1 });
      }
      if (path.endsWith("/compliance/vendors/vendor-1/assessments")) {
        return response({ id: "vendor-1", status: "active" }, 201);
      }
      if (path.endsWith("/compliance/report") && method === "GET") {
        return response({ contractVersion: 1, tenantId: "tenant-a", generatedAt: "2026-01-01T00:00:00.000Z" });
      }
      if (path.endsWith("/compliance/report") && method === "POST") {
        return response({ contractVersion: 1, tenantId: "tenant-a", generatedAt: "2026-01-01T00:00:00.000Z" }, 201);
      }
      return response({ error: { code: "OPEN_PLATFORM_COMPLIANCE_RESOURCE_NOT_FOUND" } }, 404);
    });

    const assets = await client.compliance.dataAssets.listAll({ limit: 1 });
    assert.deepEqual(assets.map((item) => item.id), ["data-asset-1", "data-asset-2"]);
    assert.equal(JSON.stringify(assets).includes("raw-secret"), false);
    assert.equal(await client.compliance.dataAssets.get("data-asset-1").then((item) => item.status), "active");
    const createdAsset = await client.compliance.dataAssets.create({
      name: "Orders",
      code: "orders",
      classification: "personal",
      categories: ["identity"],
      personalData: true,
      sensitivePersonalData: false,
      residencyRegions: ["CN"],
      crossBorder: false,
      evidence: [{ reference: "doc://orders-1", kind: "document" }],
    });
    assert.equal(createdAsset.status, "draft");
    await client.compliance.dataAssets.update("data-asset-1", { purposes: ["order fulfilment"] });
    await client.compliance.dataAssets.transitionStatus("data-asset-1", { targetStatus: "registered" });
    const consents = await client.compliance.consents.list({ limit: 10 });
    assert.equal(consents.items[0].subjectRefMasked, "****1234");
    await client.compliance.consents.withdraw("consent-1", { reason: "customer request" });
    const requests = await client.compliance.privacyRequests.list({ status: "verified" });
    assert.equal(requests.items.length, 1);
    await client.compliance.privacyRequests.get("privacy-request-1");
    const sla = await client.compliance.privacyRequests.getSla("privacy-request-1", { at: "2026-01-01T00:00:00.000Z" });
    assert.equal(sla.state, "withinSla");
    await client.compliance.privacyRequests.recordIdentityVerification("privacy-request-1", { status: "verified" });
    await client.compliance.privacyRequests.decide("privacy-request-1", {
      decision: "granted",
      evidence: [{ reference: "ticket://pr-1", kind: "ticket" }],
    });
    await client.compliance.privacyRequests.recordAction("privacy-request-1", {
      action: "erased",
      dataAssetId: "data-asset-1",
    });
    await client.compliance.privacyRequests.transitionStatus("privacy-request-1", { targetStatus: "inProgress" });
    await client.compliance.retentionPolicies.list();
    await client.compliance.retentionPolicies.transitionStatus("retention-policy-1", { targetStatus: "active" });
    await client.compliance.retentionExecutions.list();
    await client.compliance.retentionExecutions.record({ policyId: "retention-policy-1", status: "completed" });
    await client.compliance.crossBorderAssessments.list();
    await client.compliance.crossBorderAssessments.get("cross-border-1");
    await client.compliance.crossBorderAssessments.decide("cross-border-1", { targetStatus: "approved" });
    await client.compliance.vendors.list();
    await client.compliance.vendors.recordAssessment("vendor-1", { status: "passed" });
    const report = await client.compliance.report.get({ from: "2026-01-01T00:00:00.000Z" });
    assert.equal(report.tenantId, "tenant-a");
    const generated = await client.compliance.report.generate({ to: "2026-01-31T00:00:00.000Z" });
    assert.equal(generated.contractVersion, 1);

    assert.equal(client.complianceCatalog, client.compliance);
    assert.equal(client.events, client.domainEvents);
    const paths = calls.map((call) => new URL(call.url).pathname);
    const methods = calls.map((call) => call.init.method ?? "GET");
    assert.deepEqual(paths.slice(0, 6), [
      "/api/open/v1/compliance/data-assets",
      "/api/open/v1/compliance/data-assets",
      "/api/open/v1/compliance/data-assets/data-asset-1",
      "/api/open/v1/compliance/data-assets",
      "/api/open/v1/compliance/data-assets/data-asset-1",
      "/api/open/v1/compliance/data-assets/data-asset-1/status",
    ]);
    assert.deepEqual(methods.slice(0, 6), ["GET", "GET", "GET", "POST", "PATCH", "POST"]);
    assert.equal(paths.includes("/api/open/v1/compliance/consents/consent-1/withdraw"), true);
    assert.equal(paths.includes("/api/open/v1/compliance/privacy-requests/privacy-request-1/sla"), true);
    assert.equal(paths.includes("/api/open/v1/compliance/retention-executions"), true);
    assert.equal(paths.includes("/api/open/v1/compliance/cross-border-assessments/cross-border-1/decision"), true);
    assert.equal(paths.includes("/api/open/v1/compliance/vendors/vendor-1/assessments"), true);
    assert.equal(paths.includes("/api/open/v1/compliance/report"), true);
    assert.equal(calls.every((call) => call.init.cache === "no-store"), true);
    assert.equal(
      calls.filter((call) => (call.init.method ?? "GET") !== "GET")
        .every((call) => new Headers(call.init.headers).has("idempotency-key")),
      true,
    );
    assert.equal(calls.every((call) => new Headers(call.init.headers).get("x-tenant-id") === "tenant-a"), true);
  });

  it("exposes domain event pages and idempotent retry with safe summaries", async () => {
    const { client, calls } = clientWith(async (request) => {
      const url = new URL(request.url);
      const path = url.pathname;
      if (path.endsWith("/domain-events/retry")) return response({
        tenantId: "tenant-a",
        flushed: 1,
        results: [{ eventId: "event-1", delivered: 2, deadLettered: false, payload: "secret-payload" }],
        replayed: false,
        data: "secret-data",
      }, 200);
      if (url.searchParams.get("sequence") === "5" || url.searchParams.get("cursor") === "5") {
        return response({
          tenantId: "tenant-a",
          items: [],
          hasMore: false,
        });
      }
      return response({
        tenantId: "tenant-a",
        items: [
          {
            eventId: "event-1",
            tenantId: "tenant-a",
            type: "application.status_changed",
            resource: { type: "application", id: "app-1" },
            status: "failed",
            attempt: 2,
            occurredAt: "2026-01-01T00:00:00.000Z",
            errorCode: "DELIVERY_FAILED",
            data: { subjectRef: "secret" },
            payload: "secret-payload",
            leaseId: "lease-secret",
            actorId: "actor-secret",
          },
        ],
        nextSequence: 5,
        hasMore: true,
        secret: "secret-value",
      });
    });

    const page = await client.domainEvents.list({ limit: 1, eventType: "application.status_changed" });
    assert.equal(page.tenantId, "tenant-a");
    assert.equal(page.hasMore, true);
    assert.equal(page.nextSequence, 5);
    assert.equal(page.nextCursor, "5");
    assert.equal(page.items.length, 1);
    assert.deepEqual(page.items[0], {
      eventId: "event-1",
      tenantId: "tenant-a",
      type: "application.status_changed",
      resource: { type: "application", id: "app-1" },
      status: "failed",
      attempt: 2,
      occurredAt: "2026-01-01T00:00:00.000Z",
      errorCode: "DELIVERY_FAILED",
    });
    const serialized = JSON.stringify(page);
    for (const leaked of ["secret-payload", "lease-secret", "actor-secret", "secret-value"]) {
      assert.equal(serialized.includes(leaked), false);
    }

    const all = await client.domainEvents.listAll({ limit: 1 });
    assert.equal(all.length, 1);
    assert.equal(new URL(calls[2].url).searchParams.get("cursor"), "5");
    assert.equal(new URL(calls[2].url).searchParams.get("sequence"), null);

    const retry = await client.domainEvents.retry({ eventType: "application.status_changed", limit: 10 });
    assert.equal(retry.flushed, 1);
    assert.equal(retry.replayed, false);
    assert.deepEqual(retry.results, [{ eventId: "event-1", delivered: 2, deadLettered: false }]);
    assert.equal(JSON.stringify(retry).includes("secret-payload"), false);
    const retryCall = calls[calls.length - 1];
    assert.equal(new URL(retryCall.url).pathname, "/api/open/v1/domain-events/retry");
    assert.equal(retryCall.init.method, "POST");
    assert.equal(new Headers(retryCall.init.headers).has("idempotency-key"), true);
    assert.deepEqual(JSON.parse(String(retryCall.init.body)), { eventType: "application.status_changed", limit: 10 });

    const clientRetry = await client.retryDomainEvents({}, { idempotencyKey: "retry-once" });
    assert.equal(clientRetry.flushed, 1);
    assert.equal(new Headers(calls[calls.length - 1].init.headers).get("idempotency-key"), "retry-once");
    assert.equal(calls.every((call) => call.init.cache === "no-store"), true);
  });

  it("rejects unsafe compliance and domain event identifiers before dispatch", async () => {
    const { client, calls } = clientWith(async () => response({}));
    await assert.rejects(
      client.compliance.dataAssets.get("asset id"),
      (error: unknown) => error instanceof Error,
    );
    await assert.rejects(
      client.compliance.consents.get("consent-secret"),
      (error: unknown) => error instanceof Error,
    );
    await assert.rejects(
      client.domainEvents.retry({ idempotencyKey: "" }),
      (error: unknown) => error instanceof Error,
    );
    await assert.rejects(
      client.compliance.dataAssets.create({
        name: "Orders",
        code: "orders",
        classification: "personal",
        categories: ["identity"],
        personalData: true,
        sensitivePersonalData: false,
        residencyRegions: ["CN"],
        crossBorder: false,
        ...{ password: "plaintext" },
      }),
      (error: unknown) => error instanceof Error,
    );
    assert.equal(calls.length, 0);
  });
});
