import { describe, expect, it } from "vitest";
import { run, type CliIO } from "../src/cli.js";
import { createCliIO } from "../src/main.js";
import { EXIT_ENVIRONMENT, EXIT_USAGE } from "../src/ops.js";

interface CapturedRequest {
  url: string;
  init: RequestInit | undefined;
}

function response(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function makeIO(
  handler: (request: CapturedRequest) => Response | Promise<Response>,
  env: NodeJS.ProcessEnv = {
    OPEN_PLATFORM_BASE_URL: "https://api.example.test",
    OPEN_PLATFORM_TENANT_ID: "tenant-cli",
    OPEN_PLATFORM_TOKEN: "access-token-secret",
  },
) {
  const lines: string[] = [];
  const requests: CapturedRequest[] = [];
  const io = {
    cwd: "/tmp/getbrick-cli",
    env,
    log: (line: string) => lines.push(line),
    runMigrate: () => 0,
    openPlatformFetch: async (input: string, init?: RequestInit) => {
      const request = { url: input, init };
      requests.push(request);
      return handler(request);
    },
  } satisfies CliIO;
  return { io, lines, requests };
}

describe("getbrick open-platform cli", () => {
  it("routes the SDK resources and accepts global equals flags and JSON output", async () => {
    const { io, lines, requests } = makeIO((request) => {
      const path = new URL(request.url).pathname;
      if (path.endsWith("/applications") && request.init?.method === "GET") {
        return response({ items: [{ id: "app-1", name: "Orders" }], hasMore: false });
      }
      if (path.endsWith("/applications/app-1")) return response({ id: "app-1", name: "Orders", status: "draft" });
      if (path.endsWith("/applications/app-1/publish")) return response({ id: "app-1", status: "published" });
      if (path.endsWith("/catalog/products")) return response({ items: [{ id: "product-1" }], hasMore: false });
      if (path.endsWith("/credentials")) return response({ items: [{ id: "credential-1" }], hasMore: false });
      if (path.endsWith("/credentials/credential-1/rotate")) {
        return response({
          credential: { id: "credential-2" },
          previousCredential: { id: "credential-1" },
          secret: "rotated-secret",
        });
      }
      if (path.endsWith("/credentials/credential-1/revoke")) return response({ id: "credential-1", status: "archived" });
      if (path.endsWith("/usage")) return response({ items: [{ id: "usage-1" }], hasMore: false });
      return response({ items: [{ id: "subscription-1" }], hasMore: false });
    });

    const commands = [
      ["open-platform", "--base-url=https://api.example.test", "--tenant=tenant-cli", "--json", "app:list", "--limit=10"],
      ["open-platform", "app:get", "app-1", "--base-url", "https://api.example.test", "--tenant", "tenant-cli"],
      ["open-platform", "app:publish", "--application-id=app-1", "--tenant", "tenant-cli", "--base-url=https://api.example.test"],
      ["open-platform", "catalog:list", "--base-url=https://api.example.test", "--tenant=tenant-cli", "--json"],
      ["open-platform", "credential:list", "--base-url=https://api.example.test", "--tenant=tenant-cli", "--json"],
      ["open-platform", "credential:rotate", "credential-1", "--base-url=https://api.example.test", "--tenant=tenant-cli", "--json"],
      ["open-platform", "credential:revoke", "--credential-id=credential-1", "--base-url=https://api.example.test", "--tenant=tenant-cli"],
      ["open-platform", "usage:list", "--base-url=https://api.example.test", "--tenant=tenant-cli", "--json"],
      ["open-platform", "subscription:list", "--base-url=https://api.example.test", "--tenant=tenant-cli", "--json"],
    ];

    for (const command of commands) {
      expect(await run(command, io)).toBe(0);
    }

    expect(requests.map((request) => new URL(request.url).pathname)).toEqual([
      "/api/open/v1/applications",
      "/api/open/v1/applications/app-1",
      "/api/open/v1/applications/app-1/publish",
      "/api/open/v1/catalog/products",
      "/api/open/v1/credentials",
      "/api/open/v1/credentials/credential-1/rotate",
      "/api/open/v1/credentials/credential-1/revoke",
      "/api/open/v1/usage",
      "/api/open/v1/subscriptions",
    ]);
    expect(new URL(requests[0].url).searchParams.get("limit")).toBe("10");
    expect(new Headers(requests[0].init?.headers).get("x-tenant-id")).toBe("tenant-cli");
    expect(new Headers(requests[0].init?.headers).get("authorization")).toBe("Bearer access-token-secret");
    expect(lines.join("\n")).not.toContain("access-token-secret");
    expect(lines.join("\n")).not.toContain("Authorization");
    expect(lines.join("\n")).not.toContain("Idempotency-Key");
  });

  it("uses environment exit code 78 and does not construct a request when configuration is missing", async () => {
    const { io, lines, requests } = makeIO(() => response({}), {});
    expect(await run(["open-platform", "app:list"], io)).toBe(EXIT_ENVIRONMENT);
    expect(requests).toHaveLength(0);
    expect(lines.join("\n")).toContain("OPEN_PLATFORM_BASE_URL");
    expect(lines.join("\n")).not.toContain("access-token-secret");
  });

  it("rejects duplicate, missing, and unknown open-platform arguments", async () => {
    const { io, lines } = makeIO(() => response({ items: [], hasMore: false }));
    expect(await run(["open-platform", "app:list", "--base-url=https://a.test", "--base-url=https://b.test"], io)).toBe(EXIT_USAGE);
    expect(await run(["open-platform", "app:list", "--json", "--json"], io)).toBe(EXIT_USAGE);
    expect(await run(["open-platform", "app:get"], io)).toBe(EXIT_USAGE);
    expect(await run(["open-platform", "app:list", "--unknown=value"], io)).toBe(EXIT_USAGE);
    expect(lines.some((line) => line.includes("may only be specified once"))).toBe(true);
    expect(lines.some((line) => line.includes("unknown argument"))).toBe(true);
  });

  it("reveals a rotated credential secret once and strips secrets from other responses", async () => {
    const secret = "one-time-credential-secret";
    const { io, lines } = makeIO((request) => {
      const path = new URL(request.url).pathname;
      if (path.endsWith("/rotate")) {
        return response({
          credential: { id: "credential-2", secret: `${secret}-duplicate` },
          previousCredential: { id: "credential-1" },
          secret,
        });
      }
      return response({ items: [{ id: "credential-1", secret }], hasMore: false });
    });

    expect(await run([
      "open-platform",
      "credential:rotate",
      "credential-1",
      "--base-url=https://api.example.test",
      "--tenant=tenant-cli",
      "--json",
    ], io)).toBe(0);
    expect(lines.join("\n").match(new RegExp(secret, "gu"))).toHaveLength(1);

    lines.length = 0;
    expect(await run([
      "open-platform",
      "credential:list",
      "--base-url=https://api.example.test",
      "--tenant=tenant-cli",
      "--json",
    ], io)).toBe(0);
    expect(lines.join("\n")).not.toContain(secret);
  });

  it("maps API failures to a safe exit code without exposing response secrets", async () => {
    const token = "error-token-secret";
    const { io, lines } = makeIO(() => response({
      error: {
        code: "INTERNAL_ERROR",
        message: `Bearer ${token}`,
        authorization: token,
        idempotencyKey: "private-idempotency-key",
      },
    }, 500));

    expect(await run([
      "open-platform",
      "app:list",
      "--base-url=https://api.example.test",
      "--tenant=tenant-cli",
      "--json",
    ], io)).toBe(1);
    const output = lines.join("\n");
    expect(output).toContain("INTERNAL_ERROR");
    expect(output).not.toContain(token);
    expect(output).not.toContain("private-idempotency-key");
    expect(output).not.toContain("Authorization");
  });

  it("routes commerce, billing, audit, and safe webhook commands", async () => {
    const responseSecret = "webhook-response-secret-0123456789";
    const { io, lines, requests } = makeIO((request) => {
      const path = new URL(request.url).pathname;
      const method = request.init?.method ?? "GET";
      if (path.endsWith("/webhooks") && method === "GET") return response({ items: [{ id: "webhook-1", secret: responseSecret }], hasMore: false });
      if (path.endsWith("/webhooks/webhook-1/test") && method === "POST") {
        return response({ delivery: { id: "delivery-1", eventId: "event-1", eventType: "application.status_changed" }, deliveries: [], attempts: 1, duplicate: false, deadLettered: false, secret: responseSecret });
      }
      if (path.endsWith("/audit-events")) return response({ items: [{ id: "audit-1" }], hasMore: false });
      if (path.endsWith("/marketplace/listings") && method === "GET") return response({ items: [{ id: "listing-1" }], hasMore: false });
      if (path.endsWith("/marketplace/listings/listing-1")) return response({ id: "listing-1", status: "published" });
      if (path.endsWith("/billing/invoices") && method === "GET") return response({ items: [{ id: "invoice-1", total: { amountMinor: "100", currency: "CNY" } }], hasMore: false });
      if (path.endsWith("/billing/invoices/invoice-1")) return response({ id: "invoice-1", total: { amountMinor: "100", currency: "CNY" } });
      return response({});
    });

    const commands = [
      ["open-platform", "webhook:list", "--limit=5", "--json"],
      ["open-platform", "webhook:test", "webhook-1", "--event-id", "event-1", "--event-type", "application.status_changed", "--json"],
      ["open-platform", "audit:list", "--action", "webhook.dispatch", "--json"],
      ["open-platform", "marketplace:list", "--status=published", "--json"],
      ["open-platform", "marketplace:get", "listing-1", "--json"],
      ["open-platform", "billing:invoices", "--limit=5", "--json"],
      ["open-platform", "billing:invoice", "invoice-1", "--json"],
    ];
    for (const command of commands) expect(await run(command, io)).toBe(0);

    expect(requests.map((request) => new URL(request.url).pathname)).toEqual([
      "/api/open/v1/webhooks",
      "/api/open/v1/webhooks/webhook-1/test",
      "/api/open/v1/audit-events",
      "/api/open/v1/marketplace/listings",
      "/api/open/v1/marketplace/listings/listing-1",
      "/api/open/v1/billing/invoices",
      "/api/open/v1/billing/invoices/invoice-1",
    ]);
    expect(new URL(requests[0].url).searchParams.get("limit")).toBe("5");
    expect(new URL(requests[2].url).searchParams.get("action")).toBe("webhook.dispatch");
    expect(new URL(requests[3].url).searchParams.get("status")).toBe("published");
    expect(requests[1].init?.method).toBe("POST");
    expect(new Headers(requests[1].init?.headers).get("idempotency-key")).toBeTruthy();
    expect(requests.every((request) => request.init?.cache === "no-store")).toBe(true);
    expect(lines.join("\n")).not.toContain(responseSecret);
    expect(lines.join("\n")).not.toContain("access-token-secret");
  });

  it("rejects unsafe webhook test event types and identifiers before dispatch", async () => {
    const { io, lines, requests } = makeIO(() => response({}));
    const invalidType = await run([
      "open-platform",
      "webhook:test",
      "webhook-1",
      "--event-id",
      "event-1",
      "--event-type",
      "secret.payload",
      "--json",
    ], io);
    expect(invalidType).toBe(EXIT_USAGE);
    const invalidId = await run([
      "open-platform",
      "webhook:test",
      "webhook-1",
      "--event-id",
      "secret-event-value",
      "--event-type",
      "application.status_changed",
    ], io);
    expect(invalidId).toBe(EXIT_USAGE);
    expect(requests).toHaveLength(0);
    expect(lines.join("\n")).not.toContain("secret-event-value");
  });

  it("routes invoice dispute reads and adjudication writes", async () => {
    const { io, lines, requests } = makeIO((request) => {
      const path = new URL(request.url).pathname;
      const method = request.init?.method ?? "GET";
      if (path.endsWith("/billing/invoices/invoice-1/disputes") && method === "GET") {
        return response({ items: [{ id: "invoice-dispute-1", status: "open" }], hasMore: false });
      }
      if (path.endsWith("/billing/disputes/invoice-dispute-1") && method === "GET") {
        return response({ id: "invoice-dispute-1", status: "open" });
      }
      if (path.endsWith("/review")) {
        return response({ dispute: { id: "invoice-dispute-1", status: "underReview" }, fromStatus: "open", replayed: false });
      }
      if (path.endsWith("/decisions")) {
        return response({ dispute: { id: "invoice-dispute-1", status: "accepted" }, fromStatus: "underReview", replayed: false });
      }
      if (path.endsWith("/withdrawal")) {
        return response({ dispute: { id: "invoice-dispute-1", status: "withdrawn" }, fromStatus: "open", replayed: false });
      }
      return response({});
    });

    const commands = [
      ["open-platform", "billing:disputes:list", "invoice-1", "--status", "open", "--limit=5", "--json"],
      ["open-platform", "billing:disputes:get", "invoice-dispute-1", "--json"],
      ["open-platform", "billing:disputes:review", "invoice-dispute-1", "--invoice-id", "invoice-1", "--idempotency-key", "review-1", "--json"],
      ["open-platform", "billing:disputes:decide", "invoice-dispute-1", "--invoice-id", "invoice-1", "--outcome", "accepted", "--reference", "resolution://case-1", "--note", "credit issued", "--json"],
      ["open-platform", "billing:disputes:withdraw", "invoice-dispute-1", "--invoice-id", "invoice-1", "--reference", "withdrawal://case-1", "--json"],
    ];
    for (const command of commands) expect(await run(command, io)).toBe(0);

    expect(requests.map((request) => new URL(request.url).pathname)).toEqual([
      "/api/open/v1/billing/invoices/invoice-1/disputes",
      "/api/open/v1/billing/disputes/invoice-dispute-1",
      "/api/open/v1/billing/invoices/invoice-1/disputes/invoice-dispute-1/review",
      "/api/open/v1/billing/invoices/invoice-1/disputes/invoice-dispute-1/decisions",
      "/api/open/v1/billing/invoices/invoice-1/disputes/invoice-dispute-1/withdrawal",
    ]);
    expect(new URL(requests[0].url).searchParams.get("status")).toBe("open");
    expect(new URL(requests[0].url).searchParams.get("limit")).toBe("5");
    expect(requests.map((request) => request.init?.method)).toEqual([
      "GET",
      "GET",
      "POST",
      "POST",
      "POST",
    ]);
    expect(new Headers(requests[2].init?.headers).get("idempotency-key")).toBe("review-1");
    expect(JSON.parse(String(requests[3].init?.body))).toEqual({
      outcome: "accepted",
      reference: "resolution://case-1",
      resolutionNote: "credit issued",
    });
    expect(JSON.parse(String(requests[4].init?.body))).toEqual({
      reference: "withdrawal://case-1",
    });
    expect(requests.every((request) => request.init?.cache === "no-store")).toBe(true);
    const output = lines.join("\n");
    expect(output).toContain("invoice-dispute-1");
    expect(output).not.toContain("access-token-secret");
  });

  it("validates invoice dispute arguments and prints the command help", async () => {
    const { io, lines, requests } = makeIO(() => response({}));
    const usage = [
      ["open-platform", "billing:disputes:list"],
      ["open-platform", "billing:disputes:get"],
      ["open-platform", "billing:disputes:review", "invoice-dispute-1"],
      ["open-platform", "billing:disputes:decide", "invoice-dispute-1", "--invoice-id", "invoice-1", "--outcome", "unknown", "--reference", "resolution://case-1"],
      ["open-platform", "billing:disputes:decide", "invoice-dispute-1", "--invoice-id", "invoice-1", "--outcome", "accepted"],
      ["open-platform", "billing:disputes:withdraw", "invoice-dispute-1", "--invoice-id", "invoice-1"],
      ["open-platform", "billing:disputes:review", "invoice-dispute-1", "--invoice-id", "invoice-1", "--outcome", "accepted"],
      ["open-platform", "billing:disputes:list", "invoice-1", "--status", "unknown"],
      ["open-platform", "billing:disputes:list", "invoice-1", "--invoice-id", "invoice-2"],
      ["open-platform", "billing:disputes:get", "invoice-dispute-1", "--invoice-id", "invoice-1"],
      ["open-platform", "billing:disputes:review", "invoice-dispute-1", "--invoice-id", "invoice-1", "--note", "note text"],
      ["open-platform", "billing:disputes:decide", "invoice-dispute-1", "--invoice-id", "invoice-1", "--outcome", "accepted", "--reference", "resolution://case-1", "--note", "n".repeat(501)],
      ["open-platform", "billing:disputes:decide", "invoice-dispute-1", "--invoice-id", "invoice-1", "--outcome", "accepted", "--reference", "bad reference", "--json"],
    ];
    for (const command of usage) expect(await run(command, io)).toBe(EXIT_USAGE);
    expect(requests).toHaveLength(0);
    const output = lines.join("\n");
    expect(output).toContain("invoice id is required");
    expect(output).toContain("invoice dispute id is required");
    expect(output).toContain("--outcome is invalid");
    expect(output).toContain("--reference is required");
    expect(output).toContain("unknown argument");
    expect(output).toContain("--status has an invalid value");
    expect(output).toContain("use either a positional invoice id or --invoice-id, not both");
    expect(output).toContain("--invoice-id is not valid for a dispute read");
    expect(output).toContain("--note has an invalid value");
    expect(output).toContain("getbrick open-platform billing:disputes:decide");
    expect(output).toContain("getbrick open-platform billing:disputes:withdraw");
    expect(output).toContain("getbrick open-platform billing:disputes:list");
    expect(output).toContain("getbrick open-platform billing:disputes:review");
    expect(output).toContain("getbrick open-platform billing:disputes:get");
  });

  it("supports the main IO fetch injection seam", async () => {
    const calls: string[] = [];
    const io = createCliIO(
      "/tmp/getbrick-cli",
      {
        OPEN_PLATFORM_BASE_URL: "https://api.example.test",
        OPEN_PLATFORM_TENANT_ID: "tenant-cli",
        OPEN_PLATFORM_TOKEN: "access-token-secret",
      },
      undefined,
      async (input) => {
        calls.push(input);
        return response({ items: [], hasMore: false });
      },
    );
    const lines: string[] = [];
    io.log = (line) => lines.push(line);
    expect(await run(["open-platform", "app:list", "--json"], io)).toBe(0);
    expect(calls).toEqual(["https://api.example.test/api/open/v1/applications"]);
    expect(lines.join("\n")).not.toContain("access-token-secret");
  });

  it("routes compliance reads with tenant headers, masked subjects, and no-store caching", async () => {
    const { io, lines, requests } = makeIO((request) => {
      const path = new URL(request.url).pathname;
      if (path.endsWith("/compliance/data-assets") && request.init?.method === "GET") {
        return response({ items: [{ id: "asset-1", code: "orders", subjectRef: "raw-secret" }], hasMore: false, total: 1 });
      }
      if (path.endsWith("/compliance/data-assets/asset-1")) {
        return response({ id: "asset-1", code: "orders", status: "active" });
      }
      if (path.endsWith("/compliance/privacy-requests") && request.init?.method === "GET") {
        return response({ items: [{ id: "privacy-request-1", subjectRefMasked: "****1234" }], hasMore: false, total: 1 });
      }
      if (path.endsWith("/compliance/privacy-requests/privacy-request-1/sla")) {
        return response({ id: "privacy-request-1_sla", requestId: "privacy-request-1", state: "withinSla", millisecondsRemaining: 60000 });
      }
      if (path.endsWith("/compliance/privacy-requests/privacy-request-1")) {
        return response({ id: "privacy-request-1", subjectRefMasked: "****1234", status: "verified" });
      }
      if (path.endsWith("/compliance/report")) {
        return response({ contractVersion: 1, tenantId: "tenant-cli", generatedAt: "2026-01-01T00:00:00.000Z", redaction: { placeholder: "[redacted]", applies: true } });
      }
      return response({});
    });

    const commands = [
      ["open-platform", "compliance:data-assets", "--status=draft", "--limit=5", "--json"],
      ["open-platform", "compliance:data-assets", "asset-1", "--json"],
      ["open-platform", "compliance:privacy-requests", "--limit=5", "--json"],
      ["open-platform", "compliance:privacy-requests", "privacy-request-1", "--sla", "--at=2026-02-01T00:00:00.000Z", "--json"],
      ["open-platform", "compliance:privacy-requests", "--id=privacy-request-1", "--json"],
      ["open-platform", "compliance:report", "--from=2026-01-01T00:00:00.000Z", "--json"],
    ];
    for (const command of commands) expect(await run(command, io)).toBe(0);

    expect(requests.map((request) => new URL(request.url).pathname)).toEqual([
      "/api/open/v1/compliance/data-assets",
      "/api/open/v1/compliance/data-assets/asset-1",
      "/api/open/v1/compliance/privacy-requests",
      "/api/open/v1/compliance/privacy-requests/privacy-request-1/sla",
      "/api/open/v1/compliance/privacy-requests/privacy-request-1",
      "/api/open/v1/compliance/report",
    ]);
    const listUrl = new URL(requests[0].url);
    expect(listUrl.searchParams.get("status")).toBe("draft");
    expect(listUrl.searchParams.get("limit")).toBe("5");
    expect(new URL(requests[1].url).searchParams.get("status")).toBeNull();
    expect(new URL(requests[3].url).searchParams.get("at")).toBe("2026-02-01T00:00:00.000Z");
    expect(new URL(requests[5].url).searchParams.get("from")).toBe("2026-01-01T00:00:00.000Z");
    expect(requests.every((request) => request.init?.method === "GET")).toBe(true);
    expect(requests.every((request) => request.init?.cache === "no-store")).toBe(true);
    expect(new Headers(requests[0].init?.headers).get("x-tenant-id")).toBe("tenant-cli");
    const output = lines.join("\n");
    expect(output).toContain("****1234");
    expect(output).not.toContain("raw-secret");
    expect(output).not.toContain("access-token-secret");
  });

  it("generates the compliance report only with idempotency keys", async () => {
    const { io, lines, requests } = makeIO((request) => {
      const path = new URL(request.url).pathname;
      if (request.init?.method === "POST") {
        return response({ contractVersion: 1, tenantId: "tenant-cli", generatedAt: "2026-01-01T00:00:00.000Z" }, 201);
      }
      expect(path).toBe("/api/open/v1/compliance/report");
      return response({ contractVersion: 1, tenantId: "tenant-cli", generatedAt: "2026-01-01T00:00:00.000Z" });
    });

    expect(await run([
      "open-platform",
      "compliance:report",
      "--generate",
      "--to=2026-01-31T00:00:00.000Z",
      "--json",
    ], io)).toBe(0);
    const generated = requests[requests.length - 1];
    expect(generated.init?.method).toBe("POST");
    expect(new Headers(generated.init?.headers).has("idempotency-key")).toBe(true);
    expect(JSON.parse(String(generated.init?.body))).toEqual({ to: "2026-01-31T00:00:00.000Z" });

    expect(await run([
      "open-platform",
      "compliance:report",
      "--generate",
      "--idempotency-key=report-run-1",
      "--json",
    ], io)).toBe(0);
    const replay = requests[requests.length - 1];
    expect(new Headers(replay.init?.headers).get("idempotency-key")).toBe("report-run-1");

    expect(await run([
      "open-platform",
      "compliance:report",
      "--idempotency-key=report-run-1",
    ], io)).toBe(EXIT_USAGE);
    expect(lines.join("\n")).toContain("only valid with --generate");
    expect(lines.join("\n")).not.toContain("Idempotency-Key");
  });

  it("routes domain event listing and retry with whitelisted event types", async () => {
    const { io, lines, requests } = makeIO((request) => {
      const path = new URL(request.url).pathname;
      if (path.endsWith("/domain-events/retry")) {
        return response({
          tenantId: "tenant-cli",
          flushed: 1,
          results: [{ eventId: "event-1", delivered: 2, deadLettered: false, data: "raw-secret" }],
          replayed: false,
        });
      }
      return response({
        tenantId: "tenant-cli",
        items: [
          {
            eventId: "event-1",
            tenantId: "tenant-cli",
            type: "credential.status_changed",
            resource: { type: "credential", id: "credential-1" },
            status: "failed",
            attempt: 1,
            occurredAt: "2026-01-01T00:00:00.000Z",
            payload: "raw-secret",
          },
        ],
        hasMore: false,
      });
    });

    expect(await run([
      "open-platform",
      "events:list",
      "--event-type=credential.status_changed",
      "--status=failed",
      "--limit=5",
      "--json",
    ], io)).toBe(0);
    const listUrl = new URL(requests[0].url);
    expect(listUrl.pathname).toBe("/api/open/v1/domain-events");
    expect(listUrl.searchParams.get("eventType")).toBe("credential.status_changed");
    expect(listUrl.searchParams.get("status")).toBe("failed");
    expect(listUrl.searchParams.get("limit")).toBe("5");

    expect(await run([
      "open-platform",
      "events:retry",
      "--event-type=usage.threshold_reached",
      "--limit=10",
      "--json",
    ], io)).toBe(0);
    const retry = requests[requests.length - 1];
    expect(new URL(retry.url).pathname).toBe("/api/open/v1/domain-events/retry");
    expect(retry.init?.method).toBe("POST");
    expect(new Headers(retry.init?.headers).has("idempotency-key")).toBe(true);
    expect(JSON.parse(String(retry.init?.body))).toEqual({ eventType: "usage.threshold_reached", limit: 10 });
    expect(requests.every((request) => request.init?.cache === "no-store")).toBe(true);
    const output = lines.join("\n");
    expect(output).toContain("event-1");
    expect(output).not.toContain("raw-secret");
    expect(output).not.toContain("access-token-secret");
  });

  it("rejects unsafe domain event types, arbitrary sql or url inputs, and unknown options", async () => {
    const { io, lines, requests } = makeIO(() => response({ items: [], hasMore: false }));
    const rejected = [
      ["open-platform", "events:list", "--event-type=secret.payload"],
      ["open-platform", "events:list", "--status=not-a-status"],
      ["open-platform", "events:list", "--sequence=-1"],
      ["open-platform", "events:list", "--cursor=next-1", "--sequence=2"],
      ["open-platform", "events:retry", "--event-type=DELETE FROM events"],
      ["open-platform", "events:retry", "--url=https://evil.example.test/hook"],
      ["open-platform", "events:retry", "--sql=UPDATE domain_events SET status='published'"],
      ["open-platform", "events:retry", "--idempotency-key=secret-key-value"],
      ["open-platform", "events:retry", "--page-size=10"],      ["open-platform", "compliance:data-assets", "--id=asset-1", "--status=draft"],
      ["open-platform", "compliance:privacy-requests", "--sla"],
      ["open-platform", "compliance:privacy-requests", "--at=2026-02-01T00:00:00.000Z"],
      ["open-platform", "compliance:privacy-requests", "privacy-request-1", "--at=2026-02-01T00:00:00.000Z"],
      ["open-platform", "compliance:report", "--generate=maybe"],
    ];
    for (const command of rejected) {
      expect(await run(command, io)).toBe(EXIT_USAGE);
    }
    expect(requests).toHaveLength(0);
    const output = lines.join("\n");
    expect(output).toContain("event type is invalid");
    expect(output).toContain("not valid with --id");
    expect(output).toContain("unknown argument");
    expect(output).not.toContain("access-token-secret");
  });

  it("keeps the webhook test command bound to the contract event catalog", async () => {
    const { io, requests } = makeIO((request) => {
      expect(new URL(request.url).pathname).toBe("/api/open/v1/webhooks/webhook-1/test");
      return response({
        delivery: { id: "delivery-1", eventId: "event-1", eventType: "tenant.created" },
        deliveries: [],
        attempts: 1,
        duplicate: false,
        deadLettered: false,
      });
    });
    expect(await run([
      "open-platform",
      "webhook:test",
      "webhook-1",
      "--event-id=event-1",
      "--event-type=tenant.created",
      "--json",
    ], io)).toBe(0);
    expect(JSON.parse(String(requests[0].init?.body))).toEqual({
      eventId: "event-1",
      eventType: "tenant.created",
    });
  });

  it("maps compliance and domain event failures to safe exit codes", async () => {
    const { io, lines } = makeIO(() => response({
      error: {
        code: "OPEN_PLATFORM_COMPLIANCE_TENANT_MISMATCH",
        message: "Bearer access-token-secret",
        idempotencyKey: "private-idempotency-key",
      },
    }, 403));
    expect(await run([
      "open-platform",
      "compliance:privacy-requests",
      "--json",
    ], io)).toBe(1);
    expect(await run([
      "open-platform",
      "events:retry",
      "--json",
    ], io)).toBe(1);
    const output = lines.join("\n");
    expect(output).toContain("OPEN_PLATFORM_COMPLIANCE_TENANT_MISMATCH");
    expect(output).toContain("open platform access was denied");
    expect(output).not.toContain("access-token-secret");
    expect(output).not.toContain("private-idempotency-key");
  });
});
