import "reflect-metadata";
import { randomUUID } from "node:crypto";
import { Test } from "@nestjs/testing";
import request from "supertest";
import { describe, expect, it } from "vitest";
import {
  createOpenPlatformRequestContextIssuer,
  OpenPlatformCommerceModule,
  OPEN_PLATFORM_HTTP_BASE_PATH,
  toOpenPlatformHttpError,
  type OpenPlatformHttpRequest,
} from "../src/open-platform/index.js";
import {
  CommerceDomainService,
  InMemoryCommerceRepositories,
  commerceResourceNotFound,
} from "../src/open-platform/commerce/index.js";

const now = new Date("2030-02-15T00:00:00.000Z");
const periodStart = "2030-02-01T00:00:00.000Z";
const periodEnd = "2030-03-01T00:00:00.000Z";
const tenantId = "tenant-commerce-http";
const actorId = "actor-commerce-http";

async function createFixture() {
  const repositories = new InMemoryCommerceRepositories();
  const service = new CommerceDomainService({
    repositories,
    clock: () => now,
  });
  const partner = await service.createPartnerAccount({
    tenantId,
    legalName: "伙伴结算主体",
    partnerCode: "partner-http",
    settlementReference: "settlement://private-bank-account-123456",
  });
  await service.transition({
    tenantId,
    resource: "partnerAccount",
    id: partner.id,
    targetStatus: "underReview",
  });
  await service.transition({
    tenantId,
    resource: "partnerAccount",
    id: partner.id,
    targetStatus: "active",
  });
  const listing = await service.createMarketplaceListing({
    tenantId,
    partnerAccountId: partner.id,
    productId: `product_${randomUUID()}`,
    title: "HTTP market listing",
    description: "Listing used by commerce HTTP tests",
  });
  await service.transition({
    tenantId,
    resource: "marketplaceListing",
    id: listing.id,
    targetStatus: "pendingReview",
  });
  await service.transition({
    tenantId,
    resource: "marketplaceListing",
    id: listing.id,
    targetStatus: "published",
  });
  const price = await service.createPrice({
    tenantId,
    code: "http-fixed-price",
    name: "HTTP fixed price",
    priceType: "fixed",
    fixedAmount: { amountMinor: 12345, currency: "CNY" },
    effectiveFrom: periodStart,
  });
  await service.transition({
    tenantId,
    resource: "price",
    id: price.id,
    targetStatus: "active",
  });
  const plan = await service.createPlan({
    tenantId,
    code: "http-plan",
    name: "HTTP plan",
    priceIds: [price.id],
    effectiveFrom: periodStart,
  });
  await service.transition({
    tenantId,
    resource: "plan",
    id: plan.id,
    targetStatus: "active",
  });
  const subscription = await service.createSubscription({
    tenantId,
    applicationId: `app_${randomUUID()}`,
    planId: plan.id,
    name: "HTTP subscription",
    currentPeriodStart: periodStart,
    currentPeriodEnd: periodEnd,
  });
  await service.transition({
    tenantId,
    resource: "subscription",
    id: subscription.id,
    targetStatus: "active",
  });
  const generated = await service.generateInvoice({
    tenantId,
    subscriptionId: subscription.id,
    periodStart,
    periodEnd,
    idempotencyKey: "http-invoice-generate",
    taxRateBps: 600,
    taxMode: "exclusive",
    mainlandChina: {
      invoiceType: "vatSpecial",
      buyerName: "大陆发票主体",
      unifiedSocialCreditCode: "91310000MA1FL0000X",
      buyerBankName: "测试银行",
      buyerBankAccount: "6222021234567890123",
      buyerPhone: "13800138000",
      taxRateBps: 600,
      issueMode: "platform",
      invoiceCode: "0123456789",
      invoiceNumber: "12345678",
    },
  });
  return { repositories, service, partner, listing, invoice: generated.invoice };
}

async function createApp(service: CommerceDomainService) {
  const issuer = createOpenPlatformRequestContextIssuer({
    issuerId: "commerce-http-tests",
    attestation: Object.freeze({ test: true }),
    clock: () => now,
  });
  const moduleRef = await Test.createTestingModule({
    imports: [
      OpenPlatformCommerceModule.forRoot({
        service,
        mode: "test",
        contextIssuer: issuer,
        resolver: {
          resolve: (httpRequest: OpenPlatformHttpRequest) => {
            const headers = httpRequest.headers ?? {};
            const authenticated = Object.entries(headers).some(
              ([key, value]) => key.toLowerCase() === "x-commerce-auth" && value === "valid",
            );
            return authenticated
              ? { tenantId, actorId, requestId: "commerce-request" }
              : undefined;
          },
        },
      }),
    ],
  }).compile();
  const app = moduleRef.createNestApplication();
  await app.init();
  return app;
}

function authenticated<T extends { set: (name: string, value: string) => T }>(value: T): T {
  return value.set("x-commerce-auth", "valid");
}

describe("open platform commerce HTTP", () => {
  it("paginates tenant-scoped reads and redacts financial metadata", async () => {
    const fixture = await createFixture();
    const app = await createApp(fixture.service);
    const server = app.getHttpServer();
    const first = await authenticated(
      request(server).get(`${OPEN_PLATFORM_HTTP_BASE_PATH}/marketplace/listings?limit=1`),
    );
    expect(first.status).toBe(200);
    expect(first.headers["cache-control"]).toBe("no-store");
    expect(first.body.items).toHaveLength(1);
    expect(first.body.hasMore).toBe(false);
    const partner = await authenticated(
      request(server).get(`${OPEN_PLATFORM_HTTP_BASE_PATH}/partners/${fixture.partner.id}`),
    );
    expect(partner.status).toBe(200);
    expect(JSON.stringify(partner.body)).not.toContain("private-bank-account-123456");
    const invoice = await authenticated(
      request(server).get(`${OPEN_PLATFORM_HTTP_BASE_PATH}/billing/invoices/${fixture.invoice.id}`),
    );
    expect(invoice.status).toBe(200);
    expect(invoice.body.total.amountMinor).toBe(13086);
    expect(JSON.stringify(invoice.body)).not.toContain("6222021234567890123");
    expect(invoice.body.mainlandChina.buyerBankAccount).toMatch(/^\*{4}/u);
    expect(invoice.body).not.toHaveProperty("requestHash");
    expect(invoice.body).not.toHaveProperty("idempotencyKey");
    const mismatch = await authenticated(
      request(server).get(`${OPEN_PLATFORM_HTTP_BASE_PATH}/marketplace/listings?tenantId=tenant-other`),
    );
    expect(mismatch.status).toBe(403);
    expect(mismatch.body.code).toBe("OPEN_PLATFORM_TENANT_MISMATCH");
    await app.close();
  });

  it("keeps service pagination cursors tenant and filter scoped", async () => {
    const fixture = await createFixture();
    const otherPartner = await fixture.service.createPartnerAccount({
      tenantId: "tenant-commerce-other",
      legalName: "其他租户伙伴",
      partnerCode: "partner-other",
      settlementReference: "settlement://other",
    });
    const otherTenantListing = await fixture.service.createMarketplaceListing({
      tenantId: "tenant-commerce-other",
      partnerAccountId: otherPartner.id,
      productId: `product_${randomUUID()}`,
      title: "Other tenant listing",
      description: "Must not appear in the first tenant page",
    });
    await fixture.service.createMarketplaceListing({
      tenantId: fixture.partner.tenantId,
      partnerAccountId: fixture.partner.id,
      productId: `product_${randomUUID()}`,
      title: "Second tenant listing",
      description: "Second page",
    });
    const first = await fixture.service.listMarketplaceListings({
      tenantId: fixture.partner.tenantId,
      limit: 1,
    });
    expect(first.items).toHaveLength(1);
    expect(first.items[0]?.id).not.toBe(otherTenantListing.id);
    expect(first.hasMore).toBe(true);
    expect(first.nextCursor).toEqual(expect.any(String));
    const second = await fixture.service.listMarketplaceListings({
      tenantId: fixture.partner.tenantId,
      limit: 1,
      cursor: first.nextCursor,
    });
    expect(second.items).toHaveLength(1);
    expect(second.items[0]?.id).not.toBe(first.items[0]?.id);
    await expect(fixture.service.listMarketplaceListings({
      tenantId: fixture.partner.tenantId,
      limit: 1,
      cursor: first.nextCursor,
      status: "draft",
    })).rejects.toMatchObject({
      code: "OPEN_PLATFORM_COMMERCE_VALIDATION_ERROR",
    });
  });

  it("rejects invalid mainland invoice metadata without echoing values", async () => {
    const fixture = await createFixture();
    await expect(fixture.service.generateInvoice({
      tenantId,
      subscriptionId: fixture.invoice.subscriptionId,
      periodStart,
      periodEnd,
      idempotencyKey: "invalid-bank-account",
      taxRateBps: 600,
      taxMode: "exclusive",
      mainlandChina: {
        invoiceType: "vatSpecial",
        buyerName: "大陆发票主体",
        buyerBankAccount: "1234",
        taxRateBps: 600,
        issueMode: "platform",
      },
    })).rejects.toMatchObject({
      code: "OPEN_PLATFORM_COMMERCE_VALIDATION_ERROR",
    });
    await expect(fixture.service.generateInvoice({
      tenantId,
      subscriptionId: fixture.invoice.subscriptionId,
      periodStart,
      periodEnd,
      idempotencyKey: "invalid-invoice-number",
      taxRateBps: 600,
      taxMode: "exclusive",
      mainlandChina: {
        invoiceType: "vatSpecial",
        buyerName: "大陆发票主体",
        taxRateBps: 600,
        issueMode: "platform",
        invoiceNumber: 12345678 as unknown as string,
      },
    })).rejects.toMatchObject({
      code: "OPEN_PLATFORM_COMMERCE_VALIDATION_ERROR",
    });
  });

  it("requires idempotency for writes and replays the same listing transition", async () => {
    const fixture = await createFixture();
    const app = await createApp(fixture.service);
    const server = app.getHttpServer();
    const missingKey = await authenticated(
      request(server).post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/marketplace/listings/${fixture.listing.id}/suspend`),
    );
    expect(missingKey.status).toBe(400);
    expect(missingKey.body.code).toBe("OPEN_PLATFORM_COMMERCE_VALIDATION_ERROR");
    const first = await authenticated(
      request(server)
        .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/marketplace/listings/${fixture.listing.id}/suspend`)
        .set("Idempotency-Key", "listing-suspend-1")
        .send({}),
    );
    const replay = await authenticated(
      request(server)
        .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/marketplace/listings/${fixture.listing.id}/suspend`)
        .set("Idempotency-Key", "listing-suspend-1")
        .send({}),
    );
    expect(first.status).toBe(201);
    expect(replay.status).toBe(201);
    expect(replay.body.id).toBe(first.body.id);
    expect(replay.body.version).toBe(first.body.version);
    await app.close();
  });

  it("returns a safe invoice dispute view and keeps replays idempotent", async () => {
    const fixture = await createFixture();
    const app = await createApp(fixture.service);
    const server = app.getHttpServer();
    await fixture.service.transition({
      tenantId,
      resource: "invoice",
      id: fixture.invoice.id,
      targetStatus: "reconciling",
    });
    await fixture.service.transition({
      tenantId,
      resource: "invoice",
      id: fixture.invoice.id,
      targetStatus: "awaitingPayment",
    });
    const key = `dispute-${randomUUID()}`;
    const disputed = await authenticated(
      request(server)
        .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/billing/invoices/${fixture.invoice.id}/disputes`)
        .set("Idempotency-Key", key)
        .send({ reason: "Invoice charge not recognized", evidenceReference: "evidence://ticket-0001" }),
    );
    expect(disputed.status).toBe(201);
    expect(disputed.headers["cache-control"]).toBe("no-store");
    expect(disputed.body.invoice).toMatchObject({ id: fixture.invoice.id, status: "disputed" });
    expect(disputed.body.replayed).toBe(false);
    expect(disputed.body.dispute).toMatchObject({
      invoiceId: fixture.invoice.id,
      tenantId,
      kind: "invoiceDispute",
      event: "invoice.dispute.opened",
      status: "open",
      invoiceStatus: "awaitingPayment",
      reason: "Invoice charge not recognized",
      evidenceReference: "evidence://ticket-0001",
      evidenceCount: 1,
      actorId,
    });
    expect(disputed.body.dispute).not.toHaveProperty("requestHash");
    expect(disputed.body.dispute).not.toHaveProperty("idempotencyKey");
    expect(JSON.stringify(disputed.body)).not.toContain("6222021234567890123");

    const replay = await authenticated(
      request(server)
        .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/billing/invoices/${fixture.invoice.id}/disputes`)
        .set("Idempotency-Key", key)
        .send({ reason: "Invoice charge not recognized", evidenceReference: "evidence://ticket-0001" }),
    );
    expect(replay.status).toBe(201);
    expect(replay.body.replayed).toBe(true);
    expect(replay.body.dispute.id).toBe(disputed.body.dispute.id);
    await expect(fixture.repositories.invoiceDisputes.list(tenantId)).resolves.toHaveLength(1);

    const reused = await authenticated(
      request(server)
        .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/billing/invoices/${fixture.invoice.id}/dispute`)
        .set("Idempotency-Key", key)
        .send({ reason: "Another dispute reason" }),
    );
    expect(reused.status).toBe(409);
    expect(reused.body.code).toBe("OPEN_PLATFORM_COMMERCE_IDEMPOTENCY_KEY_REUSED");

    const unsafe = await authenticated(
      request(server)
        .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/billing/invoices/${fixture.invoice.id}/disputes`)
        .set("Idempotency-Key", `dispute-${randomUUID()}`)
        .send({ reason: "Refund to bank account 6222021234567890123 was never received" }),
    );
    expect(unsafe.status).toBe(400);
    expect(unsafe.body.code).toBe("OPEN_PLATFORM_COMMERCE_VALIDATION_ERROR");
    expect(JSON.stringify(unsafe.body)).not.toContain("6222021234567890123");
    await expect(fixture.repositories.invoiceDisputes.list(tenantId)).resolves.toHaveLength(1);
    await app.close();
  });

  it("lists, reads, reviews, decides, and withdraws invoice disputes", async () => {
    const fixture = await createFixture();
    const app = await createApp(fixture.service);
    const server = app.getHttpServer();
    await fixture.service.transition({
      tenantId,
      resource: "invoice",
      id: fixture.invoice.id,
      targetStatus: "reconciling",
    });
    await fixture.service.transition({
      tenantId,
      resource: "invoice",
      id: fixture.invoice.id,
      targetStatus: "awaitingPayment",
    });
    const disputed = await authenticated(
      request(server)
        .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/billing/invoices/${fixture.invoice.id}/disputes`)
        .set("Idempotency-Key", `dispute-${randomUUID()}`)
        .send({ reason: "Invoice charge not recognized" }),
    );
    expect(disputed.status).toBe(201);
    const disputeId = disputed.body.dispute.id as string;

    const listed = await authenticated(
      request(server).get(
        `${OPEN_PLATFORM_HTTP_BASE_PATH}/billing/invoices/${fixture.invoice.id}/disputes?status=open&limit=10`,
      ),
    );
    expect(listed.status).toBe(200);
    expect(listed.headers["cache-control"]).toBe("no-store");
    expect(listed.body.items).toHaveLength(1);
    expect(listed.body.items[0]).toMatchObject({ id: disputeId, status: "open" });
    expect(listed.body.items[0]).not.toHaveProperty("requestHash");
    const filtered = await authenticated(
      request(server).get(
        `${OPEN_PLATFORM_HTTP_BASE_PATH}/billing/invoices/${fixture.invoice.id}/disputes?status=rejected`,
      ),
    );
    expect(filtered.status).toBe(200);
    expect(filtered.body.items).toEqual([]);
    const invalidStatus = await authenticated(
      request(server).get(
        `${OPEN_PLATFORM_HTTP_BASE_PATH}/billing/invoices/${fixture.invoice.id}/disputes?status=unknown`,
      ),
    );
    expect(invalidStatus.status).toBe(400);
    expect(invalidStatus.body.code).toBe("OPEN_PLATFORM_COMMERCE_VALIDATION_ERROR");
    const invalidQuery = await authenticated(
      request(server).get(
        `${OPEN_PLATFORM_HTTP_BASE_PATH}/billing/invoices/${fixture.invoice.id}/disputes?unknown=1`,
      ),
    );
    expect(invalidQuery.status).toBe(400);

    const single = await authenticated(
      request(server).get(`${OPEN_PLATFORM_HTTP_BASE_PATH}/billing/disputes/${disputeId}`),
    );
    expect(single.status).toBe(200);
    expect(single.body).toMatchObject({ id: disputeId, invoiceId: fixture.invoice.id });
    const alias = await authenticated(
      request(server).get(`${OPEN_PLATFORM_HTTP_BASE_PATH}/billing/invoice-disputes/${disputeId}`),
    );
    expect(alias.status).toBe(200);
    expect(alias.body).toEqual(single.body);
    const missing = await authenticated(
      request(server).get(
        `${OPEN_PLATFORM_HTTP_BASE_PATH}/billing/disputes/invoice-dispute_${randomUUID()}`,
      ),
    );
    expect(missing.status).toBe(404);
    expect(missing.body.code).toBe("OPEN_PLATFORM_COMMERCE_RESOURCE_NOT_FOUND");

    const missingKey = await authenticated(
      request(server).post(
        `${OPEN_PLATFORM_HTTP_BASE_PATH}/billing/invoices/${fixture.invoice.id}/disputes/${disputeId}/review`,
      ),
    );
    expect(missingKey.status).toBe(400);
    expect(missingKey.body.code).toBe("OPEN_PLATFORM_COMMERCE_VALIDATION_ERROR");

    const reviewKey = `review-${randomUUID()}`;
    const reviewed = await authenticated(
      request(server)
        .post(
          `${OPEN_PLATFORM_HTTP_BASE_PATH}/billing/invoices/${fixture.invoice.id}/disputes/${disputeId}/review`,
        )
        .set("Idempotency-Key", reviewKey)
        .send({}),
    );
    expect(reviewed.status).toBe(201);
    expect(reviewed.headers["cache-control"]).toBe("no-store");
    expect(reviewed.body).toMatchObject({
      fromStatus: "open",
      replayed: false,
      dispute: { id: disputeId, status: "underReview", version: 2 },
    });
    const reviewReplay = await authenticated(
      request(server)
        .post(
          `${OPEN_PLATFORM_HTTP_BASE_PATH}/billing/invoices/${fixture.invoice.id}/disputes/${disputeId}/review`,
        )
        .set("Idempotency-Key", reviewKey)
        .send({}),
    );
    expect(reviewReplay.status).toBe(201);
    expect(reviewReplay.body.replayed).toBe(true);
    expect(reviewReplay.body.dispute.version).toBe(2);

    const decideKey = `decide-${randomUUID()}`;
    const invalidOutcome = await authenticated(
      request(server)
        .post(
          `${OPEN_PLATFORM_HTTP_BASE_PATH}/billing/invoices/${fixture.invoice.id}/disputes/${disputeId}/decisions`,
        )
        .set("Idempotency-Key", `decide-${randomUUID()}`)
        .send({ outcome: "unknown", reference: "resolution://case-1" }),
    );
    expect(invalidOutcome.status).toBe(400);
    expect(invalidOutcome.body.code).toBe("OPEN_PLATFORM_COMMERCE_VALIDATION_ERROR");
    const decided = await authenticated(
      request(server)
        .post(
          `${OPEN_PLATFORM_HTTP_BASE_PATH}/billing/invoices/${fixture.invoice.id}/disputes/${disputeId}/decisions`,
        )
        .set("Idempotency-Key", decideKey)
        .send({
          outcome: "accepted",
          reference: "resolution://case-0001",
          resolutionNote: "Credit note issued",
        }),
    );
    expect(decided.status).toBe(201);
    expect(decided.body).toMatchObject({
      fromStatus: "underReview",
      replayed: false,
      dispute: {
        id: disputeId,
        status: "accepted",
        version: 3,
        resolution: {
          outcome: "accepted",
          actorId,
          reference: "resolution://case-0001",
          note: "Credit note issued",
          noteLength: "Credit note issued".length,
        },
      },
    });
    expect(decided.body.dispute).not.toHaveProperty("requestHash");
    expect(decided.body.dispute).not.toHaveProperty("idempotencyKey");
    const decideReplay = await authenticated(
      request(server)
        .post(
          `${OPEN_PLATFORM_HTTP_BASE_PATH}/billing/invoices/${fixture.invoice.id}/disputes/${disputeId}/decisions`,
        )
        .set("Idempotency-Key", decideKey)
        .send({
          outcome: "accepted",
          reference: "resolution://case-0001",
          resolutionNote: "Credit note issued",
        }),
    );
    expect(decideReplay.status).toBe(201);
    expect(decideReplay.body.replayed).toBe(true);
    const reused = await authenticated(
      request(server)
        .post(
          `${OPEN_PLATFORM_HTTP_BASE_PATH}/billing/invoices/${fixture.invoice.id}/disputes/${disputeId}/decisions`,
        )
        .set("Idempotency-Key", decideKey)
        .send({ outcome: "rejected", reference: "resolution://case-0002" }),
    );
    expect(reused.status).toBe(409);
    expect(reused.body.code).toBe("OPEN_PLATFORM_COMMERCE_IDEMPOTENCY_KEY_REUSED");
    const terminal = await authenticated(
      request(server)
        .post(
          `${OPEN_PLATFORM_HTTP_BASE_PATH}/billing/invoices/${fixture.invoice.id}/disputes/${disputeId}/review`,
        )
        .set("Idempotency-Key", `review-${randomUUID()}`)
        .send({}),
    );
    expect(terminal.status).toBe(409);
    expect(terminal.body.code).toBe("OPEN_PLATFORM_COMMERCE_INVALID_STATE_TRANSITION");

    const crossInvoice = await authenticated(
      request(server)
        .post(
          `${OPEN_PLATFORM_HTTP_BASE_PATH}/billing/invoices/invoice_${randomUUID()}/disputes/${disputeId}/review`,
        )
        .set("Idempotency-Key", `review-${randomUUID()}`)
        .send({}),
    );
    expect(crossInvoice.status).toBe(404);
    const crossTenant = await authenticated(
      request(server).get(
        `${OPEN_PLATFORM_HTTP_BASE_PATH}/billing/invoices/${fixture.invoice.id}/disputes?tenantId=tenant-commerce-other`,
      ),
    );
    expect(crossTenant.status).toBe(403);
    expect(crossTenant.body.code).toBe("OPEN_PLATFORM_TENANT_MISMATCH");
    await app.close();
  });

  it("withdraws an open invoice dispute over the withdrawal route", async () => {
    const fixture = await createFixture();
    const app = await createApp(fixture.service);
    const server = app.getHttpServer();
    await fixture.service.transition({
      tenantId,
      resource: "invoice",
      id: fixture.invoice.id,
      targetStatus: "reconciling",
    });
    await fixture.service.transition({
      tenantId,
      resource: "invoice",
      id: fixture.invoice.id,
      targetStatus: "awaitingPayment",
    });
    const disputed = await authenticated(
      request(server)
        .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/billing/invoices/${fixture.invoice.id}/disputes`)
        .set("Idempotency-Key", `dispute-${randomUUID()}`)
        .send({ reason: "Charge withdrawn by the buyer" }),
    );
    expect(disputed.status).toBe(201);
    const disputeId = disputed.body.dispute.id as string;
    const withdrawKey = `withdraw-${randomUUID()}`;
    const withdrawn = await authenticated(
      request(server)
        .post(
          `${OPEN_PLATFORM_HTTP_BASE_PATH}/billing/invoices/${fixture.invoice.id}/disputes/${disputeId}/withdrawal`,
        )
        .set("Idempotency-Key", withdrawKey)
        .send({ reference: "withdrawal://case-0001", resolutionNote: "Buyer cancelled" }),
    );
    expect(withdrawn.status).toBe(201);
    expect(withdrawn.headers["cache-control"]).toBe("no-store");
    expect(withdrawn.body).toMatchObject({
      fromStatus: "open",
      replayed: false,
      dispute: {
        id: disputeId,
        status: "withdrawn",
        version: 2,
        resolution: {
          outcome: "withdrawn",
          actorId,
          reference: "withdrawal://case-0001",
          fromStatus: "open",
        },
      },
    });
    const replay = await authenticated(
      request(server)
        .post(
          `${OPEN_PLATFORM_HTTP_BASE_PATH}/billing/invoices/${fixture.invoice.id}/disputes/${disputeId}/withdrawal`,
        )
        .set("Idempotency-Key", withdrawKey)
        .send({ reference: "withdrawal://case-0001", resolutionNote: "Buyer cancelled" }),
    );
    expect(replay.status).toBe(201);
    expect(replay.body.replayed).toBe(true);
    const missingReference = await authenticated(
      request(server)
        .post(
          `${OPEN_PLATFORM_HTTP_BASE_PATH}/billing/invoices/${fixture.invoice.id}/disputes/${disputeId}/withdrawal`,
        )
        .set("Idempotency-Key", `withdraw-${randomUUID()}`)
        .send({}),
    );
    expect(missingReference.status).toBe(400);
    expect(missingReference.body.code).toBe("OPEN_PLATFORM_COMMERCE_VALIDATION_ERROR");
    const unknownDispute = await authenticated(
      request(server)
        .post(
          `${OPEN_PLATFORM_HTTP_BASE_PATH}/billing/invoices/${fixture.invoice.id}/disputes/invoice-dispute_${randomUUID()}/withdrawal`,
        )
        .set("Idempotency-Key", `withdraw-${randomUUID()}`)
        .send({ reference: "withdrawal://case-0002" }),
    );
    expect(unknownDispute.status).toBe(404);
    await app.close();
  });

  it("returns safe commerce errors without internal exception text", async () => {
    const fixture = await createFixture();
    const app = await createApp(fixture.service);
    const server = app.getHttpServer();
    const invalidCursor = await authenticated(
      request(server).get(`${OPEN_PLATFORM_HTTP_BASE_PATH}/billing/invoices?cursor=not-a-cursor`),
    );
    expect(invalidCursor.status).toBe(400);
    expect(invalidCursor.body).toMatchObject({
      code: "OPEN_PLATFORM_COMMERCE_VALIDATION_ERROR",
      message: "Open platform commerce request failed",
    });
    expect(JSON.stringify(invalidCursor.body)).not.toContain("not-a-cursor");
    expect(toOpenPlatformHttpError(commerceResourceNotFound("invoice"), "commerce-request"))
      .toMatchObject({
        statusCode: 404,
        body: { code: "OPEN_PLATFORM_COMMERCE_RESOURCE_NOT_FOUND" },
      });
    await app.close();
  });
});
