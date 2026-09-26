import "reflect-metadata";
import { randomUUID } from "node:crypto";
import { Test } from "@nestjs/testing";
import request from "supertest";
import { describe, expect, it } from "vitest";
import {
  createOpenPlatformRequestContextIssuer,
  InMemoryOpenPlatformAuditEventStore,
  OpenPlatformCommerceModule,
  OPEN_PLATFORM_HTTP_BASE_PATH,
  type OpenPlatformHttpRequest,
} from "../src/open-platform/index.js";
import {
  CommerceDomainService,
  InMemoryCommerceAuditEventStore,
  InMemoryCommerceIdempotencyStore,
  InMemoryCommerceRepositories,
  createCommerceAuditAdapter,
  createCommerceAuthorizationAdapter,
  COMMERCE_AUTHORIZATION_ACTIONS,
  COMMERCE_DISPUTE_AUTHORIZATION_ACTIONS,
  commercePermissionFor,
  createDevelopmentCommerceAuthorization,
  createInMemoryCommerceAuditEventStore,
  createInMemoryCommerceIdempotencyStore,
  isCommerceAuthorizationProductionReady,
  type CommerceAuditEventInput,
  type CommerceAuditPort,
  type CommerceAuthorizationPort,
  type CommerceIdempotencyPort,
} from "../src/open-platform/commerce/index.js";
import {
  createOpenCommerceIdempotencyMigrationSql,
  createSqlCommerceIdempotencyStore,
  getOpenCommerceIdempotencyMigrationDefinition,
  getOpenCommerceInvoiceDisputeMigrationDefinition,
  getOpenCommerceMigrationDefinition,
  getOpenCommerceMigrations,
} from "../src/open-platform/commerce/persistence/index.js";
import type { CommerceDatabaseAdapter } from "../src/open-platform/commerce/persistence/adapter.js";
import type { CommerceDependencyReadiness } from "../src/open-platform/commerce/types.js";

const now = new Date("2031-03-15T00:00:00.000Z");
const periodStart = "2031-03-01T00:00:00.000Z";
const periodEnd = "2031-04-01T00:00:00.000Z";
const tenantId = "tenant-commerce-security";
const otherTenantId = "tenant-commerce-security-other";
const actorId = "actor-commerce-security";
const basePath = OPEN_PLATFORM_HTTP_BASE_PATH;

interface Fixture {
  readonly service: CommerceDomainService;
  readonly partnerId: string;
  readonly listingId: string;
  readonly invoiceId: string;
}

class RecordingCommerceAudit implements CommerceAuditPort {
  readonly events: CommerceAuditEventInput[] = [];
  readonly productionReady: boolean;
  readonly readiness: CommerceDependencyReadiness;
  available = true;

  constructor(production = false) {
    this.productionReady = production;
    this.readiness = Object.freeze({
      storage: production ? "persistent" as const : "memory" as const,
      distributed: production,
      ready: () => true,
    });
  }

  async append(event: CommerceAuditEventInput) {
    if (!this.available) throw new Error("commerce audit storage is unavailable");
    this.events.push(event);
    return {
      id: `commerce_audit_${this.events.length}`,
      tenantId: event.tenantId,
      action: event.action,
      outcome: event.outcome,
      actor: event.actor,
      target: event.target,
      metadata: {},
      occurredAt: now.toISOString(),
      source: "open-platform-commerce",
    };
  }

  outcomes(): string[] {
    return this.events.map((event) => `${event.action}:${event.outcome}`);
  }
}

function allowAllAuthorization(productionReady = true): CommerceAuthorizationPort {
  return {
    productionReady,
    authorize: () => true,
  };
}

function denyEverythingAuthorization(productionReady = true): CommerceAuthorizationPort {
  return {
    productionReady,
    authorize: () => false,
  };
}

async function createFixture(
  service: CommerceDomainService = new CommerceDomainService({ clock: () => now }),
  scope: string = tenantId,
): Promise<Fixture> {
  const partner = await service.createPartnerAccount({
    tenantId: scope,
    legalName: `${scope} 结算主体`,
    partnerCode: `partner-${randomUUID().slice(0, 8)}`,
    settlementReference: `settlement://private-bank-account-${scope}`,
  });
  await service.transition({
    tenantId: scope,
    resource: "partnerAccount",
    id: partner.id,
    targetStatus: "underReview",
  });
  await service.transition({
    tenantId: scope,
    resource: "partnerAccount",
    id: partner.id,
    targetStatus: "active",
  });
  const listing = await service.createMarketplaceListing({
    tenantId: scope,
    partnerAccountId: partner.id,
    productId: `product_${randomUUID()}`,
    title: "Security listing",
    description: "Listing used by commerce security tests",
  });
  await service.transition({
    tenantId: scope,
    resource: "marketplaceListing",
    id: listing.id,
    targetStatus: "pendingReview",
  });
  await service.transition({
    tenantId: scope,
    resource: "marketplaceListing",
    id: listing.id,
    targetStatus: "published",
  });
  const price = await service.createPrice({
    tenantId: scope,
    code: `price-${randomUUID().slice(0, 8)}`,
    name: "Security price",
    priceType: "fixed",
    fixedAmount: { amountMinor: 5000, currency: "CNY" },
    effectiveFrom: periodStart,
  });
  await service.transition({
    tenantId: scope,
    resource: "price",
    id: price.id,
    targetStatus: "active",
  });
  const plan = await service.createPlan({
    tenantId: scope,
    code: `plan-${randomUUID().slice(0, 8)}`,
    name: "Security plan",
    priceIds: [price.id],
    effectiveFrom: periodStart,
  });
  await service.transition({
    tenantId: scope,
    resource: "plan",
    id: plan.id,
    targetStatus: "active",
  });
  const subscription = await service.createSubscription({
    tenantId: scope,
    applicationId: `app_${randomUUID()}`,
    planId: plan.id,
    name: "Security subscription",
    currentPeriodStart: periodStart,
    currentPeriodEnd: periodEnd,
  });
  await service.transition({
    tenantId: scope,
    resource: "subscription",
    id: subscription.id,
    targetStatus: "active",
  });
  const generated = await service.generateInvoice({
    tenantId: scope,
    subscriptionId: subscription.id,
    periodStart,
    periodEnd,
    idempotencyKey: `invoice-${randomUUID()}`,
    taxRateBps: 600,
    taxMode: "exclusive",
    mainlandChina: {
      invoiceType: "vatSpecial",
      buyerName: "大陆发票主体",
      buyerBankName: "测试银行",
      buyerBankAccount: "6222021234567890123",
      taxRateBps: 600,
      issueMode: "platform",
    },
  });
  await service.transition({
    tenantId: scope,
    resource: "invoice",
    id: generated.invoice.id,
    targetStatus: "reconciling",
  });
  await service.transition({
    tenantId: scope,
    resource: "invoice",
    id: generated.invoice.id,
    targetStatus: "awaitingPayment",
  });
  return {
    service,
    partnerId: partner.id,
    listingId: listing.id,
    invoiceId: generated.invoice.id,
  };
}

interface AppOptions {
  readonly mode?: "development" | "test" | "production";
  readonly authorization?: CommerceAuthorizationPort;
  readonly audit?: CommerceAuditPort;
  readonly idempotency?: CommerceIdempotencyPort;
  readonly service?: CommerceDomainService;
  readonly repositories?: InMemoryCommerceRepositories;
  readonly clock?: () => Date;
  readonly authenticated?: boolean;
  readonly tenantOverride?: string;
  readonly actorOverride?: string;
}

async function createApp(options: AppOptions = {}) {
  const issuer = createOpenPlatformRequestContextIssuer({
    issuerId: "commerce-security-tests",
    attestation: Object.freeze({ test: true }),
    clock: options.clock ?? (() => now),
  });
  const moduleRef = await Test.createTestingModule({
    imports: [
      OpenPlatformCommerceModule.forRoot({
        ...(options.service === undefined ? {} : { service: options.service }),
        ...(options.repositories === undefined ? {} : { repositories: options.repositories }),
        mode: options.mode ?? "test",
        contextIssuer: issuer,
        ...(options.authorization === undefined
          ? {}
          : { authorization: options.authorization }),
        ...(options.audit === undefined ? {} : { audit: options.audit }),
        ...(options.idempotency === undefined ? {} : { idempotency: options.idempotency }),
        ...(options.clock === undefined ? {} : { clock: options.clock }),
        resolver: {
          resolve: (httpRequest: OpenPlatformHttpRequest) => {
            const headers = httpRequest.headers ?? {};
            const authenticated = Object.entries(headers).some(
              ([key, value]) => key.toLowerCase() === "x-commerce-auth" && value === "valid",
            );
            const isAuthenticated = options.authenticated ?? true;
            if (!authenticated || !isAuthenticated) return undefined;
            return {
              tenantId: options.tenantOverride ?? tenantId,
              actorId: options.actorOverride ?? actorId,
              requestId: "commerce-security-request",
            };
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

describe("open platform commerce HTTP authorization", () => {
  it("denies every read and write route family without commerce permission", async () => {
    const fixture = await createFixture();
    const app = await createApp({
      service: fixture.service,
      authorization: denyEverythingAuthorization(false),
    });
    const server = app.getHttpServer();
    const readRoutes = [
      `${basePath}/marketplace/listings`,
      `${basePath}/listings`,
      `${basePath}/marketplace/listings/${fixture.listingId}`,
      `${basePath}/marketplace/listings/${fixture.listingId}/commission-rules`,
      `${basePath}/partners`,
      `${basePath}/partner-accounts`,
      `${basePath}/marketplace/partners`,
      `${basePath}/partners/${fixture.partnerId}`,
      `${basePath}/marketplace/partners/${fixture.partnerId}`,
      `${basePath}/partners/${fixture.partnerId}/commission-rules`,
      `${basePath}/commission-rules`,
      `${basePath}/marketplace/commission-rules`,
      `${basePath}/commission-rules/rule-1`,
      `${basePath}/marketplace/commission-rules/rule-1`,
      `${basePath}/billing/accounts`,
      `${basePath}/billing/accounts/${fixture.partnerId}`,
      `${basePath}/billing/invoices`,
      `${basePath}/billing/invoices/${fixture.invoiceId}`,
      `${basePath}/billing/invoices/${fixture.invoiceId}/disputes`,
      `${basePath}/billing/disputes/invoice-dispute_1`,
      `${basePath}/billing/invoice-disputes/invoice-dispute_1`,
    ];
    for (const route of readRoutes) {
      const response = await authenticated(request(server).get(route));
      expect(response.status, route).toBe(403);
      expect(response.body.code, route).toBe("OPEN_PLATFORM_FORBIDDEN");
      expect(response.headers["cache-control"]).toBe("no-store");
    }
    const writeRoutes = [
      `${basePath}/marketplace/listings`,
      `${basePath}/marketplace/listings/${fixture.listingId}/submit-review`,
      `${basePath}/marketplace/listings/${fixture.listingId}/submit`,
      `${basePath}/marketplace/listings/${fixture.listingId}/publish`,
      `${basePath}/marketplace/listings/${fixture.listingId}/suspend`,
      `${basePath}/marketplace/listings/${fixture.listingId}/restore`,
      `${basePath}/marketplace/listings/${fixture.listingId}/remove`,
      `${basePath}/marketplace/listings/${fixture.listingId}/unpublish`,
      `${basePath}/marketplace/listings/${fixture.listingId}/lifecycle`,
      `${basePath}/billing/invoices/${fixture.invoiceId}/disputes`,
      `${basePath}/billing/invoices/${fixture.invoiceId}/dispute`,
      `${basePath}/billing/invoices/${fixture.invoiceId}/disputes/invoice-dispute_1/review`,
      `${basePath}/billing/invoices/${fixture.invoiceId}/disputes/invoice-dispute_1/decisions`,
      `${basePath}/billing/invoices/${fixture.invoiceId}/disputes/invoice-dispute_1/withdrawal`,
    ];
    for (const route of writeRoutes) {
      const response = await authenticated(
        request(server)
          .post(route)
          .set("Idempotency-Key", `denied-${randomUUID()}`)
          .send({
            partnerAccountId: fixture.partnerId,
            productId: `product_${randomUUID()}`,
            title: "Denied listing",
            description: "Denied listing description",
            reason: "Invoice charge not recognized",
            targetStatus: "suspended",
          }),
      );
      expect(response.status, route).toBe(403);
      expect(response.body.code, route).toBe("OPEN_PLATFORM_FORBIDDEN");
    }
    await app.close();
  });

  it("requires dedicated dispute actions so update cannot review or decide", async () => {
    expect(COMMERCE_DISPUTE_AUTHORIZATION_ACTIONS).toEqual([
      "dispute.review",
      "dispute.decide",
      "dispute.withdraw",
    ]);
    expect(COMMERCE_AUTHORIZATION_ACTIONS).toContain("dispute.decide");
    expect(COMMERCE_AUTHORIZATION_ACTIONS).not.toContain("dispute.resolve");
    expect(commercePermissionFor({
      context: createOpenPlatformRequestContextIssuer({
        issuerId: "commerce-security-tests",
        attestation: Object.freeze({ test: true }),
        clock: () => now,
      }).issueDevelopment({
        tenantId,
        actorId,
        requestId: "commerce-permission-request",
      }),
      tenantId,
      action: "dispute.decide",
      resource: "invoice",
    })).toBe("invoice.dispute.decide");
    const fixture = await createFixture();
    const updateOnly = createDevelopmentCommerceAuthorization([
      "invoice.read",
      "invoice.update",
    ]);
    const denied = await createApp({
      service: fixture.service,
      authorization: updateOnly,
    });
    const deniedServer = denied.getHttpServer();
    const disputes = await authenticated(
      request(deniedServer)
        .post(`${basePath}/billing/invoices/${fixture.invoiceId}/disputes`)
        .set("Idempotency-Key", `dispute-${randomUUID()}`)
        .send({ reason: "Invoice charge not recognized" }),
    );
    expect(disputes.status).toBe(201);
    const disputeId = disputes.body.dispute.id as string;
    const reviewed = await authenticated(
      request(deniedServer)
        .post(`${basePath}/billing/invoices/${fixture.invoiceId}/disputes/${disputeId}/review`)
        .set("Idempotency-Key", `review-${randomUUID()}`)
        .send({}),
    );
    expect(reviewed.status).toBe(403);
    expect(reviewed.body.code).toBe("OPEN_PLATFORM_FORBIDDEN");
    const decided = await authenticated(
      request(deniedServer)
        .post(`${basePath}/billing/invoices/${fixture.invoiceId}/disputes/${disputeId}/decisions`)
        .set("Idempotency-Key", `decide-${randomUUID()}`)
        .send({ outcome: "accepted", reference: "resolution://case-0001" }),
    );
    expect(decided.status).toBe(403);
    const withdrawn = await authenticated(
      request(deniedServer)
        .post(`${basePath}/billing/invoices/${fixture.invoiceId}/disputes/${disputeId}/withdrawal`)
        .set("Idempotency-Key", `withdraw-${randomUUID()}`)
        .send({ reference: "withdrawal://case-0001" }),
    );
    expect(withdrawn.status).toBe(403);
    expect(JSON.stringify(decided.body)).not.toContain("resolution://case-0001");
    await expect(fixture.service.repositories.invoiceDisputes.get(tenantId, disputeId))
      .resolves.toMatchObject({ status: "open", version: 1 });
    await denied.close();

    const adjudicator = createDevelopmentCommerceAuthorization([
      "invoice.read",
      "invoice.dispute.review",
      "invoice.dispute.decide",
      "invoice.dispute.withdraw",
    ]);
    const allowed = await createApp({
      service: fixture.service,
      authorization: adjudicator,
    });
    const allowedServer = allowed.getHttpServer();
    const allowedReview = await authenticated(
      request(allowedServer)
        .post(`${basePath}/billing/invoices/${fixture.invoiceId}/disputes/${disputeId}/review`)
        .set("Idempotency-Key", `review-${randomUUID()}`)
        .send({}),
    );
    expect(allowedReview.status).toBe(201);
    expect(allowedReview.body.dispute.status).toBe("underReview");
    const allowedWithdraw = await authenticated(
      request(allowedServer)
        .post(`${basePath}/billing/invoices/${fixture.invoiceId}/disputes/${disputeId}/withdrawal`)
        .set("Idempotency-Key", `withdraw-${randomUUID()}`)
        .send({ reference: "withdrawal://case-0001" }),
    );
    expect(allowedWithdraw.status).toBe(201);
    expect(allowedWithdraw.body.dispute.status).toBe("withdrawn");
    const readOnly = createDevelopmentCommerceAuthorization(["invoice.dispute.decide"]);
    const readDenied = await createApp({ service: fixture.service, authorization: readOnly });
    const listed = await authenticated(
      request(readDenied.getHttpServer()).get(
        `${basePath}/billing/invoices/${fixture.invoiceId}/disputes`,
      ),
    );
    expect(listed.status).toBe(403);
    const single = await authenticated(
      request(readDenied.getHttpServer()).get(`${basePath}/billing/disputes/${disputeId}`),
    );
    expect(single.status).toBe(403);
    await readDenied.close();
    await allowed.close();
  });

  it("keeps dispute adjudication audit metadata free of notes and references", async () => {
    const fixture = await createFixture();
    const audit = new RecordingCommerceAudit();
    const app = await createApp({ service: fixture.service, audit });
    const server = app.getHttpServer();
    const disputed = await authenticated(
      request(server)
        .post(`${basePath}/billing/invoices/${fixture.invoiceId}/disputes`)
        .set("Idempotency-Key", `dispute-${randomUUID()}`)
        .send({ reason: "Invoice charge not recognized" }),
    );
    expect(disputed.status).toBe(201);
    const disputeId = disputed.body.dispute.id as string;
    await authenticated(
      request(server)
        .post(`${basePath}/billing/invoices/${fixture.invoiceId}/disputes/${disputeId}/review`)
        .set("Idempotency-Key", `review-${randomUUID()}`)
        .send({}),
    );
    const decided = await authenticated(
      request(server)
        .post(`${basePath}/billing/invoices/${fixture.invoiceId}/disputes/${disputeId}/decisions`)
        .set("Idempotency-Key", `decide-${randomUUID()}`)
        .send({
          outcome: "rejected",
          reference: "resolution://case-0001",
          resolutionNote: "Duplicate usage line confirmed",
        }),
    );
    expect(decided.status).toBe(201);
    expect(audit.outcomes().slice(-2)).toEqual([
      "invoice.dispute.review:success",
      "invoice.dispute.decide:success",
    ]);
    const decision = audit.events.at(-1);
    expect(decision?.target).toMatchObject({ type: "invoice", id: disputeId });
    expect(decision?.metadata).toEqual({
      invoiceId: fixture.invoiceId,
      disputeId,
      fromStatus: "underReview",
      toStatus: "rejected",
      outcome: "rejected",
      noteLength: "Duplicate usage line confirmed".length,
      replayed: false,
    });
    const serialized = JSON.stringify(audit.events);
    expect(serialized).not.toContain("resolution://case-0001");
    expect(serialized).not.toContain("Duplicate usage line confirmed");
    expect(serialized).not.toContain("Invoice charge not recognized");
    expect(serialized).not.toContain("6222021234567890123");
    const denied = await createApp({
      service: fixture.service,
      audit,
      authorization: denyEverythingAuthorization(false),
    });
    const deniedDecision = await authenticated(
      request(denied.getHttpServer())
        .post(`${basePath}/billing/invoices/${fixture.invoiceId}/disputes/${disputeId}/decisions`)
        .set("Idempotency-Key", `decide-${randomUUID()}`)
        .send({ outcome: "accepted", reference: "resolution://case-0002" }),
    );
    expect(deniedDecision.status).toBe(403);
    expect(audit.outcomes().at(-1)).toBe("invoice.dispute.decide:denied");
    await denied.close();
    await app.close();
  });

  it("keeps cross-tenant access a safe error before authorization", async () => {
    const fixture = await createFixture();
    const app = await createApp({ service: fixture.service });
    const server = app.getHttpServer();
    const query = await authenticated(
      request(server).get(`${basePath}/marketplace/listings?tenantId=${otherTenantId}`),
    );
    expect(query.status).toBe(403);
    expect(query.body.code).toBe("OPEN_PLATFORM_TENANT_MISMATCH");
    const body = await authenticated(
      request(server)
        .post(`${basePath}/marketplace/listings/${fixture.listingId}/suspend`)
        .set("Idempotency-Key", `cross-tenant-${randomUUID()}`)
        .send({ tenantId: otherTenantId }),
    );
    expect(body.status).toBe(403);
    expect(body.body.code).toBe("OPEN_PLATFORM_TENANT_MISMATCH");
    await app.close();
  });

  it("appends security audit events for successful and denied writes", async () => {
    const fixture = await createFixture();
    const audit = new RecordingCommerceAudit();
    const app = await createApp({ service: fixture.service, audit });
    const server = app.getHttpServer();
    const created = await authenticated(
      request(server)
        .post(`${basePath}/marketplace/listings`)
        .set("Idempotency-Key", `audit-create-${randomUUID()}`)
        .send({
          partnerAccountId: fixture.partnerId,
          productId: `product_${randomUUID()}`,
          title: "Audited listing",
          description: "Audited listing description",
        }),
    );
    expect(created.status).toBe(201);
    const disputed = await authenticated(
      request(server)
        .post(`${basePath}/billing/invoices/${fixture.invoiceId}/dispute`)
        .set("Idempotency-Key", `audit-dispute-${randomUUID()}`)
        .send({ reason: "Invoice charge not recognized" }),
    );
    expect(disputed.status).toBe(201);
    expect(audit.outcomes()).toEqual([
      "marketplaceListing.create:success",
      "invoice.update:success",
    ]);
    const createdEvent = audit.events[0];
    expect(createdEvent?.actor).toEqual({ type: "user", id: actorId });
    expect(createdEvent?.requestId).toBe("commerce-security-request");
    expect(createdEvent?.target.id).toBe(created.body.id);
    expect(createdEvent?.metadata).toEqual({ status: "draft" });
    const denied = await createApp({
      service: fixture.service,
      audit,
      authorization: denyEverythingAuthorization(false),
    });
    const deniedResponse = await authenticated(
      request(denied.getHttpServer())
        .post(`${basePath}/billing/invoices/${fixture.invoiceId}/dispute`)
        .set("Idempotency-Key", `audit-denied-${randomUUID()}`)
        .send({ reason: "Invoice charge not recognized" }),
    );
    expect(deniedResponse.status).toBe(403);
    expect(audit.outcomes().at(-1)).toBe("invoice.update:denied");
    expect(audit.events.at(-1)?.tenantId).toBe(tenantId);
    await denied.close();
    await app.close();
  });

  it("never persists secrets, bank accounts, or reasons in audit metadata", async () => {
    const fixture = await createFixture();
    const audit = new RecordingCommerceAudit();
    const app = await createApp({ service: fixture.service, audit });
    const server = app.getHttpServer();
    const secretAudit = await authenticated(
      request(server)
        .post(`${basePath}/marketplace/listings`)
        .set("Idempotency-Key", `metadata-${randomUUID()}`)
        .send({
          partnerAccountId: fixture.partnerId,
          productId: `product_${randomUUID()}`,
          title: "Metadata listing",
          description: "Metadata listing description",
          settlementReference: "settlement://private-bank-account-123456",
          buyerBankAccount: "6222021234567890123",
        }),
    );
    expect(secretAudit.status).toBe(201);
    const serialized = JSON.stringify(audit.events);
    expect(serialized).not.toContain("private-bank-account-123456");
    expect(serialized).not.toContain("6222021234567890123");
    expect(serialized).not.toContain("settlementReference");
    expect(serialized).not.toContain("buyerBankAccount");
    const partner = await authenticated(
      request(server).get(`${basePath}/partners/${fixture.partnerId}`),
    );
    expect(partner.status).toBe(200);
    expect(JSON.stringify(partner.body)).not.toContain("private-bank-account-999999");
    await app.close();
  });

  it("reuses the shared open platform audit port through the commerce adapter", async () => {
    const platformAudit = new InMemoryOpenPlatformAuditEventStore({ clock: () => now });
    const audit = createCommerceAuditAdapter(platformAudit);
    const fixture = await createFixture();
    const app = await createApp({ service: fixture.service, audit });
    const server = app.getHttpServer();
    const created = await authenticated(
      request(server)
        .post(`${basePath}/marketplace/listings`)
        .set("Idempotency-Key", `shared-audit-${randomUUID()}`)
        .send({
          partnerAccountId: fixture.partnerId,
          productId: `product_${randomUUID()}`,
          title: "Shared audit listing",
          description: "Shared audit listing description",
        }),
    );
    expect(created.status).toBe(201);
    const page = await platformAudit.list({ tenantId });
    const event = page.items.at(-1);
    expect(event?.action).toBe("commerce.marketplaceListing.create");
    expect(event?.outcome).toBe("success");
    expect(event?.target.type).toBe("api_product");
    expect(event?.target.id).toBe(created.body.id);
    expect(event?.actor).toMatchObject({ type: "user", id: actorId });
    expect(event?.metadata).toMatchObject({
      commerceResource: "marketplaceListing",
      status: "draft",
    });
    await expect(platformAudit.verifyChain(tenantId)).resolves.toBe(true);
    await app.close();
  });

  it("fails closed when production audit is unavailable", async () => {
    const repositories = persistentCommerceRepositories();
    const idempotency = productionIdempotencyStore();
    const audit = new RecordingCommerceAudit(true);
    const service = new CommerceDomainService({
      repositories,
      clock: () => now,
      idempotency,
    });
    const app = await createApp({
      service,
      mode: "production",
      audit,
      authorization: allowAllAuthorization(),
    });
    const server = app.getHttpServer();
    const partnerId = await activePartnerId(service);
    audit.available = false;
    const failed = await authenticated(
      request(server)
        .post(`${basePath}/marketplace/listings`)
        .set("Idempotency-Key", `fail-closed-${randomUUID()}`)
        .send({
          partnerAccountId: partnerId,
          productId: `product_${randomUUID()}`,
          title: "Fail closed listing",
          description: "Fail closed listing description",
        }),
    );
    expect(failed.status).toBe(503);
    expect(failed.body.code).toBe("OPEN_PLATFORM_COMMERCE_STORAGE_UNAVAILABLE");
    expect(audit.events).toHaveLength(0);
    audit.available = true;
    const recovered = await authenticated(
      request(server)
        .post(`${basePath}/marketplace/listings`)
        .set("Idempotency-Key", `fail-closed-${randomUUID()}`)
        .send({
          partnerAccountId: partnerId,
          productId: `product_${randomUUID()}`,
          title: "Recovered listing",
          description: "Recovered listing description",
        }),
    );
    expect(recovered.status).toBe(201);
    expect(audit.outcomes()).toEqual(["marketplaceListing.create:success"]);
    await app.close();
  });

  it("keeps commerce development in-memory and throws on production readiness", async () => {
    await expect(createApp({
      mode: "production",
      authenticated: true,
    })).rejects.toThrow(/commerce authorization is not ready|persistent distributed storage/iu);
  });

  it("rejects production commerce without a production authorization port", async () => {
    await expect(createApp({
      mode: "production",
      authorization: createDevelopmentCommerceAuthorization("all"),
    })).rejects.toThrow(/production authorization port/iu);
    await expect(createApp({
      mode: "production",
      authorization: { productionReady: false, authorize: () => true },
    })).rejects.toThrow(/production authorization port/iu);
  });

  it("fails production readiness without persistent idempotency and audit", async () => {
    await expect(createApp({
      mode: "production",
      authorization: allowAllAuthorization(),
      audit: new RecordingCommerceAudit(true),
    })).rejects.toThrow(/storage is not ready/iu);
    await expect(createApp({
      mode: "production",
      authorization: allowAllAuthorization(),
      repositories: persistentCommerceRepositories(),
      idempotency: new InMemoryCommerceIdempotencyStore({ production: true }),
      audit: new RecordingCommerceAudit(true),
    })).rejects.toThrow(/storage is not ready/iu);
    await expect(createApp({
      mode: "production",
      authorization: allowAllAuthorization(),
      repositories: persistentCommerceRepositories(),
      idempotency: new InMemoryCommerceIdempotencyStore(),
      audit: new RecordingCommerceAudit(true),
    })).rejects.toThrow(/persistent distributed storage/iu);
    await expect(createApp({
      mode: "production",
      authorization: allowAllAuthorization(),
      repositories: persistentCommerceRepositories(),
      idempotency: productionIdempotencyStore(),
      audit: new RecordingCommerceAudit(false),
    })).rejects.toThrow(/audit dependency is not ready/iu);
  });

  it("accepts production commerce with production ready dependencies", async () => {
    const app = await createApp({
      mode: "production",
      authorization: allowAllAuthorization(),
      audit: new RecordingCommerceAudit(true),
      repositories: persistentCommerceRepositories(),
      idempotency: productionIdempotencyStore(),
    });
    await app.close();
    expect(isCommerceAuthorizationProductionReady(allowAllAuthorization())).toBe(true);
    expect(isCommerceAuthorizationProductionReady(createDevelopmentCommerceAuthorization("all")))
      .toBe(false);
  });
});

describe("open platform commerce idempotency scope", () => {
  it("replays the same key and rejects a different request for the same scope", async () => {
    const fixture = await createFixture();
    const key = `scope-${randomUUID()}`;
    const command = {
      tenantId,
      partnerAccountId: fixture.partnerId,
      productId: `product_${randomUUID()}`,
      title: "Scoped listing",
      description: "Scoped listing description",
      idempotencyKey: key,
      actorId: actorId,
    };
    const first = await fixture.service.createMarketplaceListing(command);
    const replay = await fixture.service.createMarketplaceListing(command);
    expect(replay.id).toBe(first.id);
    await expect(fixture.service.createMarketplaceListing({
      ...command,
      title: "Scoped listing with another title",
    })).rejects.toMatchObject({
      code: "OPEN_PLATFORM_COMMERCE_IDEMPOTENCY_KEY_REUSED",
    });
    const otherActor = await fixture.service.createMarketplaceListing({
      ...command,
      actorId: `${actorId}-other`,
    });
    expect(otherActor.id).not.toBe(first.id);
  });

  it("never lets the same key collide across tenants", async () => {
    const service = new CommerceDomainService({ clock: () => now });
    const first = await createFixture(service, tenantId);
    const second = await createFixture(service, otherTenantId);
    const key = `tenant-scoped-${randomUUID()}`;
    const shared = {
      productId: `product_${randomUUID()}`,
      title: "Tenant isolated listing",
      description: "Tenant isolated listing description",
      idempotencyKey: key,
    };
    const created = await service.createMarketplaceListing({
      ...shared,
      tenantId,
      partnerAccountId: first.partnerId,
    });
    const replay = await service.createMarketplaceListing({
      ...shared,
      tenantId,
      partnerAccountId: first.partnerId,
    });
    expect(replay.id).toBe(created.id);
    const other = await service.createMarketplaceListing({
      ...shared,
      tenantId: otherTenantId,
      partnerAccountId: second.partnerId,
    });
    expect(other.id).not.toBe(created.id);
    await expect(service.createMarketplaceListing({
      ...shared,
      tenantId,
      partnerAccountId: first.partnerId,
      title: "Tenant isolated listing mutated",
    })).rejects.toMatchObject({
      code: "OPEN_PLATFORM_COMMERCE_IDEMPOTENCY_KEY_REUSED",
    });
    await expect(service.createMarketplaceListing({
      ...shared,
      tenantId: otherTenantId,
      partnerAccountId: second.partnerId,
      title: "Other tenant listing mutated",
    })).rejects.toMatchObject({
      code: "OPEN_PLATFORM_COMMERCE_IDEMPOTENCY_KEY_REUSED",
    });
  });

  it("scopes transitions and disputes by tenant, actor, and operation", async () => {
    const service = new CommerceDomainService({ clock: () => now });
    const first = await createFixture(service, tenantId);
    const second = await createFixture(service, otherTenantId);
    const key = `transition-${randomUUID()}`;
    const firstResult = await service.transitionWithIdempotency({
      tenantId,
      resource: "marketplaceListing",
      id: first.listingId,
      targetStatus: "suspended",
      idempotencyKey: key,
      actorId: actorId,
    });
    const replay = await service.transitionWithIdempotency({
      tenantId,
      resource: "marketplaceListing",
      id: first.listingId,
      targetStatus: "suspended",
      idempotencyKey: key,
      actorId: actorId,
    });
    expect(replay.replayed).toBe(true);
    expect(replay.record.id).toBe(firstResult.record.id);
    const otherTenant = await service.transitionWithIdempotency({
      tenantId: otherTenantId,
      resource: "marketplaceListing",
      id: second.listingId,
      targetStatus: "suspended",
      idempotencyKey: key,
      actorId: actorId,
    });
    expect(otherTenant.replayed).toBe(false);
    expect(otherTenant.record.id).toBe(second.listingId);
    const otherActor = await service.transitionWithIdempotency({
      tenantId,
      resource: "marketplaceListing",
      id: first.listingId,
      targetStatus: "published",
      idempotencyKey: key,
      actorId: `${actorId}-other`,
    });
    expect(otherActor.replayed).toBe(false);
    const disputeKey = `dispute-${randomUUID()}`;
    const firstDispute = await service.disputeInvoice({
      tenantId,
      invoiceId: first.invoiceId,
      reason: "Invoice charge not recognized",
      idempotencyKey: disputeKey,
      actorId: actorId,
    });
    const disputeReplay = await service.disputeInvoice({
      tenantId,
      invoiceId: first.invoiceId,
      reason: "Invoice charge not recognized",
      idempotencyKey: disputeKey,
      actorId: actorId,
    });
    expect(firstDispute.replayed).toBe(false);
    expect(disputeReplay.replayed).toBe(true);
    expect(disputeReplay.invoice.id).toBe(first.invoiceId);
    const secondDispute = await service.disputeInvoice({
      tenantId: otherTenantId,
      invoiceId: second.invoiceId,
      reason: "Invoice charge not recognized",
      idempotencyKey: disputeKey,
      actorId: actorId,
    });
    expect(secondDispute.replayed).toBe(false);
    await expect(service.disputeInvoice({
      tenantId,
      invoiceId: first.invoiceId,
      reason: "Another dispute reason",
      idempotencyKey: disputeKey,
      actorId: actorId,
    })).rejects.toMatchObject({
      code: "OPEN_PLATFORM_COMMERCE_IDEMPOTENCY_KEY_REUSED",
    });
  });

  it("expires idempotency records and enforces capacity bounds", async () => {
    let clock = new Date("2031-03-15T00:00:00.000Z");
    const store = createInMemoryCommerceIdempotencyStore({
      clock: () => clock,
      retentionMs: 60_000,
      maxEntries: 100,
    });
    const scope = {
      tenantId,
      actorId,
      operation: "marketplaceListing.create",
      key: "ttl-key",
    };
    await store.put({
      scope,
      requestHash: "a".repeat(64),
      value: { id: "listing-1" },
      createdAt: clock.toISOString(),
    });
    expect((await store.get(scope))?.value).toEqual({ id: "listing-1" });
    clock = new Date(clock.getTime() + 60_001);
    expect(await store.get(scope)).toBeUndefined();
    expect(store.size()).toBe(0);
    for (let index = 0; index < 150; index += 1) {
      await store.put({
        scope: { ...scope, key: `capacity-${index}` },
        requestHash: "b".repeat(64),
        value: { id: `listing-${index}` },
        createdAt: clock.toISOString(),
      });
    }
    expect(store.size()).toBe(100);
    expect(await store.get({ ...scope, key: "capacity-0" })).toBeUndefined();
    expect(await store.get({ ...scope, key: "capacity-149" })).toBeDefined();
  });

  it("keeps idempotency readiness fail closed for in-memory stores", async () => {
    const repositories = new InMemoryCommerceRepositories();
    const service = new CommerceDomainService({
      repositories,
      clock: () => now,
      idempotency: new InMemoryCommerceIdempotencyStore({ production: true }),
    });
    await expect(service.isReady()).resolves.toEqual({
      ready: false,
      storage: "memory",
      distributed: false,
    });
    const ready = new CommerceDomainService({
      repositories,
      clock: () => now,
    });
    await expect(ready.isReady()).resolves.toEqual({
      ready: true,
      storage: "memory",
      distributed: false,
    });
  });
});

describe("open platform commerce idempotency SQL persistence", () => {
  it("appends a versioned idempotency table migration without changing version one", () => {
    const foundation = getOpenCommerceMigrationDefinition({ mode: "shared", tenantId });
    const idempotency = getOpenCommerceIdempotencyMigrationDefinition({ mode: "shared", tenantId });
    const dispute = getOpenCommerceInvoiceDisputeMigrationDefinition({ mode: "shared", tenantId });
    expect(foundation.version).toBe(1);
    expect(foundation.sql).not.toContain("gb_open_commerce_idempotency");
    expect(foundation.sql).not.toContain("gb_open_commerce_invoice_dispute");
    expect(idempotency.version).toBe(2);
    expect(idempotency.additive).toBe(true);
    expect(idempotency.requires).toEqual([1]);
    expect(idempotency.sql).not.toContain("gb_open_commerce_invoice_dispute");
    expect(dispute.version).toBe(3);
    expect(dispute.additive).toBe(true);
    expect(dispute.requires).toEqual([2]);
    expect(getOpenCommerceMigrations({ mode: "shared", tenantId }).map((entry) => entry.version))
      .toEqual([1, 2, 3, 4]);
    const sql = createOpenCommerceIdempotencyMigrationSql({ mode: "shared", tenantId });
    expect(sql).toContain('"gb_open_commerce_idempotency"');
    expect(sql).toContain("PRIMARY KEY (\"tenant_id\", \"actor_id\", \"operation\", \"idempotency_key\")");
    expect(sql).toContain("expiry_idx");
    expect(sql).toContain("FORCE ROW LEVEL SECURITY");
  });

  it("stores and replays scoped results through the SQL port", async () => {
    const rows: Record<string, unknown>[] = [];
    const adapter: CommerceDatabaseAdapter & { readonly calls: { text: string; values: unknown[] }[] } = {
      calls: [],
      query: async (text: string, values: unknown[] = []) => {
        adapter.calls.push({ text, values });
        if (text.startsWith("SELECT")) {
          const now = String(values[4] ?? "");
          return {
            rows: rows.filter((row) =>
              row.tenantId === values[0] &&
              row.actorId === values[1] &&
              row.operation === values[2] &&
              row.key === values[3] &&
              String(row.expiresAt ?? "") > now),
          };
        }
        if (text.startsWith("DELETE")) {
          const removed = rows.filter((row) =>
            row.tenantId === values[0] &&
            row.actorId === values[1] &&
            row.operation === values[2] &&
            row.key === values[3]);
          for (const row of removed) rows.splice(rows.indexOf(row), 1);
          return { rows: removed, rowCount: removed.length };
        }
        const next: Record<string, unknown> = {
          tenantId: values[0],
          actorId: values[1],
          operation: values[2],
          key: values[3],
          requestHash: values[4],
          result: JSON.parse(String(values[5])),
          createdAt: values[6],
          expiresAt: values[7],
        };
        const existing = rows.findIndex((row) =>
          row.tenantId === next.tenantId &&
          row.actorId === next.actorId &&
          row.operation === next.operation &&
          row.key === next.key);
        if (existing < 0) rows.push(next);
        else rows[existing] = next;
        return { rows: [next] };
      },
      transaction: async <T>(callback: (executor: CommerceDatabaseAdapter) => Promise<T>): Promise<T> =>
        callback(adapter),
    };
    const store = createSqlCommerceIdempotencyStore({ adapter, mode: "shared", tenantId });
    expect(store.productionReady).toBe(true);
    expect(store.readiness.storage).toBe("persistent");
    const scope = {
      tenantId,
      actorId,
      operation: "marketplaceListing.create",
      key: "sql-key",
    };
    expect(await store.get(scope)).toBeUndefined();
    const written = await store.put({
      scope,
      requestHash: "c".repeat(64),
      value: { id: "listing-sql" },
      createdAt: "2031-03-15T00:00:00.000Z",
    });
    expect(written.value).toEqual({ id: "listing-sql" });
    const replayed = await store.get(scope);
    expect(replayed?.requestHash).toBe("c".repeat(64));
    expect(replayed?.value).toEqual({ id: "listing-sql" });
    expect(await store.get({ ...scope, tenantId: otherTenantId })).toBeUndefined();
    expect(adapter.calls.some((call) => call.text.includes("ON CONFLICT"))).toBe(true);
    expect(await store.delete(scope)).toBe(true);
  });

  it("forwards authenticated contexts to a production platform authorization port", async () => {
    const calls: Array<{ assurance: string; resource: string; action: string }> = [];
    const platformAuthorization = {
      productionReady: true,
      authorize: (request: { context: { assurance: string }; resource: string; action: string }) => {
        calls.push({
          assurance: request.context.assurance,
          resource: request.resource,
          action: request.action,
        });
        return true;
      },
    };
    const commerceAuthorization = createCommerceAuthorizationAdapter(platformAuthorization);
    const issuer = createOpenPlatformRequestContextIssuer({
      issuerId: "commerce-authenticated-context",
      attestation: Object.freeze({ test: true }),
      clock: () => now,
    });
    const context = issuer.issueAuthenticated({
      tenantId,
      actorId,
      requestId: "authenticated-commerce-request",
    });
    await expect(commerceAuthorization.authorize({
      context,
      tenantId,
      action: "read",
      resource: "marketplaceListing",
    })).resolves.toBe(true);
    expect(calls).toEqual([{
      assurance: "authenticated",
      resource: "apiProduct",
      action: "read",
    }]);
  });
});

function persistentCommerceRepositories(): InMemoryCommerceRepositories {
  const inMemory = new InMemoryCommerceRepositories();
  return {
    ...inMemory,
    readiness: Object.freeze({
      storage: "persistent" as const,
      distributed: true,
      ready: () => true,
    }),
  } as unknown as InMemoryCommerceRepositories;
}

function productionIdempotencyStore(): CommerceIdempotencyPort {
  return createSqlCommerceIdempotencyStore({
    adapter: idempotencySqlAdapter(),
    mode: "shared",
    tenantId,
  });
}

function idempotencySqlAdapter(): CommerceDatabaseAdapter {
  const query = async (text: string, values: unknown[] = []) => {
    if (text.startsWith("SELECT")) return { rows: [] };
    return {
      rows: [{
        tenantId: values[0],
        actorId: values[1],
        operation: values[2],
        key: values[3],
        requestHash: values[4],
        result: JSON.parse(String(values[5])),
        createdAt: values[6],
        expiresAt: values[7],
      }],
    };
  };
  return {
    query,
    transaction: async <T>(callback: (executor: CommerceDatabaseAdapter) => Promise<T>): Promise<T> =>
      callback({ query }),
  };
}

async function activePartnerId(service: CommerceDomainService): Promise<string> {
  const partner = await service.createPartnerAccount({
    tenantId,
    legalName: "就绪伙伴主体",
    partnerCode: `partner-${randomUUID().slice(0, 8)}`,
    settlementReference: "settlement://fail-closed",
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
  return partner.id;
}
