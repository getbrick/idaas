import { createHash, randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  InMemoryOpenPlatformOutbox,
  OPEN_PLATFORM_CROSS_DOMAIN_EVENT_RESOURCE_BINDINGS,
  OpenPlatformEventPublisher,
  containsOpenPlatformSensitiveEventData,
  type OpenPlatformEventPublisherPort,
  type OpenPlatformOutboxPort,
  type OpenPlatformOutboxRecord,
} from "../src/open-platform/index.js";
import {
  COMMERCE_DOMAIN_EVENT_ID_PREFIX,
  COMMERCE_DOMAIN_EVENT_RESOURCE_TYPES,
  COMMERCE_DOMAIN_EVENT_TYPES,
  CommerceDomainService,
  InMemoryCommerceRepositories,
  OPEN_PLATFORM_COMMERCE_ERROR_CODES,
  commerceCreatedDomainEventFactory,
  commerceDisputeDecidedEvent,
  commerceDisputeOpenedEvent,
  commerceDisputeStatusChangedEvent,
  commerceDomainEventId,
  commerceStatusChangedDomainEventFactory,
  createCommerceService,
  createInMemoryCommerceAuditEventStore,
  InMemoryCommerceAuditEventStore,
  type CommerceDisputeEventSource,
  type CommissionRule,
  type InvoiceDisputeResolution,
  type Meter,
  type Plan,
  type Price,
  type Subscription,
} from "../src/open-platform/commerce/index.js";

const now = new Date("2030-01-15T00:00:00.000Z");
const periodStart = "2030-01-01T00:00:00.000Z";
const periodEnd = "2030-02-01T00:00:00.000Z";
const reason = "Usage disagrees with the contracted quota";
const evidenceReference = "evidence://dispute/2030-01";

interface Harness {
  readonly service: CommerceDomainService;
  readonly outbox: OpenPlatformOutboxPort;
  readonly repositories: InMemoryCommerceRepositories;
  readonly audit: InMemoryCommerceAuditEventStore;
}

function createHarness(
  options: {
    readonly production?: boolean;
    readonly eventsEnabled?: boolean;
    readonly publisher?: OpenPlatformEventPublisherPort;
  } = {},
): Harness {
  const repositories = new InMemoryCommerceRepositories({
    ...(options.production === undefined ? {} : { production: options.production }),
  });
  const outbox = new InMemoryOpenPlatformOutbox({ clock: () => now });
  const audit = createInMemoryCommerceAuditEventStore({ clock: () => now });
  const service = createCommerceService({
    repositories,
    clock: () => now,
    ...(options.production === undefined ? {} : { production: options.production }),
    eventPublisher: options.publisher ?? new OpenPlatformEventPublisher({
      outbox,
      clock: () => now,
    }),
    ...(options.eventsEnabled === undefined ? {} : { eventsEnabled: options.eventsEnabled }),
    audit,
  });
  return { service, outbox, repositories, audit };
}

async function createBillableFixture(
  harness: Harness,
  tenantId: string,
): Promise<{ subscription: Subscription; plan: Plan; meter: Meter; price: Price }> {
  const meter = await harness.service.createMeter({
    tenantId,
    key: "api.requests",
    name: "API requests",
    unit: "request",
    aggregation: "sum",
    dimensions: ["region"],
  });
  await harness.service.transition({
    tenantId,
    resource: "meter",
    id: meter.id,
    targetStatus: "active",
  });
  const price = await harness.service.createPrice({
    tenantId,
    code: "requests-cny",
    name: "CNY requests",
    priceType: "perUnit",
    meterId: meter.id,
    unitAmount: { amountMinor: 10, currency: "CNY" },
    includedUnits: "0",
    minimumCharge: { amountMinor: 0, currency: "CNY" },
    effectiveFrom: periodStart,
  });
  await harness.service.transition({
    tenantId,
    resource: "price",
    id: price.id,
    targetStatus: "active",
  });
  const plan = await harness.service.createPlan({
    tenantId,
    code: "standard",
    name: "Standard plan",
    priceIds: [price.id],
    effectiveFrom: periodStart,
  });
  await harness.service.transition({
    tenantId,
    resource: "plan",
    id: plan.id,
    targetStatus: "active",
  });
  const subscription = await harness.service.createSubscription({
    tenantId,
    applicationId: `app_${randomUUID()}`,
    planId: plan.id,
    name: "Standard subscription",
    quantity: "1",
    currentPeriodStart: periodStart,
    currentPeriodEnd: periodEnd,
  });
  await harness.service.transition({
    tenantId,
    resource: "subscription",
    id: subscription.id,
    targetStatus: "active",
  });
  return { subscription, plan, meter, price };
}

async function seedMarketplace(
  harness: Harness,
  tenantId: string,
): Promise<{ partnerId: string; listingId: string; ruleId: string }> {
  const partner = await harness.service.createPartnerAccount({
    tenantId,
    legalName: "生态伙伴有限公司",
    partnerCode: "partner-cn",
    settlementReference: "settlement://partner/cn",
  });
  const listing = await harness.service.createMarketplaceListing({
    tenantId,
    partnerAccountId: partner.id,
    productId: `product_${randomUUID()}`,
    title: "Marketplace API",
    description: "Partner supplied API",
    idempotencyKey: "listing-create",
    actorId: "actor-commerce",
  });
  const rule = await harness.service.createCommissionRule({
    tenantId,
    partnerAccountId: partner.id,
    listingId: listing.id,
    name: "Standard commission",
    rateBps: 1000,
    capBps: 2000,
    capAmount: { amountMinor: 1500, currency: "CNY" },
    effectiveFrom: periodStart,
  });
  return { partnerId: partner.id, listingId: listing.id, ruleId: rule.id };
}

async function listEvents(
  outbox: OpenPlatformOutboxPort,
  tenantId: string,
): Promise<readonly OpenPlatformOutboxRecord[]> {
  return (await outbox.list({ tenantId, limit: 200 })).items;
}

function eventNames(records: readonly OpenPlatformOutboxRecord[]): string[] {
  return records.map((record) => record.eventType);
}

describe("open platform commerce domain event identifiers", () => {
  it("derives the deterministic event id from the core operation scope", () => {
    const scope = {
      tenantId: "tenant-commerce-events",
      actorId: "actor-commerce",
      operation: "marketplaceListing.create",
      idempotencyKey: "listing-create",
    };
    const digest = createHash("sha256")
      .update(
        [
          scope.tenantId,
          scope.actorId,
          scope.operation,
          scope.idempotencyKey,
        ].join("\u0000"),
        "utf8",
      )
      .digest("hex")
      .slice(0, 32);
    expect(commerceDomainEventId(scope)).toBe(`${COMMERCE_DOMAIN_EVENT_ID_PREFIX}${digest}`);
    expect(commerceDomainEventId(scope)).toBe(commerceDomainEventId({ ...scope }));
    expect(commerceDomainEventId({ ...scope, idempotencyKey: "other" }))
      .not.toBe(commerceDomainEventId(scope));
  });

  it("only uses registered commerce event names and outbox resource types", () => {
    for (const eventType of Object.values(COMMERCE_DOMAIN_EVENT_TYPES)) {
      expect(eventType).toMatch(/^commerce_[a-z]+\.[a-z_]+$/u);
      expect(OPEN_PLATFORM_CROSS_DOMAIN_EVENT_RESOURCE_BINDINGS[
        eventType.slice(0, eventType.indexOf(".")) as keyof typeof OPEN_PLATFORM_CROSS_DOMAIN_EVENT_RESOURCE_BINDINGS
      ]).toBeDefined();
    }
    expect(new Set(Object.values(COMMERCE_DOMAIN_EVENT_RESOURCE_TYPES))).toEqual(
      new Set(["marketplaceListing", "partnerAccount", "commissionRule", "invoice", "invoiceDispute"]),
    );
  });

  it("skips unknown resources and undecided disputes without throwing", () => {
    const plan = {
      id: "plan_1",
      tenantId: "tenant-commerce-events",
      kind: "plan",
      version: 1,
      code: "standard",
      name: "Standard plan",
      status: "draft",
      priority: 0,
      currency: "CNY",
      priceIds: [],
      entitlementIds: [],
      quotaIds: [],
      effectiveFrom: periodStart,
      createdAt: now.toISOString(),
      updatedAt: now.toISOString(),
    } satisfies Plan;
    expect(commerceCreatedDomainEventFactory(plan)(plan)).toBeUndefined();
    expect(commerceStatusChangedDomainEventFactory(plan)(plan)).toBeUndefined();
    expect(commerceDisputeDecidedEvent({
      id: "invoice-dispute_1",
      version: 1,
      status: "open",
      invoiceId: "invoice_1",
      subscriptionId: "subscription_1",
      planId: "plan_1",
      invoiceStatus: "disputed",
      invoiceVersion: 4,
      reasonLength: reason.length,
      evidenceCount: 0,
    })).toBeUndefined();
  });

  it("describes a decided dispute with the decided action", () => {
    const resolution: InvoiceDisputeResolution = {
      outcome: "rejected",
      actorId: "actor-commerce",
      reference: "resolution://dispute/1",
      resolvedAt: now.toISOString(),
    };
    const dispute: CommerceDisputeEventSource = {
      id: "invoice-dispute_1",
      version: 1,
      status: "rejected",
      invoiceId: "invoice_1",
      subscriptionId: "subscription_1",
      planId: "plan_1",
      invoiceStatus: "disputed",
      invoiceVersion: 4,
      reasonLength: reason.length,
      evidenceCount: 1,
      resolution,
    };
    expect(commerceDisputeDecidedEvent(dispute)).toMatchObject({
      eventType: COMMERCE_DOMAIN_EVENT_TYPES.disputeDecided,
      resourceType: COMMERCE_DOMAIN_EVENT_RESOURCE_TYPES.invoiceDispute,
      resourceId: dispute.id,
      resourceStatus: "rejected",
      data: {
        invoiceId: dispute.invoiceId,
        outcome: "rejected",
        resolvedAt: now.toISOString(),
      },
    });
    expect(containsOpenPlatformSensitiveEventData(
      commerceDisputeDecidedEvent(dispute)?.data,
    )).toBe(false);
    expect(commerceDisputeStatusChangedEvent({
      ...dispute,
      status: "underReview",
      resolution: undefined,
    } as CommerceDisputeEventSource, "open")).toMatchObject({
      eventType: COMMERCE_DOMAIN_EVENT_TYPES.disputeStatusChanged,
      resourceType: COMMERCE_DOMAIN_EVENT_RESOURCE_TYPES.invoiceDispute,
      resourceId: dispute.id,
      resourceStatus: "underReview",
      data: {
        invoiceId: dispute.invoiceId,
        fromStatus: "open",
        toStatus: "underReview",
      },
    });
    expect(commerceDisputeStatusChangedEvent(dispute)?.data)
      .not.toHaveProperty("fromStatus");
  });
});

describe("open platform commerce domain event publishing", () => {
  it("publishes the expected event name and resource type for every key write", async () => {
    const harness = createHarness();
    const tenantId = "tenant-commerce-events";
    const { subscription } = await createBillableFixture(harness, tenantId);
    const { partnerId, listingId, ruleId } = await seedMarketplace(harness, tenantId);

    for (const [id, targetStatus] of [
      [partnerId, "underReview"],
      [partnerId, "active"],
    ] as const) {
      await harness.service.transitionWithIdempotency({
        tenantId,
        resource: "partnerAccount",
        id,
        targetStatus,
        idempotencyKey: `partner-${targetStatus}`,
        actorId: "actor-commerce",
      });
    }
    await harness.service.transitionWithIdempotency({
      tenantId,
      resource: "marketplaceListing",
      id: listingId,
      targetStatus: "pendingReview",
      idempotencyKey: "listing-review",
      actorId: "actor-commerce",
    });
    await harness.service.transitionWithIdempotency({
      tenantId,
      resource: "marketplaceListing",
      id: listingId,
      targetStatus: "published",
      idempotencyKey: "listing-publish",
      actorId: "actor-commerce",
    });
    await harness.service.transitionWithIdempotency({
      tenantId,
      resource: "commissionRule",
      id: ruleId,
      targetStatus: "active",
      idempotencyKey: "rule-activate",
      actorId: "actor-commerce",
    });
    const generated = await harness.service.generateInvoice({
      tenantId,
      subscriptionId: subscription.id,
      periodStart,
      periodEnd,
      idempotencyKey: "invoice-create",
      taxRateBps: 600,
      taxMode: "exclusive",
    });
    await harness.service.transitionWithIdempotency({
      tenantId,
      resource: "invoice",
      id: generated.invoice.id,
      targetStatus: "reconciling",
      idempotencyKey: "invoice-reconciling",
      actorId: "actor-commerce",
    });
    await harness.service.transitionWithIdempotency({
      tenantId,
      resource: "invoice",
      id: generated.invoice.id,
      targetStatus: "awaitingPayment",
      idempotencyKey: "invoice-awaiting",
      actorId: "actor-commerce",
    });
    await harness.service.disputeInvoice({
      tenantId,
      invoiceId: generated.invoice.id,
      reason,
      evidenceReference,
      idempotencyKey: "dispute-create",
      actorId: "actor-commerce",
      requestId: "request-dispute",
    });

    const events = await listEvents(harness.outbox, tenantId);
    expect(events).toHaveLength(12);
    expect(events.every((event) => event.tenantId === tenantId)).toBe(true);
    expect(eventNames(events)).toEqual([
      COMMERCE_DOMAIN_EVENT_TYPES.partnerCreated,
      COMMERCE_DOMAIN_EVENT_TYPES.listingCreated,
      COMMERCE_DOMAIN_EVENT_TYPES.commissionCreated,
      COMMERCE_DOMAIN_EVENT_TYPES.partnerStatusChanged,
      COMMERCE_DOMAIN_EVENT_TYPES.partnerStatusChanged,
      COMMERCE_DOMAIN_EVENT_TYPES.listingStatusChanged,
      COMMERCE_DOMAIN_EVENT_TYPES.listingStatusChanged,
      COMMERCE_DOMAIN_EVENT_TYPES.commissionStatusChanged,
      COMMERCE_DOMAIN_EVENT_TYPES.invoiceCreated,
      COMMERCE_DOMAIN_EVENT_TYPES.invoiceStatusChanged,
      COMMERCE_DOMAIN_EVENT_TYPES.invoiceStatusChanged,
      COMMERCE_DOMAIN_EVENT_TYPES.disputeCreated,
    ]);
    expect(events.map((event) => event.resourceType)).toEqual([
      COMMERCE_DOMAIN_EVENT_RESOURCE_TYPES.partnerAccount,
      COMMERCE_DOMAIN_EVENT_RESOURCE_TYPES.marketplaceListing,
      COMMERCE_DOMAIN_EVENT_RESOURCE_TYPES.commissionRule,
      COMMERCE_DOMAIN_EVENT_RESOURCE_TYPES.partnerAccount,
      COMMERCE_DOMAIN_EVENT_RESOURCE_TYPES.partnerAccount,
      COMMERCE_DOMAIN_EVENT_RESOURCE_TYPES.marketplaceListing,
      COMMERCE_DOMAIN_EVENT_RESOURCE_TYPES.marketplaceListing,
      COMMERCE_DOMAIN_EVENT_RESOURCE_TYPES.commissionRule,
      COMMERCE_DOMAIN_EVENT_RESOURCE_TYPES.invoice,
      COMMERCE_DOMAIN_EVENT_RESOURCE_TYPES.invoice,
      COMMERCE_DOMAIN_EVENT_RESOURCE_TYPES.invoice,
      COMMERCE_DOMAIN_EVENT_RESOURCE_TYPES.invoiceDispute,
    ]);
    const listing = events.find((event) => event.eventType === COMMERCE_DOMAIN_EVENT_TYPES.listingCreated);
    expect(listing).toMatchObject({
      resourceId: listingId,
      resourceVersion: 1,
      resourceStatus: "draft",
    });
    const dispute = events.find((event) => event.eventType === COMMERCE_DOMAIN_EVENT_TYPES.disputeCreated);
    expect(dispute?.resourceId).toMatch(/^invoice-dispute_/u);
    expect(dispute?.actorId).toBe("actor-commerce");
    expect(dispute?.requestId).toBe("request-dispute");
    expect(events.every((event) => event.status === "published")).toBe(true);
  });

  it("publishes the deprecated listing event when a listing is removed", async () => {
    const harness = createHarness();
    const tenantId = "tenant-commerce-deprecated";
    const { listingId } = await seedMarketplace(harness, tenantId);
    await harness.service.transitionWithIdempotency({
      tenantId,
      resource: "marketplaceListing",
      id: listingId,
      targetStatus: "pendingReview",
      idempotencyKey: "deprecated-review",
      actorId: "actor-commerce",
    });
    await harness.service.transitionWithIdempotency({
      tenantId,
      resource: "marketplaceListing",
      id: listingId,
      targetStatus: "published",
      idempotencyKey: "deprecated-publish",
      actorId: "actor-commerce",
    });
    const removed = await harness.service.transitionWithIdempotency({
      tenantId,
      resource: "marketplaceListing",
      id: listingId,
      targetStatus: "removed",
      idempotencyKey: "deprecated-remove",
      actorId: "actor-commerce",
    });
    expect(removed.record.kind).toBe("marketplaceListing");
    const deprecated = (await listEvents(harness.outbox, tenantId)).find(
      (event) => event.eventType === COMMERCE_DOMAIN_EVENT_TYPES.listingDeprecated,
    );
    expect(deprecated).toMatchObject({
      resourceType: COMMERCE_DOMAIN_EVENT_RESOURCE_TYPES.marketplaceListing,
      resourceId: listingId,
      resourceStatus: "removed",
      data: { fromStatus: "published", toStatus: "removed" },
    });
  });

  it("keeps one outbox record per idempotency key and replays the same event id", async () => {
    const harness = createHarness();
    const tenantId = "tenant-commerce-replay";
    const { subscription } = await createBillableFixture(harness, tenantId);
    const partner = await harness.service.createPartnerAccount({
      tenantId,
      legalName: "生态伙伴有限公司",
      partnerCode: "partner-replay",
      settlementReference: "settlement://partner/replay",
    });
    const listingCommand = {
      tenantId,
      partnerAccountId: partner.id,
      productId: `product_${randomUUID()}`,
      title: "Marketplace API",
      description: "Partner supplied API",
      idempotencyKey: "replay-listing",
      actorId: "actor-commerce",
    };
    const created = await harness.service.createMarketplaceListing(listingCommand);
    const replayed = await harness.service.createMarketplaceListing(listingCommand);
    expect(replayed.id).toBe(created.id);
    const transitionCommand = {
      tenantId,
      resource: "marketplaceListing" as const,
      id: created.id,
      targetStatus: "pendingReview",
      idempotencyKey: "replay-transition",
      actorId: "actor-commerce",
    };
    const transitioned = await harness.service.transitionWithIdempotency(transitionCommand);
    const transitionReplay = await harness.service.transitionWithIdempotency(transitionCommand);
    expect(transitionReplay.replayed).toBe(true);
    expect(transitionReplay.record).toEqual(transitioned.record);
    const invoiceCommand = {
      tenantId,
      subscriptionId: subscription.id,
      periodStart,
      periodEnd,
      idempotencyKey: "replay-invoice",
      taxRateBps: 0,
      taxMode: "exclusive" as const,
    };
    const generated = await harness.service.generateInvoice(invoiceCommand);
    const invoiceReplay = await harness.service.generateInvoice(invoiceCommand);
    expect(invoiceReplay.replayed).toBe(true);
    expect(invoiceReplay.invoice.id).toBe(generated.invoice.id);
    for (const targetStatus of ["reconciling", "awaitingPayment"] as const) {
      await harness.service.transitionWithIdempotency({
        tenantId,
        resource: "invoice",
        id: generated.invoice.id,
        targetStatus,
        idempotencyKey: `replay-invoice-${targetStatus}`,
        actorId: "actor-commerce",
      });
    }
    const disputeCommand = {
      tenantId,
      invoiceId: generated.invoice.id,
      reason,
      evidenceReference,
      idempotencyKey: "replay-dispute",
      actorId: "actor-commerce",
    };
    const disputed = await harness.service.disputeInvoice(disputeCommand);
    const disputeReplay = await harness.service.disputeInvoice(disputeCommand);
    expect(disputeReplay.replayed).toBe(true);
    expect(disputeReplay.dispute.id).toBe(disputed.dispute.id);

    const events = await listEvents(harness.outbox, tenantId);
    expect(events).toHaveLength(7);
    expect(new Set(events.map((event) => event.eventId)).size).toBe(7);
    expect(events.every((event) => event.eventId.startsWith(COMMERCE_DOMAIN_EVENT_ID_PREFIX))).toBe(true);
    expect(events.find(
      (event) => event.eventType === COMMERCE_DOMAIN_EVENT_TYPES.listingCreated,
    )?.eventId).toBe(commerceDomainEventId({
      tenantId,
      actorId: "actor-commerce",
      operation: "marketplaceListing.create",
      idempotencyKey: "replay-listing",
    }));
    expect(events.find(
      (event) => event.eventType === COMMERCE_DOMAIN_EVENT_TYPES.listingStatusChanged,
    )?.eventId).toBe(commerceDomainEventId({
      tenantId,
      actorId: "actor-commerce",
      operation: "marketplaceListing.transition",
      idempotencyKey: "replay-transition",
    }));
    expect(events.find(
      (event) => event.eventType === COMMERCE_DOMAIN_EVENT_TYPES.invoiceCreated,
    )?.eventId).toBe(commerceDomainEventId({
      tenantId,
      actorId: "service",
      operation: "invoice.create",
      idempotencyKey: "replay-invoice",
    }));
    expect(events.find(
      (event) => event.eventType === COMMERCE_DOMAIN_EVENT_TYPES.disputeCreated,
    )?.eventId).toBe(commerceDomainEventId({
      tenantId,
      actorId: "actor-commerce",
      operation: "invoice.dispute",
      idempotencyKey: "replay-dispute",
    }));
  });

  it("never exposes sensitive commerce data in event payloads", async () => {
    const harness = createHarness();
    const tenantId = "tenant-commerce-redaction";
    const { subscription } = await createBillableFixture(harness, tenantId);
    const { partnerId, listingId, ruleId } = await seedMarketplace(harness, tenantId);
    await harness.service.transitionWithIdempotency({
      tenantId,
      resource: "partnerAccount",
      id: partnerId,
      targetStatus: "underReview",
      idempotencyKey: "redaction-partner",
      actorId: "actor-commerce",
    });
    await harness.service.transitionWithIdempotency({
      tenantId,
      resource: "marketplaceListing",
      id: listingId,
      targetStatus: "pendingReview",
      idempotencyKey: "redaction-listing",
      actorId: "actor-commerce",
    });
    await harness.service.transitionWithIdempotency({
      tenantId,
      resource: "commissionRule",
      id: ruleId,
      targetStatus: "active",
      idempotencyKey: "redaction-rule",
      actorId: "actor-commerce",
    });
    const generated = await harness.service.generateInvoice({
      tenantId,
      subscriptionId: subscription.id,
      periodStart,
      periodEnd,
      idempotencyKey: "redaction-invoice",
      taxRateBps: 600,
      taxMode: "exclusive",
      mainlandChina: {
        invoiceType: "vatSpecial",
        buyerName: "中国大陆示例有限公司",
        buyerPhone: "13800000000",
        buyerAddress: "上海市浦东新区示例路1号",
        buyerBankName: "示例银行",
        buyerBankAccount: "6222021234567890123",
        taxRateBps: 600,
        issueMode: "platform",
      },
    });
    for (const targetStatus of ["reconciling", "awaitingPayment"] as const) {
      await harness.service.transitionWithIdempotency({
        tenantId,
        resource: "invoice",
        id: generated.invoice.id,
        targetStatus,
        idempotencyKey: `redaction-invoice-${targetStatus}`,
        actorId: "actor-commerce",
      });
    }
    await harness.service.disputeInvoice({
      tenantId,
      invoiceId: generated.invoice.id,
      reason,
      evidenceReference,
      idempotencyKey: "redaction-dispute",
      actorId: "actor-commerce",
    });

    const events = await listEvents(harness.outbox, tenantId);
    expect(events.length).toBeGreaterThan(0);
    for (const event of events) {
      expect(containsOpenPlatformSensitiveEventData(event.data)).toBe(false);
      expect(JSON.stringify(event.data)).not.toContain("生态伙伴有限公司");
      expect(JSON.stringify(event.data)).not.toContain("settlement://");
      expect(JSON.stringify(event.data)).not.toContain("中国大陆示例有限公司");
      expect(JSON.stringify(event.data)).not.toContain("13800000000");
      expect(JSON.stringify(event.data)).not.toContain("示例银行");
      expect(JSON.stringify(event.data)).not.toContain("6222021234567890123");
      expect(JSON.stringify(event.data)).not.toContain(evidenceReference);
      expect(JSON.stringify(event.data)).not.toContain(reason);
    }
    const commission = events.find(
      (event) => event.eventType === COMMERCE_DOMAIN_EVENT_TYPES.commissionCreated,
    );
    expect(commission?.data).toEqual({
      partnerAccountId: partnerId,
      listingId,
      status: "draft",
      rateBps: 1000,
      capBps: 2000,
      capAmount: "15",
      priority: 0,
    });
    const invoice = events.find(
      (event) => event.eventType === COMMERCE_DOMAIN_EVENT_TYPES.invoiceCreated,
    );
    expect(invoice?.data).toMatchObject({
      subscriptionId: subscription.id,
      currency: "CNY",
      status: "draft",
      subtotal: "0",
      tax: "0",
      total: "0",
    });
    const dispute = events.find(
      (event) => event.eventType === COMMERCE_DOMAIN_EVENT_TYPES.disputeCreated,
    );
    expect(dispute?.data).toEqual({
      invoiceId: generated.invoice.id,
      subscriptionId: subscription.id,
      planId: expect.any(String),
      status: "open",
      invoiceStatus: "awaitingPayment",
      invoiceVersion: 3,
      reasonLength: reason.length,
      evidenceCount: 1,
    });
  });

  it("keeps commerce events isolated per tenant", async () => {
    const harness = createHarness();
    const tenantA = "tenant-commerce-isolation-a";
    const tenantB = "tenant-commerce-isolation-b";
    await seedMarketplace(harness, tenantA);
    await seedMarketplace(harness, tenantB);
    const tenantAEvents = await listEvents(harness.outbox, tenantA);
    const tenantBEvents = await listEvents(harness.outbox, tenantB);
    expect(tenantAEvents).toHaveLength(3);
    expect(tenantBEvents).toHaveLength(3);
    expect(tenantAEvents.every((event) => event.tenantId === tenantA)).toBe(true);
    expect(tenantBEvents.every((event) => event.tenantId === tenantB)).toBe(true);
    const tenantAResourceIds = new Set(tenantAEvents.map((event) => event.resourceId));
    for (const event of tenantBEvents) {
      expect(tenantAResourceIds.has(event.resourceId)).toBe(false);
    }
    expect(tenantAEvents.map((event) => event.eventId).some(
      (eventId) => tenantBEvents.some((event) => event.eventId === eventId),
    )).toBe(false);
  });

  it("publishes dispute status changes and decisions once per adjudication", async () => {
    const harness = createHarness();
    const tenantId = "tenant-commerce-dispute-decision";
    const { subscription } = await createBillableFixture(harness, tenantId);
    const generated = await harness.service.generateInvoice({
      tenantId,
      subscriptionId: subscription.id,
      periodStart,
      periodEnd,
      idempotencyKey: "decision-invoice",
      taxRateBps: 0,
      taxMode: "exclusive",
    });
    await harness.service.transitionWithIdempotency({
      tenantId,
      resource: "invoice",
      id: generated.invoice.id,
      targetStatus: "reconciling",
      idempotencyKey: "decision-invoice-reconciling",
      actorId: "actor-commerce",
    });
    await harness.service.transitionWithIdempotency({
      tenantId,
      resource: "invoice",
      id: generated.invoice.id,
      targetStatus: "awaitingPayment",
      idempotencyKey: "decision-invoice-awaiting",
      actorId: "actor-commerce",
    });
    const disputed = await harness.service.disputeInvoice({
      tenantId,
      invoiceId: generated.invoice.id,
      reason,
      evidenceReference,
      idempotencyKey: "decision-dispute",
      actorId: "actor-commerce",
    });
    const disputeId = disputed.dispute.id;
    const reviewCommand = {
      tenantId,
      invoiceId: generated.invoice.id,
      disputeId,
      idempotencyKey: "decision-review",
      actorId: "actor-commerce",
    };
    const reviewed = await harness.service.startInvoiceDisputeReview(reviewCommand);
    const reviewReplay = await harness.service.startInvoiceDisputeReview(reviewCommand);
    expect(reviewReplay.replayed).toBe(true);
    const decideCommand = {
      tenantId,
      invoiceId: generated.invoice.id,
      disputeId,
      outcome: "accepted" as const,
      reference: "resolution://case-0001",
      resolutionNote: "Credit note issued",
      idempotencyKey: "decision-accept",
      actorId: "actor-commerce",
    };
    const decided = await harness.service.decideInvoiceDispute(decideCommand);
    const decideReplay = await harness.service.decideInvoiceDispute(decideCommand);
    expect(decideReplay.replayed).toBe(true);
    expect(decideReplay.dispute.id).toBe(decided.dispute.id);
    expect(reviewed.dispute.status).toBe("underReview");

    const events = await listEvents(harness.outbox, tenantId);
    expect(eventNames(events)).toEqual([
      COMMERCE_DOMAIN_EVENT_TYPES.invoiceCreated,
      COMMERCE_DOMAIN_EVENT_TYPES.invoiceStatusChanged,
      COMMERCE_DOMAIN_EVENT_TYPES.invoiceStatusChanged,
      COMMERCE_DOMAIN_EVENT_TYPES.disputeCreated,
      COMMERCE_DOMAIN_EVENT_TYPES.disputeStatusChanged,
      COMMERCE_DOMAIN_EVENT_TYPES.disputeDecided,
    ]);
    const statusChanged = events.find(
      (event) => event.eventType === COMMERCE_DOMAIN_EVENT_TYPES.disputeStatusChanged,
    );
    expect(statusChanged).toMatchObject({
      resourceId: disputeId,
      resourceType: COMMERCE_DOMAIN_EVENT_RESOURCE_TYPES.invoiceDispute,
      resourceStatus: "underReview",
      resourceVersion: 2,
      actorId: "actor-commerce",
      data: {
        invoiceId: generated.invoice.id,
        subscriptionId: subscription.id,
        fromStatus: "open",
        toStatus: "underReview",
      },
    });
    const decidedEvent = events.find(
      (event) => event.eventType === COMMERCE_DOMAIN_EVENT_TYPES.disputeDecided,
    );
    expect(decidedEvent).toMatchObject({
      resourceId: disputeId,
      resourceStatus: "accepted",
      resourceVersion: 3,
      data: {
        invoiceId: generated.invoice.id,
        subscriptionId: subscription.id,
        status: "accepted",
        outcome: "accepted",
        resolvedAt: now.toISOString(),
      },
    });
    expect(decidedEvent?.eventId).toBe(commerceDomainEventId({
      tenantId,
      actorId: "actor-commerce",
      operation: "invoice.dispute.decide",
      idempotencyKey: "decision-accept",
    }));
    expect(events).toHaveLength(6);
    expect(new Set(events.map((event) => event.eventId)).size).toBe(6);
    expect(events.every((event) => event.status === "published")).toBe(true);
    for (const event of [statusChanged, decidedEvent]) {
      expect(containsOpenPlatformSensitiveEventData(event?.data)).toBe(false);
      expect(JSON.stringify(event?.data)).not.toContain(reason);
      expect(JSON.stringify(event?.data)).not.toContain(evidenceReference);
      expect(JSON.stringify(event?.data)).not.toContain("Credit note issued");
    }
  });

  it("publishes a status change for a withdrawal and emits no events when disabled", async () => {
    const harness = createHarness();
    const tenantId = "tenant-commerce-dispute-withdrawal";
    const { subscription } = await createBillableFixture(harness, tenantId);
    const generated = await harness.service.generateInvoice({
      tenantId,
      subscriptionId: subscription.id,
      periodStart,
      periodEnd,
      idempotencyKey: "withdrawal-invoice",
      taxRateBps: 0,
      taxMode: "exclusive",
    });
    await harness.service.transition({
      tenantId,
      resource: "invoice",
      id: generated.invoice.id,
      targetStatus: "reconciling",
    });
    await harness.service.transition({
      tenantId,
      resource: "invoice",
      id: generated.invoice.id,
      targetStatus: "awaitingPayment",
    });
    const disputed = await harness.service.disputeInvoice({
      tenantId,
      invoiceId: generated.invoice.id,
      reason,
      idempotencyKey: "withdrawal-dispute",
      actorId: "actor-commerce",
    });
    await harness.service.withdrawInvoiceDispute({
      tenantId,
      invoiceId: generated.invoice.id,
      disputeId: disputed.dispute.id,
      reference: "withdrawal://case-0001",
      idempotencyKey: "withdrawal-withdraw",
      actorId: "actor-commerce",
    });
    const events = await listEvents(harness.outbox, tenantId);
    expect(eventNames(events)).toEqual([
      COMMERCE_DOMAIN_EVENT_TYPES.invoiceCreated,
      COMMERCE_DOMAIN_EVENT_TYPES.disputeCreated,
      COMMERCE_DOMAIN_EVENT_TYPES.disputeStatusChanged,
    ]);
    expect(events.at(-1)).toMatchObject({
      eventType: COMMERCE_DOMAIN_EVENT_TYPES.disputeStatusChanged,
      resourceStatus: "withdrawn",
      data: { fromStatus: "open", toStatus: "withdrawn" },
    });
    expect(events.some(
      (event) => event.eventType === COMMERCE_DOMAIN_EVENT_TYPES.disputeDecided,
    )).toBe(false);

    const disabled = createHarness({ eventsEnabled: false });
    const disabledTenant = "tenant-commerce-dispute-disabled";
    const disabledFixture = await createBillableFixture(disabled, disabledTenant);
    const disabledInvoice = await disabled.service.generateInvoice({
      tenantId: disabledTenant,
      subscriptionId: disabledFixture.subscription.id,
      periodStart,
      periodEnd,
      idempotencyKey: "disabled-invoice",
      taxRateBps: 0,
      taxMode: "exclusive",
    });
    await disabled.service.transition({
      tenantId: disabledTenant,
      resource: "invoice",
      id: disabledInvoice.invoice.id,
      targetStatus: "reconciling",
    });
    await disabled.service.transition({
      tenantId: disabledTenant,
      resource: "invoice",
      id: disabledInvoice.invoice.id,
      targetStatus: "awaitingPayment",
    });
    const disabledDispute = await disabled.service.disputeInvoice({
      tenantId: disabledTenant,
      invoiceId: disabledInvoice.invoice.id,
      reason,
      idempotencyKey: "disabled-dispute",
      actorId: "actor-commerce",
    });
    await expect(disabled.service.startInvoiceDisputeReview({
      tenantId: disabledTenant,
      invoiceId: disabledInvoice.invoice.id,
      disputeId: disabledDispute.dispute.id,
      idempotencyKey: "disabled-review",
      actorId: "actor-commerce",
    })).resolves.toMatchObject({ dispute: { status: "underReview" } });
    await expect(disabled.service.decideInvoiceDispute({
      tenantId: disabledTenant,
      invoiceId: disabledInvoice.invoice.id,
      disputeId: disabledDispute.dispute.id,
      outcome: "rejected",
      reference: "resolution://case-0002",
      idempotencyKey: "disabled-decide",
      actorId: "actor-commerce",
    })).resolves.toMatchObject({ dispute: { status: "rejected" } });
    await expect(listEvents(disabled.outbox, disabledTenant)).resolves.toEqual([]);
  });

  it("keeps existing behavior when no publisher is injected", async () => {
    const repositories = new InMemoryCommerceRepositories();
    const service = createCommerceService({ repositories, clock: () => now });
    expect(service.eventPublisher).toBeUndefined();
    await expect(service.isReady()).resolves.toMatchObject({
      ready: true,
      storage: "memory",
      distributed: false,
    });
    const tenantId = "tenant-commerce-no-publisher";
    const { listingId } = await seedMarketplace({ service, repositories } as Harness, tenantId);
    const transitioned = await service.transitionWithIdempotency({
      tenantId,
      resource: "marketplaceListing",
      id: listingId,
      targetStatus: "pendingReview",
      idempotencyKey: "no-publisher-transition",
      actorId: "actor-commerce",
    });
    expect(transitioned.replayed).toBe(false);
    expect(transitioned.record).toMatchObject({ status: "pendingReview", version: 2 });
    await expect(service.transitionWithIdempotency({
      tenantId,
      resource: "marketplaceListing",
      id: listingId,
      targetStatus: "pendingReview",
      idempotencyKey: "no-publisher-transition",
      actorId: "actor-commerce",
    })).resolves.toMatchObject({ replayed: true });
  });

  it("keeps existing behavior when events are explicitly disabled", async () => {
    const harness = createHarness({ eventsEnabled: false });
    const tenantId = "tenant-commerce-events-disabled";
    await seedMarketplace(harness, tenantId);
    await harness.service.transitionWithIdempotency({
      tenantId,
      resource: "partnerAccount",
      id: (await harness.repositories.partnerAccounts.list(tenantId))[0]?.id ?? "",
      targetStatus: "underReview",
      idempotencyKey: "disabled-transition",
      actorId: "actor-commerce",
    });
    await expect(listEvents(harness.outbox, tenantId)).resolves.toEqual([]);
    await expect(harness.service.isReady()).resolves.toMatchObject({ ready: true });
  });

  it("fails production writes closed and audits the event failure", async () => {
    const harness = createHarness({
      production: true,
      publisher: {
        readiness: { storage: "persistent", distributed: true, ready: () => true },
        record: async () => {
          throw new Error("outbox unavailable");
        },
        publish: async () => ({
          eventId: "unused",
          delivered: 0,
          deadLettered: false,
        }),
      },
    });
    const tenantId = "tenant-commerce-production-events";
    await expect(harness.service.createPartnerAccount({
      tenantId,
      legalName: "生态伙伴有限公司",
      partnerCode: "partner-production",
      settlementReference: "settlement://partner/production",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.STORAGE_UNAVAILABLE,
    });
    const records = harness.audit.list(tenantId);
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      tenantId,
      action: "partnerAccount.create.event",
      outcome: "failure",
      target: { type: "partnerAccount" },
      metadata: { errorCode: OPEN_PLATFORM_COMMERCE_ERROR_CODES.STORAGE_UNAVAILABLE },
    });
    await expect(listEvents(harness.outbox, tenantId)).resolves.toEqual([]);
  });

  it("skips event failures silently outside production", async () => {
    const harness = createHarness({
      publisher: {
        readiness: { storage: "memory", distributed: false, ready: () => true },
        record: async () => {
          throw new Error("outbox unavailable");
        },
        publish: async () => ({
          eventId: "unused",
          delivered: 0,
          deadLettered: false,
        }),
      },
    });
    const tenantId = "tenant-commerce-development-events";
    const partner = await harness.service.createPartnerAccount({
      tenantId,
      legalName: "生态伙伴有限公司",
      partnerCode: "partner-development",
      settlementReference: "settlement://partner/development",
    });
    expect(partner.status).toBe("pending");
    await expect(harness.service.transitionWithIdempotency({
      tenantId,
      resource: "partnerAccount",
      id: partner.id,
      targetStatus: "underReview",
      idempotencyKey: "development-transition",
      actorId: "actor-commerce",
    })).resolves.toMatchObject({
      replayed: false,
      record: { status: "underReview" },
    });
    expect(harness.audit.list(tenantId)).toEqual([]);
    await expect(listEvents(harness.outbox, tenantId)).resolves.toEqual([]);
  });

  it("reports not ready while an enabled publisher is not ready", async () => {
    const harness = createHarness({
      publisher: {
        readiness: { storage: "memory", distributed: false, ready: () => false },
        record: async () => {
          throw new Error("record must not be reached");
        },
        publish: async () => ({
          eventId: "unused",
          delivered: 0,
          deadLettered: false,
        }),
      },
    });
    await expect(harness.service.isReady()).resolves.toMatchObject({ ready: false });
    const tenantId = "tenant-commerce-not-ready";
    await expect(harness.service.createPartnerAccount({
      tenantId,
      legalName: "生态伙伴有限公司",
      partnerCode: "partner-not-ready",
      settlementReference: "settlement://partner/not-ready",
    })).resolves.toMatchObject({ status: "pending" });
    await expect(listEvents(harness.outbox, tenantId)).resolves.toEqual([]);
  });
});
