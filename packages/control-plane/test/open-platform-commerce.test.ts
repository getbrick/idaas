import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  CommerceDomainService,
  InMemoryCommerceRepositories,
  OPEN_PLATFORM_COMMERCE_ERROR_CODES,
  INVOICE_DISPUTE_TRANSITIONS,
  assertInvoiceDisputeTransition,
  calculateMarketplaceCommission,
  canTransitionInvoice,
  canTransitionInvoiceDispute,
  isTerminalInvoiceDisputeStatus,
  createCommerceService,
  decimalToUnits,
  toOpenPlatformCommerceContractError,
  type CommissionRule,
  type DecideInvoiceDisputeCommand,
  type GenerateInvoiceCommand,
  type Meter,
  type Plan,
  type Price,
  type Subscription,
} from "../src/open-platform/commerce/index.js";

const now = new Date("2030-01-15T00:00:00.000Z");
const periodStart = "2030-01-01T00:00:00.000Z";
const periodEnd = "2030-02-01T00:00:00.000Z";

interface Fixture {
  readonly service: CommerceDomainService;
  readonly repositories: InMemoryCommerceRepositories;
  readonly tenantId: string;
  readonly meter: Meter;
  readonly price: Price;
  readonly plan: Plan;
  readonly subscription: Subscription;
}

function createService(): {
  service: CommerceDomainService;
  repositories: InMemoryCommerceRepositories;
} {
  const repositories = new InMemoryCommerceRepositories();
  return {
    repositories,
    service: createCommerceService({ repositories, clock: () => now }),
  };
}

async function activateMeter(
  service: CommerceDomainService,
  tenantId: string,
  meter: Meter,
): Promise<void> {
  await service.transition({
    tenantId,
    resource: "meter",
    id: meter.id,
    targetStatus: "active",
  });
}

async function activatePrice(
  service: CommerceDomainService,
  tenantId: string,
  price: Price,
): Promise<void> {
  await service.transition({
    tenantId,
    resource: "price",
    id: price.id,
    targetStatus: "active",
  });
}

async function activatePlan(
  service: CommerceDomainService,
  tenantId: string,
  plan: Plan,
): Promise<void> {
  await service.transition({
    tenantId,
    resource: "plan",
    id: plan.id,
    targetStatus: "active",
  });
}

async function activateSubscription(
  service: CommerceDomainService,
  tenantId: string,
  subscription: Subscription,
): Promise<void> {
  await service.transition({
    tenantId,
    resource: "subscription",
    id: subscription.id,
    targetStatus: "active",
  });
}

async function createFixture(
  input: {
    tenantId?: string;
    service?: CommerceDomainService;
    repositories?: InMemoryCommerceRepositories;
    unitAmountMinor?: number;
  } = {},
): Promise<Fixture> {
  const created = input.service === undefined
    ? createService()
    : {
      service: input.service,
      repositories: input.repositories as InMemoryCommerceRepositories,
    };
  const tenantId = input.tenantId ?? "tenant-commerce";
  const meter = await created.service.createMeter({
    tenantId,
    key: "api.requests",
    name: "API requests",
    unit: "request",
    aggregation: "sum",
    dimensions: ["region"],
  });
  await activateMeter(created.service, tenantId, meter);
  const price = await created.service.createPrice({
    tenantId,
    code: "requests-cny",
    name: "CNY requests",
    priceType: "perUnit",
    meterId: meter.id,
    unitAmount: {
      amountMinor: input.unitAmountMinor ?? 10,
      currency: "CNY",
    },
    includedUnits: "0",
    minimumCharge: { amountMinor: 0, currency: "CNY" },
    effectiveFrom: periodStart,
  });
  await activatePrice(created.service, tenantId, price);
  const plan = await created.service.createPlan({
    tenantId,
    code: "standard",
    name: "Standard plan",
    priceIds: [price.id],
    effectiveFrom: periodStart,
  });
  await activatePlan(created.service, tenantId, plan);
  const subscription = await created.service.createSubscription({
    tenantId,
    applicationId: `app_${randomUUID()}`,
    planId: plan.id,
    name: "Standard subscription",
    quantity: "1",
    currentPeriodStart: periodStart,
    currentPeriodEnd: periodEnd,
  });
  await activateSubscription(created.service, tenantId, subscription);
  return {
    service: created.service,
    repositories: created.repositories,
    tenantId,
    meter,
    price,
    plan,
    subscription,
  };
}

async function activateEntitlement(
  service: CommerceDomainService,
  tenantId: string,
  id: string,
): Promise<void> {
  await service.transition({
    tenantId,
    resource: "entitlement",
    id,
    targetStatus: "active",
  });
}

describe("open platform commerce tenant scope and entitlement priority", () => {
  it("keeps every repository and resolution tenant scoped", async () => {
    const fixture = await createFixture({ tenantId: "tenant-commerce-a" });
    const other = await createFixture({
      tenantId: "tenant-commerce-b",
      service: fixture.service,
      repositories: fixture.repositories,
    });
    const tenantGrant = await fixture.service.grantEntitlement({
      tenantId: fixture.tenantId,
      feature: "api.access",
      effect: "allow",
      source: "tenant",
      sourceId: fixture.tenantId,
      priority: 1,
      effectiveFrom: periodStart,
    });
    await activateEntitlement(
      fixture.service,
      fixture.tenantId,
      tenantGrant.id,
    );
    await expect(fixture.service.resolveEntitlements({
      tenantId: other.tenantId,
      features: ["api.access"],
      at: now.toISOString(),
    })).resolves.toMatchObject({
      entitlements: [{ allowed: false, reason: "defaultDenied" }],
    });
    await expect(fixture.repositories.plans.get(
      other.tenantId,
      fixture.plan.id,
    )).resolves.toBeUndefined();
    await expect(fixture.repositories.entitlements.list(other.tenantId))
      .resolves.toEqual([]);
  });

  it("uses the highest priority and then source specificity deterministically", async () => {
    const fixture = await createFixture();
    const planDeny = await fixture.service.grantEntitlement({
      tenantId: fixture.tenantId,
      feature: "exports",
      effect: "deny",
      source: "plan",
      sourceId: fixture.plan.id,
      priority: 50,
      effectiveFrom: periodStart,
    });
    const subscriptionAllow = await fixture.service.grantEntitlement({
      tenantId: fixture.tenantId,
      feature: "exports",
      effect: "allow",
      value: true,
      source: "subscription",
      sourceId: fixture.subscription.id,
      priority: 100,
      effectiveFrom: periodStart,
    });
    await activateEntitlement(fixture.service, fixture.tenantId, planDeny.id);
    await activateEntitlement(
      fixture.service,
      fixture.tenantId,
      subscriptionAllow.id,
    );
    const result = await fixture.service.resolveEntitlements({
      tenantId: fixture.tenantId,
      planId: fixture.plan.id,
      subscriptionId: fixture.subscription.id,
      features: ["exports"],
      at: now.toISOString(),
    });
    expect(result.entitlements).toEqual([
      expect.objectContaining({
        feature: "exports",
        allowed: true,
        entitlementId: subscriptionAllow.id,
        source: "subscription",
        priority: 100,
      }),
    ]);
  });
});

describe("open platform commerce exact pricing", () => {
  it("uses integer minor units with half-up and half-even boundaries", async () => {
    const fixture = await createFixture({ unitAmountMinor: 1 });
    const halfEven = await fixture.service.createPrice({
      tenantId: fixture.tenantId,
      code: "half-even",
      name: "Half even",
      priceType: "perUnit",
      meterId: fixture.meter.id,
      unitAmount: { amountMinor: 1, currency: "CNY" },
      includedUnits: "0",
      minimumCharge: { amountMinor: 0, currency: "CNY" },
      roundingMode: "halfEven",
      effectiveFrom: periodStart,
    });
    await activatePrice(fixture.service, fixture.tenantId, halfEven);
    await expect(fixture.service.calculate({
      tenantId: fixture.tenantId,
      priceId: fixture.price.id,
      usage: [{ meterId: fixture.meter.id, quantity: "0.5" }],
    })).resolves.toMatchObject({ total: { amountMinor: 1 } });
    await expect(fixture.service.calculate({
      tenantId: fixture.tenantId,
      priceId: halfEven.id,
      usage: [{ meterId: fixture.meter.id, quantity: "0.5" }],
    })).resolves.toMatchObject({ total: { amountMinor: 0 } });
    await expect(fixture.service.calculate({
      tenantId: fixture.tenantId,
      priceId: fixture.price.id,
      usage: [{ meterId: fixture.meter.id, quantity: "2.5" }],
    })).resolves.toMatchObject({ total: { amountMinor: 3 } });
    await expect(fixture.service.calculate({
      tenantId: fixture.tenantId,
      priceId: halfEven.id,
      usage: [{ meterId: fixture.meter.id, quantity: "2.5" }],
    })).resolves.toMatchObject({ total: { amountMinor: 2 } });
  });

  it("accepts zero prices and rejects negative money and usage", async () => {
    const fixture = await createFixture();
    const free = await fixture.service.createPrice({
      tenantId: fixture.tenantId,
      code: "free",
      name: "Free",
      priceType: "perUnit",
      meterId: fixture.meter.id,
      unitAmount: { amountMinor: 0, currency: "CNY" },
      includedUnits: "0",
      minimumCharge: { amountMinor: 0, currency: "CNY" },
      effectiveFrom: periodStart,
    });
    await activatePrice(fixture.service, fixture.tenantId, free);
    await expect(fixture.service.calculate({
      tenantId: fixture.tenantId,
      priceId: free.id,
      usage: [{ meterId: fixture.meter.id, quantity: "999.125" }],
    })).resolves.toMatchObject({ total: { amountMinor: 0 } });
    await expect(fixture.service.createPrice({
      tenantId: fixture.tenantId,
      code: "negative",
      name: "Negative",
      priceType: "fixed",
      fixedAmount: { amountMinor: -1, currency: "CNY" },
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.NEGATIVE_AMOUNT,
    });
    await expect(fixture.service.calculate({
      tenantId: fixture.tenantId,
      priceId: fixture.price.id,
      usage: [{ meterId: fixture.meter.id, quantity: "-1" }],
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.VALIDATION_ERROR,
    });
    await expect(fixture.service.calculate({
      tenantId: fixture.tenantId,
      priceId: fixture.price.id,
      usage: [{ meterId: fixture.meter.id, quantity: "9".repeat(129) }],
    })).rejects.toMatchObject({
      name: "OpenPlatformCommerceError",
      code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.VALIDATION_ERROR,
    });
  });

  it("prices cumulative tiers across carry, boundaries, and high quantities", async () => {
    expect(decimalToUnits("100.5")).toBe(100_500_000_000_000_000_000n);
    const fixture = await createFixture();
    const tiers = [
      { upTo: "100", unitAmount: { amountMinor: 1, currency: "CNY" as const } },
      { upTo: "1000", unitAmount: { amountMinor: 2, currency: "CNY" as const } },
      { upTo: null, unitAmount: { amountMinor: 3, currency: "CNY" as const } },
    ];
    const tiered = await fixture.service.createPrice({
      tenantId: fixture.tenantId,
      code: "tiered-half-up",
      name: "Tiered half up",
      priceType: "tiered",
      meterId: fixture.meter.id,
      tiers,
      roundingMode: "halfUp",
      effectiveFrom: periodStart,
    });
    const halfEven = await fixture.service.createPrice({
      tenantId: fixture.tenantId,
      code: "tiered-half-even",
      name: "Tiered half even",
      priceType: "tiered",
      meterId: fixture.meter.id,
      tiers: [
        { upTo: "100", unitAmount: { amountMinor: 1, currency: "CNY" } },
        { upTo: null, unitAmount: { amountMinor: 1, currency: "CNY" } },
      ],
      roundingMode: "halfEven",
      effectiveFrom: periodStart,
    });
    const overflow = await fixture.service.createPrice({
      tenantId: fixture.tenantId,
      code: "tiered-overflow",
      name: "Tiered overflow",
      priceType: "tiered",
      meterId: fixture.meter.id,
      tiers: [{
        upTo: null,
        unitAmount: {
          amountMinor: Number.MAX_SAFE_INTEGER,
          currency: "CNY",
        },
      }],
      effectiveFrom: periodStart,
    });
    await activatePrice(fixture.service, fixture.tenantId, tiered);
    await activatePrice(fixture.service, fixture.tenantId, halfEven);
    await activatePrice(fixture.service, fixture.tenantId, overflow);
    const cases = [
      ["0", 0],
      ["100", 100],
      ["100.000000000000000001", 100],
      ["100.5", 101],
      ["1000", 1900],
      ["1000.5", 1902],
      ["1000000000000000", 2_999_999_999_998_900],
    ] as const;
    for (const [quantity, expected] of cases) {
      await expect(fixture.service.calculate({
        tenantId: fixture.tenantId,
        priceId: tiered.id,
        usage: [{ meterId: fixture.meter.id, quantity }],
      })).resolves.toMatchObject({ total: { amountMinor: expected } });
    }
    await expect(fixture.service.calculate({
      tenantId: fixture.tenantId,
      priceId: halfEven.id,
      usage: [{ meterId: fixture.meter.id, quantity: "100.5" }],
    })).resolves.toMatchObject({ total: { amountMinor: 100 } });
    await expect(fixture.service.calculate({
      tenantId: fixture.tenantId,
      priceId: overflow.id,
      usage: [{ meterId: fixture.meter.id, quantity: "2" }],
    })).rejects.toMatchObject({
      name: "OpenPlatformCommerceError",
      code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.CALCULATION_ERROR,
    });
  });
});

describe("open platform commerce usage and quota concurrency", () => {
  it("deduplicates concurrent event ingestion and aggregation", async () => {
    const fixture = await createFixture();
    const command = {
      tenantId: fixture.tenantId,
      subscriptionId: fixture.subscription.id,
      meterId: fixture.meter.id,
      quantity: "2.5",
      occurredAt: "2030-01-15T00:00:00.000Z",
      periodStart,
      periodEnd,
      dimensions: { region: "cn-mainland" },
      sourceEventId: "gateway-request-001",
      idempotencyKey: "usage-request-001",
    } as const;
    const results = await Promise.all([
      fixture.service.recordAndAggregate(command),
      fixture.service.recordAndAggregate(command),
    ]);
    expect(results.filter((result) => result.event.accepted)).toHaveLength(1);
    const aggregates = await fixture.repositories.usageEvents.list(fixture.tenantId);
    expect(aggregates).toHaveLength(1);
    const final = await fixture.service.aggregateUsage({
      tenantId: fixture.tenantId,
      subscriptionId: fixture.subscription.id,
      meterId: fixture.meter.id,
      periodStart,
      periodEnd,
      dimensions: { region: "cn-mainland" },
    });
    expect(final.aggregate.quantity).toBe("2.5");
    expect(final.aggregate.eventIds).toHaveLength(1);
    const replay = await fixture.service.recordAndAggregate(command);
    expect(replay.aggregate.aggregate.quantity).toBe("2.5");
    expect(replay.aggregate.aggregate.eventIds).toHaveLength(1);
    const sourceRetry = await fixture.service.recordAndAggregate({
      ...command,
      idempotencyKey: "usage-request-retry",
    });
    expect(sourceRetry.event.accepted).toBe(false);
    expect(sourceRetry.aggregate.aggregate.quantity).toBe("2.5");
    expect(sourceRetry.aggregate.aggregate.eventIds).toHaveLength(1);
  });

  it("allows only one concurrent reservation at the quota boundary and settles once", async () => {
    const fixture = await createFixture();
    const quota = await fixture.service.createQuota({
      tenantId: fixture.tenantId,
      planId: fixture.plan.id,
      meterId: fixture.meter.id,
      limit: "10",
    });
    const attempts = await Promise.allSettled([
      fixture.service.reserve({
        tenantId: fixture.tenantId,
        subscriptionId: fixture.subscription.id,
        quotaId: quota.id,
        quantity: "6",
        expiresAt: "2030-01-20T00:00:00.000Z",
        idempotencyKey: "quota-reservation-a",
      }),
      fixture.service.reserve({
        tenantId: fixture.tenantId,
        subscriptionId: fixture.subscription.id,
        quotaId: quota.id,
        quantity: "6",
        expiresAt: "2030-01-20T00:00:00.000Z",
        idempotencyKey: "quota-reservation-b",
      }),
    ]);
    expect(attempts.filter((attempt) => attempt.status === "fulfilled"))
      .toHaveLength(1);
    expect(attempts.filter((attempt) => attempt.status === "rejected"))
      .toHaveLength(1);
    const successful = attempts.find(
      (attempt): attempt is PromiseFulfilledResult<
        Awaited<ReturnType<typeof fixture.service.reserve>>
      > => attempt.status === "fulfilled",
    );
    if (successful === undefined) throw new Error("quota reservation did not succeed");
    const settled = await fixture.service.settle({
      tenantId: fixture.tenantId,
      quotaId: quota.id,
      reservationId: successful.value.reservation.id,
      actualQuantity: "4",
      idempotencyKey: "quota-settlement",
    });
    expect(settled.quota).toMatchObject({ reserved: "0", consumed: "4" });
    const replay = await fixture.service.settle({
      tenantId: fixture.tenantId,
      quotaId: quota.id,
      reservationId: successful.value.reservation.id,
      actualQuantity: "4",
      idempotencyKey: "quota-settlement",
    });
    expect(replay.replayed).toBe(true);
    expect(replay.quota.consumed).toBe("4");
    const idempotentCommand = {
      tenantId: fixture.tenantId,
      subscriptionId: fixture.subscription.id,
      quotaId: quota.id,
      quantity: "1",
      expiresAt: "2030-01-20T00:00:00.000Z",
      idempotencyKey: "quota-reservation-idempotent",
    } as const;
    const idempotent = await Promise.all([
      fixture.service.reserve(idempotentCommand),
      fixture.service.reserve(idempotentCommand),
    ]);
    expect(idempotent[0]?.reservation.id).toBe(idempotent[1]?.reservation.id);
    expect(idempotent.map((result) => result.replayed).sort()).toEqual([
      false,
      true,
    ]);
    await fixture.service.release({
      tenantId: fixture.tenantId,
      quotaId: quota.id,
      reservationId: idempotent[0]?.reservation.id ?? "",
      idempotencyKey: "quota-release-idempotent",
    });
  });

  it("scopes reservation idempotency by operation, quota, and subscription", async () => {
    const fixture = await createFixture();
    const secondSubscription = await fixture.service.createSubscription({
      tenantId: fixture.tenantId,
      applicationId: `app_${randomUUID()}`,
      planId: fixture.plan.id,
      name: "Second subscription",
      currentPeriodStart: periodStart,
      currentPeriodEnd: periodEnd,
    });
    await activateSubscription(
      fixture.service,
      fixture.tenantId,
      secondSubscription,
    );
    const firstQuota = await fixture.service.createQuota({
      tenantId: fixture.tenantId,
      planId: fixture.plan.id,
      meterId: fixture.meter.id,
      limit: "100",
    });
    const secondQuota = await fixture.service.createQuota({
      tenantId: fixture.tenantId,
      planId: fixture.plan.id,
      meterId: fixture.meter.id,
      limit: "100",
    });
    const sharedKey = "shared-reservation-key";
    const first = await fixture.service.reserve({
      tenantId: fixture.tenantId,
      subscriptionId: fixture.subscription.id,
      quotaId: firstQuota.id,
      quantity: "1",
      expiresAt: "2030-01-20T00:00:00.000Z",
      idempotencyKey: sharedKey,
    });
    const otherSubscription = await fixture.service.reserve({
      tenantId: fixture.tenantId,
      subscriptionId: secondSubscription.id,
      quotaId: firstQuota.id,
      quantity: "2",
      expiresAt: "2030-01-20T00:00:00.000Z",
      idempotencyKey: sharedKey,
    });
    const otherQuota = await fixture.service.reserve({
      tenantId: fixture.tenantId,
      subscriptionId: fixture.subscription.id,
      quotaId: secondQuota.id,
      quantity: "3",
      expiresAt: "2030-01-20T00:00:00.000Z",
      idempotencyKey: sharedKey,
    });
    expect(new Set([
      first.reservation.id,
      otherSubscription.reservation.id,
      otherQuota.reservation.id,
    ]).size).toBe(3);
    await expect(fixture.service.reserve({
      tenantId: fixture.tenantId,
      subscriptionId: fixture.subscription.id,
      quotaId: firstQuota.id,
      quantity: "4",
      expiresAt: "2030-01-20T00:00:00.000Z",
      idempotencyKey: sharedKey,
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.IDEMPOTENCY_KEY_REUSED,
    });
    const terminalKey = "shared-terminal-key";
    await fixture.service.settle({
      tenantId: fixture.tenantId,
      quotaId: firstQuota.id,
      reservationId: first.reservation.id,
      actualQuantity: "1",
      idempotencyKey: terminalKey,
    });
    await expect(fixture.service.settle({
      tenantId: fixture.tenantId,
      quotaId: firstQuota.id,
      reservationId: first.reservation.id,
      actualQuantity: "1",
      idempotencyKey: terminalKey,
    })).resolves.toMatchObject({ replayed: true });
    await expect(fixture.service.settle({
      tenantId: fixture.tenantId,
      quotaId: firstQuota.id,
      reservationId: first.reservation.id,
      actualQuantity: "0.5",
      idempotencyKey: terminalKey,
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.IDEMPOTENCY_KEY_REUSED,
    });
    await expect(fixture.service.release({
      tenantId: fixture.tenantId,
      quotaId: firstQuota.id,
      reservationId: first.reservation.id,
      idempotencyKey: terminalKey,
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.RESOURCE_CONFLICT,
    });
  });
});

describe("open platform commerce invoice and marketplace", () => {
  it("generates tiered invoices without internal arithmetic failures", async () => {
    const fixture = await createFixture();
    const tiered = await fixture.service.createPrice({
      tenantId: fixture.tenantId,
      code: "invoice-tiered",
      name: "Invoice tiered",
      priceType: "tiered",
      meterId: fixture.meter.id,
      tiers: [
        { upTo: "100", unitAmount: { amountMinor: 1, currency: "CNY" } },
        { upTo: null, unitAmount: { amountMinor: 2, currency: "CNY" } },
      ],
      roundingMode: "halfUp",
      effectiveFrom: periodStart,
    });
    await activatePrice(fixture.service, fixture.tenantId, tiered);
    const plan = await fixture.service.createPlan({
      tenantId: fixture.tenantId,
      code: "tiered-plan",
      name: "Tiered plan",
      priceIds: [tiered.id],
      effectiveFrom: periodStart,
    });
    await activatePlan(fixture.service, fixture.tenantId, plan);
    const subscription = await fixture.service.createSubscription({
      tenantId: fixture.tenantId,
      applicationId: `app_${randomUUID()}`,
      planId: plan.id,
      name: "Tiered subscription",
      currentPeriodStart: periodStart,
      currentPeriodEnd: periodEnd,
    });
    await activateSubscription(
      fixture.service,
      fixture.tenantId,
      subscription,
    );
    const usage = await fixture.service.recordAndAggregate({
      tenantId: fixture.tenantId,
      subscriptionId: subscription.id,
      meterId: fixture.meter.id,
      quantity: "100.5",
      occurredAt: "2030-01-15T00:00:00.000Z",
      periodStart,
      periodEnd,
      dimensions: { region: "cn-mainland" },
      sourceEventId: "tiered-invoice-event",
      idempotencyKey: "tiered-invoice-usage",
    });
    await fixture.service.transition({
      tenantId: fixture.tenantId,
      resource: "usageAggregate",
      id: usage.aggregate.aggregate.id,
      targetStatus: "closed",
    });
    const generated = await fixture.service.generateInvoice({
      tenantId: fixture.tenantId,
      subscriptionId: subscription.id,
      periodStart,
      periodEnd,
      idempotencyKey: "tiered-invoice",
      taxRateBps: 0,
      taxMode: "exclusive",
    });
    expect(generated.invoice).toMatchObject({
      subtotal: { amountMinor: 101 },
      tax: { amountMinor: 0 },
      total: { amountMinor: 101 },
    });
  });

  it("generates idempotent CNY invoices and rejects over-refunds", async () => {
    const fixture = await createFixture({ unitAmountMinor: 10 });
    const usage = await fixture.service.recordAndAggregate({
      tenantId: fixture.tenantId,
      subscriptionId: fixture.subscription.id,
      meterId: fixture.meter.id,
      quantity: "2.5",
      occurredAt: "2030-01-15T00:00:00.000Z",
      periodStart,
      periodEnd,
      dimensions: { region: "cn-mainland" },
      sourceEventId: "invoice-request-001",
      idempotencyKey: "invoice-usage-001",
    });
    await fixture.service.transition({
      tenantId: fixture.tenantId,
      resource: "usageAggregate",
      id: usage.aggregate.aggregate.id,
      targetStatus: "closed",
    });
    const command: GenerateInvoiceCommand = {
      tenantId: fixture.tenantId,
      subscriptionId: fixture.subscription.id,
      periodStart,
      periodEnd,
      idempotencyKey: "invoice-2030-01",
      taxRateBps: 600,
      taxMode: "exclusive",
      mainlandChina: {
        invoiceType: "vatSpecial",
        buyerName: "中国大陆示例有限公司",
        unifiedSocialCreditCode: "91310000MA1FL0000X",
        taxRateBps: 600,
        issueMode: "platform",
      },
    };
    const generated = await fixture.service.generateInvoice(command);
    expect(generated.invoice).toMatchObject({
      currency: "CNY",
      subtotal: { amountMinor: 25 },
      tax: { amountMinor: 2 },
      total: { amountMinor: 27 },
      mainlandChina: { invoiceType: "vatSpecial" },
    });
    const replay = await fixture.service.generateInvoice(command);
    expect(replay.replayed).toBe(true);
    expect(replay.invoice.id).toBe(generated.invoice.id);
    await expect(fixture.repositories.invoices.list(fixture.tenantId))
      .resolves.toHaveLength(1);
    await expect(fixture.service.generateInvoice({
      ...command,
      adjustments: [{
        id: "discount-001",
        type: "discount",
        direction: "credit",
        amount: { amountMinor: 1, currency: "CNY" },
        reason: "service credit",
      }],
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.IDEMPOTENCY_KEY_REUSED,
    });
    await expect(fixture.service.generateInvoice({
      ...command,
      idempotencyKey: "invoice-over-refund",
      adjustments: [{
        id: "refund-001",
        type: "refund",
        direction: "credit",
        amount: { amountMinor: 26, currency: "CNY" },
        reason: "refund exceeds bill",
      }],
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.INVALID_TOTAL,
    });
    await expect(fixture.service.generateInvoice({
      ...command,
      idempotencyKey: "invoice-negative",
      adjustments: [{
        id: "negative-001",
        type: "refund",
        direction: "credit",
        amount: { amountMinor: -1, currency: "CNY" },
        reason: "invalid negative amount",
      }],
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.NEGATIVE_AMOUNT,
    });
  });

  it("enforces commission rate and fixed caps without floating point", async () => {
    const fixture = await createFixture();
    const partner = await fixture.service.createPartnerAccount({
      tenantId: fixture.tenantId,
      legalName: "生态伙伴有限公司",
      partnerCode: "partner-cn",
      settlementReference: "settlement://partner/cn",
    });
    await fixture.service.transition({
      tenantId: fixture.tenantId,
      resource: "partnerAccount",
      id: partner.id,
      targetStatus: "underReview",
    });
    await fixture.service.transition({
      tenantId: fixture.tenantId,
      resource: "partnerAccount",
      id: partner.id,
      targetStatus: "active",
    });
    const listing = await fixture.service.createMarketplaceListing({
      tenantId: fixture.tenantId,
      partnerAccountId: partner.id,
      productId: `product_${randomUUID()}`,
      title: "Marketplace API",
      description: "Partner supplied API",
    });
    await fixture.service.transition({
      tenantId: fixture.tenantId,
      resource: "marketplaceListing",
      id: listing.id,
      targetStatus: "pendingReview",
    });
    await fixture.service.transition({
      tenantId: fixture.tenantId,
      resource: "marketplaceListing",
      id: listing.id,
      targetStatus: "published",
    });
    const rule = await fixture.service.createCommissionRule({
      tenantId: fixture.tenantId,
      partnerAccountId: partner.id,
      listingId: listing.id,
      name: "Capped commission",
      rateBps: 3000,
      capBps: 2000,
      capAmount: { amountMinor: 1500, currency: "CNY" },
      effectiveFrom: periodStart,
    });
    await fixture.service.transition({
      tenantId: fixture.tenantId,
      resource: "commissionRule",
      id: rule.id,
      targetStatus: "active",
    });
    const result = await fixture.service.calculateCommission({
      tenantId: fixture.tenantId,
      listingId: listing.id,
      grossAmount: { amountMinor: 10_000, currency: "CNY" },
      at: now.toISOString(),
    });
    expect(result).toMatchObject({
      rateBps: 2000,
      uncappedAmount: { amountMinor: 2000 },
      commissionAmount: { amountMinor: 1500 },
      partnerAmount: { amountMinor: 8500 },
      capped: true,
    });
  });

  it("normalizes internal arithmetic failures before HTTP mapping", async () => {
    const internalError = new RangeError("secret BigInt exponent internals");
    const hostileRule = new Proxy({} as CommissionRule, {
      get() {
        throw internalError;
      },
    });
    let commissionError: unknown;
    try {
      calculateMarketplaceCommission(
        "tenant-commerce",
        { amountMinor: 100, currency: "CNY" },
        hostileRule,
      );
    } catch (error) {
      commissionError = error;
    }
    expect(commissionError).toMatchObject({
      name: "OpenPlatformCommerceError",
      code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.CALCULATION_ERROR,
    });
    const contractError = toOpenPlatformCommerceContractError(internalError);
    expect(contractError).toEqual({
      statusCode: 400,
      body: {
        code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.CALCULATION_ERROR,
        message: "Open platform commerce request failed",
      },
    });
    expect(JSON.stringify(contractError)).not.toContain("BigInt exponent");

    const fixture = await createFixture();
    const originalCreate = fixture.repositories.invoices.createIdempotent;
    fixture.repositories.invoices.createIdempotent = async () => {
      throw new RangeError("invoice repository internals");
    };
    await expect(fixture.service.generateInvoice({
      tenantId: fixture.tenantId,
      subscriptionId: fixture.subscription.id,
      periodStart,
      periodEnd,
      idempotencyKey: "invoice-internal-error",
      taxRateBps: 0,
      taxMode: "exclusive",
    })).rejects.toMatchObject({
      name: "OpenPlatformCommerceError",
      code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.CALCULATION_ERROR,
    });
    fixture.repositories.invoices.createIdempotent = originalCreate;
  });

  it("exposes fail-closed readiness and legal invoice transitions", async () => {
    const repositories = new InMemoryCommerceRepositories({ production: true });
    const service = createCommerceService({ repositories, clock: () => now });
    await expect(service.isReady()).resolves.toEqual({
      ready: false,
      storage: "memory",
      distributed: false,
    });
    expect(canTransitionInvoice("draft", "reconciling")).toBe(true);
    expect(canTransitionInvoice("draft", "completed")).toBe(false);
  });
});

describe("open platform commerce invoice dispute evidence", () => {
  const otherTenantId = "tenant-commerce-dispute-other";
  const reason = "Invoice charge not recognized by the buyer";
  const evidenceReference = "evidence://ticket-0001/attachment";

  async function awaitPayment(
    service: CommerceDomainService,
    tenantId: string,
    invoiceId: string,
  ): Promise<void> {
    await service.transition({
      tenantId,
      resource: "invoice",
      id: invoiceId,
      targetStatus: "reconciling",
    });
    await service.transition({
      tenantId,
      resource: "invoice",
      id: invoiceId,
      targetStatus: "awaitingPayment",
    });
  }

  it("appends dispute evidence with the invoice transition and never writes twice", async () => {
    const fixture = await createFixture();
    const generated = await fixture.service.generateInvoice({
      tenantId: fixture.tenantId,
      subscriptionId: fixture.subscription.id,
      periodStart,
      periodEnd,
      idempotencyKey: "dispute-invoice",
      taxRateBps: 600,
      taxMode: "exclusive",
    });
    await awaitPayment(fixture.service, fixture.tenantId, generated.invoice.id);
    const first = await fixture.service.disputeInvoice({
      tenantId: fixture.tenantId,
      invoiceId: generated.invoice.id,
      reason,
      evidenceReference,
      idempotencyKey: "dispute-key",
      actorId: "actor-dispute",
      requestId: "request-dispute",
    });
    expect(first.replayed).toBe(false);
    expect(first.invoice).toMatchObject({
      id: generated.invoice.id,
      status: "disputed",
      version: 4,
      total: { amountMinor: 0, currency: "CNY" },
    });
    expect(first.dispute).toMatchObject({
      tenantId: fixture.tenantId,
      kind: "invoiceDispute",
      version: 1,
      event: "invoice.dispute.opened",
      invoiceId: generated.invoice.id,
      subscriptionId: fixture.subscription.id,
      planId: fixture.plan.id,
      invoiceStatus: "awaitingPayment",
      invoiceVersion: 3,
      reason,
      reasonLength: reason.length,
      evidenceReference,
      evidenceCount: 1,
      actorId: "actor-dispute",
      requestId: "request-dispute",
      status: "open",
      createdAt: now.toISOString(),
      updatedAt: now.toISOString(),
      recordedAt: now.toISOString(),
    });
    expect(first.dispute.id).toMatch(/^invoice-dispute_[0-9a-f-]{36}$/u);
    expect(first.dispute).not.toHaveProperty("requestHash");
    expect(first.dispute).not.toHaveProperty("idempotencyKey");
    expect(first.dispute).not.toHaveProperty("reasonDigest");
    expect(first.dispute).not.toHaveProperty("evidenceReferenceDigest");

    const replay = await fixture.service.disputeInvoice({
      tenantId: fixture.tenantId,
      invoiceId: generated.invoice.id,
      reason,
      evidenceReference,
      idempotencyKey: "dispute-key",
      actorId: "actor-dispute",
      requestId: "request-dispute",
    });
    expect(replay.replayed).toBe(true);
    expect(replay.dispute.id).toBe(first.dispute.id);
    expect(replay.invoice).toEqual(first.invoice);
    const persisted = await fixture.repositories.invoiceDisputes.list(fixture.tenantId);
    expect(persisted).toHaveLength(1);
    expect(persisted[0]).toMatchObject({
      id: first.dispute.id,
      requestHash: expect.stringMatching(/^[a-f0-9]{64}$/u),
      idempotencyKey: "dispute-key",
      evidenceReferenceDigest: expect.stringMatching(/^[a-f0-9]{64}$/u),
    });
    await expect(fixture.repositories.invoiceDisputes.get(fixture.tenantId, first.dispute.id))
      .resolves.toMatchObject({ id: first.dispute.id });
    await expect(fixture.repositories.invoiceDisputes.findByIdempotency(
      fixture.tenantId,
      "dispute-key",
    )).resolves.toMatchObject({ id: first.dispute.id });
    await expect(fixture.repositories.invoiceDisputes.list(fixture.tenantId, {
      invoiceId: generated.invoice.id,
      status: "open",
      actorId: "actor-dispute",
    })).resolves.toHaveLength(1);
    await expect(fixture.repositories.invoiceDisputes.list(fixture.tenantId, {
      status: "rejected",
    })).resolves.toEqual([]);
    await expect(fixture.repositories.invoiceDisputes.list(otherTenantId)).resolves.toEqual([]);

    await expect(fixture.service.disputeInvoice({
      tenantId: fixture.tenantId,
      invoiceId: generated.invoice.id,
      reason: "Another dispute reason",
      evidenceReference,
      idempotencyKey: "dispute-key",
      actorId: "actor-dispute",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.IDEMPOTENCY_KEY_REUSED,
    });
    await expect(fixture.repositories.invoiceDisputes.list(fixture.tenantId)).resolves.toHaveLength(1);

    await expect(fixture.service.disputeInvoice({
      tenantId: fixture.tenantId,
      invoiceId: generated.invoice.id,
      reason,
      evidenceReference,
      idempotencyKey: "dispute-key-second",
      actorId: "actor-dispute",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.RESOURCE_CONFLICT,
    });
    await expect(fixture.repositories.invoiceDisputes.findByIdempotency(
      fixture.tenantId,
      "dispute-key-second",
    )).resolves.toBeUndefined();
    await expect(fixture.repositories.invoiceDisputes.list(fixture.tenantId)).resolves.toHaveLength(1);
  });

  it("keeps dispute evidence tenant scoped and free of secrets", async () => {
    const fixture = await createFixture();
    const other = await createFixture({
      tenantId: otherTenantId,
      service: fixture.service,
      repositories: fixture.repositories,
    });
    const generated = await fixture.service.generateInvoice({
      tenantId: fixture.tenantId,
      subscriptionId: fixture.subscription.id,
      periodStart,
      periodEnd,
      idempotencyKey: "tenant-scoped-invoice",
      taxRateBps: 0,
      taxMode: "exclusive",
    });
    const otherGenerated = await fixture.service.generateInvoice({
      tenantId: other.tenantId,
      subscriptionId: other.subscription.id,
      periodStart,
      periodEnd,
      idempotencyKey: "tenant-scoped-invoice",
      taxRateBps: 0,
      taxMode: "exclusive",
    });
    await awaitPayment(fixture.service, fixture.tenantId, generated.invoice.id);
    await awaitPayment(fixture.service, other.tenantId, otherGenerated.invoice.id);
    await expect(fixture.service.disputeInvoice({
      tenantId: other.tenantId,
      invoiceId: generated.invoice.id,
      reason,
      idempotencyKey: "cross-tenant-dispute",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.RESOURCE_NOT_FOUND,
    });
    await expect(fixture.repositories.invoiceDisputes.list(other.tenantId)).resolves.toEqual([]);
    expect((await fixture.repositories.invoices.get(fixture.tenantId, generated.invoice.id))?.status)
      .toBe("awaitingPayment");

    await expect(fixture.service.disputeInvoice({
      tenantId: other.tenantId,
      invoiceId: otherGenerated.invoice.id,
      reason,
      idempotencyKey: "shared-dispute-key",
      actorId: "actor-dispute",
    })).resolves.toMatchObject({ replayed: false, dispute: { tenantId: other.tenantId } });
    await expect(fixture.service.disputeInvoice({
      tenantId: fixture.tenantId,
      invoiceId: generated.invoice.id,
      reason,
      idempotencyKey: "shared-dispute-key",
      actorId: "actor-dispute",
    })).resolves.toMatchObject({ replayed: false, dispute: { tenantId: fixture.tenantId } });
    const tenantDisputes = await fixture.repositories.invoiceDisputes.list(fixture.tenantId);
    const otherDisputes = await fixture.repositories.invoiceDisputes.list(other.tenantId);
    expect(tenantDisputes).toHaveLength(1);
    expect(otherDisputes).toHaveLength(1);
    expect(tenantDisputes[0]?.id).not.toBe(otherDisputes[0]?.id);
    expect(tenantDisputes[0]?.invoiceId).toBe(generated.invoice.id);
    expect(otherDisputes[0]?.invoiceId).toBe(otherGenerated.invoice.id);
    await expect(fixture.repositories.invoiceDisputes.findByIdempotency(
      other.tenantId,
      "shared-dispute-key",
    )).resolves.toMatchObject({ id: otherDisputes[0]?.id });

    const scoped = await fixture.repositories.invoiceDisputes.append({
      id: "invoice-dispute_00000000-0000-4000-8000-0000000000ff",
      tenantId: fixture.tenantId,
      kind: "invoiceDispute",
      version: 1,
      event: "invoice.dispute.opened",
      invoiceId: "invoice_00000000-0000-4000-8000-0000000000ff",
      subscriptionId: fixture.subscription.id,
      planId: fixture.plan.id,
      invoiceStatus: "awaitingPayment",
      invoiceVersion: 3,
      reason,
      reasonDigest: "a".repeat(64),
      reasonLength: reason.length,
      evidenceCount: 0,
      actorId: "actor-dispute",
      requestId: "request-dispute",
      idempotencyKey: "shared-dispute-key",
      requestHash: "b".repeat(64),
      status: "open",
      createdAt: now.toISOString(),
      updatedAt: now.toISOString(),
      recordedAt: now.toISOString(),
    });
    expect(scoped.accepted).toBe(true);
    await expect(fixture.repositories.invoiceDisputes.findByIdempotency(
      fixture.tenantId,
      "shared-dispute-key",
    )).resolves.toMatchObject({ id: scoped.dispute.id });
    await expect(fixture.repositories.invoiceDisputes.findByIdempotency(
      other.tenantId,
      "shared-dispute-key",
    )).resolves.toMatchObject({ id: otherDisputes[0]?.id });

    const sensitive = await fixture.service.generateInvoice({
      tenantId: fixture.tenantId,
      subscriptionId: fixture.subscription.id,
      periodStart,
      periodEnd,
      idempotencyKey: "sensitive-dispute-invoice",
      taxRateBps: 0,
      taxMode: "exclusive",
    });
    await awaitPayment(fixture.service, fixture.tenantId, sensitive.invoice.id);
    for (const unsafe of [
      "Refund to bank account 6222021234567890123 was not received",
      "Settlement reference settlement://private-bank-account-123456",
      "The operator shared password=hunter2 for the portal",
      "-----BEGIN RSA PRIVATE KEY-----",
      "Session token sk-livekey-9f8e7d6c5b4a3210 leaked",
    ]) {
      await expect(fixture.service.disputeInvoice({
        tenantId: fixture.tenantId,
        invoiceId: sensitive.invoice.id,
        reason: unsafe,
        idempotencyKey: `unsafe-${randomUUID()}`,
      })).rejects.toMatchObject({
        code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.VALIDATION_ERROR,
      });
    }
    await expect(fixture.service.disputeInvoice({
      tenantId: fixture.tenantId,
      invoiceId: sensitive.invoice.id,
      reason,
      evidenceReference: "6222021234567890123",
      idempotencyKey: "unsafe-evidence",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.VALIDATION_ERROR,
    });
    await expect(fixture.service.disputeInvoice({
      tenantId: fixture.tenantId,
      invoiceId: sensitive.invoice.id,
      reason: "x".repeat(501),
      idempotencyKey: "unsafe-reason-length",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.VALIDATION_ERROR,
    });
    expect((await fixture.repositories.invoices.get(fixture.tenantId, sensitive.invoice.id))?.status)
      .toBe("awaitingPayment");
    const serialized = JSON.stringify(await fixture.repositories.invoiceDisputes.list(fixture.tenantId));
    expect(serialized).not.toContain("6222021234567890123");
    expect(serialized).not.toContain("private-bank-account-123456");
    expect(serialized).not.toContain("hunter2");
    expect(serialized).not.toContain("sk-livekey-9f8e7d6c5b4a3210");
    expect(serialized).not.toContain("BEGIN RSA PRIVATE KEY");
  });
});

describe("open platform commerce domain event opt-in", () => {
  it("keeps the unwired commerce service free of domain event publishing", async () => {
    const repositories = new InMemoryCommerceRepositories();
    const service = createCommerceService({ repositories, clock: () => now });
    expect(service.eventPublisher).toBeUndefined();
    await expect(service.isReady()).resolves.toEqual({
      ready: true,
      storage: "memory",
      distributed: false,
    });
    const tenantId = "tenant-commerce-events-opt-in";
    const fixture = await createFixture({ tenantId, service, repositories });
    const partner = await service.createPartnerAccount({
      tenantId,
      legalName: "生态伙伴有限公司",
      partnerCode: "partner-opt-in",
      settlementReference: "settlement://partner/opt-in",
    });
    const listing = await service.createMarketplaceListing({
      tenantId,
      partnerAccountId: partner.id,
      productId: `product_${randomUUID()}`,
      title: "Marketplace API",
      description: "Partner supplied API",
      idempotencyKey: "opt-in-listing",
      actorId: "actor-opt-in",
    });
    const rule = await service.createCommissionRule({
      tenantId,
      partnerAccountId: partner.id,
      listingId: listing.id,
      name: "Opt in commission",
      rateBps: 1000,
      effectiveFrom: periodStart,
    });
    const transitioned = await service.transitionWithIdempotency({
      tenantId,
      resource: "marketplaceListing",
      id: listing.id,
      targetStatus: "pendingReview",
      idempotencyKey: "opt-in-transition",
      actorId: "actor-opt-in",
    });
    const generated = await service.generateInvoice({
      tenantId,
      subscriptionId: fixture.subscription.id,
      periodStart,
      periodEnd,
      idempotencyKey: "opt-in-invoice",
      taxRateBps: 600,
      taxMode: "exclusive",
    });
    expect(transitioned.replayed).toBe(false);
    expect(transitioned.record).toMatchObject({ status: "pendingReview", version: 2 });
    expect(listing).toMatchObject({ status: "draft", version: 1 });
    expect(partner).toMatchObject({ status: "pending", version: 1 });
    expect(rule).toMatchObject({ status: "draft", rateBps: 1000 });
    expect(generated.invoice).toMatchObject({ status: "draft", version: 1 });
    await expect(service.generateInvoice({
      tenantId,
      subscriptionId: fixture.subscription.id,
      periodStart,
      periodEnd,
      idempotencyKey: "opt-in-invoice",
      taxRateBps: 600,
      taxMode: "exclusive",
    })).resolves.toMatchObject({ replayed: true });
    await expect(service.isReady()).resolves.toEqual({
      ready: true,
      storage: "memory",
      distributed: false,
    });
  });
});

describe("open platform commerce invoice dispute adjudication", () => {
  const reason = "Invoice charge not recognized by the buyer";
  const reference = "resolution://case-0001";

  async function awaitPayment(
    service: CommerceDomainService,
    tenantId: string,
    invoiceId: string,
  ): Promise<void> {
    await service.transition({
      tenantId,
      resource: "invoice",
      id: invoiceId,
      targetStatus: "reconciling",
    });
    await service.transition({
      tenantId,
      resource: "invoice",
      id: invoiceId,
      targetStatus: "awaitingPayment",
    });
  }

  async function openDispute(
    fixture: Fixture,
    idempotencyKey = "adjudication-dispute",
  ): Promise<{ invoiceId: string; disputeId: string }> {
    const generated = await fixture.service.generateInvoice({
      tenantId: fixture.tenantId,
      subscriptionId: fixture.subscription.id,
      periodStart,
      periodEnd,
      idempotencyKey: `${idempotencyKey}-invoice`,
      taxRateBps: 600,
      taxMode: "exclusive",
    });
    await awaitPayment(fixture.service, fixture.tenantId, generated.invoice.id);
    const disputed = await fixture.service.disputeInvoice({
      tenantId: fixture.tenantId,
      invoiceId: generated.invoice.id,
      reason,
      idempotencyKey,
      actorId: "actor-dispute",
    });
    return { invoiceId: generated.invoice.id, disputeId: disputed.dispute.id };
  }

  it("keeps the legal dispute transitions and terminal states immutable", () => {
    expect(INVOICE_DISPUTE_TRANSITIONS.open).toEqual([
      "underReview",
      "accepted",
      "rejected",
      "withdrawn",
    ]);
    expect(INVOICE_DISPUTE_TRANSITIONS.underReview).toEqual([
      "accepted",
      "rejected",
      "withdrawn",
    ]);
    for (const terminal of ["accepted", "rejected", "withdrawn"] as const) {
      expect(INVOICE_DISPUTE_TRANSITIONS[terminal]).toEqual([]);
      expect(canTransitionInvoiceDispute(terminal, "underReview")).toBe(false);
      expect(canTransitionInvoiceDispute(terminal, "accepted")).toBe(false);
      expect(isTerminalInvoiceDisputeStatus(terminal)).toBe(true);
    }
    expect(canTransitionInvoiceDispute("open", "underReview")).toBe(true);
    expect(canTransitionInvoiceDispute("open", "accepted")).toBe(true);
    expect(canTransitionInvoiceDispute("open", "rejected")).toBe(true);
    expect(canTransitionInvoiceDispute("open", "withdrawn")).toBe(true);
    expect(canTransitionInvoiceDispute("underReview", "open")).toBe(false);
    expect(canTransitionInvoiceDispute("underReview", "underReview")).toBe(false);
    expect(isTerminalInvoiceDisputeStatus("underReview")).toBe(false);
    expect(() => assertInvoiceDisputeTransition("accepted", "underReview"))
      .toThrowError(expect.objectContaining({
        code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.INVALID_STATE_TRANSITION,
        details: { from: "accepted", to: "underReview" },
      }));
  });

  it("moves a dispute to under review, decides it, and refuses every further change", async () => {
    const fixture = await createFixture();
    const { invoiceId, disputeId } = await openDispute(fixture);
    const reviewed = await fixture.service.startInvoiceDisputeReview({
      tenantId: fixture.tenantId,
      invoiceId,
      disputeId,
      idempotencyKey: "review-1",
      actorId: "actor-reviewer",
    });
    expect(reviewed.replayed).toBe(false);
    expect(reviewed.fromStatus).toBe("open");
    expect(reviewed.dispute).toMatchObject({
      id: disputeId,
      status: "underReview",
      version: 2,
      updatedAt: now.toISOString(),
    });
    expect(reviewed.dispute.resolution).toBeUndefined();
    const reviewReplay = await fixture.service.startInvoiceDisputeReview({
      tenantId: fixture.tenantId,
      invoiceId,
      disputeId,
      idempotencyKey: "review-1",
      actorId: "actor-reviewer",
    });
    expect(reviewReplay.replayed).toBe(true);
    expect(reviewReplay.dispute.version).toBe(2);

    const decided = await fixture.service.decideInvoiceDispute({
      tenantId: fixture.tenantId,
      invoiceId,
      disputeId,
      outcome: "accepted",
      reference,
      resolutionNote: "Credit note issued for the duplicated line",
      idempotencyKey: "decide-1",
      actorId: "actor-adjudicator",
    });
    expect(decided.fromStatus).toBe("underReview");
    expect(decided.dispute).toMatchObject({
      status: "accepted",
      version: 3,
      resolvedAt: now.toISOString(),
      resolution: {
        outcome: "accepted",
        actorId: "actor-adjudicator",
        reference,
        fromStatus: "underReview",
        note: "Credit note issued for the duplicated line",
        noteLength: "Credit note issued for the duplicated line".length,
        resolvedAt: now.toISOString(),
      },
    });
    expect(decided.dispute).not.toHaveProperty("requestHash");
    expect(decided.dispute).not.toHaveProperty("idempotencyKey");
    expect(decided.dispute).not.toHaveProperty("reasonDigest");

    await expect(fixture.service.startInvoiceDisputeReview({
      tenantId: fixture.tenantId,
      invoiceId,
      disputeId,
      idempotencyKey: "review-2",
      actorId: "actor-reviewer",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.INVALID_STATE_TRANSITION,
    });
    await expect(fixture.service.decideInvoiceDispute({
      tenantId: fixture.tenantId,
      invoiceId,
      disputeId,
      outcome: "rejected",
      reference,
      idempotencyKey: "decide-2",
      actorId: "actor-adjudicator",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.INVALID_STATE_TRANSITION,
    });
    await expect(fixture.service.withdrawInvoiceDispute({
      tenantId: fixture.tenantId,
      invoiceId,
      disputeId,
      reference,
      idempotencyKey: "withdraw-1",
      actorId: "actor-dispute",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.INVALID_STATE_TRANSITION,
    });
    await expect(fixture.repositories.invoiceDisputes.get(fixture.tenantId, disputeId))
      .resolves.toMatchObject({ status: "accepted", version: 3 });
  });

  it("withdraws an open dispute and decides a withdrawal as withdrawn", async () => {
    const fixture = await createFixture();
    const first = await openDispute(fixture, "withdraw-dispute");
    const withdrawn = await fixture.service.withdrawInvoiceDispute({
      tenantId: fixture.tenantId,
      invoiceId: first.invoiceId,
      disputeId: first.disputeId,
      reference: "withdrawal://case-0001",
      idempotencyKey: "withdraw-1",
      actorId: "actor-dispute",
    });
    expect(withdrawn.fromStatus).toBe("open");
    expect(withdrawn.dispute).toMatchObject({
      status: "withdrawn",
      version: 2,
      resolution: { outcome: "withdrawn", fromStatus: "open" },
    });

    const second = await openDispute(fixture, "decide-withdraw-dispute");
    const decidedWithdrawal = await fixture.service.decideInvoiceDispute({
      tenantId: fixture.tenantId,
      invoiceId: second.invoiceId,
      disputeId: second.disputeId,
      outcome: "withdrawn",
      reference: "withdrawal://case-0002",
      idempotencyKey: "decide-withdraw-1",
      actorId: "actor-adjudicator",
    });
    expect(decidedWithdrawal.dispute).toMatchObject({
      status: "withdrawn",
      resolution: { outcome: "withdrawn", actorId: "actor-adjudicator" },
    });
  });

  it("rejects reused idempotency keys, unknown outcomes, and unsafe resolution notes", async () => {
    const fixture = await createFixture();
    const { invoiceId, disputeId } = await openDispute(fixture);
    await expect(fixture.service.decideInvoiceDispute({
      tenantId: fixture.tenantId,
      invoiceId,
      disputeId,
      outcome: "unknown" as never,
      reference,
      idempotencyKey: "decide-invalid",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.VALIDATION_ERROR,
      details: { field: "outcome" },
    });
    await expect(fixture.service.decideInvoiceDispute({
      tenantId: fixture.tenantId,
      invoiceId,
      disputeId,
      outcome: "rejected",
      reference,
      idempotencyKey: "decide-note",
      resolutionNote: "Refund to bank account 6222021234567890123 was issued",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.VALIDATION_ERROR,
    });
    await expect(fixture.service.decideInvoiceDispute({
      tenantId: fixture.tenantId,
      invoiceId,
      disputeId,
      outcome: "rejected",
      reference,
      idempotencyKey: "decide-long-note",
      resolutionNote: "n".repeat(501),
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.VALIDATION_ERROR,
    });
    await expect(fixture.service.decideInvoiceDispute({
      tenantId: fixture.tenantId,
      invoiceId,
      disputeId,
      outcome: "rejected",
      idempotencyKey: "decide-no-reference",
    } as unknown as DecideInvoiceDisputeCommand)).rejects.toMatchObject({
      code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.VALIDATION_ERROR,
    });
    const decided = await fixture.service.decideInvoiceDispute({
      tenantId: fixture.tenantId,
      invoiceId,
      disputeId,
      outcome: "rejected",
      reference,
      idempotencyKey: "decide-1",
      actorId: "actor-adjudicator",
    });
    expect(decided.dispute.status).toBe("rejected");
    await expect(fixture.service.decideInvoiceDispute({
      tenantId: fixture.tenantId,
      invoiceId,
      disputeId,
      outcome: "accepted",
      reference: "resolution://case-0002",
      idempotencyKey: "decide-1",
      actorId: "actor-adjudicator",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.IDEMPOTENCY_KEY_REUSED,
    });
  });

  it("detects a stale dispute version and keeps the invoice scope of a decision", async () => {
    const fixture = await createFixture();
    const { invoiceId, disputeId } = await openDispute(fixture);
    await expect(fixture.service.decideInvoiceDispute({
      tenantId: fixture.tenantId,
      invoiceId: "invoice_00000000-0000-4000-8000-0000000000ff",
      disputeId,
      outcome: "accepted",
      reference,
      idempotencyKey: "decide-other-invoice",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.RESOURCE_NOT_FOUND,
    });
    await expect(fixture.service.decideInvoiceDispute({
      tenantId: "tenant-commerce-dispute-other",
      invoiceId,
      disputeId,
      outcome: "accepted",
      reference,
      idempotencyKey: "decide-other-tenant",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.RESOURCE_NOT_FOUND,
    });
    await expect(fixture.repositories.invoiceDisputes.decide(
      fixture.tenantId,
      disputeId,
      {
        targetStatus: "underReview",
        expectedVersion: 5,
        decidedBy: "actor-adjudicator",
        decidedAt: now.toISOString(),
      },
    )).rejects.toMatchObject({
      code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.RESOURCE_CONFLICT,
    });
    await expect(fixture.repositories.invoiceDisputes.get(fixture.tenantId, disputeId))
      .resolves.toMatchObject({ status: "open", version: 1 });
    const decided = await fixture.repositories.invoiceDisputes.decide(
      fixture.tenantId,
      disputeId,
      {
        targetStatus: "underReview",
        expectedVersion: 1,
        decidedBy: "actor-adjudicator",
        decidedAt: now.toISOString(),
      },
    );
    expect(decided).toMatchObject({ status: "underReview", version: 2 });
    await expect(fixture.repositories.invoiceDisputes.decide(
      fixture.tenantId,
      disputeId,
      {
        targetStatus: "rejected",
        expectedVersion: 1,
        decidedBy: "actor-adjudicator",
        decidedAt: now.toISOString(),
        reference,
      },
    )).rejects.toMatchObject({
      code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.RESOURCE_CONFLICT,
    });
  });

  it("lists and reads tenant scoped disputes with pagination and status filters", async () => {
    const fixture = await createFixture();
    const first = await openDispute(fixture, "list-dispute-a");
    const second = await openDispute(fixture, "list-dispute-b");
    const page = await fixture.service.listInvoiceDisputes({
      tenantId: fixture.tenantId,
      limit: 1,
    });
    expect(page.items).toHaveLength(1);
    expect(page.total).toBe(2);
    expect(page.hasMore).toBe(true);
    expect(page.nextCursor).toEqual(expect.any(String));
    const secondPage = await fixture.service.listInvoiceDisputes({
      tenantId: fixture.tenantId,
      limit: 1,
      ...(page.nextCursor === undefined ? {} : { cursor: page.nextCursor }),
    });
    expect(secondPage.items).toHaveLength(1);
    expect(secondPage.items[0]?.id).not.toBe(page.items[0]?.id);
    expect(secondPage.hasMore).toBe(false);

    const scoped = await fixture.service.listInvoiceDisputes({
      tenantId: fixture.tenantId,
      invoiceId: first.invoiceId,
    });
    expect(scoped.items.map((item) => item.id)).toEqual([first.disputeId]);
    await expect(fixture.service.listInvoiceDisputes({
      tenantId: fixture.tenantId,
      status: "accepted",
    })).resolves.toMatchObject({ items: [], total: 0 });
    await expect(fixture.service.listInvoiceDisputes({
      tenantId: fixture.tenantId,
      status: "unknown",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.VALIDATION_ERROR,
    });
    await expect(fixture.service.listInvoiceDisputes({
      tenantId: fixture.tenantId,
      tenantIdOther: second.invoiceId,
    } as never)).rejects.toMatchObject({
      code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.VALIDATION_ERROR,
    });
    await expect(fixture.service.getInvoiceDispute({
      tenantId: fixture.tenantId,
      id: first.disputeId,
    })).resolves.toMatchObject({ id: first.disputeId, status: "open" });
    await expect(fixture.service.getInvoiceDispute(fixture.tenantId, second.disputeId))
      .resolves.toMatchObject({ id: second.disputeId });
    await expect(fixture.service.getInvoiceDispute({
      tenantId: "tenant-commerce-dispute-other",
      id: first.disputeId,
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.RESOURCE_NOT_FOUND,
    });
    await expect(fixture.service.getInvoiceDispute({
      tenantId: fixture.tenantId,
      id: "invoice-dispute_00000000-0000-4000-8000-0000000000ff",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_COMMERCE_ERROR_CODES.RESOURCE_NOT_FOUND,
    });
    await expect(fixture.service.listInvoiceDisputes("tenant-commerce-dispute-other"))
      .resolves.toMatchObject({ items: [], total: 0 });
  });
});
