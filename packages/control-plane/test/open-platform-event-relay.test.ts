import "reflect-metadata";
import { Test } from "@nestjs/testing";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  InMemoryOpenPlatformOutbox,
  OPEN_PLATFORM_ERROR_CODES,
  OPEN_PLATFORM_EVENT_RELAY,
  OPEN_PLATFORM_EVENT_RELAY_ENABLED,
  OPEN_PLATFORM_EVENT_RELAY_LEASE_KEY,
  OpenPlatformEventPublisher,
  OpenPlatformEventRelay,
  OpenPlatformEventRelayModule,
  OpenPlatformPersistence,
  createInMemoryOpenPlatformRelayLease,
  createOpenPlatformEventRelay,
  createOpenPlatformEventRelayModule,
  createOpenPlatformOutboxTenantResolver,
  flushOpenPlatformOutboxTenant,
  listOpenPlatformOutboxTenants,
  type OpenPlatformEventFlushResult,
  type OpenPlatformEventRelayError,
  type OpenPlatformEventSink,
  type OpenPlatformOutboxPort,
  type OpenPlatformOutboxRecord,
  type OpenPlatformOutboxTenantResolver,
  type OpenPlatformRelayLeasePort,
} from "../src/open-platform/index.js";

const tenantAlpha = "relay-alpha";
const tenantBeta = "relay-beta";
const tenantGamma = "relay-gamma";

interface Harness {
  readonly outbox: InMemoryOpenPlatformOutbox;
  readonly publisher: OpenPlatformEventPublisher;
  readonly delivered: OpenPlatformOutboxRecord[];
  readonly relay: OpenPlatformEventRelay;
}

function createHarness(
  options: {
    sink?: OpenPlatformEventSink;
    tenantIds?: readonly string[];
    tenants?: OpenPlatformOutboxTenantResolver;
    intervalMs?: number;
    jitterMs?: number;
    batchSize?: number;
    maxTenantsPerTick?: number;
    tenantPageSize?: number;
    random?: () => number;
    onError?: (error: OpenPlatformEventRelayError) => void;
    lease?: OpenPlatformRelayLeasePort;
    leaseKey?: string;
    leaseTtlMs?: number;
    ownerId?: string;
  } = {},
): Harness {
  const outbox = new InMemoryOpenPlatformOutbox({ clock: () => new Date() });
  const delivered: OpenPlatformOutboxRecord[] = [];
  const sink: OpenPlatformEventSink = options.sink ?? {
    deliver: (event) => {
      delivered.push(event);
      return { delivered: 1 };
    },
  };
  const publisher = new OpenPlatformEventPublisher({
    outbox,
    clock: () => new Date(),
    sink,
  });
  const relay = createOpenPlatformEventRelay({
    publisher,
    outbox,
    mode: "test",
    enabled: true,
    intervalMs: options.intervalMs ?? 1_000,
    ...(options.jitterMs === undefined ? {} : { jitterMs: options.jitterMs }),
    ...(options.batchSize === undefined ? {} : { batchSize: options.batchSize }),
    ...(options.maxTenantsPerTick === undefined
      ? {}
      : { maxTenantsPerTick: options.maxTenantsPerTick }),
    ...(options.tenantPageSize === undefined
      ? {}
      : { tenantPageSize: options.tenantPageSize }),
    ...(options.tenantIds === undefined
      ? options.tenants === undefined
        ? { tenantIds: [tenantAlpha, tenantBeta, tenantGamma] }
        : { tenants: options.tenants }
      : { tenantIds: options.tenantIds }),
    ...(options.lease === undefined ? {} : { lease: options.lease }),
    ...(options.leaseKey === undefined ? {} : { leaseKey: options.leaseKey }),
    ...(options.leaseTtlMs === undefined
      ? {}
      : { leaseTtlMs: options.leaseTtlMs }),
    ...(options.ownerId === undefined ? {} : { ownerId: options.ownerId }),
    ...(options.random === undefined ? {} : { random: options.random }),
    ...(options.onError === undefined ? {} : { onError: options.onError }),
    clock: () => new Date(),
  });
  return { outbox, publisher, delivered, relay };
}

async function seed(
  outbox: InMemoryOpenPlatformOutbox,
  tenantId: string,
  eventId: string,
  occurredAt = new Date().toISOString(),
): Promise<OpenPlatformOutboxRecord> {
  return outbox.append({
    eventId,
    tenantId,
    eventType: "application.created",
    resourceType: "application",
    resourceId: `app-${eventId}`,
    occurredAt,
    data: { name: "Relay tenant" },
  });
}

function productionOutbox(inner: InMemoryOpenPlatformOutbox): OpenPlatformOutboxPort {
  return {
    productionReady: true,
    readiness: Object.freeze({
      storage: "persistent" as const,
      distributed: true,
      ready: () => true,
    }),
    append: (event) => inner.append(event),
    get: (tenantId, eventId) => inner.get(tenantId, eventId),
    list: (query) => inner.list(query),
    claim: (request) => inner.claim(request),
    complete: (request) => inner.complete(request),
    fail: (request) => inner.fail(request),
  };
}

interface Fleet {
  readonly outbox: InMemoryOpenPlatformOutbox;
  readonly publisher: OpenPlatformEventPublisher;
  readonly delivered: OpenPlatformOutboxRecord[];
  readonly relays: readonly OpenPlatformEventRelay[];
}

function createFleet(
  lease: OpenPlatformRelayLeasePort,
  ownerIds: readonly string[],
): Fleet {
  const outbox = new InMemoryOpenPlatformOutbox({ clock: () => new Date() });
  const delivered: OpenPlatformOutboxRecord[] = [];
  const publisher = new OpenPlatformEventPublisher({
    outbox,
    clock: () => new Date(),
    sink: {
      deliver: (event) => {
        delivered.push(event);
        return { delivered: 1 };
      },
    },
  });
  const relays = ownerIds.map((ownerId) =>
    createOpenPlatformEventRelay({
      publisher,
      outbox,
      lease,
      ownerId,
      tenantIds: [tenantAlpha, tenantBeta, tenantGamma],
      mode: "test",
      enabled: true,
      clock: () => new Date(),
    }),
  );
  return { outbox, publisher, delivered, relays };
}

describe("open platform event relay", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2031-05-01T00:00:00.000Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("publishes every tenant backlog on a scheduled tick", async () => {
    const harness = createHarness();
    await seed(harness.outbox, tenantAlpha, "evt-alpha-1");
    await seed(harness.outbox, tenantBeta, "evt-beta-1");

    await harness.relay.start();
    await vi.advanceTimersByTimeAsync(0);

    const metrics = harness.relay.metrics();
    expect(metrics.started).toBe(1);
    expect(metrics.ticks).toBe(1);
    expect(metrics.tenants).toBe(3);
    expect(metrics.published).toBe(2);
    expect(metrics.errors).toBe(0);
    expect(
      harness.delivered.map((event) => event.tenantId).sort(),
    ).toEqual([tenantAlpha, tenantBeta]);
    expect(
      (await harness.outbox.get(tenantAlpha, "evt-alpha-1"))?.status,
    ).toBe("published");
  });

  it("does not start a second loop when start is called twice", async () => {
    const harness = createHarness();
    await seed(harness.outbox, tenantAlpha, "evt-alpha-1");

    await harness.relay.start();
    await harness.relay.start();
    await harness.relay.start();

    expect(harness.relay.metrics().started).toBe(1);
    expect(vi.getTimerCount()).toBe(1);
    await vi.advanceTimersByTimeAsync(0);
    expect(harness.relay.metrics().ticks).toBe(1);
    expect(harness.relay.metrics().published).toBe(1);
    expect(vi.getTimerCount()).toBe(1);

    await vi.advanceTimersByTimeAsync(1_000);
    expect(harness.relay.metrics().ticks).toBe(2);
    expect(harness.relay.metrics().published).toBe(1);
  });

  it("applies jitter to the scheduled interval", async () => {
    const harness = createHarness({ intervalMs: 1_000, jitterMs: 500, random: () => 0.5 });
    await harness.relay.start();
    await vi.advanceTimersByTimeAsync(0);
    expect(harness.relay.metrics().ticks).toBe(1);
    await vi.advanceTimersByTimeAsync(1_249);
    expect(harness.relay.metrics().ticks).toBe(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(harness.relay.metrics().ticks).toBe(2);
  });

  it("keeps runOnce idempotent and never overlaps ticks", async () => {
    const harness = createHarness();
    await seed(harness.outbox, tenantAlpha, "evt-alpha-1");
    await seed(harness.outbox, tenantAlpha, "evt-alpha-2");

    const first = await harness.relay.runOnce();
    const second = await harness.relay.runOnce();

    expect(first.published).toBe(2);
    expect(second.published).toBe(0);
    expect(second.failed).toBe(0);
    expect(second.skipped).toBe(0);
    expect(second.tenants).toBe(3);
    expect(harness.relay.metrics().ticks).toBe(2);
    expect(harness.relay.metrics().published).toBe(2);
    expect(harness.delivered).toHaveLength(2);
  });

  it("coalesces concurrent runOnce calls into one tick", async () => {
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const harness = createHarness({
      sink: {
        deliver: async (event) => {
          await gate;
          return { delivered: 1 };
        },
      },
    });
    await seed(harness.outbox, tenantAlpha, "evt-alpha-1");

    const first = harness.relay.runOnce();
    const second = harness.relay.runOnce();
    release?.();
    const [left, right] = await Promise.all([first, second]);

    expect(left).toBe(right);
    expect(harness.relay.metrics().ticks).toBe(1);
    expect(harness.relay.metrics().published).toBe(1);
  });

  it("caps each tenant at the configured batch size per tick", async () => {
    const harness = createHarness({ batchSize: 2 });
    for (let index = 0; index < 5; index += 1) {
      await seed(harness.outbox, tenantAlpha, `evt-alpha-${index}`);
    }

    const first = await harness.relay.runOnce();
    expect(first.published).toBe(2);
    expect(first.truncated).toBe(true);
    const second = await harness.relay.runOnce();
    expect(second.published).toBe(2);
    const third = await harness.relay.runOnce();
    expect(third.published).toBe(1);
    expect(third.truncated).toBe(false);
    expect(harness.relay.metrics().published).toBe(5);
  });

  it("isolates a failing tenant and keeps draining the others", async () => {
    const reports: string[] = [];
    const harness = createHarness({
      onError: (error) => reports.push(`${error.scope}:${error.code}`),
      sink: {
        deliver: (event) => {
          if (event.tenantId === tenantAlpha) throw new Error("alpha sink down");
          return { delivered: 1 };
        },
      },
    });
    await seed(harness.outbox, tenantAlpha, "evt-alpha-1");
    await seed(harness.outbox, tenantBeta, "evt-beta-1");
    await seed(harness.outbox, tenantGamma, "evt-gamma-1");

    const tickResult = await harness.relay.runOnce();

    expect(tickResult.published).toBe(2);
    expect(tickResult.failed).toBe(1);
    expect(tickResult.errors).toBe(0);
    expect(harness.relay.metrics().failed).toBe(1);
    expect(harness.relay.metrics().published).toBe(2);
    expect(
      (await harness.outbox.get(tenantAlpha, "evt-alpha-1"))?.status,
    ).toBe("failed");
    expect(
      (await harness.outbox.get(tenantBeta, "evt-beta-1"))?.status,
    ).toBe("published");
    expect(reports).toHaveLength(0);

    const deferred = await harness.relay.runOnce();
    expect(deferred.skipped).toBe(1);
    expect(deferred.failed).toBe(0);
    expect(deferred.published).toBe(0);

    vi.setSystemTime(new Date("2031-05-01T00:01:00.000Z"));
    const retry = await harness.relay.runOnce();
    expect(retry.retried).toBe(1);
    expect(retry.failed).toBe(1);
    expect(harness.relay.metrics().retried).toBe(1);
  });

  it("keeps ticking after a tenant flush throws", async () => {
    const harness = createHarness();
    const failing = harness.outbox.list.bind(harness.outbox);
    let calls = 0;
    vi.spyOn(harness.outbox, "list").mockImplementation(async (query) => {
      calls += 1;
      if (calls === 1) throw new Error("outbox unavailable");
      return failing(query);
    });
    await seed(harness.outbox, tenantAlpha, "evt-alpha-1");

    const broken = await harness.relay.runOnce();
    expect(broken.errors).toBe(1);
    expect(broken.published).toBe(0);

    const recovered = await harness.relay.runOnce();
    expect(recovered.published).toBe(1);
    expect(harness.relay.metrics().errors).toBe(1);
    expect(harness.relay.metrics().published).toBe(1);
    expect(harness.relay.metrics().tenantErrors).toBe(1);
  });

  it("dead letters events when the sink reports a dead letter", async () => {
    const harness = createHarness({
      sink: { deliver: () => ({ delivered: 0, deadLettered: 1 }) },
    });
    await seed(harness.outbox, tenantAlpha, "evt-alpha-1");

    const tickResult = await harness.relay.runOnce();
    expect(tickResult.deadLettered).toBe(1);
    expect(tickResult.failed).toBe(0);
    expect(harness.relay.metrics().deadLettered).toBe(1);
    expect(
      (await harness.outbox.get(tenantAlpha, "evt-alpha-1"))?.status,
    ).toBe("dead_lettered");
    const again = await harness.relay.runOnce();
    expect(again.deadLettered).toBe(0);
    expect(again.published).toBe(0);
  });

  it("stops scheduling timers and cancels the pending tick", async () => {
    const harness = createHarness();
    await seed(harness.outbox, tenantAlpha, "evt-alpha-1");

    await harness.relay.start();
    expect(vi.getTimerCount()).toBe(1);
    await harness.relay.stop();

    expect(harness.relay.isRunning()).toBe(false);
    expect(vi.getTimerCount()).toBe(0);
    const before = harness.relay.metrics().ticks;
    await vi.advanceTimersByTimeAsync(10_000);
    expect(harness.relay.metrics().ticks).toBe(before);
    expect(harness.relay.metrics().stopped).toBe(1);

    await harness.relay.stop();
    expect(harness.relay.metrics().stopped).toBe(1);
  });

  it("stops gracefully while a tick is still running", async () => {
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const harness = createHarness({
      sink: {
        deliver: async () => {
          await gate;
          return { delivered: 1 };
        },
      },
    });
    await seed(harness.outbox, tenantAlpha, "evt-alpha-1");
    await harness.relay.start();
    expect(vi.getTimerCount()).toBe(1);

    const inFlight = harness.relay.runOnce();
    const stopped = harness.relay.stop();
    release?.();
    const tick = await inFlight;
    await stopped;

    expect(tick.published).toBe(1);
    expect(harness.relay.isRunning()).toBe(false);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("stops on abort and leaves no timer behind", async () => {
    const controller = new AbortController();
    const harness = createHarness();
    await harness.relay.start({ signal: controller.signal });
    expect(harness.relay.isRunning()).toBe(true);

    controller.abort();
    await vi.advanceTimersByTimeAsync(0);

    expect(harness.relay.isRunning()).toBe(false);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("ignores start when the supplied signal is already aborted", async () => {
    const controller = new AbortController();
    controller.abort();
    const harness = createHarness();
    await harness.relay.start({ signal: controller.signal });
    expect(harness.relay.isRunning()).toBe(false);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("pages tenants across ticks and never crosses tenant boundaries", async () => {
    const harness = createHarness({
      maxTenantsPerTick: 1,
      tenantIds: [tenantAlpha, tenantBeta, tenantGamma],
    });
    for (const tenantId of [tenantAlpha, tenantBeta, tenantGamma]) {
      await seed(harness.outbox, tenantId, `evt-${tenantId}-1`);
      await seed(harness.outbox, tenantId, `evt-${tenantId}-2`);
    }

    const published: number[] = [];
    for (let index = 0; index < 3; index += 1) {
      const result = await harness.relay.runOnce();
      expect(result.tenants).toBe(1);
      published.push(result.published);
    }
    expect(published).toEqual([2, 2, 2]);

    const first = await harness.outbox.get(tenantAlpha, "evt-relay-alpha-1");
    const second = await harness.outbox.get(tenantBeta, "evt-relay-beta-1");
    const third = await harness.outbox.get(tenantGamma, "evt-relay-gamma-1");
    expect([first?.status, second?.status, third?.status]).toEqual([
      "published",
      "published",
      "published",
    ]);
    expect(harness.delivered).toHaveLength(6);
    expect(
      harness.delivered.every((event) =>
        [tenantAlpha, tenantBeta, tenantGamma].includes(event.tenantId),
      ),
    ).toBe(true);
  });

  it("resets the tenant cursor when a pass completes", async () => {
    const harness = createHarness({ maxTenantsPerTick: 2, tenantPageSize: 2 });
    await seed(harness.outbox, tenantAlpha, "evt-alpha-1");
    await seed(harness.outbox, tenantGamma, "evt-gamma-1");

    const first = await harness.relay.runOnce();
    expect(first.tenants).toBe(2);
    expect(first.published).toBe(1);
    const second = await harness.relay.runOnce();
    expect(second.tenants).toBe(1);
    expect(second.published).toBe(1);
    const third = await harness.relay.runOnce();
    expect(third.tenants).toBe(2);
    expect(third.published).toBe(0);
  });

  it("rejects malformed tenant identifiers from a resolver", async () => {
    const resolver: OpenPlatformOutboxTenantResolver = {
      listTenants: () =>
        Promise.resolve({
          tenantIds: [tenantAlpha, "Tenant_Bad", tenantAlpha],
        }),
    };
    const harness = createHarness({ tenants: resolver });
    await seed(harness.outbox, tenantAlpha, "evt-alpha-1");

    const result = await harness.relay.runOnce();
    expect(result.published).toBe(1);
    expect(harness.relay.metrics().errors).toBe(1);
    expect(harness.relay.metrics().lastErrorCode).toBe(
      "OPEN_PLATFORM_EVENT_RELAY_ERROR",
    );
  });

  it("reports a resolver that never advances its tenant cursor", async () => {
    const resolver: OpenPlatformOutboxTenantResolver = {
      listTenants: (query) =>
        Promise.resolve({
          tenantIds: [tenantAlpha],
          ...(query.cursor === undefined ? {} : { cursor: query.cursor }),
          hasMore: true,
        }),
    };
    const harness = createHarness({ tenants: resolver });
    await seed(harness.outbox, tenantAlpha, "evt-alpha-1");

    const first = await harness.relay.runOnce();
    expect(first.errors).toBe(1);
    expect(first.tenants).toBe(0);
    const stalled = await harness.relay.runOnce();
    expect(stalled.errors).toBe(1);
    expect(harness.relay.metrics().published).toBe(0);
    expect(
      (await harness.outbox.get(tenantAlpha, "evt-alpha-1"))?.status,
    ).toBe("pending");
  });

  it("refuses to flush records that belong to another tenant", async () => {
    const harness = createHarness({ tenantIds: [tenantAlpha] });
    await seed(harness.outbox, tenantBeta, "evt-beta-1");

    const flush = await flushOpenPlatformOutboxTenant({
      publisher: harness.publisher,
      outbox: harness.outbox,
      tenantId: tenantAlpha,
    });

    expect(flush.outcomes).toHaveLength(0);
    expect(
      (await harness.outbox.get(tenantBeta, "evt-beta-1"))?.status,
    ).toBe("pending");
  });

  it("fails closed in production when the publisher is not production ready", async () => {
    const harness = createHarness();
    const relay = createOpenPlatformEventRelay({
      publisher: harness.publisher,
      outbox: harness.outbox,
      tenantIds: [tenantAlpha],
      mode: "production",
    });

    expect(relay.enabled).toBe(true);
    await expect(relay.start()).rejects.toThrow(
      /production event publisher/iu,
    );
    expect(relay.isRunning()).toBe(false);
    expect(vi.getTimerCount()).toBe(0);
    expect(relay.metrics().errors).toBe(1);
  });

  it("fails closed in production when the outbox is not production ready", async () => {
    const harness = createHarness();
    const relay = createOpenPlatformEventRelay({
      publisher: {
        productionReady: true,
        readiness: Object.freeze({
          storage: "persistent" as const,
          distributed: true,
          ready: () => true,
        }),
        record: (event) => harness.publisher.record(event),
        publish: (event) => harness.publisher.publish(event),
      },
      outbox: harness.outbox,
      tenantIds: [tenantAlpha],
      mode: "production",
    });

    await expect(relay.start()).rejects.toThrow(
      /production domain event outbox/iu,
    );
    await expect(relay.runOnce()).rejects.toThrow(
      /production domain event outbox/iu,
    );
    expect(relay.isRunning()).toBe(false);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("starts in production only when the publisher and outbox are ready", async () => {
    const inner = new InMemoryOpenPlatformOutbox({ clock: () => new Date() });
    const outbox = productionOutbox(inner);
    const publisher = new OpenPlatformEventPublisher({
      outbox,
      clock: () => new Date(),
      sink: { deliver: () => ({ delivered: 1 }) },
    });
    const relay = createOpenPlatformEventRelay({
      publisher,
      outbox,
      tenantIds: [tenantAlpha],
      mode: "production",
      intervalMs: 500,
      clock: () => new Date(),
    });
    await seed(inner, tenantAlpha, "evt-alpha-1");

    await relay.start();
    await vi.advanceTimersByTimeAsync(0);

    expect(relay.isRunning()).toBe(true);
    expect(relay.metrics().published).toBe(1);
    await relay.stop();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("fails closed when the outbox readiness rejects", async () => {
    const harness = createHarness();
    const relay = createOpenPlatformEventRelay({
      publisher: {
        productionReady: false,
        record: () => Promise.reject(new Error("unused")),
        publish: (event) => Promise.resolve({ eventId: event.eventId, delivered: 0, deadLettered: false }),
      },
      outbox: {
        append: () => Promise.reject(new Error("unused")),
        get: () => Promise.resolve(undefined),
        list: () => Promise.resolve({ items: [], hasMore: false }),
        readiness: {
          storage: "persistent",
          distributed: true,
          ready: () => Promise.reject(new Error("outbox down")),
        },
      },
      tenantIds: [tenantAlpha],
      mode: "test",
      enabled: true,
    });

    expect(await relay.isReady()).toBe(false);
    await expect(relay.start()).rejects.toThrow(
      /ready domain event outbox/iu,
    );
    expect(vi.getTimerCount()).toBe(0);
    expect(relay.metrics().errors).toBe(1);
    expect(harness.delivered).toHaveLength(0);
  });

  it("does not auto start in development or test without an explicit flag", () => {
    const harness = createHarness();
    expect(
      createOpenPlatformEventRelay({
        publisher: harness.publisher,
        outbox: harness.outbox,
        tenantIds: [tenantAlpha],
        mode: "development",
      }).enabled,
    ).toBe(false);
    expect(
      createOpenPlatformEventRelay({
        publisher: harness.publisher,
        outbox: harness.outbox,
        tenantIds: [tenantAlpha],
        mode: "test",
      }).enabled,
    ).toBe(false);
    expect(
      createOpenPlatformEventRelay({
        publisher: harness.publisher,
        outbox: harness.outbox,
        tenantIds: [tenantAlpha],
        mode: "test",
        enabled: true,
      }).enabled,
    ).toBe(true);
  });

  it("validates relay configuration", () => {
    const harness = createHarness();
    expect(() =>
      createOpenPlatformEventRelay({
        publisher: harness.publisher,
        outbox: harness.outbox,
        tenantIds: [tenantAlpha],
        intervalMs: 5,
      }),
    ).toThrow(/interval is invalid/iu);
    expect(() =>
      createOpenPlatformEventRelay({
        publisher: harness.publisher,
        outbox: harness.outbox,
        tenantIds: [tenantAlpha],
        jitterMs: -1,
      }),
    ).toThrow(/jitter is invalid/iu);
    expect(() =>
      createOpenPlatformEventRelay({
        publisher: harness.publisher,
        outbox: harness.outbox,
        tenantIds: [tenantAlpha],
        batchSize: 5_000,
      }),
    ).toThrow(/batch size is invalid/iu);
    expect(() =>
      createOpenPlatformEventRelay({
        publisher: harness.publisher,
        outbox: harness.outbox,
        tenantIds: ["Tenant_Bad"],
      }),
    ).toThrow(/tenant identifier is invalid/iu);
    expect(() =>
      createOpenPlatformEventRelay({
        publisher: harness.publisher,
        outbox: harness.outbox,
        tenantIds: [tenantAlpha],
        tenants: createOpenPlatformOutboxTenantResolver([tenantBeta]),
      }),
    ).toThrow(/tenant options conflict/iu);
  });
});

describe("open platform event relay leader lease", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2031-05-01T00:00:00.000Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("does not deliver on an instance that misses the lease", async () => {
    const lease = createInMemoryOpenPlatformRelayLease({ clock: () => new Date() });
    const fleet = createFleet(lease, ["relay_owner_a", "relay_owner_b"]);
    const [leader, follower] = fleet.relays;
    await lease.acquire({
      key: OPEN_PLATFORM_EVENT_RELAY_LEASE_KEY,
      ownerId: "relay_owner_a",
      now: new Date().toISOString(),
      ttlMs: 60_000,
    });
    await seed(fleet.outbox, tenantAlpha, "evt-alpha-1");
    const publish = vi.spyOn(fleet.publisher, "publish");

    const skipped = await follower.runOnce();

    expect(skipped.published).toBe(0);
    expect(skipped.claimed).toBe(0);
    expect(skipped.tenants).toBe(0);
    expect(skipped.skipped).toBe(1);
    expect(publish).not.toHaveBeenCalled();
    expect(fleet.delivered).toHaveLength(0);
    const snapshot = follower.snapshot();
    expect(snapshot.leader).toBe(false);
    expect(snapshot.delivered).toBe(0);
    expect(snapshot.claimed).toBe(0);
    expect(snapshot.skipped).toBe(1);
    expect(snapshot.ticks).toBe(1);
    expect(snapshot.leaseOwnerId).toBe("relay_owner_a");
    expect(snapshot.leaseKey).toBe(OPEN_PLATFORM_EVENT_RELAY_LEASE_KEY);
    expect(
      (await fleet.outbox.get(tenantAlpha, "evt-alpha-1"))?.status,
    ).toBe("pending");
    expect(leader.snapshot().ticks).toBe(0);
  });

  it("releases leadership at the end of a tick for the next instance", async () => {
    const lease = createInMemoryOpenPlatformRelayLease({ clock: () => new Date() });
    const fleet = createFleet(lease, ["relay_owner_a", "relay_owner_b"]);
    const [leader, follower] = fleet.relays;
    await seed(fleet.outbox, tenantAlpha, "evt-alpha-1");
    await seed(fleet.outbox, tenantBeta, "evt-beta-1");

    const drained = await leader.runOnce();
    expect(drained.published).toBe(2);
    expect(leader.snapshot().leader).toBe(true);
    expect(await lease.holder(OPEN_PLATFORM_EVENT_RELAY_LEASE_KEY)).toBeUndefined();

    const idle = await follower.runOnce();
    expect(idle.published).toBe(0);
    expect(idle.skipped).toBe(0);
    expect(follower.snapshot().leader).toBe(true);
    expect(fleet.delivered).toHaveLength(2);

    await seed(fleet.outbox, tenantGamma, "evt-gamma-1");
    const next = await follower.runOnce();
    expect(next.published).toBe(1);
    expect(fleet.delivered.map((event) => event.eventId)).toEqual([
      "evt-alpha-1",
      "evt-beta-1",
      "evt-gamma-1",
    ]);
  });

  it("hands an expired lease to another instance", async () => {
    const lease = createInMemoryOpenPlatformRelayLease({ clock: () => new Date() });
    const fleet = createFleet(lease, ["relay_owner_a", "relay_owner_b"]);
    const [stuck, taker] = fleet.relays;
    const expired = {
      key: OPEN_PLATFORM_EVENT_RELAY_LEASE_KEY,
      ownerId: "relay_owner_c",
      now: "2031-05-01T00:00:00.000Z",
      ttlMs: 1_000,
    };
    const held = await lease.acquire(expired);
    expect(held.held).toBe(true);
    const contested = await lease.acquire({ ...expired, ownerId: "relay_owner_b" });
    expect(contested.held).toBe(false);
    expect(contested.ownerId).toBe("relay_owner_c");
    expect(await lease.holder(OPEN_PLATFORM_EVENT_RELAY_LEASE_KEY)).toMatchObject({
      ownerId: "relay_owner_c",
    });
    await seed(fleet.outbox, tenantAlpha, "evt-alpha-1");

    const blocked = await stuck.runOnce();
    expect(blocked.published).toBe(0);
    expect(blocked.skipped).toBe(1);
    expect(stuck.snapshot().leader).toBe(false);
    expect(fleet.delivered).toHaveLength(0);

    vi.setSystemTime(new Date("2031-05-01T00:00:01.000Z"));
    const takenOver = await taker.runOnce();
    expect(takenOver.published).toBe(1);
    expect(takenOver.skipped).toBe(0);
    expect(taker.snapshot().leader).toBe(true);
    expect(fleet.delivered.map((event) => event.eventId)).toEqual([
      "evt-alpha-1",
    ]);
    expect(
      (await fleet.outbox.get(tenantAlpha, "evt-alpha-1"))?.status,
    ).toBe("published");
    expect(await lease.holder(OPEN_PLATFORM_EVENT_RELAY_LEASE_KEY)).toBeUndefined();
    expect(
      await lease.release({ ...expired, now: "2031-05-01T00:00:02.000Z" }),
    ).toBe(false);
  });

  it("delivers a contested event exactly once", async () => {
    const lease = createInMemoryOpenPlatformRelayLease({ clock: () => new Date() });
    const fleet = createFleet(lease, ["relay_owner_a", "relay_owner_b"]);
    const [leader, follower] = fleet.relays;
    await seed(fleet.outbox, tenantAlpha, "evt-alpha-1");

    const [left, right] = await Promise.all([
      leader.runOnce(),
      follower.runOnce(),
    ]);

    expect([left.published, right.published].reduce((sum, value) => sum + value, 0)).toBe(1);
    expect([left.claimed, right.claimed].reduce((sum, value) => sum + value, 0)).toBe(1);
    expect([left.skipped, right.skipped].reduce((sum, value) => sum + value, 0)).toBe(1);
    expect(fleet.delivered.map((event) => event.eventId)).toEqual([
      "evt-alpha-1",
    ]);
    expect(
      (await fleet.outbox.get(tenantAlpha, "evt-alpha-1"))?.status,
    ).toBe("published");
    expect(leader.snapshot().claimed + follower.snapshot().claimed).toBe(1);
    expect(leader.snapshot().delivered + follower.snapshot().delivered).toBe(1);
    expect(leader.snapshot().skipped + follower.snapshot().skipped).toBe(1);
  });

  it("renews only a lease held by the same owner", async () => {
    const lease = createInMemoryOpenPlatformRelayLease({ clock: () => new Date() });
    const request = {
      key: OPEN_PLATFORM_EVENT_RELAY_LEASE_KEY,
      ownerId: "relay_owner_a",
      now: "2031-05-01T00:00:00.000Z",
      ttlMs: 1_000,
    };
    expect((await lease.renew({ ...request, ownerId: "relay_owner_b" })).held).toBe(
      false,
    );
    expect((await lease.acquire(request)).held).toBe(true);
    const renewed = await lease.renew({
      ...request,
      now: "2031-05-01T00:00:00.500Z",
    });
    expect(renewed.held).toBe(true);
    expect(renewed.expiresAt).toBe("2031-05-01T00:00:01.500Z");
    const contested = await lease.renew({
      ...request,
      ownerId: "relay_owner_b",
      now: "2031-05-01T00:00:00.600Z",
    });
    expect(contested.held).toBe(false);
    expect(contested.ownerId).toBe("relay_owner_a");
  });

  it("reports a lease failure without delivering", async () => {
    const reports: string[] = [];
    const harness = createHarness({
      lease: {
        acquire: () => Promise.reject(new Error("lease store down")),
        release: () => Promise.resolve(true),
      },
      onError: (error) => reports.push(`${error.scope}:${error.code}`),
    });
    await seed(harness.outbox, tenantAlpha, "evt-alpha-1");

    const tick = await harness.relay.runOnce();

    expect(tick.published).toBe(0);
    expect(tick.skipped).toBe(1);
    expect(tick.errors).toBe(0);
    expect(harness.delivered).toHaveLength(0);
    expect(reports).toEqual(["lease:OPEN_PLATFORM_EVENT_RELAY_ERROR"]);
    const snapshot = harness.relay.snapshot();
    expect(snapshot.errors).toBe(1);
    expect(snapshot.lastErrorCode).toBe("OPEN_PLATFORM_EVENT_RELAY_ERROR");
    expect(snapshot.leader).toBe(false);
  });

  it("exposes a delivery snapshot without tenant or payload fields", async () => {
    const lease = createInMemoryOpenPlatformRelayLease({ clock: () => new Date() });
    const harness = createHarness({
      lease,
      sink: { deliver: () => ({ delivered: 1 }) },
    });
    await seed(harness.outbox, tenantAlpha, "evt-alpha-1");
    await harness.relay.start();
    await vi.advanceTimersByTimeAsync(0);
    await seed(harness.outbox, tenantBeta, "evt-beta-1");
    vi.setSystemTime(new Date("2031-05-01T00:00:30.000Z"));
    await vi.advanceTimersByTimeAsync(1_000);
    await harness.relay.stop();

    const snapshot = harness.relay.snapshot();
    expect(snapshot.running).toBe(false);
    expect(snapshot.claimed).toBe(2);
    expect(snapshot.delivered).toBe(2);
    expect(snapshot.failed).toBe(0);
    expect(snapshot.retried).toBe(0);
    expect(snapshot.deadLettered).toBe(0);
    expect(snapshot.skipped).toBe(0);
    expect(snapshot.ticks).toBe(2);
    expect(snapshot.lastRunAt).toBe("2031-05-01T00:00:31.000Z");
    expect(snapshot.lastSuccessAt).toBe("2031-05-01T00:00:31.000Z");
    expect(snapshot.lastErrorAt).toBeNull();
    expect(snapshot.leaseExpiresAt).not.toBeNull();
    const serialized = JSON.stringify(snapshot);
    expect(serialized).not.toContain(tenantAlpha);
    expect(serialized).not.toContain(tenantBeta);
    expect(serialized).not.toContain("evt-alpha-1");
    expect(serialized).not.toContain("application.created");
    expect(Object.keys(snapshot).sort()).toEqual([
      "claimed",
      "deadLettered",
      "delivered",
      "enabled",
      "errors",
      "failed",
      "lastErrorAt",
      "lastErrorCode",
      "lastRunAt",
      "lastSuccessAt",
      "leader",
      "leaseExpiresAt",
      "leaseKey",
      "leaseOwnerId",
      "mode",
      "retried",
      "running",
      "skipped",
      "started",
      "stopped",
      "tenantErrors",
      "tenants",
      "ticks",
    ]);
    expect(Object.isFrozen(snapshot)).toBe(true);
  });

  it("keeps single instance behaviour when no lease port is injected", async () => {
    const harness = createHarness();
    await seed(harness.outbox, tenantAlpha, "evt-alpha-1");

    const first = await harness.relay.runOnce();
    const second = await harness.relay.runOnce();

    expect(first.published).toBe(1);
    expect(first.claimed).toBe(1);
    expect(first.skipped).toBe(0);
    expect(second.published).toBe(0);
    expect(second.skipped).toBe(0);
    const snapshot = harness.relay.snapshot();
    expect(snapshot.leader).toBe(true);
    expect(snapshot.leaseKey).toBeNull();
    expect(snapshot.leaseOwnerId).toBeNull();
    expect(snapshot.leaseExpiresAt).toBeNull();
    expect(snapshot.delivered).toBe(1);
    expect(snapshot.lastSuccessAt).toBe("2031-05-01T00:00:00.000Z");
  });

  it("validates lease configuration", () => {
    const harness = createHarness();
    expect(() =>
      createOpenPlatformEventRelay({
        publisher: harness.publisher,
        outbox: harness.outbox,
        tenantIds: [tenantAlpha],
        leaseKey: OPEN_PLATFORM_EVENT_RELAY_LEASE_KEY,
      }),
    ).toThrow(/lease options require a lease port/iu);
    expect(() =>
      createOpenPlatformEventRelay({
        publisher: harness.publisher,
        outbox: harness.outbox,
        tenantIds: [tenantAlpha],
        lease: { acquire: () => Promise.reject(new Error("unused")), release: () => Promise.resolve(false) },
        leaseKey: "short",
      }),
    ).toThrow(/lease key is invalid/iu);
    expect(() =>
      createOpenPlatformEventRelay({
        publisher: harness.publisher,
        outbox: harness.outbox,
        tenantIds: [tenantAlpha],
        lease: createInMemoryOpenPlatformRelayLease(),
        leaseTtlMs: 10,
      }),
    ).toThrow(/lease duration is invalid/iu);
    expect(() =>
      createOpenPlatformEventRelay({
        publisher: harness.publisher,
        outbox: harness.outbox,
        tenantIds: [tenantAlpha],
        lease: createInMemoryOpenPlatformRelayLease(),
        ownerId: "owner id",
      }),
    ).toThrow(/lease owner is invalid/iu);
    expect(() =>
      createOpenPlatformEventRelay({
        publisher: harness.publisher,
        outbox: harness.outbox,
        tenantIds: [tenantAlpha],
        mode: "production",
        lease: createInMemoryOpenPlatformRelayLease(),
      }),
    ).toThrow(/production relay lease/iu);
  });
});

describe("open platform SQL relay lease", () => {
  type QueryResult = { rows?: unknown[]; rowCount?: number };
  type Responder = (text: string, values: unknown[]) => unknown | Promise<unknown>;
  type TestAdapter = OpenPlatformPersistence.DatabaseAdapter & {
    calls: { text: string; values: unknown[] }[];
  };

  function adapter(responder: Responder): TestAdapter {
    const calls: { text: string; values: unknown[] }[] = [];
    const query = async (text: string, values: unknown[] = []): Promise<unknown> => {
      calls.push({ text, values });
      return responder(text, values);
    };
    return {
      calls,
      query,
      transaction: async <T>(callback: (executor: OpenPlatformPersistence.DatabaseAdapter) => Promise<T>): Promise<T> =>
        callback({ query }),
    };
  }

  function leaseRequest(ownerId: string, now = "2031-05-01T00:00:00.000Z") {
    return {
      key: OPEN_PLATFORM_EVENT_RELAY_LEASE_KEY,
      ownerId,
      now,
      ttlMs: 30_000,
    };
  }

  it("acquires and releases a stable advisory lock key", async () => {
    const executor = adapter((text) => {
      if (text.includes("pg_try_advisory_lock")) {
        return { rows: [{ acquired: true }], rowCount: 1 };
      }
      if (text.includes("pg_advisory_unlock")) {
        return { rows: [{ released: true }], rowCount: 1 };
      }
      return { rows: [] };
    });
    const lease = new OpenPlatformPersistence.SqlOpenPlatformRelayLease(
      new OpenPlatformPersistence.OpenPlatformSqlRuntime({
        adapter: executor,
        tenantId: "relay-alpha",
      }),
    );

    expect(lease.productionReady).toBe(true);
    expect(lease.readiness).toMatchObject({
      storage: "persistent",
      distributed: true,
    });
    expect(await lease.isReady()).toBe(true);

    const acquired = await lease.acquire(leaseRequest("relay_owner_a"));
    expect(acquired).toEqual({
      key: OPEN_PLATFORM_EVENT_RELAY_LEASE_KEY,
      ownerId: "relay_owner_a",
      held: true,
      expiresAt: "2031-05-01T00:00:30.000Z",
    });
    const acquire = executor.calls.at(-1);
    expect(acquire?.text).toBe(
      'SELECT pg_try_advisory_lock(hashtextextended($1, 0)) AS "acquired"',
    );
    expect(acquire?.values).toEqual([OPEN_PLATFORM_EVENT_RELAY_LEASE_KEY]);
    expect((await lease.renew(leaseRequest("relay_owner_a"))).held).toBe(true);
    expect(executor.calls.at(-1)?.text).toBe(acquire?.text);

    expect(await lease.release(leaseRequest("relay_owner_a"))).toBe(true);
    const release = executor.calls.at(-1);
    expect(release?.text).toBe(
      'SELECT pg_advisory_unlock(hashtextextended($1, 0)) AS "released"',
    );
    expect(release?.values).toEqual([OPEN_PLATFORM_EVENT_RELAY_LEASE_KEY]);
  });

  it("reports a lost lock and a stable key across instances", async () => {
    const locks = new Map<string, string>();
    const session = (name: string): TestAdapter =>
      adapter((text, values) => {
        const key = String(values[0]);
        if (text.includes("pg_try_advisory_lock")) {
          const acquired = !locks.has(key);
          if (acquired) locks.set(key, name);
          return { rows: [{ acquired }], rowCount: 1 };
        }
        if (text.includes("pg_advisory_unlock")) {
          const released = locks.get(key) === name;
          if (released) locks.delete(key);
          return { rows: [{ released }], rowCount: 1 };
        }
        return { rows: [] };
      });
    const firstSession = session("session_a");
    const secondSession = session("session_b");
    const first = new OpenPlatformPersistence.SqlOpenPlatformRelayLease(
      new OpenPlatformPersistence.OpenPlatformSqlRuntime({
        adapter: firstSession,
        tenantId: "relay-alpha",
      }),
    );
    const second = new OpenPlatformPersistence.SqlOpenPlatformRelayLease(
      new OpenPlatformPersistence.OpenPlatformSqlRuntime({
        adapter: secondSession,
        tenantId: "relay-beta",
      }),
    );
    const staging = {
      ...leaseRequest("relay_owner_b"),
      key: "getbrick:open-platform:outbox-relay:staging",
    };

    expect((await first.acquire(leaseRequest("relay_owner_a"))).held).toBe(true);
    expect((await second.acquire(leaseRequest("relay_owner_b"))).held).toBe(false);
    expect(await second.release(leaseRequest("relay_owner_b"))).toBe(false);
    expect(await first.release(leaseRequest("relay_owner_a"))).toBe(true);
    expect((await second.acquire(leaseRequest("relay_owner_b"))).held).toBe(true);
    expect((await first.acquire(staging)).held).toBe(true);
    const statements = [...firstSession.calls, ...secondSession.calls];
    expect(statements).toHaveLength(6);
    expect(
      statements.every(
        (call) =>
          call.text.includes("pg_try_advisory_lock(hashtextextended($1, 0))") ||
          call.text.includes("pg_advisory_unlock(hashtextextended($1, 0))"),
      ),
    ).toBe(true);
    expect(
      statements.filter((call) => call.values[0] === staging.key),
    ).toHaveLength(1);
    expect(
      statements.filter(
        (call) => call.values[0] === OPEN_PLATFORM_EVENT_RELAY_LEASE_KEY,
      ),
    ).toHaveLength(5);
  });

  it("propagates SQL errors and rejects invalid lease keys", async () => {
    const executor = adapter(() => {
      throw new Error("connection terminated");
    });
    const lease = new OpenPlatformPersistence.SqlOpenPlatformRelayLease(
      new OpenPlatformPersistence.OpenPlatformSqlRuntime({
        adapter: executor,
        tenantId: "relay-alpha",
      }),
    );

    await expect(lease.acquire(leaseRequest("relay_owner_a"))).rejects.toThrow(
      /connection terminated/u,
    );
    await expect(lease.release(leaseRequest("relay_owner_a"))).rejects.toThrow(
      /connection terminated/u,
    );
    await expect(
      lease.acquire({ ...leaseRequest("relay_owner_a"), key: "short" }),
    ).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.VALIDATION_ERROR,
    });
    await expect(
      lease.acquire({ ...leaseRequest("relay_owner_a"), ttlMs: 10 }),
    ).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.VALIDATION_ERROR,
    });
    expect(executor.calls).toHaveLength(2);
  });
});

describe("open platform event relay outbox helpers", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2031-05-01T00:00:00.000Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("pages a static tenant resolver with normalized identifiers", async () => {
    const resolver = createOpenPlatformOutboxTenantResolver([
      tenantAlpha,
      tenantAlpha,
      tenantBeta,
    ]);
    const first = await listOpenPlatformOutboxTenants(resolver, { limit: 2 });
    expect(first.tenantIds).toEqual([tenantAlpha, tenantBeta]);
    expect(first.cursor).toBeUndefined();
    expect(first.hasMore).toBe(false);

    const paged = createOpenPlatformOutboxTenantResolver([
      tenantAlpha,
      tenantBeta,
      tenantGamma,
    ]);
    const page = await listOpenPlatformOutboxTenants(paged, { limit: 2 });
    expect(page.tenantIds).toEqual([tenantAlpha, tenantBeta]);
    expect(page.cursor).toBe("2");
    expect(page.hasMore).toBe(true);
    const next = await listOpenPlatformOutboxTenants(paged, {
      cursor: page.cursor,
      limit: 2,
    });
    expect(next.tenantIds).toEqual([tenantGamma]);
    expect(next.hasMore).toBe(false);
  });

  it("rejects an invalid tenant page from a resolver", async () => {
    await expect(
      listOpenPlatformOutboxTenants(
        { listTenants: () => Promise.resolve({ tenantIds: "nope" as unknown as string[] }) },
        { limit: 2 },
      ),
    ).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.VALIDATION_ERROR,
    });
    await expect(
      listOpenPlatformOutboxTenants(
        { listTenants: () => Promise.resolve({ tenantIds: [], cursor: "bad cursor" }) },
        { limit: 2 },
      ),
    ).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.VALIDATION_ERROR,
    });
  });

  it("reports settled, deferred and truncated records per tenant", async () => {
    const outbox = new InMemoryOpenPlatformOutbox({ clock: () => new Date() });
    const publisher = new OpenPlatformEventPublisher({
      outbox,
      clock: () => new Date(),
      sink: { deliver: () => ({ delivered: 1 }) },
    });
    for (let index = 0; index < 4; index += 1) {
      await seed(outbox, tenantAlpha, `evt-alpha-${index}`);
    }

    const flush: OpenPlatformEventFlushResult =
      await flushOpenPlatformOutboxTenant({
        publisher,
        outbox,
        tenantId: tenantAlpha,
        limit: 2,
      });

    expect(flush.tenantId).toBe(tenantAlpha);
    expect(flush.outcomes.map((outcome) => outcome.status)).toEqual([
      "published",
      "published",
    ]);
    expect(flush.outcomes.every((outcome) => outcome.tenantId === tenantAlpha)).toBe(
      true,
    );
    expect(flush.truncated).toBe(true);
    expect(flush.scanned).toBe(2);

    const settled = await flushOpenPlatformOutboxTenant({
      publisher,
      outbox,
      tenantId: tenantAlpha,
      limit: 5,
    });
    expect(settled.outcomes).toHaveLength(2);
    expect(settled.deferred).toBe(0);
  });
});

describe("open platform event relay module", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2031-05-01T00:00:00.000Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("stays disabled by default and does not touch the timer", async () => {
    const harness = createHarness();
    const moduleRef = await Test.createTestingModule({
      imports: [
        createOpenPlatformEventRelayModule({
          publisher: harness.publisher,
          outbox: harness.outbox,
          tenantIds: [tenantAlpha],
          mode: "test",
        }),
      ],
    }).compile();
    await moduleRef.init();

    const relay = moduleRef.get<OpenPlatformEventRelay>(OPEN_PLATFORM_EVENT_RELAY);
    expect(moduleRef.get<boolean>(OPEN_PLATFORM_EVENT_RELAY_ENABLED)).toBe(false);
    expect(relay.isRunning()).toBe(false);
    expect(vi.getTimerCount()).toBe(0);

    await moduleRef.close();
  });

  it("starts on init and stops on destroy when enabled", async () => {
    const harness = createHarness();
    await seed(harness.outbox, tenantAlpha, "evt-alpha-1");
    const moduleRef = await Test.createTestingModule({
      imports: [
        OpenPlatformEventRelayModule.forRoot({
          publisher: harness.publisher,
          outbox: harness.outbox,
          tenantIds: [tenantAlpha, tenantBeta],
          mode: "test",
          enabled: true,
          intervalMs: 500,
        }),
      ],
    }).compile();
    await moduleRef.init();

    const relay = moduleRef.get<OpenPlatformEventRelay>(OPEN_PLATFORM_EVENT_RELAY);
    expect(relay.isRunning()).toBe(true);
    await vi.advanceTimersByTimeAsync(0);
    expect(relay.metrics().published).toBe(1);

    await moduleRef.close();
    expect(relay.isRunning()).toBe(false);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("accepts a prebuilt relay instance", async () => {
    const harness = createHarness();
    const moduleRef = await Test.createTestingModule({
      imports: [
        createOpenPlatformEventRelayModule({ relay: harness.relay }),
      ],
    }).compile();
    await moduleRef.init();
    expect(moduleRef.get<OpenPlatformEventRelay>(OPEN_PLATFORM_EVENT_RELAY)).toBe(
      harness.relay,
    );
    expect(harness.relay.isRunning()).toBe(true);
    await moduleRef.close();
    expect(harness.relay.isRunning()).toBe(false);
  });

  it("does not read or publish while the module is wired", async () => {
    const harness = createHarness();
    const list = vi.spyOn(harness.outbox, "list");
    const append = vi.spyOn(harness.outbox, "append");
    const publish = vi.spyOn(harness.publisher, "publish");
    const moduleRef = await Test.createTestingModule({
      imports: [
        createOpenPlatformEventRelayModule({
          publisher: harness.publisher,
          outbox: harness.outbox,
          tenantIds: [tenantAlpha],
          mode: "test",
          enabled: true,
        }),
      ],
    }).compile();
    await moduleRef.init();

    expect(list).not.toHaveBeenCalled();
    expect(append).not.toHaveBeenCalled();
    expect(publish).not.toHaveBeenCalled();

    await moduleRef.close();
  });

  it("fails module init in production when the relay is not ready", async () => {
    const harness = createHarness();
    const moduleRef = await Test.createTestingModule({
      imports: [
        createOpenPlatformEventRelayModule({
          publisher: harness.publisher,
          outbox: harness.outbox,
          tenantIds: [tenantAlpha],
          mode: "production",
        }),
      ],
    }).compile();

    await expect(moduleRef.init()).rejects.toThrow(
      /open platform event relay did not start/iu,
    );
    expect(vi.getTimerCount()).toBe(0);
  });

  it("validates module options", async () => {
    const harness = createHarness();
    expect(() =>
      createOpenPlatformEventRelayModule({} as never),
    ).toThrow(/requires a publisher and outbox/iu);
    expect(() =>
      createOpenPlatformEventRelayModule({
        relay: harness.relay,
        publisher: harness.publisher,
        outbox: harness.outbox,
      } as never),
    ).toThrow(/event relay options conflict/iu);
    expect(() =>
      createOpenPlatformEventRelayModule({ relay: {} as never }),
    ).toThrow(/event relay is invalid/iu);
  });
});
