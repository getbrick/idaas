import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  InMemoryOpenPlatformOutbox,
  OPEN_PLATFORM_EVENT_RELAY_LEASE_KEY,
  OpenPlatformEventPublisher,
  type InMemoryOpenPlatformOutboxOptions,
  type OpenPlatformEventFlushResult,
  type OpenPlatformEventRelay,
  type OpenPlatformEventSink,
  type OpenPlatformOutboxClaimRequest,
  type OpenPlatformOutboxClaimResult,
  type OpenPlatformOutboxRecord,
  type OpenPlatformRelayLeasePort,
  createInMemoryOpenPlatformRelayLease,
  createOpenPlatformEventRelay,
  flushOpenPlatformOutboxTenant,
} from "../src/open-platform/index.js";

const tenantAlpha = "contention-alpha";
const tenantBeta = "contention-beta";
const tenantGamma = "contention-gamma";
const tenantDelta = "contention-delta";
const startedAt = "2032-03-01T00:00:00.000Z";
const leaseMs = 30_000;

function at(offsetMs: number): string {
  return new Date(Date.parse(startedAt) + offsetMs).toISOString();
}

function createOutbox(
  options: InMemoryOpenPlatformOutboxOptions = {},
): InMemoryOpenPlatformOutbox {
  return new InMemoryOpenPlatformOutbox({ clock: () => new Date(), ...options });
}

interface SinkHooks {
  readonly gate?: Promise<void>;
  readonly onDeliver?: () => void;
}

function createSink(
  hooks: SinkHooks = {},
): {
  readonly calls: OpenPlatformOutboxRecord[];
  readonly sink: OpenPlatformEventSink;
} {
  const calls: OpenPlatformOutboxRecord[] = [];
  return {
    calls,
    sink: {
      deliver: async (event) => {
        calls.push(event);
        hooks.onDeliver?.();
        if (hooks.gate !== undefined) await hooks.gate;
        return { delivered: 1 };
      },
    },
  };
}

function createPublisher(
  outbox: InMemoryOpenPlatformOutbox,
  sink: OpenPlatformEventSink,
): OpenPlatformEventPublisher {
  return new OpenPlatformEventPublisher({ outbox, clock: () => new Date(), sink });
}

function deferred(): {
  readonly promise: Promise<void>;
  readonly resolve: () => void;
} {
  let resolve: () => void = () => undefined;
  const promise = new Promise<void>((settle) => {
    resolve = settle;
  });
  return { promise, resolve };
}

async function seed(
  outbox: InMemoryOpenPlatformOutbox,
  tenantId: string,
  eventId: string,
  occurredAt = startedAt,
): Promise<OpenPlatformOutboxRecord> {
  return outbox.append({
    eventId,
    tenantId,
    eventType: "application.created",
    resourceType: "application",
    resourceId: `app-${eventId}`,
    occurredAt,
    data: { name: "contention fixture" },
  });
}

function claimAt(
  tenantId: string,
  eventId: string,
  leaseId: string,
  now: string,
  attempt = 1,
): OpenPlatformOutboxClaimRequest {
  return {
    tenantId,
    eventId,
    attempt,
    leaseId,
    now,
    leaseExpiresAt: new Date(Date.parse(now) + leaseMs).toISOString(),
  };
}

async function publishOnce(
  publisher: OpenPlatformEventPublisher,
  outbox: InMemoryOpenPlatformOutbox,
  tenantId: string,
  eventId: string,
): Promise<number> {
  const record = await outbox.get(tenantId, eventId);
  if (record === undefined) throw new Error(`missing fixture ${eventId}`);
  const result = await publisher.publish(record);
  return result.delivered;
}

function flushTenant(
  publisher: OpenPlatformEventPublisher,
  outbox: InMemoryOpenPlatformOutbox,
  tenantId: string,
): Promise<OpenPlatformEventFlushResult> {
  return flushOpenPlatformOutboxTenant({ publisher, outbox, tenantId, limit: 50 });
}

interface RelayFleet {
  readonly outbox: InMemoryOpenPlatformOutbox;
  readonly delivered: OpenPlatformOutboxRecord[];
  readonly relays: readonly OpenPlatformEventRelay[];
}

function createRelayFleet(
  lease: OpenPlatformRelayLeasePort,
  ownerIds: readonly string[],
  tenantIds: readonly string[],
): RelayFleet {
  const outbox = createOutbox();
  const { sink, calls } = createSink();
  const publisher = createPublisher(outbox, sink);
  const relays = ownerIds.map((ownerId) =>
    createOpenPlatformEventRelay({
      publisher,
      outbox,
      lease,
      ownerId,
      tenantIds,
      mode: "test",
      enabled: true,
      intervalMs: 1_000,
      batchSize: 50,
      clock: () => new Date(),
    }),
  );
  return { outbox, delivered: calls, relays };
}

describe("open platform outbox claim contention", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(startedAt));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("grants a contested claim to exactly one claimer", async () => {
    const outbox = createOutbox();
    await seed(outbox, tenantAlpha, "evt-contended");
    const leaseIds = ["lease-a", "lease-b", "lease-c", "lease-d", "lease-e"];

    const results: OpenPlatformOutboxClaimResult[] = await Promise.all(
      leaseIds.map((leaseId) =>
        outbox.claim(claimAt(tenantAlpha, "evt-contended", leaseId, startedAt)),
      ),
    );

    const winners = results.filter((result) => result.claimed === true);
    const losers = results.filter((result) => result.claimed !== true);
    expect(winners).toHaveLength(1);
    expect(losers).toHaveLength(4);
    expect(losers.every((result) => result.record === undefined)).toBe(true);
    const winnerIndex = results.findIndex((result) => result.claimed === true);
    expect(winners[0].record?.leaseId).toBe(leaseIds[winnerIndex]);
    expect(winners[0].record?.status).toBe("delivering");
    expect(winners[0].record?.attempt).toBe(1);
    expect(winners[0].record?.sequence).toBe(1);
    const stored = await outbox.get(tenantAlpha, "evt-contended");
    expect(stored?.leaseId).toBe(leaseIds[winnerIndex]);
    expect(stored?.leaseExpiresAt).toBe(at(leaseMs));
    expect(stored?.status).toBe("delivering");
  });

  it("keeps an unexpired lease exclusive and hands it over after expiry", async () => {
    const outbox = createOutbox();
    await seed(outbox, tenantAlpha, "evt-leased");
    expect(
      (await outbox.claim(claimAt(tenantAlpha, "evt-leased", "lease-holder", startedAt)))
        .claimed,
    ).toBe(true);

    const beforeExpiry = await Promise.all(
      ["lease-b", "lease-c"].map((leaseId) =>
        outbox.claim(claimAt(tenantAlpha, "evt-leased", leaseId, at(leaseMs - 1))),
      ),
    );
    expect(beforeExpiry.map((result) => result.claimed)).toEqual([false, false]);
    expect(beforeExpiry.every((result) => result.record === undefined)).toBe(true);
    expect((await outbox.get(tenantAlpha, "evt-leased"))?.leaseId).toBe(
      "lease-holder",
    );

    const contenders = ["lease-d", "lease-e"];
    const takeover = await Promise.all(
      contenders.map((leaseId) =>
        outbox.claim(claimAt(tenantAlpha, "evt-leased", leaseId, at(leaseMs))),
      ),
    );
    const takerIndex = takeover.findIndex((result) => result.claimed === true);
    expect(takeover.filter((result) => result.claimed === true)).toHaveLength(1);
    expect(takeover.filter((result) => result.claimed === false)).toHaveLength(1);
    expect(takeover[takerIndex].record?.leaseId).toBe(contenders[takerIndex]);
    const stored = await outbox.get(tenantAlpha, "evt-leased");
    expect(stored?.leaseId).toBe(contenders[takerIndex]);
    expect(stored?.leaseExpiresAt).toBe(at(leaseMs + leaseMs));
    expect(stored?.attempt).toBe(1);
  });

  it("gives a claim loser no record it could settle", async () => {
    const outbox = createOutbox();
    await seed(outbox, tenantAlpha, "evt-locked");
    const winner = await outbox.claim(
      claimAt(tenantAlpha, "evt-locked", "lease-winner", startedAt),
    );
    const loser = await outbox.claim(
      claimAt(tenantAlpha, "evt-locked", "lease-loser", startedAt),
    );

    expect(winner.record?.leaseId).toBe("lease-winner");
    expect(loser.claimed).toBe(false);
    expect(loser.record).toBeUndefined();
    const stored = await outbox.get(tenantAlpha, "evt-locked");
    expect(stored?.status).toBe("delivering");
    expect(stored?.leaseId).toBe("lease-winner");
    expect(stored?.leaseExpiresAt).toBe(at(leaseMs));
    expect(stored?.updatedAt).toBe(startedAt);
  });

  it("keeps the same event identifier independent per tenant", async () => {
    const outbox = createOutbox();
    await Promise.all([
      seed(outbox, tenantAlpha, "evt-shared"),
      seed(outbox, tenantBeta, "evt-shared"),
      seed(outbox, tenantGamma, "evt-shared"),
    ]);

    const claims = await Promise.all([
      outbox.claim(claimAt(tenantAlpha, "evt-shared", "lease-alpha", startedAt)),
      outbox.claim(claimAt(tenantBeta, "evt-shared", "lease-beta", startedAt)),
      outbox.claim(claimAt(tenantGamma, "evt-shared", "lease-gamma", startedAt)),
    ]);

    expect(claims.map((result) => result.claimed)).toEqual([true, true, true]);
    expect(claims.map((result) => result.record?.tenantId)).toEqual([
      tenantAlpha,
      tenantBeta,
      tenantGamma,
    ]);
    expect(claims.map((result) => result.record?.leaseId)).toEqual([
      "lease-alpha",
      "lease-beta",
      "lease-gamma",
    ]);
    expect(await outbox.get(tenantAlpha, "evt-foreign")).toBeUndefined();
    expect(await outbox.get(tenantBeta, "evt-foreign")).toBeUndefined();
    expect(await outbox.get(tenantGamma, "evt-foreign")).toBeUndefined();
    for (const tenantId of [tenantAlpha, tenantBeta, tenantGamma]) {
      const records = outbox.snapshot(tenantId);
      expect(records).toHaveLength(1);
      expect(records[0].sequence).toBe(1);
    }
  });

  it("refuses a claim for an already published event", async () => {
    const outbox = createOutbox();
    const { sink, calls } = createSink();
    const publisher = createPublisher(outbox, sink);
    await seed(outbox, tenantAlpha, "evt-settled");
    expect(await publishOnce(publisher, outbox, tenantAlpha, "evt-settled")).toBe(1);

    const again = await outbox.claim(
      claimAt(tenantAlpha, "evt-settled", "lease-after-publish", startedAt),
    );
    expect(again.claimed).toBe(false);
    expect(again.record).toBeUndefined();
    expect((await outbox.get(tenantAlpha, "evt-settled"))?.status).toBe("published");
    expect(calls).toHaveLength(1);
  });
});

describe("open platform outbox delivery under concurrent flush loops", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(startedAt));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("delivers a contested event exactly once across two flush loops", async () => {
    const outbox = createOutbox();
    const gate = deferred();
    const { sink, calls } = createSink({ gate: gate.promise });
    const publisher = createPublisher(outbox, sink);
    await seed(outbox, tenantAlpha, "evt-once");

    const first = flushTenant(publisher, outbox, tenantAlpha);
    const second = flushTenant(publisher, outbox, tenantAlpha);
    gate.resolve();
    const [left, right] = await Promise.all([first, second]);

    expect(calls).toHaveLength(1);
    expect(calls[0].eventId).toBe("evt-once");
    expect(calls[0].tenantId).toBe(tenantAlpha);
    expect(calls[0].leaseId).toBeDefined();
    expect(calls[0].status).toBe("delivering");
    const outcomes = [...left.outcomes, ...right.outcomes];
    expect(outcomes).toHaveLength(2);
    expect(outcomes.every((outcome) => outcome.tenantId === tenantAlpha)).toBe(true);
    expect(outcomes.every((outcome) => outcome.eventId === "evt-once")).toBe(true);
    expect(outcomes.filter((outcome) => outcome.delivered === 1)).toHaveLength(1);
    expect(
      outcomes.reduce((sum, outcome) => sum + outcome.delivered, 0),
    ).toBe(1);
    expect(outcomes.every((outcome) => outcome.retryScheduled === false)).toBe(true);
    const stored = await outbox.get(tenantAlpha, "evt-once");
    expect(stored?.status).toBe("published");
    expect(stored?.attempt).toBe(1);
    expect(stored?.leaseId).toBeUndefined();
    expect(stored?.leaseExpiresAt).toBeUndefined();
  });

  it("defers a second flush loop while the first holds the delivery lease", async () => {
    const outbox = createOutbox();
    const gate = deferred();
    const entered = deferred();
    const { sink, calls } = createSink({
      gate: gate.promise,
      onDeliver: entered.resolve,
    });
    const publisher = createPublisher(outbox, sink);
    await seed(outbox, tenantAlpha, "evt-inflight");

    const first = flushTenant(publisher, outbox, tenantAlpha);
    await entered.promise;
    const second = await flushTenant(publisher, outbox, tenantAlpha);

    expect(second.outcomes).toHaveLength(0);
    expect(second.deferred).toBe(1);
    expect(second.truncated).toBe(false);
    expect(calls).toHaveLength(1);

    gate.resolve();
    const settled = await first;
    expect(settled.outcomes).toHaveLength(1);
    expect(settled.outcomes[0]?.status).toBe("published");
    expect(settled.outcomes[0]?.delivered).toBe(1);
    expect(calls).toHaveLength(1);
    expect((await outbox.get(tenantAlpha, "evt-inflight"))?.status).toBe(
      "published",
    );
  });

  it("keeps the first terminal state when complete and fail race", async () => {
    const outbox = createOutbox();
    await seed(outbox, tenantAlpha, "evt-terminal");
    expect(
      (
        await outbox.claim(
          claimAt(tenantAlpha, "evt-terminal", "lease-terminal", startedAt),
        )
      ).claimed,
    ).toBe(true);

    const [completed, failed] = await Promise.all([
      outbox.complete({
        tenantId: tenantAlpha,
        eventId: "evt-terminal",
        now: startedAt,
        leaseId: "lease-terminal",
      }),
      outbox.fail({
        tenantId: tenantAlpha,
        eventId: "evt-terminal",
        now: startedAt,
        leaseId: "lease-terminal",
        errorCode: "SINK_DOWN",
      }),
    ]);

    expect(completed.status).toBe("published");
    expect(failed.status).toBe("published");
    expect(failed.publishedAt).toBe(completed.publishedAt);
    expect(failed.errorCode).toBeUndefined();
    expect(failed.nextAttemptAt).toBeUndefined();
    expect(failed.attempt).toBe(completed.attempt);

    const repeats = await Promise.all([
      outbox.complete({
        tenantId: tenantAlpha,
        eventId: "evt-terminal",
        now: at(1_000),
        leaseId: "lease-terminal",
      }),
      outbox.complete({
        tenantId: tenantAlpha,
        eventId: "evt-terminal",
        now: at(2_000),
        leaseId: "lease-other",
      }),
    ]);

    for (const repeat of repeats) {
      expect(repeat.status).toBe("published");
      expect(repeat.publishedAt).toBe(completed.publishedAt);
      expect(repeat.attempt).toBe(completed.attempt);
      expect(repeat.leaseId).toBeUndefined();
      expect(repeat.leaseExpiresAt).toBeUndefined();
      expect(repeat.errorCode).toBeUndefined();
    }
  });

  it("never re-delivers a settled event on a repeated publish", async () => {
    const outbox = createOutbox();
    const { sink, calls } = createSink();
    const publisher = createPublisher(outbox, sink);
    await seed(outbox, tenantAlpha, "evt-published");
    await seed(outbox, tenantAlpha, "evt-dead");
    expect(await publishOnce(publisher, outbox, tenantAlpha, "evt-published")).toBe(1);
    expect(
      (
        await outbox.claim(claimAt(tenantAlpha, "evt-dead", "lease-dead", startedAt))
      ).claimed,
    ).toBe(true);
    await outbox.fail({
      tenantId: tenantAlpha,
      eventId: "evt-dead",
      now: startedAt,
      leaseId: "lease-dead",
      errorCode: "SINK_DOWN",
      deadLetter: true,
    });

    const repeated = await publishOnce(
      publisher,
      outbox,
      tenantAlpha,
      "evt-published",
    );
    const deadLettered = await publishOnce(
      publisher,
      outbox,
      tenantAlpha,
      "evt-dead",
    );

    expect(repeated).toBe(0);
    expect(deadLettered).toBe(0);
    expect(calls).toHaveLength(1);
    expect((await outbox.get(tenantAlpha, "evt-dead"))?.status).toBe(
      "dead_lettered",
    );
    expect((await outbox.get(tenantAlpha, "evt-dead"))?.nextAttemptAt).toBeUndefined();
  });

  it("records one delivery attempt when two flush loops race a failing sink", async () => {
    const outbox = createOutbox();
    let attempts = 0;
    const flaky: OpenPlatformEventSink = {
      deliver: () => {
        attempts += 1;
        if (attempts === 1) throw new Error("sink unavailable");
        return { delivered: 1 };
      },
    };
    const publisher = createPublisher(outbox, flaky);
    await seed(outbox, tenantAlpha, "evt-retry");

    const [left, right] = await Promise.all([
      flushTenant(publisher, outbox, tenantAlpha),
      flushTenant(publisher, outbox, tenantAlpha),
    ]);

    expect(attempts).toBe(1);
    const outcomes = [...left.outcomes, ...right.outcomes];
    expect(outcomes.every((outcome) => outcome.delivered === 0)).toBe(true);
    expect(outcomes.some((outcome) => outcome.status === "published")).toBe(false);
    expect(outcomes.every((outcome) => outcome.status === "failed")).toBe(true);
    expect(outcomes.every((outcome) => outcome.retryScheduled === true)).toBe(true);
    const failed = await outbox.get(tenantAlpha, "evt-retry");
    expect(failed?.status).toBe("failed");
    expect(failed?.attempt).toBe(1);
    expect(failed?.errorCode).toBe("EVENT_SINK_ERROR");
    expect(failed?.nextAttemptAt).toBe(at(1_000));
    expect(failed?.leaseId).toBeUndefined();
    expect(failed?.leaseExpiresAt).toBeUndefined();

    const early = await flushTenant(publisher, outbox, tenantAlpha);
    expect(early.outcomes).toHaveLength(0);
    expect(early.deferred).toBe(1);
    expect(attempts).toBe(1);

    vi.setSystemTime(new Date(at(1_000)));
    const retry = await flushTenant(publisher, outbox, tenantAlpha);
    expect(attempts).toBe(2);
    expect(retry.outcomes[0]?.status).toBe("published");
    expect(retry.outcomes[0]?.delivered).toBe(1);
    expect(retry.outcomes[0]?.retryScheduled).toBe(false);
    expect((await outbox.get(tenantAlpha, "evt-retry"))?.status).toBe("published");
  });
});

describe("open platform outbox tenant isolation under concurrency", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(startedAt));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("keeps per-tenant sequences monotonic under interleaved appends", async () => {
    const outbox = createOutbox();
    const tenants = [tenantAlpha, tenantBeta, tenantGamma, tenantDelta];
    const perTenant = 25;
    const appends: Promise<OpenPlatformOutboxRecord>[] = [];
    for (let index = 0; index < perTenant; index += 1) {
      for (const tenantId of tenants) {
        appends.push(seed(outbox, tenantId, `evt-${tenantId}-${index}`));
      }
    }

    const appended = await Promise.all(appends);

    expect(appended).toHaveLength(tenants.length * perTenant);
    expect(outbox.size()).toBe(tenants.length * perTenant);
    for (const tenantId of tenants) {
      const snapshot = outbox.snapshot(tenantId);
      expect(snapshot).toHaveLength(perTenant);
      expect(snapshot.every((record) => record.tenantId === tenantId)).toBe(true);
      expect(snapshot.map((record) => record.sequence)).toEqual(
        Array.from({ length: perTenant }, (_value, index) => index + 1),
      );
      expect(snapshot.map((record) => record.resourceId)).toEqual(
        Array.from({ length: perTenant }, (_value, index) =>
          `app-evt-${tenantId}-${index}`,
        ),
      );
      const page = await outbox.list({ tenantId, limit: 500 });
      expect(page.items).toHaveLength(perTenant);
      expect(page.hasMore).toBe(false);
      expect(page.nextSequence).toBe(perTenant);
    }
    expect(tenants.reduce((sum, tenantId) => sum + outbox.snapshot(tenantId).length, 0)).toBe(
      outbox.size(),
    );
  });

  it("settles a shared event identifier inside each tenant only", async () => {
    const outbox = createOutbox();
    const tenants = [tenantAlpha, tenantBeta, tenantGamma, tenantDelta];
    const { sink } = createSink();
    const publisher = createPublisher(outbox, sink);
    await Promise.all(
      tenants.map((tenantId) => seed(outbox, tenantId, "evt-shared")),
    );

    const claims = await Promise.all(
      tenants.map((tenantId, index) =>
        outbox.claim(claimAt(tenantId, "evt-shared", `lease-${index}`, startedAt)),
      ),
    );
    expect(claims.map((result) => result.claimed)).toEqual([true, true, true, true]);
    expect(claims.map((result) => result.record?.leaseId)).toEqual([
      "lease-0",
      "lease-1",
      "lease-2",
      "lease-3",
    ]);

    const flushed = await Promise.all(
      tenants.map((tenantId) => flushTenant(publisher, outbox, tenantId)),
    );
    expect(flushed.map((flush) => flush.deferred)).toEqual([1, 1, 1, 1]);
    expect(
      flushed.every((flush) => flush.outcomes.length === 0),
    ).toBe(true);
    expect(
      tenants.reduce((sum, tenantId) => sum + outbox.snapshot(tenantId).length, 0),
    ).toBe(4);

    const settled = await Promise.all(
      tenants.map((tenantId, index) =>
        outbox.complete({
          tenantId,
          eventId: "evt-shared",
          now: startedAt,
          leaseId: `lease-${index}`,
        }),
      ),
    );
    expect(settled.map((record) => record.status)).toEqual(
      tenants.map(() => "published"),
    );
    expect(settled.map((record) => record.tenantId)).toEqual(tenants);
    expect(settled.map((record) => record.sequence)).toEqual([1, 1, 1, 1]);

    for (const tenantId of tenants) {
      const record = await outbox.get(tenantId, "evt-shared");
      expect(record?.tenantId).toBe(tenantId);
      expect(record?.status).toBe("published");
      expect(record?.sequence).toBe(1);
      expect(outbox.snapshot(tenantId)).toHaveLength(1);
    }
  });

  it("keeps a failing tenant from blocking the other tenants", async () => {
    const outbox = createOutbox();
    const seen: string[] = [];
    const selective: OpenPlatformEventSink = {
      deliver: (event) => {
        seen.push(`${event.tenantId}/${event.eventId}`);
        if (event.tenantId === tenantAlpha) throw new Error("alpha sink down");
        return { delivered: 1 };
      },
    };
    const publisher = createPublisher(outbox, selective);
    await Promise.all(
      [tenantAlpha, tenantBeta, tenantGamma].map((tenantId) =>
        seed(outbox, tenantId, "evt-isolated"),
      ),
    );

    const flushed = await Promise.all(
      [tenantAlpha, tenantBeta, tenantGamma].map((tenantId) =>
        flushTenant(publisher, outbox, tenantId),
      ),
    );

    expect(flushed.map((flush) => flush.outcomes[0]?.status)).toEqual([
      "failed",
      "published",
      "published",
    ]);
    expect(seen).toEqual([
      `${tenantAlpha}/evt-isolated`,
      `${tenantBeta}/evt-isolated`,
      `${tenantGamma}/evt-isolated`,
    ]);
    expect((await outbox.get(tenantAlpha, "evt-isolated"))?.status).toBe("failed");
    expect((await outbox.get(tenantBeta, "evt-isolated"))?.status).toBe("published");
    expect((await outbox.get(tenantGamma, "evt-isolated"))?.status).toBe("published");
  });
});

describe("open platform outbox capacity pruning under concurrency", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(startedAt));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("never prunes an undelivered event while trimming settled ones", async () => {
    const outbox = createOutbox({ maxEventsPerTenant: 2 });
    const { sink } = createSink();
    const publisher = createPublisher(outbox, sink);
    await Promise.all([
      seed(outbox, tenantAlpha, "evt-1"),
      seed(outbox, tenantAlpha, "evt-2"),
      seed(outbox, tenantAlpha, "evt-3"),
      seed(outbox, tenantAlpha, "evt-4"),
    ]);

    await Promise.all([
      publishOnce(publisher, outbox, tenantAlpha, "evt-2"),
      publishOnce(publisher, outbox, tenantAlpha, "evt-4"),
    ]);
    await seed(outbox, tenantAlpha, "evt-5");

    expect(await outbox.get(tenantAlpha, "evt-2")).toBeUndefined();
    const retained = outbox.snapshot(tenantAlpha);
    expect(retained.map((record) => record.sequence)).toEqual([1, 3, 4, 5]);
    expect(retained.map((record) => record.status)).toEqual([
      "pending",
      "pending",
      "published",
      "pending",
    ]);
    expect(retained.every((record) => record.eventId !== "evt-2")).toBe(true);
    expect(retained.filter((record) => record.status === "pending")).toHaveLength(3);
    expect(outbox.size()).toBe(4);
  });

  it("never prunes an event whose delivery lease is still valid", async () => {
    const outbox = createOutbox({ maxEventsPerTenant: 2 });
    const { sink } = createSink();
    const publisher = createPublisher(outbox, sink);
    await Promise.all([
      seed(outbox, tenantAlpha, "evt-1"),
      seed(outbox, tenantAlpha, "evt-2"),
      seed(outbox, tenantAlpha, "evt-3"),
      seed(outbox, tenantAlpha, "evt-4"),
    ]);
    expect(await publishOnce(publisher, outbox, tenantAlpha, "evt-4")).toBe(1);
    expect(
      (
        await outbox.claim(
          claimAt(tenantAlpha, "evt-3", "lease-inflight", startedAt),
        )
      ).claimed,
    ).toBe(true);
    await seed(outbox, tenantAlpha, "evt-5");
    expect((await outbox.get(tenantAlpha, "evt-4"))?.status).toBe("published");
    await seed(outbox, tenantAlpha, "evt-6");

    expect(await outbox.get(tenantAlpha, "evt-4")).toBeUndefined();
    const retained = outbox.snapshot(tenantAlpha);
    expect(retained.map((record) => record.eventId)).toEqual([
      "evt-1",
      "evt-2",
      "evt-3",
      "evt-5",
      "evt-6",
    ]);
    const inflight = await outbox.get(tenantAlpha, "evt-3");
    expect(inflight?.status).toBe("delivering");
    expect(inflight?.leaseId).toBe("lease-inflight");
    expect(inflight?.leaseExpiresAt).toBe(at(leaseMs));
    expect(
      retained.filter(
        (record) => record.status !== "published" && record.status !== "dead_lettered",
      ),
    ).toHaveLength(5);
  });

  it("prunes only inside the tenant that outgrew its window", async () => {
    const outbox = createOutbox({ maxEventsPerTenant: 2 });
    const { sink } = createSink();
    const publisher = createPublisher(outbox, sink);
    await Promise.all([
      seed(outbox, tenantAlpha, "evt-alpha-1"),
      seed(outbox, tenantAlpha, "evt-alpha-2"),
      seed(outbox, tenantAlpha, "evt-alpha-3"),
      seed(outbox, tenantAlpha, "evt-alpha-4"),
      seed(outbox, tenantBeta, "evt-beta-1"),
      seed(outbox, tenantBeta, "evt-beta-2"),
    ]);
    await Promise.all([
      publishOnce(publisher, outbox, tenantAlpha, "evt-alpha-1"),
      publishOnce(publisher, outbox, tenantAlpha, "evt-alpha-3"),
    ]);
    await seed(outbox, tenantAlpha, "evt-alpha-5");

    expect(await outbox.get(tenantAlpha, "evt-alpha-1")).toBeUndefined();
    expect(outbox.snapshot(tenantAlpha).map((record) => record.sequence)).toEqual([
      2, 4, 5,
    ]);
    const beta = outbox.snapshot(tenantBeta);
    expect(beta.map((record) => record.sequence)).toEqual([1, 2]);
    expect(beta.every((record) => record.status === "pending")).toBe(true);
    expect(await outbox.get(tenantBeta, "evt-beta-1")).toBeDefined();
    expect(outbox.size()).toBe(5);
  });
});

describe("open platform relay leader lease contention", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(startedAt));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("keeps a single holder per lease key under concurrent acquires", async () => {
    const lease = createInMemoryOpenPlatformRelayLease({ clock: () => new Date() });
    const owners = [
      "relay_owner_a",
      "relay_owner_b",
      "relay_owner_c",
      "relay_owner_d",
      "relay_owner_e",
      "relay_owner_f",
    ];

    const states = await Promise.all(
      owners.map((ownerId) =>
        lease.acquire({
          key: OPEN_PLATFORM_EVENT_RELAY_LEASE_KEY,
          ownerId,
          now: startedAt,
          ttlMs: leaseMs,
        }),
      ),
    );

    const held = states.filter((state) => state.held);
    expect(held).toHaveLength(1);
    const winnerIndex = states.findIndex((state) => state.held);
    const winner = owners[winnerIndex];
    expect(
      states
        .filter((state) => state.held !== true)
        .every((state) => state.ownerId === winner),
    ).toBe(true);
    expect(states.every((state) => state.key === OPEN_PLATFORM_EVENT_RELAY_LEASE_KEY)).toBe(
      true,
    );
    expect(held[0].expiresAt).toBe(at(leaseMs));
    expect(await lease.holder(OPEN_PLATFORM_EVENT_RELAY_LEASE_KEY)).toMatchObject({
      key: OPEN_PLATFORM_EVENT_RELAY_LEASE_KEY,
      ownerId: winner,
      expiresAt: at(leaseMs),
    });
  });

  it("rejects a release from a non-owner and reopens the key afterwards", async () => {
    const lease = createInMemoryOpenPlatformRelayLease({ clock: () => new Date() });
    const request = (ownerId: string, now = startedAt) => ({
      key: OPEN_PLATFORM_EVENT_RELAY_LEASE_KEY,
      ownerId,
      now,
      ttlMs: leaseMs,
    });

    expect((await lease.acquire(request("relay_owner_a"))).held).toBe(true);
    const rejected = await Promise.all([
      lease.release(request("relay_owner_b")),
      lease.release(request("relay_owner_c")),
      lease.renew(request("relay_owner_d", at(1_000))),
    ]);
    expect(rejected.slice(0, 2)).toEqual([false, false]);
    expect(rejected[2].held).toBe(false);
    expect(rejected[2].ownerId).toBe("relay_owner_a");
    expect((await lease.holder(OPEN_PLATFORM_EVENT_RELAY_LEASE_KEY))?.ownerId).toBe(
      "relay_owner_a",
    );

    expect(await lease.release(request("relay_owner_a"))).toBe(true);
    expect(await lease.holder(OPEN_PLATFORM_EVENT_RELAY_LEASE_KEY)).toBeUndefined();
    expect((await lease.acquire(request("relay_owner_b"))).held).toBe(true);
    expect((await lease.acquire(request("relay_owner_a"))).held).toBe(false);
  });

  it("lets exactly one instance take over an expired leader lease", async () => {
    const lease = createInMemoryOpenPlatformRelayLease({ clock: () => new Date() });
    const stuck = await lease.acquire({
      key: OPEN_PLATFORM_EVENT_RELAY_LEASE_KEY,
      ownerId: "relay_owner_stuck",
      now: at(-leaseMs),
      ttlMs: leaseMs,
    });
    expect(stuck.held).toBe(true);

    const contenders = ["relay_owner_b", "relay_owner_c", "relay_owner_d"];
    const takeovers = await Promise.all(
      contenders.map((ownerId) =>
        lease.acquire({
          key: OPEN_PLATFORM_EVENT_RELAY_LEASE_KEY,
          ownerId,
          now: startedAt,
          ttlMs: leaseMs,
        }),
      ),
    );

    const winners = takeovers.filter((state) => state.held);
    expect(winners).toHaveLength(1);
    expect(contenders).toContain(winners[0].ownerId);
    expect(
      takeovers
        .filter((state) => state.held !== true)
        .every((state) => state.ownerId === winners[0].ownerId),
    ).toBe(true);
    expect((await lease.holder(OPEN_PLATFORM_EVENT_RELAY_LEASE_KEY))?.ownerId).toBe(
      winners[0].ownerId,
    );
  });

  it("drains a backlog exactly once across four relay instances", async () => {
    const lease = createInMemoryOpenPlatformRelayLease({ clock: () => new Date() });
    const fleet = createRelayFleet(
      lease,
      ["relay_owner_a", "relay_owner_b", "relay_owner_c", "relay_owner_d"],
      [tenantAlpha, tenantBeta],
    );
    await Promise.all(
      [tenantAlpha, tenantBeta, tenantAlpha, tenantBeta, tenantAlpha, tenantBeta].map(
        (tenantId, index) => seed(fleet.outbox, tenantId, `evt-backlog-${index}`),
      ),
    );

    const ticks = await Promise.all(
      fleet.relays.map((relay) => relay.runOnce()),
    );

    const totals = ticks.reduce(
      (accumulator, tick) => ({
        claimed: accumulator.claimed + tick.claimed,
        published: accumulator.published + tick.published,
        skipped: accumulator.skipped + tick.skipped,
        errors: accumulator.errors + tick.errors,
      }),
      { claimed: 0, published: 0, skipped: 0, errors: 0 },
    );
    expect(totals).toEqual({ claimed: 6, published: 6, skipped: 3, errors: 0 });
    expect(fleet.delivered).toHaveLength(6);
    expect(new Set(fleet.delivered.map((record) => record.eventId)).size).toBe(6);
    const snapshots = fleet.relays.map((relay) => relay.snapshot());
    expect(snapshots.filter((snapshot) => snapshot.leader)).toHaveLength(1);
    expect(
      snapshots.every(
        (snapshot) => snapshot.leaseKey === OPEN_PLATFORM_EVENT_RELAY_LEASE_KEY,
      ),
    ).toBe(true);
    expect(snapshots.reduce((sum, snapshot) => sum + snapshot.claimed, 0)).toBe(6);
    expect(snapshots.reduce((sum, snapshot) => sum + snapshot.delivered, 0)).toBe(6);
    expect(snapshots.reduce((sum, snapshot) => sum + snapshot.skipped, 0)).toBe(3);
    expect(snapshots.reduce((sum, snapshot) => sum + snapshot.errors, 0)).toBe(0);
    expect(await lease.holder(OPEN_PLATFORM_EVENT_RELAY_LEASE_KEY)).toBeUndefined();
    for (const tenantId of [tenantAlpha, tenantBeta]) {
      const records = fleet.outbox.snapshot(tenantId);
      expect(records).toHaveLength(3);
      expect(records.every((record) => record.status === "published")).toBe(true);
    }
  });

  it("lets a standby instance continue after the leader releases", async () => {
    const lease = createInMemoryOpenPlatformRelayLease({ clock: () => new Date() });
    const fleet = createRelayFleet(lease, ["relay_owner_a", "relay_owner_b"], [
      tenantAlpha,
    ]);
    await seed(fleet.outbox, tenantAlpha, "evt-handover-1");
    await seed(fleet.outbox, tenantAlpha, "evt-handover-2");

    const drained = await Promise.all(
      fleet.relays.map((relay) => relay.runOnce()),
    );
    expect(
      drained.map((tick) => tick.published).reduce((sum, value) => sum + value, 0),
    ).toBe(2);
    expect(fleet.delivered).toHaveLength(2);
    expect(
      fleet.relays
        .map((relay) => relay.snapshot().delivered)
        .reduce((sum, value) => sum + value, 0),
    ).toBe(2);

    await seed(fleet.outbox, tenantAlpha, "evt-handover-3");
    const next = await Promise.all(fleet.relays.map((relay) => relay.runOnce()));
    expect(
      next.map((tick) => tick.published).reduce((sum, value) => sum + value, 0),
    ).toBe(1);
    expect(fleet.delivered.map((record) => record.eventId)).toEqual([
      "evt-handover-1",
      "evt-handover-2",
      "evt-handover-3",
    ]);
    expect(
      fleet.relays
        .map((relay) => relay.snapshot().delivered)
        .reduce((sum, value) => sum + value, 0),
    ).toBe(3);
    expect(
      fleet.relays
        .map((relay) => relay.snapshot().skipped)
        .reduce((sum, value) => sum + value, 0),
    ).toBe(2);
  });
});
