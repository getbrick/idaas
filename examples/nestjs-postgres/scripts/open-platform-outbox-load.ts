import { randomUUID } from "node:crypto";
import type { Pool } from "pg";
import {
  InMemoryOpenPlatformOutbox,
  OPEN_PLATFORM_DOMAIN_EVENT_OUTBOX_STATUSES,
  OpenPlatformEventPublisher,
  OpenPlatformPersistence,
  type OpenPlatformDomainEventStatus,
  type OpenPlatformEventRelay,
  type OpenPlatformEventRelaySnapshot,
  type OpenPlatformEventSink,
  type OpenPlatformOutboxClaimRequest,
  type OpenPlatformOutboxClaimResult,
  type OpenPlatformOutboxCompleteRequest,
  type OpenPlatformOutboxFailRequest,
  type OpenPlatformOutboxPage,
  type OpenPlatformOutboxPort,
  type OpenPlatformOutboxRecord,
  createOpenPlatformEventRelay,
} from "@getbrick/idaas-control-plane/open-platform";
import {
  applyOpenPlatformSmokeMigration,
  createOpenPlatformSmokeAdapter,
  createOpenPlatformSmokePool,
  probeOpenPlatformSmokeDatabase,
} from "../src/open-platform-smoke.js";

const TOOL = "open-platform-outbox-load";
const APPEND_CONCURRENCY = 32;
const STALL_POLL_MS = 50;

type LatencySummary = {
  readonly count: number;
  readonly p50: number;
  readonly p95: number;
  readonly max: number;
};

type BacklogSummary = {
  readonly pending: number;
  readonly delivering: number;
  readonly failed: number;
  readonly published: number;
  readonly dead_lettered: number;
  readonly drained: boolean;
};

type LoadConfig = {
  readonly tenants: number;
  readonly events: number;
  readonly flushers: number;
  readonly batchSize: number;
  readonly failRate: number;
  readonly latencyMs: number;
  readonly maxTicks: number;
  readonly drainTimeoutMs: number;
  readonly dryRun: boolean;
  readonly databaseUrl: string | undefined;
  readonly tenantPrefix: string;
};

type ClaimCounters = {
  granted: number;
  rejected: number;
  completes: number;
  fails: number;
  latencies: number[];
};

type SinkCounters = {
  attempts: number;
  succeeded: number;
  failed: number;
  deadLettered: number;
  duplicates: number;
  duplicateEventIds: string[];
  latencies: number[];
  endToEnd: number[];
  inFlight: Set<string>;
  settled: Set<string>;
};

type TenantRuntime = {
  readonly tenantId: string;
  readonly outbox: OpenPlatformOutboxPort;
  readonly publisher: OpenPlatformEventPublisher;
};

type FlusherRuntime = {
  readonly name: string;
  readonly tenants: readonly TenantRuntime[];
  readonly relays: readonly OpenPlatformEventRelay[];
};

const usage = [
  `Usage: pnpm --filter @getbrick/example-nestjs-postgres load:open-platform -- [options]`,
  "",
  "Options:",
  "  --tenants <n>          tenants to write and flush (default 4)",
  "  --events <n>           events per tenant (default 50)",
  "  --flushers <n>         concurrent delivery loops (default 4)",
  "  --batch-size <n>       events claimed per tenant per tick (default 25)",
  "  --fail-rate <ratio>    share of deliveries that throw, 0..1 (default 0)",
  "  --latency-ms <n>       sink latency per delivery (default 0)",
  "  --max-ticks <n>        drain rounds per flusher (default 500)",
  "  --drain-timeout-ms <n> drain budget per flusher (default 60000)",
  "  --tenant-prefix <text> tenant id prefix (default load)",
  "  --database-url <url>   override DATABASE_URL",
  "  --dry-run              in-memory outbox only, never connect to PostgreSQL",
  "  --help                 print this message",
].join("\n");

function emit(payload: unknown): void {
  process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
}

function fail(code: string, message: string, hint?: string): number {
  emit({ ok: false, tool: TOOL, error: { code, message, ...(hint === undefined ? {} : { hint }) } });
  return 2;
}

function parseInteger(flag: string, raw: string | undefined, min: number, max: number): number {
  const value = Number(raw);
  if (raw === undefined || !Number.isSafeInteger(value) || value < min || value > max) {
    throw new Error(`${flag} expects an integer between ${min} and ${max}`);
  }
  return value;
}

function parseConfig(argv: readonly string[]): LoadConfig {
  const defaults: LoadConfig = {
    tenants: 4,
    events: 50,
    flushers: 4,
    batchSize: 25,
    failRate: 0,
    latencyMs: 0,
    maxTicks: 500,
    drainTimeoutMs: 60_000,
    dryRun: false,
    databaseUrl: undefined,
    tenantPrefix: "load",
  };
  let config = defaults;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === undefined) continue;
    const separator = argument.indexOf("=");
    const flag = separator === -1 ? argument : argument.slice(0, separator);
    const inline = separator === -1 ? undefined : argument.slice(separator + 1);
    const take = (): string | undefined => {
      if (inline !== undefined) return inline;
      index += 1;
      return argv[index];
    };
    switch (flag) {
      case "--tenants":
        config = { ...config, tenants: parseInteger(flag, take(), 1, 500) };
        break;
      case "--events":
        config = { ...config, events: parseInteger(flag, take(), 1, 100_000) };
        break;
      case "--flushers":
        config = { ...config, flushers: parseInteger(flag, take(), 1, 64) };
        break;
      case "--batch-size":
        config = { ...config, batchSize: parseInteger(flag, take(), 1, 500) };
        break;
      case "--fail-rate": {
        const raw = take();
        const value = Number(raw);
        if (raw === undefined || !Number.isFinite(value) || value < 0 || value > 1) {
          throw new Error(`${flag} expects a ratio between 0 and 1`);
        }
        config = { ...config, failRate: value };
        break;
      }
      case "--latency-ms":
        config = { ...config, latencyMs: parseInteger(flag, take(), 0, 60_000) };
        break;
      case "--max-ticks":
        config = { ...config, maxTicks: parseInteger(flag, take(), 1, 1_000_000) };
        break;
      case "--drain-timeout-ms":
        config = { ...config, drainTimeoutMs: parseInteger(flag, take(), 0, 3_600_000) };
        break;
      case "--tenant-prefix": {
        const raw = take();
        if (raw === undefined || !/^[a-z0-9][a-z0-9-]{0,40}$/u.test(raw)) {
          throw new Error(`${flag} expects a lowercase identifier prefix`);
        }
        config = { ...config, tenantPrefix: raw };
        break;
      }
      case "--database-url":
        config = { ...config, databaseUrl: take() };
        break;
      case "--dry-run":
        config = { ...config, dryRun: true };
        break;
      default:
        throw new Error(`unknown argument ${flag}`);
    }
  }
  if (!/^[a-z0-9][a-z0-9-]{0,40}$/u.test(config.tenantPrefix)) {
    throw new Error("--tenant-prefix expects a lowercase identifier prefix");
  }
  return config;
}

function nowMs(): number {
  return Date.now();
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

async function runBounded(
  items: readonly unknown[],
  limit: number,
  worker: (item: unknown, index: number) => Promise<void>,
): Promise<void> {
  let cursor = 0;
  const size = Math.max(1, Math.min(limit, items.length));
  const runners = Array.from({ length: size }, async () => {
    for (;;) {
      const index = cursor;
      cursor += 1;
      if (index >= items.length) return;
      await worker(items[index], index);
    }
  });
  await Promise.all(runners);
}

function percentiles(values: readonly number[]): LatencySummary {
  if (values.length === 0) return { count: 0, p50: 0, p95: 0, max: 0 };
  const sorted = [...values].sort((left, right) => left - right);
  const at = (quantile: number): number => {
    const position = Math.ceil(quantile * sorted.length) - 1;
    return sorted[Math.min(sorted.length - 1, Math.max(0, position))] ?? 0;
  };
  const round = (value: number): number => Math.round(value * 1_000) / 1_000;
  return {
    count: sorted.length,
    p50: round(at(0.5)),
    p95: round(at(0.95)),
    max: round(sorted[sorted.length - 1] ?? 0),
  };
}

function rate(count: number, durationMs: number): number {
  if (durationMs <= 0) return 0;
  return Math.round((count / (durationMs / 1_000)) * 1_000) / 1_000;
}

function instrumentOutbox(
  inner: OpenPlatformOutboxPort,
  counters: ClaimCounters,
): OpenPlatformOutboxPort {
  const base = inner.claim;
  const complete = inner.complete;
  const fail = inner.fail;
  return {
    productionReady: inner.productionReady,
    readiness: inner.readiness,
    ...(inner.isReady === undefined ? {} : { isReady: () => inner.isReady?.() ?? false }),
    append: (event) => inner.append(event),
    get: (tenantId, eventId) => inner.get(tenantId, eventId),
    list: (query) => inner.list(query),
    ...(base === undefined
      ? {}
      : {
          claim: async (
            request: OpenPlatformOutboxClaimRequest,
          ): Promise<OpenPlatformOutboxClaimResult> => {
            const startedAt = nowMs();
            const result = await base.call(inner, request);
            counters.latencies.push(nowMs() - startedAt);
            if (result.claimed === true) counters.granted += 1;
            else counters.rejected += 1;
            return result;
          },
        }),
    ...(complete === undefined
      ? {}
      : {
          complete: async (request: OpenPlatformOutboxCompleteRequest) => {
            counters.completes += 1;
            return complete.call(inner, request);
          },
        }),
    ...(fail === undefined
      ? {}
      : {
          fail: async (request: OpenPlatformOutboxFailRequest) => {
            counters.fails += 1;
            return fail.call(inner, request);
          },
        }),
  };
}

function createLoadSink(
  counters: SinkCounters,
  config: LoadConfig,
  appendedAt: Map<string, number>,
): OpenPlatformEventSink {
  return {
    deliver: async (event) => {
      const startedAt = nowMs();
      counters.attempts += 1;
      if (counters.inFlight.has(event.eventId) || counters.settled.has(event.eventId)) {
        counters.duplicates += 1;
        if (counters.duplicateEventIds.length < 20) {
          counters.duplicateEventIds.push(event.eventId);
        }
      }
      counters.inFlight.add(event.eventId);
      if (config.latencyMs > 0) await sleep(config.latencyMs);
      const appended = appendedAt.get(event.eventId);
      if (appended !== undefined) counters.endToEnd.push(nowMs() - appended);
      const every = config.failRate > 0 ? Math.max(1, Math.round(1 / config.failRate)) : 0;
      if (every > 0 && counters.attempts % every === 0) {
        counters.failed += 1;
        counters.inFlight.delete(event.eventId);
        counters.latencies.push(nowMs() - startedAt);
        throw new Error("open platform load sink failure");
      }
      counters.succeeded += 1;
      counters.inFlight.delete(event.eventId);
      counters.settled.add(event.eventId);
      counters.latencies.push(nowMs() - startedAt);
      return { delivered: 1 };
    },
  };
}

async function probeReadiness(
  outbox: OpenPlatformOutboxPort,
): Promise<{ readonly storage: string; readonly distributed: boolean; readonly ready: boolean }> {
  const readiness = outbox.readiness;
  let ready = false;
  try {
    if (readiness !== undefined && typeof readiness.ready === "function") {
      ready = (await readiness.ready()) === true;
    } else if (typeof outbox.isReady === "function") {
      ready = (await outbox.isReady()) === true;
    }
  } catch {
    ready = false;
  }
  return {
    storage: readiness?.storage ?? "unknown",
    distributed: readiness?.distributed ?? false,
    ready,
  };
}

async function countByStatus(
  outbox: OpenPlatformOutboxPort,
  tenantId: string,
): Promise<Record<OpenPlatformDomainEventStatus, number>> {
  const counts: Record<OpenPlatformDomainEventStatus, number> = {
    pending: 0,
    delivering: 0,
    published: 0,
    failed: 0,
    dead_lettered: 0,
  };
  for (const status of OPEN_PLATFORM_DOMAIN_EVENT_OUTBOX_STATUSES) {
    let cursor = 0;
    for (let guard = 0; guard < 10_000; guard += 1) {
      const page: OpenPlatformOutboxPage = await outbox.list({
        tenantId,
        status,
        fromSequence: cursor,
        limit: 500,
      });
      counts[status] += page.items.length;
      if (page.hasMore !== true || page.items.length === 0) break;
      cursor = page.nextSequence ?? cursor + page.items.length;
    }
  }
  return counts;
}

async function soonestRetryDelayMs(
  outbox: OpenPlatformOutboxPort,
  tenantId: string,
): Promise<number | undefined> {
  let soonest: number | undefined;
  let cursor = 0;
  for (let guard = 0; guard < 1_000; guard += 1) {
    const page: OpenPlatformOutboxPage = await outbox.list({
      tenantId,
      status: "failed",
      fromSequence: cursor,
      limit: 500,
    });
    for (const record of page.items) {
      if (record.nextAttemptAt === undefined) continue;
      const delay = Date.parse(record.nextAttemptAt) - nowMs();
      soonest = soonest === undefined ? delay : Math.min(soonest, delay);
    }
    if (page.hasMore !== true || page.items.length === 0) break;
    cursor = page.nextSequence ?? cursor + page.items.length;
  }
  return soonest;
}

async function nextWakeupMs(tenants: readonly TenantRuntime[]): Promise<number | undefined> {
  let outstanding = 0;
  let soonest: number | undefined;
  for (const tenant of tenants) {
    const counts = await countByStatus(tenant.outbox, tenant.tenantId);
    outstanding += counts.pending + counts.delivering + counts.failed;
    if (counts.failed > 0) {
      const delay = await soonestRetryDelayMs(tenant.outbox, tenant.tenantId);
      if (delay !== undefined) soonest = soonest === undefined ? delay : Math.min(soonest, delay);
    }
  }
  if (outstanding === 0) return undefined;
  return Math.max(soonest ?? STALL_POLL_MS, 1);
}

async function drain(
  flusher: FlusherRuntime,
  config: LoadConfig,
  budgetDeadlineMs: number,
): Promise<number> {
  let rounds = 0;
  while (rounds < config.maxTicks) {
    rounds += 1;
    let claimed = 0;
    for (const relay of flusher.relays) {
      const tick = await relay.runOnce();
      claimed += tick.claimed;
    }
    if (claimed > 0) continue;
    const wakeup = await nextWakeupMs(flusher.tenants);
    if (wakeup === undefined) return rounds;
    const remaining = budgetDeadlineMs - nowMs();
    if (remaining <= 0) return rounds;
    await sleep(Math.min(wakeup, remaining));
  }
  return rounds;
}

function aggregateSnapshots(
  snapshots: readonly OpenPlatformEventRelaySnapshot[],
): Record<string, number> {
  const totals: Record<string, number> = {};
  for (const snapshot of snapshots) {
    for (const [key, value] of Object.entries(snapshot)) {
      if (typeof value !== "number") continue;
      totals[key] = (totals[key] ?? 0) + value;
    }
  }
  return totals;
}

async function seedTenants(pool: Pool, tenantIds: readonly string[]): Promise<void> {
  const timestamp = new Date().toISOString();
  for (const tenantId of tenantIds) {
    await pool.query(
      `INSERT INTO gb_open_tenant (id, tenant_id, kind, name, status, version, etag, created_at, updated_at) VALUES ($1, $2, 'tenant', $3, 'published', 1, $4, $5, $5) ON CONFLICT (tenant_id) DO NOTHING`,
      [
        `tenant_${tenantId}`,
        tenantId,
        `Load test tenant ${tenantId}`,
        OpenPlatformPersistence.createEtag("tenant", `tenant_${tenantId}`, 1),
        timestamp,
      ],
    );
  }
}

async function run(): Promise<number> {
  const argv = process.argv.slice(2).filter((argument) => argument !== "--");
  if (argv.includes("--help") || argv.includes("-h")) {
    process.stdout.write(`${usage}\n`);
    return 0;
  }
  let config: LoadConfig;
  try {
    config = parseConfig(argv);
  } catch (error) {
    return fail("INVALID_ARGUMENT", errorMessage(error), "run with --help for usage");
  }

  const runId = randomUUID().replace(/-/gu, "").slice(0, 12);
  const tenantIds = Array.from(
    { length: config.tenants },
    (_value, index) => `${config.tenantPrefix}-${runId}-${index + 1}`,
  );
  const mode: "memory" | "postgres" = config.dryRun ? "memory" : "postgres";
  const claimCounters: ClaimCounters = {
    granted: 0,
    rejected: 0,
    completes: 0,
    fails: 0,
    latencies: [],
  };
  const sinkCounters: SinkCounters = {
    attempts: 0,
    succeeded: 0,
    failed: 0,
    deadLettered: 0,
    duplicates: 0,
    duplicateEventIds: [],
    latencies: [],
    endToEnd: [],
    inFlight: new Set<string>(),
    settled: new Set<string>(),
  };
  const appendedAt = new Map<string, number>();
  const appendLatencies: number[] = [];
  const warnings: string[] = [];

  let pool: Pool | undefined;
  const startedAt = new Date().toISOString();
  const runStartedAtMs = nowMs();

  try {
    if (pool === undefined && mode === "postgres") {
      pool = createOpenPlatformSmokePool(
        config.databaseUrl ?? process.env["DATABASE_URL"],
      );
      const reachable = await probeOpenPlatformSmokeDatabase(pool);
      if (!reachable) {
        return fail(
          "DATABASE_UNAVAILABLE",
          "PostgreSQL is not reachable with the configured connection",
          "start the example database with `pnpm --filter @getbrick/example-nestjs-postgres db:up`, pass --database-url, or use --dry-run for the in-memory outbox",
        );
      }
      await applyOpenPlatformSmokeMigration(pool);
      await seedTenants(pool, tenantIds);
    }

    const sink = createLoadSink(sinkCounters, config, appendedAt);
    const tenants: TenantRuntime[] = tenantIds.map((tenantId) => {
      const inner: OpenPlatformOutboxPort =
        mode === "memory"
          ? new InMemoryOpenPlatformOutbox({
              clock: () => new Date(),
              maxEventsPerTenant: 1_000_000,
            })
          : new OpenPlatformPersistence.SqlDomainEventOutboxRepository({
              adapter: createOpenPlatformSmokeAdapter(pool as Pool),
              mode: "fixed",
              tenantId,
              requireTransactions: true,
            });
      const outbox = instrumentOutbox(inner, claimCounters);
      return {
        tenantId,
        outbox,
        publisher: new OpenPlatformEventPublisher({ outbox, sink }),
      };
    });

    const readiness = await probeReadiness(tenants[0].outbox);
    if (readiness.ready !== true) {
      warnings.push(
        "outbox readiness reported false; confirm the database role is a non-superuser without BYPASSRLS and that the open-platform migrations are applied",
      );
    }

    const appendStartedAtMs = nowMs();
    let appended = 0;
    let appendErrors = 0;
    const appendErrorSamples: string[] = [];
    const events: unknown[] = [];
    for (const tenant of tenants) {
      for (let index = 0; index < config.events; index += 1) {
        events.push({ tenantId: tenant.tenantId, index });
      }
    }
    await runBounded(events, APPEND_CONCURRENCY, async (item) => {
      const target = item as { tenantId: string; index: number };
      const tenant = tenants.find((candidate) => candidate.tenantId === target.tenantId);
      if (tenant === undefined) return;
      const eventId = `load_${target.tenantId}_${target.index + 1}`;
      const eventStartedAtMs = nowMs();
      try {
        await tenant.outbox.append({
          eventId,
          tenantId: target.tenantId,
          eventType: "application.created",
          resourceType: "application",
          resourceId: `app_load_${target.index + 1}`,
          resourceVersion: 1,
          resourceStatus: "draft",
          occurredAt: new Date().toISOString(),
          data: { source: TOOL, run: runId, index: target.index + 1 },
        });
        appended += 1;
        appendedAt.set(eventId, nowMs());
      } catch (error) {
        appendErrors += 1;
        if (appendErrorSamples.length < 3) appendErrorSamples.push(errorMessage(error));
      }
      appendLatencies.push(nowMs() - eventStartedAtMs);
    });
    const appendDurationMs = Math.max(nowMs() - appendStartedAtMs, 1);

    const flushers: FlusherRuntime[] = Array.from(
      { length: config.flushers },
      (_value, flusherIndex) => ({
        name: `flusher-${flusherIndex + 1}`,
        tenants,
        relays: tenants.map((tenant) =>
          createOpenPlatformEventRelay({
            publisher: tenant.publisher,
            outbox: tenant.outbox,
            tenantIds: [tenant.tenantId],
            mode: "test",
            enabled: true,
            intervalMs: 1_000,
            batchSize: config.batchSize,
          }),
        ),
      }),
    );

    const drainStartedAtMs = nowMs();
    const drainDeadlineMs = drainStartedAtMs + config.drainTimeoutMs;
    await Promise.all(
      flushers.map((flusher) => drain(flusher, config, drainDeadlineMs)),
    );
    const drainDurationMs = Math.max(nowMs() - drainStartedAtMs, 1);

    const snapshots: OpenPlatformEventRelaySnapshot[] = flushers.flatMap((flusher) =>
      flusher.relays.map((relay) => relay.snapshot()),
    );

    const totals: Record<OpenPlatformDomainEventStatus, number> = {
      pending: 0,
      delivering: 0,
      published: 0,
      failed: 0,
      dead_lettered: 0,
    };
    for (const tenant of tenants) {
      const counts = await countByStatus(tenant.outbox, tenant.tenantId);
      for (const status of OPEN_PLATFORM_DOMAIN_EVENT_OUTBOX_STATUSES) {
        totals[status] += counts[status];
      }
    }
    const backlog: BacklogSummary = {
      pending: totals.pending,
      delivering: totals.delivering,
      failed: totals.failed,
      published: totals.published,
      dead_lettered: totals.dead_lettered,
      drained: totals.pending + totals.delivering + totals.failed === 0,
    };
    if (!backlog.drained) {
      warnings.push(
        "the backlog was not fully drained; raise --max-ticks or --drain-timeout-ms, or lower --fail-rate",
      );
    }
    if (appendErrors > 0) {
      warnings.push(
        `${appendErrors} of ${tenants.length * config.events} outbox appends failed; first error: ${appendErrorSamples[0] ?? "unknown"}`,
      );
    }

    const durationMs = Math.max(nowMs() - runStartedAtMs, 1);
    const total = tenants.length * config.events;
    const healthy = sinkCounters.duplicates === 0 && appendErrors === 0;
    const summary = {
      ok: healthy,
      tool: TOOL,
      mode,
      startedAt,
      finishedAt: new Date().toISOString(),
      config: {
        tenants: config.tenants,
        eventsPerTenant: config.events,
        flushers: config.flushers,
        batchSize: config.batchSize,
        failRate: config.failRate,
        latencyMs: config.latencyMs,
        maxTicks: config.maxTicks,
        dryRun: config.dryRun,
      },
      events: {
        total,
        appended,
        appendErrors,
        appendErrorSamples,
      },
      claims: {
        granted: claimCounters.granted,
        rejected: claimCounters.rejected,
        completes: claimCounters.completes,
        fails: claimCounters.fails,
      },
      deliveries: {
        attempts: sinkCounters.attempts,
        succeeded: sinkCounters.succeeded,
        failed: sinkCounters.failed,
        deadLettered: sinkCounters.deadLettered,
        duplicates: sinkCounters.duplicates,
        duplicateEventIds: sinkCounters.duplicateEventIds,
      },
      backlog,
      throughput: {
        durationMs,
        appendDurationMs,
        drainDurationMs,
        eventsPerSecond: rate(total, durationMs),
        appendsPerSecond: rate(appended, appendDurationMs),
        claimsPerSecond: rate(claimCounters.granted, drainDurationMs),
        deliveriesPerSecond: rate(sinkCounters.succeeded, drainDurationMs),
      },
      latencyMs: {
        append: percentiles(appendLatencies),
        claim: percentiles(claimCounters.latencies),
        deliver: percentiles(sinkCounters.latencies),
        endToEnd: percentiles(sinkCounters.endToEnd),
      },
      relay: {
        instances: snapshots.length,
        aggregate: aggregateSnapshots(snapshots),
        snapshots,
      },
      readiness,
      warnings,
    };
    emit(summary);
    return healthy ? 0 : 1;
  } catch (error) {
    return fail("LOAD_FAILED", errorMessage(error));
  } finally {
    if (pool !== undefined) await pool.end().catch(() => undefined);
  }
}

function errorMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  if (/(?:postgres(?:ql)?:\/\/|password|secret|token)/iu.test(message)) {
    return "open platform outbox load failed";
  }
  const single = message.replace(/[\u0000-\u001f\u007f]/gu, " ").trim();
  return single.length === 0 ? "open platform outbox load failed" : single.slice(0, 256);
}

process.exitCode = await run();
