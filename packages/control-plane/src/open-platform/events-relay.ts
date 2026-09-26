import { randomUUID } from "node:crypto";
import {
  configurationError,
  isOpenPlatformDomainError,
  validationError,
} from "./errors.js";
import {
  createOpenPlatformOutboxTenantResolver,
  flushOpenPlatformOutboxTenants,
  listOpenPlatformOutboxTenants,
  type OpenPlatformEventPublisherPort,
  type OpenPlatformOutboxPort,
  type OpenPlatformOutboxTenantBatch,
  type OpenPlatformOutboxTenantResolver,
} from "./events.js";
import { normalizeIdentifier } from "./validation.js";
import type {
  MaybePromise,
  OpenPlatformDependencyReadiness,
  OpenPlatformRuntimeMode,
} from "./types.js";

export const OPEN_PLATFORM_EVENT_RELAY_DEFAULT_INTERVAL_MS = 1_000;

export const OPEN_PLATFORM_EVENT_RELAY_MIN_INTERVAL_MS = 10;

export const OPEN_PLATFORM_EVENT_RELAY_MAX_INTERVAL_MS = 3_600_000;

export const OPEN_PLATFORM_EVENT_RELAY_DEFAULT_BATCH_SIZE = 50;

export const OPEN_PLATFORM_EVENT_RELAY_MAX_BATCH_SIZE = 500;

export const OPEN_PLATFORM_EVENT_RELAY_DEFAULT_TENANT_PAGE_SIZE = 100;

export const OPEN_PLATFORM_EVENT_RELAY_MAX_TENANTS_PER_TICK = 10_000;

export const OPEN_PLATFORM_EVENT_RELAY_MAX_JITTER_MS = 600_000;

export const OPEN_PLATFORM_EVENT_RELAY_LEASE_KEY =
  "getbrick:open-platform:outbox-relay";

export const OPEN_PLATFORM_EVENT_RELAY_MIN_LEASE_KEY_LENGTH = 8;

export const OPEN_PLATFORM_EVENT_RELAY_MIN_LEASE_TTL_MS = 1_000;

export const OPEN_PLATFORM_EVENT_RELAY_MAX_LEASE_TTL_MS = 3_600_000;

export const OPEN_PLATFORM_EVENT_RELAY_DEFAULT_LEASE_TTL_MS = 30_000;

export type OpenPlatformEventRelayErrorScope =
  | "start"
  | "tick"
  | "lease"
  | "tenants"
  | "tenant";

export interface OpenPlatformEventRelayError {
  readonly scope: OpenPlatformEventRelayErrorScope;
  readonly tenantId?: string;
  readonly code: string;
  readonly message: string;
  readonly occurredAt: string;
}

export interface OpenPlatformEventRelayMetrics {
  readonly ticks: number;
  readonly started: number;
  readonly stopped: number;
  readonly tenants: number;
  readonly tenantErrors: number;
  readonly published: number;
  readonly failed: number;
  readonly deadLettered: number;
  readonly retried: number;
  readonly skipped: number;
  readonly errors: number;
  readonly lastRunAt?: string;
  readonly lastErrorAt?: string;
  readonly lastErrorCode?: string;
}

export interface OpenPlatformEventRelayTick {
  readonly startedAt: string;
  readonly durationMs: number;
  readonly tenants: number;
  readonly claimed: number;
  readonly published: number;
  readonly failed: number;
  readonly deadLettered: number;
  readonly retried: number;
  readonly skipped: number;
  readonly errors: number;
  readonly truncated: boolean;
}

export interface OpenPlatformEventRelayRunOptions {
  readonly signal?: AbortSignal;
}

export interface OpenPlatformEventRelaySnapshot {
  readonly mode: OpenPlatformRuntimeMode;
  readonly enabled: boolean;
  readonly running: boolean;
  readonly leader: boolean;
  readonly leaseKey: string | null;
  readonly leaseOwnerId: string | null;
  readonly leaseExpiresAt: string | null;
  readonly ticks: number;
  readonly started: number;
  readonly stopped: number;
  readonly tenants: number;
  readonly tenantErrors: number;
  readonly claimed: number;
  readonly delivered: number;
  readonly failed: number;
  readonly retried: number;
  readonly deadLettered: number;
  readonly skipped: number;
  readonly errors: number;
  readonly lastRunAt: string | null;
  readonly lastSuccessAt: string | null;
  readonly lastErrorAt: string | null;
  readonly lastErrorCode: string | null;
}

export interface OpenPlatformEventRelayOptions {
  readonly publisher: OpenPlatformEventPublisherPort;
  readonly outbox: OpenPlatformOutboxPort;
  readonly tenants?: OpenPlatformOutboxTenantResolver;
  readonly tenantIds?: readonly string[];
  readonly lease?: OpenPlatformRelayLeasePort;
  readonly leaseKey?: string;
  readonly leaseTtlMs?: number;
  readonly ownerId?: string;
  readonly mode?: OpenPlatformRuntimeMode;
  readonly enabled?: boolean;
  readonly intervalMs?: number;
  readonly jitterMs?: number;
  readonly batchSize?: number;
  readonly tenantPageSize?: number;
  readonly maxTenantsPerTick?: number;
  readonly signal?: AbortSignal;
  readonly clock?: () => Date;
  readonly random?: () => number;
  readonly onError?: (error: OpenPlatformEventRelayError) => void;
}

export interface OpenPlatformRelayLeaseRequest {
  readonly key: string;
  readonly ownerId: string;
  readonly now: string;
  readonly ttlMs: number;
}

export interface OpenPlatformRelayLeaseState {
  readonly key: string;
  readonly ownerId: string;
  readonly held: boolean;
  readonly expiresAt?: string;
}

export interface OpenPlatformRelayLeaseHolder {
  readonly key: string;
  readonly ownerId: string;
  readonly expiresAt: string;
}

export interface OpenPlatformRelayLeasePort {
  readonly productionReady?: boolean;
  readonly readiness?: OpenPlatformDependencyReadiness;
  isReady?(): MaybePromise<boolean>;
  acquire(
    request: OpenPlatformRelayLeaseRequest,
  ): Promise<OpenPlatformRelayLeaseState>;
  renew?(
    request: OpenPlatformRelayLeaseRequest,
  ): Promise<OpenPlatformRelayLeaseState>;
  release(request: OpenPlatformRelayLeaseRequest): Promise<boolean>;
  holder?(key: string): Promise<OpenPlatformRelayLeaseHolder | undefined>;
}

export interface InMemoryOpenPlatformRelayLeaseOptions {
  readonly clock?: () => Date;
}

interface OpenPlatformRelayLeaseEntry {
  readonly ownerId: string;
  readonly expiresAtMs: number;
}

interface OpenPlatformEventRelayCounters {
  ticks: number;
  started: number;
  stopped: number;
  tenants: number;
  tenantErrors: number;
  claimed: number;
  published: number;
  failed: number;
  deadLettered: number;
  retried: number;
  skipped: number;
  errors: number;
}

export class OpenPlatformEventRelay {
  readonly mode: OpenPlatformRuntimeMode;
  readonly enabled: boolean;
  readonly intervalMs: number;
  readonly jitterMs: number;
  readonly batchSize: number;
  readonly maxTenantsPerTick: number;
  private readonly publisher: OpenPlatformEventPublisherPort;
  private readonly outbox: OpenPlatformOutboxPort;
  private readonly tenants: OpenPlatformOutboxTenantResolver | undefined;
  private readonly tenantPageSize: number;
  private readonly lease: OpenPlatformRelayLeasePort | undefined;
  private readonly leaseKey: string | undefined;
  private readonly leaseTtlMs: number;
  private readonly ownerId: string | undefined;
  private readonly clock: () => Date;
  private readonly random: () => number;
  private readonly onError:
    | ((error: OpenPlatformEventRelayError) => void)
    | undefined;
  private readonly lifetimeSignal: AbortSignal | undefined;
  private readonly counters: OpenPlatformEventRelayCounters = {
    ticks: 0,
    started: 0,
    stopped: 0,
    tenants: 0,
    tenantErrors: 0,
    claimed: 0,
    published: 0,
    failed: 0,
    deadLettered: 0,
    retried: 0,
    skipped: 0,
    errors: 0,
  };
  private timer: ReturnType<typeof setTimeout> | undefined;
  private inFlight: Promise<OpenPlatformEventRelayTick> | undefined;
  private starting: Promise<void> | undefined;
  private detachSignals: Array<() => void> = [];
  private readonly attachedSignals = new Set<AbortSignal>();
  private running = false;
  private tenantCursor: string | undefined;
  private leader = true;
  private leaseHeld = false;
  private leaseOwnerId: string | null = null;
  private leaseExpiresAt: string | null = null;
  private lastRunAt: string | undefined;
  private lastSuccessAt: string | undefined;
  private lastErrorAt: string | undefined;
  private lastErrorCode: string | undefined;

  constructor(options: OpenPlatformEventRelayOptions) {
    if (options === null || typeof options !== "object") {
      throw configurationError(
        "Open platform event relay configuration is required",
      );
    }
    if (
      options.publisher === null ||
      typeof options.publisher !== "object" ||
      typeof options.publisher.publish !== "function"
    ) {
      throw configurationError("Open platform event relay publisher is invalid");
    }
    if (
      options.outbox === null ||
      typeof options.outbox !== "object" ||
      typeof options.outbox.list !== "function" ||
      typeof options.outbox.get !== "function"
    ) {
      throw configurationError("Open platform event relay outbox is invalid");
    }
    const mode = options.mode ?? "development";
    if (!isRelayRuntimeMode(mode)) {
      throw configurationError("Open platform event relay mode is invalid");
    }
    if (options.tenants !== undefined && options.tenantIds !== undefined) {
      throw configurationError(
        "Open platform event relay tenant options conflict",
      );
    }
    if (options.lease !== undefined && !isOpenPlatformRelayLeasePort(options.lease)) {
      throw configurationError("Open platform event relay lease is invalid");
    }
    if (options.lease === undefined && hasRelayLeaseOptions(options)) {
      throw configurationError(
        "Open platform event relay lease options require a lease port",
      );
    }
    if (
      mode === "production" &&
      options.lease !== undefined &&
      options.lease.productionReady !== true
    ) {
      throw configurationError(
        "Production open platform event relay requires a production relay lease",
      );
    }
    this.mode = mode;
    this.publisher = options.publisher;
    this.outbox = options.outbox;
    this.tenants =
      options.tenants ??
      (options.tenantIds === undefined
        ? undefined
        : createOpenPlatformOutboxTenantResolver(options.tenantIds));
    this.tenantPageSize = normalizeTenantPageSize(options.tenantPageSize);
    this.lease = options.lease;
    this.leaseKey =
      options.lease === undefined
        ? undefined
        : normalizeRelayLeaseKeyOption(
            options.leaseKey ?? OPEN_PLATFORM_EVENT_RELAY_LEASE_KEY,
          );
    this.leaseTtlMs = normalizeRelayLeaseTtl(options.leaseTtlMs);
    this.ownerId =
      options.ownerId === undefined
        ? options.lease === undefined
          ? undefined
          : `relay_leader_${randomUUID()}`
        : normalizeRelayOwnerIdOption(options.ownerId);
    this.leader = options.lease === undefined;
    this.maxTenantsPerTick = normalizeMaxTenantsPerTick(
      options.maxTenantsPerTick,
    );
    this.batchSize = normalizeRelayBatchSize(options.batchSize);
    this.intervalMs = normalizeRelayInterval(options.intervalMs);
    this.jitterMs = normalizeRelayJitter(options.jitterMs);
    this.clock = options.clock ?? (() => new Date());
    this.random = options.random ?? Math.random;
    this.onError = options.onError;
    const enabled = options.enabled ?? mode === "production";
    if (typeof enabled !== "boolean") {
      throw configurationError(
        "Open platform event relay enabled flag is invalid",
      );
    }
    this.enabled = enabled;
    this.lifetimeSignal = options.signal;
    this.attachSignal(this.lifetimeSignal);
  }

  isRunning(): boolean {
    return this.running;
  }

  metrics(): OpenPlatformEventRelayMetrics {
    return Object.freeze({
      ...this.counters,
      ...(this.lastRunAt === undefined ? {} : { lastRunAt: this.lastRunAt }),
      ...(this.lastErrorAt === undefined
        ? {}
        : { lastErrorAt: this.lastErrorAt }),
      ...(this.lastErrorCode === undefined
        ? {}
        : { lastErrorCode: this.lastErrorCode }),
    });
  }

  snapshot(): OpenPlatformEventRelaySnapshot {
    return Object.freeze({
      mode: this.mode,
      enabled: this.enabled,
      running: this.running,
      leader: this.leader,
      leaseKey: this.leaseKey ?? null,
      leaseOwnerId: this.leaseOwnerId,
      leaseExpiresAt: this.leaseExpiresAt,
      ticks: this.counters.ticks,
      started: this.counters.started,
      stopped: this.counters.stopped,
      tenants: this.counters.tenants,
      tenantErrors: this.counters.tenantErrors,
      claimed: this.counters.claimed,
      delivered: this.counters.published,
      failed: this.counters.failed,
      retried: this.counters.retried,
      deadLettered: this.counters.deadLettered,
      skipped: this.counters.skipped,
      errors: this.counters.errors,
      lastRunAt: this.lastRunAt ?? null,
      lastSuccessAt: this.lastSuccessAt ?? null,
      lastErrorAt: this.lastErrorAt ?? null,
      lastErrorCode: this.lastErrorCode ?? null,
    });
  }

  async isReady(): Promise<boolean> {
    return (
      (await resolveRelayDependencyReady(this.publisher)) &&
      (await resolveRelayDependencyReady(this.outbox))
    );
  }

  async start(options: OpenPlatformEventRelayRunOptions = {}): Promise<void> {
    if (this.running) return;
    if (this.starting !== undefined) return this.starting;
    const attempt = this.beginStart(options).finally(() => {
      if (this.starting === attempt) this.starting = undefined;
    });
    this.starting = attempt;
    return attempt;
  }

  async stop(): Promise<void> {
    const wasRunning = this.running;
    const inFlight = this.inFlight;
    this.running = false;
    this.clearTimer();
    this.detachAttachedSignals();
    if (wasRunning) this.counters.stopped += 1;
    if (inFlight !== undefined) await inFlight.catch(() => undefined);
  }

  runOnce(
    options: OpenPlatformEventRelayRunOptions = {},
  ): Promise<OpenPlatformEventRelayTick> {
    return this.startTick(options.signal ?? this.lifetimeSignal, true);
  }

  private async beginStart(
    options: OpenPlatformEventRelayRunOptions,
  ): Promise<void> {
    const signal = options.signal ?? this.lifetimeSignal;
    if (signal?.aborted === true) return;
    try {
      await this.assertOperationalReady();
    } catch (error) {
      this.counters.errors += 1;
      this.report("start", undefined, error);
      throw error;
    }
    this.attachSignal(signal);
    this.running = true;
    this.counters.started += 1;
    this.scheduleTick(0, signal);
  }

  private async assertOperationalReady(): Promise<void> {
    if (this.mode === "production") {
      if (this.publisher.productionReady !== true) {
        throw configurationError(
          "Production open platform event relay requires a production event publisher",
        );
      }
      if (this.outbox.productionReady !== true) {
        throw configurationError(
          "Production open platform event relay requires a production domain event outbox",
        );
      }
    }
    if (!(await this.isReady())) {
      throw configurationError(
        "Open platform event relay requires a ready domain event outbox",
      );
    }
  }

  private startTick(
    signal: AbortSignal | undefined,
    gated: boolean,
  ): Promise<OpenPlatformEventRelayTick> {
    const existing = this.inFlight;
    if (existing !== undefined) return existing;
    const tick = (
      gated
        ? this.assertOperationalReady().then(() => this.executeTick(signal))
        : this.executeTick(signal)
    ).finally(() => {
      if (this.inFlight === tick) this.inFlight = undefined;
    });
    this.inFlight = tick;
    return tick;
  }

  private async executeTick(
    signal: AbortSignal | undefined,
  ): Promise<OpenPlatformEventRelayTick> {
    const startedAtMs = this.nowMs();
    const startedAt = new Date(startedAtMs).toISOString();
    this.counters.ticks += 1;
    const tick = emptyTickCounters();
    if (!(await this.acquireLeadership())) {
      tick.skipped = 1;
      return this.completeTick(startedAt, startedAtMs, tick, false, false);
    }
    try {
      let batch: OpenPlatformOutboxTenantBatch | undefined;
      try {
        batch = await this.nextTenantBatch(signal);
      } catch (error) {
        tick.errors = 1;
        this.report("tenants", undefined, error);
        return this.completeTick(startedAt, startedAtMs, tick, false);
      }
      const flushes = await flushOpenPlatformOutboxTenants({
        publisher: this.publisher,
        outbox: this.outbox,
        tenants: batch,
        limit: this.batchSize,
        clock: this.clock,
        ...(signal === undefined ? {} : { signal }),
      });
      if (batch.rejected > 0) {
        tick.errors = batch.rejected;
        this.report(
          "tenants",
          undefined,
          relayFailure(
            `Open platform event relay rejected ${batch.rejected} tenant identifiers`,
          ),
        );
      }
      tick.tenants = flushes.tenants.length + flushes.failures.length;
      for (const failure of flushes.failures) {
        this.report("tenant", failure.tenantId, failure.cause);
        tick.tenantErrors += 1;
        tick.errors += 1;
      }
      let truncated = false;
      for (const flush of flushes.tenants) {
        tick.skipped += flush.deferred;
        truncated = truncated || flush.truncated;
        for (const outcome of flush.outcomes) {
          tick.claimed += 1;
          if (outcome.attempt > 0) tick.retried += 1;
          if (outcome.status === "published") {
            tick.published += 1;
          } else if (outcome.status === "failed") {
            tick.failed += 1;
          } else if (outcome.status === "dead_lettered") {
            tick.deadLettered += 1;
          } else {
            tick.skipped += 1;
          }
        }
      }
      return this.completeTick(startedAt, startedAtMs, tick, truncated);
    } finally {
      await this.releaseLeadership();
    }
  }

  private async acquireLeadership(): Promise<boolean> {
    const lease = this.lease;
    if (lease === undefined) return true;
    let state: OpenPlatformRelayLeaseState;
    try {
      state = await lease.acquire(this.leaseRequest());
    } catch (error) {
      this.leader = false;
      this.leaseHeld = false;
      this.countError("lease", undefined, error);
      return false;
    }
    if (!isRelayLeaseState(state)) {
      this.leader = false;
      this.leaseHeld = false;
      this.countError(
        "lease",
        undefined,
        relayFailure("Open platform event relay lease state is invalid"),
      );
      return false;
    }
    this.leader = state.held;
    this.leaseHeld = state.held;
    this.leaseOwnerId = state.ownerId;
    this.leaseExpiresAt = state.expiresAt ?? null;
    return state.held;
  }

  private async releaseLeadership(): Promise<void> {
    const lease = this.lease;
    if (lease === undefined || !this.leaseHeld) return;
    this.leaseHeld = false;
    try {
      await lease.release(this.leaseRequest());
    } catch (error) {
      this.countError("lease", undefined, error);
    }
  }

  private leaseRequest(): OpenPlatformRelayLeaseRequest {
    const ownerId = this.ownerId;
    if (ownerId === undefined) {
      throw configurationError(
        "Open platform event relay lease owner is required",
      );
    }
    return {
      key: this.leaseKey ?? OPEN_PLATFORM_EVENT_RELAY_LEASE_KEY,
      ownerId,
      now: new Date(this.nowMs()).toISOString(),
      ttlMs: this.leaseTtlMs,
    };
  }

  private completeTick(
    startedAt: string,
    startedAtMs: number,
    tick: OpenPlatformEventRelayCounters,
    truncated: boolean,
    successful = true,
  ): OpenPlatformEventRelayTick {
    this.counters.tenants += tick.tenants;
    this.counters.tenantErrors += tick.tenantErrors;
    this.counters.claimed += tick.claimed;
    this.counters.published += tick.published;
    this.counters.failed += tick.failed;
    this.counters.deadLettered += tick.deadLettered;
    this.counters.retried += tick.retried;
    this.counters.skipped += tick.skipped;
    this.counters.errors += tick.errors;
    const finishedAt = this.nowMs();
    this.lastRunAt = new Date(finishedAt).toISOString();
    if (successful && tick.errors === 0) this.lastSuccessAt = this.lastRunAt;
    return Object.freeze({
      startedAt,
      durationMs: Math.max(finishedAt - startedAtMs, 0),
      tenants: tick.tenants,
      claimed: tick.claimed,
      published: tick.published,
      failed: tick.failed,
      deadLettered: tick.deadLettered,
      retried: tick.retried,
      skipped: tick.skipped,
      errors: tick.errors,
      truncated,
    });
  }

  private async nextTenantBatch(
    signal: AbortSignal | undefined,
  ): Promise<OpenPlatformOutboxTenantBatch> {
    if (this.tenants === undefined) {
      return Object.freeze({
        tenantIds: Object.freeze([]),
        hasMore: false,
        rejected: 0,
      });
    }
    const batch = await listOpenPlatformOutboxTenants(this.tenants, {
      ...(this.tenantCursor === undefined ? {} : { cursor: this.tenantCursor }),
      limit: Math.min(this.maxTenantsPerTick, this.tenantPageSize),
      ...(signal === undefined ? {} : { signal }),
    });
    if (batch.hasMore && batch.cursor === this.tenantCursor) {
      this.tenantCursor = undefined;
      throw relayFailure(
        "Open platform event relay tenant cursor did not advance",
      );
    }
    this.tenantCursor = batch.hasMore ? batch.cursor : undefined;
    return batch;
  }

  private scheduleTick(delayMs: number, signal: AbortSignal | undefined): void {
    if (!this.running) return;
    this.clearTimer();
    const handle = setTimeout(() => {
      this.timer = undefined;
      if (!this.running) return;
      void this.runScheduledTick(signal);
    }, Math.max(delayMs, 0));
    detachTimer(handle);
    this.timer = handle;
  }

  private async runScheduledTick(
    signal: AbortSignal | undefined,
  ): Promise<void> {
    try {
      await this.startTick(signal, false);
    } catch (error) {
      this.countError("tick", undefined, error);
    }
    if (!this.running) return;
    this.scheduleTick(this.nextDelayMs(), signal);
  }

  private nextDelayMs(): number {
    if (this.jitterMs <= 0) return this.intervalMs;
    const sample = this.random();
    const factor = Number.isFinite(sample)
      ? Math.min(Math.max(sample, 0), 0.999_999)
      : 0;
    return this.intervalMs + Math.floor(factor * this.jitterMs);
  }

  private clearTimer(): void {
    if (this.timer === undefined) return;
    clearTimeout(this.timer);
    this.timer = undefined;
  }

  private attachSignal(signal: AbortSignal | undefined): void {
    if (signal === undefined || signal.aborted) return;
    if (this.attachedSignals.has(signal)) return;
    const onAbort = (): void => {
      void this.stop();
    };
    signal.addEventListener("abort", onAbort, { once: true });
    this.attachedSignals.add(signal);
    this.detachSignals.push(() => {
      signal.removeEventListener("abort", onAbort);
      this.attachedSignals.delete(signal);
    });
  }

  private detachAttachedSignals(): void {
    for (const detach of this.detachSignals) detach();
    this.detachSignals = [];
  }

  private countError(
    scope: OpenPlatformEventRelayErrorScope,
    tenantId: string | undefined,
    error: unknown,
  ): void {
    this.counters.errors += 1;
    this.report(scope, tenantId, error);
  }

  private report(
    scope: OpenPlatformEventRelayErrorScope,
    tenantId: string | undefined,
    error: unknown,
  ): void {
    const occurredAt = new Date(this.nowMs()).toISOString();
    this.lastErrorAt = occurredAt;
    this.lastErrorCode = isOpenPlatformDomainError(error)
      ? error.code
      : "OPEN_PLATFORM_EVENT_RELAY_ERROR";
    if (this.onError === undefined) return;
    try {
      this.onError(
        Object.freeze({
          scope,
          ...(tenantId === undefined ? {} : { tenantId }),
          code: this.lastErrorCode,
          message: relayErrorMessage(error),
          occurredAt,
        }),
      );
    } catch {
      return;
    }
  }

  private nowMs(): number {
    const value = this.clock();
    if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
      throw configurationError("Open platform event relay clock is invalid");
    }
    return value.getTime();
  }
}

export function createOpenPlatformEventRelay(
  options: OpenPlatformEventRelayOptions,
): OpenPlatformEventRelay {
  return new OpenPlatformEventRelay(options);
}

export function isOpenPlatformEventRelay(
  value: unknown,
): value is OpenPlatformEventRelay {
  if (value === null || typeof value !== "object") return false;
  const candidate = value as OpenPlatformEventRelay;
  return (
    typeof candidate.start === "function" &&
    typeof candidate.stop === "function" &&
    typeof candidate.runOnce === "function" &&
    typeof candidate.metrics === "function"
  );
}

export class InMemoryOpenPlatformRelayLease implements OpenPlatformRelayLeasePort {
  readonly productionReady = false;
  readonly readiness: OpenPlatformDependencyReadiness = Object.freeze({
    storage: "memory" as const,
    distributed: false,
    ready: () => true,
  });
  private readonly leases = new Map<string, OpenPlatformRelayLeaseEntry>();
  private readonly clock: () => Date;

  constructor(options: InMemoryOpenPlatformRelayLeaseOptions = {}) {
    this.clock = options.clock ?? (() => new Date());
  }

  async acquire(
    request: OpenPlatformRelayLeaseRequest,
  ): Promise<OpenPlatformRelayLeaseState> {
    const normalized = normalizeOpenPlatformRelayLeaseRequest(request);
    const nowMs = Date.parse(normalized.now);
    const existing = this.activeLease(normalized.key, nowMs);
    if (existing !== undefined && existing.ownerId !== normalized.ownerId) {
      return leaseState(normalized.key, existing, false);
    }
    return this.grant(normalized, nowMs);
  }

  async renew(
    request: OpenPlatformRelayLeaseRequest,
  ): Promise<OpenPlatformRelayLeaseState> {
    const normalized = normalizeOpenPlatformRelayLeaseRequest(request);
    const nowMs = Date.parse(normalized.now);
    const existing = this.activeLease(normalized.key, nowMs);
    if (existing === undefined) {
      return Object.freeze({
        key: normalized.key,
        ownerId: normalized.ownerId,
        held: false,
      });
    }
    if (existing.ownerId !== normalized.ownerId) {
      return leaseState(normalized.key, existing, false);
    }
    return this.grant(normalized, nowMs);
  }

  async release(request: OpenPlatformRelayLeaseRequest): Promise<boolean> {
    const normalized = normalizeOpenPlatformRelayLeaseRequest(request);
    const existing = this.leases.get(normalized.key);
    if (existing === undefined || existing.ownerId !== normalized.ownerId) {
      return false;
    }
    return this.leases.delete(normalized.key);
  }

  async holder(
    key: string,
  ): Promise<OpenPlatformRelayLeaseHolder | undefined> {
    const normalizedKey = normalizeOpenPlatformRelayLeaseKey(key);
    const existing = this.activeLease(normalizedKey, this.nowMs());
    return existing === undefined
      ? undefined
      : Object.freeze({
          key: normalizedKey,
          ownerId: existing.ownerId,
          expiresAt: new Date(existing.expiresAtMs).toISOString(),
        });
  }

  private grant(
    request: OpenPlatformRelayLeaseRequest,
    nowMs: number,
  ): OpenPlatformRelayLeaseState {
    const entry: OpenPlatformRelayLeaseEntry = Object.freeze({
      ownerId: request.ownerId,
      expiresAtMs: nowMs + request.ttlMs,
    });
    this.leases.set(request.key, entry);
    return leaseState(request.key, entry, true);
  }

  private activeLease(
    key: string,
    nowMs: number,
  ): OpenPlatformRelayLeaseEntry | undefined {
    const existing = this.leases.get(key);
    if (existing === undefined) return undefined;
    if (existing.expiresAtMs > nowMs) return existing;
    this.leases.delete(key);
    return undefined;
  }

  private nowMs(): number {
    const value = this.clock();
    if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
      throw configurationError("Open platform relay lease clock is invalid");
    }
    return value.getTime();
  }
}

export const InMemoryOpenPlatformRelayLeaseStore =
  InMemoryOpenPlatformRelayLease;

export function createInMemoryOpenPlatformRelayLease(
  options: InMemoryOpenPlatformRelayLeaseOptions = {},
): InMemoryOpenPlatformRelayLease {
  return new InMemoryOpenPlatformRelayLease(options);
}

export function isOpenPlatformRelayLeasePort(
  value: unknown,
): value is OpenPlatformRelayLeasePort {
  if (value === null || typeof value !== "object") return false;
  const candidate = value as OpenPlatformRelayLeasePort;
  return (
    typeof candidate.acquire === "function" &&
    typeof candidate.release === "function"
  );
}

export function normalizeOpenPlatformRelayLeaseKey(value: unknown): string {
  const key = normalizeIdentifier(value, "leaseKey");
  if (key.length < OPEN_PLATFORM_EVENT_RELAY_MIN_LEASE_KEY_LENGTH) {
    throw validationError("Open platform relay lease key is invalid", {
      field: "leaseKey",
    });
  }
  return key;
}

export function normalizeOpenPlatformRelayLeaseRequest(
  request: OpenPlatformRelayLeaseRequest,
): OpenPlatformRelayLeaseRequest {
  if (request === null || typeof request !== "object") {
    throw validationError("Open platform relay lease request is invalid", {
      field: "lease",
    });
  }
  const nowMs = typeof request.now === "string" ? Date.parse(request.now) : Number.NaN;
  if (!Number.isFinite(nowMs)) {
    throw validationError("Open platform relay lease request is invalid", {
      field: "now",
    });
  }
  if (
    !Number.isSafeInteger(request.ttlMs) ||
    request.ttlMs < OPEN_PLATFORM_EVENT_RELAY_MIN_LEASE_TTL_MS ||
    request.ttlMs > OPEN_PLATFORM_EVENT_RELAY_MAX_LEASE_TTL_MS
  ) {
    throw validationError("Open platform relay lease duration is invalid", {
      field: "ttlMs",
    });
  }
  return {
    key: normalizeOpenPlatformRelayLeaseKey(request.key),
    ownerId: normalizeIdentifier(request.ownerId, "ownerId"),
    now: new Date(nowMs).toISOString(),
    ttlMs: request.ttlMs,
  };
}

function leaseState(
  key: string,
  entry: OpenPlatformRelayLeaseEntry,
  held: boolean,
): OpenPlatformRelayLeaseState {
  return Object.freeze({
    key,
    ownerId: entry.ownerId,
    held,
    expiresAt: new Date(entry.expiresAtMs).toISOString(),
  });
}

function isRelayLeaseState(value: unknown): value is OpenPlatformRelayLeaseState {
  if (value === null || typeof value !== "object") return false;
  const candidate = value as OpenPlatformRelayLeaseState;
  return (
    typeof candidate.key === "string" &&
    typeof candidate.ownerId === "string" &&
    typeof candidate.held === "boolean" &&
    (candidate.expiresAt === undefined ||
      typeof candidate.expiresAt === "string")
  );
}

function hasRelayLeaseOptions(options: OpenPlatformEventRelayOptions): boolean {
  return (
    options.leaseKey !== undefined ||
    options.leaseTtlMs !== undefined ||
    options.ownerId !== undefined
  );
}

function isRelayRuntimeMode(value: unknown): value is OpenPlatformRuntimeMode {
  return value === "development" || value === "test" || value === "production";
}

function emptyTickCounters(): OpenPlatformEventRelayCounters {
  return {
    ticks: 0,
    started: 0,
    stopped: 0,
    tenants: 0,
    tenantErrors: 0,
    claimed: 0,
    published: 0,
    failed: 0,
    deadLettered: 0,
    retried: 0,
    skipped: 0,
    errors: 0,
  };
}

function normalizeRelayInterval(value: unknown): number {
  if (value === undefined) return OPEN_PLATFORM_EVENT_RELAY_DEFAULT_INTERVAL_MS;
  if (
    !Number.isSafeInteger(value) ||
    (value as number) < OPEN_PLATFORM_EVENT_RELAY_MIN_INTERVAL_MS ||
    (value as number) > OPEN_PLATFORM_EVENT_RELAY_MAX_INTERVAL_MS
  ) {
    throw configurationError("Open platform event relay interval is invalid");
  }
  return value as number;
}

function normalizeRelayJitter(value: unknown): number {
  if (value === undefined) return 0;
  if (
    !Number.isSafeInteger(value) ||
    (value as number) < 0 ||
    (value as number) > OPEN_PLATFORM_EVENT_RELAY_MAX_JITTER_MS
  ) {
    throw configurationError("Open platform event relay jitter is invalid");
  }
  return value as number;
}

function normalizeRelayBatchSize(value: unknown): number {
  if (value === undefined) return OPEN_PLATFORM_EVENT_RELAY_DEFAULT_BATCH_SIZE;
  if (
    !Number.isSafeInteger(value) ||
    (value as number) < 1 ||
    (value as number) > OPEN_PLATFORM_EVENT_RELAY_MAX_BATCH_SIZE
  ) {
    throw configurationError("Open platform event relay batch size is invalid");
  }
  return value as number;
}

function normalizeTenantPageSize(value: unknown): number {
  if (value === undefined) {
    return OPEN_PLATFORM_EVENT_RELAY_DEFAULT_TENANT_PAGE_SIZE;
  }
  if (
    !Number.isSafeInteger(value) ||
    (value as number) < 1 ||
    (value as number) > OPEN_PLATFORM_EVENT_RELAY_MAX_TENANTS_PER_TICK
  ) {
    throw configurationError(
      "Open platform event relay tenant page size is invalid",
    );
  }
  return value as number;
}

function normalizeMaxTenantsPerTick(value: unknown): number {
  if (value === undefined) return OPEN_PLATFORM_EVENT_RELAY_MAX_TENANTS_PER_TICK;
  if (
    !Number.isSafeInteger(value) ||
    (value as number) < 1 ||
    (value as number) > OPEN_PLATFORM_EVENT_RELAY_MAX_TENANTS_PER_TICK
  ) {
    throw configurationError(
      "Open platform event relay tenant batch is invalid",
    );
  }
  return value as number;
}

function normalizeRelayLeaseKeyOption(value: unknown): string {
  try {
    return normalizeOpenPlatformRelayLeaseKey(value);
  } catch {
    throw configurationError("Open platform event relay lease key is invalid");
  }
}

function normalizeRelayOwnerIdOption(value: unknown): string {
  try {
    return normalizeIdentifier(value, "ownerId");
  } catch {
    throw configurationError(
      "Open platform event relay lease owner is invalid",
    );
  }
}

function normalizeRelayLeaseTtl(value: unknown): number {
  if (value === undefined) return OPEN_PLATFORM_EVENT_RELAY_DEFAULT_LEASE_TTL_MS;
  if (
    !Number.isSafeInteger(value) ||
    (value as number) < OPEN_PLATFORM_EVENT_RELAY_MIN_LEASE_TTL_MS ||
    (value as number) > OPEN_PLATFORM_EVENT_RELAY_MAX_LEASE_TTL_MS
  ) {
    throw configurationError(
      "Open platform event relay lease duration is invalid",
    );
  }
  return value as number;
}

async function resolveRelayDependencyReady(
  dependency:
    | Pick<OpenPlatformEventPublisherPort, "productionReady" | "readiness" | "isReady">
    | Pick<OpenPlatformOutboxPort, "productionReady" | "readiness" | "isReady">,
): Promise<boolean> {
  const readiness: OpenPlatformDependencyReadiness | undefined =
    dependency.readiness;
  if (readiness !== undefined && typeof readiness.ready === "function") {
    try {
      return (await readiness.ready()) === true;
    } catch {
      return false;
    }
  }
  if (typeof dependency.isReady === "function") {
    try {
      return (await dependency.isReady()) === true;
    } catch {
      return false;
    }
  }
  return dependency.productionReady === true;
}

function detachTimer(handle: ReturnType<typeof setTimeout>): void {
  if (
    typeof handle === "object" &&
    handle !== null &&
    typeof (handle as { unref?: unknown }).unref === "function"
  ) {
    (handle as { unref: () => void }).unref();
  }
}

function relayFailure(message: string): Error {
  return new Error(message);
}

function relayErrorMessage(error: unknown): string {
  if (isOpenPlatformDomainError(error)) return error.message;
  if (error instanceof Error) {
    return error.message
      .replace(/[\u0000-\u001f\u007f]/gu, " ")
      .trim()
      .slice(0, 256);
  }
  return "Open platform event relay failed";
}
