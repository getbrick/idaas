import type { OpenPlatformRuntimeMode } from "../types.js";
import {
  normalizeIdentifier,
  normalizeResourceId,
  normalizeTenantKey,
} from "../validation.js";
import {
  isOpenPlatformApiRequestContext,
  normalizeCredentialVersion,
} from "./context.js";
import {
  OPEN_PLATFORM_RUNTIME_ERROR_CODES,
  isOpenPlatformRuntimeError,
  runtimeError,
} from "./errors.js";
import { normalizeOpenPlatformApiRoutePolicy } from "./policy.js";
import type {
  OpenPlatformApiPrincipal,
  OpenPlatformApiRequestContext,
  OpenPlatformApiRoutePolicy,
  OpenPlatformDependencyReadiness,
  OpenPlatformRateLimitConsumption,
  OpenPlatformRateLimitConsumptionResult,
  OpenPlatformRateLimitKey,
  OpenPlatformRateLimitPolicy,
  OpenPlatformRateLimitStorePort,
  OpenPlatformRateLimitWindowState,
} from "./types.js";

export interface InMemoryOpenPlatformRateLimitStoreOptions {
  readonly clock?: () => Date;
  readonly maxEntries?: number;
}

export interface OpenPlatformRateLimitServiceOptions {
  readonly mode?: OpenPlatformRuntimeMode;
  readonly store: OpenPlatformRateLimitStorePort;
  readonly clock?: () => Date;
}

interface WindowEntry {
  count: number;
  resetAt: number;
}

export class InMemoryOpenPlatformRateLimitStore
implements OpenPlatformRateLimitStorePort {
  readonly productionReady = false;
  readonly readiness: OpenPlatformDependencyReadiness;
  private readonly windows = new Map<string, WindowEntry>();
  private readonly clock: () => Date;
  private readonly maxEntries: number;

  get entryCount(): number {
    return this.windows.size;
  }

  constructor(options: InMemoryOpenPlatformRateLimitStoreOptions = {}) {
    if (
      options.clock !== undefined &&
      typeof options.clock !== "function"
    ) {
      throw runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.CONFIGURATION_ERROR,
      );
    }
    if (
      options.maxEntries !== undefined &&
      (!Number.isSafeInteger(options.maxEntries) ||
        options.maxEntries < 1 ||
        options.maxEntries > 1_000_000)
    ) {
      throw runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.CONFIGURATION_ERROR,
      );
    }
    this.clock = options.clock ?? (() => new Date());
    this.maxEntries = options.maxEntries ?? 10_000;
    this.readiness = Object.freeze({
      storage: "memory" as const,
      distributed: false,
      ready: () => true,
    });
  }

  async consume(
    request: OpenPlatformRateLimitConsumption,
  ): Promise<OpenPlatformRateLimitConsumptionResult> {
    const now = normalizeNow(request?.now, this.clock);
    const key = normalizeRateLimitKey(request?.key);
    const ratePolicy = request.rateLimit === undefined
      ? undefined
      : normalizeStorePolicy(request.rateLimit);
    const quotaPolicy = request.quota === undefined
      ? undefined
      : normalizeStorePolicy(request.quota);
    const timestamp = Date.parse(now);
    purge(this.windows, timestamp);
    const rateConsumption = ratePolicy === undefined
      ? undefined
      : consumeWindow(
        this.windows,
        windowKey("rate", key, ratePolicy),
        ratePolicy,
        timestamp,
        this.maxEntries,
      );
    const quotaConsumption = quotaPolicy === undefined ||
        (rateConsumption !== undefined && !rateConsumption.allowed)
      ? undefined
      : consumeWindow(
        this.windows,
        windowKey("quota", key, quotaPolicy),
        quotaPolicy,
        timestamp,
        this.maxEntries,
      );
    const allowed = (rateConsumption?.allowed ?? true) &&
      (quotaConsumption?.allowed ?? true);
    const limitedBy = rateConsumption?.allowed === false
      ? "rateLimit" as const
      : quotaConsumption?.allowed === false
      ? "quota" as const
      : undefined;
    return Object.freeze({
      allowed,
      ...(limitedBy === undefined ? {} : { limitedBy }),
      ...(rateConsumption === undefined
        ? {}
        : { rateLimit: rateConsumption.state }),
      ...(quotaConsumption === undefined
        ? {}
        : { quota: quotaConsumption.state }),
    });
  }
}

export class OpenPlatformRateLimitService {
  readonly storage: "memory" | "persistent";
  private readonly store: OpenPlatformRateLimitStorePort;
  private readonly clock: () => Date;

  constructor(options: OpenPlatformRateLimitServiceOptions) {
    if (
      options === null ||
      typeof options !== "object" ||
      !isRateLimitStore(options.store) ||
      (options.clock !== undefined && typeof options.clock !== "function")
    ) {
      throw runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.CONFIGURATION_ERROR,
      );
    }
    const mode = options.mode ?? "test";
    if (
      !isRuntimeMode(mode) ||
      (mode === "production" && !isProductionRateLimitPort(options.store))
    ) {
      throw runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.CONFIGURATION_ERROR,
      );
    }
    this.store = options.store;
    this.storage = options.store.readiness.storage;
    this.clock = options.clock ?? (() => new Date());
  }

  async isReady(): Promise<boolean> {
    try {
      return (await this.store.readiness.ready()) === true;
    } catch {
      return false;
    }
  }

  async enforce(
    context: OpenPlatformApiRequestContext,
    principal: OpenPlatformApiPrincipal,
    routeValue: OpenPlatformApiRoutePolicy,
  ): Promise<OpenPlatformRateLimitConsumptionResult> {
    if (!isOpenPlatformApiRequestContext(context)) {
      throw runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.AUTHENTICATION_REQUIRED,
      );
    }
    const route = normalizeOpenPlatformApiRoutePolicy(routeValue);
    const normalizedPrincipal = normalizeRateLimitPrincipal(
      context,
      principal,
      route,
    );
    if (!(await this.isReady())) {
      throw runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.RATE_LIMITER_UNAVAILABLE,
        { requestId: context.requestId },
      );
    }
    let result: OpenPlatformRateLimitConsumptionResult;
    try {
      result = await this.store.consume({
        key: {
          tenantId: context.tenantId,
          applicationId: context.applicationId,
          credentialId: normalizedPrincipal.credentialId,
          routeId: route.routeId,
        },
        ...(route.rateLimit === undefined
          ? {}
          : { rateLimit: route.rateLimit }),
        ...(route.quota === undefined ? {} : { quota: route.quota }),
        now: normalizeNow(undefined, this.clock),
      });
    } catch (error) {
      if (isOpenPlatformRuntimeError(error)) throw error;
      throw runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.RATE_LIMITER_UNAVAILABLE,
        { requestId: context.requestId },
      );
    }
    const normalized = normalizeConsumptionResult(result);
    if (normalized.allowed) return normalized;
    const limitedBy = normalized.limitedBy ??
      (normalized.rateLimit?.remaining === 0
        ? "rateLimit"
        : "quota");
    const limited = limitedBy === "rateLimit"
      ? normalized.rateLimit
      : normalized.quota;
    if (limited === undefined || limited.remaining !== 0) {
      throw runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.RATE_LIMITER_UNAVAILABLE,
        { requestId: context.requestId },
      );
    }
    throw runtimeError(
      limitedBy === "rateLimit"
        ? OPEN_PLATFORM_RUNTIME_ERROR_CODES.RATE_LIMIT_EXCEEDED
        : OPEN_PLATFORM_RUNTIME_ERROR_CODES.QUOTA_EXCEEDED,
      {
        requestId: context.requestId,
        retryAfterSeconds: limited.retryAfterSeconds,
        details: {
          limit: limited.limit,
          remaining: limited.remaining,
          retryAfterSeconds: limited.retryAfterSeconds,
        },
      },
    );
  }
}

export function createInMemoryOpenPlatformRateLimitStore(
  options: InMemoryOpenPlatformRateLimitStoreOptions = {},
): InMemoryOpenPlatformRateLimitStore {
  return new InMemoryOpenPlatformRateLimitStore(options);
}

export function createOpenPlatformRateLimitService(
  options: OpenPlatformRateLimitServiceOptions,
): OpenPlatformRateLimitService {
  return new OpenPlatformRateLimitService(options);
}

function normalizeRateLimitPrincipal(
  context: OpenPlatformApiRequestContext,
  principal: OpenPlatformApiPrincipal,
  route: OpenPlatformApiRoutePolicy,
): OpenPlatformApiPrincipal {
  if (
    principal === null ||
    typeof principal !== "object" ||
    principal.tenantId !== context.tenantId ||
    principal.applicationId !== context.applicationId ||
    principal.clientId !== context.clientId ||
    principal.audience !== route.audience ||
    !route.clientIds.includes(context.clientId)
  ) {
    throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.POLICY_DENIED, {
      requestId: context.requestId,
    });
  }
  try {
    return Object.freeze({
      ...principal,
      credentialId: normalizeResourceId(
        principal.credentialId,
        "credential",
      ),
      credentialVersion: normalizeCredentialVersion(
        principal.credentialVersion,
      ),
      scopes: Object.freeze([...principal.scopes]),
    });
  } catch {
    throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.POLICY_DENIED, {
      requestId: context.requestId,
    });
  }
}

function consumeWindow(
  windows: Map<string, WindowEntry>,
  key: string,
  policy: OpenPlatformRateLimitPolicy,
  now: number,
  maxEntries: number,
): { readonly allowed: boolean; readonly state: OpenPlatformRateLimitWindowState } {
  let entry = windows.get(key);
  if (entry === undefined) {
    ensureWindowCapacity(windows, maxEntries);
    entry = { count: 0, resetAt: now + policy.windowMs };
  } else {
    windows.delete(key);
  }
  windows.set(key, entry);
  const allowed = entry.count < policy.requests;
  if (allowed) entry.count += 1;
  return { allowed, state: windowState(entry, policy.requests, now) };
}

function ensureWindowCapacity(
  windows: Map<string, WindowEntry>,
  maxEntries: number,
): void {
  if (windows.size < maxEntries) return;
  const oldest = windows.keys().next();
  if (oldest.done === true) {
    throw runtimeError(
      OPEN_PLATFORM_RUNTIME_ERROR_CODES.RATE_LIMITER_UNAVAILABLE,
    );
  }
  windows.delete(oldest.value);
}

function windowState(
  entry: WindowEntry,
  limit: number,
  now: number,
): OpenPlatformRateLimitWindowState {
  const remaining = Math.max(0, limit - entry.count);
  return Object.freeze({
    limit,
    remaining,
    resetAt: new Date(entry.resetAt).toISOString(),
    retryAfterSeconds: remaining === 0
      ? Math.max(1, Math.ceil((entry.resetAt - now) / 1000))
      : 0,
  });
}

function purge(entries: Map<string, WindowEntry>, now: number): void {
  for (const [key, entry] of entries) {
    if (entry.resetAt <= now) entries.delete(key);
  }
}

function normalizeStorePolicy(
  value: OpenPlatformRateLimitPolicy,
): OpenPlatformRateLimitPolicy {
  if (
    value === null ||
    typeof value !== "object" ||
    !Number.isSafeInteger(value.requests) ||
    value.requests < 1 ||
    value.requests > 1_000_000 ||
    !Number.isSafeInteger(value.windowMs) ||
    value.windowMs < 1 ||
    value.windowMs > 604_800_000
  ) {
    throw runtimeError(
      OPEN_PLATFORM_RUNTIME_ERROR_CODES.RATE_LIMITER_UNAVAILABLE,
    );
  }
  return Object.freeze({
    requests: value.requests,
    windowMs: value.windowMs,
  });
}

function windowKey(
  type: "rate" | "quota",
  key: OpenPlatformRateLimitKey,
  policy: OpenPlatformRateLimitPolicy,
): string {
  return JSON.stringify([
    type,
    key.tenantId,
    key.applicationId,
    key.credentialId,
    key.routeId,
    policy.requests,
    policy.windowMs,
  ]);
}

function normalizeRateLimitKey(value: unknown): OpenPlatformRateLimitKey {
  if (value === null || typeof value !== "object") {
    throw runtimeError(
      OPEN_PLATFORM_RUNTIME_ERROR_CODES.RATE_LIMITER_UNAVAILABLE,
    );
  }
  const key = value as OpenPlatformRateLimitKey;
  try {
    return Object.freeze({
      tenantId: normalizeTenantKey(key.tenantId),
      applicationId: normalizeResourceId(
        key.applicationId,
        "application",
      ),
      credentialId: normalizeResourceId(key.credentialId, "credential"),
      routeId: normalizeIdentifier(key.routeId, "routeId"),
    });
  } catch {
    throw runtimeError(
      OPEN_PLATFORM_RUNTIME_ERROR_CODES.RATE_LIMITER_UNAVAILABLE,
    );
  }
}

function normalizeNow(value: unknown, clock: () => Date): string {
  if (value === undefined) {
    const now = clock();
    if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
      throw runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.CONFIGURATION_ERROR,
      );
    }
    return now.toISOString();
  }
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) {
    throw runtimeError(
      OPEN_PLATFORM_RUNTIME_ERROR_CODES.RATE_LIMITER_UNAVAILABLE,
    );
  }
  return new Date(Date.parse(value)).toISOString();
}

function normalizeConsumptionResult(
  value: unknown,
): OpenPlatformRateLimitConsumptionResult {
  if (
    value === null ||
    typeof value !== "object" ||
    typeof (value as OpenPlatformRateLimitConsumptionResult).allowed !== "boolean"
  ) {
    throw runtimeError(
      OPEN_PLATFORM_RUNTIME_ERROR_CODES.RATE_LIMITER_UNAVAILABLE,
    );
  }
  const result = value as OpenPlatformRateLimitConsumptionResult;
  const rateLimit = normalizeWindowState(result.rateLimit);
  const quota = normalizeWindowState(result.quota);
  if (
    (result.rateLimit !== undefined && rateLimit === undefined) ||
    (result.quota !== undefined && quota === undefined)
  ) {
    throw runtimeError(
      OPEN_PLATFORM_RUNTIME_ERROR_CODES.RATE_LIMITER_UNAVAILABLE,
    );
  }
  if (
    !result.allowed &&
    [rateLimit, quota].some((state) =>
      state !== undefined &&
      state.remaining === 0 &&
      state.retryAfterSeconds < 1
    )
  ) {
    throw runtimeError(
      OPEN_PLATFORM_RUNTIME_ERROR_CODES.RATE_LIMITER_UNAVAILABLE,
    );
  }
  if (
    result.limitedBy !== undefined &&
    result.limitedBy !== "rateLimit" &&
    result.limitedBy !== "quota"
  ) {
    throw runtimeError(
      OPEN_PLATFORM_RUNTIME_ERROR_CODES.RATE_LIMITER_UNAVAILABLE,
    );
  }
  if (result.allowed && result.limitedBy !== undefined) {
    throw runtimeError(
      OPEN_PLATFORM_RUNTIME_ERROR_CODES.RATE_LIMITER_UNAVAILABLE,
    );
  }
  return Object.freeze({
    allowed: result.allowed,
    ...(result.limitedBy === undefined ? {} : { limitedBy: result.limitedBy }),
    ...(rateLimit === undefined ? {} : { rateLimit }),
    ...(quota === undefined ? {} : { quota }),
  });
}

function normalizeWindowState(
  value: unknown,
): OpenPlatformRateLimitWindowState | undefined {
  if (value === undefined) return undefined;
  if (
    value === null ||
    typeof value !== "object" ||
    !Number.isSafeInteger((value as OpenPlatformRateLimitWindowState).limit) ||
    (value as OpenPlatformRateLimitWindowState).limit < 1 ||
    !Number.isSafeInteger(
      (value as OpenPlatformRateLimitWindowState).remaining,
    ) ||
    (value as OpenPlatformRateLimitWindowState).remaining < 0 ||
    (value as OpenPlatformRateLimitWindowState).remaining >
      (value as OpenPlatformRateLimitWindowState).limit ||
    typeof (value as OpenPlatformRateLimitWindowState).resetAt !== "string" ||
    !Number.isFinite(
      Date.parse((value as OpenPlatformRateLimitWindowState).resetAt),
    ) ||
    !Number.isSafeInteger(
      (value as OpenPlatformRateLimitWindowState).retryAfterSeconds,
    ) ||
    (value as OpenPlatformRateLimitWindowState).retryAfterSeconds < 0 ||
    (value as OpenPlatformRateLimitWindowState).retryAfterSeconds > 86_400
  ) {
    return undefined;
  }
  return Object.freeze({
    limit: (value as OpenPlatformRateLimitWindowState).limit,
    remaining: (value as OpenPlatformRateLimitWindowState).remaining,
    resetAt: new Date(
      Date.parse((value as OpenPlatformRateLimitWindowState).resetAt),
    ).toISOString(),
    retryAfterSeconds: (value as OpenPlatformRateLimitWindowState)
      .retryAfterSeconds,
  });
}

function isRateLimitStore(value: unknown): value is OpenPlatformRateLimitStorePort {
  if (value === null || typeof value !== "object") return false;
  const store = value as OpenPlatformRateLimitStorePort;
  return typeof store.consume === "function" &&
    (store.productionReady === undefined ||
      typeof store.productionReady === "boolean") &&
    typeof store.readiness === "object" &&
    store.readiness !== null &&
    typeof store.readiness.ready === "function" &&
    (store.readiness.storage === "memory" ||
      store.readiness.storage === "persistent") &&
    typeof store.readiness.distributed === "boolean";
}

function isRuntimeMode(value: unknown): value is OpenPlatformRuntimeMode {
  return value === "development" || value === "test" || value === "production";
}

function isProductionRateLimitPort(
  store: OpenPlatformRateLimitStorePort,
): boolean {
  return store.productionReady === true &&
    store.readiness.storage === "persistent" &&
    store.readiness.distributed;
}
