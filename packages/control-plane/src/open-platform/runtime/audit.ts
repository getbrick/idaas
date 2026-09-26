import { randomUUID } from "node:crypto";
import type { OpenPlatformRuntimeMode } from "../types.js";
import { normalizeIdentifier, normalizeResourceId } from "../validation.js";
import { isOpenPlatformApiRequestContext } from "./context.js";
import { normalizeCredentialVersion, normalizeRuntimeInstant } from "./context.js";
import {
  OPEN_PLATFORM_RUNTIME_ERROR_CODES,
  isOpenPlatformRuntimeError,
  runtimeError,
} from "./errors.js";
import type {
  OpenPlatformApiCallAuditEvent,
  OpenPlatformApiCallAuditInput,
  OpenPlatformApiCallEventType,
  OpenPlatformApiCallOutcome,
  OpenPlatformApiPrincipal,
  OpenPlatformApiRequestContext,
  OpenPlatformAuditMetadata,
  OpenPlatformAuditOutboxPort,
  OpenPlatformAuditOutboxReceipt,
  OpenPlatformDependencyReadiness,
} from "./types.js";

const AUDIT_METADATA_KEYS = new Set([
  "apiVersionId",
  "billingPeriod",
  "cacheHit",
  "credentialVersion",
  "durationMs",
  "errorCode",
  "policyId",
  "policyVersion",
  "quantity",
  "retryable",
  "routeId",
  "source",
  "statusCode",
  "unit",
]);

const AUDIT_UNITS = new Set(["byte", "call", "millisecond", "request"]);

const EVENT_OUTCOMES = Object.freeze({
  "api.call.accepted": "accepted",
  "api.call.rejected": "rejected",
  "api.call.completed": "completed",
  "api.call.failed": "failed",
  "api.call.rate_limited": "rate_limited",
} satisfies Readonly<Record<OpenPlatformApiCallEventType, OpenPlatformApiCallOutcome>>);

export interface OpenPlatformApiAuditServiceOptions {
  readonly mode?: OpenPlatformRuntimeMode;
  readonly outbox: OpenPlatformAuditOutboxPort;
  readonly clock?: () => Date;
  readonly idGenerator?: () => string;
}

export class OpenPlatformApiAuditService {
  readonly storage: "memory" | "persistent";
  private readonly outbox: OpenPlatformAuditOutboxPort;
  private readonly clock: () => Date;
  private readonly idGenerator: () => string;

  constructor(options: OpenPlatformApiAuditServiceOptions) {
    if (
      options === null ||
      typeof options !== "object" ||
      !isAuditOutbox(options.outbox) ||
      (options.clock !== undefined && typeof options.clock !== "function") ||
      (options.idGenerator !== undefined &&
        typeof options.idGenerator !== "function")
    ) {
      throw runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.CONFIGURATION_ERROR,
      );
    }
    const mode = options.mode ?? "test";
    if (
      !isRuntimeMode(mode) ||
      (mode === "production" && !isProductionAuditOutbox(options.outbox))
    ) {
      throw runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.CONFIGURATION_ERROR,
      );
    }
    this.outbox = options.outbox;
    this.storage = options.outbox.readiness.storage;
    this.clock = options.clock ?? (() => new Date());
    this.idGenerator = options.idGenerator ?? randomUUID;
  }

  async isReady(): Promise<boolean> {
    try {
      return (await this.outbox.readiness.ready()) === true;
    } catch {
      return false;
    }
  }

  async record(
    input: OpenPlatformApiCallAuditInput,
  ): Promise<OpenPlatformApiCallAuditEvent> {
    if (
      input === null ||
      typeof input !== "object" ||
      !isOpenPlatformApiRequestContext(input.context)
    ) {
      throw runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.AUTHENTICATION_REQUIRED,
      );
    }
    const type = normalizeEventType(input.type);
    const principal = normalizePrincipal(input.context, input.principal, type);
    const event: OpenPlatformApiCallAuditEvent = Object.freeze({
      id: input.eventId === undefined
        ? normalizeAuditEventId(this.idGenerator())
        : normalizeAuditEventId(input.eventId),
      schemaVersion: "open-platform.api-call.audit.v1",
      type,
      outcome: EVENT_OUTCOMES[type],
      occurredAt: input.occurredAt === undefined
        ? now(this.clock)
        : normalizeRuntimeInstant(input.occurredAt),
      tenantId: input.context.tenantId,
      applicationId: input.context.applicationId,
      clientId: input.context.clientId,
      ...(principal === undefined
        ? {}
        : {
            credentialId: principal.credentialId,
            credentialVersion: principal.credentialVersion,
          }),
      request: Object.freeze({
        method: input.context.method,
        path: input.context.path,
        audience: input.context.audience,
        ip: input.context.ip,
        requestId: input.context.requestId,
      }),
      metadata: sanitizeOpenPlatformAuditMetadata(input.metadata),
    });
    if (!(await this.isReady())) {
      throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.AUDIT_UNAVAILABLE, {
        requestId: input.context.requestId,
      });
    }
    try {
      const receipt = await this.outbox.enqueue(event);
      if (
        receipt === null ||
        typeof receipt !== "object" ||
        normalizeIdentifier(receipt.eventId, "eventId") !== event.id
      ) {
        throw new Error("audit outbox receipt mismatch");
      }
    } catch (error) {
      if (isOpenPlatformRuntimeError(error)) throw error;
      throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.AUDIT_UNAVAILABLE, {
        requestId: input.context.requestId,
      });
    }
    return event;
  }
}

export class InMemoryOpenPlatformAuditOutbox
implements OpenPlatformAuditOutboxPort {
  readonly productionReady = false;
  readonly readiness: OpenPlatformDependencyReadiness;
  private readonly events: OpenPlatformApiCallAuditEvent[] = [];

  constructor() {
    this.readiness = Object.freeze({
      storage: "memory" as const,
      distributed: false,
      ready: () => true,
    });
  }

  async enqueue(
    event: OpenPlatformApiCallAuditEvent,
  ): Promise<OpenPlatformAuditOutboxReceipt> {
    if (
      event === null ||
      typeof event !== "object" ||
      normalizeIdentifier(event.id, "eventId") !== event.id
    ) {
      throw new Error("invalid audit event");
    }
    if (this.events.some((candidate) => candidate.id === event.id)) {
      throw new Error("duplicate audit event");
    }
    this.events.push(structuredClone(event));
    return Object.freeze({ eventId: event.id });
  }

  snapshot(): OpenPlatformApiCallAuditEvent[] {
    return this.events.map((event) => structuredClone(event));
  }
}

export function sanitizeOpenPlatformAuditMetadata(
  value: Readonly<Record<string, unknown>> | undefined,
): OpenPlatformAuditMetadata {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return Object.freeze({});
  }
  const safe: Record<string, string | number | boolean | null> = {};
  for (const key of Object.keys(value).sort()) {
    if (!AUDIT_METADATA_KEYS.has(key)) continue;
    const nested = value[key];
    if (
      nested === null ||
      typeof nested === "boolean" ||
      (typeof nested === "number" && Number.isFinite(nested)) ||
      (typeof nested === "string" && isSafeMetadataString(key, nested))
    ) {
      safe[key] = nested;
    }
  }
  return Object.freeze(safe);
}

export function createOpenPlatformApiAuditService(
  options: OpenPlatformApiAuditServiceOptions,
): OpenPlatformApiAuditService {
  return new OpenPlatformApiAuditService(options);
}

function normalizePrincipal(
  context: OpenPlatformApiRequestContext,
  value: OpenPlatformApiPrincipal | undefined,
  type: OpenPlatformApiCallEventType,
): Pick<OpenPlatformApiPrincipal, "credentialId" | "credentialVersion"> | undefined {
  if (value === undefined) {
    if (
      type === "api.call.accepted" ||
      type === "api.call.completed"
    ) {
      throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.INVALID_REQUEST, {
        requestId: context.requestId,
      });
    }
    return undefined;
  }
  if (
    value === null ||
    typeof value !== "object" ||
    value.tenantId !== context.tenantId ||
    value.applicationId !== context.applicationId ||
    value.clientId !== context.clientId
  ) {
    throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.INVALID_REQUEST, {
      requestId: context.requestId,
    });
  }
  try {
    return Object.freeze({
      credentialId: normalizeResourceId(value.credentialId, "credential"),
      credentialVersion: normalizeCredentialVersion(value.credentialVersion),
    });
  } catch {
    throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.INVALID_REQUEST, {
      requestId: context.requestId,
    });
  }
}

function normalizeAuditEventId(value: unknown): string {
  try {
    return normalizeIdentifier(value, "eventId");
  } catch {
    throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.INVALID_REQUEST);
  }
}

function normalizeEventType(value: unknown): OpenPlatformApiCallEventType {
  if (
    typeof value !== "string" ||
    !Object.prototype.hasOwnProperty.call(EVENT_OUTCOMES, value)
  ) {
    throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.INVALID_REQUEST);
  }
  return value as OpenPlatformApiCallEventType;
}

function isSafeMetadataString(key: string, value: string): boolean {
  if (value.length < 1 || value.length > 256) return false;
  if (/[\u0000-\u001f\u007f]/u.test(value)) return false;
  if (/(?:bearer\s+|basic\s+|jwt\b|secret\s*[:=]|token\s*[:=]|password\s*[:=])/iu.test(value)) {
    return false;
  }
  if (key === "errorCode") return /^[a-z][a-z0-9_]{0,127}$/u.test(value);
  if (key === "apiVersionId") {
    return /^apiver_[0-9a-f-]{36}$/u.test(value);
  }
  if (key === "billingPeriod") return /^\d{4}-(?:0[1-9]|1[0-2])$/u.test(value);
  if (key === "unit") return AUDIT_UNITS.has(value);
  if (
    key === "routeId" ||
    key === "policyId" ||
    key === "policyVersion" ||
    key === "source"
  ) {
    return /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/u.test(value);
  }
  return false;
}

function isAuditOutbox(value: unknown): value is OpenPlatformAuditOutboxPort {
  if (value === null || typeof value !== "object") return false;
  const outbox = value as OpenPlatformAuditOutboxPort;
  return typeof outbox.enqueue === "function" &&
    (outbox.productionReady === undefined ||
      typeof outbox.productionReady === "boolean") &&
    typeof outbox.readiness === "object" &&
    outbox.readiness !== null &&
    typeof outbox.readiness.ready === "function" &&
    (outbox.readiness.storage === "memory" ||
      outbox.readiness.storage === "persistent") &&
    typeof outbox.readiness.distributed === "boolean";
}

function isRuntimeMode(value: unknown): value is OpenPlatformRuntimeMode {
  return value === "development" || value === "test" || value === "production";
}

function isProductionAuditOutbox(
  outbox: OpenPlatformAuditOutboxPort,
): boolean {
  return outbox.productionReady === true &&
    outbox.readiness.storage === "persistent" &&
    outbox.readiness.distributed;
}

function now(clock: () => Date): string {
  const value = clock();
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.CONFIGURATION_ERROR);
  }
  return value.toISOString();
}
