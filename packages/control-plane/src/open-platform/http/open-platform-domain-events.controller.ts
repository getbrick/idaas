import {
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  Inject,
  Post,
  Query,
  Req,
  Res,
  UseFilters,
  UseGuards,
  UseInterceptors,
} from "@nestjs/common";
import {
  authenticationRequired,
  configurationError,
  forbidden,
  idempotencyKeyReused,
  idempotencyRequestInProgress,
  isOpenPlatformDomainError,
  storageUnavailable,
  tenantMismatch,
  validationError,
} from "../errors.js";
import {
  isOpenPlatformRequestContext,
  type OpenPlatformRequestContext,
} from "../authorization.js";
import { hashOpenPlatformIdempotencyRequest } from "../idempotency.js";
import {
  isOpenPlatformDomainEventStatus,
  isOpenPlatformDomainEventType,
  OPEN_PLATFORM_DOMAIN_EVENT_RESOURCE_KINDS,
  type OpenPlatformDomainEventStatus,
  type OpenPlatformDomainEventType,
  type OpenPlatformEventPublishResult,
  type OpenPlatformOutboxPage,
  type OpenPlatformOutboxQuery,
  type OpenPlatformOutboxRecord,
} from "../events.js";
import {
  normalizeIdentifier,
  normalizeIdempotencyKey,
} from "../validation.js";
import type { OpenPlatformEntityKind } from "../types.js";
import { OpenPlatformService } from "../service.js";
import { OpenPlatformHttpContextGuard } from "./open-platform-http.guard.js";
import { OpenPlatformHttpExceptionFilter } from "./open-platform-http.filter.js";
import { OpenPlatformHttpResponseInterceptor } from "./open-platform-http.interceptor.js";
import {
  OPEN_PLATFORM_HTTP_BASE_PATH,
  OPEN_PLATFORM_HTTP_CONTEXT,
  isOpenPlatformHttpRecord,
  type OpenPlatformHttpRequest,
} from "./open-platform-http.types.js";

export const OPEN_PLATFORM_DOMAIN_EVENTS_BASE_PATH =
  `${OPEN_PLATFORM_HTTP_BASE_PATH}/domain-events`;

export const OPEN_PLATFORM_DOMAIN_EVENTS_RETRY_OPERATION =
  "domainEvents.retry";

export const OPEN_PLATFORM_DOMAIN_EVENTS_REPLAY_HEADER =
  "idempotency-replayed";

export const OPEN_PLATFORM_DOMAIN_EVENTS_MAX_PAGE_SIZE = 100;

const RETRY_IDEMPOTENCY_RETENTION_MS = 86_400_000;

const RETRY_IDEMPOTENCY_MAX_ENTRIES = 1_024;

const LIST_QUERY_KEYS = Object.freeze([
  "tenantId",
  "tenant_id",
  "status",
  "eventType",
  "event_type",
  "resourceType",
  "resource_type",
  "resourceId",
  "resource_id",
  "sequence",
  "cursor",
  "limit",
] as const);

const RETRY_BODY_KEYS = Object.freeze([
  "tenantId",
  "tenant_id",
  "eventType",
  "event_type",
  "limit",
] as const);

const DOMAIN_EVENT_RESOURCE_TYPES: readonly string[] = Object.freeze([
  ...new Set<string>([
    ...Object.values(OPEN_PLATFORM_DOMAIN_EVENT_RESOURCE_KINDS),
    "webhook",
    "auditEvent",
  ]),
]);

export interface OpenPlatformDomainEventResourceSummary {
  readonly type: string;
  readonly id: string;
}

export interface OpenPlatformDomainEventSummary {
  readonly eventId: string;
  readonly tenantId: string;
  readonly type: string;
  readonly resource: OpenPlatformDomainEventResourceSummary;
  readonly status: string;
  readonly attempt: number;
  readonly occurredAt: string;
  readonly errorCode?: string;
  readonly nextAttemptAt?: string;
}

export interface OpenPlatformDomainEventSummaryPage {
  readonly tenantId: string;
  readonly items: readonly OpenPlatformDomainEventSummary[];
  readonly nextSequence?: number;
  readonly hasMore: boolean;
}

export interface OpenPlatformDomainEventRetryEventResult {
  readonly eventId: string;
  readonly delivered: number;
  readonly deadLettered: boolean;
}

export interface OpenPlatformDomainEventRetryOutcome {
  readonly tenantId: string;
  readonly flushed: number;
  readonly results: readonly OpenPlatformDomainEventRetryEventResult[];
}

export interface OpenPlatformDomainEventRetryResponse
  extends OpenPlatformDomainEventRetryOutcome {
  readonly replayed: boolean;
}

export interface OpenPlatformDomainEventRetryExecution {
  readonly value: OpenPlatformDomainEventRetryOutcome;
  readonly replayed: boolean;
}

interface DomainEventRetryIdempotencyEntry {
  readonly requestHash: string;
  readonly outcome: OpenPlatformDomainEventRetryOutcome;
  readonly expiresAt: number;
}

interface DomainEventRetryIdempotencyRequest {
  readonly tenantId: string;
  readonly actorId: string;
  readonly key: string;
  readonly request: unknown;
  readonly action: () => Promise<OpenPlatformDomainEventRetryOutcome>;
}

interface DomainEventRetryCommand {
  readonly tenantId: string;
  readonly eventType?: string;
  readonly limit?: number;
}

interface DomainEventRetryResponse {
  setHeader?(name: string, value: string): unknown;
}

export class OpenPlatformDomainEventRetryIdempotency {
  private readonly completed = new Map<
    string,
    DomainEventRetryIdempotencyEntry
  >();
  private readonly inFlight = new Set<string>();

  async execute(
    request: DomainEventRetryIdempotencyRequest,
  ): Promise<OpenPlatformDomainEventRetryExecution> {
    const storageKey = [
      request.tenantId,
      request.actorId,
      OPEN_PLATFORM_DOMAIN_EVENTS_RETRY_OPERATION,
      request.key,
    ].join("\u0000");
    const requestHash = hashOpenPlatformIdempotencyRequest(request.request);
    const existing = this.completed.get(storageKey);
    if (existing !== undefined) {
      if (existing.expiresAt > Date.now()) {
        if (existing.requestHash !== requestHash) throw idempotencyKeyReused();
        return { value: existing.outcome, replayed: true };
      }
      this.completed.delete(storageKey);
    }
    if (this.inFlight.has(storageKey)) throw idempotencyRequestInProgress();
    this.inFlight.add(storageKey);
    try {
      const outcome = await request.action();
      this.commit(storageKey, requestHash, outcome);
      return { value: outcome, replayed: false };
    } finally {
      this.inFlight.delete(storageKey);
    }
  }

  private commit(
    storageKey: string,
    requestHash: string,
    outcome: OpenPlatformDomainEventRetryOutcome,
  ): void {
    const now = Date.now();
    for (const [key, entry] of this.completed) {
      if (entry.expiresAt <= now) this.completed.delete(key);
    }
    while (this.completed.size >= RETRY_IDEMPOTENCY_MAX_ENTRIES) {
      const oldest = this.completed.keys().next();
      if (oldest.done === true) break;
      this.completed.delete(oldest.value);
    }
    this.completed.set(storageKey, {
      requestHash,
      outcome,
      expiresAt: now + RETRY_IDEMPOTENCY_RETENTION_MS,
    });
  }
}

@Controller(OPEN_PLATFORM_DOMAIN_EVENTS_BASE_PATH)
@UseGuards(OpenPlatformHttpContextGuard)
@UseFilters(OpenPlatformHttpExceptionFilter)
@UseInterceptors(OpenPlatformHttpResponseInterceptor)
export class OpenPlatformDomainEventsController {
  private readonly idempotency = new OpenPlatformDomainEventRetryIdempotency();

  constructor(
    @Inject(OpenPlatformService)
    private readonly service: OpenPlatformService,
  ) {}

  @Get()
  async listDomainEvents(
    @Query() query: unknown,
    @Req() request: OpenPlatformHttpRequest,
  ): Promise<OpenPlatformDomainEventSummaryPage> {
    const context = this.context(request);
    const value = this.record(query, LIST_QUERY_KEYS);
    const tenantId = this.tenant(context, value);
    await this.authorizeRead(context, tenantId);
    const page = await this.list({
      tenantId,
      ...this.optionalStatus(value),
      ...this.optionalEventType(value),
      ...this.optionalResourceType(value),
      ...this.optionalResourceId(value),
      ...this.optionalSequence(value),
      ...this.optionalLimit(value),
    });
    const items = page.items
      .filter((record) => record.tenantId === tenantId)
      .map((record) => toDomainEventSummary(record));
    return {
      tenantId,
      items: Object.freeze(items),
      ...(page.nextSequence === undefined
        ? {}
        : { nextSequence: page.nextSequence }),
      hasMore: page.hasMore === true,
    };
  }

  @Post("retry")
  @HttpCode(200)
  async retryDomainEvents(
    @Body() body: unknown,
    @Headers("idempotency-key") idempotencyKey: string | string[] | undefined,
    @Req() request: OpenPlatformHttpRequest,
    @Res({ passthrough: true }) response: DomainEventRetryResponse,
  ): Promise<OpenPlatformDomainEventRetryResponse> {
    const context = this.context(request);
    const value = this.record(body, RETRY_BODY_KEYS);
    const tenantId = this.tenant(context, value);
    const command: DomainEventRetryCommand = {
      tenantId,
      ...this.optionalEventType(value),
      ...this.optionalLimit(value),
    };
    const key = this.idempotencyKey(idempotencyKey);
    const result = await this.idempotency.execute({
      tenantId: context.tenantId,
      actorId: context.actorId,
      key,
      request: command,
      action: () => this.flush(context, command),
    });
    if (result.replayed) {
      response.setHeader?.(
        OPEN_PLATFORM_DOMAIN_EVENTS_REPLAY_HEADER,
        "true",
      );
    }
    return { ...result.value, replayed: result.replayed };
  }

  private context(request: OpenPlatformHttpRequest): OpenPlatformRequestContext {
    const value = request[OPEN_PLATFORM_HTTP_CONTEXT];
    if (!isOpenPlatformRequestContext(value)) throw authenticationRequired();
    return value;
  }

  private tenant(
    context: OpenPlatformRequestContext,
    value: Record<string, unknown>,
  ): string {
    for (const candidate of [value.tenantId, value.tenant_id]) {
      if (candidate !== undefined && candidate !== context.tenantId) {
        throw tenantMismatch();
      }
    }
    return context.tenantId;
  }

  private record(
    value: unknown,
    allowed: readonly string[],
  ): Record<string, unknown> {
    if (!isOpenPlatformHttpRecord(value)) return {};
    for (const key of Object.keys(value)) {
      if (!allowed.includes(key)) {
        throw validationError("Open platform domain event request is invalid", {
          field: key,
        });
      }
    }
    return value;
  }

  private idempotencyKey(value: string | string[] | undefined): string {
    const raw = Array.isArray(value) ? value[0] : value;
    if (raw === undefined) {
      throw validationError("Idempotency-Key is required");
    }
    return normalizeIdempotencyKey(raw);
  }

  private async authorizeRead(
    context: OpenPlatformRequestContext,
    tenantId: string,
  ): Promise<void> {
    try {
      if (typeof this.service.listWebhooks !== "function") throw forbidden();
      await this.service.listWebhooks(context, { tenantId, limit: 1 });
    } catch (error) {
      if (isOpenPlatformDomainError(error)) throw error;
      throw forbidden();
    }
  }

  private async list(query: OpenPlatformOutboxQuery): Promise<OpenPlatformOutboxPage> {
    try {
      const page = await this.service.outbox.list(query);
      if (page === null || typeof page !== "object" || !Array.isArray(page.items)) {
        throw storageUnavailable();
      }
      return page;
    } catch (error) {
      if (isOpenPlatformDomainError(error)) throw error;
      throw storageUnavailable();
    }
  }

  private async flush(
    context: OpenPlatformRequestContext,
    command: DomainEventRetryCommand,
  ): Promise<OpenPlatformDomainEventRetryOutcome> {
    let results: OpenPlatformEventPublishResult[];
    try {
      if (typeof this.service.retryDomainEvents !== "function") {
        throw configurationError(
          "Open platform domain event retry is unavailable",
        );
      }
      results = await this.service.retryDomainEvents(context, command);
      if (!Array.isArray(results)) throw storageUnavailable();
    } catch (error) {
      if (isOpenPlatformDomainError(error)) throw error;
      throw storageUnavailable();
    }
    const entries = results.map((result) =>
      toDomainEventRetryResult(result),
    );
    return {
      tenantId: command.tenantId,
      flushed: entries.length,
      results: Object.freeze(entries),
    };
  }

  private optionalStatus(
    value: Record<string, unknown>,
  ): { status?: OpenPlatformDomainEventStatus } {
    const candidate = value.status;
    if (candidate === undefined) return {};
    if (!isOpenPlatformDomainEventStatus(candidate)) {
      throw validationError("Open platform domain event status is invalid", {
        field: "status",
      });
    }
    return { status: candidate };
  }

  private optionalEventType(
    value: Record<string, unknown>,
  ): { eventType?: OpenPlatformDomainEventType } {
    const candidate = aliased(value, "eventType", "event_type");
    if (candidate === undefined) return {};
    if (!isOpenPlatformDomainEventType(candidate)) {
      throw validationError("Open platform domain event type is invalid", {
        field: "eventType",
      });
    }
    return { eventType: candidate };
  }

  private optionalResourceType(
    value: Record<string, unknown>,
  ): { resourceType?: OpenPlatformEntityKind } {
    const candidate = aliased(value, "resourceType", "resource_type");
    if (candidate === undefined) return {};
    if (
      typeof candidate !== "string" ||
      !DOMAIN_EVENT_RESOURCE_TYPES.includes(candidate)
    ) {
      throw validationError("Open platform domain event resource is invalid", {
        field: "resourceType",
      });
    }
    return { resourceType: candidate as OpenPlatformEntityKind };
  }

  private optionalResourceId(
    value: Record<string, unknown>,
  ): { resourceId?: string } {
    const candidate = aliased(value, "resourceId", "resource_id");
    if (candidate === undefined) return {};
    return { resourceId: normalizeIdentifier(candidate, "resourceId") };
  }

  private optionalSequence(
    value: Record<string, unknown>,
  ): { fromSequence?: number } {
    const candidate = aliased(value, "sequence", "cursor");
    if (candidate === undefined) return {};
    if (typeof candidate !== "number" && typeof candidate !== "string") {
      throw validationError("Open platform domain event cursor is invalid", {
        field: "sequence",
      });
    }
    const normalized = Number(candidate);
    if (
      !Number.isSafeInteger(normalized) ||
      normalized < 0 ||
      (typeof candidate === "string" && !/^(?:0|[1-9][0-9]*)$/u.test(candidate))
    ) {
      throw validationError("Open platform domain event cursor is invalid", {
        field: "sequence",
      });
    }
    return { fromSequence: normalized };
  }

  private optionalLimit(
    value: Record<string, unknown>,
  ): { limit?: number } {
    const candidate = value.limit;
    if (candidate === undefined) return {};
    if (typeof candidate !== "number" && typeof candidate !== "string") {
      throw validationError("Open platform domain event limit is invalid", {
        field: "limit",
      });
    }
    const normalized = Number(candidate);
    if (
      (typeof candidate === "string" && !/^[1-9][0-9]{0,2}$/u.test(candidate)) ||
      !Number.isSafeInteger(normalized) ||
      normalized < 1 ||
      normalized > OPEN_PLATFORM_DOMAIN_EVENTS_MAX_PAGE_SIZE
    ) {
      throw validationError("Open platform domain event limit is invalid", {
        field: "limit",
      });
    }
    return { limit: normalized };
  }
}

export { OpenPlatformDomainEventsController as DomainEventsController };

function aliased(
  value: Record<string, unknown>,
  key: string,
  alias: string,
): unknown {
  const primary = value[key];
  const alternative = value[alias];
  if (
    primary !== undefined &&
    alternative !== undefined &&
    primary !== alternative
  ) {
    throw validationError("Open platform domain event request is invalid", {
      field: key,
    });
  }
  return primary === undefined ? alternative : primary;
}

function toDomainEventSummary(
  record: OpenPlatformOutboxRecord,
): OpenPlatformDomainEventSummary {
  const errorCode = optionalText(record.errorCode);
  const nextAttemptAt = optionalText(record.nextAttemptAt);
  return Object.freeze({
    eventId: text(record.eventId),
    tenantId: text(record.tenantId),
    type: text(record.eventType),
    resource: Object.freeze({
      type: text(record.resourceType),
      id: text(record.resourceId),
    }),
    status: text(record.status),
    attempt: count(record.attempt),
    occurredAt: text(record.occurredAt),
    ...(errorCode === undefined ? {} : { errorCode }),
    ...(nextAttemptAt === undefined ? {} : { nextAttemptAt }),
  });
}

function toDomainEventRetryResult(
  result: OpenPlatformEventPublishResult,
): OpenPlatformDomainEventRetryEventResult {
  return Object.freeze({
    eventId: text(result?.eventId),
    delivered: count(result?.delivered),
    deadLettered: result?.deadLettered === true,
  });
}

function optionalText(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  if (normalized.length < 1) return undefined;
  return normalized.length > 128 ? normalized.slice(0, 128) : normalized;
}

function text(value: unknown): string {
  return optionalText(value) ?? "unknown";
}

function count(value: unknown): number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0
    ? value
    : 0;
}
