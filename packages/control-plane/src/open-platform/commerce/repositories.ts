import {
  commerceIdempotencyKeyReused,
  commerceInvalidTotal,
  commerceNegativeAmount,
  commerceQuotaExceeded,
  commerceResourceConflict,
  commerceResourceNotFound,
  commerceStorageUnavailable,
  commerceValidationError,
} from "./errors.js";
import {
  addDecimalStrings,
  assertDecimalString,
  assertMoney,
  compareDecimalStrings,
  subtractDecimalStrings,
  zeroMoney,
} from "./money.js";
import {
  assertCommissionRuleTransition,
  assertEntitlementTransition,
  assertInvoiceDisputeTransition,
  assertInvoiceTransition,
  assertMarketplaceListingTransition,
  assertMeterTransition,
  assertPartnerAccountTransition,
  assertPlanTransition,
  assertPriceTransition,
  assertQuotaReservationTransition,
  assertQuotaTransition,
  assertSubscriptionTransition,
  assertUsageAggregateTransition,
  transitionInvoiceDispute,
} from "./state-machine.js";
import {
  INVOICE_DISPUTE_EVENTS,
  INVOICE_DISPUTE_OUTCOMES,
  INVOICE_DISPUTE_STATUSES,
  INVOICE_STATUSES,
} from "./types.js";
import type {
  CommerceDependencyReadiness,
  CommerceEntityKind,
  CommerceRecord,
  CommerceRepositories,
  CommissionRule,
  Entitlement,
  Invoice,
  InvoiceDispute,
  InvoiceDisputeAppendResult,
  InvoiceDisputeDecision,
  InvoiceDisputeListQuery,
  InvoiceDisputeRepository,
  InvoiceDisputeStatus,
  InvoiceIdempotentCreateRequest,
  InvoiceIdempotentCreateResult,
  InvoiceLine,
  InvoiceRepository,
  InvoiceStatus,
  MarketplaceListing,
  PartnerAccount,
  Plan,
  Price,
  Quota,
  QuotaReleaseRequest,
  QuotaRepository,
  QuotaReserveRequest,
  QuotaReserveResult,
  QuotaReservation,
  QuotaReservationRepository,
  QuotaSettlementRequest,
  QuotaTerminalResult,
  Subscription,
  TenantScopedRepository,
  UsageAggregate,
  UsageAggregateRepository,
  UsageEvent,
  UsageEventAppendResult,
  UsageEventRepository,
} from "./types.js";
import {
  assertCommerceHasNoSensitiveValue,
  assertCommerceId,
  cloneCommerceValue,
  normalizeCommerceLimit,
  normalizeCommerceTenantId,
  normalizeCommerceTimestamp,
  normalizeIdempotencyKey,
  normalizeMainlandChinaInvoiceMetadata,
  normalizePeriod,
  requireCommerceDisputeReason,
  requireCommerceDisputeResolutionNote,
  requireCommerceEvidenceReference,
  requireCommerceIdentifier,
} from "./validation.js";

export class InMemoryCommerceRecordStore<T extends CommerceRecord> {
  private readonly records = new Map<string, T>();
  readonly kind: CommerceEntityKind;

  constructor(kind: CommerceEntityKind) {
    this.kind = kind;
  }

  createSynchronously(record: T): T {
    validateCommerceRecord(record, this.kind);
    if (record.version !== 1) {
      throw commerceValidationError("Commerce record version is invalid", "version");
    }
    const key = storageKey(record.tenantId, record.id);
    if (this.records.has(key)) throw commerceResourceConflict();
    const stored = cloneCommerceValue(record);
    this.records.set(key, stored);
    return cloneCommerceValue(stored);
  }

  getStored(tenantId: string, id: string): T | undefined {
    const normalizedTenantId = normalizeCommerceTenantId(tenantId);
    const normalizedId = assertCommerceId(id, this.kind);
    const record = this.records.get(storageKey(normalizedTenantId, normalizedId));
    return record === undefined
      ? undefined
      : cloneCommerceValue(record);
  }

  getRaw(tenantId: string, id: string): T | undefined {
    const normalizedTenantId = normalizeCommerceTenantId(tenantId);
    const normalizedId = assertCommerceId(id, this.kind);
    return this.records.get(storageKey(normalizedTenantId, normalizedId));
  }

  setRaw(record: T): T {
    const stored = cloneCommerceValue(record);
    this.records.set(storageKey(stored.tenantId, stored.id), stored);
    return cloneCommerceValue(stored);
  }

  listStored(tenantId: string): T[] {
    const normalizedTenantId = normalizeCommerceTenantId(tenantId);
    return [...this.records.values()]
      .filter((record) => record.tenantId === normalizedTenantId)
      .sort(compareCommerceRecords)
      .map((record) => cloneCommerceValue(record));
  }

  replaceSynchronously(record: T): T {
    validateCommerceRecord(record, this.kind);
    const current = this.getRaw(record.tenantId, record.id);
    if (current === undefined) throw commerceResourceNotFound(this.kind);
    if (record.version !== current.version + 1) {
      throw commerceResourceConflict("Commerce record version is stale");
    }
    if (
      record.kind !== current.kind ||
      record.tenantId !== current.tenantId ||
      record.id !== current.id ||
      record.createdAt !== current.createdAt
    ) {
      throw commerceResourceConflict("Commerce record identity is immutable");
    }
    assertCommerceTransition(current, record);
    assertImmutableCommerceFields(current, record);
    return this.setRaw(record);
  }

  snapshot(tenantId: string): T[] {
    return this.listStored(tenantId);
  }
}

export class InMemoryTenantScopedRepository<T extends CommerceRecord>
implements TenantScopedRepository<T> {
  protected readonly store: InMemoryCommerceRecordStore<T>;

  constructor(
    kind: CommerceEntityKind,
    store = new InMemoryCommerceRecordStore<T>(kind),
  ) {
    this.store = store;
  }

  async create(record: T): Promise<T> {
    return this.store.createSynchronously(record);
  }

  async get(tenantId: string, id: string): Promise<T | undefined> {
    return this.store.getStored(tenantId, id);
  }

  async list(tenantId: string): Promise<T[]> {
    return this.store.listStored(tenantId);
  }

  async save(record: T): Promise<T> {
    return this.store.replaceSynchronously(record);
  }

  snapshot(tenantId: string): T[] {
    return this.store.snapshot(tenantId);
  }
}

export class InMemoryUsageAggregateRepository
  extends InMemoryTenantScopedRepository<UsageAggregate>
  implements UsageAggregateRepository {
  constructor() {
    super("usageAggregate");
  }

  async findByKey(
    tenantId: string,
    aggregateKey: string,
  ): Promise<UsageAggregate | undefined> {
    const normalizedTenantId = normalizeCommerceTenantId(tenantId);
    return (await this.list(normalizedTenantId)).find(
      (record) => record.aggregateKey === aggregateKey,
    );
  }
}

export class InMemoryUsageEventRepository implements UsageEventRepository {
  private readonly events = new Map<string, UsageEvent>();
  private readonly idempotency = new Map<string, string>();
  private readonly sourceEvents = new Map<string, string>();

  async append(event: UsageEvent): Promise<UsageEventAppendResult> {
    validateUsageEvent(event);
    const tenantId = normalizeCommerceTenantId(event.tenantId);
    const key = storageKey(tenantId, event.idempotencyKey);
    const existingId = this.idempotency.get(key);
    if (existingId !== undefined) {
      const existing = this.events.get(storageKey(tenantId, existingId));
      if (existing === undefined) throw commerceStorageUnavailable();
      if (existing.requestHash !== event.requestHash) {
        throw commerceIdempotencyKeyReused();
      }
      return { event: cloneCommerceValue(existing), accepted: false };
    }
    const sourceKey = storageKey(tenantId, event.sourceEventId);
    const sourceId = this.sourceEvents.get(sourceKey);
    if (sourceId !== undefined) {
      const existing = this.events.get(storageKey(tenantId, sourceId));
      if (existing === undefined) throw commerceStorageUnavailable();
      if (existing.payloadHash !== event.payloadHash) {
        throw commerceResourceConflict("Usage source event conflicts with existing state");
      }
      this.idempotency.set(key, existing.id);
      return { event: cloneCommerceValue(existing), accepted: false };
    }
    if (this.events.has(storageKey(tenantId, event.id))) {
      throw commerceResourceConflict("Usage event already exists");
    }
    const stored = cloneCommerceValue(event);
    this.events.set(storageKey(tenantId, stored.id), stored);
    this.idempotency.set(key, stored.id);
    this.sourceEvents.set(sourceKey, stored.id);
    return { event: cloneCommerceValue(stored), accepted: true };
  }

  async get(tenantId: string, id: string): Promise<UsageEvent | undefined> {
    const normalizedTenantId = normalizeCommerceTenantId(tenantId);
    const normalizedId = assertCommerceId(id, "usageEvent");
    const event = this.events.get(storageKey(normalizedTenantId, normalizedId));
    return event === undefined ? undefined : cloneCommerceValue(event);
  }

  async list(tenantId: string): Promise<UsageEvent[]> {
    const normalizedTenantId = normalizeCommerceTenantId(tenantId);
    return [...this.events.values()]
      .filter((event) => event.tenantId === normalizedTenantId)
      .sort(compareUsageEvents)
      .map((event) => cloneCommerceValue(event));
  }

  async findByIdempotencyKey(
    tenantId: string,
    idempotencyKey: string,
  ): Promise<UsageEvent | undefined> {
    const normalizedTenantId = normalizeCommerceTenantId(tenantId);
    const key = normalizeIdempotencyKey(idempotencyKey);
    const id = this.idempotency.get(storageKey(normalizedTenantId, key));
    if (id === undefined) return undefined;
    const event = this.events.get(storageKey(normalizedTenantId, id));
    return event === undefined ? undefined : cloneCommerceValue(event);
  }

  snapshot(tenantId: string): UsageEvent[] {
    const normalizedTenantId = normalizeCommerceTenantId(tenantId);
    return [...this.events.values()]
      .filter((event) => event.tenantId === normalizedTenantId)
      .sort(compareUsageEvents)
      .map((event) => cloneCommerceValue(event));
  }
}

export class InMemoryInvoiceRepository implements InvoiceRepository {
  private readonly invoices = new Map<string, Invoice>();
  private readonly idempotency = new Map<string, string>();

  async createIdempotent(
    request: InvoiceIdempotentCreateRequest,
  ): Promise<InvoiceIdempotentCreateResult> {
    const tenantId = normalizeCommerceTenantId(request.tenantId);
    const idempotencyKey = normalizeIdempotencyKey(request.idempotencyKey);
    validateInvoice(request.invoice);
    if (request.invoice.tenantId !== tenantId) {
      throw commerceValidationError("Invoice tenant scope is invalid", "tenantId");
    }
    if (request.invoice.idempotencyKey !== idempotencyKey) {
      throw commerceValidationError("Invoice idempotency key is invalid", "idempotencyKey");
    }
    if (!/^[a-f0-9]{64}$/u.test(request.requestHash)) {
      throw commerceValidationError("Invoice request hash is invalid", "requestHash");
    }
    const key = storageKey(tenantId, idempotencyKey);
    const existingId = this.idempotency.get(key);
    if (existingId !== undefined) {
      const existing = this.invoices.get(storageKey(tenantId, existingId));
      if (existing === undefined) throw commerceStorageUnavailable();
      if (existing.requestHash !== request.requestHash) {
        throw commerceIdempotencyKeyReused();
      }
      return { invoice: cloneCommerceValue(existing), replayed: true };
    }
    if (this.invoices.has(storageKey(tenantId, request.invoice.id))) {
      throw commerceResourceConflict("Invoice already exists");
    }
    const stored = cloneCommerceValue(request.invoice);
    this.invoices.set(storageKey(tenantId, stored.id), stored);
    this.idempotency.set(key, stored.id);
    return { invoice: cloneCommerceValue(stored), replayed: false };
  }

  async get(tenantId: string, id: string): Promise<Invoice | undefined> {
    const normalizedTenantId = normalizeCommerceTenantId(tenantId);
    const normalizedId = assertCommerceId(id, "invoice");
    const invoice = this.invoices.get(storageKey(normalizedTenantId, normalizedId));
    return invoice === undefined ? undefined : cloneCommerceValue(invoice);
  }

  async list(tenantId: string): Promise<Invoice[]> {
    const normalizedTenantId = normalizeCommerceTenantId(tenantId);
    return [...this.invoices.values()]
      .filter((invoice) => invoice.tenantId === normalizedTenantId)
      .sort(compareInvoices)
      .map((invoice) => cloneCommerceValue(invoice));
  }

  async transition(
    tenantId: string,
    id: string,
    targetStatus: InvoiceStatus,
    at: string,
  ): Promise<Invoice> {
    const normalizedTenantId = normalizeCommerceTenantId(tenantId);
    const normalizedId = assertCommerceId(id, "invoice");
    const current = this.invoices.get(storageKey(normalizedTenantId, normalizedId));
    if (current === undefined) throw commerceResourceNotFound("invoice");
    const timestamp = normalizeCommerceTimestamp(at, "at");
    assertInvoiceTransition(current.status, targetStatus);
    const updated: Invoice = {
      ...current,
      status: targetStatus,
      version: current.version + 1,
      updatedAt: timestamp,
      ...(targetStatus === "paid" ? { paidAt: timestamp } : {}),
      ...(targetStatus === "completed" ? { finalizedAt: timestamp } : {}),
      ...(targetStatus === "voided" ? { voidedAt: timestamp } : {}),
    };
    this.invoices.set(storageKey(normalizedTenantId, normalizedId), updated);
    return cloneCommerceValue(updated);
  }

  snapshot(tenantId: string): Invoice[] {
    const normalizedTenantId = normalizeCommerceTenantId(tenantId);
    return [...this.invoices.values()]
      .filter((invoice) => invoice.tenantId === normalizedTenantId)
      .sort(compareInvoices)
      .map((invoice) => cloneCommerceValue(invoice));
  }
}

export class InMemoryInvoiceDisputeRepository implements InvoiceDisputeRepository {
  private readonly disputes = new Map<string, InvoiceDispute>();
  private readonly idempotency = new Map<string, string>();
  private readonly transactions: Array<{
    readonly disputes: Map<string, InvoiceDispute>;
    readonly idempotency: Map<string, string>;
  }> = [];

  async append(dispute: InvoiceDispute): Promise<InvoiceDisputeAppendResult> {
    validateInvoiceDispute(dispute);
    const tenantId = normalizeCommerceTenantId(dispute.tenantId);
    const key = disputeIdempotencyKey(tenantId, dispute.invoiceId, dispute.idempotencyKey);
    const existingId = this.idempotency.get(key);
    if (existingId !== undefined) {
      const existing = this.disputes.get(storageKey(tenantId, existingId));
      if (existing === undefined) throw commerceStorageUnavailable();
      if (existing.requestHash !== dispute.requestHash) {
        throw commerceIdempotencyKeyReused();
      }
      return { dispute: cloneCommerceValue(existing), accepted: false };
    }
    if (this.disputes.has(storageKey(tenantId, dispute.id))) {
      throw commerceResourceConflict("Invoice dispute already exists");
    }
    const stored = cloneCommerceValue(dispute);
    this.disputes.set(storageKey(tenantId, stored.id), stored);
    this.idempotency.set(key, stored.id);
    return { dispute: cloneCommerceValue(stored), accepted: true };
  }

  async get(tenantId: string, id: string): Promise<InvoiceDispute | undefined> {
    const tenant = normalizeCommerceTenantId(tenantId);
    const dispute = this.disputes.get(
      storageKey(tenant, assertCommerceId(id, "invoiceDispute", "id")),
    );
    return dispute === undefined ? undefined : cloneCommerceValue(dispute);
  }

  async list(
    tenantId: string,
    query: InvoiceDisputeListQuery = {},
  ): Promise<InvoiceDispute[]> {
    const tenant = normalizeCommerceTenantId(tenantId);
    const options = normalizeInvoiceDisputeListQuery(query);
    return [...this.disputes.values()]
      .filter((dispute) => dispute.tenantId === tenant)
      .filter((dispute) => matchesInvoiceDisputeQuery(dispute, options))
      .sort(compareInvoiceDisputes)
      .slice(0, options.limit)
      .map((dispute) => cloneCommerceValue(dispute));
  }

  async findByIdempotency(
    tenantId: string,
    idempotencyKey: string,
    query: Pick<InvoiceDisputeListQuery, "invoiceId"> = {},
  ): Promise<InvoiceDispute | undefined> {
    const tenant = normalizeCommerceTenantId(tenantId);
    const key = normalizeIdempotencyKey(idempotencyKey);
    const invoiceId = query.invoiceId === undefined
      ? undefined
      : assertCommerceId(query.invoiceId, "invoice", "invoiceId");
    const candidates = [...this.disputes.values()]
      .filter((dispute) => dispute.tenantId === tenant)
      .filter((dispute) => dispute.idempotencyKey === key)
      .filter((dispute) => invoiceId === undefined || dispute.invoiceId === invoiceId)
      .sort(compareInvoiceDisputes);
    const dispute = candidates.at(0);
    return dispute === undefined ? undefined : cloneCommerceValue(dispute);
  }

  async decide(
    tenantId: string,
    id: string,
    decision: InvoiceDisputeDecision,
  ): Promise<InvoiceDispute> {
    const tenant = normalizeCommerceTenantId(tenantId);
    const disputeId = assertCommerceId(id, "invoiceDispute", "id");
    const normalized = normalizeInvoiceDisputeDecision(decision);
    const current = this.disputes.get(storageKey(tenant, disputeId));
    if (current === undefined || current.tenantId !== tenant) {
      throw commerceResourceNotFound("invoiceDispute");
    }
    if (current.version !== normalized.expectedVersion) {
      throw commerceResourceConflict("Invoice dispute version is stale");
    }
    const next = transitionInvoiceDispute(current, normalized);
    validateInvoiceDispute(next);
    this.disputes.set(storageKey(tenant, disputeId), next);
    return cloneCommerceValue(next);
  }

  async withTransaction<T>(operation: () => Promise<T>): Promise<T> {
    this.transactions.push({
      disputes: new Map(this.disputes),
      idempotency: new Map(this.idempotency),
    });
    try {
      const value = await operation();
      this.transactions.pop();
      return value;
    } catch (error) {
      const snapshot = this.transactions.pop();
      if (snapshot !== undefined) {
        this.disputes.clear();
        for (const [key, dispute] of snapshot.disputes) this.disputes.set(key, dispute);
        this.idempotency.clear();
        for (const [key, id] of snapshot.idempotency) this.idempotency.set(key, id);
      }
      throw error;
    }
  }

  snapshot(tenantId: string): InvoiceDispute[] {
    const tenant = normalizeCommerceTenantId(tenantId);
    return [...this.disputes.values()]
      .filter((dispute) => dispute.tenantId === tenant)
      .sort(compareInvoiceDisputes)
      .map((dispute) => cloneCommerceValue(dispute));
  }
}

export class InMemoryQuotaReservationRepository
  extends InMemoryTenantScopedRepository<QuotaReservation>
  implements QuotaReservationRepository {
  constructor(
    reservationStore = new InMemoryCommerceRecordStore<QuotaReservation>(
      "quotaReservation",
    ),
  ) {
    super("quotaReservation", reservationStore);
  }
}

export class InMemoryQuotaRepository
  extends InMemoryTenantScopedRepository<Quota>
  implements QuotaRepository {
  private readonly reservationStore: InMemoryCommerceRecordStore<QuotaReservation>;

  constructor(
    reservationStore = new InMemoryCommerceRecordStore<QuotaReservation>(
      "quotaReservation",
    ),
  ) {
    super("quota");
    this.reservationStore = reservationStore;
  }

  async reserveAtomic(request: QuotaReserveRequest): Promise<QuotaReserveResult> {
    const tenantId = normalizeCommerceTenantId(request.tenantId);
    if (request.operation !== "quota.reserve") {
      throw commerceValidationError("Quota operation is invalid", "operation");
    }
    const quotaId = assertCommerceId(request.quotaId, "quota");
    const reservation = request.reservation;
    validateCommerceRecord(reservation, "quotaReservation");
    if (
      reservation.tenantId !== tenantId ||
      reservation.quotaId !== quotaId ||
      assertCommerceId(reservation.planId, "plan", "planId") !== reservation.planId ||
      assertCommerceId(reservation.subscriptionId, "subscription", "subscriptionId") !==
        reservation.subscriptionId ||
      assertCommerceId(reservation.meterId, "meter", "meterId") !== reservation.meterId ||
      reservation.operation !== "quota.reserve" ||
      reservation.status !== "reserved" ||
      reservation.version !== 1 ||
      reservation.terminalIdempotencyKey !== undefined
    ) {
      throw commerceValidationError("Quota reservation is inconsistent");
    }
    const existing = this.reservationStore.getRaw(tenantId, reservation.id);
    if (existing !== undefined) {
      if (existing.requestHash !== reservation.requestHash) {
        throw commerceResourceConflict("Quota reservation already exists");
      }
      const quota = this.store.getStored(tenantId, quotaId);
      if (quota === undefined) throw commerceResourceNotFound("quota");
      return { quota, reservation: existing, replayed: true };
    }
    const sameKey = this.reservationStore
      .listStored(tenantId)
      .find((record) =>
        record.operation === "quota.reserve" &&
        record.quotaId === reservation.quotaId &&
        record.subscriptionId === reservation.subscriptionId &&
        record.idempotencyKey === reservation.idempotencyKey
      );
    if (sameKey !== undefined) {
      if (sameKey.requestHash !== reservation.requestHash) {
        throw commerceIdempotencyKeyReused();
      }
      const quota = this.store.getStored(tenantId, quotaId);
      if (quota === undefined) throw commerceResourceNotFound("quota");
      return { quota, reservation: sameKey, replayed: true };
    }
    const current = this.store.getStored(tenantId, quotaId);
    if (current === undefined) throw commerceResourceNotFound("quota");
    if (current.status !== "active") {
      throw commerceResourceConflict("Quota is not active");
    }
    const committed = addDecimalStrings(
      addDecimalStrings(current.reserved, current.consumed),
      reservation.quantity,
    );
    if (compareDecimalStrings(committed, current.limit) > 0) {
      throw commerceQuotaExceeded();
    }
    const updatedQuota: Quota = {
      ...current,
      reserved: addDecimalStrings(current.reserved, reservation.quantity),
      version: current.version + 1,
      updatedAt: reservation.createdAt,
    };
    const savedQuota = this.store.replaceSynchronously(updatedQuota);
    const savedReservation = this.reservationStore.createSynchronously(reservation);
    return { quota: savedQuota, reservation: savedReservation, replayed: false };
  }

  async settleAtomic(
    request: QuotaSettlementRequest,
  ): Promise<QuotaTerminalResult> {
    return this.terminateReservation(request, "settled");
  }

  async releaseAtomic(
    request: QuotaReleaseRequest,
  ): Promise<QuotaTerminalResult> {
    return this.terminateReservation(request, "released");
  }

  private async terminateReservation(
    request: QuotaSettlementRequest | QuotaReleaseRequest,
    target: "settled" | "released",
  ): Promise<QuotaTerminalResult> {
    const expectedOperation = target === "settled"
      ? "quota.settle"
      : "quota.release";
    if (request.operation !== expectedOperation) {
      throw commerceValidationError("Quota operation is invalid", "operation");
    }
    const tenantId = normalizeCommerceTenantId(request.tenantId);
    const quotaId = assertCommerceId(request.quotaId, "quota");
    const reservationId = assertCommerceId(request.reservationId, "quotaReservation");
    if (!/^[a-f0-9]{64}$/u.test(request.requestHash)) {
      throw commerceValidationError("Quota request hash is invalid", "requestHash");
    }
    const currentReservation = this.reservationStore.getRaw(tenantId, reservationId);
    if (currentReservation === undefined) {
      throw commerceResourceNotFound("quotaReservation");
    }
    if (currentReservation.quotaId !== quotaId) {
      throw commerceResourceNotFound("quotaReservation");
    }
    if (currentReservation.status !== "reserved") {
      if (
        currentReservation.terminalOperation === expectedOperation &&
        currentReservation.terminalIdempotencyKey === request.idempotencyKey
      ) {
        if (currentReservation.terminalRequestHash !== request.requestHash) {
          throw commerceIdempotencyKeyReused();
        }
        const quota = this.store.getStored(tenantId, quotaId);
        if (quota === undefined) throw commerceResourceNotFound("quota");
        return {
          quota,
          reservation: cloneCommerceValue(currentReservation),
          replayed: true,
        };
      }
      throw commerceResourceConflict("Quota reservation is already terminal");
    }
    const currentQuota = this.store.getStored(tenantId, quotaId);
    if (currentQuota === undefined) throw commerceResourceNotFound("quota");
    if (
      currentQuota.planId !== currentReservation.planId ||
      currentQuota.meterId !== currentReservation.meterId
    ) {
      throw commerceResourceConflict("Quota reservation does not match quota");
    }
    const at = normalizeCommerceTimestamp(
      target === "settled"
        ? (request as QuotaSettlementRequest).settledAt
        : (request as QuotaReleaseRequest).releasedAt,
      "at",
    );
    if (Date.parse(at) < Date.parse(currentReservation.createdAt)) {
      throw commerceValidationError("Quota terminal time is invalid", "at");
    }
    const terminalQuantity = target === "settled"
      ? assertDecimalString(
        (request as QuotaSettlementRequest).actualQuantity,
        "actualQuantity",
      )
      : "0";
    if (compareDecimalStrings(terminalQuantity, currentReservation.quantity) > 0) {
      throw commerceValidationError(
        "Quota settlement cannot exceed the reservation",
        "actualQuantity",
      );
    }
    const updatedQuota: Quota = {
      ...currentQuota,
      reserved: subtractDecimalStrings(
        currentQuota.reserved,
        currentReservation.quantity,
      ),
      consumed: target === "settled"
        ? addDecimalStrings(currentQuota.consumed, terminalQuantity)
        : currentQuota.consumed,
      version: currentQuota.version + 1,
      updatedAt: at,
    };
    const updatedReservation: QuotaReservation = {
      ...currentReservation,
      status: target,
      version: currentReservation.version + 1,
      updatedAt: at,
      ...(target === "settled"
        ? { settledQuantity: terminalQuantity, settledAt: at }
        : { releasedAt: at }),
      terminalOperation: target === "settled" ? "quota.settle" : "quota.release",
      terminalIdempotencyKey: normalizeIdempotencyKey(
        target === "settled"
          ? (request as QuotaSettlementRequest).idempotencyKey
          : (request as QuotaReleaseRequest).idempotencyKey,
      ),
      terminalRequestHash: request.requestHash,
    };
    assertQuotaReservationTransition("reserved", target);
    const savedQuota = this.store.replaceSynchronously(updatedQuota);
    const savedReservation = this.reservationStore.replaceSynchronously(
      updatedReservation,
    );
    return { quota: savedQuota, reservation: savedReservation, replayed: false };
  }
}

export interface InMemoryCommerceRepositoriesOptions {
  readonly production?: boolean;
  readonly ready?: boolean;
}

export class InMemoryCommerceRepositories implements CommerceRepositories {
  readonly readiness: CommerceDependencyReadiness;
  readonly plans = new InMemoryTenantScopedRepository<Plan>("plan");
  readonly entitlements = new InMemoryTenantScopedRepository<Entitlement>(
    "entitlement",
  );
  readonly meters = new InMemoryTenantScopedRepository<import("./types.js").Meter>(
    "meter",
  );
  readonly prices = new InMemoryTenantScopedRepository<Price>("price");
  readonly subscriptions =
    new InMemoryTenantScopedRepository<Subscription>("subscription");
  readonly usageAggregates = new InMemoryUsageAggregateRepository();
  readonly usageEvents = new InMemoryUsageEventRepository();
  readonly invoices = new InMemoryInvoiceRepository();
  readonly invoiceDisputes = new InMemoryInvoiceDisputeRepository();
  readonly marketplaceListings =
    new InMemoryTenantScopedRepository<MarketplaceListing>(
      "marketplaceListing",
    );
  readonly partnerAccounts =
    new InMemoryTenantScopedRepository<PartnerAccount>("partnerAccount");
  readonly commissionRules =
    new InMemoryTenantScopedRepository<CommissionRule>("commissionRule");
  readonly quotaReservations: InMemoryQuotaReservationRepository;
  readonly quotas: InMemoryQuotaRepository;

  constructor(options: InMemoryCommerceRepositoriesOptions = {}) {
    const reservationStore = new InMemoryCommerceRecordStore<QuotaReservation>(
      "quotaReservation",
    );
    this.quotaReservations = new InMemoryQuotaReservationRepository(
      reservationStore,
    );
    this.quotas = new InMemoryQuotaRepository(reservationStore);
    this.readiness = Object.freeze({
      storage: "memory" as const,
      distributed: false,
      ready: () => options.ready ?? options.production !== true,
    });
  }

  async isReady(): Promise<boolean> {
    return this.readiness.ready();
  }
}

export function createInMemoryCommerceRepositories(
  options: InMemoryCommerceRepositoriesOptions = {},
): InMemoryCommerceRepositories {
  return new InMemoryCommerceRepositories(options);
}

function validateCommerceRecord(
  record: CommerceRecord,
  expectedKind: CommerceEntityKind,
): void {
  if (record === null || typeof record !== "object") {
    throw commerceValidationError("Commerce record is invalid");
  }
  const id = assertCommerceId(record.id, expectedKind, "id");
  const tenantId = normalizeCommerceTenantId(record.tenantId);
  const createdAt = normalizeCommerceTimestamp(record.createdAt, "createdAt");
  const updatedAt = normalizeCommerceTimestamp(record.updatedAt, "updatedAt");
  if (
    id !== record.id ||
    tenantId !== record.tenantId ||
    record.kind !== expectedKind ||
    !Number.isSafeInteger(record.version) ||
    record.version < 1 ||
    createdAt !== record.createdAt ||
    updatedAt !== record.updatedAt ||
    Date.parse(updatedAt) < Date.parse(createdAt) ||
    (record.kind === "quotaReservation" &&
      record.operation !== "quota.reserve")
  ) {
    throw commerceValidationError("Commerce record identity is invalid");
  }
}

function validateUsageEvent(event: UsageEvent): void {
  if (event === null || typeof event !== "object") {
    throw commerceValidationError("Usage event is invalid");
  }
  assertCommerceId(event.id, "usageEvent", "id");
  normalizeCommerceTenantId(event.tenantId);
  requireCommerceIdentifier(event.sourceEventId, "sourceEventId");
  assertCommerceId(event.subscriptionId, "subscription", "subscriptionId");
  assertCommerceId(event.meterId, "meter", "meterId");
  assertDecimalString(event.quantity, "quantity", false);
  normalizeIdempotencyKey(event.idempotencyKey);
  if (!/^[a-f0-9]{64}$/u.test(event.requestHash)) {
    throw commerceValidationError("Usage request hash is invalid", "requestHash");
  }
  if (!/^[a-f0-9]{64}$/u.test(event.payloadHash)) {
    throw commerceValidationError("Usage payload hash is invalid", "payloadHash");
  }
  const occurredAt = normalizeCommerceTimestamp(event.occurredAt, "occurredAt");
  const receivedAt = normalizeCommerceTimestamp(event.receivedAt, "receivedAt");
  if (occurredAt !== event.occurredAt || receivedAt !== event.receivedAt) {
    throw commerceValidationError("Usage event timestamp is not canonical");
  }
  const period = normalizePeriod(event.periodStart, event.periodEnd);
  if (
    period.periodStart !== event.periodStart ||
    period.periodEnd !== event.periodEnd
  ) {
    throw commerceValidationError("Usage period is not canonical");
  }
  if (event.kind !== "usageEvent" || event.version !== 1) {
    throw commerceValidationError("Usage event identity is invalid");
  }
}

function validateInvoice(invoice: Invoice): void {
  if (invoice === null || typeof invoice !== "object") {
    throw commerceValidationError("Invoice is invalid");
  }
  assertCommerceId(invoice.id, "invoice", "id");
  normalizeCommerceTenantId(invoice.tenantId);
  assertCommerceId(invoice.subscriptionId, "subscription", "subscriptionId");
  assertCommerceId(invoice.planId, "plan", "planId");
  normalizeIdempotencyKey(invoice.idempotencyKey);
  if (!/^[a-f0-9]{64}$/u.test(invoice.requestHash)) {
    throw commerceValidationError("Invoice request hash is invalid", "requestHash");
  }
  if (
    invoice.kind !== "invoice" ||
    !Number.isSafeInteger(invoice.version) ||
    invoice.version < 1
  ) {
    throw commerceValidationError("Invoice identity is invalid");
  }
  const period = normalizePeriod(invoice.periodStart, invoice.periodEnd);
  if (
    period.periodStart !== invoice.periodStart ||
    period.periodEnd !== invoice.periodEnd
  ) {
    throw commerceValidationError("Invoice period is not canonical");
  }
  const subtotal = assertMoney(invoice.subtotal, "subtotal");
  const tax = assertMoney(invoice.tax, "tax");
  const total = assertMoney(invoice.total, "total");
  if (
    subtotal.currency !== "CNY" ||
    tax.currency !== "CNY" ||
    total.currency !== "CNY" ||
    invoice.currency !== "CNY"
  ) {
    throw commerceValidationError("Mainland China invoices require CNY", "currency");
  }
  const lineIds = new Set<string>();
  for (const line of invoice.lines) validateInvoiceLine(line, invoice, lineIds);
  const nonTaxSignedTotal = invoice.lines
    .filter((line) => line.type !== "tax")
    .reduce(
      (sum, line) => sum + signedMinorAmount(line),
      0n,
    );
  const taxLineTotal = invoice.lines
    .filter((line) => line.type === "tax")
    .reduce(
      (sum, line) => sum + BigInt(line.amount.amountMinor),
      0n,
    );
  const expectedNonTaxTotal = invoice.taxMode === "inclusive"
    ? BigInt(subtotal.amountMinor) + BigInt(tax.amountMinor)
    : BigInt(subtotal.amountMinor);
  const expectedTotal = invoice.taxMode === "inclusive"
    ? BigInt(subtotal.amountMinor)
    : BigInt(subtotal.amountMinor) + BigInt(tax.amountMinor);
  if (
    (invoice.taxMode !== "inclusive" && invoice.taxMode !== "exclusive") ||
    nonTaxSignedTotal !== expectedNonTaxTotal ||
    taxLineTotal !== BigInt(tax.amountMinor) ||
    BigInt(total.amountMinor) !== expectedTotal
  ) {
    throw commerceInvalidTotal("Invoice totals do not match invoice lines");
  }
  if (invoice.mainlandChina !== undefined) {
    normalizeMainlandChinaInvoiceMetadata(
      invoice.mainlandChina,
      invoice.mainlandChina.taxRateBps,
    );
  }
}

function validateInvoiceLine(
  line: InvoiceLine,
  invoice: Invoice,
  lineIds: Set<string>,
): void {
  assertCommerceId(line.id, "invoiceLine", "id");
  normalizeCommerceTenantId(line.tenantId);
  if (line.tenantId !== invoice.tenantId || line.invoiceId !== invoice.id) {
    throw commerceValidationError("Invoice line tenant scope is invalid", "tenantId");
  }
  if (line.kind !== "invoiceLine") {
    throw commerceValidationError("Invoice line kind is invalid", "kind");
  }
  if (lineIds.has(line.id)) {
    throw commerceValidationError("Invoice line identifier is duplicated", "id");
  }
  lineIds.add(line.id);
  assertDecimalString(line.quantity, "quantity");
  const unitAmount = assertMoney(line.unitAmount, "unitAmount");
  const amount = assertMoney(line.amount, "amount");
  if (unitAmount.currency !== "CNY" || amount.currency !== "CNY") {
    throw commerceValidationError("Invoice line currency is invalid", "currency");
  }
  if (line.meterId !== undefined) assertCommerceId(line.meterId, "meter", "meterId");
  if (line.priceId !== undefined) assertCommerceId(line.priceId, "price", "priceId");
  if (
    line.aggregateId !== undefined
  ) assertCommerceId(line.aggregateId, "usageAggregate", "aggregateId");
  if (line.direction !== "debit" && line.direction !== "credit") {
    throw commerceValidationError("Invoice line direction is invalid", "direction");
  }
}

function assertCommerceTransition(
  current: CommerceRecord,
  next: CommerceRecord,
): void {
  if (
    (current.kind === "quota" || current.kind === "usageAggregate") &&
    current.status === next.status
  ) {
    return;
  }
  switch (current.kind) {
    case "plan":
      assertPlanTransition(current.status, (next as Plan).status);
      break;
    case "entitlement":
      assertEntitlementTransition(
        current.status,
        (next as Entitlement).status,
      );
      break;
    case "meter":
      assertMeterTransition(current.status, (next as import("./types.js").Meter).status);
      break;
    case "price":
      assertPriceTransition(current.status, (next as Price).status);
      break;
    case "subscription":
      assertSubscriptionTransition(
        current.status,
        (next as Subscription).status,
      );
      break;
    case "quota":
      assertQuotaTransition(current.status, (next as Quota).status);
      break;
    case "quotaReservation":
      assertQuotaReservationTransition(
        current.status,
        (next as QuotaReservation).status,
      );
      break;
    case "usageAggregate":
      assertUsageAggregateTransition(
        current.status,
        (next as UsageAggregate).status,
      );
      break;
    case "marketplaceListing":
      assertMarketplaceListingTransition(
        current.status,
        (next as MarketplaceListing).status,
      );
      break;
    case "partnerAccount":
      assertPartnerAccountTransition(
        current.status,
        (next as PartnerAccount).status,
      );
      break;
    case "commissionRule":
      assertCommissionRuleTransition(
        current.status,
        (next as CommissionRule).status,
      );
      break;
  }
}

function assertImmutableCommerceFields(
  current: CommerceRecord,
  next: CommerceRecord,
): void {
  const currentProjection = immutableProjection(current);
  const nextProjection = immutableProjection(next);
  if (JSON.stringify(currentProjection) !== JSON.stringify(nextProjection)) {
    throw commerceResourceConflict("Commerce financial or identity fields are immutable");
  }
}

function immutableProjection(record: CommerceRecord): unknown {
  switch (record.kind) {
    case "plan": {
      const { status: _status, version: _version, updatedAt: _updatedAt, ...rest } = record;
      return rest;
    }
    case "entitlement": {
      const { status: _status, version: _version, updatedAt: _updatedAt, ...rest } = record;
      return rest;
    }
    case "meter": {
      const { status: _status, version: _version, updatedAt: _updatedAt, ...rest } = record;
      return rest;
    }
    case "price": {
      const { status: _status, version: _version, updatedAt: _updatedAt, ...rest } = record;
      return rest;
    }
    case "subscription": {
      const { status: _status, version: _version, updatedAt: _updatedAt, cancelAtPeriodEnd: _cancelAtPeriodEnd, canceledAt: _canceledAt, ...rest } = record;
      return rest;
    }
    case "quota": {
      const { status: _status, version: _version, updatedAt: _updatedAt, reserved: _reserved, consumed: _consumed, ...rest } = record;
      return rest;
    }
    case "quotaReservation": {
      const { status: _status, version: _version, updatedAt: _updatedAt, settledQuantity: _settledQuantity, settledAt: _settledAt, releasedAt: _releasedAt, terminalOperation: _terminalOperation, terminalIdempotencyKey: _terminalIdempotencyKey, terminalRequestHash: _terminalRequestHash, ...rest } = record;
      return rest;
    }
    case "usageAggregate":
      return {
        id: record.id,
        tenantId: record.tenantId,
        kind: record.kind,
        createdAt: record.createdAt,
        aggregateKey: record.aggregateKey,
        subscriptionId: record.subscriptionId,
        meterId: record.meterId,
        aggregation: record.aggregation,
        unit: record.unit,
        periodStart: record.periodStart,
        periodEnd: record.periodEnd,
        dimensions: record.dimensions,
      };
    case "marketplaceListing": {
      const { status: _status, version: _version, updatedAt: _updatedAt, submittedAt: _submittedAt, publishedAt: _publishedAt, removedAt: _removedAt, ...rest } = record;
      return rest;
    }
    case "partnerAccount": {
      const { status: _status, version: _version, updatedAt: _updatedAt, activatedAt: _activatedAt, ...rest } = record;
      return rest;
    }
    case "commissionRule": {
      const { status: _status, version: _version, updatedAt: _updatedAt, ...rest } = record;
      return rest;
    }
  }
}

function validateInvoiceDispute(dispute: InvoiceDispute): void {
  if (dispute === null || typeof dispute !== "object") {
    throw commerceValidationError("Invoice dispute is invalid");
  }
  assertCommerceId(dispute.id, "invoiceDispute", "id");
  normalizeCommerceTenantId(dispute.tenantId);
  assertCommerceId(dispute.invoiceId, "invoice", "invoiceId");
  assertCommerceId(dispute.subscriptionId, "subscription", "subscriptionId");
  assertCommerceId(dispute.planId, "plan", "planId");
  requireCommerceDisputeReason(dispute.reason);
  assertCommerceHash(dispute.reasonDigest, "reasonDigest");
  if (!Number.isSafeInteger(dispute.reasonLength) || dispute.reasonLength !== dispute.reason.length) {
    throw commerceValidationError("Invoice dispute reason length is invalid", "reasonLength");
  }
  if (dispute.evidenceReference !== undefined) {
    requireCommerceEvidenceReference(dispute.evidenceReference);
    assertCommerceHash(dispute.evidenceReferenceDigest, "evidenceReferenceDigest");
  } else if (dispute.evidenceReferenceDigest !== undefined) {
    throw commerceValidationError("Invoice dispute evidence digest is invalid", "evidenceReferenceDigest");
  }
  const evidenceCount = dispute.evidenceReference === undefined ? 0 : 1;
  if (!Number.isSafeInteger(dispute.evidenceCount) || dispute.evidenceCount !== evidenceCount) {
    throw commerceValidationError("Invoice dispute evidence count is invalid", "evidenceCount");
  }
  requireCommerceIdentifier(dispute.actorId, "actorId");
  requireCommerceIdentifier(dispute.requestId, "requestId");
  normalizeIdempotencyKey(dispute.idempotencyKey);
  assertCommerceHash(dispute.requestHash, "requestHash");
  if (dispute.kind !== "invoiceDispute") {
    throw commerceValidationError("Invoice dispute identity is invalid", "kind");
  }
  if (!Number.isSafeInteger(dispute.version) || dispute.version < 1) {
    throw commerceValidationError("Invoice dispute version is invalid", "version");
  }
  if (!INVOICE_DISPUTE_EVENTS.includes(dispute.event)) {
    throw commerceValidationError("Invoice dispute event is invalid", "event");
  }
  if (!INVOICE_STATUSES.includes(dispute.invoiceStatus)) {
    throw commerceValidationError("Invoice dispute invoice status is invalid", "invoiceStatus");
  }
  if (!Number.isSafeInteger(dispute.invoiceVersion) || dispute.invoiceVersion < 1) {
    throw commerceValidationError("Invoice dispute invoice version is invalid", "invoiceVersion");
  }
  if (!INVOICE_DISPUTE_STATUSES.includes(dispute.status)) {
    throw commerceValidationError("Invoice dispute status is invalid", "status");
  }
  assertInvoiceDisputeResolution(dispute);
  const createdAt = normalizeCommerceTimestamp(dispute.createdAt, "createdAt");
  const updatedAt = normalizeCommerceTimestamp(dispute.updatedAt, "updatedAt");
  const recordedAt = normalizeCommerceTimestamp(dispute.recordedAt, "recordedAt");
  if (
    createdAt !== dispute.createdAt ||
    updatedAt !== dispute.updatedAt ||
    recordedAt !== dispute.recordedAt ||
    Date.parse(recordedAt) < Date.parse(createdAt) ||
    Date.parse(updatedAt) < Date.parse(createdAt)
  ) {
    throw commerceValidationError("Invoice dispute timestamps are invalid", "createdAt");
  }
}

function normalizeInvoiceDisputeDecision(
  decision: InvoiceDisputeDecision,
): InvoiceDisputeDecision {
  if (decision === null || typeof decision !== "object") {
    throw commerceValidationError("Invoice dispute decision is invalid");
  }
  if (!INVOICE_DISPUTE_STATUSES.includes(decision.targetStatus)) {
    throw commerceValidationError(
      "Invoice dispute decision target status is invalid",
      "targetStatus",
    );
  }
  if (!Number.isSafeInteger(decision.expectedVersion) || decision.expectedVersion < 1) {
    throw commerceValidationError(
      "Invoice dispute decision version is invalid",
      "expectedVersion",
    );
  }
  requireCommerceIdentifier(decision.decidedBy, "decidedBy");
  const decidedAt = normalizeCommerceTimestamp(decision.decidedAt, "decidedAt");
  if (decidedAt !== decision.decidedAt) {
    throw commerceValidationError("Invoice dispute decision time is invalid", "decidedAt");
  }
  const terminal = (INVOICE_DISPUTE_OUTCOMES as readonly InvoiceDisputeStatus[])
    .includes(decision.targetStatus);
  if (!terminal && (decision.reference !== undefined || decision.resolutionNote !== undefined)) {
    throw commerceValidationError(
      "Invoice dispute review accepts only a target status",
      "reference",
    );
  }
  return {
    targetStatus: decision.targetStatus,
    expectedVersion: decision.expectedVersion,
    decidedBy: decision.decidedBy,
    decidedAt,
    ...(decision.reference === undefined
      ? {}
      : { reference: requireCommerceEvidenceReference(decision.reference) }),
    ...(decision.resolutionNote === undefined
      ? {}
      : {
          resolutionNote: requireCommerceDisputeResolutionNote(
            decision.resolutionNote,
          ),
        }),
  };
}

function assertInvoiceDisputeResolution(dispute: InvoiceDispute): void {
  if (dispute.resolution === undefined) {
    if (dispute.resolvedAt !== undefined || dispute.status !== "open" && dispute.status !== "underReview") {
      throw commerceValidationError("Invoice dispute resolution is invalid", "resolution");
    }
    return;
  }
  const resolution = dispute.resolution;
  if (resolution === null || typeof resolution !== "object") {
    throw commerceValidationError("Invoice dispute resolution is invalid", "resolution");
  }
  if (!INVOICE_DISPUTE_OUTCOMES.includes(resolution.outcome)) {
    throw commerceValidationError("Invoice dispute resolution outcome is invalid", "resolution");
  }
  requireCommerceIdentifier(resolution.actorId, "resolution.actorId");
  requireCommerceEvidenceReference(resolution.reference);
  assertCommerceHasNoSensitiveValue(resolution.reference, "resolution.reference");
  if (resolution.note !== undefined) {
    requireCommerceDisputeResolutionNote(resolution.note);
  }
  if (resolution.noteLength !== undefined) {
    if (
      !Number.isSafeInteger(resolution.noteLength) ||
      resolution.noteLength !== (resolution.note ?? "").length
    ) {
      throw commerceValidationError(
        "Invoice dispute resolution note length is invalid",
        "resolution.noteLength",
      );
    }
  } else if (resolution.note !== undefined) {
    throw commerceValidationError(
      "Invoice dispute resolution note length is invalid",
      "resolution.noteLength",
    );
  }
  if (resolution.fromStatus !== undefined) {
    if (!INVOICE_DISPUTE_STATUSES.includes(resolution.fromStatus)) {
      throw commerceValidationError(
        "Invoice dispute resolution origin status is invalid",
        "resolution.fromStatus",
      );
    }
  }
  const resolvedAt = normalizeCommerceTimestamp(resolution.resolvedAt, "resolvedAt");
  if (
    resolvedAt !== resolution.resolvedAt ||
    dispute.resolvedAt !== resolution.resolvedAt ||
    dispute.status !== resolution.outcome ||
    Date.parse(resolution.resolvedAt) < Date.parse(dispute.createdAt)
  ) {
    throw commerceValidationError("Invoice dispute resolution timestamp is invalid", "resolvedAt");
  }
}

function assertCommerceHash(value: unknown, field: string): void {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/u.test(value)) {
    throw commerceValidationError("Invoice dispute hash is invalid", field);
  }
}

function normalizeInvoiceDisputeListQuery(
  value: InvoiceDisputeListQuery,
): Omit<InvoiceDisputeListQuery, "limit"> & { readonly limit: number } {
  const input = value ?? {};
  const status = input.status === undefined
    ? undefined
    : normalizeInvoiceDisputeStatus(input.status, "status");
  const from = input.from === undefined
    ? undefined
    : normalizeCommerceTimestamp(input.from, "from");
  const to = input.to === undefined
    ? undefined
    : normalizeCommerceTimestamp(input.to, "to");
  if (from !== undefined && to !== undefined && Date.parse(from) > Date.parse(to)) {
    throw commerceValidationError("Invoice dispute date range is invalid", "to");
  }
  return {
    limit: normalizeCommerceLimit(input.limit),
    ...(input.invoiceId === undefined
      ? {}
      : { invoiceId: assertCommerceId(input.invoiceId, "invoice", "invoiceId") }),
    ...(input.actorId === undefined
      ? {}
      : { actorId: requireCommerceIdentifier(input.actorId, "actorId") }),
    ...(status === undefined ? {} : { status }),
    ...(from === undefined ? {} : { from }),
    ...(to === undefined ? {} : { to }),
  };
}

function normalizeInvoiceDisputeStatus(value: unknown, field: string): string {
  if (typeof value !== "string" || !INVOICE_DISPUTE_STATUSES.includes(value as never)) {
    throw commerceValidationError("Invoice dispute status filter is invalid", field);
  }
  return value;
}

function matchesInvoiceDisputeQuery(
  dispute: InvoiceDispute,
  query: ReturnType<typeof normalizeInvoiceDisputeListQuery>,
): boolean {
  if (query.invoiceId !== undefined && dispute.invoiceId !== query.invoiceId) return false;
  if (query.actorId !== undefined && dispute.actorId !== query.actorId) return false;
  if (query.status !== undefined && dispute.status !== query.status) return false;
  if (query.from !== undefined && Date.parse(dispute.createdAt) < Date.parse(query.from)) return false;
  if (query.to !== undefined && Date.parse(dispute.createdAt) > Date.parse(query.to)) return false;
  return true;
}

function compareInvoiceDisputes(
  left: InvoiceDispute,
  right: InvoiceDispute,
): number {
  const created = left.createdAt.localeCompare(right.createdAt);
  return created === 0 ? left.id.localeCompare(right.id) : created;
}

function signedMinorAmount(line: InvoiceLine): bigint {
  assertMoney(line.amount, "amount");
  const amount = BigInt(line.amount.amountMinor);
  return line.direction === "debit" ? amount : -amount;
}

function storageKey(tenantId: string, id: string): string {
  return `${tenantId}\u0000${id}`;
}

function disputeIdempotencyKey(
  tenantId: string,
  invoiceId: string,
  idempotencyKey: string,
): string {
  return storageKey(tenantId, `${invoiceId}\u0001${idempotencyKey}`);
}

function compareCommerceRecords(
  left: CommerceRecord,
  right: CommerceRecord,
): number {
  const created = left.createdAt.localeCompare(right.createdAt);
  return created === 0 ? left.id.localeCompare(right.id) : created;
}

function compareUsageEvents(left: UsageEvent, right: UsageEvent): number {
  const occurred = left.occurredAt.localeCompare(right.occurredAt);
  return occurred === 0 ? left.id.localeCompare(right.id) : occurred;
}

function compareInvoices(left: Invoice, right: Invoice): number {
  const created = left.createdAt.localeCompare(right.createdAt);
  return created === 0 ? left.id.localeCompare(right.id) : created;
}
