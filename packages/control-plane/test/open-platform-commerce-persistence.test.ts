import { describe, expect, it } from "vitest";
import {
  COMMERCE_FOUNDATION_SQL_TABLES,
  COMMERCE_SQL_TABLES,
  CommerceSqlRuntime,
  createOpenCommerceIdempotencyMigrationSql,
  createOpenCommerceInvoiceDisputeDecisionMigrationSql,
  createOpenCommerceInvoiceDisputeMigrationSql,
  createOpenCommerceMigrationSql,
  createSqlCommerceRepositories,
  getOpenCommerceIdempotencyMigrationDefinition,
  getOpenCommerceInvoiceDisputeDecisionMigrationDefinition,
  getOpenCommerceInvoiceDisputeMigrationDefinition,
  getOpenCommerceMigrationDefinition,
  getOpenCommerceMigrations,
  SqlCommissionRuleRepository,
  SqlInvoiceDisputeRepository,
  SqlInvoiceRepository,
  SqlPlanRepository,
  SqlPriceRepository,
  SqlQuotaRepository,
  SqlUsageAggregateRepository,
  SqlUsageEventRepository,
  type CommerceDatabaseAdapter,
} from "../src/open-platform/commerce/persistence/index.js";
import type {
  CommissionRule,
  Invoice,
  InvoiceDispute,
  Plan,
  Price,
  Quota,
  QuotaReservation,
  UsageAggregate,
  UsageEvent,
} from "../src/open-platform/commerce/types.js";

const tenantId = "tenant-a";
const otherTenantId = "tenant-b";
const timestamp = "2030-01-01T00:00:00.000Z";
const periodStart = "2030-01-01T00:00:00.000Z";
const periodEnd = "2030-02-01T00:00:00.000Z";
const planId = "plan_00000000-0000-4000-8000-000000000001";
const meterId = "meter_00000000-0000-4000-8000-000000000001";
const quotaId = "quota_00000000-0000-4000-8000-000000000001";
const reservationId = "quota-reservation_00000000-0000-4000-8000-000000000001";
const priceId = "price_00000000-0000-4000-8000-000000000001";
const subscriptionId = "subscription_00000000-0000-4000-8000-000000000001";
const usageEventId = "usage-event_00000000-0000-4000-8000-000000000001";
const aggregateId = "usage-aggregate_00000000-0000-4000-8000-000000000001";
const aggregateKey = "aggregate-key-1";
const partnerId = "partner_00000000-0000-4000-8000-000000000001";
const listingId = "listing_00000000-0000-4000-8000-000000000001";
const ruleId = "commission-rule_00000000-0000-4000-8000-000000000001";
const invoiceId = "invoice_00000000-0000-4000-8000-000000000001";
const disputeId = "invoice-dispute_00000000-0000-4000-8000-000000000001";
const disputeReason = "Invoice charge not recognized by the buyer";
const disputeEvidence = "evidence://ticket-0001/attachment";

interface Call {
  readonly text: string;
  readonly values: unknown[];
}

function fakeAdapter(
  responder: (text: string, values: unknown[]) => unknown,
): CommerceDatabaseAdapter & { readonly calls: Call[] } {
  const calls: Call[] = [];
  const query = async (text: string, values: unknown[] = []): Promise<unknown> => {
    calls.push({ text, values });
    return responder(text, values);
  };
  return {
    calls,
    query,
    transaction: async <T>(callback: (executor: CommerceDatabaseAdapter) => Promise<T>): Promise<T> =>
      callback({ query }),
  };
}

function expectedPolicyRow(table: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const base = table.split(".").at(-1) ?? table;
  const available = Math.max(1, 63 - base.length - "tenant_policy".length - 1);
  return {
    policyName: `${base.slice(0, available)}_tenant_policy`,
    permissive: "PERMISSIVE",
    qual: "tenant_id = current_setting('app.tenant_id'::text, true)",
    withCheck: "tenant_id = current_setting('app.tenant_id'::text, true)",
    roles: ["public"],
    ...overrides,
  };
}

function plan(overrides: Partial<Plan> = {}): Plan {
  return {
    id: planId,
    tenantId,
    kind: "plan",
    code: "standard",
    name: "Standard",
    status: "draft",
    priority: 0,
    currency: "CNY",
    priceIds: [],
    entitlementIds: [],
    quotaIds: [],
    effectiveFrom: periodStart,
    version: 1,
    createdAt: timestamp,
    updatedAt: timestamp,
    ...overrides,
  };
}

function planRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: planId,
    tenantId,
    kind: "plan",
    code: "standard",
    name: "Standard",
    description: null,
    status: "draft",
    priority: 0,
    currency: "CNY",
    priceIds: [],
    entitlementIds: [],
    quotaIds: [],
    effectiveFrom: periodStart,
    effectiveTo: null,
    version: 1,
    createdAt: timestamp,
    updatedAt: timestamp,
    ...overrides,
  };
}

function price(overrides: Partial<Price> = {}): Price {
  return {
    id: priceId,
    tenantId,
    kind: "price",
    code: "requests",
    name: "Requests",
    status: "draft",
    currency: "CNY",
    roundingMode: "halfUp",
    priceType: "perUnit",
    meterId,
    unitAmount: { amountMinor: 10, currency: "CNY" },
    includedUnits: "0.25",
    minimumCharge: { amountMinor: 0, currency: "CNY" },
    effectiveFrom: periodStart,
    version: 1,
    createdAt: timestamp,
    updatedAt: timestamp,
    ...overrides,
  } as Price;
}

function priceRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: priceId,
    tenantId,
    kind: "price",
    code: "requests",
    name: "Requests",
    status: "draft",
    currency: "CNY",
    roundingMode: "halfUp",
    priceType: "perUnit",
    fixedAmountMinor: null,
    meterId,
    unitAmountMinor: 10,
    includedUnits: "0.25",
    minimumChargeMinor: 0,
    tiers: null,
    effectiveFrom: periodStart,
    effectiveTo: null,
    version: 1,
    createdAt: timestamp,
    updatedAt: timestamp,
    ...overrides,
  };
}

function quota(overrides: Partial<Quota> = {}): Quota {
  return {
    id: quotaId,
    tenantId,
    kind: "quota",
    planId,
    meterId,
    limit: "10",
    reserved: "0",
    consumed: "0",
    status: "active",
    version: 1,
    createdAt: timestamp,
    updatedAt: timestamp,
    ...overrides,
  };
}

function quotaRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: quotaId,
    tenantId,
    kind: "quota",
    planId,
    meterId,
    limit: "10",
    reserved: "0",
    consumed: "0",
    status: "active",
    version: 1,
    createdAt: timestamp,
    updatedAt: timestamp,
    ...overrides,
  };
}

function reservation(overrides: Partial<QuotaReservation> = {}): QuotaReservation {
  return {
    id: reservationId,
    tenantId,
    kind: "quotaReservation",
    quotaId,
    planId,
    subscriptionId,
    meterId,
    quantity: "6",
    status: "reserved",
    operation: "quota.reserve",
    idempotencyKey: "quota-key-1",
    requestHash: "d".repeat(64),
    expiresAt: "2030-01-20T00:00:00.000Z",
    version: 1,
    createdAt: timestamp,
    updatedAt: timestamp,
    ...overrides,
  };
}

function reservationRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: reservationId,
    tenantId,
    kind: "quotaReservation",
    quotaId,
    planId,
    subscriptionId,
    meterId,
    quantity: "6",
    status: "reserved",
    operation: "quota.reserve",
    idempotencyKey: "quota-key-1",
    requestHash: "d".repeat(64),
    expiresAt: "2030-01-20T00:00:00.000Z",
    settledQuantity: null,
    settledAt: null,
    releasedAt: null,
    terminalOperation: null,
    terminalIdempotencyKey: null,
    terminalRequestHash: null,
    version: 1,
    createdAt: timestamp,
    updatedAt: timestamp,
    ...overrides,
  };
}

function aggregate(overrides: Partial<UsageAggregate> = {}): UsageAggregate {
  return {
    id: aggregateId,
    tenantId,
    kind: "usageAggregate",
    aggregateKey,
    subscriptionId,
    meterId,
    aggregation: "sum",
    quantity: "1",
    unit: "request",
    periodStart,
    periodEnd,
    dimensions: { region: "cn" },
    eventIds: [],
    status: "collecting",
    version: 1,
    createdAt: timestamp,
    updatedAt: timestamp,
    ...overrides,
  };
}

function aggregateRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: aggregateId,
    tenantId,
    kind: "usageAggregate",
    aggregateKey,
    subscriptionId,
    meterId,
    aggregation: "sum",
    quantity: "1",
    unit: "request",
    periodStart,
    periodEnd,
    dimensions: { region: "cn" },
    eventIds: [],
    status: "collecting",
    version: 1,
    createdAt: timestamp,
    updatedAt: timestamp,
    ...overrides,
  };
}

function usageEvent(overrides: Partial<UsageEvent> = {}): UsageEvent {
  return {
    id: usageEventId,
    tenantId,
    kind: "usageEvent",
    version: 1,
    sourceEventId: "source-1",
    subscriptionId,
    meterId,
    quantity: "1.25",
    occurredAt: "2030-01-15T00:00:00.000Z",
    periodStart,
    periodEnd,
    dimensions: { region: "cn" },
    idempotencyKey: "usage-key-1",
    requestHash: "a".repeat(64),
    payloadHash: "b".repeat(64),
    receivedAt: timestamp,
    ...overrides,
  };
}

function usageEventRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: usageEventId,
    tenantId,
    kind: "usageEvent",
    version: 1,
    sourceEventId: "source-1",
    subscriptionId,
    meterId,
    quantity: "1.25",
    occurredAt: "2030-01-15T00:00:00.000Z",
    periodStart,
    periodEnd,
    dimensions: { region: "cn" },
    idempotencyKey: "usage-key-1",
    requestHash: "a".repeat(64),
    payloadHash: "b".repeat(64),
    receivedAt: timestamp,
    ...overrides,
  };
}

function invoice(overrides: Partial<Invoice> = {}): Invoice {
  return {
    id: invoiceId,
    tenantId,
    kind: "invoice",
    version: 1,
    subscriptionId,
    planId,
    periodStart,
    periodEnd,
    status: "draft",
    currency: "CNY",
    taxMode: "exclusive",
    lines: [],
    subtotal: { amountMinor: 0, currency: "CNY" },
    tax: { amountMinor: 0, currency: "CNY" },
    total: { amountMinor: 0, currency: "CNY" },
    idempotencyKey: "invoice-key-1",
    requestHash: "c".repeat(64),
    createdAt: timestamp,
    updatedAt: timestamp,
    ...overrides,
  };
}

function invoiceRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: invoiceId,
    tenantId,
    kind: "invoice",
    version: 1,
    subscriptionId,
    planId,
    periodStart,
    periodEnd,
    status: "draft",
    currency: "CNY",
    taxMode: "exclusive",
    subtotalMinor: 0,
    taxMinor: 0,
    totalMinor: 0,
    idempotencyKey: "invoice-key-1",
    requestHash: "c".repeat(64),
    mainlandChina: null,
    finalizedAt: null,
    paidAt: null,
    voidedAt: null,
    createdAt: timestamp,
    updatedAt: timestamp,
    ...overrides,
  };
}

function commissionRule(overrides: Partial<CommissionRule> = {}): CommissionRule {
  return {
    id: ruleId,
    tenantId,
    kind: "commissionRule",
    partnerAccountId: partnerId,
    listingId,
    name: "Default commission",
    status: "draft",
    rateBps: 1000,
    priority: 0,
    effectiveFrom: periodStart,
    version: 1,
    createdAt: timestamp,
    updatedAt: timestamp,
    ...overrides,
  };
}

function dispute(overrides: Partial<InvoiceDispute> = {}): InvoiceDispute {
  return {
    id: disputeId,
    tenantId,
    kind: "invoiceDispute",
    version: 1,
    event: "invoice.dispute.opened",
    invoiceId,
    subscriptionId,
    planId,
    invoiceStatus: "awaitingPayment",
    invoiceVersion: 3,
    reason: disputeReason,
    reasonDigest: "d".repeat(64),
    reasonLength: disputeReason.length,
    evidenceReference: disputeEvidence,
    evidenceReferenceDigest: "e".repeat(64),
    evidenceCount: 1,
    actorId: "actor-dispute",
    requestId: "request-dispute",
    idempotencyKey: "dispute-key-1",
    requestHash: "f".repeat(64),
    status: "open",
    createdAt: timestamp,
    updatedAt: timestamp,
    recordedAt: timestamp,
    ...overrides,
  };
}

function disputeRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: disputeId,
    tenantId,
    kind: "invoiceDispute",
    version: 1,
    event: "invoice.dispute.opened",
    invoiceId,
    subscriptionId,
    planId,
    invoiceStatus: "awaitingPayment",
    invoiceVersion: 3,
    reason: disputeReason,
    reasonDigest: "d".repeat(64),
    reasonLength: disputeReason.length,
    evidenceReference: disputeEvidence,
    evidenceReferenceDigest: "e".repeat(64),
    evidenceCount: 1,
    actorId: "actor-dispute",
    requestId: "request-dispute",
    idempotencyKey: "dispute-key-1",
    requestHash: "f".repeat(64),
    status: "open",
    resolutionOutcome: null,
    resolutionActorId: null,
    resolutionReference: null,
    resolutionNote: null,
    resolutionNoteLength: null,
    resolutionFromStatus: null,
    resolvedAt: null,
    createdAt: timestamp,
    updatedAt: timestamp,
    recordedAt: timestamp,
    ...overrides,
  };
}

describe("open platform commerce SQL persistence", () => {
  it("creates an independent commerce schema with exact numeric money and RLS", () => {
    const sql = createOpenCommerceMigrationSql({ mode: "shared", tenantId });
    for (const table of Object.values(COMMERCE_FOUNDATION_SQL_TABLES)) expect(sql).toContain(`\"${table}\"`);
    expect(sql).toContain("NUMERIC(38,18)");
    expect(sql).toContain("BIGINT");
    expect(sql).toContain("FORCE ROW LEVEL SECURITY");
    expect(sql).toContain("current_setting('app.tenant_id', true)");
    expect(sql).toContain("gb_open_commerce_usage_event is append-only");
    expect(sql).toContain("gb_open_commerce_invoice is append-only");
    expect(sql).toContain("commission_rule financial fields are immutable");
    expect(sql).toContain("idempotency_uq");
    expect(sql).not.toMatch(/\b(?:REAL|DOUBLE PRECISION|FLOAT)\b/u);
    expect(sql).not.toContain("gb_idaas_");
  });

  it("appends an invoice dispute table without changing migration versions one or two", () => {
    const disputeTable = COMMERCE_SQL_TABLES.invoiceDisputes;
    expect(disputeTable).toBe("gb_open_commerce_invoice_dispute");
    const foundation = getOpenCommerceMigrationDefinition({ mode: "shared", tenantId });
    const idempotency = getOpenCommerceIdempotencyMigrationDefinition({ mode: "shared", tenantId });
    const disputeMigration = getOpenCommerceInvoiceDisputeMigrationDefinition({ mode: "shared", tenantId });
    expect(foundation.version).toBe(1);
    expect(foundation.sql).not.toContain(disputeTable);
    expect(idempotency.version).toBe(2);
    expect(idempotency.sql).not.toContain(disputeTable);
    expect(disputeMigration.version).toBe(3);
    expect(disputeMigration.additive).toBe(true);
    expect(disputeMigration.requires).toEqual([2]);
    expect(getOpenCommerceMigrations({ mode: "shared", tenantId }).map((entry) => entry.version))
      .toEqual([1, 2, 3, 4]);
    expect(createOpenCommerceIdempotencyMigrationSql({ mode: "shared", tenantId }))
      .not.toContain(disputeTable);
    const sql = createOpenCommerceInvoiceDisputeMigrationSql({ mode: "shared", tenantId });
    expect(sql).toContain(`CREATE TABLE IF NOT EXISTS \"${disputeTable}\"`);
    expect(sql).toContain("PRIMARY KEY (\"tenant_id\", \"id\")");
    expect(sql).toContain("CREATE UNIQUE INDEX IF NOT EXISTS");
    expect(sql).toContain("ON \"gb_open_commerce_invoice_dispute\" (\"tenant_id\", \"invoice_id\", \"idempotency_key\")");
    expect(sql).toContain("ON \"gb_open_commerce_invoice_dispute\" (\"tenant_id\", \"invoice_id\", \"created_at\", \"id\")");
    expect(sql).toContain("ON \"gb_open_commerce_invoice_dispute\" (\"tenant_id\", \"actor_id\", \"created_at\")");
    expect(sql).toContain("ON \"gb_open_commerce_invoice_dispute\" (\"tenant_id\", \"status\", \"created_at\")");
    expect(sql).toContain("ON \"gb_open_commerce_invoice_dispute\" (\"tenant_id\", \"idempotency_key\", \"created_at\")");
    expect(sql).toContain("gb_open_commerce_invoice_dispute is append-only");
    expect(sql).toContain("FORCE ROW LEVEL SECURITY");
    expect(sql).toContain("current_setting('app.tenant_id', true)");
    expect(sql).toContain("FOREIGN KEY (\"tenant_id\", \"invoice_id\")");
    expect(sql).toContain("gb_open_commerce_reject_invoice_dispute_mutation");
    expect(sql).toContain("CHECK (char_length(\"reason\") BETWEEN 1 AND 500 AND \"reason\" !~ '[0-9]{8,}')");
    expect(sql).toContain("CHECK ((\"status\" IN ('open', 'underReview')");
    expect(sql).toContain("\"request_hash\" TEXT NOT NULL CHECK (\"request_hash\" ~ '^[a-f0-9]{64}$')");
    expect(sql).not.toMatch(/\b(?:REAL|DOUBLE PRECISION|FLOAT)\b/u);
    expect(sql).not.toContain("gb_idaas_");
    expect(sql).not.toContain("gb_open_commerce_schema_migration");
  });

  it("appends dispute evidence once and replays the same idempotency key", async () => {
    let insertCount = 0;
    const adapter = fakeAdapter((text, values) => {
      if (text.startsWith("INSERT INTO \"gb_open_commerce_invoice_dispute\"")) {
        insertCount += 1;
        return insertCount === 1 ? { rowCount: 1, rows: [disputeRow()] } : { rowCount: 0, rows: [] };
      }
      if (text.includes("FROM \"gb_open_commerce_invoice_dispute\"")) {
        const row = disputeRow();
        if (row.tenantId !== values[0]) return { rows: [] };
        const statusFilter = /"status" = \$(\d+)/u.exec(text);
        if (statusFilter !== null && row.status !== values[Number(statusFilter[1]) - 1]) {
          return { rows: [] };
        }
        if (text.includes('("id" = $2 OR "idempotency_key" = $3)')) {
          return { rows: row.id === values[1] || row.idempotencyKey === values[2] ? [row] : [] };
        }
        if (text.includes('"id" = $2')) return { rows: row.id === values[1] ? [row] : [] };
        if (text.includes('"idempotency_key" = $2')) {
          if (row.idempotencyKey !== values[1]) return { rows: [] };
          if (text.includes('"invoice_id" = $3') && row.invoiceId !== values[2]) return { rows: [] };
          return { rows: [row] };
        }
        return { rows: [row] };
      }
      return { rows: [] };
    });
    const disputes = new SqlInvoiceDisputeRepository(new CommerceSqlRuntime({ adapter, tenantId }));
    const first = await disputes.append(dispute());
    expect(first).toMatchObject({ accepted: true, dispute: { id: disputeId, status: "open" } });
    const replay = await disputes.append(dispute({
      id: "invoice-dispute_00000000-0000-4000-8000-000000000002",
    }));
    expect(replay).toMatchObject({ accepted: false, dispute: { id: disputeId } });
    expect(insertCount).toBe(2);
    const insert = adapter.calls.find((call) => call.text.startsWith("INSERT INTO \"gb_open_commerce_invoice_dispute\""));
    expect(insert?.text).toContain("ON CONFLICT DO NOTHING");
    expect(insert?.values.slice(0, 2)).toEqual([disputeId, tenantId]);
    expect(insert?.values).toContain(disputeReason);
    expect(insert?.values).toContain("dispute-key-1");
    expect(insert?.values).toContain("actor-dispute");
    expect(insert?.values).toContain("request-dispute");
    expect(JSON.stringify(insert?.values)).not.toContain("6222021234567890123");
    await expect(disputes.findByIdempotency(tenantId, "dispute-key-1")).resolves.toMatchObject({ id: disputeId });
    await expect(disputes.findByIdempotency(tenantId, "dispute-key-1", { invoiceId })).resolves.toMatchObject({ id: disputeId });
    await expect(disputes.findByIdempotency(tenantId, "dispute-key-1", { invoiceId: "invoice_00000000-0000-4000-8000-000000000009" })).resolves.toBeUndefined();
    await expect(disputes.get(tenantId, disputeId)).resolves.toMatchObject({ id: disputeId, evidenceCount: 1 });
    await expect(disputes.list(tenantId, { invoiceId, status: "open" })).resolves.toMatchObject([{ id: disputeId }]);
    await expect(disputes.list(tenantId, { status: "rejected" })).resolves.toEqual([]);
    expect(adapter.calls.some((call) => call.text.includes('\"status\" = $3'))).toBe(true);
  });

  it("adds dispute adjudication columns, indexes, and forced row level security in version four", () => {
    const disputeTable = COMMERCE_SQL_TABLES.invoiceDisputes;
    const dispute = getOpenCommerceInvoiceDisputeMigrationDefinition({ mode: "shared", tenantId });
    const decision = getOpenCommerceInvoiceDisputeDecisionMigrationDefinition({ mode: "shared", tenantId });
    expect(dispute.version).toBe(3);
    expect(decision.version).toBe(4);
    expect(decision.additive).toBe(true);
    expect(decision.requires).toEqual([3]);
    expect(dispute.sql).not.toContain("resolution_note");
    expect(dispute.sql).not.toContain("updated_at");
    const sql = createOpenCommerceInvoiceDisputeDecisionMigrationSql({ mode: "shared", tenantId });
    expect(sql).toContain(`ALTER TABLE "${disputeTable}" ADD COLUMN IF NOT EXISTS "updated_at" TIMESTAMPTZ`);
    expect(sql).toContain(`UPDATE "${disputeTable}" SET "updated_at" = "recorded_at" WHERE "updated_at" IS NULL`);
    expect(sql).toContain(`ALTER TABLE "${disputeTable}" ALTER COLUMN "updated_at" SET NOT NULL`);
    expect(sql).toContain(`ADD COLUMN IF NOT EXISTS "resolution_note" TEXT`);
    expect(sql).toContain(`ADD COLUMN IF NOT EXISTS "resolution_note_length" INTEGER`);
    expect(sql).toContain(`ADD COLUMN IF NOT EXISTS "resolution_from_status" TEXT`);
    expect(sql).toContain("char_length(\"resolution_note\") BETWEEN 1 AND 500");
    expect(sql).toContain(`"resolution_note" !~ '[[:cntrl:]]'`);
    expect(sql).toContain(`"resolution_note" !~ '[0-9]{8,}'`);
    expect(sql).toContain("DROP CONSTRAINT IF EXISTS \"gb_open_commerce_invoice_dispute_version_check\"");
    expect(sql).toContain("ADD CONSTRAINT \"gb_open_commerce_invoice_dispute_version_check\" CHECK (\"version\" > 0)");
    expect(sql).toContain(`"updated_at" >= "created_at"`);
    expect(sql).toContain(`"resolution_note_length" = char_length("resolution_note")`);
    expect(sql).toContain("ADD CONSTRAINT \"gb_open_commerce_invoice_dispute_updated_at_check\"");
    expect(sql).toContain("ADD CONSTRAINT \"gb_open_commerce_invoice_dispute_resolution_note_check\"");
    expect(sql).toContain("ON \"gb_open_commerce_invoice_dispute\" (\"tenant_id\", \"status\", \"updated_at\", \"id\")");
    expect(sql).toContain("ON \"gb_open_commerce_invoice_dispute\" (\"tenant_id\", \"resolution_outcome\", \"resolved_at\")");
    expect(sql).toContain("gb_open_commerce_enforce_invoice_dispute_immutability");
    expect(sql).toContain("DROP TRIGGER IF EXISTS \"gb_open_commerce_in_append_only\"");
    expect(sql).toContain("CREATE TRIGGER \"gb_open_commerce_invo_immutable\" BEFORE UPDATE OR DELETE");
    expect(sql).toContain("gb_open_commerce_invoice_dispute evidence is immutable");
    expect(sql).not.toContain("gb_open_commerce_invoice_dispute is append-only");
    expect(sql).toContain("FORCE ROW LEVEL SECURITY");
    expect(sql).toContain("current_setting('app.tenant_id', true)");
    expect(sql).not.toContain("CREATE TABLE");
    expect(sql).not.toMatch(/\b(?:REAL|DOUBLE PRECISION|FLOAT)\b/u);
    expect(sql).not.toContain("gb_idaas_");
    expect(sql).not.toContain("gb_open_commerce_schema_migration");
    const guarded = createOpenCommerceInvoiceDisputeDecisionMigrationSql({
      mode: "shared",
      tenantId,
      requireRls: true,
    });
    expect(guarded).toContain("FORCE ROW LEVEL SECURITY");
    expect(() => getOpenCommerceInvoiceDisputeDecisionMigrationDefinition({
      mode: "shared",
      tenantId,
      disputeDecisionMigrationVersion: 3,
    })).toThrowError(TypeError);
  });

  it("keeps the dispute version check compatible with adjudication rows", () => {
    const decision = getOpenCommerceInvoiceDisputeDecisionMigrationDefinition({ mode: "shared", tenantId });
    const immutable = decision.sql
      .split(";\n")
      .filter((statement) => statement.includes("IS DISTINCT FROM OLD"));
    expect(immutable).toHaveLength(1);
    const trigger = immutable[0] ?? "";
    for (const column of [
      '"tenant_id"',
      '"id"',
      '"kind"',
      '"event"',
      '"invoice_id"',
      '"reason"',
      '"reason_digest"',
      '"evidence_reference"',
      '"actor_id"',
      '"idempotency_key"',
      '"request_hash"',
      '"created_at"',
      '"recorded_at"',
    ]) {
      expect(trigger, column).toContain(`NEW.${column} IS DISTINCT FROM OLD.${column}`);
    }
    for (const column of ['"status"', '"resolution_outcome"', '"resolved_at"', '"updated_at"', '"version"']) {
      expect(trigger.split(";\n")[0] ?? "").not.toContain(`NEW.${column} IS DISTINCT FROM OLD.${column}`);
    }
  });

  it("writes a dispute decision with a parameterized optimistic update", async () => {
    let stored = disputeRow();
    const adapter = fakeAdapter((text, values) => {
      if (text.startsWith("UPDATE \"gb_open_commerce_invoice_dispute\"")) {
        if (values[2] !== stored.version) return { rowCount: 0, rows: [] };
        stored = disputeRow({
          version: Number(values[2]) + 1,
          status: String(values[3]),
          updatedAt: "2030-01-02T00:00:00.000Z",
        });
        return { rowCount: 1, rows: [stored] };
      }
      if (text.includes("FOR UPDATE")) {
        return values[0] === tenantId && values[1] === disputeId
          ? { rows: [stored] }
          : { rows: [] };
      }
      return { rows: [] };
    });
    const disputes = new SqlInvoiceDisputeRepository(new CommerceSqlRuntime({ adapter, tenantId }));
    const decided = await disputes.decide(tenantId, disputeId, {
      targetStatus: "underReview",
      expectedVersion: 1,
      decidedBy: "actor-adjudicator",
      decidedAt: "2030-01-02T00:00:00.000Z",
    });
    expect(decided).toMatchObject({ id: disputeId, status: "underReview", version: 2 });
    const update = adapter.calls.find((call) => call.text.startsWith("UPDATE \"gb_open_commerce_invoice_dispute\""));
    expect(update?.text).toContain("SET \"status\" = $4");
    expect(update?.text).toContain(`WHERE "tenant_id" = $1 AND "id" = $2 AND "version" = $3`);
    expect(update?.text).toContain("RETURNING");
    expect(update?.values).toEqual([
      tenantId,
      disputeId,
      1,
      "underReview",
      null,
      "actor-adjudicator",
      null,
      null,
      null,
      null,
      "2030-01-02T00:00:00.000Z",
      2,
    ]);
    await expect(disputes.decide(tenantId, disputeId, {
      targetStatus: "rejected",
      expectedVersion: 1,
      decidedBy: "actor-adjudicator",
      decidedAt: "2030-01-02T00:00:00.000Z",
      reference: "resolution://case-0001",
    })).rejects.toMatchObject({
      code: "OPEN_PLATFORM_COMMERCE_RESOURCE_CONFLICT",
    });
    await expect(disputes.decide(tenantId, "invoice-dispute_00000000-0000-4000-8000-0000000000ff", {
      targetStatus: "underReview",
      expectedVersion: 1,
      decidedBy: "actor-adjudicator",
      decidedAt: "2030-01-02T00:00:00.000Z",
    })).rejects.toMatchObject({
      code: "OPEN_PLATFORM_COMMERCE_RESOURCE_NOT_FOUND",
    });
    await expect(disputes.decide(otherTenantId, disputeId, {
      targetStatus: "underReview",
      expectedVersion: 1,
      decidedBy: "actor-adjudicator",
      decidedAt: "2030-01-02T00:00:00.000Z",
    })).rejects.toMatchObject({
      code: "OPEN_PLATFORM_COMMERCE_VALIDATION_ERROR",
    });
    await expect(disputes.decide(tenantId, disputeId, {
      targetStatus: "unknown" as never,
      expectedVersion: 1,
      decidedBy: "actor-adjudicator",
      decidedAt: "2030-01-02T00:00:00.000Z",
    })).rejects.toMatchObject({
      code: "OPEN_PLATFORM_COMMERCE_VALIDATION_ERROR",
    });
    await expect(disputes.decide(tenantId, disputeId, {
      targetStatus: "accepted",
      expectedVersion: 1,
      decidedBy: "actor-adjudicator",
      decidedAt: "2030-01-02T00:00:00.000Z",
    })).rejects.toMatchObject({
      code: "OPEN_PLATFORM_COMMERCE_VALIDATION_ERROR",
    });
    await expect(disputes.decide(tenantId, disputeId, {
      targetStatus: "underReview",
      expectedVersion: 1,
      decidedBy: "actor-adjudicator",
      decidedAt: "2030-01-02T00:00:00.000Z",
      resolutionNote: "Refund to bank account 6222021234567890123",
    })).rejects.toMatchObject({
      code: "OPEN_PLATFORM_COMMERCE_VALIDATION_ERROR",
    });
  });

  it("rejects cross-tenant and sensitive dispute evidence before issuing SQL", async () => {
    const adapter = fakeAdapter(() => ({ rows: [] }));
    const disputes = new SqlInvoiceDisputeRepository(new CommerceSqlRuntime({ adapter, tenantId }));
    await expect(disputes.append(dispute({ tenantId: otherTenantId }))).rejects.toMatchObject({
      code: "OPEN_PLATFORM_COMMERCE_VALIDATION_ERROR",
    });
    await expect(disputes.get(otherTenantId, disputeId)).rejects.toMatchObject({
      code: "OPEN_PLATFORM_COMMERCE_VALIDATION_ERROR",
    });
    await expect(disputes.list(otherTenantId)).rejects.toMatchObject({
      code: "OPEN_PLATFORM_COMMERCE_VALIDATION_ERROR",
    });
    await expect(disputes.findByIdempotency(otherTenantId, "dispute-key-1")).rejects.toMatchObject({
      code: "OPEN_PLATFORM_COMMERCE_VALIDATION_ERROR",
    });
    await expect(disputes.append(dispute({
      reason: "Refund to bank account 6222021234567890123 was never received",
    }))).rejects.toMatchObject({ code: "OPEN_PLATFORM_COMMERCE_VALIDATION_ERROR" });
    await expect(disputes.append(dispute({
      evidenceReference: "6222021234567890123",
    }))).rejects.toMatchObject({ code: "OPEN_PLATFORM_COMMERCE_VALIDATION_ERROR" });
    await expect(disputes.append(dispute({
      reason: "Invoice charge not recognized",
      reasonLength: 4,
    }))).rejects.toMatchObject({ code: "OPEN_PLATFORM_COMMERCE_VALIDATION_ERROR" });
    await expect(disputes.append(dispute({
      reasonDigest: "not-a-digest",
    }))).rejects.toMatchObject({ code: "OPEN_PLATFORM_COMMERCE_VALIDATION_ERROR" });
    await expect(disputes.append(dispute({ status: "accepted" }))).rejects.toMatchObject({
      code: "OPEN_PLATFORM_COMMERCE_VALIDATION_ERROR",
    });
    expect(adapter.calls).toHaveLength(0);
  });

  it("keeps readiness persistent, distributed, and tenant-context aware", async () => {
    const adapter = fakeAdapter((text, values) => {
      if (text.includes("pg_roles")) return { rows: [{ superuser: false, bypassRls: false }] };
      if (text.includes("pg_policies")) {
        const table = String(values[0] ?? "gb_open_commerce_plan");
        return { rows: [expectedPolicyRow(table)] };
      }
      if (text.includes("pg_class")) return { rows: [{ rls: true, forceRls: true }] };
      return { rows: [] };
    });
    const repositories = createSqlCommerceRepositories({ adapter, mode: "shared", tenantId });
    expect(repositories.readiness).toMatchObject({ storage: "persistent", distributed: true });
    await expect(repositories.isReady()).resolves.toBe(true);
    expect(adapter.calls.some((call) => call.text.includes("set_config('app.tenant_id'"))).toBe(true);
    expect(repositories.invoiceLines).toBeDefined();
    expect(repositories.plans).toBeInstanceOf(SqlPlanRepository);
  });

  it("rejects shared tenant mode in production and allows only an explicit override", async () => {
    const adapter = fakeAdapter(() => ({ rows: [] }));
    expect(() => createSqlCommerceRepositories({ adapter, mode: "shared", tenantId, production: true })).toThrow(/shared tenant mode is experimental/iu);
    expect(() => createSqlCommerceRepositories({ adapter, mode: "shared", tenantId, production: true, productionReady: true })).not.toThrow();
    const development = createSqlCommerceRepositories({ adapter, mode: "shared", tenantId });
    await expect(development.productionReady()).resolves.toBe(false);
    expect(() => development.assertProductionDependencies()).toThrow(/shared tenant mode is experimental/iu);
    expect(() => createSqlCommerceRepositories({ adapter, mode: "shared", tenantId })).not.toThrow();
  });

  it("rejects RLS policy bypasses and non-tenant predicates", async () => {
    const adapter = fakeAdapter((text, values) => {
      if (text.includes("pg_roles")) return { rows: [{ superuser: false, bypassRls: false }] };
      if (text.includes("pg_policies")) {
        const table = String(values[0] ?? "gb_open_commerce_plan");
        return {
          rows: [
            expectedPolicyRow(table),
            { policyName: "gb_open_commerce_bypass", permissive: "PERMISSIVE", qual: "true", withCheck: "true", roles: ["public"] },
          ],
        };
      }
      if (text.includes("pg_class")) return { rows: [{ rls: true, forceRls: true }] };
      return { rows: [] };
    });
    const repositories = createSqlCommerceRepositories({ adapter, mode: "shared", tenantId });
    await expect(repositories.isReady()).resolves.toBe(false);

    const incompleteAdapter = fakeAdapter((text, values) => {
      if (text.includes("pg_roles")) return { rows: [{ superuser: false, bypassRls: false }] };
      if (text.includes("pg_policies")) {
        const table = String(values[0] ?? "gb_open_commerce_plan");
        return { rows: [expectedPolicyRow(table, { qual: "tenant_id IS NOT NULL", withCheck: "tenant_id IS NOT NULL" })] };
      }
      if (text.includes("pg_class")) return { rows: [{ rls: true, forceRls: true }] };
      return { rows: [] };
    });
    const incomplete = createSqlCommerceRepositories({ adapter: incompleteAdapter, mode: "shared", tenantId });
    await expect(incomplete.isReady()).resolves.toBe(false);
  });

  it("rejects every cross-tenant invoice entry point before issuing SQL", async () => {
    const adapter = fakeAdapter(() => ({ rows: [] }));
    const invoices = new SqlInvoiceRepository(new CommerceSqlRuntime({ adapter, tenantId }));
    const crossTenantInvoice = invoice({ tenantId: otherTenantId });
    await expect(invoices.createIdempotent({
      tenantId: otherTenantId,
      idempotencyKey: crossTenantInvoice.idempotencyKey,
      requestHash: crossTenantInvoice.requestHash,
      invoice: crossTenantInvoice,
    })).rejects.toMatchObject({ code: "OPEN_PLATFORM_COMMERCE_VALIDATION_ERROR" });
    await expect(invoices.get(otherTenantId, invoiceId)).rejects.toMatchObject({ code: "OPEN_PLATFORM_COMMERCE_VALIDATION_ERROR" });
    await expect(invoices.list(otherTenantId)).rejects.toMatchObject({ code: "OPEN_PLATFORM_COMMERCE_VALIDATION_ERROR" });
    await expect(invoices.transition(otherTenantId, invoiceId, "reconciling", timestamp)).rejects.toMatchObject({ code: "OPEN_PLATFORM_COMMERCE_VALIDATION_ERROR" });
    await expect(invoices.getLines(otherTenantId, invoiceId)).rejects.toMatchObject({ code: "OPEN_PLATFORM_COMMERCE_VALIDATION_ERROR" });
    expect(adapter.calls).toHaveLength(0);
  });

  it("rejects direct cumulative saves and routes usage aggregate updates through an atomic method", async () => {
    const currentQuota = quotaRow();
    const quotaAdapter = fakeAdapter((text) => {
      if (text.startsWith("UPDATE \"gb_open_commerce_quota\"")) return { rowCount: 1, rows: [currentQuota] };
      if (text.includes("FROM \"gb_open_commerce_quota\"")) return { rows: [currentQuota] };
      return { rows: [] };
    });
    const quotas = new SqlQuotaRepository(new CommerceSqlRuntime({ adapter: quotaAdapter, tenantId }));
    await expect(quotas.save(quota({ reserved: "1", version: 2 }))).rejects.toMatchObject({
      code: "OPEN_PLATFORM_COMMERCE_RESOURCE_CONFLICT",
    });
    expect(quotaAdapter.calls.some((call) => call.text.startsWith("UPDATE \"gb_open_commerce_quota\""))).toBe(false);

    let currentAggregate = aggregateRow();
    const aggregateAdapter = fakeAdapter((text) => {
      if (text.startsWith("UPDATE \"gb_open_commerce_usage_aggregate\"")) {
        currentAggregate = aggregateRow({ quantity: "2", version: 2 });
        return { rowCount: 1, rows: [currentAggregate] };
      }
      if (text.includes("FROM \"gb_open_commerce_usage_aggregate\"")) return { rows: [currentAggregate] };
      return { rows: [] };
    });
    const aggregates = new SqlUsageAggregateRepository(new CommerceSqlRuntime({ adapter: aggregateAdapter, tenantId }));
    await expect(aggregates.save(aggregate({ quantity: "2", version: 2 }))).rejects.toMatchObject({
      code: "OPEN_PLATFORM_COMMERCE_RESOURCE_CONFLICT",
    });
    expect(aggregateAdapter.calls.some((call) => call.text.startsWith("UPDATE \"gb_open_commerce_usage_aggregate\""))).toBe(false);
    await expect(aggregates.saveAggregateAtomic(aggregate({ quantity: "2", version: 2 }))).resolves.toMatchObject({ quantity: "2", version: 2 });
    const atomicUpdate = aggregateAdapter.calls.find((call) => call.text.startsWith("UPDATE \"gb_open_commerce_usage_aggregate\""));
    expect(atomicUpdate?.text).toContain('"quantity" = $5::numeric');
    expect(atomicUpdate?.values[4]).toBe("2");
  });

  it("parameterizes tenant scope and uses version/status CAS for plan writes", async () => {
    let current = planRow();
    const adapter = fakeAdapter((text) => {
      if (text.startsWith("INSERT INTO \"gb_open_commerce_plan\"")) return { rowCount: 1, rows: [current] };
      if (text.startsWith("UPDATE \"gb_open_commerce_plan\"")) return { rowCount: 0, rows: [] };
      if (text.includes("FROM \"gb_open_commerce_plan\"")) return { rows: [current] };
      return { rows: [] };
    });
    const repository = new SqlPlanRepository(new CommerceSqlRuntime({ adapter, tenantId }));
    await expect(repository.create(plan())).resolves.toMatchObject({ id: planId });
    await expect(repository.save(plan({ status: "active", version: 2 }))).rejects.toMatchObject({
      code: "OPEN_PLATFORM_COMMERCE_RESOURCE_CONFLICT",
    });
    const update = adapter.calls.find((call) => call.text.startsWith("UPDATE \"gb_open_commerce_plan\""));
    expect(update?.text).toContain('"tenant_id" = $1');
    expect(update?.text).toContain('"version" = $3');
    expect(update?.text).toContain('"status" = $4');
    expect(update?.values.slice(0, 4)).toEqual([tenantId, planId, 1, "draft"]);
    await expect(repository.get(otherTenantId, planId)).resolves.toBeUndefined();
    const get = adapter.calls.at(-1);
    expect(get?.values[0]).toBe(otherTenantId);
  });

  it("stores decimal quantities and integer cents without floating parameters", async () => {
    const adapter = fakeAdapter((text) => {
      if (text.startsWith("INSERT INTO \"gb_open_commerce_price\"")) return { rowCount: 1, rows: [priceRow()] };
      return { rows: [] };
    });
    const repository = new SqlPriceRepository(new CommerceSqlRuntime({ adapter, tenantId }));
    await expect(repository.create(price())).resolves.toMatchObject({
      id: priceId,
      includedUnits: "0.25",
      unitAmount: { amountMinor: 10, currency: "CNY" },
    });
    const insert = adapter.calls.find((call) => call.text.startsWith("INSERT INTO \"gb_open_commerce_price\""));
    expect(insert?.values).toContain("0.25");
    expect(insert?.values).toContain(10);
    expect(insert?.values.some((value) => typeof value === "number" && !Number.isSafeInteger(value))).toBe(false);
    expect(insert?.text).not.toMatch(/\b(?:REAL|DOUBLE PRECISION|FLOAT)\b/u);
  });

  it("replays usage idempotently and keeps invoice facts append-only", async () => {
    const usageCalls: Call[] = [];
    const usageAdapter = fakeAdapter((text) => {
      usageCalls.push({ text, values: [] });
      if (text.startsWith("INSERT INTO \"gb_open_commerce_usage_event\"")) {
        if (usageCalls.filter((call) => call.text.startsWith("INSERT INTO \"gb_open_commerce_usage_event\"")).length === 1) {
          return { rowCount: 1, rows: [usageEventRow()] };
        }
        return { rowCount: 0, rows: [] };
      }
      if (text.includes("FROM \"gb_open_commerce_usage_event\"")) return { rows: [usageEventRow()] };
      return { rows: [] };
    });
    const usage = new SqlUsageEventRepository(new CommerceSqlRuntime({ adapter: usageAdapter, tenantId }));
    const first = await usage.append(usageEvent());
    const replay = await usage.append(usageEvent({ id: "usage-event_00000000-0000-4000-8000-000000000002" }));
    expect(first).toMatchObject({ accepted: true });
    expect(replay).toMatchObject({ accepted: false, event: { id: usageEventId } });
    expect(usageCalls.some((call) => call.text.includes("ON CONFLICT DO NOTHING"))).toBe(true);

    let invoiceInsertCount = 0;
    const invoiceAdapter = fakeAdapter((text) => {
      if (text.startsWith("INSERT INTO \"gb_open_commerce_invoice\" (")) {
        invoiceInsertCount += 1;
        return invoiceInsertCount === 1
          ? { rowCount: 1, rows: [invoiceRow()] }
          : { rowCount: 0, rows: [] };
      }
      if (text.includes("INSERT INTO \"gb_open_commerce_invoice_status_event\"")) return { rowCount: 1, rows: [] };
      if (text.includes("FROM \"gb_open_commerce_invoice\"")) return { rows: [invoiceRow()] };
      if (text.includes("FROM \"gb_open_commerce_invoice_status_event\"")) return { rows: [] };
      if (text.includes("FROM \"gb_open_commerce_invoice_line\"")) return { rows: [] };
      return { rows: [] };
    });
    const invoices = new SqlInvoiceRepository(new CommerceSqlRuntime({ adapter: invoiceAdapter, tenantId }));
    const created = await invoices.createIdempotent({
      tenantId,
      idempotencyKey: invoice().idempotencyKey,
      requestHash: invoice().requestHash,
      invoice: invoice(),
    });
    const replayed = await invoices.createIdempotent({
      tenantId,
      idempotencyKey: invoice().idempotencyKey,
      requestHash: invoice().requestHash,
      invoice: invoice(),
    });
    expect(created.replayed).toBe(false);
    expect(replayed).toMatchObject({ replayed: true, invoice: { id: invoiceId } });
    const transitioned = await invoices.transition(tenantId, invoiceId, "reconciling", timestamp);
    expect(transitioned).toMatchObject({ status: "reconciling", version: 2 });
    expect(invoiceAdapter.calls.some((call) => call.text.startsWith("UPDATE \"gb_open_commerce_invoice\""))).toBe(false);
    expect(invoiceAdapter.calls.some((call) => call.text.includes("INSERT INTO \"gb_open_commerce_invoice_status_event\""))).toBe(true);
  });

  it("executes quota reservation and terminal operations transactionally", async () => {
    let quotaState = quotaRow();
    let reservationState: Record<string, unknown> | undefined;
    const adapter = fakeAdapter((text, values) => {
      if (text.startsWith("SELECT") && text.includes("FROM \"gb_open_commerce_quota_reservation\"")) {
        if (text.includes("\"idempotency_key\" =")) {
          return { rows: reservationState !== undefined && values[3] === "quota-key-1" ? [reservationState] : [] };
        }
        return { rows: reservationState === undefined ? [] : [reservationState] };
      }
      if (text.startsWith("INSERT INTO \"gb_open_commerce_quota_reservation\"")) {
        reservationState = reservationRow();
        return { rowCount: 1, rows: [reservationState] };
      }
      if (text.startsWith("SELECT") && text.includes("FROM \"gb_open_commerce_quota\"")) return { rows: [quotaState] };
      if (text.startsWith("UPDATE \"gb_open_commerce_quota\"")) {
        quotaState = quotaRow({
          reserved: values.length > 4 ? "0" : String(values[2]),
          consumed: values.length > 4 ? String(values[3]) : "0",
          version: Number(quotaState.version) + 1,
          updatedAt: String(values[values.length - 1]),
        });
        return { rowCount: 1, rows: [quotaState] };
      }
      if (text.startsWith("UPDATE \"gb_open_commerce_quota_reservation\"")) {
        reservationState = reservationRow({ status: "settled", settledQuantity: "4", settledAt: "2030-01-16T00:00:00.000Z", terminalOperation: "quota.settle", terminalIdempotencyKey: "quota-terminal-1", terminalRequestHash: "e".repeat(64), version: 2, updatedAt: "2030-01-16T00:00:00.000Z" });
        return { rowCount: 1, rows: [reservationState] };
      }
      return { rows: [] };
    });
    const repository = new SqlQuotaRepository(new CommerceSqlRuntime({ adapter, tenantId }));
    const reserved = await repository.reserveAtomic({
      tenantId,
      operation: "quota.reserve",
      quotaId,
      reservation: reservation(),
    });
    expect(reserved).toMatchObject({ replayed: false, quota: { reserved: "6" } });
    await expect(repository.reserveAtomic({
      tenantId,
      operation: "quota.reserve",
      quotaId,
      reservation: reservation(),
    })).resolves.toMatchObject({ replayed: true });
    const settled = await repository.settleAtomic({
      tenantId,
      operation: "quota.settle",
      quotaId,
      reservationId,
      actualQuantity: "4",
      requestHash: "e".repeat(64),
      settledAt: "2030-01-16T00:00:00.000Z",
      idempotencyKey: "quota-terminal-1",
    });
    expect(settled).toMatchObject({ replayed: false, quota: { reserved: "0", consumed: "4" }, reservation: { status: "settled" } });
    await expect(repository.settleAtomic({
      tenantId,
      operation: "quota.settle",
      quotaId,
      reservationId,
      actualQuantity: "4",
      requestHash: "e".repeat(64),
      settledAt: "2030-01-16T00:00:00.000Z",
      idempotencyKey: "quota-terminal-1",
    })).resolves.toMatchObject({ replayed: true, reservation: { status: "settled" } });
    const quotaUpdate = adapter.calls.find((call) => call.text.startsWith("UPDATE \"gb_open_commerce_quota\""));
    expect(quotaUpdate?.values[2]).toBe("6");
  });

  it("rejects commission term mutation while allowing status CAS", async () => {
    const current = {
      id: ruleId,
      tenantId,
      kind: "commissionRule",
      partnerAccountId: partnerId,
      listingId,
      name: "Default commission",
      status: "draft",
      rateBps: 1000,
      capBps: null,
      capAmountMinor: null,
      currency: "CNY",
      priority: 0,
      effectiveFrom: periodStart,
      effectiveTo: null,
      version: 1,
      createdAt: timestamp,
      updatedAt: timestamp,
    };
    const adapter = fakeAdapter((text) => {
      if (text.includes("FROM \"gb_open_commerce_commission_rule\"")) return { rows: [current] };
      if (text.startsWith("UPDATE \"gb_open_commerce_commission_rule\"")) return { rowCount: 1, rows: [{ ...current, status: "active", version: 2 }] };
      return { rows: [] };
    });
    const repository = new SqlCommissionRuleRepository(new CommerceSqlRuntime({ adapter, tenantId }));
    await expect(repository.save(commissionRule({ rateBps: 2000, version: 2 }))).rejects.toMatchObject({
      code: "OPEN_PLATFORM_COMMERCE_RESOURCE_CONFLICT",
    });
    await expect(repository.save(commissionRule({ status: "active", version: 2 }))).resolves.toMatchObject({ status: "active", version: 2 });
    const update = adapter.calls.find((call) => call.text.startsWith("UPDATE \"gb_open_commerce_commission_rule\""));
    expect(update?.text).toContain('"version" = $3');
    expect(update?.text).toContain('"status" = $4');
  });
});
