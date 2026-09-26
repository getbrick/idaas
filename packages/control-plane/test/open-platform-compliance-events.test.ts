import { createHash } from "node:crypto";
import "reflect-metadata";
import { Test } from "@nestjs/testing";
import request from "supertest";
import { describe, expect, it } from "vitest";
import {
  InMemoryOpenPlatformOutbox,
  OPEN_PLATFORM_CROSS_DOMAIN_EVENT_RESOURCE_BINDINGS,
  OpenPlatformComplianceModule,
  OpenPlatformEventPublisher,
  OPEN_PLATFORM_COMPLIANCE_BASE_PATH,
  containsOpenPlatformSensitiveEventData,
  createOpenPlatformRequestContextIssuer,
  type OpenPlatformEventPublisherPort,
  type OpenPlatformHttpRequest,
  type OpenPlatformOutboxPort,
  type OpenPlatformOutboxRecord,
} from "../src/open-platform/index.js";
import {
  COMPLIANCE_AUDIT_ACTIONS,
  COMPLIANCE_ERROR_CODES,
  COMPLIANCE_DOMAIN_EVENT_ID_PREFIX,
  COMPLIANCE_DOMAIN_EVENT_RESOURCE_TYPES,
  COMPLIANCE_DOMAIN_EVENT_TYPES,
  ComplianceDomainService,
  InMemoryComplianceAuditStore,
  InMemoryComplianceEventStore,
  InMemoryComplianceRepositories,
  complianceDomainEventDescriptor,
  complianceDomainEventId,
  createComplianceService,
  type ComplianceDataAsset,
} from "../src/open-platform/compliance/index.js";

const now = new Date("2031-06-01T00:00:00.000Z");
const timestamp = now.toISOString();
const tenantA = "tenant-compliance-events-a";
const tenantB = "tenant-compliance-events-b";
const actor = { type: "user", id: "actor-compliance" } as const;
const subjectRef = "subject-9f2c4a71";
const assetName = "客户主数据资产";
const consentPurpose = "marketing-analytics";
const vendorLegalName = "示例数据处理者有限公司";
const decisionRationale = "已完成数据核对并确认删除范围";
const evidenceReference = "doc://compliance/evidence/2031-06.pdf";
const identityEvidence = "sys://idv/verification/2031-06";

interface Harness {
  readonly service: ComplianceDomainService;
  readonly outbox: OpenPlatformOutboxPort;
  readonly repositories: InMemoryComplianceRepositories;
  readonly audit: InMemoryComplianceAuditStore;
  readonly events: InMemoryComplianceEventStore;
}

function createHarness(
  options: {
    readonly production?: boolean;
    readonly eventsEnabled?: boolean;
    readonly publisher?: OpenPlatformEventPublisherPort;
  } = {},
): Harness {
  const repositories = new InMemoryComplianceRepositories();
  const outbox = new InMemoryOpenPlatformOutbox({ clock: () => now });
  const audit = new InMemoryComplianceAuditStore({ clock: () => now });
  const events = new InMemoryComplianceEventStore();
  const service = createComplianceService({
    repositories,
    audit,
    events,
    clock: () => now,
    ...(options.production === undefined ? {} : { production: options.production }),
    eventPublisher: options.publisher ?? new OpenPlatformEventPublisher({
      outbox,
      clock: () => now,
    }),
    eventsEnabled: options.eventsEnabled ?? true,
  });
  return { service, outbox, repositories, audit, events };
}

async function listEvents(
  outbox: OpenPlatformOutboxPort,
  tenantId: string,
): Promise<readonly OpenPlatformOutboxRecord[]> {
  return (await outbox.list({ tenantId, limit: 200 })).items;
}

function eventNames(records: readonly OpenPlatformOutboxRecord[]): string[] {
  return records.map((record) => record.eventType);
}

function complianceIssuer() {
  return createOpenPlatformRequestContextIssuer({
    issuerId: "compliance-events-tests",
    attestation: Object.freeze({ test: true }),
    clock: () => now,
  });
}

function complianceResolver(targetTenantId: string) {
  return (httpRequest: OpenPlatformHttpRequest) => ({
    tenantId: targetTenantId,
    actorId: actor.id,
    requestId: "compliance-request",
  });
}

async function createComplianceApp(
  options: {
    readonly publisher: OpenPlatformEventPublisherPort;
    readonly eventsEnabled?: boolean;
  },
) {
  const moduleRef = await Test.createTestingModule({
    imports: [
      OpenPlatformComplianceModule.forRoot({
        mode: "test",
        contextIssuer: complianceIssuer(),
        resolver: complianceResolver(tenantA),
        eventPublisher: options.publisher,
        ...(options.eventsEnabled === undefined
          ? {}
          : { eventsEnabled: options.eventsEnabled }),
      }),
    ],
  }).compile();
  const app = moduleRef.createNestApplication();
  await app.init();
  return app;
}

function dataAssetFixture(
  overrides: Partial<ComplianceDataAsset> = {},
): ComplianceDataAsset {
  return {
    id: "data-asset_2f1a9c34-0b7e-4c1a-9a55-1b0f5f3f7a11",
    tenantId: tenantA,
    kind: "dataAsset",
    version: 1,
    name: assetName,
    code: "asset-fixture",
    status: "draft",
    classification: "personal",
    categories: ["identity", "contact"],
    personalData: true,
    sensitivePersonalData: false,
    legalBasis: "consent",
    purposes: ["service-delivery"],
    dataSubjects: ["customer"],
    residencyRegions: ["CN"],
    retentionDays: 180,
    crossBorder: false,
    evidence: [{ reference: evidenceReference, kind: "document" }],
    createdAt: timestamp,
    updatedAt: timestamp,
    ...overrides,
  };
}

async function seedDataAsset(
  service: ComplianceDomainService,
  tenantId: string,
  code: string,
  idempotencyKey?: string,
): Promise<ComplianceDataAsset> {
  return service.createDataAsset({
    tenantId,
    name: assetName,
    code,
    classification: "personal",
    categories: ["identity", "contact"],
    personalData: true,
    sensitivePersonalData: false,
    legalBasis: "consent",
    purposes: ["service-delivery", consentPurpose],
    dataSubjects: ["customer"],
    residencyRegions: ["CN"],
    retentionDays: 180,
    crossBorder: false,
    evidence: [{ reference: evidenceReference, kind: "document" }],
    actor,
    requestId: "compliance-request",
    ...(idempotencyKey === undefined ? {} : { idempotencyKey }),
  });
}

describe("open platform compliance domain event identifiers", () => {
  it("derives the deterministic event id from the core operation scope", () => {
    const scope = {
      tenantId: "tenant-compliance-events",
      actorId: "actor-compliance",
      operation: "dataAsset.create",
      idempotencyKey: "asset-create",
    };
    const digest = createHash("sha256")
      .update(
        [
          scope.tenantId,
          scope.actorId,
          scope.operation,
          scope.idempotencyKey,
        ].join("\u0000"),
        "utf8",
      )
      .digest("hex")
      .slice(0, 32);
    expect(complianceDomainEventId(scope)).toBe(
      `${COMPLIANCE_DOMAIN_EVENT_ID_PREFIX}${digest}`,
    );
    expect(complianceDomainEventId(scope)).toBe(complianceDomainEventId({ ...scope }));
    expect(complianceDomainEventId({ ...scope, idempotencyKey: "other" })).not.toBe(
      complianceDomainEventId(scope),
    );
    expect(complianceDomainEventId({ ...scope, tenantId: "tenant-other" })).not.toBe(
      complianceDomainEventId(scope),
    );
  });

  it("only uses registered compliance event names and outbox resource types", () => {
    for (const eventType of Object.values(COMPLIANCE_DOMAIN_EVENT_TYPES)) {
      expect(eventType).toMatch(/^compliance_[a-z_]+\.[a-z_]+$/u);
      expect(
        OPEN_PLATFORM_CROSS_DOMAIN_EVENT_RESOURCE_BINDINGS[
          eventType.slice(0, eventType.indexOf(".")) as keyof typeof OPEN_PLATFORM_CROSS_DOMAIN_EVENT_RESOURCE_BINDINGS
        ],
      ).toBeDefined();
    }
    expect(new Set(Object.values(COMPLIANCE_DOMAIN_EVENT_RESOURCE_TYPES))).toEqual(
      new Set([
        "dataAsset",
        "consentRecord",
        "privacyRequest",
        "retentionPolicy",
        "crossBorderAssessment",
        "vendor",
      ]),
    );
  });

  it("describes data asset writes with operational metadata only", () => {
    const record = dataAssetFixture();
    expect(
      complianceDomainEventDescriptor({ action: "dataAsset.create", record }),
    ).toMatchObject({
      eventType: COMPLIANCE_DOMAIN_EVENT_TYPES.dataAssetCreated,
      resourceType: COMPLIANCE_DOMAIN_EVENT_RESOURCE_TYPES.dataAsset,
      resourceId: record.id,
      resourceVersion: 1,
      resourceStatus: "draft",
      data: {
        operation: "dataAsset.create",
        status: "draft",
        classification: "personal",
        personalData: true,
        sensitivePersonalData: false,
        crossBorder: false,
        residencyRegions: ["CN"],
        residencyRegionCount: 1,
        dataSubjectGroupCount: 1,
        categoryCount: 2,
        purposeCount: 1,
        hasRetention: true,
        retentionDays: 180,
      },
    });
    expect(
      complianceDomainEventDescriptor({ action: "dataAsset.transition", record })?.eventType,
    ).toBe(COMPLIANCE_DOMAIN_EVENT_TYPES.dataAssetUpdated);
    expect(
      complianceDomainEventDescriptor({
        action: "dataAsset.transition",
        record,
        transition: { fromStatus: "draft", toStatus: "registered" },
      }),
    ).toMatchObject({
      eventType: COMPLIANCE_DOMAIN_EVENT_TYPES.dataAssetStatusChanged,
      data: {
        fromStatus: "draft",
        toStatus: "registered",
        status: "draft",
      },
    });
  });

  it("skips writes without a registered domain event without throwing", () => {
    const record = dataAssetFixture();
    expect(
      complianceDomainEventDescriptor({ action: "dataAsset.retire", record }),
    ).toBeUndefined();
    expect(
      complianceDomainEventDescriptor({
        action: "report.generate",
        record,
      }),
    ).toBeUndefined();
    expect(
      complianceDomainEventDescriptor({
        action: "dataAsset.create",
        record: { ...record, id: "数据资产" },
      }),
    ).toBeUndefined();
  });
});

describe("open platform compliance domain event publishing", () => {
  it("publishes the expected event name and resource type for every key write", async () => {
    const harness = createHarness();
    const service = harness.service;
    const asset = await seedDataAsset(service, tenantA, "asset-events");
    await service.updateDataAsset({
      tenantId: tenantA,
      id: asset.id,
      residencyRegions: ["CN", "SG"],
      actor,
      requestId: "compliance-request",
    });
    await service.transitionDataAsset({
      tenantId: tenantA,
      id: asset.id,
      targetStatus: "registered",
      actor,
      requestId: "compliance-request",
    });
    await service.transitionDataAsset({
      tenantId: tenantA,
      id: asset.id,
      targetStatus: "active",
      actor,
      requestId: "compliance-request",
    });

    const consent = await service.createConsentRecord({
      tenantId: tenantA,
      subjectRef,
      subjectCount: 12,
      purpose: consentPurpose,
      policyVersion: "2026-04",
      channel: "web",
      scopes: ["profile.read"],
      actor,
      requestId: "compliance-request",
    });
    await service.grantConsent({
      tenantId: tenantA,
      id: consent.id,
      proof: [{ reference: evidenceReference, kind: "document" }],
      actor,
      requestId: "compliance-request",
    });
    await service.withdrawConsent({
      tenantId: tenantA,
      id: consent.id,
      reason: "数据主体主动撤回",
      actor,
      requestId: "compliance-request",
    });
    const expiring = await service.createConsentRecord({
      tenantId: tenantA,
      subjectRef: "subject-3b81de07",
      purpose: consentPurpose,
      policyVersion: "2026-04",
      channel: "app",
      actor,
      requestId: "compliance-request",
    });
    await service.grantConsent({
      tenantId: tenantA,
      id: expiring.id,
      proof: [{ reference: identityEvidence, kind: "systemRecord" }],
      actor,
      requestId: "compliance-request",
    });
    await service.expireConsent({
      tenantId: tenantA,
      id: expiring.id,
      actor,
      requestId: "compliance-request",
    });

    const request = await service.createPrivacyRequest({
      tenantId: tenantA,
      requestType: "deletion",
      subjectRef,
      subjectCount: 3,
      receivedAt: timestamp,
      responseDays: 30,
      actor,
      requestId: "compliance-request",
    });
    await service.transitionPrivacyRequest({
      tenantId: tenantA,
      id: request.id,
      targetStatus: "verifyingIdentity",
      actor,
      requestId: "compliance-request",
    });
    await service.recordIdentityVerification({
      tenantId: tenantA,
      id: request.id,
      status: "verified",
      method: "reauthentication",
      evidence: [{ reference: identityEvidence, kind: "systemRecord" }],
      actor,
      requestId: "compliance-request",
    });
    await service.transitionPrivacyRequest({
      tenantId: tenantA,
      id: request.id,
      targetStatus: "verified",
      actor,
      requestId: "compliance-request",
    });
    await service.decidePrivacyRequest({
      tenantId: tenantA,
      id: request.id,
      decision: "granted",
      rationale: decisionRationale,
      evidence: [{ reference: evidenceReference, kind: "document" }],
      actor,
      requestId: "compliance-request",
    });
    await service.recordPrivacyRequestAction({
      tenantId: tenantA,
      id: request.id,
      action: "erased",
      dataAssetId: asset.id,
      affectedRecords: 4,
      actor,
      requestId: "compliance-request",
    });
    await service.transitionPrivacyRequest({
      tenantId: tenantA,
      id: request.id,
      targetStatus: "fulfilled",
      actor,
      requestId: "compliance-request",
    });

    const policy = await service.createRetentionPolicy({
      tenantId: tenantA,
      name: "营销画像留存策略",
      code: "retention-events",
      trigger: "time",
      action: "delete",
      retentionDays: 365,
      requiresApproval: false,
      legalHold: false,
      dataAssetIds: [asset.id],
      evidence: [{ reference: evidenceReference, kind: "document" }],
      actor,
      requestId: "compliance-request",
    });
    await service.transitionRetentionPolicy({
      tenantId: tenantA,
      id: policy.id,
      targetStatus: "active",
      actor,
      requestId: "compliance-request",
    });
    await service.recordRetentionExecution({
      tenantId: tenantA,
      policyId: policy.id,
      status: "completed",
      recordsScanned: 120,
      recordsDeleted: 40,
      recordsAnonymized: 0,
      recordsArchived: 0,
      actor,
      requestId: "compliance-request",
    });

    const assessment = await service.createCrossBorderAssessment({
      tenantId: tenantA,
      title: "新加坡数据出境评估",
      code: "cross-border-events",
      sourceRegion: "CN",
      destinationRegions: ["SG"],
      transferPurpose: "为海外提供订阅结算服务",
      dataAssetIds: [asset.id],
      personalData: true,
      riskLevel: "medium",
      mechanisms: ["standardContract"],
      evidence: [{ reference: evidenceReference, kind: "document" }],
      actor,
      requestId: "compliance-request",
    });
    await service.transitionCrossBorderAssessment({
      tenantId: tenantA,
      id: assessment.id,
      targetStatus: "assessing",
      actor,
      requestId: "compliance-request",
    });
    await service.transitionCrossBorderAssessment({
      tenantId: tenantA,
      id: assessment.id,
      targetStatus: "pendingApproval",
      actor,
      requestId: "compliance-request",
    });
    await service.transitionCrossBorderAssessment({
      tenantId: tenantA,
      id: assessment.id,
      targetStatus: "approved",
      validUntil: "2032-06-01T00:00:00.000Z",
      actor,
      requestId: "compliance-request",
    });

    const vendor = await service.createVendor({
      tenantId: tenantA,
      role: "processor",
      code: "vendor-events",
      legalName: vendorLegalName,
      regions: ["CN", "SG"],
      dataAssetIds: [asset.id],
      dataCategories: ["identity"],
      crossBorder: true,
      evidence: [{ reference: evidenceReference, kind: "document" }],
      actor,
      requestId: "compliance-request",
    });
    await service.transitionVendor({
      tenantId: tenantA,
      id: vendor.id,
      targetStatus: "pendingAssessment",
      actor,
      requestId: "compliance-request",
    });
    await service.recordVendorAssessment({
      tenantId: tenantA,
      id: vendor.id,
      status: "passed",
      evidence: [{ reference: evidenceReference, kind: "document" }],
      actor,
      requestId: "compliance-request",
    });
    await service.transitionVendor({
      tenantId: tenantA,
      id: vendor.id,
      targetStatus: "active",
      actor,
      requestId: "compliance-request",
    });

    const events = await listEvents(harness.outbox, tenantA);
    expect(events.every((event) => event.tenantId === tenantA)).toBe(true);
    expect(eventNames(events)).toEqual([
      COMPLIANCE_DOMAIN_EVENT_TYPES.dataAssetCreated,
      COMPLIANCE_DOMAIN_EVENT_TYPES.dataAssetUpdated,
      COMPLIANCE_DOMAIN_EVENT_TYPES.dataAssetStatusChanged,
      COMPLIANCE_DOMAIN_EVENT_TYPES.dataAssetStatusChanged,
      COMPLIANCE_DOMAIN_EVENT_TYPES.consentRecordCreated,
      COMPLIANCE_DOMAIN_EVENT_TYPES.consentRecordGranted,
      COMPLIANCE_DOMAIN_EVENT_TYPES.consentRecordWithdrawn,
      COMPLIANCE_DOMAIN_EVENT_TYPES.consentRecordCreated,
      COMPLIANCE_DOMAIN_EVENT_TYPES.consentRecordGranted,
      COMPLIANCE_DOMAIN_EVENT_TYPES.consentRecordStatusChanged,
      COMPLIANCE_DOMAIN_EVENT_TYPES.privacyRequestCreated,
      COMPLIANCE_DOMAIN_EVENT_TYPES.privacyRequestStatusChanged,
      COMPLIANCE_DOMAIN_EVENT_TYPES.privacyRequestVerified,
      COMPLIANCE_DOMAIN_EVENT_TYPES.privacyRequestStatusChanged,
      COMPLIANCE_DOMAIN_EVENT_TYPES.privacyRequestDecided,
      COMPLIANCE_DOMAIN_EVENT_TYPES.privacyRequestStatusChanged,
      COMPLIANCE_DOMAIN_EVENT_TYPES.retentionPolicyCreated,
      COMPLIANCE_DOMAIN_EVENT_TYPES.retentionPolicyStatusChanged,
      COMPLIANCE_DOMAIN_EVENT_TYPES.retentionPolicyExecuted,
      COMPLIANCE_DOMAIN_EVENT_TYPES.crossBorderAssessmentCreated,
      COMPLIANCE_DOMAIN_EVENT_TYPES.crossBorderAssessmentStatusChanged,
      COMPLIANCE_DOMAIN_EVENT_TYPES.crossBorderAssessmentStatusChanged,
      COMPLIANCE_DOMAIN_EVENT_TYPES.crossBorderAssessmentDecided,
      COMPLIANCE_DOMAIN_EVENT_TYPES.vendorCreated,
      COMPLIANCE_DOMAIN_EVENT_TYPES.vendorStatusChanged,
      COMPLIANCE_DOMAIN_EVENT_TYPES.vendorUpdated,
      COMPLIANCE_DOMAIN_EVENT_TYPES.vendorStatusChanged,
    ]);
    expect(events.map((event) => event.resourceType)).toEqual([
      "dataAsset",
      "dataAsset",
      "dataAsset",
      "dataAsset",
      "consentRecord",
      "consentRecord",
      "consentRecord",
      "consentRecord",
      "consentRecord",
      "consentRecord",
      "privacyRequest",
      "privacyRequest",
      "privacyRequest",
      "privacyRequest",
      "privacyRequest",
      "privacyRequest",
      "retentionPolicy",
      "retentionPolicy",
      "retentionPolicy",
      "crossBorderAssessment",
      "crossBorderAssessment",
      "crossBorderAssessment",
      "crossBorderAssessment",
      "vendor",
      "vendor",
      "vendor",
      "vendor",
    ]);
    const created = events.find(
      (event) => event.eventType === COMPLIANCE_DOMAIN_EVENT_TYPES.dataAssetCreated,
    );
    expect(created).toMatchObject({
      resourceId: asset.id,
      resourceVersion: 1,
      resourceStatus: "draft",
      actorId: actor.id,
      requestId: "compliance-request",
      status: "published",
    });
    const executed = events.find(
      (event) => event.eventType === COMPLIANCE_DOMAIN_EVENT_TYPES.retentionPolicyExecuted,
    );
    expect(executed).toMatchObject({
      resourceType: COMPLIANCE_DOMAIN_EVENT_RESOURCE_TYPES.retentionPolicy,
      resourceId: policy.id,
      resourceStatus: "active",
      data: { retentionAction: "delete", recordsDeleted: 40, recordsScanned: 120 },
    });
    const granted = events.find(
      (event) => event.eventType === COMPLIANCE_DOMAIN_EVENT_TYPES.consentRecordGranted,
    );
    expect(granted?.data).toMatchObject({
      channel: "web",
      subjectCount: 12,
      scopeCount: 1,
      granted: true,
      withdrawn: false,
    });
    const verified = events.find(
      (event) => event.eventType === COMPLIANCE_DOMAIN_EVENT_TYPES.privacyRequestVerified,
    );
    expect(verified?.data).toMatchObject({
      requestType: "deletion",
      identityVerificationStatus: "verified",
      identityVerificationAttempts: 1,
      identityVerificationMethod: "reauthentication",
      slaState: "withinSla",
      responseDays: 30,
      decided: false,
    });
    const decided = events.find(
      (event) => event.eventType === COMPLIANCE_DOMAIN_EVENT_TYPES.privacyRequestDecided,
    );
    expect(decided?.data).toMatchObject({
      decision: "granted",
      status: "inProgress",
      fromStatus: "verified",
    });
    const vendorUpdated = events.find(
      (event) => event.eventType === COMPLIANCE_DOMAIN_EVENT_TYPES.vendorUpdated,
    );
    expect(vendorUpdated).toMatchObject({
      resourceId: vendor.id,
      resourceStatus: "pendingAssessment",
      data: { role: "processor", assessmentStatus: "passed", regionCount: 2 },
    });
    expect(events.every((event) => event.status === "published")).toBe(true);
    expect(new Set(events.map((event) => event.eventId)).size).toBe(events.length);
  });

  it("keeps one outbox record per idempotency key and replays the same event id", async () => {
    const harness = createHarness();
    const service = harness.service;
    const first = await seedDataAsset(service, tenantA, "asset-replay-a", "replay-asset");
    const second = await seedDataAsset(service, tenantA, "asset-replay-b", "replay-asset");
    expect(second.id).not.toBe(first.id);
    const events = await listEvents(harness.outbox, tenantA);
    expect(events).toHaveLength(1);
    expect(events[0]?.eventId).toBe(
      complianceDomainEventId({
        tenantId: tenantA,
        actorId: actor.id,
        operation: "dataAsset.create",
        idempotencyKey: "replay-asset",
      }),
    );
    expect(events[0]?.eventId.startsWith(COMPLIANCE_DOMAIN_EVENT_ID_PREFIX)).toBe(true);
    await seedDataAsset(service, tenantA, "asset-replay-c", "replay-other");
    expect(await listEvents(harness.outbox, tenantA)).toHaveLength(2);
  });

  it("never exposes sensitive compliance data in event payloads", async () => {
    const harness = createHarness();
    const service = harness.service;
    const asset = await seedDataAsset(service, tenantA, "asset-redaction");
    await service.transitionDataAsset({
      tenantId: tenantA,
      id: asset.id,
      targetStatus: "registered",
      actor,
      requestId: "compliance-request",
    });
    const consent = await service.createConsentRecord({
      tenantId: tenantA,
      subjectRef,
      purpose: consentPurpose,
      policyVersion: "2026-04",
      channel: "web",
      proof: [{ reference: evidenceReference, kind: "document" }],
      actor,
      requestId: "compliance-request",
    });
    await service.grantConsent({
      tenantId: tenantA,
      id: consent.id,
      proof: [{ reference: evidenceReference, kind: "document" }],
      actor,
      requestId: "compliance-request",
    });
    const request = await service.createPrivacyRequest({
      tenantId: tenantA,
      requestType: "access",
      subjectRef,
      dataAssetIds: [asset.id],
      receivedAt: timestamp,
      actor,
      requestId: "compliance-request",
    });
    await service.transitionPrivacyRequest({
      tenantId: tenantA,
      id: request.id,
      targetStatus: "verifyingIdentity",
      actor,
      requestId: "compliance-request",
    });
    await service.recordIdentityVerification({
      tenantId: tenantA,
      id: request.id,
      status: "verified",
      method: "documentReview",
      evidence: [{ reference: identityEvidence, kind: "systemRecord" }],
      verifiedByRef: subjectRef,
      actor,
      requestId: "compliance-request",
    });
    await service.transitionPrivacyRequest({
      tenantId: tenantA,
      id: request.id,
      targetStatus: "verified",
      actor,
      requestId: "compliance-request",
    });
    await service.decidePrivacyRequest({
      tenantId: tenantA,
      id: request.id,
      decision: "denied",
      rationale: decisionRationale,
      evidence: [{ reference: evidenceReference, kind: "document" }],
      actor,
      requestId: "compliance-request",
    });
    await service.createVendor({
      tenantId: tenantA,
      role: "processor",
      code: "vendor-redaction",
      legalName: vendorLegalName,
      displayName: "示例处理者",
      regions: ["CN"],
      dataAssetIds: [asset.id],
      actor,
      requestId: "compliance-request",
    });

    const events = await listEvents(harness.outbox, tenantA);
    expect(events.length).toBeGreaterThan(0);
    const forbidden = [
      subjectRef,
      assetName,
      consentPurpose,
      vendorLegalName,
      decisionRationale,
      evidenceReference,
      identityEvidence,
      "retention-events",
      "cross-border-events",
      "vendor-redaction",
      "asset-redaction",
      "compliance-request",
    ];
    for (const event of events) {
      expect(containsOpenPlatformSensitiveEventData(event.data)).toBe(false);
      const keys = Object.keys(event.data);
      for (const key of keys) {
        expect(key).not.toMatch(
          /(?:email|phone|name|idnumber|idcard|passport|address|notes|note|reason|rationale|proof|evidence|reference|subjectref|verifiedbyref|signature|token|secret|credential)/iu,
        );
      }
      const serialized = JSON.stringify(event.data);
      for (const candidate of forbidden) {
        expect(serialized).not.toContain(candidate);
      }
    }
    const assetCreated = events.find(
      (event) => event.eventType === COMPLIANCE_DOMAIN_EVENT_TYPES.dataAssetCreated,
    );
    expect(assetCreated?.data).toEqual({
      operation: "dataAsset.create",
      status: "draft",
      classification: "personal",
      personalData: true,
      sensitivePersonalData: false,
      crossBorder: false,
      residencyRegions: ["CN"],
      residencyRegionCount: 1,
      dataSubjectGroupCount: 1,
      categoryCount: 2,
      purposeCount: 2,
      hasRetention: true,
      retentionDays: 180,
    });
  });

  it("keeps compliance events isolated per tenant", async () => {
    const harness = createHarness();
    const tenantAAsset = await seedDataAsset(harness.service, tenantA, "asset-isolation");
    const tenantBAsset = await seedDataAsset(harness.service, tenantB, "asset-isolation");
    await harness.service.transitionDataAsset({
      tenantId: tenantA,
      id: tenantAAsset.id,
      targetStatus: "registered",
      actor,
      requestId: "compliance-request",
    });
    await harness.service.transitionDataAsset({
      tenantId: tenantB,
      id: tenantBAsset.id,
      targetStatus: "registered",
      actor,
      requestId: "compliance-request",
    });
    const tenantAEvents = await listEvents(harness.outbox, tenantA);
    const tenantBEvents = await listEvents(harness.outbox, tenantB);
    expect(tenantAEvents).toHaveLength(2);
    expect(tenantBEvents).toHaveLength(2);
    expect(tenantAEvents.every((event) => event.tenantId === tenantA)).toBe(true);
    expect(tenantBEvents.every((event) => event.tenantId === tenantB)).toBe(true);
    const tenantAResourceIds = new Set(tenantAEvents.map((event) => event.resourceId));
    for (const event of tenantBEvents) {
      expect(tenantAResourceIds.has(event.resourceId)).toBe(false);
    }
    expect(
      tenantAEvents.some((event) => tenantBEvents.some((other) => other.eventId === event.eventId)),
    ).toBe(false);
  });

  it("keeps existing behavior when no publisher is injected", async () => {
    const repositories = new InMemoryComplianceRepositories();
    const audit = new InMemoryComplianceAuditStore({ clock: () => now });
    const events = new InMemoryComplianceEventStore();
    const service = createComplianceService({ repositories, audit, events, clock: () => now });
    expect(service.eventPublisher).toBeUndefined();
    expect(service.eventReadiness).toBeUndefined();
    await expect(service.isReady()).resolves.toBe(true);
    const tenantId = "tenant-compliance-no-publisher";
    const asset = await seedDataAsset(service, tenantId, "asset-no-publisher");
    const registered = await service.transitionDataAsset({
      tenantId,
      id: asset.id,
      targetStatus: "registered",
      actor,
      requestId: "compliance-request",
    });
    expect(registered).toMatchObject({ status: "registered", version: 2 });
    const tenantAudit = await service.listAuditEvents(tenantId);
    expect(tenantAudit.map((entry) => entry.action)).toEqual([
      "dataAsset.create",
      "dataAsset.transition",
    ]);
    expect(tenantAudit.every((entry) => entry.outcome === "success")).toBe(true);
    const tenantEvents = await service.listDomainEvents(tenantId);
    expect(tenantEvents).toHaveLength(2);
    expect(await service.verifyEventChain(tenantId)).toBe(true);
  });

  it("rejects an invalid event publisher configuration", () => {
    expect(() =>
      createComplianceService({
        clock: () => now,
        eventPublisher: { record: async () => undefined },
      } as never),
    ).toThrow(/event publisher is invalid/u);
  });

  it("keeps existing behavior when events are not enabled", async () => {
    const harness = createHarness({ eventsEnabled: false });
    const asset = await seedDataAsset(harness.service, tenantA, "asset-disabled");
    await harness.service.transitionDataAsset({
      tenantId: tenantA,
      id: asset.id,
      targetStatus: "registered",
      actor,
      requestId: "compliance-request",
    });
    await expect(listEvents(harness.outbox, tenantA)).resolves.toEqual([]);
    await expect(harness.service.isReady()).resolves.toBe(true);
    expect(harness.audit.list(tenantA).map((entry) => entry.action)).toEqual([
      "dataAsset.create",
      "dataAsset.transition",
    ]);
  });

  it("fails production writes closed and audits the event failure", async () => {
    const harness = createHarness({
      production: true,
      publisher: {
        readiness: { storage: "persistent", distributed: true, ready: () => true },
        record: async () => {
          throw new Error("outbox unavailable");
        },
        publish: async () => ({
          eventId: "unused",
          delivered: 0,
          deadLettered: false,
        }),
      },
    });
    await expect(seedDataAsset(harness.service, tenantA, "asset-production")).rejects.toMatchObject({
      code: COMPLIANCE_ERROR_CODES.STORAGE_UNAVAILABLE,
    });
    const records = harness.audit.list(tenantA);
    expect(records).toHaveLength(2);
    expect(records[1]).toMatchObject({
      tenantId: tenantA,
      action: "dataAsset.create.event",
      outcome: "failure",
      target: { type: "dataAsset" },
      metadata: {
        errorCode: COMPLIANCE_ERROR_CODES.STORAGE_UNAVAILABLE,
        eventType: COMPLIANCE_DOMAIN_EVENT_TYPES.dataAssetCreated,
      },
    });
    expect(COMPLIANCE_AUDIT_ACTIONS).not.toContain("dataAsset.create.event");
    await expect(listEvents(harness.outbox, tenantA)).resolves.toEqual([]);
  });

  it("skips event failures silently outside production", async () => {
    const harness = createHarness({
      publisher: {
        readiness: { storage: "memory", distributed: false, ready: () => true },
        record: async () => {
          throw new Error("outbox unavailable");
        },
        publish: async () => ({
          eventId: "unused",
          delivered: 0,
          deadLettered: false,
        }),
      },
    });
    const asset = await seedDataAsset(harness.service, tenantA, "asset-development");
    expect(asset.status).toBe("draft");
    const registered = await harness.service.transitionDataAsset({
      tenantId: tenantA,
      id: asset.id,
      targetStatus: "registered",
      actor,
      requestId: "compliance-request",
    });
    expect(registered).toMatchObject({ status: "registered", version: 2 });
    expect(harness.audit.list(tenantA).every((entry) => entry.outcome === "success")).toBe(true);
    await expect(listEvents(harness.outbox, tenantA)).resolves.toEqual([]);
  });

  it("reports not ready while an enabled publisher is not ready", async () => {
    const harness = createHarness({
      publisher: {
        readiness: { storage: "memory", distributed: false, ready: () => false },
        record: async () => {
          throw new Error("outbox unavailable");
        },
        publish: async () => ({
          eventId: "unused",
          delivered: 0,
          deadLettered: false,
        }),
      },
    });
    expect(harness.service.eventReadiness).toMatchObject({
      storage: "memory",
      distributed: false,
    });
    await expect(harness.service.eventReadiness?.ready()).resolves.toBe(false);
    await expect(harness.service.isReady()).resolves.toBe(false);
    const asset = await seedDataAsset(harness.service, tenantA, "asset-not-ready");
    expect(asset.status).toBe("draft");
    await expect(listEvents(harness.outbox, tenantA)).resolves.toEqual([]);
  });

  it("replays the same event id over HTTP idempotency without a second outbox record", async () => {
    const outbox = new InMemoryOpenPlatformOutbox({ clock: () => now });
    const publisher = new OpenPlatformEventPublisher({ outbox, clock: () => now });
    const app = await createComplianceApp({ publisher, eventsEnabled: true });
    const server = app.getHttpServer();
    const payload = {
      name: "Replay asset",
      code: "http-replay-asset",
      classification: "internal",
      categories: ["other"],
      personalData: false,
      sensitivePersonalData: false,
      residencyRegions: ["CN"],
      retentionDays: 30,
      crossBorder: false,
    };
    const first = await request(server)
      .post(`${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/data-assets`)
      .set("Idempotency-Key", "http-replay-asset")
      .send(payload);
    const replay = await request(server)
      .post(`${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/data-assets`)
      .set("Idempotency-Key", "http-replay-asset")
      .send(payload);
    expect(first.status).toBe(201);
    expect(replay.status).toBe(201);
    expect(replay.body.id).toBe(first.body.id);
    expect(replay.headers["idempotency-replayed"]).toBe("true");
    const events = await listEvents(outbox, tenantA);
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      eventType: COMPLIANCE_DOMAIN_EVENT_TYPES.dataAssetCreated,
      resourceType: COMPLIANCE_DOMAIN_EVENT_RESOURCE_TYPES.dataAsset,
      resourceId: first.body.id,
      tenantId: tenantA,
      actorId: actor.id,
      requestId: "compliance-request",
    });
    await app.close();
  });

  it("publishes no compliance events over HTTP when the switch stays off", async () => {
    const outbox = new InMemoryOpenPlatformOutbox({ clock: () => now });
    const publisher = new OpenPlatformEventPublisher({ outbox, clock: () => now });
    const app = await createComplianceApp({ publisher });
    const server = app.getHttpServer();
    const created = await request(server)
      .post(`${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/data-assets`)
      .set("Idempotency-Key", "http-disabled-asset")
      .send({
        name: "Disabled asset",
        code: "http-disabled-asset",
        classification: "internal",
        categories: ["other"],
        personalData: false,
        sensitivePersonalData: false,
        residencyRegions: ["CN"],
        retentionDays: 30,
        crossBorder: false,
      });
    expect(created.status).toBe(201);
    await expect(listEvents(outbox, tenantA)).resolves.toEqual([]);
    await app.close();
  });
});
