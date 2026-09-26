import { describe, expect, it } from "vitest";
import {
  COMPLIANCE_ERROR_CODES,
  COMPLIANCE_REDACTED,
  ComplianceDomainService,
  InMemoryComplianceAuditStore,
  InMemoryComplianceEventStore,
  InMemoryComplianceRepositories,
  assertComplianceReportIsRedacted,
  canTransitionConsent,
  canTransitionCrossBorder,
  canTransitionDataAsset,
  canTransitionPrivacyRequest,
  canTransitionRetentionPolicy,
  canTransitionVendor,
  complianceReportContainsSensitiveValue,
  createComplianceService,
  isPersonalDataComplianceField,
  isSensitiveComplianceField,
  redactComplianceText,
  toComplianceAuditMetadata,
  toComplianceConsentRecordDto,
  toComplianceDataAssetDto,
  toComplianceRecordDto,
  type ComplianceConsentRecord,
  type ComplianceCrossBorderAssessment,
  type ComplianceDataAsset,
  type ComplianceEventRecord,
  type CompliancePrivacyRequest,
  type ComplianceRetentionPolicy,
  type ComplianceVendor,
} from "../src/open-platform/compliance/index.js";
import {
  createOpenComplianceMigrationSql,
  getOpenComplianceMigrationChecksum,
} from "../src/open-platform/compliance/persistence/migration.js";

const tenantA = "tenant-alpha";
const tenantB = "tenant-beta";
const startInstant = "2031-03-01T00:00:00.000Z";
const subjectAlpha = "subject-9f2c4a71";
const subjectBeta = "subject-3b81de07";
const rawEmail = "zhangwei.contact@example.com";
const rawPhone = "13800138000";

function createHarness(initial: string = startInstant): {
  service: ComplianceDomainService;
  repositories: InMemoryComplianceRepositories;
  audit: InMemoryComplianceAuditStore;
  events: InMemoryComplianceEventStore;
  setNow: (value: string) => void;
  now: () => string;
} {
  const repositories = new InMemoryComplianceRepositories();
  const audit = new InMemoryComplianceAuditStore();
  const events = new InMemoryComplianceEventStore();
  let current = initial;
  const service = createComplianceService({
    repositories,
    audit,
    events,
    clock: () => new Date(current),
  });
  return {
    service,
    repositories,
    audit,
    events,
    setNow: (value: string) => {
      current = value;
    },
    now: () => current,
  };
}

async function createRetentionPolicy(
  service: ComplianceDomainService,
  tenantId: string,
  overrides: { readonly code?: string; readonly requiresApproval?: boolean } = {},
): Promise<ComplianceRetentionPolicy> {
  return service.createRetentionPolicy({
    tenantId,
    name: "Marketing profile retention",
    code: overrides.code ?? `retention-${tenantId}`,
    trigger: "time",
    action: "delete",
    retentionDays: 365,
    requiresApproval: overrides.requiresApproval ?? false,
    legalHold: false,
    evidence: [
      { reference: `doc://retention/${tenantId}/v1.pdf`, kind: "document" },
    ],
  });
}

async function activateRetentionPolicy(
  service: ComplianceDomainService,
  tenantId: string,
  policy: ComplianceRetentionPolicy,
): Promise<ComplianceRetentionPolicy> {
  return service.transitionRetentionPolicy({
    tenantId,
    id: policy.id,
    targetStatus: "active",
  });
}

async function createActiveDataAsset(
  service: ComplianceDomainService,
  tenantId: string,
  input: {
    readonly code: string;
    readonly retentionPolicyId?: string;
    readonly classification?: ComplianceDataAsset["classification"];
    readonly categories?: readonly ComplianceDataAsset["categories"][number][];
    readonly sensitivePersonalData?: boolean;
    readonly legalBasis?: ComplianceDataAsset["legalBasis"];
    readonly purposes?: readonly string[];
    readonly residencyRegions?: readonly string[];
    readonly crossBorder?: boolean;
  } = { code: "asset-default" },
): Promise<ComplianceDataAsset> {
  const asset = await service.createDataAsset({
    tenantId,
    name: `Asset ${input.code}`,
    code: input.code,
    classification:
      input.classification ??
      ((input.sensitivePersonalData ?? false) ? "sensitivePersonal" : "personal"),
    categories: input.categories ?? ["identity", "contact"],
    personalData: true,
    sensitivePersonalData: input.sensitivePersonalData ?? false,
    legalBasis: input.legalBasis ?? "consent",
    purposes: input.purposes ?? ["service-delivery"],
    dataSubjects: ["customer"],
    residencyRegions: input.residencyRegions ?? ["CN"],
    retentionDays: input.retentionPolicyId === undefined ? 180 : undefined,
    crossBorder: input.crossBorder ?? false,
  });
  await service.transitionDataAsset({
    tenantId,
    id: asset.id,
    targetStatus: "registered",
  });
  return service.transitionDataAsset({
    tenantId,
    id: asset.id,
    targetStatus: "active",
  });
}

async function createVerifiedPrivacyRequest(
  service: ComplianceDomainService,
  tenantId: string,
  input: {
    readonly subjectRef: string;
    readonly requestType?: CompliancePrivacyRequest["requestType"];
    readonly dataAssetId?: string;
    readonly receivedAt: string;
    readonly responseDays?: number;
  },
): Promise<CompliancePrivacyRequest> {
  const request = await service.createPrivacyRequest({
    tenantId,
    requestType: input.requestType ?? "access",
    subjectRef: input.subjectRef,
    ...(input.dataAssetId === undefined
      ? {}
      : { dataAssetIds: [input.dataAssetId] }),
    receivedAt: input.receivedAt,
    ...(input.responseDays === undefined
      ? {}
      : { responseDays: input.responseDays }),
  });
  await service.transitionPrivacyRequest({
    tenantId,
    id: request.id,
    targetStatus: "verifyingIdentity",
  });
  await service.recordIdentityVerification({
    tenantId,
    id: request.id,
    status: "verified",
    method: "reauthentication",
    evidence: [
      { reference: `sys://idv/${request.id}/result`, kind: "systemRecord" },
    ],
  });
  return service.transitionPrivacyRequest({
    tenantId,
    id: request.id,
    targetStatus: "verified",
  });
}

async function createActiveVendor(
  service: ComplianceDomainService,
  tenantId: string,
  input: {
    readonly code: string;
    readonly regions: readonly string[];
    readonly role?: ComplianceVendor["role"];
    readonly parentVendorId?: string;
  },
): Promise<ComplianceVendor> {
  const vendor = await service.createVendor({
    tenantId,
    role: input.role ?? "processor",
    code: input.code,
    legalName: `${input.code} Processing Ltd`,
    regions: input.regions,
    ...(input.parentVendorId === undefined
      ? {}
      : { parentVendorId: input.parentVendorId }),
  });
  const assessed = await service.recordVendorAssessment({
    tenantId,
    id: vendor.id,
    status: "passed",
    assessedByRef: "assessor-ops-1",
    evidence: [
      { reference: `attestation://vendor/${input.code}/2026`, kind: "attestation" },
    ],
  });
  await service.transitionVendor({
    tenantId,
    id: assessed.id,
    targetStatus: "pendingAssessment",
  });
  return service.transitionVendor({
    tenantId,
    id: assessed.id,
    targetStatus: "active",
  });
}

describe("open platform compliance domain", () => {
  it("keeps every compliance aggregate scoped to its tenant", async () => {
    const { service } = createHarness();
    const assetA = await createActiveDataAsset(service, tenantA, { code: "asset-alpha" });
    await createActiveDataAsset(service, tenantB, { code: "asset-beta" });
    const consentA = await service.createConsentRecord({
      tenantId: tenantA,
      subjectRef: subjectAlpha,
      purpose: "marketing-profile",
      policyVersion: "2026-02",
      channel: "web",
      dataAssetIds: [assetA.id],
    });
    await service.createConsentRecord({
      tenantId: tenantB,
      subjectRef: subjectBeta,
      purpose: "marketing-profile",
      policyVersion: "2026-02",
      channel: "web",
    });
    const requestA = await service.createPrivacyRequest({
      tenantId: tenantA,
      requestType: "access",
      subjectRef: subjectAlpha,
      dataAssetIds: [assetA.id],
    });

    expect(await service.getDataAsset(tenantB, assetA.id)).toBeUndefined();
    expect(await service.getConsentRecord(tenantB, consentA.id)).toBeUndefined();
    expect(await service.getPrivacyRequest(tenantB, requestA.id)).toBeUndefined();

    const assetsA = await service.listDataAssets({ tenantId: tenantA });
    const assetsB = await service.listDataAssets({ tenantId: tenantB });
    expect(assetsA.total).toBe(1);
    expect(assetsB.total).toBe(1);
    expect(assetsA.items[0]?.code).toBe("asset-alpha");
    expect(assetsB.items[0]?.code).toBe("asset-beta");

    const consentB = await service.listConsentRecords({ tenantId: tenantB });
    expect(consentB.total).toBe(1);
    expect(consentB.items[0]?.subjectRef).toBe(subjectBeta);

    const reportA = await service.generateComplianceReport({
      tenantId: tenantA,
      from: "2031-01-01T00:00:00.000Z",
      to: "2031-04-01T00:00:00.000Z",
    });
    const reportB = await service.generateComplianceReport({
      tenantId: tenantB,
      from: "2031-01-01T00:00:00.000Z",
      to: "2031-04-01T00:00:00.000Z",
    });
    expect(reportA.tenantId).toBe(tenantA);
    expect(reportB.tenantId).toBe(tenantB);
    expect(reportA.consent.activeSubjects + reportA.consent.withdrawnSubjects).toBe(0);
    expect(reportB.consent.records.total).toBe(1);
    expect(reportA.consent.records.total).toBe(1);

    const eventsA = await service.listDomainEvents(tenantA);
    const eventsB = await service.listDomainEvents(tenantB);
    expect(eventsA.length).toBeGreaterThan(0);
    expect(eventsB.length).toBeGreaterThan(0);
    expect(eventsA.every((event) => event.tenantId === tenantA)).toBe(true);
    expect(eventsB.every((event) => event.tenantId === tenantB)).toBe(true);
    expect(eventsA.map((event) => event.sequence)).toEqual(
      eventsA.map((_event, index) => index + 1),
    );
    const auditA = await service.listAuditEvents(tenantA);
    const auditB = await service.listAuditEvents(tenantB);
    expect(auditA.every((event) => event.tenantId === tenantA)).toBe(true);
    expect(auditB.every((event) => event.tenantId === tenantB)).toBe(true);
    expect(auditB.some((event) => event.target.id === assetA.id)).toBe(false);
    expect(auditA.some((event) => event.target.id === assetA.id)).toBe(true);

    await expect(
      service.createPrivacyRequest({
        tenantId: tenantB,
        requestType: "access",
        subjectRef: subjectBeta,
        dataAssetIds: [assetA.id],
      }),
    ).rejects.toMatchObject({ code: COMPLIANCE_ERROR_CODES.RESOURCE_NOT_FOUND });

    await expect(
      service.transitionDataAsset({
        tenantId: tenantB,
        id: assetA.id,
        targetStatus: "retired",
      }),
    ).rejects.toMatchObject({
      code: COMPLIANCE_ERROR_CODES.RESOURCE_NOT_FOUND,
    });

    await expect(service.getDataAsset(tenantA, assetA.id)).resolves.toMatchObject({
      tenantId: tenantA,
    });
  });

  it("enforces data catalog classification, purpose, and retention invariants", async () => {
    const { service } = createHarness();
    const policy = await createRetentionPolicy(service, tenantA);

    await expect(
      service.createDataAsset({
        tenantId: tenantA,
        name: "Biometric template",
        code: "asset-biometric",
        classification: "personal",
        categories: ["biometric"],
        personalData: true,
        sensitivePersonalData: true,
        legalBasis: "consent",
        residencyRegions: ["CN"],
        crossBorder: false,
      }),
    ).rejects.toMatchObject({
      code: COMPLIANCE_ERROR_CODES.VALIDATION_ERROR,
      details: { field: "classification" },
    });

    await expect(
      service.createDataAsset({
        tenantId: tenantA,
        name: "Risk score",
        code: "asset-risk",
        classification: "sensitivePersonal",
        categories: ["financial"],
        personalData: true,
        sensitivePersonalData: true,
        residencyRegions: ["CN"],
        crossBorder: false,
      }),
    ).rejects.toMatchObject({ code: COMPLIANCE_ERROR_CODES.LEGAL_BASIS_REQUIRED });

    await expect(
      service.createDataAsset({
        tenantId: tenantA,
        name: "Contact list",
        code: "asset-contact",
        classification: "personal",
        categories: ["contact"],
        personalData: true,
        sensitivePersonalData: false,
        legalBasis: "consent",
        residencyRegions: ["CN"],
        crossBorder: false,
        retentionPolicyId: policy.id,
        retentionDays: 30,
      }),
    ).rejects.toMatchObject({
      code: COMPLIANCE_ERROR_CODES.VALIDATION_ERROR,
      details: { field: "retentionPolicyId" },
    });

    await service.createDataAsset({
      tenantId: tenantA,
      name: "Contact list",
      code: "asset-contact",
      classification: "personal",
      categories: ["contact"],
      personalData: true,
      sensitivePersonalData: false,
      legalBasis: "consent",
      residencyRegions: ["CN"],
      crossBorder: false,
    });
    await expect(
      service.createDataAsset({
        tenantId: tenantA,
        name: "Duplicate contact list",
        code: "asset-contact",
        classification: "personal",
        categories: ["contact"],
        personalData: true,
        sensitivePersonalData: false,
        legalBasis: "consent",
        residencyRegions: ["CN"],
        crossBorder: false,
      }),
    ).rejects.toMatchObject({
      code: COMPLIANCE_ERROR_CODES.RESOURCE_CONFLICT,
    });

    const draft = await service.createDataAsset({
      tenantId: tenantA,
      name: "Session telemetry",
      code: "asset-telemetry",
      classification: "internal",
      categories: ["usage"],
      personalData: false,
      sensitivePersonalData: false,
      residencyRegions: ["CN"],
      crossBorder: false,
    });
    await expect(
      service.transitionDataAsset({
        tenantId: tenantA,
        id: draft.id,
        targetStatus: "registered",
      }),
    ).rejects.toMatchObject({
      code: COMPLIANCE_ERROR_CODES.VALIDATION_ERROR,
      details: { field: "purposes" },
    });

    await expect(
      service.createDataAsset({
        tenantId: tenantA,
        name: "Voiceprint template",
        code: "asset-voiceprint",
        classification: "sensitivePersonal",
        categories: ["biometric", "identity"],
        personalData: true,
        sensitivePersonalData: true,
        legalBasis: "explicitConsent" as ComplianceDataAsset["legalBasis"],
        purposes: ["fraud-prevention"],
        dataSubjects: ["customer"],
        residencyRegions: ["CN"],
        retentionPolicyId: policy.id,
        crossBorder: true,
      }),
    ).rejects.toMatchObject({
      code: COMPLIANCE_ERROR_CODES.VALIDATION_ERROR,
      details: { field: "legalBasis" },
    });

    await expect(
      service.createDataAsset({
        tenantId: tenantA,
        name: "Voiceprint template",
        code: "asset-voiceprint-2",
        classification: "sensitivePersonal",
        categories: ["biometric", "identity"],
        personalData: true,
        sensitivePersonalData: true,
        legalBasis: "consent",
        purposes: ["fraud-prevention"],
        dataSubjects: ["customer"],
        residencyRegions: ["CN"],
        retentionPolicyId: policy.id,
        crossBorder: true,
      }),
    ).resolves.toMatchObject({
      classification: "sensitivePersonal",
      sensitivePersonalData: true,
      legalBasis: "consent",
    });
  });

  it("blocks raw personal information at the domain boundary and redacts free text", async () => {
    const { service, audit } = createHarness();

    await expect(
      service.createDataAsset({
        tenantId: tenantA,
        name: `Contact export for ${rawEmail}`,
        code: "asset-email",
        classification: "internal",
        categories: ["usage"],
        personalData: false,
        sensitivePersonalData: false,
        residencyRegions: ["CN"],
        crossBorder: false,
      }),
    ).rejects.toMatchObject({ code: COMPLIANCE_ERROR_CODES.REDACTION_FAILED });

    await expect(
      service.createVendor({
        tenantId: tenantA,
        role: "processor",
        code: "vendor-phone",
        legalName: `Support ${rawPhone}`,
        regions: ["SG"],
      }),
    ).rejects.toMatchObject({ code: COMPLIANCE_ERROR_CODES.REDACTION_FAILED });

    expect(redactComplianceText(`owner ${rawEmail}`)).not.toContain(rawEmail);
    expect(redactComplianceText(`mobile ${rawPhone}`)).not.toContain(rawPhone);
    expect(redactComplianceText("region CN host 10.20.30.40")).toContain(
      COMPLIANCE_REDACTED,
    );
    expect(isSensitiveComplianceField("subjectRef")).toBe(false);
    expect(isSensitiveComplianceField("idToken")).toBe(true);
    expect(isPersonalDataComplianceField("subjectRef")).toBe(true);
    expect(isPersonalDataComplianceField("contactEmail")).toBe(true);
    expect(isPersonalDataComplianceField("dataAssetId")).toBe(false);

    const metadata = toComplianceAuditMetadata({
      subjectRef: subjectAlpha,
      contactEmail: rawEmail,
      resourceId: "data-asset_0b0f5f0e-6c1c-4a2b-8a4a-2f2f0f0c1d2e",
      nested: { authorization: "Bearer abc" },
      note: `escalation owner ${rawEmail}`,
      breached: true,
    });
    expect(Object.keys(metadata).sort()).toEqual([
      "breached",
      "note",
      "resourceId",
    ]);
    expect(metadata.note).not.toContain(rawEmail);
    expect(JSON.stringify(metadata)).not.toContain("Bearer");
    expect(JSON.stringify(metadata)).not.toContain(subjectAlpha);

    const asset = await createActiveDataAsset(service, tenantA, {
      code: "asset-redaction",
    });
    const consent = await service.createConsentRecord({
      tenantId: tenantA,
      subjectRef: subjectAlpha,
      purpose: "marketing-profile",
      policyVersion: "2026-02",
      channel: "web",
      dataAssetIds: [asset.id],
      proof: [
        { reference: `sys://consent/${subjectAlpha}/capture`, kind: "systemRecord" },
      ],
    });
    const dto = toComplianceConsentRecordDto(consent);
    expect(dto.subjectRef).toBe(subjectAlpha);
    expect(() => assertComplianceReportIsRedacted(dto)).not.toThrow();
    expect(toComplianceDataAssetDto(asset).personalData).toBe(true);
    expect(toComplianceRecordDto(consent).kind).toBe("consentRecord");

    const auditRecords = await service.listAuditEvents(tenantA);
    const serializedAudit = JSON.stringify(auditRecords);
    expect(serializedAudit).not.toContain(subjectAlpha);
    expect(serializedAudit).not.toContain(rawEmail);
    expect(serializedAudit).toContain("dataAsset.create");
    expect(audit.readiness.storage).toBe("memory");

    await expect(
      service.createPrivacyRequest({
        tenantId: tenantA,
        requestType: "access",
        subjectRef: "redacted",
      }),
    ).rejects.toMatchObject({ code: COMPLIANCE_ERROR_CODES.VALIDATION_ERROR });
  });

  it("withdraws consent once, keeps the proof trail, and blocks restoration", async () => {
    const { service, setNow } = createHarness();
    const asset = await createActiveDataAsset(service, tenantA, { code: "asset-consent" });
    const consent = await service.createConsentRecord({
      tenantId: tenantA,
      subjectRef: subjectAlpha,
      purpose: "marketing-profile",
      policyVersion: "2026-02",
      channel: "app",
      dataAssetIds: [asset.id],
    });
    expect(consent.status).toBe("pending");

    const granted = await service.grantConsent({
      tenantId: tenantA,
      id: consent.id,
      proof: [
        { reference: "sys://consent/capture/2026-02-01", kind: "systemRecord" },
      ],
    });
    expect(granted.status).toBe("granted");
    expect(granted.grantedAt).toBe(startInstant);
    expect(granted.proof).toHaveLength(1);
    expect(await service.findActiveConsent(tenantA, subjectAlpha, "marketing-profile"))
      .toMatchObject({ id: consent.id, status: "granted" });

    setNow("2031-03-05T00:00:00.000Z");
    const withdrawn = await service.withdrawConsent({
      tenantId: tenantA,
      id: consent.id,
      reason: "user-requested-withdrawal",
      proof: [
        { reference: "sys://consent/withdrawal/2026-03-05", kind: "systemRecord" },
      ],
    });
    expect(withdrawn.status).toBe("withdrawn");
    expect(withdrawn.withdrawnAt).toBe("2031-03-05T00:00:00.000Z");
    expect(withdrawn.withdrawalReason).toBe("user-requested-withdrawal");
    expect(withdrawn.proof).toHaveLength(2);
    expect(withdrawn.version).toBe(3);
    expect(
      await service.findActiveConsent(tenantA, subjectAlpha, "marketing-profile"),
    ).toBeUndefined();

    await expect(
      service.grantConsent({
        tenantId: tenantA,
        id: consent.id,
        proof: [{ reference: "sys://consent/regrant", kind: "systemRecord" }],
      }),
    ).rejects.toMatchObject({
      code: COMPLIANCE_ERROR_CODES.INVALID_STATE_TRANSITION,
    });
    await expect(
      service.withdrawConsent({ tenantId: tenantA, id: consent.id }),
    ).rejects.toMatchObject({
      code: COMPLIANCE_ERROR_CODES.INVALID_STATE_TRANSITION,
    });

    const reconsent = await service.createConsentRecord({
      tenantId: tenantA,
      subjectRef: subjectAlpha,
      purpose: "marketing-profile",
      policyVersion: "2026-03",
      channel: "app",
      dataAssetIds: [asset.id],
    });
    expect(reconsent.id).not.toBe(consent.id);
    expect(reconsent.status).toBe("pending");

    const report = await service.generateComplianceReport({
      tenantId: tenantA,
      from: "2031-01-01T00:00:00.000Z",
      to: "2031-06-01T00:00:00.000Z",
    });
    expect(report.consent.withdrawnSubjects).toBe(1);
    expect(report.consent.withdrawnProofCount).toBe(2);
    expect(
      report.gaps.find((gap) => gap.code === "consentWithdrawnWhileAssetActive")
        ?.resourceIds,
    ).toEqual([consent.id]);
  });

  it("drives privacy requests through identity verification, decisions, and SLA accounting", async () => {
    const { service, setNow } = createHarness();
    const asset = await createActiveDataAsset(service, tenantA, { code: "asset-privacy" });
    const request = await service.createPrivacyRequest({
      tenantId: tenantA,
      requestType: "deletion",
      subjectRef: subjectAlpha,
      dataAssetIds: [asset.id],
      receivedAt: startInstant,
      responseDays: 15,
      policyCode: "cn-baseline-15d",
    });
    expect(request.status).toBe("submitted");
    expect(request.sla.dueAt).toBe("2031-03-16T00:00:00.000Z");
    expect(request.sla.state).toBe("withinSla");
    expect(request.sla.responseDays).toBe(15);
    expect(request.sla.policyCode).toBe("cn-baseline-15d");

    await expect(
      service.transitionPrivacyRequest({
        tenantId: tenantA,
        id: request.id,
        targetStatus: "verified",
      }),
    ).rejects.toMatchObject({
      code: COMPLIANCE_ERROR_CODES.INVALID_STATE_TRANSITION,
    });

    await service.transitionPrivacyRequest({
      tenantId: tenantA,
      id: request.id,
      targetStatus: "verifyingIdentity",
    });
    await expect(
      service.decidePrivacyRequest({
        tenantId: tenantA,
        id: request.id,
        decision: "granted",
        evidence: [{ reference: "sys://decision/premature", kind: "systemRecord" }],
      }),
    ).rejects.toMatchObject({
      code: COMPLIANCE_ERROR_CODES.IDENTITY_VERIFICATION_REQUIRED,
    });

    const failed = await service.recordIdentityVerification({
      tenantId: tenantA,
      id: request.id,
      status: "failed",
    });
    expect(failed.identityVerification.status).toBe("failed");
    expect(failed.identityVerification.attempts).toBe(1);

    setNow("2031-03-02T00:00:00.000Z");
    const verified = await service.recordIdentityVerification({
      tenantId: tenantA,
      id: request.id,
      status: "verified",
      method: "documentReview",
      verifiedByRef: "reviewer-ops-7",
      evidence: [
        { reference: "doc://idv/2026-03-02/result", kind: "document" },
      ],
    });
    expect(verified.identityVerification.status).toBe("verified");
    expect(verified.identityVerification.verifiedAt).toBe("2031-03-02T00:00:00.000Z");
    expect(verified.identityVerification.verifiedByRef).toBe("reviewer-ops-7");
    expect(verified.identityVerification.attempts).toBe(2);

    const ready = await service.transitionPrivacyRequest({
      tenantId: tenantA,
      id: request.id,
      targetStatus: "verified",
    });
    expect(ready.status).toBe("verified");

    setNow("2031-03-14T00:00:00.000Z");
    const dueSoon = await service.evaluatePrivacyRequestSla(tenantA, request.id);
    expect(dueSoon.state).toBe("dueSoon");
    expect(dueSoon.millisecondsRemaining).toBe(2 * 86_400_000);

    setNow("2031-03-18T00:00:00.000Z");
    const breached = await service.evaluatePrivacyRequestSla(tenantA, request.id);
    expect(breached.state).toBe("breached");
    expect(breached.millisecondsRemaining).toBeLessThan(0);

    await expect(
      service.transitionPrivacyRequest({
        tenantId: tenantA,
        id: request.id,
        targetStatus: "fulfilled",
      }),
    ).rejects.toMatchObject({
      code: COMPLIANCE_ERROR_CODES.INVALID_STATE_TRANSITION,
    });

    const inProgress = await service.decidePrivacyRequest({
      tenantId: tenantA,
      id: request.id,
      decision: "granted",
      rationale: "verified data subject request",
      evidence: [{ reference: "ticket://privacy/2031-0318", kind: "ticket" }],
    });
    expect(inProgress.status).toBe("inProgress");
    expect(inProgress.decision?.decision).toBe("granted");
    expect(inProgress.decision?.decidedByRef).toBe("compliance-service");

    const executed = await service.recordPrivacyRequestAction({
      tenantId: tenantA,
      id: request.id,
      action: "erased",
      dataAssetId: asset.id,
      affectedRecords: 12,
      executionRef: "job://erasure/2031-0318",
    });
    expect(executed.actions).toHaveLength(1);
    expect(executed.actions[0]?.action).toBe("erased");

    await expect(
      service.recordPrivacyRequestAction({
        tenantId: tenantA,
        id: request.id,
        action: "erased",
        dataAssetId: "data-asset_0b0f5f0e-6c1c-4a2b-8a4a-2f2f0f0c1d2e",
      }),
    ).rejects.toMatchObject({ code: COMPLIANCE_ERROR_CODES.VALIDATION_ERROR });

    const closed = await service.transitionPrivacyRequest({
      tenantId: tenantA,
      id: request.id,
      targetStatus: "fulfilled",
    });
    expect(closed.status).toBe("fulfilled");
    expect(closed.sla.state).toBe("closedBreached");
    expect(closed.sla.closedAt).toBe("2031-03-18T00:00:00.000Z");

    await expect(
      service.recordPrivacyRequestAction({
        tenantId: tenantA,
        id: request.id,
        action: "erased",
        dataAssetId: asset.id,
      }),
    ).rejects.toMatchObject({ code: COMPLIANCE_ERROR_CODES.RESOURCE_CONFLICT });

    const undecided = await createVerifiedPrivacyRequest(service, tenantA, {
      subjectRef: subjectBeta,
      dataAssetId: asset.id,
      receivedAt: "2031-03-01T00:00:00.000Z",
      responseDays: 30,
    });
    const inProgressOnly = await service.transitionPrivacyRequest({
      tenantId: tenantA,
      id: undecided.id,
      targetStatus: "inProgress",
    });
    await expect(
      service.transitionPrivacyRequest({
        tenantId: tenantA,
        id: inProgressOnly.id,
        targetStatus: "fulfilled",
      }),
    ).rejects.toMatchObject({
      code: COMPLIANCE_ERROR_CODES.VALIDATION_ERROR,
      details: { field: "decision" },
    });
    const denied = await service.decidePrivacyRequest({
      tenantId: tenantA,
      id: inProgressOnly.id,
      decision: "denied",
      rationale: "identity could not be re-confirmed",
      evidence: [{ reference: "ticket://privacy/deny-2031", kind: "ticket" }],
      targetStatus: "rejected",
    });
    expect(denied.status).toBe("rejected");
    expect(denied.decision?.decision).toBe("denied");

    const report = await service.generateComplianceReport({
      tenantId: tenantA,
      from: "2031-01-01T00:00:00.000Z",
      to: "2031-06-01T00:00:00.000Z",
    });
    expect(report.privacyRequests.requests.counts.fulfilled).toBe(1);
    expect(report.privacyRequests.breached).toBe(1);
    expect(report.privacyRequests.fulfilledWithinSla).toBe(0);
    expect(
      report.gaps.find((gap) => gap.code === "privacyRequestSlaBreached")?.count,
    ).toBe(1);

    const met = await createVerifiedPrivacyRequest(service, tenantB, {
      subjectRef: subjectBeta,
      dataAssetId: (await createActiveDataAsset(service, tenantB, { code: "asset-beta-2" })).id,
      receivedAt: "2031-03-01T00:00:00.000Z",
      responseDays: 10,
    });
    setNow("2031-03-05T00:00:00.000Z");
    const progressed = await service.decidePrivacyRequest({
      tenantId: tenantB,
      id: met.id,
      decision: "partiallyGranted",
      evidence: [{ reference: "ticket://privacy/beta-1", kind: "ticket" }],
    });
    const acted = await service.recordPrivacyRequestAction({
      tenantId: tenantB,
      id: progressed.id,
      action: "exported",
      dataAssetId: met.dataAssetIds[0] as string,
    });
    const closedMet = await service.transitionPrivacyRequest({
      tenantId: tenantB,
      id: acted.id,
      targetStatus: "fulfilled",
    });
    expect(closedMet.sla.state).toBe("closedMet");
    const reportB = await service.generateComplianceReport({
      tenantId: tenantB,
      from: "2031-01-01T00:00:00.000Z",
      to: "2031-06-01T00:00:00.000Z",
    });
    expect(reportB.privacyRequests.fulfilledWithinSla).toBe(1);
    expect(reportB.privacyRequests.breached).toBe(0);
  });

  it("records retention policy executions as append-only delete or anonymize evidence", async () => {
    const { service, repositories } = createHarness();
    const policy = await createRetentionPolicy(service, tenantA);
    const active = await activateRetentionPolicy(service, tenantA, policy);
    expect(active.status).toBe("active");

    await expect(
      service.recordRetentionExecution({
        tenantId: tenantA,
        policyId: policy.id,
        status: "completed",
        recordsScanned: 10,
        recordsDeleted: 10,
      }),
    ).resolves.toMatchObject({
      version: 1,
      status: "completed",
      action: "delete",
      result: { recordsScanned: 10, recordsDeleted: 10 },
    });

    const completed = (await service.listRetentionExecutions({
      tenantId: tenantA,
    })).items[0];
    expect(completed).toBeDefined();
    await expect(
      repositories.retentionExecutions.save({
        ...(completed as NonNullable<typeof completed>),
        status: "failed",
      }),
    ).rejects.toMatchObject({ code: COMPLIANCE_ERROR_CODES.RESOURCE_CONFLICT });

    const anonymizePolicy = await createRetentionPolicy(service, tenantA, {
      code: "retention-anonymize",
    });
    const activeAnonymize = await activateRetentionPolicy(
      service,
      tenantA,
      anonymizePolicy,
    );
    expect(activeAnonymize.action).toBe("delete");
    const anonymized = await service.recordRetentionExecution({
      tenantId: tenantA,
      policyId: anonymizePolicy.id,
      action: "anonymize",
      status: "completed",
      recordsScanned: 40,
      recordsAnonymized: 40,
      evidence: [
        { reference: "job://anonymize/2031-03-01", kind: "systemRecord" },
      ],
    });
    expect(anonymized.result.recordsAnonymized).toBe(40);

    await expect(
      service.recordRetentionExecution({
        tenantId: tenantA,
        policyId: policy.id,
        runId: completed?.runId,
        status: "completed",
      }),
    ).rejects.toMatchObject({ code: COMPLIANCE_ERROR_CODES.RESOURCE_CONFLICT });

    const holdPolicy = await createRetentionPolicy(service, tenantA, {
      code: "retention-hold",
    });
    const held = await service.transitionRetentionPolicy({
      tenantId: tenantA,
      id: holdPolicy.id,
      targetStatus: "active",
    });
    expect(held.legalHold).toBe(false);

    const approvalPolicy = await createRetentionPolicy(service, tenantA, {
      code: "retention-approval",
      requiresApproval: true,
    });
    await service.transitionRetentionPolicy({
      tenantId: tenantA,
      id: approvalPolicy.id,
      targetStatus: "active",
    });
    await expect(
      service.recordRetentionExecution({
        tenantId: tenantA,
        policyId: approvalPolicy.id,
        status: "completed",
        recordsDeleted: 1,
      }),
    ).rejects.toMatchObject({ code: COMPLIANCE_ERROR_CODES.RESOURCE_CONFLICT });

    const linked = await service.getRetentionPolicy(tenantA, policy.id);
    expect(linked?.lastExecutionId).toBe(completed?.id);

    const report = await service.generateComplianceReport({
      tenantId: tenantA,
      from: "2031-01-01T00:00:00.000Z",
      to: "2031-06-01T00:00:00.000Z",
    });
    expect(report.retention.recordsDeleted).toBe(10);
    expect(report.retention.recordsAnonymized).toBe(40);
    expect(report.retention.executions.total).toBe(2);
  });

  it("gates cross-border assessments on a declared mechanism and evidence", async () => {
    const { service } = createHarness();
    const asset = await createActiveDataAsset(service, tenantA, {
      code: "asset-cross-border",
      sensitivePersonalData: true,
      categories: ["biometric", "identity"],
      residencyRegions: ["CN", "SG"],
      crossBorder: true,
    });
    const vendor = await createActiveVendor(service, tenantA, {
      code: "vendor-sg",
      regions: ["SG"],
    });

    const draft = await service.createCrossBorderAssessment({
      tenantId: tenantA,
      title: "APAC biometric analytics",
      code: "xborder-apac",
      sourceRegion: "CN",
      destinationRegions: ["SG"],
      transferPurpose: "fraud-model-training",
      dataAssetIds: [asset.id],
      sensitivePersonalData: true,
      riskFactors: ["biometric-template", "re-identification-risk"],
      recipientVendorId: vendor.id,
      evidence: [
        { reference: "doc://xborder/apac/assessment", kind: "document" },
      ],
    });
    expect(draft.riskLevel).toBe("high");
    expect(draft.personalData).toBe(true);
    expect(draft.mechanisms).toEqual([]);

    await expect(
      service.transitionCrossBorderAssessment({
        tenantId: tenantA,
        id: draft.id,
        targetStatus: "assessing",
      }),
    ).resolves.toMatchObject({ status: "assessing" });

    await expect(
      service.transitionCrossBorderAssessment({
        tenantId: tenantA,
        id: draft.id,
        targetStatus: "pendingApproval",
      }),
    ).rejects.toMatchObject({
      code: COMPLIANCE_ERROR_CODES.CROSS_BORDER_MECHANISM_REQUIRED,
    });

    const pending = await service.transitionCrossBorderAssessment({
      tenantId: tenantA,
      id: draft.id,
      targetStatus: "pendingApproval",
      mechanisms: ["standardContract", "securityAssessment"],
      riskLevel: "critical",
    });
    expect(pending.mechanisms).toHaveLength(2);
    expect(pending.riskLevel).toBe("critical");

    const approved = await service.transitionCrossBorderAssessment({
      tenantId: tenantA,
      id: pending.id,
      targetStatus: "approved",
      validUntil: "2032-03-01T00:00:00.000Z",
    });
    expect(approved.status).toBe("approved");
    expect(approved.decidedAt).toBe(startInstant);
    expect(approved.decidedByRef).toBe("compliance-service");
    expect(approved.validUntil).toBe("2032-03-01T00:00:00.000Z");

    await expect(
      service.transitionCrossBorderAssessment({
        tenantId: tenantA,
        id: approved.id,
        targetStatus: "pendingApproval",
      }),
    ).rejects.toMatchObject({
      code: COMPLIANCE_ERROR_CODES.INVALID_STATE_TRANSITION,
    });

    const expired = await service.transitionCrossBorderAssessment({
      tenantId: tenantA,
      id: approved.id,
      targetStatus: "expired",
    });
    expect(expired.status).toBe("expired");

    const awaiting = await service.createCrossBorderAssessment({
      tenantId: tenantA,
      title: "Analytics without mechanism",
      code: "xborder-open",
      sourceRegion: "CN",
      destinationRegions: ["US"],
      transferPurpose: "aggregate-analytics",
      dataAssetIds: [asset.id],
    });
    const report = await service.generateComplianceReport({
      tenantId: tenantA,
      from: "2031-01-01T00:00:00.000Z",
      to: "2031-06-01T00:00:00.000Z",
    });
    expect(report.crossBorder.assessments.total).toBe(2);
    expect(report.crossBorder.withoutMechanism).toEqual([awaiting.id]);
    expect(report.crossBorder.awaitingDecision).toEqual([awaiting.id]);
    expect(report.crossBorder.byRiskLevel.total).toBe(2);

    await expect(
      service.createCrossBorderAssessment({
        tenantId: tenantA,
        title: "Invalid sensitive scope",
        code: "xborder-invalid",
        sourceRegion: "CN",
        destinationRegions: ["SG"],
        transferPurpose: "invalid",
        personalData: false,
        sensitivePersonalData: true,
      }),
    ).rejects.toMatchObject({ code: COMPLIANCE_ERROR_CODES.VALIDATION_ERROR });
  });

  it("registers processors and sub-processors with regional and assessment state", async () => {
    const { service } = createHarness();
    const processor = await createActiveVendor(service, tenantA, {
      code: "vendor-processor",
      regions: ["SG", "HK"],
    });
    expect(processor.role).toBe("processor");
    expect(processor.status).toBe("active");
    expect(processor.assessment.status).toBe("passed");
    expect(processor.assessment.evidence).toHaveLength(1);
    expect(processor.crossBorder).toBe(true);

    const subProcessor = await createActiveVendor(service, tenantA, {
      code: "vendor-sub",
      regions: ["US"],
      role: "subProcessor",
      parentVendorId: processor.id,
    });
    expect(subProcessor.parentVendorId).toBe(processor.id);

    await expect(
      service.createVendor({
        tenantId: tenantA,
        role: "subProcessor",
        code: "vendor-orphan",
        legalName: "Orphan Sub Processor Ltd",
        regions: ["US"],
      }),
    ).rejects.toMatchObject({ code: COMPLIANCE_ERROR_CODES.VALIDATION_ERROR });

    const draft = await service.createVendor({
      tenantId: tenantA,
      role: "processor",
      code: "vendor-unassessed",
      legalName: "Unassessed Processor Ltd",
      regions: ["DE"],
    });
    await expect(
      service.transitionVendor({
        tenantId: tenantA,
        id: draft.id,
        targetStatus: "active",
      }),
    ).rejects.toMatchObject({
      code: COMPLIANCE_ERROR_CODES.INVALID_STATE_TRANSITION,
    });

    await service.transitionVendor({
      tenantId: tenantA,
      id: draft.id,
      targetStatus: "pendingAssessment",
    });
    await expect(
      service.transitionVendor({
        tenantId: tenantA,
        id: draft.id,
        targetStatus: "active",
      }),
    ).rejects.toMatchObject({
      code: COMPLIANCE_ERROR_CODES.VALIDATION_ERROR,
      details: { field: "assessment.status" },
    });

    const failed = await service.recordVendorAssessment({
      tenantId: tenantA,
      id: draft.id,
      status: "failed",
    });
    expect(failed.assessment.status).toBe("failed");
    expect(failed.status).toBe("pendingAssessment");

    const suspended = await service.transitionVendor({
      tenantId: tenantA,
      id: processor.id,
      targetStatus: "suspended",
    });
    expect(suspended.status).toBe("suspended");
    const terminated = await service.transitionVendor({
      tenantId: tenantA,
      id: suspended.id,
      targetStatus: "terminated",
      contractTerminatedAt: "2031-03-02T00:00:00.000Z",
    });
    expect(terminated.status).toBe("terminated");
    expect(terminated.contractTerminatedAt).toBe("2031-03-02T00:00:00.000Z");
    await expect(
      service.transitionVendor({
        tenantId: tenantA,
        id: terminated.id,
        targetStatus: "active",
      }),
    ).rejects.toMatchObject({
      code: COMPLIANCE_ERROR_CODES.INVALID_STATE_TRANSITION,
    });

    const vendors = await service.listVendors({ tenantId: tenantA });
    expect(vendors.total).toBe(3);
    expect(vendors.items.filter((vendor) => vendor.status === "active")).toHaveLength(1);

    const report = await service.generateComplianceReport({
      tenantId: tenantA,
      from: "2031-01-01T00:00:00.000Z",
      to: "2031-06-01T00:00:00.000Z",
    });
    expect(report.vendors.vendors.counts.terminated).toBe(1);
    expect(report.vendors.byRole.counts.subProcessor).toBe(1);
    expect(report.vendors.assessment.counts.passed).toBe(2);
    expect(report.vendors.regions).toEqual(["DE", "HK", "SG", "US"]);
    expect(
      report.gaps.find((gap) => gap.code === "vendorAssessmentIncomplete")?.count,
    ).toBe(1);
  });

  it("rejects illegal state transitions across every compliance state machine", async () => {
    const { service } = createHarness();
    expect(canTransitionDataAsset("draft", "active")).toBe(false);
    expect(canTransitionDataAsset("draft", "registered")).toBe(true);
    expect(canTransitionDataAsset("retired", "draft")).toBe(false);
    expect(canTransitionConsent("pending", "granted")).toBe(true);
    expect(canTransitionConsent("withdrawn", "granted")).toBe(false);
    expect(canTransitionConsent("granted", "withdrawn")).toBe(true);
    expect(canTransitionPrivacyRequest("submitted", "fulfilled")).toBe(false);
    expect(canTransitionPrivacyRequest("verifyingIdentity", "verified")).toBe(true);
    expect(canTransitionPrivacyRequest("fulfilled", "inProgress")).toBe(false);
    expect(canTransitionRetentionPolicy("active", "superseded")).toBe(true);
    expect(canTransitionRetentionPolicy("superseded", "active")).toBe(false);
    expect(canTransitionCrossBorder("pendingApproval", "approved")).toBe(true);
    expect(canTransitionCrossBorder("rejected", "assessing")).toBe(false);
    expect(canTransitionVendor("active", "suspended")).toBe(true);
    expect(canTransitionVendor("terminated", "active")).toBe(false);

    const policy = await createRetentionPolicy(service, tenantA);
    await service.transitionRetentionPolicy({
      tenantId: tenantA,
      id: policy.id,
      targetStatus: "active",
    });
    await expect(
      service.transitionRetentionPolicy({
        tenantId: tenantA,
        id: policy.id,
        targetStatus: "superseded",
      }),
    ).rejects.toMatchObject({
      code: COMPLIANCE_ERROR_CODES.RESOURCE_CONFLICT,
    });

    const successor = await createRetentionPolicy(service, tenantA, {
      code: "retention-successor",
    });
    await activateRetentionPolicy(service, tenantA, successor);
    await expect(
      service.transitionRetentionPolicy({
        tenantId: tenantA,
        id: policy.id,
        targetStatus: "superseded",
      }),
    ).resolves.toMatchObject({ status: "superseded" });
    await expect(
      service.transitionRetentionPolicy({
        tenantId: tenantA,
        id: policy.id,
        targetStatus: "active",
      }),
    ).rejects.toMatchObject({
      code: COMPLIANCE_ERROR_CODES.INVALID_STATE_TRANSITION,
    });

    const asset = await createActiveDataAsset(service, tenantA, { code: "asset-machine" });
    await service.transitionDataAsset({
      tenantId: tenantA,
      id: asset.id,
      targetStatus: "retired",
    });
    await expect(
      service.transitionDataAsset({
        tenantId: tenantA,
        id: asset.id,
        targetStatus: "active",
      }),
    ).rejects.toMatchObject({
      code: COMPLIANCE_ERROR_CODES.INVALID_STATE_TRANSITION,
    });
  });

  it("produces a tenant scoped redacted compliance report without raw personal information", async () => {
    const { service, setNow } = createHarness();
    const policy = await createRetentionPolicy(service, tenantA);
    const active = await activateRetentionPolicy(service, tenantA, policy);
    const asset = await service.createDataAsset({
      tenantId: tenantA,
      name: "Loyalty profile",
      code: "asset-loyalty",
      classification: "personal",
      categories: ["identity", "contact"],
      personalData: true,
      sensitivePersonalData: false,
      legalBasis: "consent",
      purposes: ["loyalty-program"],
      dataSubjects: ["customer"],
      residencyRegions: ["CN"],
      retentionPolicyId: active.id,
      crossBorder: true,
    });
    const registered = await service.transitionDataAsset({
      tenantId: tenantA,
      id: asset.id,
      targetStatus: "registered",
    });
    const consent = await service.createConsentRecord({
      tenantId: tenantA,
      subjectRef: subjectAlpha,
      purpose: "loyalty-program",
      policyVersion: "2026-02",
      channel: "web",
      dataAssetIds: [registered.id],
    });
    await service.grantConsent({
      tenantId: tenantA,
      id: consent.id,
      proof: [{ reference: "sys://consent/loyalty/capture", kind: "systemRecord" }],
    });
    const vendor = await createActiveVendor(service, tenantA, {
      code: "vendor-report",
      regions: ["SG"],
    });
    const assetWithVendor = await service.updateDataAsset({
      tenantId: tenantA,
      id: registered.id,
      processorVendorId: vendor.id,
    });
    expect(assetWithVendor.processorVendorId).toBe(vendor.id);
    const request = await createVerifiedPrivacyRequest(service, tenantA, {
      subjectRef: subjectAlpha,
      dataAssetId: registered.id,
      receivedAt: "2031-03-01T00:00:00.000Z",
    });
    setNow("2031-03-20T00:00:00.000Z");
    const progressed = await service.decidePrivacyRequest({
      tenantId: tenantA,
      id: request.id,
      decision: "granted",
      evidence: [{ reference: "ticket://privacy/report", kind: "ticket" }],
    });
    expect(progressed.status).toBe("inProgress");
    const acted = await service.recordPrivacyRequestAction({
      tenantId: tenantA,
      id: progressed.id,
      action: "exported",
      dataAssetId: registered.id,
      affectedRecords: 3,
    });
    await service.transitionPrivacyRequest({
      tenantId: tenantA,
      id: acted.id,
      targetStatus: "fulfilled",
    });
    await service.recordRetentionExecution({
      tenantId: tenantA,
      policyId: active.id,
      status: "completed",
      recordsScanned: 5,
      recordsDeleted: 5,
    });

    const report = await service.generateComplianceReport({
      tenantId: tenantA,
      from: "2031-01-01T00:00:00.000Z",
      to: "2031-06-01T00:00:00.000Z",
      generatedAt: "2031-04-01T00:00:00.000Z",
    });

    expect(report.contractVersion).toBe(1);
    expect(report.redaction).toEqual({ placeholder: COMPLIANCE_REDACTED, applies: true });
    expect(report.period).toEqual({
      from: "2031-01-01T00:00:00.000Z",
      to: "2031-06-01T00:00:00.000Z",
    });
    expect(report.dataCatalog.assets.total).toBe(1);
    expect(report.dataCatalog.byClassification.counts.personal).toBe(1);
    expect(report.dataCatalog.personalDataAssets).toBe(1);
    expect(report.dataCatalog.sensitivePersonalDataAssets).toBe(0);
    expect(report.dataCatalog.crossBorderAssets).toBe(1);
    expect(report.dataCatalog.withoutPurpose).toEqual([]);
    expect(report.dataCatalog.withoutRetentionPolicy).toEqual([]);
    expect(report.consent.records.total).toBe(1);
    expect(report.consent.records.counts.granted).toBe(1);
    expect(report.consent.activeSubjects).toBe(1);
    expect(report.consent.withdrawnSubjects).toBe(0);
    expect(report.privacyRequests.requests.total).toBe(1);
    expect(report.privacyRequests.breached).toBe(1);
    expect(report.retention.recordsDeleted).toBe(5);
    expect(report.vendors.vendors.total).toBe(1);
    expect(report.limitations).toContain(
      "No legal conclusion, adequacy determination, or regulatory filing status is asserted.",
    );
    expect(
      complianceReportContainsSensitiveValue(report, [
        subjectAlpha,
        subjectBeta,
        rawEmail,
        rawPhone,
        "sys://consent/loyalty/capture",
        "ticket://privacy/report",
      ]),
    ).toBe(false);
    expect(JSON.stringify(report)).not.toContain(subjectAlpha);
    expect(() => assertComplianceReportIsRedacted(report)).not.toThrow();
    expect(report.gaps.every((gap) => gap.resourceIds.length === gap.count)).toBe(true);
  });

  it("keeps an append-only hash chained compliance event log per tenant", async () => {
    const { service, events } = createHarness();
    const asset = await createActiveDataAsset(service, tenantA, { code: "asset-events" });
    await service.transitionDataAsset({
      tenantId: tenantA,
      id: asset.id,
      targetStatus: "retired",
    });

    const recorded = (await service.listDomainEvents(tenantA)) as ComplianceEventRecord[];
    expect(recorded.map((event) => event.sequence)).toEqual([1, 2, 3, 4]);
    expect(recorded[0]?.eventHash).toMatch(/^[a-f0-9]{64}$/u);
    expect(recorded[1]?.previousHash).toBe(recorded[0]?.eventHash);
    expect(recorded[3]?.previousHash).toBe(recorded[2]?.eventHash);
    expect(recorded.map((event) => event.eventType)).toEqual([
      "dataAsset.create",
      "dataAsset.draft->registered",
      "dataAsset.registered->active",
      "dataAsset.retired",
    ]);
    expect(recorded[3]?.fromStatus).toBe("active");
    expect(recorded[3]?.toStatus).toBe("retired");
    expect(await service.verifyEventChain(tenantA)).toBe(true);
    expect(await service.verifyEventChain(tenantB)).toBe(true);

    const page = await events.list({ tenantId: tenantA, limit: 2 });
    expect(page.items).toHaveLength(2);
    expect(page.hasMore).toBe(true);
    expect(page.total).toBe(4);
    expect(page.nextSequence).toBe(2);

    const scoped = await events.list({ tenantId: tenantA, kind: "dataAsset" });
    expect(scoped.total).toBe(4);
    expect((await events.list({ tenantId: tenantB })).total).toBe(0);
  });

  it("keeps the outbox event switch off and the write path unchanged by default", async () => {
    const { service, audit, events } = createHarness();
    expect(service.eventPublisher).toBeUndefined();
    expect(service.eventReadiness).toBeUndefined();
    await expect(service.isReady()).resolves.toBe(true);
    const asset = await createActiveDataAsset(service, tenantA, { code: "asset-outbox-off" });
    expect(asset.status).toBe("active");
    expect(audit.list(tenantA).map((entry) => entry.action)).toEqual([
      "dataAsset.create",
      "dataAsset.transition",
      "dataAsset.transition",
    ]);
    expect((await events.list({ tenantId: tenantA })).total).toBe(3);
  });

  it("describes the v1 SQL foundation with tenant RLS and append-only triggers", () => {
    const sql = createOpenComplianceMigrationSql();
    expect(sql).toContain("gb_open_compliance_data_asset");
    expect(sql).toContain("gb_open_compliance_consent_record");
    expect(sql).toContain("gb_open_compliance_privacy_request");
    expect(sql).toContain("gb_open_compliance_retention_policy");
    expect(sql).toContain("gb_open_compliance_retention_execution");
    expect(sql).toContain("gb_open_compliance_cross_border_assessment");
    expect(sql).toContain("gb_open_compliance_vendor");
    expect(sql).toContain("gb_open_compliance_event");
    expect(
      (sql.match(/ENABLE ROW LEVEL SECURITY/g) ?? []).length,
    ).toBe(8);
    expect((sql.match(/FORCE ROW LEVEL SECURITY/g) ?? []).length).toBe(8);
    expect(
      (sql.match(/CREATE POLICY/g) ?? []).length,
    ).toBe(8);
    expect(sql).toContain("current_setting('app.tenant_id', true)");
    expect(sql).toContain("gb_open_compliance_reject_retention_executions_mutation");
    expect(sql).toContain("gb_open_compliance_reject_domain_events_mutation");
    expect(sql).toContain("gb_open_compliance_reject_retention_policy_mutation");
    expect(sql).toContain("_append_only_");
    expect(sql).toContain("_immutable_");
    expect(sql).toContain("is append-only");
    const objectNames = [
      ...sql.matchAll(
        /(?:CREATE (?:UNIQUE )?INDEX IF NOT EXISTS|CREATE POLICY|CREATE TRIGGER) "([^"]+)"/gu,
      ),
    ].map((match) => match[1]);
    expect(objectNames.length).toBeGreaterThan(20);
    expect(new Set(objectNames).size).toBe(objectNames.length);
    expect(
      objectNames.every((name) => name.length <= 63 && /^[a-z0-9_]+$/u.test(name)),
    ).toBe(true);
    expect(
      sql.includes(`"status" NOT IN ('fulfilled', 'partiallyFulfilled') OR "identity_verification_status" = 'verified'`),
    ).toBe(true);
    expect(
      createOpenComplianceMigrationSql({ includeRls: false }).includes(
        "ROW LEVEL SECURITY",
      ),
    ).toBe(false);
    expect(getOpenComplianceMigrationChecksum()).toBe(
      getOpenComplianceMigrationChecksum(),
    );
    expect(
      getOpenComplianceMigrationChecksum({ schema: "compliance" }),
    ).not.toBe(getOpenComplianceMigrationChecksum());
  });
});
