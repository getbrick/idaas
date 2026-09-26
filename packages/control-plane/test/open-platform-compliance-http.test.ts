import "reflect-metadata";
import { randomUUID } from "node:crypto";
import { Test } from "@nestjs/testing";
import request from "supertest";
import { describe, expect, it } from "vitest";
import {
  createOpenPlatformRequestContextIssuer,
  OpenPlatformComplianceModule,
  OPEN_PLATFORM_COMPLIANCE_BASE_PATH,
  toOpenPlatformComplianceHttpError,
  type OpenPlatformHttpRequest,
} from "../src/open-platform/index.js";
import {
  ComplianceDomainService,
  COMPLIANCE_REDACTED,
  createInMemoryComplianceIdempotencyStore,
  createDevelopmentComplianceAuthorization,
  createUnavailableComplianceAuthorization,
  InMemoryComplianceAuditStore,
  InMemoryComplianceRepositories,
  complianceResourceNotFound,
  type ComplianceAuthorizationPort,
  type ComplianceIdempotencyPort,
  type ComplianceDataAsset,
  type CompliancePrivacyRequest,
} from "../src/open-platform/compliance/index.js";

const startInstant = "2031-05-04T09:00:00.000Z";
const periodFrom = "2031-04-01T00:00:00.000Z";
const periodTo = "2031-05-31T00:00:00.000Z";
const tenantId = "tenant-compliance-http";
const otherTenantId = "tenant-compliance-other";
const actorId = "actor-compliance-http";
const subjectRef = "subject-9f2c4a71";

type Harness = {
  service: ComplianceDomainService;
  repositories: InMemoryComplianceRepositories;
  audit: InMemoryComplianceAuditStore;
  setNow: (value: string) => void;
};

function createHarness(): Harness {
  const repositories = new InMemoryComplianceRepositories();
  const audit = new InMemoryComplianceAuditStore();
  let current = startInstant;
  const service = new ComplianceDomainService({
    repositories,
    audit,
    clock: () => new Date(current),
  });
  return {
    service,
    repositories,
    audit,
    setNow: (value: string) => {
      current = value;
    },
  };
}

function issuer() {
  return createOpenPlatformRequestContextIssuer({
    issuerId: "compliance-http-tests",
    attestation: Object.freeze({ test: true }),
    clock: () => new Date(startInstant),
  });
}

function resolverFor(targetTenantId: string) {
  return (httpRequest: OpenPlatformHttpRequest) => {
    const headers = httpRequest.headers ?? {};
    const authenticated = Object.entries(headers).some(
      ([key, value]) => key.toLowerCase() === "x-compliance-auth" && value === "valid",
    );
    const tenant = Object.entries(headers).some(
      ([key, value]) => key.toLowerCase() === "x-compliance-tenant" && typeof value === "string",
    )
      ? (headers["x-compliance-tenant"] as string)
      : targetTenantId;
    return authenticated ? { tenantId: tenant, actorId, requestId: "compliance-request" } : undefined;
  };
}

interface AppOptions {
  readonly mode?: "development" | "test" | "production";
  readonly authorization?: ComplianceAuthorizationPort;
  readonly audit?: InMemoryComplianceAuditStore;
  readonly idempotency?: ComplianceIdempotencyPort;
  readonly resolverTenantId?: string;
  readonly withResolver?: boolean;
}

async function createApp(
  service: ComplianceDomainService,
  options: AppOptions = {},
) {
  const mode = options.mode ?? "test";
  const moduleRef = await Test.createTestingModule({
    imports: [
      OpenPlatformComplianceModule.forRoot({
        service,
        mode,
        contextIssuer: issuer(),
        ...(options.authorization === undefined
          ? {}
          : { authorization: options.authorization }),
        ...(options.audit === undefined ? {} : { audit: options.audit }),
        ...(options.idempotency === undefined
          ? {}
          : { idempotency: options.idempotency }),
        ...(options.withResolver === false
          ? {}
          : { resolver: resolverFor(options.resolverTenantId ?? tenantId) }),
      }),
    ],
  }).compile();
  const app = moduleRef.createNestApplication();
  await app.init();
  return app;
}

function authenticated<T extends { set: (name: string, value: string) => T }>(value: T): T {
  return value.set("x-compliance-auth", "valid");
}

function tenantHeader<T extends { set: (name: string, value: string) => T }>(
  value: T,
  target: string,
): T {
  return value.set("x-compliance-tenant", target);
}

function idempotent<T extends { set: (name: string, value: string) => T }>(value: T, key: string): T {
  return value.set("Idempotency-Key", key);
}

async function seedDataAsset(
  service: ComplianceDomainService,
  target: string = tenantId,
  code = "http-asset-1",
): Promise<ComplianceDataAsset> {
  return service.createDataAsset({
    tenantId: target,
    name: "Marketing profile",
    code,
    classification: "personal",
    categories: ["identity"],
    personalData: true,
    sensitivePersonalData: false,
    legalBasis: "consent",
    purposes: ["marketing"],
    residencyRegions: ["CN"],
    retentionDays: 365,
    crossBorder: false,
    evidence: [{ reference: "doc://policy/http-asset-1", kind: "document" }],
  });
}

async function seedPrivacyRequest(
  service: ComplianceDomainService,
  target: string = tenantId,
): Promise<CompliancePrivacyRequest> {
  return service.createPrivacyRequest({
    tenantId: target,
    requestType: "access",
    subjectRef,
    subjectCount: 1,
  });
}

async function seedRetentionPolicy(
  service: ComplianceDomainService,
  target: string = tenantId,
) {
  return service.createRetentionPolicy({
    tenantId: target,
    name: "Profile retention",
    code: `http-retention-${target}`,
    trigger: "time",
    action: "delete",
    retentionDays: 365,
    requiresApproval: false,
    legalHold: false,
    evidence: [{ reference: "doc://retention/http-v1", kind: "document" }],
  });
}

function denyingAuthorization(): ComplianceAuthorizationPort {
  return Object.freeze({
    productionReady: false,
    authorize(): boolean {
      return false;
    },
  });
}

function recordingAuthorization(allowed: boolean) {
  const calls: { action: string; resource: string; resourceId?: string }[] = [];
  const authorization: ComplianceAuthorizationPort = Object.freeze({
    productionReady: true,
    authorize(request: {
      readonly action: string;
      readonly resource: string;
      readonly resourceId?: string;
    }) {
      calls.push({
        action: request.action,
        resource: request.resource,
        ...(request.resourceId === undefined ? {} : { resourceId: request.resourceId }),
      });
      return allowed;
    },
  });
  return { authorization, calls };
}

function productionIdempotency(): ComplianceIdempotencyPort {
  const store = createInMemoryComplianceIdempotencyStore();
  return Object.freeze({
    productionReady: true,
    readiness: Object.freeze({
      storage: "persistent" as const,
      distributed: true,
      ready: () => true,
    }),
    get: (scope: Parameters<ComplianceIdempotencyPort["get"]>[0]) => store.get(scope),
    put: (entry: Parameters<ComplianceIdempotencyPort["put"]>[0]) => store.put(entry),
    delete: (scope: Parameters<ComplianceIdempotencyPort["delete"]>[0]) => store.delete(scope),
    prune: () => store.prune(),
  });
}

function productionAudit(): InMemoryComplianceAuditStore {
  return Object.freeze({
    productionReady: true,
    readiness: Object.freeze({
      storage: "persistent" as const,
      distributed: true,
      ready: () => true,
    }),
    append: (event: never) => Promise.resolve(event),
  }) as unknown as InMemoryComplianceAuditStore;
}

describe("open platform compliance HTTP", () => {
  it("requires an idempotency key on writes and replays the stored response", async () => {
    const harness = createHarness();
    const app = await createApp(harness.service);
    const server = app.getHttpServer();
    const missingKey = await authenticated(
      request(server).post(`${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/data-assets`).send({
        name: "Missing key asset",
        code: "http-missing-key",
        classification: "internal",
        categories: ["other"],
        personalData: false,
        sensitivePersonalData: false,
        residencyRegions: ["CN"],
        retentionDays: 30,
        crossBorder: false,
      }),
    );
    expect(missingKey.status).toBe(400);
    expect(missingKey.body.code).toBe("OPEN_PLATFORM_COMPLIANCE_VALIDATION_ERROR");
    expect(missingKey.headers["cache-control"]).toBe("no-store");
    expect(JSON.stringify(missingKey.body)).not.toContain("idempotencyKey");

    const payload = {
      name: "Replayed asset",
      code: "http-replay-1",
      classification: "internal",
      categories: ["other"],
      personalData: false,
      sensitivePersonalData: false,
      residencyRegions: ["CN"],
      retentionDays: 30,
      crossBorder: false,
    };
    const first = await idempotent(
      authenticated(request(server).post(`${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/data-assets`)),
      "replay-data-asset-1",
    ).send(payload);
    const replay = await idempotent(
      authenticated(request(server).post(`${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/data-assets`)),
      "replay-data-asset-1",
    ).send(payload);
    expect(first.status).toBe(201);
    expect(replay.status).toBe(201);
    expect(replay.body.id).toBe(first.body.id);
    expect(replay.body.version).toBe(first.body.version);
    expect(replay.headers["idempotency-replayed"]).toBe("true");
    expect(first.headers["idempotency-replayed"]).toBeUndefined();
    await expect(harness.repositories.dataAssets.list(tenantId)).resolves.toHaveLength(1);

    const reused = await idempotent(
      authenticated(request(server).post(`${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/data-assets`)),
      "replay-data-asset-1",
    ).send({ ...payload, name: "Different payload" });
    expect(reused.status).toBe(409);
    expect(reused.body.code).toBe("OPEN_PLATFORM_COMPLIANCE_IDEMPOTENCY_KEY_REUSED");
    await expect(harness.repositories.dataAssets.list(tenantId)).resolves.toHaveLength(1);
    await app.close();
  });

  it("denies unauthorized reads and writes with 403 and no-store", async () => {
    const harness = createHarness();
    const app = await createApp(harness.service, {
      authorization: denyingAuthorization(),
    });
    const server = app.getHttpServer();
    const read = await authenticated(
      request(server).get(`${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/data-assets`),
    );
    expect(read.status).toBe(403);
    expect(read.body.code).toBe("OPEN_PLATFORM_FORBIDDEN");
    expect(read.headers["cache-control"]).toBe("no-store");
    const write = await idempotent(
      authenticated(request(server).post(`${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/data-assets`)),
      "denied-write-0001",
    ).send({
      name: "Denied asset",
      code: "http-denied-1",
      classification: "internal",
      categories: ["other"],
      personalData: false,
      sensitivePersonalData: false,
      residencyRegions: ["CN"],
      retentionDays: 30,
      crossBorder: false,
    });
    expect(write.status).toBe(403);
    await expect(harness.repositories.dataAssets.list(tenantId)).resolves.toHaveLength(0);
    const denied = harness.audit.list(tenantId).filter((entry) => entry.outcome === "denied");
    expect(denied.length).toBeGreaterThanOrEqual(1);
    expect(denied[0]?.action).toBe("dataAsset.create");
    await app.close();
  });

  it("keeps tenant context isolated across query, body and record scope", async () => {
    const harness = createHarness();
    const asset = await seedDataAsset(harness.service);
    await seedDataAsset(harness.service, otherTenantId, "http-other-1");
    const app = await createApp(harness.service);
    const server = app.getHttpServer();

    const queryMismatch = await authenticated(
      request(server).get(
        `${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/data-assets?tenantId=${otherTenantId}`,
      ),
    );
    expect(queryMismatch.status).toBe(403);
    expect(queryMismatch.body.code).toBe("OPEN_PLATFORM_TENANT_MISMATCH");

    const bodyMismatch = await idempotent(
      authenticated(request(server).post(`${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/privacy-requests`)),
      "cross-tenant-body-0001",
    ).send({ requestType: "access", subjectRef, tenantId: otherTenantId });
    expect(bodyMismatch.status).toBe(403);
    expect(bodyMismatch.body.code).toBe("OPEN_PLATFORM_TENANT_MISMATCH");

    const otherTenantAsset = await harness.repositories.dataAssets.get(otherTenantId, asset.id);
    expect(otherTenantAsset).toBeUndefined();
    const foreignId = (await harness.repositories.dataAssets.list(otherTenantId))[0];
    expect(foreignId).toBeDefined();
    const foreignRead = await authenticated(
      request(server).get(`${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/data-assets/${foreignId?.id}`),
    );
    expect(foreignRead.status).toBe(404);
    expect(JSON.stringify(foreignRead.body)).not.toContain(otherTenantId);

    const scoped = await tenantHeader(
      authenticated(request(server).get(`${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/data-assets`)),
      otherTenantId,
    );
    expect(scoped.status).toBe(200);
    expect(scoped.body.items).toHaveLength(1);
    expect(scoped.body.items[0].id).toBe(foreignId?.id);
    expect(scoped.body.items[0].id).not.toBe(asset.id);
    await app.close();
  });

  it("rejects illegal state transitions and blocked compliance flows with 409", async () => {
    const harness = createHarness();
    const privacyRequest = await seedPrivacyRequest(harness.service);
    const policy = await seedRetentionPolicy(harness.service);
    const app = await createApp(harness.service);
    const server = app.getHttpServer();

    const illegalTransition = await idempotent(
      authenticated(
        request(server).post(
          `${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/privacy-requests/${privacyRequest.id}/status`,
        ),
      ),
      "illegal-transition-0001",
    ).send({ targetStatus: "fulfilled" });
    expect(illegalTransition.status).toBe(409);
    expect(illegalTransition.body.code).toBe(
      "OPEN_PLATFORM_COMPLIANCE_INVALID_STATE_TRANSITION",
    );
    expect(JSON.stringify(illegalTransition.body)).not.toContain("fulfilled");

    const unverifiedDecision = await idempotent(
      authenticated(
        request(server).post(
          `${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/privacy-requests/${privacyRequest.id}/decision`,
        ),
      ),
      "unverified-decision-0001",
    ).send({
      decision: "granted",
      evidence: [{ reference: "doc://ticket/http-1", kind: "ticket" }],
    });
    expect(unverifiedDecision.status).toBe(409);
    expect(unverifiedDecision.body.code).toBe(
      "OPEN_PLATFORM_COMPLIANCE_IDENTITY_VERIFICATION_REQUIRED",
    );

    const inactivePolicy = await idempotent(
      authenticated(
        request(server).post(`${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/retention-executions`),
      ),
      "inactive-policy-0001",
    ).send({ policyId: policy.id, status: "completed" });
    expect(inactivePolicy.status).toBe(409);
    expect(inactivePolicy.body.code).toBe("OPEN_PLATFORM_COMPLIANCE_RESOURCE_CONFLICT");

    const missingTargetStatus = await idempotent(
      authenticated(
        request(server).post(
          `${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/privacy-requests/${privacyRequest.id}/status`,
        ),
      ),
      "missing-target-status-0001",
    ).send({});
    expect(missingTargetStatus.status).toBe(400);
    expect(missingTargetStatus.body.code).toBe("OPEN_PLATFORM_COMPLIANCE_VALIDATION_ERROR");
    await app.close();
  });

  it("masks subject references in compliance read models and reports", async () => {
    const harness = createHarness();
    const consent = await harness.service.createConsentRecord({
      tenantId,
      subjectRef,
      purpose: "profile marketing",
      policyVersion: "v1",
      channel: "web",
      status: "granted",
      proof: [{ reference: "doc://consent/http-1", kind: "document" }],
    });
    const privacyRequest = await seedPrivacyRequest(harness.service);
    const app = await createApp(harness.service);
    const server = app.getHttpServer();

    const consentList = await authenticated(
      request(server).get(`${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/consents`),
    );
    expect(consentList.status).toBe(200);
    expect(consentList.body.items[0].subjectRefMasked).toBeDefined();
    expect(consentList.body.items[0]).not.toHaveProperty("subjectRef");
    expect(JSON.stringify(consentList.body)).not.toContain(subjectRef);

    const privacyRead = await authenticated(
      request(server).get(
        `${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/privacy-requests/${privacyRequest.id}`,
      ),
    );
    expect(privacyRead.status).toBe(200);
    expect(privacyRead.body).not.toHaveProperty("subjectRef");
    expect(privacyRead.body.subjectRefMasked).not.toBe(subjectRef);
    expect(JSON.stringify(privacyRead.body)).not.toContain(subjectRef);

    harness.setNow("2031-06-30T09:00:00.000Z");
    const sla = await authenticated(
      request(server).get(
        `${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/privacy-requests/${privacyRequest.id}/sla`,
      ),
    );
    expect(sla.status).toBe(200);
    expect(sla.body.state).toBe("breached");
    expect(sla.body.dueAt).toBe(privacyRequest.sla.dueAt);
    expect(sla.body).not.toHaveProperty("subjectRef");
    expect(JSON.stringify(sla.body)).not.toContain(subjectRef);

    const report = await authenticated(
      request(server).get(
        `${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/report?from=${periodFrom}&to=${periodTo}`,
      ),
    );
    expect(report.status).toBe(200);
    expect(report.body.redaction.applies).toBe(true);
    expect(report.body.consent.records.total).toBe(1);
    expect(JSON.stringify(report.body)).not.toContain(subjectRef);
    expect(JSON.stringify(report.body)).not.toContain("subjectRef");
    expect(consent.id).not.toBe("");
    await app.close();
  });

  it("bounds pagination, rejects unknown parameters and hides error internals", async () => {
    const harness = createHarness();
    await seedDataAsset(harness.service);
    const app = await createApp(harness.service);
    const server = app.getHttpServer();

    const tooLarge = await authenticated(
      request(server).get(`${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/data-assets?limit=100000`),
    );
    expect(tooLarge.status).toBe(400);
    expect(tooLarge.body.code).toBe("OPEN_PLATFORM_COMPLIANCE_VALIDATION_ERROR");

    const unknownParameter = await authenticated(
      request(server).get(`${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/data-assets?subjectRef=x`),
    );
    expect(unknownParameter.status).toBe(400);
    expect(unknownParameter.body.code).toBe("OPEN_PLATFORM_COMPLIANCE_VALIDATION_ERROR");
    expect(JSON.stringify(unknownParameter.body)).not.toContain("subjectRef=x");

    const invalidCursor = await authenticated(
      request(server).get(
        `${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/data-assets?cursor=not-a-compliance-cursor`,
      ),
    );
    expect(invalidCursor.status).toBe(400);
    expect(invalidCursor.body).toMatchObject({
      code: "OPEN_PLATFORM_COMPLIANCE_VALIDATION_ERROR",
      message: "Open platform compliance request failed",
    });
    expect(JSON.stringify(invalidCursor.body)).not.toContain("not-a-compliance-cursor");

    const missing = await authenticated(
      request(server).get(
        `${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/data-assets/data-asset_00000000-0000-4000-8000-000000000000`,
      ),
    );
    expect(missing.status).toBe(404);
    expect(missing.body.code).toBe("OPEN_PLATFORM_COMPLIANCE_RESOURCE_NOT_FOUND");
    expect(JSON.stringify(missing.body)).not.toContain("0000000000000000");

    const unsafe = await idempotent(
      authenticated(request(server).post(`${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/consents`)),
      "unsafe-consent-0001",
    ).send({
      subjectRef,
      purpose: "Contact zhangwei.contact@example.com about the campaign",
      policyVersion: "v1",
      channel: "web",
    });
    expect(unsafe.status).toBe(500);
    expect(unsafe.body.code).toBe("OPEN_PLATFORM_COMPLIANCE_REDACTION_FAILED");
    expect(unsafe.body.message).toBe("Open platform compliance request failed");
    expect(JSON.stringify(unsafe.body)).not.toContain("zhangwei.contact@example.com");
    expect(toOpenPlatformComplianceHttpError(complianceResourceNotFound("dataAsset"), "compliance-request"))
      .toMatchObject({
        statusCode: 404,
        body: { code: "OPEN_PLATFORM_COMPLIANCE_RESOURCE_NOT_FOUND" },
      });
    await app.close();
  });

  it("exposes list, get and status write routes for every compliance resource", async () => {
    const harness = createHarness();
    const app = await createApp(harness.service);
    const server = app.getHttpServer();
    const created: Record<string, string> = {};

    created.dataAsset = (await idempotent(
      authenticated(request(server).post(`${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/data-assets`)),
      "route-data-asset-0001",
    ).send({
      name: "Routing asset",
      code: "http-route-asset",
      classification: "personal",
      categories: ["identity"],
      personalData: true,
      sensitivePersonalData: false,
      legalBasis: "consent",
      purposes: ["routing"],
      residencyRegions: ["CN"],
      retentionDays: 180,
      crossBorder: false,
    })).body.id;

    const patched = await idempotent(
      authenticated(
        request(server).patch(
          `${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/data-assets/${created.dataAsset}`,
        ),
      ),
      "route-data-asset-patch-0001",
    ).send({ purposes: ["routing", "reporting"] });
    expect(patched.status).toBe(200);
    expect(patched.body.purposes).toEqual(["reporting", "routing"]);

    const registered = await idempotent(
      authenticated(
        request(server).post(
          `${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/data-assets/${created.dataAsset}/status`,
        ),
      ),
      "route-data-asset-status-0001",
    ).send({ targetStatus: "registered" });
    expect(registered.status).toBe(201);
    expect(registered.body.status).toBe("registered");

    created.consentRecord = (await idempotent(
      authenticated(request(server).post(`${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/consents`)),
      "route-consent-0001",
    ).send({
      subjectRef,
      purpose: "routing consent",
      policyVersion: "v1",
      channel: "web",
    })).body.id;
    const granted = await idempotent(
      authenticated(
        request(server).post(
          `${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/consents/${created.consentRecord}/grant`,
        ),
      ),
      "route-consent-grant-0001",
    ).send({ proof: [{ reference: "doc://consent/route-1", kind: "document" }] });
    expect(granted.status).toBe(201);
    expect(granted.body.status).toBe("granted");
    const withdrawn = await idempotent(
      authenticated(
        request(server).post(
          `${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/consents/${created.consentRecord}/withdraw`,
        ),
      ),
      "route-consent-withdraw-0001",
    ).send({ reason: "subject asked to opt out" });
    expect(withdrawn.status).toBe(201);
    expect(withdrawn.body.status).toBe("withdrawn");

    created.privacyRequest = (await idempotent(
      authenticated(
        request(server).post(`${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/privacy-requests`),
      ),
      "route-privacy-request-0001",
    ).send({ requestType: "deletion", subjectRef, dataAssetIds: [created.dataAsset] })).body.id;
    const verifying = await idempotent(
      authenticated(
        request(server).post(
          `${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/privacy-requests/${created.privacyRequest}/status`,
        ),
      ),
      "route-privacy-status-0001",
    ).send({ targetStatus: "verifyingIdentity" });
    expect(verifying.status).toBe(201);
    expect(verifying.body.status).toBe("verifyingIdentity");
    const approvedIdentity = await idempotent(
      authenticated(
        request(server).post(
          `${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/privacy-requests/${created.privacyRequest}/status`,
        ),
      ),
      "route-privacy-verified-0001",
    ).send({ targetStatus: "verified" });
    expect(approvedIdentity.status).toBe(201);
    expect(approvedIdentity.body.status).toBe("verified");
    const verified = await idempotent(
      authenticated(
        request(server).post(
          `${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/privacy-requests/${created.privacyRequest}/identity-verification`,
        ),
      ),
      "route-privacy-identity-0001",
    ).send({
      status: "verified",
      method: "reauthentication",
      evidence: [{ reference: "doc://identity/route-1", kind: "document" }],
    });
    expect(verified.status).toBe(201);
    const decided = await idempotent(
      authenticated(
        request(server).post(
          `${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/privacy-requests/${created.privacyRequest}/decision`,
        ),
      ),
      "route-privacy-decision-0001",
    ).send({
      decision: "granted",
      rationale: "Deletion confirmed by the operator",
      evidence: [{ reference: "doc://ticket/route-1", kind: "ticket" }],
    });
    expect(decided.status).toBe(201);
    expect(decided.body.decision.decision).toBe("granted");
    const actioned = await idempotent(
      authenticated(
        request(server).post(
          `${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/privacy-requests/${created.privacyRequest}/actions`,
        ),
      ),
      "route-privacy-action-0001",
    ).send({ action: "erased", dataAssetId: created.dataAsset, affectedRecords: 4 });
    expect(actioned.status).toBe(201);
    expect(actioned.body.actions).toHaveLength(1);
    const fulfilled = await idempotent(
      authenticated(
        request(server).post(
          `${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/privacy-requests/${created.privacyRequest}/status`,
        ),
      ),
      "route-privacy-fulfil-0001",
    ).send({ targetStatus: "fulfilled" });
    expect(fulfilled.status).toBe(201);
    expect(fulfilled.body.status).toBe("fulfilled");
    expect(fulfilled.body.sla.state).toBe("closedMet");

    created.retentionPolicy = (await idempotent(
      authenticated(
        request(server).post(`${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/retention-policies`),
      ),
      "route-retention-policy-0001",
    ).send({
      name: "Routing retention",
      code: "http-route-retention",
      trigger: "time",
      action: "delete",
      retentionDays: 90,
      requiresApproval: false,
      legalHold: false,
      evidence: [{ reference: "doc://retention/route-1", kind: "document" }],
    })).body.id;
    const activated = await idempotent(
      authenticated(
        request(server).post(
          `${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/retention-policies/${created.retentionPolicy}/status`,
        ),
      ),
      "route-retention-activate-0001",
    ).send({ targetStatus: "active" });
    expect(activated.status).toBe(201);
    const execution = await idempotent(
      authenticated(
        request(server).post(`${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/retention-executions`),
      ),
      "route-retention-exec-0001",
    ).send({
      policyId: created.retentionPolicy,
      runId: `run-${randomUUID()}`,
      status: "completed",
      recordsScanned: 10,
      recordsDeleted: 10,
    });
    expect(execution.status).toBe(201);
    expect(execution.body.recordsDeleted).toBe(10);
    expect(execution.body).not.toHaveProperty("result");

    created.crossBorderAssessment = (await idempotent(
      authenticated(
        request(server).post(`${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/cross-border-assessments`),
      ),
      "route-cross-border-0001",
    ).send({
      title: "Routing transfer",
      code: "http-route-cross-border",
      sourceRegion: "CN",
      destinationRegions: ["SG"],
      transferPurpose: "analytics",
      dataAssetIds: [created.dataAsset],
      riskLevel: "high",
      mechanisms: ["standardContract"],
      evidence: [{ reference: "doc://transfer/route-1", kind: "document" }],
    })).body.id;
    const assessing = await idempotent(
      authenticated(
        request(server).post(
          `${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/cross-border-assessments/${created.crossBorderAssessment}/status`,
        ),
      ),
      "route-cross-border-status-0001",
    ).send({ targetStatus: "assessing" });
    expect(assessing.status).toBe(201);
    const pendingApproval = await idempotent(
      authenticated(
        request(server).post(
          `${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/cross-border-assessments/${created.crossBorderAssessment}/status`,
        ),
      ),
      "route-cross-border-pending-0001",
    ).send({ targetStatus: "pendingApproval" });
    expect(pendingApproval.status).toBe(201);
    const approved = await idempotent(
      authenticated(
        request(server).post(
          `${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/cross-border-assessments/${created.crossBorderAssessment}/decision`,
        ),
      ),
      "route-cross-border-decision-0001",
    ).send({ targetStatus: "approved" });
    expect(approved.status).toBe(201);
    expect(approved.body.status).toBe("approved");
    expect(approved.body.decidedByRef).toBe(actorId);

    created.vendor = (await idempotent(
      authenticated(request(server).post(`${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/vendors`)),
      "route-vendor-0001",
    ).send({
      role: "processor",
      code: "http-route-vendor",
      legalName: "Routing Processor Ltd",
      regions: ["CN"],
      dataAssetIds: [created.dataAsset],
    })).body.id;
    const assessed = await idempotent(
      authenticated(
        request(server).post(
          `${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/vendors/${created.vendor}/assessments`,
        ),
      ),
      "route-vendor-assess-0001",
    ).send({
      status: "passed",
      evidence: [{ reference: "doc://assessment/route-1", kind: "document" }],
    });
    expect(assessed.status).toBe(201);
    expect(assessed.body.assessment.status).toBe("passed");
    const vendorActive = await idempotent(
      authenticated(
        request(server).post(`${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/vendors/${created.vendor}/status`),
      ),
      "route-vendor-status-0001",
    ).send({ targetStatus: "pendingAssessment" });
    expect(vendorActive.status).toBe(201);
    const vendorApproved = await idempotent(
      authenticated(
        request(server).post(`${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/vendors/${created.vendor}/status`),
      ),
      "route-vendor-active-0001",
    ).send({ targetStatus: "active" });
    expect(vendorApproved.status).toBe(201);
    expect(vendorApproved.body.status).toBe("active");

    for (const [collection, id] of Object.entries(created)) {
      const route = collectionRoute(collection);
      const list = await authenticated(
        request(server).get(`${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/${route}`),
      );
      expect(list.status).toBe(200);
      expect(list.body.total).toBeGreaterThanOrEqual(1);
      expect(list.body).not.toHaveProperty("items.subjectRef");
      const read = await authenticated(
        request(server).get(`${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/${route}/${id}`),
      );
      expect(read.status).toBe(200);
      expect(read.body.id).toBe(id);
      expect(read.body.kind).toBe(collection);
    }

    const executions = await authenticated(
      request(server).get(`${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/retention-executions`),
    );
    expect(executions.status).toBe(200);
    expect(executions.body.items[0].policyId).toBe(created.retentionPolicy);
    expect(executions.body.items[0].recordedByRef).toBe(actorId);

    const report = await idempotent(
      authenticated(request(server).post(`${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/report`)),
      "route-report-0001",
    ).send({ from: periodFrom, to: periodTo });
    expect(report.status).toBe(201);
    expect(report.body.privacyRequests.requests.total).toBe(1);
    expect(report.body.dataCatalog.assets.total).toBe(1);
    expect(JSON.stringify(report.body)).not.toContain(subjectRef);
    expect(COMPLIANCE_REDACTED).toBe("[redacted]");
    await app.close();
  });

  it("authorizes the documented action and resource matrix", async () => {
    const harness = createHarness();
    const { authorization, calls } = recordingAuthorization(true);
    const app = await createApp(harness.service, { authorization });
    const server = app.getHttpServer();
    await authenticated(request(server).get(`${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/vendors`));
    await authenticated(request(server).get(`${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/report?from=${periodFrom}&to=${periodTo}`));
    await idempotent(
      authenticated(request(server).post(`${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/vendors`)),
      "matrix-vendor-0001",
    ).send({
      role: "processor",
      code: "matrix-vendor",
      legalName: "Matrix Processor Ltd",
      regions: ["CN"],
    });
    expect(calls).toEqual([
      { action: "read", resource: "vendor" },
      { action: "read", resource: "report" },
      { action: "create", resource: "vendor" },
    ]);
    await app.close();
  });

  it("fails closed when production dependencies are missing", async () => {
    const harness = createHarness();
    const base = {
      service: harness.service,
      mode: "production" as const,
      contextIssuer: issuer(),
      resolver: resolverFor(tenantId),
    };

    expect(() =>
      OpenPlatformComplianceModule.forRoot({ ...base })
    ).toThrowError(/requires an idempotency port/u);

    expect(() =>
      OpenPlatformComplianceModule.forRoot({
        service: harness.service,
        mode: "production",
        contextIssuer: issuer(),
        idempotency: productionIdempotency(),
      })
    ).toThrowError(/requires a context resolver/u);

    for (const authorization of [
      createDevelopmentLikeAuthorization(),
      createUnavailableComplianceAuthorization(),
    ]) {
      expect(() =>
        OpenPlatformComplianceModule.forRoot({
          ...base,
          idempotency: productionIdempotency(),
          authorization,
        })
      ).toThrowError(/requires a production authorization port/u);
    }

    expect(() =>
      OpenPlatformComplianceModule.forRoot({
        ...base,
        idempotency: productionIdempotency(),
        authorization: createDevelopmentComplianceAuthorization("all"),
      })
    ).toThrowError(/requires a production authorization port/u);

    const { authorization: allowing } = recordingAuthorization(true);
    const auditFailureRef = await Test.createTestingModule({
      imports: [
        OpenPlatformComplianceModule.forRoot({
          ...base,
          idempotency: productionIdempotency(),
          authorization: allowing,
        }),
      ],
    }).compile();
    const auditFailureApp = auditFailureRef.createNestApplication();
    await expect(auditFailureApp.init()).rejects.toThrowError(
      /open platform compliance audit dependency is not ready/u,
    );

    const storageFailureRef = await Test.createTestingModule({
      imports: [
        OpenPlatformComplianceModule.forRoot({
          ...base,
          service: productionService(harness.service, { persistentStorage: false }),
          idempotency: productionIdempotency(),
          authorization: allowing,
        }),
      ],
    }).compile();
    const storageFailureApp = storageFailureRef.createNestApplication();
    await expect(storageFailureApp.init()).rejects.toThrowError(
      /production compliance requires persistent distributed storage/u,
    );

    const { authorization: denying } = recordingAuthorization(false);
    const app = await createApp(
      productionService(harness.service, { persistentStorage: true }),
      {
        mode: "production",
        authorization: denying,
        idempotency: productionIdempotency(),
      },
    );
    const denied = await authenticated(
      request(app.getHttpServer()).get(
        `${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/privacy-requests`,
      ),
    );
    expect(denied.status).toBe(403);
    expect(denied.body.code).toBe("OPEN_PLATFORM_FORBIDDEN");
    expect(denied.headers["cache-control"]).toBe("no-store");
    await app.close();

    const ready = await createApp(
      productionService(harness.service, { persistentStorage: true }),
      {
        mode: "production",
        authorization: allowing,
        idempotency: productionIdempotency(),
      },
    );
    const unauthenticated = await request(ready.getHttpServer()).get(
      `${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/consents`,
    );
    expect(unauthenticated.status).toBe(401);
    expect(unauthenticated.body.code).toBe("OPEN_PLATFORM_AUTHENTICATION_REQUIRED");
    const read = await authenticated(
      request(ready.getHttpServer()).get(`${OPEN_PLATFORM_COMPLIANCE_BASE_PATH}/consents`),
    );
    expect(read.status).toBe(200);
    expect(read.headers["cache-control"]).toBe("no-store");
    await ready.close();
  });
});

function productionService(
  service: ComplianceDomainService,
  options: { readonly persistentStorage: boolean },
): ComplianceDomainService {
  const repositories = Object.create(service.repositories, {
    readiness: {
      value: Object.freeze({
        storage: options.persistentStorage ? "persistent" as const : "memory" as const,
        distributed: options.persistentStorage,
        ready: () => true,
      }),
    },
  });
  return Object.create(service, {
    audit: { value: productionAudit() },
    repositories: { value: repositories },
  }) as ComplianceDomainService;
}

function createDevelopmentLikeAuthorization(): ComplianceAuthorizationPort {
  return Object.freeze({
    productionReady: false,
    authorize(): boolean {
      return true;
    },
  });
}

function collectionRoute(collection: string): string {
  switch (collection) {
    case "dataAsset":
      return "data-assets";
    case "consentRecord":
      return "consents";
    case "privacyRequest":
      return "privacy-requests";
    case "retentionPolicy":
      return "retention-policies";
    case "crossBorderAssessment":
      return "cross-border-assessments";
    case "vendor":
      return "vendors";
    default:
      throw new Error(`Unsupported collection ${collection}`);
  }
}
