import "reflect-metadata";
import { Test } from "@nestjs/testing";
import request from "supertest";
import { describe, expect, it } from "vitest";
import {
  createDevelopmentOpenPlatformAuthorization,
  createDevelopmentOpenPlatformRequestContext,
  createOpenPlatformRequestContextIssuer,
  authenticationRequired,
  credentialUnavailable,
  forbidden,
  idempotencyRequestInProgress,
  resourceConflict,
  secretIssuanceFailed,
  storageUnavailable,
  tenantMismatch,
  toOpenPlatformHttpError,
  validationError,
  OpenPlatformHttpModule,
  OPEN_PLATFORM_HTTP_BASE_PATH,
  type OpenPlatformHttpContextResolution,
  type OpenPlatformHttpRequest,
  type OpenPlatformService,
} from "../src/open-platform/index.js";

const fixedNow = new Date("2030-01-01T00:00:00.000Z");
const tenantId = "tenant-http";
const actorId = "actor-http";
const requestId = "request-http";

function createApp(
  resolve: (
    request: OpenPlatformHttpRequest,
  ) => OpenPlatformHttpContextResolution,
) {
  const issuer = createOpenPlatformRequestContextIssuer({
    issuerId: "open-platform-http-tests",
    attestation: Object.freeze({ test: true }),
    clock: () => fixedNow,
  });
  return Test.createTestingModule({
    imports: [
      OpenPlatformHttpModule.forRoot({
        mode: "test",
        authorization: createDevelopmentOpenPlatformAuthorization("all"),
        contextIssuer: issuer,
        clock: () => fixedNow,
        resolver: {
          resolve: async (httpRequest) => resolve(httpRequest),
        },
      }),
    ],
  }).compile();
}

function authenticatedResolver(
  requestValue: OpenPlatformHttpRequest,
): { tenantId: string; actorId: string; requestId: string } | undefined {
  const headers = requestValue.headers ?? {};
  const authenticated = Object.entries(headers).some(
    ([key, value]) => key.toLowerCase() === "x-test-auth" && value === "valid",
  );
  return authenticated
    ? { tenantId, actorId, requestId }
    : undefined;
}

function auth<T extends { set: (name: string, value: string) => T }>(test: T): T {
  return test.set("x-test-auth", "valid");
}

describe("open platform HTTP control plane", () => {
  it("rejects missing context and tenant mismatches before the service", async () => {
    const moduleRef = await createApp(authenticatedResolver);
    const app = moduleRef.createNestApplication();
    await app.init();
    const server = app.getHttpServer();

    const missing = await request(server)
      .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/tenants`)
      .set("Idempotency-Key", "missing-context")
      .send({ name: "Missing context" });
    expect(missing.status).toBe(401);
    expect(missing.body).toMatchObject({
      code: "OPEN_PLATFORM_AUTHENTICATION_REQUIRED",
      message: "Authentication is required",
    });
    expect(JSON.stringify(missing.body)).not.toContain("tenant-http");

    const mismatch = await auth(
      request(server)
        .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/tenants`)
        .set("Idempotency-Key", "tenant-mismatch")
        .send({ tenantId: "tenant-other", name: "Wrong tenant" }),
    );
    expect(mismatch.status).toBe(403);
    expect(mismatch.body).toMatchObject({
      code: "OPEN_PLATFORM_TENANT_MISMATCH",
      message: "Access is forbidden",
    });
    expect(JSON.stringify(mismatch.body)).not.toContain("tenant-other");

    const queryMismatch = await auth(
      request(server).get(`${OPEN_PLATFORM_HTTP_BASE_PATH}/tenants?tenantId=tenant-other`),
    );
    expect(queryMismatch.status).toBe(403);
    expect(queryMismatch.body.code).toBe("OPEN_PLATFORM_TENANT_MISMATCH");

    await app.close();
  });

  it("maps resolver backend failures to retryable service errors and preserves domain denials", async () => {
    const moduleRef = await createApp((requestValue) => {
      const mode = requestValue.headers?.["x-resolver-mode"];
      if (mode === "auth") throw authenticationRequired();
      if (mode === "tenant") throw tenantMismatch();
      if (mode === "forbidden") throw forbidden();
      throw new Error("resolver backend unavailable");
    });
    const app = moduleRef.createNestApplication();
    await app.init();
    const server = app.getHttpServer();

    const unavailable = await auth(
      request(server)
        .get(`${OPEN_PLATFORM_HTTP_BASE_PATH}/tenants`)
        .set("x-resolver-mode", "backend"),
    );
    expect(unavailable.status).toBe(503);
    expect(unavailable.body).toMatchObject({
      code: "OPEN_PLATFORM_STORAGE_UNAVAILABLE",
      message: "Open platform service is unavailable",
    });
    expect(unavailable.headers["retry-after"]).toBe("1");
    expect(JSON.stringify(unavailable.body)).not.toContain("resolver backend unavailable");

    const authenticationFailure = await auth(
      request(server)
        .get(`${OPEN_PLATFORM_HTTP_BASE_PATH}/tenants`)
        .set("x-resolver-mode", "auth"),
    );
    expect(authenticationFailure.status).toBe(401);
    expect(authenticationFailure.body.code).toBe("OPEN_PLATFORM_AUTHENTICATION_REQUIRED");

    const tenantDenied = await auth(
      request(server)
        .get(`${OPEN_PLATFORM_HTTP_BASE_PATH}/tenants`)
        .set("x-resolver-mode", "tenant"),
    );
    expect(tenantDenied.status).toBe(403);
    expect(tenantDenied.body.code).toBe("OPEN_PLATFORM_TENANT_MISMATCH");

    const forbiddenDenied = await auth(
      request(server)
        .get(`${OPEN_PLATFORM_HTTP_BASE_PATH}/tenants`)
        .set("x-resolver-mode", "forbidden"),
    );
    expect(forbiddenDenied.status).toBe(403);
    expect(forbiddenDenied.body.code).toBe("OPEN_PLATFORM_FORBIDDEN");

    await app.close();
  });

  it("completes basic development requests and keeps credential metadata secret-free", async () => {
    const moduleRef = await createApp(authenticatedResolver);
    const app = moduleRef.createNestApplication();
    await app.init();
    const server = app.getHttpServer();

    const tenant = await auth(
      request(server)
        .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/tenants`)
        .set("Idempotency-Key", "http-tenant-create")
        .send({ name: "HTTP tenant" }),
    );
    expect(tenant.status).toBe(201);
    expect(tenant.body).toMatchObject({ tenantId, name: "HTTP tenant" });
    expect(tenant.headers["cache-control"]).toBe("no-store");

    const publishedTenant = await auth(
      request(server)
        .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/tenants/${tenant.body.tenantId}/publish`)
        .set("Idempotency-Key", "http-tenant-publish")
        .send({}),
    );
    expect(publishedTenant.status).toBe(201);
    expect(publishedTenant.body.status).toBe("published");

    const tenantRecord = await auth(
      request(server).get(`${OPEN_PLATFORM_HTTP_BASE_PATH}/tenant-records/${tenant.body.id}`),
    );
    expect(tenantRecord.status).toBe(200);
    expect(tenantRecord.body.id).toBe(tenant.body.id);

    const resourceIdInTenantKeyPath = await auth(
      request(server).get(`${OPEN_PLATFORM_HTTP_BASE_PATH}/tenants/${tenant.body.id}`),
    );
    expect(resourceIdInTenantKeyPath.status).toBe(403);
    expect(resourceIdInTenantKeyPath.body.code).toBe("OPEN_PLATFORM_TENANT_MISMATCH");

    const listed = await auth(request(server).get(`${OPEN_PLATFORM_HTTP_BASE_PATH}/tenants`));
    expect(listed.status).toBe(200);
    expect(listed.body).toHaveLength(1);

    const organization = await auth(
      request(server)
        .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/organizations`)
        .set("Idempotency-Key", "http-organization-create")
        .send({ name: "HTTP organization" }),
    );
    expect(organization.status).toBe(201);

    const publishedOrganization = await auth(
      request(server)
        .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/organizations/${organization.body.id}/publish`)
        .set("Idempotency-Key", "http-organization-publish")
        .send({}),
    );
    expect(publishedOrganization.status).toBe(201);

    const application = await auth(
      request(server)
        .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/applications`)
        .set("Idempotency-Key", "http-application-create")
        .send({ organizationId: organization.body.id, name: "HTTP application" }),
    );
    expect(application.status).toBe(201);

    const publishedApplication = await auth(
      request(server)
        .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/applications/${application.body.id}/publish`)
        .set("Idempotency-Key", "http-application-publish")
        .send({}),
    );
    expect(publishedApplication.status).toBe(201);

    const environment = await auth(
      request(server)
        .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/applications/${application.body.id}/environments`)
        .set("Idempotency-Key", "http-environment-create")
        .send({ name: "Production" }),
    );
    expect(environment.status).toBe(201);

    const publishedEnvironment = await auth(
      request(server)
        .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/applications/${application.body.id}/environments/${environment.body.id}/publish`)
        .set("Idempotency-Key", "http-environment-publish")
        .send({}),
    );
    expect(publishedEnvironment.status).toBe(201);

    const product = await auth(
      request(server)
        .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/catalog/products`)
        .set("Idempotency-Key", "http-product-create")
        .send({ name: "Orders API", scopes: ["orders:read"] }),
    );
    expect(product.status).toBe(201);

    const publishedProduct = await auth(
      request(server)
        .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/catalog/products/${product.body.id}/publish`)
        .set("Idempotency-Key", "http-product-publish")
        .send({}),
    );
    expect(publishedProduct.status).toBe(201);

    const version = await auth(
      request(server)
        .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/catalog/products/${product.body.id}/versions`)
        .set("Idempotency-Key", "http-version-create")
        .send({ apiVersion: "1.0.0", scopes: ["orders:read"] }),
    );
    expect(version.status).toBe(201);

    const publishedVersion = await auth(
      request(server)
        .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/catalog/products/${product.body.id}/versions/${version.body.id}/publish`)
        .set("Idempotency-Key", "http-version-publish")
        .send({}),
    );
    expect(publishedVersion.status).toBe(201);

    const issued = await auth(
      request(server)
        .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/credentials`)
        .set("Idempotency-Key", "http-credential-issue")
        .send({
          applicationId: application.body.id,
          environmentId: environment.body.id,
          name: "HTTP credential",
          scopes: ["orders:read"],
        }),
    );
    expect(issued.status).toBe(201);
    expect(issued.headers["cache-control"]).toBe("no-store");
    expect(typeof issued.body.secret).toBe("string");
    expect(issued.body.secret.length).toBeGreaterThan(31);
    expect(issued.body.credential).not.toHaveProperty("secret");

    const credential = await auth(
      request(server).get(`${OPEN_PLATFORM_HTTP_BASE_PATH}/credentials/${issued.body.credential.id}`),
    );
    expect(credential.status).toBe(200);
    expect(credential.body).not.toHaveProperty("secret");
    expect(credential.body).not.toHaveProperty("fingerprint");
    expect(JSON.stringify(credential.body)).not.toContain(issued.body.secret);

    const credentials = await auth(request(server).get(`${OPEN_PLATFORM_HTTP_BASE_PATH}/credentials`));
    expect(credentials.status).toBe(200);
    expect(JSON.stringify(credentials.body)).not.toContain(issued.body.secret);

    const subscription = await auth(
      request(server)
        .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/subscriptions`)
        .set("Idempotency-Key", "http-subscription-create")
        .send({
          applicationId: application.body.id,
          productId: product.body.id,
          apiVersionId: version.body.id,
          name: "HTTP subscription",
          scopes: ["orders:read"],
        }),
    );
    expect(subscription.status).toBe(201);

    const publishedSubscription = await auth(
      request(server)
        .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/subscriptions/${subscription.body.id}/publish`)
        .set("Idempotency-Key", "http-subscription-publish")
        .send({}),
    );
    expect(publishedSubscription.status).toBe(201);

    const grant = await auth(
      request(server)
        .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/scope-grants`)
        .set("Idempotency-Key", "http-grant-create")
        .send({
          credentialId: issued.body.credential.id,
          productId: product.body.id,
          apiVersionId: version.body.id,
          scopes: ["orders:read"],
        }),
    );
    expect(grant.status).toBe(201);

    const usage = await auth(
      request(server)
        .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/usage`)
        .set("Idempotency-Key", "http-usage-record")
        .send({
          subscriptionId: subscription.body.id,
          credentialId: issued.body.credential.id,
          metric: "api.requests",
          quantity: 2,
        }),
    );
    expect(usage.status).toBe(201);

    const usageList = await auth(request(server).get(`${OPEN_PLATFORM_HTTP_BASE_PATH}/usage`));
    expect(usageList.status).toBe(200);
    expect(usageList.body).toHaveLength(1);

    const revokedGrant = await auth(
      request(server)
        .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/scope-grants/${grant.body.id}/revoke`)
        .set("Idempotency-Key", "http-grant-revoke")
        .send({}),
    );
    expect(revokedGrant.status).toBe(200);
    expect(revokedGrant.body.status).toBe("revoked");

    const rotated = await auth(
      request(server)
        .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/credentials/${issued.body.credential.id}/rotate`)
        .set("Idempotency-Key", "http-credential-rotate")
        .send({}),
    );
    expect(rotated.status).toBe(200);
    expect(rotated.headers["cache-control"]).toBe("no-store");
    expect(typeof rotated.body.secret).toBe("string");
    expect(rotated.body.credential).not.toHaveProperty("secret");

    const revokedCredential = await auth(
      request(server)
        .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/credentials/${rotated.body.credential.id}/revoke`)
        .set("Idempotency-Key", "http-credential-revoke")
        .send({}),
    );
    expect(revokedCredential.status).toBe(200);
    expect(revokedCredential.body.status).toBe("revoked");

    await app.close();
  });

  it("manages webhook and audit routes with idempotency and no-store responses", async () => {
    const issuer = createOpenPlatformRequestContextIssuer({
      issuerId: "open-platform-http-management",
      attestation: Object.freeze({ test: true }),
      clock: () => fixedNow,
    });
    const moduleRef = await Test.createTestingModule({
      imports: [
        OpenPlatformHttpModule.forRoot({
          mode: "test",
          authorization: createDevelopmentOpenPlatformAuthorization("all"),
          contextIssuer: issuer,
          clock: () => fixedNow,
          resolver: { resolve: () => ({ tenantId, actorId, requestId }) },
          webhookTransport: { send: async () => ({ statusCode: 204 }) },
        }),
      ],
    }).compile();
    const app = moduleRef.createNestApplication();
    await app.init();
    const server = app.getHttpServer();

    const missingKey = await auth(request(server)
      .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/webhooks`)
      .send({
        applicationId: "app-1",
        environmentId: "env-1",
        name: "Events",
        endpointUrl: "https://client.example.test/webhook",
        events: ["application.status_changed"],
      }));
    expect(missingKey.status).toBe(400);

    const created = await auth(request(server)
      .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/webhooks`)
      .set("Idempotency-Key", "http-webhook-create")
      .send({
        applicationId: "app-1",
        environmentId: "env-1",
        name: "Events",
        endpointUrl: "https://client.example.test/webhook",
        events: ["application.status_changed"],
      }));
    expect(created.status).toBe(201);
    expect(created.headers["cache-control"]).toBe("no-store");
    expect(typeof created.body.secret).toBe("string");
    expect(created.body.secretVersion).toBe(1);
    expect(created.body.webhook).not.toHaveProperty("signingSecretReference");
    expect(JSON.stringify(created.body)).not.toContain("vault://");
    const replayed = await auth(request(server)
      .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/webhooks`)
      .set("Idempotency-Key", "http-webhook-create")
      .send({
        applicationId: "app-1",
        environmentId: "env-1",
        name: "Events",
        endpointUrl: "https://client.example.test/webhook",
        events: ["application.status_changed"],
      }));
    expect(replayed.status).toBe(201);
    expect(replayed.body.webhook.id).toBe(created.body.webhook.id);
    expect(replayed.body.replayed).toBe(true);
    expect(replayed.body.secret).toBe("");

    const webhookId = created.body.webhook.id;
    const listed = await auth(request(server).get(`${OPEN_PLATFORM_HTTP_BASE_PATH}/webhooks`));
    expect(listed.status).toBe(200);
    expect(listed.body.items).toHaveLength(1);
    expect(listed.body.items[0]).not.toHaveProperty("signingSecretReference");

    const paused = await auth(request(server)
      .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/webhooks/${webhookId}/pause`)
      .set("Idempotency-Key", "http-webhook-pause")
      .send({}));
    expect(paused.status).toBe(200);
    expect(paused.body.status).toBe("paused");
    const resumed = await auth(request(server)
      .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/webhooks/${webhookId}/resume`)
      .set("Idempotency-Key", "http-webhook-resume")
      .send({}));
    expect(resumed.status).toBe(200);
    expect(resumed.body.status).toBe("active");
    const rotated = await auth(request(server)
      .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/webhooks/${webhookId}/rotate-secret`)
      .set("Idempotency-Key", "http-webhook-rotate")
      .send({}));
    expect(rotated.status).toBe(200);
    expect(rotated.body.secretVersion).toBe(2);
    expect(JSON.stringify(rotated.body)).not.toContain("vault://");
    const tested = await auth(request(server)
      .post(`${OPEN_PLATFORM_HTTP_BASE_PATH}/webhooks/${webhookId}/test`)
      .set("Idempotency-Key", "http-webhook-test")
      .send({ eventId: "http-event-1", eventType: "application.status_changed" }));
    expect(tested.status).toBe(200);
    expect(tested.body.deadLettered).toBe(false);
    const audit = await auth(request(server).get(`${OPEN_PLATFORM_HTTP_BASE_PATH}/audit-events?limit=100`));
    expect(audit.status).toBe(200);
    expect(audit.body.items.length).toBeGreaterThan(0);
    expect(JSON.stringify(audit.body)).not.toContain("vault://");
    expect(JSON.stringify(audit.body)).not.toContain(rotated.body.secret);

    await app.close();
  });

  it("delegates domain status mapping to the shared error contract", () => {
    expect(toOpenPlatformHttpError(validationError("invalid"), "request-safe")).toMatchObject({
      statusCode: 400,
      body: {
        code: "OPEN_PLATFORM_VALIDATION_ERROR",
        message: "Open platform request is invalid",
        requestId: "request-safe",
      },
    });
    expect(toOpenPlatformHttpError(credentialUnavailable())).toMatchObject({
      statusCode: 423,
      body: {
        code: "OPEN_PLATFORM_CREDENTIAL_UNAVAILABLE",
        message: "Credential is unavailable",
      },
    });
    expect(toOpenPlatformHttpError(idempotencyRequestInProgress())).toMatchObject({
      statusCode: 409,
      body: {
        code: "OPEN_PLATFORM_IDEMPOTENCY_REQUEST_IN_PROGRESS",
        message: "Open platform request conflicts with current state",
      },
    });
    expect(toOpenPlatformHttpError(storageUnavailable())).toMatchObject({
      statusCode: 503,
      body: {
        code: "OPEN_PLATFORM_STORAGE_UNAVAILABLE",
        message: "Open platform service is unavailable",
      },
    });
    expect(toOpenPlatformHttpError(secretIssuanceFailed())).toMatchObject({
      statusCode: 503,
      body: {
        code: "OPEN_PLATFORM_SECRET_ISSUANCE_FAILED",
        message: "Open platform service is unavailable",
      },
    });
    expect(toOpenPlatformHttpError(resourceConflict("conflict"))).toMatchObject({
      statusCode: 409,
      body: {
        code: "OPEN_PLATFORM_RESOURCE_CONFLICT",
        message: "Open platform request conflicts with current state",
      },
    });
    const unknown = toOpenPlatformHttpError(new Error("vault://hidden-secret"));
    expect(unknown.statusCode).toBe(500);
    expect(JSON.stringify(unknown)).not.toContain("vault://");
    expect(JSON.stringify(unknown)).not.toContain("hidden-secret");
  });

  it("rejects development assurance in production without upgrading it", async () => {
    const contextIssuer = createOpenPlatformRequestContextIssuer({
      issuerId: "open-platform-http-production-context",
      attestation: Object.freeze({ production: true }),
      clock: () => fixedNow,
    });
    const developmentContext = createDevelopmentOpenPlatformRequestContext(
      { tenantId, actorId, requestId },
      { issuerId: "open-platform-http-development-context", clock: () => fixedNow },
    );
    const service = {
      mode: "production",
      isReady: async () => ({
        ready: true,
        mode: "production",
        storage: "persistent",
        distributed: true,
      }),
    } as unknown as OpenPlatformService;
    const moduleRef = await Test.createTestingModule({
      imports: [
        OpenPlatformHttpModule.forRoot({
          service,
          mode: "production",
          contextIssuer,
          resolver: { resolve: () => developmentContext },
        }),
      ],
    }).compile();
    const app = moduleRef.createNestApplication();
    await app.init();
    const response = await request(app.getHttpServer()).get(
      `${OPEN_PLATFORM_HTTP_BASE_PATH}/tenants`,
    );
    expect(response.status).toBe(401);
    expect(response.body.code).toBe("OPEN_PLATFORM_AUTHENTICATION_REQUIRED");
    await app.close();
  });

  it("rejects a service branch whose mode differs from service.mode", () => {
    const contextIssuer = createOpenPlatformRequestContextIssuer({
      issuerId: "open-platform-http-mode-mismatch",
      attestation: Object.freeze({ test: true }),
      clock: () => fixedNow,
    });
    const service = {
      mode: "test",
      isReady: async () => ({
        ready: true,
        mode: "test",
        storage: "memory",
        distributed: false,
      }),
    } as unknown as OpenPlatformService;
    expect(() => OpenPlatformHttpModule.forRoot({
      service,
      mode: "production",
      contextIssuer,
      resolver: { resolve: () => ({ tenantId, actorId, requestId }) },
    })).toThrowError("Open platform HTTP mode must match service mode");
  });

  it("fails service-branch startup when readiness is false", async () => {
    const service = {
      mode: "test",
      isReady: async () => ({
        ready: false,
        mode: "test",
        storage: "memory",
        distributed: false,
      }),
    } as unknown as OpenPlatformService;
    const contextIssuer = createOpenPlatformRequestContextIssuer({
      issuerId: "open-platform-http-readiness",
      attestation: Object.freeze({ test: true }),
      clock: () => fixedNow,
    });
    const moduleRef = await Test.createTestingModule({
      imports: [
        OpenPlatformHttpModule.forRoot({
          service,
          contextIssuer,
          resolver: {
            resolve: () => ({ tenantId, actorId, requestId }),
          },
        }),
      ],
    }).compile();
    await expect(moduleRef.init()).rejects.toThrow("open platform storage is not ready");
  });

  it("fails closed when production has no explicit resolver", () => {
    expect(() => OpenPlatformHttpModule.forRoot({
      mode: "production",
      authorization: {
        productionReady: true,
        authorize: () => true,
      },
      contextIssuer: createOpenPlatformRequestContextIssuer({
        issuerId: "open-platform-http-production",
        attestation: Object.freeze({ production: true }),
      }),
      allowInMemoryInProduction: true,
    })).toThrowError();
  });
});
