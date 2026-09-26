import { describe, expect, it } from "vitest";
import {
  InMemoryOpenPlatformRepositories,
  createDevelopmentOpenPlatformAuthorization,
  createOpenPlatformRequestContextIssuer,
  createOpenPlatformService,
  type ApiVersion,
  type Application,
  type ApplicationEnvironment,
  type ApiProduct,
  type CredentialDto,
  type OpenPlatformRequestContext,
  type OpenPlatformService,
  type Tenant,
} from "../src/open-platform/index.js";
import {
  InMemoryOpenPlatformAuditOutbox,
  InMemoryOpenPlatformRateLimitStore,
  OPEN_PLATFORM_RUNTIME_ERROR_CODES,
  OpenPlatformApiAuditService,
  OpenPlatformApiRuntimeService,
  OpenPlatformCredentialVerificationService,
  OpenPlatformPolicyEvaluator,
  OpenPlatformRateLimitService,
  OpenPlatformRuntimeModule,
  createOpenPlatformApiRequestContext,
  createOpenPlatformPolicyEvaluator,
  sanitizeOpenPlatformAuditMetadata,
  toOpenPlatformRuntimeContractError,
  type OpenPlatformApiPrincipal,
  type OpenPlatformApiRequestContext,
  type OpenPlatformAuditOutboxPort,
  type OpenPlatformApiRoutePolicy,
  type OpenPlatformOidcBearerVerifierPort,
  type OpenPlatformRateLimitStorePort,
  type OpenPlatformServiceClientVerifierPort,
} from "../src/open-platform/runtime/index.js";

const initialNow = new Date("2030-01-01T00:00:00.000Z");
const tenantId = "tenant-runtime";
const audience = "urn:getbrick:api:orders";
const path = "/open/orders/1.0.0/orders";
const clientId = "orders-service-client";

interface MutableClock {
  value: Date;
}

interface RuntimeHarness {
  service: OpenPlatformService;
  issuer: ReturnType<typeof createOpenPlatformRequestContextIssuer>;
  clock: MutableClock;
  tenant: Tenant;
  application: Application;
  environment: ApplicationEnvironment;
  product: ApiProduct;
  version: ApiVersion;
  credential: CredentialDto;
  secret: string;
  trustedContext(requestId?: string): OpenPlatformRequestContext;
  requestContext(requestId?: string): OpenPlatformApiRequestContext;
}

interface RouteOptions {
  readonly scopes?: readonly string[];
  readonly rateLimit?: { readonly requests: number; readonly windowMs: number };
  readonly quota?: { readonly requests: number; readonly windowMs: number };
}

async function createHarness(
  options: {
    readonly expiresAt?: string;
    readonly clock?: MutableClock;
    readonly productScopes?: readonly string[];
  } = {},
): Promise<RuntimeHarness> {
  const clock = options.clock ?? { value: new Date(initialNow) };
  const repositories = new InMemoryOpenPlatformRepositories({
    clock: () => clock.value,
  });
  const service = createOpenPlatformService({
    mode: "test",
    authorization: createDevelopmentOpenPlatformAuthorization("all"),
    repositories,
    clock: () => clock.value,
  });
  const issuer = createOpenPlatformRequestContextIssuer({
    issuerId: "open-platform-runtime-tests",
    attestation: Object.freeze({ test: true }),
    clock: () => clock.value,
  });
  const setupContext = trusted(issuer, "runtime-setup");
  const tenant = await service.createTenant(setupContext, {
    tenantId,
    name: "Runtime tenant",
    idempotencyKey: "runtime-tenant-create",
  });
  await service.publish(setupContext, {
    resource: "tenant",
    tenantId,
    id: tenant.id,
    idempotencyKey: "runtime-tenant-publish",
  });
  const organization = await service.createDeveloperOrganization(setupContext, {
    tenantId,
    name: "Runtime organization",
    idempotencyKey: "runtime-organization-create",
  });
  await service.publish(setupContext, {
    resource: "developerOrganization",
    tenantId,
    id: organization.id,
    idempotencyKey: "runtime-organization-publish",
  });
  const application = await service.createApplication(setupContext, {
    tenantId,
    organizationId: organization.id,
    name: "Runtime application",
    idempotencyKey: "runtime-application-create",
  });
  await service.publish(setupContext, {
    resource: "application",
    tenantId,
    id: application.id,
    idempotencyKey: "runtime-application-publish",
  });
  const environment = await service.createApplicationEnvironment(setupContext, {
    tenantId,
    applicationId: application.id,
    name: "Production",
    idempotencyKey: "runtime-environment-create",
  });
  await service.publish(setupContext, {
    resource: "applicationEnvironment",
    tenantId,
    id: environment.id,
    idempotencyKey: "runtime-environment-publish",
  });
  const product = await service.createApiProduct(setupContext, {
    tenantId,
    name: "Orders API",
    scopes: options.productScopes ?? ["orders:read", "orders:write"],
    idempotencyKey: "runtime-product-create",
  });
  await service.publish(setupContext, {
    resource: "apiProduct",
    tenantId,
    id: product.id,
    idempotencyKey: "runtime-product-publish",
  });
  const version = await service.createApiVersion(setupContext, {
    tenantId,
    productId: product.id,
    apiVersion: "1.0.0",
    scopes: ["orders:read"],
    idempotencyKey: "runtime-version-create",
  });
  await service.publish(setupContext, {
    resource: "apiVersion",
    tenantId,
    id: version.id,
    idempotencyKey: "runtime-version-publish",
  });
  const issued = await service.issueCredential(setupContext, {
    tenantId,
    applicationId: application.id,
    environmentId: environment.id,
    name: "Orders runtime credential",
    scopes: ["orders:read", "orders:write"],
    ...(options.expiresAt === undefined ? {} : { expiresAt: options.expiresAt }),
    idempotencyKey: "runtime-credential-issue",
  });
  const secret = issued.secret;
  if (secret === undefined) throw new Error("runtime fixture secret missing");
  await service.grantScopes(setupContext, {
    tenantId,
    credentialId: issued.credential.id,
    productId: product.id,
    apiVersionId: version.id,
    scopes: ["orders:read"],
    idempotencyKey: "runtime-grant-create",
  });
  return {
    service,
    issuer,
    clock,
    tenant,
    application,
    environment,
    product,
    version,
    credential: issued.credential,
    secret,
    trustedContext(requestId = `runtime-request-${randomSuffix()}`) {
      return trusted(issuer, requestId);
    },
    requestContext(requestId) {
      const resolved = requestId ?? `runtime-request-${randomSuffix()}`;
      return createOpenPlatformApiRequestContext({
        method: "GET",
        path,
        audience,
        tenantId,
        applicationId: application.id,
        clientId,
        ip: "192.0.2.10",
        requestId: resolved,
      }, trusted(issuer, resolved));
    },
  };
}

function trusted(
  issuer: ReturnType<typeof createOpenPlatformRequestContextIssuer>,
  requestId: string,
): OpenPlatformRequestContext {
  return issuer.issueDevelopment({
    tenantId,
    actorId: "api-gateway",
    requestId,
  });
}

function route(
  harness: RuntimeHarness,
  options: RouteOptions = {},
): OpenPlatformApiRoutePolicy {
  return {
    routeId: "orders-list",
    policyVersion: "policy-v1",
    enabled: true,
    method: "GET",
    path,
    audience,
    productId: harness.product.id,
    apiVersionId: harness.version.id,
    requiredScopes: options.scopes ?? ["orders:read"],
    clientIds: [clientId],
    ...(options.rateLimit === undefined
      ? {}
      : { rateLimit: options.rateLimit }),
    ...(options.quota === undefined ? {} : { quota: options.quota }),
  };
}

function verifier(
  harness: RuntimeHarness,
  adapters: {
    readonly oidcBearerVerifier?: OpenPlatformOidcBearerVerifierPort;
    readonly serviceClientVerifier?: OpenPlatformServiceClientVerifierPort;
  } = {},
): OpenPlatformCredentialVerificationService {
  return new OpenPlatformCredentialVerificationService({
    domain: harness.service,
    mode: "test",
    clock: () => harness.clock.value,
    ...adapters,
  });
}

function apiKey(
  harness: RuntimeHarness,
  version = harness.credential.version,
): {
  readonly type: "apiKey";
  readonly credentialId: string;
  readonly credentialVersion: number;
  readonly secret: string;
} {
  return {
    type: "apiKey",
    credentialId: harness.credential.id,
    credentialVersion: version,
    secret: harness.secret,
  };
}

function adapterIdentity(harness: RuntimeHarness) {
  return {
    active: true as const,
    tenantId,
    applicationId: harness.application.id,
    clientId,
    credentialId: harness.credential.id,
    credentialVersion: harness.credential.version,
    scopes: ["orders:read"],
    audiences: [audience],
    issuedAt: new Date(harness.clock.value.getTime() - 60_000).toISOString(),
    expiresAt: new Date(harness.clock.value.getTime() + 300_000).toISOString(),
  };
}

async function capturedError(operation: () => Promise<unknown>): Promise<unknown> {
  try {
    await operation();
  } catch (error) {
    return error;
  }
  throw new Error("expected operation to fail");
}

let suffix = 0;

function randomSuffix(): string {
  suffix += 1;
  return suffix.toString(36);
}

describe("open platform API runtime credentials and policy", () => {
  it("accepts an active API key through the trusted domain context", async () => {
    const harness = await createHarness();
    const context = harness.requestContext();
    const principal = await verifier(harness).verify(
      context,
      route(harness),
      apiKey(harness),
    );
    expect(principal).toMatchObject({
      authenticationType: "apiKey",
      tenantId,
      applicationId: harness.application.id,
      clientId,
      credentialId: harness.credential.id,
      credentialVersion: 1,
      audience,
    });
    expect(principal.scopes).toEqual(["orders:read"]);
    expect(principal.scopes).not.toContain("orders:write");
    await expect(verifier(harness).verify(
      { ...context } as OpenPlatformApiRequestContext,
      route(harness),
      apiKey(harness),
    )).rejects.toMatchObject({
      code: OPEN_PLATFORM_RUNTIME_ERROR_CODES.AUTHENTICATION_REQUIRED,
    });
  });

  it("supports OIDC bearer and service client adapter ports", async () => {
    const harness = await createHarness();
    const identity = adapterIdentity(harness);
    const oidcVerifier: OpenPlatformOidcBearerVerifierPort = {
      productionReady: false,
      verify: (input) => {
        expect(input.token).toBe("opaque-access-token");
        expect(input.audience).toBe(audience);
        return identity;
      },
    };
    const serviceVerifier: OpenPlatformServiceClientVerifierPort = {
      productionReady: false,
      verify: (input) => {
        expect(input.assertion).toBe("signed-client-assertion");
        expect(input.clientId).toBe(clientId);
        return identity;
      },
    };
    const runtimeVerifier = verifier(harness, {
      oidcBearerVerifier: oidcVerifier,
      serviceClientVerifier: serviceVerifier,
    });
    await expect(runtimeVerifier.verifyOidcBearer(
      harness.requestContext(),
      route(harness),
      { type: "oidcBearer", token: "opaque-access-token" },
    )).resolves.toMatchObject({ authenticationType: "oidcBearer" });
    await expect(runtimeVerifier.verifyServiceClient(
      harness.requestContext(),
      route(harness),
      {
        type: "serviceClient",
        clientId,
        assertion: "signed-client-assertion",
      },
    )).resolves.toMatchObject({ authenticationType: "serviceClient" });
  });

  it("rejects expired, revoked, stale, and parent-disabled credentials", async () => {
    const expiring = await createHarness({
      expiresAt: new Date(initialNow.getTime() + 1_000).toISOString(),
    });
    expiring.clock.value = new Date(initialNow.getTime() + 1_000);
    await expect(verifier(expiring).verify(
      expiring.requestContext(),
      route(expiring),
      apiKey(expiring),
    )).rejects.toMatchObject({
      code: OPEN_PLATFORM_RUNTIME_ERROR_CODES.CREDENTIAL_EXPIRED,
    });

    const revoked = await createHarness();
    await revoked.service.revokeCredential(
      revoked.trustedContext("runtime-revoke"),
      {
        tenantId,
        credentialId: revoked.credential.id,
        idempotencyKey: "runtime-credential-revoke",
      },
    );
    await expect(verifier(revoked).verify(
      revoked.requestContext(),
      route(revoked),
      apiKey(revoked),
    )).rejects.toMatchObject({
      code: OPEN_PLATFORM_RUNTIME_ERROR_CODES.CREDENTIAL_REVOKED,
    });

    const stale = await createHarness();
    await expect(verifier(stale).verify(
      stale.requestContext(),
      route(stale),
      apiKey(stale, stale.credential.version + 1),
    )).rejects.toMatchObject({
      code: OPEN_PLATFORM_RUNTIME_ERROR_CODES.CREDENTIAL_VERSION_MISMATCH,
    });

    const disabled = await createHarness();
    await disabled.service.deactivate(
      disabled.trustedContext("runtime-disable-parent"),
      {
        resource: "applicationEnvironment",
        tenantId,
        id: disabled.environment.id,
        idempotencyKey: "runtime-environment-disable",
      },
    );
    await expect(verifier(disabled).verify(
      disabled.requestContext(),
      route(disabled),
      apiKey(disabled),
    )).rejects.toMatchObject({
      code: OPEN_PLATFORM_RUNTIME_ERROR_CODES.PARENT_RESOURCE_DISABLED,
    });
  });

  it("fails closed for scope and policy failures", async () => {
    const productRestricted = await createHarness({
      productScopes: ["orders:read"],
    });
    const restrictedPrincipal = await verifier(productRestricted).verify(
      productRestricted.requestContext(),
      route(productRestricted),
      apiKey(productRestricted),
    );
    expect(restrictedPrincipal.scopes).toEqual(["orders:read"]);
    expect(restrictedPrincipal.scopes).not.toContain("orders:write");

    const harness = await createHarness();
    await expect(verifier(harness).verify(
      harness.requestContext(),
      route(harness, { scopes: ["orders:write"] }),
      apiKey(harness),
    )).rejects.toMatchObject({
      code: OPEN_PLATFORM_RUNTIME_ERROR_CODES.INVALID_SCOPE,
    });
    const principal = await verifier(harness).verify(
      harness.requestContext(),
      route(harness),
      apiKey(harness),
    );
    const context = harness.requestContext();
    const failing = createOpenPlatformPolicyEvaluator({
      decisionPort: {
        evaluate: () => {
          throw new Error("policy backend unavailable");
        },
      },
    });
    await expect(failing.evaluate({
      context,
      route: route(harness),
      principal,
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_RUNTIME_ERROR_CODES.POLICY_UNAVAILABLE,
    });
  });
});

describe("open platform API runtime rate limits and audit", () => {
  it("keys limits by tenant, application, credential, and route", async () => {
    const harness = await createHarness();
    const store = new InMemoryOpenPlatformRateLimitStore({
      clock: () => harness.clock.value,
    });
    const rateLimits = new OpenPlatformRateLimitService({
      store,
      clock: () => harness.clock.value,
    });
    const outbox = new InMemoryOpenPlatformAuditOutbox();
    const runtime = new OpenPlatformApiRuntimeService({
      mode: "test",
      credentials: verifier(harness),
      policyEvaluator: new OpenPlatformPolicyEvaluator(),
      rateLimits,
      audit: new OpenPlatformApiAuditService({
        outbox,
        clock: () => harness.clock.value,
      }),
      readiness: async () => true,
    });
    const limitedRoute = route(harness, {
      rateLimit: { requests: 1, windowMs: 60_000 },
    });
    const context = harness.requestContext();
    await expect(runtime.admit(
      context,
      limitedRoute,
      apiKey(harness),
    )).resolves.toMatchObject({
      rateLimit: {
        allowed: true,
        rateLimit: { remaining: 0 },
      },
    });
    const error = await capturedError(() => runtime.admit(
      context,
      limitedRoute,
      apiKey(harness),
    ));
    expect(error).toMatchObject({
      code: OPEN_PLATFORM_RUNTIME_ERROR_CODES.RATE_LIMIT_EXCEEDED,
      retryAfterSeconds: 60,
    });
    expect(toOpenPlatformRuntimeContractError(
      error,
      context.requestId,
    )).toMatchObject({
      statusCode: 429,
      headers: { "Retry-After": "60" },
      body: {
        error: { code: OPEN_PLATFORM_RUNTIME_ERROR_CODES.RATE_LIMIT_EXCEEDED },
        requestId: context.requestId,
      },
    });
  });

  it("bounds capacity by evicting expired and least-recently-used windows", async () => {
    const harness = await createHarness();
    const store = new InMemoryOpenPlatformRateLimitStore({
      clock: () => harness.clock.value,
      maxEntries: 2,
    });
    const consume = (routeId: string) => store.consume({
      key: {
        tenantId,
        applicationId: harness.application.id,
        credentialId: harness.credential.id,
        routeId,
      },
      rateLimit: { requests: 1, windowMs: 1_000 },
      now: harness.clock.value.toISOString(),
    });
    await expect(consume("route-a")).resolves.toMatchObject({ allowed: true });
    await expect(consume("route-b")).resolves.toMatchObject({ allowed: true });
    expect(store.entryCount).toBe(2);
    await expect(consume("route-c")).resolves.toMatchObject({ allowed: true });
    expect(store.entryCount).toBe(2);
    await expect(consume("route-b")).resolves.toMatchObject({
      allowed: false,
      limitedBy: "rateLimit",
    });
    await expect(consume("route-a")).resolves.toMatchObject({ allowed: true });
    expect(store.entryCount).toBe(2);
    harness.clock.value = new Date(initialNow.getTime() + 2_000);
    await expect(consume("route-d")).resolves.toMatchObject({ allowed: true });
    expect(store.entryCount).toBe(1);
  });

  it("enforces quota with a stable retryable error", async () => {
    const harness = await createHarness();
    const store = new InMemoryOpenPlatformRateLimitStore({
      clock: () => harness.clock.value,
    });
    const service = new OpenPlatformRateLimitService({
      store,
      clock: () => harness.clock.value,
    });
    const principal = await verifier(harness).verify(
      harness.requestContext(),
      route(harness),
      apiKey(harness),
    );
    const quotaRoute = route(harness, {
      rateLimit: { requests: 2, windowMs: 60_000 },
      quota: { requests: 1, windowMs: 30_000 },
    });
    const context = harness.requestContext();
    await expect(service.enforce(context, principal, quotaRoute)).resolves
      .toMatchObject({ allowed: true });
    await expect(service.enforce(context, principal, quotaRoute)).rejects
      .toMatchObject({
        code: OPEN_PLATFORM_RUNTIME_ERROR_CODES.QUOTA_EXCEEDED,
        retryAfterSeconds: 30,
      });
  });

  it("rejects non-production ports and gates production services on readiness", async () => {
    const harness = await createHarness();
    const persistentReadiness = Object.freeze({
      storage: "persistent" as const,
      distributed: true,
      ready: () => true,
    });
    const notReadyStore: OpenPlatformRateLimitStorePort = {
      productionReady: false,
      readiness: persistentReadiness,
      consume: async () => {
        throw new Error("rate store must not be called");
      },
    };
    const unavailableStore: OpenPlatformRateLimitStorePort = {
      productionReady: true,
      readiness: {
        storage: "persistent",
        distributed: true,
        ready: () => false,
      },
      consume: async () => {
        throw new Error("rate store must not be called");
      },
    };
    expect(() => new OpenPlatformRateLimitService({
      mode: "production",
      store: new InMemoryOpenPlatformRateLimitStore(),
    })).toThrowError();
    expect(() => new OpenPlatformRateLimitService({
      mode: "production",
      store: notReadyStore,
    })).toThrowError();
    const rateLimits = new OpenPlatformRateLimitService({
      mode: "production",
      store: unavailableStore,
      clock: () => harness.clock.value,
    });
    await expect(rateLimits.isReady()).resolves.toBe(false);

    const notReadyOutbox: OpenPlatformAuditOutboxPort = {
      productionReady: false,
      readiness: persistentReadiness,
      enqueue: async () => {
        throw new Error("audit outbox must not be called");
      },
    };
    const unavailableOutbox: OpenPlatformAuditOutboxPort = {
      productionReady: true,
      readiness: {
        storage: "persistent",
        distributed: true,
        ready: () => false,
      },
      enqueue: async () => {
        throw new Error("audit outbox must not be called");
      },
    };
    expect(() => new OpenPlatformApiAuditService({
      mode: "production",
      outbox: new InMemoryOpenPlatformAuditOutbox(),
    })).toThrowError();
    expect(() => new OpenPlatformApiAuditService({
      mode: "production",
      outbox: notReadyOutbox,
    })).toThrowError();
    const audit = new OpenPlatformApiAuditService({
      mode: "production",
      outbox: unavailableOutbox,
      clock: () => harness.clock.value,
    });
    await expect(audit.isReady()).resolves.toBe(false);

    const context = harness.requestContext();
    const principal = await verifier(harness).verify(
      context,
      route(harness),
      apiKey(harness),
    );
    await expect(rateLimits.enforce(
      context,
      principal,
      route(harness),
    )).rejects.toMatchObject({
      code: OPEN_PLATFORM_RUNTIME_ERROR_CODES.RATE_LIMITER_UNAVAILABLE,
    });
    await expect(audit.record({
      context,
      principal,
      type: "api.call.accepted",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_RUNTIME_ERROR_CODES.AUDIT_UNAVAILABLE,
    });
  });

  it("writes only allowlisted sanitized audit metadata to the outbox", async () => {
    const harness = await createHarness();
    const context = harness.requestContext();
    const principal: OpenPlatformApiPrincipal = await verifier(harness).verify(
      context,
      route(harness),
      apiKey(harness),
    );
    const outbox = new InMemoryOpenPlatformAuditOutbox();
    const audit = new OpenPlatformApiAuditService({
      outbox,
      clock: () => harness.clock.value,
      idGenerator: () => "audit-event-one",
    });
    const secret = "raw-api-key-never-persist";
    const token = "raw-bearer-token-never-persist";
    const event = await audit.record({
      context,
      principal,
      type: "api.call.completed",
      metadata: {
        token,
        secret,
        authorization: `Bearer ${token}`,
        nested: { token },
        routeId: "orders-list",
        statusCode: 200,
        durationMs: 12,
      },
    });
    expect(event.metadata).toEqual({
      durationMs: 12,
      routeId: "orders-list",
      statusCode: 200,
    });
    const serialized = JSON.stringify(outbox.snapshot());
    expect(serialized).not.toContain(secret);
    expect(serialized).not.toContain(token);
    expect(serialized).not.toContain("authorization");
    expect(sanitizeOpenPlatformAuditMetadata({
      errorCode: "rate_limit_exceeded",
      token,
    })).toEqual({ errorCode: "rate_limit_exceeded" });
  });

  it("exposes a standalone Nest module and rejects production memory defaults", async () => {
    const harness = await createHarness();
    const module = OpenPlatformRuntimeModule.forRoot({
      mode: "test",
      domain: harness.service,
      clock: () => harness.clock.value,
    });
    expect(module.controllers).toBeUndefined();
    const providers = module.providers?.map((provider) =>
      "provide" in provider ? provider.provide : undefined
    );
    expect(providers).toEqual(expect.arrayContaining([
      OpenPlatformCredentialVerificationService,
      OpenPlatformRateLimitService,
      OpenPlatformApiAuditService,
      OpenPlatformApiRuntimeService,
    ]));
    expect(() => OpenPlatformRuntimeModule.forRoot({
      mode: "production",
      domain: harness.service,
    })).toThrowError();
  });
});
