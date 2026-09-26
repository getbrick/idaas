import { randomUUID } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  InMemoryIdempotencyStore,
  InMemoryOpenPlatformRepositories,
  OPEN_PLATFORM_AUTHORIZATION,
  OPEN_PLATFORM_ERROR_CODES,
  OPEN_PLATFORM_EVENT_PUBLISHER,
  OPEN_PLATFORM_OUTBOX,
  OPEN_PLATFORM_REQUEST_CONTEXT_ISSUER,
  OPEN_PLATFORM_SERVICE,
  OPEN_PLATFORM_WEBHOOK_SERVICE,
  OpenPlatformProviderModule,
  OpenPlatformService,
  canTransitionCredential,
  canTransitionLifecycle,
  createDevelopmentOpenPlatformAuthorization,
  createOpenPlatformRequestContextIssuer,
  createOpenPlatformService,
  hashOpenPlatformIdempotencyRequest,
  resourceNotFound,
  toCredentialDto,
  toOpenPlatformContractError,
  type Application,
  type ApplicationEnvironment,
  type ApiProduct,
  type ApiVersion,
  type CredentialRecord,
  type CredentialSecretProvider,
  type IssueCredentialCommand,
  type OpenPlatformDependencyReadiness,
  type OpenPlatformRequestContext,
  type OpenPlatformServiceOptions,
  type ScopeGrant,
  type Subscription,
  type Tenant,
} from "../src/open-platform/index.js";

const fixedNow = new Date("2030-01-01T00:00:00.000Z");
const persistentReadiness: OpenPlatformDependencyReadiness = Object.freeze({
  storage: "persistent" as const,
  distributed: true,
  ready: () => true,
});

interface Harness {
  service: OpenPlatformService;
  repositories: InMemoryOpenPlatformRepositories;
  context(tenantId: string, actorId?: string): OpenPlatformRequestContext;
}

function createHarness(options: {
  repositories?: InMemoryOpenPlatformRepositories;
  secretProvider?: CredentialSecretProvider;
  authorization?: OpenPlatformServiceOptions["authorization"];
  mode?: OpenPlatformServiceOptions["mode"];
  allowInMemoryInProduction?: boolean;
} = {}): Harness {
  const repositories = options.repositories ?? new InMemoryOpenPlatformRepositories({
    clock: () => fixedNow,
  });
  const authorization = options.authorization ??
    createDevelopmentOpenPlatformAuthorization("all");
  const service = createOpenPlatformService({
    mode: options.mode ?? "test",
    authorization,
    repositories,
    clock: () => fixedNow,
    ...(options.secretProvider === undefined
      ? {}
      : { secretProvider: options.secretProvider }),
    ...(options.allowInMemoryInProduction === undefined
      ? {}
      : { allowInMemoryInProduction: options.allowInMemoryInProduction }),
  });
  const contextIssuer = createOpenPlatformRequestContextIssuer({
    issuerId: "open-platform-tests",
    attestation: Object.freeze({ test: true }),
    clock: () => fixedNow,
  });
  let requestSequence = 0;
  return {
    service,
    repositories,
    context(tenantId, actorId = "actor-one") {
      requestSequence += 1;
      return contextIssuer.issueDevelopment({
        tenantId,
        actorId,
        requestId: `request-${requestSequence}`,
      });
    },
  };
}

async function createPublishedTenant(
  service: OpenPlatformService,
  context: OpenPlatformRequestContext,
  tenantId: string,
): Promise<Tenant> {
  const tenant = await service.createTenant(context, {
    tenantId,
    name: `${tenantId} tenant`,
    idempotencyKey: `${tenantId}-create`,
  });
  await service.publish(context, {
    resource: "tenant",
    tenantId,
    id: tenant.id,
    idempotencyKey: `${tenantId}-publish`,
  });
  return tenant;
}

interface ApiFixture {
  tenant: Tenant;
  application: Application;
  environment: ApplicationEnvironment;
  product: ApiProduct;
  version: ApiVersion;
  subscription: Subscription;
  credential: CredentialRecord;
  credentialSecret: string;
  grant: ScopeGrant;
}

async function createApiFixture(
  harness: Harness,
  tenantId = "tenant-api",
): Promise<ApiFixture> {
  const context = harness.context(tenantId);
  const tenant = await createPublishedTenant(
    harness.service,
    context,
    tenantId,
  );
  const organization = await harness.service.createDeveloperOrganization(
    context,
    {
      tenantId,
      name: "API organization",
      idempotencyKey: `${tenantId}-organization-create`,
    },
  );
  await harness.service.publish(context, {
    resource: "developerOrganization",
    tenantId,
    id: organization.id,
    idempotencyKey: `${tenantId}-organization-publish`,
  });
  const application = await harness.service.createApplication(context, {
    tenantId,
    organizationId: organization.id,
    name: "API application",
    idempotencyKey: `${tenantId}-application-create`,
  });
  await harness.service.publish(context, {
    resource: "application",
    tenantId,
    id: application.id,
    idempotencyKey: `${tenantId}-application-publish`,
  });
  const environment = await harness.service.createApplicationEnvironment(
    context,
    {
      tenantId,
      applicationId: application.id,
      name: "Production",
      idempotencyKey: `${tenantId}-environment-create`,
    },
  );
  await harness.service.publish(context, {
    resource: "applicationEnvironment",
    tenantId,
    id: environment.id,
    idempotencyKey: `${tenantId}-environment-publish`,
  });
  const product = await harness.service.createApiProduct(context, {
    tenantId,
    name: "Orders API",
    scopes: ["orders:read", "orders:write"],
    idempotencyKey: `${tenantId}-product-create`,
  });
  await harness.service.publish(context, {
    resource: "apiProduct",
    tenantId,
    id: product.id,
    idempotencyKey: `${tenantId}-product-publish`,
  });
  const version = await harness.service.createApiVersion(context, {
    tenantId,
    productId: product.id,
    apiVersion: "1.0.0",
    scopes: ["orders:read"],
    idempotencyKey: `${tenantId}-version-create`,
  });
  await harness.service.publish(context, {
    resource: "apiVersion",
    tenantId,
    id: version.id,
    idempotencyKey: `${tenantId}-version-publish`,
  });
  const issued = await harness.service.issueCredential(context, {
    tenantId,
    applicationId: application.id,
    environmentId: environment.id,
    name: "Orders credential",
    scopes: ["orders:read", "orders:write"],
    idempotencyKey: `${tenantId}-credential-issue`,
  });
  const credentialSecret = issued.secret;
  if (credentialSecret === undefined) {
    throw new Error("fixture credential secret was not issued");
  }
  const subscription = await harness.service.createSubscription(context, {
    tenantId,
    applicationId: application.id,
    productId: product.id,
    apiVersionId: version.id,
    name: "Orders subscription",
    scopes: ["orders:read"],
    idempotencyKey: `${tenantId}-subscription-create`,
  });
  await harness.service.publish(context, {
    resource: "subscription",
    tenantId,
    id: subscription.id,
    idempotencyKey: `${tenantId}-subscription-publish`,
  });
  const grant = await harness.service.grantScopes(context, {
    tenantId,
    credentialId: issued.credential.id,
    productId: product.id,
    apiVersionId: version.id,
    scopes: ["orders:read"],
    idempotencyKey: `${tenantId}-grant-create`,
  });
  const stored = await harness.repositories.credentials.get(
    tenantId,
    issued.credential.id,
  );
  if (stored === undefined) throw new Error("fixture credential was not stored");
  return {
    tenant,
    application,
    environment,
    product,
    version,
    subscription,
    credential: stored,
    credentialSecret,
    grant,
  };
}

describe("open platform request trust boundary", () => {
  it("requires explicit runtime configuration and rejects missing or forged contexts", async () => {
    expect(() => new OpenPlatformService(
      undefined as unknown as OpenPlatformServiceOptions,
    )).toThrowError();

    const harness = createHarness();
    const command = {
      tenantId: "tenant-auth",
      name: "Auth tenant",
      idempotencyKey: "tenant-auth-create",
    } as const;
    await expect(harness.service.createTenant(
      undefined as unknown as OpenPlatformRequestContext,
      command,
    )).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.AUTHENTICATION_REQUIRED,
    });
    await expect(harness.service.createTenant({
      tenantId: command.tenantId,
      actorId: "forged",
      requestId: "forged",
      issuerId: "forged",
      assurance: "authenticated",
      issuedAt: fixedNow.toISOString(),
    } as OpenPlatformRequestContext, command)).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.AUTHENTICATION_REQUIRED,
    });
  });

  it("uses the authenticated tenant as authority and enforces resource authorization", async () => {
    const harness = createHarness();
    const tenantA = harness.context("tenant-authority-a");
    const tenantB = harness.context("tenant-authority-b");
    await createPublishedTenant(harness.service, tenantA, "tenant-authority-a");
    await expect(harness.service.getTenant(tenantB, {
      tenantId: "tenant-authority-a",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.TENANT_MISMATCH,
    });
    await expect(harness.service.createTenant(tenantB, {
      tenantId: "tenant-authority-a",
      name: "Impersonation",
      idempotencyKey: "tenant-impersonation",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.TENANT_MISMATCH,
    });

    const restricted = createHarness({
      authorization: createDevelopmentOpenPlatformAuthorization([
        "tenant.read",
      ]),
    });
    await expect(restricted.service.createTenant(
      restricted.context("tenant-restricted"),
      {
        tenantId: "tenant-restricted",
        name: "Restricted tenant",
        idempotencyKey: "tenant-restricted-create",
      },
    )).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.FORBIDDEN,
    });

    const truthy = createHarness({
      authorization: {
        productionReady: false,
        authorize: () => "allowed" as unknown as boolean,
      },
    });
    await expect(truthy.service.createTenant(
      truthy.context("tenant-truthy"),
      {
        tenantId: "tenant-truthy",
        name: "Truthy tenant",
        idempotencyKey: "tenant-truthy-create",
      },
    )).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.FORBIDDEN,
    });
  });

  it("fails closed for in-memory production state", async () => {
    const productionAuthorization = {
      productionReady: true,
      authorize: () => true,
    };
    const repositories = new InMemoryOpenPlatformRepositories({
      clock: () => fixedNow,
      production: true,
    });
    const service = createOpenPlatformService({
      mode: "production",
      authorization: productionAuthorization,
      repositories,
      allowInMemoryInProduction: true,
      clock: () => fixedNow,
      secretProvider: {
        readiness: persistentReadiness,
        issue: () => ({ secret: "production-secret-value-0000000000000001" }),
        revoke: () => undefined,
        compensate: () => undefined,
      },
    });
    const issuer = createOpenPlatformRequestContextIssuer({
      issuerId: "production-auth-adapter",
      attestation: Object.freeze({ trusted: true }),
      clock: () => fixedNow,
    });
    const context = issuer.issueAuthenticated({
      tenantId: "tenant-production",
      actorId: "production-actor",
      requestId: "production-request",
    });
    await expect(service.isReady()).resolves.toMatchObject({ ready: false });
    await expect(service.createTenant(
      undefined as unknown as OpenPlatformRequestContext,
      {
        tenantId: "tenant-production",
        name: "Missing context",
        idempotencyKey: "production-missing-context",
      },
    )).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.AUTHENTICATION_REQUIRED,
    });
    await expect(service.createTenant(context, {
      tenantId: "tenant-production",
      name: "Production tenant",
      idempotencyKey: "production-tenant-create",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.STORAGE_UNAVAILABLE,
    });
    expect(() => createOpenPlatformService({
      mode: "production",
      authorization: productionAuthorization,
      repositories,
      clock: () => fixedNow,
      secretProvider: {
        readiness: persistentReadiness,
        issue: () => ({ secret: "production-secret-value-0000000000000002" }),
        revoke: () => undefined,
        compensate: () => undefined,
      },
    })).toThrowError();
  });

  it("registers providers without exposing HTTP controllers", () => {
    const issuer = createOpenPlatformRequestContextIssuer({
      issuerId: "module-test",
      attestation: Object.freeze({ module: true }),
      clock: () => fixedNow,
    });
    const dynamicModule = OpenPlatformProviderModule.forRoot({
      mode: "test",
      authorization: createDevelopmentOpenPlatformAuthorization("all"),
      contextIssuer: issuer,
      clock: () => fixedNow,
    });
    expect(dynamicModule.controllers).toBeUndefined();
    expect(dynamicModule.providers?.map((provider) =>
      typeof provider === "object" && provider !== null && "provide" in provider
        ? provider.provide
        : provider
    )).toEqual([
      OPEN_PLATFORM_SERVICE,
      OpenPlatformService,
      OPEN_PLATFORM_AUTHORIZATION,
      OPEN_PLATFORM_REQUEST_CONTEXT_ISSUER,
      OPEN_PLATFORM_OUTBOX,
      OPEN_PLATFORM_EVENT_PUBLISHER,
      OPEN_PLATFORM_WEBHOOK_SERVICE,
      expect.anything(),
    ]);
  });
});

describe("open platform lifecycle, identifiers, and idempotency", () => {
  it("uses generated internal identifiers and legal lifecycle transitions", async () => {
    const harness = createHarness();
    const context = harness.context("tenant-state");
    const tenant = await harness.service.createTenant(context, {
      tenantId: "tenant-state",
      name: "State tenant",
      idempotencyKey: "tenant-state-create",
    });
    expect(tenant.id).toMatch(/^tenant_[0-9a-f-]{36}$/u);
    expect(tenant.id).not.toBe(tenant.tenantId);

    expect(canTransitionLifecycle("draft", "disabled")).toBe(false);
    await expect(harness.service.deactivate(context, {
      resource: "tenant",
      tenantId: tenant.tenantId,
      id: tenant.id,
      idempotencyKey: "tenant-state-deactivate",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.INVALID_STATE_TRANSITION,
    });
    await harness.service.publish(context, {
      resource: "tenant",
      tenantId: tenant.tenantId,
      id: tenant.id,
      idempotencyKey: "tenant-state-publish",
    });
    await harness.service.deactivate(context, {
      resource: "tenant",
      tenantId: tenant.tenantId,
      id: tenant.id,
      idempotencyKey: "tenant-state-disable",
    });
    await harness.service.publish(context, {
      resource: "tenant",
      tenantId: tenant.tenantId,
      id: tenant.id,
      idempotencyKey: "tenant-state-republish",
    });
    const archived = await harness.service.archive(context, {
      resource: "tenant",
      tenantId: tenant.tenantId,
      id: tenant.id,
      idempotencyKey: "tenant-state-archive",
    });
    expect(archived.status).toBe("archived");

    await expect(harness.service.createApplication(context, {
      tenantId: tenant.tenantId,
      organizationId: `app_${randomUUID()}`,
      name: "Invalid identifier",
      idempotencyKey: "tenant-state-invalid-id",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.VALIDATION_ERROR,
    });
  });

  it("scopes idempotency by actor and operation and supports lease takeover", async () => {
    const harness = createHarness();
    const context = harness.context("tenant-idempotent");
    const command = {
      tenantId: "tenant-idempotent",
      name: "Idempotent tenant",
      idempotencyKey: "tenant-command",
    } as const;
    const first = await harness.service.createTenant(context, command);
    await expect(harness.service.createTenant(context, command)).resolves.toEqual(
      first,
    );
    await expect(harness.service.createTenant(context, {
      ...command,
      name: "Different request",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.IDEMPOTENCY_KEY_REUSED,
    });

    let now = new Date("2030-01-01T00:00:00.000Z");
    const store = new InMemoryIdempotencyStore({
      clock: () => now,
      leaseMs: 1000,
      retentionMs: 10_000,
    });
    const requestHash = hashOpenPlatformIdempotencyRequest({ value: 1 });
    const base = {
      scope: {
        tenantId: "tenant-lease",
        actorId: "actor-one",
        operation: "usage.record",
        key: "lease-key",
      },
      requestHash,
      now: now.toISOString(),
      leaseExpiresAt: new Date(now.getTime() + 1000).toISOString(),
      expiresAt: new Date(now.getTime() + 10_000).toISOString(),
    };
    await expect(store.acquire({
      ...base,
      leaseToken: "a".repeat(32),
    })).resolves.toEqual({ state: "acquired" });
    await expect(store.acquire({
      ...base,
      leaseToken: "b".repeat(32),
    })).resolves.toEqual({ state: "inProgress" });
    await expect(store.acquire({
      ...base,
      scope: { ...base.scope, actorId: "actor-two" },
      leaseToken: "d".repeat(32),
    })).resolves.toEqual({ state: "acquired" });
    await expect(store.acquire({
      ...base,
      scope: { ...base.scope, operation: "usage.reconcile" },
      leaseToken: "e".repeat(32),
    })).resolves.toEqual({ state: "acquired" });
    now = new Date("2030-01-01T00:00:01.001Z");
    await expect(store.acquire({
      ...base,
      now: now.toISOString(),
      leaseExpiresAt: new Date(now.getTime() + 1000).toISOString(),
      expiresAt: new Date(now.getTime() + 10_000).toISOString(),
      leaseToken: "c".repeat(32),
    })).resolves.toEqual({ state: "acquired" });
    await expect(store.complete({
      scope: base.scope,
      requestHash,
      leaseToken: "a".repeat(32),
      now: now.toISOString(),
      expiresAt: new Date(now.getTime() + 10_000).toISOString(),
      response: { stale: true },
    })).resolves.toBe(false);
  });
});

describe("open platform tenant and credential DTO isolation", () => {
  it("does not expose or accept resources across tenants", async () => {
    const harness = createHarness();
    const contextA = harness.context("tenant-a");
    const contextB = harness.context("tenant-b");
    await createPublishedTenant(harness.service, contextA, "tenant-a");
    await createPublishedTenant(harness.service, contextB, "tenant-b");
    const organization = await harness.service.createDeveloperOrganization(
      contextA,
      {
        tenantId: "tenant-a",
        name: "Tenant A organization",
        idempotencyKey: "organization-a-create",
      },
    );
    await expect(harness.service.getApplication(contextB, {
      tenantId: "tenant-b",
      id: `app_${randomUUID()}`,
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.RESOURCE_NOT_FOUND,
    });
    await expect(harness.service.createApplication(contextB, {
      tenantId: "tenant-b",
      organizationId: organization.id,
      name: "Cross tenant",
      idempotencyKey: "application-cross-tenant",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.RESOURCE_NOT_FOUND,
    });
  });

  it("separates internal credential storage from public issuance and query DTOs", async () => {
    const secrets = [
      "issued-credential-secret-0000000000000001",
      "rotated-credential-secret-0000000000000002",
    ];
    let index = 0;
    const activeReferences = new Set<string>();
    const revokedReferences: string[] = [];
    const compensatedReferences: string[] = [];
    const secretProvider: CredentialSecretProvider = {
      readiness: persistentReadiness,
      issue: () => {
        const secret = secrets[index++] ??
          "fallback-credential-secret-00000000000003";
        const reference = `vault://open-platform/credential/${index}`;
        activeReferences.add(reference);
        return { secret, reference };
      },
      revoke: (input) => {
        if (input.reference !== undefined) {
          revokedReferences.push(input.reference);
          activeReferences.delete(input.reference);
        }
      },
      compensate: (input) => {
        if (input.reference !== undefined) {
          compensatedReferences.push(input.reference);
          activeReferences.delete(input.reference);
        }
      },
    };
    const harness = createHarness({ secretProvider });
    const tenantId = "tenant-credential";
    const context = harness.context(tenantId);
    const tenant = await createPublishedTenant(
      harness.service,
      context,
      tenantId,
    );
    const organization = await harness.service.createDeveloperOrganization(
      context,
      {
        tenantId,
        name: "Credential organization",
        idempotencyKey: "credential-organization-create",
      },
    );
    await harness.service.publish(context, {
      resource: "developerOrganization",
      tenantId,
      id: organization.id,
      idempotencyKey: "credential-organization-publish",
    });
    const application = await harness.service.createApplication(context, {
      tenantId,
      organizationId: organization.id,
      name: "Credential application",
      idempotencyKey: "credential-application-create",
    });
    await harness.service.publish(context, {
      resource: "application",
      tenantId,
      id: application.id,
      idempotencyKey: "credential-application-publish",
    });
    const issueCommand: IssueCredentialCommand = {
      tenantId,
      applicationId: application.id,
      name: "Primary credential",
      scopes: ["orders:read"],
      idempotencyKey: "credential-issue",
    };
    const issued = await harness.service.issueCredential(context, issueCommand);
    const plaintext = issued.secret;
    if (plaintext === undefined) throw new Error("credential secret was not issued");
    const stored = await harness.repositories.credentials.get(
      tenantId,
      issued.credential.id,
    );
    if (stored === undefined) throw new Error("credential was not stored");

    expect(stored.secret.digest).toMatch(/^sha256:[a-f0-9]{64}$/u);
    expect(stored.secret.reference).toMatch(/^vault:\/\//u);
    expect(issued.credential).not.toHaveProperty("secret");
    expect(issued.credential).not.toHaveProperty("fingerprint");
    expect(JSON.stringify(issued.credential)).not.toContain(stored.secret.digest);
    expect(JSON.stringify(issued.credential)).not.toContain(
      stored.secret.reference ?? "missing",
    );
    expect(toCredentialDto(stored)).toEqual(issued.credential);
    const queried = await harness.service.getCredential(context, {
      tenantId,
      id: issued.credential.id,
    });
    const listed = await harness.service.listCredentials(context, { tenantId });
    expect(queried).toEqual(issued.credential);
    expect(listed).toEqual([issued.credential]);
    expect(JSON.stringify([queried, listed])).not.toContain(plaintext);

    const replay = await harness.service.issueCredential(context, issueCommand);
    expect(replay).toMatchObject({
      credential: { id: issued.credential.id },
      secret: undefined,
      replayed: true,
    });
    const sanitized = await harness.repositories.credentials.create({
      ...stored,
      id: `credential_${randomUUID()}`,
      plaintext,
    } as CredentialRecord & { plaintext: string });
    expect(JSON.stringify(sanitized)).not.toContain(plaintext);
    expect(sanitized).not.toHaveProperty("plaintext");

    const rotation = await harness.service.rotateCredential(context, {
      tenantId,
      credentialId: issued.credential.id,
      idempotencyKey: "credential-rotate",
    });
    expect(rotation.credential).not.toHaveProperty("secret");
    expect(rotation.previousCredential).not.toHaveProperty("secret");
    expect(rotation.credential.previousCredentialId).toBe(issued.credential.id);
    expect(revokedReferences).toEqual([stored.secret.reference]);
    expect(activeReferences.size).toBe(1);
    const rotationReplay = await harness.service.rotateCredential(context, {
      tenantId,
      credentialId: issued.credential.id,
      idempotencyKey: "credential-rotate",
    });
    expect(rotationReplay.secret).toBeUndefined();
    const revoked = await harness.service.revokeCredential(context, {
      tenantId,
      credentialId: rotation.credential.id,
      idempotencyKey: "credential-revoke",
    });
    expect(revoked.status).toBe("revoked");
    expect(activeReferences.size).toBe(0);
    expect(compensatedReferences).toEqual([]);
    await expect(harness.service.verifyCredentialSecret(context, {
      tenantId,
      credentialId: rotation.credential.id,
      secret: rotation.secret ?? "",
    })).resolves.toBe(false);
    await expect(harness.service.getTenant(context, { tenantId })).resolves
      .toMatchObject({ id: tenant.id, status: "published" });
  });

  it("compensates failed issuance and rotation and retries revoked cleanup", async () => {
    const secrets = [
      "initial-secret-value-000000000000000001",
      "equal-reference-secret-value-00000000000002",
      "scheme-reference-secret-value-000000000000003",
      "charset-reference-secret-value-00000000000004",
      "length-reference-secret-value-000000000000005",
      "failed-create-secret-value-000000000000006",
      "failed-rotation-secret-value-00000000000007",
    ];
    const invalidReferences = new Map<number, string>([
      [1, secrets[1]],
      [2, "data:text/plain,opaque"],
      [3, "vault://open platform/credential"],
      [4, `vault://${"a".repeat(2050)}`],
    ]);
    let issueIndex = 0;
    let revokeFailures = 0;
    const activeReferences = new Set<string>();
    const compensatedReferences: string[] = [];
    const revokedReferences: string[] = [];
    const secretProvider: CredentialSecretProvider = {
      issue: () => {
        const current = issueIndex;
        const secret = secrets[current] ??
          "fallback-secret-value-000000000000000008";
        const reference = invalidReferences.get(current) ??
          `vault://open-platform/credential/${current}`;
        if (reference !== secret) activeReferences.add(reference);
        issueIndex += 1;
        return { secret, reference };
      },
      revoke: (input) => {
        if (revokeFailures > 0) {
          revokeFailures -= 1;
          throw new Error("vault unavailable");
        }
        if (input.reference !== undefined) {
          revokedReferences.push(input.reference);
          activeReferences.delete(input.reference);
        }
      },
      compensate: (input) => {
        if (input.reference !== undefined) {
          compensatedReferences.push(input.reference);
          activeReferences.delete(input.reference);
        }
      },
    };
    const harness = createHarness({ secretProvider });
    const tenantId = "tenant-lifecycle-failure";
    const context = harness.context(tenantId);
    const fixture = await createApiFixture(harness, tenantId);
    const initialReference = (
      await harness.repositories.credentials.get(
        tenantId,
        fixture.credential.id,
      )
    )?.secret.reference;
    if (initialReference === undefined) throw new Error("fixture reference missing");

    for (const [position, label] of [
      [1, "equal-secret"],
      [2, "invalid-scheme"],
      [3, "invalid-charset"],
      [4, "invalid-length"],
    ] as const) {
      await expect(harness.service.issueCredential(context, {
        tenantId,
        applicationId: fixture.application.id,
        name: `Invalid reference ${label}`,
        scopes: ["orders:read"],
        idempotencyKey: `invalid-reference-${position}`,
      })).rejects.toMatchObject({
        code: OPEN_PLATFORM_ERROR_CODES.SECRET_ISSUANCE_FAILED,
      });
      expect(compensatedReferences).toHaveLength(position);
      expect(activeReferences).toEqual(new Set([initialReference]));
    }

    const createSpy = vi.spyOn(
      harness.repositories.credentials,
      "create",
    ).mockRejectedValueOnce(new Error("database unavailable"));
    await expect(harness.service.issueCredential(context, {
      tenantId,
      applicationId: fixture.application.id,
      name: "Failed persistence",
      scopes: ["orders:read"],
      idempotencyKey: "failed-create-issue",
    })).rejects.toThrow();
    createSpy.mockRestore();
    expect(compensatedReferences).toHaveLength(5);
    expect(activeReferences).toEqual(new Set([initialReference]));

    const rotateSpy = vi.spyOn(
      harness.repositories.credentials,
      "rotate",
    ).mockRejectedValueOnce(new Error("rotation transaction failed"));
    await expect(harness.service.rotateCredential(context, {
      tenantId,
      credentialId: fixture.credential.id,
      idempotencyKey: "failed-rotation",
    })).rejects.toThrow();
    rotateSpy.mockRestore();
    expect(compensatedReferences).toHaveLength(6);
    expect(revokedReferences).toEqual([]);
    expect(activeReferences).toEqual(new Set([initialReference]));

    revokeFailures = 2;
    const revokeCommand = {
      tenantId,
      credentialId: fixture.credential.id,
      idempotencyKey: "revoke-retry",
    } as const;
    await expect(harness.service.revokeCredential(
      context,
      revokeCommand,
    )).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.SECRET_ISSUANCE_FAILED,
    });
    await expect(harness.service.revokeCredential(
      context,
      revokeCommand,
    )).resolves.toMatchObject({ status: "revoked" });
    expect(revokedReferences).toEqual([initialReference]);
    expect(activeReferences).toEqual(new Set());
  });
});

describe("open platform fail-closed hierarchy, scopes, and usage", () => {
  it("invalidates credentials and grants when parents are disabled", async () => {
    const harness = createHarness();
    const tenantId = "tenant-hierarchy";
    const context = harness.context(tenantId);
    const fixture = await createApiFixture(harness, tenantId);
    await expect(harness.service.verifyCredentialSecret(context, {
      tenantId,
      credentialId: fixture.credential.id,
      secret: fixture.credentialSecret,
    })).resolves.toBe(true);

    await harness.service.deactivate(context, {
      resource: "applicationEnvironment",
      tenantId,
      id: fixture.environment.id,
      idempotencyKey: "hierarchy-environment-disable",
    });
    expect(fixture.credential.environmentId).toBe(fixture.environment.id);
    expect((await harness.repositories.applicationEnvironments.get(
      tenantId,
      fixture.environment.id,
    ))?.status).toBe("disabled");
    await expect(harness.service.verifyCredentialSecret(context, {
      tenantId,
      credentialId: fixture.credential.id,
      secret: fixture.credentialSecret,
    })).resolves.toBe(false);
    await expect(harness.service.authorizeScopes(context, {
      tenantId,
      credentialId: fixture.credential.id,
      productId: fixture.product.id,
      apiVersionId: fixture.version.id,
      scopes: ["orders:read"],
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.RESOURCE_UNAVAILABLE,
    });
    await harness.service.publish(context, {
      resource: "applicationEnvironment",
      tenantId,
      id: fixture.environment.id,
      idempotencyKey: "hierarchy-environment-republish",
    });
    await harness.service.deactivate(context, {
      resource: "application",
      tenantId,
      id: fixture.application.id,
      idempotencyKey: "hierarchy-application-disable",
    });
    await expect(harness.service.verifyCredentialSecret(context, {
      tenantId,
      credentialId: fixture.credential.id,
      secret: fixture.credentialSecret,
    })).resolves.toBe(false);
    await harness.service.publish(context, {
      resource: "application",
      tenantId,
      id: fixture.application.id,
      idempotencyKey: "hierarchy-application-republish",
    });
    await harness.service.deactivate(context, {
      resource: "apiVersion",
      tenantId,
      id: fixture.version.id,
      idempotencyKey: "hierarchy-version-disable",
    });
    await expect(harness.service.authorizeScopes(context, {
      tenantId,
      credentialId: fixture.credential.id,
      productId: fixture.product.id,
      apiVersionId: fixture.version.id,
      scopes: ["orders:read"],
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.RESOURCE_UNAVAILABLE,
    });
    await harness.service.publish(context, {
      resource: "apiVersion",
      tenantId,
      id: fixture.version.id,
      idempotencyKey: "hierarchy-version-republish",
    });
    await harness.service.archive(context, {
      resource: "tenant",
      tenantId,
      id: fixture.tenant.id,
      idempotencyKey: "hierarchy-tenant-archive",
    });
    await expect(harness.service.verifyCredentialSecret(context, {
      tenantId,
      credentialId: fixture.credential.id,
      secret: fixture.credentialSecret,
    })).resolves.toBe(false);
  });

  it("uses version scopes, revokes grants, and keeps usage append-only", async () => {
    const harness = createHarness();
    const tenantId = "tenant-scope-usage";
    const context = harness.context(tenantId);
    const fixture = await createApiFixture(harness, tenantId);

    await expect(harness.service.grantScopes(context, {
      tenantId,
      credentialId: fixture.credential.id,
      productId: fixture.product.id,
      apiVersionId: fixture.version.id,
      scopes: ["orders:write"],
      idempotencyKey: "scope-version-write-denied",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.SCOPE_NOT_ALLOWED,
    });
    await expect(harness.service.authorizeScopes(context, {
      tenantId,
      credentialId: fixture.credential.id,
      productId: fixture.product.id,
      apiVersionId: fixture.version.id,
      scopes: ["orders:read"],
    })).resolves.toMatchObject({
      valid: true,
      scopeGrantId: fixture.grant.id,
      apiVersionId: fixture.version.id,
    });
    await harness.service.grantScopes(context, {
      tenantId,
      credentialId: fixture.credential.id,
      productId: fixture.product.id,
      scopes: ["orders:read"],
      idempotencyKey: "scope-product-grant",
    });

    const usageCommand = {
      tenantId,
      subscriptionId: fixture.subscription.id,
      credentialId: fixture.credential.id,
      metric: "api.requests",
      quantity: 25,
      occurredAt: "2029-12-31T23:59:00.000Z",
      idempotencyKey: "usage-record",
    } as const;
    const usage = await harness.service.recordUsage(context, usageCommand);
    await expect(harness.service.recordUsage(context, usageCommand)).resolves.toEqual(
      usage,
    );
    expect((harness.repositories.usage as unknown as { save?: unknown }).save)
      .toBeUndefined();

    const revokeCommand = {
      tenantId,
      scopeGrantId: fixture.grant.id,
      idempotencyKey: "version-grant-revoke",
    } as const;
    const revoked = await harness.service.revokeScopeGrant(context, revokeCommand);
    expect(revoked.status).toBe("revoked");
    await expect(harness.service.revokeScopeGrant(context, revokeCommand))
      .resolves.toEqual(revoked);
    await expect(harness.service.authorizeScopes(context, {
      tenantId,
      credentialId: fixture.credential.id,
      productId: fixture.product.id,
      apiVersionId: fixture.version.id,
      scopes: ["orders:read"],
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.SCOPE_GRANT_INVALID,
    });
    await expect(harness.service.recordUsage(context, {
      ...usageCommand,
      quantity: 2,
      idempotencyKey: "usage-after-grant-revoke",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.SCOPE_GRANT_INVALID,
    });

    await harness.service.grantScopes(context, {
      tenantId,
      credentialId: fixture.credential.id,
      productId: fixture.product.id,
      apiVersionId: fixture.version.id,
      scopes: ["orders:read"],
      idempotencyKey: "version-grant-recreate",
    });
    await expect(harness.service.recordUsage(context, {
      ...usageCommand,
      quantity: 3,
      idempotencyKey: "usage-before-parent-disable",
    })).resolves.toBeDefined();
    await harness.service.deactivate(context, {
      resource: "apiProduct",
      tenantId,
      id: fixture.product.id,
      idempotencyKey: "usage-product-disable",
    });
    await expect(harness.service.recordUsage(context, {
      ...usageCommand,
      quantity: 4,
      idempotencyKey: "usage-disabled-product",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.RESOURCE_UNAVAILABLE,
    });
    await harness.service.publish(context, {
      resource: "apiProduct",
      tenantId,
      id: fixture.product.id,
      idempotencyKey: "usage-product-republish",
    });
    await harness.service.deactivate(context, {
      resource: "subscription",
      tenantId,
      id: fixture.subscription.id,
      idempotencyKey: "usage-subscription-disable",
    });
    await expect(harness.service.recordUsage(context, {
      ...usageCommand,
      quantity: 4,
      idempotencyKey: "usage-disabled-subscription",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_ERROR_CODES.RESOURCE_UNAVAILABLE,
    });
    await expect(harness.service.listUsage(context, {
      tenantId,
      subscriptionId: fixture.subscription.id,
    })).resolves.toHaveLength(2);
    expect(canTransitionCredential("active", "rotated")).toBe(true);
  });
});

describe("open platform safe error contract", () => {
  it("maps domain and unknown failures without sensitive serialization", () => {
    const unknown = toOpenPlatformContractError(
      new Error("digest=sha256:secret reference=vault://hidden"),
      "request-safe",
    );
    expect(unknown).toEqual({
      statusCode: 500,
      body: {
        code: OPEN_PLATFORM_ERROR_CODES.INTERNAL_ERROR,
        message: "Open platform request failed",
        requestId: "request-safe",
      },
    });
    expect(JSON.stringify(unknown)).not.toContain("sha256");
    expect(JSON.stringify(unknown)).not.toContain("vault://");

    const notFound = toOpenPlatformContractError(resourceNotFound("credential"));
    expect(notFound).toEqual({
      statusCode: 404,
      body: {
        code: OPEN_PLATFORM_ERROR_CODES.RESOURCE_NOT_FOUND,
        message: "Open platform resource was not found",
      },
    });
    expect(notFound.body).not.toHaveProperty("details");
    const serializedDomainError = JSON.stringify(resourceNotFound("credential"));
    expect(serializedDomainError).not.toContain("details");
  });
});
