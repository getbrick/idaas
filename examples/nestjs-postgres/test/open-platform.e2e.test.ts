import { randomUUID } from "node:crypto";
import { afterAll, expect, it } from "vitest";
import {
  OPEN_PLATFORM_ERROR_CODES,
  OpenPlatformRuntime,
} from "@getbrick/idaas-control-plane/open-platform";
import {
  applyOpenPlatformSmokeMigration,
  createOpenPlatformSmokeApiRequestContext,
  createOpenPlatformSmokeContext,
  createOpenPlatformSmokeCredentialVerifier,
  createOpenPlatformSmokePool,
  createOpenPlatformSmokeRoute,
  createOpenPlatformSmokeService,
  createOpenPlatformSmokeTenant,
  createOpenPlatformSmokeTenantId,
  probeOpenPlatformSmokeDatabase,
  readOpenPlatformSmokeCredentialStorage,
} from "../src/open-platform-smoke.js";

const pool = createOpenPlatformSmokePool();
const databaseAvailable = await probeOpenPlatformSmokeDatabase(pool);

if (!databaseAvailable) {
  console.warn("open-platform e2e skipped: PostgreSQL is unavailable at the configured test database");
}

const databaseIt = databaseAvailable ? it : it.skip;

databaseIt("persists the open-platform lifecycle and enforces runtime boundaries", async () => {
  const runId = randomUUID().replace(/-/gu, "");
  const key = (label: string) => `smoke-${runId}-${label}`;
  const tenantA = createOpenPlatformSmokeTenantId("a");
  const tenantB = createOpenPlatformSmokeTenantId("b");
  const actorA = `smoke-actor-a-${runId}`;
  const actorB = `smoke-actor-b-${runId}`;
  const contextA = createOpenPlatformSmokeContext(tenantA, actorA, `setup-a-${runId}`);
  const contextB = createOpenPlatformSmokeContext(tenantB, actorB, `setup-b-${runId}`);

  const migration = await applyOpenPlatformSmokeMigration(pool);
  expect(migration.atomic).toBe(true);
  expect(migration.applied.length + migration.skipped.length).toBe(5);

  const serviceA = createOpenPlatformSmokeService(pool, tenantA);
  const serviceB = createOpenPlatformSmokeService(pool, tenantB);
  await expect(serviceA.isReady()).resolves.toMatchObject({
    ready: true,
    storage: "persistent",
    distributed: true,
  });

  const tenant = await createOpenPlatformSmokeTenant(
    serviceA.repositories,
    tenantA,
    "Open platform smoke tenant",
  );
  await serviceA.publish(contextA, {
    resource: "tenant",
    tenantId: tenantA,
    id: tenant.id,
    idempotencyKey: key("tenant-publish"),
  });

  const organization = await serviceA.createDeveloperOrganization(contextA, {
    tenantId: tenantA,
    name: "Open platform smoke organization",
    description: "PostgreSQL persistence smoke",
    idempotencyKey: key("organization-create"),
  });
  await serviceA.publish(contextA, {
    resource: "developerOrganization",
    tenantId: tenantA,
    id: organization.id,
    idempotencyKey: key("organization-publish"),
  });

  const application = await serviceA.createApplication(contextA, {
    tenantId: tenantA,
    organizationId: organization.id,
    name: "Open platform smoke application",
    idempotencyKey: key("application-create"),
  });
  await serviceA.publish(contextA, {
    resource: "application",
    tenantId: tenantA,
    id: application.id,
    idempotencyKey: key("application-publish"),
  });

  const environment = await serviceA.createApplicationEnvironment(contextA, {
    tenantId: tenantA,
    applicationId: application.id,
    name: "Smoke",
    idempotencyKey: key("environment-create"),
  });
  await serviceA.publish(contextA, {
    resource: "applicationEnvironment",
    tenantId: tenantA,
    id: environment.id,
    idempotencyKey: key("environment-publish"),
  });

  const product = await serviceA.createApiProduct(contextA, {
    tenantId: tenantA,
    name: "Open platform smoke API",
    scopes: ["smoke:read", "smoke:write"],
    idempotencyKey: key("product-create"),
  });
  await serviceA.publish(contextA, {
    resource: "apiProduct",
    tenantId: tenantA,
    id: product.id,
    idempotencyKey: key("product-publish"),
  });

  const version = await serviceA.createApiVersion(contextA, {
    tenantId: tenantA,
    productId: product.id,
    apiVersion: "2026-01-01",
    scopes: ["smoke:read"],
    idempotencyKey: key("version-create"),
  });
  await serviceA.publish(contextA, {
    resource: "apiVersion",
    tenantId: tenantA,
    id: version.id,
    idempotencyKey: key("version-publish"),
  });

  const issued = await serviceA.issueCredential(contextA, {
    tenantId: tenantA,
    applicationId: application.id,
    environmentId: environment.id,
    name: "Open platform smoke credential",
    scopes: ["smoke:read", "smoke:write"],
    idempotencyKey: key("credential-create"),
  });
  const secret = issued.secret;
  if (secret === undefined) throw new Error("smoke credential secret was not issued");

  const grant = await serviceA.grantScopes(contextA, {
    tenantId: tenantA,
    credentialId: issued.credential.id,
    productId: product.id,
    apiVersionId: version.id,
    scopes: ["smoke:read"],
    idempotencyKey: key("grant-create"),
  });
  expect(grant.status).toBe("active");

  const subscription = await serviceA.createSubscription(contextA, {
    tenantId: tenantA,
    applicationId: application.id,
    productId: product.id,
    apiVersionId: version.id,
    name: "Open platform smoke subscription",
    scopes: ["smoke:read"],
    idempotencyKey: key("subscription-create"),
  });
  await serviceA.publish(contextA, {
    resource: "subscription",
    tenantId: tenantA,
    id: subscription.id,
    idempotencyKey: key("subscription-publish"),
  });

  const usageCommand = {
    tenantId: tenantA,
    subscriptionId: subscription.id,
    credentialId: issued.credential.id,
    metric: "api.requests",
    quantity: 3,
    idempotencyKey: key("usage-create"),
  } as const;
  const usage = await serviceA.recordUsage(contextA, usageCommand);
  const replayedUsage = await serviceA.recordUsage(contextA, usageCommand);
  expect(replayedUsage).toEqual(usage);
  await expect(serviceA.listUsage(contextA, {
    tenantId: tenantA,
    subscriptionId: subscription.id,
  })).resolves.toHaveLength(1);

  const storedCredential = await serviceA.repositories.credentials.get(
    tenantA,
    issued.credential.id,
  );
  if (storedCredential === undefined) throw new Error("smoke credential was not persisted");
  const secretReference = storedCredential.secret.reference;
  if (secretReference === undefined) throw new Error("smoke credential reference was not persisted");
  expect(storedCredential.secret.digest).toMatch(/^sha256:[a-f0-9]{64}$/u);
  expect(storedCredential.secret.reference).toBe(secretReference);

  const storage = await readOpenPlatformSmokeCredentialStorage(
    pool,
    tenantA,
    issued.credential.id,
  );
  expect(storage?.secretDigest).toBe(storedCredential.secret.digest);
  expect(storage?.secretReference).toBe(secretReference);

  const queriedCredential = await serviceA.getCredential(contextA, {
    tenantId: tenantA,
    id: issued.credential.id,
  });
  const listedCredentials = await serviceA.listCredentials(contextA, { tenantId: tenantA });
  expect(listedCredentials).toHaveLength(1);
  for (const credential of [queriedCredential, ...listedCredentials]) {
    expect(credential).not.toHaveProperty("secret");
    expect(credential).not.toHaveProperty("digest");
    expect(credential).not.toHaveProperty("reference");
    expect(credential).not.toHaveProperty("secretDigest");
    expect(credential).not.toHaveProperty("secretReference");
    const serialized = JSON.stringify(credential);
    expect(serialized).not.toContain(storedCredential.secret.digest);
    expect(serialized).not.toContain(secretReference);
  }

  const runtimeTrustedContext = createOpenPlatformSmokeContext(
    tenantA,
    actorA,
    `runtime-${runId}`,
  );
  const runtimeContext = createOpenPlatformSmokeApiRequestContext(
    runtimeTrustedContext,
    application.id,
    `runtime-${runId}`,
  );
  const route = createOpenPlatformSmokeRoute(product.id, version.id);
  const verifier = createOpenPlatformSmokeCredentialVerifier(serviceA);
  const authentication = {
    type: "apiKey" as const,
    credentialId: issued.credential.id,
    credentialVersion: issued.credential.version,
    secret,
  };
  await expect(serviceA.verifyCredentialSecret(runtimeTrustedContext, {
    tenantId: tenantA,
    credentialId: issued.credential.id,
    secret,
  })).resolves.toBe(true);
  await expect(verifier.verify(runtimeContext, route, authentication)).resolves.toMatchObject({
    tenantId: tenantA,
    applicationId: application.id,
    credentialId: issued.credential.id,
  });

  await serviceA.deactivate(contextA, {
    resource: "application",
    tenantId: tenantA,
    id: application.id,
    idempotencyKey: key("application-disable"),
  });
  await expect(serviceA.verifyCredentialSecret(runtimeTrustedContext, {
    tenantId: tenantA,
    credentialId: issued.credential.id,
    secret,
  })).resolves.toBe(false);
  await expect(verifier.verify(runtimeContext, route, authentication)).rejects.toMatchObject({
    code: OpenPlatformRuntime.OPEN_PLATFORM_RUNTIME_ERROR_CODES.PARENT_RESOURCE_DISABLED,
  });

  const tenantBRecord = await createOpenPlatformSmokeTenant(
    serviceB.repositories,
    tenantB,
    "Open platform isolation tenant",
  );
  await serviceB.publish(contextB, {
    resource: "tenant",
    tenantId: tenantB,
    id: tenantBRecord.id,
    idempotencyKey: key("tenant-b-publish"),
  });
  await expect(serviceB.getCredential(contextB, {
    tenantId: tenantB,
    id: issued.credential.id,
  })).rejects.toMatchObject({
    code: OPEN_PLATFORM_ERROR_CODES.RESOURCE_NOT_FOUND,
  });
  await expect(serviceB.getApplication(contextB, {
    tenantId: tenantB,
    id: application.id,
  })).rejects.toMatchObject({
    code: OPEN_PLATFORM_ERROR_CODES.RESOURCE_NOT_FOUND,
  });
  await expect(serviceB.listCredentials(contextB, { tenantId: tenantB })).resolves.toEqual([]);

  const crossTenantRows = await pool.query(
    `SELECT "id" FROM "gb_open_credential" WHERE "tenant_id" = $1 AND "id" = $2`,
    [tenantB, issued.credential.id],
  );
  expect(crossTenantRows.rows).toHaveLength(0);
});

afterAll(async () => {
  await pool.end();
});
