import { randomBytes, randomUUID } from "node:crypto";
import { Pool } from "pg";
import {
  OpenPlatformPersistence,
  OpenPlatformRuntime,
  createDevelopmentOpenPlatformAuthorization,
  createDevelopmentOpenPlatformRequestContext,
  createOpenPlatformService,
  type CredentialSecretProvider,
  type OpenPlatformRepositories,
  type OpenPlatformRequestContext,
  type OpenPlatformService,
} from "@getbrick/idaas-control-plane/open-platform";

export const OPEN_PLATFORM_SMOKE_DATABASE_URL =
  process.env.DATABASE_URL ?? "postgres://postgres:gbtest@localhost:54329/getbrick";
export const OPEN_PLATFORM_SMOKE_MIGRATION_TENANT_ID = "open-platform-smoke";
export const OPEN_PLATFORM_SMOKE_CLIENT_ID = "open-platform-smoke-client";
export const OPEN_PLATFORM_SMOKE_AUDIENCE = "urn:getbrick:open-platform-smoke";
export const OPEN_PLATFORM_SMOKE_PATH = "/open/platform-smoke";

export function createOpenPlatformSmokePool(
  connectionString = OPEN_PLATFORM_SMOKE_DATABASE_URL,
): Pool {
  return new Pool({
    connectionString,
    connectionTimeoutMillis: 2_000,
    idleTimeoutMillis: 1_000,
    max: 8,
  });
}

export function createOpenPlatformSmokeAdapter(
  pool: Pool,
): OpenPlatformPersistence.DatabaseAdapter {
  return {
    query: (text, values = []) => pool.query(text, values),
    transaction: async <T>(
      callback: (executor: OpenPlatformPersistence.DatabaseAdapter) => Promise<T>,
    ): Promise<T> => {
      const client = await pool.connect();
      const executor: OpenPlatformPersistence.DatabaseAdapter = {
        query: (text, values = []) => client.query(text, values),
      };
      let began = false;
      try {
        await client.query("BEGIN");
        began = true;
        const result = await callback(executor);
        await client.query("COMMIT");
        return result;
      } catch (error) {
        if (began) await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }
    },
  };
}

export async function probeOpenPlatformSmokeDatabase(pool: Pool): Promise<boolean> {
  try {
    await pool.query("SELECT 1");
    return true;
  } catch {
    return false;
  }
}

export function applyOpenPlatformSmokeMigration(pool: Pool) {
  return OpenPlatformPersistence.applyVersionedOpenPlatformMigration(
    createOpenPlatformSmokeAdapter(pool),
    {
      mode: "fixed",
      tenantId: OPEN_PLATFORM_SMOKE_MIGRATION_TENANT_ID,
      requireTransaction: true,
    },
  );
}

export function createOpenPlatformSmokeSecretProvider(): CredentialSecretProvider {
  return {
    readiness: {
      storage: "memory",
      distributed: false,
      ready: () => true,
    },
    issue: ({ credentialId }) => ({
      secret: `smoke-secret-${randomBytes(24).toString("hex")}`,
      reference: `vault://open-platform-smoke/${credentialId}`,
    }),
    revoke: () => undefined,
    compensate: () => undefined,
  };
}

export function createOpenPlatformSmokeService(
  pool: Pool,
  tenantId: string,
): OpenPlatformService {
  return createOpenPlatformService({
    mode: "test",
    authorization: createDevelopmentOpenPlatformAuthorization("all"),
    repositories: OpenPlatformPersistence.createSqlOpenPlatformRepositories({
      adapter: createOpenPlatformSmokeAdapter(pool),
      mode: "fixed",
      tenantId,
      requireTransactions: true,
    }),
    secretProvider: createOpenPlatformSmokeSecretProvider(),
  });
}

export async function createOpenPlatformSmokeTenant(
  repositories: OpenPlatformRepositories,
  tenantId: string,
  name: string,
) {
  const timestamp = new Date().toISOString();
  return repositories.tenants.create({
    id: `tenant_${randomUUID()}`,
    tenantId,
    kind: "tenant",
    name,
    status: "draft",
    version: 1,
    createdAt: timestamp,
    updatedAt: timestamp,
  });
}

export function createOpenPlatformSmokeContext(
  tenantId: string,
  actorId: string,
  requestId: string,
): OpenPlatformRequestContext {
  return createDevelopmentOpenPlatformRequestContext({
    tenantId,
    actorId,
    requestId,
  });
}

export function createOpenPlatformSmokeTenantId(label: "a" | "b"): string {
  return `smoke-${label}-${randomUUID().replace(/-/gu, "").slice(0, 20)}`;
}

export function createOpenPlatformSmokeCredentialVerifier(
  service: OpenPlatformService,
): OpenPlatformRuntime.OpenPlatformCredentialVerificationService {
  return new OpenPlatformRuntime.OpenPlatformCredentialVerificationService({
    domain: service,
    mode: "test",
  });
}

export function createOpenPlatformSmokeApiRequestContext(
  trustedContext: OpenPlatformRequestContext,
  applicationId: string,
  requestId: string,
): OpenPlatformRuntime.OpenPlatformApiRequestContext {
  return OpenPlatformRuntime.createOpenPlatformApiRequestContext(
    {
      method: "GET",
      path: OPEN_PLATFORM_SMOKE_PATH,
      audience: OPEN_PLATFORM_SMOKE_AUDIENCE,
      tenantId: trustedContext.tenantId,
      applicationId,
      clientId: OPEN_PLATFORM_SMOKE_CLIENT_ID,
      ip: "192.0.2.10",
      requestId,
    },
    trustedContext,
  );
}

export function createOpenPlatformSmokeRoute(
  productId: string,
  apiVersionId: string,
): OpenPlatformRuntime.OpenPlatformApiRoutePolicy {
  return {
    routeId: "open-platform-smoke",
    policyVersion: "smoke-v1",
    enabled: true,
    method: "GET",
    path: OPEN_PLATFORM_SMOKE_PATH,
    audience: OPEN_PLATFORM_SMOKE_AUDIENCE,
    productId,
    apiVersionId,
    requiredScopes: ["smoke:read"],
    clientIds: [OPEN_PLATFORM_SMOKE_CLIENT_ID],
  };
}

export async function readOpenPlatformSmokeCredentialStorage(
  pool: Pool,
  tenantId: string,
  credentialId: string,
): Promise<Record<string, unknown> | undefined> {
  const result = await pool.query(
    `SELECT "secret_digest" AS "secretDigest", "secret_reference" AS "secretReference" FROM "gb_open_credential" WHERE "tenant_id" = $1 AND "id" = $2`,
    [tenantId, credentialId],
  );
  return result.rows[0] as Record<string, unknown> | undefined;
}
