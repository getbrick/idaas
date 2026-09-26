import { describe, expect, it } from "vitest";
import {
  createApplicationManagementMigrationSql,
  getApplicationManagementMigrationDefinition,
} from "../src/application-migration.js";
import {
  InMemoryApplicationRepository,
} from "../src/application-repository.js";
import { SqlApplicationRepository } from "../src/application-sql-repository.js";
import {
  InMemorySecretBindingRepository,
  SqlSecretBindingRepository,
  isSecretBindingUsable,
} from "../src/secret-binding.js";
import {
  SqlIdentityRepository,
  externalIdentityCanonicalKey,
} from "../src/identity.js";
import {
  MigrationCoordinator,
  migrationChecksum,
  type MigrationSqlExecutor,
} from "../src/migration-coordinator.js";
import { defineTenantConfig } from "../src/tenant.js";

type Call = { text: string; values: unknown[] };

function executor(calls: Call[], response: (text: string, values: unknown[]) => unknown = () => ({ rows: [] })): MigrationSqlExecutor & { calls: Call[] } {
  const query = async (text: string, values: unknown[] = []) => {
    calls.push({ text, values });
    return response(text, values);
  };
  return {
    calls,
    query,
    transaction: async <T>(callback: (value: MigrationSqlExecutor) => Promise<T>) => callback({ query }),
  };
}

describe("track B tenant persistence", () => {
  it("keeps shared context mandatory and dedicated fallback forbidden", async () => {
    expect(defineTenantConfig({ mode: "shared", tenantId: "tenant-a" })).toMatchObject({ requireRls: true, requireTransactions: true });
    expect(() => defineTenantConfig({ mode: "dedicated", allowSharedFallback: true })).toThrow(/shared pool/i);
    const calls: Call[] = [];
    const scoped = executor(calls, (text) => {
      if (text.startsWith("SELECT set_config")) return { rows: [] };
      if (text.startsWith("INSERT INTO")) return { rows: [{ id: "binding-1", tenant_id: "tenant-a", subject_type: "application", subject_id: "app-1", purpose: "client", version: 1, secret_ref: "vault://one", status: "active", grace_period_seconds: 0, valid_from: new Date().toISOString(), grace_until: null, superseded_at: null, revoked_at: null, created_at: new Date().toISOString(), updated_at: new Date().toISOString() }] };
      return { rows: [] };
    });
    const repository = new SqlSecretBindingRepository({ executor: scoped, mode: "shared", tenantId: "tenant-a" });
    await repository.create({ subjectType: "application", subjectId: "app-1", purpose: "client", secretRef: "vault://one" });
    expect(calls[0]?.text).toContain("set_config('app.tenant_id'");
    expect(calls.some((call) => call.text.startsWith("INSERT INTO") && call.values.includes("tenant-a"))).toBe(true);
  });

  it("selects dedicated executors without shared fallback", async () => {
    const dedicatedCalls: Call[] = [];
    const sharedCalls: Call[] = [];
    const dedicated = executor(dedicatedCalls);
    const shared = executor(sharedCalls);
    const bindings = new SqlSecretBindingRepository({ mode: "dedicated", tenantId: "tenant-a", dedicatedExecutor: dedicated });
    const identities = new SqlIdentityRepository({ mode: "dedicated", tenantId: "tenant-a", dedicatedExecutor: dedicated });
    await bindings.get("binding-1");
    await identities.get("identity-1");
    expect(dedicatedCalls).toHaveLength(2);
    expect(sharedCalls).toHaveLength(0);
  });

  it("routes identity delete through tenant context", async () => {
    const calls: Call[] = [];
    const scoped = executor(calls, (text) => text.startsWith("SELECT set_config") ? { rows: [] } : { rowCount: 1, rows: [] });
    const repository = new SqlIdentityRepository({ executor: scoped, mode: "shared", tenantId: "tenant-a" });
    await repository.delete("identity-1", 1);
    expect(calls[0]?.text).toContain("set_config('app.tenant_id'");
    expect(calls[1]?.text).toContain('"tenant_id" = $1');
    expect(calls[1]?.text).toContain('"id" = $2');
  });

  it("keeps active and retiring secret candidates usable during grace", async () => {
    const repository = new InMemorySecretBindingRepository({ tenantId: "tenant-a" });
    const first = await repository.create({ subjectType: "application", subjectId: "app-1", purpose: "client", secretRef: "vault://one" });
    const second = await repository.rotate("application", "app-1", "client", { secretRef: "vault://two", gracePeriodSeconds: 60 });
    expect(second.version).toBe(first.version + 1);
    expect((await repository.resolve("application", "app-1", "client"))?.binding.version).toBe(2);
    const retiring = { ...first, status: "retiring" as const, graceUntil: new Date(Date.now() - 1) };
    expect(isSecretBindingUsable(retiring)).toBe(false);
  });

  it("uses the full external identity key and preserves firstLinkedAt in memory", async () => {
    const canonical = externalIdentityCanonicalKey({ tenantId: "tenant-a", applicationId: "app-1", provider: "wechat", platform: "mini", providerAppId: "wx-1", subject: "subject-1" });
    expect(canonical.key).toContain("tenant-a");
    const repository = new InMemoryApplicationRepository({ tenantId: "tenant-a", applications: [{ id: "app-1", name: "App", slug: "app", status: "active" }] });
    const first = await repository.upsertExternalIdentity("app-1", { provider: "wechat", platform: "mini", appId: "wx-1", subject: "subject-1", email: "a@example.test" }, { actorId: "actor" });
    const second = await repository.upsertExternalIdentity("app-1", { provider: "wechat", platform: "mini", appId: "wx-1", subject: "subject-1", nickname: "nick" }, { actorId: "actor" });
    expect(second.id).toBe(first.id);
    expect(second.firstLinkedAt).toEqual(first.firstLinkedAt);
    expect(repository.snapshot().auditEvents.filter((event) => event.event === "application.external_identity.upserted")).toHaveLength(2);
    await repository.deleteApplication("app-1");
    expect(repository.snapshot().externalIdentities).toHaveLength(0);
  });

  it("recomputes effective state and does not confuse public client ids", async () => {
    const repository = new InMemoryApplicationRepository({
      tenantId: "tenant-a",
      applications: [
        { id: "app-1", name: "One", slug: "one", status: "active" },
        { id: "app-2", name: "Two", slug: "two", status: "active" },
      ],
      clients: [{ id: "record-public", applicationId: "app-1", clientId: "public", status: "disabled", readiness: "ready", effectiveStatus: "active" }],
    });
    const client = await repository.getClient("app-1", "public");
    expect(client).toMatchObject({ status: "disabled", readiness: "not_ready", effectiveStatus: "not_ready" });
    expect(await repository.getClient("app-2", "public")).toBeUndefined();
  });

  it("keeps SQL external identity upserts canonical and audited", async () => {
    const calls: Call[] = [];
    const firstLinkedAt = "2026-01-01T00:00:00.000Z";
    const existing = {
      id: "identity-1",
      tenant_id: "tenant-a",
      application_id: "app-1",
      platform_id: "platform-1",
      platform: "mini",
      provider: "wechat",
      provider_app_id: "wx-1",
      subject: "subject-1",
      external_app_id: "wx-1",
      openid: "openid-1",
      unionid: null,
      nickname: null,
      display_name: null,
      email: "old@example.test",
      avatar_url: null,
      scopes: "[]",
      first_linked_at: firstLinkedAt,
      linked_at: firstLinkedAt,
      last_authenticated_at: firstLinkedAt,
      version: 1,
      created_at: firstLinkedAt,
      updated_at: firstLinkedAt,
    };
    const sqlExecutor: MigrationSqlExecutor = {
      query: async (text, values = []) => {
        calls.push({ text, values });
        if (text.includes('FROM "gb_idaas_application"')) return { rows: [{ id: "app-1", tenant_id: "tenant-a", name: "App", slug: "app", status: "active", version: 1 }] };
        if (text.includes('FROM "gb_idaas_application_external_identity"')) return { rows: [existing] };
        if (text.startsWith('INSERT INTO "gb_idaas_application_external_identity"')) return { rows: [{ ...existing, nickname: "new", version: 2 }] };
        if (text.startsWith('INSERT INTO "gb_idaas_audit"')) return { rowCount: 1, rows: [] };
        return { rows: [] };
      },
    };
    const repository = new SqlApplicationRepository({ query: sqlExecutor.query, tenantId: "tenant-a" });
    const result = await repository.upsertExternalIdentity("app-1", { provider: "wechat", platform: "mini", appId: "wx-1", subject: "subject-1", nickname: "new" });
    expect(result).toMatchObject({ id: "identity-1", firstLinkedAt, version: 2 });
    const insert = calls.find((call) => call.text.startsWith('INSERT INTO "gb_idaas_application_external_identity"'));
     expect(insert?.text).toContain('"platform"');
     expect(insert?.text).toContain('"provider_app_id"');
     expect(insert?.text).toContain('AS "__idaas_identity_target"');
     expect(insert?.text).toContain('"__idaas_identity_target"."version" + 1');
     expect(insert?.values).toContain("old@example.test");
    expect(calls.some((call) => call.text.startsWith('INSERT INTO "gb_idaas_audit"'))).toBe(true);
  });

  it("creates tenant-scoped platform login state and scoped replay history", async () => {
    const sql = createApplicationManagementMigrationSql({ mode: "shared", tenantId: "tenant-a" });
    expect(sql).toContain("gb_idaas_platform_login_state");
    expect(sql).toContain("state_hash");
    expect(sql).toContain("binding_hash");
     expect(sql).toContain("lease_expires_at");
     expect(sql).toContain("PRIMARY KEY (\"tenant_id\", \"application_id\", \"state_hash\")");
     expect(sql).toContain('FOREIGN KEY ("tenant_id", "application_id", "platform_id") REFERENCES "gb_idaas_application_platform" ("tenant_id", "application_id", "id")');
     expect(sql).toContain("FORCE ROW LEVEL SECURITY");
    const definition = getApplicationManagementMigrationDefinition({ tenantId: "tenant-a" });
    const calls: Call[] = [];
    const applied = new Map<string, { version: number; name: string; checksum: string; scope: string }>();
    const migrationExecutor = executor(calls, (text, values) => {
      if (text.includes("FROM \"gb_idaas_schema_migration\"")) return { rows: [...applied.values()] };
      if (text.includes("INSERT INTO \"gb_idaas_schema_migration\"")) {
        applied.set(`${String(values[9])}:${String(values[0])}`, { version: Number(values[0]), name: String(values[1]), checksum: String(values[2]), scope: String(values[9]) });
        return { rowCount: 1, rows: [] };
      }
      return { rows: [] };
    });
    const coordinator = new MigrationCoordinator(migrationExecutor, [definition], { scope: "application-management:fixed:public:tenant-a", ownerId: "owner-a" });
    const first = await coordinator.run();
    const second = await coordinator.run();
    expect(first.applied).toHaveLength(1);
    expect(second.skipped).toHaveLength(1);
    expect(applied.size).toBe(1);
    expect(migrationChecksum(definition.sql)).toBe(definition.checksum);
  });

  it("keeps public clients ready without a secret binding", async () => {
    const repository = new InMemoryApplicationRepository({
      tenantId: "tenant-a",
      applications: [{ id: "app-public", name: "Public", slug: "public", status: "active" }],
      secretBindings: new InMemorySecretBindingRepository({ tenantId: "tenant-a" }),
    });
    const client = await repository.createClient("app-public", {
      clientId: "public-client",
      redirectUris: ["https://client.example.test/callback"],
      tokenEndpointAuthMethod: "none",
    });
    expect(client).toMatchObject({ readiness: "ready", effectiveStatus: "active", hasSecret: false, secretStatus: "not_required" });
  });

  it("keeps distinct application identity keys separate", async () => {
    const repository = new InMemoryApplicationRepository({
      tenantId: "tenant-a",
      applications: [{ id: "app-1", name: "App", slug: "app", status: "active" }],
    });
    const mini = await repository.upsertExternalIdentity("app-1", { provider: "wechat", platform: "mini", appId: "wx-1", subject: "subject-1" });
    const official = await repository.upsertExternalIdentity("app-1", { provider: "wechat", platform: "official", appId: "wx-2", subject: "subject-1" });
    const repeated = await repository.upsertExternalIdentity("app-1", { provider: "wechat", platform: "mini", appId: "wx-1", subject: "subject-1", nickname: "updated" });
    expect(official.id).not.toBe(mini.id);
    expect(repeated.id).toBe(mini.id);
    expect(repository.snapshot().externalIdentities).toHaveLength(2);
  });

  it("revokes every usable secret version for a subject", async () => {
    const repository = new InMemorySecretBindingRepository({ tenantId: "tenant-a" });
    await repository.create({ subjectType: "application-client", subjectId: "client-1", purpose: "oidc-client-secret", secretRef: "vault://one", gracePeriodSeconds: 60 });
    await repository.rotate("application-client", "client-1", "oidc-client-secret", { secretRef: "vault://two", gracePeriodSeconds: 60 });
    const revoked = await repository.revokeSubject("application-client", "client-1", "oidc-client-secret");
    expect(revoked).toHaveLength(2);
    expect(revoked.every((item) => item.status === "revoked")).toBe(true);
    expect(await repository.resolve("application-client", "client-1", "oidc-client-secret")).toBeUndefined();
  });

  it("uses table-scoped migration object names for custom schemas", () => {
    const sql = createApplicationManagementMigrationSql({
      mode: "shared",
      tables: {
        applications: "probe_app",
        platforms: "probe_platform",
        clients: "probe_client",
        auditEvents: "probe_audit",
        externalIdentities: "probe_external_identity",
        secretBindings: "probe_secret_binding",
        platformLoginStates: "probe_login_state",
      },
      tenantsTable: "probe_tenant",
      identityTable: "probe_identity",
      secretBindingTable: "probe_secret_binding",
      externalIdentitiesTable: "probe_external_identity",
      platformLoginStateTable: "probe_login_state",
      migrationTable: "probe_migration",
      migrationLockTable: "probe_migration_lock",
    });
    expect(sql).toContain('"probe_platform_application_id_uq"');
    expect(sql).toContain('"probe_external_identity_canonical_uq"');
    expect(sql).toContain('"probe_secret_binding_active_uq"');
    expect(sql).toContain('"probe_platform_tenant"');
  });

  it("rolls back a failed migration and its metadata", async () => {
    let rolledBack = false;
    let migrationExecuted = false;
    const migrationSql = "CREATE TABLE probe_failed_migration (id TEXT); SELECT 1 / 0;";
    const migrationExecutor: MigrationSqlExecutor = {
      query: async (text) => {
        if (text === migrationSql) {
          migrationExecuted = true;
          throw new Error("injected migration failure");
        }
        return { rows: [] };
      },
      transaction: async <T>(callback: (executor: MigrationSqlExecutor) => Promise<T>) => {
        try {
          return await callback(migrationExecutor);
        } catch (error) {
          rolledBack = true;
          throw error;
        }
      },
    };
    const coordinator = new MigrationCoordinator(migrationExecutor, [{ version: 1, name: "failure", sql: migrationSql }], {
      tableName: "probe_migration_history",
      lockTableName: "probe_migration_lock",
      scope: "probe-failure",
    });
    await expect(coordinator.run()).rejects.toThrow("injected migration failure");
    expect(migrationExecuted).toBe(true);
    expect(rolledBack).toBe(true);
  });
});
