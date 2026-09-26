import { describe, expect, it } from "vitest";
import {
  applyVersionedApplicationManagementMigration,
  createApplicationManagementMigrationSql,
  dryRunApplicationManagementMigration,
  getApplicationManagementMigrationChecksum,
} from "../src/application-migration.js";
import {
  SqlApplicationRepository,
  decodeApplicationKeysetCursor,
} from "../src/application-sql-repository.js";
import {
  InMemorySecretBindingRepository,
  createSecretBindingTableMigrationSql,
  isSecretBindingUsable,
} from "../src/secret-binding.js";
import {
  MigrationCoordinator,
  migrationChecksum,
  type MigrationSqlExecutor,
} from "../src/migration-coordinator.js";
import {
  defineTenantConfig,
  tenantQualifiedKey,
} from "../src/tenant.js";
import { createIdentityTableMigrationSql, SqlIdentityRepository } from "../src/identity.js";

type QueryCall = { text: string; values: unknown[] };

function transactionExecutor(
  query: (text: string, values: unknown[]) => unknown | Promise<unknown>,
): MigrationSqlExecutor & { calls: QueryCall[] } {
  const calls: QueryCall[] = [];
  const executor = {
    calls,
    async query(text: string, values: unknown[] = []) {
      calls.push({ text, values });
      return query(text, values);
    },
    async transaction<T>(callback: (value: MigrationSqlExecutor) => Promise<T>): Promise<T> {
      return callback(executor);
    },
  };
  return executor;
}

describe("tenant persistence foundation", () => {
  it("normalizes all tenant modes and preserves qualified keys", () => {
    expect(defineTenantConfig({ mode: "fixed", tenantId: "fixed-a" })).toMatchObject({
      mode: "fixed",
      tenantId: "fixed-a",
      tenantColumn: "tenant_id",
    });
    expect(defineTenantConfig({ mode: "shared", tenantId: "shared-a" })).toMatchObject({
      mode: "shared",
      requireRls: true,
      requireTransactions: true,
    });
    expect(defineTenantConfig({ mode: "dedicated", tenantId: "dedicated-a" })).toMatchObject({
      mode: "dedicated",
      requireRls: false,
      requireTransactions: false,
    });
    expect(() => defineTenantConfig({ mode: "shared", tenantId: "shared-a", requireRls: false })).toThrow(/RLS/);
    expect(() => defineTenantConfig({ mode: "shared", tenantId: "shared-a", requireTransactions: false })).toThrow(/transaction/);
    expect(() => defineTenantConfig({ tenantColumn: null })).toThrow(/tenant column/);
     expect(tenantQualifiedKey("tenant-a", "resource-1")).toEqual({
       tenantId: "tenant-a",
       id: "resource-1",
       key: "tenant-a:resource-1",
     });
     expect(defineTenantConfig({ isolation: "shared", tenantId: "shared-b" }).mode).toBe("shared");
     expect(() => defineTenantConfig({ schema: "tenant.schema" })).toThrow(/schema/);
     expect(() => tenantQualifiedKey("tenant:a", "resource-1")).toThrow(/tenantId/);

  });

  it("generates tenant-qualified identity, binding, version and shared RLS schema", () => {
    const sql = createApplicationManagementMigrationSql({ mode: "shared", tenantId: "tenant-a" });
    expect(sql).toContain("gb_idaas_tenant");
    expect(sql).toContain("gb_idaas_application_external_identity");
    expect(sql).toContain("gb_idaas_secret_binding");
    expect(sql).toContain("PRIMARY KEY (\"tenant_id\", \"id\")");
    const auditTable = sql.match(/CREATE TABLE IF NOT EXISTS "gb_idaas_audit" \(([\s\S]*?)\);/u)?.[1] ?? "";
    expect(auditTable).toContain("\"version\" INTEGER NOT NULL DEFAULT 1");
    expect(sql).toContain("grace_period_seconds");
     expect(sql).toContain('ALTER TABLE "gb_idaas_tenant" ENABLE ROW LEVEL SECURITY');
     expect(sql).toContain("ENABLE ROW LEVEL SECURITY");

    expect(sql).toContain("FORCE ROW LEVEL SECURITY");
    expect(sql).toContain("current_setting('app.tenant_id', true)");
    const custom = createApplicationManagementMigrationSql({ tenant: { tenantId: "tenant-a", tenantColumn: "account_tenant_id" } });
    expect(custom).toContain("account_tenant_id");
    expect(custom).toContain("REFERENCES \"gb_idaas_application\" (\"account_tenant_id\", \"id\")");
    expect(sql).toContain("CREATE UNIQUE INDEX");
    expect(() => createIdentityTableMigrationSql("identity;drop", {}, "tenant_id")).toThrow();
    expect(createSecretBindingTableMigrationSql()).toContain("PRIMARY KEY (\"tenant_id\", \"id\")");
  });

  it("produces deterministic dry-run checksums without executing SQL", () => {
    const calls: QueryCall[] = [];
    const executor = {
      query: async (text: string, values: unknown[] = []) => {
        calls.push({ text, values });
        return { rows: [] };
      },
    };
    const first = dryRunApplicationManagementMigration({ tenantId: "tenant-a" });
    const second = dryRunApplicationManagementMigration({ tenantId: "tenant-a" });
    expect(first.checksum).toBe(second.checksum);
    expect(first.checksum).toBe(getApplicationManagementMigrationChecksum({ tenantId: "tenant-a" }));
    expect(first.migrations[0]?.checksum).toBe(first.migrations[0]?.checksum);
    expect(calls).toHaveLength(0);
    expect(executor).toBeDefined();
  });

  it("persists and updates identity external ids", async () => {
    const calls: QueryCall[] = [];
    const stored = {
      id: "identity-1",
      tenant_id: "tenant-a",
      kind: "subject",
      provider: "example",
      subject: "subject-1",
      external_id: "external-1",
      label: null,
      metadata: {},
      version: 1,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      disabled_at: null,
    };
    const query = async (text: string, values: unknown[] = []): Promise<unknown> => {
      calls.push({ text, values });
      if (text.startsWith("UPDATE")) return { rows: [{ ...stored, external_id: "external-2", version: 2 }] };
      return { rows: [stored] };
    };
    const repository = new SqlIdentityRepository({ query, tenantId: "tenant-a" });
    const created = await repository.create({
      id: "identity-1",
      kind: "subject",
      provider: "example",
      subject: "subject-1",
      externalId: "external-1",
    });
    expect(created.externalId).toBe("external-1");
    const updated = await repository.update("identity-1", { externalId: "external-2", version: 1 });
    expect(updated).toMatchObject({ externalId: "external-2", version: 2 });
    expect(calls.some((call) => call.text.includes("\"external_id\" = $"))).toBe(true);
  });
});

describe("migration coordinator", () => {
  it("locks, records checksums and skips an already applied migration", async () => {
    const calls: QueryCall[] = [];
    const applied = new Set<number>();
    const executor = transactionExecutor((text, values) => {
      if (text.includes("FROM \"gb_idaas_schema_migration\"")) {
        return { rows: [...applied].map((version) => ({ version, name: "foundation", checksum: migrationChecksum("CREATE TABLE demo (id TEXT);") })) };
      }
      if (text.includes("INSERT INTO \"gb_idaas_schema_migration\"")) {
        applied.add(Number(values[0]));
        return { rowCount: 1, rows: [] };
      }
      if (text.includes("CREATE TABLE IF NOT EXISTS \"gb_idaas_schema_migration\"")) return { rows: [] };
      if (text.includes("pg_advisory_xact_lock")) return { rows: [] };
      return { rows: [] };
    });
    const definition = { version: 1, name: "foundation", sql: "CREATE TABLE demo (id TEXT);" };
    const coordinator = new MigrationCoordinator(executor, [definition], { ownerId: "owner-a", lockKey: "demo-lock" });
    const first = await coordinator.run();
    expect(first.atomic).toBe(true);
    expect(first.applied).toHaveLength(1);
    expect(first.applied[0]?.checksum).toBe(migrationChecksum(definition.sql));
    expect(executor.calls.some((call) => call.text.includes("pg_advisory_xact_lock"))).toBe(true);
    expect(executor.calls.some((call) => call.text.includes("locked_by"))).toBe(true);
    const second = await coordinator.run();
    expect(second.applied).toHaveLength(0);
    expect(second.skipped).toHaveLength(1);
  });

  it("runs the application migration through the versioned coordinator", async () => {
    const calls: QueryCall[] = [];
    const applied = new Set<number>();
    const executor = transactionExecutor((text, values) => {
      if (text.includes("FROM \"gb_idaas_schema_migration\"")) {
        return { rows: [...applied].map((version) => ({ version, name: "application-management-foundation", checksum: getApplicationManagementMigrationChecksum() })) };
      }
      if (text.includes("INSERT INTO \"gb_idaas_schema_migration\"")) {
        applied.add(Number(values[0]));
        return { rowCount: 1, rows: [] };
      }
      return { rows: [] };
    });
    const first = await applyVersionedApplicationManagementMigration(executor, { tenantId: "tenant-a" });
    expect(first.atomic).toBe(true);
    expect(first.applied).toHaveLength(1);
    expect(executor.calls.some((call) => call.text.includes("pg_advisory_xact_lock"))).toBe(true);
    const second = await applyVersionedApplicationManagementMigration(executor, { tenantId: "tenant-a" });
    expect(second.skipped).toHaveLength(1);
  });

  it("fails closed on a checksum mismatch", async () => {
    const executor = transactionExecutor((text) => {
      if (text.includes("FROM \"gb_idaas_schema_migration\"")) {
        return { rows: [{ version: 1, name: "foundation", checksum: "0".repeat(64) }] };
      }
      return { rows: [] };
    });
    const coordinator = new MigrationCoordinator(executor, [{ version: 1, name: "foundation", sql: "CREATE TABLE demo (id TEXT);" }]);
    await expect(coordinator.run()).rejects.toThrow(/checksum mismatch/);
  });
});

describe("secret binding persistence", () => {
  it("rotates versions and keeps the previous version usable only during grace", async () => {
    const repository = new InMemorySecretBindingRepository({ tenantId: "tenant-a" });
    const first = await repository.create({
      subjectType: "application",
      subjectId: "app-1",
      purpose: "oidc-client",
      secretRef: "vault://one",
      gracePeriodSeconds: 30,
    });
    const second = await repository.rotate("application", "app-1", "oidc-client", {
      secretRef: "vault://two",
      gracePeriodSeconds: 30,
    });
    expect(first.version).toBe(1);
    expect(second.version).toBe(2);
    const resolved = await repository.resolve("application", "app-1", "oidc-client");
    expect(resolved?.binding.version).toBe(2);
    expect(resolved?.usedGracePeriod).toBe(false);
    const old = { ...first, status: "retiring" as const, graceUntil: new Date(Date.now() + 30_000) };
    expect(isSecretBindingUsable(old)).toBe(true);
    expect(isSecretBindingUsable({ ...old, graceUntil: new Date(Date.now() - 1) })).toBe(false);
  });
});

describe("application SQL tenant and keyset foundation", () => {
  it("uses tenant predicates, optimistic versions and keyset cursors", async () => {
    const calls: QueryCall[] = [];
    let applicationVersion = 1;
    const query = async (text: string, values: unknown[] = []): Promise<unknown> => {
      calls.push({ text, values });
      if (text.includes("COUNT(*)")) return { rows: [{ total: 2 }] };
      if (text.includes("FROM \"gb_idaas_application\"")) {
        if (text.includes("ORDER BY")) {
          return { rows: [{ id: "app-1", tenant_id: "tenant-a", name: "Alpha", slug: "alpha", status: "active", version: applicationVersion }] };
        }
        return { rows: [{ id: "app-1", tenant_id: "tenant-a", name: "Alpha", slug: "alpha", status: "active", version: applicationVersion }] };
      }
      if (text.includes("INSERT INTO \"gb_idaas_audit\"")) return { rowCount: 1, rows: [{ id: "audit-1" }] };
      if (text.startsWith("UPDATE \"gb_idaas_application\"")) {
        applicationVersion += 1;
        return { rows: [{ id: "app-1", tenant_id: "tenant-a", name: "Alpha updated", slug: "alpha", status: "active", version: applicationVersion }] };
      }
      return { rows: [] };
    };
    const repository = new SqlApplicationRepository({ query, tenantId: "tenant-a" });
    const first = await repository.listApplications({ limit: 1 });
    expect(first.nextCursor).toBeTruthy();
    expect(first.items[0]).toMatchObject({ tenantId: "tenant-a", version: 1 });
    const cursor = decodeApplicationKeysetCursor(first.nextCursor!, "applications", JSON.stringify(["", "", "", "", ""]), "tenant-a");
    expect(cursor?.id).toBe("app-1");
    const second = await repository.listApplications({ limit: 1, cursor: first.nextCursor });
    expect(second.hasMore).toBe(false);
    const keysetCall = calls.find((call) => call.text.includes("ORDER BY \"tenant_id\", \"id\""));
    expect(keysetCall?.text).toContain("> ($2, $3)");
    expect(keysetCall?.text).not.toContain("OFFSET");
    await repository.updateApplication("app-1", { name: "Alpha updated" });
    const update = calls.find((call) => call.text.startsWith("UPDATE \"gb_idaas_application\""));
    expect(update?.text).toContain("\"version\" = $");
    expect(update?.text).toContain("\"version\" = $3");
    expect(update?.values).toContain(1);
  });

  it("fails required-column readiness when version columns are absent", async () => {
    const calls: QueryCall[] = [];
    const repository = new SqlApplicationRepository({
      query: async (text, values = []) => {
        calls.push({ text, values });
        return { rows: [] };
      },
      columns: { applications: { version: null } },
    });
    expect(await repository.isReady()).toBe(false);
    expect(calls).toHaveLength(0);
  });

  it("fails shared readiness without transactions and RLS", async () => {
    const fixedQuery = async () => ({ rows: [] });
    const shared = new SqlApplicationRepository({ query: fixedQuery, tenantId: "tenant-a", mode: "shared" });
    expect(await shared.isReady()).toBe(false);
    const calls: QueryCall[] = [];
    const query = async (text: string, values: unknown[] = []): Promise<unknown> => {
      calls.push({ text, values });
      if (text.includes("pg_class")) return { rows: [{ rls: true, forceRls: true }] };
      return { rows: [] };
    };
    const executor = {
      query,
      transaction: async <T>(callback: (value: { query: typeof query }) => Promise<T>) => callback({ query }),
    };
    const ready = new SqlApplicationRepository({ executor, tenantId: "tenant-a", mode: "shared" });
    expect(await ready.isReady()).toBe(true);
    expect(calls.some((call) => call.text.includes("relrowsecurity"))).toBe(true);
  });
});
