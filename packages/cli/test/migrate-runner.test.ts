import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";
import {
  errorMessage,
  findMigrationIntegrations,
  loadAuth,
  parseArgs,
} from "../src/migrate-runner.js";

describe("migration runner integration discovery", () => {
  it("discovers OIDC and application integrations and avoids duplicate combined exports", () => {
    const oidc = { dryRun: () => "oidc" };
    const application = { run: () => undefined };
    expect(findMigrationIntegrations({ oidcMigration: oidc, applicationManagementMigration: application })).toEqual([oidc, application]);
    const combined = { dryRun: () => "all", run: () => undefined };
    expect(findMigrationIntegrations({ migrationIntegration: combined, oidcMigration: oidc, applicationManagementMigration: application })).toEqual([combined]);
  });

  it("flattens array dry-run output and handles cyclic exports", () => {
    const integration = { dryRun: () => ["one", ["two"]] };
    const cyclic: Record<string, unknown> = { migrationIntegration: integration };
    cyclic.self = cyclic;
    expect(findMigrationIntegrations(cyclic)).toEqual([integration]);
  });

  it("prefers the additive application migration series for direct exports", async () => {
    const directory = mkdtempSync(join(tmpdir(), "gb-migration-runner-"));
    const authFile = join(directory, "auth.mjs");
    writeFileSync(authFile, [
      "export const auth = { options: { database: {} } };",
      "export function getApplicationManagementMigrations() { return [{ sql: 'foundation' }, { sql: 'additive' }]; }",
      "export function applyVersionedApplicationManagementMigrations() {}",
    ].join("\n"));
    const loaded = await loadAuth(authFile);
    const dryRun = loaded.integrations.find((integration) => typeof integration.dryRun === "function");
    expect(dryRun).toBeDefined();
    expect(await dryRun?.dryRun?.()).toEqual([{ sql: "foundation" }, { sql: "additive" }]);
    const run = loaded.integrations.find((integration) => typeof integration.run === "function");
    expect(run).toBeDefined();
    await run?.run?.();
  });

  it("does not echo secret-bearing migration failures or argument values", () => {
    const secret = "postgres://user:password@internal.example/db";
    expect(errorMessage(new Error(`connection failed: ${secret}`))).toBe("migration operation failed");
    expect(() => parseArgs(["auth.ts", "--unknown", secret])).toThrow("unknown argument");
  });

  it("discovers open-platform and commerce integrations after the core exports", () => {
    const oidc = { dryRun: () => "oidc" };
    const application = { run: () => undefined };
    const openPlatform = { dryRun: () => "open-platform" };
    const commerce = { run: () => undefined };
    expect(findMigrationIntegrations({
      oidcMigration: oidc,
      applicationManagementMigration: application,
      openPlatformMigration: openPlatform,
      commerceMigration: commerce,
    })).toEqual([oidc, application, openPlatform, commerce]);
    expect(findMigrationIntegrations({ openPlatformMigrations: openPlatform, commerceMigrations: commerce }))
      .toEqual([openPlatform, commerce]);
    const combined = { dryRun: () => "all", run: () => undefined };
    expect(findMigrationIntegrations({
      migrationIntegration: combined,
      openPlatformMigration: openPlatform,
      commerceMigration: commerce,
    })).toEqual([combined]);
  });

  it("plans the open-platform series and the full commerce series from direct exports", async () => {
    const directory = mkdtempSync(join(tmpdir(), "gb-commerce-runner-"));
    const authFile = join(directory, "auth.mjs");
    writeFileSync(authFile, [
      "export const calls = [];",
      "export const auth = { options: { database: {",
      "  query: () => ({ rows: [] }),",
      "  transaction: async (callback) => callback({ query: () => ({ rows: [] }) }),",
      "} } };",
      "export function getOpenPlatformMigrations() { return [{ version: 1, sql: 'open-platform-foundation' }, { version: 2, sql: 'open-platform-management' }]; }",
      "export function applyVersionedOpenPlatformMigration(executor) { calls.push('open-platform:' + (typeof executor.transaction === 'function' ? 'transactional' : 'pooled')); }",
      "export function getOpenCommerceMigrations() { return [{ version: 1, sql: 'commerce-foundation' }, { version: 2, sql: 'commerce-idempotency' }]; }",
      "export const OPEN_COMMERCE_MIGRATION_TABLE = 'gb_open_commerce_schema_migration';",
      "export const OPEN_COMMERCE_MIGRATION_LOCK_TABLE = 'gb_open_commerce_schema_migration_lock';",
      "export class MigrationCoordinator {",
      "  constructor(executor, migrations, options) { calls.push('commerce-coordinator:' + options.tableName + ':' + options.lockTableName + ':' + options.requireTransaction + ':' + migrations.length); }",
      "  run(migrations) { calls.push('commerce-run:' + migrations.map((migration) => migration.version).join(',')); return Promise.resolve({ dryRun: false }); }",
      "}",
    ].join("\n"));
    const loaded = await loadAuth(authFile);
    expect(loaded.integrations).toHaveLength(4);
    const plan: string[] = [];
    for (const integration of loaded.integrations) {
      if (typeof integration.dryRun !== "function") continue;
      const value = await integration.dryRun();
      const statements = Array.isArray(value)
        ? value.map((migration) => (typeof migration === "object" && migration !== null && "sql" in migration ? String(migration.sql) : ""))
        : [String(value)];
      plan.push(...statements);
    }
    expect(plan).toEqual([
      "open-platform-foundation",
      "open-platform-management",
      "commerce-foundation",
      "commerce-idempotency",
    ]);
    for (const integration of loaded.integrations) {
      if (typeof integration.run === "function") await integration.run();
    }
    const module = await import(pathToFileURL(authFile).href) as { calls: string[] };
    expect(module.calls).toEqual([
      "open-platform:transactional",
      "commerce-coordinator:gb_open_commerce_schema_migration:gb_open_commerce_schema_migration_lock:true:2",
      "commerce-run:1,2",
    ]);
  });

  it("keeps failing migration integrations reported without their cause", () => {
    expect(errorMessage(new Error("migration integration 4 dry-run failed"))).toBe("migration integration 4 dry-run failed");
    expect(errorMessage(new Error("migration integration 4 failed: vault://internal/credential")))
      .toBe("migration operation failed");
  });
});
