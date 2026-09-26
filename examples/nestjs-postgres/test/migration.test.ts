import { afterAll, expect, it } from "vitest";
import {
  OpenPlatformCommercePersistence,
  OpenPlatformCompliancePersistence,
  OpenPlatformPersistence,
} from "@getbrick/idaas-control-plane/open-platform";

const previousOidcClientSecret = process.env.OIDC_CLIENT_SECRET;
process.env.OIDC_CLIENT_SECRET = "migration-integration-test-secret";

const {
  applicationManagementMigration,
  commerceMigration,
  commerceMigrationOptions,
  complianceMigration,
  complianceMigrationOptions,
  migrationIntegration,
  oidcMigration,
  openPlatformMigration,
  openPlatformMigrationOptions,
  pool,
} = await import("../src/auth.js");

it("exposes one migration integration for application, OIDC, open platform, commerce, and compliance", () => {
  for (const integration of [applicationManagementMigration, oidcMigration, openPlatformMigration, commerceMigration, complianceMigration, migrationIntegration]) {
    expect(typeof integration.dryRun).toBe("function");
    expect(typeof integration.run).toBe("function");
  }
});

it("applies the full open-platform, commerce, and compliance version series under the fixed tenant", () => {
  const openPlatform = OpenPlatformPersistence.getOpenPlatformMigrations(openPlatformMigrationOptions);
  const commerce = OpenPlatformCommercePersistence.getOpenCommerceMigrations(commerceMigrationOptions);
  const compliance = [OpenPlatformCompliancePersistence.getOpenComplianceMigrationDefinition(complianceMigrationOptions)];
  expect(openPlatform.map((migration) => migration.version)).toEqual([1, 2, 3, 4, 5]);
  expect(commerce.map((migration) => migration.version)).toEqual([1, 2, 3, 4]);
  expect(compliance.map((migration) => migration.version)).toEqual([1]);
  expect(openPlatformMigrationOptions.mode).toBe("fixed");
  expect(commerceMigrationOptions.mode).toBe("fixed");
  expect(complianceMigrationOptions.mode).toBe("fixed");
  expect(complianceMigrationOptions.tenantId).toBe(commerceMigrationOptions.tenantId);
  expect(complianceMigrationOptions.requireTransaction).toBe(true);
  expect(complianceMigrationOptions.lockKey).toBe("getbrick-open-compliance-schema");
  expect(complianceMigrationOptions.lockNamespace).toBe("open-platform-compliance");
  expect(openPlatform.every((migration) => migration.scope?.includes(openPlatformMigrationOptions.tenantId))).toBe(true);
  expect(commerce.every((migration) => migration.scope?.includes(commerceMigrationOptions.tenantId))).toBe(true);
  expect(compliance.every((migration) => migration.scope?.includes(complianceMigrationOptions.tenantId))).toBe(true);
  expect(openPlatform.every((migration) => migration.sql.length > 0)).toBe(true);
  expect(commerce.every((migration) => migration.sql.length > 0)).toBe(true);
  expect(compliance.every((migration) => migration.sql.length > 0)).toBe(true);
});

it("prints the open-platform, commerce, and compliance SQL in the migration order", async () => {
  const sql = await migrationIntegration.dryRun();
  const positions = [
    '"gb_idaas_oidc_artifact"',
    '"gb_idaas_application"',
    '"gb_open_tenant"',
    '"gb_open_webhook_delivery"',
    '"gb_open_commerce_plan"',
    '"gb_open_commerce_idempotency"',
    '"gb_open_compliance_data_asset"',
    '"gb_open_compliance_consent_record"',
    '"gb_open_compliance_privacy_request"',
    '"gb_open_compliance_retention_policy"',
    '"gb_open_compliance_retention_execution"',
    '"gb_open_compliance_cross_border_assessment"',
    '"gb_open_compliance_vendor"',
    '"gb_open_compliance_event"',
    '"gb_open_compliance_schema_migration"',
  ].map((identifier) => sql.indexOf(identifier));
  expect(positions.every((position) => position >= 0)).toBe(true);
  expect([...positions].sort((left, right) => left - right)).toEqual(positions);
  expect(sql).toContain("CREATE TABLE IF NOT EXISTS");
  expect(sql).not.toMatch(/"secret"\s+(?:TEXT|VARCHAR|BYTEA)/u);
  expect(sql).toContain("secret_digest");
  expect(sql).toContain("secret_reference");
  expect(sql).toContain("settlement_reference");
});

it("keeps the compliance series on evidence and status only", async () => {
  const sql = await complianceMigration.dryRun();
  expect(sql).toContain("ROW LEVEL SECURITY");
  expect(sql).toContain("app.tenant_id");
  expect(sql).toContain("gb_open_compliance_schema_migration_lock");
  expect(sql).toContain("append-only");
  expect(sql).toContain("gb_open_compliance_reject_domain_events_mutation");
  expect(sql).not.toMatch(/"(?:id_card|id_number|phone|email|raw_data|raw_payload|pii)"\s+(?:TEXT|VARCHAR|BYTEA)/u);
});

afterAll(async () => {
  await pool.end();
  if (previousOidcClientSecret === undefined) delete process.env.OIDC_CLIENT_SECRET;
  else process.env.OIDC_CLIENT_SECRET = previousOidcClientSecret;
});
