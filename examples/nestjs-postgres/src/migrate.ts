import { getMigrations } from "better-auth/db/migration";
import { Pool, type PoolClient } from "pg";
import {
  applyVersionedApplicationManagementMigrations,
  getApplicationManagementMigrations,
  MigrationCoordinator,
  type MigrationSqlExecutor,
} from "@getbrick/idaas-control-plane";
import {
  OpenPlatformCommercePersistence,
  OpenPlatformCompliancePersistence,
  OpenPlatformPersistence,
} from "@getbrick/idaas-control-plane/open-platform";
import {
  createIdaas,
  getPostgresOidcMigrationSql,
  migratePostgresOidcSchema,
  type IdaasConfigInput,
} from "@getbrick/idaas-core";

const configModuleUrl = new URL("../getbrick.config.ts", import.meta.url).href;
const { idaas } = (await import(configModuleUrl)) as { idaas: IdaasConfigInput };

const rawArgs = process.argv.slice(2);
const args = rawArgs[0] === "--" ? rawArgs.slice(1) : rawArgs;
const unknown = args.find((argument) => argument !== "--dry-run");
if (unknown) throw new Error("unknown migration argument");

const dryRun = args.includes("--dry-run");
const connectionString =
  process.env.DATABASE_URL ?? "postgres://postgres:gbtest@localhost:54329/getbrick";
const migrationTenant = {
  mode: "fixed" as const,
  tenantId: process.env.IDAAS_TENANT_ID ?? "getbrick-example",
  requireTransactions: true,
};
const pool = new Pool({ connectionString });
const auth = createIdaas({ config: idaas, database: pool });
const migrationExecutor = createMigrationExecutor();

export const openPlatformMigrationOptions = {
  mode: migrationTenant.mode,
  tenantId: migrationTenant.tenantId,
  requireTransaction: migrationTenant.requireTransactions,
};

export const commerceMigrationOptions = {
  mode: migrationTenant.mode,
  tenantId: migrationTenant.tenantId,
  requireTransaction: migrationTenant.requireTransactions,
  requireTransactions: migrationTenant.requireTransactions,
};

export const oidcApplicationMigration = {
  dryRun: async () => [
    getPostgresOidcMigrationSql({ namespace: migrationTenant.tenantId }),
    ...getApplicationManagementMigrations(migrationTenant).map((migration) => migration.sql),
  ].join("\n\n"),
  run: async () => {
    await migratePostgresOidcSchema(pool, { namespace: migrationTenant.tenantId });
    await applyVersionedApplicationManagementMigrations(migrationExecutor, migrationTenant);
  },
};

export const openPlatformMigration = {
  dryRun: () => OpenPlatformPersistence.getOpenPlatformMigrations(openPlatformMigrationOptions)
    .map((migration) => migration.sql)
    .join("\n\n"),
  run: () => OpenPlatformPersistence.applyVersionedOpenPlatformMigration(
    migrationExecutor,
    openPlatformMigrationOptions,
  ),
};

export const commerceMigrations = () => OpenPlatformCommercePersistence.getOpenCommerceMigrations(commerceMigrationOptions);

export const commerceMigrationLock = {
  key: "getbrick-open-commerce-schema",
  namespace: "open-platform-commerce",
};

export const commerceMigration = {
  dryRun: () => commerceMigrations().map((migration) => migration.sql).join("\n\n"),
  run: () => {
    const migrations = commerceMigrations();
    return new MigrationCoordinator(
      migrationExecutor,
      migrations,
      {
        tableName: OpenPlatformCommercePersistence.OPEN_COMMERCE_MIGRATION_TABLE,
        lockTableName: OpenPlatformCommercePersistence.OPEN_COMMERCE_MIGRATION_LOCK_TABLE,
        lockKey: commerceMigrationLock.key,
        lockNamespace: commerceMigrationLock.namespace,
        requireTransaction: migrationTenant.requireTransactions,
      },
    ).run(migrations);
  },
};

export const complianceMigrationLock = {
  key: "getbrick-open-compliance-schema",
  namespace: "open-platform-compliance",
};

export const complianceMigrationOptions = {
  mode: migrationTenant.mode,
  tenantId: migrationTenant.tenantId,
  requireTransaction: migrationTenant.requireTransactions,
  requireTransactions: migrationTenant.requireTransactions,
  lockKey: complianceMigrationLock.key,
  lockNamespace: complianceMigrationLock.namespace,
};

export const complianceMigrationDefinition = () =>
  OpenPlatformCompliancePersistence.getOpenComplianceMigrationDefinition(complianceMigrationOptions);

export const complianceMigration = {
  dryRun: () => complianceMigrationDefinition().sql,
  run: () => OpenPlatformCompliancePersistence.applyVersionedOpenComplianceMigration(
    migrationExecutor,
    complianceMigrationOptions,
  ),
};

export const migrationIntegration = {
  dryRun: async () => [
    await oidcApplicationMigration.dryRun(),
    await openPlatformMigration.dryRun(),
    await commerceMigration.dryRun(),
    await complianceMigration.dryRun(),
  ].join("\n\n"),
  run: async () => {
    await oidcApplicationMigration.run();
    await openPlatformMigration.run();
    await commerceMigration.run();
    await complianceMigration.run();
  },
};

function createMigrationExecutor() {
  return {
    query: (text: string, values?: unknown[]) => pool.query(text, values),
    transaction: async <T>(callback: (executor: MigrationSqlExecutor) => Promise<T>): Promise<T> => {
      const client: PoolClient = await pool.connect();
      const executor = {
        query: (text: string, values?: unknown[]) => client.query(text, values),
      };
      try {
        await client.query("BEGIN");
        const result = await callback(executor);
        await client.query("COMMIT");
        return result;
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }
    },
  };
}

try {
  const plan = await getMigrations(auth.options, { throwOnUnsafe: !dryRun });
  if (dryRun) {
    const sql = await plan.compileMigrations();
    const normalizedSql = sql.trim();
    const integrationSql = await migrationIntegration.dryRun();
    const output = normalizedSql && normalizedSql !== ";"
      ? `${sql}\n\n${integrationSql}\n`
      : `${integrationSql}\n`;
    process.stdout.write(output);
  } else {
     await plan.runMigrations();
     await migrationIntegration.run();
     console.log("✓ migration completed");
  }
} catch (error) {
  console.error(`✗ migration failed: ${safeMigrationError(error)}`);
  process.exitCode = 1;
} finally {
  await pool.end();
}

function safeMigrationError(error: unknown): string {
  const message = error instanceof Error ? error.message : typeof error === "string" ? error : "";
  if (/(?:postgres(?:ql)?:\/\/|secret|password|token|private[-_]?key|authorization|cookie)/iu.test(message)) {
    return "migration operation failed";
  }
  return message.trim().length > 0 && message.length <= 256 ? message : "migration operation failed";
}
