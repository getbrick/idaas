import { createRequire, register } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";
import { resolve } from "node:path";

export interface MigrationPlan {
  compileMigrations: () => Promise<string>;
  runMigrations: () => Promise<void>;
}

export interface MigrationApi {
  getMigrations: (options: unknown, settings?: { throwOnUnsafe?: boolean }) => Promise<MigrationPlan>;
}

export interface MigrationAuth {
  options?: unknown;
}

export interface MigrationIntegration {
  dryRun?: () => unknown;
  run?: () => void | Promise<void>;
}

export interface LoadedAuth {
  auth: MigrationAuth;
  integrations: MigrationIntegration[];
}

export interface RunnerArgs {
  authFile: string;
  configFile?: string;
  dryRun: boolean;
}

interface MigrationCoordinatorRunner {
  run(migrations: readonly unknown[]): Promise<unknown>;
}

type MigrationCoordinatorConstructor = new (
  executor: Record<string, unknown>,
  migrations: readonly unknown[],
  options: Record<string, unknown>,
) => MigrationCoordinatorRunner;

const runningAsMain = process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (runningAsMain) register(new URL(import.meta.url.endsWith(".ts") ? "./resolve-ts.ts" : "./resolve-ts.js", import.meta.url));

export async function runMigrationRunner(argv = process.argv.slice(2)): Promise<number> {
  let loaded: LoadedAuth | undefined;
  try {
    const args = parseArgs(argv);
    loaded = await loadAuth(args.authFile, args.configFile);
    if (!isRecord(loaded.auth) || loaded.auth.options === undefined) {
      throw new Error("auth file must export a Better Auth instance with options");
    }
    const { getMigrations } = await loadMigrationApi();
    const plan = await getMigrations(loaded.auth.options, { throwOnUnsafe: !args.dryRun });
    if (args.dryRun) {
      if (typeof plan.compileMigrations !== "function") {
        throw new Error("installed better-auth version does not support dry-run migrations");
      }
      if (loaded.integrations.length > 0 && !loaded.integrations.some((integration) => typeof integration.dryRun === "function")) {
        throw new Error("migration integrations do not expose dry-run output");
      }
      const parts: string[] = [await plan.compileMigrations()];
      for (const [index, integration] of loaded.integrations.entries()) {
        if (typeof integration.dryRun !== "function") continue;
        try {
          appendMigrationOutput(parts, await integration.dryRun());
        } catch {
          throw new Error(`migration integration ${index + 1} dry-run failed`);
        }
      }
      const normalized = parts
        .map((part) => part.trim())
        .filter((part) => part.length > 0 && part !== ";")
        .join("\n\n");
      process.stdout.write(normalized.length > 0 ? `${normalized}\n` : "No migrations needed.\n");
    } else {
      if (typeof plan.runMigrations !== "function") {
        throw new Error("installed better-auth version does not expose runMigrations");
      }
      if (loaded.integrations.length > 0 && !loaded.integrations.some((integration) => typeof integration.run === "function")) {
        throw new Error("migration integrations do not expose run");
      }
      await plan.runMigrations();
      for (const [index, integration] of loaded.integrations.entries()) {
        if (typeof integration.run !== "function") continue;
        try {
          await integration.run();
        } catch {
          throw new Error(`migration integration ${index + 1} failed`);
        }
      }
      console.log("✓ migration completed");
    }
    return 0;
  } catch (error) {
    console.error(`✗ migration failed: ${errorMessage(error)}`);
    return 1;
  } finally {
    if (loaded) {
      try {
        await closeDatabase(loaded.auth);
      } catch (error) {
        console.error(`✗ failed to close the migration database: ${errorMessage(error)}`);
        process.exitCode = 1;
      }
    }
  }
}

export function parseArgs(args: string[]): RunnerArgs {
  const values = args[0] === "--" ? args.slice(1) : args;
  if (!values[0]) throw new Error("an auth file is required");
  const result: RunnerArgs = { authFile: values[0], dryRun: false };
  for (let index = 1; index < values.length; index++) {
    const argument = values[index];
    if (argument === "--dry-run") {
      if (result.dryRun) throw new Error("--dry-run may only be specified once");
      result.dryRun = true;
      continue;
    }
    if (argument === "--config") {
      if (result.configFile !== undefined) throw new Error("--config may only be specified once");
      const value = args[++index];
      if (!value || value.startsWith("-")) throw new Error("--config requires a value");
      result.configFile = value;
      continue;
    }
    throw new Error("unknown argument");
  }
  return result;
}

export async function loadAuth(authFile: string, configFile?: string): Promise<LoadedAuth> {
  const authPath = resolve(process.cwd(), authFile);
  const authUrl = pathToFileURL(authPath).href;
  const authModule = await import(authUrl);
  let auth = findAuth(authModule);
  const modules: unknown[] = [authModule];
  if (configFile) {
    const configUrl = pathToFileURL(resolve(process.cwd(), configFile)).href;
    if (configUrl !== authUrl) {
      const configModule = await import(configUrl);
      modules.push(configModule);
      auth = findAuth(configModule) ?? auth;
    }
  }
  if (!auth) throw new Error("auth file must export a Better Auth instance");
  const integrations = modules.flatMap((module) => findMigrationIntegrations(module));
  if (!integrations.some((integration) => isRecord(integration) && typeof integration.dryRun === "function" && typeof integration.run === "function")) {
    for (const module of modules) integrations.push(...findDirectMigrationIntegrations(module, auth));
  }
  return { auth, integrations: uniqueIntegrations(integrations) };
}

export function findAuth(value: unknown, depth = 0): MigrationAuth | undefined {
  if (!isRecord(value) || depth > 3) return undefined;
  for (const key of ["auth", "default", "defaultAuth", "idaasAuth", "betterAuth"]) {
    const candidate = value[key];
    if (isRecord(candidate) && candidate.options !== undefined) return candidate as MigrationAuth;
    const nested = findAuth(candidate, depth + 1);
    if (nested) return nested;
  }
  return undefined;
}

export function findMigrationIntegrations(
  value: unknown,
  depth = 0,
  seen = new Set<object>(),
): MigrationIntegration[] {
  if (!isRecord(value) || depth > 4 || seen.has(value)) return [];
  seen.add(value);
  const combined = value.migrationIntegration;
  if (isMigrationIntegration(combined)) return [combined];
  const integrations: MigrationIntegration[] = [];
  for (const key of [
    "oidcMigration",
    "oidcMigrations",
    "postgresOidcMigration",
    "oidcApplicationMigration",
    "applicationMigration",
    "applicationMigrations",
    "applicationManagementMigration",
    "idaasApplicationMigration",
    "applicationManagement",
    "openPlatformMigration",
    "openPlatformMigrations",
    "openPlatformPersistenceMigration",
    "idaasOpenPlatformMigration",
    "openPlatformManagementMigration",
    "commerceMigration",
    "commerceMigrations",
    "openCommerceMigration",
    "openPlatformCommerceMigration",
    "idaasCommerceMigration",
    "complianceMigration",
    "complianceMigrations",
    "openComplianceMigration",
    "openComplianceMigrations",
    "openPlatformComplianceMigration",
    "compliancePersistenceMigration",
    "openCompliancePersistenceMigration",
    "openPlatformCompliancePersistenceMigration",
    "idaasComplianceMigration",
    "openPlatformCompliance",
    "compliance",
    "openCompliance",
    "compliancePersistence",
    "openPlatform",
    "commerce",
    "oidc",
    "migration",
    "migrationIntegration",
    "migrationIntegrations",
    "migrations",
  ]) {
    const candidate = value[key];
    if (Array.isArray(candidate)) {
      for (const item of candidate) integrations.push(...findMigrationIntegrations(item, depth + 1, seen));
    } else if (isMigrationIntegration(candidate)) {
      integrations.push(candidate);
    } else if (isRecord(candidate)) {
      integrations.push(...findMigrationIntegrations(candidate, depth + 1, seen));
    }
  }
  for (const key of ["auth", "default", "defaultAuth", "idaasAuth", "betterAuth"]) {
    integrations.push(...findMigrationIntegrations(value[key], depth + 1, seen));
  }
  return uniqueIntegrations(integrations);
}

export function isMigrationIntegration(value: unknown): value is MigrationIntegration {
  return isRecord(value) && (typeof value.dryRun === "function" || typeof value.run === "function");
}

function findDirectMigrationIntegrations(value: unknown, auth: MigrationAuth): MigrationIntegration[] {
  if (!isRecord(value)) return [];
  const integrations: MigrationIntegration[] = [];
  const oidcSql = value.getPostgresOidcMigrationSql ?? value.getOidcMigrationSql;
  const applicationSeriesSql = value.getApplicationManagementMigrations ??
    value.getApplicationManagementMigrationDefinitions ??
    value.getApplicationManagementMigrationSeries ??
    value.createApplicationManagementMigrationSeriesPlan ??
    value.planApplicationManagementMigrations ??
    value.dryRunApplicationManagementMigrations;
  const applicationSql = value.getApplicationManagementMigrationSql ??
    value.createApplicationManagementMigrationSql ??
    value.getApplicationManagementMigration;
  const openPlatformSeriesSql = value.getOpenPlatformMigrations ??
    value.getOpenPlatformPersistenceMigrations ??
    value.createOpenPlatformMigrationsPlan ??
    value.getOpenPlatformMigrationPlan;
  const openPlatformSql = value.getOpenPlatformMigrationSql ??
    value.getOpenPlatformPersistenceMigrationSql ??
    value.createOpenPlatformMigrationSql ??
    value.createOpenPlatformPersistenceMigrationSql;
  const commerceSeriesSql = value.getOpenCommerceMigrations ?? value.getCommerceMigrations;
  const commerceSql = value.getOpenCommerceMigrationSql ??
    value.getCommerceMigrationSql ??
    value.createOpenCommerceMigrationSql ??
    value.createCommerceMigrationSql;
  const complianceSql = value.getOpenComplianceMigrationDefinition ??
    value.getComplianceMigrationDefinition ??
    value.createComplianceMigrationDefinition ??
    value.createOpenComplianceMigrationDefinition ??
    value.getOpenComplianceMigrationPlan ??
    value.createOpenComplianceMigrationPlan ??
    value.getOpenComplianceMigrationSql ??
    value.getComplianceMigrationSql ??
    value.getOpenComplianceMigrations;
  if (typeof oidcSql === "function") {
    integrations.push({ dryRun: () => oidcSql() });
  }
  if (typeof applicationSeriesSql === "function") {
    integrations.push({ dryRun: () => applicationSeriesSql() });
  } else if (typeof applicationSql === "function") {
    integrations.push({ dryRun: () => applicationSql() });
  }
  if (typeof openPlatformSeriesSql === "function") {
    integrations.push({ dryRun: () => openPlatformSeriesSql() });
  } else if (typeof openPlatformSql === "function") {
    integrations.push({ dryRun: () => openPlatformSql() });
  }
  if (typeof commerceSeriesSql === "function") {
    integrations.push({ dryRun: () => commerceSeriesSql() });
  } else if (typeof commerceSql === "function") {
    integrations.push({ dryRun: () => commerceSql() });
  }
  if (typeof complianceSql === "function") {
    integrations.push({ dryRun: () => complianceSql() });
  }
  const oidcRun = value.migratePostgresOidcSchema ?? value.runPostgresOidcMigration;
  const applicationSeriesRun = value.applyVersionedApplicationManagementMigrations ??
    value.applyApplicationManagementMigrations ??
    value.runApplicationManagementMigrations ??
    value.applyVersionedApplicationManagementMigrationSeries;
  const applicationRun = value.applyVersionedApplicationManagementMigration ??
    value.applyApplicationManagementMigration;
  const openPlatformRun = value.applyVersionedOpenPlatformMigration ??
    value.applyOpenPlatformMigration ??
    value.runOpenPlatformMigration ??
    value.applyOpenPlatformPersistenceMigration;
  const commerceRun = value.applyVersionedOpenCommerceMigration ??
    value.applyOpenCommerceMigration ??
    value.runOpenCommerceMigration ??
    value.applyVersionedCommerceMigration;
  const complianceRun = value.applyVersionedOpenComplianceMigration ??
    value.applyOpenComplianceMigration ??
    value.runOpenComplianceMigration ??
    value.applyVersionedComplianceMigration ??
    value.applyComplianceMigration ??
    value.runComplianceMigration ??
    value.applyOpenPlatformComplianceMigration;
  const database = isRecord(auth.options) ? auth.options.database : undefined;
  const executor = isRecord(database) ? migrationExecutorForDatabase(database) : undefined;
  if (typeof oidcRun === "function" && executor !== undefined) {
    integrations.push({ run: () => oidcRun(executor) });
  }
  if (typeof applicationSeriesRun === "function" && executor !== undefined) {
    integrations.push({ run: () => applicationSeriesRun(executor) });
  } else if (typeof applicationRun === "function" && executor !== undefined) {
    integrations.push({ run: () => applicationRun(executor) });
  }
  if (typeof openPlatformRun === "function" && executor !== undefined) {
    integrations.push({ run: () => openPlatformRun(executor) });
  }
  const commerceSeriesRun = createCommerceSeriesRun(
    value.MigrationCoordinator,
    value.getOpenCommerceMigrations ?? value.getCommerceMigrations,
    value.OPEN_COMMERCE_MIGRATION_TABLE,
    value.OPEN_COMMERCE_MIGRATION_LOCK_TABLE,
  );
  if (commerceSeriesRun !== undefined && executor !== undefined) {
    integrations.push({ run: () => commerceSeriesRun(executor) });
  } else if (typeof commerceRun === "function" && executor !== undefined) {
    integrations.push({ run: () => commerceRun(executor) });
  }
  if (typeof complianceRun === "function" && executor !== undefined) {
    integrations.push({ run: () => complianceRun(executor) });
  }
  return integrations;
}

function createCommerceSeriesRun(
  coordinatorFactory: unknown,
  migrationsFactory: unknown,
  tableName: unknown,
  lockTableName: unknown,
): ((executor: Record<string, unknown>) => Promise<void>) | undefined {
  if (typeof coordinatorFactory !== "function" || typeof migrationsFactory !== "function") return undefined;
  if (typeof tableName !== "string" || typeof lockTableName !== "string") return undefined;
  const Coordinator = coordinatorFactory as MigrationCoordinatorConstructor;
  return async (executor) => {
    const migrations = (migrationsFactory as () => readonly unknown[])();
    const coordinator = new Coordinator(executor, migrations, {
      tableName,
      lockTableName,
      requireTransaction: true,
    });
    await coordinator.run(migrations);
  };
}

function migrationExecutorForDatabase(database: Record<string, unknown>): Record<string, unknown> {
  if (typeof database.transaction === "function") return database;
  const query = database.query;
  const connect = database.connect;
  if (typeof query !== "function" || typeof connect !== "function") return database;
  return {
    query: (text: string, values?: unknown[]) => query.call(database, text, values),
    transaction: async <T>(callback: (executor: Record<string, unknown>) => Promise<T>): Promise<T> => {
      const client = await connect.call(database);
      if (!isRecord(client) || typeof client.query !== "function") {
        throw new Error("migration database client is invalid");
      }
      const clientQuery = client.query;
      const executor = {
        query: (text: string, values?: unknown[]) => clientQuery.call(client, text, values),
      };
      try {
        await clientQuery.call(client, "BEGIN");
        const result = await callback(executor);
        await clientQuery.call(client, "COMMIT");
        return result;
      } catch (error) {
        await clientQuery.call(client, "ROLLBACK");
        throw error;
      } finally {
        if (typeof client.release === "function") client.release();
      }
    },
  };
}

export async function loadMigrationApi(): Promise<MigrationApi> {
  const bases = [resolve(process.cwd(), "package.json"), import.meta.url];
  try {
    bases.push(createRequire(import.meta.url).resolve("@getbrick/idaas-core"));
  } catch {
  }
  for (const base of bases) {
    try {
      const modulePath = createRequire(base).resolve("better-auth/db/migration");
      const loaded: unknown = await import(pathToFileURL(modulePath).href);
      if (isRecord(loaded) && typeof loaded.getMigrations === "function") return loaded as unknown as MigrationApi;
    } catch {
    }
  }
  throw new Error("better-auth migration support is unavailable");
}

export async function closeDatabase(auth: MigrationAuth): Promise<void> {
  if (!isRecord(auth.options)) return;
  const database = auth.options.database;
  if (!isRecord(database)) return;
  const close = database.end ?? database.close ?? database.disconnect;
  if (typeof close !== "function") return;
  await close.call(database);
}

export function errorMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : typeof error === "string" ? error : "";
  const normalized = message.trim();
  if (
    normalized.length === 0 ||
    normalized.length > 512 ||
    /[\u0000-\u001f\u007f]/u.test(normalized) ||
    /(?:postgres(?:ql)?:\/\/|mysql:\/\/|mongodb(?:\+srv)?:\/\/|secret|password|token|private[-_]?key|authorization|cookie|vault:\/\/)/iu.test(normalized)
  ) return "migration operation failed";
  if (/^(?:an auth file is required|auth file must export|installed better-auth|better-auth migration|migration integrations|migration integration|unknown argument|--|the installed|operation failed)/u.test(normalized)) {
    return normalized;
  }
  return "migration operation failed";
}

function appendMigrationOutput(output: string[], value: unknown): void {
  if (typeof value === "string") {
    output.push(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) appendMigrationOutput(output, item);
    return;
  }
  if (isRecord(value)) {
    if (typeof value.sql === "string") {
      output.push(value.sql);
      return;
    }
    if (Array.isArray(value.migrations)) {
      for (const migration of value.migrations) {
        if (isRecord(migration) && typeof migration.sql === "string") output.push(migration.sql);
      }
      return;
    }
    if (Array.isArray(value.sql)) {
      for (const sql of value.sql) appendMigrationOutput(output, sql);
    }
  }
}

function uniqueIntegrations(integrations: MigrationIntegration[]): MigrationIntegration[] {
  const output: MigrationIntegration[] = [];
  const seen = new Set<unknown>();
  for (const integration of integrations) {
    if (seen.has(integration)) continue;
    seen.add(integration);
    output.push(integration);
  }
  return output;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

if (runningAsMain) {
  process.exitCode = await runMigrationRunner();
}
