import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { Pool } from "pg";
import {
  ApplicationOidcClientStore,
  SqlApplicationRepository,
  SqlIdentityRepository,
  SqlSecretBindingRepository,
   SqlTenantRepository,
   applyVersionedApplicationManagementMigrations,
   getApplicationManagementMigrations,
   getTenantTransactionExecutor,
   MigrationCoordinator,
   normalizeTenantConfig,
   runWithTenantTransaction,
   type OpaqueClientSessionCreateInput,
   type OpaqueClientSessionRecord,
   type OpaqueClientSessionStore,
   type TenantConfig,
   type TenantSqlExecutor,

} from "@getbrick/idaas-control-plane";
import {
  buildTableMap,
  createIdaas,
  createPostgresOidcAdapterFactory,
  getPostgresOidcMigrationSql,
  migratePostgresOidcSchema,
} from "@getbrick/idaas-core";
import {
  OpenPlatformCommercePersistence,
  OpenPlatformCompliancePersistence,
  OpenPlatformPersistence,
} from "@getbrick/idaas-control-plane/open-platform";
import { idaas } from "../getbrick.config.js";

const connectionString =
  process.env.DATABASE_URL ??
  "postgres://postgres:gbtest@localhost:54329/getbrick";

export const pool = new Pool({ connectionString });

export const auth = createIdaas({
  config: idaas,
  database: pool,
});

export const applicationTenantConfig: TenantConfig = normalizeTenantConfig({
  mode: "fixed",
  tenantId: process.env.IDAAS_TENANT_ID ?? "getbrick-example",
  requireTransactions: true,
});

export const applicationTenantMode = applicationTenantConfig.mode;

export const oidcAdapter = createPostgresOidcAdapterFactory(pool, {
  namespace: "getbrick-example",
});

export const applicationSqlExecutor: TenantSqlExecutor = {
  query: (text, values) => pool.query(text, values),
  transaction: async <T>(callback: (executor: TenantSqlExecutor) => Promise<T>): Promise<T> => {
    const client = await pool.connect();
    const executor: TenantSqlExecutor = {
      query: (queryText, queryValues) => client.query(queryText, queryValues),
    };
    try {
      await client.query("BEGIN");
      const result = await runWithTenantTransaction(applicationSqlExecutor, executor, () => callback(executor));
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

export class PostgresOpaqueClientSessionStore implements OpaqueClientSessionStore {
  private readonly executor: TenantSqlExecutor;
  private readonly namespace: string;
  private readonly encryptionKey: Buffer;
  private readonly table = '"gb_idaas_oidc_artifact"';

  constructor(options: { executor: TenantSqlExecutor; namespace: string; encryptionKey: string }) {
    this.executor = options.executor;
    this.namespace = `${options.namespace}:default`;
    this.encryptionKey = createHash("sha256").update(options.encryptionKey).digest();
  }

  async create(input: OpaqueClientSessionCreateInput): Promise<OpaqueClientSessionRecord> {
    const now = Date.now();
    const sessionReference = input.sessionReference ?? `ocs_${randomBytes(32).toString("base64url")}`;
    const record: OpaqueClientSessionRecord = {
      sessionReference,
      userId: input.userId,
      ...(input.tenantId === undefined ? {} : { tenantId: input.tenantId }),
      applicationId: input.applicationId,
      platformId: input.platformId,
      ...(input.identityKey === undefined ? {} : { identityKey: input.identityKey }),
      client: input.client,
      hostSessionToken: input.hostSessionToken,
      createdAt: input.createdAt ?? now,
      expiresAt: input.expiresAt,
      updatedAt: now,
    };
    await this.write(record);
    return { ...record };
  }

  async get(sessionReference: string): Promise<OpaqueClientSessionRecord | undefined> {
    const id = this.id(sessionReference);
    const result = await this.activeExecutor().query(
      `SELECT payload, expires_at FROM ${this.table} WHERE namespace = $1 AND model = $2 AND id = $3 AND deleted_at IS NULL LIMIT 1`,
      [this.namespace, "ClientSession", id],
    );
    const row = rows(result)[0];
    if (row === undefined) return undefined;
    const record = this.decode(row);
    if (record === undefined || record.expiresAt <= Date.now()) return undefined;
    return record;
  }

  async findActive(input: {
    userId: string;
    tenantId?: string;
    applicationId: string;
    platformId: string;
    identityKey?: string;
    client: OpaqueClientSessionRecord["client"];
  }): Promise<OpaqueClientSessionRecord | undefined> {
    const result = await this.activeExecutor().query(
      `SELECT payload, expires_at FROM ${this.table} WHERE namespace = $1 AND model = $2 AND account_id = $3 AND client_id = $4 AND deleted_at IS NULL ORDER BY updated_at DESC`,
      [this.namespace, "ClientSession", input.userId, `${input.applicationId}:${input.platformId}`],
    );
    for (const row of rows(result)) {
      const record = this.decode(row);
      if (record === undefined || record.expiresAt <= Date.now()) continue;
      if (record.userId !== input.userId || record.applicationId !== input.applicationId || record.platformId !== input.platformId || record.client !== input.client) continue;
      if (input.tenantId !== undefined && record.tenantId !== input.tenantId) continue;
      if (input.identityKey !== undefined && record.identityKey !== input.identityKey) continue;
      return record;
    }
    return undefined;
  }

  async rotate(sessionReference: string, update: { hostSessionToken?: string; expiresAt: number; client?: OpaqueClientSessionRecord["client"] }): Promise<OpaqueClientSessionRecord> {
    const current = await this.get(sessionReference);
    if (current === undefined) throw new Error("Client session is unavailable");
    const next: OpaqueClientSessionRecord = {
      ...current,
      sessionReference: `ocs_${randomBytes(32).toString("base64url")}`,
      client: update.client ?? current.client,
      ...(update.hostSessionToken === undefined ? {} : { hostSessionToken: update.hostSessionToken }),
      expiresAt: update.expiresAt,
      updatedAt: Date.now(),
    };
    const operation = async (executor: TenantSqlExecutor): Promise<void> => {
      const update = await executor.query(
        `UPDATE ${this.table} SET deleted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE namespace = $1 AND model = $2 AND id = $3 AND deleted_at IS NULL AND expires_at > $4`,
        [this.namespace, "ClientSession", this.id(current.sessionReference), new Date()],
      );
      if (affected(update) !== 1) throw new Error("Client session is unavailable");
      await this.write(next, executor);
    };
    const active = getTenantTransactionExecutor(this.executor);
    if (active !== undefined) await operation(active);
    else if (typeof this.executor.transaction === "function") await this.executor.transaction(operation);
    else await operation(this.executor);
    return { ...next };
  }

  async revoke(sessionReference: string): Promise<boolean> {
    const result = await this.activeExecutor().query(
      `UPDATE ${this.table} SET deleted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE namespace = $1 AND model = $2 AND id = $3 AND deleted_at IS NULL`,
      [this.namespace, "ClientSession", this.id(sessionReference)],
    );
    return affected(result) > 0;
  }

  async ready(): Promise<boolean> {
    try {
      await this.executor.query(`SELECT namespace, model, id, payload, expires_at FROM ${this.table} LIMIT 0`, []);
      return true;
    } catch {
      return false;
    }
  }

  private activeExecutor(): TenantSqlExecutor {
    return getTenantTransactionExecutor(this.executor) ?? this.executor;
  }

  private async write(record: OpaqueClientSessionRecord, executor: TenantSqlExecutor = this.activeExecutor()): Promise<void> {
    const payload = this.encode(record);
    await executor.query(
      `INSERT INTO ${this.table} (namespace, model, id, payload, expires_at, account_id, client_id) VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7) ON CONFLICT (namespace, model, id) DO UPDATE SET payload = EXCLUDED.payload, expires_at = EXCLUDED.expires_at, account_id = EXCLUDED.account_id, client_id = EXCLUDED.client_id, deleted_at = NULL, updated_at = CURRENT_TIMESTAMP`,
      [this.namespace, "ClientSession", this.id(record.sessionReference), JSON.stringify(payload), new Date(record.expiresAt), record.userId, `${record.applicationId}:${record.platformId}`],
    );
  }

  private encode(record: OpaqueClientSessionRecord): Record<string, unknown> {
    return {
      version: 1,
      sessionReference: encryptSecret(this.encryptionKey, record.sessionReference),
      userId: record.userId,
      tenantId: record.tenantId,
      applicationId: record.applicationId,
      platformId: record.platformId,
      identityKey: record.identityKey,
      client: record.client,
      hostSessionToken: encryptSecret(this.encryptionKey, record.hostSessionToken),
      createdAt: record.createdAt,
      expiresAt: record.expiresAt,
      updatedAt: record.updatedAt,
    };
  }

  private decode(row: Record<string, unknown>): OpaqueClientSessionRecord | undefined {
    const payload = isRecord(row.payload) ? row.payload : parseRecord(row.payload);
    if (!isRecord(payload) || typeof payload.sessionReference !== "string" || typeof payload.userId !== "string" || typeof payload.applicationId !== "string" || typeof payload.platformId !== "string" || (payload.client !== "mp_weixin" && payload.client !== "native") || typeof payload.hostSessionToken !== "string") return undefined;
    const expiresAt = numberValue(payload.expiresAt ?? row.expires_at);
    const createdAt = numberValue(payload.createdAt);
    if (expiresAt === undefined || createdAt === undefined) return undefined;
    try {
      const sessionReference = decryptSecret(this.encryptionKey, payload.sessionReference);
      if (!/^[A-Za-z0-9_-]{16,512}$/u.test(sessionReference)) return undefined;
      return {
        sessionReference,
        userId: payload.userId,
        ...(typeof payload.tenantId === "string" ? { tenantId: payload.tenantId } : {}),
        applicationId: payload.applicationId,
        platformId: payload.platformId,
        ...(typeof payload.identityKey === "string" ? { identityKey: payload.identityKey } : {}),
        client: payload.client as OpaqueClientSessionRecord["client"],
        hostSessionToken: decryptSecret(this.encryptionKey, payload.hostSessionToken),
        createdAt,
        expiresAt,
        updatedAt: numberValue(payload.updatedAt) ?? createdAt,
      };
    } catch {
      return undefined;
    }
  }

  private id(reference: string): string {
    return createHash("sha256").update(reference).digest("hex");
  }

}

export const applicationManagementMigration = {
  dryRun: () => getApplicationManagementMigrations({
    tenantId: applicationTenantConfig.tenantId,
    mode: applicationTenantConfig.mode,
    requireTransactions: applicationTenantConfig.requireTransactions,
  }).map((migration) => migration.sql).join("\n\n"),
  run: () => applyVersionedApplicationManagementMigrations(applicationSqlExecutor, {
    tenantId: applicationTenantConfig.tenantId,
    mode: applicationTenantConfig.mode,
    requireTransactions: applicationTenantConfig.requireTransactions,
  }),
};

export const oidcMigration = {
  dryRun: () => getPostgresOidcMigrationSql({ namespace: "getbrick-example" }),
  run: () => migratePostgresOidcSchema(pool, { namespace: "getbrick-example" }),
};

export const openPlatformMigrationOptions = {
  mode: applicationTenantConfig.mode,
  tenantId: applicationTenantConfig.tenantId,
  requireTransaction: applicationTenantConfig.requireTransactions,
};

export const commerceMigrationOptions = {
  mode: applicationTenantConfig.mode,
  tenantId: applicationTenantConfig.tenantId,
  requireTransaction: applicationTenantConfig.requireTransactions,
  requireTransactions: applicationTenantConfig.requireTransactions,
};

export const openPlatformMigration = {
  dryRun: () => OpenPlatformPersistence.getOpenPlatformMigrations(openPlatformMigrationOptions)
    .map((migration) => migration.sql)
    .join("\n\n"),
  run: () => OpenPlatformPersistence.applyVersionedOpenPlatformMigration(
    applicationSqlExecutor,
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
      applicationSqlExecutor,
      migrations,
      {
        tableName: OpenPlatformCommercePersistence.OPEN_COMMERCE_MIGRATION_TABLE,
        lockTableName: OpenPlatformCommercePersistence.OPEN_COMMERCE_MIGRATION_LOCK_TABLE,
        lockKey: commerceMigrationLock.key,
        lockNamespace: commerceMigrationLock.namespace,
        requireTransaction: applicationTenantConfig.requireTransactions,
      },
    ).run(migrations);
  },
};

export const complianceMigrationLock = {
  key: "getbrick-open-compliance-schema",
  namespace: "open-platform-compliance",
};

export const complianceMigrationOptions = {
  mode: applicationTenantConfig.mode,
  tenantId: applicationTenantConfig.tenantId,
  requireTransaction: applicationTenantConfig.requireTransactions,
  requireTransactions: applicationTenantConfig.requireTransactions,
  lockKey: complianceMigrationLock.key,
  lockNamespace: complianceMigrationLock.namespace,
};

export const complianceMigrationDefinition = () =>
  OpenPlatformCompliancePersistence.getOpenComplianceMigrationDefinition(complianceMigrationOptions);

export const complianceMigration = {
  dryRun: () => complianceMigrationDefinition().sql,
  run: () => OpenPlatformCompliancePersistence.applyVersionedOpenComplianceMigration(
    toComplianceExecutor(applicationSqlExecutor),
    complianceMigrationOptions,
  ),
};

interface ComplianceMigrationQuery {
  query: (text: string, values?: unknown[]) => Promise<unknown>;
}

interface ComplianceMigrationExecutor extends ComplianceMigrationQuery {
  transaction: <T>(callback: (executor: ComplianceMigrationQuery) => Promise<T>) => Promise<T>;
}

function toComplianceExecutor(executor: TenantSqlExecutor): ComplianceMigrationExecutor {
  return {
    query: (text, values) => Promise.resolve(executor.query(text, values)),
    transaction: async (callback) =>
      executor.transaction!(async (transactionExecutor) =>
        callback({
          query: (text, values) => Promise.resolve(transactionExecutor.query(text, values)),
        }),
      ),
  };
}

export const migrationIntegration = {
  dryRun: async () => [
    await oidcMigration.dryRun(),
    await applicationManagementMigration.dryRun(),
    await openPlatformMigration.dryRun(),
    await commerceMigration.dryRun(),
    await complianceMigration.dryRun(),
  ].join("\n\n"),
  run: async () => {
    await oidcMigration.run();
    await applicationManagementMigration.run();
    await openPlatformMigration.run();
    await commerceMigration.run();
    await complianceMigration.run();
  },
};

 export const secretBindingRepository = new SqlSecretBindingRepository(applicationSqlExecutor, {
   tenant: applicationTenantConfig,
 });

 export const applicationRepository = new SqlApplicationRepository(applicationSqlExecutor, {
   tenant: applicationTenantConfig,
   secretBindings: secretBindingRepository,
 });

 export const tenantRepository = new SqlTenantRepository(applicationSqlExecutor, {
   tenant: applicationTenantConfig,
 });

 export const identityRepository = new SqlIdentityRepository(applicationSqlExecutor, {
   tenant: applicationTenantConfig,
 });

export const applicationOidcClientStore = new ApplicationOidcClientStore(
  applicationRepository,
   {
     secretBindings: secretBindingRepository,
     resolveSecret: async (secretRef) => {

      const value = secretRef === "env:OIDC_CLIENT_SECRET"
        ? process.env.OIDC_CLIENT_SECRET
        : undefined;
      if (!value) throw new Error("application secret is not configured");
      return value;
    },
  },
);

function rows(value: unknown): Record<string, unknown>[] {
  if (Array.isArray(value)) return value.filter(isRecord);
  return isRecord(value) && Array.isArray(value.rows) ? value.rows.filter(isRecord) : [];
}

function affected(value: unknown): number {
  if (isRecord(value) && typeof value.rowCount === "number") return value.rowCount;
  return rows(value).length;
}

function parseRecord(value: unknown): unknown {
  if (typeof value !== "string") return undefined;
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return undefined;
  }
}

function numberValue(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isSafeInteger(value)) return value;
  if (typeof value === "bigint" && value >= 0n && Number.isSafeInteger(Number(value))) return Number(value);
  if (value instanceof Date) {
    const time = value.getTime();
    return Number.isSafeInteger(time) ? time : undefined;
  }
  if (typeof value === "string") {
    const time = new Date(value).getTime();
    return Number.isSafeInteger(time) ? time : undefined;
  }
  return undefined;
}

function encryptSecret(key: Buffer, value: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return [iv, cipher.getAuthTag(), encrypted].map((item) => item.toString("base64url")).join(".");
}

function decryptSecret(key: Buffer, value: string): string {
  const parts = value.split(".");
  if (parts.length !== 3) throw new Error("Client session payload is invalid");
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(parts[0]!, "base64url"));
  decipher.setAuthTag(Buffer.from(parts[1]!, "base64url"));
  return Buffer.concat([decipher.update(Buffer.from(parts[2]!, "base64url")), decipher.final()]).toString("utf8");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const userTable = buildTableMap(idaas.tables).user;
const quotedUserTable = `"${userTable.replace(/"/g, '""')}"`;

export async function findOidcUser(id: string) {
  const result = await pool.query(
    `SELECT id, name, email, "emailVerified", image, banned, "banExpires" FROM ${quotedUserTable} WHERE id = $1`,
    [id],
  );
  const user = result.rows[0] as
    | {
        id: string;
        name?: string | null;
        email?: string | null;
        emailVerified?: boolean | null;
        image?: string | null;
        banned?: boolean | null;
        banExpires?: Date | string | null;
      }
    | undefined;
  if (!user) return null;
  if (isActiveBan(user.banned, user.banExpires)) {
    await oidcAdapter.revokeByAccountId(user.id);
    return null;
  }
  return {
    id: user.id,
    name: user.name ?? undefined,
    email: user.email ?? undefined,
    emailVerified: user.emailVerified ?? false,
    image: user.image ?? undefined,
  };
}

function isActiveBan(banned: boolean | null | undefined, banExpires: Date | string | null | undefined): boolean {
  if (banned !== true) return false;
  if (banExpires === null || banExpires === undefined) return true;
  const expiresAt = banExpires instanceof Date ? banExpires.getTime() : new Date(banExpires).getTime();
  return !Number.isFinite(expiresAt) || expiresAt > Date.now();
}

const demoClientSecret = process.env.OIDC_CLIENT_SECRET;
if (!demoClientSecret) {
  throw new Error("[getbrick-example] OIDC_CLIENT_SECRET is required");
}

export const oidcClientSecrets = {
  "getbrick-demo-client": demoClientSecret,
};
