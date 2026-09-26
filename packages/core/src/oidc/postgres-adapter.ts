import { randomUUID } from "node:crypto";
import {
  errors,
  type Adapter,
  type AdapterPayload,
} from "oidc-provider";
import type {
  OidcArtifactReadMode,
  OidcArtifactReadOptions,
  OidcNamespaceBindingInput,
  OidcNamespaceBindingPort,
} from "./contracts.js";

const DEFAULT_SCHEMA = "public";
const DEFAULT_TABLE = "gb_idaas_oidc_artifact";
const IDENTIFIER_PATTERN = /^[a-z_][a-z0-9_]*$/u;
const DEFAULT_RETENTION_SECONDS = 86_400;
const ACTIVE_ARTIFACT_PREDICATE =
  "deleted_at IS NULL AND consumed_at IS NULL AND (expires_at IS NULL OR expires_at > clock_timestamp())";
const REPLAY_ARTIFACT_PREDICATE =
  "deleted_at IS NULL AND ((expires_at IS NULL OR expires_at > clock_timestamp()) OR consumed_at IS NOT NULL)";
const REPLAY_READ_MODELS = new Set([
  "AuthorizationCode",
  "RefreshToken",
  "DeviceCode",
  "BackchannelAuthenticationRequest",
  "PushedAuthorizationRequest",
]);
const READINESS_CANARY_MODEL = "__getbrick_oidc_readiness_canary__";

export interface OidcSqlResult<Row = Record<string, unknown>> {
  rows: Row[];
  rowCount: number | null;
}

export interface OidcSqlClient {
  query<Row = Record<string, unknown>>(
    text: string,
    values?: unknown[],
  ): Promise<OidcSqlResult<Row>>;
}

export interface PostgresOidcAdapterInstance extends Adapter {
  find(id: string, options?: OidcArtifactReadOptions): Promise<AdapterPayload | undefined>;
  findActive(id: string): Promise<AdapterPayload | undefined>;
  findForReplay(id: string): Promise<AdapterPayload | undefined>;
  findByUid(uid: string, options?: OidcArtifactReadOptions): Promise<AdapterPayload | undefined>;
  findByUserCode(userCode: string, options?: OidcArtifactReadOptions): Promise<AdapterPayload | undefined>;
}

export interface PostgresOidcAdapterOptions {
  namespace?: string;
  namespaceBinding?: OidcNamespaceBindingPort;
  schema?: string;
  tableName?: string;
}

export type PostgresOidcAdapterFactory = ((model: string) => PostgresOidcAdapterInstance) & {
  readonly namespace: string;
  readonly namespaceBinding?: OidcNamespaceBindingPort;
  readonly schema: string;
  readonly tableName: string;
  ready(): Promise<boolean>;
  cleanup(retentionSeconds?: number): Promise<number>;
  bindNamespace(input: OidcNamespaceBindingInput): Promise<string>;
  revokeByGrantId(grantId: string): Promise<number>;
  revokeByAccountId(accountId: string): Promise<number>;
};

export function createPostgresOidcAdapterFactory(
  sql: OidcSqlClient,
  options: PostgresOidcAdapterOptions = {},
): PostgresOidcAdapterFactory {
  const normalized = normalizeOptions(options);
  const table = qualifiedTable(normalized.schema, normalized.tableName);
  const factory = ((model: string) =>
    new PostgresOidcAdapter(sql, normalized.namespace, model, table)) as unknown as PostgresOidcAdapterFactory;
  Object.defineProperties(factory, {
    namespace: { enumerable: true, value: normalized.namespace },
    namespaceBinding: { enumerable: true, value: normalized.namespaceBinding },
    schema: { enumerable: true, value: normalized.schema },
    tableName: { enumerable: true, value: normalized.tableName },
    ready: {
      enumerable: true,
      value: async () => {
        await checkPostgresOidcAdapterReadiness(
          sql,
          normalized.namespace,
          normalized.schema,
          normalized.tableName,
          table,
        );
        return true;
      },
    },
    cleanup: {
      enumerable: true,
      value: (retentionSeconds = DEFAULT_RETENTION_SECONDS) =>
        cleanupExpiredArtifacts(sql, normalized.namespace, table, retentionSeconds),
    },
    bindNamespace: {
      enumerable: true,
      value: (input: OidcNamespaceBindingInput) => bindNamespace(normalized, input),
    },
    revokeByGrantId: {
      enumerable: true,
      value: (grantId: string) =>
        revokeArtifactsForGrant(sql, normalized.namespace, table, grantId),
    },
    revokeByAccountId: {
      enumerable: true,
      value: (accountId: string) =>
        revokeArtifactsForAccount(sql, normalized.namespace, table, accountId),
    },
  });
  return factory;
}

export async function migratePostgresOidcSchema(
  sql: OidcSqlClient,
  options: PostgresOidcAdapterOptions = {},
): Promise<void> {
  const normalized = normalizeOptions(options);
  await sql.query(getPostgresOidcMigrationSql(normalized));
}

export function getPostgresOidcMigrationSql(
  options: PostgresOidcAdapterOptions = {},
): string {
  const normalized = normalizeOptions(options);
  const table = qualifiedTable(normalized.schema, normalized.tableName);
  const tableName = normalized.tableName;
  const migration = `
CREATE TABLE IF NOT EXISTS ${table} (
  namespace text NOT NULL CHECK (char_length(namespace) BETWEEN 1 AND 200),
  model text NOT NULL CHECK (char_length(model) BETWEEN 1 AND 200),
  id text NOT NULL CHECK (char_length(id) BETWEEN 1 AND 512),
  payload jsonb NOT NULL,
  expires_at timestamptz NULL,
  grant_id text NULL,
  session_uid text NULL,
  user_code text NULL,
  client_id text NULL,
  account_id text NULL,
  consumed_at timestamptz NULL,
  deleted_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (namespace, model, id)
);
ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS namespace text;
ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS model text;
ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS id text;
ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS payload jsonb;
ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS expires_at timestamptz;
ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS grant_id text;
ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS session_uid text;
ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS user_code text;
ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS client_id text;
ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS account_id text;
ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS consumed_at timestamptz;
ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS deleted_at timestamptz;
ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS created_at timestamptz DEFAULT clock_timestamp();
ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS updated_at timestamptz DEFAULT clock_timestamp();
CREATE INDEX IF NOT EXISTS ${quoteIdentifier(`${tableName}_expires_at_idx`)} ON ${table} (expires_at);
CREATE INDEX IF NOT EXISTS ${quoteIdentifier(`${tableName}_grant_id_idx`)} ON ${table} (namespace, model, grant_id) WHERE grant_id IS NOT NULL AND deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ${quoteIdentifier(`${tableName}_session_uid_idx`)} ON ${table} (namespace, session_uid) WHERE model = 'Session' AND session_uid IS NOT NULL AND deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ${quoteIdentifier(`${tableName}_user_code_idx`)} ON ${table} (namespace, user_code) WHERE model = 'DeviceCode' AND user_code IS NOT NULL AND deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS ${quoteIdentifier(`${tableName}_client_id_idx`)} ON ${table} (namespace, client_id) WHERE client_id IS NOT NULL AND deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS ${quoteIdentifier(`${tableName}_account_id_idx`)} ON ${table} (namespace, account_id) WHERE account_id IS NOT NULL AND deleted_at IS NULL;
`;
  return migration.trim();
}

export async function assertPostgresOidcAdapterReady(
  factory: PostgresOidcAdapterFactory,
): Promise<void> {
  if (typeof factory.ready !== "function") {
    throw new Error("[getbrick-idaas] OIDC adapter does not expose a readiness check");
  }
  await factory.ready();
}

interface StoredArtifactRow {
  payload: AdapterPayload;
  consumed_at?: unknown;
  grant_id?: unknown;
}

interface OidcReadinessRow extends Record<string, unknown> {
  columns_ok?: unknown;
  primary_key_ok?: unknown;
  session_uid_unique_ok?: unknown;
  user_code_unique_ok?: unknown;
  can_select?: unknown;
  can_insert?: unknown;
  can_update?: unknown;
  can_delete?: unknown;
  can_schema_usage?: unknown;
}

interface OidcCanaryConnection extends OidcSqlClient {
  release?: () => void;
}

interface OidcCanaryClient extends OidcSqlClient {
  connect?: () => Promise<OidcCanaryConnection>;
  transaction?: <T>(callback: (executor: OidcSqlClient) => Promise<T>) => Promise<T>;
}

async function checkPostgresOidcAdapterReadiness(
  sql: OidcSqlClient,
  namespace: string,
  schema: string,
  tableName: string,
  table: string,
): Promise<void> {
  let result: OidcSqlResult<OidcReadinessRow>;
  try {
    result = await sql.query<OidcReadinessRow>(
      `WITH required_columns(column_name) AS (
         VALUES ('namespace'), ('model'), ('id'), ('payload'), ('expires_at'),
                ('grant_id'), ('session_uid'), ('user_code'), ('client_id'), ('account_id'),
                ('consumed_at'), ('deleted_at'), ('created_at'), ('updated_at')
       ), table_target AS (
         SELECT $4::regclass::oid AS oid
       ), table_info AS (
         SELECT c.oid
         FROM pg_class c
         JOIN pg_namespace n ON n.oid = c.relnamespace
         JOIN table_target target ON target.oid = c.oid
         WHERE n.nspname = $2 AND c.relname = $3 AND c.relkind IN ('r', 'p')
       ), indexes AS (
         SELECT i.indexrelid, i.indrelid, i.indisprimary, i.indisunique,
                i.indisvalid, i.indisready, i.indpred, i.indkey
         FROM pg_index i
         JOIN table_info t ON t.oid = i.indrelid
       ), index_columns AS (
         SELECT i.indexrelid, i.indrelid, i.indisprimary, i.indisunique,
                i.indisvalid, i.indisready, i.indpred,
                array_agg(a.attname::text ORDER BY keys.ordinality) AS column_names
         FROM indexes i
         CROSS JOIN LATERAL unnest(i.indkey::int2[]) WITH ORDINALITY AS keys(attnum, ordinality)
         JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = keys.attnum
         GROUP BY i.indexrelid, i.indrelid, i.indisprimary, i.indisunique,
                  i.indisvalid, i.indisready, i.indpred
       ), catalog AS (
         SELECT
           COALESCE((
             SELECT bool_and(EXISTS (
               SELECT 1
               FROM information_schema.columns c
               WHERE c.table_schema = $2 AND c.table_name = $3
                 AND c.column_name = r.column_name
             ))
             FROM required_columns r
           ), false) AS columns_ok,
           EXISTS (
             SELECT 1 FROM index_columns
             WHERE indisprimary AND indisvalid AND indisready
               AND column_names = ARRAY['namespace', 'model', 'id']
           ) AS primary_key_ok,
           EXISTS (
             SELECT 1 FROM index_columns
             WHERE indisunique AND indisvalid AND indisready
               AND column_names = ARRAY['namespace', 'session_uid']
               AND indpred IS NOT NULL
               AND pg_get_expr(indpred, indrelid) ILIKE '%deleted_at%'
           ) AS session_uid_unique_ok,
           EXISTS (
             SELECT 1 FROM index_columns
             WHERE indisunique AND indisvalid AND indisready
               AND column_names = ARRAY['namespace', 'user_code']
               AND indpred IS NOT NULL
               AND pg_get_expr(indpred, indrelid) ILIKE '%deleted_at%'
           ) AS user_code_unique_ok,
           has_table_privilege(current_user, $4, 'SELECT') AS can_select,
           has_table_privilege(current_user, $4, 'INSERT') AS can_insert,
           has_table_privilege(current_user, $4, 'UPDATE') AS can_update,
           has_table_privilege(current_user, $4, 'DELETE') AS can_delete,
           has_schema_privilege(current_user, $2, 'USAGE') AS can_schema_usage
         FROM table_info
       )
       SELECT artifact.namespace, artifact.model, artifact.id, artifact.payload,
              artifact.expires_at, artifact.grant_id, artifact.session_uid,
              artifact.user_code, artifact.client_id, artifact.account_id,
              artifact.consumed_at, artifact.deleted_at, artifact.created_at,
              artifact.updated_at,
              catalog.columns_ok, catalog.primary_key_ok,
              catalog.session_uid_unique_ok, catalog.user_code_unique_ok,
              catalog.can_select, catalog.can_insert, catalog.can_update,
              catalog.can_delete, catalog.can_schema_usage
       FROM catalog
       LEFT JOIN LATERAL (
         SELECT namespace, model, id, payload, expires_at, grant_id, session_uid,
                user_code, client_id, account_id, consumed_at, deleted_at,
                created_at, updated_at
         FROM ${table}
         WHERE namespace = $1
         LIMIT 1
       ) artifact ON TRUE`,
      [namespace, schema, tableName, table],
    );
  } catch {
    throw new Error("[getbrick-idaas] OIDC adapter readiness catalog check failed");
  }
  if (!Array.isArray(result.rows) || result.rows.length !== 1 || result.rows[0] === undefined) {
    throw new Error("[getbrick-idaas] OIDC adapter readiness catalog returned no rows");
  }
  assertReadinessChecks(result.rows[0]);
  try {
    await verifyReadinessCanary(sql, namespace, table);
  } catch {
    throw new Error("[getbrick-idaas] OIDC adapter readiness write check failed");
  }
}

function assertReadinessChecks(row: OidcReadinessRow): void {
  const checks: Array<[string, unknown]> = [
    ["columns_ok", row.columns_ok],
    ["primary_key_ok", row.primary_key_ok],
    ["session_uid_unique_ok", row.session_uid_unique_ok],
    ["user_code_unique_ok", row.user_code_unique_ok],
    ["can_select", row.can_select],
    ["can_insert", row.can_insert],
    ["can_update", row.can_update],
    ["can_delete", row.can_delete],
    ["can_schema_usage", row.can_schema_usage],
  ];
  for (const [name, value] of checks) {
    if (value !== true && value !== 1 && value !== "true") {
      throw new Error(`[getbrick-idaas] OIDC adapter readiness check failed: ${name}`);
    }
  }
}

async function verifyReadinessCanary(
  sql: OidcSqlClient,
  namespace: string,
  table: string,
): Promise<void> {
  const id = `oidc-readiness-${randomUUID()}`;
  const client = sql as OidcCanaryClient;
  try {
    if (typeof client.transaction === "function") {
      await client.transaction(async (executor) => {
        await runReadinessCanaryQueries(executor, namespace, table, id);
      });
      return;
    }
    if (typeof client.connect === "function") {
      const connection = await client.connect();
      let began = false;
      try {
        await connection.query("BEGIN");
        began = true;
        await runReadinessCanaryQueries(connection, namespace, table, id);
        await connection.query("ROLLBACK");
      } catch (error) {
        if (began) {
          try {
            await connection.query("ROLLBACK");
          } catch {
            await Promise.resolve();
          }
        }
        throw error;
      } finally {
        connection.release?.();
      }
      return;
    }
    await runReadinessCanaryQueries(sql, namespace, table, id);
  } catch (error) {
    await cleanupReadinessCanary(sql, namespace, table, id);
    throw error;
  }
}

async function runReadinessCanaryQueries(
  sql: OidcSqlClient,
  namespace: string,
  table: string,
  id: string,
): Promise<void> {
  const inserted = await sql.query<{ id: string }>(
    `INSERT INTO ${table} (namespace, model, id, payload, expires_at)
     VALUES ($1, $2, $3, $4::jsonb, clock_timestamp() + interval '1 hour')
     RETURNING id`,
    [namespace, READINESS_CANARY_MODEL, id, "{}"],
  );
  assertCanaryRow(inserted, "insert");
  const updated = await sql.query<{ id: string }>(
    `UPDATE ${table}
     SET payload = $4::jsonb, expires_at = clock_timestamp() + interval '1 hour', updated_at = clock_timestamp()
     WHERE namespace = $1 AND model = $2 AND id = $3
       AND deleted_at IS NULL AND consumed_at IS NULL
     RETURNING id`,
    [namespace, READINESS_CANARY_MODEL, id, "{}"],
  );
  assertCanaryRow(updated, "update");
  const deleted = await sql.query<{ id: string }>(
    `DELETE FROM ${table}
     WHERE namespace = $1 AND model = $2 AND id = $3
     RETURNING id`,
    [namespace, READINESS_CANARY_MODEL, id],
  );
  assertCanaryRow(deleted, "delete");
}

function assertCanaryRow(result: OidcSqlResult<{ id: string }>, operation: string): void {
  if (result.rows.length !== 1 || result.rows[0] === undefined || readRowCount(result) !== 1) {
    throw new Error(`[getbrick-idaas] OIDC adapter readiness canary ${operation} failed`);
  }
}

async function cleanupReadinessCanary(
  sql: OidcSqlClient,
  namespace: string,
  table: string,
  id: string,
): Promise<void> {
  try {
    await sql.query(
      `DELETE FROM ${table}
       WHERE namespace = $1 AND model = $2 AND id = $3`,
      [namespace, READINESS_CANARY_MODEL, id],
    );
  } catch {
    await Promise.resolve();
  }
}

class PostgresOidcAdapter implements PostgresOidcAdapterInstance {
  constructor(
    private readonly sql: OidcSqlClient,
    private readonly namespace: string,
    private readonly model: string,
    private readonly table: string,
  ) {}

  async upsert(
    id: string,
    payload: AdapterPayload,
    expiresIn?: number,
  ): Promise<void> {
    const expiresAt = resolveExpiration(payload, expiresIn);
    const result = await this.sql.query<{ id: string }>(
      `INSERT INTO ${this.table} AS current (
        namespace, model, id, payload, expires_at, grant_id, session_uid,
        user_code, client_id, account_id
       ) VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8, $9, $10)
       ON CONFLICT (namespace, model, id) DO UPDATE SET

         payload = EXCLUDED.payload,
         expires_at = EXCLUDED.expires_at,
         grant_id = EXCLUDED.grant_id,
         session_uid = EXCLUDED.session_uid,
         user_code = EXCLUDED.user_code,
         client_id = EXCLUDED.client_id,
         account_id = EXCLUDED.account_id,
         updated_at = clock_timestamp()
       WHERE current.deleted_at IS NULL AND current.consumed_at IS NULL
       RETURNING current.id`,
      [
        this.namespace,
        this.model,
        id,
        JSON.stringify(payload),
        expiresAt,
        readString(payload.grantId),
        readSessionUid(payload),
        readString(payload.userCode),
        readClientId(payload),
        readString(payload.accountId),
      ],
    );
    if (readRowCount(result) === 0) {
      throw new Error("[getbrick-idaas] cannot update a consumed or deleted OIDC artifact");
    }
  }

  async find(id: string, options?: OidcArtifactReadOptions): Promise<AdapterPayload | undefined> {
    const mode = resolveReadMode(options, REPLAY_READ_MODELS.has(this.model) ? "replay" : "active");
    return mode === "replay" ? this.findForReplay(id) : this.findActive(id);
  }

  async findActive(id: string): Promise<AdapterPayload | undefined> {
    return this.findStoredArtifact("id", this.model, id, "active");
  }

  async findForReplay(id: string): Promise<AdapterPayload | undefined> {
    return this.findStoredArtifact("id", this.model, id, "replay");
  }

  async findByUid(uid: string, options?: OidcArtifactReadOptions): Promise<AdapterPayload | undefined> {
    const mode = resolveReadMode(options, "active");
    return this.findStoredArtifact("session_uid", "Session", uid, mode, "updated_at DESC");
  }

  async findByUserCode(userCode: string, options?: OidcArtifactReadOptions): Promise<AdapterPayload | undefined> {
    const mode = resolveReadMode(options, "replay");
    return this.findStoredArtifact("user_code", "DeviceCode", userCode, mode);
  }

  private async findStoredArtifact(
    column: "id" | "session_uid" | "user_code",
    model: string,
    value: string,
    mode: OidcArtifactReadMode,
    orderBy?: string,
  ): Promise<AdapterPayload | undefined> {
    const predicate = mode === "replay" ? REPLAY_ARTIFACT_PREDICATE : ACTIVE_ARTIFACT_PREDICATE;
    const result = await this.sql.query<StoredArtifactRow>(
      `SELECT payload${mode === "replay" ? ", consumed_at, grant_id" : ""} FROM ${this.table}
       WHERE namespace = $1 AND model = $2 AND ${column} = $3
         AND ${predicate}
       ${orderBy === undefined ? "" : `ORDER BY ${orderBy}`}
       LIMIT 1`,
      [this.namespace, model, value],
    );
    const row = result.rows[0];
    if (row === undefined) return undefined;
    return mode === "replay" ? projectReplayPayload(row) : projectActivePayload(row.payload);
  }

  async consume(id: string): Promise<void> {
    const result = await this.sql.query<{ id: string }>(
      `UPDATE ${this.table}
       SET payload = jsonb_set(
             COALESCE(payload, '{}'::jsonb),
             '{consumed}',
             to_jsonb(EXTRACT(EPOCH FROM clock_timestamp())::bigint),
             true
           ),
           consumed_at = clock_timestamp(),
           updated_at = clock_timestamp()
       WHERE namespace = $1 AND model = $2 AND id = $3
         AND (expires_at IS NULL OR expires_at > clock_timestamp())
         AND deleted_at IS NULL AND consumed_at IS NULL
       RETURNING id`,
      [this.namespace, this.model, id],
    );
    if (readRowCount(result) !== 1) {
      throw new errors.InvalidGrant("OIDC artifact is already consumed or unavailable");
    }
  }

  async destroy(id: string): Promise<void> {
    await revokeArtifactById(this.sql, this.namespace, this.model, this.table, id);
  }

  async revokeByGrantId(grantId: string): Promise<void> {
    await revokeArtifactsForGrant(this.sql, this.namespace, this.table, grantId, this.model);
  }
}

function resolveReadMode(
  options: OidcArtifactReadOptions | undefined,
  fallback: OidcArtifactReadMode,
): OidcArtifactReadMode {
  const mode = options?.mode;
  if (mode === undefined) return fallback;
  if (mode !== "active" && mode !== "replay") {
    throw new Error("[getbrick-idaas] OIDC artifact read mode is invalid");
  }
  return mode;
}

function projectActivePayload(payload: AdapterPayload): AdapterPayload | undefined {
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) return payload;
  if (payload.consumed !== undefined && payload.consumed !== null && payload.consumed !== false) return undefined;
  return payload;
}

function projectReplayPayload(row: StoredArtifactRow): AdapterPayload {
  if (row.consumed_at === null || row.consumed_at === undefined) return row.payload;
  if (typeof row.payload !== "object" || row.payload === null || Array.isArray(row.payload)) {
    return row.payload;
  }
  const grantId = typeof row.grant_id === "string" && row.grant_id.length > 0
    ? row.grant_id
    : undefined;
  return {
    ...row.payload,
    ...(grantId !== undefined && row.payload.grantId === undefined ? { grantId } : {}),
    consumed: true,
  };
}

async function revokeArtifactById(
  sql: OidcSqlClient,
  namespace: string,
  model: string,
  table: string,
  id: string,
): Promise<number> {
  assertArtifactId(id, "OIDC artifact ID");
  const result = await sql.query<{ id: string }>(
    `UPDATE ${table}
     SET deleted_at = clock_timestamp(), updated_at = clock_timestamp()
     WHERE namespace = $1 AND model = $2 AND id = $3
       AND ${ACTIVE_ARTIFACT_PREDICATE}
     RETURNING id`,
    [namespace, model, id],
  );
  return readRowCount(result);
}

async function revokeArtifactsForGrant(
  sql: OidcSqlClient,
  namespace: string,
  table: string,
  grantId: string,
  model?: string,
): Promise<number> {
  assertArtifactId(grantId, "OIDC grant ID");
  const modelClause = model === undefined ? "" : "AND model = $2 ";
  const grantParameter = model === undefined ? 2 : 3;
  const result = await sql.query<{ id: string }>(
    `UPDATE ${table}
     SET deleted_at = clock_timestamp(), updated_at = clock_timestamp()
     WHERE namespace = $1 ${modelClause}AND grant_id = $${grantParameter}
       AND ${ACTIVE_ARTIFACT_PREDICATE}
     RETURNING id`,
    model === undefined ? [namespace, grantId] : [namespace, model, grantId],
  );
  return readRowCount(result);
}

async function revokeArtifactsForAccount(
  sql: OidcSqlClient,
  namespace: string,
  table: string,
  accountId: string,
): Promise<number> {
  assertArtifactId(accountId, "OIDC account ID");
  const result = await sql.query<{ id: string }>(
    `UPDATE ${table}
     SET deleted_at = clock_timestamp(), updated_at = clock_timestamp()
     WHERE namespace = $1 AND account_id = $2
       AND ${ACTIVE_ARTIFACT_PREDICATE}
     RETURNING id`,
    [namespace, accountId],
  );
  return readRowCount(result);
}

async function cleanupExpiredArtifacts(
  sql: OidcSqlClient,
  namespace: string,
  table: string,
  retentionSeconds: number,
): Promise<number> {
  if (!Number.isSafeInteger(retentionSeconds) || retentionSeconds < 0) {
    throw new Error("[getbrick-idaas] OIDC cleanup retention must be a non-negative integer");
  }
  const result = await sql.query<{ id: string }>(
    `DELETE FROM ${table}
     WHERE namespace = $1 AND expires_at IS NOT NULL
       AND expires_at < clock_timestamp() - ($2 * interval '1 second')
     RETURNING id`,
    [namespace, retentionSeconds],
  );
  return readRowCount(result);
}

function bindNamespace(
  options: NormalizedPostgresOidcAdapterOptions,
  input: OidcNamespaceBindingInput,
): Promise<string> {
  if (
    input === null ||
    typeof input !== "object" ||
    typeof input.tenantId !== "string" ||
    input.tenantId.length === 0 ||
    input.tenantId.length > 200 ||
    /[\u0000-\u001F\u007F]/u.test(input.tenantId)
  ) {
    return Promise.reject(new Error("[getbrick-idaas] OIDC namespace binding tenant ID is invalid"));
  }
  if (input.namespace !== undefined) normalizeNamespace(input.namespace);
  const resolve = async (): Promise<string> => {
    if (options.namespaceBinding === undefined) return options.namespace;
    const namespace = await options.namespaceBinding.resolveNamespace({
      tenantId: input.tenantId,
      ...(input.namespace === undefined ? {} : { namespace: input.namespace }),
    });
    return normalizeNamespace(namespace);
  };
  return resolve();
}

function readRowCount(result: OidcSqlResult<unknown>): number {
  const rowCount = result.rowCount as unknown;
  if (typeof rowCount === "number" && Number.isSafeInteger(rowCount) && rowCount >= 0) {
    return rowCount;
  }
  if (typeof rowCount === "bigint" && rowCount >= 0n && rowCount <= BigInt(Number.MAX_SAFE_INTEGER)) {
    return Number(rowCount);
  }
  return Array.isArray(result.rows) ? result.rows.length : 0;
}

function assertArtifactId(value: string, label: string): void {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 512 ||
    /[\u0000-\u001F\u007F]/u.test(value)
  ) {
    throw new Error(`[getbrick-idaas] ${label} is invalid`);
  }
}

interface NormalizedPostgresOidcAdapterOptions {
  namespace: string;
  namespaceBinding?: OidcNamespaceBindingPort;
  schema: string;
  tableName: string;
}

function normalizeOptions(options: PostgresOidcAdapterOptions): NormalizedPostgresOidcAdapterOptions {
  const namespace = options.namespace ?? "default";
  const schema = options.schema ?? DEFAULT_SCHEMA;
  const tableName = options.tableName ?? DEFAULT_TABLE;
  normalizeNamespace(namespace);
  if (
    options.namespaceBinding !== undefined &&
    (options.namespaceBinding === null || typeof options.namespaceBinding.resolveNamespace !== "function")
  ) {
    throw new Error("[getbrick-idaas] OIDC adapter namespace binding port is invalid");
  }
  assertIdentifier(schema, "schema");
  assertIdentifier(tableName, "tableName");
  return { namespace, namespaceBinding: options.namespaceBinding, schema, tableName };
}

function normalizeNamespace(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 200 ||
    /[\u0000-\u001F\u007F]/u.test(value)
  ) {
    throw new Error("[getbrick-idaas] OIDC adapter namespace is invalid");
  }
  return value;
}

function assertIdentifier(value: string, label: string): void {
  if (!IDENTIFIER_PATTERN.test(value)) {
    throw new Error(`[getbrick-idaas] OIDC adapter ${label} is invalid`);
  }
}

function qualifiedTable(schema: string, tableName: string): string {
  return `${quoteIdentifier(schema)}.${quoteIdentifier(tableName)}`;
}

function quoteIdentifier(value: string): string {
  if (!IDENTIFIER_PATTERN.test(value)) {
    throw new Error("[getbrick-idaas] OIDC adapter identifier is invalid");
  }
  return `"${value}"`;
}

function resolveExpiration(payload: AdapterPayload, expiresIn?: number): Date | null {
  const exp = typeof payload.exp === "number" && Number.isFinite(payload.exp)
    ? payload.exp
    : undefined;
  if (exp !== undefined) return new Date(exp * 1000);
  if (expiresIn !== undefined && Number.isFinite(expiresIn)) {
    return new Date(Date.now() + Math.max(0, expiresIn) * 1000);
  }
  return null;
}

function readString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function readSessionUid(payload: AdapterPayload): string | null {
  return readString(payload.sessionUid) ??
    readString(payload.uid) ??
    readString(payload.session?.uid);
}

function readClientId(payload: AdapterPayload): string | null {
  return readString(payload.clientId) ?? readString(payload.client_id);
}
