import { describe, expect, expectTypeOf, it, vi } from "vitest";
import type { AdapterPayload } from "oidc-provider";
import {
  createPostgresOidcAdapterFactory,
  getPostgresOidcMigrationSql,
  type OidcNamespaceBindingPort,
  type OidcSqlClient,
  type OidcSqlResult,
  type PostgresOidcAdapterFactory,
} from "../src/index.js";

interface FakeQueryResult {
  rows: Record<string, unknown>[];
  rowCount: number | null;
}

class FakeSqlClient implements OidcSqlClient {
  readonly queries: Array<{ text: string; values?: unknown[] }> = [];
  rows: Record<string, unknown>[] = [];
  rowCount: number | null = 1;
  readinessRows: Record<string, unknown>[] | undefined;
  canaryResults: FakeQueryResult[] = [
    { rows: [{ id: "canary" }], rowCount: 1 },
    { rows: [{ id: "canary" }], rowCount: 1 },
    { rows: [{ id: "canary" }], rowCount: 1 },
  ];

  async query<Row = Record<string, unknown>>(
    text: string,
    values?: unknown[],
  ): Promise<OidcSqlResult<Row>> {
    this.queries.push({ text, values });
    if (text.includes("information_schema.columns")) {
      const rows = this.readinessRows ?? [readinessRow()];
      return { rows: rows as Row[], rowCount: rows.length === 0 ? 0 : 1 };
    }
    if (values?.[1] === "__getbrick_oidc_readiness_canary__") {
      const result = this.canaryResults.shift() ?? { rows: [{ id: "canary" }], rowCount: 1 };
      return { rows: result.rows as Row[], rowCount: result.rowCount };
    }
    return {
      rows: this.rows as Row[],
      rowCount: this.rowCount,
    };
  }
}

function readinessRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    columns_ok: true,
    primary_key_ok: true,
    session_uid_unique_ok: true,
    user_code_unique_ok: true,
    can_select: true,
    can_insert: true,
    can_update: true,
    can_delete: true,
    can_schema_usage: true,
    ...overrides,
  };
}

describe("PostgreSQL OIDC adapter", () => {
  it("generates a namespaced artifact schema with replay indexes", () => {
    const sql = getPostgresOidcMigrationSql({ namespace: "tenant-a" });
    expect(sql).toContain('CREATE TABLE IF NOT EXISTS "public"."gb_idaas_oidc_artifact"');
    expect(sql).toContain("consumed_at timestamptz NULL");
    expect(sql).toContain("session_uid");
    expect(sql).toContain("user_code");
    expect(sql).toContain("PRIMARY KEY (namespace, model, id)");
    expect(sql).toContain("ALTER TABLE");
    expect(sql).toContain("ADD COLUMN IF NOT EXISTS consumed_at");

    const binding: OidcNamespaceBindingPort = {
      resolveNamespace: async ({ namespace }) => namespace ?? "tenant-a",
    };
    expect(getPostgresOidcMigrationSql({ namespace: "tenant-a", namespaceBinding: binding })).toBe(sql);
    expect(() => getPostgresOidcMigrationSql({ schema: "public;drop" })).toThrow(/schema/i);
  });

  it("stores indexes and expires artifacts without exposing tokens in SQL values", async () => {
    const sql = new FakeSqlClient();
    const factory = createPostgresOidcAdapterFactory(sql, { namespace: "tenant-a" });
    const adapter = factory("Session");
    const payload: AdapterPayload = {
      uid: "session-uid",
      accountId: "user-1",
      clientId: "client-1",
      grantId: "grant-1",
      exp: Math.floor(Date.now() / 1000) + 600,
    };
    await adapter.upsert("session-1", payload, 60);
    const upsert = sql.queries[0];
    expect(upsert?.values?.[0]).toBe("tenant-a");
    expect(upsert?.values?.[1]).toBe("Session");
    expect(upsert?.values?.[2]).toBe("session-1");
    expect(upsert?.values?.[3]).toBe(JSON.stringify(payload));
    expect(upsert?.values?.[5]).toBe("grant-1");
    expect(upsert?.values?.[6]).toBe("session-uid");
    expect(upsert?.values?.[8]).toBe("client-1");
    expect(upsert?.values?.[9]).toBe("user-1");
    expect(upsert?.text).toContain("consumed_at");
  });

  it("checks required columns, namespace queryability, and can revoke active account artifacts", async () => {
    const sql = new FakeSqlClient();
    const factory = createPostgresOidcAdapterFactory(sql, { namespace: "tenant-a" });
    await factory.ready();
    const readyQuery = sql.queries[0];
    expect(readyQuery?.text).not.toContain("LIMIT 0");
    expect(readyQuery?.text).toContain("WHERE namespace = $1");
    expect(readyQuery?.values).toEqual([
      "tenant-a",
      "public",
      "gb_idaas_oidc_artifact",
      '"public"."gb_idaas_oidc_artifact"',
    ]);
    for (const column of ["namespace", "model", "id", "payload", "expires_at", "consumed_at", "deleted_at"]) {
      expect(readyQuery?.text).toContain(column);
    }
    expect(readyQuery?.text).toContain("information_schema.columns");
    expect(readyQuery?.text).toContain("pg_index");
    expect(readyQuery?.text).toContain("indisprimary");
    expect(readyQuery?.text).toContain("indisunique");
    expect(readyQuery?.text).toContain("has_table_privilege");
    expect(readyQuery?.text).toContain("'INSERT'");
    expect(readyQuery?.text).toContain("'UPDATE'");
    expect(readyQuery?.text).toContain("'DELETE'");
    const canaryQueries = sql.queries.filter((query) => query.values?.[1] === "__getbrick_oidc_readiness_canary__");
    expect(canaryQueries).toHaveLength(3);
    expect(canaryQueries.every((query) => query.values?.[0] === "tenant-a")).toBe(true);

    sql.rowCount = 2;
    await expect(factory.revokeByAccountId("user-1")).resolves.toBe(2);
    const revokeQuery = sql.queries.find((query) => query.text.includes("account_id = $2"));
    expect(revokeQuery?.values).toEqual(["tenant-a", "user-1"]);
    expect(revokeQuery?.text).toContain("account_id = $2");
    expect(revokeQuery?.text).toContain("expires_at IS NULL OR expires_at > clock_timestamp()");
    expect(revokeQuery?.text).toContain("consumed_at IS NULL");
    expect(revokeQuery?.text).toContain("deleted_at IS NULL");
    expect(revokeQuery?.text).toContain("RETURNING id");
  });

  it("fails readiness when catalog constraints or write privileges are missing", async () => {
    const missingPrimaryKey = new FakeSqlClient();
    missingPrimaryKey.readinessRows = [readinessRow({ primary_key_ok: false })];
    const missingPrimaryFactory = createPostgresOidcAdapterFactory(missingPrimaryKey, { namespace: "tenant-a" });
    await expect(missingPrimaryFactory.ready()).rejects.toThrow(/primary_key_ok/);

    const missingInsert = new FakeSqlClient();
    missingInsert.readinessRows = [readinessRow({ can_insert: false })];
    const missingInsertFactory = createPostgresOidcAdapterFactory(missingInsert, { namespace: "tenant-a" });
    await expect(missingInsertFactory.ready()).rejects.toThrow(/can_insert/);
  });

  it("fails closed on empty catalog rows, missing unique constraints, and read-only writes", async () => {
    const emptyCatalog = new FakeSqlClient();
    emptyCatalog.readinessRows = [];
    const emptyFactory = createPostgresOidcAdapterFactory(emptyCatalog, { namespace: "tenant-a" });
    await expect(emptyFactory.ready()).rejects.toThrow(/catalog returned no rows/);
    expect(emptyCatalog.queries.some((query) => query.values?.[1] === "__getbrick_oidc_readiness_canary__")).toBe(false);

    const missingUnique = new FakeSqlClient();
    missingUnique.readinessRows = [readinessRow({ user_code_unique_ok: false })];
    const missingUniqueFactory = createPostgresOidcAdapterFactory(missingUnique, { namespace: "tenant-a" });
    await expect(missingUniqueFactory.ready()).rejects.toThrow(/user_code_unique_ok/);

    const readOnly = new FakeSqlClient();
    readOnly.readinessRows = [readinessRow({ can_insert: false, can_update: false, can_delete: false })];
    const readOnlyFactory = createPostgresOidcAdapterFactory(readOnly, { namespace: "tenant-a" });
    await expect(readOnlyFactory.ready()).rejects.toThrow(/can_insert/);
  });

  it("cleans a failed namespaced canary and redacts the write error", async () => {
    const sql = new FakeSqlClient();
    sql.canaryResults = [
      { rows: [{ id: "canary" }], rowCount: 1 },
      { rows: [], rowCount: 0 },
      { rows: [], rowCount: 0 },
    ];
    const factory = createPostgresOidcAdapterFactory(sql, { namespace: "tenant-a" });
    await expect(factory.ready()).rejects.toThrow(/write check failed/);
    const canaryQueries = sql.queries.filter((query) => query.values?.[1] === "__getbrick_oidc_readiness_canary__");
    expect(canaryQueries.filter((query) => query.text.trimStart().startsWith("DELETE"))).toHaveLength(1);
    expect(canaryQueries.every((query) => !query.text.includes("password"))).toBe(true);
  });

  it("does not update consumed or deleted artifacts on conflict", async () => {
    const sql = new FakeSqlClient();
    const factory = createPostgresOidcAdapterFactory(sql);
    const adapter = factory("AuthorizationCode");
    await adapter.upsert("code-1", { exp: Math.floor(Date.now() / 1000) + 600 }, 600);
    expect(sql.queries[0]?.text).toContain("WHERE current.deleted_at IS NULL AND current.consumed_at IS NULL");
    expect(sql.queries[0]?.text).not.toContain("deleted_at = NULL");

    sql.rowCount = 0;
    await expect(adapter.upsert("code-1", { exp: Math.floor(Date.now() / 1000) + 600 }, 600)).rejects.toThrow(/consumed or deleted/i);
    expect(sql.queries[1]?.text).toContain("current.consumed_at IS NULL");
  });

  it("uses an atomic active predicate and fails closed after consumption or expiration", async () => {
    const sql = new FakeSqlClient();
    const factory = createPostgresOidcAdapterFactory(sql);
    const adapter = factory("AuthorizationCode");
    sql.rowCount = null;
    sql.rows = [];
    await expect(adapter.consume("code-1")).rejects.toThrow(/invalid_grant/i);
    const consumeQuery = sql.queries[0];
    expect(consumeQuery?.text).toContain("expires_at IS NULL OR expires_at > clock_timestamp()");
    expect(consumeQuery?.text).toContain("consumed_at IS NULL");
    expect(consumeQuery?.text).toContain("deleted_at IS NULL");
    expect(consumeQuery?.text).toContain("RETURNING id");
  });

  it("keeps consumed grant artifacts visible to replay lookup while active lookup hides them", async () => {
    const sql = new FakeSqlClient();
    const factory = createPostgresOidcAdapterFactory(sql, { namespace: "tenant-a" });
    const payload: AdapterPayload = {
      exp: Math.floor(Date.now() / 1000) + 600,
      grantId: "grant-1",
      clientId: "client-1",
    };
    sql.rows = [{ payload, consumed_at: new Date() }];

    const replay = await factory("AuthorizationCode").find("code-1");
    expect(replay).toMatchObject({ consumed: true, grantId: "grant-1" });
    expect(sql.queries[0]?.text).not.toContain("consumed_at IS NULL");
    expect(sql.queries[0]?.text).toContain("consumed_at IS NOT NULL");
    expect(sql.queries[0]?.text).toContain("consumed_at");
    expect(sql.queries[0]?.values).toEqual(["tenant-a", "AuthorizationCode", "code-1"]);

    sql.rows = [];
    await expect(factory("AuthorizationCode").findActive("code-1")).resolves.toBeUndefined();
    expect(sql.queries[1]?.text).toContain("consumed_at IS NULL");
    expect(sql.queries[1]?.values).toEqual(["tenant-a", "AuthorizationCode", "code-1"]);

    sql.rows = [{ payload: { grantId: "grant-1", clientId: "client-1" }, consumed_at: new Date() }];
    const refresh = await factory("RefreshToken").find("refresh-1");
    expect(refresh).toMatchObject({ consumed: true, grantId: "grant-1" });
    expect(sql.queries[2]?.text).not.toContain("consumed_at IS NULL");
  });

  it("keeps device-code replay visible but session reads active", async () => {
    const sql = new FakeSqlClient();
    const factory = createPostgresOidcAdapterFactory(sql, { namespace: "tenant-a" });
    sql.rows = [{ payload: { userCode: "user-code", grantId: "grant-1" }, consumed_at: new Date() }];

    await expect(factory("DeviceCode").findByUserCode("user-code")).resolves.toMatchObject({ consumed: true });
    expect(sql.queries[0]?.text).not.toContain("consumed_at IS NULL");
    sql.rows = [];
    await expect(factory("Session").findByUid("session-uid")).resolves.toBeUndefined();
    expect(sql.queries[1]?.text).toContain("consumed_at IS NULL");
  });

  it("uses the active predicate for model-scoped destroy and grant revocation", async () => {
    const sql = new FakeSqlClient();
    const adapter = createPostgresOidcAdapterFactory(sql, { namespace: "tenant-a" })("AuthorizationCode");
    await adapter.destroy("code-1");
    await adapter.revokeByGrantId("grant-1");

    expect(sql.queries[0]?.values).toEqual(["tenant-a", "AuthorizationCode", "code-1"]);
    expect(sql.queries[1]?.values).toEqual(["tenant-a", "AuthorizationCode", "grant-1"]);
    for (const query of sql.queries) {
      expect(query.text).toContain("expires_at IS NULL OR expires_at > clock_timestamp()");
      expect(query.text).toContain("consumed_at IS NULL");
      expect(query.text).toContain("deleted_at IS NULL");
      expect(query.text).toContain("RETURNING id");
    }
  });

  it("returns stable counts for grant revocation and cleanup", async () => {
    const sql = new FakeSqlClient();
    const factory = createPostgresOidcAdapterFactory(sql, { namespace: "tenant-a" });
    sql.rowCount = null;
    sql.rows = [{ id: "one" }, { id: "two" }];

    await expect(factory.revokeByGrantId("grant-1")).resolves.toBe(2);
    await expect(factory.revokeByAccountId("user-1")).resolves.toBe(2);
    await expect(factory.cleanup(60)).resolves.toBe(2);
    expect(sql.queries[0]?.values).toEqual(["tenant-a", "grant-1"]);
    expect(sql.queries[1]?.values).toEqual(["tenant-a", "user-1"]);
    expect(sql.queries[2]?.values).toEqual(["tenant-a", 60]);
    for (const query of sql.queries.slice(0, 2)) {
      expect(query.text).toContain("expires_at IS NULL OR expires_at > clock_timestamp()");
      expect(query.text).toContain("consumed_at IS NULL");
      expect(query.text).toContain("deleted_at IS NULL");
      expect(query.text).toContain("RETURNING id");
    }
    expect(sql.queries[2]?.text).toContain("expires_at < clock_timestamp() - ($2 * interval '1 second')");
    expect(sql.queries[2]?.text).toContain("RETURNING id");

    sql.rowCount = 4;
    sql.rows = [];
    await expect(factory.cleanup()).resolves.toBe(4);
  });

  it("exposes stable adapter contracts and an explicit namespace binding port", async () => {
    expectTypeOf<PostgresOidcAdapterFactory["cleanup"]>().toEqualTypeOf<
      (retentionSeconds?: number) => Promise<number>
    >();
    expectTypeOf<PostgresOidcAdapterFactory["revokeByAccountId"]>().toEqualTypeOf<
      (accountId: string) => Promise<number>
    >();
    expectTypeOf<PostgresOidcAdapterFactory["revokeByGrantId"]>().toEqualTypeOf<
      (grantId: string) => Promise<number>
    >();

    const resolveNamespace = vi.fn(async (input: { tenantId: string; namespace?: string }) =>
      `${input.namespace ?? "base"}:${input.tenantId}`);
    const binding: OidcNamespaceBindingPort = { resolveNamespace };
    const factory = createPostgresOidcAdapterFactory(new FakeSqlClient(), {
      namespace: "base",
      namespaceBinding: binding,
    });
    await expect(factory.bindNamespace({ tenantId: "tenant-a", namespace: "bound" })).resolves.toBe("bound:tenant-a");
    expect(resolveNamespace).toHaveBeenCalledWith({ tenantId: "tenant-a", namespace: "bound" });

    const invalidFactory = createPostgresOidcAdapterFactory(new FakeSqlClient(), {
      namespaceBinding: { resolveNamespace: async () => "" },
    });
    await expect(invalidFactory.bindNamespace({ tenantId: "tenant-a" })).rejects.toThrow(/namespace/i);
    await expect(invalidFactory.revokeByAccountId("")).rejects.toThrow(/account ID/i);
    await expect(invalidFactory.revokeByGrantId("x".repeat(513))).rejects.toThrow(/grant ID/i);
    await expect(invalidFactory.cleanup(-1)).rejects.toThrow(/retention/i);
  });
});
