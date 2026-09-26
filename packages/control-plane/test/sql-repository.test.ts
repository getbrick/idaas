import "reflect-metadata";
import { describe, expect, it } from "vitest";
import {
  BETTER_AUTH_CONTROL_PLANE_COLUMNS,
  BETTER_AUTH_CONTROL_PLANE_TABLES,
  ControlPlaneService,
  ControlPlaneSqlRollbackError,
  type ControlPlaneSqlExecutor,
  SqlControlPlaneRepository,
  validateControlPlaneSqlIdentifier,
} from "../src/index.js";

type QueryCall = { text: string; values: readonly unknown[] };

function actor() {
  return { user: { id: "actor" }, permissions: ["audit:read"] };
}

describe("SqlControlPlaneRepository", () => {
  it("uses validated identifiers, tenant parameters, cursor pagination and masking", async () => {
    const calls: QueryCall[] = [];
    let auditUnavailable = false;
    let userStatus = "active";
    const query = async (text: string, values: readonly unknown[]): Promise<unknown> => {
      calls.push({ text, values });
      if (text.includes('"audit_events"') && auditUnavailable) throw new Error("postgres://control-plane:secret@internal/db");
      if (text.startsWith("SELECT 1 FROM")) return { rows: [] };
      if (text.includes("COUNT(*)")) {
        if (text.includes('"audit_events"')) return { rows: [{ total: 1 }] };
        if (text.includes('"users"')) return { rows: [{ total: 2 }] };
        return { rows: [{ total: 0 }] };
      }
      if (text.includes('FROM "users"')) {
        if (text.includes('"id" = $2')) {
          return { rows: [{ id: "user-1", tenantId: "tenant", status: userStatus, role: "user", email: "user@example.test", password: "raw-password" }] };
        }
        if (text.includes("COALESCE(\"status\", 'active') = 'active'")) {
          return { rows: [{ id: "user-1", tenantId: "tenant", status: "active", role: "user" }] };
        }
        const limit = Number(values.at(-2));
        const offset = Number(values.at(-1));
        const rows = [
          { id: "user-1", tenantId: "tenant", status: "active", role: "user", password: "raw-password" },
          { id: "user-2", tenantId: "tenant", status: "active", role: "user", password: "raw-password-2" },
        ];
        return { rows: rows.slice(offset, offset + limit) };
      }
      if (text.includes('FROM "audit_events"')) {
        return { rows: [{ id: "audit-1", tenantId: "tenant", event: "user.created", detail: { safe: "yes", password: "raw-password" } }] };
      }
      return { rows: [] };
    };
    const repository = new SqlControlPlaneRepository({
      query,
      tenantId: "tenant",
      tables: { users: "users", roles: "roles", sessions: "sessions", auditEvents: "audit_events" },
    });

    const first = await repository.listUsers({ limit: 1 });
    expect(first.items.map((item) => item.id)).toEqual(["user-1"]);
    expect(first.total).toBe(2);
    expect(first.hasMore).toBe(true);
    expect(first.items[0]).not.toHaveProperty("password");
    expect(first.nextCursor).toBeTruthy();
    const second = await repository.listUsers({ limit: 1, cursor: first.nextCursor });
    expect(second.items.map((item) => item.id)).toEqual(["user-2"]);
    expect(calls.some((call) => call.values.includes("tenant") && call.text.includes("tenantId"))).toBe(true);

    const auditService = new ControlPlaneService(repository);
    const audit = await auditService.listAuditEvents({}, actor());
    expect(audit.items[0]?.detail).toEqual({ safe: "yes" });
    expect(JSON.stringify(audit)).not.toContain("raw-password");

    expect(await repository.isReady()).toBe(true);
    auditUnavailable = true;
    expect(await repository.isReady()).toBe(false);
    await expect(repository.listAuditEvents()).rejects.toThrow("Control-plane SQL query failed");
    await expect(repository.listAuditEvents()).rejects.not.toThrow("secret");
  });

  it("rejects unsafe identifiers and keeps writes parameterized with rollback", async () => {
    expect(() => validateControlPlaneSqlIdentifier("users; DROP TABLE users")).toThrow();
    expect(() => validateControlPlaneSqlIdentifier("public.users")).not.toThrow();
    expect(() => validateControlPlaneSqlIdentifier("public.users;select")).toThrow();

    const calls: QueryCall[] = [];
    let userStatus = "active";
    let failAudit = true;
    const query = async (text: string, values: readonly unknown[]): Promise<unknown> => {
      calls.push({ text, values });
      if (text.startsWith("SELECT 1 FROM")) return { rows: [] };
      if (text.includes('FROM "users"') && text.includes('"id" = $2')) {
        return { rows: [{ id: "user-1", tenantId: "tenant", status: userStatus, role: "user" }] };
      }
      if (text.includes('UPDATE "users"')) {
        userStatus = String(values[0]);
        return { rows: [{ id: "user-1" }] };
      }
      if (text.includes('INSERT INTO "audit_events"')) {
        if (failAudit) throw new Error("database password should not escape");
        return { rows: [{ id: "audit-1" }] };
      }
      return { rows: [] };
    };
    const repository = new SqlControlPlaneRepository({ query, tenantId: "tenant" });
    await expect(repository.disableUser("user-1", { actorId: "actor" })).rejects.toThrow("Control-plane SQL query failed");
    expect(userStatus).toBe("active");
    const update = calls.find((call) => call.text.startsWith('UPDATE "users"'));
    expect(update?.text).not.toContain("user-1");
    expect(update?.values).toContain("user-1");
    expect(calls.some((call) => call.text.includes("INSERT INTO \"audit_events\""))).toBe(true);

    failAudit = false;
    await expect(repository.disableUser("user-1", { actorId: "actor" })).resolves.toMatchObject({ status: "disabled" });
  });

  it("queries Better Auth single-tenant tables without a tenant column or parameter", async () => {
    const calls: QueryCall[] = [];
    const query = async (text: string, values: readonly unknown[]): Promise<unknown> => {
      calls.push({ text, values });
      if (text.includes('"username"') || text.includes('"phoneNumber"') || text.includes('"revokedAt"')) {
        throw new Error("Better Auth mock received a non-existent column");
      }
      if (text.includes("COUNT(*)")) return { rows: [{ total: 1 }] };
      if (text.includes('FROM "gb_idaas_user"')) {
        return {
          rows: [{
            id: "user-1",
            name: "Alice",
            email: "alice@example.test",
            emailVerified: true,
            createdAt: "2026-01-01T00:00:00.000Z",
            updatedAt: "2026-01-01T00:00:00.000Z",
          }],
        };
      }
      if (text.includes('FROM "gb_idaas_session"')) {
        return { rows: [{ id: "session-1", userId: "user-1", expiresAt: "2026-01-08T00:00:00.000Z" }] };
      }
      if (text.includes('INSERT INTO "gb_idaas_audit"')) return { rows: [{ id: "audit-1" }] };
      return { rows: [] };
    };
    const repository = new SqlControlPlaneRepository({
      query,
      tenantId: "configured-tenant",
      tenantColumn: null,
      tables: {
        ...BETTER_AUTH_CONTROL_PLANE_TABLES,
        roles: "gb_idaas_role",
        auditEvents: "gb_idaas_audit",
      },
      columns: BETTER_AUTH_CONTROL_PLANE_COLUMNS,
    });

    const users = await repository.listUsers({ email: "alice@example.test" });
    expect(users.items[0]).toMatchObject({ id: "user-1", tenantId: "configured-tenant" });
    const count = calls.find((call) => call.text.includes("COUNT(*)"));
    const select = calls.find((call) => call.text.includes('FROM "gb_idaas_user"') && !call.text.includes("COUNT(*)"));
    expect(count?.text).not.toMatch(/tenantId/i);
    expect(count?.text).toContain('WHERE LOWER("email") = LOWER($1)');
    expect(count?.values).toEqual(["alice@example.test"]);
    expect(select?.text).not.toMatch(/tenantId/i);
    expect(select?.text).not.toContain('"username"');
    expect(select?.text).not.toContain('"status"');
    expect(select?.text).toContain('WHERE LOWER("email") = LOWER($1)');
    expect(select?.values).toEqual(["alice@example.test", 20, 0]);

    const session = await repository.getSession("session-1");
    expect(session).toMatchObject({ id: "session-1", tenantId: "configured-tenant" });
    const sessionCall = calls.at(-1);
    expect(sessionCall?.text).not.toMatch(/tenantId/i);
    expect(sessionCall?.values).toEqual(["session-1"]);

    const audit = await repository.addAuditEvent({ event: "user.created", tenantId: "other-tenant" });
    expect(audit.tenantId).toBe("configured-tenant");
    const auditCall = calls.at(-1);
    expect(auditCall?.text).not.toMatch(/tenantId/i);
    expect(auditCall?.values).not.toContain("other-tenant");
    expect(auditCall?.values).not.toContain("configured-tenant");
  });

  it("prefers an executor transaction for the mutation and audit", async () => {
    const baseCalls: QueryCall[] = [];
    const transactionCalls: QueryCall[] = [];
    let transactionCount = 0;
    let rolledBack = false;
    const baseQuery = async (text: string, values: readonly unknown[]): Promise<unknown> => {
      baseCalls.push({ text, values });
      if (text.includes('FROM "users"') && text.includes('"id" = $2')) {
        return { rows: [{ id: "user-1", tenantId: "tenant", status: "active", role: "user" }] };
      }
      return { rows: [] };
    };
    const transactionQuery = async (text: string, values: readonly unknown[]): Promise<unknown> => {
      transactionCalls.push({ text, values });
      if (text.includes('UPDATE "users"')) return { rows: [{ id: "user-1" }] };
      if (text.includes('INSERT INTO "audit_events"')) throw new Error("audit unavailable");
      return { rows: [] };
    };
    const executor: ControlPlaneSqlExecutor = {
      query: baseQuery,
      async transaction<T>(callback: (executor: ControlPlaneSqlExecutor) => Promise<T>): Promise<T> {
        transactionCount += 1;
        try {
          return await callback({ query: transactionQuery });
        } catch (error) {
          rolledBack = true;
          throw error;
        }
      },
    };
    const repository = new SqlControlPlaneRepository({ executor, tenantId: "tenant" });

    await expect(repository.disableUser("user-1")).rejects.toThrow("Control-plane SQL query failed");
    expect(transactionCount).toBe(1);
    expect(rolledBack).toBe(true);
    expect(baseCalls.some((call) => call.text.includes('UPDATE "users"'))).toBe(false);
    expect(transactionCalls.some((call) => call.text.includes('UPDATE "users"'))).toBe(true);
    expect(transactionCalls.some((call) => call.text.includes('INSERT INTO "audit_events"'))).toBe(true);
  });

  it("surfaces rollback failures with the original error category", async () => {
    const calls: QueryCall[] = [];
    let userStatus = "active";
    let updateCount = 0;
    const auditError = Object.assign(new Error("audit unavailable"), { code: "AUDIT_UNAVAILABLE" });
    const rollbackError = Object.assign(new Error("rollback unavailable"), { code: "ROLLBACK_UNAVAILABLE" });
    const query = async (text: string, values: readonly unknown[]): Promise<unknown> => {
      calls.push({ text, values });
      if (text.includes('FROM "users"') && text.includes('"id" = $2')) {
        return { rows: [{ id: "user-1", tenantId: "tenant", status: userStatus, role: "user" }] };
      }
      if (text.includes('UPDATE "users"')) {
        updateCount += 1;
        if (updateCount > 1) throw rollbackError;
        userStatus = String(values[0]);
        return { rows: [{ id: "user-1" }] };
      }
      if (text.includes('INSERT INTO "audit_events"')) throw auditError;
      return { rows: [] };
    };
    const repository = new SqlControlPlaneRepository({ query, tenantId: "tenant" });

    const failure = await repository.disableUser("user-1").catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(ControlPlaneSqlRollbackError);
    expect(failure).toMatchObject({
      code: "INTERNAL_ERROR",
      originalErrorCode: "AUDIT_UNAVAILABLE",
      rollbackErrorCode: "ROLLBACK_UNAVAILABLE",
    });
    expect((failure as ControlPlaneSqlRollbackError).originalError).toMatchObject({
      message: "Control-plane SQL query failed",
    });
    expect((failure as ControlPlaneSqlRollbackError).rollbackError).toMatchObject({
      message: "Control-plane SQL query failed",
    });
    expect(userStatus).toBe("disabled");
  });
});
