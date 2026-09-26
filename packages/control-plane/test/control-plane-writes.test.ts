import "reflect-metadata";
import { describe, expect, it, vi } from "vitest";
import { Test } from "@nestjs/testing";
import request from "supertest";
import type { GetbrickAuthLike } from "@getbrick/idaas-nestjs";
import {
  CONTROL_PLANE_BASE_PATH,
  ControlPlaneController,
  ControlPlaneModule,
  ControlPlaneService,
  InMemoryControlPlaneRepository,
} from "../src/index.js";

function actor(permissions: string[], id = "actor") {
  return { user: { id }, permissions };
}

function writeActor() {
  return actor(["users:write", "sessions:write"]);
}

describe("control-plane writes", () => {
  it("enforces permissions, transitions, protected roles and auditing", async () => {
    const repository = new InMemoryControlPlaneRepository({
      users: [
        { id: "admin-1", role: "admin" },
        { id: "admin-2", role: "admin" },
        { id: "owner-1", role: "owner" },
        { id: "owner-2", role: "owner" },
        { id: "user-1", role: "user" },
        { id: "foreign", tenantId: "other", role: "user" },
      ],
      sessions: [{ id: "session-1", userId: "user-1", status: "active" }],
    });
    const service = new ControlPlaneService(repository);
    const writer = writeActor();

    await expect(service.disableUser("user-1", writer)).resolves.toMatchObject({ id: "user-1", status: "disabled" });
    await expect(service.disableUser("user-1", writer)).rejects.toMatchObject({ code: "CONFLICT", statusCode: 409 });
    await expect(service.enableUser("user-1", writer)).resolves.toMatchObject({ id: "user-1", status: "active" });
    await expect(service.enableUser("user-1", writer)).rejects.toMatchObject({ code: "CONFLICT", statusCode: 409 });
    await expect(service.disableUser("admin-2", writer)).resolves.toMatchObject({ status: "disabled" });
    await expect(service.disableUser("admin-2", writer)).rejects.toMatchObject({ code: "CONFLICT" });
    await expect(service.disableUser("owner-2", writer)).resolves.toMatchObject({ status: "disabled" });
    await expect(service.disableUser("owner-2", writer)).rejects.toMatchObject({ code: "CONFLICT" });
    await expect(service.disableUser("foreign", writer)).rejects.toMatchObject({ code: "NOT_FOUND", statusCode: 404 });
    await expect(service.disableUser("user-1", { tenantId: "other" }, writer)).rejects.toMatchObject({
      code: "INVALID_REQUEST",
      statusCode: 400,
    });
    await expect(service.disableUser("user-1", actor(["sessions:write"]))).rejects.toMatchObject({
      code: "FORBIDDEN",
      statusCode: 403,
    });
    await expect(service.revokeSession("session-1", actor(["users:write"]))).rejects.toMatchObject({
      code: "FORBIDDEN",
      statusCode: 403,
    });
    await expect(service.revokeSession("session-1", writer)).resolves.toMatchObject({ status: "revoked" });

    const audit = repository.snapshot().auditEvents;
    expect(audit.map((event) => event.event)).toEqual(expect.arrayContaining([
      "user.disabled",
      "user.enabled",
      "session.revoked",
    ]));
    expect(JSON.stringify(audit)).not.toContain("password");
  });

  it("revokes one or all sessions and rejects duplicate or empty revocations", async () => {
    const repository = new InMemoryControlPlaneRepository({
      users: [{ id: "user-1", role: "user" }],
      sessions: [
        { id: "session-1", userId: "user-1", status: "active" },
        { id: "session-2", userId: "user-1", status: "active" },
        { id: "session-3", userId: "user-1", status: "revoked", revokedAt: "2026-01-01T00:00:00.000Z" },
      ],
    });
    const service = new ControlPlaneService(repository);
    const writer = writeActor();

    await expect(service.revokeSession("session-1", writer)).resolves.toMatchObject({ id: "session-1", status: "revoked" });
    await expect(service.revokeSession("session-1", writer)).rejects.toMatchObject({ code: "CONFLICT" });
    const result = await service.revokeUserSessions("user-1", writer);
    expect(result).toEqual({ userId: "user-1", revokedCount: 1, sessionIds: ["session-2"] });
    await expect(service.revokeUserSessions("user-1", writer)).rejects.toMatchObject({ code: "CONFLICT" });
    await expect(service.revokeUserSessions("missing", writer)).rejects.toMatchObject({ code: "NOT_FOUND" });
    expect(repository.snapshot().auditEvents.filter((event) => event.event === "session.revoked")).toHaveLength(1);
    expect(repository.snapshot().auditEvents.filter((event) => event.event === "user.sessions.revoked")).toHaveLength(1);
  });

  it("restores in-memory state when audit persistence fails", async () => {
    const repository = new InMemoryControlPlaneRepository({
      users: [{ id: "user-1", role: "user", status: "active" }],
      sessions: [{ id: "session-1", userId: "user-1", status: "active" }],
    });
    repository.addAuditEvent = () => {
      throw new Error("postgres://control-plane:secret@internal/db");
    };
    const service = new ControlPlaneService(repository);
    await expect(service.disableUser("user-1", writeActor())).rejects.toMatchObject({ code: "INTERNAL_ERROR", statusCode: 500 });
    expect(repository.snapshot().users[0]?.status).toBe("active");

    repository.addAuditEvent = () => {
      throw new Error("audit unavailable");
    };
    await expect(service.revokeSession("session-1", writeActor())).rejects.toMatchObject({ code: "INTERNAL_ERROR" });
    expect(repository.snapshot().sessions[0]?.status).toBe("active");
  });
});

describe("control-plane write controller", () => {
  it("uses forwarded IP only when proxy trust is explicitly enabled", async () => {
    const disableUser = vi.fn(async () => ({ id: "user-1", status: "disabled", roles: [] }));
    const service = { disableUser } as unknown as ControlPlaneService;
    const controller = new ControlPlaneController(service, true);

    await controller.disableUser(
      "user-1",
      {},
      {},
      { id: "actor" },
      ["users:write"],
      { ip: "10.0.0.1", headers: { "x-forwarded-for": "198.51.100.77" } },
    );

    expect(disableUser).toHaveBeenCalledWith(
      "user-1",
      {},
      expect.objectContaining({ user: { id: "actor" } }),
      expect.objectContaining({ ipAddress: "198.51.100.77" }),
    );
  });

  it("returns 401/403, rejects tenant bodies and keeps cross-tenant targets hidden", async () => {
    const repository = new InMemoryControlPlaneRepository({
      users: [
        { id: "user-1", role: "user" },
        { id: "foreign", tenantId: "other", role: "user" },
      ],
      sessions: [{ id: "session-1", userId: "user-1", status: "active" }],
    });
    const auth: GetbrickAuthLike = {
      api: {
        getSession: async ({ headers }) => {
          const id = headers.get("x-test-user");
          if (!id) return null;
          const role = id === "reader" ? "reader" : id === "writer" ? "writer" : "user";
          return { user: { id, role } };
        },
      },
      handler: async () => new Response("ok"),
    };
    const moduleRef = await Test.createTestingModule({
      imports: [
        ControlPlaneModule.forRoot({
          auth,
          repository,
          rbac: {
            user: { permissions: [] },
            reader: { permissions: ["users:read", "sessions:read"] },
            writer: { permissions: ["users:read", "sessions:read", "users:write", "sessions:write"] },
          },
        }),
      ],
    }).compile();
    const app = moduleRef.createNestApplication();
    await app.init();
    const server = app.getHttpServer();

    const unauthenticated = await request(server).post(`${CONTROL_PLANE_BASE_PATH}/users/user-1/disable`).send({});
    expect(unauthenticated.status).toBe(401);
    expect(unauthenticated.body.error.code).toBe("UNAUTHENTICATED");

    const forbidden = await request(server)
      .post(`${CONTROL_PLANE_BASE_PATH}/users/user-1/disable`)
      .set("x-test-user", "reader")
      .send({});
    expect(forbidden.status).toBe(403);
    expect(forbidden.body.error.code).toBe("FORBIDDEN");

    const tenantBody = await request(server)
      .post(`${CONTROL_PLANE_BASE_PATH}/users/user-1/disable`)
      .set("x-test-user", "writer")
      .send({ tenantId: "other" });
    expect(tenantBody.status).toBe(400);
    expect(tenantBody.body.error.details).toEqual({ field: "tenantId" });

    const crossTenant = await request(server)
      .post(`${CONTROL_PLANE_BASE_PATH}/users/foreign/disable`)
      .set("x-test-user", "writer")
      .send({});
    expect(crossTenant.status).toBe(404);
    expect(crossTenant.body.error.code).toBe("NOT_FOUND");

    const disabled = await request(server)
      .post(`${CONTROL_PLANE_BASE_PATH}/users/user-1/disable`)
      .set("x-test-user", "writer")
      .set("x-request-id", "write-1")
      .set("x-forwarded-for", "198.51.100.77")
      .send({});
    expect(disabled.status).toBe(200);
    expect(disabled.body).toMatchObject({ id: "user-1", status: "disabled" });

    const sessionForbidden = await request(server)
      .delete(`${CONTROL_PLANE_BASE_PATH}/sessions/session-1`)
      .set("x-test-user", "reader")
      .send({});
    expect(sessionForbidden.status).toBe(403);

    const revoked = await request(server)
      .delete(`${CONTROL_PLANE_BASE_PATH}/sessions/session-1`)
      .set("x-test-user", "writer")
      .send({});
    expect(revoked.status).toBe(200);
    expect(revoked.body).toMatchObject({ id: "session-1", status: "revoked" });

    const tenantDelete = await request(server)
      .delete(`${CONTROL_PLANE_BASE_PATH}/sessions/session-1`)
      .set("x-test-user", "writer")
      .send({ tenantId: "other" });
    expect(tenantDelete.status).toBe(400);

    const audit = repository.snapshot().auditEvents;
    const userAudit = audit.find((event) => event.event === "user.disabled" && event.requestId === "write-1");
    expect(userAudit).toBeDefined();
    expect(userAudit?.ipAddress).not.toBe("198.51.100.77");
    expect(audit.some((event) => event.event === "session.revoked")).toBe(true);

    await app.close();
  });
});
