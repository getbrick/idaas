import "reflect-metadata";
import { describe, expect, it } from "vitest";
import { Test } from "@nestjs/testing";
import request from "supertest";
import { GETBRICK_PUBLIC, type GetbrickAuthLike } from "@getbrick/idaas-nestjs";
import {
  CONTROL_PLANE_BASE_PATH,
  ControlPlaneController,
  ControlPlaneModule,
  ControlPlaneService,
  InMemoryControlPlaneRepository,
  type ControlPlaneUser,
} from "../src/index.js";

const repository = new InMemoryControlPlaneRepository({
  users: [
    {
      id: "user-1",
      name: "Alice",
      email: "alice@example.test",
      role: "admin",
      createdAt: "2026-01-01T00:00:00.000Z",
      password: "password-1",
      passwordHash: "hash-1",
      token: "token-1",
      secret: "secret-1",
    },
    {
      id: "user-2",
      name: "Bob",
      email: "bob@example.test",
      role: "user",
      createdAt: "2026-01-02T00:00:00.000Z",
    },
    {
      id: "user-3",
      name: "Carol",
      email: "carol@example.test",
      role: "user",
      createdAt: "2026-01-03T00:00:00.000Z",
    },
  ],
  roles: [
    {
      id: "role-1",
      code: "admin",
      name: "Administrator",
      permissions: ["*:*"],
    },
    {
      id: "role-2",
      code: "user",
      name: "User",
      permissions: [],
    },
  ],
  sessions: [
    {
      id: "session-1",
      userId: "user-1",
      organizationId: "organization-1",
      status: "active",
      token: "raw-session-token",
      lastActiveAt: "2026-01-01T00:00:00.000Z",
    },
    {
      id: "session-2",
      userId: "user-2",
      status: "revoked",
      revokedAt: "2026-01-02T00:00:00.000Z",
      refreshToken: "raw-refresh-token",
      lastActiveAt: "2026-01-02T00:00:00.000Z",
    },
    {
      id: "session-foreign",
      tenantId: "other-tenant",
      userId: "user-3",
      status: "active",
      token: "foreign-session-token",
    },
  ],
  auditEvents: [
    {
      id: "audit-1",
      event: "user.created",
      userId: "user-1",
      detail: {
        safe: "visible",
        password: "raw-password",
        token: "raw-token",
        apiKey: "raw-api-key",
        databaseUrl: "postgres://control-plane:database-secret@internal/db",
        nested: { secret: "raw-secret", hash: "raw-hash" },
      },
      occurredAt: "2026-01-01T00:00:00.000Z",
    },
    {
      id: "audit-2",
      event: "user.updated",
      userId: "user-2",
      detail: { safe: "updated" },
      occurredAt: "2026-01-02T00:00:00.000Z",
    },
    {
      id: "audit-foreign",
      tenantId: "other-tenant",
      event: "foreign.created",
      detail: { secret: "foreign-secret" },
      occurredAt: "2026-01-03T00:00:00.000Z",
    },
  ],
});

function adminActor() {
  return { user: { id: "admin", role: "admin" }, permissions: ["*:*"] };
}

function createAuth(): GetbrickAuthLike {
  return {
    api: {
      getSession: async ({ headers }) => {
        const userId = headers.get("x-test-user");
        if (!userId) return null;
        const user = repositorySnapshot().find((item) => item.id === userId);
        if (!user) return null;
        return { user: { id: user.id, email: user.email, role: user.role } };
      },
    },
    handler: async () => new Response("ok"),
  };
}

function repositorySnapshot(): ControlPlaneUser[] {
  return [
    { id: "user-1", email: "alice@example.test", role: "admin" },
    { id: "user-2", email: "bob@example.test", role: "user" },
    { id: "user-3", email: "carol@example.test", role: "user" },
  ];
}

describe("ControlPlaneService", () => {
  it("paginates, filters and masks repository records", async () => {
    const service = new ControlPlaneService(repository);
    const first = await service.listUsers({ limit: 2 }, adminActor());
    expect(first.items).toHaveLength(2);
    expect(first.total).toBe(3);
    expect(first.hasMore).toBe(true);
    expect(first.nextCursor).toBeTruthy();
    expect(JSON.stringify(first)).not.toContain("password-1");
    expect(JSON.stringify(first)).not.toContain("hash-1");
    expect(JSON.stringify(first)).not.toContain("token-1");
    expect(JSON.stringify(first)).not.toContain("secret-1");
    expect(first.items[0]).not.toHaveProperty("password");
    expect(first.items[0]).not.toHaveProperty("token");

    const second = await service.listUsers({ limit: 2, cursor: first.nextCursor }, adminActor());
    expect(second.items.map((item) => item.id)).toEqual(["user-3"]);
    expect(second.hasMore).toBe(false);

    const audit = await service.listAuditEvents({}, adminActor());
    expect(audit.items[0]?.detail).toEqual({ safe: "visible", nested: {} });
    expect(JSON.stringify(audit)).not.toContain("raw-password");
    expect(JSON.stringify(audit)).not.toContain("raw-token");
    expect(JSON.stringify(audit)).not.toContain("raw-secret");
    expect(JSON.stringify(audit)).not.toContain("raw-hash");
    expect(JSON.stringify(audit)).not.toContain("raw-api-key");
    expect(JSON.stringify(audit)).not.toContain("database-secret");
  });

  it("accepts role-based authorization from user role values", async () => {
    const service = new ControlPlaneService(repository);
    await expect(service.getCapabilities({ user: { id: "role-admin", role: " ADMIN " } })).resolves.toBeDefined();
    await expect(service.getCapabilities({ user: { id: "role-user", role: "user" } })).rejects.toMatchObject({ statusCode: 403 });
  });

  it("rejects missing authorization and invalid pagination", async () => {
    const service = new ControlPlaneService(repository);
    await expect(service.listUsers({}, undefined)).rejects.toMatchObject({ statusCode: 401 });
    await expect(service.listUsers({}, { user: { id: "u" }, permissions: ["users:read"] })).resolves.toBeDefined();
    await expect(service.listSessions({}, { user: { id: "u" }, permissions: ["sessions:read"] })).resolves.toBeDefined();
    await expect(service.listSessions({}, { user: { id: "u" }, permissions: ["audit:read"] })).rejects.toMatchObject({ statusCode: 403 });
    await expect(service.listAuditEvents({}, { user: { id: "u" }, permissions: ["users:read"] })).rejects.toMatchObject({ statusCode: 403 });
    await expect(service.listUsers({ limit: 0 }, adminActor())).rejects.toMatchObject({ statusCode: 400 });
  });

  it("lists tenant-scoped sessions with pagination, filters and masking", async () => {
    const service = new ControlPlaneService(repository);
    const first = await service.listSessions({ limit: 1 }, adminActor());
    expect(first.items.map((item) => item.id)).toEqual(["session-1"]);
    expect(first.total).toBe(2);
    expect(first.hasMore).toBe(true);
    expect(first.nextCursor).toBeTruthy();
    expect(first.items[0]).toMatchObject({ organizationId: "organization-1" });
    expect(first.items[0]).not.toHaveProperty("token");
    expect(JSON.stringify(first)).not.toContain("raw-session-token");

    const second = await service.listSessions({ limit: 1, cursor: first.nextCursor }, adminActor());
    expect(second.items.map((item) => item.id)).toEqual(["session-2"]);
    expect(second.hasMore).toBe(false);
    expect(JSON.stringify(second)).not.toContain("raw-refresh-token");

    const active = await service.listSessions({ active: true }, adminActor());
    expect(active.items.map((item) => item.id)).toEqual(["session-1"]);
    expect(JSON.stringify(active)).not.toContain("foreign-session-token");
  });

  it("gets tenant-scoped audit events with authorization and masking", async () => {
    const service = new ControlPlaneService(repository);
    const event = await service.getAuditEvent("audit-1", adminActor());
    expect(event.id).toBe("audit-1");
    expect(event.detail).toEqual({ safe: "visible", nested: {} });
    expect(JSON.stringify(event)).not.toContain("raw-password");
    expect(JSON.stringify(event)).not.toContain("raw-token");
    expect(JSON.stringify(event)).not.toContain("raw-secret");
    expect(JSON.stringify(event)).not.toContain("raw-hash");
    expect(JSON.stringify(event)).not.toContain("raw-api-key");
    expect(JSON.stringify(event)).not.toContain("database-secret");
    await expect(service.getAuditEvent("audit-foreign", adminActor())).rejects.toMatchObject({ statusCode: 404 });
    await expect(service.getAuditEvent("missing", adminActor())).rejects.toMatchObject({
      code: "NOT_FOUND",
      statusCode: 404,
    });
  });

  it("returns only authenticated allowlisted system information", async () => {
    const service = new ControlPlaneService(repository);
    await expect(service.getSystemInfo()).rejects.toMatchObject({
      code: "UNAUTHENTICATED",
      statusCode: 401,
    });

    const system = await service.getSystemInfo(adminActor(), " request-1 ");
    expect(Object.keys(system)).toEqual(["version", "capabilities", "requestId"]);
    expect(system).toMatchObject({
      version: "0.1.0",
      requestId: "request-1",
      capabilities: {
        singleTenant: true,
        masking: true,
      },
    });
    expect(system).not.toHaveProperty("secret");
    expect(system).not.toHaveProperty("database");
    expect(system).not.toHaveProperty("repository");

    const unsafe = await service.getSystemInfo(adminActor(), "request\u0000id");
    expect(unsafe).not.toHaveProperty("requestId");
  });

  it("validates session and audit input and hides repository failures", async () => {
    const service = new ControlPlaneService(repository);
    await expect(service.listSessions({ active: "yes" }, adminActor())).rejects.toMatchObject({
      statusCode: 400,
      details: { field: "active" },
    });
    await expect(service.listSessions({ limit: 1, cursor: "not-a-cursor" }, adminActor())).rejects.toMatchObject({
      statusCode: 400,
      details: { field: "cursor" },
    });
    await expect(service.listAuditEvents({ from: "not-a-date" }, adminActor())).rejects.toMatchObject({
      statusCode: 400,
      details: { field: "from" },
    });
    await expect(service.listAuditEvents({ tenantId: "other-tenant" }, adminActor())).rejects.toMatchObject({
      statusCode: 400,
      details: { field: "tenantId" },
    });
    await expect(service.getAuditEvent("   ", adminActor())).rejects.toMatchObject({
      statusCode: 400,
      details: { field: "id" },
    });

    const failingRepository = new InMemoryControlPlaneRepository();
    failingRepository.listSessions = async () => {
      throw new Error("postgres://control-plane:database-secret@internal/db");
    };
    const failure = await new ControlPlaneService(failingRepository)
      .listSessions({}, adminActor())
      .catch((error: unknown) => error);
    expect(failure).toMatchObject({ code: "INTERNAL_ERROR", statusCode: 500 });
    expect(JSON.stringify(failure)).not.toContain("database-secret");
  });
});

describe("ControlPlaneController", () => {
  it("protects control-plane routes and leaves health public", async () => {
    const auth = createAuth();
    const moduleRef = await Test.createTestingModule({
      imports: [ControlPlaneModule.forRoot({ auth, repository })],
    }).compile();
    const app = moduleRef.createNestApplication();
    await app.init();
    const server = app.getHttpServer();

    const unauthenticated = await request(server).get(`${CONTROL_PLANE_BASE_PATH}/users`);
    expect(unauthenticated.status).toBe(401);
    expect(unauthenticated.body.error.code).toBe("UNAUTHENTICATED");

    const unauthenticatedSessions = await request(server).get(`${CONTROL_PLANE_BASE_PATH}/sessions`);
    expect(unauthenticatedSessions.status).toBe(401);

    const unauthenticatedAudit = await request(server).get(`${CONTROL_PLANE_BASE_PATH}/audit-events/audit-1`);
    expect(unauthenticatedAudit.status).toBe(401);

    const unauthenticatedSystem = await request(server).get(`${CONTROL_PLANE_BASE_PATH}/system/info`);
    expect(unauthenticatedSystem.status).toBe(401);

    const forbidden = await request(server)
      .get(`${CONTROL_PLANE_BASE_PATH}/users`)
      .set("x-test-user", "user-2");
    expect(forbidden.status).toBe(403);
    expect(forbidden.body.error.code).toBe("FORBIDDEN");

    const forbiddenSessions = await request(server)
      .get(`${CONTROL_PLANE_BASE_PATH}/sessions`)
      .set("x-test-user", "user-2");
    expect(forbiddenSessions.status).toBe(403);

    const live = await request(server).get(`${CONTROL_PLANE_BASE_PATH}/health/live`);
    const ready = await request(server).get(`${CONTROL_PLANE_BASE_PATH}/health/ready`);
    expect(live.status).toBe(200);
    expect(live.body.status).toBe("ok");
    expect(ready.status).toBe(200);
    expect(ready.body.status).toBe("ready");
    expect(Reflect.getMetadata(GETBRICK_PUBLIC, ControlPlaneController.prototype.healthLive)).toBe(true);
    expect(Reflect.getMetadata(GETBRICK_PUBLIC, ControlPlaneController.prototype.healthReady)).toBe(true);

    const users = await request(server)
      .get(`${CONTROL_PLANE_BASE_PATH}/users?limit=1`)
      .set("x-test-user", "user-1");
    expect(users.status).toBe(200);
    expect(users.body.items).toHaveLength(1);
    expect(users.body.total).toBe(3);
    expect(users.body.nextCursor).toBeTruthy();
    expect(users.body.items[0]).not.toHaveProperty("password");
    expect(users.body.items[0]).not.toHaveProperty("token");
    expect(JSON.stringify(users.body)).not.toContain("password-1");

    const capabilities = await request(server)
      .get(`${CONTROL_PLANE_BASE_PATH}/capabilities`)
      .set("x-test-user", "user-1");
    expect(capabilities.status).toBe(200);
    expect(capabilities.body.version).toBe("0.1.0");

    const forbiddenSystem = await request(server)
      .get(`${CONTROL_PLANE_BASE_PATH}/system/info`)
      .set("x-test-user", "user-2");
    expect(forbiddenSystem.status).toBe(403);

    const system = await request(server)
      .get(`${CONTROL_PLANE_BASE_PATH}/system/info`)
      .set("x-test-user", "user-1")
      .set("x-request-id", "request-system-1");
    expect(system.status).toBe(200);
    expect(Object.keys(system.body)).toEqual(["version", "capabilities", "requestId"]);
    expect(system.body).toMatchObject({
      version: "0.1.0",
      requestId: "request-system-1",
      capabilities: { singleTenant: true, masking: true },
    });
    expect(system.body).not.toHaveProperty("secret");
    expect(system.body).not.toHaveProperty("database");
    expect(system.body).not.toHaveProperty("repository");

    const roles = await request(server)
      .get(`${CONTROL_PLANE_BASE_PATH}/roles`)
      .set("x-test-user", "user-1");
    expect(roles.status).toBe(200);
    expect(roles.body.items).toHaveLength(2);

    const sessions = await request(server)
      .get(`${CONTROL_PLANE_BASE_PATH}/sessions?limit=1`)
      .set("x-test-user", "user-1");
    expect(sessions.status).toBe(200);
    expect(sessions.body.items.map((item: { id: string }) => item.id)).toEqual(["session-1"]);
    expect(sessions.body.total).toBe(2);
    expect(sessions.body.hasMore).toBe(true);
    expect(sessions.body.nextCursor).toBeTruthy();
    expect(sessions.body.items[0]).not.toHaveProperty("token");
    expect(JSON.stringify(sessions.body)).not.toContain("raw-session-token");
    expect(JSON.stringify(sessions.body)).not.toContain("foreign-session-token");

    const invalidSessions = await request(server)
      .get(`${CONTROL_PLANE_BASE_PATH}/sessions?tenantId=other-tenant`)
      .set("x-test-user", "user-1");
    expect(invalidSessions.status).toBe(400);
    expect(invalidSessions.body.error).toMatchObject({
      code: "INVALID_REQUEST",
      details: { field: "tenantId" },
    });

    const audit = await request(server)
      .get(`${CONTROL_PLANE_BASE_PATH}/audit-events?limit=1`)
      .set("x-test-user", "user-1");
    expect(audit.status).toBe(200);
    expect(audit.body.items).toHaveLength(1);
    expect(audit.body.items[0].detail).toEqual({ safe: "visible", nested: {} });

    const auditDetail = await request(server)
      .get(`${CONTROL_PLANE_BASE_PATH}/audit-events/audit-1`)
      .set("x-test-user", "user-1");
    expect(auditDetail.status).toBe(200);
    expect(auditDetail.body.id).toBe("audit-1");
    expect(auditDetail.body.detail).toEqual({ safe: "visible", nested: {} });
    expect(JSON.stringify(auditDetail.body)).not.toContain("raw-password");
    expect(JSON.stringify(auditDetail.body)).not.toContain("raw-token");
    expect(JSON.stringify(auditDetail.body)).not.toContain("raw-secret");
    expect(JSON.stringify(auditDetail.body)).not.toContain("raw-hash");
    expect(JSON.stringify(auditDetail.body)).not.toContain("raw-api-key");
    expect(JSON.stringify(auditDetail.body)).not.toContain("database-secret");

    const missingAudit = await request(server)
      .get(`${CONTROL_PLANE_BASE_PATH}/audit-events/missing`)
      .set("x-test-user", "user-1");
    expect(missingAudit.status).toBe(404);
    expect(missingAudit.body.error.code).toBe("NOT_FOUND");

    const invalidAudit = await request(server)
      .get(`${CONTROL_PLANE_BASE_PATH}/audit-events/%20`)
      .set("x-test-user", "user-1");
    expect(invalidAudit.status).toBe(400);
    expect(invalidAudit.body.error.details).toEqual({ field: "id" });

    const missing = await request(server)
      .get(`${CONTROL_PLANE_BASE_PATH}/users/missing`)
      .set("x-test-user", "user-1");
    expect(missing.status).toBe(404);
    expect(missing.body.error.code).toBe("NOT_FOUND");

    await app.close();
  });
});
