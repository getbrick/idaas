import "reflect-metadata";
import { describe, expect, it, vi } from "vitest";
import { Test } from "@nestjs/testing";
import { Controller, Get, Module } from "@nestjs/common";
import { APP_GUARD } from "@nestjs/core";
import request from "supertest";
import express from "express";
import { memoryAdapter } from "better-auth/adapters/memory";
import { buildTableMap, createIdaas, type RoleGraph } from "@getbrick/idaas-core";
import {
  GetbrickIdaasModule,
  GetbrickAuthGuard,
  GetbrickAuthMiddleware,
  CurrentUser,
  DataScope,
  EffectivePermissions,
  CurrentOrganization,
  CurrentMember,
  GetDataScope,
  GetbrickPermissions,
  GetbrickRoles,
  CurrentSession,
  Public,
  RequireOrganization,
  GETBRICK_PUBLIC,
  isAuthPath,
  type GetbrickAuthLike,
} from "../src/index.js";

@Controller("me")
class MeController {
  @Get()
  me(@CurrentUser() user: Record<string, unknown> | undefined) {
    return { email: user?.email };
  }
}

@Controller("public")
class PublicController {
  @Get()
  @Public()
  read() {
    return { ok: true };
  }
}

@Controller("session")
class SessionController {
  @Get()
  read(@CurrentSession() session: Record<string, unknown> | undefined) {
    return session;
  }
}

@Controller("organization")
class OrganizationController {
  @Get("required")
  @RequireOrganization()
  required() {
    return { ok: true };
  }

  @Get("optional")
  optional() {
    return { ok: true };
  }
}

@Controller("projects")
class ProjectsController {
  @Get("admin-only")
  @GetbrickRoles("admin")
  adminOnly() {
    return { ok: true };
  }

  @Get()
  @GetbrickPermissions("project:read")
  list(@GetDataScope("project") scope: string, @EffectivePermissions() perms: string[]) {
    return { scope, perms };
  }

  @Get("write")
  @GetbrickPermissions("project:write")
  write() {
    return { ok: true };
  }

  @Get("org")
  @GetbrickPermissions("project:read")
  org(
    @CurrentOrganization() organization: Record<string, unknown> | undefined,
    @CurrentMember() member: Record<string, unknown> | undefined,
  ) {
    return { slug: organization?.slug, memberRole: member?.role };
  }
}

const TEST_ROLE_GRAPH: RoleGraph = {
  user: { extends: [], permissions: [] },
  member: { extends: ["user"], permissions: ["project:read:own"] },
  owner: { extends: ["member"], permissions: ["project:write"] },
  admin: { extends: ["owner"], permissions: ["*:*"] },
};

function createAuth(features: Record<string, boolean> = {}) {
  const tables = buildTableMap();
  const data: Record<string, Record<string, unknown>[]> = {};
  for (const name of Object.values(tables)) data[name] = [];
  const auth = createIdaas({
    config: { appName: "E2E", baseURL: "http://localhost", lockout: { maxAttempts: 1000, windowSeconds: 600 }, features },
    database: memoryAdapter(data as any),
  });
  return { auth, data, userTable: tables.user };
}

@Module({
  imports: [GetbrickIdaasModule.forRoot({ auth: createAuth().auth })],
  controllers: [MeController, PublicController, SessionController],
})
class BasicAppModule {}

@Module({
  imports: [GetbrickIdaasModule.forRoot({ auth: createAuth().auth, guard: "manual" })],
  controllers: [MeController, PublicController],
  providers: [{ provide: APP_GUARD, useClass: GetbrickAuthGuard }],
})
class ManualAppModule {}

describe("nestjs adapter e2e", () => {
  it("signs up via proxied handler and protects routes", async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [BasicAppModule],
    }).compile();
    const app = moduleRef.createNestApplication();
    app.use(express.json());
    await app.init();

    const server = app.getHttpServer();

    const signUp = await request(server)
      .post("/api/auth/sign-up/email")
      .send({ email: "u@example.com", password: "supersecret123", name: "U" });
    expect(signUp.status).toBe(200);

    const cookies = ((signUp.headers["set-cookie"] ?? []) as unknown as string[])
      .map((c) => c.split(";")[0])
      .join("; ");
    expect(cookies).toBeTruthy();

    const meUnauthed = await request(server).get("/me");
    expect(meUnauthed.status).toBe(401);

    const publicUnauthed = await request(server).get("/public");
    expect(publicUnauthed.status).toBe(200);
    expect(Reflect.getMetadata(GETBRICK_PUBLIC, PublicController.prototype.read)).toBe(true);

    const meAuthed = await request(server)
      .get("/me")
      .set("Cookie", cookies);
    expect(meAuthed.status).toBe(200);
    expect(meAuthed.body.email).toBe("u@example.com");

    const session = await request(server)
      .get("/session")
      .set("Cookie", cookies);
    expect(session.status).toBe(200);
    expect(session.body.session).toBeDefined();
    expect(session.body.session).not.toHaveProperty("token");

    await app.close();
  });

  it("supports explicit manual guard registration", async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [ManualAppModule],
    }).compile();
    const app = moduleRef.createNestApplication();
    app.use(express.json());
    await app.init();
    const server = app.getHttpServer();

    const publicResponse = await request(server).get("/public");
    expect(publicResponse.status).toBe(200);

    const protectedResponse = await request(server).get("/me");
    expect(protectedResponse.status).toBe(401);

    await app.close();
  });

  it("returns unauthorized when session lookup fails", async () => {
    const auth = {
      api: {
        getSession: vi.fn().mockRejectedValue(new Error("session backend secret")),
      },
      handler: vi.fn(),
    } as unknown as GetbrickAuthLike;
    const moduleRef = await Test.createTestingModule({
      imports: [GetbrickIdaasModule.forRoot({ auth })],
      controllers: [MeController],
    }).compile();
    const app = moduleRef.createNestApplication();
    app.use(express.json());
    await app.init();

    const response = await request(app.getHttpServer()).get("/me");
    expect(response.status).toBe(401);
    expect(JSON.stringify(response.body)).not.toContain("session backend secret");

    await app.close();
  });

  it("uses a bounded auth path and hides middleware exceptions", async () => {
    const auth = {
      api: { getSession: vi.fn() },
      handler: vi.fn().mockRejectedValue(new Error("raw middleware secret")),
    } as unknown as GetbrickAuthLike;
    const middleware = new GetbrickAuthMiddleware(auth);
    const json = vi.fn();
    const response = {
      headersSent: false,
      status: vi.fn().mockReturnThis(),
      json,
      end: vi.fn(),
    };

    await middleware.use(
      { originalUrl: "/api/auth/test", method: "GET", headers: {} },
      response,
      vi.fn(),
    );

    expect(isAuthPath("/api/authorized")).toBe(false);
    expect(isAuthPath("/custom/auth/sign-in", "/custom/auth/")).toBe(true);
    expect(response.status).toHaveBeenCalledWith(500);
    expect(json).toHaveBeenCalledWith({ message: "Internal Server Error" });
    expect(JSON.stringify(json.mock.calls)).not.toContain("raw middleware secret");
  });

  it("supports an explicit auth base path", async () => {
    const auth = {
      api: { getSession: vi.fn() },
      handler: vi.fn().mockResolvedValue(new Response("ok")),
    } as unknown as GetbrickAuthLike;
    const moduleRef = await Test.createTestingModule({
      imports: [GetbrickIdaasModule.forRoot({ auth, basePath: "/custom/auth" })],
    }).compile();
    const app = moduleRef.createNestApplication();
    await app.init();

    const response = await request(app.getHttpServer()).get("/custom/auth/ping");
    expect(response.status).toBe(200);
    expect(response.text).toBe("ok");

    await app.close();
  });

  it("enforces roles, permission inheritance and data scope", async () => {
    const { auth, data, userTable } = createAuth();
    const moduleRef = await Test.createTestingModule({
      imports: [GetbrickIdaasModule.forRoot({ auth, rbac: TEST_ROLE_GRAPH })],
      controllers: [MeController, ProjectsController],
    }).compile();
    const app = moduleRef.createNestApplication();
    app.use(express.json());
    await app.init();
    const server = app.getHttpServer();

    const signUp = async (email: string) => {
      const res = await request(server)
        .post("/api/auth/sign-up/email")
        .send({ email, password: "supersecret123", name: email });
      expect(res.status).toBe(200);
      return ((res.headers["set-cookie"] ?? []) as unknown as string[])
        .map((c) => c.split(";")[0])
        .join("; ");
    };

    const memberCookie = await signUp("member@example.com");
    const ownerCookie = await signUp("owner@example.com");
    const adminCookie = await signUp("admin@example.com");

    const users = data[userTable];
    const byEmail = (email: string) => users.find((u: any) => u.email === email) as any;
    byEmail("member@example.com").role = "member";
    byEmail("owner@example.com").role = "owner";
    byEmail("admin@example.com").role = "admin";

    const adminOnly = await request(server)
      .get("/projects/admin-only")
      .set("Cookie", memberCookie);
    expect(adminOnly.status).toBe(403);

    const write = await request(server)
      .get("/projects/write")
      .set("Cookie", memberCookie);
    expect(write.status).toBe(403);

    const inheritedWrite = await request(server)
      .get("/projects/write")
      .set("Cookie", ownerCookie);
    expect(inheritedWrite.status).toBe(200);

    const list = await request(server)
      .get("/projects")
      .set("Cookie", memberCookie);
    expect(list.status).toBe(200);
    expect(list.body.scope).toBe("own");
    expect(list.body.perms).toContain("project:read:own");

    const adminList = await request(server)
      .get("/projects")
      .set("Cookie", adminCookie);
    expect(adminList.status).toBe(200);
    expect(adminList.body.scope).toBe("all");

    const adminRoute = await request(server)
      .get("/projects/admin-only")
      .set("Cookie", adminCookie);
    expect(adminRoute.status).toBe(200);

    await app.close();
  });

  it("fails closed only for routes that require organization context", async () => {
    const auth = {
      api: {
        getSession: vi.fn().mockResolvedValue({
          user: { id: "user-1" },
          session: { id: "session-1", activeOrganizationId: "org-1", token: "raw-token" },
        }),
        getActiveMember: vi.fn().mockRejectedValue(new Error("organization backend secret")),
        getFullOrganization: vi.fn().mockResolvedValue({ id: "org-1", slug: "acme" }),
      },
      handler: vi.fn(),
    } as unknown as GetbrickAuthLike;
    const moduleRef = await Test.createTestingModule({
      imports: [GetbrickIdaasModule.forRoot({ auth })],
      controllers: [OrganizationController],
    }).compile();
    const app = moduleRef.createNestApplication();
    app.use(express.json());
    await app.init();
    const server = app.getHttpServer();

    const required = await request(server).get("/organization/required");
    expect(required.status).toBe(403);

    const optional = await request(server).get("/organization/optional");
    expect(optional.status).toBe(200);

    await app.close();
  });

  it("merges organization member roles into effective permissions", async () => {
    const { auth } = createAuth({ organization: true });
    const moduleRef = await Test.createTestingModule({
      imports: [GetbrickIdaasModule.forRoot({ auth, rbac: TEST_ROLE_GRAPH })],
      controllers: [MeController, ProjectsController],
    }).compile();
    const app = moduleRef.createNestApplication();
    app.use(express.json());
    await app.init();
    const server = app.getHttpServer();

    const res = await request(server)
      .post("/api/auth/sign-up/email")
      .send({ email: "ceo@example.com", password: "supersecret123", name: "CEO" });
    expect(res.status).toBe(200);
    const cookie = ((res.headers["set-cookie"] ?? []) as unknown as string[])
      .map((c) => c.split(";")[0])
      .join("; ");

    const org = await request(server)
      .post("/api/auth/organization/create")
      .set("Cookie", cookie)
      .set("Origin", "http://localhost")
      .send({ name: "Acme", slug: "acme" });
    expect(org.status).toBe(200);

    const before = await request(server)
      .get("/projects/org")
      .set("Cookie", cookie);
    expect(before.status).toBe(200);
    expect(before.body.slug).toBe("acme");
    expect(before.body.memberRole).toBe("owner");

    await app.close();
  });
});
