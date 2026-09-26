import "reflect-metadata";
import { describe, expect, it } from "vitest";
import { Test } from "@nestjs/testing";
import request from "supertest";
import type { GetbrickAuthLike } from "@getbrick/idaas-nestjs";
import {
  APPLICATION_MANAGEMENT_BASE_PATH,
  ApplicationManagementModule,
  ApplicationService,
  InMemoryApplicationRepository,
  SqlApplicationRepository,
  createApplicationManagementMigrationSql,
  validateApplicationSqlIdentifier,
} from "../src/index.js";

const basePath = APPLICATION_MANAGEMENT_BASE_PATH;

function actor(permissions: string[], id = "actor") {
  return { user: { id }, permissions };
}

function allActor() {
  return actor([
    "applications:read",
    "applications:write",
    "applications:enable",
    "applications:disable",
    "applications:archive",
    "applications:restore",
    "applications:purge",
    "application-platforms:read",
    "application-platforms:write",
    "application-platforms:enable",
    "application-platforms:disable",
    "application-platforms:archive",
    "application-platforms:restore",
    "application-platforms:purge",
    "application-platforms:rotate-secret",
    "application-platforms:revoke-secret",
    "application-clients:read",
    "application-clients:write",
    "application-clients:enable",
    "application-clients:disable",
    "application-clients:archive",
    "application-clients:restore",
    "application-clients:purge",
    "application-clients:rotate-secret",
    "application-clients:revoke-secret",
  ]);
}

describe("ApplicationService", () => {
  it("supports directory pagination, search, status filters, CRUD and auditing", async () => {
    const repository = new InMemoryApplicationRepository({
      applications: [
        { id: "app-1", name: "Alpha", slug: "alpha", status: "active" },
        { id: "app-2", name: "Beta", slug: "beta", status: "disabled" },
        { id: "foreign", tenantId: "other", name: "Foreign", slug: "foreign", status: "active" },
      ],
    });
    const service = new ApplicationService(repository);
    const first = await service.listApplications({ limit: 1 }, allActor());
    expect(first.items.map((item) => item.id)).toEqual(["app-1"]);
    expect(first.total).toBe(2);
    expect(first.hasMore).toBe(true);
    expect(first.nextCursor).toBeTruthy();
    const second = await service.listApplications({ limit: 1, cursor: first.nextCursor }, allActor());
    expect(second.items.map((item) => item.id)).toEqual(["app-2"]);
    expect((await service.listApplications({ search: "foreign" }, allActor())).total).toBe(0);
    expect((await service.listApplications({ status: "disabled" }, allActor())).items[0]?.id).toBe("app-2");

    const created = await service.createApplication({ name: "Gamma", slug: "gamma" }, allActor());
    expect(created).toMatchObject({ name: "Gamma", slug: "gamma", status: "active" });
    await expect(service.createApplication({ name: "Other", slug: "GAMMA" }, allActor())).rejects.toMatchObject({
      code: "CONFLICT",
      statusCode: 409,
    });
    expect((await service.updateApplication(created.id, { name: "Gamma updated" }, allActor())).name).toBe("Gamma updated");
    await expect(service.disableApplication(created.id, allActor())).resolves.toMatchObject({ status: "disabled" });
    await expect(service.disableApplication(created.id, allActor())).rejects.toMatchObject({ code: "CONFLICT" });
    await expect(service.enableApplication(created.id, allActor())).resolves.toMatchObject({ status: "active" });

    const platform = await service.createPlatform(created.id, {
      type: "web",
      displayName: "Web",
      endpointUrl: "https://login.example.test/callback",
      secretRef: "vault://applications/gamma",
    }, allActor());
    expect(platform).toMatchObject({ type: "web", credentialConfigured: true });
    expect(platform).not.toHaveProperty("secret");
    expect(platform).not.toHaveProperty("secretRef");
    expect(JSON.stringify(platform)).not.toContain("vault://applications/gamma");
    expect((await service.updatePlatform(created.id, platform.id, { loginMode: "redirect" }, allActor())).loginMode).toBe("redirect");

    const client = await service.createClient(created.id, {
      clientId: "gamma-client",
      redirectUris: ["https://client.example.test/callback"],
      postLogoutRedirectUris: ["https://client.example.test/logout"],
      grantTypes: ["authorization_code", "refresh_token"],
      responseTypes: ["code"],
      scopes: ["openid", "profile"],
      tokenEndpointAuthMethod: "client_secret_basic",
      requirePkce: true,
      secretRef: "vault://applications/gamma-client",
    }, allActor());
    expect(client).toMatchObject({
      id: expect.any(String),
      applicationId: created.id,
      clientId: "gamma-client",
      status: "active",
      hasSecret: true,
      requirePkce: true,
    });
    expect(client).not.toHaveProperty("secret");
    expect(client).not.toHaveProperty("secretRef");
    expect((await service.listClients(created.id, {}, allActor())).items[0]?.clientId).toBe("gamma-client");
    await expect(service.createClient(created.id, { clientId: "gamma-client", redirectUris: ["https://client.example.test/callback"], tokenEndpointAuthMethod: "none" }, allActor())).rejects.toMatchObject({ code: "CONFLICT" });
    await expect(service.disableClient(created.id, client.id, allActor())).resolves.toMatchObject({ status: "disabled" });
    await expect(service.disableClient(created.id, client.id, allActor())).rejects.toMatchObject({ code: "CONFLICT" });

    const audit = repository.snapshot().auditEvents;
    expect(audit.map((event) => event.event)).toEqual(expect.arrayContaining([
      "application.created",
      "application.updated",
      "application.enabled",
      "application.disabled",
      "application-platform.created",
      "application-client.created",
    ]));
    expect(JSON.stringify(audit)).not.toContain("vault://applications/gamma");
    expect(JSON.stringify(audit)).not.toContain("vault://applications/gamma");
  });

  it("enforces permissions and rejects tenant, sensitive, arbitrary and unsafe fields", async () => {
    const repository = new InMemoryApplicationRepository({
      applications: [{ id: "app-1", name: "Alpha", slug: "alpha", status: "active" }],
      platforms: [{ id: "platform-1", applicationId: "app-1", type: "web", status: "active" }],
      clients: [{
        id: "client-1",
        applicationId: "app-1",
        clientId: "client-1",
        status: "active",
        tokenEndpointAuthMethod: "none",
        redirectUris: ["https://client.example.test/callback"],
        grantTypes: ["authorization_code"],
        responseTypes: ["code"],
        scopes: ["openid"],
      }],
    });
    const service = new ApplicationService(repository);
    await expect(service.listApplications({}, undefined)).rejects.toMatchObject({ code: "UNAUTHENTICATED", statusCode: 401 });
    await expect(service.listApplications({}, actor(["application-platforms:read"]))).rejects.toMatchObject({ code: "FORBIDDEN", statusCode: 403 });
    await expect(service.listApplications({ tenantId: "other" }, allActor())).rejects.toMatchObject({ statusCode: 400 });
    await expect(service.createApplication({ name: "Alpha", slug: "alpha", metadata: { any: true } } as never, allActor())).rejects.toMatchObject({ statusCode: 400 });
    await expect(service.createApplication({ name: "Alpha", slug: "alpha", secret: "raw" } as never, allActor())).rejects.toMatchObject({ statusCode: 400 });
    await expect(service.createPlatform("app-1", { type: "web", endpointUrl: "https://user:pass@example.test/callback" }, allActor())).rejects.toMatchObject({ statusCode: 400 });
    await expect(service.createPlatform("app-1", { type: "web", endpointUrl: "https://example.test/callback?token=raw" }, allActor())).rejects.toMatchObject({ statusCode: 400 });
    await expect(service.createPlatform("app-1", { type: "bad/type" }, allActor())).rejects.toMatchObject({ statusCode: 400 });
    await expect(service.createClient("app-1", { clientId: "client-1", secret: "raw" } as never, allActor())).rejects.toMatchObject({ statusCode: 400 });
    await expect(service.createClient("app-1", { clientId: "client-2", redirectUris: ["https://client.example.test/callback"] }, allActor())).rejects.toMatchObject({ statusCode: 400 });
    await expect(service.createClient("app-1", {
      clientId: "client-3",
      redirectUris: ["https://client.example.test/callback"],
      grantTypes: ["authorization_code", "client_credentials"],
      tokenEndpointAuthMethod: "none",
    } as never, allActor())).rejects.toMatchObject({ statusCode: 400 });
    await expect(service.createClient("app-1", {
      clientId: "client-4",
      redirectUris: ["https://client.example.test/callback"],
      responseTypes: ["code", "token"],
      tokenEndpointAuthMethod: "none",
    } as never, allActor())).rejects.toMatchObject({ statusCode: 400 });
    const appOnlyWriter = actor(["applications:read", "applications:write"]);
    await expect(service.deleteApplication("app-1", {}, appOnlyWriter)).rejects.toMatchObject({ code: "FORBIDDEN", statusCode: 403 });
  });

  it("does not expose seeded credential material", async () => {
    const repository = new InMemoryApplicationRepository({
      applications: [{ id: "app-1", name: "Alpha", slug: "alpha", status: "active" }],
      platforms: [{ id: "platform-1", applicationId: "app-1", type: "web", redirectUris: [], status: "active", secretRef: "vault://platform-secret" }],
      clients: [{ id: "client-1", applicationId: "app-1", clientId: "client-1", status: "active", redirectUris: [], postLogoutRedirectUris: [], grantTypes: [], responseTypes: [], scopes: [], secretRef: "vault://client-secret" }],
    });
    const service = new ApplicationService(repository);
    const platforms = await service.listPlatforms("app-1", {}, allActor());
    const clients = await service.listClients("app-1", {}, allActor());
    expect(platforms.items[0]).toMatchObject({ credentialConfigured: true });
    expect(clients.items[0]).toMatchObject({ hasSecret: true });
    expect(JSON.stringify(platforms)).not.toContain("vault://platform-secret");
    expect(JSON.stringify(clients)).not.toContain("vault://client-secret");
  });
});

describe("ApplicationController", () => {
  it("protects routes, exposes CRUD and maps invalid input through the control-plane filter", async () => {
    const repository = new InMemoryApplicationRepository();
    const auth: GetbrickAuthLike = {
      api: {
        getSession: async ({ headers }) => {
          const id = headers.get("x-test-user");
          return id ? { user: { id, role: id === "reader" ? "reader" : "writer" } } : null;
        },
      },
      handler: async () => new Response("ok"),
    };
    const moduleRef = await Test.createTestingModule({
      imports: [ApplicationManagementModule.forRoot({
        auth,
        repository,
        rbac: {
          reader: { permissions: ["applications:read"] },
          writer: { permissions: ["*:*"] },
        },
      })],
    }).compile();
    const app = moduleRef.createNestApplication();
    await app.init();
    const server = app.getHttpServer();

    const unauthenticated = await request(server).get(`${basePath}/applications`);
    expect(unauthenticated.status).toBe(401);
    expect(unauthenticated.body.error.code).toBe("UNAUTHENTICATED");
    const forbidden = await request(server).get(`${basePath}/applications`).set("x-test-user", "reader");
    expect(forbidden.status).toBe(200);
    const platformForbidden = await request(server).get(`${basePath}/applications/app-1/platforms`).set("x-test-user", "reader");
    expect(platformForbidden.status).toBe(403);

    const created = await request(server)
      .post(`${basePath}/applications`)
      .set("x-test-user", "writer")
      .send({ name: "HTTP App", slug: "http-app" });
    expect(created.status).toBe(201);
    expect(created.body).toMatchObject({ name: "HTTP App", slug: "http-app", status: "active" });
    const appId = created.body.id as string;

    const invalidTenant = await request(server)
      .post(`${basePath}/applications`)
      .set("x-test-user", "writer")
      .send({ name: "Bad", slug: "bad", tenantId: "other" });
    expect(invalidTenant.status).toBe(400);
    expect(invalidTenant.body.error.details).toEqual({ field: "tenantId" });

    const platform = await request(server)
      .post(`${basePath}/applications/${appId}/platforms`)
      .set("x-test-user", "writer")
       .send({ type: "wechat_mini_program", externalAppId: "wx-mini", endpointUrl: "https://example.test/endpoint", secretRef: "vault://platform" });

    expect(platform.status).toBe(201);
    expect(platform.body).toMatchObject({ type: "wechat_mini_program", credentialConfigured: true });
    expect(platform.body).not.toHaveProperty("secret");

    const client = await request(server)
      .post(`${basePath}/applications/${appId}/clients`)
      .set("x-test-user", "writer")
       .send({ clientId: "http-client", redirectUris: ["https://client.example.test/callback"], tokenEndpointAuthMethod: "none" });

    expect(client.status).toBe(201);
    expect(client.body).toMatchObject({ clientId: "http-client", hasSecret: false });
    const clientId = client.body.id as string;
    const updated = await request(server)
      .patch(`${basePath}/applications/${appId}/clients/${clientId}`)
      .set("x-test-user", "writer")
      .send({ scopes: ["openid"] });
    expect(updated.status).toBe(200);
    expect(updated.body.scopes).toEqual(["openid"]);
    const disabled = await request(server)
      .post(`${basePath}/applications/${appId}/clients/${clientId}/disable`)
      .set("x-test-user", "writer")
      .send({});
    expect(disabled.status).toBe(200);
    const conflict = await request(server)
      .post(`${basePath}/applications/${appId}/clients/${clientId}/disable`)
      .set("x-test-user", "writer")
      .send({});
    expect(conflict.status).toBe(409);
    expect(conflict.body.error.code).toBe("CONFLICT");

     const deletedClient = await request(server)
       .delete(`${basePath}/applications/${appId}/clients/${clientId}`)
       .set("x-test-user", "writer")
       .send({});
     expect(deletedClient.status).toBe(200);
     expect(deletedClient.body.status).toBe("archived");
     expect((await request(server).get(`${basePath}/applications/${appId}/clients`).set("x-test-user", "writer")).body.items).toHaveLength(1);

    const invalidUrl = await request(server)
      .post(`${basePath}/applications/${appId}/platforms`)
      .set("x-test-user", "writer")
      .send({ type: "web", endpointUrl: "https://example.test/callback#fragment" });
    expect(invalidUrl.status).toBe(400);

    await app.close();
  });
});

describe("application SQL migration", () => {
  it("uses validated identifiers, parameterized tenant values and secret references", async () => {
    const calls: Array<{ text: string; values: readonly unknown[] }> = [];
    const query = async (text: string, values: readonly unknown[]): Promise<unknown> => {
      calls.push({ text, values });
      if (text.includes("COUNT(*)")) return { rows: [{ total: 1 }] };
      if (text.includes("FROM \"gb_idaas_application\"")) {
        return { rows: [{ id: "app-1", tenant_id: "tenant", name: "Alpha", slug: "alpha", status: "active" }] };
      }
      return { rows: [] };
    };
    const repository = new SqlApplicationRepository({ query, tenantId: "tenant" });
    const page = await repository.listApplications({ search: "alpha" });
    expect(page.items[0]?.id).toBe("app-1");
    expect(calls.some((call) => call.values.includes("tenant"))).toBe(true);
    expect(calls.every((call) => !call.text.includes("alpha"))).toBe(true);
    expect(() => validateApplicationSqlIdentifier("gb_idaas_application; DROP TABLE users")).toThrow();

    const migration = createApplicationManagementMigrationSql();
    expect(migration).toContain("gb_idaas_application");
    expect(migration).toContain("gb_idaas_application_platform");
    expect(migration).toContain("gb_idaas_application_client");
    expect(migration).toContain("secret_ref");
     expect(migration).toContain("CREATE UNIQUE INDEX");
     expect(migration).toContain("LOWER(\"slug\")");
     expect(migration).toContain("LOWER(\"client_id\")");
     expect(migration).toContain("ALTER TABLE");
     expect(migration).toContain("require_pkce");

    expect(migration).not.toMatch(/\bsecret\b/);
  });
});
