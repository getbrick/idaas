import "reflect-metadata";
import { createHash, randomBytes } from "node:crypto";
import { afterAll, describe, expect, it } from "vitest";
import { Test } from "@nestjs/testing";
import { Controller, Get, Module } from "@nestjs/common";
import request from "supertest";
import { CurrentUser } from "@getbrick/idaas-nestjs";
import { buildTableMap } from "@getbrick/idaas-core";
import { ApplicationService } from "@getbrick/idaas-control-plane";
import { idaas } from "../getbrick.config.js";

const previousOidcClientSecret = process.env.OIDC_CLIENT_SECRET;
process.env.OIDC_CLIENT_SECRET = "local-demo-client-secret";
const { AppModule } = await import("../src/app.module.js");
const { applicationRepository, findOidcUser, oidcAdapter, pool, secretBindingRepository } = await import("../src/auth.js");
const quotedUserTable = `"${buildTableMap(idaas.tables).user.replace(/"/g, '""')}"`;

@Controller("me")
class MeController {
  @Get()
  me(@CurrentUser() user: Record<string, unknown> | undefined) {
    return { email: user?.email };
  }
}

@Module({
  imports: [AppModule],
  controllers: [MeController],
})
class ExampleAppModule {}

describe("nestjs-postgres example e2e", () => {
  it("signs up against real postgres and protects routes", async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [ExampleAppModule],
    }).compile();
    const app = moduleRef.createNestApplication();
    (app as unknown as { useBodyParser: (type: string) => void }).useBodyParser("json");
    await app.init();

    const server = app.getHttpServer();
    const email = `e2e-${Date.now()}@example.com`;

    const signUp = await request(server)
      .post("/api/auth/sign-up/email")
      .send({ email, password: "supersecret123", name: "E2E" });
    expect(signUp.status).toBe(200);

    const cookies = ((signUp.headers["set-cookie"] ?? []) as unknown as string[])
      .map((c) => c.split(";")[0])
      .join("; ");
    expect(cookies).toBeTruthy();

    const meAuthed = await request(server).get("/me").set("Cookie", cookies);
    expect(meAuthed.status).toBe(200);
    expect(meAuthed.body.email).toBe(email);

    const meUnauthed = await request(server).get("/me");
    expect(meUnauthed.status).toBe(401);

    const health = await request(server).get("/api/idaas/v1/health/live");
    expect(health.status).toBe(200);
    expect(health.body).toMatchObject({
      status: "ok",
      service: "idaas-control-plane",
    });

    const usersUnauthed = await request(server).get("/api/idaas/v1/users");
    expect(usersUnauthed.status).toBe(401);

    const discovery = await request(server).get("/oidc/.well-known/openid-configuration");
    expect(discovery.status).toBe(200);
    expect(discovery.body.issuer).toBe("http://localhost:3000/oidc");

    const jwks = await request(server).get("/oidc/jwks");
    expect(jwks.status).toBe(200);
    expect(jwks.body.keys.length).toBeGreaterThan(0);

    await app.close();
  });

  it("does not resolve banned users for OIDC", async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [ExampleAppModule],
    }).compile();
    const app = moduleRef.createNestApplication();
    (app as unknown as { useBodyParser: (type: string) => void }).useBodyParser("json");
    await app.init();
    try {
      const email = `banned-${Date.now()}@example.com`;
      const signUp = await request(app.getHttpServer())
        .post("/api/auth/sign-up/email")
        .send({ email, password: "supersecret123", name: "Banned User" });
      expect(signUp.status).toBe(200);
      const userId = String(signUp.body.user.id);
      await pool.query(`UPDATE ${quotedUserTable} SET banned = true WHERE id = $1`, [userId]);
      await expect(findOidcUser(userId)).resolves.toBeNull();
      await pool.query(`UPDATE ${quotedUserTable} SET banned = false WHERE id = $1`, [userId]);
    } finally {
      await app.close();
    }
  });

  it("completes an OIDC code flow through the postgres adapter", async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [ExampleAppModule],
    }).compile();
    const app = moduleRef.createNestApplication();
    (app as unknown as { useBodyParser: (type: string) => void }).useBodyParser("json");
    await app.init();
    const server = app.getHttpServer();
    const agent = request.agent(server);
    const email = `oidc-e2e-${Date.now()}@example.com`;
    const signUp = await agent
      .post("/api/auth/sign-up/email")
      .send({ email, password: "supersecret123", name: "OIDC E2E" });
    expect(signUp.status).toBe(200);
    const userId = String(signUp.body.user.id);
    const verifier = "a".repeat(64);
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const authorization = await agent.get("/oidc/auth").query({
      client_id: "getbrick-demo-client",
      redirect_uri: "http://localhost:3000/demo/callback",
      response_type: "code",
      scope: "openid profile email",
      state: "example-state",
      nonce: "example-nonce",
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    expect(authorization.status).toBe(303);
    let nextUrl = new URL(String(authorization.headers.location), "http://localhost:3000");
    let callbackResponse: Awaited<ReturnType<typeof agent.get>> | undefined;
    for (let step = 0; step < 6; step += 1) {
      const response = await agent.get(`${nextUrl.pathname}${nextUrl.search}`);
      expect(response.status).toBe(303);
      const location = new URL(String(response.headers.location), "http://localhost:3000");
      if (location.origin + location.pathname === "http://localhost:3000/demo/callback") {
        callbackResponse = response;
        break;
      }
      nextUrl = location;
    }
    expect(callbackResponse).toBeTruthy();
    const callbackUrl = new URL(String(callbackResponse!.headers.location), "http://localhost:3000");
    const code = callbackUrl.searchParams.get("code");
    expect(code).toBeTruthy();
    const token = await agent.post("/oidc/token").type("form").send({
      grant_type: "authorization_code",
      code,
      redirect_uri: "http://localhost:3000/demo/callback",
      client_id: "getbrick-demo-client",
      client_secret: "local-demo-client-secret",
      code_verifier: verifier,
    });
    expect(token.status).toBe(200);
    expect(token.body.id_token).toBeTruthy();
    const payload = JSON.parse(
      Buffer.from(String(token.body.id_token).split(".")[1] ?? "", "base64url").toString("utf8"),
    ) as Record<string, unknown>;
    expect(payload.sub).toBe(userId);
    const userInfo = await agent
      .get("/oidc/me")
      .set("Authorization", `Bearer ${token.body.access_token}`);
    expect(userInfo.status).toBe(200);
    expect(userInfo.body.email).toBe(email);
    await app.close();
  });

  it("uses a managed OIDC client stored in postgres", async () => {
    const previousSecret = process.env.OIDC_CLIENT_SECRET;
    process.env.OIDC_CLIENT_SECRET = "dynamic-client-secret";
    const moduleRef = await Test.createTestingModule({
      imports: [ExampleAppModule],
    }).compile();
    const app = moduleRef.createNestApplication();
    (app as unknown as { useBodyParser: (type: string) => void }).useBodyParser("json");
    await app.init();
    const server = app.getHttpServer();
    const agent = request.agent(server);
    const signUp = await agent.post("/api/auth/sign-up/email").send({
      email: `dynamic-oidc-${Date.now()}@example.com`,
      password: "supersecret123",
      name: "Dynamic OIDC User",
    });
    expect(signUp.status).toBe(200);
    const service = new ApplicationService(applicationRepository, { secretBindings: secretBindingRepository });

    const admin = { user: { id: "dynamic-client-admin" }, permissions: ["*:*"] };
    const application = await service.createApplication({
      name: `Dynamic OIDC ${Date.now()}`,
      slug: `dynamic-oidc-${Date.now()}`,
    }, admin);
    let clientRecordId: string | undefined;
    try {
      const managedClient = await service.createClient(application.id, {
        clientId: `dynamic-client-${Date.now()}`,
        redirectUris: ["http://localhost:3000/demo/callback"],
        grantTypes: ["authorization_code"],
        responseTypes: ["code"],
        scopes: ["openid", "profile", "email"],
        tokenEndpointAuthMethod: "client_secret_basic",
        secretRef: "env:OIDC_CLIENT_SECRET",
      }, admin);
      clientRecordId = managedClient.id;
      const verifier = "b".repeat(64);
      const challenge = createHash("sha256").update(verifier).digest("base64url");
      const authorization = await agent.get("/oidc/auth").query({
        client_id: managedClient.clientId,
        redirect_uri: "http://localhost:3000/demo/callback",
        response_type: "code",
        scope: "openid profile email",
        state: "dynamic-state",
        nonce: "dynamic-nonce",
        code_challenge: challenge,
        code_challenge_method: "S256",
      });
      expect(authorization.status).toBe(303);
      let nextUrl = new URL(String(authorization.headers.location), "http://localhost:3000");
      let callbackResponse: Awaited<ReturnType<typeof agent.get>> | undefined;
      for (let step = 0; step < 6; step += 1) {
        const response = await agent.get(`${nextUrl.pathname}${nextUrl.search}`);
        expect(response.status).toBe(303);
        const location = new URL(String(response.headers.location), "http://localhost:3000");
        if (location.origin + location.pathname === "http://localhost:3000/demo/callback") {
          callbackResponse = response;
          break;
        }
        nextUrl = location;
      }
      expect(callbackResponse).toBeTruthy();
      const callbackUrl = new URL(String(callbackResponse!.headers.location), "http://localhost:3000");
      const token = await agent.post("/oidc/token").type("form").send({
        grant_type: "authorization_code",
        code: callbackUrl.searchParams.get("code"),
        redirect_uri: "http://localhost:3000/demo/callback",
        client_id: managedClient.clientId,
        client_secret: "dynamic-client-secret",
        code_verifier: verifier,
      });
      expect(token.status).toBe(200);
      expect(token.body.id_token).toBeTruthy();
    } finally {
      if (clientRecordId) await service.deleteClient(application.id, clientRecordId, admin);
      await service.deleteApplication(application.id, admin);
      await app.close();
      if (previousSecret === undefined) delete process.env.OIDC_CLIENT_SECRET;
      else process.env.OIDC_CLIENT_SECRET = previousSecret;
    }
  });

  it("persists WeChat application channels and managed OIDC clients", async () => {
    const service = new ApplicationService(applicationRepository, { secretBindings: secretBindingRepository });
    const actor = { user: { id: "application-admin" }, permissions: ["*:*"] };
    const application = await service.createApplication({
      name: `WeChat App ${Date.now()}`,
      slug: `wechat-app-${Date.now()}`,
    }, actor);
    try {
      const official = await service.createPlatform(application.id, {
        type: "wechat_official_account",
        externalAppId: "wx-official-example",
        displayName: "微信公众号",
        loginMode: "oauth_code",
        scope: "snsapi_userinfo",
        secretRef: "env:WECHAT_OFFICIAL_SECRET",
      }, actor);
      const miniProgram = await service.createPlatform(application.id, {
        type: "wechat_mini_program",
        externalAppId: "wx-mini-example",
        displayName: "微信小程序",
        loginMode: "code_exchange",
        secretRef: "env:WECHAT_MINI_SECRET",
      }, actor);
      const client = await service.createClient(application.id, {
        clientId: `wechat-client-${Date.now()}`,
        redirectUris: ["https://client.example.test/callback"],
        grantTypes: ["authorization_code", "refresh_token"],
        responseTypes: ["code"],
        scopes: ["openid", "profile", "offline_access"],
        tokenEndpointAuthMethod: "client_secret_basic",
        secretRef: "env:OIDC_CLIENT_SECRET",
      }, actor);
      expect(official.type).toBe("wechat_official_account");
      expect(miniProgram.type).toBe("wechat_mini_program");
      expect(miniProgram.credentialConfigured).toBe(true);
      expect(client.hasSecret).toBe(true);
      expect(JSON.stringify({ official, miniProgram, client })).not.toContain("WECHAT_OFFICIAL_SECRET");
    } finally {
      await service.deleteClient(application.id, (await service.listClients(application.id, {}, actor)).items[0]!.id, actor);
      const platforms = await service.listPlatforms(application.id, {}, actor);
      for (const platform of platforms.items) await service.deletePlatform(application.id, platform.id, actor);
      await service.deleteApplication(application.id, actor);
    }
  });

  it("atomically consumes a persisted authorization code", async () => {
    const adapter = oidcAdapter("AuthorizationCode");
    const id = `test-${Date.now()}-${randomBytes(8).toString("base64url")}`;
    await adapter.upsert(id, { exp: Math.floor(Date.now() / 1000) + 60 }, 60);
    const results = await Promise.allSettled([
      adapter.consume(id),
      adapter.consume(id),
    ]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
    await adapter.destroy(id);
  });
});

afterAll(async () => {
  await pool.end();
  if (previousOidcClientSecret === undefined) delete process.env.OIDC_CLIENT_SECRET;
  else process.env.OIDC_CLIENT_SECRET = previousOidcClientSecret;
});
