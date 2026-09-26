import "reflect-metadata";
import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { Test } from "@nestjs/testing";
import request from "supertest";
import {
  ClientAuthBffController,
  ClientAuthBffModule,
  ClientAuthBffService,
  InMemoryClientAuthBffStateStore,
  SqlClientAuthBffStateStore,
  createClientAuthBffBindingHash,
  createSqlClientAuthBffStateStore,
  type ClientAuthBffSqlExecutor,
  type ClientAuthBffHostAdapter,
  type ClientAuthBffServiceOptions,
  type ClientAuthBffStateRecord,
  type ClientAuthBffTrustedClientConfiguration,
  type ClientAuthBffSessionService,
} from "../src/index.js";

const redirectUri = "https://app.example.test/oidc/callback";
const clientId = "uniapp-client";
const state = "state_abcdefghijklmnopqrstuvwxyz123456";
const nonce = "nonce_abcdefghijklmnopqrstuvwxyz123456";
const codeVerifier = "verifier_abcdefghijklmnopqrstuvwxyz123456789";
const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url");
const binding = "b".repeat(43);

function configuration(clientType: "web" | "native" = "web", uri = redirectUri): ClientAuthBffTrustedClientConfiguration {
  return {
    clientId,
    clientType,
    redirectUris: [uri],
    scopes: ["openid", "profile", "email"],
    issuer: "https://issuer.example.test",
    clientSecret: "server-only-secret",
  };
}

function startRequest(clientType: "web" | "native" = "web", uri = redirectUri) {
  return {
    redirectUri: uri,
    clientType,
    clientId,
    scope: "openid profile email",
    state,
    nonce,
    codeChallenge,
    codeChallengeMethod: "S256" as const,
  };
}

function exchangeRequest(uri = redirectUri, clientType: "web" | "native" = "web") {
  return {
    code: "authorization-code",
    codeVerifier,
    redirectUri: uri,
    state,
    clientId,
    clientType,
  };
}

function identity() {
  return {
    provider: "oidc",
    platform: "oidc",
    appId: clientId,
    subject: "subject-1",
    scopes: ["openid", "profile", "email"],
  };
}

function user() {
  return {
    id: "user-1",
    name: "Test User",
    email: "user@example.test",
    emailVerified: true,
    avatarUrl: "https://cdn.example.test/avatar.png",
  };
}

function adapter(overrides: Partial<ClientAuthBffHostAdapter> = {}): ClientAuthBffHostAdapter {
  return {
    createAuthorizationUrl: vi.fn(async (input) => {
      const url = new URL("https://provider.example.test/authorize");
      url.searchParams.set("client_id", input.clientId);
      url.searchParams.set("redirect_uri", input.redirectUri);
      url.searchParams.set("response_type", "code");
      url.searchParams.set("scope", input.scope);
      url.searchParams.set("state", input.state);
      url.searchParams.set("nonce", input.nonce);
      url.searchParams.set("code_challenge", input.codeChallenge);
      url.searchParams.set("code_challenge_method", input.codeChallengeMethod);
      return url;
    }),
    exchangeCode: vi.fn(async () => ({
      identity: identity(),
      session: {
        sessionReference: "native-session-reference",
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
        clientKind: "native" as const,
        user: user(),
      },
    })),
    ...overrides,
  };
}

function service(
  hostAdapter: ClientAuthBffHostAdapter = adapter(),
  options: Partial<ClientAuthBffServiceOptions> = {},
): ClientAuthBffService {
  return new ClientAuthBffService({
    adapter: hostAdapter,
    clientConfiguration: configuration(),
    ...options,
  });
}

function responseRecorder() {
  const headers: Record<string, string | string[]> = {};
  let status = 0;
  let body: unknown;
  let ended = false;
  const response = {
    setHeader(name: string, value: string | string[]) {
      headers[name] = value;
      return response;
    },
    getHeader(name: string) {
      return headers[name];
    },
    status(code: number) {
      status = code;
      return response;
    },
    json(value: unknown) {
      body = value;
      return response;
    },
    end(value?: unknown) {
      if (value !== undefined) body = value;
      ended = true;
      return response;
    },
  };
  return { response, headers, get status() { return status; }, get body() { return body; }, get ended() { return ended; } };
}

describe("client auth BFF", () => {
  it("starts an authorization transaction with the requested state, nonce, and PKCE challenge", async () => {
    const host = adapter();
    const bff = service(host);
    const result = await bff.start(startRequest(), { bindingHash: createClientAuthBffBindingHash(binding) });
    const url = new URL(result.authorizationUrl);
    expect(result).toMatchObject({ state, redirectUri, expiresAt: expect.any(String) });
    expect(url.searchParams.get("state")).toBe(state);
    expect(url.searchParams.get("nonce")).toBe(nonce);
    expect(url.searchParams.get("code_challenge")).toBe(codeChallenge);
    expect(host.createAuthorizationUrl).toHaveBeenCalledWith(expect.objectContaining({
      client: expect.objectContaining({ clientId, clientSecret: "server-only-secret" }),
      configuration: expect.objectContaining({ clientId }),
      nonce,
      codeChallenge,
    }));
  });

  it("rejects aliases, unknown fields, raw credentials, and malformed transaction values", async () => {
    const bff = service();
    const base = startRequest();
    const invalidBodies: unknown[] = [
      { ...base, clientKind: "web" },
      { ...base, access_token: "raw-token" },
      { ...base, userId: "user-1" },
      { ...base, tenantId: "tenant-1" },
      { ...base, state: "short" },
      { ...base, nonce: "short" },
      { ...base, codeChallenge: "bad" },
      { ...base, codeChallengeMethod: "plain" },
      { ...base, redirectUri: "javascript:alert(1)" },
    ];
    for (const body of invalidBodies) {
      await expect(bff.start(body, { bindingHash: createClientAuthBffBindingHash(binding) })).rejects.toMatchObject({ statusCode: 400 });
    }
    await expect(bff.start({ ...base, scope: "profile" }, { bindingHash: createClientAuthBffBindingHash(binding) })).rejects.toMatchObject({ statusCode: 400 });
  });

  it("rejects non-loopback HTTP authorization URLs and mismatched returned state", async () => {
    const unsafe = service(adapter({
      createAuthorizationUrl: async () => "http://provider.example.test/authorize?state=" + state,
    }));
    await expect(unsafe.start(startRequest(), { bindingHash: createClientAuthBffBindingHash(binding) })).rejects.toMatchObject({ statusCode: 400 });

    const mismatched = service(adapter({
      createAuthorizationUrl: async () => "https://provider.example.test/authorize?state=" + "x".repeat(state.length),
    }));
    await expect(mismatched.start(startRequest(), { bindingHash: createClientAuthBffBindingHash(binding) })).rejects.toMatchObject({ statusCode: 400 });
  });

  it("binds H5 start and exchange with an HttpOnly cookie, clears it, and filters host response headers", async () => {
    const host = adapter({
      exchangeCode: vi.fn(async () => new Response("host body must not escape", {
        status: 302,
        headers: {
          "Set-Cookie": "host_session=opaque-value; Path=/; HttpOnly; Secure; SameSite=Lax",
          "Cache-Control": "no-store",
          Pragma: "no-cache",
          Location: "https://evil.example.test/redirect?code=raw-code",
          "Content-Type": "text/plain",
        },
      })),
    });
    const bff = service(host);
    const controller = new ClientAuthBffController(bff);
    const startResponse = responseRecorder();
    await controller.start(startRequest(), { headers: { origin: "https://app.example.test" } }, startResponse.response);
    const setCookie = String(startResponse.headers["Set-Cookie"]);
    expect(setCookie).toContain("HttpOnly");
    expect(setCookie).toContain("Secure");
    expect(setCookie).toContain("SameSite=Lax");
    const cookie = setCookie.split(";")[0] ?? "";
    const exchangeResponse = responseRecorder();
    await controller.exchange(exchangeRequest(), { headers: { cookie, origin: "https://app.example.test" } }, exchangeResponse.response);
    expect(exchangeResponse.status).toBe(204);
    expect(exchangeResponse.body).toBeUndefined();
    expect(String(exchangeResponse.headers["Set-Cookie"])).toContain("host_session=opaque-value");
    expect(String(exchangeResponse.headers["Set-Cookie"])).toContain("Max-Age=0");
    expect(exchangeResponse.headers.Location).toBeUndefined();
    expect(exchangeResponse.headers["Content-Type"]).toBeUndefined();
    expect(exchangeResponse.headers["Cache-Control"]).toBe("no-store");
    expect(exchangeResponse.headers.Pragma).toBe("no-cache");
    expect(host.exchangeCode).toHaveBeenCalledWith(expect.objectContaining({ nonce, codeVerifier, codeChallenge }));
  });

  it("does not consume a state on a binding or client mismatch", async () => {
    const host = adapter({
      exchangeCode: vi.fn(async () => new Response(null, {
        status: 204,
        headers: { "Set-Cookie": "host_session=opaque-value; Path=/; HttpOnly; Secure; SameSite=Lax" },
      })),
    });
    const bff = service(host);
    await bff.start(startRequest(), { bindingHash: createClientAuthBffBindingHash(binding) });
    await expect(bff.exchange(exchangeRequest(), { bindingHash: createClientAuthBffBindingHash("c".repeat(43)) })).rejects.toMatchObject({ statusCode: 400 });
    await expect(bff.exchange({ ...exchangeRequest(), clientId: "other-client" }, { bindingHash: createClientAuthBffBindingHash(binding) })).rejects.toMatchObject({ statusCode: 400 });
    await expect(bff.exchange(exchangeRequest(), { bindingHash: createClientAuthBffBindingHash(binding) })).resolves.toMatchObject({ clientType: "web" });
  });

  it("verifies PKCE before the adapter, burns state on failure, and rejects replay and expiry", async () => {
    const host = adapter();
    const bff = service(host);
    await bff.start(startRequest(), { bindingHash: createClientAuthBffBindingHash(binding) });
    await expect(bff.exchange({ ...exchangeRequest(), codeVerifier: "x".repeat(43) }, { bindingHash: createClientAuthBffBindingHash(binding) })).rejects.toMatchObject({ statusCode: 400 });
    expect(host.exchangeCode).not.toHaveBeenCalled();
    await expect(bff.exchange(exchangeRequest(), { bindingHash: createClientAuthBffBindingHash(binding) })).rejects.toMatchObject({ statusCode: 400 });

    let now = 1_000_000;
    const expiring = service(adapter(), { now: () => now, stateTtlMs: 1_000 });
    await expiring.start(startRequest(), { bindingHash: createClientAuthBffBindingHash(binding) });
    now += 1_001;
    await expect(expiring.exchange(exchangeRequest(), { bindingHash: createClientAuthBffBindingHash(binding) })).rejects.toMatchObject({ statusCode: 400 });
  });

  it("returns only the native allowlist and rejects credential fields from adapter results", async () => {
    const host = adapter();
    const bff = service(host, { clientConfiguration: configuration("native", "com.example.app:/oauth/callback") });
    await bff.start(startRequest("native", "com.example.app:/oauth/callback"), {});
    const result = await bff.exchange(exchangeRequest("com.example.app:/oauth/callback", "native"), {});
    expect(result.publicResult).toEqual({
      sessionReference: "native-session-reference",
      expiresAt: expect.any(String),
      clientKind: "native",
      user: user(),
    });
    expect(Object.keys(result.publicResult ?? {})).toEqual(["sessionReference", "expiresAt", "clientKind", "user"]);

    const leaking = service(adapter({
      exchangeCode: async () => ({
        identity: identity(),
        session: {
          sessionReference: "native-session-reference",
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
          clientKind: "native" as const,
          user: user(),
          access_token: "provider-raw-token",
        },
      }),
    }), { clientConfiguration: configuration("native", "com.example.app:/oauth/callback") });
    await leaking.start(startRequest("native", "com.example.app:/oauth/callback"), {});
    await expect(leaking.exchange(exchangeRequest("com.example.app:/oauth/callback", "native"), {})).rejects.toMatchObject({ statusCode: 400 });
  });

  it("does not expose provider credentials in controller JSON or response headers", async () => {
    const host = adapter({
      exchangeCode: async () => ({
        identity: identity(),
        session: {
          sessionReference: "native-session-reference",
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
          clientKind: "native" as const,
          user: user(),
        },
      }),
    });
    const moduleRef = await Test.createTestingModule({
      controllers: [ClientAuthBffController],
      providers: [{ provide: ClientAuthBffService, useValue: service(host, { clientConfiguration: configuration("native", "com.example.app:/oauth/callback") }) }],
    }).compile();
    const app = moduleRef.createNestApplication();
    await app.init();
    const server = app.getHttpServer();
    const start = await request(server).post("/api/idaas/v1/client/auth/oidc/start").send(startRequest("native", "com.example.app:/oauth/callback"));
    expect(start.status).toBe(200);
    expect(start.headers["set-cookie"]).toBeUndefined();
    const exchange = await request(server).post("/api/idaas/v1/client/auth/oidc/callback").send(exchangeRequest("com.example.app:/oauth/callback", "native"));
    expect(exchange.status).toBe(200);
    expect(exchange.body).toEqual({
      sessionReference: "native-session-reference",
      expiresAt: expect.any(String),
      clientKind: "native",
      user: user(),
    });
    expect(JSON.stringify(exchange.body)).not.toContain("provider-raw-token");
    expect(JSON.stringify(exchange.body)).not.toContain("access_token");
    await app.close();
  });

  it("supports optional session routes and returns 503 when they are not configured", async () => {
    const sessionService: ClientAuthBffSessionService = {
      refresh: async () => ({
        sessionReference: "refreshed-session-reference",
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
        clientKind: "native",
        user: user(),
      }),
      logout: async () => ({
        sessionReference: "refreshed-session-reference",
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
        clientKind: "native",
        user: user(),
      }),
      me: async () => ({
        sessionReference: "refreshed-session-reference",
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
        clientKind: "native",
        user: user(),
      }),
    };
    const bff = service(adapter(), { sessionService });
    const controller = new ClientAuthBffController(bff);
    const response = responseRecorder();
    await controller.refresh({ sessionReference: "refreshed-session-reference" }, { headers: {} }, response.response);
    expect(response.status).toBe(200);
    expect(response.body).toMatchObject({ sessionReference: "refreshed-session-reference", clientKind: "native" });
    const meResponse = responseRecorder();
    await controller.me({ headers: { "x-client-session": "refreshed-session-reference" } }, meResponse.response);
    expect(meResponse.status).toBe(200);
    expect(meResponse.body).toMatchObject({ sessionReference: "refreshed-session-reference" });
    const missing = service();
    await expect(missing.refresh({ sessionReference: "refreshed-session-reference" })).rejects.toMatchObject({ statusCode: 503 });
  });

  it("registers a public dynamic module without a default provider", async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [ClientAuthBffModule.forRoot({
        adapter: adapter(),
        clientConfiguration: configuration(),
        store: new InMemoryClientAuthBffStateStore(),
      })],
    }).compile();
    const app = moduleRef.createNestApplication();
    await app.init();
    const response = await request(app.getHttpServer())
      .post("/api/idaas/v1/client/auth/oidc/start")
      .set("Origin", "https://app.example.test")
      .send(startRequest());
    expect(response.status).toBe(200);
    expect(response.body).toMatchObject({ state, redirectUri });
    await app.close();
  });

  it("supports cookie-only web session refresh, logout, and me routes", async () => {
    const cookie = "host_session=opaque-value; Path=/; HttpOnly; Secure; SameSite=Lax";
    const sessionService: ClientAuthBffSessionService = {
      refreshWeb: async () => new Response(null, { status: 204, headers: { "Set-Cookie": cookie } }),
      logoutWeb: async () => new Response(null, { status: 204, headers: { "Set-Cookie": cookie } }),
      meWeb: async () => ({ user: user() }),
    };
    const bff = service(adapter(), { sessionService, trustedOrigins: ["https://app.example.test"] });
    const controller = new ClientAuthBffController(bff);
    const origin = { origin: "https://app.example.test" };
    const refreshResponse = responseRecorder();
    await controller.refresh({}, { headers: origin }, refreshResponse.response);
    expect(refreshResponse.status).toBe(204);
    expect(String(refreshResponse.headers["Set-Cookie"])).toContain("host_session=opaque-value");
    const meResponse = responseRecorder();
    await controller.me({ headers: origin }, meResponse.response);
    expect(meResponse.body).toEqual({ user: user() });
    const logoutResponse = responseRecorder();
    await controller.logout({}, { headers: origin }, logoutResponse.response);
    expect(logoutResponse.status).toBe(204);
    await expect(controller.refresh({}, { headers: {} }, responseRecorder().response)).rejects.toMatchObject({ statusCode: 400 });
  });

  it("requires a trusted Origin for web start and supports explicit cross-origin hosts", async () => {
    const bff = service();
    const controller = new ClientAuthBffController(bff);
    await expect(controller.start(startRequest(), { headers: {} }, responseRecorder().response)).rejects.toMatchObject({ statusCode: 400 });
    await expect(controller.start(startRequest(), { headers: { origin: "https://evil.example.test" } }, responseRecorder().response)).rejects.toMatchObject({ statusCode: 400 });
    const trusted = service(adapter(), { trustedOrigins: ["https://api.example.test"] });
    await expect(trusted.start(startRequest(), { request: { headers: { origin: "https://api.example.test" } }, bindingHash: createClientAuthBffBindingHash(binding) })).resolves.toMatchObject({ state });
  });

  it("uses a parameterized SQL state store with one-shot claim matching", async () => {
    let now = 1_800_000_000_000;
    const records = new Map<string, ClientAuthBffStateRecord>();
    const calls: Array<{ text: string; values: readonly unknown[] }> = [];
    let failReady = false;
    const stateHash = createHash("sha256").update(state).digest("hex");
    const bindingHash = createClientAuthBffBindingHash(binding);
    const record: ClientAuthBffStateRecord = {
      version: 1,
      stateHash,
      nonce,
      codeChallenge,
      redirectUri,
      clientType: "web",
      clientId,
      scope: "openid profile email",
      expiresAt: now + 600_000,
      bindingHash,
    };
    const executor: ClientAuthBffSqlExecutor = {
      query: async (text, values = []) => {
        const params = [...values];
        calls.push({ text, values: params });
        if (text.startsWith("SELECT 1 FROM")) {
          if (failReady) throw new Error("not ready");
           return { rows: [], rowCount: 1 };
        }
        if (text.startsWith("INSERT INTO")) {
          const [tenant, hash, recordNonce, recordChallenge, recordRedirect, recordType, recordClientId, recordScope, recordBinding, recordExpiry] = params;
          records.set(`${String(tenant)}:${String(hash)}`, {
            version: 1,
            stateHash: String(hash),
            nonce: String(recordNonce),
            codeChallenge: String(recordChallenge),
            redirectUri: String(recordRedirect),
            clientType: recordType as "web" | "native",
            clientId: String(recordClientId),
            scope: String(recordScope),
            expiresAt: new Date(String(recordExpiry)).getTime(),
            ...(recordBinding === null || recordBinding === undefined ? {} : { bindingHash: String(recordBinding) }),
          });
          return { rowCount: 1, rows: [] };
        }
        if (text.startsWith("DELETE FROM") && text.includes("RETURNING")) {
          const [tenant, hash, expiry, expectedRedirect, expectedClientId, expectedType, expectedBinding] = params;
          const key = `${String(tenant)}:${String(hash)}`;
          const current = records.get(key);
          if (current === undefined || current.expiresAt <= new Date(String(expiry)).getTime()) return { rows: [] };
          if (current.redirectUri !== expectedRedirect || current.clientId !== expectedClientId || current.clientType !== expectedType) return { rows: [] };
          if ((current.bindingHash ?? null) !== (expectedBinding ?? null)) return { rows: [] };
          records.delete(key);
          return {
            rows: [{
              tenant_id: tenant,
              state_hash: current.stateHash,
              nonce: current.nonce,
              code_challenge: current.codeChallenge,
              redirect_uri: current.redirectUri,
              client_type: current.clientType,
              client_id: current.clientId,
              scope: current.scope,
              binding_hash: current.bindingHash ?? null,
              expires_at: new Date(current.expiresAt).toISOString(),
            }],
          };
        }
        if (text.startsWith("DELETE FROM") && text.includes("expires_at")) {
          const [tenant, expiry] = params;
          let removed = 0;
          for (const [key, current] of records) {
            if (key.startsWith(`${String(tenant)}:`) && current.expiresAt <= new Date(String(expiry)).getTime()) {
              records.delete(key);
              removed += 1;
            }
          }
          return { rowCount: removed, rows: [] };
        }
        if (text.startsWith("DELETE FROM")) {
          const [tenant, hash] = params;
          records.delete(`${String(tenant)}:${String(hash)}`);
          return { rowCount: 1, rows: [] };
        }
        return { rows: [] };
      },
    };
    const store = createSqlClientAuthBffStateStore(executor, {
      tenantId: "tenant-a",
      schema: "auth",
      now: () => now,
    });
    expect(store.persistent).toBe(true);
    expect(await store.ready()).toBe(true);
    await store.save(record);
    const insert = calls.find((call) => call.text.startsWith("INSERT INTO"));
    expect(insert?.text).toContain('"auth"."gb_idaas_client_auth_bff_state"');
    expect(insert?.text).not.toMatch(/code[_]?verifier/iu);
    expect(insert?.values).toContain(stateHash);
    expect(insert?.values).not.toContain(state);
    expect(insert?.values).not.toContain(codeVerifier);
    await expect(store.consume(stateHash, { redirectUri, clientId, clientType: "web", bindingHash: createClientAuthBffBindingHash("c".repeat(43)) })).resolves.toBeUndefined();
    await expect(store.consume(stateHash, { redirectUri: "https://other.example.test/callback", clientId, clientType: "web", bindingHash })).resolves.toBeUndefined();
    await expect(store.consume(stateHash, { redirectUri, clientId: "other-client", clientType: "web", bindingHash })).resolves.toBeUndefined();
    await expect(store.consume(stateHash, { redirectUri, clientId, clientType: "native", bindingHash })).resolves.toBeUndefined();
    await expect(store.consume(stateHash, { redirectUri, clientId, clientType: "web", bindingHash })).resolves.toMatchObject({ stateHash, bindingHash });
    await expect(store.consume(stateHash, { redirectUri, clientId, clientType: "web", bindingHash })).resolves.toBeUndefined();
    await store.save({ ...record, stateHash: createHash("sha256").update("expired").digest("hex"), expiresAt: now - 1 });
    now += 1;
    await expect(store.consume(record.stateHash, { redirectUri, clientId, clientType: "web", bindingHash })).resolves.toBeUndefined();
    expect(await store.cleanupExpired()).toBe(1);
    await store.save(record);
    await store.remove(stateHash);
    expect(records.size).toBe(0);
    failReady = true;
    expect(await store.ready()).toBe(false);
    expect(() => new SqlClientAuthBffStateStore(executor, { tableName: "state; DROP TABLE users" })).toThrow();
    const malformed = createSqlClientAuthBffStateStore({ query: async () => ({ rows: [{ state_hash: stateHash }] }) });
    await expect(malformed.consume(stateHash)).rejects.toThrow();
    expect(() => new ClientAuthBffService({ adapter: adapter(), clientConfiguration: configuration(), profile: "production", store })).not.toThrow();
  });

  it("requires an explicit state store in production module configuration", () => {
    expect(() => ClientAuthBffModule.forRoot({
      adapter: adapter(),
      profile: "production",
      auth: {
        api: { getSession: async () => undefined },
        handler: async () => new Response(null, { status: 204 }),
      },
    })).toThrow(/state store/i);
  });
});
