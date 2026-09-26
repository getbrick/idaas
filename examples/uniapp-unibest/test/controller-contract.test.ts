import { describe, expect, it } from "vitest";
import { AuthClient } from "../src/auth/client";
import { createPkceTransaction, OidcTransactionStore } from "../src/auth/pkce";
import type { AuthApi } from "../src/services/auth";
import type { ClientConfig } from "../src/config";
import { createMemoryStorage, type UniRequestOptions, type UniResponse, type UniRuntime } from "../src/types/runtime";

const h5RedirectUri = "https://app.example.com/pages/auth/callback";
const appOrigin = "https://app.example.com";
const appRedirectUri = "https://app.example.com/oidc-bridge.html";
const clientId = "client-1";
const sessionReference = "opaque_abcdefghijklmnopqrstuvwxyz123456";
const expiresAt = "2099-01-01T00:00:00.000Z";
const user = { id: "user-1", name: "User", email: null, emailVerified: false };

const config: ClientConfig = {
  apiBaseUrl: "https://api.example.com",
  authBasePath: "/auth",
  platformBasePath: "/platform",
  applicationId: "app-1",
  platformId: "platform-1",
  requestTimeoutMs: 15_000,
  oidc: {
    clientId,
    scope: "openid profile",
    h5RedirectUri,
    appRedirectUri,
    webviewOrigin: appOrigin,
    allowedOrigins: [appOrigin],
    webviewAllowedOrigins: [appOrigin],
  },
};

type RequestRecord = { url: string; body: Record<string, unknown>; headers: Record<string, string> };

function createControllerRuntime(handler: (request: RequestRecord) => UniResponse): { runtime: UniRuntime; requests: RequestRecord[] } {
  const requests: RequestRecord[] = [];
  const runtime: UniRuntime = {
    request(options) {
      const body = isRecord(options.data) ? options.data : {};
      const request = { url: options.url, body, headers: options.header ?? {} };
      requests.push(request);
      options.success?.(handler(request));
    },
    login() { return undefined; },
    navigateTo() { return undefined; },
    redirectTo() { return undefined; },
    navigateBack() { return undefined; },
    getStorageSync() { return undefined; },
    setStorageSync() { return undefined; },
    removeStorageSync() { return undefined; },
    showToast() { return undefined; },
  };
  return { runtime, requests };
}

function exactKeys(value: Record<string, unknown>, allowed: readonly string[]): void {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) throw new Error(`unexpected field: ${key}`);
  }
  for (const key of allowed) {
    if (value[key] === undefined) throw new Error(`missing field: ${key}`);
  }
}

function runtimeStub(): UniRuntime {
  return createControllerRuntime(() => ({ statusCode: 500, data: {} })).runtime;
}

function handoffUrl(): { open: (url: string) => Promise<void>; urls: string[] } {
  const urls: string[] = [];
  return { urls, open: async (url) => { urls.push(url); } };
}

function authApi(overrides: Partial<AuthApi>): AuthApi {
  return {
    loginWithWechatCode: async () => { throw new Error("unused"); },
    startOidc: async () => { throw new Error("unused"); },
    exchangeOidc: async () => { throw new Error("unused"); },
    exchangeWebviewTicket: async () => { throw new Error("unused"); },
    refresh: async () => { throw new Error("unused"); },
    logout: async () => undefined,
    me: async () => null,
    refreshWeb: async () => undefined,
    logoutWeb: async () => undefined,
    meWeb: async () => null,
    ...overrides,
  };
}

describe("controller-like UniApp contracts", () => {
  it("keeps H5 BFF start/exchange exact and resolves callback by state", async () => {
    const handoff = handoffUrl();
    const { runtime, requests } = createControllerRuntime((request) => {
      if (request.url.endsWith("/auth/oidc/start")) {
        exactKeys(request.body, ["redirectUri", "clientType", "clientId", "scope", "state", "nonce", "codeChallenge", "codeChallengeMethod"]);
        const state = String(request.body.state);
        const nonce = String(request.body.nonce);
        const challenge = String(request.body.codeChallenge);
        return {
          statusCode: 200,
          data: {
            authorizationUrl: `https://provider.example/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(h5RedirectUri)}&response_type=code&scope=openid%20profile&state=${state}&nonce=${nonce}&code_challenge=${challenge}&code_challenge_method=S256`,
            state,
            expiresAt,
          },
        };
      }
      if (request.url.endsWith("/auth/oidc/callback")) {
        exactKeys(request.body, ["code", "codeVerifier", "redirectUri", "state", "clientId", "clientType"]);
        return { statusCode: 204, data: undefined };
      }
      if (request.url.endsWith("/auth/me")) return { statusCode: 200, data: { user } };
      throw new Error(`unexpected route: ${request.url}`);
    });
    const client = new AuthClient({ config, runtime, storage: createMemoryStorage(), platform: "h5", handoff, now: () => 1000 });
    await client.startOidcLogin();
    const transaction = client.transactionStore.load();
    expect(transaction).not.toBeNull();
    await expect(client.completeOidcCallback({ state: String(requests[0]?.body.state), code: "authorization-code" })).resolves.toBeNull();
    expect(requests[1]?.body).toEqual({
      code: "authorization-code",
      codeVerifier: transaction?.codeVerifier,
      redirectUri: h5RedirectUri,
      state: requests[0]?.body.state,
      clientId,
      clientType: "web",
    });
    expect(requests[1]?.body).not.toHaveProperty("flowId");
    expect(requests[1]?.body).not.toHaveProperty("origin");
    expect(requests[1]?.body).not.toHaveProperty("nonce");
    expect(requests[1]?.body).not.toHaveProperty("codeChallenge");
    expect(handoff.urls).toHaveLength(1);
  });

  it("keeps H5 session operations on cookie routes", async () => {
    const { runtime, requests } = createControllerRuntime((request) => {
      if (request.url.endsWith("/auth/refresh") || request.url.endsWith("/auth/logout")) {
        if (Object.keys(request.body).length !== 0) throw new Error("H5 session operation must not send a body");
        return { statusCode: request.url.endsWith("/refresh") ? 204 : 204, data: undefined };
      }
      if (request.url.endsWith("/auth/me")) return { statusCode: 200, data: { user } };
      throw new Error(`unexpected route: ${request.url}`);
    });
    const client = new AuthClient({ config, runtime, storage: createMemoryStorage(), platform: "h5", now: () => 1000 });
    await client.bootstrap();
    await client.refresh();
    await expect(client.me()).resolves.toMatchObject({ id: "user-1" });
    await client.logout();
    expect(requests.every((request) => request.url.endsWith("/auth/refresh") || request.url.endsWith("/auth/me") || request.url.endsWith("/auth/logout"))).toBe(true);
    expect(requests.every((request) => request.body === undefined || Object.keys(request.body).length === 0)).toBe(true);
  });

  it("uses the platform controller fields and server state for webview", async () => {
    const serverState = "server-state_abcdefghijklmnopqrstuvwxyz123456";
    const handoff = handoffUrl();
    const { runtime, requests } = createControllerRuntime((request) => {
      if (request.url.endsWith("/login/webview/start")) {
        exactKeys(request.body, ["redirectUri", "client", "flowBinding", "scope"]);
        if (request.body.client !== "webview") throw new Error("client must be webview");
        return {
          statusCode: 200,
          data: { authorizationUrl: `https://provider.example/authorize?redirect_uri=${encodeURIComponent(appRedirectUri)}&state=${serverState}`, state: serverState, expiresAt, flow: { id: "server-flow_abcdefghijklmnopqrstuvwxyz123456" } },
        };
      }
      if (request.url.endsWith("/login/webview/callback")) {
        exactKeys(request.body, ["state", "code", "flowBinding"]);
        return { statusCode: 200, data: { sessionReference, expiresAt, clientKind: "native", user } };
      }
      throw new Error(`unexpected route: ${request.url}`);
    });
    const client = new AuthClient({ config, runtime, storage: createMemoryStorage(), platform: "app", handoff, now: () => 1000 });
    await client.startOidcLogin();
    const transaction = client.transactionStore.load();
    expect(transaction?.state).toBe(serverState);
    expect(requests[0]?.body.flowBinding).toBe(transaction?.flowId);
    expect(requests[0]?.body).not.toHaveProperty("clientType");
    expect(requests[0]?.body).not.toHaveProperty("state");
    expect(requests[0]?.body).not.toHaveProperty("flowId");
    expect(requests[0]?.body).not.toHaveProperty("nonce");
    expect(requests[0]?.body).not.toHaveProperty("codeChallenge");
    await expect(client.completeOidcCallback({ flowId: "server-flow_abcdefghijklmnopqrstuvwxyz123456", state: serverState, origin: appOrigin, code: "authorization-code" })).resolves.toMatchObject({ sessionReference });
    expect(requests[1]?.body).toEqual({ state: serverState, code: "authorization-code", flowBinding: transaction?.flowId });
    expect(requests[1]?.body).not.toHaveProperty("clientType");
  });

  it("uses the platform ticket route without local flow fields", async () => {
    const transaction = await createPkceTransaction({ redirectUri: appRedirectUri, clientType: "webview", randomBytes: (length) => bytes(11, length), sha256, now: () => 1000 });
    const storage = createMemoryStorage();
    new OidcTransactionStore({ storage, now: () => 1000 }).save(transaction);
    storage.set("getbrick.client.opaque-session", JSON.stringify({ sessionReference, expiresAt, clientKind: "native" }));
    const { runtime, requests } = createControllerRuntime((request) => {
      if (request.url.endsWith("/webview/ticket/exchange")) {
        exactKeys(request.body, ["ticketReference", "sessionReference", "clientId"]);
        return { statusCode: 200, data: { sessionReference: "opaque_abcdefghijklmnopqrstuvwxyz654321", expiresAt, clientKind: "webview" } };
      }
      throw new Error(`unexpected route: ${request.url}`);
    });
    const client = new AuthClient({ config, storage, runtime, platform: "app", now: () => 1000 });
    await expect(client.completeOidcCallback({ state: transaction.state, origin: appOrigin, ticketReference: "ticket_abcdefghijklmnopqrstuvwxyz123456" })).resolves.toMatchObject({ clientKind: "webview" });
    expect(requests[0]?.body).toEqual({ ticketReference: "ticket_abcdefghijklmnopqrstuvwxyz123456", sessionReference, clientId });
    expect(requests[0]?.body).not.toHaveProperty("flowId");
    expect(requests[0]?.body).not.toHaveProperty("nonce");
    expect(requests[0]?.body).not.toHaveProperty("origin");
  });

  it("selects platform session routes for native and BFF me without a body", async () => {
    const { runtime, requests } = createControllerRuntime((request) => {
      if (request.url.endsWith("/login/session/refresh")) {
        exactKeys(request.body, ["sessionReference", "client"]);
        return { statusCode: 200, data: { sessionReference: "opaque_abcdefghijklmnopqrstuvwxyz654321", expiresAt, clientKind: "native" } };
      }
      if (request.url.endsWith("/login/session/logout")) {
        exactKeys(request.body, ["sessionReference", "client"]);
        return { statusCode: 204, data: undefined };
      }
      if (request.url.endsWith("/auth/me")) {
        if (Object.keys(request.body).length !== 0) throw new Error("me must use the session header");
        return { statusCode: 200, data: { user } };
      }
      throw new Error(`unexpected route: ${request.url}`);
    });
    const storage = createMemoryStorage();
    storage.set("getbrick.client.opaque-session", JSON.stringify({ sessionReference, expiresAt, clientKind: "native" }));
    const client = new AuthClient({ config, storage, runtime, platform: "app", now: () => 1000 });
    await client.refresh();
    await expect(client.me()).resolves.toMatchObject({ id: "user-1" });
    await client.logout();
    expect(requests.map((request) => request.url)).toEqual([
      "https://api.example.com/platform/applications/app-1/platforms/platform-1/login/session/refresh",
      "https://api.example.com/auth/me",
      "https://api.example.com/platform/applications/app-1/platforms/platform-1/login/session/logout",
    ]);
    expect(requests[1]?.body).toEqual({});
    expect(requests[1]?.headers["x-client-session"]).toBe("opaque_abcdefghijklmnopqrstuvwxyz654321");
  });

  it("uses platform session routes for a webview client kind", async () => {
    const { runtime, requests } = createControllerRuntime((request) => {
      if (request.url.endsWith("/login/session/refresh")) {
        exactKeys(request.body, ["sessionReference"]);
        return { statusCode: 200, data: { sessionReference: "opaque_abcdefghijklmnopqrstuvwxyz654321", expiresAt, clientKind: "webview" } };
      }
      if (request.url.endsWith("/login/session/logout")) {
        exactKeys(request.body, ["sessionReference"]);
        return { statusCode: 204, data: undefined };
      }
      if (request.url.endsWith("/auth/me")) {
        if (Object.keys(request.body).length !== 0) throw new Error("me must use the session header");
        return { statusCode: 200, data: { user } };
      }
      throw new Error(`unexpected route: ${request.url}`);
    });
    const storage = createMemoryStorage();
    storage.set("getbrick.client.opaque-session", JSON.stringify({ sessionReference, expiresAt, clientKind: "webview" }));
    const client = new AuthClient({ config, storage, runtime, platform: "app", now: () => 1000 });
    await client.refresh();
    await client.me();
    await client.logout();
    expect(requests.map((request) => request.url)).toEqual([
      "https://api.example.com/platform/applications/app-1/platforms/platform-1/login/session/refresh",
      "https://api.example.com/auth/me",
      "https://api.example.com/platform/applications/app-1/platforms/platform-1/login/session/logout",
    ]);
    expect(requests[0]?.body).toEqual({ sessionReference });
    expect(requests[2]?.body).toEqual({ sessionReference: "opaque_abcdefghijklmnopqrstuvwxyz654321" });
  });

  it("fences an old transaction as soon as a new login starts", async () => {
    const handoff = handoffUrl();
    const api = authApi({
      startOidc: async (input) => ({
        authorizationUrl: `https://provider.example/authorize?redirect_uri=${encodeURIComponent(h5RedirectUri)}&state=${input.state}`,
        state: input.state as string,
        expiresAt,
        redirectUri: h5RedirectUri,
      }),
    });
    const client = new AuthClient({ config, api, storage: createMemoryStorage(), runtime: runtimeStub(), platform: "h5", handoff, now: () => 1000 });
    await client.startOidcLogin();
    const first = client.transactionStore.load();
    await client.startOidcLogin();
    expect(first).not.toBeNull();
    expect(client.transactionStore.load(first?.flowId ?? "missing_flow_123456")).toBeNull();
  });

  it("does not consume a transaction for an unbound error callback", async () => {
    const storage = createMemoryStorage();
    const transaction = await createPkceTransaction({ redirectUri: h5RedirectUri, randomBytes: (length) => bytes(9, length), sha256, now: () => 1000 });
    new OidcTransactionStore({ storage, now: () => 1000 }).save(transaction);
    const client = new AuthClient({ config, storage, runtime: runtimeStub(), platform: "h5", now: () => 1000 });
    await expect(client.completeOidcCallback({ error: "access_denied", flowId: transaction.flowId })).rejects.toMatchObject({ code: "oidc_callback_denied" });
    expect(client.transactionStore.load(transaction.flowId)).not.toBeNull();
  });
});

function bytes(seed: number, length: number): Uint8Array {
  return new Uint8Array(Array.from({ length }, (_, index) => (seed + index) % 256));
}

async function sha256(value: Uint8Array): Promise<ArrayBuffer> {
  const digest = await import("node:crypto").then(({ createHash }) => createHash("sha256").update(value).digest().buffer);
  return digest as ArrayBuffer;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
