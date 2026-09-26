import { describe, expect, it } from "vitest";
import { createAuthApi, type AuthApi } from "../src/services/auth";
import { ApiRequestClient } from "../src/services/request";
import { AuthClient } from "../src/auth/client";
import { normalizeOidcCallback, parseWebViewCallback } from "../src/auth/callback";
import { getOidcRedirectUri, getPlatformRoute, type ClientConfig } from "../src/config";
import { createPkceTransaction, getOidcTransactionStorageKey, OidcTransactionStore } from "../src/auth/pkce";
import { SessionCoordinator } from "../src/auth/session-coordinator";
import { OpaqueSessionStore } from "../src/auth/session";
import { createMemoryStorage, type UniRequestOptions, type UniResponse, type UniRuntime } from "../src/types/runtime";

const h5RedirectUri = "https://app.example.com/pages/auth/callback";
const origin = "https://app.example.com";
const flowId = "flow_abcdefghijklmnopqrstuvwxyz123456";
const nonce = "nonce_abcdefghijklmnopqrstuvwxyz123456";
const state = "state_abcdefghijklmnopqrstuvwxyz123456";
const code = "authorization-code";
const reference = "opaque_abcdefghijklmnopqrstuvwxyz123456";
const expiresAt = "2099-01-01T00:00:00.000Z";

const config: ClientConfig = {
  apiBaseUrl: "https://api.example.com",
  authBasePath: "/auth",
  platformBasePath: "/platform",
  applicationId: "app-1",
  platformId: "platform-1",
  requestTimeoutMs: 15_000,
  oidc: {
    clientId: "client-1",
    scope: "openid profile",
    h5RedirectUri,
    appRedirectUri: "https://app.example.com/oidc-bridge.html",
    webviewOrigin: origin,
    allowedOrigins: [origin],
    webviewAllowedOrigins: [origin],
  },
};

describe("O5 client contract", () => {
  it("uses an exact H5 callback and the real application platform route", () => {
    expect(getOidcRedirectUri("h5", config)).toBe(h5RedirectUri);
    expect(getOidcRedirectUri("app", config)).toBe("https://app.example.com/oidc-bridge.html");
    expect(getPlatformRoute(config, "webview/ticket/exchange")).toBe("/platform/applications/app-1/platforms/platform-1/webview/ticket/exchange");
    expect(() => getOidcRedirectUri("h5", { ...config, oidc: { ...config.oidc, h5RedirectUri: "https://app.example.com/#/pages/auth/callback" } })).toThrow();
  });

  it("stores and atomically consumes independent flow transactions", async () => {
    const storage = createMemoryStorage();
    const store = new OidcTransactionStore({ storage, now: () => 1000 });
    const first = await createPkceTransaction({ redirectUri: h5RedirectUri, origin, clientType: "web", randomBytes: (length) => bytes(1, length), sha256, now: () => 1000 });
    const second = await createPkceTransaction({ redirectUri: h5RedirectUri, origin, clientType: "webview", randomBytes: (length) => bytes(2, length), sha256, now: () => 1000 });
    store.save(first);
    store.save(second);

    expect(storage.get(getOidcTransactionStorageKey(first.flowId))).toBeDefined();
    expect(storage.get(getOidcTransactionStorageKey(second.flowId))).toBeDefined();
    expect(store.load(first.flowId)?.flowId).toBe(first.flowId);
    expect(store.consume(first.flowId)?.flowId).toBe(first.flowId);
    expect(store.consume(first.flowId)).toBeNull();
    expect(store.load(second.flowId)?.flowId).toBe(second.flowId);
  });

  it("binds callback flow, nonce, and origin", () => {
    const callback = { flowId, nonce, origin, state, code };
    expect(normalizeOidcCallback(callback, { requireFlowId: true, requireNonce: true, requireOrigin: true, allowedOrigins: [origin] })).toMatchObject(callback);
    expect(() => normalizeOidcCallback({ ...callback, origin: "https://evil.example.com" }, { requireFlowId: true, requireNonce: true, requireOrigin: true, allowedOrigins: [origin] })).toThrow("origin");
    expect(parseWebViewCallback({ type: "getbrick-oidc-callback", ...callback }, { expectedOrigin: origin })).toMatchObject(callback);
  });

  it("does not let a refresh complete after logout", async () => {
    const sessions = new OpaqueSessionStore({ storage: createMemoryStorage(), now: () => Date.parse("2028-01-01T00:00:00.000Z") });
    sessions.save({ sessionReference: reference, expiresAt });
    const coordinator = new SessionCoordinator({ sessions });
    let release: ((session: { sessionReference: string; expiresAt: string }) => void) | undefined;
    const pending = coordinator.refresh(() => new Promise((resolve) => {
      release = resolve;
    }));
    await Promise.resolve();
    await coordinator.logout();
    release?.({ sessionReference: "opaque_abcdefghijklmnopqrstuvwxyz654321", expiresAt });

    await expect(pending).rejects.toMatchObject({ code: "session_generation_mismatch", status: 409, retryable: false });
    expect(coordinator.current()).toBeNull();
  });

  it("fences an AuthClient refresh that races logout", async () => {
    const storage = createMemoryStorage();
    storage.set("getbrick.client.opaque-session", JSON.stringify({ sessionReference: reference, expiresAt }));
    let release: ((session: { sessionReference: string; expiresAt: string }) => void) | undefined;
    const api = mockApi({
      refresh: async () => new Promise((resolve) => {
        release = resolve;
      }),
      logout: async () => undefined,
    });
    const client = new AuthClient({ config, storage, runtime: emptyRuntime(), platform: "app", api, now: () => 1000 });
    const pending = client.refresh();
    await Promise.resolve();
    await client.logout();
    release?.({ sessionReference: "opaque_abcdefghijklmnopqrstuvwxyz654321", expiresAt });
    await expect(pending).rejects.toMatchObject({ code: "session_generation_mismatch", status: 409, retryable: false });
    expect(client.getSession()).toBeNull();
  });

  it("preserves structured API errors without provider details", async () => {
    const { runtime } = runtimeWith([{ statusCode: 503, data: { error: { code: "temporarily_unavailable", status: 503, retryable: true, message: "provider secret" } } }]);
    const client = new ApiRequestClient({ baseUrl: "https://api.example.com", runtime });
    await expect(client.request({ path: "/resource" })).rejects.toMatchObject({ code: "temporarily_unavailable", status: 503, retryable: true });
  });

  it("sends flow binding to the real webview platform routes", async () => {
    const authorizationUrl = `https://provider.example/authorize?redirect_uri=${encodeURIComponent("https://app.example.com/oidc-bridge.html")}&state=${state}&nonce=${nonce}`;
    const { runtime, requests } = runtimeWith([
      { statusCode: 200, data: { authorizationUrl, state, expiresAt } },
      { statusCode: 200, data: { sessionReference: reference, expiresAt } },
    ]);
    const request = new ApiRequestClient({ baseUrl: config.apiBaseUrl, runtime });
    const api = createAuthApi(request, config);
    const start = await api.startOidc({
      redirectUri: "https://app.example.com/oidc-bridge.html",
      clientType: "native",
      clientId: config.oidc.clientId,
      scope: config.oidc.scope,
      state,
      nonce,
      flowId,
      flowBinding: flowId,
      origin,
      codeChallenge: "challenge_abcdefghijklmnopqrstuvwxyz123456789",
    });
    expect(start.state).toBe(state);
    expect(requests[0]?.url).toContain("/platform/applications/app-1/platforms/platform-1/login/webview/start");
    expect(requests[0]?.data).toEqual({ redirectUri: "https://app.example.com/oidc-bridge.html", client: "webview", flowBinding: flowId, scope: config.oidc.scope });

    await api.exchangeOidc({
      code,
      codeVerifier: "verifier_abcdefghijklmnopqrstuvwxyz123456789",
      redirectUri: "https://app.example.com/oidc-bridge.html",
      state,
      clientId: config.oidc.clientId,
      clientType: "native",
      flowId,
      flowBinding: flowId,
      nonce,
      origin,
    });
    expect(requests[1]?.url).toContain("/login/webview/callback");
    expect(requests[1]?.data).toEqual({ state, code, flowBinding: flowId });
  });

  it("rejects missing or mismatched webview flow bindings before transport", async () => {
    const { runtime, requests } = runtimeWith([]);
    const api = createAuthApi(new ApiRequestClient({ baseUrl: config.apiBaseUrl, runtime }), config);
    const startInput = {
      redirectUri: config.oidc.appRedirectUri,
      clientType: "webview" as const,
      scope: config.oidc.scope,
    };
    await expect(api.startOidc(startInput)).rejects.toMatchObject({ code: "invalid_oidc_transaction" });
    await expect(api.startOidc({ ...startInput, flowId, flowBinding: "wrong_abcdefghijklmnopqrstuvwxyz123456" })).rejects.toMatchObject({ code: "invalid_oidc_transaction" });
    const exchangeInput = {
      code,
      redirectUri: config.oidc.appRedirectUri,
      state,
      clientType: "webview" as const,
    };
    await expect(api.exchangeOidc(exchangeInput)).rejects.toMatchObject({ code: "invalid_oidc_transaction" });
    await expect(api.exchangeOidc({ ...exchangeInput, flowId, flowBinding: "wrong_abcdefghijklmnopqrstuvwxyz123456" })).rejects.toMatchObject({ code: "invalid_oidc_transaction" });
    expect(requests).toHaveLength(0);
  });

  it("routes AuthClient webview callbacks through the flow-bound API", async () => {
    const storage = createMemoryStorage();
    const transaction = await createPkceTransaction({ redirectUri: config.oidc.appRedirectUri, origin, clientType: "webview", randomBytes: (length) => bytes(3, length), sha256, now: () => 1000 });
    new OidcTransactionStore({ storage, now: () => 1000 }).save(transaction);
    const calls: string[] = [];
    const api = mockApi({
      exchangeWebviewTicket: async (ticket) => {
        calls.push(ticket);
        return { sessionReference: reference, expiresAt };
      },
    });
    const client = new AuthClient({ config, storage, runtime: emptyRuntime(), platform: "app", api, now: () => 1000 });
    storage.set("getbrick.client.opaque-session", JSON.stringify({ sessionReference: reference, expiresAt }));
    const result = await client.completeOidcCallback({ flowId: transaction.flowId, state: transaction.state, nonce: transaction.nonce, origin, ticketReference: "ticket_abcdefghijklmnopqrstuvwxyz123456" });
    expect(result?.sessionReference).toBe(reference);
    expect(calls).toEqual(["ticket_abcdefghijklmnopqrstuvwxyz123456"]);
  });
});

function bytes(seed: number, length: number): Uint8Array {
  return new Uint8Array(Array.from({ length }, (_, index) => (seed + index) % 256));
}

async function sha256(value: Uint8Array): Promise<ArrayBuffer> {
  const digest = await import("node:crypto").then(({ createHash }) => createHash("sha256").update(value).digest().buffer);
  return digest as ArrayBuffer;
}

function runtimeWith(responses: UniResponse[]): { runtime: UniRuntime; requests: UniRequestOptions[] } {
  const requests: UniRequestOptions[] = [];
  const runtime: UniRuntime = {
    request(options) {
      requests.push({ ...options, success: undefined, fail: undefined, complete: undefined });
      const response = responses.shift();
      if (response === undefined) throw new Error("missing response");
      options.success?.(response);
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

function emptyRuntime(): UniRuntime {
  return runtimeWith([]).runtime;
}

function mockApi(overrides: Partial<AuthApi>): AuthApi {
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
