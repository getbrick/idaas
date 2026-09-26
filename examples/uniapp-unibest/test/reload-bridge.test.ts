import { describe, expect, it } from "vitest";
import { AuthClient } from "../src/auth/client";
import { assertWebViewMessageOrigin, parseWebViewCallback } from "../src/auth/callback";
import { OIDC_FLOW_FENCE_STORAGE_KEY, getOidcTransactionStorageKey } from "../src/auth/pkce";
import type { AuthHandoff } from "../src/auth/handoff";
import { getWebviewBridgeOrigin, type ClientConfig } from "../src/config";
import { createMemoryStorage, type UniRequestOptions, type UniResponse, type UniRuntime } from "../src/types/runtime";

const h5RedirectUri = "https://app.example.com/pages/auth/callback";
const bridgeRedirectUri = "https://app.example.com/oidc-bridge.html";
const bridgeOrigin = "https://app.example.com";
const clientId = "client-1";
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
    appRedirectUri: bridgeRedirectUri,
    webviewOrigin: bridgeOrigin,
    allowedOrigins: [bridgeOrigin],
    webviewAllowedOrigins: [bridgeOrigin],
  },
};

type RequestRecord = { url: string; body: Record<string, unknown>; headers: Record<string, string> };

function createRuntime(handler: (request: RequestRecord) => UniResponse | Promise<UniResponse>): { runtime: UniRuntime; requests: RequestRecord[] } {
  const requests: RequestRecord[] = [];
  const runtime: UniRuntime = {
    request(options) {
      const body = isRecord(options.data) ? options.data : {};
      const request = { url: options.url, body, headers: options.header ?? {} };
      requests.push(request);
      const response = handler(request);
      if (isPromiseLike(response)) response.then((value) => options.success?.(value));
      else options.success?.(response);
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

function handoff(): AuthHandoff & { urls: string[] } {
  const urls: string[] = [];
  return { urls, open: async (url) => { urls.push(url); } };
}

function authorizationUrl(redirectUri: string, state: string, nonce?: string, challenge?: string): string {
  const params = new URLSearchParams({ redirect_uri: redirectUri, state });
  if (nonce !== undefined) params.set("nonce", nonce);
  if (challenge !== undefined) {
    params.set("code_challenge", challenge);
    params.set("code_challenge_method", "S256");
  }
  return `https://provider.example/authorize?${params.toString()}`;
}

function h5Runtime(): { runtime: UniRuntime; requests: RequestRecord[] } {
  return createRuntime((request) => {
    if (request.url.endsWith("/auth/oidc/start")) {
      const state = String(request.body.state);
      const nonce = String(request.body.nonce);
      const challenge = String(request.body.codeChallenge);
      return { statusCode: 200, data: { authorizationUrl: authorizationUrl(h5RedirectUri, state, nonce, challenge), state, expiresAt } };
    }
    if (request.url.endsWith("/auth/oidc/callback")) return { statusCode: 204, data: undefined };
    if (request.url.endsWith("/auth/me")) return { statusCode: 200, data: { user } };
    if (request.url.endsWith("/auth/logout")) return { statusCode: 204, data: undefined };
    throw new Error(`unexpected H5 route: ${request.url}`);
  });
}

function appRuntime(): { runtime: UniRuntime; requests: RequestRecord[] } {
  return createRuntime((request) => {
    if (request.url.endsWith("/login/webview/start")) {
      return {
        statusCode: 200,
        data: {
          authorizationUrl: authorizationUrl(bridgeRedirectUri, "server-state_abcdefghijklmnopqrstuvwxyz123456"),
          state: "server-state_abcdefghijklmnopqrstuvwxyz123456",
          expiresAt,
          flow: { id: "server-flow_abcdefghijklmnopqrstuvwxyz123456" },
        },
      };
    }
    if (request.url.endsWith("/login/webview/callback")) {
      return { statusCode: 200, data: { sessionReference: "opaque_abcdefghijklmnopqrstuvwxyz123456", expiresAt, clientKind: "webview", user } };
    }
    if (request.url.endsWith("/auth/me")) return { statusCode: 200, data: { user } };
    throw new Error(`unexpected App route: ${request.url}`);
  });
}

function missingBridgeConfig(): ClientConfig {
  return { ...config, oidc: { ...config.oidc, appRedirectUri: "" } };
}

describe("reload and bridge contracts", () => {
  it("keeps an H5 callback valid in a new AuthClient instance", async () => {
    const storage = createMemoryStorage();
    const { runtime, requests } = h5Runtime();
    const firstHandoff = handoff();
    const first = new AuthClient({ config, storage, runtime, platform: "h5", handoff: firstHandoff, now: () => 1000 });
    const start = await first.startOidcLogin();
    const state = start.state;
    const firstFlow = first.transactionStore.load();
    expect(storage.get(OIDC_FLOW_FENCE_STORAGE_KEY)).toBeDefined();
    expect(firstFlow).not.toBeNull();
    expect(storage.get(getOidcTransactionStorageKey(firstFlow?.flowId ?? "missing_flow_123456"))).toBeDefined();

    const secondHandoff = handoff();
    const second = new AuthClient({ config, storage, runtime, platform: "h5", handoff: secondHandoff, now: () => 1000 });
    await expect(second.completeOidcCallback({ state, code: "authorization-code" })).resolves.toBeNull();
    expect(second.isCookieAuthenticated()).toBe(true);
    expect(requests[1]?.body).toMatchObject({ state, code: "authorization-code", clientType: "web" });
    expect(secondHandoff.urls).toHaveLength(0);
  });

  it("invalidates an old H5 flow across a reload when a new login starts", async () => {
    const storage = createMemoryStorage();
    const { runtime } = h5Runtime();
    const first = new AuthClient({ config, storage, runtime, platform: "h5", handoff: handoff(), now: () => 1000 });
    const oldStart = await first.startOidcLogin();
    const second = new AuthClient({ config, storage, runtime, platform: "h5", handoff: handoff(), now: () => 1000 });
    await second.startOidcLogin();
    await expect(first.completeOidcCallback({ state: oldStart.state, code: "authorization-code" })).rejects.toMatchObject({ code: "invalid_oidc_transaction" });
  });

  it("invalidates and clears the transaction before a delayed logout request", async () => {
    const storage = createMemoryStorage();
    let release: ((response: UniResponse) => void) | undefined;
    let started = false;
    const { runtime } = createRuntime((request) => {
      if (request.url.endsWith("/auth/oidc/start")) {
        started = true;
        const state = String(request.body.state);
        const nonce = String(request.body.nonce);
        const challenge = String(request.body.codeChallenge);
        return { statusCode: 200, data: { authorizationUrl: authorizationUrl(h5RedirectUri, state, nonce, challenge), state, expiresAt } };
      }
      if (request.url.endsWith("/auth/logout")) return new Promise<UniResponse>((resolve) => { release = resolve; });
      throw new Error(`unexpected route: ${request.url}`);
    });
    const client = new AuthClient({ config, storage, runtime, platform: "h5", handoff: handoff(), now: () => 1000 });
    const start = await client.startOidcLogin();
    const transaction = client.transactionStore.load();
    expect(started).toBe(true);
    expect(transaction).not.toBeNull();
    const pending = client.logout();
    await Promise.resolve();
    expect(client.transactionStore.load()).toBeNull();
    expect(client.flowFenceStore.load().generation).toBe(2);
    const replacement = new AuthClient({ config, storage, runtime, platform: "h5", handoff: handoff(), now: () => 1000 });
    await replacement.startOidcLogin();
    const replacementTransaction = replacement.transactionStore.load();
    expect(replacementTransaction).not.toBeNull();
    release?.({ statusCode: 204, data: undefined });
    await pending;
    expect(replacement.transactionStore.load(replacementTransaction?.flowId ?? "missing_flow_123456")).not.toBeNull();
  });

  it("uses the explicit bridge redirect and exchanges only accepted callback fields", async () => {
    const storage = createMemoryStorage();
    const { runtime, requests } = appRuntime();
    const firstHandoff = handoff();
    const first = new AuthClient({ config, storage, runtime, platform: "app", handoff: firstHandoff, now: () => 1000 });
    const start = await first.startOidcLogin();
    const firstTransaction = first.transactionStore.load();
    expect(start.authorizationUrl).toContain(encodeURIComponent(bridgeRedirectUri));
    expect(start.authorizationUrl).not.toContain("/login/webview/callback");
    expect(start.authorizationUrl).not.toContain(firstTransaction?.flowId ?? "missing_flow_123456");
    expect(requests[0]?.body).toEqual({ redirectUri: bridgeRedirectUri, client: "webview", flowBinding: firstTransaction?.flowId, scope: config.oidc.scope });

    const second = new AuthClient({ config, storage, runtime, platform: "app", handoff: handoff(), now: () => 1000 });
    const transaction = second.transactionStore.load();
    expect(transaction?.state).toBe(start.state);
    expect(requests[0]?.body.flowBinding).toBe(transaction?.flowId);

    const message = parseWebViewCallback({
      type: "getbrick-oidc-callback",
      state: start.state,
      code: "authorization-code",
      flowId: "server-flow_abcdefghijklmnopqrstuvwxyz123456",
    }, { expectedOrigin: bridgeOrigin, sourceOrigin: bridgeOrigin, requireOrigin: true, requireState: true });
    expect(message).not.toHaveProperty("flowBinding");

    await expect(second.completeOidcCallback(message)).resolves.toMatchObject({ clientKind: "webview" });
    expect(requests[1]?.body).toEqual({ state: start.state, code: "authorization-code", flowBinding: transaction?.flowId });
    expect(requests[1]?.body).not.toHaveProperty("clientType");
    expect(requests[1]?.body).not.toHaveProperty("flowId");
    expect(requests[1]?.body).not.toHaveProperty("nonce");
    expect(requests[1]?.body).not.toHaveProperty("origin");
  });

  it("rejects an untrusted bridge origin and mismatched bridge binding", async () => {
    const storage = createMemoryStorage();
    const { runtime } = appRuntime();
    const client = new AuthClient({ config, storage, runtime, platform: "app", handoff: handoff(), now: () => 1000 });
    const start = await client.startOidcLogin();
    const transaction = client.transactionStore.load();
    expect(transaction).not.toBeNull();
    expect(() => assertWebViewMessageOrigin("https://evil.example.com", bridgeOrigin)).toThrow("origin");
    const message = parseWebViewCallback({ type: "getbrick-oidc-callback", state: start.state, nonce: "nonce_wrong_abcdefghijklmnopqrstuvwxyz123456", code: "authorization-code" }, { expectedOrigin: bridgeOrigin, sourceOrigin: bridgeOrigin, requireOrigin: true, requireState: true });
    await expect(client.completeOidcCallback(message)).rejects.toMatchObject({ code: "oidc_nonce_mismatch" });
    expect(client.transactionStore.load()).not.toBeNull();
  });

  it("fails fast before starting App OIDC without an explicit bridge redirect", async () => {
    const { runtime, requests } = appRuntime();
    const client = new AuthClient({ config: missingBridgeConfig(), storage: createMemoryStorage(), runtime, platform: "app", handoff: handoff(), now: () => 1000 });
    await expect(client.startOidcLogin()).rejects.toMatchObject({ code: "oidc_configuration_missing" });
    expect(requests).toHaveLength(0);
  });
});

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isPromiseLike(value: unknown): value is Promise<UniResponse> {
  return isRecord(value) && typeof (value as { then?: unknown }).then === "function";
}
