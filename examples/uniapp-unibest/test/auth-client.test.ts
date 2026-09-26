import { describe, expect, it } from "vitest";
import { AuthClient } from "../src/auth/client";
import { createPkceTransaction, OidcTransactionStore } from "../src/auth/pkce";
import type { AuthApi } from "../src/services/auth";
import type { ClientConfig } from "../src/config";
import { createMemoryStorage, type UniRuntime } from "../src/types/runtime";

const redirectUri = "https://app.example.com/oidc/callback";
const appRedirectUri = "https://app.example.com/oidc-bridge.html";

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
    h5RedirectUri: redirectUri,
    appRedirectUri,
    webviewOrigin: "https://app.example.com",
    allowedOrigins: ["https://app.example.com"],
    webviewAllowedOrigins: ["https://app.example.com"],
  },
};

function runtime(): UniRuntime {
  return {
    request() { return undefined; },
    login() { return undefined; },
    navigateTo() { return undefined; },
    redirectTo() { return undefined; },
    navigateBack() { return undefined; },
    getStorageSync() { return undefined; },
    setStorageSync() { return undefined; },
    removeStorageSync() { return undefined; },
    showToast() { return undefined; },
  };
}

function api(exchange: AuthApi["exchangeOidc"]): AuthApi {
  return {
    loginWithWechatCode: async () => { throw new Error("unused"); },
    startOidc: async () => { throw new Error("unused"); },
    exchangeOidc: exchange,
    exchangeWebviewTicket: async () => { throw new Error("unused"); },
    refresh: async () => { throw new Error("unused"); },
    logout: async () => undefined,
    me: async () => null,
    refreshWeb: async () => undefined,
    logoutWeb: async () => undefined,
    meWeb: async () => null,
  };
}

describe("AuthClient OIDC session boundary", () => {
  it("keeps an H5 204 exchange out of opaque storage", async () => {
    const storage = createMemoryStorage();
    const transaction = await createPkceTransaction({ redirectUri });
    new OidcTransactionStore({ storage }).save(transaction);
    const client = new AuthClient({
      config,
      storage,
      runtime: runtime(),
      platform: "h5",
      api: api(async () => ({ clientType: "web", status: 204 })),
    });

    await expect(client.completeOidcCallback({ flowId: transaction.flowId, state: transaction.state, code: "authorization-code" })).resolves.toBeNull();
    expect(client.sessionStore.load()).toBeNull();
    expect(client.isCookieAuthenticated()).toBe(true);
  });

  it("stores native exchange results as opaque sessions", async () => {
    const storage = createMemoryStorage();
    const transaction = await createPkceTransaction({ redirectUri: appRedirectUri, origin: "https://app.example.com", clientType: "webview" });
    new OidcTransactionStore({ storage }).save(transaction);
    const session = {
      sessionReference: "opaque_abcdefghijklmnopqrstuvwxyz123456",
      expiresAt: "2099-01-01T00:00:00.000Z",
      clientKind: "native" as const,
      user: { id: "user-1", name: "User", email: null, emailVerified: false },
    };
    const client = new AuthClient({
      config,
      storage,
      runtime: runtime(),
      platform: "app",
      api: api(async () => ({ clientType: "native", session })),
    });

    await expect(client.completeOidcCallback({ flowId: transaction.flowId, state: transaction.state, nonce: transaction.nonce, origin: transaction.origin, code: "authorization-code" })).resolves.toMatchObject({ sessionReference: session.sessionReference });
    expect(client.sessionStore.load()).toMatchObject({ sessionReference: session.sessionReference });
  });
});
