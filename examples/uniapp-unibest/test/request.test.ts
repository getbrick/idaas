import { describe, expect, it } from "vitest";
import { ApiRequestClient } from "../src/services/request";
import { createAuthApi } from "../src/services/auth";
import type { ClientConfig } from "../src/config";
import { OpaqueSessionStore } from "../src/auth/session";
import { createMemoryStorage, type UniRequestOptions, type UniResponse, type UniRuntime } from "../src/types/runtime";

const reference = "opaque_abcdefghijklmnopqrstuvwxyz123456";
const expiresAt = "2099-01-01T00:00:00.000Z";

function createRuntime(responses: UniResponse[]): { runtime: UniRuntime; requests: UniRequestOptions[] } {
  const requests: UniRequestOptions[] = [];
  const runtime: UniRuntime = {
    request(options) {
      requests.push({ ...options, success: undefined, fail: undefined, complete: undefined });
      const response = responses.shift();
      if (response === undefined) throw new Error("missing response");
      options.success?.(response);
    },
    login() {
      return undefined;
    },
    navigateTo() {
      return undefined;
    },
    redirectTo() {
      return undefined;
    },
    navigateBack() {
      return undefined;
    },
    getStorageSync() {
      return undefined;
    },
    setStorageSync() {
      return undefined;
    },
    removeStorageSync() {
      return undefined;
    },
    showToast() {
      return undefined;
    },
  };
  return { runtime, requests };
}

describe("API request client", () => {
  it("refreshes an opaque session once and retries the request", async () => {
    const storage = createMemoryStorage();
    const sessions = new OpaqueSessionStore({ storage });
    sessions.save({ sessionReference: reference, expiresAt });
    const { runtime, requests } = createRuntime([
      { statusCode: 401, data: { error: "expired" } },
      { statusCode: 200, data: { data: { ok: true } } },
    ]);
    const client = new ApiRequestClient({ baseUrl: "https://api.example.com", sessions, runtime });
    let refreshCalls = 0;
    client.setRefreshHandler(async () => {
      refreshCalls += 1;
      return sessions.save({ sessionReference: "opaque_abcdefghijklmnopqrstuvwxyz654321", expiresAt });
    });

    await expect(client.request<{ ok: boolean }>({ path: "/resource" })).resolves.toEqual({ ok: true });
    expect(refreshCalls).toBe(1);
    expect(requests).toHaveLength(2);
    expect(requests[0]?.header?.["x-client-session"]).toBe(reference);
    expect(requests[0]?.withCredentials).toBe(true);
    expect(requests[1]?.header?.["x-client-session"]).toBe("opaque_abcdefghijklmnopqrstuvwxyz654321");
  });

  it("coalesces concurrent refresh operations", async () => {
    const storage = createMemoryStorage();
    const sessions = new OpaqueSessionStore({ storage });
    sessions.save({ sessionReference: reference, expiresAt });
    const { runtime } = createRuntime([
      { statusCode: 401, data: { error: "expired" } },
      { statusCode: 401, data: { error: "expired" } },
      { statusCode: 200, data: { data: { ok: true } } },
      { statusCode: 200, data: { data: { ok: true } } },
    ]);
    const client = new ApiRequestClient({ baseUrl: "https://api.example.com", sessions, runtime });
    let refreshCalls = 0;
    client.setRefreshHandler(async () => {
      refreshCalls += 1;
      await Promise.resolve();
      return sessions.save({ sessionReference: "opaque_abcdefghijklmnopqrstuvwxyz654321", expiresAt });
    });

    await Promise.all([
      client.request({ path: "/one" }),
      client.request({ path: "/two" }),
    ]);
    expect(refreshCalls).toBe(1);
  });

  it("turns HTTP failures into safe errors", async () => {
    const sessions = new OpaqueSessionStore({ storage: createMemoryStorage() });
    const { runtime } = createRuntime([{ statusCode: 500, data: { message: "internal provider detail" } }]);
    const client = new ApiRequestClient({ baseUrl: "https://api.example.com", sessions, runtime });

    await expect(client.request({ path: "/resource" })).rejects.toMatchObject({
      code: "http_500",
      status: 500,
      retryable: true,
    });
  });

  it("keeps web OIDC exchange cookie-only while native receives opaque JSON", async () => {
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
        h5RedirectUri: "https://app.example.com/callback",
        appRedirectUri: "com.example.app:/oauth/callback",
      },
    };
    const { runtime, requests } = createRuntime([
      { statusCode: 204, data: undefined },
      { statusCode: 200, data: { sessionReference: reference, expiresAt, clientKind: "native", user: { id: "user-1", name: "User", email: null, emailVerified: false } } },
    ]);
    const client = new ApiRequestClient({ baseUrl: config.apiBaseUrl, runtime });
    const api = createAuthApi(client, config);
    const web = await api.exchangeOidc({
      code: "authorization-code",
      codeVerifier: "verifier_abcdefghijklmnopqrstuvwxyz123456789",
      redirectUri: config.oidc.h5RedirectUri,
      state: "state_abcdefghijklmnopqrstuvwxyz123456",
      clientId: config.oidc.clientId,
      clientType: "web",
      flowId: "flow_abcdefghijklmnopqrstuvwxyz123456",
      nonce: "nonce_abcdefghijklmnopqrstuvwxyz123456",
      origin: "https://app.example.com",
    });
    const native = await api.exchangeOidc({
      code: "authorization-code",
      codeVerifier: "verifier_abcdefghijklmnopqrstuvwxyz123456789",
      redirectUri: config.oidc.appRedirectUri,
      state: "state_abcdefghijklmnopqrstuvwxyz123456",
      clientId: config.oidc.clientId,
       clientType: "native",
       flowId: "flow_abcdefghijklmnopqrstuvwxyz123456",
       flowBinding: "flow_abcdefghijklmnopqrstuvwxyz123456",
       nonce: "nonce_abcdefghijklmnopqrstuvwxyz123456",

      origin: "https://app.example.com",
    });
    expect(web).toEqual({ clientType: "web", status: 204 });
    expect(native.clientType).toBe("native");
    if (native.clientType === "native") expect(native.session.sessionReference).toBe(reference);
    expect(requests[0]?.withCredentials).toBe(true);
    expect(requests[0]?.data).toEqual({
      code: "authorization-code",
      codeVerifier: "verifier_abcdefghijklmnopqrstuvwxyz123456789",
      redirectUri: config.oidc.h5RedirectUri,
      state: "state_abcdefghijklmnopqrstuvwxyz123456",
      clientId: "client-1",
      clientType: "web",
    });
    expect(requests[1]?.withCredentials).toBe(true);
     expect(requests[1]?.data).toEqual({ state: "state_abcdefghijklmnopqrstuvwxyz123456", code: "authorization-code", flowBinding: "flow_abcdefghijklmnopqrstuvwxyz123456" });

  });
});
