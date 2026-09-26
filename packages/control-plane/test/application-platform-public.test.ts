import { describe, expect, it, vi } from "vitest";
import {
  InMemoryPlatformLoginStateStore,
  hashPlatformLoginBinding,
  hashPlatformLoginState,
  type PlatformIdentity,
  type PlatformSessionIssueInput,
} from "@getbrick/idaas-core";
import { ApplicationPlatformAuthService } from "../src/application-platform-service.js";
import { ApplicationPlatformRuntimeController } from "../src/application-platform-controller.js";
import { InMemoryApplicationRepository } from "../src/application-repository.js";

const callbackUri = "https://app.example.test/platform/callback";

function repository() {
  return new InMemoryApplicationRepository({
    applications: [{ id: "app-1", name: "Alpha", slug: "alpha", status: "active" }],
    platforms: [{
      id: "platform-1",
      applicationId: "app-1",
      type: "wechat_official_account",
      externalAppId: "wx-app",
      redirectUris: [callbackUri],
      status: "active",
    }],
  });
}

function identity(subject = "subject-1"): PlatformIdentity {
  return {
    provider: "wechat",
    platform: "wechat_official_account",
    appId: "wx-app",
    subject,
    scopes: ["snsapi_userinfo"],
  };
}

describe("ApplicationPlatformAuthService public channel boundaries", () => {
  it("rejects public user targets and uses host context for linking", async () => {
    const linker = vi.fn(async () => ({ userId: "host-user", user: { id: "host-user", name: "Host", email: null, emailVerified: false } }));
    const issued: PlatformSessionIssueInput[] = [];
    const service = new ApplicationPlatformAuthService(repository(), {
      resolveCredentials: () => ({ appId: "wx-app", appSecret: "server-secret" }),
      adapters: [{
        type: "wechat_official_account",
        supportsAuthorization: true,
        createAuthorizationUrl: ({ state }) => `https://provider.example.test/authorize?state=${encodeURIComponent(state)}`,
        exchangeCode: async () => identity(),
      }],
      resolveHostContext: () => ({ userId: "host-user", identityLinkingPolicy: { mode: "link_existing", userId: "host-user" } }),
      login: {
        stateStore: new InMemoryPlatformLoginStateStore(),
        identityLinker: { link: linker },
        sessionIssuer: { issue: async (input) => {
          issued.push(input);
           return { response: new Response(null, { status: 204, headers: { "Set-Cookie": "host_session=opaque; Path=/; HttpOnly; Secure; SameSite=Lax" } }) };
        } },
      },
    });

    await expect(service.createPublicLogin("app-1", "platform-1", {
      redirectUri: callbackUri,
      requestedUserId: "attacker",
    } as never)).rejects.toMatchObject({ code: "invalid_platform_request" });
     const start = await service.createPublicLogin("app-1", "platform-1", { redirectUri: callbackUri, returnTo: "/dashboard/continue%41" }, undefined, { browserId: "binding" });
     const result = await service.completePublicLogin("app-1", "platform-1", {
      state: start.state,
      code: "provider-code",
    }, undefined, { browserId: "binding" });
     expect(result.user.id).toBe("host-user");
     expect(result.returnTo).toBe("/dashboard/continue%41");
     expect(linker).toHaveBeenCalledWith(expect.objectContaining({ policy: expect.objectContaining({ mode: "link_existing", userId: "host-user" }), requestedUserId: "host-user" }));
    expect(issued[0]?.user.id).toBe("host-user");
  });

  it("uses the repository tenant for state, identity scope, and production callbacks", async () => {
    const tenantRepository = new InMemoryApplicationRepository({
      tenantId: "tenant-a",
      applications: [{ id: "app-1", name: "Alpha", slug: "alpha", status: "active" }],
      platforms: [{ id: "platform-1", applicationId: "app-1", type: "wechat_official_account", externalAppId: "wx-app", redirectUris: [callbackUri], status: "active" }],
    });
    const stateStore = new InMemoryPlatformLoginStateStore();
    const linker = vi.fn(async () => ({ userId: "user-1" }));
    const service = new ApplicationPlatformAuthService(tenantRepository, {
      resolveCredentials: () => ({ appId: "wx-app", appSecret: "server-secret" }),
      adapters: [{
        type: "wechat_official_account",
        supportsAuthorization: true,
        createAuthorizationUrl: ({ state }) => `https://provider.example.test/authorize?state=${encodeURIComponent(state)}`,
        exchangeCode: async () => identity(),
      }],
      login: {
         stateStore,
         identityLinker: { link: linker },
         sessionIssuer: { issue: async () => ({ response: new Response(null, { status: 204, headers: { "Set-Cookie": "host_session=opaque; Path=/; HttpOnly; Secure; SameSite=Lax" } }) }) },
      },
    });
    const start = await service.createPublicLogin("app-1", "platform-1", { redirectUri: callbackUri }, undefined, { browserId: "server-binding" });
    const records = (stateStore as unknown as { records: Map<string, { tenantId: string }> }).records;
    expect([...records.values()][0]?.tenantId).toBe("tenant-a");
    await service.completePublicLogin("app-1", "platform-1", { state: start.state, code: "provider-code" }, undefined, { browserId: "server-binding" });
    expect(linker).toHaveBeenCalledWith(expect.objectContaining({
      tenantId: "tenant-a",
      applicationId: "app-1",
      identityKey: expect.stringContaining("tenant-a|app-1|"),
    }));
  });

  it("rejects client browser bindings and linking fields at the public start boundary", async () => {
    const service = new ApplicationPlatformAuthService(repository(), {
      resolveCredentials: () => ({ appId: "wx-app", appSecret: "server-secret" }),
      login: {
        stateStore: new InMemoryPlatformLoginStateStore(),
        identityLinker: { link: async () => ({ userId: "user-1" }) },
        sessionIssuer: { issue: async () => ({ sessionReference: "host-reference" }) },
      },
    });
    await expect(service.createPublicLogin("app-1", "platform-1", { redirectUri: callbackUri, browserId: "client" } as never)).rejects.toMatchObject({ code: "invalid_platform_request" });
    await expect(service.createPublicLogin("app-1", "platform-1", { redirectUri: callbackUri, identityLinkingPolicy: "create" } as never)).rejects.toMatchObject({ code: "invalid_platform_request" });
    await expect(service.createPublicLogin("app-1", "platform-1", { redirectUri: callbackUri, returnTo: "//evil.example/path" })).rejects.toMatchObject({ code: "invalid_return_to" });
  });

  it("keeps native exchange state-bound and mini-program exchange state-free", async () => {
    const exchangeCode = vi.fn(async ({ redirectUri }: { redirectUri?: string }) => identity(redirectUri === undefined ? "mini" : "native"));
    const service = new ApplicationPlatformAuthService(repository(), {
      resolveCredentials: () => ({ appId: "wx-app", appSecret: "server-secret" }),
      adapters: [{
        type: "wechat_official_account",
        supportsAuthorization: true,
        createAuthorizationUrl: ({ state }) => `https://provider.example.test/authorize?state=${state}`,
        exchangeCode,
      }],
      login: {
        stateStore: new InMemoryPlatformLoginStateStore(),
        identityLinker: { link: async () => ({ userId: "user-1" }) },
        sessionIssuer: { issue: async () => ({ sessionId: "app-session" }) },
      },
    });
    await expect(service.startNativeLogin("app-1", "platform-1", { redirectUri: callbackUri, returnTo: "/dashboard" } as never)).rejects.toMatchObject({ code: "invalid_return_to" });
    const native = await service.startNativeLogin("app-1", "platform-1", { redirectUri: callbackUri });
    const nativeResult = await service.exchangeNativeLogin("app-1", "platform-1", { state: native.state, code: "native-code" });
    expect(nativeResult.client).toBe("native");
    const miniResult = await service.exchangeMiniProgram("app-1", "platform-1", { code: "mini-code" });
    expect(miniResult.client).toBe("mini_program");
    expect(exchangeCode).toHaveBeenLastCalledWith(expect.objectContaining({ code: "mini-code" }));
  });

  it("exposes separate native and mini-program HTTP contracts", async () => {
    const calls: string[] = [];
    const service = {
      startNativeLogin: async () => {
        calls.push("native-start");
        return { authorizationUrl: "https://provider.example.test/authorize?state=" + "b".repeat(43), state: "b".repeat(43), expiresAt: new Date().toISOString() };
      },
      exchangeNativeLogin: async () => {
        calls.push("native-exchange");
        return { user: { id: "u", name: "U", email: null, emailVerified: false }, identity: {}, account: {}, session: { sessionId: "app-session" }, created: true, linked: false, client: "native" };
      },
      exchangeMiniProgram: async () => {
        calls.push("mini-exchange");
        return { user: { id: "u", name: "U", email: null, emailVerified: false }, identity: {}, account: {}, session: { sessionId: "app-session" }, created: true, linked: false, client: "mini_program" };
      },
    };
    const controller = new ApplicationPlatformRuntimeController(service as never);
    const headers: Record<string, string> = {};
    const response = {
      setHeader(name: string, value: string) { headers[name] = value; },
      status() { return response; },
      json() { return response; },
      end() { return response; },
    };
    await controller.startNativeLogin("app-1", "platform-1", { redirectUri: callbackUri }, { headers: {} }, response);
    expect(headers["Set-Cookie"]).toBeUndefined();
    await controller.exchangeNativeLogin("app-1", "platform-1", { state: "b".repeat(43), code: "native-code" }, { headers: {} }, response);
    await controller.exchangeMiniProgram("app-1", "platform-1", { code: "mini-code" }, { headers: {} }, response);
    expect(calls).toEqual(["native-start", "native-exchange", "mini-exchange"]);
  });

  it("does not silently discard a response-only native session", async () => {
    const service = {
      exchangeNativeLogin: async () => ({
        user: { id: "u", name: "U", email: null, emailVerified: false },
        identity: {},
        account: {},
        session: { response: new Response(null, { status: 204 }) },
        created: true,
        linked: false,
        client: "native" as const,
      }),
    };
    const controller = new ApplicationPlatformRuntimeController(service as never);
    let statusCode = 0;
    let body: unknown;
    const response = {
      setHeader() { return response; },
      status(code: number) { statusCode = code; return response; },
      json(value: unknown) { body = value; return response; },
      end() { return response; },
    };
    await controller.exchangeNativeLogin("app-1", "platform-1", { state: "b".repeat(43), code: "native-code" }, { headers: {} }, response);
    expect(statusCode).toBe(400);
    expect(body).toMatchObject({ error: { code: "INVALID_REQUEST", details: { reason: "invalid_session_issuer_result" } } });
  });

  it("rejects provider error fields on mini-program exchange", async () => {
    const calls: string[] = [];
    const service = {
      exchangeMiniProgram: async () => {
        calls.push("mini-exchange");
        return {
          user: { id: "u", name: "U", email: null, emailVerified: false },
          identity: {},
          account: {},
          session: { sessionReference: "app-session" },
          created: true,
          linked: false,
          client: "mini_program" as const,
        };
      },
    };
    const controller = new ApplicationPlatformRuntimeController(service as never);
    const response = {
      setHeader() { return response; },
      status() { return response; },
      json() { return response; },
      end() { return response; },
    };
    await controller.exchangeMiniProgram("app-1", "platform-1", { code: "mini-code", error: "denied" }, { headers: {} }, response);
    expect(calls).toEqual([]);
  });

  it("uses an HttpOnly Secure SameSite binding cookie on the web channel", async () => {
    const calls: Array<Record<string, unknown>> = [];
    const service = {
      createPublicLogin: async (...args: unknown[]) => {
        calls.push({ kind: "start", args });
        return { authorizationUrl: "https://provider.example.test/authorize?state=" + "a".repeat(43), state: "a".repeat(43), expiresAt: new Date().toISOString() };
      },
      completePublicLogin: async (...args: unknown[]) => {
        calls.push({ kind: "callback", args });
        return {
          user: { id: "user-1", name: "User", email: null, emailVerified: false },
          identity: { provider: "wechat", platform: "wechat_official_account", appId: "wx", subject: "s", scopes: [], email: null },
          account: { providerId: "wechat", accountId: "s", platform: "wechat_official_account", appId: "wx", scopes: [] },
          session: { response: new Response(null, { status: 204 }) },
          created: true,
          linked: false,
        };
      },
    };
    const controller = new ApplicationPlatformRuntimeController(service as never);
    const headers: Record<string, string> = {};
    const response = {
      setHeader(name: string, value: string) { headers[name] = value; },
      status() { return response; },
      json() { return response; },
      end() { return response; },
    };
    await controller.startLogin("app-1", "platform-1", { redirectUri: callbackUri }, { headers: {} }, response);
    const setCookie = headers["Set-Cookie"] ?? "";
    expect(setCookie).toContain("HttpOnly");
    expect(setCookie).toContain("Secure");
    expect(setCookie).toContain("SameSite=Lax");
    expect(headers["Cache-Control"]).toBe("no-store");
    const cookie = setCookie.split(";")[0] ?? "";
    await controller.postCallback("app-1", "platform-1", { state: "a".repeat(43), code: "provider-code" }, { headers: { cookie } }, response);
    const callback = calls.find((call) => call.kind === "callback");
    expect(callback?.args).toBeDefined();
  });

  it("redirects web GET callbacks with a trusted returnTo and ignores issuer Location", async () => {
    const calls: string[] = [];
    const service = {
      createPublicLogin: async () => ({
        authorizationUrl: "https://provider.example.test/authorize?state=" + "r".repeat(43),
        state: "r".repeat(43),
        expiresAt: new Date().toISOString(),
      }),
      completePublicLogin: async () => {
        calls.push("callback");
        return {
          user: { id: "user-1", name: "User", email: null, emailVerified: false },
          identity: {},
          account: {},
          session: { response: new Response(null, { status: 302, headers: { Location: "https://evil.example/redirect", "Set-Cookie": "host_session=opaque; Path=/; HttpOnly; Secure; SameSite=Lax" } }) },
          returnTo: "/dashboard/continue%41",
          created: true,
          linked: false,
        };
      },
    };
    const controller = new ApplicationPlatformRuntimeController(service as never);
    const headers: Record<string, string | string[]> = {};
    const response = {
      setHeader(name: string, value: string | string[]) { headers[name] = value; return response; },
      getHeader(name: string) { return headers[name]; },
      status(code: number) { headers.Status = String(code); return response; },
      json(value: unknown) { headers.Body = JSON.stringify(value); return response; },
      end() { headers.Ended = "true"; return response; },
    };
    await controller.startLogin("app-1", "platform-1", { redirectUri: callbackUri }, { headers: {} }, response);
    const bindingCookie = (headers["Set-Cookie"] as string).split(";")[0] ?? "";
    await controller.getCallback("app-1", "platform-1", { headers: { cookie: bindingCookie }, query: { state: "r".repeat(43), code: "provider-code" } }, response);
    expect(calls).toEqual(["callback"]);
    expect(headers.Status).toBe("303");
    expect(headers.Location).toBe("/dashboard/continue%41");
    expect(headers.Location).not.toContain("evil.example");
    expect(String(headers["Set-Cookie"])).toContain("host_session=opaque");
    expect(String(headers["Set-Cookie"])).toContain("Max-Age=0");
    expect(headers.Ended).toBe("true");
  });

  it("keeps POST and no-returnTo behavior JSON or 204 without redirecting", async () => {
    const service = {
      createPublicLogin: async () => ({
        authorizationUrl: "https://provider.example.test/authorize?state=" + "s".repeat(43),
        state: "s".repeat(43),
        expiresAt: new Date().toISOString(),
      }),
      completePublicLogin: async () => ({
        user: { id: "user-1", name: "User", email: null, emailVerified: false },
        identity: {},
        account: {},
        session: { sessionReference: "host-reference" },
        created: true,
        linked: false,
      }),
    };
    const controller = new ApplicationPlatformRuntimeController(service as never);
    const headers: Record<string, string | string[]> = {};
    const response = {
      setHeader(name: string, value: string | string[]) { headers[name] = value; return response; },
      getHeader(name: string) { return headers[name]; },
      status(code: number) { headers.Status = String(code); return response; },
      json(value: unknown) { headers.Body = JSON.stringify(value); return response; },
      end() { headers.Ended = "true"; return response; },
    };
    await controller.startLogin("app-1", "platform-1", { redirectUri: callbackUri }, { headers: {} }, response);
    const bindingCookie = (headers["Set-Cookie"] as string).split(";")[0] ?? "";
    await controller.postCallback("app-1", "platform-1", { state: "s".repeat(43), code: "provider-code" }, { headers: { cookie: bindingCookie } }, response);
    expect(headers.Status).toBe("200");
    expect(headers.Body).toContain("clientKind");
    expect(headers.Location).toBeUndefined();
  });
});

const bridgeBinding = "flow_abcdefghijklmnopqrstuvwxyz123456";

function bridgeRepository() {
  return new InMemoryApplicationRepository({
    applications: [
      { id: "app-1", name: "Alpha", slug: "alpha", status: "active" },
      { id: "app-2", name: "Beta", slug: "beta", status: "active" },
    ],
    platforms: [
      { id: "platform-1", applicationId: "app-1", type: "wechat_official_account", externalAppId: "wx-app", redirectUris: [callbackUri], status: "active" },
      { id: "platform-2", applicationId: "app-2", type: "wechat_official_account", externalAppId: "wx-app", redirectUris: [callbackUri], status: "active" },
    ],
  });
}

function bridgeService(stateStore = new InMemoryPlatformLoginStateStore()) {
  const service = new ApplicationPlatformAuthService(bridgeRepository(), {
    resolveCredentials: () => ({ appId: "wx-app", appSecret: "server-secret" }),
    adapters: [{
      type: "wechat_official_account",
      supportsAuthorization: true,
      createAuthorizationUrl: ({ state }) => `https://provider.example.test/authorize?state=${encodeURIComponent(state)}`,
      exchangeCode: async () => identity(),
    }],
    login: {
      stateStore,
      identityLinker: { link: async () => ({ userId: "user-1" }) },
      sessionIssuer: { issue: async () => ({ sessionReference: "ocs_bridge_session_reference_123" }) },
    },
  });
  return { service, stateStore };
}

function responseRecorder() {
  const headers: Record<string, string | string[]> = {};
  let statusCode = 0;
  let body: unknown;
  const response = {
    setHeader(name: string, value: string | string[]) { headers[name] = value; return response; },
    getHeader(name: string) { return headers[name]; },
    status(code: number) { statusCode = code; return response; },
    json(value: unknown) { body = value; return response; },
    end() { return response; },
  };
  return { response, headers, body: () => body, status: () => statusCode };
}

describe("ApplicationPlatform webview bridge binding", () => {
  it("stores only a hashed flowBinding as the webview session binding and preserves state on binding failures", async () => {
    const { service, stateStore } = bridgeService();
    const start = await service.startWebviewLogin("app-1", "platform-1", {
      redirectUri: callbackUri,
      flowBinding: bridgeBinding,
    });
    const stateHash = hashPlatformLoginState(start.state);
    const records = (stateStore as unknown as { records: Map<string, { sessionBindingHash?: string; browserBindingHash?: string; flow?: string }> }).records;
    const record = [...records.values()][0];
    expect(record).toMatchObject({ flow: "webview", sessionBindingHash: hashPlatformLoginBinding(bridgeBinding) });
    expect(record?.browserBindingHash).toBeUndefined();
    expect(JSON.stringify(record)).not.toContain(bridgeBinding);

    await expect(service.completeWebviewLogin("app-1", "platform-1", {
      state: start.state,
      code: "provider-code",
    })).rejects.toMatchObject({ code: "invalid_platform_binding" });
    expect(stateStore.status(stateHash, "default", "app-1")).toBe("issued");

    await expect(service.completeWebviewLogin("app-1", "platform-1", {
      state: start.state,
      code: "provider-code",
      flowBinding: "flow_wrong_abcdefghijklmnopqrstuvwxyz123456",
    })).rejects.toMatchObject({ code: "platform_state_binding_mismatch" });
    expect(stateStore.status(stateHash, "default", "app-1")).toBe("issued");

    await expect(service.completeWebviewLogin("app-2", "platform-2", {
      state: start.state,
      code: "provider-code",
      flowBinding: bridgeBinding,
    })).rejects.toMatchObject({ code: "invalid_platform_state" });
    expect(stateStore.status(stateHash, "default", "app-1")).toBe("issued");

    const result = await service.completeWebviewLogin("app-1", "platform-1", {
      state: start.state,
      code: "provider-code",
      flowBinding: bridgeBinding,
    });
    expect(result).toMatchObject({ client: "webview", session: { sessionReference: "ocs_bridge_session_reference_123" } });
    expect(stateStore.status(stateHash, "default", "app-1")).toBe("consumed");
    await expect(service.completeWebviewLogin("app-1", "platform-1", {
      state: start.state,
      code: "provider-code",
      flowBinding: bridgeBinding,
    })).rejects.toMatchObject({ code: "invalid_platform_state" });
  });

  it("rejects generic binding fields and untrusted callback scope at the service boundary", async () => {
    const { service } = bridgeService();
    await expect(service.startWebviewLogin("app-1", "platform-1", {
      redirectUri: callbackUri,
      flowBinding: bridgeBinding,
      browserId: "browser-binding",
    } as never)).rejects.toMatchObject({ code: "invalid_platform_request" });
    await expect(service.completeWebviewLogin("app-1", "platform-1", {
      state: "a".repeat(43),
      code: "provider-code",
      flowBinding: bridgeBinding,
      applicationId: "app-2",
    } as never)).rejects.toMatchObject({ code: "invalid_platform_request" });
  });

  it("accepts a bridge POST without a cookie, rejects missing/wrong token, cross-application, and replay", async () => {
    const { service, stateStore } = bridgeService();
    const controller = new ApplicationPlatformRuntimeController(service as never);
    const startRecorder = responseRecorder();
    await controller.startWebviewLogin("app-1", "platform-1", {
      redirectUri: callbackUri,
      client: "webview",
      flowBinding: bridgeBinding,
    }, { headers: {} }, startRecorder.response);
    expect(startRecorder.status()).toBe(200);
    expect(startRecorder.body()).toMatchObject({ client: "webview" });
    expect(startRecorder.body()).not.toHaveProperty("flowBinding");
    expect(startRecorder.headers["Set-Cookie"]).toBeUndefined();
    const started = startRecorder.body() as { state: string };

    const missingRecorder = responseRecorder();
    await controller.completeWebviewLogin("app-1", "platform-1", {
      state: started.state,
      code: "provider-code",
    }, { headers: {} }, missingRecorder.response);
    expect(missingRecorder.status()).toBe(400);
    expect(missingRecorder.body()).toMatchObject({ error: { details: { reason: "invalid_platform_binding" } } });

    const wrongRecorder = responseRecorder();
    await controller.completeWebviewLogin("app-1", "platform-1", {
      state: started.state,
      code: "provider-code",
      flowBinding: "flow_wrong_abcdefghijklmnopqrstuvwxyz123456",
    }, { headers: {} }, wrongRecorder.response);
    expect(wrongRecorder.status()).toBe(400);
    expect(stateStore.status(hashPlatformLoginState(started.state), "default", "app-1")).toBe("issued");

    const crossRecorder = responseRecorder();
    await controller.completeWebviewLogin("app-2", "platform-2", {
      state: started.state,
      code: "provider-code",
      flowBinding: bridgeBinding,
    }, { headers: {} }, crossRecorder.response);
    expect(crossRecorder.status()).toBe(400);
    expect(stateStore.status(hashPlatformLoginState(started.state), "default", "app-1")).toBe("issued");

    const getRecorder = responseRecorder();
    await controller.getWebviewCallback("app-1", "platform-1", {
      headers: {},
      query: { state: started.state, code: "provider-code" },
    }, getRecorder.response);
    expect(getRecorder.status()).toBe(400);
    expect(getRecorder.body()).toMatchObject({ error: { details: { reason: "invalid_platform_binding" } } });

    const successRecorder = responseRecorder();
    await controller.completeWebviewLogin("app-1", "platform-1", {
      state: started.state,
      code: "provider-code",
      flowBinding: bridgeBinding,
    }, { headers: {} }, successRecorder.response);
    expect(successRecorder.status()).toBe(200);
    expect(successRecorder.body()).toMatchObject({ clientKind: "webview", session: { sessionReference: "ocs_bridge_session_reference_123" } });
    expect(JSON.stringify(successRecorder.body())).not.toContain(bridgeBinding);

    const replayRecorder = responseRecorder();
    await controller.completeWebviewLogin("app-1", "platform-1", {
      state: started.state,
      code: "provider-code",
      flowBinding: bridgeBinding,
    }, { headers: {} }, replayRecorder.response);
    expect(replayRecorder.status()).toBe(400);
  });
});
