import { describe, expect, it, vi } from "vitest";
import {
  ApplicationPlatformError,
  ExplicitPlatformIdentityLinker,
  InMemoryPlatformLoginStateStore,
  PlatformLoginFlow,
  PlatformLoginStateManager,
  createPlatformLoginFlow,
  createPlaceholderEmail,
  createPlatformIdentityKey,
  createPostgresPlatformLoginStateStore,
  createPlatformSessionIssuerBridge,
  hashPlatformLoginBinding,
  isValidPlatformLoginReturnTo,
  projectPlatformIdentity,
  type PlatformIdentity,
  type PlatformIdentityLinkStore,
  type PlatformSessionIssueInput,
} from "../src/index.js";

const redirectUri = "https://app.example.test/platform/callback";

function identity(overrides: Partial<PlatformIdentity> = {}): PlatformIdentity {
  return {
    provider: "wechat",
    platform: "wechat_official_account",
    appId: "wx-app",
    subject: "subject-1",
    nickname: "Platform User",
    scopes: ["snsapi_userinfo"],
    ...overrides,
  };
}

describe("platform login state", () => {
  it("stores only a hash, binds browser and session, expires, and consumes once", async () => {
    const store = new InMemoryPlatformLoginStateStore();
    let now = 1_000;
    let issueIndex = 0;
    const manager = new PlatformLoginStateManager(store, {
      now: () => now,
      randomState: () => ["a".repeat(43), "c".repeat(43)][issueIndex++],
    });
    const issued = await manager.issue({
      applicationId: "app-1",
      platformId: "platform-1",
      redirectUri,
      binding: { browserId: "browser-1", sessionId: "session-1" },
      linkingPolicy: "create",
    });

    expect(issued.state).toBe("a".repeat(43));
    const records = (store as unknown as { records: Map<string, unknown> }).records;
    expect(JSON.stringify([...records.values()])).not.toContain(issued.state);
    expect(JSON.stringify([...records.values()])).toContain(issued.record.stateHash);
    await expect(manager.consume({
      state: issued.state,
      binding: { browserId: "other-browser", sessionId: "session-1" },
    })).rejects.toMatchObject({ code: "platform_state_binding_mismatch" });
    await expect(manager.consume({
      state: issued.state,
      binding: { browserId: "browser-1", sessionId: "session-1" },
    })).resolves.toMatchObject({ stateHash: issued.record.stateHash });
    await expect(manager.consume({
      state: issued.state,
      binding: { browserId: "browser-1", sessionId: "session-1" },
    })).rejects.toMatchObject({ code: "invalid_platform_state" });

    const expiring = await manager.issue({
      applicationId: "app-1",
      platformId: "platform-1",
      redirectUri,
      binding: { browserId: "browser-1" },
      linkingPolicy: "create",
    });
    now += 10 * 60 * 1000;
    await expect(manager.consume({
      state: expiring.state,
      binding: { browserId: "browser-1" },
    })).rejects.toMatchObject({ code: "platform_state_expired" });
  });
  it("persists the exact returnTo and fails closed when state is tampered", async () => {
    const store = new InMemoryPlatformLoginStateStore();
    let index = 0;
    const manager = new PlatformLoginStateManager(store, {
      randomState: () => ["j".repeat(43), "k".repeat(43)][index++],
    });
    const returnTo = "/workspace/continue?tab=one%41two";
    const issued = await manager.issue({
      applicationId: "app-1",
      platformId: "platform-1",
      redirectUri,
      returnTo,
      binding: { browserId: "browser-1" },
      linkingPolicy: "create",
    });
    expect(issued.record.returnTo).toBe(returnTo);
    expect(store.peek(issued.record.stateHash, { tenantId: "default" })).toMatchObject({ returnTo });
    const stored = [...(store as unknown as { records: Map<string, { returnTo?: string }> }).records.values()][0];
    if (stored !== undefined) stored.returnTo = "https://evil.example/redirect";
    expect(store.peek(issued.record.stateHash, { tenantId: "default" })).toBeUndefined();
    await expect(manager.consume({ state: issued.state, binding: { browserId: "browser-1" } })).rejects.toMatchObject({ code: "invalid_platform_state" });

    const second = await manager.issue({
      applicationId: "app-1",
      platformId: "platform-1",
      redirectUri,
      returnTo,
      binding: { browserId: "browser-1" },
      linkingPolicy: "create",
    });
    await expect(manager.consume({ state: second.state, binding: { browserId: "browser-1" } })).resolves.toMatchObject({ returnTo });
    await expect(manager.consume({ state: second.state, binding: { browserId: "browser-1" } })).rejects.toMatchObject({ code: "invalid_platform_state" });
  });

  it("keeps webview and mp claims distinct and only consumes a lease with its owner", async () => {
    const store = new InMemoryPlatformLoginStateStore();
    let index = 0;
    const manager = new PlatformLoginStateManager(store, {
      randomState: () => ["h".repeat(43), "i".repeat(43)][index++],
    });
    const webview = await manager.issue({
      applicationId: "app-1",
      platformId: "webview-1",
      redirectUri,
      client: "webview",
      linkingPolicy: "create",
    });
    const mp = await manager.issue({
      applicationId: "app-1",
      platformId: "mp-1",
      redirectUri,
      client: "mini_program",
      linkingPolicy: "create",
    });
    expect(webview.record).toMatchObject({ client: "webview", flow: "webview" });
    expect(mp.record).toMatchObject({ client: "mp_weixin", flow: "mp_weixin" });
    const leased = store.lease(mp.record.stateHash, "worker-a", 1_000, {
      tenantId: "default",
      applicationId: "app-1",
      platformId: "mp-1",
      client: "mp_weixin",
      flow: "mp_weixin",
    });
    expect(leased).toMatchObject({ status: "leased", leaseOwner: "worker-a" });
    await expect(manager.consume({ state: mp.state, client: "mp_weixin", leaseOwner: "worker-b" })).rejects.toMatchObject({ code: "invalid_platform_state" });
    await expect(manager.consume({ state: mp.state, client: "mp_weixin", leaseOwner: "worker-a" })).resolves.toMatchObject({ status: "consumed" });
  });
});

describe("tenant-scoped platform state persistence", () => {
  it("isolates identical state hashes by tenant and preserves a state after a bad binding", async () => {
    const store = new InMemoryPlatformLoginStateStore();
    const states = ["a".repeat(43), "a".repeat(43)];
    let index = 0;
    const first = new PlatformLoginStateManager(store, { now: () => 1_000, randomState: () => states[index++] });
    const second = new PlatformLoginStateManager(store, { now: () => 1_000, randomState: () => states[index++] });
    const tenantA = await first.issue({
      tenantId: "tenant-a",
      applicationId: "app-1",
      platformId: "platform-1",
      redirectUri,
      binding: { browserId: "browser-a" },
      linkingPolicy: "create",
    });
    const tenantB = await second.issue({
      tenantId: "tenant-b",
      applicationId: "app-1",
      platformId: "platform-1",
      redirectUri,
      binding: { browserId: "browser-b" },
      linkingPolicy: "create",
    });
    expect(tenantA.record.stateHash).toBe(tenantB.record.stateHash);
    expect(tenantA.record.tenantId).toBe("tenant-a");
    expect(tenantB.record.tenantId).toBe("tenant-b");
    await expect(first.consume({ tenantId: "tenant-a", state: tenantA.state, binding: { browserId: "wrong" } })).rejects.toMatchObject({ code: "platform_state_binding_mismatch" });
    await expect(first.consume({ tenantId: "tenant-a", state: tenantA.state, binding: { browserId: "browser-a" } })).resolves.toMatchObject({ tenantId: "tenant-a" });
    await expect(second.consume({ tenantId: "tenant-b", state: tenantB.state, binding: { browserId: "browser-b" } })).resolves.toMatchObject({ tenantId: "tenant-b" });
  });

  it("recovers returnTo across manager instances sharing the same state store", async () => {
    const store = new InMemoryPlatformLoginStateStore();
    const issuer = new PlatformLoginStateManager(store, { randomState: () => "l".repeat(43) });
    const consumer = new PlatformLoginStateManager(store, { randomState: () => "m".repeat(43) });
    const issued = await issuer.issue({
      applicationId: "app-1",
      platformId: "platform-1",
      redirectUri,
      returnTo: "/resume%41",
      binding: { browserId: "browser-1" },
      linkingPolicy: "create",
    });
    await expect(consumer.consume({ state: issued.state, binding: { browserId: "browser-1" } })).resolves.toMatchObject({ returnTo: "/resume%41" });
  });

  it("uses the migrated tenant schema without runtime DDL and atomically consumes once", async () => {
    const calls: Array<{ text: string; values: unknown[] }> = [];
    let row: Record<string, unknown> | undefined;
    const executor = {
      query: async (text: string, values: unknown[] = []) => {
        calls.push({ text, values });
        if (text.startsWith("INSERT INTO")) {
          row = {
            tenant_id: values[0],
            state_hash: values[1],
            binding_hash: values[2],
            browser_binding_hash: values[3],
            session_binding_hash: values[4],
            application_id: values[5],
            platform_id: values[6],
            flow: values[7],
            status: values[8],
            lease_owner: values[9],
            lease_expires_at: values[10],
            expires_at: values[11],
            redirect_uri: values[12],
            scope: values[13],
            linking_policy: values[14],
             requested_user_id: values[15],
             created_at: values[16],
             updated_at: values[17],
             consumed_at: values[18],
             return_to: values[19],
           };
          return { rows: [] };
        }
        if (text.startsWith("UPDATE")) {
          if (row?.status === "issued" && values.includes(hashPlatformLoginBinding("browser-1"))) {
            row = { ...row, status: "consumed", consumed_at: new Date(1_000).toISOString(), updated_at: new Date(1_000).toISOString() };
            return { rows: [row] };
          }
          return { rows: [] };
        }
        return { rows: row === undefined ? [] : [row] };
      },
    };
      const store = createPostgresPlatformLoginStateStore(executor, { tenantId: "tenant-a", now: () => 1_000 });
      expect(await store.ready()).toBe(true);
      expect(calls.some((call) => call.text.includes("SELECT return_to"))).toBe(true);
     const manager = new PlatformLoginStateManager(store, { now: () => 1_000, randomState: () => "b".repeat(43) });
     const issued = await manager.issue({
       tenantId: "tenant-a",
       applicationId: "app-1",
       platformId: "platform-1",
       redirectUri,
       returnTo: "/workspace/continue%41",
       binding: { browserId: "browser-1", sessionId: "session-1" },
      linkingPolicy: "create",
    });
    expect(calls.some((call) => /CREATE\s+TABLE/iu.test(call.text))).toBe(false);
     expect(calls.find((call) => call.text.startsWith("INSERT INTO"))?.text).toContain("tenant_id");
      expect(calls.find((call) => call.text.startsWith("INSERT INTO"))?.text).toContain("return_to");
      expect(calls.find((call) => call.text.startsWith("INSERT INTO"))?.text).toContain("status");
      await store.peek(issued.record.stateHash, { tenantId: "tenant-a", applicationId: "app-1" });
      expect(await store.peek(issued.record.stateHash, { tenantId: "tenant-a", applicationId: "app-1" })).toMatchObject({ returnTo: "/workspace/continue%41" });
     expect(calls.find((call) => call.text.startsWith("SELECT") && call.values.includes("app-1"))?.text).toContain("application_id = $3");
     const wrong = await store.claim(issued.record.stateHash, {
      tenantId: "tenant-a",
      browserBindingHash: hashPlatformLoginBinding("wrong"),
      sessionBindingHash: hashPlatformLoginBinding("session-1"),
      client: "web",
      flow: "web",
    });
    expect(wrong).toBeUndefined();
    expect(await store.status(issued.record.stateHash, "tenant-a")).toBe("issued");
    const results = await Promise.all([
      store.claim(issued.record.stateHash, { tenantId: "tenant-a", browserBindingHash: hashPlatformLoginBinding("browser-1"), sessionBindingHash: hashPlatformLoginBinding("session-1"), client: "web", flow: "web" }),
      store.claim(issued.record.stateHash, { tenantId: "tenant-a", browserBindingHash: hashPlatformLoginBinding("browser-1"), sessionBindingHash: hashPlatformLoginBinding("session-1"), client: "web", flow: "web" }),
    ]);
    expect(results.filter((result) => result !== undefined)).toHaveLength(1);
    expect(await store.status(issued.record.stateHash, "tenant-a")).toBe("consumed");
    expect(calls.find((call) => call.text.startsWith("UPDATE"))?.text).toContain("status = 'consumed'");
  });
  it("keeps application scope on preview and consume claims", async () => {
    const store = new InMemoryPlatformLoginStateStore();
    const manager = new PlatformLoginStateManager(store, { randomState: () => "d".repeat(43) });
    const issued = await manager.issue({
      applicationId: "app-a",
      platformId: "platform-a",
      redirectUri,
      binding: { browserId: "browser-a" },
      linkingPolicy: "create",
    });
     const other = await manager.issue({
       applicationId: "app-b",
       platformId: "platform-b",
       redirectUri,
       binding: { browserId: "browser-b" },
       linkingPolicy: "create",
     });
     expect(other.state).toBe(issued.state);
     expect(store.peek(issued.record.stateHash, { tenantId: "default", applicationId: "app-b" })).toMatchObject({ applicationId: "app-b" });
      await expect(manager.consume({
        state: issued.state,
        binding: { browserId: "browser-b" },
        expectedApplicationId: "app-c",
      })).rejects.toMatchObject({ code: "invalid_platform_state" });
      await expect(manager.consume({
        state: issued.state,
        binding: { browserId: "browser-b" },
        expectedApplicationId: "app-b",
      })).resolves.toMatchObject({ applicationId: "app-b" });
      expect(store.status(issued.record.stateHash, "default", "app-a")).toBe("issued");
      await expect(manager.consume({
        state: issued.state,
        binding: { browserId: "browser-a" },
        expectedApplicationId: "app-a",
      })).resolves.toMatchObject({ applicationId: "app-a" });
      expect(store.status(other.record.stateHash, "default", "app-b")).toBe("consumed");
   });

  it("does not claim expired or claimed state and releases only the lease owner", async () => {
    let now = 1_000;
    const store = new InMemoryPlatformLoginStateStore({ now: () => now });
    const states = ["e".repeat(43), "f".repeat(43), "g".repeat(43)];
    let stateIndex = 0;
    const manager = new PlatformLoginStateManager(store, { now: () => now, randomState: () => states[stateIndex++] });
    const issued = await manager.issue({
      applicationId: "app-a",
      platformId: "platform-a",
      redirectUri,
      binding: { browserId: "browser-a" },
      linkingPolicy: "create",
    });
    now = issued.record.expiresAt;
    expect(store.claim(issued.record.stateHash, { tenantId: "default" })).toBeUndefined();
    expect(store.status(issued.record.stateHash, "default")).toBe("issued");
    now = 1_000;
    const leased = await manager.issue({
      applicationId: "app-a",
      platformId: "platform-a",
      redirectUri,
      binding: { browserId: "browser-a" },
      linkingPolicy: "create",
    });
    expect(store.lease(leased.record.stateHash, "owner-a", 1_000, { tenantId: "default" })).toMatchObject({ status: "leased", leaseOwner: "owner-a" });
    expect(store.lease(leased.record.stateHash, "owner-b", 1_000, { tenantId: "default" })).toBeUndefined();
    now = 2_000;
    expect(store.lease(leased.record.stateHash, "owner-b", 1_000, { tenantId: "default" })).toMatchObject({ status: "leased", leaseOwner: "owner-b" });
    now = 1_000;
    const claimed = await manager.issue({
      applicationId: "app-a",
      platformId: "platform-a",
      redirectUri,
      binding: { browserId: "browser-a" },
      linkingPolicy: "create",
    });
    const records = (store as unknown as { records: Map<string, { stateHash: string; status: string }> }).records;
    const record = [...records.values()].find((item) => item.stateHash === claimed.record.stateHash);
    if (record !== undefined) record.status = "claimed";
    expect(store.claim(claimed.record.stateHash, { tenantId: "default" })).toBeUndefined();
  });
});

describe("platform login returnTo validation", () => {
  it("accepts only exact same-origin relative interaction paths", () => {
    for (const value of [
      "/",
      "/dashboard",
      "/dashboard/continue?tab=one%41two",
       "/dashboard/%E2%82%AC",
       "/oidc/interaction/one?redirect_uri=https%3A%2F%2Fapp.example%2Fcallback",
     ]) {
      expect(isValidPlatformLoginReturnTo(value)).toBe(true);
    }
    for (const value of [
      "",
      "dashboard",
      "//evil.example/path",
      "/safe//path",
      "https://evil.example/path",
      "/safe\\path",
      "/safe%5cpath",
      "/safe%255cpath",
      "/safe%2fpath",
      "/safe%252fpath",
      "/safe#fragment",
      "/safe%23fragment",
      "/safe%2523fragment",
      "/safe\npath",
      "/safe%20path",
      "/safe%0Apath",
      "/safe%ZZ",
      `/${"a".repeat(2048)}`,
    ]) {
      expect(isValidPlatformLoginReturnTo(value)).toBe(false);
    }
  });
});

describe("platform login flow", () => {
  it("keeps provider secrets server-side and projects placeholder email safely", async () => {
    const store = new InMemoryPlatformLoginStateStore();
    const exchangeCode = vi.fn(async () => ({
      ...identity(),
      accessToken: "provider-access-token",
      refreshToken: "provider-refresh-token",
      session_key: "provider-session-key",
    } as PlatformIdentity));
    const linker = {
      link: vi.fn(async () => ({ userId: "user-1", created: true, linked: false })),
    };
    let sessionInput: PlatformSessionIssueInput | undefined;
    const issuer = {
      issue: vi.fn(async (input: PlatformSessionIssueInput) => {
        sessionInput = input;
        return { response: new Response(null, { status: 204, headers: { "Set-Cookie": "getbrick_session=opaque; HttpOnly" } }) };
      }),
    };
    const flow = createPlatformLoginFlow({
      stateStore: store,
      registeredRedirectUris: [redirectUri],
      createAuthorizationUrl: async ({ state }) =>
        `https://provider.example.test/authorize?state=${encodeURIComponent(state)}`,
      exchangeCode,
      identityLinker: linker,
      sessionIssuer: issuer,
    });

    const start = await flow.start({
      applicationId: "app-1",
      platformId: "platform-1",
      redirectUri,
      browserId: "browser-1",
      sessionId: "session-1",
      identityLinkingPolicy: "create",
    });
    const callbackUrl = new URL(start.authorizationUrl);
    expect(callbackUrl.searchParams.get("state")).toBe(start.state);

    const result = await flow.handleCallback({
      state: start.state,
      code: "provider-code",
      redirectUri,
      browserId: "browser-1",
      sessionId: "session-1",
    });

    expect(exchangeCode).toHaveBeenCalledWith({
      applicationId: "app-1",
      platformId: "platform-1",
      redirectUri,
      code: "provider-code",
    });
    expect(result.user).toMatchObject({ id: "user-1", email: null, emailVerified: false });
    expect(result.identity.email).toBeNull();
    expect(sessionInput?.projection.placeholderEmail).toBe(true);
    expect(sessionInput?.projection.betterAuthUser.email).toMatch(/@placeholder\.invalid$/u);
    expect(sessionInput?.user.email).toBeNull();
    expect(JSON.stringify(result)).not.toContain("provider-access-token");
    expect(JSON.stringify(result)).not.toContain("provider-refresh-token");
    expect(JSON.stringify(result)).not.toContain("provider-session-key");
    expect(JSON.stringify(result)).not.toContain("provider-code");
    await expect(flow.handleCallback({
      state: start.state,
      code: "provider-code",
      redirectUri,
      browserId: "browser-1",
      sessionId: "session-1",
    })).rejects.toMatchObject({ code: "invalid_platform_state" });
  });

  it("returns only the consumed returnTo and rejects callback-supplied returnTo", async () => {
    const store = new InMemoryPlatformLoginStateStore();
    const flow = createPlatformLoginFlow({
      stateStore: store,
      registeredRedirectUris: [redirectUri],
      createAuthorizationUrl: async ({ state }) => `https://provider.example.test/authorize?state=${encodeURIComponent(state)}`,
      exchangeCode: async () => identity(),
      identityLinker: { link: async () => ({ userId: "user-1" }) },
      sessionIssuer: { issue: async () => ({ response: new Response(null, { status: 204, headers: { "Set-Cookie": "getbrick_session=opaque; HttpOnly" } }) }) },
    });
    const returnTo = "/after-login?tab=one%41two";
    const start = await flow.start({ applicationId: "app-1", platformId: "platform-1", redirectUri, browserId: "browser-1", returnTo });
    await expect(flow.handleCallback({ state: start.state, code: "provider-code", browserId: "browser-1", returnTo: "/attacker" } as never)).rejects.toMatchObject({ code: "invalid_platform_callback" });
    await expect(flow.handleCallback({ state: start.state, code: "provider-code", browserId: "browser-1" })).resolves.toMatchObject({ returnTo });
    await expect(flow.handleCallback({ state: start.state, code: "provider-code", browserId: "browser-1" })).rejects.toMatchObject({ code: "invalid_platform_state" });
    await expect(flow.startNative({ applicationId: "app-1", platformId: "platform-1", redirectUri, returnTo } as never)).rejects.toMatchObject({ code: "invalid_return_to" });
    await expect(flow.exchangeMiniProgram({ applicationId: "app-1", platformId: "platform-1", code: "mini-code", returnTo } as never)).rejects.toMatchObject({ code: "invalid_platform_callback" });
  });

  it("enforces registered redirects and does not exchange on a provider denial", async () => {
    const exchangeCode = vi.fn(async () => identity());
    const flow = new PlatformLoginFlow({
      stateStore: new InMemoryPlatformLoginStateStore(),
      registeredRedirectUris: [redirectUri],
      createAuthorizationUrl: async ({ state }) => `https://provider.example.test/authorize?state=${state}`,
      exchangeCode,
      identityLinker: { link: async () => ({ userId: "user-1" }) },
      sessionIssuer: { issue: async () => ({ response: new Response(null, { status: 204, headers: { "Set-Cookie": "getbrick_session=opaque; HttpOnly" } }) }) },
    });

    await expect(flow.start({
      applicationId: "app-1",
      platformId: "platform-1",
      redirectUri: "https://attacker.example/callback",
      browserId: "browser-1",
    })).rejects.toMatchObject({ code: "invalid_redirect_uri" });

    const start = await flow.start({
      applicationId: "app-1",
      platformId: "platform-1",
      redirectUri,
      browserId: "browser-1",
    });
    await expect(flow.handleCallback({
      state: start.state,
      error: "access_denied",
      errorDescription: "secret provider detail",
      browserId: "browser-1",
    })).rejects.toMatchObject({ code: "platform_provider_denied" });
    expect(exchangeCode).not.toHaveBeenCalled();
  });

  it("rejects a session issuer that returns provider secrets", async () => {
    const flow = new PlatformLoginFlow({
      stateStore: new InMemoryPlatformLoginStateStore(),
      registeredRedirectUris: [redirectUri],
      createAuthorizationUrl: async ({ state }) => `https://provider.example.test/authorize?state=${state}`,
      exchangeCode: async () => identity(),
      identityLinker: { link: async () => ({ userId: "user-1" }) },
      sessionIssuer: { issue: async () => ({ sessionKey: "must-not-leak" } as never) },
    });
    const start = await flow.start({
      applicationId: "app-1",
      platformId: "platform-1",
      redirectUri,
      browserId: "browser-1",
    });
    const error = await flow.handleCallback({
      state: start.state,
      code: "provider-code",
      browserId: "browser-1",
    }).catch((value: unknown) => value);
    expect(error).toBeInstanceOf(ApplicationPlatformError);
    expect(String(error)).not.toContain("must-not-leak");
  });

  it("allows only a host session cookie or opaque session reference", async () => {
    const safe = createPlatformSessionIssuerBridge(async () => ({ sessionReference: "host-session-reference" }));
    await expect(safe.issue({} as never)).resolves.toMatchObject({ sessionReference: "host-session-reference" });
    const unsafe = createPlatformSessionIssuerBridge(async () => new Response(JSON.stringify({ session_key: "provider-secret" }), { status: 200 }));
    await expect(unsafe.issue({} as never)).rejects.toMatchObject({ code: "session_issuer_secret_exposed" });
    const tokenResult = createPlatformSessionIssuerBridge(async () => ({ token: "provider-token" } as never));
    await expect(tokenResult.issue({} as never)).rejects.toMatchObject({ code: "session_issuer_secret_exposed" });
    const authorizationResult = createPlatformSessionIssuerBridge(async () => new Response("{}", { status: 200, headers: { authorization: "Bearer opaque-host-value" } }));
    await expect(authorizationResult.issue({} as never)).rejects.toMatchObject({ code: "session_issuer_secret_exposed" });
  });

  it("rejects response-only host sessions for native and mini-program clients", async () => {
    const flow = createPlatformLoginFlow({
      stateStore: new InMemoryPlatformLoginStateStore(),
      registeredRedirectUris: [redirectUri],
      createAuthorizationUrl: async ({ state }) => `https://provider.example.test/authorize?state=${state}`,
      exchangeCode: async () => identity(),
      identityLinker: { link: async () => ({ userId: "user-native" }) },
      sessionIssuer: { issue: async () => ({ response: new Response(null, { status: 204, headers: { "Set-Cookie": "getbrick_session=opaque; HttpOnly" } }) }) },
    });
    const native = await flow.startNative({
      applicationId: "app-1",
      platformId: "platform-1",
      redirectUri,
    });
    await expect(flow.exchangeNative({
      applicationId: "app-1",
      platformId: "platform-1",
      state: native.state,
      code: "native-code",
    })).rejects.toMatchObject({ code: "invalid_session_issuer_result" });
    await expect(flow.exchangeMiniProgram({
      applicationId: "app-1",
      platformId: "platform-1",
      code: "mini-code",
    })).rejects.toMatchObject({ code: "invalid_session_issuer_result" });
  });

  it("keeps native state separate and supports a state-free mini-program exchange", async () => {
    const exchange = vi.fn(async (input: { redirectUri?: string }) => ({
      ...identity(),
      subject: input.redirectUri === undefined ? "mini-subject" : "native-subject",
    }));
    const issued: PlatformSessionIssueInput[] = [];
    const flow = createPlatformLoginFlow({
      stateStore: new InMemoryPlatformLoginStateStore(),
      registeredRedirectUris: [redirectUri],
      createAuthorizationUrl: async ({ state }) => `https://provider.example.test/authorize?state=${state}`,
      exchangeCode: exchange,
      identityLinker: { link: async () => ({ userId: "user-native" }) },
      sessionIssuer: { issue: async (input) => {
        issued.push(input);
        return { sessionReference: "host-session-reference" };
      } },
    });
    const native = await flow.startNative({
      applicationId: "app-1",
      platformId: "platform-1",
      redirectUri,
    });
    const nativeResult = await flow.exchangeNative({
      applicationId: "app-1",
      platformId: "platform-1",
      state: native.state,
      code: "native-code",
    });
    expect(nativeResult.client).toBe("native");
    expect(exchange).toHaveBeenCalledWith(expect.objectContaining({ redirectUri }));
    const miniResult = await flow.exchangeMiniProgram({
      applicationId: "app-1",
      platformId: "platform-1",
      code: "mini-code",
    });
    expect(miniResult.client).toBe("mp_weixin");
    expect(exchange).toHaveBeenLastCalledWith({
      applicationId: "app-1",
      platformId: "platform-1",
      code: "mini-code",
      client: "mini_program",
      clientType: "mp_weixin",
    });
    expect(issued.map((input) => input.client)).toEqual(["native", "mp_weixin"]);
  });

  it("keeps webview on an opaque session and rejects a cookie response", async () => {
    const issued: PlatformSessionIssueInput[] = [];
    const flow = createPlatformLoginFlow({
      stateStore: new InMemoryPlatformLoginStateStore(),
      registeredRedirectUris: [redirectUri],
      createAuthorizationUrl: async ({ state, clientType }) => `https://provider.example.test/authorize?state=${state}&kind=${clientType ?? "web"}`,
      exchangeCode: async () => identity({ subject: "webview-subject" }),
      identityLinker: { link: async () => ({ userId: "user-webview" }) },
      sessionIssuer: { issue: async (input) => {
        issued.push(input);
        return input.client === "webview"
          ? { sessionReference: "webview-opaque-session" }
          : { response: new Response(null, { status: 204, headers: { "Set-Cookie": "getbrick_session=opaque; HttpOnly" } }) };
      } },
    });
    const start = await flow.startWebview({ applicationId: "app-1", platformId: "platform-1", redirectUri });
    expect(start.client).toBe("webview");
    const result = await flow.handleWebviewCallback({ state: start.state, code: "webview-code" });
    expect(result.client).toBe("webview");
    expect(result.session.response).toBeUndefined();
    expect(result.session.sessionReference).toBe("webview-opaque-session");
    expect(issued[0]?.client).toBe("webview");

    const cookieFlow = createPlatformLoginFlow({
      stateStore: new InMemoryPlatformLoginStateStore(),
      registeredRedirectUris: [redirectUri],
      createAuthorizationUrl: async ({ state }) => `https://provider.example.test/authorize?state=${state}`,
      exchangeCode: async () => identity(),
      identityLinker: { link: async () => ({ userId: "user-webview" }) },
      sessionIssuer: { issue: async () => ({ response: new Response(null, { status: 204, headers: { "Set-Cookie": "getbrick_session=opaque; HttpOnly" } }) }) },
    });
    const cookieStart = await cookieFlow.startWebview({ applicationId: "app-1", platformId: "platform-1", redirectUri });
    await expect(cookieFlow.handleWebviewCallback({ state: cookieStart.state, code: "webview-code" })).rejects.toMatchObject({ code: "invalid_session_issuer_result" });
  });
  it("accepts a registered private-use native redirect without treating it as a web URI", async () => {
    const nativeRedirect = "com.example.app:/oauth/callback";
    const exchange = vi.fn(async () => identity({ subject: "native-subject" }));
    const flow = createPlatformLoginFlow({
      stateStore: new InMemoryPlatformLoginStateStore(),
      registeredRedirectUris: [nativeRedirect],
      createAuthorizationUrl: async ({ state }) => `https://provider.example.test/authorize?state=${state}`,
      exchangeCode: exchange,
      identityLinker: { link: async () => ({ userId: "user-native" }) },
      sessionIssuer: { issue: async () => ({ sessionId: "app-session" }) },
    });
    const start = await flow.startNative({ applicationId: "app-1", platformId: "platform-1", redirectUri: nativeRedirect });
    await expect(flow.exchangeNative({ state: start.state, code: "native-code", redirectUri: nativeRedirect })).resolves.toMatchObject({ client: "native" });
    expect(exchange).toHaveBeenCalledWith(expect.objectContaining({ redirectUri: nativeRedirect, client: "native" }));
  });

  it("rejects authority and non-private native redirect schemes", async () => {
    const flow = new PlatformLoginFlow({
      stateStore: new InMemoryPlatformLoginStateStore(),
       registeredRedirectUris: ["com.example.app://callback", "com.example.app:callback", "ftp://callback.example", "https://localhost/callback"],
      createAuthorizationUrl: async ({ state }) => `https://provider.example.test/authorize?state=${state}`,
      exchangeCode: async () => identity(),
      identityLinker: { link: async () => ({ userId: "user-native" }) },
      sessionIssuer: { issue: async () => ({ sessionId: "app-session" }) },
    });
     for (const redirectUri of ["com.example.app://callback", "com.example.app:callback", "ftp://callback.example", "https://localhost/callback"]) {
      await expect(flow.startNative({ applicationId: "app-1", platformId: "platform-1", redirectUri })).rejects.toMatchObject({ code: "invalid_redirect_uri" });
    }
  });

  it("prefers canonical linker user and account over provider projection", async () => {
    const sessionInputs: PlatformSessionIssueInput[] = [];
    const flow = createPlatformLoginFlow({
      stateStore: new InMemoryPlatformLoginStateStore(),
      registeredRedirectUris: [redirectUri],
      createAuthorizationUrl: async ({ state }) => `https://provider.example.test/authorize?state=${state}`,
      exchangeCode: async () => identity({ nickname: "Provider Name" }),
      identityLinker: {
        link: async () => ({
           userId: "canonical-user",
           user: { id: "wrong-user", name: "Wrong Name", email: null, emailVerified: false },
           canonicalUser: { id: "canonical-user", name: "Canonical Name", email: "canonical@example.test", emailVerified: true },
           account: { providerId: "wrong-provider", accountId: "wrong-account", platform: "wrong-platform", appId: "wrong-app", scopes: [] },
           canonicalAccount: { providerId: "canonical-provider", accountId: "canonical-account", platform: "canonical-platform", appId: "canonical-app", scopes: ["canonical"] },

        }),
      },
      sessionIssuer: { issue: async (input) => {
        sessionInputs.push(input);
         return { response: new Response(null, { status: 204, headers: { "Set-Cookie": "getbrick_session=opaque; HttpOnly" } }) };
      } },
    });
    const start = await flow.start({ applicationId: "app-1", platformId: "platform-1", redirectUri, browserId: "browser-1" });
    const result = await flow.handleCallback({ state: start.state, code: "provider-code", browserId: "browser-1" });
    expect(result.user).toMatchObject({ id: "canonical-user", name: "Canonical Name", email: "canonical@example.test" });
    expect(result.account).toMatchObject({ providerId: "canonical-provider", accountId: "canonical-account" });
    expect(sessionInputs[0]?.user).toEqual(result.user);
    expect(sessionInputs[0]?.account).toEqual(result.account);
  });
});

describe("explicit platform identity linker", () => {
  it("never auto-links a new identity by email in create mode", async () => {
    const createUser = vi.fn(async () => ({ userId: "new-user" }));
    const findByEmail = vi.fn(async () => ({ userId: "existing-user" }));
    const store: PlatformIdentityLinkStore = {
      findByIdentity: async () => undefined,
      findByEmail,
      createUser,
      linkIdentity: async () => ({ userId: "existing-user" }),
    };
    const linker = new ExplicitPlatformIdentityLinker(store);
    await expect(linker.link({
      applicationId: "app-1",
      platformId: "platform-1",
      identity: identity({ email: "person@example.test", emailVerified: true }),
      policy: "create",
    })).rejects.toMatchObject({ code: "identity_email_conflict" });
    expect(createUser).not.toHaveBeenCalled();
  });

  it("requires an explicit user for existing-account linking", async () => {
    const linkIdentity = vi.fn(async () => ({ userId: "user-1" }));
    const linker = new ExplicitPlatformIdentityLinker({
      findByIdentity: async () => undefined,
      createUser: async () => ({ userId: "new-user" }),
      linkIdentity,
    });
    await expect(linker.link({
      applicationId: "app-1",
      platformId: "platform-1",
      identity: identity(),
      policy: "link_existing",
    })).rejects.toMatchObject({ code: "identity_link_authorization_required" });
    await linker.link({
      applicationId: "app-1",
      platformId: "platform-1",
      identity: identity(),
      policy: { mode: "link_existing", userId: "user-1" },
      hostContext: { userId: "user-1" },
    });
    expect(linkIdentity).toHaveBeenCalledWith(expect.objectContaining({ userId: "user-1" }));
  });

  it("uses the same tenant and application scope for projection, linker, and canonical key", async () => {
    const createUser = vi.fn(async (input: { identityKey: string; projection: { identityKey: string; tenantId: string; applicationId: string } }) => ({ userId: "user-1" }));
    const store: PlatformIdentityLinkStore = {
      findByIdentity: vi.fn(async () => undefined),
      createUser,
      linkIdentity: async () => ({ userId: "user-1" }),
    };
    const linker = new ExplicitPlatformIdentityLinker(store);
    const inputIdentity = identity();
    const scope = { tenantId: "tenant-a", applicationId: "app-a" };
    const key = createPlatformIdentityKey(inputIdentity, scope);
    await linker.link({
      tenantId: scope.tenantId,
      applicationId: scope.applicationId,
      platformId: "platform-1",
      identity: inputIdentity,
      policy: "create",
    });
    expect(key).toBe(["tenant-a", "app-a", "wechat", "wechat_official_account", "wx-app", "subject-1"].map((value) => encodeURIComponent(value)).join("|"));
    expect(store.findByIdentity).toHaveBeenCalledWith(key, expect.objectContaining({ tenantId: scope.tenantId, applicationId: scope.applicationId, identityKey: key }));
    expect(createUser).toHaveBeenCalledWith(expect.objectContaining({ identityKey: key, projection: expect.objectContaining({ identityKey: key, tenantId: scope.tenantId, applicationId: scope.applicationId }) }));
  });

  it("rejects linker results whose user does not match the canonical user", async () => {
    const linker = new ExplicitPlatformIdentityLinker({
      findByIdentity: async () => ({ userId: "user-a", user: { id: "user-b", name: "Wrong", email: null, emailVerified: false } }),
      createUser: async () => ({ userId: "user-a" }),
      linkIdentity: async () => ({ userId: "user-a" }),
    });
    await expect(linker.link({
      tenantId: "tenant-a",
      applicationId: "app-a",
      platformId: "platform-a",
      identity: identity(),
      policy: "create",
    })).rejects.toMatchObject({ code: "identity_link_scope_mismatch" });
  });

  it("projects no-email identities to a unique internal placeholder and public null", () => {
    const projection = projectPlatformIdentity(identity());
    expect(projection.betterAuthUser.email).toBe(createPlaceholderEmail(projection.identityKey));
    expect(projection.betterAuthUser.email.endsWith("@placeholder.invalid")).toBe(true);
    expect(projection.publicUser.email).toBeNull();
    expect(projection.publicEmail).toBeNull();
    expect(projection.internalEmail).toMatch(/@placeholder\.invalid$/u);
    expect(projection.betterAuthAccount).toMatchObject({
      providerId: projection.identityKey,
      accountId: "subject-1",
    });
  });
});
