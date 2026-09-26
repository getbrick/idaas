import { describe, expect, it } from "vitest";
import {
  ApplicationPlatformAuthService,
  InMemoryApplicationRepository,
  InMemoryOpaqueClientSessionStore,
  SqlOpaqueClientSessionRepository,
  createApplicationPlatformIdentitySessionBoundary,
  createOpaqueClientSessionIssuer,
} from "../src/index.js";

describe("ApplicationPlatformAuthService", () => {
  it("loads active platform records, resolves credentials and delegates code exchange", async () => {
    const repository = new InMemoryApplicationRepository({
      applications: [{ id: "app-1", name: "Alpha", slug: "alpha", status: "active" }],
      platforms: [{
        id: "wechat-1",
        applicationId: "app-1",
        type: "wechat_mini_program",
        externalAppId: "wx-app",
        redirectUris: [],
        secretRef: "vault://wechat/app",
        status: "active",
      }],
    });
    const calls: Array<{ appId: string; appSecret?: string; code: string }> = [];
    const service = new ApplicationPlatformAuthService(repository, {
      resolveCredentials: () => ({ appId: "wx-app", appSecret: "server-secret" }),
      adapters: [{
        type: "wechat_mini_program",
        supportsAuthorization: false,
        createAuthorizationUrl() {
          throw new Error("not supported");
        },
        async exchangeCode(input) {
          calls.push(input);
          return {
            provider: "wechat",
            platform: "wechat_mini_program",
            appId: input.appId,
            subject: "wx:openid-1",
            openid: "openid-1",
            scopes: [],
          };
        },
      }],
    });
    await expect(service.exchangeCode("app-1", "wechat-1", "wx-code")).resolves.toMatchObject({
      subject: "wx:openid-1",
    });
    expect(calls).toEqual([{ appId: "wx-app", appSecret: "server-secret", code: "wx-code" }]);
    expect(JSON.stringify(calls)).not.toContain("vault://wechat/app");
  });

  it("requires a registered redirect URI for browser authorization", async () => {
    const repository = new InMemoryApplicationRepository({
      applications: [{ id: "app-1", name: "Alpha", slug: "alpha", status: "active" }],
      platforms: [{
        id: "wechat-1",
        applicationId: "app-1",
        type: "wechat_official_account",
        externalAppId: "wx-official",
        redirectUris: ["https://auth.example.test/wechat/callback"],
        secretRef: "vault://wechat/official",
        status: "active",
      }],
    });
    const service = new ApplicationPlatformAuthService(repository, {
      resolveCredentials: () => ({ appId: "wx-official", appSecret: "official-secret" }),
    });
    await expect(service.createAuthorizationUrl("app-1", "wechat-1", {
      redirectUri: "https://attacker.example/callback",
      state: "state",
    })).rejects.toMatchObject({ code: "invalid_redirect_uri" });
  });

  it("redacts credential resolver failures", async () => {
    const repository = new InMemoryApplicationRepository({
      applications: [{ id: "app-1", name: "Alpha", slug: "alpha", status: "active" }],
      platforms: [{ id: "wechat-1", applicationId: "app-1", type: "wechat_mini_program", externalAppId: "wx-app", status: "active" }],
    });
    const service = new ApplicationPlatformAuthService(repository, {
      resolveCredentials: () => {
        throw new Error("vault secret=do-not-leak");
      },
    });
    const error = await service.exchangeCode("app-1", "wechat-1", "wx-code").catch((value: unknown) => value);
    expect(error).toMatchObject({ code: "credential_unavailable" });
    expect(String(error)).not.toContain("do-not-leak");
  });

  it("persists sanitized identities and removes them on purge", async () => {
    const repository = new InMemoryApplicationRepository({
      applications: [{ id: "app-1", name: "Alpha", slug: "alpha", status: "active" }],
      platforms: [{ id: "wechat-1", applicationId: "app-1", type: "wechat_mini_program", status: "active" }],
    });
    const service = new ApplicationPlatformAuthService(repository, {
      resolveCredentials: () => ({ appId: "wx-app", appSecret: "server-secret" }),
      adapters: [{
        type: "wechat_mini_program",
        supportsAuthorization: false,
        createAuthorizationUrl() {
          throw new Error("not supported");
        },
        async exchangeCode(input) {
          return {
            provider: "wechat",
            platform: "wechat_mini_program",
            appId: input.appId,
            subject: "subject-1",
            openid: "openid-1",
            unionid: "unionid-1",
            scopes: ["profile"],
          };
        },
      }],
    });
    await service.exchangeCode("app-1", "wechat-1", "code");
     expect(repository.snapshot().externalIdentities).toHaveLength(1);
     expect(repository.snapshot().externalIdentities[0]).toMatchObject({ applicationId: "app-1", subject: "subject-1", linkStatus: "pending" });
    await repository.archiveApplication("app-1");
    await repository.purgeApplication("app-1");
    expect(repository.snapshot().externalIdentities).toHaveLength(0);
  });

  it("does not use disabled applications or platforms", async () => {
    const repository = new InMemoryApplicationRepository({
      applications: [{ id: "app-1", name: "Alpha", slug: "alpha", status: "disabled" }],
      platforms: [{ id: "wechat-1", applicationId: "app-1", type: "wechat_mini_program", status: "active" }],
    });
    const service = new ApplicationPlatformAuthService(repository, {
      resolveCredentials: () => ({ appId: "wx-app", appSecret: "server-secret" }),
    });
    await expect(service.exchangeCode("app-1", "wechat-1", "wx-code")).rejects.toMatchObject({
      code: "application_unavailable",
    });
  });
});

describe("platform identity session boundary", () => {
  it("coalesces only an explicitly bound state and clears the entry after settlement", async () => {
    const boundary = createApplicationPlatformIdentitySessionBoundary();
    const context = {
      tenantId: "default",
      applicationId: "app-1",
      platformId: "platform-1",
      client: "web" as const,
      state: "state-1",
      binding: "browser-1",
      code: "code-1",
    };
    let calls = 0;
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const first = boundary.run(async () => {
      calls += 1;
      await gate;
      return "first";
    }, context);
    const second = boundary.run(async () => {
      calls += 1;
      return "second";
    }, context);
    await Promise.resolve();
    expect(calls).toBe(1);
    release?.();
    await expect(first).resolves.toBe("first");
    await expect(second).resolves.toBe("first");
    await expect(boundary.run(async () => {
      calls += 1;
      return "third";
    }, context)).resolves.toBe("third");
    expect(calls).toBe(2);
  });

  it("does not serialize arbitrary request objects or coalesce unbound operations", async () => {
    const boundary = createApplicationPlatformIdentitySessionBoundary();
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    let calls = 0;
    await Promise.all([
      boundary.run(async () => { calls += 1; return "a"; }, cyclic as never),
      boundary.run(async () => { calls += 1; return "b"; }, cyclic as never),
    ]);
    expect(calls).toBe(2);
  });
});

describe("SQL opaque platform session repository", () => {
  it("filters inactive and expired records in the query and defensively", async () => {
    const calls: Array<{ text: string; values: unknown[] }> = [];
    const row = {
      id: "session-row",
      tenant_id: "default",
      application_id: "app-1",
      client_id: "client-1",
      client_kind: "native",
      session_hash: "a".repeat(64),
      user_id: "user-1",
      status: "revoked",
      created_at: "2020-01-01T00:00:00.000Z",
      updated_at: "2020-01-01T00:00:00.000Z",
      expires_at: "2099-01-01T00:00:00.000Z",
    };
    const repository = new SqlOpaqueClientSessionRepository({
      executor: {
        query: async (text, values = []) => {
          calls.push({ text, values });
          return { rows: [row] };
        },
      },
    });
    await expect(repository.find("opaque_session_reference_123")).resolves.toBeUndefined();
    expect(calls[0]?.text).toContain('"status" = \'active\'');
    expect(calls[0]?.text).toContain('"expires_at" > $3');
  });
});

describe("opaque platform session issuer", () => {
  it("issues an opaque session for webview instead of delegating to the web cookie issuer", async () => {
    const store = new InMemoryOpaqueClientSessionStore();
    let webIssuerCalled = false;
    const issuer = createOpaqueClientSessionIssuer({
      store,
      host: {
        issue: async () => ({
          hostSessionToken: "host-session-token",
          expiresAt: new Date(Date.now() + 60_000),
        }),
      },
      webSessionIssuer: {
        issue: async () => {
          webIssuerCalled = true;
          return new Response(null, { status: 204 });
        },
      },
    });
    const result = await issuer.issue({
      tenantId: "default",
      applicationId: "app-1",
      platformId: "platform-1",
      userId: "user-1",
      user: { name: "User", email: null, emailVerified: false },
      identity: {
        provider: "wechat",
        platform: "wechat_official_account",
        appId: "wx-app",
        subject: "subject-1",
        scopes: [],
      },
      projection: {} as never,
      client: "webview",
      created: true,
      linked: false,
    });
    expect(webIssuerCalled).toBe(false);
    expect(result.sessionReference).toMatch(/^ocs_/u);
    expect(result.clientKind).toBe("webview");
  });

  it("rotates a transferred session into an independent webview reference", async () => {
    const store = new InMemoryOpaqueClientSessionStore();
    const issuer = createOpaqueClientSessionIssuer({
      store,
      host: {
        issue: async () => ({ hostSessionToken: "host-session-token", expiresAt: new Date(Date.now() + 60_000) }),
        refresh: async ({ record }) => ({ hostSessionToken: `${record.hostSessionToken}-refreshed`, expiresAt: new Date(Date.now() + 120_000) }),
      },
    });
    const issued = await issuer.issue({
      applicationId: "app-1",
      platformId: "platform-1",
      userId: "user-1",
      user: { name: "User", email: null, emailVerified: false },
      identity: { provider: "wechat", platform: "wechat_mini_program", appId: "wx-app", subject: "subject-1", scopes: [] },
      projection: {} as never,
      client: "mp_weixin",
      created: true,
      linked: false,
    });
    const sourceReference = issued.sessionReference;
    if (sourceReference === undefined) throw new Error("source session was not issued");
    const transferred = await issuer.refresh({ sessionReference: sourceReference, client: "webview" });
    expect(transferred.sessionReference).not.toBe(sourceReference);
    expect(transferred.client).toBe("webview");
    expect(await store.get(sourceReference)).toBeUndefined();
  });
});
