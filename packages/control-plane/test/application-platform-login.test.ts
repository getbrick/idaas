import { describe, expect, it, vi } from "vitest";
import {
  ApplicationPlatformAuthService,
  InMemoryApplicationRepository,
} from "../src/index.js";
import {
  InMemoryPlatformLoginStateStore,
  type PlatformIdentity,
  type PlatformSessionIssueInput,
} from "@getbrick/idaas-core";

const callbackUri = "https://app.example.test/wechat/callback";

describe("ApplicationPlatformAuthService login flow", () => {
  it("owns state, callback exchange, identity projection, and session issuance", async () => {
    const repository = new InMemoryApplicationRepository({
      applications: [{ id: "app-1", name: "Alpha", slug: "alpha", status: "active" }],
      platforms: [{
        id: "wechat-1",
        applicationId: "app-1",
        type: "wechat_official_account",
        externalAppId: "wx-app",
        redirectUris: [callbackUri],
        secretRef: "vault://wechat",
        status: "active",
      }],
    });
    const exchangeCode = vi.fn(async (input: { appId: string; code: string }) => ({
      provider: "wechat",
      platform: "wechat_official_account",
      appId: input.appId,
      subject: "subject-1",
      scopes: ["snsapi_userinfo"],
      accessToken: "provider-access-token",
      session_key: "provider-session-key",
    } as PlatformIdentity));
    const linker = {
      link: vi.fn(async () => ({ userId: "user-1", created: true, linked: false })),
    };
    let issued: PlatformSessionIssueInput | undefined;
    const service = new ApplicationPlatformAuthService(repository, {
      resolveCredentials: () => ({ appId: "wx-app", appSecret: "server-secret" }),
      adapters: [{
        type: "wechat_official_account",
        supportsAuthorization: true,
        createAuthorizationUrl({ redirectUri, state }) {
          const url = new URL("https://provider.example.test/authorize");
          url.searchParams.set("redirect_uri", redirectUri);
          url.searchParams.set("state", state);
          return url.toString();
        },
        exchangeCode,
      }],
      login: {
        stateStore: new InMemoryPlatformLoginStateStore(),
        identityLinker: linker,
        sessionIssuer: {
          issue: async (input) => {
            issued = input;
             return { response: new Response(null, { status: 204, headers: { "Set-Cookie": "host_session=opaque; Path=/; HttpOnly; Secure; SameSite=Lax" } }) };
          },
        },
      },
    });

    const start = await service.createLogin("app-1", "wechat-1", {
      redirectUri: callbackUri,
      browserId: "browser-1",
      sessionId: "session-1",
      identityLinkingPolicy: "create",
    });
    expect(new URL(start.authorizationUrl).searchParams.get("state")).toBe(start.state);

    const result = await service.completeLogin("app-1", "wechat-1", {
      state: start.state,
      code: "provider-code",
      redirectUri: callbackUri,
      browserId: "browser-1",
      sessionId: "session-1",
    });

    expect(result.user).toMatchObject({ id: "user-1", email: null });
    expect(result.identity.email).toBeNull();
    expect(issued?.projection.betterAuthUser.email).toMatch(/@placeholder\.invalid$/u);
    expect(exchangeCode).toHaveBeenCalledWith(expect.objectContaining({
      appId: "wx-app",
      appSecret: "server-secret",
      code: "provider-code",
      redirectUri: callbackUri,
    }));
    expect(JSON.stringify(result)).not.toContain("provider-access-token");
    expect(JSON.stringify(result)).not.toContain("provider-session-key");
    const directIdentity = await service.exchangeCode("app-1", "wechat-1", "another-code", callbackUri);
    expect(JSON.stringify(directIdentity)).not.toContain("provider-access-token");
    expect(JSON.stringify(directIdentity)).not.toContain("provider-session-key");
    await expect(service.completeLogin("app-1", "wechat-1", {
      state: start.state,
      code: "provider-code",
      redirectUri: callbackUri,
      browserId: "browser-1",
      sessionId: "session-1",
    })).rejects.toMatchObject({ code: "invalid_platform_state" });
  });

  it("does not create a login flow unless all host adapters are supplied", async () => {
    const repository = new InMemoryApplicationRepository({
      applications: [{ id: "app-1", name: "Alpha", slug: "alpha", status: "active" }],
      platforms: [{ id: "wechat-1", applicationId: "app-1", type: "wechat_official_account", status: "active" }],
    });
    const service = new ApplicationPlatformAuthService(repository, {
      resolveCredentials: () => ({ appId: "wx-app", appSecret: "server-secret" }),
    });
    await expect(service.createLogin("app-1", "wechat-1", {
      redirectUri: callbackUri,
      browserId: "browser-1",
    })).rejects.toMatchObject({ code: "platform_login_not_configured" });
  });
});
