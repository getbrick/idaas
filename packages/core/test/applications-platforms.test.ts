import { describe, expect, it, vi } from "vitest";
import {
  ApplicationPlatformError,
  createGenericMiniProgramAdapter,
  createWechatMiniProgramAdapter,
  createWechatOfficialAccountAdapter,
  createWechatOpenPlatformAdapter,
  redactWechatProviderUrl,
} from "../src/index.js";

describe("application platform adapters", () => {
  it("creates WeChat official-account and open-platform authorization URLs", () => {
    const official = createWechatOfficialAccountAdapter();
    const officialUrl = new URL(official.createAuthorizationUrl({
      appId: "wx-official",
      redirectUri: "https://auth.example.test/wechat/callback?source=official",
      state: "state-value",
      scope: "snsapi_userinfo",
    }));
    expect(officialUrl.origin + officialUrl.pathname).toBe("https://open.weixin.qq.com/connect/oauth2/authorize");
    expect(officialUrl.searchParams.get("appid")).toBe("wx-official");
    expect(officialUrl.searchParams.get("scope")).toBe("snsapi_userinfo");
    expect(officialUrl.searchParams.get("state")).toBe("state-value");
    expect(officialUrl.hash).toBe("#wechat_redirect");

    const openPlatform = createWechatOpenPlatformAdapter();
    const openUrl = new URL(openPlatform.createAuthorizationUrl({
      appId: "wx-open",
      redirectUri: "https://auth.example.test/wechat/open/callback",
      state: "state-value",
    }));
    expect(openPlatform.type).toBe("wechat_open_platform");
     expect(openUrl.pathname).toBe("/connect/qrconnect");
     expect(openUrl.searchParams.get("scope")).toBe("snsapi_login");
     const nativeUrl = official.createAuthorizationUrl({
       appId: "wx-official",
       redirectUri: "com.example.app:/oauth/callback",
       state: "state-value",
       client: "native",
     });
     expect(new URL(nativeUrl).searchParams.get("redirect_uri")).toBe("com.example.app:/oauth/callback");
     expect(() => official.createAuthorizationUrl({
       appId: "wx-official",
       redirectUri: "com.example.app:/oauth/callback",
       state: "state-value",
     })).toThrow(/redirect URI/i);
   });

  it("enforces WeChat scopes and redirect security without exposing secrets", () => {
    const official = createWechatOfficialAccountAdapter();
    expect(() => official.createAuthorizationUrl({
      appId: "wx-official",
      redirectUri: "https://auth.example.test/wechat/callback?code=secret",
      state: "state-value",
    })).toThrow(/redirect URI|secret/iu);
    expect(() => official.createAuthorizationUrl({
      appId: "wx-official",
      redirectUri: "https://auth.example.test/wechat/callback",
      state: "state-value",
      scope: "snsapi_login",
    })).toThrow(/scope/iu);
    expect(() => official.createAuthorizationUrl({
      appId: "wx-official",
      redirectUri: "http://auth.example.test/wechat/callback",
      state: "state-value",
    })).toThrow(/redirect URI/iu);

    const openPlatform = createWechatOpenPlatformAdapter();
    expect(() => openPlatform.createAuthorizationUrl({
      appId: "wx-open",
      redirectUri: "https://auth.example.test/wechat/open/callback",
      state: "state-value",
      scope: "snsapi_userinfo",
    })).toThrow(/scope/iu);
    expect(redactWechatProviderUrl("https://api.weixin.qq.com/sns/oauth2/access_token?appid=wx&secret=do-not-leak&code=oauth-code")).not.toContain("do-not-leak");
  });

  it("exchanges official-account code without returning provider tokens", async () => {
    const fetch = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({
        access_token: "provider-access-token",
        refresh_token: "provider-refresh-token",
        expires_in: 7200,
        openid: "openid-1",
        unionid: "unionid-1",
        scope: "snsapi_userinfo",
      }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        nickname: "小明",
        headimgurl: "https://img.example.test/avatar.png",
      }), { status: 200 }));
    const adapter = createWechatOfficialAccountAdapter({ fetch });
    const identity = await adapter.exchangeCode({
      appId: "wx-official",
      appSecret: "official-secret",
      code: "oauth-code",
    });
    expect(identity).toMatchObject({
      provider: "wechat",
      platform: "wechat_official_account",
      appId: "wx-official",
      subject: "unionid-1",
      openid: "openid-1",
      unionid: "unionid-1",
      nickname: "小明",
      scopes: ["snsapi_userinfo"],
    });
    expect(identity).not.toHaveProperty("accessToken");
    expect(identity).not.toHaveProperty("refreshToken");
    expect(identity).not.toHaveProperty("sessionKey");
    expect(JSON.stringify(identity)).not.toContain("provider-access-token");
    expect(JSON.stringify(identity)).not.toContain("official-secret");
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(String(fetch.mock.calls[0]?.[0])).toContain("appid=wx-official");
    expect(String(fetch.mock.calls[0]?.[0])).toContain("secret=official-secret");
  });

  it("resolves official-account secrets on the server", async () => {
    const fetch = vi.fn().mockImplementation(async () => new Response(JSON.stringify({
      access_token: "provider-access-token",
      openid: "openid-resolved",
      scope: "snsapi_base",
    }), { status: 200 }));
    const appSecretResolver = vi.fn().mockResolvedValue("server-only-secret");
    const adapter = createWechatOfficialAccountAdapter({ fetch, appSecretResolver });
    await expect(adapter.exchangeCode({
      appId: "wx-official",
      code: "oauth-code",
    })).resolves.toMatchObject({
      appId: "wx-official",
      openid: "openid-resolved",
      scopes: ["snsapi_base"],
    });
    expect(appSecretResolver).toHaveBeenCalledWith({
      appId: "wx-official",
      platform: "wechat_official_account",
    });
    expect(String(fetch.mock.calls[0]?.[0])).toContain("secret=server-only-secret");
    expect(JSON.stringify(await adapter.exchangeCode({
      appId: "wx-official",
      code: "oauth-code",
    }))).not.toContain("server-only-secret");
  });

  it("exchanges mini-program code and hides the session key", async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      openid: "mini-openid",
      session_key: "session-key-must-not-leak",
      unionid: "mini-unionid",
    }), { status: 200 }));
    const adapter = createWechatMiniProgramAdapter({ fetch });
    const identity = await adapter.exchangeCode({
      appId: "wx-mini",
      appSecret: "mini-secret",
      code: "js-code",
    });
    expect(identity).toMatchObject({
      platform: "wechat_mini_program",
      appId: "wx-mini",
      subject: "mini-unionid",
      openid: "mini-openid",
      unionid: "mini-unionid",
    });
    expect(JSON.stringify(identity)).not.toContain("session-key-must-not-leak");
    expect(JSON.stringify(identity)).not.toContain("mini-secret");
  });

  it("supports a response-mapped generic mini-program adapter", async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      data: { user: { id: "openid-2", nickname: "User" } },
    }), { status: 200 }));
    const adapter = createGenericMiniProgramAdapter({
      type: "alipay_mini_program",
      endpoint: "https://open.example.test/mini/session",
      fetch,
      mapResponse: (payload) => {
        const record = payload as { data?: { user?: { id?: string; nickname?: string } } };
        return {
          subject: record.data?.user?.id ?? "",
          openid: record.data?.user?.id,
          nickname: record.data?.user?.nickname,
        };
      },
    });
    await expect(adapter.exchangeCode({
      appId: "alipay-app",
      appSecret: "alipay-secret",
      code: "mini-code",
    })).resolves.toMatchObject({
      provider: "alipay_mini_program",
      subject: "openid-2",
      openid: "openid-2",
    });
  });

  it("requires HTTPS for custom platform endpoints by default", () => {
    expect(() => createGenericMiniProgramAdapter({
      type: "alipay_mini_program",
      endpoint: "http://example.test/mini/session",
      mapResponse: () => ({ subject: "subject" }),
    })).toThrow(/endpoint/i);
  });

  it("rejects provider errors and unsafe input without exposing credentials", async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      errcode: 40029,
      errmsg: "invalid code",
    }), { status: 200 }));
    const adapter = createWechatMiniProgramAdapter({ fetch });
    const error = await adapter.exchangeCode({
      appId: "wx-mini",
      appSecret: "super-secret",
      code: "bad-code",
    }).catch((value: unknown) => value);
    expect(error).toBeInstanceOf(ApplicationPlatformError);
    expect(error).toMatchObject({ code: "provider_error" });
    expect(String(error)).not.toContain("super-secret");
    expect(String(error)).not.toContain("bad-code");

    expect(() => createWechatOfficialAccountAdapter().createAuthorizationUrl({
      appId: "wx-official",
      redirectUri: "javascript:alert(1)",
      state: "state",
    })).toThrow(ApplicationPlatformError);
  });
});
