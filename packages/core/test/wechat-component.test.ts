import { describe, expect, it, vi } from "vitest";
import {
  ApplicationPlatformError,
  createWechatComponentAccessTokenResolver,
  createWechatComponentAdapter,
  createWechatComponentProvider,
  createWechatOfficialAccountAdapter,
  createWechatOpenPlatformAdapter,
} from "../src/index.js";
import { createWechatComponentAdapter as createDirectComponentAdapter } from "../src/applications/wechat-component.js";

const componentAppId = "wx-component-1";
const authorizedAppId = "wx-authorized-1";

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status });
}

describe("WeChat component provider", () => {
  it("enables component mode from the official-account factory", () => {
    const adapter = createWechatOfficialAccountAdapter({
      componentAppId,
      bindings: [{ componentAppId, authorizedAppId }],
      componentAccessTokenResolver: async () => "component-token",
    });
    const url = new URL(adapter.createAuthorizationUrl({
      appId: authorizedAppId,
      redirectUri: "https://app.example.test/wechat/official/callback",
      state: "state-value",
    }));
    expect(adapter.type).toBe("wechat_official_account");
    expect(url.searchParams.get("component_appid")).toBe(componentAppId);
  });

  it("uses component authorization for an official-account H5 flow", async () => {
    const resolveComponentAccessToken = vi.fn(async ({ componentAppId: id, authorizedAppId: accountId }) =>
      `component-token-${id}-${accountId}`,
    );
    const fetch = vi.fn()
      .mockResolvedValueOnce(jsonResponse({
        access_token: "oauth-access-token",
        refresh_token: "oauth-refresh-token",
        openid: "openid-1",
        scope: "snsapi_userinfo",
      }))
      .mockResolvedValueOnce(jsonResponse({
        nickname: "Component User",
        headimgurl: "https://wx.qlogo.cn/mmopen/avatar/0",
      }));
    const provider = createWechatComponentAdapter({
      componentAppId,
      bindings: [{ componentAppId, authorizedAppId }],
      componentAccessTokenResolver: resolveComponentAccessToken,
      fetch,
    });

    const authorizationUrl = new URL(provider.createAuthorizationUrl({
      appId: authorizedAppId,
      redirectUri: "https://app.example.test/wechat/official/callback",
      state: "state-value",
    }));
    expect(provider.type).toBe("wechat_official_account");
    expect(authorizationUrl.searchParams.get("component_appid")).toBe(componentAppId);
    expect(authorizationUrl.searchParams.get("scope")).toBe("snsapi_userinfo");
    expect(authorizationUrl.searchParams.has("component_access_token")).toBe(false);

    const identity = await provider.exchangeCode({
      appId: authorizedAppId,
      appSecret: "unused-authorized-secret",
      code: "oauth-code",
    });
    expect(identity).toMatchObject({
      provider: "wechat",
      platform: "wechat_official_account",
      appId: authorizedAppId,
      openid: "openid-1",
      nickname: "Component User",
      scopes: ["snsapi_userinfo"],
    });
    expect(resolveComponentAccessToken).toHaveBeenCalledWith({
      componentAppId,
      authorizedAppId,
    });
    expect(String(fetch.mock.calls[0]?.[0])).toContain("component_access_token=component-token-");
    expect(String(fetch.mock.calls[0]?.[0])).not.toContain("unused-authorized-secret");
    expect(JSON.stringify(identity)).not.toContain("oauth-access-token");
    expect(JSON.stringify(identity)).not.toContain("oauth-refresh-token");
    expect(JSON.stringify(identity)).not.toContain("unused-authorized-secret");
  });

  it("binds multiple authorized accounts and keeps component tokens server-side", async () => {
    const resolveComponentAccessToken = vi.fn(async ({ authorizedAppId: accountId }: { authorizedAppId: string }) =>
      accountId === authorizedAppId ? "component-token-1" : "component-token-2",
    );
    const fetch = vi.fn().mockResolvedValueOnce(jsonResponse({
      authorizer_access_token: "authorizer-access-token",
      authorizer_refresh_token: "authorizer-refresh-token-2",
      expires_in: 7200,
    }));
    const provider = createWechatComponentProvider({
      componentAppId,
      bindings: [
        {
          componentAppId,
          authorizedAppId,
          appSecret: "authorized-secret-1",
          authorizerRefreshToken: "authorizer-refresh-token-1",
        },
        {
          componentAppId,
          authorizedAppId: "wx-authorized-2",
          appSecret: "authorized-secret-2",
          authorizerRefreshToken: "authorizer-refresh-token-2",
        },
      ],
      componentAccessTokenResolver: resolveComponentAccessToken,
      fetch,
    });

    expect(provider.listAuthorizedAccounts()).toEqual([authorizedAppId, "wx-authorized-2"]);
    await expect(provider.getAuthorizedAccount(authorizedAppId)).resolves.toMatchObject({
      componentAppId,
      authorizedAppId,
      bound: true,
      hasAppSecret: true,
      hasAuthorizerRefreshToken: true,
    });
    const metadata = (await Promise.all([
      provider.getAuthorizerAccessToken(authorizedAppId),
      provider.getAuthorizerAccessToken(authorizedAppId),
    ]))[0];
    expect(metadata).toEqual({ componentAppId, authorizedAppId, expiresIn: 7200 });
    expect(resolveComponentAccessToken).toHaveBeenCalledWith({ componentAppId, authorizedAppId });
    expect(fetch).toHaveBeenCalledTimes(1);
    const request = fetch.mock.calls[0];
    expect(String(request?.[0])).toContain("component_access_token=component-token-1");
    expect(request?.[1]?.body).toContain("component_appid");
    expect(request?.[1]?.body).toContain("authorizer_refresh_token");
    expect(JSON.stringify(metadata)).not.toContain("authorizer-access-token");
    expect(JSON.stringify(provider)).not.toContain("authorized-secret-1");
    expect(JSON.stringify(provider)).not.toContain("authorizer-refresh-token-1");
    expect(JSON.stringify(await provider.getAuthorizedAccount(authorizedAppId))).not.toContain("authorized-secret-1");

    expect(() => provider.createAuthorizationUrl({

      appId: "wx-not-bound",
      redirectUri: "https://app.example.test/wechat/official/callback",
      state: "state-value",
    })).toThrow(ApplicationPlatformError);
  });

  it("coalesces concurrent component token resolutions", async () => {
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let calls = 0;
    const provider = createWechatComponentProvider({
      componentAppId,
      bindings: [{ componentAppId, authorizedAppId }],
      componentAccessTokenResolver: async () => {
        calls += 1;
        await gate;
        return "component-token";
      },
    });
    const first = provider.resolveComponentAccessToken(authorizedAppId);
    const second = provider.resolveComponentAccessToken(authorizedAppId);
    await Promise.resolve();
    expect(calls).toBe(1);
    release?.();
    await expect(Promise.all([first, second])).resolves.toEqual(["component-token", "component-token"]);
  });

  it("normalizes resolver and provider failures without returning secret material", async () => {
    const resolverError = new Error("component-secret=do-not-leak");
    const provider = createWechatComponentProvider({
      componentAppId,
      bindings: [{ componentAppId, authorizedAppId }],
      componentAccessTokenResolver: async () => {
        throw resolverError;
      },
    });
    const error = await provider.resolveComponentAccessToken(authorizedAppId).catch((value: unknown) => value);
    expect(error).toMatchObject({ code: "component_access_token_unavailable" });
    expect(String(error)).not.toContain("do-not-leak");

    const fetch = vi.fn().mockResolvedValue(jsonResponse({ errcode: 40029, errmsg: "invalid code" }));
    const official = createWechatOfficialAccountAdapter({ fetch });
    const providerError = await official.exchangeCode({
      appId: authorizedAppId,
      appSecret: "official-secret",
      code: "bad-code",
    }).catch((value: unknown) => value);
    expect(providerError).toMatchObject({ code: "provider_error" });
    expect(String((providerError as { providerUrl?: string }).providerUrl ?? "")).not.toContain("official-secret");
    expect(String(providerError)).not.toContain("invalid code");
    expect(String(providerError)).not.toContain("official-secret");
  });

  it("creates a server-side component token resolver with body-only secrets", async () => {
    const fetch = vi.fn().mockResolvedValue(jsonResponse({
      component_access_token: "component-token-from-api",
      expires_in: 7200,
    }));
    const resolve = createWechatComponentAccessTokenResolver({
      componentAppId,
      componentAppSecret: "component-app-secret",
      componentVerifyTicket: "component-verify-ticket",
      fetch,
    });
    await expect(resolve({ componentAppId, authorizedAppId })).resolves.toBe("component-token-from-api");
    expect(String(fetch.mock.calls[0]?.[0])).not.toContain("component-app-secret");
    expect(String(fetch.mock.calls[0]?.[0])).not.toContain("component-verify-ticket");
    expect(fetch.mock.calls[0]?.[1]?.body).toContain("component_appsecret");
    expect(fetch.mock.calls[0]?.[1]?.body).toContain("component_verify_ticket");
  });

  it("keeps the open-platform QR adapter on snsapi_login", () => {
    const adapter = createWechatOpenPlatformAdapter();
    const url = new URL(adapter.createAuthorizationUrl({
      appId: "wx-open",
      redirectUri: "https://app.example.test/wechat/open/callback",
      state: "state-value",
      scope: "snsapi_login",
    }));
    expect(url.pathname).toBe("/connect/qrconnect");
    expect(url.searchParams.get("scope")).toBe("snsapi_login");
    expect(createDirectComponentAdapter).toBe(createWechatComponentAdapter);
  });
});
