import { describe, expect, it, vi } from "vitest";
import {
  ApplicationOidcClientStore,
  ApplicationPlatformAuthService,
  ApplicationPlatformRuntimeController,
  InMemoryApplicationRepository,
  createDefaultApplicationPlatformRegistry,
  createApplicationPlatformWebviewTicketService,
  parseApplicationClientCreateRequest,
  parseApplicationClientUpdateRequest,
  parseApplicationPlatformCreateRequest,
} from "../src/index.js";

const redirectUri = "https://rp.example.test/callback";

function repository() {
  return new InMemoryApplicationRepository({
    applications: [{ id: "app-1", name: "Alpha", slug: "alpha", status: "active" }],
    platforms: [{
      id: "platform-1",
      applicationId: "app-1",
      type: "wechat_component",
      componentAppId: "wx-component",
      authorizedAppId: "wx-authorized",
      redirectUris: [redirectUri],
      status: "active",
    }],
  });
}

describe("application integration boundaries", () => {
  it("validates RP aliases and rejects public secrets", () => {
    const rpClient = {
      clientId: "third-party-rp",
      clientType: "web" as const,
      clientKind: "web" as const,
      redirectUris: [redirectUri],
      redirectUriPolicy: "exact" as const,
      requirePkce: true,
      pkceMethod: "S256" as const,
      consent: { required: true, mode: "explicit" as const },
    };
    expect(parseApplicationClientCreateRequest({
      clientId: rpClient.clientId,
      clientKind: "web",
      clientType: "web",
      redirectUris: [redirectUri],
      tokenEndpointAuthMethod: "none",
      rpClient,
    })).toMatchObject({
      clientKind: "web",
      redirectUriPolicy: "exact",
      requirePkce: true,
      pkceMethod: "S256",
      consentRequired: true,
      requireExplicitConsent: true,
    });
    expect(() => parseApplicationClientCreateRequest({
      clientId: rpClient.clientId,
      clientKind: "web",
      clientType: "native",
      redirectUris: [redirectUri],
      tokenEndpointAuthMethod: "none",
      rpClient,
    })).toThrow();
    expect(() => parseApplicationClientCreateRequest({
      clientId: rpClient.clientId,
      clientKind: "web",
      clientType: "web",
      redirectUris: [redirectUri],
      tokenEndpointAuthMethod: "none",
      secretRef: "vault://public-secret",
      rpClient,
    })).toThrow();
     expect(() => parseApplicationClientCreateRequest({
       clientId: rpClient.clientId,
       clientKind: "web",
       clientType: "web",
       redirectUris: [redirectUri],
       tokenEndpointAuthMethod: "none",
       pkceMethod: "plain",
       rpClient,
     })).toThrow();
     expect(parseApplicationClientUpdateRequest({ rpClient })).toMatchObject({
       clientKind: "web",
       clientType: "web",
       redirectUriPolicy: "exact",
       requirePkce: true,
       pkceMethod: "S256",
       consentRequired: true,
       requireExplicitConsent: true,
     });
   });

  it("rejects secret and conflicting client aliases in update requests", () => {
    expect(() => parseApplicationClientUpdateRequest({ secretRef: "vault://client" })).toThrow();
    expect(() => parseApplicationClientUpdateRequest({ clientKind: "web", clientType: "native" })).toThrow();
  });

  it("parses component binding fields and rejects component data on ordinary platforms", () => {
    expect(parseApplicationPlatformCreateRequest({
      type: "wechat_component",
      componentAppId: "wx-component",
      authorizedAppId: "wx-authorized",
      componentBinding: {
        componentAppSecretRef: "vault://wechat/component",
        componentAccessTokenRef: "vault://wechat/component-token",
        status: "active",
      },
    })).toMatchObject({
      type: "wechat_component",
      componentAppId: "wx-component",
      authorizedAppId: "wx-authorized",
      componentAppSecretRef: "vault://wechat/component",
      componentAccessTokenRef: "vault://wechat/component-token",
      componentBindingStatus: "active",
    });
    expect(() => parseApplicationPlatformCreateRequest({
      type: "wechat_official_account",
      externalAppId: "wx-official",
      componentAppId: "wx-component",
      authorizedAppId: "wx-authorized",
    })).toThrow();
    expect(() => parseApplicationPlatformCreateRequest({
      type: "wechat_component",
      componentAppId: "wx-component",
      authorizedAppId: "wx-authorized",
      componentBinding: {
        componentAppId: "other-component",
      },
    })).toThrow();
  });

  it("keeps the component adapter explicit and fails closed without one", async () => {
    expect(createDefaultApplicationPlatformRegistry().has("wechat_component")).toBe(false);
    const service = new ApplicationPlatformAuthService(repository(), {
      resolveCredentials: () => ({ appId: "wx-authorized", appSecret: "secret" }),
    });
    await expect(service.createAuthorizationUrl("app-1", "platform-1", {
      redirectUri,
      state: "s".repeat(43),
    })).rejects.toMatchObject({ code: "component_adapter_not_configured" });
    const adapter = {
      type: "wechat_component",
      supportsAuthorization: true,
       createAuthorizationUrl: ({ state }: { state: string }) => `https://provider.example.test/authorize?state=${state}`,
       exchangeCode: vi.fn(async () => ({ provider: "wechat", platform: "wechat_official_account", appId: "wx-authorized", subject: "subject", scopes: [] })),
    };
    const configured = new ApplicationPlatformAuthService(repository(), {
      resolveCredentials: () => ({ appId: "wx-authorized", appSecret: "secret" }),
      adapters: [adapter],
    });
    await expect(configured.createAuthorizationUrl("app-1", "platform-1", {
      redirectUri,
      state: "s".repeat(43),
     })).resolves.toContain("provider.example.test");
     await expect(configured.exchangeCode("app-1", "platform-1", "code", redirectUri, "web", false)).resolves.toMatchObject({ appId: "wx-authorized" });
     expect(adapter.exchangeCode).toHaveBeenCalledWith(expect.objectContaining({ componentAppId: "wx-component", authorizedAppId: "wx-authorized" }));
   });

  it("projects RP configuration and rejects public secret metadata", async () => {
    const rpRepository = new InMemoryApplicationRepository({
      applications: [{ id: "app-1", name: "Alpha", slug: "alpha", applicationType: "web", status: "active" }],
      clients: [{
        id: "client-1",
        applicationId: "app-1",
        clientId: "third-party-rp",
        clientKind: "web",
        clientType: "web",
        redirectUris: [redirectUri],
        grantTypes: ["authorization_code"],
        responseTypes: ["code"],
        scopes: ["openid"],
        tokenEndpointAuthMethod: "none",
        requirePkce: true,
        redirectUriPolicy: "exact",
        pkceMethod: "S256",
        consent: { required: true, mode: "explicit" },
        rpClient: {
          clientId: "third-party-rp",
          redirectUris: [redirectUri],
          redirectUriPolicy: "exact",
          requirePkce: true,
          pkceMethod: "S256",
          consent: { required: true, mode: "explicit" },
        },
        status: "active",
      }],
    });
    const store = new ApplicationOidcClientStore(rpRepository);
    await expect(store.find("third-party-rp")).resolves.toMatchObject({
      client_id: "third-party-rp",
      client_kind: "web",
      application_type: "web",
      require_pkce: true,
      pkce_method: "S256",
      redirect_uri_policy: "exact",
      consent: { required: true, mode: "explicit" },
    });
    const publicSecretRepository = new InMemoryApplicationRepository({
      applications: [{ id: "app-1", name: "Alpha", slug: "alpha", status: "active" }],
      clients: [{
        id: "client-2",
        applicationId: "app-1",
        clientId: "public-rp",
        redirectUris: [redirectUri],
        tokenEndpointAuthMethod: "none",
        secretRef: "vault://public-secret",
        status: "active",
      }],
    });
    const publicStore = new ApplicationOidcClientStore(publicSecretRepository, { resolveSecret: () => "secret" });
    await expect(publicStore.find("public-rp")).rejects.toThrow(/public/i);
  });

  it("returns only public login data and hides the ticket session reference", async () => {
    const response = {
      setHeader() { return response; },
      status() { return response; },
      json(value: unknown) { body = value; return response; },
      end() { return response; },
    };
    let body: unknown;
    const controller = new ApplicationPlatformRuntimeController({
      exchangeMiniProgram: async () => ({
        user: { id: "user-1", name: "User", email: null, emailVerified: false },
        identity: { provider: "wechat", platform: "wechat_mini_program", appId: "wx-secret", subject: "openid-secret", openid: "openid-secret", unionid: "unionid-secret", scopes: [] },
        account: { providerId: "wechat", accountId: "subject-secret", platform: "wechat_mini_program", appId: "wx-secret", scopes: [] },
        session: { sessionReference: "opaque_session_reference_123", expiresAt: "2026-01-01T00:00:00.000Z" },
        created: true,
        linked: false,
        client: "mp_weixin" as const,
      }),
      issueWebviewTicket: async () => ({
        ticket: "ticket_reference_123",
        ticketReference: "ticket_reference_123",
        expiresAt: "2026-01-01T00:00:00.000Z",
        sessionReference: "opaque_session_reference_123",
        clientKind: "webview" as const,
      }),
    } as never);
    await controller.exchangeMiniProgram("app-1", "platform-1", { code: "mini-code" }, { headers: {} }, response);
    expect(body).toMatchObject({ user: { id: "user-1" }, created: true, linked: false, clientKind: "mp_weixin", session: { sessionReference: "opaque_session_reference_123" } });
    expect(body).not.toHaveProperty("identity");
    expect(body).not.toHaveProperty("account");
    expect(JSON.stringify(body)).not.toMatch(/openid-secret|unionid-secret|subject-secret|wx-secret/);
    await controller.issueWebviewTicket("app-1", "platform-1", { sessionReference: "opaque_session_reference_123" }, { headers: {} }, response);
    expect(body).not.toHaveProperty("sessionReference");
  });

  it("binds webview tickets to an RP client and the current client session", async () => {
    const sessionReference = "ocs_current_session_reference";
    const sessionService = {
      refresh: async (input: { sessionReference: string; client?: string }) => ({
        sessionReference: "ocs_webview_session_reference",
        expiresAt: "2026-01-01T00:00:00.000Z",
        userId: "user-1",
        applicationId: "app-1",
        platformId: "platform-1",
        client: (input.client ?? "webview") as "webview",
        clientKind: (input.client ?? "webview") as "webview",
      }),
      logout: async () => { throw new Error("unused"); },
      revoke: async () => { throw new Error("unused"); },
      get: async (input: { sessionReference: string }) => input.sessionReference === sessionReference ? {
        sessionReference,
        expiresAt: "2026-01-01T00:00:00.000Z",
        userId: "user-1",
        applicationId: "app-1",
        platformId: "platform-1",
        client: "mp_weixin" as const,
      } : undefined,
    };
    const webviewTicketService = createApplicationPlatformWebviewTicketService();
    const rpRepository = new InMemoryApplicationRepository({
      applications: [{ id: "app-1", name: "Alpha", slug: "alpha", status: "active" }],
      platforms: [{ id: "platform-1", applicationId: "app-1", type: "wechat_mini_program", externalAppId: "wx-app", redirectUris: ["https://platform.example.test/callback"], status: "active" }],
      clients: [{ id: "client-1", applicationId: "app-1", clientId: "rp-client", redirectUris: [redirectUri], status: "active" }],
    });
    const service = new ApplicationPlatformAuthService(rpRepository, { sessionService, webviewTicketService });
    const issued = await service.issueWebviewTicket("app-1", "platform-1", {
      sessionReference,
      clientId: "rp-client",
      redirectUri,
    });
    expect(issued.redirectUri).toBe(redirectUri);
    await expect(service.exchangeWebviewTicket("app-1", "platform-1", {
      ticket: issued.ticket,
      sessionReference: "ocs_other_session_reference",
      clientId: "rp-client",
    })).rejects.toMatchObject({ code: "invalid_webview_ticket" });
    await expect(service.exchangeWebviewTicket("app-1", "platform-1", {
      ticket: issued.ticket,
    })).rejects.toMatchObject({ code: "invalid_webview_ticket" });
    await expect(service.exchangeWebviewTicket("app-1", "platform-1", {
      ticket: issued.ticket,
      sessionReference,
      clientId: "rp-client",
    })).resolves.toMatchObject({ sessionReference: "ocs_webview_session_reference", client: "webview" });
  });
});
