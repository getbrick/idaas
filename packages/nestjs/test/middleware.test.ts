import { describe, expect, it, vi } from "vitest";
import { Test } from "@nestjs/testing";
import request from "supertest";
import {
  GetbrickIdaasModule,
  GetbrickOidcMiddleware,
  toWebRequest,
  type GetbrickAuthLike,
} from "../src/index.js";
import { normalizeOidcClaimPolicy, normalizeOidcConsentPolicy } from "@getbrick/idaas-core";

const authRequest = {
  originalUrl: "/api/auth/test?next=%2Fdashboard",
  method: "GET",
  headers: {
    host: "attacker.example",
    "x-forwarded-host": "public.example",
    "x-forwarded-proto": "https",
  },
};

describe("Nest auth request origin", () => {
  it("ignores forged Host and forwarded headers by default", () => {
    const request = toWebRequest(authRequest);

    expect(request.url).toBe("http://localhost/api/auth/test?next=%2Fdashboard");
    expect(request.headers.get("host")).toBe("localhost");
    expect(request.headers.get("x-forwarded-host")).toBeNull();
    expect(request.headers.get("x-forwarded-proto")).toBeNull();
  });

  it("uses the explicit canonical origin", () => {
    const request = toWebRequest(authRequest, {
      baseURL: "https://auth.example.test/tenant",
    });

    expect(request.url).toBe("https://auth.example.test/api/auth/test?next=%2Fdashboard");
    expect(request.headers.get("host")).toBe("auth.example.test");
  });

  it("uses forwarded origin only with trustProxy enabled", () => {
    const request = toWebRequest(authRequest, { trustProxy: true });

    expect(request.url).toBe("https://public.example/api/auth/test?next=%2Fdashboard");
    expect(request.headers.get("x-forwarded-host")).toBe("public.example");
    expect(request.headers.get("x-forwarded-proto")).toBe("https");
  });

  it("rejects invalid origins and forwarded values", () => {
    expect(() => toWebRequest(authRequest, { baseURL: "ftp://auth.example.test" })).toThrow(/baseURL/);
    expect(() => toWebRequest(authRequest, { trustProxy: true, baseURL: "https://auth.example.test" })).not.toThrow();
    expect(() => toWebRequest({
      ...authRequest,
      headers: { "x-forwarded-host": "https://public.example", "x-forwarded-proto": "https" },
    }, { trustProxy: true })).toThrow(/X-Forwarded-Host/);
    expect(() => toWebRequest({
      ...authRequest,
      originalUrl: "https://attacker.example/api/auth/test",
    }, { baseURL: "https://auth.example.test" })).toThrow(/canonical origin/);
  });

  it("keeps the configured origin through the Express auth route", async () => {
    const requests: Request[] = [];
    const auth = {
      options: { baseURL: "https://configured.example/tenant" },
      api: { getSession: async () => undefined },
      handler: async (webRequest: Request) => {
        requests.push(webRequest);
        return new Response("ok");
      },
    } as unknown as GetbrickAuthLike;
    const moduleRef = await Test.createTestingModule({
      imports: [GetbrickIdaasModule.forRoot({ auth })],
    }).compile();
    const app = moduleRef.createNestApplication();
    await app.init();

    const response = await request(app.getHttpServer())
      .get("/api/auth/probe")
      .set("Host", "attacker.example")
      .set("X-Forwarded-Host", "public.example")
      .set("X-Forwarded-Proto", "https");

    expect(response.status).toBe(200);
    expect(requests[0].url).toBe("https://configured.example/api/auth/probe");
    await app.close();
  });

  it("denies an OIDC interaction bound to another account", async () => {
    const finished: unknown[] = [];
    const runtime = {
      issuer: "https://id.example.test/oidc",
      basePath: "/oidc",
      interactionPath: "/oidc/interaction",
      provider: {
        interactionDetails: async () => ({
          uid: "interaction-1",
          grantId: "grant-1",
          params: { client_id: "client" },
          prompt: { name: "consent" },
          session: { accountId: "user-a", clientId: "client" },
        }),
        interactionFinished: async (_request: unknown, _response: unknown, result: unknown) => {
          finished.push(result);
        },
      },
    } as never;
    const auth = {
      options: {},
      api: { getSession: async () => ({ user: { id: "user-b" } }) },
      handler: async () => new Response("ok"),
    } as GetbrickAuthLike;
    const middleware = new GetbrickOidcMiddleware(runtime, auth);
    const response = {
      headersSent: false,
      end: () => undefined,
      setHeader: () => undefined,
    };
    await middleware.use({
      originalUrl: "/oidc/interaction/interaction-1",
      method: "GET",
      headers: {},
    }, response, () => undefined);
    expect(finished).toEqual([{ error: "access_denied" }]);
  });

  it("does not silently grant sensitive scopes without an explicit decision", async () => {
    const finished: unknown[] = [];
    const runtime = {
      issuer: "https://id.example.test/oidc",
      basePath: "/oidc",
      interactionPath: "/oidc/interaction",
      consentPolicy: normalizeOidcConsentPolicy(),
      provider: {
        interactionDetails: async () => ({
          uid: "interaction-1",
          grantId: "grant-1",
          params: { client_id: "client", scope: "openid offline_access" },
          prompt: { name: "consent", details: { missingOIDCScope: ["offline_access"] } },
          session: { accountId: "user-a", clientId: "client" },
        }),
        interactionFinished: async (_request: unknown, _response: unknown, result: unknown) => {
          finished.push(result);
        },
      },
    } as never;
    const auth = {
      options: {},
      api: { getSession: async () => ({ user: { id: "user-a" } }) },
      handler: async () => new Response("ok"),
    } as GetbrickAuthLike;
    const middleware = new GetbrickOidcMiddleware(runtime, auth);
    const response = {
      headersSent: false,
      end: () => undefined,
      setHeader: () => undefined,
    };
    await middleware.use({
      originalUrl: "/oidc/interaction/interaction-1",
      method: "GET",
      headers: {},
    }, response, () => undefined);
    expect(finished).toEqual([{ error: "consent_required" }]);
  });

  it("uses verified V2 context and grants only approved missing values", async () => {
    const addedScopes: string[] = [];
    const addedClaims: string[][] = [];
    const rejectedScopes: string[] = [];
    const rejectedClaims: string[][] = [];
    let receivedContext: Record<string, unknown> | undefined;
    const resolver = vi.fn(async (context: Record<string, unknown>) => {
      receivedContext = context;
      return {
        decision: "approved" as const,
        consentId: context.consentId,
        approvedScopes: ["openid"],
        approvedClaims: ["role"],
        policyVersion: context.policyVersion,
        userGesture: true as const,
      };
    });
    const grant = {
      accountId: "user-a",
      clientId: "client",
      jti: "grant-1",
      getOIDCScope: () => "",
      getOIDCClaims: () => [],
      addOIDCScope: (value: string) => { addedScopes.push(value); },
      addOIDCClaims: (value: string[]) => { addedClaims.push(value); },
      rejectOIDCScope: (value: string) => { rejectedScopes.push(value); },
      rejectOIDCClaims: (value: string[]) => { rejectedClaims.push(value); },
      save: async () => "grant-1",
    };
    const runtime = {
      issuer: "https://id.example.test/oidc",
      basePath: "/oidc",
      interactionPath: "/oidc/interaction",
      consentResolverMode: "v2",
      consentTenantId: "tenant-verified",
      consentApplicationId: "application-verified",
      claimPolicy: normalizeOidcClaimPolicy({
        policyVersion: "policy-v2",
        definitions: [{
          name: "role",
          scopes: ["profile"],
          clients: ["client"],
          source: "membership",
          required: false,
          sensitive: false,
          version: "1",
        }],
      }),
      resolveConsentV2: resolver,
      provider: {
        Client: {
          find: async () => ({ metadata: () => ({ client_id: "client", application_type: "web" }) }),
        },
        Grant: {
          find: async () => grant,
        },
        interactionDetails: async () => ({
          uid: "interaction-1",
          grantId: "grant-1",
          params: {
            client_id: "client",
            scope: "openid profile",
            claims: JSON.stringify({ role: null, email: null }),
            tenant_id: "forged-tenant",
            application_id: "forged-application",
            user_id: "forged-user",
            grant_id: "forged-grant",
          },
          prompt: {
            name: "consent",
            details: {
              missingOIDCScope: ["openid", "profile"],
              missingOIDCClaims: ["role", "email"],
            },
          },
          session: { accountId: "user-a", clientId: "client" },
        }),
        interactionFinished: async () => undefined,
      },
    } as never;
    const auth = {
      options: {},
      api: { getSession: async () => ({ user: { id: "user-a" } }) },
      handler: async () => new Response("ok"),
    } as GetbrickAuthLike;
    const middleware = new GetbrickOidcMiddleware(runtime, auth);
    const response = { headersSent: false, setHeader: () => undefined, end: () => undefined };
    await middleware.use({
      originalUrl: "/oidc/interaction/interaction-1",
      method: "GET",
      headers: {},
    }, response, () => undefined);
    expect(resolver).toHaveBeenCalledTimes(1);
    expect(receivedContext).toMatchObject({
      tenantId: "tenant-verified",
      applicationId: "application-verified",
      clientId: "client",
      userId: "user-a",
      grantId: "grant-1",
      interactionId: "interaction-1",
      requestedScopes: ["openid", "profile"],
      requestedClaims: ["role", "email"],
      policyVersion: "policy-v2",
    });
    expect(addedScopes).toEqual(["openid"]);
    expect(addedClaims).toEqual([["role"]]);
    expect(rejectedScopes).toEqual(["profile"]);
    expect(rejectedClaims).toEqual([["email"]]);
  });

  it("passes the exact interaction return path to the platform login handler", async () => {
    const headers: Record<string, string> = {};
    const received: string[] = [];
    const runtime = {
      issuer: "https://id.example.test/oidc",
      basePath: "/oidc",
      interactionPath: "/oidc/interaction",
      provider: {
        interactionDetails: async () => ({
          uid: "interaction-1",
          params: { client_id: "client" },
          prompt: { name: "login" },
        }),
      },
    } as never;
    const auth = {
      options: {},
      api: { getSession: async () => undefined },
      handler: async () => new Response("ok"),
    } as GetbrickAuthLike;
    const middleware = new GetbrickOidcMiddleware(
      runtime,
      auth,
      undefined,
      async (input) => {
        received.push(input.returnTo);
        return { redirectUrl: "https://wechat.example.test/oauth/authorize" };
      },
    );
    const response = {
      headersSent: false,
      setHeader: (name: string, value: string) => { headers[name] = value; },
      end: () => undefined,
    };

    await middleware.use({
      originalUrl: "/oidc/interaction/interaction-1?client_id=client&x=%2Ffoo",
      method: "GET",
      headers: {},
    }, response, () => undefined);

    expect(received).toEqual(["/oidc/interaction/interaction-1?client_id=client&x=%2Ffoo"]);
    expect(response).toMatchObject({ statusCode: 303 });
    expect(headers.Location).toBe("https://wechat.example.test/oauth/authorize");
    expect(headers["Cache-Control"]).toBe("no-store");
    expect(headers["Referrer-Policy"]).toBe("no-referrer");
  });

  it("fails closed for an unsafe OIDC interaction continuation", async () => {
    const headers: Record<string, string> = {};
    const runtime = {
      issuer: "https://id.example.test/oidc",
      basePath: "/oidc",
      interactionPath: "/oidc/interaction",
      provider: {
        interactionDetails: async () => ({
          uid: "interaction-1",
          params: { client_id: "client" },
          prompt: { name: "login" },
        }),
      },
    } as never;
    const auth = {
      options: {},
      api: { getSession: async () => undefined },
      handler: async () => new Response("ok"),
    } as GetbrickAuthLike;
    const middleware = new GetbrickOidcMiddleware(runtime, auth, "https://login.example.test/start");
    const response = {
      headersSent: false,
      setHeader: (name: string, value: string) => { headers[name] = value; },
      json: (value: unknown) => { response.body = value; },
      end: () => undefined,
    } as { headersSent: boolean; setHeader: (name: string, value: string) => void; json: (value: unknown) => void; end: () => void; body?: unknown; statusCode?: number };

    await middleware.use({
      originalUrl: "/oidc/interaction/%2f%2fevil",
      method: "GET",
      headers: {},
    }, response, () => undefined);

    expect(response.statusCode).toBe(400);
    expect(response.body).toEqual({ error: "invalid_request" });
    expect(headers.Location).toBeUndefined();
  });

  it("requires an explicit decision for every prompt=consent interaction", async () => {
    const finished: unknown[] = [];
    const runtime = {
      issuer: "https://id.example.test/oidc",
      basePath: "/oidc",
      interactionPath: "/oidc/interaction",
      consentPolicy: normalizeOidcConsentPolicy({ requireExplicitConsent: false }),
      provider: {
        interactionDetails: async () => ({
          uid: "interaction-1",
          grantId: "grant-1",
          params: { client_id: "client", scope: "openid profile", prompt: "consent" },
          prompt: { name: "consent" },
          session: { accountId: "user-a", clientId: "client" },
        }),
        interactionFinished: async (_request: unknown, _response: unknown, result: unknown) => {
          finished.push(result);
        },
      },
    } as never;
    const auth = {
      options: {},
      api: { getSession: async () => ({ user: { id: "user-a" } }) },
      handler: async () => new Response("ok"),
    } as GetbrickAuthLike;
    const middleware = new GetbrickOidcMiddleware(runtime, auth);
    const response = { headersSent: false, end: () => undefined, setHeader: () => undefined };
    await middleware.use({ originalUrl: "/oidc/interaction/interaction-1", method: "GET", headers: {} }, response, () => undefined);
    expect(finished).toEqual([{ error: "consent_required" }]);
  });

  it("does not satisfy an explicit prompt=login with the existing host session", async () => {
    let reauthenticate = false;
    const runtime = {
      issuer: "https://id.example.test/oidc",
      basePath: "/oidc",
      interactionPath: "/oidc/interaction",
      provider: {
        interactionDetails: async () => ({
          uid: "interaction-1",
          params: { client_id: "client", prompt: "login" },
          prompt: { name: "login" },
        }),
      },
    } as never;
    const auth = {
      options: {},
      api: { getSession: async () => ({ user: { id: "user-a" } }) },
      handler: async () => new Response("ok"),
    } as GetbrickAuthLike;
    const middleware = new GetbrickOidcMiddleware(runtime, auth, undefined, async (input) => {
      reauthenticate = input.reauthenticate === true;
      return { redirectUrl: "https://login.example.test/reauthenticate" };
    });
    const response = { headersSent: false, setHeader: () => undefined, end: () => undefined };
    await middleware.use({ originalUrl: "/oidc/interaction/interaction-1", method: "GET", headers: {} }, response, () => undefined);
    expect(reauthenticate).toBe(true);
    expect(response).toMatchObject({ statusCode: 303 });
  });

  it("rejects invalid module configuration", () => {
    const auth = {
      api: { getSession: async () => undefined },
      handler: async () => new Response("ok"),
    } as unknown as GetbrickAuthLike;

    expect(() => GetbrickIdaasModule.forRoot({ auth, baseURL: "not-a-url" })).toThrow(/baseURL/);
    expect(() => GetbrickIdaasModule.forRoot({ auth, trustProxy: "yes" as unknown as boolean })).toThrow(/trustProxy/);
  });
});
