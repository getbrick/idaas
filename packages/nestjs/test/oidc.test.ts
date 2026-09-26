import "reflect-metadata";
import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { Test } from "@nestjs/testing";
import { Module } from "@nestjs/common";
import express from "express";
import request from "supertest";
import { memoryAdapter } from "better-auth/adapters/memory";
import { buildTableMap, createIdaas, defineIdaasConfig, type OidcClaimPolicyInput, type OidcConsentContext, type OidcConsentResolverV2, type OidcUser } from "@getbrick/idaas-core";
import {
  GETBRICK_OIDC_READINESS,
  GETBRICK_OIDC_RUNTIME,
  GetbrickIdaasModule,
  GetbrickOidcModule,
} from "../src/index.js";

function createOauthApplication() {
  const tables = buildTableMap();
  const data: Record<string, unknown[]> = {};
  for (const name of Object.values(tables)) data[name] = [];
  const users = new Map<string, OidcUser>();
  const config = defineIdaasConfig({
    appName: "OIDC Test",
    baseURL: "http://localhost",
    trustedOrigins: ["http://localhost"],
    oidc: {
      op: {
        enabled: true,
        issuer: "http://localhost/oidc",
        basePath: "/oidc",
        clients: [
          {
            clientId: "client",
            clientSecret: "client-secret",
            redirectUris: ["http://client.example/callback"],
            postLogoutRedirectUris: ["http://client.example/callback"],
            grantTypes: ["authorization_code", "refresh_token"],
            scopes: ["openid", "profile", "email", "offline_access"],
          },
        ],
      },
    },
  });
  const auth = createIdaas({
    config,
    database: memoryAdapter(data as never),
  });
  return { auth, users, config };
}

function createProductionRemoteJwksConfig() {
  return {
    profile: "production" as const,
    appName: "OIDC Production JWKS",
    baseURL: "https://auth.example.com",
    secret: "s".repeat(32),
    trustedOrigins: ["https://app.example.com"],
    registration: { publicSignUp: false, requireEmailVerification: true },
    oidc: {
      op: {
        enabled: true,
        issuer: "https://id.example.com/oidc",
        basePath: "/oidc",
        clients: [{
          clientId: "remote-client",
          tokenEndpointAuthMethod: "private_key_jwt" as const,
          redirectUris: ["https://app.example.com/callback"],
          jwksUri: "https://client.example.com/jwks",
        }],
      },
    },
  };
}

@Module({})
class OidcTestModule {
  static forRoot(
    auth: ReturnType<typeof createOauthApplication>["auth"],
    users: Map<string, OidcUser>,
    v2?: {
      resolver: OidcConsentResolverV2;
      tenantId: string;
      applicationId: string;
      claimPolicy?: OidcClaimPolicyInput;
    },
  ) {
    return {
      module: OidcTestModule,
      imports: [
        GetbrickIdaasModule.forRoot({ auth }),
        GetbrickOidcModule.forRoot({
          auth,
          config: {
            appName: "OIDC Test",
            baseURL: "http://localhost",
            trustedOrigins: ["http://localhost"],
            oidc: {
              op: {
                enabled: true,
                issuer: "http://localhost/oidc",
                basePath: "/oidc",
                clients: [
                  {
                    clientId: "client",
                    clientSecret: "client-secret",
                    redirectUris: ["http://client.example/callback"],
                    postLogoutRedirectUris: ["http://client.example/callback"],
                    grantTypes: ["authorization_code", "refresh_token"],
                    scopes: ["openid", "profile", "email", "offline_access"],
                  },
                ],
              },
            },
          },
           findUser: async (id) => users.get(id) ?? null,
           ...(v2 === undefined
             ? { consentResolver: async () => true }
             : {
                 consentResolverV2: v2.resolver,
                 tenantId: v2.tenantId,
                 applicationId: v2.applicationId,
                 ...(v2.claimPolicy === undefined ? {} : { claimPolicy: v2.claimPolicy }),
               }),

         }),
      ],
    };
  }
}

describe("OIDC provider", () => {
  it("fails closed without persistent production storage", () => {
    expect(() =>
      GetbrickOidcModule.forRoot({
        auth: { options: {}, api: { getSession: async () => null }, handler: async () => new Response("ok") },
        config: {
          profile: "production",
          baseURL: "https://auth.example.com",
          secret: "s".repeat(32),
          trustedOrigins: ["https://app.example.com"],
          registration: { publicSignUp: false, requireEmailVerification: true },
          oidc: {
            op: {
              enabled: true,
              issuer: "https://id.example.com/oidc",
              basePath: "/oidc",
              clients: [{ clientId: "client", redirectUris: ["https://app.example.com/callback"] }],
            },
          },
        },
        findUser: async () => null,
      }),
    ).toThrow(/persistent adapter/i);
  });

  it("rejects static remote JWKS by default and requires an allowlist in production", () => {
    const auth = { options: { secret: "s".repeat(32) }, api: { getSession: async () => null }, handler: async () => new Response("ok") };
    expect(() => GetbrickOidcModule.forRoot({
      auth,
      config: createProductionRemoteJwksConfig(),
      findUser: async () => null,
    })).toThrow(/production.*jwks_uri.*disabled/i);
    expect(() => GetbrickOidcModule.forRoot({
      auth,
      config: createProductionRemoteJwksConfig(),
      findUser: async () => null,
      allowRemoteJwksUri: true,
    })).toThrow(/trusted.*allowlist/i);
  });

  it("requires a production storage readiness check", () => {
    const adapter = () => ({
      find: async () => undefined,
      upsert: async () => undefined,
      destroy: async () => undefined,
    });
    expect(() => GetbrickOidcModule.forRoot({
      auth: { options: { secret: "s".repeat(32) }, api: { getSession: async () => null }, handler: async () => new Response("ok") },
      config: {
        profile: "production",
        baseURL: "https://auth.example.com",
        secret: "s".repeat(32),
        trustedOrigins: ["https://app.example.com"],
        registration: { publicSignUp: false, requireEmailVerification: true },
        oidc: {
          op: {
            enabled: true,
            issuer: "https://id.example.com/oidc",
            basePath: "/oidc",
            clients: [{ clientId: "client", redirectUris: ["https://app.example.com/callback"] }],
          },
        },
      },
      findUser: async () => null,
      adapter: adapter as never,
      jwks: { keys: [{}] } as never,
      cookieKeys: ["s".repeat(32)],
    })).toThrow(/storage readiness check/i);
  });

  it("allows an explicitly trusted remote JWKS origin in development", () => {
    const { auth, users, config } = createOauthApplication();
    const client = config.oidc.op.clients[0]!;
    client.tokenEndpointAuthMethod = "private_key_jwt";
    client.jwksUri = "https://client.example.test/jwks";
    delete client.clientSecret;
    expect(() => GetbrickOidcModule.forRoot({
      auth,
      config,
      findUser: async (id) => users.get(id) ?? null,
      allowRemoteJwksUri: true,
      trustedJwksOrigins: ["https://client.example.test"],
    })).not.toThrow();
  });

  it("rejects void and non-boolean readiness results", async () => {
    const { auth, users, config } = createOauthApplication();
    const adapter = Object.assign(
      () => ({
        find: async () => undefined,
        upsert: async () => undefined,
        destroy: async () => undefined,
      }),
      { ready: async () => true },
    );
    const module = GetbrickOidcModule.forRoot({
      auth,
      config,
      findUser: async (id) => users.get(id) ?? null,
      adapter: adapter as never,
      readiness: async () => undefined as never,
    });
    const provider = module.providers?.find(
      (value) => "provide" in value && value.provide === GETBRICK_OIDC_READINESS,
    );
    const readiness = provider && "useValue" in provider
      ? provider.useValue as () => Promise<boolean>
      : undefined;
    expect(readiness).toBeTypeOf("function");
    await expect(readiness?.()).resolves.toBe(false);

    const stringModule = GetbrickOidcModule.forRoot({
      auth,
      config,
      findUser: async (id) => users.get(id) ?? null,
      adapter: Object.assign(
        () => ({
          find: async () => undefined,
          upsert: async () => undefined,
          destroy: async () => undefined,
        }),
        { ready: async () => true },
      ) as never,
      readiness: async () => "ready" as never,
    });
    const stringProvider = stringModule.providers?.find(
      (value) => "provide" in value && value.provide === GETBRICK_OIDC_READINESS,
    );
    const stringReadiness = stringProvider && "useValue" in stringProvider
      ? stringProvider.useValue as () => Promise<boolean>
      : undefined;
    await expect(stringReadiness?.()).resolves.toBe(false);

    const voidAdapterModule = GetbrickOidcModule.forRoot({
      auth,
      config,
      findUser: async (id) => users.get(id) ?? null,
      adapter: Object.assign(
        () => ({
          find: async () => undefined,
          upsert: async () => undefined,
          destroy: async () => undefined,
        }),
        { ready: async () => undefined },
      ) as never,
      readiness: async () => true,
    });
    const voidAdapterProvider = voidAdapterModule.providers?.find(
      (value) => "provide" in value && value.provide === GETBRICK_OIDC_READINESS,
    );
    const voidAdapterReadiness = voidAdapterProvider && "useValue" in voidAdapterProvider
      ? voidAdapterProvider.useValue as () => Promise<boolean>
      : undefined;
    await expect(voidAdapterReadiness?.()).resolves.toBe(false);
  });

  it("includes dynamic client store validation in readiness", async () => {
    const { auth, users, config } = createOauthApplication();
    const validate = vi.fn(async () => true);
    const adapter = () => ({
      find: async () => undefined,
      upsert: async () => undefined,
      destroy: async () => undefined,
    });
    const module = GetbrickOidcModule.forRoot({
      auth,
      config,
      findUser: async (id) => users.get(id) ?? null,
      adapter: adapter as never,
      clientStore: {
        find: async () => undefined,
        validate,
      },
    });
    const provider = module.providers?.find(
      (value) => "provide" in value && value.provide === GETBRICK_OIDC_READINESS,
    );
    const readiness = provider && "useValue" in provider
      ? provider.useValue as () => Promise<boolean>
      : undefined;

    expect(readiness).toBeTypeOf("function");
    await expect(readiness?.()).resolves.toBe(true);
    expect(validate).toHaveBeenCalledTimes(1);
  });

  it("passes V2 consent store and claim policy options into the provider", () => {
    const { auth, users, config } = createOauthApplication();
    const store = { findActive: async () => null } as never;
    const module = GetbrickOidcModule.forRoot({
      auth,
      config,
      findUser: async (id) => users.get(id) ?? null,
      hostConsentGrantStore: store,
      tenantId: "tenant-options",
      applicationId: "application-options",
      claimPolicy: { policyVersion: "policy-options" },
    });
    const runtime = module.providers?.find(
      (value) => "provide" in value && value.provide === GETBRICK_OIDC_RUNTIME,
    );
    const value = runtime && "useValue" in runtime ? runtime.useValue as { consentGrantStore?: unknown; claimPolicy?: { policyVersion?: string } } : undefined;
    expect(value?.consentGrantStore).toBe(store);
    expect(value?.claimPolicy?.policyVersion).toBe("policy-options");
  });

  it("fails closed when production logout ports are missing", () => {
    const adapter = Object.assign(
      () => ({ find: async () => undefined, upsert: async () => undefined, destroy: async () => undefined }),
      { ready: async () => true },
    );
    expect(() =>
      GetbrickOidcModule.forRoot({
        auth: { options: { secret: "s".repeat(32) }, api: { getSession: async () => null }, handler: async () => new Response("ok") },
        config: {
          profile: "production",
          baseURL: "https://auth.example.com",
          secret: "s".repeat(32),
          trustedOrigins: ["https://app.example.com"],
          registration: { publicSignUp: false, requireEmailVerification: true },
          oidc: {
            op: {
              enabled: true,
              issuer: "https://id.example.com/oidc",
              basePath: "/oidc",
              clients: [{
                clientId: "client",
                redirectUris: ["https://app.example.com/callback"],
                postLogoutRedirectUris: ["https://app.example.com/logout"],
              }],
            },
          },
        },
        findUser: async () => null,
        adapter: adapter as never,
        jwks: { keys: [{}] } as never,
        cookieKeys: ["s".repeat(32)],
      }),
    ).toThrow(/logout session and grant revocation ports/i);
  });

  it("fails closed when production revocation readiness is missing", () => {
    const adapter = Object.assign(
      () => ({ find: async () => undefined, upsert: async () => undefined, destroy: async () => undefined }),
      { ready: async () => true },
    );
    const persistence = {
      ready: async () => true,
      load: async () => undefined,
      save: async () => undefined,
      delete: async () => undefined,
    };
    expect(() =>
      GetbrickOidcModule.forRoot({
        auth: { options: { secret: "s".repeat(32) }, api: { getSession: async () => null }, handler: async () => new Response("ok") },
        config: {
          profile: "production",
          baseURL: "https://auth.example.com",
          secret: "s".repeat(32),
          trustedOrigins: ["https://app.example.com"],
          registration: { publicSignUp: false, requireEmailVerification: true },
          oidc: {
            op: {
              enabled: true,
              issuer: "https://id.example.com/oidc",
              basePath: "/oidc",
              clients: [{ clientId: "client", redirectUris: ["https://app.example.com/callback"] }],
            },
          },
        },
        findUser: async () => null,
        adapter: adapter as never,
        jwks: { keys: [{}] } as never,
        cookieKeys: ["s".repeat(32)],
        sessionRevocationPort: { revoke: async () => [] },
        grantRevocationPort: { revoke: async () => [] },
        logoutPersistence: persistence,
      }),
    ).toThrow(/ready revocation/i);
  });

  it("fails closed when production logout persistence is missing", () => {
    const adapter = Object.assign(
      () => ({ find: async () => undefined, upsert: async () => undefined, destroy: async () => undefined }),
      { ready: async () => true },
    );
    expect(() =>
      GetbrickOidcModule.forRoot({
        auth: { options: { secret: "s".repeat(32) }, api: { getSession: async () => null }, handler: async () => new Response("ok") },
        config: {
          profile: "production",
          baseURL: "https://auth.example.com",
          secret: "s".repeat(32),
          trustedOrigins: ["https://app.example.com"],
          registration: { publicSignUp: false, requireEmailVerification: true },
          oidc: {
            op: {
              enabled: true,
              issuer: "https://id.example.com/oidc",
              basePath: "/oidc",
              clients: [{
                clientId: "client",
                redirectUris: ["https://app.example.com/callback"],
                postLogoutRedirectUris: ["https://app.example.com/logout"],
              }],
            },
          },
        },
        findUser: async () => null,
        adapter: adapter as never,
        jwks: { keys: [{}] } as never,
        cookieKeys: ["s".repeat(32)],
        sessionRevocationPort: { revoke: async () => [] },
        grantRevocationPort: { revoke: async () => [] },
      }),
    ).toThrow(/ready persistent logout coordinator/i);
  });

  it("fails closed when production persistence readiness is missing", () => {
    const adapter = Object.assign(
      () => ({ find: async () => undefined, upsert: async () => undefined, destroy: async () => undefined }),
      { ready: async () => true },
    );
    const persistence = {
      load: async () => undefined,
      save: async () => undefined,
      delete: async () => undefined,
    };
    expect(() =>
      GetbrickOidcModule.forRoot({
        auth: { options: { secret: "s".repeat(32) }, api: { getSession: async () => null }, handler: async () => new Response("ok") },
        config: {
          profile: "production",
          baseURL: "https://auth.example.com",
          secret: "s".repeat(32),
          trustedOrigins: ["https://app.example.com"],
          registration: { publicSignUp: false, requireEmailVerification: true },
          oidc: {
            op: {
              enabled: true,
              issuer: "https://id.example.com/oidc",
              basePath: "/oidc",
              clients: [{ clientId: "client", redirectUris: ["https://app.example.com/callback"] }],
            },
          },
        },
        findUser: async () => null,
        adapter: adapter as never,
        jwks: { keys: [{}] } as never,
        cookieKeys: ["s".repeat(32)],
        sessionRevocationPort: { ready: async () => true, revoke: async () => [] },
        grantRevocationPort: { ready: async () => true, revoke: async () => [] },
        logoutPersistence: persistence as never,
      }),
    ).toThrow(/persistence readiness/i);
  });

  it("fails closed when a custom production coordinator lacks persistence", () => {
    const adapter = Object.assign(
      () => ({ find: async () => undefined, upsert: async () => undefined, destroy: async () => undefined }),
      { ready: async () => true },
    );
    expect(() =>
      GetbrickOidcModule.forRoot({
        auth: { options: { secret: "s".repeat(32) }, api: { getSession: async () => null }, handler: async () => new Response("ok") },
        config: {
          profile: "production",
          baseURL: "https://auth.example.com",
          secret: "s".repeat(32),
          trustedOrigins: ["https://app.example.com"],
          registration: { publicSignUp: false, requireEmailVerification: true },
          oidc: {
            op: {
              enabled: true,
              issuer: "https://id.example.com/oidc",
              basePath: "/oidc",
              clients: [{ clientId: "client", redirectUris: ["https://app.example.com/callback"] }],
            },
          },
        },
        findUser: async () => null,
        adapter: adapter as never,
        jwks: { keys: [{}] } as never,
        cookieKeys: ["s".repeat(32)],
        logoutCoordinator: {
          ready: async () => true,
          prepare: async () => { throw new Error("not called"); },
          complete: async () => { throw new Error("not called"); },
        } as never,
      }),
    ).toThrow(/ready persistent logout coordinator/i);
  });

  it("rejects an OIDC provider mounted at the application root", () => {
    expect(() =>
      GetbrickOidcModule.forRoot({
        auth: { options: {}, api: { getSession: async () => null }, handler: async () => new Response("ok") },
        config: {
          profile: "production",
          baseURL: "https://auth.example.com",
          secret: "s".repeat(32),
          trustedOrigins: ["https://app.example.com"],
          registration: { publicSignUp: false, requireEmailVerification: true },
          oidc: {
            op: {
              enabled: true,
              issuer: "https://id.example.com",
              basePath: "/",
              clients: [{ clientId: "client", redirectUris: ["https://app.example.com/callback"] }],
            },
          },
        },
        findUser: async () => null,
      }),
    ).toThrow(/application root/i);
  });

  it("applies only the V2-approved scope and claim subset in the authorization chain", async () => {
    const { auth, users } = createOauthApplication();
    let consentContext: OidcConsentContext | undefined;
    const resolver: OidcConsentResolverV2 = async (context) => {
      consentContext = context;
      return {
        decision: "approved",
        consentId: context.consentId,
        approvedScopes: ["openid"],
        approvedClaims: [],
        policyVersion: context.policyVersion,
        userGesture: true,
      };
    };
    const moduleRef = await Test.createTestingModule({
      imports: [OidcTestModule.forRoot(auth, users, {
        resolver,
        tenantId: "tenant-v2",
        applicationId: "application-v2",
        claimPolicy: {
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
        },
      })],
    }).compile();
    const app = moduleRef.createNestApplication();
    await app.init();
    const server = app.getHttpServer();
    const agent = request.agent(server);
    const signUp = await agent
      .post("/api/auth/sign-up/email")
      .set("Host", "localhost")
      .send({ email: "v2@example.com", password: "supersecret123", name: "V2 User" });
    expect(signUp.status).toBe(200);
    const userId = String(signUp.body.user.id);
    users.set(userId, { id: userId, name: "V2 User", email: "v2@example.com", claims: { role: "admin" } });
    const verifier = "b".repeat(64);
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const authorization = await agent
      .get("/oidc/auth")
      .set("Host", "localhost")
      .query({
        client_id: "client",
        redirect_uri: "http://client.example/callback",
        response_type: "code",
        scope: "openid profile email offline_access",
         claims: JSON.stringify({ userinfo: { role: null } }),
        prompt: "consent",
        state: "v2-state",
        nonce: "v2-nonce",
        code_challenge: challenge,
        code_challenge_method: "S256",
      });
    expect(authorization.status).toBe(303);
    let nextUrl = new URL(String(authorization.headers.location), "http://localhost");
    let callback: Awaited<ReturnType<typeof agent.get>> | undefined;
    for (let step = 0; step < 6; step += 1) {
       const response = await agent.get(`${nextUrl.pathname}${nextUrl.search}`).set("Host", "localhost");
       expect(response.status).toBe(303);
       const location = new URL(String(response.headers.location), "http://localhost");
      if (location.origin + location.pathname === "http://client.example/callback") {
        callback = response;
        break;
      }
      nextUrl = location;
    }
    expect(callback).toBeTruthy();
    const callbackUrl = new URL(String(callback!.headers.location), "http://localhost");
    const code = callbackUrl.searchParams.get("code");
    expect(code).toBeTruthy();
    const token = await agent
      .post("/oidc/token")
      .set("Host", "localhost")
      .type("form")
      .send({
        grant_type: "authorization_code",
        code,
        redirect_uri: "http://client.example/callback",
        client_id: "client",
        client_secret: "client-secret",
        code_verifier: verifier,
      });
    expect(token.status).toBe(200);
    expect(token.body.scope).toBe("openid");
    const payload = JSON.parse(Buffer.from(String(token.body.id_token).split(".")[1] ?? "", "base64url").toString("utf8")) as Record<string, unknown>;
    expect(payload).toMatchObject({ sub: userId, nonce: "v2-nonce" });
    expect(payload).not.toHaveProperty("email");
    expect(payload).not.toHaveProperty("role");
    const userInfo = await agent
      .get("/oidc/me")
      .set("Host", "localhost")
      .set("Authorization", `Bearer ${token.body.access_token}`);
    expect(userInfo.status).toBe(200);
    expect(userInfo.body).toMatchObject({ sub: userId });
    expect(userInfo.body).not.toHaveProperty("email");
    expect(userInfo.body).not.toHaveProperty("role");
    expect(consentContext).toMatchObject({
      tenantId: "tenant-v2",
      applicationId: "application-v2",
      clientId: "client",
      userId,
      requestedScopes: ["openid", "profile", "email", "offline_access"],
       requestedClaims: ["role"],
      policyVersion: "policy-v2",
    });
    expect(consentContext?.consentId).toBeTruthy();
    expect(consentContext?.grantId).toBeTruthy();
    expect(consentContext?.interactionId).toBe(consentContext?.consentId);
    await app.close();
  });

  it("serves discovery, JWKS and an authorization code flow", async () => {
    const { auth, users } = createOauthApplication();
    const moduleRef = await Test.createTestingModule({
      imports: [OidcTestModule.forRoot(auth, users)],
    }).compile();
    const app = moduleRef.createNestApplication();
    app.use(express.json());
    await app.init();
    const server = app.getHttpServer();
    const agent = request.agent(server);

    const signUp = await agent
      .post("/api/auth/sign-up/email")
      .set("Host", "localhost")
      .send({ email: "oidc@example.com", password: "supersecret123", name: "OIDC User" });
    expect(signUp.status).toBe(200);
    const userId = String(signUp.body.user.id);
    users.set(userId, {
      id: userId,
      name: "OIDC User",
      email: "oidc@example.com",
      emailVerified: false,
    });

    const discovery = await agent
      .get("/oidc/.well-known/openid-configuration")
      .set("Host", "localhost");
    expect(discovery.status).toBe(200);
    expect(discovery.body.issuer).toBe("http://localhost/oidc");
    expect(discovery.body.authorization_endpoint).toBe("http://localhost/oidc/auth");
    expect(discovery.body.token_endpoint).toBe("http://localhost/oidc/token");
    const metadataAlias = await agent
      .get("/.well-known/oauth-authorization-server")
      .set("Host", "localhost");
    expect(metadataAlias.status).toBe(200);
    expect(metadataAlias.body.issuer).toBe("http://localhost/oidc");

    const jwks = await agent.get("/oidc/jwks").set("Host", "localhost");
    expect(jwks.status).toBe(200);
    expect(jwks.body.keys.length).toBeGreaterThan(0);

    const verifier = "a".repeat(64);
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const authorization = await agent
      .get("/oidc/auth")
      .set("Host", "localhost")
      .query({
        client_id: "client",
        redirect_uri: "http://client.example/callback",
        response_type: "code",
        scope: "openid profile email offline_access",
        prompt: "consent",
        state: "state-value",
        nonce: "nonce-value",
        code_challenge: challenge,
        code_challenge_method: "S256",
      });
    expect(authorization.status).toBe(303);
    const interactionUrl = new URL(String(authorization.headers.location), "http://localhost");
    expect(interactionUrl.pathname).toMatch(/^\/oidc\/interaction\//u);

    let nextUrl = interactionUrl;
    let callback: Awaited<ReturnType<typeof agent.get>> | undefined;
    for (let step = 0; step < 6; step += 1) {
      const response = await agent
        .get(`${nextUrl.pathname}${nextUrl.search}`)
        .set("Host", "localhost");
      expect(response.status).toBe(303);
      const location = new URL(String(response.headers.location), "http://localhost");
      if (location.origin + location.pathname === "http://client.example/callback") {
        callback = response;
        break;
      }
      nextUrl = location;
    }
    expect(callback).toBeTruthy();
    const callbackUrl = new URL(String(callback!.headers.location), "http://localhost");
    expect(callbackUrl.origin + callbackUrl.pathname).toBe("http://client.example/callback");
    expect(callbackUrl.searchParams.get("state")).toBe("state-value");
    const code = callbackUrl.searchParams.get("code");
    expect(code).toBeTruthy();

    const token = await agent
      .post("/oidc/token")
      .set("Host", "localhost")
      .type("form")
      .send({
        grant_type: "authorization_code",
        code,
        redirect_uri: "http://client.example/callback",
        client_id: "client",
        client_secret: "client-secret",
        code_verifier: verifier,
      });
    expect(token.status).toBe(200);
    expect(token.body.token_type).toBe("Bearer");
    expect(token.body.access_token).toBeTruthy();
    expect(token.body.id_token).toBeTruthy();
    const payload = JSON.parse(
      Buffer.from(String(token.body.id_token).split(".")[1] ?? "", "base64url").toString("utf8"),
    ) as Record<string, unknown>;
    expect(payload.sub).toBe(userId);
    expect(payload.nonce).toBe("nonce-value");
    expect(token.body.refresh_token).toBeTruthy();

    const refreshed = await agent
      .post("/oidc/token")
      .set("Host", "localhost")
      .type("form")
      .send({
        grant_type: "refresh_token",
        refresh_token: token.body.refresh_token,
        client_id: "client",
        client_secret: "client-secret",
      });
    expect(refreshed.status).toBe(200);
    expect(refreshed.body.access_token).toBeTruthy();

    const userInfo = await agent
      .get("/oidc/me")
      .set("Host", "localhost")
      .set("Authorization", `Bearer ${refreshed.body.access_token}`);
    expect(userInfo.status).toBe(200);
    expect(userInfo.body.sub).toBe(userId);
    expect(userInfo.body.email).toBe("oidc@example.com");

    const reusedRefresh = await agent
      .post("/oidc/token")
      .set("Host", "localhost")
      .type("form")
      .send({
        grant_type: "refresh_token",
        refresh_token: token.body.refresh_token,
        client_id: "client",
        client_secret: "client-secret",
      });
    expect(reusedRefresh.status).toBe(400);
    expect(reusedRefresh.body.error).toBe("invalid_grant");

    const revoke = await agent
      .post("/oidc/token/revocation")
      .set("Host", "localhost")
      .type("form")
      .send({
        token: refreshed.body.access_token,
        client_id: "client",
        client_secret: "client-secret",
      });
    expect(revoke.status).toBe(200);

    const replay = await agent
      .post("/oidc/token")
      .set("Host", "localhost")
      .type("form")
      .send({
        grant_type: "authorization_code",
        code,
        redirect_uri: "http://client.example/callback",
        client_id: "client",
        client_secret: "client-secret",
        code_verifier: verifier,
      });
    expect(replay.status).toBe(400);
    expect(replay.body.error).toBe("invalid_grant");

    const invalidRedirect = await agent
      .get("/oidc/session/end")
      .set("Host", "localhost")
      .query({
        client_id: "client",
        id_token_hint: token.body.id_token,
        post_logout_redirect_uri: "https://attacker.example/callback",
      });
    expect(invalidRedirect.status).toBe(400);
    const sessionAfterInvalidRedirect = await agent
      .get("/api/auth/get-session")
      .set("Host", "localhost");
    expect(sessionAfterInvalidRedirect.body?.user ?? null).not.toBeNull();

    const forgedHint = `${Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url")}.${Buffer.from(JSON.stringify({ aud: "client" })).toString("base64url")}.forged`;
    const forgedLogout = await agent
      .get("/oidc/session/end")
      .set("Host", "localhost")
      .query({
        id_token_hint: forgedHint,
        post_logout_redirect_uri: "http://client.example/callback",
      });
    expect([400, 500]).toContain(forgedLogout.status);
    const sessionAfterForgedHint = await agent
      .get("/api/auth/get-session")
      .set("Host", "localhost");
    expect(sessionAfterForgedHint.body?.user ?? null).not.toBeNull();

    const logout = await agent
      .get("/oidc/session/end")
      .set("Host", "localhost")
      .query({
        id_token_hint: token.body.id_token,
        post_logout_redirect_uri: "http://client.example/callback",
      });
    expect(logout.status).toBe(200);
    const form = /action="([^"]+)"[^>]*>[\s\S]*?name="xsrf" value="([^"]+)"/u.exec(String(logout.text));
    expect(form).toBeTruthy();
    const confirmUrl = new URL(form?.[1] ?? "", "http://localhost");
    const confirmed = await agent
      .post(`${confirmUrl.pathname}${confirmUrl.search}`)
      .set("Host", "localhost")
      .type("form")
      .send({ xsrf: form?.[2], logout: "yes" });
    expect(confirmed.status).toBe(303);
    expect(String(confirmed.headers.location)).toContain("http://client.example/callback");
    const cookies = confirmed.headers["set-cookie"] as unknown as string[] | undefined;
    expect(cookies?.some((cookie) => cookie.includes("better-auth") || cookie.includes("session_token"))).toBe(true);
    const sessionAfterLogout = await agent
      .get("/api/auth/get-session")
      .set("Host", "localhost");
    expect(sessionAfterLogout.body?.user ?? null).toBeNull();

    const repeated = await agent
      .get("/oidc/session/end")
      .set("Host", "localhost")
      .query({
        client_id: "client",
        post_logout_redirect_uri: "http://client.example/callback",
      });
    expect([200, 303, 400, 500]).toContain(repeated.status);

    await app.close();
  });
});
