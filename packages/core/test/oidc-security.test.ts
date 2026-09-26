import { createServer } from "node:http";
import { SignJWT, generateKeyPair, exportJWK } from "jose";
import { describe, expect, expectTypeOf, it } from "vitest";
import {
  assertExactOidcRedirectUri,
  createDynamicOidcClientAdapter,
  createOidcProvider,
  createOidcProviderEndpointResolver,
  defineIdaasConfig,
  isSafeOidcRedirectUri,
  isSafeOidcUrl,
  isRfc8252PrivateUseRedirectUri,
  isExactOidcRedirectUri,
  createOidcConsentContext,
  createOidcConsentResolverV2,
  hashOidcConsentValues,
  isOidcProtocolReservedClaim,
  normalizeOidcClaimPolicy,
  OIDC_LEGACY_CONSENT_RESOLVER_SEMANTICS,
  normalizeOidcConsentPolicy,
  projectOidcClaims,
  requiresExplicitOidcConsent,
  resolveOidcConsentDecision,
  resolveOidcConsentDecisionV2,
  resolveLegacyOidcConsentDecision,
  resolveOidcHostGrant,
  toDynamicOidcClientPayload,
  validateOidcConsentDecision,
  type OidcClaimsResolverContext,
  type OidcConsentContext,
  type OidcHostGrant,
  validateOidcClientJwks,
} from "../src/index.js";

async function publicKey(kid: string) {
  const { publicKey: key } = await generateKeyPair("RS256");
  const jwk = await exportJWK(key);
  return { ...jwk, kid, alg: "RS256", use: "sig" };
}

describe("OIDC security policies", () => {
  it("allows only authority-free reverse-domain schemes for native public PKCE clients", () => {
    const nativePublic = {
      applicationType: "native" as const,
      tokenEndpointAuthMethod: "none",
      requirePkce: true,
    };
    expect(isRfc8252PrivateUseRedirectUri("com.example.app:/oauth2redirect")).toBe(true);
    expect(isSafeOidcRedirectUri("com.example.app:/oauth2redirect", nativePublic)).toBe(true);
    expect(isSafeOidcRedirectUri("com.example.app://callback", nativePublic)).toBe(false);
    expect(isSafeOidcRedirectUri("com.example.app:callback", nativePublic)).toBe(false);
    expect(isSafeOidcRedirectUri("com.example.app:/oauth2redirect", {
      ...nativePublic,
      tokenEndpointAuthMethod: "private_key_jwt",
    })).toBe(false);
    expect(isSafeOidcRedirectUri("com.example.app:/oauth2redirect", {
      ...nativePublic,
      applicationType: "web",
    })).toBe(false);
    expect(isSafeOidcRedirectUri("https://client.example/callback", {
      ...nativePublic,
      applicationType: "web",
    })).toBe(true);
  });

  it("keeps webview PKCE-bound and compares redirect registrations exactly", () => {
    expect(() => defineIdaasConfig({
      oidc: {
        op: {
          enabled: true,
          issuer: "https://id.example.test/oidc",
          clients: [{
            clientId: "webview-no-pkce",
            applicationType: "webview",
            tokenEndpointAuthMethod: "none",
            requirePkce: false as never,
            redirectUris: ["https://client.example.test/callback"],
          }],
        },
      },
    })).toThrow();
    const payload = toDynamicOidcClientPayload({
      client_id: "webview",
      application_type: "webview",
      token_endpoint_auth_method: "none",
      redirect_uris: ["https://client.example.test/callback"],
      grant_types: ["authorization_code"],
      response_types: ["code"],
      scope: "openid",
    });
    expect(payload).toMatchObject({ application_type: "web", "getbrick:require_pkce": true, "getbrick:client_kind": "webview" });
    expect(assertExactOidcRedirectUri("https://client.example.test/callback", "https://client.example.test/callback")).toBe("https://client.example.test/callback");
    expect(() => assertExactOidcRedirectUri("https://client.example.test/callback", "https://client.example.test/callback/")).toThrow();
    expect(isExactOidcRedirectUri("https://client.example.test/%2f", "https://client.example.test/%2F")).toBe(false);
  });
  it("rejects encoded control characters and malformed redirect URLs", () => {
    const webClient = {
      applicationType: "web" as const,
      tokenEndpointAuthMethod: "client_secret_basic",
      requirePkce: true,
    };
    expect(isSafeOidcRedirectUri("https://client.example/callback/%0d%0aX", webClient)).toBe(false);
    expect(isSafeOidcRedirectUri("https://client.example/callback/%255cX", webClient)).toBe(false);
    expect(isSafeOidcRedirectUri("https://client.example/callback/%25", webClient)).toBe(true);
    expect(isSafeOidcRedirectUri("https:///callback", webClient)).toBe(false);
    expect(isSafeOidcUrl("https://client.example/callback/%0d%0aX", true)).toBe(false);
    expect(isSafeOidcUrl("https://client.example/callback/%25", true)).toBe(true);
  });
  it("accepts a query-bearing private_key_jwt JWKS URI", () => {
    expect(defineIdaasConfig({
      oidc: {
        op: {
          enabled: true,
          issuer: "https://id.example.test/oidc",
          clients: [{
            clientId: "query-jwks",
            tokenEndpointAuthMethod: "private_key_jwt",
            redirectUris: ["https://client.example.test/callback"],
            jwksUri: "https://client.example.test/jwks?version=2",
          }],
        },
      },
    }).oidc.op.clients[0]?.jwksUri).toBe("https://client.example.test/jwks?version=2");
  });

  it("retains old and new public client keys for private_key_jwt", async () => {
    const first = await publicKey("client-old");
    const second = await publicKey("client-new");
    const jwks = { keys: [first, second] };
    expect(validateOidcClientJwks(jwks, { algorithm: "RS256" }).keys).toHaveLength(2);
    const payload = toDynamicOidcClientPayload({
      client_id: "managed",
      application_type: "web",
      redirect_uris: ["https://client.example/callback"],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      scope: "openid profile offline_access",
      token_endpoint_auth_method: "private_key_jwt",
      client_secret: "legacy-secret-from-store",
      jwks,
    });
    expect(payload).toMatchObject({
      application_type: "web",
      token_endpoint_auth_method: "private_key_jwt",
      token_endpoint_auth_signing_alg: "RS256",
      jwks: { keys: [{ kid: "client-old" }, { kid: "client-new" }] },
    });
    expect(payload).not.toHaveProperty("client_secret");
  });

  it("loads private_key_jwt clients without a secret and preserves both keys", async () => {
    const config = defineIdaasConfig({
      oidc: {
        op: {
          enabled: true,
          issuer: "https://id.example.test/oidc",
          basePath: "/oidc",
          clients: [{
            clientId: "managed",
            applicationType: "web",
            tokenEndpointAuthMethod: "private_key_jwt",
            redirectUris: ["https://client.example/callback"],
            jwks: { keys: [await publicKey("old"), await publicKey("new")] },
          }],
        },
      },
    });
    const runtime = createOidcProvider({
      config: config.oidc.op,
      findUser: async () => null,
      cookieKeys: ["a".repeat(32)],
    });
    const client = await runtime.provider.Client.find("managed");
    expect(client?.clientAuthMethod).toBe("private_key_jwt");
    expect(client?.applicationType).toBe("web");
    const keyStore = (client as unknown as { asymmetricKeyStore: Iterable<{ kid?: string }> }).asymmetricKeyStore;
    expect([...keyStore].map((key) => key.kid)).toEqual(["old", "new"]);
  });

  it("enriches a managed store client with an external rotating JWKS", async () => {
    const jwks = { keys: [await publicKey("old"), await publicKey("new")] };
    const baseAdapter = (() => ({
      find: async () => undefined,
      upsert: async () => undefined,
      destroy: async () => undefined,
    })) as never;
    const adapter = createDynamicOidcClientAdapter(baseAdapter, {
      find: async (clientId) => clientId === "managed" ? {
        client_id: "managed",
        client_secret: "legacy-store-secret",
        application_type: "web",
        redirect_uris: ["https://client.example/callback"],
        grant_types: ["authorization_code"],
        response_types: ["code"],
        scope: "openid profile",
        token_endpoint_auth_method: "private_key_jwt",
      } : undefined,
    }, { clientJwks: { managed: jwks } });
    const config = defineIdaasConfig({
      oidc: {
        op: {
          enabled: true,
          dynamicClients: true,
          issuer: "https://id.example.test/oidc",
          basePath: "/oidc",
        },
      },
    });
    const runtime = createOidcProvider({
      config: config.oidc.op,
      dynamicClients: true,
      adapter,
      findUser: async () => null,
      cookieKeys: ["a".repeat(32)],
    });
    const client = await runtime.provider.Client.find("managed");
    expect(client?.clientAuthMethod).toBe("private_key_jwt");
    expect(client?.metadata().client_secret).toBeUndefined();
    const keyStore = (client as unknown as { asymmetricKeyStore: Iterable<{ kid?: string }> }).asymmetricKeyStore;
    expect([...keyStore].map((key) => key.kid)).toEqual(["old", "new"]);
  });

  it("authenticates a private_key_jwt client assertion at the token endpoint", async () => {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const publicJwk = await exportJWK(publicKey);
    Object.assign(publicJwk, { kid: "managed-key", alg: "RS256", use: "sig" });
    let runtime: ReturnType<typeof createOidcProvider> | undefined;
    const server = createServer((req, res) => {
      if (!runtime) {
        res.statusCode = 503;
        res.end();
        return;
      }
      runtime.provider.callback()(req, res);
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("test server did not bind");
    const origin = `http://127.0.0.1:${address.port}`;
    const config = defineIdaasConfig({
      oidc: {
        op: {
          enabled: true,
          issuer: `${origin}/oidc`,
          basePath: "/oidc",
          clients: [{
            clientId: "managed",
            applicationType: "web",
            tokenEndpointAuthMethod: "private_key_jwt",
            redirectUris: ["https://client.example/callback"],
            jwks: { keys: [publicJwk] },
          }],
        },
      },
    });
    runtime = createOidcProvider({
      config: config.oidc.op,
      findUser: async () => null,
      cookieKeys: ["a".repeat(32)],
    });
    const assertion = await new SignJWT({})
      .setProtectedHeader({ alg: "RS256", kid: "managed-key" })
      .setIssuer("managed")
      .setSubject("managed")
      .setAudience(`${origin}/oidc`)
      .setJti("assertion-1")
      .setIssuedAt()
      .setExpirationTime("1m")
      .sign(privateKey);
    const response = await fetch(`${origin}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: "missing",
        redirect_uri: "https://client.example/callback",
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: assertion,
      }),
    });
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_grant" });
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  });

  it("authenticates private_key_jwt assertions with every supported algorithm", async () => {
    for (const algorithm of ["RS256", "PS256", "ES256", "EdDSA"] as const) {
      const { privateKey, publicKey } = await generateKeyPair(algorithm);
      const publicJwk = await exportJWK(publicKey);
      Object.assign(publicJwk, { kid: `managed-${algorithm}`, alg: algorithm, use: "sig" });
      let runtime: ReturnType<typeof createOidcProvider> | undefined;
      const server = createServer((req, res) => {
        if (!runtime) {
          res.statusCode = 503;
          res.end();
          return;
        }
        runtime.provider.callback()(req, res);
      });
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("test server did not bind");
      const origin = `http://127.0.0.1:${address.port}`;
      const config = defineIdaasConfig({
        oidc: {
          op: {
            enabled: true,
            issuer: `${origin}/oidc`,
            basePath: "/oidc",
            clients: [{
              clientId: `managed-${algorithm}`,
              applicationType: "web",
              tokenEndpointAuthMethod: "private_key_jwt",
              tokenEndpointAuthSigningAlg: algorithm,
              redirectUris: ["https://client.example/callback"],
              jwks: { keys: [publicJwk] },
            }],
          },
        },
      });
      runtime = createOidcProvider({
        config: config.oidc.op,
        findUser: async () => null,
        cookieKeys: ["a".repeat(32)],
      });
      const assertion = await new SignJWT({})
        .setProtectedHeader({ alg: algorithm, kid: `managed-${algorithm}` })
        .setIssuer(`managed-${algorithm}`)
        .setSubject(`managed-${algorithm}`)
        .setAudience(`${origin}/oidc`)
        .setJti(`assertion-${algorithm}`)
        .setIssuedAt()
        .setExpirationTime("1m")
        .sign(privateKey);
      const response = await fetch(`${origin}/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: "missing",
          redirect_uri: "https://client.example/callback",
          client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          client_assertion: assertion,
        }),
      });
      expect(response.status).toBe(400);
      expect(await response.json()).toMatchObject({ error: "invalid_grant" });
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    }
  });
  it("makes sensitive-scope consent explicit by default", () => {
    const policy = normalizeOidcConsentPolicy({ sensitiveScopes: ["offline_access", "reports"] });
    expect(requiresExplicitOidcConsent(["openid", "offline_access"], policy)).toBe(true);
    expect(requiresExplicitOidcConsent(["openid", "profile"], policy)).toBe(false);
    expect(requiresExplicitOidcConsent(["openid"], policy, true)).toBe(true);
    expect(normalizeOidcConsentPolicy({ requireExplicitConsent: false }).requireExplicitConsent).toBe(false);
  });

  it("validates V2 consent as an exact requested subset and fails closed", () => {
    const context: OidcConsentContext = createOidcConsentContext({
      consentId: "consent-1",
      tenantId: "tenant-1",
      applicationId: "application-1",
      clientId: "client-1",
      userId: "user-1",
      grantId: "grant-1",
      interactionId: "interaction-1",
      requestedScopes: ["openid", "email"],
      requestedClaims: ["email", "role"],
      policyVersion: "policy-v2",
    });
    const decision = {
      decision: "approved" as const,
      consentId: context.consentId,
      approvedScopes: ["openid"],
      approvedClaims: ["email"],
      policyVersion: context.policyVersion,
      userGesture: true as const,
    };
    const policy = normalizeOidcClaimPolicy({
      policyVersion: context.policyVersion,
      definitions: [{
        name: "role",
        scopes: ["openid"],
        clients: ["client-1"],
        source: "membership" as const,
        required: false,
        sensitive: true,
        version: "1",
      }],
    });
    expect(validateOidcConsentDecision(context, decision, policy)).toMatchObject(decision);
    expect(() => validateOidcConsentDecision(context, { ...decision, approvedScopes: ["profile"] }, policy)).toThrow(/subset|scope/i);
    expect(() => validateOidcConsentDecision(context, { ...decision, approvedClaims: ["unknown"] }, policy)).toThrow(/subset|claim/i);
    expect(() => validateOidcConsentDecision(context, { ...decision, policyVersion: "policy-v1" }, policy)).toThrow(/policyVersion/i);
    expect(() => validateOidcConsentDecision(context, { ...decision, consentId: "other" }, policy)).toThrow(/consentId/i);
    expect(resolveOidcConsentDecisionV2(context, { ...decision, userGesture: false }, policy)).toEqual({
      decision: "denied",
      reason: "policy_denied",
    });
  });

  it("requires explicit, unexpired, exact host grant approvals in V2", async () => {
    const context = createOidcConsentContext({
      consentId: "consent-expiry",
      tenantId: "tenant-1",
      applicationId: "application-1",
      clientId: "client-1",
      userId: "user-1",
      grantId: "grant-1",
      interactionId: "interaction-1",
      requestedScopes: ["openid"],
      requestedClaims: [],
      policyVersion: "policy-v2",
    });
    expectTypeOf<OidcHostGrant["expiresAt"]>().toEqualTypeOf<string>();
    expectTypeOf<OidcHostGrant["approvedScopes"]>().toEqualTypeOf<readonly string[]>();
    expectTypeOf<OidcHostGrant["approvedClaims"]>().toEqualTypeOf<readonly string[]>();
    const grant = {
      contractVersion: 1 as const,
      consentId: context.consentId,
      tenantId: context.tenantId,
      applicationId: context.applicationId,
      clientId: context.clientId,
      userId: context.userId,
      scopeHash: hashOidcConsentValues(context.requestedScopes),
      claimHash: hashOidcConsentValues(context.requestedClaims),
      policyVersion: context.policyVersion,
      status: "active" as const,
      projectionStatus: "projected" as const,
      createdAt: "2026-01-01T00:00:00.000Z",
      expiresAt: "2026-01-03T00:00:00.000Z",
      approvedScopes: ["openid"],
      approvedClaims: [],
      userGesture: true as const,
    };
    const now = Date.parse("2026-01-02T00:00:00.000Z");
    await expect(resolveOidcHostGrant({ findActive: async () => grant }, context, now)).resolves.toMatchObject({ decision: "approved" });
    await expect(resolveOidcHostGrant({ findActive: async () => ({ ...grant, expiresAt: undefined }) }, context, now)).resolves.toBeNull();
    await expect(resolveOidcHostGrant({ findActive: async () => ({ ...grant, expiresAt: "2026-01-01T12:00:00.000Z" }) }, context, now)).resolves.toBeNull();
    await expect(resolveOidcHostGrant({ findActive: async () => ({ ...grant, expiresAt: new Date(now).toISOString() }) }, context, now)).resolves.toBeNull();
    await expect(resolveOidcHostGrant({ findActive: async () => ({ ...grant, expiresAt: "invalid" }) }, context, now)).resolves.toBeNull();
    await expect(resolveOidcHostGrant({ findActive: async () => ({ ...grant, revokedAt: "2026-01-01T12:00:00.000Z" }) }, context, now)).resolves.toBeNull();
    await expect(resolveOidcHostGrant({ findActive: async () => ({ ...grant, approvedScopes: undefined, approvedClaims: undefined, userGesture: undefined }) }, context, now)).resolves.toBeNull();
    await expect(resolveOidcHostGrant({ findActive: async () => ({ ...grant, legacy: true, approvedScopes: undefined, approvedClaims: undefined, userGesture: undefined }) }, context, now)).resolves.toBeNull();
    await expect(resolveOidcHostGrant({ findActive: async () => ({ ...grant, approvedScopes: undefined }) }, context, now)).resolves.toBeNull();
    await expect(resolveOidcHostGrant({ findActive: async () => ({ ...grant, approvedClaims: undefined }) }, context, now)).resolves.toBeNull();
    const strictResolver = createOidcConsentResolverV2({
      findActive: async () => ({ ...grant, approvedScopes: undefined, approvedClaims: undefined, userGesture: undefined }),
    });
    await expect(strictResolver(context)).resolves.toEqual({ decision: "denied", reason: "policy_denied" });
    await expect(resolveOidcHostGrant({ findActive: async () => ({ ...grant, projectionStatus: "pending" as const }) }, context, now)).resolves.toBeNull();
  });

  it("keeps legacy boolean consent separate from strict V2 host grants", async () => {
    const context = createOidcConsentContext({
      consentId: "consent-2",
      tenantId: "tenant-1",
      applicationId: "application-1",
      clientId: "client-1",
      userId: "user-1",
      grantId: "grant-2",
      interactionId: "interaction-2",
      requestedScopes: ["openid", "offline_access"],
      requestedClaims: ["email"],
    });
    const resolver = createOidcConsentResolverV2({
      resolve: async () => undefined,
    });
    await expect(resolver(context)).resolves.toEqual({ decision: "denied", reason: "policy_denied" });
    expect(OIDC_LEGACY_CONSENT_RESOLVER_SEMANTICS).toMatchObject({ mode: "legacy", legacy: true });
    expect(resolveLegacyOidcConsentDecision(true)).toBe(true);
    expect(resolveOidcConsentDecision({ approved: true })).toBe(true);
    expect(isOidcProtocolReservedClaim("sub")).toBe(true);
    expect(isOidcProtocolReservedClaim("iss")).toBe(true);
    expect(isOidcProtocolReservedClaim("aud")).toBe(true);
  });

  it("projects only requested allowlisted custom claims and preserves protocol claims", () => {
    const projected = projectOidcClaims({
      sub: "attacker",
      iss: "https://attacker.example",
      aud: ["attacker"],
      role: "admin",
      email: "user@example.com",
    }, {
      requestedClaims: ["role", "email"],
      allowlist: ["role", "email"],
    });
    expect(projected).toEqual({ role: "admin", email: "user@example.com" });
    expect(hashOidcConsentValues(["b", "a"])).toBe(hashOidcConsentValues(["a", "b"]));
  });

  it("passes a minimal allowlisted context to the provider claims resolver", async () => {
    let received: OidcClaimsResolverContext | undefined;
    const config = defineIdaasConfig({
      oidc: {
        op: {
          enabled: true,
          issuer: "https://id.example.test/oidc",
          basePath: "/oidc",
          clients: [{
            clientId: "claims-client",
            tokenEndpointAuthMethod: "none",
            redirectUris: ["https://client.example.test/callback"],
          }],
        },
      },
    }).oidc.op;
    const runtime = createOidcProvider({
      config,
      findUser: async (id) => ({ id, name: "User" }),
      cookieKeys: ["a".repeat(32)],
      claimPolicy: {
        definitions: [{
          name: "role",
          scopes: ["openid"],
          clients: ["claims-client"],
          source: "membership",
          required: false,
          sensitive: false,
          version: "1",
        }],
      },
      claimsResolver: async (context) => {
        received = context;
        return {
          role: "admin",
          sub: "attacker",
          iss: "https://attacker.example",
          unrequested: true,
        };
      },
    });
    const account = await runtime.provider.Account.findAccount({
      oidc: { client: { clientId: "claims-client" } },
    } as never, "user-1");
    const claims = await account?.claims("id_token", "openid", { role: null }, []);
    expect(claims).toMatchObject({ sub: "user-1", role: "admin" });
    expect(claims).not.toHaveProperty("iss");
    expect(claims).not.toHaveProperty("unrequested");
    expect(received).toMatchObject({
      userId: "user-1",
      clientId: "claims-client",
      requestedScopes: ["openid"],
      requestedClaims: ["role"],
      allowedClaims: ["role"],
    });
  });

  it("rejects custom schemes for web clients during config validation", () => {
    expect(() => defineIdaasConfig({
      oidc: {
        op: {
          enabled: true,
          issuer: "https://id.example.test/oidc",
          clients: [{
            clientId: "web",
            applicationType: "web",
            redirectUris: ["com.example.app:/callback"],
          }],
        },
      },
    })).toThrow(/redirect policy/i);
  });

  it("resolves explicit endpoints once into an immutable provider", async () => {
    const resolver = createOidcProviderEndpointResolver();
    const resolved = await resolver.resolve({
      providerId: "corp",
      issuer: "https://issuer.example.test/oidc",
      authorizationUrl: "https://issuer.example.test/authorize",
      tokenUrl: "https://issuer.example.test/token",
      userInfoUrl: "https://issuer.example.test/userinfo",
      jwksUri: "https://issuer.example.test/jwks",
      endSessionEndpoint: "https://issuer.example.test/logout",
      trustedEndpointOrigins: ["https://issuer.example.test"],
      allowInsecureHttp: false,
      allowedIdTokenAlgorithms: ["ES256"],
    });
    expect(resolved).toMatchObject({
      contractVersion: 1,
      issuer: "https://issuer.example.test/oidc",
      source: "explicit",
      endpoints: {
        authorization: "https://issuer.example.test/authorize",
        token: "https://issuer.example.test/token",
        userInfo: "https://issuer.example.test/userinfo",
        jwks: "https://issuer.example.test/jwks",
        endSession: "https://issuer.example.test/logout",
      },
      allowedIdTokenAlgorithms: ["ES256"],
    });
    expect(Object.isFrozen(resolved)).toBe(true);
    expect(Object.isFrozen(resolved.endpoints)).toBe(true);
    expect(Object.isFrozen(resolved.allowedIdTokenAlgorithms)).toBe(true);
  });

  it("rejects unsupported explicit algorithms", async () => {
    const resolver = createOidcProviderEndpointResolver();
    await expect(resolver.resolve({
      providerId: "corp",
      issuer: "https://issuer.example.test",
      authorizationUrl: "https://issuer.example.test/authorize",
      tokenUrl: "https://issuer.example.test/token",
      userInfoUrl: "https://issuer.example.test/userinfo",
      jwksUri: "https://issuer.example.test/jwks",
      trustedEndpointOrigins: ["https://issuer.example.test"],
      allowInsecureHttp: false,
      allowedIdTokenAlgorithms: ["HS256" as never],
    })).rejects.toThrow(/algorithm/i);
  });

  it("bounds discovery time and response size", async () => {
    const base = {
      providerId: "corp",
      issuer: "https://issuer.example.test",
      discoveryUrl: "https://issuer.example.test/.well-known/openid-configuration",
      trustedEndpointOrigins: ["https://issuer.example.test"],
      allowInsecureHttp: false,
    };
    const timeoutResolver = createOidcProviderEndpointResolver({
      timeoutMs: 5,
      fetch: (async (_input, init) => new Promise<Response>((_, reject) => {
        init?.signal?.addEventListener("abort", () => reject(new Error("aborted")), { once: true });
      })) as typeof fetch,
    });
    await expect(timeoutResolver.resolve(base)).rejects.toThrow(/timed out/i);
    const sizeResolver = createOidcProviderEndpointResolver({
      maxResponseBytes: 32,
      fetch: (async () => new Response(JSON.stringify({
        issuer: "https://issuer.example.test",
        authorization_endpoint: "https://issuer.example.test/authorize",
        token_endpoint: "https://issuer.example.test/token",
        userinfo_endpoint: "https://issuer.example.test/userinfo",
        jwks_uri: "https://issuer.example.test/jwks",
        id_token_signing_alg_values_supported: ["RS256"],
      }), { headers: { "content-type": "application/json" } })) as typeof fetch,
    });
    await expect(sizeResolver.resolve(base)).rejects.toThrow(/too large/i);
  });

  it("rejects mixed endpoint sources and unsafe discovery responses", async () => {
    const base = {
      providerId: "corp",
      issuer: "https://issuer.example.test",
      trustedEndpointOrigins: ["https://issuer.example.test"],
      allowInsecureHttp: false,
    };
    const resolver = createOidcProviderEndpointResolver({
      fetch: (async () => new Response(JSON.stringify({
        issuer: "https://issuer.example.test",
        authorization_endpoint: "https://issuer.example.test/authorize",
        token_endpoint: "https://issuer.example.test/token",
        userinfo_endpoint: "https://issuer.example.test/userinfo",
        jwks_uri: "https://issuer.example.test/jwks",
        id_token_signing_alg_values_supported: ["RS256"],
      }), { headers: { "content-type": "application/json" } })) as typeof fetch,
    });
    await expect(resolver.resolve({
      ...base,
      discoveryUrl: "https://issuer.example.test/.well-known/openid-configuration",
      authorizationUrl: "https://issuer.example.test/authorize",
    })).rejects.toThrow(/discovery and explicit endpoints/i);
    await expect(resolver.resolve({
      ...base,
      discoveryUrl: "https://issuer.example.test/.well-known/openid-configuration",
    })).resolves.toMatchObject({ source: "discovery" });
    const unsafeResolver = createOidcProviderEndpointResolver({
      fetch: (async () => new Response("<html />", {
        headers: { "content-type": "text/html" },
      })) as typeof fetch,
    });
    await expect(unsafeResolver.resolve({
      ...base,
      discoveryUrl: "https://issuer.example.test/.well-known/openid-configuration",
    })).rejects.toThrow(/content type/i);
    const redirectResolver = createOidcProviderEndpointResolver({
      fetch: (async () => new Response(null, { status: 302 })) as typeof fetch,
    });
    await expect(redirectResolver.resolve({
      ...base,
      discoveryUrl: "https://issuer.example.test/.well-known/openid-configuration",
    })).rejects.toThrow(/redirected/i);
  });
});
