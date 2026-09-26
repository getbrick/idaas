import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  InMemoryOidcRevocationStore,
  OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES,
  OpenPlatformOidcAdapterNestModule,
  OpenPlatformOidcBearerVerifierAdapter,
  OpenPlatformOidcServiceClientVerifierAdapter,
  assertSafeOidcJwksEndpoint,
  createOidcJoseBearerJwtVerifier,
  createRemoteOidcJwksResolver,
  type OidcAdapterCredentialIdentity,
  type OidcBearerJwtVerifierPort,
  type OidcIdentityResolverPort,
  type OidcServiceClientJwtVerifierPort,
} from "../src/open-platform/runtime/adapters/oidc/index.js";

const initialNow = new Date("2030-01-01T00:00:00.000Z");
const nowSeconds = Math.floor(initialNow.getTime() / 1000);
const issuer = "https://issuer.example/oidc";
const tenantId = "tenant-oidc";
const applicationId = "app-oidc";
const clientId = "client-oidc";
const audience = "urn:getbrick:api:orders";
const assertionAudience = "https://issuer.example/oidc/token";
const bearerToken = "signed-bearer-token-value";
const serviceAssertion = "private-key-jwt-assertion-value";
const testPublicJwk = {
  ...generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ format: "jwk" }),
  kid: "key-1",
  alg: "RS256",
  use: "sig",
};

function bearerClaims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    iss: issuer,
    sub: "user-1",
    aud: audience,
    exp: nowSeconds + 300,
    nbf: nowSeconds - 1,
    iat: nowSeconds - 10,
    tenant_id: tenantId,
    application_id: applicationId,
    client_id: clientId,
    scope: "orders:read",
    jti: "bearer-jti-1",
    credential_id: "credential-1",
    credential_version: 1,
    ...overrides,
  };
}

function serviceClaims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    iss: clientId,
    sub: clientId,
    aud: assertionAudience,
    exp: nowSeconds + 300,
    nbf: nowSeconds - 1,
    iat: nowSeconds - 10,
    tenant_id: tenantId,
    jti: "service-jti-1",
    ...overrides,
  };
}

function identity(
  claims: Record<string, unknown>,
  overrides: Partial<OidcAdapterCredentialIdentity> = {},
): OidcAdapterCredentialIdentity {
  return {
    active: true,
    tenantId,
    applicationId,
    clientId,
    credentialId: "credential-1",
    credentialVersion: 1,
    scopes: ["orders:read"],
    audiences: [audience],
    issuedAt: new Date((claims.iat as number) * 1000).toISOString(),
    expiresAt: new Date((claims.exp as number) * 1000).toISOString(),
    principalClaims: {
      subject: "user-1",
      issuer: issuer,
      audiences: [audience],
      tenantId,
      applicationId,
      clientId,
      scopes: ["orders:read"],
      issuedAt: new Date((claims.iat as number) * 1000).toISOString(),
      notBefore: new Date((claims.nbf as number) * 1000).toISOString(),
      expiresAt: new Date((claims.exp as number) * 1000).toISOString(),
    },
    ...overrides,
  };
}

function resolver(
  claims: Record<string, unknown>,
  value: OidcAdapterCredentialIdentity = identity(claims),
): OidcIdentityResolverPort {
  return {
    productionReady: true,
    readiness: () => true,
    resolve: vi.fn(() => value),
  };
}

function bearerCrypto(
  claims: Record<string, unknown>,
): { readonly port: OidcBearerJwtVerifierPort; readonly verify: ReturnType<typeof vi.fn> } {
  const verify = vi.fn(async () => ({
    signatureVerified: true as const,
    claims,
    protectedHeader: { alg: "RS256", typ: "at+jwt", kid: "key-1" },
  }));
  return {
    port: {
      kind: "bearer",
      productionReady: true,
      readiness: () => true,
      verify,
    },
    verify,
  };
}

function serviceCrypto(
  claims: Record<string, unknown>,
): { readonly port: OidcServiceClientJwtVerifierPort; readonly verify: ReturnType<typeof vi.fn> } {
  const verify = vi.fn(async () => ({
    signatureVerified: true as const,
    claims,
    protectedHeader: { alg: "RS256", typ: "JWT", kid: "service-key-1" },
  }));
  return {
    port: {
      kind: "serviceClient",
      productionReady: true,
      readiness: () => true,
      verify,
    },
    verify,
  };
}

function bearerAdapter(
  claims: Record<string, unknown>,
  options: {
    readonly requiredScopes?: readonly string[];
    readonly revocation?: InMemoryOidcRevocationStore;
    readonly identityResolver?: OidcIdentityResolverPort;
  } = {},
): { readonly adapter: OpenPlatformOidcBearerVerifierAdapter; readonly crypto: ReturnType<typeof bearerCrypto> } {
  const crypto = bearerCrypto(claims);
  const adapter = new OpenPlatformOidcBearerVerifierAdapter({
    mode: "test",
    issuer,
    tenantId,
    applicationId,
    clientId,
    requiredScopes: options.requiredScopes ?? ["orders:read"],
    jwtVerifier: crypto.port,
    identityResolver: options.identityResolver ?? resolver(claims),
    revocation: options.revocation ?? new InMemoryOidcRevocationStore(),
    clock: () => new Date(initialNow),
  });
  return { adapter, crypto };
}

function serviceAdapter(
  claims: Record<string, unknown>,
): { readonly adapter: OpenPlatformOidcServiceClientVerifierAdapter; readonly crypto: ReturnType<typeof serviceCrypto> } {
  const crypto = serviceCrypto(claims);
  const adapter = new OpenPlatformOidcServiceClientVerifierAdapter({
    mode: "test",
    issuer,
    tenantId,
    applicationId,
    clientId,
    authenticationMethod: "private_key_jwt",
    assertionAudience,
    requiredScopes: ["orders:read"],
    allowedScopes: ["orders:read"],
    jwtVerifier: crypto.port,
    identityResolver: {
      productionReady: true,
      resolve: () => ({
        ...identity(claims, {
          principalClaims: {
            subject: clientId,
            issuer: clientId,
            audiences: [audience],
            tenantId,
            applicationId,
            clientId,
            scopes: ["orders:read"],
            issuedAt: new Date((claims.iat as number) * 1000).toISOString(),
            notBefore: new Date((claims.nbf as number) * 1000).toISOString(),
            expiresAt: new Date((claims.exp as number) * 1000).toISOString(),
          },
        }),
      }),
    },
    revocation: new InMemoryOidcRevocationStore(),
    clock: () => new Date(initialNow),
  });
  return { adapter, crypto };
}

describe("OIDC runtime verifier adapter", () => {
  it("accepts a valid signed bearer token and returns only sanitized principal claims", async () => {
    const claims = bearerClaims();
    const { adapter, crypto } = bearerAdapter(claims);
    const result = await adapter.verify({
      token: bearerToken,
      audience,
      requestId: "oidc-request-1",
    });
    expect(result).toMatchObject({
      tenantId,
      applicationId,
      clientId,
      credentialId: "credential-1",
      credentialVersion: 1,
      scopes: ["orders:read"],
      audiences: [audience],
    });
    expect(result.principalClaims).toMatchObject({
      subject: "user-1",
      tenantId,
      clientId,
      scopes: ["orders:read"],
    });
    expect(result.principalClaims).not.toHaveProperty("token");
    expect(result.principalClaims).not.toHaveProperty("access_token");
    expect(JSON.stringify(result)).not.toContain(bearerToken);
    expect(crypto.verify).toHaveBeenCalledWith(expect.objectContaining({
      token: bearerToken,
      issuer,
      audience,
    }));
    await expect(adapter.isReady()).resolves.toBe(true);
  });

  it("fails closed for an expired token", async () => {
    const claims = bearerClaims({ exp: nowSeconds - 1 });
    const { adapter } = bearerAdapter(claims);
    await expect(adapter.verify({
      token: bearerToken,
      audience,
      requestId: "oidc-expired",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.EXPIRED,
    });
  });

  it("rejects a token for the wrong audience", async () => {
    const claims = bearerClaims();
    const { adapter } = bearerAdapter(claims);
    await expect(adapter.verify({
      token: bearerToken,
      audience: "urn:getbrick:api:billing",
      requestId: "oidc-audience",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_AUDIENCE,
    });
  });

  it("rejects a token missing a required scope", async () => {
    const claims = bearerClaims({ scope: "profile" });
    const { adapter } = bearerAdapter(claims, { requiredScopes: ["orders:read"] });
    await expect(adapter.verify({
      token: bearerToken,
      audience,
      requestId: "oidc-scope",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_SCOPE,
    });
  });

  it("revokes cached tokens and invalidates the cache without retaining the token", async () => {
    const claims = bearerClaims();
    const { adapter, crypto } = bearerAdapter(claims);
    await adapter.verify({ token: bearerToken, audience, requestId: "oidc-cache-1" });
    await adapter.verify({ token: bearerToken, audience, requestId: "oidc-cache-2" });
    expect(crypto.verify).toHaveBeenCalledTimes(1);
    await adapter.revoke({
      issuer,
      tenantId,
      clientId,
      tokenId: "bearer-jti-1",
    });
    expect(adapter.cacheSize()).toBe(0);
    await expect(adapter.verify({
      token: bearerToken,
      audience,
      requestId: "oidc-cache-3",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.REVOKED,
    });
    expect(JSON.stringify(adapter)).not.toContain(bearerToken);
  });

  it("uses a separate service-client verifier for private_key_jwt", async () => {
    const claims = serviceClaims();
    const { adapter, crypto } = serviceAdapter(claims);
    const result = await adapter.verify({
      assertion: serviceAssertion,
      clientId,
      audience,
      requestId: "service-request-1",
    });
    expect(result).toMatchObject({
      tenantId,
      clientId,
      scopes: ["orders:read"],
    });
    expect(crypto.verify).toHaveBeenCalledWith(expect.objectContaining({
      token: serviceAssertion,
      issuer: clientId,
      audience: assertionAudience,
      clientId,
      authenticationMethod: "private_key_jwt",
    }));
    expect(JSON.stringify(result)).not.toContain(serviceAssertion);
  });

  it("validates client_credentials tokens through the service-client port", async () => {
    const claims = serviceClaims({
      iss: issuer,
      sub: "service-account-1",
      aud: audience,
      client_id: clientId,
      scope: "orders:read",
      grant_type: "client_credentials",
    });
    const crypto = serviceCrypto(claims);
    const adapter = new OpenPlatformOidcServiceClientVerifierAdapter({
      mode: "test",
      issuer,
      tenantId,
      applicationId,
      clientId,
      authenticationMethod: "client_credentials",
      requiredScopes: ["orders:read"],
      jwtVerifier: crypto.port,
      identityResolver: resolver(claims),
      revocation: new InMemoryOidcRevocationStore(),
      clock: () => new Date(initialNow),
    });
    await expect(adapter.verify({
      assertion: serviceAssertion,
      clientId,
      audience,
      requestId: "client-credentials-request",
    })).resolves.toMatchObject({
      tenantId,
      clientId,
      scopes: ["orders:read"],
    });
    expect(crypto.verify).toHaveBeenCalledWith(expect.objectContaining({
      issuer,
      audience,
      authenticationMethod: "client_credentials",
    }));
  });

  it("requires an exact client_credentials grant and intersects resolver scopes", async () => {
    const baseClaims = serviceClaims({
      iss: issuer,
      sub: "service-account-1",
      aud: audience,
      client_id: clientId,
      scope: "orders:read",
      grant_type: "client_credentials",
    });
    const missingGrantClaims = { ...baseClaims, grant_type: undefined };
    const missingGrant = new OpenPlatformOidcServiceClientVerifierAdapter({
      mode: "test",
      issuer,
      tenantId,
      applicationId,
      clientId,
      authenticationMethod: "client_credentials",
      requiredScopes: ["orders:read"],
      jwtVerifier: serviceCrypto(missingGrantClaims).port,
      identityResolver: resolver(missingGrantClaims),
      revocation: new InMemoryOidcRevocationStore(),
      clock: () => new Date(initialNow),
    });
    await expect(missingGrant.verify({
      assertion: serviceAssertion,
      clientId,
      audience,
      requestId: "missing-grant",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_TOKEN,
    });
    const wrongGrant = new OpenPlatformOidcServiceClientVerifierAdapter({
      mode: "test",
      issuer,
      tenantId,
      applicationId,
      clientId,
      authenticationMethod: "client_credentials",
      requiredScopes: ["orders:read"],
      jwtVerifier: serviceCrypto({ ...baseClaims, grant_type: "authorization_code" }).port,
      identityResolver: resolver({ ...baseClaims, grant_type: "authorization_code" }),
      revocation: new InMemoryOidcRevocationStore(),
      clock: () => new Date(initialNow),
    });
    await expect(wrongGrant.verify({
      assertion: serviceAssertion,
      clientId,
      audience,
      requestId: "wrong-grant",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_TOKEN,
    });
    const noScopeClaims = { ...baseClaims, scope: "" };
    const noScope = new OpenPlatformOidcServiceClientVerifierAdapter({
      mode: "test",
      issuer,
      tenantId,
      applicationId,
      clientId,
      authenticationMethod: "client_credentials",
      jwtVerifier: serviceCrypto(noScopeClaims).port,
      identityResolver: resolver(
        noScopeClaims,
        identity(noScopeClaims, { scopes: ["orders:read", "orders:write"] }),
      ),
      revocation: new InMemoryOidcRevocationStore(),
      clock: () => new Date(initialNow),
    });
    await expect(noScope.verify({
      assertion: serviceAssertion,
      clientId,
      audience,
      requestId: "empty-scope",
    })).resolves.toMatchObject({ scopes: [] });
    const intersected = new OpenPlatformOidcServiceClientVerifierAdapter({
      mode: "test",
      issuer,
      tenantId,
      applicationId,
      clientId,
      authenticationMethod: "client_credentials",
      requiredScopes: ["orders:read"],
      allowedScopes: ["orders:read", "orders:write"],
      jwtVerifier: serviceCrypto(baseClaims).port,
      identityResolver: resolver(
        baseClaims,
        identity(baseClaims, { scopes: ["orders:read", "orders:write"] }),
      ),
      revocation: new InMemoryOidcRevocationStore(),
      clock: () => new Date(initialNow),
    });
    await expect(intersected.verify({
      assertion: serviceAssertion,
      clientId,
      audience,
      requestId: "scope-intersection",
    })).resolves.toMatchObject({ scopes: ["orders:read"] });
  });

  it("caches unknown kids and rate-limits resolver refreshes", async () => {
    const resolve = vi.fn(() => ({ keys: [testPublicJwk] }));
    const jwtVerify = vi.fn(async () => {
      throw new Error("signature rejected");
    });
    const verifier = createOidcJoseBearerJwtVerifier({
      jose: {
        createLocalJWKSet: vi.fn(() => ({})),
        jwtVerify,
      },
      jwks: {
        source: "preconfigured",
        productionReady: true,
        readiness: () => true,
        resolve,
      },
      clock: () => new Date(initialNow),
    });
    const tokenFor = (kid: string): string => {
      const header = Buffer.from(JSON.stringify({ alg: "RS256", kid })).toString("base64url");
      const payload = Buffer.from(JSON.stringify({ iss: issuer })).toString("base64url");
      return `${header}.${payload}.signature`;
    };
    const input = (token: string) => ({
      token,
      issuer,
      audience,
      algorithms: ["RS256" as const],
      now: nowSeconds,
      requestId: "kid-test",
    });
    await expect(verifier.verify(input(tokenFor("random-kid-a")))).rejects.toMatchObject({
      code: OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_TOKEN,
    });
    await expect(verifier.verify(input(tokenFor("random-kid-b")))).rejects.toMatchObject({
      code: OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_TOKEN,
    });
    expect(resolve).toHaveBeenCalledTimes(1);
    expect(jwtVerify).not.toHaveBeenCalled();
    await expect(verifier.verify(input(tokenFor("key-1")))).rejects.toMatchObject({
      code: OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_TOKEN,
    });
    expect(resolve).toHaveBeenCalledTimes(1);
  });

  it("blocks unsafe remote JWKS endpoints and DNS rebinding", async () => {
    expect(() => assertSafeOidcJwksEndpoint("https://localhost/jwks", {
      mode: "production",
      trustedHosts: ["localhost"],
    })).toThrowError();
    expect(() => assertSafeOidcJwksEndpoint("https://127.0.0.1/jwks", {
      mode: "production",
      trustedHosts: ["127.0.0.1"],
    })).toThrowError();
    expect(() => assertSafeOidcJwksEndpoint("https://169.254.169.254/jwks", {
      mode: "production",
      trustedHosts: ["169.254.169.254"],
    })).toThrowError();
    expect(() => assertSafeOidcJwksEndpoint("https://metadata.google.internal/jwks", {
      mode: "production",
      trustedHosts: ["metadata.google.internal"],
    })).toThrowError();
    const fetchJwks = vi.fn(async (_input: string, init?: RequestInit) => {
      expect(init?.redirect).toBe("error");
      return new Response(JSON.stringify({ keys: [testPublicJwk] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });
    const safeRemoteResolver = createRemoteOidcJwksResolver({
      mode: "test",
      jwksUri: "https://keys.example/jwks",
      issuerAllowlist: [issuer],
      trustedHosts: ["keys.example", "issuer.example"],
      allowRemoteJwks: true,
      fetch: fetchJwks,
      resolveHost: () => ["93.184.216.34"],
    });
    await expect(safeRemoteResolver.resolve({ issuer })).resolves.toMatchObject({
      keys: [testPublicJwk],
    });
    const remote = {
      source: "remote" as const,
      jwksUri: "https://keys.example/jwks",
      trustedHosts: ["keys.example", "issuer.example"],
      issuerAllowlist: [issuer],
      productionReady: true,
      readiness: () => true,
      resolve: vi.fn(() => ({ keys: [testPublicJwk] })),
    };
    expect(() => createOidcJoseBearerJwtVerifier({
      mode: "production",
      productionReady: true,
      jose: {
        createLocalJWKSet: vi.fn(() => ({})),
        jwtVerify: vi.fn(),
      },
      jwks: remote,
    })).toThrowError();
    const rebinding = createOidcJoseBearerJwtVerifier({
      mode: "production",
      productionReady: true,
      allowRemoteJwks: true,
      jose: {
        createLocalJWKSet: vi.fn(() => ({})),
        jwtVerify: vi.fn(),
      },
      jwks: {
        ...remote,
        resolveHost: () => ["127.0.0.1"],
      },
    });
    const header = Buffer.from(JSON.stringify({ alg: "RS256", kid: "key-1" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify({ iss: issuer })).toString("base64url");
    await expect(rebinding.verify({
      token: `${header}.${payload}.signature`,
      issuer,
      audience,
      algorithms: ["RS256"],
      now: nowSeconds,
      requestId: "rebinding-test",
    })).rejects.toMatchObject({
      code: OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION,
    });
  });

  it("requires readiness to return exactly true and fails closed when missing", async () => {
    const claims = bearerClaims();
    const crypto = bearerCrypto(claims).port;
    const missingReadiness = new OpenPlatformOidcBearerVerifierAdapter({
      mode: "test",
      issuer,
      tenantId,
      applicationId,
      clientId,
      jwtVerifier: crypto,
      identityResolver: {
        resolve: () => identity(claims),
      },
      revocation: new InMemoryOidcRevocationStore(),
      clock: () => new Date(initialNow),
    });
    await expect(missingReadiness.isReady()).resolves.toBe(false);
    const nonBooleanReadiness = new OpenPlatformOidcBearerVerifierAdapter({
      mode: "test",
      issuer,
      tenantId,
      applicationId,
      clientId,
      jwtVerifier: crypto,
      identityResolver: {
        resolve: () => identity(claims),
        readiness: () => undefined as never,
      },
      revocation: new InMemoryOidcRevocationStore(),
      clock: () => new Date(initialNow),
    });
    await expect(nonBooleanReadiness.isReady()).resolves.toBe(false);
    const joseWithoutReadiness = createOidcJoseBearerJwtVerifier({
      jose: {
        createLocalJWKSet: vi.fn(() => ({})),
        jwtVerify: vi.fn(),
      },
      jwks: {
        source: "preconfigured",
        productionReady: true,
        resolve: vi.fn(() => ({ keys: [testPublicJwk] })),
      },
      clock: () => new Date(initialNow),
    });
    await expect(joseWithoutReadiness.readiness?.()).resolves.toBe(false);
  });

  it("gates production mode on ready cryptographic, identity, and revocation ports", async () => {
    const claims = bearerClaims();
    const crypto = bearerCrypto(claims).port;
    const productionRevocation = {
      productionReady: true,
      readiness: () => true,
      isRevoked: () => false,
      revoke: vi.fn(),
    };
    const adapter = new OpenPlatformOidcBearerVerifierAdapter({
      mode: "production",
      issuer,
      tenantId,
      applicationId,
      clientId,
      requiredScopes: ["orders:read"],
      jwtVerifier: crypto,
      identityResolver: resolver(claims),
      revocation: productionRevocation,
      clock: () => new Date(initialNow),
    });
    await expect(adapter.isReady()).resolves.toBe(true);
    expect(() => new OpenPlatformOidcBearerVerifierAdapter({
      mode: "production",
      issuer,
      tenantId,
      applicationId,
      clientId,
      jwtVerifier: {
        kind: "bearer",
        productionReady: true,
        verify: crypto.verify,
      },
      identityResolver: resolver(claims),
      revocation: productionRevocation,
      clock: () => new Date(initialNow),
    })).toThrowError();
  });

  it("wires both ports as Nest providers", () => {
    const claims = bearerClaims();
    const bearer = bearerAdapter(claims).adapter;
    const service = serviceAdapter(serviceClaims()).adapter;
    const module = OpenPlatformOidcAdapterNestModule.forRoot({
      mode: "test",
      oidcBearerVerifier: bearer,
      serviceClientVerifier: service,
    });
    expect(module.providers).toHaveLength(4);
    expect(module.exports).toHaveLength(4);
  });

  it("uses the injected jose/JWK verifier without accepting unverified claims", async () => {
    const header = Buffer.from(JSON.stringify({ alg: "RS256", kid: "key-1" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify(bearerClaims())).toString("base64url");
    const token = `${header}.${payload}.signature`;
    const jwtVerify = vi.fn(async () => ({
      payload: bearerClaims(),
      protectedHeader: { alg: "RS256", kid: "key-1" },
    }));
    const verifier = createOidcJoseBearerJwtVerifier({
      mode: "test",
      jose: {
        createLocalJWKSet: vi.fn(() => ({})),
        jwtVerify,
      },
      jwks: {
        source: "preconfigured",
        productionReady: true,
        resolve: vi.fn(() => ({ keys: [testPublicJwk] })),
      },
      productionReady: true,
      clock: () => new Date(initialNow),
    });
    const adapter = new OpenPlatformOidcBearerVerifierAdapter({
      mode: "test",
      issuer,
      tenantId,
      applicationId,
      clientId,
      requiredScopes: ["orders:read"],
      jwtVerifier: verifier,
      identityResolver: resolver(bearerClaims()),
      revocation: new InMemoryOidcRevocationStore(),
      clock: () => new Date(initialNow),
    });
    await expect(adapter.verify({ token, audience, requestId: "jose-request" })).resolves.toMatchObject({
      credentialId: "credential-1",
    });
    expect(jwtVerify).toHaveBeenCalledTimes(1);
  });
});
