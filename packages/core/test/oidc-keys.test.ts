import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import type { AdapterFactory } from "oidc-provider";
import { exportJWK, generateKeyPair, jwtVerify } from "jose";
import {
  OIDC_CLIENT_AUTH_SIGNING_ALGORITHMS,
  createOidcProvider,
  validateOidcCookieKeys,
  validateOidcSigningJwks,
} from "../src/index.js";

const rsaKey = {
  ...generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({ format: "jwk" }),
  kid: "key-1",
  alg: "RS256",
  use: "sig",
};

async function privateSigningJwks(algorithm: "RS256" | "PS256" | "ES256" | "EdDSA", kid: string) {
  const { privateKey } = await generateKeyPair(algorithm, { extractable: true });
  const jwk = await exportJWK(privateKey);
  return { keys: [{ ...jwk, kid, alg: algorithm, use: "sig" }] };
}

async function publicClientJwks(algorithm: "RS256" | "PS256" | "ES256" | "EdDSA", kid: string) {
  const { publicKey } = await generateKeyPair(algorithm);
  const jwk = await exportJWK(publicKey);
  return { keys: [{ ...jwk, kid, alg: algorithm, use: "sig" }] };
}

describe("OIDC key validation", () => {
  it("accepts a signing JWKS and rejects incomplete or duplicate keys", () => {
    expect(() => validateOidcSigningJwks({ keys: [rsaKey] }, "RS256")).not.toThrow();
    expect(() => validateOidcSigningJwks({ keys: [{ ...rsaKey, kid: undefined }] }, "RS256")).toThrow(/kid/i);
    expect(() => validateOidcSigningJwks({ keys: [rsaKey, rsaKey] }, "RS256")).toThrow(/duplicate/i);
    expect(() => validateOidcSigningJwks({ keys: [{ ...rsaKey, d: undefined }] }, "RS256")).toThrow(/private/i);
  });

  it("validates all four provider signing algorithms", async () => {
    for (const algorithm of OIDC_CLIENT_AUTH_SIGNING_ALGORITHMS) {
      const jwks = await privateSigningJwks(algorithm, `private-${algorithm}`);
      expect(() => validateOidcSigningJwks(jwks, algorithm)).not.toThrow();
    }
  });

  it("issues and verifies ID tokens with every supported provider algorithm", async () => {
    for (const algorithm of OIDC_CLIENT_AUTH_SIGNING_ALGORITHMS) {
      const { privateKey, publicKey } = await generateKeyPair(algorithm, { extractable: true });
      const privateJwk = await exportJWK(privateKey);
      const jwks = {
        keys: [{ ...privateJwk, kid: `provider-${algorithm}`, alg: algorithm, use: "sig" }],
      };
      const issuer = `https://id.example.test/${algorithm}`;
      const clientId = `client-${algorithm}`;
      const runtime = createOidcProvider({
        config: {
          enabled: true,
          issuer,
          basePath: "/oidc",
          scopes: ["openid"],
          clients: [{
            clientId,
            clientSecret: "client-secret",
            redirectUris: ["https://client.example.test/callback"],
            grantTypes: ["authorization_code"],
            responseTypes: ["code"],
            scopes: ["openid"],
            tokenEndpointAuthMethod: "client_secret_basic",
          }],
          signingAlgorithm: algorithm,
          jwks,
          refreshTokenEnabled: true,
          sensitiveScopes: ["offline_access"],
          requireExplicitConsent: true,
          dynamicClients: false,
        } as never,
        findUser: async () => null,
        cookieKeys: ["a".repeat(32)],
      });
      const client = await runtime.provider.Client.find(clientId);
      const token = await new runtime.provider.IdToken({ sub: "user-1" }, { client: client! }).issue({ use: "idtoken" });
      await expect(jwtVerify(token, publicKey, {
        issuer,
        audience: clientId,
        algorithms: [algorithm],
      })).resolves.toMatchObject({ payload: { iss: issuer, aud: clientId } });
    }
  });
  it("projects all four private_key_jwt algorithms through the provider", async () => {
    for (const algorithm of OIDC_CLIENT_AUTH_SIGNING_ALGORITHMS) {
      const jwks = await publicClientJwks(algorithm, `client-${algorithm}`);
      const clientId = `client-${algorithm}`;
      const config = {
        enabled: true,
        issuer: "https://id.example.test/oidc",
        basePath: "/oidc",
        scopes: ["openid"],
        clients: [{
          clientId,
          applicationType: "web",
          redirectUris: ["https://client.example.test/callback"],
          grantTypes: ["authorization_code"],
          responseTypes: ["code"],
          scopes: ["openid"],
          tokenEndpointAuthMethod: "private_key_jwt",
          tokenEndpointAuthSigningAlg: algorithm,
          jwks,
        }],
        signingAlgorithm: "RS256",
        refreshTokenEnabled: true,
        sensitiveScopes: ["offline_access"],
        requireExplicitConsent: true,
        dynamicClients: false,
      } as never;
      const runtime = createOidcProvider({
        config,
        findUser: async () => null,
        cookieKeys: ["a".repeat(32)],
      });
      const client = await runtime.provider.Client.find(clientId);
      expect(client?.clientAuthSigningAlg).toBe(algorithm);
    }
  });

  it("does not allow insecure HTTP redirects in production", () => {
    expect(() => createOidcProvider({
      config: { enabled: true, issuer: "https://id.example.test/oidc" } as never,
      profile: "production",
      allowInsecureHttp: true,
      findUser: async () => null,
    })).toThrow(/insecure HTTP/i);
  });

  it("rejects production static remote JWKS before provider construction", () => {
    const adapter = Object.assign(
      () => ({ find: async () => undefined, upsert: async () => undefined, destroy: async () => undefined }),
      { ready: async () => true },
    );
    expect(() => createOidcProvider({
      config: {
        enabled: true,
        issuer: "https://id.example.test/oidc",
        basePath: "/oidc",
        scopes: ["openid"],
        clients: [{
          clientId: "remote-static",
          redirectUris: ["https://client.example.test/callback"],
          grantTypes: ["authorization_code"],
          responseTypes: ["code"],
          scopes: ["openid"],
          tokenEndpointAuthMethod: "private_key_jwt",
          jwksUri: "https://client.example.test/jwks",
        }],
        signingAlgorithm: "RS256",
        refreshTokenEnabled: true,
        sensitiveScopes: ["offline_access"],
        requireExplicitConsent: true,
        dynamicClients: false,
      } as never,
      profile: "production",
      adapter: adapter as never,
      jwks: { keys: [rsaKey] },
      findUser: async () => null,
      cookieKeys: ["a".repeat(32)],
    })).toThrow(/jwks_uri.*invalid/i);
  });

  it("defaults confidential static clients to private_key_jwt", async () => {
    const jwks = await publicClientJwks("RS256", "default-private-key");
    const config = {
      enabled: true,
      issuer: "https://id.example.test/oidc",
      basePath: "/oidc",
      scopes: ["openid"],
      clients: [{
        clientId: "default-private",
        redirectUris: ["https://client.example.test/callback"],
        grantTypes: ["authorization_code"],
        responseTypes: ["code"],
        scopes: ["openid"],
        jwks,
      }],
      signingAlgorithm: "RS256",
      refreshTokenEnabled: true,
      sensitiveScopes: ["offline_access"],
      requireExplicitConsent: true,
      dynamicClients: false,
    } as never;
    const runtime = createOidcProvider({
      config,
      findUser: async () => null,
      cookieKeys: ["a".repeat(32)],
    });
    const client = await runtime.provider.Client.find("default-private");
    expect(client?.clientAuthMethod).toBe("private_key_jwt");
  });

  it("prefers a static client over a managed adapter conflict", async () => {
    const managedFind = vi.fn(async () => undefined);
    const adapter = (() => ({
      find: managedFind,
      upsert: async () => undefined,
      destroy: async () => undefined,
    })) as unknown as AdapterFactory;
    const config = {
      enabled: true,
      issuer: "https://id.example.test/oidc",
      basePath: "/oidc",
      scopes: ["openid"],
      clients: [{
        clientId: "shared-static",
        clientSecret: "shared-secret",
        redirectUris: ["https://client.example.test/callback"],
        grantTypes: ["authorization_code"],
        responseTypes: ["code"],
        scopes: ["openid"],
        tokenEndpointAuthMethod: "client_secret_basic",
      }],
      signingAlgorithm: "RS256",
      refreshTokenEnabled: true,
      sensitiveScopes: ["offline_access"],
      requireExplicitConsent: true,
      dynamicClients: true,
    } as never;
    const runtime = createOidcProvider({
      config,
      adapter,
      dynamicClients: true,
      findUser: async () => null,
      cookieKeys: ["a".repeat(32)],
    });
    const client = await runtime.provider.Client.find("shared-static");
    expect(client?.clientAuthMethod).toBe("client_secret_basic");
    expect(managedFind).not.toHaveBeenCalled();
  });

  it("enforces cookie key length when requested", () => {
    expect(() => validateOidcCookieKeys(["a".repeat(32)], 32)).not.toThrow();
    expect(() => validateOidcCookieKeys(["short"], 32)).toThrow(/32/);
  });
});
